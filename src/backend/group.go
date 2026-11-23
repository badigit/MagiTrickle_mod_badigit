package magitrickle

import (
	"errors"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"magitrickle/models"
	"magitrickle/utils/netfilterTools"

	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
)

type Group struct {
	*models.Group

	enabled atomic.Bool
	locker  sync.Mutex

	app           *App
	runtimeID     string
	ipset         *netfilterTools.IPSet
	ipsetToLink   *netfilterTools.IPSetToLink
	ipsetToTProxy *netfilterTools.IPSetToTProxy

	// staticHostV4/V6 — точные host-члены ipset (одиночные IP) из статических
	// subnet-правил группы. Это permanent-записи (timeout=0); динамический add
	// с TTL (DNS-путь) не должен их перезаписывать: netlink Replace:true сбросил
	// бы timeout 0 → запись стала бы испаряемой (близнец апстримного
	// «TODO: Check already existed» в dns.go). Кэш обновляется в sync() и
	// ReassertStaticSubnets() под g.locker; читается в AddIPv4/IPv6Subnet под
	// тем же локом. nil-map до первого sync — безопасно (lookup по nil = miss;
	// до первого sync в сете ещё нет статических записей, клобберить нечего).
	staticHostV4 map[[4]byte]struct{}
	staticHostV6 map[[16]byte]struct{}
}

func (g *Group) Enabled() bool {
	return g.enabled.Load()
}

func NewGroup(group *models.Group, app *App) (*Group, error) {
	return newGroupWithRuntimeID(group, app, group.ID.String())
}

func newGroupWithRuntimeID(group *models.Group, app *App, runtimeID string) (*Group, error) {
	return &Group{
		Group:     group,
		app:       app,
		runtimeID: runtimeID,
	}, nil
}

func (g *Group) Model() *models.Group {
	return g.Group
}

func (g *Group) addIPv4Subnet(subnet netfilterTools.IPv4Subnet, ttl netfilterTools.IPSetTimeout) error {
	return g.ipset.AddIPv4Subnet(subnet, ttl)
}

func (g *Group) AddIPv4Subnet(subnet netfilterTools.IPv4Subnet, ttl netfilterTools.IPSetTimeout) error {
	g.locker.Lock()
	defer g.locker.Unlock()
	if !g.Enabled() {
		return nil
	}

	if !g.Group.Enable {
		return nil
	}

	// Guard: TTL'ный add на IP, совпадающий со статическим host-членом, скипаем —
	// permanent-запись уже покрывает этот IP, а Replace:true сбросил бы её вечность.
	if ttl != nil && (subnet.CIDR == 0 || subnet.CIDR == 32) {
		if _, ok := g.staticHostV4[subnet.Address]; ok {
			return nil
		}
	}

	return g.addIPv4Subnet(subnet, ttl)
}

func (g *Group) addIPv6Subnet(subnet netfilterTools.IPv6Subnet, ttl netfilterTools.IPSetTimeout) error {
	return g.ipset.AddIPv6Subnet(subnet, ttl)
}

func (g *Group) AddIPv6Subnet(subnet netfilterTools.IPv6Subnet, ttl netfilterTools.IPSetTimeout) error {
	g.locker.Lock()
	defer g.locker.Unlock()
	if !g.Enabled() {
		return nil
	}

	if !g.Group.Enable {
		return nil
	}

	// Guard: см. AddIPv4Subnet — не клобберим permanent host-члены TTL'ным add'ом.
	if ttl != nil && (subnet.CIDR == 0 || subnet.CIDR == 128) {
		if _, ok := g.staticHostV6[subnet.Address]; ok {
			return nil
		}
	}

	return g.addIPv6Subnet(subnet, ttl)
}

func (g *Group) delIPv4Subnet(subnet netfilterTools.IPv4Subnet) error {
	return g.ipset.DelIPv4Subnet(subnet)
}

func (g *Group) DelIPv4Subnet(subnet netfilterTools.IPv4Subnet) error {
	g.locker.Lock()
	defer g.locker.Unlock()
	if !g.Enabled() {
		return nil
	}

	if !g.Group.Enable {
		return nil
	}

	return g.delIPv4Subnet(subnet)
}

func (g *Group) delIPv6Subnet(subnet netfilterTools.IPv6Subnet) error {
	return g.ipset.DelIPv6Subnet(subnet)
}

func (g *Group) DelIPv6Subnet(subnet netfilterTools.IPv6Subnet) error {
	g.locker.Lock()
	defer g.locker.Unlock()
	if !g.Enabled() {
		return nil
	}

	if !g.Group.Enable {
		return nil
	}

	return g.delIPv6Subnet(subnet)
}

func (g *Group) listIPv4Subnets() (map[netfilterTools.IPv4Subnet]netfilterTools.IPSetTimeout, error) {
	return g.ipset.ListIPv4Subnets()
}

func (g *Group) ListIPv4Subnets() (map[netfilterTools.IPv4Subnet]netfilterTools.IPSetTimeout, error) {
	g.locker.Lock()
	defer g.locker.Unlock()
	if !g.Enabled() {
		return nil, nil
	}

	if !g.Group.Enable {
		return nil, nil
	}

	return g.listIPv4Subnets()
}

func (g *Group) listIPv6Subnets() (map[netfilterTools.IPv6Subnet]netfilterTools.IPSetTimeout, error) {
	return g.ipset.ListIPv6Subnets()
}

func (g *Group) ListIPv6Subnets() (map[netfilterTools.IPv6Subnet]netfilterTools.IPSetTimeout, error) {
	g.locker.Lock()
	defer g.locker.Unlock()
	if !g.Enabled() {
		return nil, nil
	}

	if !g.Group.Enable {
		return nil, nil
	}

	return g.listIPv6Subnets()
}

func (g *Group) enable(netfilter models.AppConfigNetfilter) error {
	if !g.enabled.CompareAndSwap(false, true) {
		return nil
	}

	if !g.Group.Enable {
		return nil
	}

	ipset := g.app.nfHelper.IPSet(g.runtimeID)

	switch g.Group.EffectiveRouteMode() {
	case models.RouteModeTProxy:
		ipsetToTProxy := g.app.nfHelper.IPSetToTProxy(g.runtimeID, netfilter.TProxyPort, ipset, netfilter.IPSet.AdditionalTTL)
		if err := ipsetToTProxy.ClearIfDisabled(); err != nil {
			return fmt.Errorf("failed to clear iptables: %w", err)
		}

		if err := ipset.Enable(); err != nil {
			return fmt.Errorf("failed to initialize ipset: %w", err)
		}
		g.ipset = ipset

		if err := ipsetToTProxy.Enable(); err != nil {
			return fmt.Errorf("failed to link ipset to tproxy: %w", err)
		}
		g.ipsetToTProxy = ipsetToTProxy

	default: // RouteModeInterface
		ipsetToLink := g.app.nfHelper.IPSetToLink(g.runtimeID, g.Interface, ipset)
		if err := ipsetToLink.ClearIfDisabled(); err != nil {
			return fmt.Errorf("failed to clear iptables: %w", err)
		}

		if err := ipset.Enable(); err != nil {
			return fmt.Errorf("failed to initialize ipset: %w", err)
		}
		g.ipset = ipset

		if err := ipsetToLink.Enable(); err != nil {
			return fmt.Errorf("failed to link ipset to interface: %w", err)
		}
		g.ipsetToLink = ipsetToLink
	}

	return nil
}

func (g *Group) Enable() error {
	return g.enableWithConfig(g.app.config.Netfilter)
}

func (g *Group) enableWithConfig(netfilter models.AppConfigNetfilter) error {
	g.locker.Lock()
	defer g.locker.Unlock()
	if err := g.enable(netfilter); err != nil {
		return errors.Join(err, g.disable())
	}
	return nil
}

func (g *Group) disable() error {
	if !g.Enabled() {
		return nil
	}

	errs := []error{g.disableRules()}
	errs = append(errs, g.destroySets())
	return errors.Join(errs...)
}

// disableRules снимает netfilter-правила группы, НЕ трогая ipset. Вызывать под
// g.locker. Отделено от уничтожения сетов ради батчинга teardown: ядро не даёт
// уничтожить сет, на который ещё ссылается правило ("failed to destroy ipset:
// busy"), а под батчем правила до финального коммита сняты только в буфере.
// Поэтому порядок обязателен: снять правила у всех групп -> закоммитить ->
// только потом уничтожать сеты (mt-jou).
func (g *Group) disableRules() error {
	if !g.Group.Enable {
		return nil
	}

	var errs []error
	errs = append(errs, func() error {
		if g.ipsetToLink == nil {
			return nil
		}
		if err := g.ipsetToLink.Disable(); err != nil {
			return fmt.Errorf("failed to unlink ipset from interface: %w", err)
		}
		g.ipsetToLink = nil
		return nil
	}())
	errs = append(errs, func() error {
		if g.ipsetToTProxy == nil {
			return nil
		}
		if err := g.ipsetToTProxy.Disable(); err != nil {
			return fmt.Errorf("failed to unlink ipset from tproxy: %w", err)
		}
		g.ipsetToTProxy = nil
		return nil
	}())
	return errors.Join(errs...)
}

// destroySets уничтожает ipset группы и гасит её флаг. Вызывать под g.locker и
// ТОЛЬКО после того, как правила, ссылающиеся на сет, реально сняты в ядре.
func (g *Group) destroySets() error {
	defer g.enabled.Store(false)

	if !g.Group.Enable {
		return nil
	}

	if g.ipset == nil {
		return nil
	}
	if err := g.ipset.Disable(); err != nil {
		return fmt.Errorf("failed to destroy ipset: %w", err)
	}
	g.ipset = nil
	return nil
}

// DisableRules — фаза 1 двухфазного teardown (см. disableRules).
func (g *Group) DisableRules() error {
	g.locker.Lock()
	defer g.locker.Unlock()
	if !g.Enabled() {
		return nil
	}
	return g.disableRules()
}

// DestroySets — фаза 2 двухфазного teardown (см. destroySets).
func (g *Group) DestroySets() error {
	g.locker.Lock()
	defer g.locker.Unlock()
	if !g.Enabled() {
		return nil
	}
	return g.destroySets()
}

func (g *Group) Disable() error {
	g.locker.Lock()
	defer g.locker.Unlock()
	return g.disable()
}

func (g *Group) sync() error {
	syncStart := time.Now()
	defer func() {
		log.Debug().
			Str("group", g.Name).
			Str("id", g.ID.String()).
			Int("rules", len(g.Rules)).
			Dur("duration", time.Since(syncStart)).
			Msg("group sync completed")
	}()

	// Статические subnet-правила — permanent-записи (timeout=0). Парсинг вынесен
	// в staticSubnetsFromRules, чтобы переиспользовать в ReassertStaticSubnets.
	v4Static, v6Static := staticSubnetsFromRules(g.Rules)
	g.updateStaticHostCache(v4Static, v6Static)
	if err := g.ipset.SyncStaticSubnets(v4Static, v6Static); err != nil {
		// Не фатально: зеркало влияет только на ipset-refresh (mt-bq8), а не на
		// маршрутизацию. Хуже расхождение, чем прерванный sync всей группы.
		log.Error().
			Err(err).
			Str("group", g.Name).
			Msg("failed to sync static-subnet mirror")
	}

	newIPv4SubnetList, newIPv6SubnetList := g.desiredSubnets(time.Now(), v4Static, v6Static)

	oldIPv4SubnetList, err := g.listIPv4Subnets()
	if err != nil {
		return fmt.Errorf("failed to get old ipset list: %w", err)
	}
	var syncErrors []error
	for subnet, newTTL := range newIPv4SubnetList {
		if oldTTL, ok := oldIPv4SubnetList[subnet]; ok {
			if oldTTL == nil || (newTTL != nil && *newTTL < *oldTTL) {
				continue
			}
		}

		if err := g.addIPv4Subnet(subnet, newTTL); err != nil {
			syncErrors = append(syncErrors, fmt.Errorf("add %s: %w", subnet.String(), err))
			log.Error().
				Err(err).
				Str("subnet", subnet.String()).
				Msg("failed to add subnet")
		} else {
			log.Debug().
				Str("subnet", subnet.String()).
				Msg("added subnet")
		}
	}
	for subnet := range oldIPv4SubnetList {
		if _, ok := newIPv4SubnetList[subnet]; ok {
			continue
		}

		if err := g.delIPv4Subnet(subnet); err != nil {
			syncErrors = append(syncErrors, fmt.Errorf("delete %s: %w", subnet.String(), err))
			log.Error().
				Err(err).
				Str("subnet", subnet.String()).
				Msg("failed to delete subnet")
		} else {
			log.Debug().
				Str("subnet", subnet.String()).
				Msg("deleted subnet")
		}
	}

	oldIPv6SubnetList, err := g.listIPv6Subnets()
	if err != nil {
		return errors.Join(append(syncErrors, fmt.Errorf("failed to get old ipset list: %w", err))...)
	}
	for subnet, newTTL := range newIPv6SubnetList {
		if oldTTL, ok := oldIPv6SubnetList[subnet]; ok {
			if oldTTL == nil || (newTTL != nil && *newTTL < *oldTTL) {
				continue
			}
		}

		if err := g.addIPv6Subnet(subnet, newTTL); err != nil {
			syncErrors = append(syncErrors, fmt.Errorf("add %s: %w", subnet.String(), err))
			log.Error().
				Err(err).
				Str("subnet", subnet.String()).
				Msg("failed to add subnet")
		} else {
			log.Debug().
				Str("subnet", subnet.String()).
				Msg("added subnet")
		}
	}
	for subnet := range oldIPv6SubnetList {
		if _, ok := newIPv6SubnetList[subnet]; ok {
			continue
		}

		if err := g.delIPv6Subnet(subnet); err != nil {
			syncErrors = append(syncErrors, fmt.Errorf("delete %s: %w", subnet.String(), err))
			log.Error().
				Err(err).
				Str("subnet", subnet.String()).
				Msg("failed to delete subnet")
		} else {
			log.Debug().
				Str("subnet", subnet.String()).
				Msg("deleted subnet")
		}
	}

	return errors.Join(syncErrors...)
}

// desiredSubnets собирает целевое состояние ipset-сетов группы на момент now:
// переданные статические subnet-правила (permanent-записи, timeout=nil) плюс
// DNS-производные host-записи из recordsCache с остаточным TTL. Чистая функция:
// парсинг правил, кэш host-членов и зеркало _s4/_s6 — забота вызывающего
// (sync), поэтому её можно звать в тестах без живого ipset. Вызывать под
// g.locker.
func (g *Group) desiredSubnets(now time.Time, v4Static []netfilterTools.IPv4Subnet, v6Static []netfilterTools.IPv6Subnet) (map[netfilterTools.IPv4Subnet]netfilterTools.IPSetTimeout, map[netfilterTools.IPv6Subnet]netfilterTools.IPSetTimeout) {
	newIPv4SubnetList := make(map[netfilterTools.IPv4Subnet]netfilterTools.IPSetTimeout)
	newIPv6SubnetList := make(map[netfilterTools.IPv6Subnet]netfilterTools.IPSetTimeout)

	for _, subnet := range v4Static {
		newIPv4SubnetList[subnet] = nil
	}
	for _, subnet := range v6Static {
		newIPv6SubnetList[subnet] = nil
	}

	knownDomains := g.app.recordsCache.ListKnownDomains()
	for _, domain := range g.Rules {
		if !domain.IsEnabled() {
			continue
		}
		switch domain.Type {
		case models.RuleTypeSubnet, models.RuleTypeSubnet6:
			// собраны выше через staticSubnetsFromRules

		default:
			for _, domainName := range knownDomains {
				if !domain.IsMatch(domainName) {
					continue
				}
				domainAddresses := g.app.recordsCache.GetAddresses(domainName)
				for _, address := range domainAddresses {
					ttl, ok := ipsetTTLFromDeadline(address.Deadline.Sub(now))
					if !ok {
						continue
					}
					if len(address.Address) == net.IPv4len {
						subnet := netfilterTools.IPv4Host([4]byte(address.Address))
						if oldTTL, exists := newIPv4SubnetList[subnet]; !exists || (oldTTL != nil && ttl > *oldTTL) {
							newIPv4SubnetList[subnet] = &ttl
						}
					} else if len(address.Address) == net.IPv6len {
						subnet := netfilterTools.IPv6Host([16]byte(address.Address))
						if oldTTL, exists := newIPv6SubnetList[subnet]; !exists || (oldTTL != nil && ttl > *oldTTL) {
							newIPv6SubnetList[subnet] = &ttl
						}
					}
				}
			}
		}
	}

	return newIPv4SubnetList, newIPv6SubnetList
}

// staticSubnetsFromRules собирает включённые subnet/subnet6-правила в виде
// ipset-подсетей (permanent-записи, timeout=0). Вынесено из sync для
// переиспользования в ReassertStaticSubnets. Повторяет прежнее поведение sync,
// включая обход netlink-бага с 0.0.0.0/0 (split на две /1,
// https://github.com/vishvananda/netlink/issues/1091).
func staticSubnetsFromRules(rules []*models.Rule) ([]netfilterTools.IPv4Subnet, []netfilterTools.IPv6Subnet) {
	var v4 []netfilterTools.IPv4Subnet
	var v6 []netfilterTools.IPv6Subnet

	for _, rule := range rules {
		if !rule.IsEnabled() {
			continue
		}
		switch rule.Type {
		case models.RuleTypeSubnet:
			ip, ipNet, err := net.ParseCIDR(rule.Rule)
			if err != nil {
				ip = net.ParseIP(rule.Rule)
				if ip == nil {
					continue
				}

				ip = ip.To4()
				if ip == nil {
					continue
				}

				ipNet = &net.IPNet{
					IP:   ip,
					Mask: net.CIDRMask(32, 32),
				}
			}

			ones, bits := ipNet.Mask.Size()
			if bits != 32 || ones > 32 {
				continue
			}

			var addr [4]byte
			copy(addr[:], ipNet.IP.Mask(ipNet.Mask).To4())
			cidr := uint8(ones)

			if addr == ([4]byte{}) && cidr == 0 {
				v4 = append(v4,
					netfilterTools.IPv4Subnet{Address: [4]byte{0x00}, CIDR: 1},
					netfilterTools.IPv4Subnet{Address: [4]byte{0x80}, CIDR: 1},
				)
			} else {
				v4 = append(v4, netfilterTools.IPv4Subnet{Address: addr, CIDR: cidr})
			}

		case models.RuleTypeSubnet6:
			ip, ipNet, err := net.ParseCIDR(rule.Rule)
			if err != nil {
				ip = net.ParseIP(rule.Rule)
				if ip == nil {
					continue
				}

				ip = ip.To16()
				if ip == nil {
					continue
				}

				ipNet = &net.IPNet{
					IP:   ip,
					Mask: net.CIDRMask(128, 128),
				}
			}

			ones, bits := ipNet.Mask.Size()
			if bits != 128 || ones > 128 {
				continue
			}

			var addr [16]byte
			copy(addr[:], ipNet.IP.Mask(ipNet.Mask).To16())
			cidr := uint8(ones)

			if addr == ([16]byte{}) && cidr == 0 {
				v6 = append(v6,
					netfilterTools.IPv6Subnet{Address: [16]byte{0x00}, CIDR: 1},
					netfilterTools.IPv6Subnet{Address: [16]byte{0x80}, CIDR: 1},
				)
			} else {
				v6 = append(v6, netfilterTools.IPv6Subnet{Address: addr, CIDR: cidr})
			}
		}
	}

	return v4, v6
}

// updateStaticHostCache пересобирает кэш host-членов (одиночных IP) статических
// subnet-правил из уже распарсенного результата staticSubnetsFromRules.
// Host-члены — только CIDR 32/128 (одиночные IP и /32-/128-правила); широкие
// подсети и dirty-hack /1 в кэш не попадают (DNS-add на IP внутри них — другой
// ipset-member, клоббера нет). Вызывать под g.locker.
func (g *Group) updateStaticHostCache(v4 []netfilterTools.IPv4Subnet, v6 []netfilterTools.IPv6Subnet) {
	hostV4 := make(map[[4]byte]struct{})
	for _, subnet := range v4 {
		if subnet.CIDR == 32 {
			hostV4[subnet.Address] = struct{}{}
		}
	}
	hostV6 := make(map[[16]byte]struct{})
	for _, subnet := range v6 {
		if subnet.CIDR == 128 {
			hostV6[subnet.Address] = struct{}{}
		}
	}
	g.staticHostV4, g.staticHostV6 = hostV4, hostV6
}

// ReassertStaticSubnets повторно добавляет статические subnet-записи как
// permanent (timeout=0, Replace). Противоядие от ipset-refresh правила TPROXY
// (mt-9g7, часть C): SET --add-set --exist --timeout при НОВОМ соединении на
// IP, совпадающий со статической /32-записью, сбрасывает её timeout с 0
// (вечный) на refresh-значение — статическое правило становилось бы
// «испаряемым» и после суток тишины тихо уходило бы direct. Дёшево: записей
// мало, листинга сета нет. Читает g.Rules — вызывать под cfgMu (WithConfigRead).
func (g *Group) ReassertStaticSubnets() error {
	g.locker.Lock()
	defer g.locker.Unlock()

	if !g.Enabled() {
		return nil
	}

	if !g.Group.Enable {
		return nil
	}

	v4, v6 := staticSubnetsFromRules(g.Rules)
	g.updateStaticHostCache(v4, v6)
	var errs []error
	// Зеркало статических подсетей держим в актуальном состоянии здесь же: у
	// route-all групп без подписок sync() почти не вызывается, а зеркало —
	// единственная защита от раздувания сета мусорными /32 (mt-bq8).
	if err := g.ipset.SyncStaticSubnets(v4, v6); err != nil {
		errs = append(errs, fmt.Errorf("failed to sync static-subnet mirror: %w", err))
	}
	for _, subnet := range v4 {
		if err := g.addIPv4Subnet(subnet, nil); err != nil {
			errs = append(errs, fmt.Errorf("failed to reassert %s: %w", subnet.String(), err))
		}
	}
	for _, subnet := range v6 {
		if err := g.addIPv6Subnet(subnet, nil); err != nil {
			errs = append(errs, fmt.Errorf("failed to reassert %s: %w", subnet.String(), err))
		}
	}
	return errors.Join(errs...)
}

func (g *Group) Sync() error {
	g.locker.Lock()
	defer g.locker.Unlock()

	if !g.Enabled() {
		return nil
	}

	if !g.Group.Enable {
		return nil
	}

	return g.sync()
}

func (g *Group) LinkUpHook(event netlink.LinkUpdate) error {
	g.locker.Lock()
	defer g.locker.Unlock()

	if !g.Enabled() {
		return nil
	}

	if !g.Group.Enable {
		return nil
	}

	if g.ipsetToLink == nil {
		return nil
	}

	return g.ipsetToLink.LinkUpHook(event)
}

// AddrChangeHook реагирует на появление/смену IP-адреса на интерфейсе группы:
// пересоздаёт iface-маршрут, если изменился шлюз. Закрывает кейс позднего
// получения адреса (туннель/PPP/DHCP), когда на момент LinkUpHook шлюз ещё не был
// известен. Актуально только для interface-режима (в tproxy ipsetToLink == nil).
func (g *Group) AddrChangeHook(event netlink.AddrUpdate) error {
	g.locker.Lock()
	defer g.locker.Unlock()

	if !g.Enabled() {
		return nil
	}

	if !g.Group.Enable {
		return nil
	}

	if g.ipsetToLink == nil {
		return nil
	}

	return g.ipsetToLink.AddrChangeHook(event)
}
