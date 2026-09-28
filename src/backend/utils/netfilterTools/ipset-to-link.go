package netfilterTools

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"sync/atomic"

	"magitrickle/utils/iptables"

	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

const (
	Blackhole = "blackhole"
	Direct    = "direct"
)

type IPSetToLink struct {
	enabled atomic.Bool
	locker  sync.Mutex

	chainName    string
	ifaceName    string
	startIdx     uint32
	ipset        *IPSet
	nh           *Helper
	mark         uint32
	table        int
	preambleHeld bool
	ip4Rule      *netlink.Rule
	ip6Rule      *netlink.Rule
	ip4Route     [2]*netlink.Route
	ip6Route     [2]*netlink.Route
}

// linkDirectChain цепляет direct-цепочку в PREROUTING указанной таблицы.
// Позиция и есть переключатель приоритета (mt-n4b): в absolute-режиме цепочка
// встаёт первой и перебивает все группы, в by-order — добавляется в конец,
// то есть в порядке поднятия групп, который совпадает с порядком списка в UI
// (routingGroups отдаёт базовые группы в порядке конфига). Правила ВНУТРИ
// цепочки от режима не зависят.
func (r *IPSetToLink) linkDirectChain(ipt *iptables.IPTables, table string) error {
	if r.nh.DirectPriorityIsByOrder() {
		return ipt.Append(table, "PREROUTING", "!", "-i", "lo", "-j", r.chainName)
	}
	return ipt.Insert(table, "PREROUTING", 1, "!", "-i", "lo", "-j", r.chainName)
}

func (r *IPSetToLink) insertIPTablesRules(ipt *iptables.IPTables) error {
	if ipt == nil {
		return nil
	}

	// Зеркала статических подсетей (<set>_s4/_s6) создаются IPSet'ом для всех
	// групп единообразно, но в direct/interface-режимах не используются: правила
	// ipset-refresh (mt-bq8) здесь нет, поэтому на них никто не ссылается —
	// они просто пустые.
	ipsetName := r.ipset.ipsetName
	if ipt.Proto() == iptables.ProtocolIPv4 {
		ipsetName += "_4"
	} else {
		ipsetName += "_6"
	}

	/*
		Direct mode: ACCEPT in both mangle and nat to bypass all MagiTrickle routing.

		Must be ACCEPT, not RETURN. The chain is Insert'ed at PREROUTING position 1
		so it runs before every group chain, but it holds a single match-set->target
		rule. RETURN from a user chain == fall-through: whether the packet matches the
		ipset or not, it returns to PREROUTING and keeps traversing the remaining group
		chains, so an IP that also sits in another group's ipset (overlap) still gets
		TPROXY'd/marked — direct fails to override. ACCEPT terminates traversal of the
		current table, which actually bypasses the remaining chains. It's needed in nat
		too, otherwise TPROXY TCP REDIRECT (nat PREROUTING) still catches the traffic.
		No filter, no ip rule/route needed.
	*/
	if r.ifaceName == Direct {
		err := ipt.RegisterChainOverride("mangle", r.chainName)
		if err != nil {
			return fmt.Errorf("failed to create chain: %w", err)
		}
		if err := r.nh.appendClientBypassGuard(ipt, "mangle", r.chainName); err != nil {
			return fmt.Errorf("failed to append client bypass guard: %w", err)
		}

		err = ipt.Append("mangle", r.chainName, "-m", "set", "--match-set", ipsetName, "dst", "-j", "ACCEPT")
		if err != nil {
			return fmt.Errorf("failed to append ACCEPT rule: %w", err)
		}

		// Позиция зависит от режима приоритета — см. linkDirectChain.
		// Exclude loopback: router-local traffic must not enter MagiTrickle routing.
		err = r.linkDirectChain(ipt, "mangle")
		if err != nil {
			return fmt.Errorf("failed to insert rule to PREROUTING: %w", err)
		}

		// Also ACCEPT in nat PREROUTING to prevent TPROXY TCP REDIRECT.
		err = ipt.RegisterChainOverride("nat", r.chainName)
		if err != nil {
			return fmt.Errorf("failed to create nat chain: %w", err)
		}
		if err := r.nh.appendClientBypassGuard(ipt, "nat", r.chainName); err != nil {
			return fmt.Errorf("failed to append client bypass guard: %w", err)
		}

		err = ipt.Append("nat", r.chainName, "-m", "set", "--match-set", ipsetName, "dst", "-j", "ACCEPT")
		if err != nil {
			return fmt.Errorf("failed to append nat ACCEPT rule: %w", err)
		}

		// Та же позиция, что и в mangle: разъехавшийся порядок дал бы режим,
		// где direct проигрывает по mangle, но выигрывает по nat.
		err = r.linkDirectChain(ipt, "nat")
		if err != nil {
			return fmt.Errorf("failed to insert rule to nat PREROUTING: %w", err)
		}

		err = ipt.Commit()
		if err != nil {
			return fmt.Errorf("failed to commit iptables rules: %w", err)
		}
		return nil
	}

	/*
		Filter Forward
	*/

	err := ipt.RegisterChainOverride("filter", r.chainName)
	if err != nil {
		return fmt.Errorf("failed to create chain: %w", err)
	}
	if err := r.nh.appendClientBypassGuard(ipt, "filter", r.chainName); err != nil {
		return fmt.Errorf("failed to append client bypass guard: %w", err)
	}

	if r.ifaceName != Blackhole {
		err = ipt.Append("filter", r.chainName, "-o", r.ifaceName, "-m", "set", "--match-set", ipsetName, "dst", "-j", "ACCEPT")
		if err != nil {
			return fmt.Errorf("failed to fix protect for IPv4: %w", err)
		}
	}

	err = ipt.Append("filter", "FORWARD", "-j", r.chainName)
	if err != nil {
		return fmt.Errorf("failed to append rule to PREROUTING: %w", err)
	}

	/*
		Mangle Prerouting
	*/

	err = ipt.RegisterChainOverride("mangle", r.chainName)
	if err != nil {
		return fmt.Errorf("failed to create chain: %w", err)
	}
	if err := r.nh.appendClientBypassGuard(ipt, "mangle", r.chainName); err != nil {
		return fmt.Errorf("failed to append client bypass guard: %w", err)
	}

	// MARK routes the packet to this group's table; save-mark persists the
	// decision into conntrack so the shared preamble can restore it on later
	// packets (see acquireInterfacePreamble). The final ACCEPT terminates mangle
	// traversal for matched packets, so the FIRST group whose chain matches wins
	// and later group chains can't overwrite the mark — arbitration consistent
	// with tproxy (where the nat REDIRECT terminates on the first match too).
	for _, iptablesArgs := range [][]string{
		{"-m", "set", "--match-set", ipsetName, "dst", "-j", "MARK", "--set-mark", strconv.Itoa(int(r.mark))},
		{"-m", "set", "--match-set", ipsetName, "dst", "-j", "CONNMARK", "--save-mark"},
		{"-m", "set", "--match-set", ipsetName, "dst", "-j", "ACCEPT"},
	} {
		err = ipt.Append("mangle", r.chainName, iptablesArgs...)
		if err != nil {
			return fmt.Errorf("failed to append rule: %w", err)
		}
	}

	// Exclude loopback: router-local traffic must not enter MagiTrickle routing,
	// otherwise router's own packets to addresses in the ipset (e.g. 127.0.0.1
	// from a poisoned subscription) get marked and routed via the tunnel routing table.
	err = ipt.Append("mangle", "PREROUTING", "!", "-i", "lo", "-j", r.chainName)
	if err != nil {
		return fmt.Errorf("failed to append rule to PREROUTING: %w", err)
	}

	/*
		NAT Postrouting
	*/

	err = ipt.RegisterChainOverride("nat", r.chainName)
	if err != nil {
		return fmt.Errorf("failed to create chain: %w", err)
	}
	if err := r.nh.appendClientBypassGuard(ipt, "nat", r.chainName); err != nil {
		return fmt.Errorf("failed to append client bypass guard: %w", err)
	}

	err = ipt.Append("nat", r.chainName, "-m", "set", "--match-set", ipsetName, "dst", "-j", "MASQUERADE")
	if err != nil {
		return fmt.Errorf("failed to create rule: %w", err)
	}

	err = ipt.Append("nat", "POSTROUTING", "-j", r.chainName)
	if err != nil {
		return fmt.Errorf("failed to append rule to POSTROUTING: %w", err)
	}

	err = ipt.Commit()
	if err != nil {
		return fmt.Errorf("failed to commit iptables rules: %w", err)
	}
	return nil
}

func (r *IPSetToLink) deleteIPTablesRules(ipt *iptables.IPTables) error {
	if ipt == nil {
		return nil
	}
	var errs []error

	// Direct mode: mangle + nat chains.
	if r.ifaceName == Direct {
		err := ipt.RegisterChainDelete("mangle", r.chainName)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to delete mangle chain: %w", err))
		}

		err = ipt.Delete("mangle", "PREROUTING", "!", "-i", "lo", "-j", r.chainName)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to unlink mangle chain: %w", err))
		}

		err = ipt.RegisterChainDelete("nat", r.chainName)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to delete nat chain: %w", err))
		}

		err = ipt.Delete("nat", "PREROUTING", "!", "-i", "lo", "-j", r.chainName)
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to unlink nat chain: %w", err))
		}

		err = ipt.Commit()
		if err != nil {
			errs = append(errs, fmt.Errorf("failed to commit iptables rules: %w", err))
		}
		return errors.Join(errs...)
	}

	/*
		Filter Forward
	*/

	err := ipt.RegisterChainDelete("filter", r.chainName)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to clear chain: %w", err))
	}

	err = ipt.Delete("filter", "FORWARD", "-j", r.chainName)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to unlinking chain: %w", err))
	}

	/*
		Mangle Prerouting
	*/

	err = ipt.RegisterChainDelete("mangle", r.chainName)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to delete chain: %w", err))
	}

	err = ipt.Delete("mangle", "PREROUTING", "!", "-i", "lo", "-j", r.chainName)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to unlinking chain: %w", err))
	}

	/*
		NAT Postrouting
	*/

	err = ipt.RegisterChainDelete("nat", r.chainName)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to delete chain: %w", err))
	}

	err = ipt.Delete("nat", "POSTROUTING", "-j", r.chainName)
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to unlinking chain: %w", err))
	}

	err = ipt.Commit()
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to commit iptables rules: %w", err))
	}
	return errors.Join(errs...)
}

func (r *IPSetToLink) insertIPRule() error {
	if r.nh.IPTables4 != nil {
		rule := netlink.NewRule()
		rule.Mark = r.mark
		rule.Table = r.table
		rule.Family = nl.FAMILY_V4
		_ = netlink.RuleDel(rule)
		err := netlink.RuleAdd(rule)
		if err != nil {
			return fmt.Errorf("error while mapping marked packages to table: %w", err)
		}
		r.ip4Rule = rule
	}

	if r.nh.IPTables6 != nil {
		rule := netlink.NewRule()
		rule.Mark = r.mark
		rule.Table = r.table
		rule.Family = nl.FAMILY_V6
		_ = netlink.RuleDel(rule)
		err := netlink.RuleAdd(rule)
		if err != nil {
			return fmt.Errorf("error while mapping marked packages to table: %w", err)
		}
		r.ip6Rule = rule
	}

	return nil
}

func (r *IPSetToLink) deleteIPRule() error {
	var errs []error

	if r.ip4Rule != nil {
		err := netlink.RuleDel(r.ip4Rule)
		if err != nil && !errors.Is(err, unix.ENOENT) {
			errs = append(errs, fmt.Errorf("error while deleting rule: %w", err))
		}
		r.ip4Rule = nil
	}

	if r.ip6Rule != nil {
		err := netlink.RuleDel(r.ip6Rule)
		if err != nil && !errors.Is(err, unix.ENOENT) {
			errs = append(errs, fmt.Errorf("error while deleting rule: %w", err))
		}
		r.ip6Rule = nil
	}

	return errors.Join(errs...)
}

func (r *IPSetToLink) insertIPRoute() error {
	if r.nh.IPTables4 != nil {
		route := &netlink.Route{
			Priority: 20,
			Dst:      &net.IPNet{IP: []byte{0, 0, 0, 0}, Mask: []byte{0, 0, 0, 0}},
			Table:    r.table,
			Type:     unix.RTN_BLACKHOLE,
			Family:   nl.FAMILY_V4,
		}
		if err := netlink.RouteAdd(route); err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("error while adding ipv4 blackhole route: %w", err)
		}
		r.ip4Route[0] = route
	}

	if r.nh.IPTables6 != nil {
		route := &netlink.Route{
			Priority: 20,
			Dst:      &net.IPNet{IP: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, Mask: []byte{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
			Table:    r.table,
			Type:     unix.RTN_BLACKHOLE,
			Family:   nl.FAMILY_V6,
		}
		if err := netlink.RouteAdd(route); err != nil && !errors.Is(err, unix.EEXIST) {
			return fmt.Errorf("error while adding ipv6 blackhole route: %w", err)
		}
		r.ip6Route[0] = route
	}

	if r.ifaceName == Blackhole {
		return nil
	}

	iface, err := netlink.LinkByName(r.ifaceName)
	if err != nil {
		if errors.As(err, &netlink.LinkNotFoundError{}) {
			log.Warn().Str("iface", r.ifaceName).Msg("interface not found, it can be catched later")
			return nil
		}
		return fmt.Errorf("error while getting interface: %w", err)
	}
	if iface.Attrs().Flags&net.FlagUp == 0 {
		log.Warn().Str("iface", r.ifaceName).Msg("interface is down")
		return nil
	}

	var errs []error
	if r.nh.IPTables4 != nil {
		r.ip4Route[1], err = r.updateIfaceRoute(iface, nl.FAMILY_V4, r.ip4Route[1])
		errs = append(errs, err)
	}
	if r.nh.IPTables6 != nil {
		r.ip6Route[1], err = r.updateIfaceRoute(iface, nl.FAMILY_V6, r.ip6Route[1])
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

// updateIfaceRoute идемпотентно поддерживает default-маршрут группы через iface
// для одного семейства. Если на интерфейсе нет адресов нужного семейства —
// маршрут не создаётся (dual-stack без IPv6 и т.п.). Если шлюз не изменился —
// текущий маршрут переиспользуется; при смене шлюза старый удаляется и ставится
// новый. current — ранее установленный маршрут (или nil).
func (r *IPSetToLink) updateIfaceRoute(iface netlink.Link, family int, current *netlink.Route) (*netlink.Route, error) {
	addrs, err := netlink.AddrList(iface, family)
	if err != nil {
		strFamily := "unknown"
		switch family {
		case nl.FAMILY_ALL:
			strFamily = "all"
		case nl.FAMILY_V4:
			strFamily = "IPv4"
		case nl.FAMILY_V6:
			strFamily = "IPv6"
		case nl.FAMILY_MPLS:
			strFamily = "MPLS"
		}
		return current, fmt.Errorf("error while listing %s addresses: %w", strFamily, err)
	}
	if len(addrs) == 0 {
		log.Warn().Str("iface", r.ifaceName).Int("family", family).Msg("no addresses on interface for current IP family, skipping route")
		return current, nil
	}

	ipLen := net.IPv4len
	if family == nl.FAMILY_V6 {
		ipLen = net.IPv6len
	}

	route := &netlink.Route{
		Priority:  10,
		LinkIndex: iface.Attrs().Index,
		Table:     r.table,
		Family:    family,
		Dst:       &net.IPNet{IP: make(net.IP, ipLen), Mask: make(net.IPMask, ipLen)},
	}

	if iface.Attrs().Flags&net.FlagPointToPoint == 0 {
		if gateway, err := getGwFromIface(iface, family); err != nil {
			log.Warn().Str("iface", r.ifaceName).Err(err).Int("family", family).Msg("gateway not found")
		} else {
			route.Gw = gateway
		}
	}

	if current != nil {
		if route.Gw != nil && route.Gw.Equal(current.Gw) {
			return current, nil
		}
		if route.Gw != nil {
			if err := netlink.RouteDel(current); err != nil && !errors.Is(err, unix.ESRCH) && !errors.Is(err, unix.ENOENT) {
				return current, fmt.Errorf("error deleting iface route: %w", err)
			}
		}
	}

	if err := netlink.RouteAdd(route); err != nil && !errors.Is(err, unix.EEXIST) {
		return nil, fmt.Errorf("error adding iface route: %w", err)
	}
	return route, nil
}

// getGwFromIface ищет шлюз, прописанный на интерфейсе для указанного семейства.
// Нужен для broadcast-интерфейсов (eth/wifi): без явного Gw маршрут default
// через них не работает на части конфигураций. Для PointToPoint-iface (туннель)
// шлюз не нужен и вызывать не надо.
func getGwFromIface(iface netlink.Link, family int) (net.IP, error) {
	routes, err := netlink.RouteListFiltered(family, &netlink.Route{
		LinkIndex: iface.Attrs().Index,
	}, netlink.RT_FILTER_OIF)
	if err != nil {
		return nil, err
	}
	for _, route := range routes {
		if route.Gw != nil {
			return route.Gw, nil
		}
	}
	return nil, fmt.Errorf("no gateway found for interface %s", iface.Attrs().Name)
}

func (r *IPSetToLink) deleteIPRoute() error {
	errs := make([]error, 0)
	// Missing routes report ESRCH; IPv6 default routes with metric 0 can report ENOENT.

	for i := 1; i >= 0; i-- {
		if r.ip4Route[i] == nil {
			continue
		}
		err := netlink.RouteDel(r.ip4Route[i])
		if err != nil && !errors.Is(err, unix.ESRCH) && !errors.Is(err, unix.ENOENT) {
			errs = append(errs, fmt.Errorf("error while deleting route: %w", err))
		}
		r.ip4Route[i] = nil
	}

	for i := 1; i >= 0; i-- {
		if r.ip6Route[i] == nil {
			continue
		}
		err := netlink.RouteDel(r.ip6Route[i])
		if err != nil && !errors.Is(err, unix.ESRCH) && !errors.Is(err, unix.ENOENT) {
			errs = append(errs, fmt.Errorf("error while deleting route: %w", err))
		}
		r.ip6Route[i] = nil
	}

	return errors.Join(errs...)
}

func (r *IPSetToLink) getUnusedMarkAndTable() (idx uint32, err error) {
	// Find unused mark and table
	markMap := make(map[uint32]struct{})
	tableMap := map[int]struct{}{0: {}, 253: {}, 254: {}, 255: {}}

	rules, err := netlink.RuleList(nl.FAMILY_ALL)
	if err != nil {
		return 0, fmt.Errorf("error while getting rules: %w", err)
	}
	for _, rule := range rules {
		markMap[rule.Mark] = struct{}{}
		tableMap[rule.Table] = struct{}{}
	}

	routes, err := netlink.RouteListFiltered(nl.FAMILY_ALL, &netlink.Route{}, netlink.RT_FILTER_TABLE)
	if err != nil {
		return 0, fmt.Errorf("error while getting routes: %w", err)
	}
	for _, route := range routes {
		tableMap[route.Table] = struct{}{}
	}

	for idx = r.startIdx; idx < 0x7ffffffe; idx++ {
		_, tableExists := tableMap[int(idx)]
		_, markExists := markMap[idx]
		if !tableExists && !markExists {
			break
		}
	}

	return idx, nil
}

func (r *IPSetToLink) enable() error {
	if !r.enabled.CompareAndSwap(false, true) {
		return nil
	}

	// Direct mode needs only iptables RETURN rules — no mark, table, ip rule, or route.
	if r.ifaceName == Direct {
		err := r.insertIPTablesRules(r.nh.IPTables4)
		if err != nil {
			return err
		}
		err = r.insertIPTablesRules(r.nh.IPTables6)
		if err != nil {
			return err
		}
		return nil
	}

	// Install (ref-counted) the shared preamble before wiring this group's
	// chain. preambleHeld gates the paired release in disable() so a failed
	// acquire is never released and a direct-mode teardown never touches it.
	if err := r.nh.acquireInterfacePreamble(); err != nil {
		return fmt.Errorf("failed to install routing preamble: %w", err)
	}
	r.preambleHeld = true

	var err error
	idx, err := r.getUnusedMarkAndTable()
	if err != nil {
		return err
	}
	r.mark, r.table = idx, int(idx)

	err = r.insertIPRule()
	if err != nil {
		return err
	}

	err = r.insertIPRoute()
	if err != nil {
		return err
	}

	err = r.insertIPTablesRules(r.nh.IPTables4)
	if err != nil {
		return err
	}

	err = r.insertIPTablesRules(r.nh.IPTables6)
	if err != nil {
		return err
	}

	return nil
}

func (r *IPSetToLink) Enable() error {
	r.locker.Lock()
	defer r.locker.Unlock()

	err := r.enable()
	if err != nil {
		r.disable()
	} else {
		log.Debug().
			Int("table", r.table).
			Int("mark", int(r.mark)).
			Msg("using ip table and mark")
	}

	return err
}

func (r *IPSetToLink) disable() error {
	if !r.enabled.Load() {
		return nil
	}
	defer r.enabled.Store(false)

	var errs []error
	errs = append(errs, r.deleteIPRoute())
	errs = append(errs, r.deleteIPRule())
	errs = append(errs, r.deleteIPTablesRules(r.nh.IPTables4))
	errs = append(errs, r.deleteIPTablesRules(r.nh.IPTables6))
	if r.preambleHeld {
		errs = append(errs, r.nh.releaseInterfacePreamble())
		r.preambleHeld = false
	}
	return errors.Join(errs...)
}

func (r *IPSetToLink) Disable() error {
	r.locker.Lock()
	defer r.locker.Unlock()

	return r.disable()
}

func (r *IPSetToLink) ClearIfDisabled() error {
	r.locker.Lock()
	defer r.locker.Unlock()

	if r.enabled.Load() {
		return nil
	}

	var errs []error
	errs = append(errs, r.deleteIPRoute())
	errs = append(errs, r.deleteIPRule())
	errs = append(errs, r.deleteIPTablesRules(r.nh.IPTables4))
	errs = append(errs, r.deleteIPTablesRules(r.nh.IPTables6))
	return errors.Join(errs...)
}

func (r *IPSetToLink) LinkUpHook(event netlink.LinkUpdate) error {
	r.locker.Lock()
	defer r.locker.Unlock()

	if !r.enabled.Load() || event.Link.Attrs().Name != r.ifaceName {
		return nil
	}

	var errs []error
	errs = append(errs, r.insertIPRoute())
	return errors.Join(errs...)
}

// AddrChangeHook пересоздаёт iface-маршрут при изменении адреса/шлюза на
// интерфейсе группы. В отличие от insertIPRoute не трогает blackhole-маршруты
// и обновляет только маршрут через интерфейс (ip4Route[1]/ip6Route[1]).
func (r *IPSetToLink) AddrChangeHook(event netlink.AddrUpdate) error {
	r.locker.Lock()
	defer r.locker.Unlock()

	if !r.enabled.Load() || r.ifaceName == Blackhole || r.ifaceName == Direct {
		return nil
	}

	iface, err := netlink.LinkByName(r.ifaceName)
	if err != nil {
		return fmt.Errorf("error while getting interface: %w", err)
	}
	if iface.Attrs().Index != event.LinkIndex {
		return nil
	}

	var errs []error
	if r.nh.IPTables4 != nil {
		r.ip4Route[1], err = r.updateIfaceRoute(iface, nl.FAMILY_V4, r.ip4Route[1])
		errs = append(errs, err)
	}
	if r.nh.IPTables6 != nil {
		r.ip6Route[1], err = r.updateIfaceRoute(iface, nl.FAMILY_V6, r.ip6Route[1])
		errs = append(errs, err)
	}
	return errors.Join(errs...)
}

func (nh *Helper) IPSetToLink(name string, ifaceName string, ipset *IPSet) *IPSetToLink {
	return &IPSetToLink{
		nh:        nh,
		chainName: nh.ChainPrefix + name,
		ifaceName: ifaceName,
		ipset:     ipset,
		startIdx:  nh.StartIdx,
	}
}
