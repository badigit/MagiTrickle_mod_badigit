package magitrickle

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"magitrickle/app"
	"magitrickle/constant"
	"magitrickle/models"
	"magitrickle/utils/dnsMITMProxy"
	"magitrickle/utils/netfilterTools"
	"magitrickle/utils/recordsCache"
	"magitrickle/utils/trie"

	"github.com/IGLOU-EU/go-wildcard/v2"
	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

var (
	ErrAlreadyRunning           = errors.New("already running")
	ErrGroupIDConflict          = errors.New("group id conflict")
	ErrRuleIDConflict           = errors.New("rule id conflict")
	ErrSubscriptionIDConflict   = errors.New("subscription id conflict")
	ErrConfigUnsupportedVersion = errors.New("config unsupported version")
)

// WildcardRule holds a compiled wildcard pattern and its group.
type WildcardRule struct {
	Rule  string
	Group *Group
}

// App – основная структура ядра приложения
type App struct {
	enabled       atomic.Bool // Start вызван
	routingActive atomic.Bool // routing+DNSOR подняты (false когда пользователь нажал паузу)
	startedAt     time.Time

	config models.AppConfig

	dnsMITM            *dnsMITMProxy.DNSMITMProxy
	nfHelper           *netfilterTools.Helper
	recordsCache       *recordsCache.Records
	groups             atomic.Pointer[[]*Group]
	subscriptionGroups atomic.Pointer[[]*Group]
	subscriptions      atomic.Pointer[[]*models.Subscription]
	dnsOverrider       *netfilterTools.PortRemap

	interfaceAliases map[string]string

	dnsCapture *DNSCapture

	domainTrie atomic.Value // holds *trie.Trie

	wildcardRules       []*WildcardRule
	wildcardRulesLocker sync.RWMutex

	// cfgMu сериализует все мутации конфига (группы/правила/подписки) и
	// защищает lock-free чтения датапаса. См. app_config_lock.go.
	cfgMu sync.RWMutex

	clientRoutingMu sync.Mutex

	// routingMutationMu сериализует операции, меняющие ТОПОЛОГИЮ цепочек в
	// ядре: подъём и снятие роутинга, перестройку групп подписок, включение и
	// выключение отдельных групп. Без него переключение directPriority
	// (teardown+bring-up всех групп) и перестройка подписок, идущая по своему
	// таймеру, перемешиваются: часть цепочек создаётся в старом режиме, часть
	// в новом, а группа подписки может подняться посреди общего teardown и
	// остаться с правилами при снятом роутинге. Гонки данных здесь нет —
	// race-детектор такое не покажет, ловится только явной сериализацией.
	//
	// Отдельный от lifecycleMu намеренно: lifecycleMu уже удерживается в Start,
	// который вызывает перестройку подписок, а сама перестройка вызывается и
	// из-под cfgMu (автообновление). Этот мьютекс с обоими совместим при одном
	// правиле — ПОД НИМ НЕЛЬЗЯ БРАТЬ cfgMu, иначе появится обратный порядок к
	// «cfgMu -> routingMutationMu» из автообновления и вернётся дедлок.
	routingMutationMu sync.Mutex

	// lifecycleMu сериализует переходы жизненного цикла роутинга: поднятие,
	// снятие и смену режима коммиттера. SetEnabled вызывается прямо из
	// HTTP-обработчика, поэтому двойной клик в UI без этого лока гоняется за
	// config.Enabled и routingActive. Берётся ВЫШЕ cfgMu и commitMu.
	lifecycleMu sync.Mutex

	// committer — асинхронный писатель правил по событиям netfilter.d.
	committer *netfilterCommitter

	// bringUpFn/bringDownFn — точки подмены подъёма и снятия роутинга. В бою
	// nil, и вызываются настоящие методы; тестам они дают проверить поведение
	// вокруг них (откат при сбое, повтор после рассогласования), не поднимая
	// netfilter, которого в тестовой среде нет.
	bringUpFn   func() error
	bringDownFn func() error
	// saveConfigFn — та же точка подмены для сохранения: тестам транзакционного
	// переключения нужен результат «сохранилось/нет», а не сериализация YAML в
	// файл, которой в тестовой среде некуда лечь.
	saveConfigFn func() error

	// shuttingDown взводится teardown'ом в Start и запрещает поднимать роутинг
	// заново: после teardown снимать его уже некому. Читается и пишется только
	// под lifecycleMu — тем же локом, что держит SetEnabled, поэтому гейт
	// закрывает и уже принятый в обработку HTTP-запрос, которому закрытие
	// листенеров не мешает (mt-kd1).
	shuttingDown bool
}

// New создаёт новый экземпляр App
func New() *App {
	a := &App{
		startedAt:        time.Now(),
		config:           constant.DefaultAppConfig,
		interfaceAliases: make(map[string]string),
		dnsCapture:       NewDNSCapture(),
	}
	emptyGroups := make([]*Group, 0)
	a.groups.Store(&emptyGroups)
	emptySubscriptionGroups := make([]*Group, 0)
	a.subscriptionGroups.Store(&emptySubscriptionGroups)
	emptySubscriptions := make([]*models.Subscription, 0)
	a.subscriptions.Store(&emptySubscriptions)
	if err := a.LoadConfig(); err != nil {
		log.Error().Err(err).Msg("failed to load config file")
	}
	if err := a.LoadInterfaceConfig(); err != nil {
		log.Error().Err(err).Msg("failed to load interface aliases")
	}
	a.domainTrie.Store(trie.New())
	return a
}

// Trie returns the current domain trie.
func (a *App) Trie() *trie.Trie {
	return a.domainTrie.Load().(*trie.Trie)
}

// RebuildTrie rebuilds the domain trie and wildcard/regex rule lists
// from all enabled routing groups. Call after any group/rule change.
func (a *App) RebuildTrie() {
	newTrie := trie.New()
	var newWildcards []*WildcardRule

	for _, g := range a.routingGroups() {
		if !g.Enabled() || !g.Group.Enable {
			continue
		}
		for _, rule := range g.Rules {
			if !rule.IsEnabled() {
				continue
			}
			switch rule.Type {
			case models.RuleTypeDomain:
				newTrie.Insert(rule.Rule, g, true)
			case models.RuleTypeWildcard:
				if strings.Contains(rule.Rule, "*") || strings.Contains(rule.Rule, "?") {
					newWildcards = append(newWildcards, &WildcardRule{
						Rule:  rule.Rule,
						Group: g,
					})
				} else {
					// wildcard without glob chars is effectively a namespace
					cleanDomain := strings.TrimPrefix(rule.Rule, "*.")
					newTrie.Insert(cleanDomain, g, false)
				}
			case models.RuleTypeNamespace:
				newTrie.Insert(rule.Rule, g, false)
			case models.RuleTypeRegEx:
				// regex rules stay as fallback — compiled lazily in rule.IsMatch
				// we don't add them to trie; they are checked in searchFallback
			}
		}
	}
	a.domainTrie.Store(newTrie)

	a.wildcardRulesLocker.Lock()
	a.wildcardRules = newWildcards
	a.wildcardRulesLocker.Unlock()

	log.Debug().
		Int("wildcards", len(newWildcards)).
		Msg("trie rebuilt")
}

// searchDomain looks up a domain in the trie, then falls back to wildcard and regex rules.
// Тонкая обёртка над searchDomainExplain: одна реализация на решение и на его
// объяснение — иначе winner в /api/v1/lookup начнёт расходиться с фактическим
// роутингом (mt-ztg).
func (a *App) searchDomain(domain string) (*Group, bool) {
	g, _, found := a.searchDomainExplain(domain)
	return g, found
}

// searchDomainExplain — тот же арбитраж, что и searchDomain, плюс слой, которым
// домен выигран: models.LookupWhy{Exact,Namespace,Wildcard,Regex}. Порядок слоёв
// и групп замораживает продуктовую политику mt-7rd (Вариант 1).
// Держит cfgMu.RLock: step 3 (regex-fallback) читает g.Rules/rule.Rule, которые
// API-писатели мутируют in-place под cfgMu.Lock. НЕ вызывать под уже взятым cfgMu.
func (a *App) searchDomainExplain(domain string) (*Group, string, bool) {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()

	// 1. Trie lookup — O(domain parts)
	if data, kind, found := a.Trie().SearchExplain(domain); found {
		if g, ok := data.(*Group); ok && g.Enabled() && g.Group.Enable {
			why := models.LookupWhyNamespace
			if kind == trie.KindExact {
				why = models.LookupWhyExact
			}
			return g, why, true
		}
	}

	// 2. Wildcard fallback
	a.wildcardRulesLocker.RLock()
	wRules := a.wildcardRules
	a.wildcardRulesLocker.RUnlock()
	for _, wr := range wRules {
		if wildcard.Match(wr.Rule, domain) {
			if wr.Group.Enabled() && wr.Group.Group.Enable {
				return wr.Group, models.LookupWhyWildcard, true
			}
		}
	}

	// 3. Regex fallback — iterate all groups, check only regex rules
	for _, g := range a.routingGroups() {
		if !g.Enabled() || !g.Group.Enable {
			continue
		}
		for _, rule := range g.Rules {
			if !rule.IsEnabled() || rule.Type != models.RuleTypeRegEx {
				continue
			}
			if rule.IsMatch(domain) {
				return g, models.LookupWhyRegex, true
			}
		}
	}

	return nil, "", false
}

// SearchDomainVerdict — экспортируемый арбитраж для API: та же функция, что
// решает роутинг, чтобы /api/v1/lookup объяснял исход, а не пересчитывал его по
// своим источникам (у lookup они шире: модели подписок вместо их рантайм-групп).
func (a *App) SearchDomainVerdict(domain string) (app.Group, string, bool) {
	g, why, found := a.searchDomainExplain(domain)
	if !found {
		return nil, "", false
	}
	return g, why, true
}

// Config возвращает конфигурацию
func (a *App) Config() models.AppConfig {
	return a.config
}

// Groups возвращает список групп
func (a *App) Groups() []app.Group {
	gs := *a.groups.Load()
	groups := make([]app.Group, len(gs))
	for i, g := range gs {
		groups[i] = g
	}
	return groups
}

// ClearGroups отключает все группы и очищает список
func (a *App) ClearGroups() {
	for _, g := range *a.groups.Load() {
		_ = g.Disable()
	}
	emptyGroups := make([]*Group, 0)
	a.groups.Store(&emptyGroups)
}

// SyncAllGroups пересинхронизирует ipset'ы всех активных групп и перестраивает trie.
// Вызывается после изменения конфига групп, чтобы удалить stale IP
// из ipset'ов групп, из которых правила были убраны.
func (a *App) SyncAllGroups() {
	a.RebuildTrie()
	for _, group := range a.routingGroups() {
		if group.Enabled() {
			_ = group.Sync()
		}
	}
}

// AddGroup добавляет новую группу
func (a *App) AddGroup(groupModel *models.Group) error {
	groups := *a.groups.Load()
	for _, group := range groups {
		if groupModel.ID == group.ID {
			return ErrGroupIDConflict
		}
	}
	// Проверка уникальности rule.ID внутри группы.
	dup := make(map[[4]byte]struct{})
	for _, rule := range groupModel.Rules {
		if _, exists := dup[rule.ID]; exists {
			return ErrRuleIDConflict
		}
		dup[rule.ID] = struct{}{}
	}

	grp, err := NewGroup(groupModel, a)
	if err != nil {
		return fmt.Errorf("failed to create group: %w", err)
	}
	newGroups := make([]*Group, len(groups)+1)
	copy(newGroups, groups)
	newGroups[len(groups)] = grp
	a.groups.Store(&newGroups)

	log.Info().
		Str("id", grp.ID.String()).
		Str("name", grp.Name).
		Msg("added group")

	// если routing активен – включаем группу и синхронизируем ipset
	if a.routingActive.Load() {
		// Включение группы вставляет её цепочки в PREROUTING — та же топология,
		// что трогают teardown/bring-up, поэтому идём в общую очередь.
		if err = a.WithRoutingMutation(func() error {
			if err := grp.Enable(); err != nil {
				return fmt.Errorf("failed to enable group: %w", err)
			}
			return grp.Sync()
		}); err != nil {
			return err
		}
	}
	return nil
}

// RemoveGroupByIndex удаляет группу по индексу
func (a *App) RemoveGroupByIndex(idx int) {
	groups := *a.groups.Load()
	newGroups := make([]*Group, 0, len(groups)-1)
	newGroups = append(newGroups, groups[:idx]...)
	newGroups = append(newGroups, groups[idx+1:]...)
	a.groups.Store(&newGroups)
}

// ListInterfaces возвращает список сетевых интерфейсов, удовлетворяющих заданным критериям
func (a *App) ListInterfaces() ([]net.Interface, error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("failed to get interfaces: %w", err)
	}

	if a.config.ShowAllInterfaces {
		return interfaces, nil
	}

	var filteredInterfaces []net.Interface
	for _, iface := range interfaces {
		if iface.Flags&net.FlagPointToPoint == 0 || slices.Contains(constant.IgnoredInterfaces, iface.Name) {
			continue
		}
		filteredInterfaces = append(filteredInterfaces, iface)
	}
	return filteredInterfaces, nil
}

// OutgoingLinkIndexes returns the set of interface indexes that carry the
// router's own egress — i.e. have a default route pointing out through them in
// any routing table. That is precisely the precondition for the external-IP
// probe (BindToDevice + HTTP GET) to succeed.
//
// It exists to tell incoming/server tunnels apart from outgoing ones: an SSTP
// server endpoint like sstp0 (the router IS the server, clients dial in) has no
// default route via it and is excluded, so the UI must not auto-run a doomed
// external-IP test against it (mt-8fi). Outgoing tunnels (WAN, WG clients) and
// interface-mode group links do have a default route via them and are included.
func (a *App) OutgoingLinkIndexes() map[int]bool {
	out := make(map[int]bool)
	// Table 0 as the filter means "all tables": interface-mode groups install
	// their default route in a per-group table, so scanning only main misses them.
	routes, err := netlink.RouteListFiltered(nl.FAMILY_ALL, &netlink.Route{}, netlink.RT_FILTER_TABLE)
	if err != nil {
		log.Warn().Err(err).Msg("failed to list routes for outgoing-interface detection")
		return out
	}
	mark := func(linkIndex int) {
		if linkIndex > 0 {
			out[linkIndex] = true
		}
	}
	for _, route := range routes {
		// Only a default route (zero-length destination) grants general egress.
		if route.Dst != nil {
			if ones, _ := route.Dst.Mask.Size(); ones != 0 {
				continue
			}
		}
		// Skip non-unicast defaults (blackhole/unreachable/prohibit) — e.g. the
		// blackhole default that interface-mode installs as a leak guard.
		if route.Type != unix.RTN_UNICAST {
			continue
		}
		mark(route.LinkIndex)
		for _, nh := range route.MultiPath {
			mark(nh.LinkIndex)
		}
	}
	return out
}

// DnsOverrider возвращает dnsOverrider
func (a *App) DnsOverrider() *netfilterTools.PortRemap {
	return a.dnsOverrider
}

// InterfaceAliases returns a copy of configured interface aliases.
func (a *App) InterfaceAliases() map[string]string {
	aliases := make(map[string]string, len(a.interfaceAliases))
	for k, v := range a.interfaceAliases {
		aliases[k] = v
	}
	return aliases
}

// DNSCapture возвращает экземпляр DNSCapture.
func (a *App) DNSCapture() app.DNSCapturer {
	return a.dnsCapture
}

// SetInterfaceAliases replaces configured interface aliases.
func (a *App) SetInterfaceAliases(aliases map[string]string) {
	a.interfaceAliases = make(map[string]string, len(aliases))
	for k, v := range aliases {
		a.interfaceAliases[k] = v
	}
}

// StartedAt returns the moment when this process was created.
func (a *App) StartedAt() time.Time {
	return a.startedAt
}

// IsRoutingActive reports whether MagiTrickle is currently capturing/routing
// traffic (DnsOverrider + groups enabled).
func (a *App) IsRoutingActive() bool {
	return a.routingActive.Load()
}

func (a *App) ClientRouting() models.AppConfigClientRouting {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	return models.AppConfigClientRouting{
		Mode:           a.config.ClientRouting.Mode,
		SourceNetworks: slices.Clone(a.config.ClientRouting.SourceNetworks),
	}
}

// SetClientRouting atomically replaces the kernel sets, then persists the
// canonical configuration. New connections observe the new selection without
// rebuilding iptables; existing conntrack/NAT sessions are intentionally not
// rewritten.
func (a *App) SetClientRouting(cfg models.AppConfigClientRouting) error {
	a.clientRoutingMu.Lock()
	defer a.clientRoutingMu.Unlock()

	if cfg.Mode != models.ClientRoutingModeExclude {
		return fmt.Errorf("unsupported client routing mode %q", cfg.Mode)
	}

	a.cfgMu.Lock()
	old := models.AppConfigClientRouting{
		Mode:           a.config.ClientRouting.Mode,
		SourceNetworks: slices.Clone(a.config.ClientRouting.SourceNetworks),
	}
	normalized, _, err := netfilterTools.NormalizeSourceNetworks(cfg.SourceNetworks)
	if err == nil && a.nfHelper != nil {
		normalized, err = a.nfHelper.UpdateClientBypass(normalized)
	}
	if err != nil {
		a.cfgMu.Unlock()
		return err
	}
	a.config.ClientRouting = models.AppConfigClientRouting{Mode: cfg.Mode, SourceNetworks: normalized}
	a.cfgMu.Unlock()

	if err := a.SaveConfig(); err != nil {
		a.cfgMu.Lock()
		rollbackErr := error(nil)
		if a.nfHelper != nil {
			_, rollbackErr = a.nfHelper.UpdateClientBypass(old.SourceNetworks)
		}
		a.config.ClientRouting = old
		a.cfgMu.Unlock()
		return errors.Join(err, rollbackErr)
	}
	return nil
}

// bringUpRouting enables DNS port-remap and all routing groups, syncs IPSet
// from the in-memory DNS cache. Idempotent: safe to call when already up.
func (a *App) bringUpRouting() error {
	if !a.routingActive.CompareAndSwap(false, true) {
		return nil
	}

	if a.dnsOverrider != nil {
		if err := a.dnsOverrider.Enable(); err != nil {
			return errors.Join(fmt.Errorf("failed to override DNS: %w", err), a.rollbackFailedBringUp())
		}
	}

	// Подъём групп идёт под одним коммитом на семейство: без этого каждая
	// группа делает свою пару iptables-save/restore — замер на проде показывал
	// 152 обращения к ядру и 14с до готовности роутинга; с батчем 6 и 7с
	// (mt-of9).
	//
	// Sync вынесен ЗА батч намеренно: он наполняет ipset через netlink и читает
	// текущее состояние сетов, поэтому ему нужны уже применённые правила.
	//
	// Историческая справка: первая попытка батчить bring-up (mt-jou) оставила
	// прод без единого правила MT_. Причиной был не сам батч, а сломанный тогда
	// teardown: сеты не уничтожались ("destroy: busy"), из-за чего ipset.Enable
	// падал, Group.Enable возвращал ошибку и rollbackFailedBringUp снимал уже
	// поднятое. После двухфазного teardown из mt-jou батч здесь безопасен, что
	// подтверждено на живом роутере.
	var enableErr error
	batchErr := a.nfHelper.Batch(func() error {
		for _, group := range a.routingGroups() {
			if err := group.Enable(); err != nil {
				enableErr = fmt.Errorf("failed to enable group %s: %w", group.Name, err)
				return enableErr
			}
		}
		return nil
	})
	if enableErr != nil {
		return errors.Join(enableErr, a.rollbackFailedBringUp())
	}
	if batchErr != nil {
		return errors.Join(batchErr, a.rollbackFailedBringUp())
	}
	for _, group := range a.routingGroups() {
		if err := group.Sync(); err != nil {
			log.Warn().Err(err).Str("group", group.Name).Msg("group sync after enable returned error")
		}
	}
	a.RebuildTrie()
	log.Info().Msg("routing brought up")
	return nil
}

// rollbackFailedBringUp снимает то, что успело подняться до ошибки, и
// возвращает ошибку неполного отката.
//
// Без отката уже включённые группы остались бы с живыми цепочками при
// routingActive=false: следующая перезапись таблиц прошивкой снесла бы их, а
// коммиттер, находясь к тому моменту на паузе, событие отбросил бы — правила
// исчезли бы молча, хотя группы считают себя включёнными.
//
// Неполный откат НЕЛЬЗЯ выдавать за успех. Group.disable и PortRemap.disable
// сбрасывают свой флаг enabled через defer даже когда снятие не удалось,
// поэтому после ошибки объекты считают себя выключенными, а цепочки в ядре
// могут остаться. Единственный честный ответ вызывающему — вернуть ошибку:
// на старте она остановит запуск (состояние подчистит CleanIPTables при
// следующем), в SetEnabled — дойдёт до пользователя, а не притворится паузой.
func (a *App) rollbackFailedBringUp() error {
	err := a.tearDownRouting()
	a.routingActive.Store(false)
	if err != nil {
		log.Error().Err(err).Msg("rollback after failed routing bring-up was incomplete")
	}
	return err
}

// bringDownRouting tears down dnsOverrider and disables all routing groups.
// Idempotent: no-op when already down.
func (a *App) bringDownRouting() error {
	if !a.routingActive.CompareAndSwap(true, false) {
		return nil
	}
	err := a.tearDownRouting()
	if err != nil {
		log.Warn().Err(err).Msg("routing brought down incompletely: some iptables chains may still be active")
	} else {
		log.Info().Msg("routing brought down")
	}
	return err
}

// tearDownRouting снимает роутинг БЕЗ гейта routingActive и возвращает всё,
// что не удалось снять.
//
// Вынесено из bringDownRouting, чтобы неуспешный bringUpRouting мог
// откатиться: там гейт уже занят текущим поднятием, и bringDownRouting
// оказался бы no-op.
func (a *App) tearDownRouting() error {
	var errs []error

	// Снятие всех групп идёт под одним коммитом: иначе каждая группа делает
	// собственную пару iptables-save/restore и время растёт линейно по их
	// числу (замер на проде: 76 обращений к ядру, ~6с на 38 группах). init.d
	// ждёт остановки ~11с и затем шлёт SIGKILL, обрывая teardown на полпути и
	// оставляя правила с сетами в системе; на медленных роутерах (mipsel)
	// запаса нет вовсе (mt-jou).
	//
	// Батчится ТОЛЬКО teardown — однородная последовательность удалений.
	// Bring-up под батчем на проде дал регрессию (после старта ни одного
	// правила MT_ в mangle/nat, трафик мимо прокси) и откачен; причина не
	// установлена, воспроизвести на fake-iptables не удалось, поэтому
	// смешанные delete+create последовательности батчем не покрываем.
	groups := a.routingGroups()

	// Фаза 1: снять netfilter-правила всех групп под одним коммитом.
	batchErr := a.nfHelper.Batch(func() error {
		for _, group := range groups {
			if err := group.DisableRules(); err != nil {
				log.Warn().Err(err).Str("group", group.Name).Msg("group rules teardown failed")
				errs = append(errs, fmt.Errorf("group %s: %w", group.Name, err))
			}
		}
		return nil
	})
	if batchErr != nil {
		errs = append(errs, batchErr)
	}

	// Фаза 2: правила сняты в ядре — теперь ipset никем не удерживается и его
	// можно уничтожить. Обратный порядок даёт "failed to destroy ipset: busy".
	for _, group := range groups {
		if err := group.DestroySets(); err != nil {
			log.Warn().Err(err).Str("group", group.Name).Msg("group ipset destroy failed")
			errs = append(errs, fmt.Errorf("group %s: %w", group.Name, err))
		}
	}

	if a.dnsOverrider != nil {
		if err := a.dnsOverrider.Disable(); err != nil {
			log.Warn().Err(err).Msg("dnsOverrider disable failed")
			errs = append(errs, fmt.Errorf("dnsOverrider: %w", err))
		}
	}

	return errors.Join(errs...)
}

// DirectPriority возвращает текущий режим арбитража direct-групп (mt-n4b).
func (a *App) DirectPriority() string {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	return a.config.Netfilter.DirectPriority
}

// directPriorityApplied сообщает, соответствует ли режим, с которым реально
// созданы цепочки, тому, что записан в конфиге. Расходятся они только после
// неудачного переключения — и тогда повторный запрос обязан не отвечать «уже
// сделано», а честно повторить попытку.
func (a *App) directPriorityApplied() bool {
	a.cfgMu.RLock()
	want := a.config.Netfilter.DirectPriority == models.DirectPriorityByOrder
	shouldRun := a.config.Enabled
	a.cfgMu.RUnlock()

	// Роутинг снят вопреки намерению пользователя — состояние рассогласовано
	// после неудачной попытки, и запрос обязан чинить, а не отвечать «уже
	// применено» на роутере без правил.
	if shouldRun != a.routingActive.Load() {
		return false
	}
	if a.nfHelper == nil {
		return true
	}
	return a.nfHelper.DirectPriorityIsByOrder() == want
}

// applyDirectPriority выставляет режим в конфиге и хелпере и, если роутинг
// поднят, пересоздаёт цепочки — позиция direct-цепочки в PREROUTING задаётся
// при её создании, править на месте нечего.
// applyDirectPriority выставляет режим в конфиге и хелпере и, если роутинг
// должен работать, пересоздаёт цепочки — позиция direct-цепочки в PREROUTING
// задаётся при её создании, править на месте нечего.
//
// ensureRouting передаётся вызывающим, а НЕ читается из routingActive: после
// неудачного подъёма флаг уже сброшен откатом bringUpRouting, и решение «надо
// ли поднимать» по нему означало бы, что аварийное восстановление молча
// пропускает подъём и оставляет роутер без правил.
func (a *App) applyDirectPriority(mode string, ensureRouting bool) error {
	a.cfgMu.Lock()
	a.config.Netfilter.DirectPriority = mode
	a.cfgMu.Unlock()
	if a.nfHelper != nil {
		a.nfHelper.SetDirectPriorityByOrder(mode == models.DirectPriorityByOrder)
	}
	if !ensureRouting {
		return nil
	}
	// cfgMu к этому моменту отпущен: запись режима шла под Lock, а пересоздание
	// цепочек идёт под RLock — RWMutex в Go не повышается и не понижается.
	return a.withRoutingMutationUnderConfig(func() error {
		if a.routingActive.Load() {
			if err := a.bringDown(); err != nil {
				return fmt.Errorf("teardown: %w", err)
			}
		}
		if err := a.bringUp(); err != nil {
			return fmt.Errorf("bring-up: %w", err)
		}
		return nil
	})
}

// routingIntended — должен ли роутинг работать по воле пользователя. Именно
// это, а не фактический routingActive, определяет, поднимать ли правила после
// смены режима: фактический флаг может быть сбит предыдущим сбоем.
func (a *App) routingIntended() bool {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	return a.config.Enabled
}

// WithRoutingMutation выполняет fn под сериализацией операций с цепочками.
// Правило внутри fn: не брать cfgMu (см. комментарий к routingMutationMu).
func (a *App) WithRoutingMutation(fn func() error) error {
	a.routingMutationMu.Lock()
	defer a.routingMutationMu.Unlock()
	return fn()
}

// withRoutingMutationUnderConfig — тот же WithRoutingMutation, но с взятым снаружи
// cfgMu.RLock. Нужен всем жизненным циклам роутинга (SetEnabled, Start,
// смена directPriority): подъём и снятие читают конфиг-модель — g.Rules в
// Group.Sync и RebuildTrie, g.Group.Enable и g.Interface в Group.enable/disable, —
// а API-писатели мутируют их in-place под cfgMu.Lock. Без этого лока
// одновременные enable/disable и правка правил (HTTP или SIGHUP) дают Sync
// полуизменённый набор правил, и нужные ipset-записи временно удаляются
// (mt-03q).
//
// Порядок локов здесь «lifecycleMu -> cfgMu -> routingMutationMu» и совпадает с
// тем, по которому идёт автообновление подписок («cfgMu -> routingMutationMu»),
// поэтому инверсии нет. Внутри fn cfgMu брать нельзя по-прежнему:
// рекурсивный RLock при ждущем писателе в Go — дедлок.
func (a *App) withRoutingMutationUnderConfig(fn func() error) error {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	return a.WithRoutingMutation(fn)
}

func (a *App) bringUp() error {
	if a.bringUpFn != nil {
		return a.bringUpFn()
	}
	return a.bringUpRouting()
}

func (a *App) bringDown() error {
	if a.bringDownFn != nil {
		return a.bringDownFn()
	}
	return a.bringDownRouting()
}

func (a *App) saveConfig() error {
	if a.saveConfigFn != nil {
		return a.saveConfigFn()
	}
	return a.SaveConfig()
}

// SetDirectPriority переключает режим арбитража direct-групп (mt-n4b).
//
// Операция транзакционная: применение к живому роутингу требует пересоздания
// цепочек, а значит может упасть на полпути. Любая ошибка возвращает систему к
// прежнему режиму — включая повторный подъём роутинга, который bringUpRouting
// снимает своим откатом. Худший исход (не поднялись даже со старым режимом)
// возвращается пользователю ошибкой, а не тихо оставляет роутер без правил.
//
// Порядок операций повторяет SetEnabled: коммиттер на паузу (иначе он
// восстановит то, что снимает teardown), затем переподнятие. Возобновляется
// коммиттер только если роутинг в итоге поднят: ready при снятом роутинге
// заставил бы его чинить то, чего быть не должно.
func (a *App) SetDirectPriority(mode string) error {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()

	if mode != models.DirectPriorityAbsolute && mode != models.DirectPriorityByOrder {
		return fmt.Errorf("unknown direct priority mode %q", mode)
	}

	previous := a.DirectPriority()
	// Ранний выход только когда состояние согласовано. После неудачной попытки
	// конфиг и цепочки расходятся, и «тот же режим» означает «повтори», а не
	// «уже применено» — иначе повторный PUT ответил бы 200 на снятом роутинге.
	if previous == mode && a.directPriorityApplied() {
		return nil
	}

	if a.committer != nil {
		a.committer.setMode(committerPaused)
	}
	defer func() {
		if a.committer != nil && a.routingActive.Load() {
			a.committer.setMode(committerReady)
		}
	}()

	// Ориентир — намерение пользователя из конфига, а не текущий routingActive:
	// после неудачной попытки флаг уже сбит откатом bringUpRouting, и по нему
	// восстановление молча пропустило бы подъём, оставив роутер без правил.
	shouldRun := a.routingIntended()

	if err := a.applyDirectPriority(mode, shouldRun); err != nil {
		log.Error().Err(err).Str("mode", mode).Msg("direct priority switch failed, rolling back")
		if rollbackErr := a.applyDirectPriority(previous, shouldRun); rollbackErr != nil {
			return errors.Join(
				fmt.Errorf("failed to switch direct priority to %q: %w", mode, err),
				fmt.Errorf("rollback to %q also failed, routing is down: %w", previous, rollbackErr),
			)
		}
		return fmt.Errorf("failed to switch direct priority to %q (rolled back): %w", mode, err)
	}

	if err := a.saveConfig(); err != nil {
		// Ядро уже живёт по новому режиму, а диск — по старому. Оставить так
		// значит соврать: после перезапуска вернётся прежнее поведение, хотя
		// API и UI показывают новое. Откатываем ядро к тому, что на диске.
		log.Error().Err(err).Msg("failed to persist netfilter.directPriority, rolling back")
		if rollbackErr := a.applyDirectPriority(previous, shouldRun); rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("rollback to %q also failed, routing is down: %w", previous, rollbackErr))
		}
		return err
	}

	log.Info().Str("mode", mode).Msg("direct priority switched")
	return nil
}

// SetEnabled toggles routing on/off and persists the choice to config.
// When enabled=false, traffic flows as if MagiTrickle were not running.
func (a *App) SetEnabled(enabled bool) error {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()

	// Демон уже гасится: правила сняты, второго teardown не будет. Поднять их
	// сейчас — значит уйти с живыми DNS-remap и TPROXY, и трафик до перезапуска
	// сервиса пойдёт в остановленный процесс (mt-kd1). Снятие при этом
	// разрешаем: оно совпадает с тем, что делает teardown.
	if a.shuttingDown && enabled {
		return errors.New("daemon is shutting down")
	}

	// Чтение config.Enabled — под cfgMu: его меняет и SIGHUP-reload, и этот же
	// метод ниже. lifecycleMu сериализует только SetEnabled между собой и
	// от писателей конфига не защищает (mt-03q).
	if a.routingIntended() == enabled && a.routingActive.Load() == enabled {
		return nil
	}

	var bringDownErr error
	if enabled {
		if err := a.withRoutingMutationUnderConfig(a.bringUp); err != nil {
			return err
		}
		if a.committer != nil {
			a.committer.setMode(committerReady)
		}
	} else {
		if a.committer != nil {
			// Сначала паузим коммиттер — setMode возвращается только после
			// того, как worker принял режим, поэтому нового прохода уже не
			// начнётся. Иначе он восстановил бы то, что снимает teardown.
			a.committer.setMode(committerPaused)
		}
		bringDownErr = a.withRoutingMutationUnderConfig(a.bringDown)
	}

	// Намерение пользователя фиксируется в конфиге безусловно, даже если
	// снятие роутинга выше не удалось (bringDownErr != nil). Пользователь
	// попросил выключить — если не сохранить это намерение, после
	// перезапуска демон снова поднимет роутинг, который просили снять.
	// Ошибка снятия при этом не глотается: она возвращается вызывающему
	// вместе с возможной ошибкой SaveConfig, чтобы HTTP-обработчик не
	// ответил 200 OK при частично снятых iptables-цепочках.
	// Запись — под эксклюзивным cfgMu, и только после выхода из секции с RLock
	// выше: RWMutex в Go не повышается. SaveConfig берёт RLock сам — зовём его
	// снаружи лока.
	a.WithConfigWrite(func() { a.config.Enabled = enabled })
	saveErr := a.saveConfig()
	if saveErr != nil {
		log.Error().Err(saveErr).Msg("failed to persist app.enabled")
	}
	return errors.Join(bringDownErr, saveErr)
}

// Restart spawns a detached shell that calls the platform restart command
// (init.d/procd or systemctl), then exits the current process so the
// supervisor brings magitrickled back up with fresh configuration.
//
// Teardown semantics: the restart command (e.g. `init.d ... restart`) stops
// this service first, which delivers SIGTERM. The normal shutdown path then
// runs gracefully — Start's deferred bringDownRouting + dnsMITM.Close tear down
// the iptables rules and the DNS override (see start.go). So in the normal case
// teardown DOES happen, via the signal, not here.
//
// The os.Exit(0) below is therefore NOT the primary exit — it is a watchdog
// fallback for the degraded case where the restart command fails to terminate
// us within 3s (signal ignored, shutdown hung). In that path teardown is
// intentionally skipped: leaving the iptables rules and DNS override in place
// avoids a routing-leak window, and the freshly started process reconciles any
// stale state on startup (each group's enable() calls ClearIfDisabled before
// re-adding its rules). Hence os.Exit(0), not teardown-then-exit.
func (a *App) Restart() {
	log.Info().Str("cmd", constant.RestartCommand).Msg("restart requested via API")

	cmd := exec.Command("sh", "-c", "sleep 1; "+constant.RestartCommand)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	if err := cmd.Start(); err != nil {
		log.Error().Err(err).Msg("failed to start restart command")
		return
	}
	go func() { _ = cmd.Wait() }()

	// Watchdog fallback: force-exit if the restart command above did not take us
	// down via SIGTERM within 3s. Teardown is intentionally skipped here — see
	// the function doc for why leaving routing in place is the safe choice.
	go func() {
		time.Sleep(3 * time.Second)
		log.Info().Msg("exiting process to let supervisor restart it")
		os.Exit(0)
	}()
}
