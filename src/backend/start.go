package magitrickle

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"runtime/debug"
	"strconv"
	"time"

	"magitrickle/api"
	"magitrickle/models"
	"magitrickle/utils/dnsMITMProxy"
	"magitrickle/utils/iptables"
	"magitrickle/utils/netfilterTools"
	"magitrickle/utils/recordsCache"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
)

// Start запускает приложение (ядро)
func (a *App) Start(ctx context.Context) (err error) {
	if !a.enabled.CompareAndSwap(false, true) {
		return ErrAlreadyRunning
	}
	defer a.enabled.Store(false)

	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(os.Stderr, "panic: %v\n%s\n", r, debug.Stack())
			err = errors.New(fmt.Sprintf("panic: %v", r))
		}
	}()

	a.setupLogging()

	a.dnsMITM = dnsMITMProxy.NewDNSMITMProxy(
		net.JoinHostPort(a.config.DNSProxy.Upstream.Address, strconv.Itoa(int(a.config.DNSProxy.Upstream.Port))),
		a.config.DNSProxy.MaxIdleConns,
		a.config.DNSProxy.MaxConcurrent,
		a.config.DNSProxy.Timeout,
	)
	a.dnsMITM.RequestHook = a.dnsRequestHook
	a.dnsMITM.ResponseHook = a.dnsResponseHook

	// dual-upstream: out-of-group домены идут в FallbackUpstream (например ndnproxy 127.0.0.1:53),
	// минуя primary (mihomo). Subnet-rules продолжают работать post-resolve независимо от пути.
	if fb := a.config.DNSProxy.FallbackUpstream; fb != nil {
		a.dnsMITM.SetFallback(
			net.JoinHostPort(fb.Address, strconv.Itoa(int(fb.Port))),
			a.config.DNSProxy.MaxIdleConns,
		)
		a.dnsMITM.UpstreamSelector = a.selectUpstream
	}
	defer func() {
		if a.dnsMITM != nil {
			_ = a.dnsMITM.Close()
		}
	}()

	a.recordsCache = recordsCache.New()
	// Персист снапшота на диск (mt-pqa) — ВЫКЛЮЧЕН по умолчанию (mt-0cf).
	// При ClientTTLCap>0 ipset и так самовосстанавливается за ClientTTLCap
	// секунд при любой потере (не только рестарте), а после планового рестарта
	// пользователь обычно ждёт чистый старт, а не подхват старого состояния.
	// Персист даёт лишь мгновенность при рестарте ценой постоянных записей на
	// флеш — включается явно через dnsProxy.persistCache в конфиге.
	if a.config.DNSProxy.PersistCache {
		if err := a.recordsCache.Load(recordsCacheSnapshotLocation); err != nil {
			log.Warn().Err(err).Msg("failed to load records cache snapshot")
		} else {
			log.Info().Int("domains", len(a.recordsCache.ListKnownDomains())).Msg("records cache snapshot loaded")
		}
	}
	a.recordsCache.StartCleanup(ctx, 30*time.Second)
	if a.config.DNSProxy.PersistCache {
		// На диск пишем только домены, релевантные правилам (+ цели их CNAME-
		// цепочек, это делает SnapshotFiltered): кэш держит ВСЕ резолвы LAN, но
		// переживать рестарт им незачем — ipset наполняется лишь по сматченным
		// (mt-fnj).
		a.recordsCache.StartPersist(ctx, 5*time.Minute, recordsCacheSnapshotLocation, a.isPersistableDomain)
	}

	nfh, err := netfilterTools.New(a.config.Netfilter.IPTables.ChainPrefix, a.config.Netfilter.IPSet.TablePrefix, a.config.Netfilter.DisableIPv4, a.config.Netfilter.DisableIPv6, a.config.Netfilter.StartMarkTableIndex)
	if err != nil {
		return fmt.Errorf("netfilter helper init fail: %w", err)
	}
	// Режим арбитража direct читается на старте: он влияет только на позицию
	// цепочки при её создании, поэтому смена режима на лету потребовала бы
	// переподнятия роутинга (см. mt-n4b, UI-часть).
	nfh.SetDirectPriorityByOrder(a.config.Netfilter.DirectPriority == models.DirectPriorityByOrder)
	a.nfHelper = nfh

	for _, ipt := range []*iptables.IPTables{a.nfHelper.IPTables4, a.nfHelper.IPTables6} {
		if ipt == nil {
			continue
		}
		ipt.RegisterChainPatch("filter", "FORWARD")
		ipt.RegisterChainPatch("mangle", "PREROUTING")
		ipt.RegisterChainPatch("nat", "PREROUTING")
		ipt.RegisterChainPatch("nat", "POSTROUTING")
	}

	if err := a.nfHelper.CleanIPTables(); err != nil {
		return fmt.Errorf("failed to clear iptables: %w", err)
	}

	normalizedBypass, err := a.nfHelper.SetupClientBypass(a.config.ClientRouting.SourceNetworks)
	if err != nil {
		return fmt.Errorf("failed to prepare client bypass: %w", err)
	}
	a.config.ClientRouting.SourceNetworks = normalizedBypass
	// Registered before bringDownRouting's defer below, so LIFO teardown first
	// removes all iptables references and only then destroys the ipsets.
	defer func() {
		if err := a.nfHelper.DestroyClientBypass(); err != nil {
			log.Warn().Err(err).Msg("failed to destroy client bypass sets")
		}
	}()

	// Subscribe to link updates BEFORE bringing routing up, otherwise an
	// interface that comes online during the bring-up window would not
	// trigger LinkUpHook and our route on it would never get installed.
	linkUpdateChannel, linkUpdateDone, err := subscribeLinkUpdates()
	if err != nil {
		return err
	}
	defer close(linkUpdateDone)

	// Подписка на изменения адресов: интерфейс может получить IP/шлюз позже
	// поднятия, тогда iface-маршрут пересоздаётся через handleAddr -> AddrChangeHook.
	addrUpdateChannel, addrUpdateDone, err := subscribeAddrUpdates()
	if err != nil {
		return err
	}
	defer close(addrUpdateDone)

	newCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	errChan := make(chan error)

	// Коммиттер запускается ДО открытия сокетов: хук netfilter.d бьёт в
	// unix-сокет, и событие может прийти сразу после SetupUnixSocket. До
	// готовности модели он в режиме starting — событие защёлкивается, но не
	// исполняется.
	//
	// defer со stop регистрируется здесь же, чтобы worker не утёк на ранних
	// return err ниже (LinkByName, RebuildSubscriptionGroups, bringUpRouting).
	// stop идемпотентен, поэтому явный вызов перед снятием правил ниже не
	// конфликтует с этим defer.
	a.committer = startNetfilterCommitter(newCtx, a.forceCommitIPTablesWake, defaultReconcileDelay)
	defer a.committer.stop()

	var httpServer, unixServer *http.Server
	var interfaceAddrs []netlink.Addr

	// lifecycleMu — тот же лок, что держит SetEnabled. Секция расширена НАЗАД
	// относительно старого варианта: сокеты (HTTP и unix) открываются здесь
	// же, и с этого момента снаружи уже может прийти SetEnabled, который
	// гоняется за a.dnsOverrider и routingGroups() — а они собираются НИЖЕ,
	// вплоть до bringUpRouting. Не покрой лок это окно — SetEnabled(true),
	// пришедший между открытием сокета и сборкой групп, мог бы выставить
	// routingActive=true раньше времени, и собственный bringUpRouting ниже
	// стал бы no-op по CAS: DNS-ремап 53 не установился бы вовсе.
	//
	// Участок обёрнут в IIFE с defer Unlock, чтобы лок освобождался на всех
	// путях выхода — включая панику и ранние return err ниже (LinkByName,
	// RebuildSubscriptionGroups, bringUpRouting). IIFE возвращает ошибку,
	// вызывающий код пробрасывает её из Start.
	lifecycleErr := func() error {
		a.lifecycleMu.Lock()
		defer a.lifecycleMu.Unlock()

		var err error
		httpServer, err = api.SetupHTTP(a, errChan)
		if err != nil {
			return fmt.Errorf("setup http fail: %w", err)
		}

		unixServer, err = api.SetupUnixSocket(a, errChan)
		if err != nil {
			return fmt.Errorf("setup unix socket fail: %w", err)
		}

		a.startDNSListeners(newCtx, errChan)

		for _, linkName := range a.config.Link {
			link, err := netlink.LinkByName(linkName)
			if err != nil {
				return fmt.Errorf("failed to find link %s: %w", linkName, err)
			}
			linkAddrList, err := netlink.AddrList(link, nl.FAMILY_ALL)
			if err != nil {
				return fmt.Errorf("failed to list address of interface %s: %w", linkName, err)
			}
			interfaceAddrs = append(interfaceAddrs, linkAddrList...)
		}

		// Always prepare dnsOverrider object so Pause/Resume can toggle it later,
		// even if the config initially has Enabled=false.
		if !a.config.DNSProxy.DisableRemap53 {
			a.dnsOverrider = a.nfHelper.PortRemap("DNSOR", 53, a.config.DNSProxy.Host.Port, interfaceAddrs)
		}

		if err := a.RebuildSubscriptionGroups(); err != nil {
			return fmt.Errorf("failed to prepare subscription groups: %w", err)
		}

		if a.config.Enabled {
			if err := a.withRoutingMutationUnderConfig(a.bringUpRouting); err != nil {
				return err
			}
			// Модель собрана — коммиттер может писать. Событие, защёлкнутое во
			// время старта, исполнится немедленно.
			a.committer.setMode(committerReady)
		} else {
			log.Warn().Msg("MagiTrickle started with app.enabled=false — routing is paused")
			a.committer.setMode(committerPaused)
		}
		return nil
	}()

	// defer Close регистрируем СРАЗУ после вызова IIFE и ДО проверки ошибки:
	// сервер должен закрыться и при успехе (обычный teardown ниже), и при
	// частичном отказе (например unixServer не поднялся, а httpServer уже
	// слушает) — как и в исходном коде, где defer шёл сразу за созданием.
	if httpServer != nil {
		defer httpServer.Close()
	}
	if unixServer != nil {
		defer unixServer.Close()
	}
	if lifecycleErr != nil {
		return lifecycleErr
	}
	// Порядок обязателен: сперва остановить коммиттер и ДОЖДАТЬСЯ его, потом
	// снимать правила. Иначе teardown снимает цепочки, пока worker их
	// восстанавливает. Одним defer это не решается: defer, зарегистрированный
	// при запуске коммиттера выше, по LIFO выполнится ПОЗЖЕ этого — поэтому
	// stop вызывается явно здесь, а тот defer остаётся страховкой от ранних
	// выходов. Повторный stop — no-op.
	//
	// lifecycleMu здесь сериализует снятие правил с конкурентным SetEnabled:
	// пока лок держится, SetEnabled(true) не может поднять правила обратно
	// между stop() коммиттера и bringDownRouting() ниже. Зазор между Unlock и
	// фактическим закрытием сокетов (они закрываются defer'ами, зарегистри-
	// рованными ВЫШЕ, то есть по LIFO уже ПОСЛЕ) закрывает флаг shuttingDown:
	// взведённый под тем же локом, он заставляет любой последующий
	// SetEnabled(true) отказать, вместо того чтобы поднять правила, снимать
	// которые уже некому (mt-kd1). Именно флаг, а не порядок закрытия сокетов:
	// http.Server.Close рвёт соединения, но не отменяет уже запущенный
	// обработчик, поэтому гейт обязан стоять внутри SetEnabled.
	defer func() {
		a.committer.stop()
		a.lifecycleMu.Lock()
		defer a.lifecycleMu.Unlock()
		a.shuttingDown = true
		_ = a.withRoutingMutationUnderConfig(a.bringDownRouting)
	}()

	if a.config.DNSProxy.PersistCache {
		// Финальный синхронный флеш снапшота — ЗДЕСЬ, а не рядом со StartPersist:
		// defer'ы идут LIFO, поэтому эта регистрация (после bringDownRouting)
		// выполняется ПЕРЕД ним, пока группы ещё включены. Иначе isPersistableDomain
		// опирался бы на уже выключенные группы, отфильтровал бы всё и затёр снапшот
		// пустым — так на проде 2026-07-26 потерялся весь накопленный прогрев
		// (в самом Save на этот случай есть ещё и страховка от пустого слепка).
		// Синхронно, потому что StartPersist-горутину на ctx.Done могут не дождаться.
		defer func() { _, _ = a.recordsCache.Save(recordsCacheSnapshotLocation, a.isPersistableDomain) }()
	}

	a.startSubscriptionSyncLoop(newCtx, errChan)
	a.startStaticSubnetReassertLoop(newCtx)

	for {
		select {
		case event := <-linkUpdateChannel:
			a.handleLink(event)
		case event := <-addrUpdateChannel:
			a.handleAddr(event)
		case err := <-errChan:
			return err
		case <-ctx.Done():
			return nil
		}
	}
}

// isPersistableDomain — предикат отбора для снапшота recordsCache: на диск идут
// только имена, сматченные активными правилами. Цели их CNAME-цепочек добирает
// сам SnapshotFiltered, поэтому здесь достаточно прямого совпадения.
//
// Побочный эффект осознан: домен, который сматчится ПОСЛЕ добавления правила
// пользователем, в прошлом снапшоте отсутствует — его ipset-запись появится с
// первым же резолвом (или по кнопке «Прогреть»), а не мгновенно после рестарта.
func (a *App) isPersistableDomain(domain string) bool {
	_, ok := a.searchDomain(domain)
	return ok
}

// startStaticSubnetReassertLoop периодически ре-фиксирует permanent
// subnet-записи всех групп (см. Group.ReassertStaticSubnets): ipset-refresh
// правило TPROXY (mt-9g7 C) сбрасывает timeout статической /32-записи при
// новом соединении на её IP; без ре-фиксации такая запись истекла бы после
// паузы в трафике. Интервал 15 мин ограничивает максимальное окно утечки.
func (a *App) startStaticSubnetReassertLoop(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(15 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				if !a.routingActive.Load() {
					continue
				}
				a.WithConfigRead(func() {
					for _, g := range a.routingGroups() {
						if err := g.ReassertStaticSubnets(); err != nil {
							log.Warn().Err(err).Str("group", g.Name).Msg("failed to reassert static subnets")
						}
					}
				})
			case <-ctx.Done():
				return
			}
		}
	}()
}

func (a *App) ForceCommitIPTables(ctx context.Context) error {
	return a.forceCommitIPTablesWake(ctx, nil)
}

// forceCommitIPTablesWake — то же, но с каналом пробуждения: событие,
// пришедшее во время пауз между попытками, прерывает ожидание и начинает
// проход заново.
//
// v6 коммитится даже если упал v4: семейства независимы, и терять оба из-за
// одного не нужно.
func (a *App) forceCommitIPTablesWake(ctx context.Context, wake <-chan struct{}) error {
	if a.nfHelper == nil {
		return nil
	}

	var errs []error

	if a.nfHelper.IPTables4 != nil {
		if err := a.nfHelper.IPTables4.CommitWithRetryWake(ctx, wake); err != nil {
			errs = append(errs, fmt.Errorf("failed to commit iptables rules: %w", err))
		}
	}

	if a.nfHelper.IPTables6 != nil {
		if err := a.nfHelper.IPTables6.CommitWithRetryWake(ctx, wake); err != nil {
			errs = append(errs, fmt.Errorf("failed to commit ip6tables rules: %w", err))
		}
	}

	return errors.Join(errs...)
}

// RequestNetfilterCommit просит коммиттер переустановить правила.
// Неблокирующий: вызывается из HTTP-обработчика хука netfilter.d.
func (a *App) RequestNetfilterCommit() {
	if a.committer != nil {
		a.committer.request()
	}
}

func (a *App) setupLogging() {
	// If CLI already set a level below info (debug/trace), keep it.
	if zerolog.GlobalLevel() < zerolog.InfoLevel {
		return
	}
	switch a.config.LogLevel {
	case "trace":
		zerolog.SetGlobalLevel(zerolog.TraceLevel)
	case "debug":
		zerolog.SetGlobalLevel(zerolog.DebugLevel)
	case "info":
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	case "warn":
		zerolog.SetGlobalLevel(zerolog.WarnLevel)
	case "error":
		zerolog.SetGlobalLevel(zerolog.ErrorLevel)
	case "fatal":
		zerolog.SetGlobalLevel(zerolog.FatalLevel)
	case "panic":
		zerolog.SetGlobalLevel(zerolog.PanicLevel)
	case "nolevel":
		zerolog.SetGlobalLevel(zerolog.NoLevel)
	case "disabled":
		zerolog.SetGlobalLevel(zerolog.Disabled)
	default:
		zerolog.SetGlobalLevel(zerolog.InfoLevel)
	}
}

func (a *App) getInterfaceAddresses() ([]netlink.Addr, error) {
	var addrList []netlink.Addr
	for _, linkName := range a.config.Link {
		link, err := netlink.LinkByName(linkName)
		if err != nil {
			return nil, fmt.Errorf("failed to find link %s: %w", linkName, err)
		}
		linkAddrList, err := netlink.AddrList(link, nl.FAMILY_ALL)
		if err != nil {
			return nil, fmt.Errorf("failed to list address of interface %s: %w", linkName, err)
		}
		addrList = append(addrList, linkAddrList...)
	}
	return addrList, nil
}
