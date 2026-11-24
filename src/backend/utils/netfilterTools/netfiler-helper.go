package netfilterTools

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"magitrickle/utils/iptables"
)

// preambleChainSuffix names the shared interface-mode preamble chain
// (ChainPrefix + suffix, e.g. "MT_PREAMBLE"). Matching ChainPrefix means the
// startup iptables cleaner removes it automatically after a crash.
const preambleChainSuffix = "PREAMBLE"

type Helper struct {
	ChainPrefix string
	IpsetPrefix string
	IPTables4   *iptables.IPTables
	IPTables6   *iptables.IPTables

	StartIdx uint32

	// directPriorityByOrder переключает арбитраж direct-групп (mt-n4b).
	// false (дефолт) — direct абсолютен: его цепочка встаёт первой в
	// PREROUTING и ACCEPT внутри неё перебивает TPROXY/MARK любой другой
	// группы, где бы direct ни стоял в списке. true — direct участвует в
	// общей очереди наравне с остальными, поэтому группа выше по списку
	// выигрывает overlap, а широкая direct-группа внизу работает catch-all'ом
	// (конфиги, сложившиеся до f326f4a). Содержимое цепочки в обоих режимах
	// одинаково: терминирует ACCEPT, возврат к RETURN означал бы баг mt-my3.
	//
	// Атомарный, а не голый bool: режим переключается из HTTP-обработчика под
	// lifecycleMu, а читается при создании direct-цепочки в Group.Enable,
	// который вызывается и с путей, этого лока не берущих (group API,
	// RebuildSubscriptionGroups) — то есть на голом поле это гонка данных.
	directPriorityByOrder atomic.Bool

	// preambleMu guards the reference count for the shared interface-mode
	// mangle preamble. The preamble is a single chain shared by all
	// interface-mode groups, installed on the first group and removed on the
	// last, so its lifecycle can't be owned by any individual group.
	preambleMu   sync.Mutex
	preambleRefs int

	clientBypassMu    sync.Mutex
	clientBypassReady bool
}

// SetDirectPriorityByOrder переключает режим арбитража direct-групп.
// Влияет только на цепочки, создаваемые ПОСЛЕ вызова: позиция уже существующей
// цепочки в PREROUTING задана в момент её создания, поэтому смена режима на
// живой системе требует переподнятия правил.
func (nh *Helper) SetDirectPriorityByOrder(byOrder bool) {
	nh.directPriorityByOrder.Store(byOrder)
}

// DirectPriorityIsByOrder сообщает текущий режим арбитража direct-групп.
func (nh *Helper) DirectPriorityIsByOrder() bool {
	return nh.directPriorityByOrder.Load()
}

// acquireInterfacePreamble ensures the shared mangle PREROUTING preamble is
// installed and bumps its reference count. The preamble runs before every
// interface-group chain:
//
//	-j CONNMARK --restore-mark      restore the per-connection routing mark
//	-m mark ! --mark 0 -j ACCEPT    connection already decided -> skip re-eval
//
// This makes the routing decision one-shot per connection: once a group chain
// has marked and save-marked a connection, subsequent packets are routed by the
// restored mark even after the destination IP has aged out of the ipset (DNS TTL
// expiry). That fixes the interface-mode long-session drop (every packet used to
// re-query the ipset; an expired IP left the packet unmarked -> default route ->
// RST). It also short-circuits decided connections so a later group cannot steal
// an already-established one.
//
// The restore-mark MUST be one shared rule, not per-group: a per-group
// restore-mark would leak a foreign group's restored mark into the next group's
// chain and corrupt arbitration.
func (nh *Helper) acquireInterfacePreamble() error {
	nh.preambleMu.Lock()
	defer nh.preambleMu.Unlock()

	if nh.preambleRefs == 0 {
		// -m conntrack (--ctdir) needs xt_conntrack; usually loaded by the
		// firewall already, but load best-effort like the tproxy modules.
		ensureKernelModule("xt_conntrack")

		var errs []error
		for _, ipt := range []*iptables.IPTables{nh.IPTables4, nh.IPTables6} {
			errs = append(errs, nh.installInterfacePreamble(ipt))
		}
		if err := errors.Join(errs...); err != nil {
			return err
		}
	}
	nh.preambleRefs++
	return nil
}

// releaseInterfacePreamble drops one reference and removes the shared preamble
// when the last interface-mode group goes away.
func (nh *Helper) releaseInterfacePreamble() error {
	nh.preambleMu.Lock()
	defer nh.preambleMu.Unlock()

	if nh.preambleRefs == 0 {
		return nil
	}
	nh.preambleRefs--
	if nh.preambleRefs > 0 {
		return nil
	}

	var errs []error
	for _, ipt := range []*iptables.IPTables{nh.IPTables4, nh.IPTables6} {
		errs = append(errs, nh.removeInterfacePreamble(ipt))
	}
	return errors.Join(errs...)
}

func (nh *Helper) installInterfacePreamble(ipt *iptables.IPTables) error {
	if ipt == nil {
		return nil
	}
	chain := nh.ChainPrefix + preambleChainSuffix

	if err := ipt.RegisterChainOverride("mangle", chain); err != nil {
		return fmt.Errorf("failed to create preamble chain: %w", err)
	}
	if err := nh.appendClientBypassGuard(ipt, "mangle", chain); err != nil {
		return fmt.Errorf("failed to append client bypass guard: %w", err)
	}
	// --ctdir ORIGINAL is CRITICAL: connmark is one value for both directions
	// of a connection, but the group routing table holds only a default route
	// via the group iface (no connected routes, unlike e.g. mwan3). Restoring
	// the mark onto a reply packet (server->client, arriving from the group
	// iface) would send it into `ip rule fwmark X -> table X -> default via
	// group iface` — straight back into the tunnel instead of to the LAN
	// client, killing the connection from the very first reply. Original-only
	// restore routes client->server packets via the group iface while replies
	// keep the pre-fix behaviour: unmarked, main table, connected route to LAN.
	if err := ipt.Append("mangle", chain, "-m", "conntrack", "--ctdir", "ORIGINAL", "-j", "CONNMARK", "--restore-mark"); err != nil {
		return fmt.Errorf("failed to append restore-mark: %w", err)
	}
	if err := ipt.Append("mangle", chain, "-m", "mark", "!", "--mark", "0x0", "-j", "ACCEPT"); err != nil {
		return fmt.Errorf("failed to append mark-accept: %w", err)
	}
	// Append, don't Insert@1: direct-mode chains Insert@1 and MUST stay above
	// the preamble (direct's contract is to override everything — adding an IP
	// to a direct group must divert even an established, connmark'ed
	// connection). Insert@1 here would race with direct for the top slot and
	// the winner would depend on group enable order. Appending is still ahead
	// of every interface-group jump because acquire runs in enable() before the
	// group appends its own jump. Exclude loopback, matching the group jumps.
	if err := ipt.Append("mangle", "PREROUTING", "!", "-i", "lo", "-j", chain); err != nil {
		return fmt.Errorf("failed to append preamble jump: %w", err)
	}
	if err := ipt.Commit(); err != nil {
		return fmt.Errorf("failed to commit preamble: %w", err)
	}
	return nil
}

func (nh *Helper) removeInterfacePreamble(ipt *iptables.IPTables) error {
	if ipt == nil {
		return nil
	}
	chain := nh.ChainPrefix + preambleChainSuffix

	var errs []error
	if err := ipt.Delete("mangle", "PREROUTING", "!", "-i", "lo", "-j", chain); err != nil {
		errs = append(errs, fmt.Errorf("failed to unlink preamble jump: %w", err))
	}
	if err := ipt.RegisterChainDelete("mangle", chain); err != nil {
		errs = append(errs, fmt.Errorf("failed to delete preamble chain: %w", err))
	}
	if err := ipt.Commit(); err != nil {
		errs = append(errs, fmt.Errorf("failed to commit preamble removal: %w", err))
	}
	return errors.Join(errs...)
}

// Batch выполняет fn в режиме отложенного коммита: промежуточные Commit()
// внутри Enable/Disable групп не ходят в ядро, а копятся, и применяются одним
// коммитом на семейство после fn.
//
// Зачем: каждый Commit — это пара iptables-save/iptables-restore. При массовых
// операциях (подъём и снятие всех групп) их число линейно по количеству групп:
// на проде замерено 152 обращения к ядру при старте и 76 при teardown, что
// давало ~6с только на снятие правил (mt-jou). Это упирается в лимит ожидания
// init.d (~11с), после которого прилетает SIGKILL и teardown обрывается на
// полпути, оставляя правила и сеты в системе. На медленных роутерах (mipsel)
// запас ещё меньше.
//
// Флаг снимается через defer — то есть при ошибке или панике внутри fn режим не
// останется включённым, иначе последующие правки правил тихо не доезжали бы до
// ядра. Финальный коммит выполняется всегда, в том числе когда fn вернула
// ошибку: часть правил уже накоплена, и оставлять её неприменённой хуже.
func (nh *Helper) Batch(fn func() error) error {
	// Helper может быть не инициализирован (ранний старт, юнит-тесты без
	// netfilter) — тогда батчить нечего, просто выполняем работу.
	if nh == nil {
		return fn()
	}

	ipts := []*iptables.IPTables{nh.IPTables4, nh.IPTables6}

	for _, ipt := range ipts {
		if ipt != nil {
			ipt.SetDeferred(true)
		}
	}
	defer func() {
		for _, ipt := range ipts {
			if ipt != nil {
				ipt.SetDeferred(false)
			}
		}
	}()

	errs := []error{fn()}

	for _, ipt := range ipts {
		if ipt == nil {
			continue
		}
		ipt.SetDeferred(false)
		if err := ipt.Commit(); err != nil {
			errs = append(errs, fmt.Errorf("failed to commit batched rules: %w", err))
		}
	}
	return errors.Join(errs...)
}

// ValidatePrefixes rejects broad prefixes before startup cleanup matches resource names.
func ValidatePrefixes(chainPrefix, ipsetPrefix string) error {
	const minPrefixLen = 3
	if len(chainPrefix) < minPrefixLen {
		return fmt.Errorf("chain prefix %q is too short: at least %d characters required", chainPrefix, minPrefixLen)
	}
	if len(ipsetPrefix) < minPrefixLen {
		return fmt.Errorf("ipset prefix %q is too short: at least %d characters required", ipsetPrefix, minPrefixLen)
	}
	return nil
}

func New(chainPrefix, ipsetPrefix string, disableIPv4, disableIPv6 bool, startIdx uint32) (*Helper, error) {
	if err := ValidatePrefixes(chainPrefix, ipsetPrefix); err != nil {
		return nil, err
	}
	var ipt4, ipt6 *iptables.IPTables

	if !disableIPv4 {
		ipt4 = iptables.NewIPTables(iptables.NewRealIPTables())
	}

	if !disableIPv6 {
		ipt6 = iptables.NewIPTables(iptables.NewRealIP6Tables())
	}

	return &Helper{
		ChainPrefix: chainPrefix,
		IpsetPrefix: ipsetPrefix,
		IPTables4:   ipt4,
		IPTables6:   ipt6,
		StartIdx:    startIdx,
	}, nil
}
