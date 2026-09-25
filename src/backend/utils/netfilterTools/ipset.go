package netfilterTools

import (
	"errors"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

type IPv4Subnet struct {
	Address [4]byte
	CIDR    uint8
}

func (subnet IPv4Subnet) String() string {
	if subnet.CIDR == 0 {
		return fmt.Sprintf("%d.%d.%d.%d", subnet.Address[0], subnet.Address[1], subnet.Address[2], subnet.Address[3])
	} else {
		return fmt.Sprintf("%d.%d.%d.%d/%d", subnet.Address[0], subnet.Address[1], subnet.Address[2], subnet.Address[3], subnet.CIDR)
	}
}

// IPv4Host — канонический ключ одиночного IP (host-записи) в hash:net: явный
// /32. Ядро при листинге ВСЕГДА отдаёт IPSET_ATTR_CIDR (hash_net4_data_list,
// безусловный nla_put_u8 — одинаково в v3.10 и master), даже если запись
// добавлялась с CIDR=0, поэтому ключ с CIDR=0 никогда не совпадёт с листингом —
// все места, сравнивающие ключи со списком из ListIPv4Subnets, обязаны
// строить host-записи через этот конструктор (mt-bku).
func IPv4Host(addr [4]byte) IPv4Subnet {
	return IPv4Subnet{Address: addr, CIDR: 32}
}

type IPv6Subnet struct {
	Address [16]byte
	CIDR    uint8
}

// IPv6Host — канонический ключ одиночного IPv6 (host-записи): явный /128.
// См. IPv4Host.
func IPv6Host(addr [16]byte) IPv6Subnet {
	return IPv6Subnet{Address: addr, CIDR: 128}
}

func (subnet IPv6Subnet) String() string {
	if subnet.CIDR == 0 {
		return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x", subnet.Address[0], subnet.Address[1], subnet.Address[2], subnet.Address[3], subnet.Address[4], subnet.Address[5], subnet.Address[6], subnet.Address[7], subnet.Address[8], subnet.Address[9], subnet.Address[10], subnet.Address[11], subnet.Address[12], subnet.Address[13], subnet.Address[14], subnet.Address[15])
	} else {
		return fmt.Sprintf("%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x:%x/%d", subnet.Address[0], subnet.Address[1], subnet.Address[2], subnet.Address[3], subnet.Address[4], subnet.Address[5], subnet.Address[6], subnet.Address[7], subnet.Address[8], subnet.Address[9], subnet.Address[10], subnet.Address[11], subnet.Address[12], subnet.Address[13], subnet.Address[14], subnet.Address[15], subnet.CIDR)
	}
}

type IPSetTimeout *uint32

var zeroTimeout = IPSetTimeout(new(uint32))

type IPSet struct {
	enabled atomic.Bool
	locker  sync.Mutex

	ipsetName string
}

// StaticSetName4/StaticSetName6 — имена зеркала статических подсетей группы
// (<name>_s4 / <name>_s6). Зеркало содержит ТОЛЬКО permanent-записи из
// subnet/subnet6-правил и служит негативным матчем для ipset-refresh правила
// TPROXY (mt-bq8): пакет, попавший в широкую статическую подсеть, не должен
// материализоваться в основном сете отдельной /32-/128-записью.
func (r *IPSet) StaticSetName4() string { return r.ipsetName + "_s4" }
func (r *IPSet) StaticSetName6() string { return r.ipsetName + "_s6" }

func (r *IPSet) AddIPv4Subnet(subnet IPv4Subnet, timeout IPSetTimeout) error {
	r.locker.Lock()
	defer r.locker.Unlock()

	if !r.enabled.Load() {
		return nil
	}

	if timeout == nil {
		timeout = zeroTimeout
	}

	err := netlink.IpsetAdd(r.ipsetName+"_4", &netlink.IPSetEntry{
		IP:      subnet.Address[:],
		CIDR:    subnet.CIDR,
		Timeout: timeout,
		Replace: true,
	})
	if err != nil {
		return fmt.Errorf("failed to add address: %w", err)
	}

	return nil
}

func (r *IPSet) AddIPv6Subnet(subnet IPv6Subnet, timeout IPSetTimeout) error {
	r.locker.Lock()
	defer r.locker.Unlock()

	if !r.enabled.Load() {
		return nil
	}

	if timeout == nil {
		timeout = zeroTimeout
	}

	err := netlink.IpsetAdd(r.ipsetName+"_6", &netlink.IPSetEntry{
		IP:      subnet.Address[:],
		CIDR:    subnet.CIDR,
		Timeout: timeout,
		Replace: true,
	})
	if err != nil {
		return fmt.Errorf("failed to add address: %w", err)
	}

	return nil
}

func (r *IPSet) DelIPv4Subnet(subnet IPv4Subnet) error {
	r.locker.Lock()
	defer r.locker.Unlock()

	if !r.enabled.Load() {
		return nil
	}

	err := netlink.IpsetDel(r.ipsetName+"_4", &netlink.IPSetEntry{
		IP:   subnet.Address[:],
		CIDR: subnet.CIDR,
	})
	if err != nil && !errors.Is(err, nl.IPSetError(nl.IPSET_ERR_EXIST)) {
		return fmt.Errorf("failed to delete address: %w", err)
	}

	return nil
}

func (r *IPSet) DelIPv6Subnet(subnet IPv6Subnet) error {
	r.locker.Lock()
	defer r.locker.Unlock()

	if !r.enabled.Load() {
		return nil
	}

	err := netlink.IpsetDel(r.ipsetName+"_6", &netlink.IPSetEntry{
		IP:   subnet.Address[:],
		CIDR: subnet.CIDR,
	})
	if err != nil && !errors.Is(err, nl.IPSetError(nl.IPSET_ERR_EXIST)) {
		return fmt.Errorf("failed to delete address: %w", err)
	}

	return nil
}

func (r *IPSet) ListIPv4Subnets() (map[IPv4Subnet]IPSetTimeout, error) {
	r.locker.Lock()
	defer r.locker.Unlock()

	if !r.enabled.Load() {
		return nil, nil
	}

	return listSubnets4(r.ipsetName + "_4")
}

// listSubnets4 читает произвольный IPv4-сет по имени (основной или зеркало
// статических подсетей).
func listSubnets4(setName string) (map[IPv4Subnet]IPSetTimeout, error) {
	addresses := make(map[IPv4Subnet]IPSetTimeout)

	list, err := netlink.IpsetList(setName)
	if err != nil {
		return nil, err
	}
	for _, entry := range list.Entries {
		if len(entry.IP) != net.IPv4len {
			continue
		}
		cidr := entry.CIDR
		// Защита от нашего же CIDR=0-канона: hash:net всегда отдаёт CIDR, но
		// если атрибута вдруг нет (другой тип сета / другое ядро) — это host.
		if cidr == 0 {
			cidr = 32
		}
		subnet := IPv4Subnet{
			Address: [4]byte(entry.IP),
			CIDR:    cidr,
		}
		if entry.Timeout != nil && *entry.Timeout == 0 {
			addresses[subnet] = nil
		} else {
			addresses[subnet] = entry.Timeout
		}
	}

	return addresses, nil
}

func (r *IPSet) ListIPv6Subnets() (map[IPv6Subnet]IPSetTimeout, error) {
	r.locker.Lock()
	defer r.locker.Unlock()

	if !r.enabled.Load() {
		return nil, nil
	}

	return listSubnets6(r.ipsetName + "_6")
}

// listSubnets6 — IPv6-близнец listSubnets4.
func listSubnets6(setName string) (map[IPv6Subnet]IPSetTimeout, error) {
	addresses := make(map[IPv6Subnet]IPSetTimeout)

	list, err := netlink.IpsetList(setName)
	if err != nil {
		return nil, err
	}
	for _, entry := range list.Entries {
		if len(entry.IP) != net.IPv6len {
			continue
		}
		cidr := entry.CIDR
		// См. ListIPv4Subnets: отсутствующий CIDR = host-запись.
		if cidr == 0 {
			cidr = 128
		}
		subnet := IPv6Subnet{
			Address: [16]byte(entry.IP),
			CIDR:    cidr,
		}
		if entry.Timeout != nil && *entry.Timeout == 0 {
			addresses[subnet] = nil
		} else {
			addresses[subnet] = entry.Timeout
		}
	}

	return addresses, nil
}

// SyncStaticSubnets приводит зеркало статических подсетей к переданному списку:
// недостающие добавляет как permanent (timeout=0), лишние — удаляет. Список
// маленький (subnet-правила группы), листинг зеркала дешёвый.
//
// Зеркало используется только как негативный матч в правиле ipset-refresh
// (mt-bq8) — трафик по нему не маршрутизируется, поэтому расхождение на один
// цикл sync безопасно.
func (r *IPSet) SyncStaticSubnets(v4 []IPv4Subnet, v6 []IPv6Subnet) error {
	r.locker.Lock()
	defer r.locker.Unlock()

	if !r.enabled.Load() {
		return nil
	}

	var errs []error

	want4 := make(map[IPv4Subnet]struct{}, len(v4))
	for _, subnet := range v4 {
		want4[subnet] = struct{}{}
	}
	have4, err := listSubnets4(r.StaticSetName4())
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to list static mirror %s: %w", r.StaticSetName4(), err))
	}
	for subnet := range want4 {
		if _, ok := have4[subnet]; ok {
			continue
		}
		if err := netlink.IpsetAdd(r.StaticSetName4(), &netlink.IPSetEntry{
			IP:      subnet.Address[:],
			CIDR:    subnet.CIDR,
			Timeout: zeroTimeout,
			Replace: true,
		}); err != nil {
			errs = append(errs, fmt.Errorf("failed to mirror %s: %w", subnet.String(), err))
		}
	}
	for subnet := range have4 {
		if _, ok := want4[subnet]; ok {
			continue
		}
		if err := netlink.IpsetDel(r.StaticSetName4(), &netlink.IPSetEntry{
			IP:   subnet.Address[:],
			CIDR: subnet.CIDR,
		}); err != nil {
			errs = append(errs, fmt.Errorf("failed to unmirror %s: %w", subnet.String(), err))
		}
	}

	want6 := make(map[IPv6Subnet]struct{}, len(v6))
	for _, subnet := range v6 {
		want6[subnet] = struct{}{}
	}
	have6, err := listSubnets6(r.StaticSetName6())
	if err != nil {
		errs = append(errs, fmt.Errorf("failed to list static mirror %s: %w", r.StaticSetName6(), err))
	}
	for subnet := range want6 {
		if _, ok := have6[subnet]; ok {
			continue
		}
		if err := netlink.IpsetAdd(r.StaticSetName6(), &netlink.IPSetEntry{
			IP:      subnet.Address[:],
			CIDR:    subnet.CIDR,
			Timeout: zeroTimeout,
			Replace: true,
		}); err != nil {
			errs = append(errs, fmt.Errorf("failed to mirror %s: %w", subnet.String(), err))
		}
	}
	for subnet := range have6 {
		if _, ok := want6[subnet]; ok {
			continue
		}
		if err := netlink.IpsetDel(r.StaticSetName6(), &netlink.IPSetEntry{
			IP:   subnet.Address[:],
			CIDR: subnet.CIDR,
		}); err != nil {
			errs = append(errs, fmt.Errorf("failed to unmirror %s: %w", subnet.String(), err))
		}
	}

	return errors.Join(errs...)
}

func (r *IPSet) ipsetCreate() error {
	err := netlink.IpsetCreate(r.ipsetName+"_4", "hash:net", netlink.IpsetCreateOptions{
		Timeout: func(i uint32) *uint32 { return &i }(300),
		Family:  unix.AF_INET,
	})
	if err != nil {
		return fmt.Errorf("failed to create ipset: %w", err)
	}

	err = netlink.IpsetCreate(r.ipsetName+"_6", "hash:net", netlink.IpsetCreateOptions{
		Timeout: func(i uint32) *uint32 { return &i }(300),
		Family:  unix.AF_INET6,
	})
	if err != nil {
		return fmt.Errorf("failed to create ipset: %w", err)
	}

	// Зеркало статических подсетей: дефолтный timeout 0 = записи вечные, как и
	// сами subnet-правила. Сет создаётся всегда, даже если статических правил у
	// группы нет — пустой сет просто никогда не матчится, а правило TPROXY
	// остаётся одним и тем же независимо от конфига группы.
	err = netlink.IpsetCreate(r.StaticSetName4(), "hash:net", netlink.IpsetCreateOptions{
		Timeout: func(i uint32) *uint32 { return &i }(0),
		Family:  unix.AF_INET,
	})
	if err != nil {
		return fmt.Errorf("failed to create static mirror ipset: %w", err)
	}

	err = netlink.IpsetCreate(r.StaticSetName6(), "hash:net", netlink.IpsetCreateOptions{
		Timeout: func(i uint32) *uint32 { return &i }(0),
		Family:  unix.AF_INET6,
	})
	if err != nil {
		return fmt.Errorf("failed to create static mirror ipset: %w", err)
	}

	return nil
}

func (r *IPSet) ipsetDestroy() error {
	var errs []error
	for _, name := range []string{
		r.ipsetName + "_4",
		r.ipsetName + "_6",
		r.StaticSetName4(),
		r.StaticSetName6(),
	} {
		err := netlink.IpsetDestroy(name)
		if err != nil && !os.IsNotExist(err) {
			errs = append(errs, err)
		}
	}
	if errs != nil {
		return fmt.Errorf("failed to destroy ipsets: %w", errors.Join(errs...))
	}
	return nil
}

func (r *IPSet) enable() error {
	if !r.enabled.CompareAndSwap(false, true) {
		return nil
	}

	err := r.ipsetDestroy()
	if err != nil {
		return err
	}

	err = r.ipsetCreate()
	if err != nil {
		return err
	}

	return nil
}

func (r *IPSet) Enable() error {
	r.locker.Lock()
	defer r.locker.Unlock()

	err := r.enable()
	if err != nil {
		r.disable()
	}

	return err
}

func (r *IPSet) disable() error {
	if !r.enabled.Load() {
		return nil
	}
	defer r.enabled.Store(false)

	return r.ipsetDestroy()
}

func (r *IPSet) Disable() error {
	r.locker.Lock()
	defer r.locker.Unlock()

	return r.disable()
}

func (nh *Helper) IPSet(name string) *IPSet {
	return &IPSet{
		ipsetName: nh.IpsetPrefix + name,
	}
}
