//go:build integration && linux

package netfilterTools

import (
	"errors"
	"net"
	"os"
	"testing"

	"github.com/vishvananda/netlink"
	"github.com/vishvananda/netlink/nl"
	"golang.org/x/sys/unix"
)

// Run the compiled test binary as root under unshare -n with
// MT_DELETE_TEST_NETNS=1. All kernel objects disappear with the namespace.
func requireDeleteTestNamespace(t *testing.T) {
	t.Helper()
	if os.Getenv("MT_DELETE_TEST_NETNS") != "1" || os.Geteuid() != 0 {
		t.Skip("requires root in a private network namespace and MT_DELETE_TEST_NETNS=1")
	}
	self, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	init, err := os.Readlink("/proc/1/ns/net")
	if err != nil || self == init {
		t.Fatal("refusing to run outside a private network namespace", err)
	}
}

func TestDeleteMissingIPSetKernel(t *testing.T) {
	requireDeleteTestNamespace(t)
	r := &IPSet{ipsetName: "mt_delete_test"}
	r.enabled.Store(true)
	v4 := IPv4Host([4]byte{192, 0, 2, 1})
	v6 := IPv6Host([16]byte(net.ParseIP("2001:db8::1").To16()))
	for _, tc := range []struct {
		name   string
		family uint8
		entry  *netlink.IPSetEntry
		add    func() error
		del    func() error
	}{
		{"_4", unix.AF_INET, &netlink.IPSetEntry{IP: v4.Address[:], CIDR: v4.CIDR},
			func() error { return r.AddIPv4Subnet(v4, nil) }, func() error { return r.DelIPv4Subnet(v4) }},
		{"_6", unix.AF_INET6, &netlink.IPSetEntry{IP: v6.Address[:], CIDR: v6.CIDR},
			func() error { return r.AddIPv6Subnet(v6, nil) }, func() error { return r.DelIPv6Subnet(v6) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			name := r.ipsetName + tc.name
			zero := uint32(0)
			if err := netlink.IpsetCreate(name, "hash:net", netlink.IpsetCreateOptions{Family: tc.family, Timeout: &zero}); err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = netlink.IpsetDestroy(name) })
			if err := tc.add(); err != nil {
				t.Fatal(err)
			}
			if err := tc.del(); err != nil {
				t.Fatalf("delete existing entry: %v", err)
			}
			if err := netlink.IpsetDel(name, tc.entry); !errors.Is(err, nl.IPSetError(nl.IPSET_ERR_EXIST)) {
				t.Fatalf("expected kernel missing-entry error, got %v", err)
			}
			if err := tc.del(); err != nil {
				t.Fatalf("delete missing entry: %v", err)
			}
			if err := netlink.IpsetDestroy(name); err != nil {
				t.Fatal(err)
			}
			if err := tc.del(); err == nil {
				t.Fatal("missing SET must remain an error")
			}
		})
	}
}

func TestDeleteMissingRoutesAndRulesKernel(t *testing.T) {
	requireDeleteTestNamespace(t)
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		t.Logf("address family: %d", family)
		rule := netlink.NewRule()
		rule.Family, rule.Table, rule.Priority = family, 31991, 31991
		route := &netlink.Route{Family: family, Table: 31991, Type: unix.RTN_BLACKHOLE}
		bits := 32
		if family == unix.AF_INET6 {
			bits = 128
		}
		route.Dst = &net.IPNet{IP: make(net.IP, bits/8), Mask: net.CIDRMask(0, bits)}
		// Keep the table alive even after deleting its default route.
		anchor := *route
		anchor.Dst = &net.IPNet{IP: net.ParseIP("192.0.2.1").To4(), Mask: net.CIDRMask(32, 32)}
		if family == unix.AF_INET6 {
			anchor.Dst = &net.IPNet{IP: net.ParseIP("2001:db8::1"), Mask: net.CIDRMask(128, 128)}
		}
		if err := netlink.RouteAdd(&anchor); err != nil {
			t.Fatal(err)
		}
		r := &IPSetToLink{}
		assign := func() {
			if family == unix.AF_INET {
				r.ip4Rule, r.ip4Route[0] = rule, route
			} else {
				r.ip6Rule, r.ip6Route[0] = rule, route
			}
		}
		if err := netlink.RuleAdd(rule); err != nil {
			t.Fatal(err)
		}
		if err := netlink.RouteAdd(route); err != nil {
			t.Fatal(err)
		}
		assign()
		if err := r.deleteIPRule(); err != nil {
			t.Fatal(err)
		}
		if err := r.deleteIPRoute(); err != nil {
			t.Fatal(err)
		}
		if err := netlink.RuleDel(rule); !errors.Is(err, unix.ENOENT) {
			t.Fatalf("expected ENOENT, got %v", err)
		}
		if err := netlink.RouteDel(route); !errors.Is(err, unix.ESRCH) && !errors.Is(err, unix.ENOENT) {
			t.Fatalf("expected ESRCH or ENOENT, got %v", err)
		}
		assign() // Retained references after the kernel already removed the objects.
		if err := r.deleteIPRule(); err != nil {
			t.Fatalf("delete missing rule: %v", err)
		}
		if err := r.deleteIPRoute(); err != nil {
			t.Fatalf("delete missing route: %v", err)
		}
		if r.ip4Rule != nil || r.ip6Rule != nil || r.ip4Route[0] != nil || r.ip6Route[0] != nil {
			t.Fatal("deleted object references were not cleared")
		}
	}
	badRule := netlink.NewRule()
	badRule.Family = 255
	badRoute := &netlink.Route{Dst: &net.IPNet{IP: net.IPv4(192, 0, 2, 0), Mask: net.CIDRMask(24, 32)}, Gw: net.ParseIP("2001:db8::1")}
	r := &IPSetToLink{ip4Rule: badRule, ip4Route: [2]*netlink.Route{badRoute, nil}}
	if err := r.deleteIPRule(); err == nil {
		t.Fatal("invalid rule family must remain an error")
	}
	if err := r.deleteIPRoute(); err == nil {
		t.Fatal("invalid route gateway family must remain an error")
	}
}
