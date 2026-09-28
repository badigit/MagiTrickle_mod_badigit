//go:build integration && linux

package netfilterTools

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"

	"magitrickle/utils/iptables"

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
	if err != nil {
		t.Fatal(err)
	}
	if self == init {
		t.Fatal("refusing to run outside a private network namespace")
	}
}

func TestDeleteMissingIPSetKernel(t *testing.T) {
	requireDeleteTestNamespace(t)
	testDeleteMissingIPSet(t, "mt_delete_test")
}

func testDeleteMissingIPSet(t *testing.T, prefix string) {
	r := &IPSet{ipsetName: prefix}
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
		for _, metric := range []int{0, 10, 20} {
			t.Run(fmt.Sprintf("family%d/metric%d", family, metric), func(t *testing.T) {
				rule := netlink.NewRule()
				rule.Family, rule.Table, rule.Priority = family, 31991+metric, 31991
				route := &netlink.Route{Family: family, Table: rule.Table, Type: unix.RTN_BLACKHOLE, Priority: metric}
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
				} else {
					t.Logf("missing route: %v", err)
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
			})
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

func TestDeleteTPROXYKernel(t *testing.T) {
	requireDeleteTestNamespace(t)
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatal(err)
	}
	r := &IPSetToTProxy{table: 32030, mark: 32030, nh: &Helper{IPTables4: new(iptables.IPTables), IPTables6: new(iptables.IPTables)}}
	for cycle := 0; cycle < 2; cycle++ {
		if err := r.insertIPRule(); err != nil {
			t.Fatal(err)
		}
		if err := r.insertIPRoute(); err != nil {
			t.Fatal(err)
		}
		for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
			routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: r.table}, netlink.RT_FILTER_TABLE)
			if err != nil || len(routes) != 1 || routes[0].Type != unix.RTN_LOCAL {
				t.Fatalf("cycle %d family %d: routes=%v err=%v", cycle, family, routes, err)
			}
		}
		// Simulate external cleanup while the objects still retain their references.
		for _, rule := range []*netlink.Rule{r.ip4Rule, r.ip6Rule} {
			if err := netlink.RuleDel(rule); err != nil {
				t.Fatal(err)
			}
		}
		for _, route := range []*netlink.Route{r.ip4Route, r.ip6Route} {
			if err := netlink.RouteDel(route); err != nil {
				t.Fatal(err)
			}
		}
		if err := r.deleteIPRule(); err != nil {
			t.Fatal(err)
		}
		if err := r.deleteIPRoute(); err != nil {
			t.Fatal(err)
		}
		if r.ip4Rule != nil || r.ip6Rule != nil || r.ip4Route != nil || r.ip6Route != nil {
			t.Fatal("stale TPROXY references")
		}
	}
}

func TestDeleteMissingGatewayKernel(t *testing.T) {
	requireDeleteTestNamespace(t)
	link := &netlink.Dummy{LinkAttrs: netlink.LinkAttrs{Name: "mt_delete_gw"}}
	if err := netlink.LinkAdd(link); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = netlink.LinkDel(link) })
	if err := netlink.LinkSetUp(link); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		family                int
		address, oldGW, newGW string
	}{
		{unix.AF_INET, "192.0.2.10/24", "192.0.2.1", "192.0.2.2"},
		{unix.AF_INET6, "2001:db8::10/64", "2001:db8::1", "2001:db8::2"},
	} {
		t.Run(fmt.Sprint(tc.family), func(t *testing.T) {
			addr, err := netlink.ParseAddr(tc.address)
			if err != nil {
				t.Fatal(err)
			}
			addr.Flags = unix.IFA_F_NODAD
			if err := netlink.AddrAdd(link, addr); err != nil {
				t.Fatal(err)
			}
			mainRoute := &netlink.Route{Family: tc.family, LinkIndex: link.Attrs().Index, Gw: net.ParseIP(tc.oldGW), Table: unix.RT_TABLE_MAIN, Priority: 100}
			if err := netlink.RouteAdd(mainRoute); err != nil {
				t.Fatal(err)
			}
			r := &IPSetToLink{table: 32040, ifaceName: link.Attrs().Name}
			current, err := r.updateIfaceRoute(link, tc.family, nil)
			if err != nil || current == nil {
				t.Fatalf("initial route: %v %v", current, err)
			}
			if err := netlink.RouteDel(current); err != nil {
				t.Fatal(err)
			}
			mainRoute.Gw = net.ParseIP(tc.newGW)
			if err := netlink.RouteReplace(mainRoute); err != nil {
				t.Fatal(err)
			}
			next, err := r.updateIfaceRoute(link, tc.family, current)
			if err != nil || next == nil || !next.Gw.Equal(mainRoute.Gw) {
				t.Fatalf("gateway replacement: %v %v", next, err)
			}
			routes, err := netlink.RouteListFiltered(tc.family, &netlink.Route{Table: r.table}, netlink.RT_FILTER_TABLE)
			if err != nil || len(routes) != 1 || !routes[0].Gw.Equal(mainRoute.Gw) || routes[0].Priority != 10 {
				t.Fatalf("kernel route: %v %v", routes, err)
			}
		})
	}
}

func TestDeleteDeniedKernel(t *testing.T) {
	if os.Getenv("MT_DELETE_TEST_UNPRIV") != "1" {
		requireDeleteTestNamespace(t)
		runDeleteDeniedChild(t)
		return
	}
	if os.Geteuid() == 0 {
		t.Fatal("permission test must run without root")
	}
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rule := netlink.NewRule()
		rule.Family, rule.Table, rule.Priority = family, 32050, 32050
		bits := 32
		if family == unix.AF_INET6 {
			bits = 128
		}
		route := &netlink.Route{Family: family, Table: rule.Table, Type: unix.RTN_BLACKHOLE, Priority: 20, Dst: &net.IPNet{IP: make(net.IP, bits/8), Mask: net.CIDRMask(0, bits)}}
		link := &IPSetToLink{}
		proxy := &IPSetToTProxy{}
		if family == unix.AF_INET {
			link.ip4Rule, link.ip4Route[0], proxy.ip4Rule, proxy.ip4Route = rule, route, rule, route
		} else {
			link.ip6Rule, link.ip6Route[0], proxy.ip6Rule, proxy.ip6Route = rule, route, rule, route
		}
		for name, del := range map[string]func() error{"link-rule": link.deleteIPRule, "link-route": link.deleteIPRoute, "tproxy-rule": proxy.deleteIPRule, "tproxy-route": proxy.deleteIPRoute} {
			if err := del(); !errors.Is(err, unix.EPERM) {
				t.Fatalf("%s family %d: expected kernel EPERM, got %v", name, family, err)
			}
		}
	}
	set := &IPSet{ipsetName: "mt_delete_denied"}
	set.enabled.Store(true)
	for _, err := range []error{set.DelIPv4Subnet(IPv4Host([4]byte{192, 0, 2, 1})), set.DelIPv6Subnet(IPv6Host([16]byte(net.ParseIP("2001:db8::1").To16())))} {
		if !errors.Is(err, unix.EPERM) {
			t.Fatalf("ipset: expected kernel EPERM, got %v", err)
		}
	}
}

func runDeleteDeniedChild(t *testing.T) {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, exe, "-test.run=^TestDeleteDeniedKernel$", "-test.v", "-test.timeout=10s")
	cmd.Env = append(os.Environ(), "MT_DELETE_TEST_UNPRIV=1")
	cmd.SysProcAttr = &syscall.SysProcAttr{Credential: &syscall.Credential{Uid: 65534, Gid: 65534}}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("unprivileged child: %v\n%s", err, out)
	}
	t.Logf("%s", out)
}

func TestDeleteTPROXYLifecycleKernel(t *testing.T) {
	requireDeleteTestNamespace(t)
	lo, err := netlink.LinkByName("lo")
	if err != nil {
		t.Fatal(err)
	}
	if err := netlink.LinkSetUp(lo); err != nil {
		t.Fatal(err)
	}
	nh, err := New("MT_DEL_", "mt_del_life_", false, false, 32100)
	if err != nil {
		t.Fatal(err)
	}
	for _, ipt := range []*iptables.IPTables{nh.IPTables4, nh.IPTables6} {
		for _, pair := range [][2]string{{"nat", "PREROUTING"}, {"mangle", "PREROUTING"}} {
			if err := ipt.RegisterChainPatch(pair[0], pair[1]); err != nil {
				t.Fatal(err)
			}
		}
	}
	if _, err := nh.SetupClientBypass(nil); err != nil {
		t.Fatal(err)
	}
	set := nh.IPSet("probe")
	r := nh.IPSetToTProxy("probe", 15001, set, 0)
	t.Cleanup(func() {
		_ = r.Disable()
		_ = nh.IPTables4.Commit()
		_ = nh.IPTables6.Commit()
		_ = set.Disable()
		_ = nh.DestroyClientBypass()
	})
	for cycle := 0; cycle < 2; cycle++ {
		if err := set.Enable(); err != nil {
			t.Fatal(err)
		}
		if err := r.Enable(); err != nil {
			t.Fatal(err)
		}
		for _, ipt := range []*iptables.IPTables{nh.IPTables4, nh.IPTables6} {
			if err := ipt.Commit(); err != nil {
				t.Fatal(err)
			}
		}
		for _, binary := range []string{"iptables-save", "ip6tables-save"} {
			out := deleteTestCommand(t, binary)
			if !strings.Contains(out, "-j MT_DEL_probe") || !strings.Contains(out, "-j TPROXY") {
				t.Fatalf("cycle %d: missing committed TPROXY rules: %s", cycle, out)
			}
		}
		for _, address := range []string{"198.51.100.10", "2001:db8:abcd::10"} {
			routes, err := netlink.RouteGetWithOptions(net.ParseIP(address), &netlink.RouteGetOptions{Mark: r.mark})
			if err != nil || len(routes) != 1 || routes[0].Type != unix.RTN_LOCAL {
				t.Fatalf("cycle %d: marked routing %s: %v %v", cycle, address, routes, err)
			}
		}
		for _, rule := range []*netlink.Rule{r.ip4Rule, r.ip6Rule} {
			if err := netlink.RuleDel(rule); err != nil {
				t.Fatal(err)
			}
		}
		for _, route := range []*netlink.Route{r.ip4Route, r.ip6Route} {
			if err := netlink.RouteDel(route); err != nil {
				t.Fatal(err)
			}
		}
		if err := r.Disable(); err != nil {
			t.Fatalf("stop after external cleanup: %v", err)
		}
		for _, ipt := range []*iptables.IPTables{nh.IPTables4, nh.IPTables6} {
			if err := ipt.Commit(); err != nil {
				t.Fatal(err)
			}
		}
		if err := set.Disable(); err != nil {
			t.Fatal(err)
		}
		for _, binary := range []string{"iptables-save", "ip6tables-save"} {
			if out := deleteTestCommand(t, binary); strings.Contains(out, "MT_DEL_probe") {
				t.Fatalf("leftover chain after stop: %s", out)
			}
		}
		for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
			routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: r.table}, netlink.RT_FILTER_TABLE)
			if err != nil || len(routes) != 0 {
				t.Fatalf("leftover routes: %v %v", routes, err)
			}
		}
	}
}

func deleteTestCommand(t *testing.T, binary string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, binary).CombinedOutput()
	if err != nil {
		t.Fatalf("%s: %v: %s", binary, err, out)
	}
	return string(out)
}
