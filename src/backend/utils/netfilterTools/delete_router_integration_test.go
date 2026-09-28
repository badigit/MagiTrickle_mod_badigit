//go:build integration && linux

package netfilterTools

import (
	"errors"
	"fmt"
	"net"
	"os"
	"testing"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

// This explicit opt-in probe is for kernels without network namespaces.
// It never installs policy rules or touches iptables or existing interfaces.
// Only unreferenced routes in an unused table and exclusively created ipsets
// are mutated. Full gateway and lifecycle tests still require a private netns.
func TestDeleteRouterProbeKernel(t *testing.T) {
	if os.Getenv("MT_DELETE_ROUTER_PROBE") != "1" || os.Geteuid() != 0 {
		t.Skip("requires explicit MT_DELETE_ROUTER_PROBE=1 and root")
	}
	table := 0x6e000000 + (os.Getpid() & 0xffff)
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		rules, err := netlink.RuleList(family)
		if err != nil {
			t.Fatal(err)
		}
		for _, rule := range rules {
			if rule.Table == table {
				t.Fatalf("refusing to use referenced table %d", table)
			}
		}
		routes, err := netlink.RouteListFiltered(family, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
		if err != nil || len(routes) != 0 {
			t.Fatalf("table %d not empty: %v %v", table, routes, err)
		}
	}
	t.Logf("temporary unreferenced table: %d", table)
	t.Run("ipset", func(t *testing.T) { testDeleteMissingIPSet(t, fmt.Sprintf("mt_del_%d", os.Getpid())) })
	for _, family := range []int{unix.AF_INET, unix.AF_INET6} {
		for _, metric := range []int{0, 10, 20} {
			t.Run(fmt.Sprintf("family%d/metric%d", family, metric), func(t *testing.T) {
				bits := 32
				if family == unix.AF_INET6 {
					bits = 128
				}
				route := &netlink.Route{Family: family, Table: table, Type: unix.RTN_BLACKHOLE, Priority: metric,
					Dst: &net.IPNet{IP: make(net.IP, bits/8), Mask: net.CIDRMask(0, bits)}}
				if err := netlink.RouteAdd(route); err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() {
					if err := netlink.RouteDel(route); err != nil && !errors.Is(err, unix.ESRCH) && !errors.Is(err, unix.ENOENT) {
						t.Errorf("cleanup: %v", err)
					}
				})
				if err := netlink.RouteDel(route); err != nil {
					t.Fatal(err)
				}
				if err := netlink.RouteDel(route); !errors.Is(err, unix.ESRCH) && !errors.Is(err, unix.ENOENT) {
					t.Fatalf("unexpected missing-route error: %v", err)
				} else {
					t.Logf("missing route: %v", err)
				}
				// No RuleAdd: there must never be a packet-routing path into this table.
				rule := netlink.NewRule()
				rule.Family, rule.Table, rule.Priority = family, table, table
				link, proxy := &IPSetToLink{}, &IPSetToTProxy{}
				if family == unix.AF_INET {
					link.ip4Rule, link.ip4Route[0], proxy.ip4Rule, proxy.ip4Route = rule, route, rule, route
				} else {
					link.ip6Rule, link.ip6Route[0], proxy.ip6Rule, proxy.ip6Route = rule, route, rule, route
				}
				for name, del := range map[string]func() error{"link-rule": link.deleteIPRule, "link-route": link.deleteIPRoute, "tproxy-rule": proxy.deleteIPRule, "tproxy-route": proxy.deleteIPRoute} {
					if err := del(); err != nil {
						t.Fatalf("%s: %v", name, err)
					}
				}
				// Re-create and remove the same route to check recovery after deletion.
				if err := netlink.RouteAdd(route); err != nil {
					t.Fatal(err)
				}
				if family == unix.AF_INET {
					proxy.ip4Route = route
				} else {
					proxy.ip6Route = route
				}
				if err := proxy.deleteIPRoute(); err != nil {
					t.Fatal(err)
				}
			})
		}
		remaining, err := netlink.RouteListFiltered(family, &netlink.Route{Table: table}, netlink.RT_FILTER_TABLE)
		if err != nil || len(remaining) != 0 {
			t.Fatalf("route cleanup: %v %v", remaining, err)
		}
	}
	runDeleteDeniedChild(t)
}
