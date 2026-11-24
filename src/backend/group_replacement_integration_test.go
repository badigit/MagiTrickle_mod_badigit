//go:build integration && linux

package magitrickle

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	v1 "magitrickle/api/v1"
	"magitrickle/config"
	"magitrickle/models"
	"magitrickle/utils/intID"
	"magitrickle/utils/netfilterTools"
	"magitrickle/utils/recordsCache"

	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestGroupReplacementRollbackInNetNS(t *testing.T) {
	if os.Getenv("MT_GROUP_REPLACEMENT_NETNS") != "1" || os.Geteuid() != 0 {
		t.Skip("requires root in a private network namespace and MT_GROUP_REPLACEMENT_NETNS=1")
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
		t.Fatal("refusing to change netfilter outside a private network namespace")
	}

	a := newApp()
	a.recordsCache = recordsCache.New()
	oldAddress := [4]byte{192, 0, 2, 11}
	a.recordsCache.AddAddress("old.example", net.IP(oldAddress[:]), 60)
	oldID, goodID, badID, subID, disabledID := intID.ID{1}, intID.ID{2}, intID.ID{3}, intID.ID{4}, intID.ID{5}
	oldGroups := []config.Group{{
		ID: oldID, Name: "old", Interface: models.InterfaceDirect,
		Rules: []config.Rule{{Type: models.RuleTypeDomain, Rule: "old.example", Enable: true}},
	}}
	subs := []config.Subscription{{ID: subID, Name: "sub", Interface: models.InterfaceDirect}}
	if err := a.ImportConfig(config.Config{ConfigVersion: "0.1.4", Groups: &oldGroups, Subscriptions: &subs}); err != nil {
		t.Fatal(err)
	}
	a.nfHelper, err = netfilterTools.New("MTR_", "mtr_", false, true, 31000)
	if err != nil {
		t.Fatal(err)
	}
	a.nfHelper.SetDirectPriorityByOrder(true)
	for _, chain := range []struct{ table, name string }{
		{"filter", "FORWARD"}, {"mangle", "PREROUTING"}, {"nat", "PREROUTING"}, {"nat", "POSTROUTING"},
	} {
		if err := a.nfHelper.IPTables4.RegisterChainPatch(chain.table, chain.name); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := a.nfHelper.SetupClientBypass(nil); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := a.bringDownRouting(); err != nil {
			t.Errorf("tear down test routing: %v", err)
		}
		if err := a.nfHelper.DestroyClientBypass(); err != nil {
			t.Errorf("remove test client bypass sets: %v", err)
		}
	})
	if err := a.bringUpRouting(); err != nil {
		t.Fatal(err)
	}
	old := a.Groups()[0]
	oldSub := a.Subscriptions()[0]
	iptables := func(args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, "iptables", args...).CombinedOutput()
		if err != nil {
			t.Fatalf("iptables %v: %v (%s)", args, err, out)
		}
		return string(out)
	}
	before := iptables("-t", "mangle", "-S", "PREROUTING")
	checkOld := func() {
		t.Helper()
		groups := a.Groups()
		if len(groups) != 1 || groups[0] != old || old.Model().Name != "old" || !old.Enabled() {
			t.Fatalf("old group not restored: %v", groups)
		}
		if a.Subscriptions()[0] != oldSub {
			t.Fatal("changed subscription model")
		}
		if winner, _, found := a.SearchDomainVerdict("old.example"); !found || winner != old {
			t.Fatal("old DNS verdict not restored")
		}
		ipset, err := old.ListIPv4Subnets()
		if err != nil {
			t.Fatal(err)
		}
		if _, ok := ipset[netfilterTools.IPv4Host(oldAddress)]; !ok {
			t.Fatal("previous DNS address was not restored in the kernel ipset")
		}
		if got := iptables("-t", "mangle", "-S", "PREROUTING"); got != before {
			t.Fatalf("kernel group order changed:\n%s\nwant:\n%s", got, before)
		}
	}
	put := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPut, "/groups", strings.NewReader(body))
		w := httptest.NewRecorder()
		v1.NewHandler(a).PutGroups(w, req)
		return w
	}
	dup := put(fmt.Sprintf(`{"groups":[{"id":%q,"name":"changed","interface":"direct"},{"id":%q,"name":"duplicate","interface":"direct"}]}`, oldID.String(), oldID.String()))
	if dup.Code != http.StatusBadRequest {
		t.Fatalf("duplicate ID: HTTP %d, %s", dup.Code, dup.Body)
	}
	checkOld()

	// Hold a reference to the second new group's set in an unrelated chain.
	// The kernel rejects its destruction after the first new group has applied.
	busySet := "mtr_" + badID.String() + "_4"
	if err := netlink.IpsetCreate(busySet, "hash:net", netlink.IpsetCreateOptions{Family: unix.AF_INET}); err != nil {
		t.Fatal(err)
	}
	iptables("-N", "HOLD_SET")
	t.Cleanup(func() {
		iptables("-F", "HOLD_SET")
		iptables("-X", "HOLD_SET")
		if err := netlink.IpsetDestroy(busySet); err != nil {
			t.Errorf("remove held test set: %v", err)
		}
	})
	iptables("-A", "HOLD_SET", "-m", "set", "--match-set", busySet, "dst", "-j", "ACCEPT")
	bad := put(fmt.Sprintf(`{"groups":[{"id":%q,"name":"first","interface":"direct"},{"id":%q,"name":"second","interface":"direct"}]}`, goodID.String(), badID.String()))
	if bad.Code != http.StatusInternalServerError || !strings.Contains(bad.Body.String(), "second") {
		t.Fatalf("kernel failure: HTTP %d, %s", bad.Code, bad.Body)
	}
	checkOld()

	newGroups := []config.Group{{ID: goodID, Interface: models.InterfaceDirect}, {ID: badID, Name: "second", Interface: models.InterfaceDirect}}
	newTTL := uint32(11)
	if err := a.ImportConfig(config.Config{ConfigVersion: "0.1.4", Groups: &newGroups,
		App: &config.App{DNSProxy: &config.DNSProxy{ClientTTLCap: &newTTL}},
	}); err == nil || !strings.Contains(err.Error(), "second") {
		t.Fatalf("failed reload must report the second group: %v", err)
	}
	if a.Config().DNSProxy.ClientTTLCap == newTTL {
		t.Fatal("failed reload changed DNS settings")
	}
	checkOld()

	ok := put(fmt.Sprintf(`{"groups":[{"id":%q,"name":"new","interface":"direct"},{"id":%q,"name":"disabled","interface":"direct","enable":false,"rules":[{"type":"domain","rule":"disabled.example","enable":true}]}]}`,
		goodID.String(), disabledID.String()))
	if ok.Code != http.StatusOK || len(a.Groups()) != 2 || a.Groups()[0].Model().Name != "new" {
		t.Fatalf("successful replacement: HTTP %d, %s", ok.Code, ok.Body)
	}
	checkOrderAndDisabledGroup := func() {
		t.Helper()
		if a.Groups()[1].Model().Enable {
			t.Fatal("replacement changed the disabled group's configuration")
		}
		after := iptables("-t", "mangle", "-S", "PREROUTING")
		userPos := strings.Index(after, "MTR_"+goodID.String())
		subPos := strings.Index(after, "MTR_s"+subID.String())
		if userPos < 0 || subPos < 0 || userPos >= subPos {
			t.Fatalf("user groups must precede subscriptions:\n%s", after)
		}
		if strings.Contains(after, "MTR_"+disabledID.String()) {
			t.Fatal("replacement activated a disabled group")
		}
		if _, _, matched := a.SearchDomainVerdict("disabled.example"); matched {
			t.Fatal("replacement installed a DNS rule for a disabled group")
		}
	}
	checkOrderAndDisabledGroup()
	disabled := false
	newGroups = []config.Group{
		{ID: goodID, Name: "new", Interface: models.InterfaceDirect},
		{ID: disabledID, Name: "disabled", Interface: models.InterfaceDirect, Enable: &disabled,
			Rules: []config.Rule{{Type: models.RuleTypeDomain, Rule: "disabled.example", Enable: true}}},
	}
	if err := a.ImportConfig(config.Config{ConfigVersion: "0.1.4", Groups: &newGroups}); err != nil {
		t.Fatalf("reload with disabled group: %v", err)
	}
	checkOrderAndDisabledGroup()
}
