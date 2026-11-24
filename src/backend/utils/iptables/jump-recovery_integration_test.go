//go:build integration && linux

package iptables

import (
	"context"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func TestPREROUTINGJumpRecoveryKernel(t *testing.T) {
	if os.Getenv("MT_JUMP_RECOVERY_NETNS") != "1" {
		t.Skip("run under unshare -n with MT_JUMP_RECOVERY_NETNS=1")
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
		t.Fatal("refusing to change iptables outside an isolated network namespace")
	}
	run := func(binary string, args ...string) string {
		t.Helper()
		ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
		defer cancel()
		out, err := exec.CommandContext(ctx, binary, args...).CombinedOutput()
		if err != nil {
			t.Fatalf("%s %v: %v: %s", binary, args, err, out)
		}
		return string(out)
	}
	run("ip", "link", "set", "lo", "up")
	for _, tc := range []struct {
		name, binary, save, family, address string
		executable                          Executable
	}{
		{"ipv4", "iptables", "iptables-save", "-4", "127.0.0.1", NewRealIPTables()},
		{"ipv6", "ip6tables", "ip6tables-save", "-6", "::1", NewRealIP6Tables()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run(tc.binary, "-t", "mangle", "-A", "PREROUTING", "-m", "comment", "--comment", "foreign")
			ipt := NewIPTables(tc.executable)
			if err := ipt.RegisterChainPatch("mangle", "PREROUTING"); err != nil {
				t.Fatal(err)
			}
			for _, chain := range []string{"MT_A", "MT_B"} {
				run(tc.binary, "-t", "mangle", "-N", chain)
				run(tc.binary, "-t", "mangle", "-A", chain, "-d", tc.address, "-j", "ACCEPT")
				if err := ipt.Append("mangle", "PREROUTING", "-i", "lo", "-j", chain); err != nil {
					t.Fatal(err)
				}
			}
			checkWinner := func() {
				t.Helper()
				run(tc.binary, "-t", "mangle", "-Z")
				run("ping", tc.family, "-c", "1", "-W", "1", tc.address)
				table := run(tc.save, "-c", "-t", "mangle")
				foreign := strings.Index(table, "-A PREROUTING -m comment --comment foreign")
				first := strings.Index(table, "-A PREROUTING -i lo -j MT_A")
				second := strings.Index(table, "-A PREROUTING -i lo -j MT_B")
				if foreign < 0 || first <= foreign || second <= first ||
					strings.Contains(table, "[0:0] -A MT_A ") || !strings.Contains(table, "[0:0] -A MT_B ") {
					t.Fatalf("foreign rule or winning chain changed:\n%s", table)
				}
			}
			if err := ipt.Commit(); err != nil {
				t.Fatal(err)
			}
			checkWinner()
			run(tc.binary, "-t", "mangle", "-D", "PREROUTING", "-i", "lo", "-j", "MT_A")
			if err := ipt.Commit(); err != nil {
				t.Fatal(err)
			}
			checkWinner()
		})
	}
}
