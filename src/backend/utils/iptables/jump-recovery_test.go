//go:build testing

package iptables

import (
	"bytes"
	"context"
	"reflect"
	"testing"
)

func TestPREROUTINGRestoresSingleJumpInPlace(t *testing.T) {
	foreign := []string{"-m", "comment", "--comment", "foreign"}
	absolute := []string{"-j", "MT_DIRECT"}
	a, b := []string{"-j", "MT_A"}, []string{"-j", "MT_B"}
	want := [][]string{absolute, foreign, a, b}
	for _, table := range []string{"mangle", "nat"} {
		for _, tc := range []struct {
			name string
			lost [][]string
			want [][]string
		}{
			{"head", [][]string{foreign, a, b}, want},
			{"middle", [][]string{absolute, foreign, b}, want},
			{"tail", [][]string{absolute, foreign, a}, want},
			{"full flush", [][]string{foreign}, want},
			{"ambiguous gap", [][]string{absolute, foreign, {"-j", "RETURN"}, b}, [][]string{absolute, foreign, {"-j", "RETURN"}, b, a}},
		} {
			t.Run(table+"/"+tc.name, func(t *testing.T) {
				fake := NewFakeIPTables(ProtocolIPv4)
				fake.SetInitialRules(table, "PREROUTING", [][]string{foreign})
				ipt := NewIPTables(fake)
				if err := ipt.RegisterChainPatch(table, "PREROUTING"); err != nil {
					t.Fatal(err)
				}
				if err := ipt.Insert(table, "PREROUTING", 1, absolute...); err != nil {
					t.Fatal(err)
				}
				for _, jump := range [][]string{a, b} {
					if err := ipt.Append(table, "PREROUTING", jump...); err != nil {
						t.Fatal(err)
					}
				}
				if err := ipt.Commit(); err != nil {
					t.Fatal(err)
				}
				fake.SetInitialRules(table, "PREROUTING", tc.lost)
				if err := ipt.Commit(); err != nil {
					t.Fatal(err)
				}
				if got := fake.GetRules(table, "PREROUTING"); !reflect.DeepEqual(got, tc.want) {
					t.Fatalf("after repair: got %v, want %v", got, tc.want)
				}
				restores, saves := fake.RestoreCalls(), fake.SaveCalls()
				if err := ipt.Commit(); err != nil {
					t.Fatal(err)
				}
				if fake.RestoreCalls() != restores || fake.SaveCalls() != saves+1 {
					t.Fatal("healthy commit must only read the table")
				}
			})
		}
	}
}

func TestJumpReadbackRejectsOrderDrift(t *testing.T) {
	plan := patchRecovery{rule: "-j MT_A", anchors: jumpAnchors{before: "-j MT_LEFT", after: "-j MT_RIGHT"}}
	left := ruleFromStrings([]string{"-j", "MT_LEFT"})
	right := ruleFromStrings([]string{"-j", "MT_RIGHT"})
	jump := ruleFromStrings([]string{"-j", "MT_A"})
	newForeign := ruleFromStrings([]string{"-j", "RETURN"})
	for i, live := range [][]Rule{{left, jump, right}, {left, newForeign, jump, right}, {left, right, jump}, {left, jump, right, right}, {left, jump, right, jump}} {
		if _, verified := plan.check(live); verified != (i < 2) {
			t.Fatalf("case %d: verified jump should stay between unique anchors", i)
		}
	}
}

type jumpRaceExecutable struct {
	*FakeIPTables
	beforeInsertion func()
}

func (e *jumpRaceExecutable) Restore(ctx context.Context, data []byte) error {
	if e.beforeInsertion != nil && bytes.Contains(data, []byte("-I PREROUTING ")) {
		e.beforeInsertion()
		e.beforeInsertion = nil
	}
	return e.FakeIPTables.Restore(ctx, data)
}

func TestJumpRecoveryRetriesAfterConcurrentForeignInsert(t *testing.T) {
	foreign := []string{"-j", "DROP"}
	concurrent := []string{"-j", "RETURN"}
	a, b := []string{"-j", "MT_A"}, []string{"-j", "MT_B"}
	fake := NewFakeIPTables(ProtocolIPv4)
	fake.SetInitialRules("mangle", "PREROUTING", [][]string{foreign})
	exec := &jumpRaceExecutable{FakeIPTables: fake}
	ipt := NewIPTables(exec)
	if err := ipt.RegisterChainPatch("mangle", "PREROUTING"); err != nil {
		t.Fatal(err)
	}
	for _, jump := range [][]string{a, b} {
		if err := ipt.Append("mangle", "PREROUTING", jump...); err != nil {
			t.Fatal(err)
		}
	}
	if err := ipt.Commit(); err != nil {
		t.Fatal(err)
	}
	fake.SetInitialRules("mangle", "PREROUTING", [][]string{foreign, b})
	exec.beforeInsertion = func() {
		fake.SetInitialRules("mangle", "PREROUTING", [][]string{concurrent, foreign, b})
	}
	if err := ipt.Commit(); err == nil {
		t.Fatal("stale position must be reported")
	}
	if got := fake.GetRules("mangle", "PREROUTING"); !reflect.DeepEqual(got, [][]string{concurrent, foreign, b}) {
		t.Fatalf("rollback should only remove the misplaced jump, got %v", got)
	}
	if err := ipt.Commit(); err != nil {
		t.Fatal(err)
	}
	if got := fake.GetRules("mangle", "PREROUTING"); !reflect.DeepEqual(got, [][]string{concurrent, foreign, a, b}) {
		t.Fatalf("fresh commit failed to insert the missing rule in place: %v", got)
	}
}
