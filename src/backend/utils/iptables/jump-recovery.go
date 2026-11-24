package iptables

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"

	"github.com/rs/zerolog/log"
)

// jumpAnchors are the immediate neighbors established at the last setup.
// An empty neighbor represents the corresponding end of the chain.
type jumpAnchors struct {
	before, after string
}

type chainLocation struct{ table, chain string }

type patchRecovery struct {
	patch    *chainPatch
	revision uint64
	observe  bool
	expected []Rule
	rule     string
	jump     Rule
	anchors  jumpAnchors
}

func (c *chainPatch) planRecovery(table string, chain []byte, live []Rule) ([]command, patchRecovery) {
	c.sync.RLock()
	defer c.sync.RUnlock()
	commands := c.compile(chain, live)
	plan := patchRecovery{patch: c, revision: c.revision, observe: c.anchors == nil}
	if plan.observe {
		return commands, plan
	}

	missing := 0
	for _, cmd := range commands {
		if cmd.Option == optionAppend || cmd.Option == optionInsert {
			missing++
		}
	}
	if missing == 0 || missing == len(c.anchors) && len(c.anchors) > 1 {
		// A full loss uses the usual head/tail placement in the new table.
		plan.observe = missing > 0
		return commands, plan
	}
	if len(commands) == 1 && missing == 1 {
		rule := commands[0].Rule.String()
		if anchors, known := c.anchors[rule]; known {
			if pos := anchors.position(live); pos >= 0 {
				commands[0].Option, commands[0].RuleNum = optionInsert, pos+1
				plan.rule, plan.jump, plan.anchors = rule, commands[0].Rule, anchors
				return commands, plan
			}
		}
	}
	// Keep the established anchors. Standard placement can change the priority
	// of the missing jump, so it should not set the target for future recovery.
	log.Warn().Str("table", table).Bytes("chain", chain).Int("missing", missing).
		Msg("iptables jump position is ambiguous; using standard placement")
	return commands, plan
}

// position returns the insertion index if both anchors are unique and adjacent.
func (a jumpAnchors) position(live []Rule) int {
	before, after := -1, len(live)
	for i, rule := range live {
		key := rule.String()
		if a.before != "" && key == a.before {
			if before != -1 {
				return -1
			}
			before = i
		}
		if a.after != "" && key == a.after {
			if after != len(live) {
				return -1
			}
			after = i
		}
	}
	if (a.before != "" && before == -1) || (a.after != "" && after == len(live)) || after != before+1 {
		return -1
	}
	return after
}

func (p patchRecovery) check(live []Rule) (count int, verified bool) {
	before, after, index := -1, len(live), -1
	var leftMatches, rightMatches int
	for i, rule := range live {
		key := rule.String()
		switch {
		case key == p.rule:
			index = i
			count++
		case p.anchors.before != "" && key == p.anchors.before:
			before = i
			leftMatches++
		case p.anchors.after != "" && key == p.anchors.after:
			after = i
			rightMatches++
		}
	}
	// The firmware may interleave new rules after insertion. Only crossing an
	// original anchor makes a verified insertion unsafe.
	leftOK := p.anchors.before == "" || leftMatches == 1
	rightOK := p.anchors.after == "" || rightMatches == 1
	return count, count == 1 && leftOK && rightOK && before < index && index < after
}

// checkJumpRecoveries verifies positional writes against a fresh snapshot. When
// an external writer moved the gap, undo the misplaced jump by specification.
// A later CommitWithRetry pass can then recompute its position from a new save.
func (ipt *IPTables) checkJumpRecoveries(ctx context.Context, tables map[string]map[string][]Rule, justRestored bool) error {
	var rollback bytes.Buffer
	var issues []error
	for location, pending := range ipt.pendingJumpChecks {
		count, verified := pending.check(tables[location.table][location.chain])
		switch {
		case verified:
			delete(ipt.pendingJumpChecks, location)
		case count == 0:
			delete(ipt.pendingJumpChecks, location)
			if justRestored {
				issues = append(issues, fmt.Errorf("iptables jump %q disappeared after restore in %s/%s", pending.rule, location.table, location.chain))
			}
		default:
			fmt.Fprintf(&rollback, "*%s\n", location.table)
			for i := 0; i < count; i++ {
				fmt.Fprintf(&rollback, "-D %s ", location.chain)
				ruleWriteTo(&rollback, pending.jump)
				rollback.WriteByte('\n')
			}
			rollback.WriteString("COMMIT\n")
			issues = append(issues, fmt.Errorf("iptables jump %q did not land between its anchors in %s/%s", pending.rule, location.table, location.chain))
		}
	}
	if rollback.Len() > 0 {
		if err := ipt.executable.Restore(ctx, rollback.Bytes()); err != nil {
			issues = append(issues, fmt.Errorf("undo misplaced iptables jump: %w", err))
		}
	}
	return errors.Join(issues...)
}

func (p patchRecovery) record(live []Rule) {
	c := p.patch
	c.sync.Lock()
	defer c.sync.Unlock()
	if c.revision != p.revision {
		return
	}
	wanted := make(map[string]struct{})
	for _, entry := range c.orderedRules {
		if entry.Option != optionDelete {
			wanted[entry.Rule.String()] = struct{}{}
		}
	}
	observed := make(map[string]jumpAnchors, len(wanted))
	for i, rule := range live {
		key := rule.String()
		if _, ok := wanted[key]; !ok {
			continue
		}
		if _, duplicate := observed[key]; duplicate {
			return
		}
		var anchors jumpAnchors
		if i > 0 {
			anchors.before = live[i-1].String()
		}
		if i+1 < len(live) {
			anchors.after = live[i+1].String()
		}
		observed[key] = anchors
	}
	if len(observed) == len(wanted) {
		c.anchors = observed
	}
}

// projectPatch returns the expected layout after a successful restore. Recovery
// still checks its neighbors in a fresh save before and after a positional write.
func projectPatch(live []Rule, commands []command) []Rule {
	live = slices.Clone(live)
	for _, cmd := range commands {
		switch cmd.Option {
		case optionAppend:
			live = append(live, cmd.Rule)
		case optionInsert:
			if cmd.RuleNum < 1 || cmd.RuleNum > len(live)+1 {
				return nil
			}
			live = slices.Insert(live, cmd.RuleNum-1, cmd.Rule)
		case optionDelete:
			for i, rule := range live {
				if ruleEqual(rule, cmd.Rule) {
					live = slices.Delete(live, i, i+1)
					break
				}
			}
		}
	}
	return live
}
