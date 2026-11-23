package iptables

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

type Protocol byte

const (
	ProtocolIPv4 Protocol = 0
	ProtocolIPv6 Protocol = 1
)

var (
	ErrChainNotInitialized = errors.New("chain not initialized")
)

type IPTables struct {
	rules      map[string]map[string]chain
	executable Executable
	sync       sync.RWMutex

	// commitMu сериализует коммиты между собой. См. CommitContext.
	commitMu sync.Mutex
	// A positional restore may have reached the kernel even on cancellation.
	pendingJumpChecks map[chainLocation]patchRecovery // guarded by commitMu

	// deferred включает батч-режим: Commit() не ходит в ядро, а лишь копит
	// правила в rules. Нужен для массовых операций (teardown/bring-up всех
	// групп), где каждый Commit — отдельная пара iptables-save/restore: на
	// проде это давало 76 обращений к ядру за 6с при снятии 38 групп и 152 при
	// подъёме, причём линейно по числу групп (mt-jou). Под батчем цена
	// становится константной. Снимать флаг обязан тот, кто его поставил —
	// см. Helper.Batch, который делает это через defer.
	deferred atomic.Bool
}

func NewIPTables(executable Executable) *IPTables {
	return &IPTables{
		rules:      make(map[string]map[string]chain),
		executable: executable,
	}
}

func (ipt *IPTables) Proto() Protocol {
	return ipt.executable.Proto()
}

func (ipt *IPTables) RegisterChainDelete(table, chainName string) error {
	ipt.sync.Lock()
	defer ipt.sync.Unlock()

	if _, ok := ipt.rules[table]; !ok {
		ipt.rules[table] = make(map[string]chain)
	}
	ipt.rules[table][chainName] = &chainDelete{}
	return nil
}

func (ipt *IPTables) RegisterChainPatch(table, chainName string) error {
	ipt.sync.Lock()
	defer ipt.sync.Unlock()

	if _, ok := ipt.rules[table]; !ok {
		ipt.rules[table] = make(map[string]chain)
	}
	ipt.rules[table][chainName] = &chainPatch{
		recoverOrder: chainName == "PREROUTING" && (table == "mangle" || table == "nat"),
	}
	return nil
}

func (ipt *IPTables) RegisterChainOverride(table, chainName string) error {
	ipt.sync.Lock()
	defer ipt.sync.Unlock()

	if _, ok := ipt.rules[table]; !ok {
		ipt.rules[table] = make(map[string]chain)
	}
	ipt.rules[table][chainName] = &chainOverride{}
	return nil
}

func (ipt *IPTables) Append(table, chain string, ruleArgs ...string) error {
	ipt.sync.RLock()
	defer ipt.sync.RUnlock()

	if ipt.rules[table] == nil || ipt.rules[table][chain] == nil {
		return ErrChainNotInitialized
	}

	return ipt.rules[table][chain].Append(ruleFromStrings(ruleArgs))
}

func (ipt *IPTables) Insert(table, chain string, ruleNum int, ruleArgs ...string) error {
	ipt.sync.RLock()
	defer ipt.sync.RUnlock()

	if ipt.rules[table] == nil || ipt.rules[table][chain] == nil {
		return ErrChainNotInitialized
	}

	return ipt.rules[table][chain].Insert(ruleNum, ruleFromStrings(ruleArgs))
}

func (ipt *IPTables) Delete(table, chain string, ruleArgs ...string) error {
	ipt.sync.RLock()
	defer ipt.sync.RUnlock()

	if ipt.rules[table] == nil || ipt.rules[table][chain] == nil {
		return ErrChainNotInitialized
	}

	return ipt.rules[table][chain].Delete(ruleFromStrings(ruleArgs))
}

func (ipt *IPTables) GetCurrentRules() (map[string]map[string][]Rule, error) {
	return ipt.getCurrentRules(context.Background())
}

func (ipt *IPTables) getCurrentRules(ctx context.Context) (map[string]map[string][]Rule, error) {
	rules := make(map[string]map[string][]Rule)

	data, err := ipt.executable.Save(ctx)
	if err != nil {
		return nil, err
	}

	lines := bytes.Split(data, []byte("\n"))
	var currentTable string
	for _, line := range lines {
		if len(line) == 0 {
			continue
		}

		switch line[0] {
		case '*':
			currentTable = string(line[1:])
			if rules[currentTable] == nil {
				rules[currentTable] = make(map[string][]Rule)
			}

		case ':':
			// Формат: ":CHAIN POLICY [packets:bytes]"
			// Найдём первый пробел для получения имени chain
			spaceIdx := bytes.IndexByte(line[1:], ' ')
			var chainName string
			if spaceIdx == -1 {
				chainName = string(line[1:])
			} else {
				chainName = string(line[1 : 1+spaceIdx])
			}
			if chainName == "" {
				return nil, fmt.Errorf("invalid chain declaration")
			}
			if rules[currentTable][chainName] == nil {
				rules[currentTable][chainName] = []Rule{}
			}

		case '-':
			if currentTable == "" {
				return nil, fmt.Errorf("rule outside of table")
			}

			fields := splitFields(line)
			if len(fields) < 2 {
				return nil, fmt.Errorf("invalid rule: %q", line)
			}

			chainName := string(fields[1])
			if len(fields[0]) < 2 {
				return nil, fmt.Errorf("invalid rule command: %q", fields[0])
			}
			switch fields[0][1] {
			case 'A': // Append
				// fields[2:] - правило без оператора
				rules[currentTable][chainName] = append(rules[currentTable][chainName], fields[2:])

			default:
				return nil, fmt.Errorf("unknown iptables command %q", fields[0])
			}

		case '#':
			continue

		case 'C':
			currentTable = ""

		default:
			return nil, fmt.Errorf("unknown iptables input %q", line)
		}
	}

	return rules, nil
}

// splitFields разбивает строку на поля по пробелам, возвращая срезы оригинального буфера
func splitFields(data []byte) [][]byte {
	var fields [][]byte
	start := -1
	for i, b := range data {
		if b == ' ' || b == '\t' {
			if start >= 0 {
				fields = append(fields, data[start:i])
				start = -1
			}
		} else {
			if start < 0 {
				start = i
			}
		}
	}
	if start >= 0 {
		fields = append(fields, data[start:])
	}
	return fields
}

// Commit применяет накопленные правила с фоновым контекстом. Потолок времени на
// каждый внешний вызов задаётся execTimeout независимо от переданного контекста.
// SetDeferred включает/выключает батч-режим (см. поле deferred). Выключение
// само по себе НЕ коммитит — вызывающий делает это явно.
func (ipt *IPTables) SetDeferred(v bool) {
	ipt.deferred.Store(v)
}

// Deferred сообщает, активен ли батч-режим.
func (ipt *IPTables) Deferred() bool {
	return ipt.deferred.Load()
}

func (ipt *IPTables) Commit() error {
	// В батч-режиме промежуточные коммиты — no-op: правила уже накоплены в
	// ipt.rules, применит их финальный коммит батча. CommitContext намеренно
	// НЕ проверяет флаг: форс-коммит (хук netfilter.d, коммиттер) должен
	// доходить до ядра всегда.
	if ipt.deferred.Load() {
		return nil
	}
	return ipt.CommitContext(context.Background())
}

// CommitContext — то же, но с внешним контекстом: он прерывает и iptables-save,
// и iptables-restore. Нужен там, где проход может стать неактуальным на лету
// (остановка демона, приход нового события netfilter.d).
func (ipt *IPTables) CommitContext(ctx context.Context) (err error) {
	// commitMu сериализует весь цикл «прочитать состояние -> вычислить дельту ->
	// применить». Без него два коммита читают один снимок ядра и пишут дельты от
	// него же. Берётся ДО ipt.sync, обратный порядок заводить нельзя.
	ipt.commitMu.Lock()
	defer ipt.commitMu.Unlock()

	ipt.sync.RLock()
	defer ipt.sync.RUnlock()

	buf := new(bytes.Buffer)
	start := time.Now()
	defer func() {
		elapsed := time.Since(start)
		iptType := "iptables"
		if ipt.Proto() == ProtocolIPv6 {
			iptType = "ip6tables"
		}
		var logEvent *zerolog.Event
		if err != nil {
			logEvent = log.Error().Err(err)
		} else {
			logEvent = log.Trace()
		}
		logEvent.Dur("elapsed_ms", elapsed).Str("type", iptType).Bytes("buf", buf.Bytes()).Msg("iptables commit")
	}()

	curRules, err := ipt.getCurrentRules(ctx)
	if err != nil {
		return err
	}
	if err := ipt.checkJumpRecoveries(ctx, curRules, false); err != nil {
		return err
	}

	var readback map[chainLocation]patchRecovery
	var observations []patchRecovery
	for tableName, table := range ipt.rules {
		curTable := curRules[tableName]

		var tableExists bool
		tableNameBytes := []byte(tableName)

		commandsPrioritized := make(map[int8][]command)
		for chainName, chain := range table {
			chainNameBytes := []byte(chainName)
			var curChain []Rule
			if curTable[chainName] != nil {
				curChain = curTable[chainName]
			}
			var commands []command
			var order priority
			if patch, ok := chain.(*chainPatch); ok && patch.recoverOrder {
				var plan patchRecovery
				commands, plan = patch.planRecovery(tableName, chainNameBytes, curChain)
				if plan.observe {
					if len(commands) == 0 {
						plan.record(curChain)
					} else {
						plan.expected = projectPatch(curChain, commands)
						observations = append(observations, plan)
					}
				}
				if plan.rule != "" {
					if readback == nil {
						readback = make(map[chainLocation]patchRecovery)
					}
					readback[chainLocation{tableName, chainName}] = plan
				}
			} else {
				commands, order, err = chain.Compile(chainNameBytes, curChain)
				if err != nil {
					return err
				}
			}
			if len(commands) > 0 {
				if !tableExists {
					buf.WriteByte('*')
					buf.Write(tableNameBytes)
					buf.WriteByte('\n')
					tableExists = true
				}
				buf.WriteByte(':')
				buf.Write(chainNameBytes)
				buf.WriteString(" - [0:0]\n")
				commandsPrioritized[int8(order)] = append(commandsPrioritized[int8(order)], commands...)
			}
		}

		if !tableExists {
			continue
		}

		priorities := make([]int8, 0, len(commandsPrioritized))
		for priority := range commandsPrioritized {
			priorities = append(priorities, priority)
		}
		slices.Sort(priorities)

		for _, priority := range priorities {
			for _, cmd := range commandsPrioritized[priority] {
				switch cmd.Option {
				case optionAppend:
					buf.WriteString("-A ")
					buf.Write(cmd.Chain)
					if len(cmd.Rule) > 0 {
						buf.WriteByte(' ')
						ruleWriteTo(buf, cmd.Rule)
					}
					buf.WriteByte('\n')
				case optionDelete:
					buf.WriteString("-D ")
					buf.Write(cmd.Chain)
					if len(cmd.Rule) > 0 {
						buf.WriteByte(' ')
						ruleWriteTo(buf, cmd.Rule)
					}
					buf.WriteByte('\n')
				case optionInsert:
					buf.WriteString("-I ")
					buf.Write(cmd.Chain)
					buf.WriteByte(' ')
					buf.WriteString(strconv.Itoa(cmd.RuleNum))
					if len(cmd.Rule) > 0 {
						buf.WriteByte(' ')
						ruleWriteTo(buf, cmd.Rule)
					}
					buf.WriteByte('\n')
				case optionFlush:
					buf.WriteString("-F ")
					buf.Write(cmd.Chain)
					buf.WriteByte('\n')
				case optionDeleteChain:
					buf.WriteString("-X ")
					buf.Write(cmd.Chain)
					buf.WriteByte('\n')
				}
			}
		}
		buf.WriteString("COMMIT\n")
	}

	if buf.Len() == 0 {
		return nil
	}

	ipt.pendingJumpChecks = readback
	if err := ipt.executable.Restore(ctx, buf.Bytes()); err != nil {
		return err
	}
	for _, plan := range observations {
		plan.record(plan.expected)
	}
	if len(readback) == 0 {
		return nil
	}
	applied, err := ipt.getCurrentRules(ctx)
	if err != nil {
		return fmt.Errorf("verify restored iptables jump: %w", err)
	}
	return ipt.checkJumpRecoveries(ctx, applied, true)
}
