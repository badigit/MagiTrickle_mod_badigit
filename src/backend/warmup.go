package magitrickle

import (
	"context"
	"net"
	"strconv"
	"sync"
	"time"

	"magitrickle/app"

	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

const (
	// warmupMaxDomains ограничивает объём одного прогона (флеш/сеть/CPU).
	// При AdditionalTTL=24ч recordsCache может держать тысячи имён.
	warmupMaxDomains = 1000
	// warmupWorkers — параллелизм ре-резолва.
	warmupWorkers = 8
)

// Warmup ре-резолвит имена из recordsCache, сматченные активными правилами,
// через локальный DNS-прокси (штатный путь dnsResponseHook→handleMessage →
// ipset). Прогревает ТОЛЬКО конкретные имена: wildcard/namespace-правила
// покрывают бесконечное множество поддоменов, «прогреть правило» резолвом нельзя.
func (a *App) Warmup(ctx context.Context) (app.WarmupResult, error) {
	var res app.WarmupResult
	if !a.routingActive.Load() {
		return res, nil // routing на паузе — наполнять ipset некуда
	}

	domains := a.recordsCache.ListKnownDomains()
	targets := make([]string, 0, len(domains))
	for _, d := range domains {
		if _, ok := a.searchDomain(d); ok {
			targets = append(targets, d)
		}
	}
	res.Matched = len(targets)

	if len(targets) > warmupMaxDomains {
		targets = targets[:warmupMaxDomains]
		res.Truncated = true
	}

	// Адрес собственного DNS-прокси. Слушатель биндит [::]/0.0.0.0 — клиентим по
	// loopback, чтобы не зависеть от внешних адресов интерфейсов.
	settings := a.dnsConfig()
	host := settings.Host.Address
	switch host {
	case "", "[::]", "::", "0.0.0.0":
		host = "127.0.0.1"
	}
	proxyAddr := net.JoinHostPort(host, strconv.Itoa(int(settings.Host.Port)))

	timeout := settings.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}

	// AAAA имеет смысл переспрашивать только если они не дропаются (иначе в ipset
	// не попадут всё равно).
	askAAAA := settings.DisableDropAAAA

	var (
		wg       sync.WaitGroup
		mu       sync.Mutex
		queried  int
		errCount int
	)
	sem := make(chan struct{}, warmupWorkers)

	for _, d := range targets {
		if ctx.Err() != nil {
			break
		}
		wg.Add(1)
		sem <- struct{}{}
		go func(domain string) {
			defer wg.Done()
			defer func() { <-sem }()
			ok := a.warmupResolve(ctx, proxyAddr, domain, timeout, askAAAA)
			mu.Lock()
			queried++
			if !ok {
				errCount++
			}
			mu.Unlock()
		}(d)
	}
	wg.Wait()

	res.Queried = queried
	res.Errors = errCount

	log.Info().
		Int("matched", res.Matched).
		Int("queried", res.Queried).
		Int("errors", res.Errors).
		Bool("truncated", res.Truncated).
		Msg("ipset warmup completed")

	return res, nil
}

// warmupResolve посылает A- (и опционально AAAA-) запрос на локальный DNS-прокси.
// Ответ проходит через dnsResponseHook→handleMessage и наполняет ipset. true —
// если хотя бы один запрос успешен.
func (a *App) warmupResolve(ctx context.Context, proxyAddr, domain string, timeout time.Duration, askAAAA bool) bool {
	c := &dns.Client{Net: "udp", Timeout: timeout}

	qtypes := []uint16{dns.TypeA}
	if askAAAA {
		qtypes = append(qtypes, dns.TypeAAAA)
	}

	any := false
	for _, qtype := range qtypes {
		if ctx.Err() != nil {
			return any
		}
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(domain), qtype)

		reqCtx, cancel := context.WithTimeout(ctx, timeout)
		_, _, err := c.ExchangeContext(reqCtx, m, proxyAddr)
		cancel()
		if err != nil {
			log.Debug().Err(err).Str("domain", domain).Uint16("qtype", qtype).Msg("warmup query failed")
			continue
		}
		any = true
	}
	return any
}
