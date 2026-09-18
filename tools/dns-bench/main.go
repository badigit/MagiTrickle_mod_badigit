// dns-bench — нагрузочный бенч для DNS-стека MagiTrickle/mihomo.
// Гонит A-запросы на указанный сервер, считает rps/latency/errors.
// Использование:
//
//	dns-bench -server 10.9.0.1:53 -domains data/in-group.txt -rps 200 -duration 60s
package main

import (
	"context"
	"flag"
	"fmt"
	"math/rand"
	"os"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"
)

type stats struct {
	sent     atomic.Int64
	ok       atomic.Int64
	errs     atomic.Int64
	timeouts atomic.Int64
	nxdomain atomic.Int64
	servfail atomic.Int64

	mu   sync.Mutex
	lats []time.Duration // микросекунды OK-запросов
}

func (s *stats) record(lat time.Duration, err error, msg *dns.Msg) {
	s.sent.Add(1)
	if err != nil {
		s.errs.Add(1)
		if strings.Contains(err.Error(), "i/o timeout") || strings.Contains(err.Error(), "deadline exceeded") {
			s.timeouts.Add(1)
		}
		return
	}
	switch msg.Rcode {
	case dns.RcodeSuccess:
		s.ok.Add(1)
		s.mu.Lock()
		s.lats = append(s.lats, lat)
		s.mu.Unlock()
	case dns.RcodeNameError:
		s.nxdomain.Add(1)
	case dns.RcodeServerFailure:
		s.servfail.Add(1)
	default:
		s.errs.Add(1)
	}
}

func (s *stats) snapshot() (sent, ok, errs, to, nx, sf int64) {
	return s.sent.Load(), s.ok.Load(), s.errs.Load(), s.timeouts.Load(), s.nxdomain.Load(), s.servfail.Load()
}

func percentile(sorted []time.Duration, p float64) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(float64(len(sorted)-1) * p)
	return sorted[idx]
}

func main() {
	server := flag.String("server", "10.9.0.1:53", "DNS server addr (host:port)")
	domainsFile := flag.String("domains", "", "файл со списком доменов (по одному на строку)")
	rps := flag.Int("rps", 100, "целевая частота запросов в секунду")
	duration := flag.Duration("duration", 30*time.Second, "длительность теста")
	concurrency := flag.Int("concurrency", 16, "количество воркеров")
	timeout := flag.Duration("timeout", 5*time.Second, "таймаут одного запроса")
	useTCP := flag.Bool("tcp", false, "использовать TCP вместо UDP")
	progress := flag.Duration("progress", 5*time.Second, "интервал прогресс-репорта (0 — выключить)")
	flag.Parse()

	if *domainsFile == "" {
		fmt.Fprintln(os.Stderr, "укажи -domains <file>")
		flag.Usage()
		os.Exit(2)
	}

	raw, err := os.ReadFile(*domainsFile)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read domains:", err)
		os.Exit(1)
	}
	var domains []string
	for _, l := range strings.Split(string(raw), "\n") {
		l = strings.TrimSpace(l)
		if l != "" && !strings.HasPrefix(l, "#") {
			domains = append(domains, dns.Fqdn(l))
		}
	}
	if len(domains) == 0 {
		fmt.Fprintln(os.Stderr, "пустой список доменов")
		os.Exit(1)
	}

	fmt.Printf("=== dns-bench ===\nserver=%s domains=%d rps=%d concurrency=%d duration=%s tcp=%v\n",
		*server, len(domains), *rps, *concurrency, *duration, *useTCP)

	s := &stats{}
	ctx, cancel := context.WithTimeout(context.Background(), *duration)
	defer cancel()

	// Очередь job-ов с rate-limiting через ticker
	jobs := make(chan string, *concurrency*4)

	// генератор
	go func() {
		defer close(jobs)
		interval := time.Second / time.Duration(*rps)
		t := time.NewTicker(interval)
		defer t.Stop()
		rng := rand.New(rand.NewSource(time.Now().UnixNano()))
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				select {
				case jobs <- domains[rng.Intn(len(domains))]:
				default: // backpressure — воркеры не успевают
				}
			}
		}
	}()

	// воркеры
	var wg sync.WaitGroup
	net := "udp"
	if *useTCP {
		net = "tcp"
	}
	for i := 0; i < *concurrency; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := &dns.Client{Net: net, Timeout: *timeout}
			for d := range jobs {
				m := new(dns.Msg)
				m.SetQuestion(d, dns.TypeA)
				m.RecursionDesired = true
				start := time.Now()
				resp, _, qerr := c.Exchange(m, *server)
				lat := time.Since(start)
				s.record(lat, qerr, resp)
			}
		}()
	}

	// прогресс
	done := make(chan struct{})
	go func() {
		defer close(done)
		if *progress <= 0 {
			return
		}
		t := time.NewTicker(*progress)
		defer t.Stop()
		var prevSent int64
		var prevT = time.Now()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				sent, ok, errs, to, nx, sf := s.snapshot()
				now := time.Now()
				curRps := float64(sent-prevSent) / now.Sub(prevT).Seconds()
				prevSent, prevT = sent, now
				fmt.Printf("[%-6s] sent=%-6d ok=%-6d err=%-3d to=%-3d nx=%-3d sf=%-3d  rps=%.0f\n",
					time.Since(prevT).Round(time.Millisecond),
					sent, ok, errs, to, nx, sf, curRps)
			}
		}
	}()

	wg.Wait()
	cancel()
	<-done

	// финальный отчёт
	sent, ok, errs, to, nx, sf := s.snapshot()
	s.mu.Lock()
	lats := append([]time.Duration(nil), s.lats...)
	s.mu.Unlock()
	sort.Slice(lats, func(i, j int) bool { return lats[i] < lats[j] })

	fmt.Println("\n=== ИТОГО ===")
	fmt.Printf("sent:     %d\n", sent)
	fmt.Printf("ok:       %d (%.1f%%)\n", ok, 100*float64(ok)/float64(sent))
	fmt.Printf("errors:   %d  timeouts: %d  NXDOMAIN: %d  SERVFAIL: %d\n", errs, to, nx, sf)
	if len(lats) > 0 {
		var sum time.Duration
		for _, d := range lats {
			sum += d
		}
		fmt.Printf("latency:  min=%s p50=%s p95=%s p99=%s max=%s avg=%s\n",
			lats[0], percentile(lats, 0.50), percentile(lats, 0.95),
			percentile(lats, 0.99), lats[len(lats)-1], sum/time.Duration(len(lats)))
	}
	fmt.Printf("effective rps: %.0f\n", float64(sent)/duration.Seconds())
}
