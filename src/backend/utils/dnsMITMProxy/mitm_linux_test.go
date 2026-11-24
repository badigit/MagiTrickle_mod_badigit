package dnsMITMProxy

import (
	"context"
	"errors"
	"io"
	"net"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

const testDNSDeadline = 3 * time.Second

func TestDNSProxyTransportPaths(t *testing.T) {
	const largeName = "large.example."
	const fallbackName = "fallback.example."
	longText := []string{strings.Repeat("a", 240), strings.Repeat("b", 240), strings.Repeat("c", 240)}
	primary := startTestDNSServer(t, "primary", largeName, longText)
	fallback := startTestDNSServer(t, "fallback", largeName, longText)
	proxy := NewDNSMITMProxy(primary, 2, 4, testDNSDeadline)
	proxy.SetFallback(fallback, 2)
	proxy.UpstreamSelector = func(query dns.Msg) bool {
		return len(query.Question) == 1 && query.Question[0].Name == fallbackName
	}
	addr := startTestDNSProxy(t, proxy)

	udp := &dns.Client{Net: "udp", Timeout: testDNSDeadline}
	tcp := &dns.Client{Net: "tcp", Timeout: testDNSDeadline}

	t.Run("regular UDP uses primary", func(t *testing.T) {
		resp := exchangeTestDNS(t, udp, addr, "regular.example.")
		requireTestDNSText(t, resp, []string{"primary"})
	})

	t.Run("truncated UDP can be retried over TCP", func(t *testing.T) {
		resp := exchangeTestDNS(t, udp, addr, largeName)
		if !resp.Truncated {
			t.Fatal("UDP response did not preserve TC")
		}
		resp = exchangeTestDNS(t, tcp, addr, largeName)
		requireTestDNSText(t, resp, longText)
	})

	t.Run("fallback answers on both transports", func(t *testing.T) {
		for _, client := range []*dns.Client{udp, tcp} {
			resp := exchangeTestDNS(t, client, addr, fallbackName)
			requireTestDNSText(t, resp, []string{"fallback"})
		}
	})

	t.Run("TCP closes after one reply and a new connection works", func(t *testing.T) {
		conn, err := tcp.Dial(addr)
		if err != nil {
			t.Fatal(err)
		}
		defer conn.Close()
		query := new(dns.Msg).SetQuestion("first.example.", dns.TypeTXT)
		resp, _, err := tcp.ExchangeWithConn(query, conn)
		if err != nil {
			t.Fatal(err)
		}
		requireTestDNSText(t, resp, []string{"primary"})
		if err := conn.SetReadDeadline(time.Now().Add(testDNSDeadline)); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.ReadMsg(); !errors.Is(err, io.EOF) {
			t.Fatalf("expected the proxy to close the connection after the first reply, got %v", err)
		}
		resp = exchangeTestDNS(t, tcp, addr, "next.example.")
		requireTestDNSText(t, resp, []string{"primary"})
	})
}

func startTestDNSServer(t *testing.T, label, largeName string, longText []string) string {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := listener.Addr().(*net.TCPAddr)
	packetConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: addr.IP, Port: addr.Port})
	if err != nil {
		listener.Close()
		t.Fatal(err)
	}
	handler := dns.HandlerFunc(func(w dns.ResponseWriter, query *dns.Msg) {
		question := query.Question[0]
		text := []string{label}
		if question.Name == largeName {
			text = longText
		}
		resp := new(dns.Msg).SetReply(query)
		resp.Answer = []dns.RR{&dns.TXT{
			Hdr: dns.RR_Header{Name: question.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 60},
			Txt: text,
		}}
		if _, udp := w.RemoteAddr().(*net.UDPAddr); udp {
			resp.Truncate(dns.MinMsgSize)
		}
		if err := w.WriteMsg(resp); err != nil {
			t.Errorf("write synthetic DNS response: %v", err)
		}
	})
	for _, server := range []*dns.Server{{Listener: listener, Handler: handler}, {PacketConn: packetConn, Handler: handler}} {
		ready := make(chan struct{})
		done := make(chan error, 1)
		server.NotifyStartedFunc = func() { close(ready) }
		go func() { done <- server.ActivateAndServe() }()
		t.Cleanup(func() {
			ctx, cancel := context.WithTimeout(context.Background(), testDNSDeadline)
			defer cancel()
			if err := server.ShutdownContext(ctx); err != nil {
				t.Errorf("stop synthetic DNS server: %v", err)
			}
		})
		select {
		case <-ready:
		case err := <-done:
			t.Fatalf("start synthetic DNS server: %v", err)
		case <-time.After(testDNSDeadline):
			t.Fatal("timed out starting synthetic DNS server")
		}
	}
	return addr.String()
}

func startTestDNSProxy(t *testing.T, proxy *DNSMITMProxy) string {
	t.Helper()
	reservation, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	addr := reservation.Addr().(*net.TCPAddr)
	if err := reservation.Close(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	tcpDone := make(chan error, 1)
	udpDone := make(chan error, 1)
	t.Cleanup(func() {
		cancel()
		deadline := time.After(testDNSDeadline)
		for _, done := range []chan error{tcpDone, udpDone} {
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("DNS proxy listener: %v", err)
				}
			case <-deadline:
				t.Error("timed out stopping DNS proxy")
				return
			}
		}
		if err := proxy.Close(); err != nil {
			t.Errorf("close DNS proxy: %v", err)
		}
	})
	go func() { tcpDone <- proxy.ListenTCP(ctx, addr) }()
	go func() {
		udpDone <- proxy.ListenUDP(ctx, &net.UDPAddr{IP: addr.IP, Port: addr.Port})
	}()

	for _, network := range []string{"udp", "tcp"} {
		client := &dns.Client{Net: network, Timeout: 100 * time.Millisecond}
		query := new(dns.Msg).SetQuestion("ready.example.", dns.TypeTXT)
		deadline := time.Now().Add(testDNSDeadline)
		for {
			if _, _, err := client.Exchange(query, addr.String()); err == nil {
				break
			} else if time.Now().After(deadline) {
				t.Fatalf("%s DNS proxy did not become ready: %v", network, err)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	return addr.String()
}

func exchangeTestDNS(t *testing.T, client *dns.Client, addr, name string) *dns.Msg {
	t.Helper()
	query := new(dns.Msg).SetQuestion(name, dns.TypeTXT)
	resp, _, err := client.Exchange(query, addr)
	if err != nil {
		t.Fatalf("%s query for %s: %v", client.Net, name, err)
	}
	if !resp.Response || resp.Rcode != dns.RcodeSuccess || len(resp.Question) != 1 || resp.Question[0] != query.Question[0] {
		t.Fatalf("unexpected %s response to %s: %v", client.Net, name, resp)
	}
	return resp
}

func requireTestDNSText(t *testing.T, resp *dns.Msg, want []string) {
	t.Helper()
	if resp.Truncated || len(resp.Answer) != 1 {
		t.Fatalf("expected one complete answer, got %v", resp)
	}
	txt, ok := resp.Answer[0].(*dns.TXT)
	if !ok || !slices.Equal(txt.Txt, want) {
		t.Fatalf("unexpected TXT answer: %v", resp.Answer[0])
	}
}
