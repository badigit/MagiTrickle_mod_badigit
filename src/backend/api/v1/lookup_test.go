package v1

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"magitrickle/api/v1/types"
	"magitrickle/app"
	"magitrickle/models"
	"magitrickle/utils/netfilterTools"
)

// fakeLookupGroup — минимальная группа для lookup: он читает только модель и
// содержимое ipset.
type fakeLookupGroup struct {
	app.Group
	model *models.Group
	ipv4  map[netfilterTools.IPv4Subnet]netfilterTools.IPSetTimeout
}

func (g *fakeLookupGroup) Model() *models.Group { return g.model }
func (g *fakeLookupGroup) Enabled() bool        { return true }
func (g *fakeLookupGroup) ListIPv4Subnets() (map[netfilterTools.IPv4Subnet]netfilterTools.IPSetTimeout, error) {
	return g.ipv4, nil
}
func (g *fakeLookupGroup) ListIPv6Subnets() (map[netfilterTools.IPv6Subnet]netfilterTools.IPSetTimeout, error) {
	return nil, nil
}

type fakeLookupApp struct {
	app.Main
	groups  []app.Group
	routing []app.Group // рантайм-набор (база + группы подписок); пусто — берём groups
	subs    []*models.Subscription
	// routingActive/directMode по умолчанию дают «роутинг поднят, direct
	// абсолютен» — состояние типового роутера, чтобы старые тесты не
	// перечисляли его каждый раз.
	routingActive bool
	directMode    string
	verdict       map[string]struct {
		group app.Group
		why   string
	}
}

func (f *fakeLookupApp) WithConfigRead(fn func())              { fn() }
func (f *fakeLookupApp) Groups() []app.Group                   { return f.groups }
func (f *fakeLookupApp) Subscriptions() []*models.Subscription { return f.subs }
func (f *fakeLookupApp) RoutingGroups() []app.Group {
	if len(f.routing) > 0 {
		return f.routing
	}
	return f.groups
}
func (f *fakeLookupApp) IsRoutingActive() bool { return f.routingActive }
func (f *fakeLookupApp) DirectPriority() string {
	if f.directMode == "" {
		return models.DirectPriorityAbsolute
	}
	return f.directMode
}
func (f *fakeLookupApp) SearchDomainVerdict(domain string) (app.Group, string, bool) {
	v, ok := f.verdict[domain]
	if !ok {
		return nil, "", false
	}
	return v.group, v.why, true
}

func lookupGroup(name string, rules ...*models.Rule) *fakeLookupGroup {
	return &fakeLookupGroup{model: &models.Group{Name: name, Enable: true, Rules: rules}}
}

func doLookup(t *testing.T, a app.Main, req types.LookupReq) types.LookupRes {
	t.Helper()
	body, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(http.MethodPost, "/lookup", bytes.NewReader(body))
	res := httptest.NewRecorder()
	NewRouter(a).ServeHTTP(res, r)
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, body = %s", res.Code, res.Body.String())
	}
	var out types.LookupRes
	if err := json.NewDecoder(res.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

// Домен: winner берётся у того же арбитража, что решает роутинг, а список
// совпадений остаётся на месте — он объясняет, ПОЧЕМУ так вышло, и его уже
// читают внешние тулы.
func TestLookupWinnerDomain(t *testing.T) {
	winner := lookupGroup("AI", &models.Rule{Type: models.RuleTypeDomain, Rule: "claude.ai", Enable: true})
	loser := lookupGroup("CDN", &models.Rule{Type: models.RuleTypeWildcard, Rule: "*.ai", Enable: true})

	a := &fakeLookupApp{
		routingActive: true,
		groups:        []app.Group{winner, loser},
		verdict: map[string]struct {
			group app.Group
			why   string
		}{
			"claude.ai": {group: winner, why: models.LookupWhyExact},
		},
	}

	out := doLookup(t, a, types.LookupReq{Queries: []string{"claude.ai"}})
	got := out.Results[0]

	if got.Winner == nil {
		t.Fatal("winner отсутствует")
	}
	if got.Winner.GroupName != "AI" {
		t.Errorf("winner = %q, want AI", got.Winner.GroupName)
	}
	if got.Winner.Why != models.LookupWhyExact {
		t.Errorf("why = %q, want %q", got.Winner.Why, models.LookupWhyExact)
	}
	if got.Winner.Pending {
		t.Error("pending = true, для доменного вердикта ожидали false")
	}
	if len(got.RuleHits) != 2 {
		t.Errorf("rule_hits = %d, want 2 (список совпадений не должен пропадать)", len(got.RuleHits))
	}
}

// Домен без совпадений: winner отсутствует, а не выдумывается.
func TestLookupNoWinner(t *testing.T) {
	a := &fakeLookupApp{groups: []app.Group{lookupGroup("AI")}, routingActive: true}

	out := doLookup(t, a, types.LookupReq{Queries: []string{"example.org"}})
	if out.Results[0].Winner != nil {
		t.Fatalf("ожидали отсутствие winner, получили %#v", out.Results[0].Winner)
	}
}

func TestLookupWildcardRuleHits(t *testing.T) {
	a := &fakeLookupApp{groups: []app.Group{lookupGroup("G",
		&models.Rule{Type: models.RuleTypeWildcard, Rule: "*.example.com", Enable: true},
		&models.Rule{Type: models.RuleTypeWildcard, Rule: "legacy.example.net", Enable: true},
	)}, routingActive: true}
	res := doLookup(t, a, types.LookupReq{Queries: []string{
		"a.b.example.com", "xexample.com", "child.legacy.example.net",
	}})
	if len(res.Results) != 3 {
		t.Fatalf("lookup returned %d results, want 3", len(res.Results))
	}
	for i, want := range []string{models.LookupWhyWildcard, "", models.LookupWhyNamespace} {
		hits := res.Results[i].RuleHits
		if want == "" {
			if len(hits) != 0 {
				t.Errorf("result %d: unexpected matches: %+v", i, hits)
			}
			continue
		}
		if len(hits) != 1 || hits[0].Match != want || hits[0].RuleType != models.RuleTypeWildcard {
			t.Errorf("result %d: matches = %+v, want one wildcard rule matched as %q", i, hits, want)
		}
	}
}

// IP: победитель — первая по порядку группа, в чьём ipset адрес уже лежит.
// Это фактический исход для пакета, поэтому pending=false.
func TestLookupWinnerIpsetFirst(t *testing.T) {
	first := lookupGroup("AI", &models.Rule{Type: models.RuleTypeSubnet, Rule: "160.79.104.0/24", Enable: true})
	first.ipv4 = map[netfilterTools.IPv4Subnet]netfilterTools.IPSetTimeout{
		{Address: [4]byte{160, 79, 104, 10}, CIDR: 32}: nil,
	}
	second := lookupGroup("CDN", &models.Rule{Type: models.RuleTypeSubnet, Rule: "160.79.0.0/16", Enable: true})
	second.ipv4 = map[netfilterTools.IPv4Subnet]netfilterTools.IPSetTimeout{
		{Address: [4]byte{160, 79, 104, 10}, CIDR: 32}: nil,
	}

	a := &fakeLookupApp{groups: []app.Group{first, second}, routingActive: true}

	out := doLookup(t, a, types.LookupReq{Queries: []string{"160.79.104.10"}, CheckIpset: true})
	got := out.Results[0]

	if got.Winner == nil {
		t.Fatal("winner отсутствует")
	}
	if got.Winner.GroupName != "AI" {
		t.Errorf("winner = %q, want AI (первая по порядку)", got.Winner.GroupName)
	}
	if got.Winner.Why != models.LookupWhyIpsetFirst {
		t.Errorf("why = %q, want %q", got.Winner.Why, models.LookupWhyIpsetFirst)
	}
	if got.Winner.Pending {
		t.Error("pending = true, но IP уже в ipset")
	}
}

// IP: правило совпало, но в ipset адреса ещё нет — победитель называется, а
// флаг pending честно говорит, что прямо сейчас трафик пойдёт мимо него.
func TestLookupWinnerPending(t *testing.T) {
	g := lookupGroup("AI", &models.Rule{Type: models.RuleTypeSubnet, Rule: "160.79.104.0/24", Enable: true})

	a := &fakeLookupApp{groups: []app.Group{g}, routingActive: true}

	out := doLookup(t, a, types.LookupReq{Queries: []string{"160.79.104.10"}, CheckIpset: true})
	got := out.Results[0]

	if got.Winner == nil {
		t.Fatal("winner отсутствует")
	}
	if got.Winner.GroupName != "AI" {
		t.Errorf("winner = %q, want AI", got.Winner.GroupName)
	}
	if got.Winner.Why != models.LookupWhySubnet {
		t.Errorf("why = %q, want %q", got.Winner.Why, models.LookupWhySubnet)
	}
	if !got.Winner.Pending {
		t.Error("pending = false, но IP в ipset ещё нет")
	}
}
