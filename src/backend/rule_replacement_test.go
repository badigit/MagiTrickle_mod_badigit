package magitrickle

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	v1 "magitrickle/api/v1"
	"magitrickle/models"
	"magitrickle/utils/intID"
)

func TestRuleEditReplacesCompiledMatcher(t *testing.T) {
	for _, tt := range []struct {
		name, path, body string
	}{
		{"single rule", "/groups/01000000/rules/02000000", `{"id":"03000000","type":"regex","rule":"^new[.]example$","enable":true}`},
		{"group", "/groups/01000000", `{"rules":[{"id":"02000000","type":"regex","rule":"^new[.]example$","enable":true}]}`},
		{"groups", "/groups", `{"groups":[{"id":"01000000","rules":[{"id":"02000000","type":"regex","rule":"^new[.]example$","enable":true}]}]}`},
	} {
		t.Run(tt.name, func(t *testing.T) {
			a := newApp()
			old := compiledTestRule(t)
			if err := a.AddGroup(&models.Group{ID: intID.ID{1}, Rules: []*models.Rule{old}}); err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			v1.NewRouter(a).ServeHTTP(w, httptest.NewRequest(http.MethodPut, tt.path, strings.NewReader(tt.body)))
			if w.Code != http.StatusOK {
				t.Fatalf("edit returned HTTP %d: %s", w.Code, w.Body)
			}
			checkEditedRule(t, old, a.Groups()[0].Model().Rules[0])
		})
	}
}

func TestSubscriptionEditReplacesCompiledMatcher(t *testing.T) {
	a := newApp()
	old := compiledTestRule(t)
	if err := a.AddSubscription(&models.Subscription{ID: intID.ID{1}, Rules: []*models.Rule{old}}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	body := `{"subscriptions":[{"id":"01000000","rules":[{"id":"02000000","type":"regex","rule":"^new[.]example$","enable":true}]}]}`
	v1.NewRouter(a).ServeHTTP(w, httptest.NewRequest(http.MethodPut, "/subscriptions", strings.NewReader(body)))
	if w.Code != http.StatusOK {
		t.Fatalf("edit returned HTTP %d: %s", w.Code, w.Body)
	}
	checkEditedRule(t, old, a.Subscriptions()[0].Rules[0])
}

func TestCreateRuleWithExistingIDAppendsFreshRule(t *testing.T) {
	a := newApp()
	old := compiledTestRule(t)
	if err := a.AddGroup(&models.Group{ID: intID.ID{1}, Rules: []*models.Rule{old}}); err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	body := `{"id":"02000000","type":"regex","rule":"^new[.]example$","enable":true}`
	v1.NewRouter(a).ServeHTTP(w, httptest.NewRequest(http.MethodPost, "/groups/01000000/rules", strings.NewReader(body)))
	if w.Code != http.StatusOK {
		t.Fatalf("create returned HTTP %d: %s", w.Code, w.Body)
	}
	rules := a.Groups()[0].Model().Rules
	if len(rules) != 2 || rules[0] != old || rules[1].ID == old.ID {
		t.Fatal("create did not append a distinct rule")
	}
	if old.Rule != "^old[.]example$" || !old.IsMatch("old.example") || !rules[1].IsMatch("new.example") {
		t.Fatal("create changed the existing rule or failed to compile the new rule")
	}
}

func compiledTestRule(t *testing.T) *models.Rule {
	t.Helper()
	rule := &models.Rule{ID: intID.ID{2}, Type: models.RuleTypeRegEx, Rule: "^old[.]example$", Enable: true}
	if !rule.IsMatch("old.example") {
		t.Fatal("failed to warm up old matcher")
	}
	return rule
}

func checkEditedRule(t *testing.T, old, updated *models.Rule) {
	t.Helper()
	if updated == old || updated.ID != old.ID {
		t.Fatal("edit must replace the rule while retaining its ID")
	}
	if updated.IsMatch("old.example") || !updated.IsMatch("new.example") {
		t.Fatal("edited rule still uses the old matcher")
	}
	if old.Rule != "^old[.]example$" || !old.IsMatch("old.example") {
		t.Fatal("edit mutated the previous rule")
	}
}
