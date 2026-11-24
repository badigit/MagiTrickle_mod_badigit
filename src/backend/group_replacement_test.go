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

func TestPutGroupsValidatesBeforeReplacingPausedGroups(t *testing.T) {
	a := newApp()
	old := &models.Group{ID: intID.ID{1}, Name: "old", Enable: true, Rules: []*models.Rule{
		{ID: intID.ID{2}, Type: models.RuleTypeDomain, Rule: "old.example", Enable: true},
	}}
	if err := a.AddGroup(old); err != nil {
		t.Fatal(err)
	}
	put := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPut, "/groups", strings.NewReader(body))
		w := httptest.NewRecorder()
		v1.NewHandler(a).PutGroups(w, r)
		return w
	}
	for _, body := range []string{
		`{"groups":[{"id":"01000000","name":"renamed"},{"id":"01000000"}]}`,
		`{"groups":[{"id":"01000000","rules":[{"id":"02000000","rule":"new.example"},{"id":"02000000"}]}]}`,
	} {
		res := put(body)
		if res.Code != http.StatusBadRequest {
			t.Fatalf("invalid replacement: HTTP %d, %s", res.Code, res.Body)
		}
		groups := a.Groups()
		if len(groups) != 1 || groups[0].Model() != old || old.Name != "old" || old.Rules[0].Rule != "old.example" {
			t.Fatal("invalid replacement changed the previous group")
		}
	}
	res := put(`{"groups":[{"id":"01000000","name":"renamed"}]}`)
	groups := a.Groups()
	if res.Code != http.StatusOK || len(groups) != 1 || groups[0].Model().Name != "renamed" {
		t.Fatalf("valid replacement: HTTP %d, %s", res.Code, res.Body)
	}
	if groups[0].Enabled() || a.IsRoutingActive() {
		t.Fatal("valid replacement resumed paused routing")
	}
	if groups[0].Model().Rules[0].ID != old.Rules[0].ID {
		t.Fatal("omitted rules were not retained")
	}
}
