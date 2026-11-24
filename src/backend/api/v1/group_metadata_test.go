package v1

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"magitrickle/app"
	"magitrickle/models"
	"magitrickle/utils/intID"
)

type metadataTestApp struct {
	app.Main
	group *metadataTestGroup
}

func (a *metadataTestApp) Groups() []app.Group { return []app.Group{a.group} }
func (a *metadataTestApp) GroupByID(id intID.ID) (app.Group, bool) {
	return a.group, id == a.group.model.ID
}
func (a *metadataTestApp) WithConfigWrite(f func()) { f() }

type metadataTestGroup struct {
	app.Group
	model *models.Group
}

func (g *metadataTestGroup) Model() *models.Group { return g.model }
func (g *metadataTestGroup) Enabled() bool        { return true }

func TestGroupMetadataEditKeepsActiveRules(t *testing.T) {
	for _, tt := range []struct{ path, body string }{
		{"/groups/01000000", `{"name":"new","interface":"direct"}`},
		{"/groups", `{"groups":[{"id":"01000000","name":"new","interface":"direct","rules":[{"id":"02000000","type":"subnet","rule":"192.0.2.0/24","enable":true}]}]}`},
	} {
		t.Run(tt.path, func(t *testing.T) {
			rule := &models.Rule{ID: intID.ID{2}, Type: models.RuleTypeSubnet, Rule: "192.0.2.0/24", Enable: true}
			group := &models.Group{ID: intID.ID{1}, Name: "old", Interface: "direct", Enable: true, Rules: []*models.Rule{rule}}
			a := &metadataTestApp{group: &metadataTestGroup{model: group}}
			w := httptest.NewRecorder()
			NewRouter(a).ServeHTTP(w, httptest.NewRequest(http.MethodPut, tt.path, strings.NewReader(tt.body)))
			if w.Code != http.StatusOK || group.Name != "new" || len(group.Rules) != 1 || group.Rules[0] != rule {
				t.Fatalf("metadata edit: HTTP %d, group=%#v, response=%s", w.Code, group, w.Body)
			}
		})
	}
}
