package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"magitrickle"
	"magitrickle/api/v1"
	"magitrickle/api/v1/types"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
)

func setupHTTP(a *magitrickle.App, rootRouter chi.Router, errChan chan error) (*http.Server, error) {
	address := fmt.Sprintf("%s:%d",
		a.Config().HTTPWeb.Host.Address,
		a.Config().HTTPWeb.Host.Port,
	)

	listener, err := net.Listen("tcp", address)
	if err != nil {
		return nil, fmt.Errorf("listen error: %v", err)
	}

	srv := &http.Server{Handler: rootRouter}

	go func() {
		if e := srv.Serve(listener); e != nil && e != http.ErrServerClosed {
			errChan <- e
		}
		_ = listener.Close()
	}()

	srv.Addr = listener.Addr().String()

	return srv, nil
}

func TestIntegration(t *testing.T) {
	core, err := magitrickle.New()
	if err != nil {
		t.Fatal(err)
	}

	errChan := make(chan error, 1)

	rootRouter := chi.NewRouter()
	rootRouter.Use(middleware.Recoverer)

	h := v1.NewHandler(core)
	apiRouter := v1.NewRouter(core)

	apiRouter.Get("/groups", h.GetGroups)
	apiRouter.Post("/groups", h.CreateGroup)

	rootRouter.Mount("/api/v1", apiRouter)

	srv, err := setupHTTP(core, rootRouter, errChan)
	if err != nil {
		t.Fatalf("setupHTTP error: %v", err)
	}

	baseURL := fmt.Sprintf("http://%s/api/v1", srv.Addr)
	t.Logf("Server started at %s", baseURL)

	var once sync.Once
	shutdown := func() {
		once.Do(func() {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			_ = srv.Shutdown(ctx)
		})
	}
	defer shutdown()

	go func() {
		if e := <-errChan; e != nil {
			t.Logf("server error: %v", e)
			shutdown()
		}
	}()

	//-----------//
	// Тесты API //
	//-----------//

	t.Run("CheckGroupsInitially", func(t *testing.T) {
		resp, body := doRequest(t, http.MethodGet, baseURL+"/groups", nil)
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			responseData, _ := io.ReadAll(body)
			t.Fatalf("GET /groups => %d, want 200. Body: %s", resp.StatusCode, string(responseData))
		}

		var gr types.GroupsRes
		mustDecode(t, body, &gr)

		if gr.Groups == nil {
			t.Log("Groups is nil => нет групп")
		} else {
			t.Logf("We have %d groups", len(*gr.Groups))
		}
	})

	t.Run("CreateGroup", func(t *testing.T) {
		req := types.GroupReq{Name: "TestGroup1"}
		payload, _ := json.Marshal(req)

		resp, body := doRequest(t, http.MethodPost, baseURL+"/groups", payload)
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			responseData, _ := io.ReadAll(body)
			t.Fatalf("POST /groups => %d, want 200. Body: %s", resp.StatusCode, string(responseData))
		}

		var newGrp types.GroupRes
		mustDecode(t, body, &newGrp)

		if newGrp.Name != "TestGroup1" {
			t.Errorf("Expected group name=TestGroup1, got %s", newGrp.Name)
		}
		t.Logf("Created group with ID=%v", newGrp.ID)
	})

	t.Run("InterfaceAliases", func(t *testing.T) {
		aliases := map[string]string{
			"wg0":  "Main tunnel",
			"ppp1": "Backup",
		}
		payload, _ := json.Marshal(aliases)

		resp, body := doRequest(t, http.MethodPost, baseURL+"/system/interfaces/aliases", payload)
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			responseData, _ := io.ReadAll(body)
			t.Fatalf("POST /system/interfaces/aliases => %d, want 200. Body: %s", resp.StatusCode, string(responseData))
		}

		resp, body = doRequest(t, http.MethodGet, baseURL+"/system/interfaces/aliases", nil)
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			responseData, _ := io.ReadAll(body)
			t.Fatalf("GET /system/interfaces/aliases => %d, want 200. Body: %s", resp.StatusCode, string(responseData))
		}

		var got map[string]string
		mustDecode(t, body, &got)

		if len(got) != len(aliases) {
			t.Fatalf("Expected %d aliases, got %d", len(aliases), len(got))
		}
		for key, want := range aliases {
			if got[key] != want {
				t.Fatalf("Alias %s => %q, want %q", key, got[key], want)
			}
		}
	})
	ruleListSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "example.com\nDOMAIN,exact.example\nIP-CIDR,10.0.0.0/8\n||adblock.example^\n")
	}))
	defer ruleListSrv.Close()

	var subscriptionID string

	t.Run("PreviewSubscriptionRules", func(t *testing.T) {
		resp, body := doRequest(
			t,
			http.MethodGet,
			baseURL+"/subscription/rules?url="+ruleListSrv.URL,
			nil,
		)
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			responseData, _ := io.ReadAll(body)
			t.Fatalf("GET /subscription/rules => %d, want 200. Body: %s", resp.StatusCode, string(responseData))
		}

		var rules types.RulesRes
		mustDecode(t, body, &rules)
		if rules.Rules == nil || len(*rules.Rules) < 3 {
			t.Fatalf("Expected parsed subscription rules, got %#v", rules.Rules)
		}
	})

	t.Run("CreateAndSyncSubscription", func(t *testing.T) {
		interval := int64(86400)
		req := types.SubscriptionReq{
			Name:      "Test subscription",
			Interface: "blackhole",
			Enable:    true,
			URL:       ruleListSrv.URL,
			Interval:  &interval,
		}
		payload, _ := json.Marshal(req)

		resp, body := doRequest(t, http.MethodPost, baseURL+"/subscription", payload)
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			responseData, _ := io.ReadAll(body)
			t.Fatalf("POST /subscription => %d, want 200. Body: %s", resp.StatusCode, string(responseData))
		}

		var created types.SubscriptionRes
		mustDecode(t, body, &created)
		subscriptionID = created.ID.String()
		if created.Name != "Test subscription" {
			t.Fatalf("Expected subscription name=Test subscription, got %s", created.Name)
		}

		resp, body = doRequest(t, http.MethodPatch, baseURL+"/subscription?id="+subscriptionID, []byte("{}"))
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			responseData, _ := io.ReadAll(body)
			t.Fatalf("PATCH /subscription => %d, want 200. Body: %s", resp.StatusCode, string(responseData))
		}

		var synced types.SubscriptionSyncRes
		mustDecode(t, body, &synced)
		if synced.Rules == nil || len(*synced.Rules) < 3 {
			t.Fatalf("Expected synced rules, got %#v", synced.Rules)
		}
		if synced.LastUpdate == 0 {
			t.Fatal("Expected non-zero last_update after sync")
		}

		resp, body = doRequest(t, http.MethodGet, baseURL+"/subscriptions", nil)
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			responseData, _ := io.ReadAll(body)
			t.Fatalf("GET /subscriptions => %d, want 200. Body: %s", resp.StatusCode, string(responseData))
		}

		var subscriptions types.SubscriptionsRes
		mustDecode(t, body, &subscriptions)
		if subscriptions.Subscriptions == nil || len(*subscriptions.Subscriptions) == 0 {
			t.Fatalf("Expected subscriptions list, got %#v", subscriptions.Subscriptions)
		}

		resp, body = doRequest(t, http.MethodDelete, baseURL+"/subscription?id="+subscriptionID, nil)
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			responseData, _ := io.ReadAll(body)
			t.Fatalf("DELETE /subscription => %d, want 200. Body: %s", resp.StatusCode, string(responseData))
		}
	})
}

func doRequest(t *testing.T, method, url string, data []byte) (*http.Response, io.ReadCloser) {
	t.Helper()
	var body io.Reader
	if data != nil {
		body = bytes.NewReader(data)
	}

	req, err := http.NewRequest(method, url, body)
	if err != nil {
		t.Fatalf("http.NewRequest failed: %v", err)
	}
	if data != nil {
		req.Header.Set("Content-Type", "application/json")
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("%s %s error: %v", method, url, err)
	}

	return resp, resp.Body
}

func mustDecode(t *testing.T, r io.Reader, v interface{}) {
	t.Helper()
	if err := json.NewDecoder(r).Decode(v); err != nil {
		t.Fatalf("JSON decode error: %v", err)
	}
}
