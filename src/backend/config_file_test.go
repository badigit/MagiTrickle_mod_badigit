package magitrickle

import (
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"testing"

	"magitrickle/config"
	"magitrickle/models"
	"magitrickle/utils/intID"

	"gopkg.in/yaml.v3"
)

func TestConfigLoadRejectsInvalidReplacement(t *testing.T) {
	a := newApp()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := a.loadConfigFile(path); err != nil {
		t.Fatalf("first start without configuration: %v", err)
	}
	old := []config.Group{{ID: intID.ID{1}, Name: "previous"}}
	if err := a.ImportConfig(config.Config{ConfigVersion: "0.1.4", Groups: &old}); err != nil {
		t.Fatal(err)
	}
	before := a.Config()
	previousGroup := a.Groups()[0]

	for _, text := range []string{
		"",
		"app: [",
		"configVersion: 0.2.0\n",
		"configVersion: 0.1.4\napp:\n  dnsProxy:\n    clientTTLCap: 123\n  clientRouting:\n    mode: unsupported\n",
		"configVersion: 0.1.4\napp:\n  netfilter:\n    iptables:\n      chainPrefix: MT\n",
		"configVersion: 0.1.4\napp:\n  netfilter:\n    ipset:\n      tablePrefix: ''\n",
	} {
		if err := os.WriteFile(path, []byte(text), 0600); err != nil {
			t.Fatal(err)
		}
		if err := a.loadConfigFile(path); err == nil {
			t.Fatalf("invalid config accepted: %q", text)
		}
		onDisk, err := os.ReadFile(path)
		if err != nil || string(onDisk) != text {
			t.Fatalf("invalid config was overwritten, read error: %v", err)
		}
		if !reflect.DeepEqual(a.Config(), before) || len(a.Groups()) != 1 || a.Groups()[0] != previousGroup {
			t.Fatal("failed reload changed live configuration or groups")
		}
	}

	newGroups := []config.Group{{ID: intID.ID{2}}, {ID: intID.ID{2}}}
	if err := a.ImportConfig(config.Config{ConfigVersion: "0.1.4", Groups: &newGroups}); err == nil {
		t.Fatal("duplicate group IDs accepted")
	}
	if len(a.Groups()) != 1 || a.Groups()[0] != previousGroup {
		t.Fatal("duplicate IDs changed live groups")
	}
}

func TestExportConfigDetachesMutableValues(t *testing.T) {
	a := newApp()
	a.config.Link = []string{"old"}
	a.config.DNSProxy.FallbackUpstream = &models.AppConfigDNSProxyServer{Address: "192.0.2.1"}
	group := &models.Group{Enable: true}
	sub := &models.Subscription{Enable: true, Interval: 60}
	if err := a.AddGroup(group); err != nil {
		t.Fatal(err)
	}
	if err := a.AddSubscription(sub); err != nil {
		t.Fatal(err)
	}
	snapshot := a.ExportConfig()
	a.config.Link[0] = "changed"
	a.config.DNSProxy.FallbackUpstream.Address = "192.0.2.2"
	group.Enable = false
	sub.Enable = false
	sub.Interval = 900
	if (*snapshot.App.Link)[0] != "old" || *snapshot.App.DNSProxy.FallbackUpstream.Address != "192.0.2.1" ||
		!*(*snapshot.Groups)[0].Enable || !*(*snapshot.Subscriptions)[0].Enable || *(*snapshot.Subscriptions)[0].Interval != 60 {
		t.Fatal("exported config still aliases mutable state")
	}
}

func TestConcurrentConfigSaveKeepsNewestSnapshot(t *testing.T) {
	a := newApp()
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := a.saveConfigFile(path); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 5)
	for writer := range 4 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range 12 {
				a.WithConfigWrite(func() { a.config.LogLevel = fmt.Sprintf("%d-%d", writer, i) })
				if err := a.saveConfigFile(path); err != nil {
					errs <- err
					return
				}
			}
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		for range 64 {
			if _, err := readSavedConfig(path); err != nil {
				errs <- err
				return
			}
		}
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Fatal(err)
	}
	saved, err := readSavedConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if *saved.App.LogLevel != a.Config().LogLevel {
		t.Fatal("last save persisted a stale snapshot")
	}
}

func readSavedConfig(path string) (config.Config, error) {
	var saved config.Config
	data, err := os.ReadFile(path)
	if err != nil {
		return saved, err
	}
	if err := yaml.Unmarshal(data, &saved); err != nil {
		return saved, err
	}
	if saved.ConfigVersion != "0.1.4" || saved.App == nil || saved.App.LogLevel == nil {
		return saved, fmt.Errorf("incomplete config snapshot")
	}
	return saved, nil
}

func TestAtomicConfigRenameFailureCleansTempFile(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "config.yaml")
	if err := os.Mkdir(target, 0700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(target, "keep")
	if err := os.WriteFile(marker, []byte("old"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := writeConfigAtomic(target, []byte("new")); err == nil {
		t.Fatal("rename over a directory unexpectedly succeeded")
	}
	files, err := os.ReadDir(dir)
	if err != nil || len(files) != 1 {
		t.Fatalf("temporary file leaked or target disappeared: %v (%v)", files, err)
	}
	if value, err := os.ReadFile(marker); err != nil || string(value) != "old" {
		t.Fatalf("failed rename changed its target: %q (%v)", value, err)
	}
}
