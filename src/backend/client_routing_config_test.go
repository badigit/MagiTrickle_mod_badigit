package magitrickle

import (
	"reflect"
	"testing"

	"magitrickle/config"
	"magitrickle/models"
)

func TestImportExportClientRouting(t *testing.T) {
	a := newApp()
	mode := models.ClientRoutingModeExclude
	values := []string{"192.168.1.25", "192.168.1.99/24", "2001:db8::1"}
	if err := a.ImportConfig(config.Config{
		ConfigVersion: "0.1.4",
		App: &config.App{ClientRouting: &config.ClientRouting{
			Mode:           &mode,
			SourceNetworks: &values,
		}},
	}); err != nil {
		t.Fatalf("ImportConfig failed: %v", err)
	}

	want := []string{"192.168.1.25", "192.168.1.0/24", "2001:db8::1"}
	if !reflect.DeepEqual(a.config.ClientRouting.SourceNetworks, want) {
		t.Fatalf("client routing mismatch: want %v, got %v", want, a.config.ClientRouting.SourceNetworks)
	}
	exported := a.ExportConfig()
	if exported.ConfigVersion != "0.1.4" {
		t.Fatalf("config version mismatch: %s", exported.ConfigVersion)
	}
	if exported.App.ClientRouting == nil || exported.App.ClientRouting.SourceNetworks == nil || !reflect.DeepEqual(*exported.App.ClientRouting.SourceNetworks, want) {
		t.Fatalf("exported client routing mismatch: %#v", exported.App.ClientRouting)
	}
}

func TestImportClientRoutingRejectsUnsupportedMode(t *testing.T) {
	a := newApp()
	mode := "include"
	if err := a.ImportConfig(config.Config{
		ConfigVersion: "0.1.4",
		App:           &config.App{ClientRouting: &config.ClientRouting{Mode: &mode}},
	}); err == nil {
		t.Fatal("expected unsupported mode error")
	}
}
