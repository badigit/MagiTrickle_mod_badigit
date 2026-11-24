package magitrickle

import (
	"testing"

	"magitrickle/config"
	"magitrickle/constant"
)

// TestPersistCacheDefaultOff — ключевой инвариант mt-0cf: дефолт выключен.
// Свежий конфиг (без ключа persistCache в yaml) не должен писать на диск.
func TestPersistCacheDefaultOff(t *testing.T) {
	if constant.DefaultAppConfig.DNSProxy.PersistCache {
		t.Error("PersistCache default must be false")
	}
}

// TestImportConfigPersistCache — ImportConfig применяет явное значение из yaml
// (нужно, чтобы пользователь мог осознанно включить фичу), а nil (ключ
// отсутствует в файле) оставляет дефолт нетронутым.
func TestImportConfigPersistCache(t *testing.T) {
	a := newApp()

	// Явный true в конфиге включает фичу.
	enable := true
	err := a.ImportConfig(config.Config{
		ConfigVersion: "0.1.3",
		App: &config.App{
			DNSProxy: &config.DNSProxy{PersistCache: &enable},
		},
	})
	if err != nil {
		t.Fatalf("ImportConfig error: %v", err)
	}
	if !a.config.DNSProxy.PersistCache {
		t.Error("explicit persistCache:true must be applied")
	}

	// Отсутствие ключа (nil) не трогает уже установленное значение.
	err = a.ImportConfig(config.Config{
		ConfigVersion: "0.1.3",
		App: &config.App{
			DNSProxy: &config.DNSProxy{},
		},
	})
	if err != nil {
		t.Fatalf("ImportConfig error: %v", err)
	}
	if !a.config.DNSProxy.PersistCache {
		t.Error("nil PersistCache in yaml must not reset previously applied value")
	}
}

// TestExportConfigRoundtripsPersistCache — ExportConfig отдаёт текущее значение,
// а не дефолт, чтобы SaveConfig не потерял осознанный выбор пользователя.
func TestExportConfigRoundtripsPersistCache(t *testing.T) {
	a := newApp()
	a.config.DNSProxy.PersistCache = true

	exported := a.ExportConfig()
	if exported.App.DNSProxy.PersistCache == nil || !*exported.App.DNSProxy.PersistCache {
		t.Error("ExportConfig must roundtrip PersistCache=true")
	}
}
