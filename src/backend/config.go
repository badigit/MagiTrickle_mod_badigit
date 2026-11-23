package magitrickle

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"magitrickle/config"
	"magitrickle/constant"
	"magitrickle/models"
	"magitrickle/utils/intID"
	"magitrickle/utils/netfilterTools"

	"github.com/dlclark/regexp2"
	"github.com/rs/zerolog/log"
	"golang.org/x/sys/unix"
	"gopkg.in/yaml.v3"
)

var colorRegExp = regexp2.MustCompile(`^#[0-9a-f]{6}$`, regexp2.IgnoreCase)

const cfgFolderLocation = constant.AppStateDir
const cfgFileLocation = cfgFolderLocation + "/config.yaml"
const cfgInterfaceFileLocation = cfgFolderLocation + "/config_interfaces.mtrickle"

// recordsCacheSnapshotLocation — персист DNS-кэша между запусками (mt-pqa).
const recordsCacheSnapshotLocation = cfgFolderLocation + "/records-cache.snap"

// normalizeDirectPriority приводит режим арбитража direct к известному
// значению. Незнакомое значение (опечатка в YAML, конфиг из более новой
// версии) не должно менять маршрутизацию молча: падаем в absolute — дефолт,
// при котором direct перебивает всех, — и говорим об этом в лог.
func normalizeDirectPriority(mode string) string {
	switch mode {
	case models.DirectPriorityAbsolute, models.DirectPriorityByOrder:
		return mode
	default:
		log.Warn().
			Str("value", mode).
			Str("fallback", models.DirectPriorityAbsolute).
			Msg("unknown netfilter.directPriority, falling back")
		return models.DirectPriorityAbsolute
	}
}

func (a *App) LoadConfig() error {
	return a.loadConfigFile(cfgFileLocation)
}

func (a *App) loadConfigFile(path string) error {
	cfgFile, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("failed to read config file: %w", err)
	}
	cfg := config.Config{}
	err = yaml.Unmarshal(cfgFile, &cfg)
	if err != nil {
		return fmt.Errorf("failed to unmarshal config file: %w", err)
	}
	err = a.ImportConfig(cfg)
	if err != nil {
		return fmt.Errorf("failed to import config file: %w", err)
	}
	return nil
}

func (a *App) SaveConfig() error {
	return a.saveConfigFile(cfgFileLocation)
}

func (a *App) saveConfigFile(path string) error {
	// Serialize from snapshot through rename, without holding cfgMu during I/O.
	a.configSaveMu.Lock()
	defer a.configSaveMu.Unlock()
	cfg := a.ExportConfig()
	out, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config file: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(path), os.ModePerm); err != nil {
		return fmt.Errorf("failed to create config folder: %w", err)
	}
	if err := writeConfigAtomic(path, out); err != nil {
		return fmt.Errorf("failed to write config file: %w", err)
	}
	return nil
}

func writeConfigAtomic(path string, data []byte) error {
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	file, err := os.CreateTemp(dir.Name(), "."+filepath.Base(path)+".*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	_, err = file.Write(data)
	if err == nil {
		err = file.Sync()
	}
	if err := errors.Join(err, file.Close()); err != nil {
		return err
	}
	if err := os.Rename(file.Name(), path); err != nil {
		return err
	}
	if err := dir.Sync(); err != nil && !errors.Is(err, unix.EINVAL) && !errors.Is(err, unix.ENOTSUP) {
		// The rename committed the new file. Report uncertainty in durability
		// without asking callers to restore a different runtime config.
		log.Warn().Err(err).Msg("failed to sync config directory after rename")
	}
	return nil
}

func (a *App) LoadInterfaceConfig() error {
	cfgFile, err := os.ReadFile(cfgInterfaceFileLocation)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return fmt.Errorf("failed to read interface config file: %w", err)
	}
	aliases := make(map[string]string)
	if err := yaml.Unmarshal(cfgFile, &aliases); err != nil {
		return fmt.Errorf("failed to unmarshal interface config file: %w", err)
	}
	a.SetInterfaceAliases(aliases)
	return nil
}

func (a *App) SaveInterfaceConfig() error {
	out, err := yaml.Marshal(a.InterfaceAliases())
	if err != nil {
		return fmt.Errorf("failed to marshal interface config file: %w", err)
	}
	if err := os.MkdirAll(cfgFolderLocation, os.ModePerm); err != nil {
		return fmt.Errorf("failed to create config folder: %w", err)
	}
	if err := os.WriteFile(cfgInterfaceFileLocation, out, 0600); err != nil {
		return fmt.Errorf("failed to write interface config file: %w", err)
	}
	return nil
}

func (a *App) ImportConfig(cfg config.Config) error {
	a.lifecycleMu.Lock()
	defer a.lifecycleMu.Unlock()
	if a.shuttingDown {
		return errors.New("cannot reload config during shutdown")
	}
	a.clientRoutingMu.Lock()
	defer a.clientRoutingMu.Unlock()
	a.cfgMu.Lock()
	defer a.cfgMu.Unlock()

	if !strings.HasPrefix(cfg.ConfigVersion, "0.1.") {
		return ErrConfigUnsupportedVersion
	}

	nextConfig := a.config
	if cfg.App != nil {
		if cfg.App.Enabled != nil {
			nextConfig.Enabled = *cfg.App.Enabled
		}
		if cfg.App.HTTPWeb != nil {
			if cfg.App.HTTPWeb.Enabled != nil {
				nextConfig.HTTPWeb.Enabled = *cfg.App.HTTPWeb.Enabled
			}
			if cfg.App.HTTPWeb.Host != nil {
				if cfg.App.HTTPWeb.Host.Address != nil {
					nextConfig.HTTPWeb.Host.Address = *cfg.App.HTTPWeb.Host.Address
				}
				if cfg.App.HTTPWeb.Host.Port != nil {
					nextConfig.HTTPWeb.Host.Port = *cfg.App.HTTPWeb.Host.Port
				}
			}
			if cfg.App.HTTPWeb.Skin != nil {
				nextConfig.HTTPWeb.Skin = *cfg.App.HTTPWeb.Skin
			}
		}

		if cfg.App.HTTPWeb != nil && cfg.App.HTTPWeb.Auth != nil {
			if cfg.App.HTTPWeb.Auth.Enabled != nil {
				nextConfig.HTTPWeb.Auth.Enabled = *cfg.App.HTTPWeb.Auth.Enabled
			}
		}

		if cfg.App.DNSProxy != nil {
			if cfg.App.DNSProxy.Upstream != nil {
				if cfg.App.DNSProxy.Upstream.Address != nil {
					nextConfig.DNSProxy.Upstream.Address = *cfg.App.DNSProxy.Upstream.Address
				}
				if cfg.App.DNSProxy.Upstream.Port != nil {
					nextConfig.DNSProxy.Upstream.Port = *cfg.App.DNSProxy.Upstream.Port
				}
			}
			if cfg.App.DNSProxy.Host != nil {
				if cfg.App.DNSProxy.Host.Address != nil {
					nextConfig.DNSProxy.Host.Address = *cfg.App.DNSProxy.Host.Address
				}
				if cfg.App.DNSProxy.Host.Port != nil {
					nextConfig.DNSProxy.Host.Port = *cfg.App.DNSProxy.Host.Port
				}
			}
			if cfg.App.DNSProxy.FallbackUpstream != nil {
				fb := models.AppConfigDNSProxyServer{}
				if cfg.App.DNSProxy.FallbackUpstream.Address != nil {
					fb.Address = *cfg.App.DNSProxy.FallbackUpstream.Address
				}
				if cfg.App.DNSProxy.FallbackUpstream.Port != nil {
					fb.Port = *cfg.App.DNSProxy.FallbackUpstream.Port
				}
				if fb.Address != "" && fb.Port != 0 {
					nextConfig.DNSProxy.FallbackUpstream = &fb
				}
			}
			if cfg.App.DNSProxy.DisableRemap53 != nil {
				nextConfig.DNSProxy.DisableRemap53 = *cfg.App.DNSProxy.DisableRemap53
			}
			if cfg.App.DNSProxy.DisableFakePTR != nil {
				nextConfig.DNSProxy.DisableFakePTR = *cfg.App.DNSProxy.DisableFakePTR
			}
			if cfg.App.DNSProxy.DisableDropAAAA != nil {
				nextConfig.DNSProxy.DisableDropAAAA = *cfg.App.DNSProxy.DisableDropAAAA
			}
			if cfg.App.DNSProxy.MaxIdleConns != nil {
				nextConfig.DNSProxy.MaxIdleConns = *cfg.App.DNSProxy.MaxIdleConns
			}
			if cfg.App.DNSProxy.MaxConcurrent != nil {
				nextConfig.DNSProxy.MaxConcurrent = *cfg.App.DNSProxy.MaxConcurrent
			}
			if cfg.App.DNSProxy.Timeout != nil {
				nextConfig.DNSProxy.Timeout = time.Duration(*cfg.App.DNSProxy.Timeout) * time.Millisecond
			}
			if cfg.App.DNSProxy.ClientTTLCap != nil {
				nextConfig.DNSProxy.ClientTTLCap = *cfg.App.DNSProxy.ClientTTLCap
			}
			if cfg.App.DNSProxy.PersistCache != nil {
				nextConfig.DNSProxy.PersistCache = *cfg.App.DNSProxy.PersistCache
			}
		}

		if cfg.App.ClientRouting != nil {
			mode := nextConfig.ClientRouting.Mode
			if cfg.App.ClientRouting.Mode != nil {
				mode = *cfg.App.ClientRouting.Mode
			}
			if mode != models.ClientRoutingModeExclude {
				return fmt.Errorf("unsupported client routing mode %q", mode)
			}
			sourceNetworks := nextConfig.ClientRouting.SourceNetworks
			if cfg.App.ClientRouting.SourceNetworks != nil {
				sourceNetworks = *cfg.App.ClientRouting.SourceNetworks
			}
			normalized, _, err := netfilterTools.NormalizeSourceNetworks(sourceNetworks)
			if err != nil {
				return err
			}
			nextConfig.ClientRouting = models.AppConfigClientRouting{
				Mode:           mode,
				SourceNetworks: normalized,
			}
		}

		if cfg.App.Netfilter != nil {
			if cfg.App.Netfilter.IPTables != nil {
				if cfg.App.Netfilter.IPTables.ChainPrefix != nil {
					nextConfig.Netfilter.IPTables.ChainPrefix = *cfg.App.Netfilter.IPTables.ChainPrefix
				}
			}
			if cfg.App.Netfilter.IPSet != nil {
				if cfg.App.Netfilter.IPSet.TablePrefix != nil {
					nextConfig.Netfilter.IPSet.TablePrefix = *cfg.App.Netfilter.IPSet.TablePrefix
				}
				if cfg.App.Netfilter.IPSet.AdditionalTTL != nil {
					nextConfig.Netfilter.IPSet.AdditionalTTL = *cfg.App.Netfilter.IPSet.AdditionalTTL
				}
			}
			if cfg.App.Netfilter.DisableIPv4 != nil {
				nextConfig.Netfilter.DisableIPv4 = *cfg.App.Netfilter.DisableIPv4
			}
			if cfg.App.Netfilter.DisableIPv6 != nil {
				nextConfig.Netfilter.DisableIPv6 = *cfg.App.Netfilter.DisableIPv6
			}
			if cfg.App.Netfilter.StartMarkTableIndex != nil {
				nextConfig.Netfilter.StartMarkTableIndex = *cfg.App.Netfilter.StartMarkTableIndex
			}
			if cfg.App.Netfilter.TProxyPort != nil {
				nextConfig.Netfilter.TProxyPort = *cfg.App.Netfilter.TProxyPort
			}
			if cfg.App.Netfilter.DirectPriority != nil {
				nextConfig.Netfilter.DirectPriority = normalizeDirectPriority(*cfg.App.Netfilter.DirectPriority)
			}
		}

		if cfg.App.Link != nil {
			nextConfig.Link = slices.Clone(*cfg.App.Link)
		}

		if cfg.App.ShowAllInterfaces != nil {
			nextConfig.ShowAllInterfaces = *cfg.App.ShowAllInterfaces
		}

		if cfg.App.LogLevel != nil {
			nextConfig.LogLevel = *cfg.App.LogLevel
		}
	}

	groups := *a.groups.Load()
	if cfg.Groups != nil {
		groupModels := make([]*models.Group, 0, len(*cfg.Groups))
		for _, group := range *cfg.Groups {
			if match, _ := colorRegExp.MatchString(group.Color); !match {
				group.Color = "#ffffff"
			} else {
				group.Color = strings.ToLower(group.Color)
			}
			groupModels = append(groupModels, newGroupModel(group))
		}
		var err error
		groups, err = a.prepareGroups(groupModels)
		if err != nil {
			return err
		}
	}

	subscriptions := *a.subscriptions.Load()
	subscriptionGroups := *a.subscriptionGroups.Load()
	if cfg.Subscriptions != nil {
		subscriptions = make([]*models.Subscription, 0, len(*cfg.Subscriptions))
		seen := make(map[intID.ID]struct{}, len(*cfg.Subscriptions))
		for _, subscription := range *cfg.Subscriptions {
			model := newSubscriptionModel(subscription)
			if _, duplicate := seen[model.ID]; duplicate {
				return ErrSubscriptionIDConflict
			}
			seen[model.ID] = struct{}{}
			if err := validateRuleIDs(model.Rules); err != nil {
				return err
			}
			subscriptions = append(subscriptions, model)
		}
		var err error
		subscriptionGroups, err = a.prepareSubscriptionGroups(subscriptions)
		if err != nil {
			return err
		}
	}

	return a.WithRoutingMutation(func() error {
		updateBypass := func() error {
			if cfg.App == nil || cfg.App.ClientRouting == nil || a.nfHelper == nil {
				return nil
			}
			_, err := a.nfHelper.UpdateClientBypass(nextConfig.ClientRouting.SourceNetworks)
			if err != nil {
				return fmt.Errorf("failed to update client bypass: %w", err)
			}
			return nil
		}
		if cfg.Groups != nil || cfg.Subscriptions != nil {
			next := slices.Concat(groups, subscriptionGroups)
			if err := a.replaceGroupRoutes(next, nextConfig.Netfilter, updateBypass); err != nil {
				return err
			}
		} else if err := updateBypass(); err != nil {
			return err
		}

		a.config = nextConfig
		a.groups.Store(&groups)
		a.subscriptions.Store(&subscriptions)
		a.subscriptionGroups.Store(&subscriptionGroups)
		a.RebuildTrie()
		return nil
	})
}

func newGroupModel(group config.Group) *models.Group {
	return &models.Group{
		ID: group.ID, Name: group.Name, Color: group.Color, Interface: group.Interface,
		Enable: group.Enable == nil || *group.Enable,
		Rules:  importRules(group.Rules),
	}
}

func newSubscriptionModel(subscription config.Subscription) *models.Subscription {
	interval := int64(86400)
	if subscription.Interval != nil && *subscription.Interval > 0 {
		interval = *subscription.Interval
	}
	lastUpdate := int64(0)
	if subscription.LastUpdate != nil {
		lastUpdate = *subscription.LastUpdate
	}
	return &models.Subscription{
		ID: subscription.ID, Name: subscription.Name, Interface: subscription.Interface,
		Enable: subscription.Enable == nil || *subscription.Enable, URL: subscription.URL,
		Interval: interval, LastUpdate: lastUpdate, Rules: importRules(subscription.Rules),
	}
}

func importRules(rules []config.Rule) []*models.Rule {
	result := make([]*models.Rule, len(rules))
	for i, rule := range rules {
		result[i] = &models.Rule{ID: rule.ID, Name: rule.Name, Type: rule.Type, Rule: rule.Rule, Enable: rule.Enable}
	}
	return result
}

func (a *App) ExportConfig() config.Config {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	settings := a.configSnapshotLocked()
	gs := *a.groups.Load()
	groups := make([]config.Group, len(gs))
	for idx, group := range gs {
		enabled := group.Group.Enable
		groupCfg := config.Group{
			ID:        group.ID,
			Name:      group.Name,
			Color:     group.Color,
			Interface: group.Interface,
			Enable:    &enabled,
			Rules:     make([]config.Rule, len(group.Rules)),
		}
		for idx, rule := range group.Rules {
			groupCfg.Rules[idx] = config.Rule{
				ID:     rule.ID,
				Name:   rule.Name,
				Type:   rule.Type,
				Rule:   rule.Rule,
				Enable: rule.Enable,
			}
		}
		groups[idx] = groupCfg
	}

	ss := *a.subscriptions.Load()
	subscriptions := make([]config.Subscription, len(ss))
	for idx, subscription := range ss {
		enabled, lastUpdate, interval := subscription.Enable, subscription.LastUpdate, subscription.Interval
		subscriptionCfg := config.Subscription{
			ID:         subscription.ID,
			Name:       subscription.Name,
			Interface:  subscription.Interface,
			Enable:     &enabled,
			URL:        subscription.URL,
			LastUpdate: &lastUpdate,
			Interval:   &interval,
			Rules:      make([]config.Rule, len(subscription.Rules)),
		}
		for ruleIdx, rule := range subscription.Rules {
			subscriptionCfg.Rules[ruleIdx] = config.Rule{
				ID:     rule.ID,
				Name:   rule.Name,
				Type:   rule.Type,
				Rule:   rule.Rule,
				Enable: rule.Enable,
			}
		}
		subscriptions[idx] = subscriptionCfg
	}

	return config.Config{
		ConfigVersion: "0.1.4",
		App: &config.App{
			Enabled: &settings.Enabled,
			HTTPWeb: &config.HTTPWeb{
				Enabled: &settings.HTTPWeb.Enabled,
				Auth: &config.Auth{
					Enabled: &settings.HTTPWeb.Auth.Enabled,
				},
				Host: &config.HTTPWebServer{
					Address: &settings.HTTPWeb.Host.Address,
					Port:    &settings.HTTPWeb.Host.Port,
				},
				Skin: &settings.HTTPWeb.Skin,
			},
			DNSProxy: &config.DNSProxy{
				Host: &config.DNSProxyServer{
					Address: &settings.DNSProxy.Host.Address,
					Port:    &settings.DNSProxy.Host.Port,
				},
				Upstream: &config.DNSProxyServer{
					Address: &settings.DNSProxy.Upstream.Address,
					Port:    &settings.DNSProxy.Upstream.Port,
				},
				FallbackUpstream: func() *config.DNSProxyServer {
					if settings.DNSProxy.FallbackUpstream == nil {
						return nil
					}
					return &config.DNSProxyServer{
						Address: &settings.DNSProxy.FallbackUpstream.Address,
						Port:    &settings.DNSProxy.FallbackUpstream.Port,
					}
				}(),
				DisableRemap53:  &settings.DNSProxy.DisableRemap53,
				DisableFakePTR:  &settings.DNSProxy.DisableFakePTR,
				DisableDropAAAA: &settings.DNSProxy.DisableDropAAAA,
				MaxIdleConns:    &settings.DNSProxy.MaxIdleConns,
				MaxConcurrent:   &settings.DNSProxy.MaxConcurrent,
				Timeout:         func(u uint) *uint { return &u }(uint(settings.DNSProxy.Timeout.Milliseconds())),
				ClientTTLCap:    &settings.DNSProxy.ClientTTLCap,
				PersistCache:    &settings.DNSProxy.PersistCache,
			},
			ClientRouting: &config.ClientRouting{
				Mode:           &settings.ClientRouting.Mode,
				SourceNetworks: &settings.ClientRouting.SourceNetworks,
			},
			Netfilter: &config.Netfilter{
				IPTables: &config.IPTables{
					ChainPrefix: &settings.Netfilter.IPTables.ChainPrefix,
				},
				IPSet: &config.IPSet{
					TablePrefix:   &settings.Netfilter.IPSet.TablePrefix,
					AdditionalTTL: &settings.Netfilter.IPSet.AdditionalTTL,
				},
				DisableIPv4:         &settings.Netfilter.DisableIPv4,
				DisableIPv6:         &settings.Netfilter.DisableIPv6,
				StartMarkTableIndex: &settings.Netfilter.StartMarkTableIndex,
				TProxyPort:          &settings.Netfilter.TProxyPort,
				DirectPriority:      &settings.Netfilter.DirectPriority,
			},
			Link:              &settings.Link,
			ShowAllInterfaces: &settings.ShowAllInterfaces,
			LogLevel:          &settings.LogLevel,
		},
		Groups:        &groups,
		Subscriptions: &subscriptions,
	}
}

// configSnapshotLocked copies mutable fields while cfgMu is held.
func (a *App) configSnapshotLocked() models.AppConfig {
	settings := a.config
	settings.Link = slices.Clone(settings.Link)
	settings.ClientRouting.SourceNetworks = slices.Clone(settings.ClientRouting.SourceNetworks)
	if fallback := settings.DNSProxy.FallbackUpstream; fallback != nil {
		copy := *fallback
		settings.DNSProxy.FallbackUpstream = &copy
	}
	return settings
}
