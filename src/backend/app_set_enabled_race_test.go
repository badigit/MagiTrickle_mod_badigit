package magitrickle

import (
	"sync"
	"testing"

	"magitrickle/models"
	"magitrickle/utils/intID"
	"magitrickle/utils/trie"
)

// TestSetEnabledRaceVsConfigMutation гоняет enable/disable конкурентно с
// правкой правил и чтением config.Enabled. Под `go test -race` ловит mt-03q:
// SetEnabled держал только lifecycleMu, а config.Enabled и конфиг-модель групп
// (g.Rules, читаемые Group.Sync и RebuildTrie из bring-up) писатели правят под
// cfgMu — то есть от них SetEnabled не был защищён вовсе.
//
// Подъём и снятие подменены хуками намеренно: настоящему bringUpRouting нужен
// netfilter, которого в тестовой среде нет. Хуки читают ровно то, что читает
// настоящий путь — g.Rules через RebuildTrie, — поэтому проверяется именно
// свойство «конфиг-лок удерживается вокруг подъёма/снятия», а не заглушка.
func TestSetEnabledRaceVsConfigMutation(t *testing.T) {
	a := &App{}
	a.domainTrie.Store(trie.New())
	a.config.Enabled = false
	a.saveConfigFn = func() error { return nil }

	g := &Group{
		Group: &models.Group{
			ID:     intID.RandomID(),
			Enable: true,
			Rules: []*models.Rule{
				{ID: intID.RandomID(), Type: models.RuleTypeDomain, Rule: "example.org", Enable: true},
				{ID: intID.RandomID(), Type: models.RuleTypeWildcard, Rule: "*.example.net", Enable: true},
			},
		},
	}
	g.enabled.Store(true)
	groups := []*Group{g}
	a.groups.Store(&groups)
	empty := make([]*Group, 0)
	a.subscriptionGroups.Store(&empty)

	// Стенд-ины подъёма/снятия: читают конфиг-модель групп так же, как это
	// делают Group.Sync и RebuildTrie на настоящем пути.
	readModel := func() {
		for _, grp := range a.routingGroups() {
			for _, rule := range grp.Rules {
				_ = rule.Rule
				_ = rule.IsEnabled()
			}
		}
		a.RebuildTrie()
	}
	a.bringUpFn = func() error { readModel(); a.routingActive.Store(true); return nil }
	a.bringDownFn = func() error { readModel(); a.routingActive.Store(false); return nil }

	var wg sync.WaitGroup
	stop := make(chan struct{})

	for i := 0; i < 4; i++ {
		wg.Add(1)
		enabled := i%2 == 0
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
					_ = a.SetEnabled(enabled)
				}
			}
		}()
	}

	// Читатель намерения пользователя: тот же путь, которым его смотрит API.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = a.routingIntended()
			}
		}
	}()

	// Писатель конфига: правка правила in-place + reassign среза, как это
	// делают PUT /groups и SIGHUP-reload.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			a.WithConfigWrite(func() {
				g.Group.Rules[0].Rule = "example.org"
				g.Group.Rules = append([]*models.Rule{}, g.Group.Rules...)
			})
		}
		close(stop)
	}()

	wg.Wait()
}
