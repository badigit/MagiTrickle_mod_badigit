package magitrickle

import (
	"context"
	"fmt"
	"magitrickle/app"
	"time"

	"magitrickle/models"
	subscriptionutils "magitrickle/utils/subscriptions"

	"github.com/rs/zerolog/log"
)

const subscriptionRuntimeGroupColor = "#ffffff"

func (a *App) routingGroups() []*Group {
	base := *a.groups.Load()
	subscriptionGroups := *a.subscriptionGroups.Load()

	result := make([]*Group, 0, len(base)+len(subscriptionGroups))
	result = append(result, base...)
	result = append(result, subscriptionGroups...)
	return result
}

// RoutingGroups отдаёт тот же набор, по которому реально строится роутинг:
// базовые группы плюс рантайм-группы подписок. API обязано смотреть сюда, а не
// на Groups(): у подписок отдельные ipset, и без них ответ о победителе по IP
// врёт для всякого адреса, попавшего в динамический сет подписки.
func (a *App) RoutingGroups() []app.Group {
	rg := a.routingGroups()
	out := make([]app.Group, len(rg))
	for i, g := range rg {
		out[i] = g
	}
	return out
}

// RebuildSubscriptionGroups пересобирает рантайм-группы подписок. Тело идёт под
// routingMutationMu: перестройка выключает старые группы и включает новые, то
// есть меняет те же цепочки, что и подъём/снятие роутинга. Без общей очереди
// она вклинивается в чужой teardown/bring-up, и часть цепочек остаётся от
// прошлого состояния.
//
// Вызывается и из-под cfgMu (автообновление подписок), поэтому порядок здесь
// «cfgMu -> routingMutationMu»; обратный порядок запрещён (см. комментарий к
// routingMutationMu в app.go).
func (a *App) RebuildSubscriptionGroups() error {
	a.routingMutationMu.Lock()
	defer a.routingMutationMu.Unlock()
	return a.rebuildSubscriptionGroupsLocked()
}

func (a *App) rebuildSubscriptionGroupsLocked() error {
	newGroups, err := a.prepareSubscriptionGroups(a.Subscriptions())
	if err != nil {
		return err
	}
	oldGroups := *a.subscriptionGroups.Load()
	if a.routingActive.Load() {
		for _, group := range oldGroups {
			_ = group.Disable()
		}
	}

	a.subscriptionGroups.Store(&newGroups)

	if !a.routingActive.Load() || a.nfHelper == nil {
		return nil
	}

	for _, group := range newGroups {
		if err := group.Enable(); err != nil {
			return fmt.Errorf("failed to enable subscription group: %w", err)
		}
	}

	a.SyncAllGroups()
	return nil
}

func (a *App) prepareSubscriptionGroups(subscriptions []*models.Subscription) ([]*Group, error) {
	groups := make([]*Group, 0, len(subscriptions))
	for _, subscription := range subscriptions {
		groupModel := &models.Group{
			ID:        subscription.ID,
			Name:      subscription.Name,
			Color:     subscriptionRuntimeGroupColor,
			Interface: subscription.Interface,
			Enable:    subscription.Enable,
			Rules:     subscription.Rules,
		}

		group, err := newGroupWithRuntimeID(groupModel, a, "s"+subscription.ID.String())
		if err != nil {
			return nil, fmt.Errorf("failed to create runtime subscription group: %w", err)
		}
		groups = append(groups, group)
	}
	return groups, nil
}

// rulesEquivalent reports whether two rule lists describe the same set of
// rules. ID and Name are ignored because FetchRules generates a fresh random
// ID on every fetch and Name is not provided by the source format.
func rulesEquivalent(a, b []*models.Rule) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		x, y := a[i], b[i]
		if x == nil || y == nil {
			if x != y {
				return false
			}
			continue
		}
		if x.Type != y.Type || x.Rule != y.Rule || x.Enable != y.Enable {
			return false
		}
	}
	return true
}

func (a *App) startSubscriptionSyncLoop(ctx context.Context, _ chan error) {
	go func() {
		ticker := time.NewTicker(1 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := a.syncDueSubscriptions(ctx); err != nil {
					log.Error().Err(err).Msg("subscription auto-sync failed")
				}
			}
		}
	}()
}

func (a *App) syncDueSubscriptions(ctx context.Context) error {
	now := time.Now()

	// Фаза 1: определить due-подписки и зафетчить (сетевой I/O — СТРОГО вне конфиг-лока,
	// иначе FetchRules заблокирует датапас на всё время HTTP-запроса). Чтение полей
	// подписки — под RLock (API мутирует их in-place, mt-jfc).
	type pending struct {
		sub   *models.Subscription
		rules []*models.Rule
	}
	var pend []pending
	for _, subscription := range a.Subscriptions() {
		var due bool
		var url string
		a.WithConfigRead(func() {
			due = subscription.Enable && subscription.Interval > 0 && subscription.URL != "" &&
				(subscription.LastUpdate == 0 ||
					now.Sub(time.UnixMilli(subscription.LastUpdate)) >= time.Duration(subscription.Interval)*time.Second)
			url = subscription.URL
		})
		if !due {
			continue
		}
		rules, err := subscriptionutils.FetchRules(ctx, url)
		if err != nil {
			log.Error().
				Err(err).
				Str("subscriptionId", subscription.ID.String()).
				Str("url", url).
				Msg("failed to auto-sync subscription")
			continue
		}
		pend = append(pend, pending{subscription, rules})
	}
	if len(pend) == 0 {
		return nil
	}

	// Фаза 2: применить мутации + rebuild под эксклюзивным конфиг-локом (mt-jfc, mt-6q1).
	changed := false
	var rebuildErr error
	a.WithConfigWrite(func() {
		for _, p := range pend {
			if rulesEquivalent(p.sub.Rules, p.rules) {
				// Источник не изменился — bump timestamp, без rebuild/сохранения (ipset/флеш).
				p.sub.LastUpdate = now.UnixMilli()
				continue
			}
			p.sub.Rules = p.rules
			p.sub.LastUpdate = now.UnixMilli()
			changed = true
		}
		if changed {
			rebuildErr = a.RebuildSubscriptionGroups()
		}
	})
	if rebuildErr != nil {
		return rebuildErr
	}
	if !changed {
		return nil
	}
	// SaveConfig — ВНЕ лока (флеш-I/O; SaveConfig берёт RLock сам).
	if err := a.SaveConfig(); err != nil {
		return fmt.Errorf("failed to save config after auto-sync: %w", err)
	}

	return nil
}
