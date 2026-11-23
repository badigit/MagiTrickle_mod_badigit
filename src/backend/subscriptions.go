package magitrickle

import (
	"magitrickle/models"
)

// Subscriptions returns a snapshot of configured subscriptions.
func (a *App) Subscriptions() []*models.Subscription {
	subs := *a.subscriptions.Load()
	out := make([]*models.Subscription, len(subs))
	copy(out, subs)
	return out
}

// ClearSubscriptions removes all subscriptions from memory.
func (a *App) ClearSubscriptions() {
	emptySubscriptions := make([]*models.Subscription, 0)
	a.subscriptions.Store(&emptySubscriptions)
}

// AddSubscription appends a subscription after validating IDs.
func (a *App) AddSubscription(subscription *models.Subscription) error {
	subs := *a.subscriptions.Load()
	for _, existing := range subs {
		if existing.ID == subscription.ID {
			return ErrSubscriptionIDConflict
		}
	}

	if err := validateRuleIDs(subscription.Rules); err != nil {
		return err
	}

	newSubs := make([]*models.Subscription, len(subs)+1)
	copy(newSubs, subs)
	newSubs[len(subs)] = subscription
	a.subscriptions.Store(&newSubs)
	return nil
}

// RemoveSubscriptionByIndex removes a subscription by slice index.
func (a *App) RemoveSubscriptionByIndex(idx int) {
	subs := *a.subscriptions.Load()
	newSubs := make([]*models.Subscription, 0, len(subs)-1)
	newSubs = append(newSubs, subs[:idx]...)
	newSubs = append(newSubs, subs[idx+1:]...)
	a.subscriptions.Store(&newSubs)
}
