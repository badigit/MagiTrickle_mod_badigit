package magitrickle

import (
	"errors"
	"fmt"
	"slices"

	"magitrickle/app"
	"magitrickle/models"
	"magitrickle/utils/intID"
)

func (a *App) prepareGroups(groups []*models.Group) ([]*Group, error) {
	result := make([]*Group, 0, len(groups))
	seen := make(map[intID.ID]struct{}, len(groups))
	for _, model := range groups {
		if _, duplicate := seen[model.ID]; duplicate {
			return nil, fmt.Errorf("%w: %w %s", app.ErrInvalidGroups, ErrGroupIDConflict, model.ID.String())
		}
		seen[model.ID] = struct{}{}
		if err := validateRuleIDs(model.Rules); err != nil {
			return nil, fmt.Errorf("%w: group %q: %w", app.ErrInvalidGroups, model.Name, err)
		}
		group, err := NewGroup(model, a)
		if err != nil {
			return nil, err
		}
		result = append(result, group)
	}
	return result, nil
}

// ReplaceGroups is called under cfgMu. Keep subscriptions after user groups
// in both the kernel and the DNS matcher.
func (a *App) ReplaceGroups(groupModels []*models.Group) error {
	groups, err := a.prepareGroups(groupModels)
	if err != nil {
		return err
	}
	return a.WithRoutingMutation(func() error {
		next := slices.Concat(groups, *a.subscriptionGroups.Load())
		if err := a.replaceGroupRoutes(next, a.config.Netfilter, nil); err != nil {
			return err
		}
		a.groups.Store(&groups)
		a.RebuildTrie()
		return nil
	})
}

func validateRuleIDs(rules []*models.Rule) error {
	seen := make(map[intID.ID]struct{}, len(rules))
	for _, rule := range rules {
		if rule == nil {
			return errors.New("missing rule")
		}
		if _, duplicate := seen[rule.ID]; duplicate {
			return ErrRuleIDConflict
		}
		seen[rule.ID] = struct{}{}
	}
	return nil
}

// replaceGroupRoutes runs under cfgMu and routingMutationMu. The caller
// publishes the new models only after all routes and final settings apply.
func (a *App) replaceGroupRoutes(next []*Group, config models.AppConfigNetfilter, finish func() error) error {
	if !a.routingActive.Load() {
		if finish != nil {
			return finish()
		}
		return nil
	}
	if a.nfHelper == nil {
		return errors.New("active routing has no netfilter helper")
	}
	var previous []*Group
	for _, group := range a.routingGroups() {
		if group.Enabled() {
			previous = append(previous, group)
		}
	}
	restore := func(err, cleanupErr error) error {
		restoreErr := enableGroupRoutes(previous, a.config.Netfilter)
		a.RebuildTrie()
		if rollbackErr := errors.Join(cleanupErr, restoreErr); rollbackErr != nil {
			return errors.Join(err, fmt.Errorf("group route rollback incomplete: %w", rollbackErr))
		}
		return err
	}
	if err := disableGroupRoutes(previous); err != nil {
		return restore(err, nil)
	}
	if err := enableGroupRoutes(next, config); err != nil {
		return restore(err, disableGroupRoutes(next))
	}
	if finish != nil {
		if err := finish(); err != nil {
			return restore(err, disableGroupRoutes(next))
		}
	}
	return nil
}

func disableGroupRoutes(groups []*Group) error {
	var errs []error
	for _, group := range groups {
		if err := group.Disable(); err != nil {
			errs = append(errs, fmt.Errorf("disable group %q: %w", group.Name, err))
		}
	}
	return errors.Join(errs...)
}

func enableGroupRoutes(groups []*Group, config models.AppConfigNetfilter) error {
	var errs []error
	for _, group := range groups {
		if err := group.enableWithConfig(config); err != nil {
			errs = append(errs, fmt.Errorf("enable group %q: %w", group.Name, err))
			continue
		}
		if err := group.Sync(); err != nil {
			errs = append(errs, fmt.Errorf("sync group %q: %w", group.Name, err))
		}
	}
	return errors.Join(errs...)
}
