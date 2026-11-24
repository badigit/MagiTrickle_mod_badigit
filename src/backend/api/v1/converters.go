package v1

import (
	"fmt"
	"strings"

	"magitrickle/api/v1/types"
	"magitrickle/models"
	"magitrickle/utils/intID"

	"github.com/dlclark/regexp2"
)

var colorRegExp = regexp2.MustCompile(`^#[0-9a-f]{6}$`, regexp2.IgnoreCase)

func detachedGroupFromReq(req types.GroupReq, existing *models.Group) (*models.Group, error) {
	if req.Rules != nil {
		seen := make(map[intID.ID]struct{}, len(*req.Rules))
		for _, rule := range *req.Rules {
			if rule.ID != nil {
				if _, duplicate := seen[*rule.ID]; duplicate {
					return nil, fmt.Errorf("duplicate rule id %s", rule.ID.String())
				}
				seen[*rule.ID] = struct{}{}
			}
		}
	}
	if existing == nil {
		return GroupFromReq(req, nil)
	}
	group := *existing
	return GroupFromReq(req, &group)
}

func groupMetadataOnly(req types.GroupReq, group *models.Group) bool {
	if (req.ID != nil && *req.ID != group.ID) || req.Interface != group.Interface ||
		(req.Enable == nil || *req.Enable) != group.Enable {
		return false
	}
	if req.Rules == nil {
		return true
	}
	if len(*req.Rules) != len(group.Rules) {
		return false
	}
	for i, rule := range *req.Rules {
		old := group.Rules[i]
		if rule.ID == nil || *rule.ID != old.ID || rule.Name != old.Name ||
			rule.Type != old.Type || rule.Rule != old.Rule || rule.Enable != old.Enable {
			return false
		}
	}
	return true
}

func applyGroupMetadata(req types.GroupReq, group *models.Group) {
	group.Name = req.Name
	group.Color = "#ffffff"
	if match, _ := colorRegExp.MatchString(req.Color); match {
		group.Color = strings.ToLower(req.Color)
	}
}

func GroupFromReq(req types.GroupReq, existing *models.Group) (*models.Group, error) {
	var group *models.Group
	if existing == nil {
		group = &models.Group{ID: intID.RandomID()}
	} else {
		group = existing
	}
	if req.ID != nil {
		if existing != nil && group.ID != *req.ID {
			return nil, fmt.Errorf("group ID mismatch")
		}
		if existing == nil {
			group.ID = *req.ID
		}
	}
	applyGroupMetadata(req, group)
	group.Interface = req.Interface
	group.Enable = true
	if req.Enable != nil {
		group.Enable = *req.Enable
	}

	if req.Rules != nil {
		newRules := make([]*models.Rule, len(*req.Rules))
		for i, ruleReq := range *req.Rules {
			newRules[i] = RuleFromReq(ruleReq, group.Rules)
		}
		group.Rules = newRules
	}
	return group, nil
}

func RuleFromReq(ruleReq types.RuleReq, existingRules []*models.Rule) *models.Rule {
	if ruleReq.ID != nil {
		for _, r := range existingRules {
			if r.ID == *ruleReq.ID {
				return newRuleFromReq(ruleReq, r.ID)
			}
		}
	}
	return newRuleFromReq(ruleReq, intID.RandomID())
}

func newRuleFromReq(req types.RuleReq, id intID.ID) *models.Rule {
	return &models.Rule{
		ID:     id,
		Name:   req.Name,
		Type:   req.Type,
		Rule:   req.Rule,
		Enable: req.Enable,
	}
}

func RespFromGroups(groups []*models.Group, withRules bool) types.GroupsRes {
	groupResList := make([]types.GroupRes, len(groups))
	for i, group := range groups {
		groupResList[i] = RespFromGroup(group, withRules)
	}
	return types.GroupsRes{Groups: &groupResList}
}

func RespFromGroup(group *models.Group, withRules bool) types.GroupRes {
	groupRes := types.GroupRes{
		ID:        group.ID,
		Name:      group.Name,
		Color:     group.Color,
		Interface: group.Interface,
		Enable:    group.Enable,
	}
	if withRules {
		groupRes.RulesRes = RespFromRules(group.Rules)
	}
	return groupRes
}

func RespFromRules(rules []*models.Rule) types.RulesRes {
	ruleResList := make([]types.RuleRes, len(rules))
	for i, rule := range rules {
		ruleResList[i] = RespFromRule(rule)
	}
	return types.RulesRes{Rules: &ruleResList}
}

func RespFromRule(rule *models.Rule) types.RuleRes {
	return types.RuleRes{
		ID:     rule.ID,
		Name:   rule.Name,
		Type:   rule.Type,
		Rule:   rule.Rule,
		Enable: rule.Enable,
	}
}

func SubscriptionFromReq(req types.SubscriptionReq, existing *models.Subscription) (*models.Subscription, error) {
	var subscription *models.Subscription
	if existing == nil {
		subscription = &models.Subscription{ID: intID.RandomID(), Interval: 86400}
	} else {
		subscription = existing
	}
	if req.ID != nil {
		if existing != nil && subscription.ID != *req.ID {
			return nil, fmt.Errorf("subscription ID mismatch")
		}
		if existing == nil {
			subscription.ID = *req.ID
		}
	}

	subscription.Name = req.Name
	subscription.Interface = req.Interface
	subscription.Enable = req.Enable
	subscription.URL = req.URL

	if req.LastUpdate != nil {
		subscription.LastUpdate = *req.LastUpdate
	}
	if req.Interval != nil && *req.Interval > 0 {
		subscription.Interval = *req.Interval
	}
	if subscription.Interval == 0 {
		subscription.Interval = 86400
	}

	if req.Rules != nil {
		newRules := make([]*models.Rule, len(*req.Rules))
		for i, ruleReq := range *req.Rules {
			newRules[i] = RuleFromReq(ruleReq, subscription.Rules)
		}
		subscription.Rules = newRules
	}

	return subscription, nil
}

func RespFromSubscriptions(subscriptions []*models.Subscription) types.SubscriptionsRes {
	subscriptionResList := make([]types.SubscriptionRes, len(subscriptions))
	for i, subscription := range subscriptions {
		subscriptionResList[i] = RespFromSubscription(subscription)
	}
	return types.SubscriptionsRes{Subscriptions: &subscriptionResList}
}

func RespFromSubscription(subscription *models.Subscription) types.SubscriptionRes {
	return types.SubscriptionRes{
		ID:         subscription.ID,
		Name:       subscription.Name,
		Interface:  subscription.Interface,
		Enable:     subscription.Enable,
		URL:        subscription.URL,
		LastUpdate: subscription.LastUpdate,
		Interval:   subscription.Interval,
		RulesRes:   RespFromRules(subscription.Rules),
	}
}

func RespFromSubscriptionSync(subscription *models.Subscription) types.SubscriptionSyncRes {
	rulesRes := RespFromRules(subscription.Rules)
	return types.SubscriptionSyncRes{
		Rules:      rulesRes.Rules,
		LastUpdate: subscription.LastUpdate,
	}
}
