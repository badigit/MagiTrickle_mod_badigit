package v1

import (
	"net"
	"net/http"
	"strings"

	"magitrickle/api/utils"
	"magitrickle/api/v1/types"
	"magitrickle/models"
)

// Lookup выполняет batch-проверку доменов/IP/подсетей по правилам групп,
// подписок и (опционально) по ipset на роутере.
func (h *Handler) Lookup(w http.ResponseWriter, r *http.Request) {
	req, err := utils.ReadJson[types.LookupReq](r)
	if err != nil {
		utils.WriteError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if len(req.Queries) == 0 {
		utils.WriteJson(w, http.StatusOK, types.LookupRes{Results: []types.LookupResult{}})
		return
	}

	// Collect all rule sources: groups + subscriptions
	type ruleSource = lookupSource

	// Чтение под RLock: matchRule/итерация читают rule.Rule и *.Rules, которые
	// API-писатели мутируют in-place (mt-gjg/mt-jfc). WriteJson — вне лока.
	var results []types.LookupResult
	var queries []parsedQuery
	h.app.WithConfigRead(func() {
		var sources []ruleSource
		appGroups := h.app.Groups()
		for _, g := range appGroups {
			m := g.Model()
			if !m.Enable {
				continue
			}
			sources = append(sources, ruleSource{
				id:     m.ID.String(),
				name:   m.Name,
				source: "group",
				rules:  m.Rules,
			})
		}
		for _, s := range h.app.Subscriptions() {
			if !s.Enable {
				continue
			}
			sources = append(sources, ruleSource{
				id:     s.ID.String(),
				name:   s.Name,
				source: "subscription",
				rules:  s.Rules,
			})
		}

		// Preload ipset data if requested
		type ipsetEntry struct {
			groupID   string
			groupName string
			source    string
			// iface нужен, чтобы отличить direct-группу: в absolute-режиме её
			// цепочка стоит первой в PREROUTING и выигрывает overlap, где бы
			// группа ни стояла в списке.
			iface   string
			setName string
			network net.IPNet
		}
		var ipsetEntries []ipsetEntry

		if req.CheckIpset {
			// Именно RoutingGroups: у групп подписок собственные ipset, и без
			// них победитель по IP не находится вовсе. Набор строится как
			// «сначала базовые группы, затем рантайм-группы подписок», и
			// принадлежность определяется позицией: ID уникальны лишь внутри
			// каждого из этих двух множеств, поэтому по ID её не выяснить.
			baseCount := len(appGroups)
			for gi, g := range h.app.RoutingGroups() {
				m := g.Model()
				if !m.Enable {
					continue
				}
				gid := m.ID.String()
				entrySource := "group"
				if gi >= baseCount {
					entrySource = "subscription"
				}

				if ipv4, err := g.ListIPv4Subnets(); err == nil {
					for subnet := range ipv4 {
						cidr := subnet.CIDR
						if cidr == 0 {
							cidr = 32
						}
						ipsetEntries = append(ipsetEntries, ipsetEntry{
							groupID:   gid,
							groupName: m.Name,
							source:    entrySource,
							iface:     m.Interface,
							network: net.IPNet{
								IP:   net.IP(subnet.Address[:]),
								Mask: net.CIDRMask(int(cidr), 32),
							},
						})
					}
				}
				if ipv6, err := g.ListIPv6Subnets(); err == nil {
					for subnet := range ipv6 {
						cidr := subnet.CIDR
						if cidr == 0 {
							cidr = 128
						}
						ipsetEntries = append(ipsetEntries, ipsetEntry{
							groupID:   gid,
							groupName: m.Name,
							source:    entrySource,
							iface:     m.Interface,
							network: net.IPNet{
								IP:   net.IP(subnet.Address[:]),
								Mask: net.CIDRMask(int(cidr), 128),
							},
						})
					}
				}
			}
		}

		results = make([]types.LookupResult, len(req.Queries))
		queries = make([]parsedQuery, len(req.Queries))
		for qi, query := range req.Queries {
			result := types.LookupResult{
				Query:    query,
				RuleHits: []types.RuleHit{},
			}

			qLower := strings.ToLower(strings.TrimSpace(query))
			qIP, qNet := parseIPOrCIDR(qLower)

			// Check rules
			for _, src := range sources {
				for _, rule := range src.rules {
					if !rule.Enable {
						continue
					}
					if hit := matchRule(rule, qLower, qIP, qNet, src); hit != nil {
						result.RuleHits = append(result.RuleHits, *hit)
					}
				}
			}

			// Check ipset
			if req.CheckIpset && qIP != nil {
				result.IpsetHits = []types.IpsetHit{}
				// Ключ дедупликации — пара источник+ID: у базовой группы и
				// подписки ID могут совпасть, и по одному ID подписка была бы
				// подавлена, а вместе с ней и её роль в арбитраже.
				seen := make(map[string]bool)
				for _, entry := range ipsetEntries {
					if entry.network.Contains(qIP) {
						key := entry.source + ":" + entry.groupID
						if !seen[key] {
							seen[key] = true
							result.IpsetHits = append(result.IpsetHits, types.IpsetHit{
								GroupID:   entry.groupID,
								GroupName: entry.groupName,
								Source:    entry.source,
								Interface: entry.iface,
							})
						}
					}
				}
			}

			results[qi] = result
			queries[qi] = parsedQuery{lower: qLower, ip: qIP, net: qNet}
		}
	})

	// Победитель считается ВНЕ WithConfigRead намеренно. sync.RWMutex в Go не
	// реентрантен: DirectPriority и SearchDomainVerdict берут cfgMu.RLock сами,
	// и повторный захват изнутри уже удерживаемого RLock встаёт намертво, если
	// между ними в очередь попал писатель (обновление подписок, правка группы,
	// смена directPriority). Дедлок был бы фатальным: следом встают все
	// читатели, включая searchDomain на датапасе, то есть DNS роутера.
	for qi := range results {
		results[qi].Winner = h.lookupWinner(queries[qi], req.CheckIpset, results[qi])
	}

	utils.WriteJson(w, http.StatusOK, types.LookupRes{Results: results, RoutingActive: h.app.IsRoutingActive()})
}

// parsedQuery — разбор запроса, переживающий выход из-под конфиг-лока: winner
// считается уже снаружи, а парсить строку второй раз незачем.
type parsedQuery struct {
	lower string
	ip    net.IP
	net   *net.IPNet
}

// lookupWinner отвечает на главный вопрос пользователя — «а куда это пойдёт
// НА САМОМ ДЕЛЕ» — по тем же правилам, которыми ходит трафик.
//
// Для домена исход спрашивается у ядра (SearchDomainVerdict), а не считается
// здесь: у lookup шире источники (модели подписок вместо их рантайм-групп), и
// собственный подсчёт разошёлся бы с роутингом ровно в спорных случаях, ради
// которых winner и добавлен (mt-ztg, корень жалоб mt-4ho/mt-4pl/mt-1wg).
//
// Для IP победителя определяет ipset — это буквально то, что увидит пакет, —
// но с поправкой на режим арбитража: в absolute direct-цепочка стоит первой в
// PREROUTING, поэтому direct-группа выигрывает overlap независимо от своего
// места в списке.
//
// Победитель НЕ называется там, где для утверждения нет данных: у CIDR-запроса
// единого исхода не существует (разные адреса диапазона могут уходить в разные
// группы), а без check_ipset неизвестно содержимое сетов.
func (h *Handler) lookupWinner(q parsedQuery, ipsetChecked bool, result types.LookupResult) *types.LookupWinner {
	// Роутинг снят целиком — ни одной цепочки MT в ядре нет, поэтому любой
	// найденный победитель относится к будущему, а не к текущему моменту.
	routingPaused := !h.app.IsRoutingActive()

	if q.ip != nil {
		// Диапазон: победителя у него нет — только список совпадений.
		if q.net != nil {
			return nil
		}
		if !ipsetChecked {
			return nil
		}
		if hit := pickIpsetWinner(result.IpsetHits, h.app.DirectPriority()); hit != nil {
			return &types.LookupWinner{
				GroupID:   hit.GroupID,
				GroupName: hit.GroupName,
				Source:    hit.Source,
				Why:       models.LookupWhyIpsetFirst,
				Pending:   routingPaused,
			}
		}
		for _, hit := range result.RuleHits {
			if hit.RuleType != models.RuleTypeSubnet && hit.RuleType != models.RuleTypeSubnet6 {
				continue
			}
			return &types.LookupWinner{
				GroupID:   hit.GroupID,
				GroupName: hit.GroupName,
				Source:    hit.Source,
				Why:       models.LookupWhySubnet,
				Pending:   true,
			}
		}
		return nil
	}

	// При снятом роутинге группы выключены, trie пуст и вердикта не будет —
	// это честный ответ «сейчас победителя нет», а не потеря информации:
	// признак RoutingActive в ответе объясняет причину.
	group, why, found := h.app.SearchDomainVerdict(q.lower)
	if !found {
		return nil
	}
	m := group.Model()
	return &types.LookupWinner{
		GroupID:   m.ID.String(),
		GroupName: m.Name,
		Source:    winnerSource(m.ID.String(), result.RuleHits),
		Why:       why,
		Pending:   routingPaused,
	}
}

// pickIpsetWinner выбирает группу так же, как выберет ядро: в absolute-режиме
// direct-цепочка вставлена в PREROUTING первой и терминирует пакет ACCEPT'ом,
// поэтому среди совпавших сетов побеждает первая direct-группа, а не первая по
// списку. В byOrder все цепочки стоят в порядке групп — выигрывает верхняя.
func pickIpsetWinner(hits []types.IpsetHit, directPriority string) *types.IpsetHit {
	if len(hits) == 0 {
		return nil
	}
	if directPriority == models.DirectPriorityAbsolute {
		// Идём с конца: каждая direct-группа вставляет свою цепочку в позицию 1
		// (ipset-to-link.go), поэтому в PREROUTING они лежат в обратном порядке
		// включения — первой стоит цепочка ПОСЛЕДНЕЙ direct-группы, она и
		// перехватит пакет.
		for i := len(hits) - 1; i >= 0; i-- {
			if hits[i].Interface == models.InterfaceDirect {
				return &hits[i]
			}
		}
	}
	return &hits[0]
}

// winnerSource достаёт источник (группа или подписка) из уже собранных
// совпадений: SearchDomainVerdict возвращает рантайм-группу, а пользователю
// важно, из подписки её правило или своё.
func winnerSource(groupID string, hits []types.RuleHit) string {
	for _, hit := range hits {
		if hit.GroupID == groupID {
			return hit.Source
		}
	}
	return "group"
}

type lookupSource struct {
	id     string
	name   string
	source string // "group" or "subscription"
	rules  []*models.Rule
}

func parseIPOrCIDR(s string) (net.IP, *net.IPNet) {
	if strings.Contains(s, "/") {
		ip, ipNet, err := net.ParseCIDR(s)
		if err != nil {
			return nil, nil
		}
		return ip, ipNet
	}
	ip := net.ParseIP(s)
	return ip, nil
}

func matchRule(rule *models.Rule, qLower string, qIP net.IP, qNet *net.IPNet, src lookupSource) *types.RuleHit {
	rLower := strings.ToLower(rule.Rule)
	hit := types.RuleHit{
		GroupID:   src.id,
		GroupName: src.name,
		Source:    src.source,
		RuleType:  rule.Type,
		Rule:      rule.Rule,
	}

	switch rule.Type {
	case models.RuleTypeDomain:
		if qLower == rLower {
			hit.Match = "exact"
			return &hit
		}

	case models.RuleTypeNamespace:
		if qLower == rLower {
			hit.Match = "exact"
			return &hit
		}
		if len(qLower) > len(rLower)+1 && qLower[len(qLower)-len(rLower)-1] == '.' && qLower[len(qLower)-len(rLower):] == rLower {
			hit.Match = "namespace"
			return &hit
		}

	case models.RuleTypeWildcard:
		if rule.IsMatch(qLower) {
			hit.Match = models.LookupWhyWildcard
			if !models.WildcardHasGlob(rule.Rule) {
				hit.Match = models.LookupWhyNamespace
			}
			return &hit
		}

	case models.RuleTypeRegEx:
		if rule.IsMatch(qLower) {
			hit.Match = "regex"
			return &hit
		}

	case models.RuleTypeSubnet, models.RuleTypeSubnet6:
		_, rNet, err := net.ParseCIDR(rule.Rule)
		if err != nil {
			rIP := net.ParseIP(rule.Rule)
			if rIP == nil {
				return nil
			}
			bits := 32
			if rIP.To4() == nil {
				bits = 128
			}
			rNet = &net.IPNet{IP: rIP, Mask: net.CIDRMask(bits, bits)}
		}

		// Query is a single IP
		if qIP != nil && qNet == nil {
			if rNet.Contains(qIP) {
				hit.Match = "contains"
				return &hit
			}
		}
		// Query is a CIDR
		if qNet != nil {
			qOnes, _ := qNet.Mask.Size()
			rOnes, _ := rNet.Mask.Size()
			if rNet.Contains(qNet.IP) && qOnes >= rOnes {
				hit.Match = "subnet_of"
				return &hit
			}
			if qNet.Contains(rNet.IP) && rOnes >= qOnes {
				hit.Match = "supernet_of"
				return &hit
			}
		}
	}
	return nil
}
