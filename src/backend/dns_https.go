package magitrickle

import (
	"net"

	"magitrickle/utils/netfilterTools"

	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

// Обработка HTTPS RR (тип 65, RFC 9460) — mt-ocy.
//
// Браузеры шлют HTTPS-запрос параллельно с A/AAAA, а ответ может нести
// ipv4hint/ipv6hint — адреса, по которым клиент вправе открыть соединение,
// не дожидаясь A/AAAA. Без обработки такие адреса не попадают в ipset
// (первый SYN уходит direct), а ipv6hint провозит IPv6-адрес «контрабандой»
// мимо drop AAAA (класс T1 из mt-240).
//
// Generic SVCB (тип 64) в ipset НЕ кладём: его QNAME имеет attrleaf-вид
// (_853._dns.example.com) и систематически не матчится правилами пользователя.
// Клиентская санитизация (stripSVCBIPv6Hints, cap TTL) покрывает оба типа.

// processHTTPSRecord разбирает один HTTPS RR по семантике RFC 9460 и ведёт
// адреса из hints тем же путём, что processARecord/processAAAARecord —
// включая арбитраж групп searchDomain (direct наследуется автоматически).
func (a *App) processHTTPSRecord(httpsRecord *dns.HTTPS, idStr, clientAddrStr, network string) {
	ownerName := trimFQDN(httpsRecord.Hdr.Name)
	targetName := trimFQDN(httpsRecord.Target)

	log.Debug().
		Str("id", idStr).
		Str("name", ownerName).
		Str("target", targetName).
		Int("priority", int(httpsRecord.Priority)).
		Int("ttl", int(httpsRecord.Hdr.Ttl)).
		Str("client", clientAddrStr).
		Str("net", network).
		Msg("processing HTTPS record")

	ttlDuration := ipsetTTLFromRecord(httpsRecord.Hdr.Ttl, a.dnsAdditionalTTL())

	// AliasMode (Priority == 0): SvcParams игнорируются (RFC 9460 §2.4.2), но
	// сама связь owner→target — нет: follow-up A/AAAA-ответ придёт уже на
	// target, и без алиаса правило, написанное для owner, его не сматчит.
	// Target "." в AliasMode означает «сервис недоступен» — пропускаем.
	if httpsRecord.Priority == 0 {
		if targetName != "" && ownerName != targetName {
			a.recordsCache.AddAlias(ownerName, targetName, ttlDuration)
		}
		return
	}

	// ServiceMode: hints принадлежат effective target. Target "." (или пустой
	// после trimFQDN) означает owner. Иной target моделируем как CNAME-алиас —
	// адреса лягут на target, а GetAliases дотянет их до owner и его правил.
	effectiveName := ownerName
	if targetName != "" && targetName != ownerName {
		effectiveName = targetName
		a.recordsCache.AddAlias(ownerName, targetName, ttlDuration)
	}

	dropAAAA := !a.dnsConfig().DisableDropAAAA

	for _, kv := range httpsRecord.Value {
		switch hint := kv.(type) {
		case *dns.SVCBIPv4Hint:
			for _, ip := range hint.Hint {
				a.routeHintIPv4(effectiveName, ip, ttlDuration, idStr)
			}
		case *dns.SVCBIPv6Hint:
			// При drop AAAA IPv6-адреса в ipset не кладём — симметрично тому,
			// что AAAA-записи отфильтрованы; клиентскую копию чистит
			// stripSVCBIPv6Hints.
			if dropAAAA {
				continue
			}
			for _, ip := range hint.Hint {
				a.routeHintIPv6(effectiveName, ip, ttlDuration, idStr)
			}
		}
	}
}

// routeHintIPv4 ведёт один IPv4-адрес из ipv4hint тем же маршрутом, что
// processARecord: кэш → алиасы → правило → ipset группы-победителя.
func (a *App) routeHintIPv4(domainName string, ip net.IP, ttl uint32, idStr string) {
	ip4 := ip.To4()
	if ip4 == nil {
		return
	}

	a.recordsCache.AddAddress(domainName, ip4, ttl)

	for _, name := range a.recordsCache.GetAliases(domainName) {
		group, found := a.searchDomain(name)
		if !found {
			continue
		}

		subnet := netfilterTools.IPv4Host([4]byte(ip4))
		if err := group.AddIPv4Subnet(subnet, &ttl); err != nil {
			log.Error().
				Err(err).
				Str("subnet", subnet.String()).
				Str("hintDomain", domainName).
				Str("matchedDomain", name).
				Msg("failed to add ipv4hint subnet")
		} else {
			log.Info().
				Str("id", idStr).
				Str("name", domainName).
				Str("groupId", group.ID.String()).
				Str("address", ip4.String()).
				Str("group", group.Name).
				Msg("added ipv4hint to routing")
		}
		break
	}
}

// routeHintIPv6 — то же для ipv6hint (вызывается только при разрешённых AAAA).
func (a *App) routeHintIPv6(domainName string, ip net.IP, ttl uint32, idStr string) {
	ip16 := ip.To16()
	if ip16 == nil || ip.To4() != nil {
		return
	}

	a.recordsCache.AddAddress(domainName, ip16, ttl)

	for _, name := range a.recordsCache.GetAliases(domainName) {
		group, found := a.searchDomain(name)
		if !found {
			continue
		}

		subnet := netfilterTools.IPv6Host([16]byte(ip16))
		if err := group.AddIPv6Subnet(subnet, &ttl); err != nil {
			log.Error().
				Err(err).
				Str("subnet", subnet.String()).
				Str("hintDomain", domainName).
				Str("matchedDomain", name).
				Msg("failed to add ipv6hint subnet")
		} else {
			log.Info().
				Str("id", idStr).
				Str("name", domainName).
				Str("groupId", group.ID.String()).
				Str("address", ip16.String()).
				Str("group", group.Name).
				Msg("added ipv6hint to routing")
		}
		break
	}
}

// stripSVCBIPv6Hints возвращает клиентскую проекцию answers, в которой из
// HTTPS/SVCB-записей удалён ipv6hint: при активном drop AAAA обычные
// AAAA-записи фильтруются, и оставлять IPv6-адреса внутри SvcParams значит
// провозить их мимо фильтра. Заодно поддерживается инвариант RFC 9460 §8:
// код удалённого ключа вычищается из mandatory, опустевший mandatory
// удаляется целиком (иначе клиент обязан отбросить весь RR).
//
// Copy-on-write: копируются ТОЛЬКО изменяемые RR (dns.Copy), остальные
// переиспользуются: handleMessage разбирает ОРИГИНАЛЬНЫЙ respMsg.Answer (defer
// в dnsResponseHook отрабатывает синхронно уже после сборки клиентской копии),
// и мутация RR на месте увела бы в ipset урезанный состав вместо исходного.
func stripSVCBIPv6Hints(answers []dns.RR) []dns.RR {
	out := make([]dns.RR, 0, len(answers))
	for _, rr := range answers {
		if rr == nil {
			continue
		}

		var value []dns.SVCBKeyValue
		switch v := rr.(type) {
		case *dns.HTTPS:
			value = v.Value
		case *dns.SVCB:
			value = v.Value
		default:
			out = append(out, rr)
			continue
		}

		if !hasIPv6Hint(value) {
			out = append(out, rr)
			continue
		}

		cp := dns.Copy(rr)
		switch v := cp.(type) {
		case *dns.HTTPS:
			v.Value = filterOutIPv6Hint(v.Value)
		case *dns.SVCB:
			v.Value = filterOutIPv6Hint(v.Value)
		}
		out = append(out, cp)
	}
	return out
}

func hasIPv6Hint(value []dns.SVCBKeyValue) bool {
	for _, kv := range value {
		if kv.Key() == dns.SVCB_IPV6HINT {
			return true
		}
	}
	return false
}

// filterOutIPv6Hint удаляет ipv6hint и чистит его код из mandatory.
// Работает по копии среза (вход — Value уже скопированного через dns.Copy RR).
func filterOutIPv6Hint(value []dns.SVCBKeyValue) []dns.SVCBKeyValue {
	out := make([]dns.SVCBKeyValue, 0, len(value))
	for _, kv := range value {
		switch v := kv.(type) {
		case *dns.SVCBIPv6Hint:
			continue
		case *dns.SVCBMandatory:
			codes := make([]dns.SVCBKey, 0, len(v.Code))
			for _, code := range v.Code {
				if code != dns.SVCB_IPV6HINT {
					codes = append(codes, code)
				}
			}
			if len(codes) == 0 {
				continue // пустой mandatory недопустим (RFC 9460 §8)
			}
			out = append(out, &dns.SVCBMandatory{Code: codes})
		default:
			out = append(out, kv)
		}
	}
	return out
}
