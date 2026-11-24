package magitrickle

import (
	"context"
	"fmt"
	"net"
	"time"

	"magitrickle/models"
	"magitrickle/utils/netfilterTools"

	"github.com/miekg/dns"
	"github.com/rs/zerolog/log"
)

var hexDigits = []byte("0123456789abcdef")

func formatID(id uint16) string {
	return string([]byte{
		hexDigits[id>>12&0xf],
		hexDigits[id>>8&0xf],
		hexDigits[id>>4&0xf],
		hexDigits[id&0xf],
	})
}

// selectUpstream решает в какой апстрим отправить DNS-запрос:
//   - есть match по domain/namespace/wildcard/regex в любой группе → primary (mihomo)
//   - нет match (или нет вопросов в req) → fallback (например ndnproxy)
//
// Subnet-правила здесь игнорируются (Rule.IsMatch для них возвращает false), потому
// что IP неизвестен до резолвинга — для subnet matching используется post-resolve
// path в processARecord, который работает независимо от выбора апстрима.
//
// Вызывается из dnsMITMProxy.processReq → возвращает true если нужен fallback.
func (a *App) selectUpstream(req dns.Msg) bool {
	if len(req.Question) == 0 {
		return true // нечего матчить — fallback (DNS должен ответить как-то)
	}
	name := trimFQDN(req.Question[0].Name)
	if name == "" {
		return true
	}
	if _, ok := a.searchDomain(name); ok {
		return false // matched любой группой — primary upstream (mihomo)
	}
	return true // нет matched group — fallback (ndnproxy)
}

func trimFQDN(name string) string {
	if len(name) > 0 && name[len(name)-1] == '.' {
		return name[:len(name)-1]
	}
	return name
}

func (a *App) dnsConfig() models.AppConfigDNSProxy {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	return a.config.DNSProxy
}

func (a *App) dnsAdditionalTTL() uint32 {
	a.cfgMu.RLock()
	defer a.cfgMu.RUnlock()
	return a.config.Netfilter.IPSet.AdditionalTTL
}

func (a *App) startDNSListeners(ctx context.Context, errChan chan error) {
	host := a.dnsConfig().Host
	go func() {
		addr, err := net.ResolveUDPAddr("udp", fmt.Sprintf("%s:%d", host.Address, host.Port))
		if err != nil {
			errChan <- fmt.Errorf("failed to resolve udp address: %v", err)
			return
		}
		if err = a.dnsMITM.ListenUDP(ctx, addr); err != nil {
			errChan <- fmt.Errorf("failed to serve DNS UDP proxy: %v", err)
		}
	}()

	go func() {
		addr, err := net.ResolveTCPAddr("tcp", fmt.Sprintf("%s:%d", host.Address, host.Port))
		if err != nil {
			errChan <- fmt.Errorf("failed to resolve tcp address: %v", err)
			return
		}
		if err = a.dnsMITM.ListenTCP(ctx, addr); err != nil {
			errChan <- fmt.Errorf("failed to serve DNS TCP proxy: %v", err)
		}
	}()
}

// dnsRequestHook обрабатывает входящие DNS-запросы
func (a *App) dnsRequestHook(clientAddr net.Addr, reqMsg dns.Msg, network string) (*dns.Msg, *dns.Msg, error) {
	var clientAddrStr string
	if clientAddr != nil {
		clientAddrStr = clientAddr.String()
	}
	idStr := formatID(reqMsg.Id)

	log.Debug().
		Str("id", idStr).
		Str("client", clientAddrStr).
		Str("net", network).
		Msg("request received")

	for _, q := range reqMsg.Question {
		log.Info().
			Str("id", idStr).
			Str("net", network).
			Str("name", q.Name).
			Str("client", clientAddrStr).
			Int("qclass", int(q.Qclass)).
			Int("qtype", int(q.Qtype)).
			Msg("dns request")

		a.dnsCapture.Record(q.Name, clientAddrStr)
	}

	if a.dnsConfig().DisableFakePTR {
		return nil, nil, nil
	}

	if len(reqMsg.Question) == 1 && reqMsg.Question[0].Qtype == dns.TypePTR {
		respMsg := &dns.Msg{
			MsgHdr: dns.MsgHdr{
				Id:                 reqMsg.Id,
				Response:           true,
				RecursionAvailable: true,
				Rcode:              dns.RcodeNameError,
			},
			Question: reqMsg.Question,
		}
		return nil, respMsg, nil
	}

	return nil, nil, nil
}

// dnsResponseHook обрабатывает ответы DNS
func (a *App) dnsResponseHook(clientAddr net.Addr, reqMsg dns.Msg, respMsg dns.Msg, network string) (*dns.Msg, error) {
	// Замыкание, а не defer a.handleMessage(respMsg, ...): аргументы defer
	// вычисляются в момент объявления, поэтому захватили бы снимок respMsg ДО
	// фильтрации AAAA ниже (dns.Msg — структура, slice-header Answer копируется).
	// В итоге handleMessage парсил бы нефильтрованный ответ и добавлял AAAA в
	// nftset даже при активном drop. Замыкание вычисляет respMsg в момент выхода.
	//
	// ВАЖНО: handleMessage должен видеть ОРИГИНАЛЬНЫЙ TTL — ipset живёт
	// origTTL+AdditionalTTL. Поэтому TTL-cap применяем к ОТДЕЛЬНОЙ клиентской
	// копии (capAnswersTTL копирует капаемые RR), не мутируя respMsg.Answer[i].
	defer func() { a.handleMessage(respMsg, clientAddr, network) }()

	dnsConfig := a.dnsConfig()
	dropAAAA := !dnsConfig.DisableDropAAAA
	if dropAAAA {
		// фильтрация записей AAAA (in-place на respMsg: handleMessage не должен
		// класть AAAA в ipset при активном drop)
		filteredAnswers := make([]dns.RR, 0, len(respMsg.Answer))
		for _, answer := range respMsg.Answer {
			if answer == nil {
				continue
			}
			if answer.Header().Rrtype != dns.TypeAAAA {
				filteredAnswers = append(filteredAnswers, answer)
			}
		}
		respMsg.Answer = filteredAnswers
	}

	ttlCap := dnsConfig.ClientTTLCap

	// Ничего менять в клиентском ответе не нужно — отдаём оригинальные байты.
	// Капать имеет смысл только для success-ответов: у NXDOMAIN/negative
	// answer-секция пуста (SOA лежит в Ns), поэтому cap их не трогает.
	if ttlCap == 0 && !dropAAAA {
		return nil, nil
	}

	// Клиентская проекция строится copy-on-write поверх respMsg.Answer:
	// обе трансформации (strip ipv6hint из HTTPS/SVCB + TTL-cap) применяются
	// последовательно к одному срезу, respMsg.Answer остаётся оригиналом для
	// handleMessage.
	clientMsg := respMsg // мелкая копия структуры (slice-header Answer общий)
	clientAnswers := respMsg.Answer
	if dropAAAA {
		// AAAA-записи уже отфильтрованы выше, но ipv6hint внутри HTTPS/SVCB
		// провёз бы IPv6-адрес мимо фильтра (mt-ocy, класс T1 из mt-240).
		clientAnswers = stripSVCBIPv6Hints(clientAnswers)
	}
	if ttlCap > 0 {
		clientAnswers = capAnswersTTL(clientAnswers, ttlCap)
	}
	clientMsg.Answer = clientAnswers
	return &clientMsg, nil
}

// capAnswersTTL возвращает копию answers, в которой A/AAAA/CNAME/HTTPS/SVCB с
// TTL > ttlCap получают TTL = ttlCap. Записи с TTL <= ttlCap и прочие типы
// переиспользуются как есть (тот же указатель). Копируются ТОЛЬКО капаемые RR —
// чтобы не мутировать RR, которые потом разбирает handleMessage: его вызов
// стоит в defer и отрабатывает синхронно уже после сборки клиентской копии, но
// видеть он обязан ОРИГИНАЛЬНЫЙ TTL — иначе cap протечёт в ipset. HTTPS/SVCB капаются по
// той же причине, что и A: клиент не должен держать адресные hints дольше
// жизни ipset-записи (mt-ocy).
func capAnswersTTL(answers []dns.RR, ttlCap uint32) []dns.RR {
	out := make([]dns.RR, 0, len(answers))
	for _, rr := range answers {
		if rr == nil {
			continue
		}
		hdr := rr.Header()
		if hdr.Ttl > ttlCap {
			switch rr.(type) {
			case *dns.A, *dns.AAAA, *dns.CNAME, *dns.HTTPS, *dns.SVCB:
				cp := dns.Copy(rr)
				cp.Header().Ttl = ttlCap
				out = append(out, cp)
				continue
			}
		}
		out = append(out, rr)
	}
	return out
}

// handleMessage обрабатывает полученное DNS-сообщение
func (a *App) handleMessage(msg dns.Msg, clientAddr net.Addr, network string) {
	idStr := formatID(msg.Id)
	var clientAddrStr string
	if clientAddr != nil {
		clientAddrStr = clientAddr.String()
	}

	if msg.Rcode != dns.RcodeSuccess {
		log.Warn().
			Str("id", idStr).
			Str("net", network).
			Str("client", clientAddrStr).
			Str("rcode", dns.RcodeToString[msg.Rcode]).
			Msg("unprocessable response")

		return
	}

	for _, rr := range msg.Answer {
		if rr == nil {
			continue
		}

		switch v := rr.(type) {
		case *dns.A:
			a.processARecord(*v, idStr, clientAddrStr, network)
		case *dns.AAAA:
			a.processAAAARecord(*v, idStr, clientAddrStr, network)
		case *dns.CNAME:
			a.processCNameRecord(*v, idStr, clientAddrStr, network)
		case *dns.HTTPS:
			// Тип 65: адресные подсказки (ipv4hint/ipv6hint) ведём в ipset тем
			// же путём, что A/AAAA (mt-ocy). Generic SVCB (тип 64) намеренно не
			// обрабатываем: его QNAME (_853._dns.example.com) не матчится
			// правилами — только клиентская санитизация в dnsResponseHook.
			a.processHTTPSRecord(v, idStr, clientAddrStr, network)
		}
	}
}

func (a *App) processARecord(aRecord dns.A, idStr, clientAddrStr, network string) {
	domainName := trimFQDN(aRecord.Hdr.Name)
	addrStr := aRecord.A.String()

	if len(aRecord.A) != 4 {
		log.Warn().
			Str("id", idStr).
			Str("name", domainName).
			Str("address", addrStr).
			Int("ttl", int(aRecord.Hdr.Ttl)).
			Str("client", clientAddrStr).
			Str("net", network).
			Msg("unprocessable A response")
		return
	}

	log.Debug().
		Str("id", idStr).
		Str("name", domainName).
		Str("address", addrStr).
		Int("ttl", int(aRecord.Hdr.Ttl)).
		Str("client", clientAddrStr).
		Str("net", network).
		Msg("processing A record")

	ttlDuration := ipsetTTLFromRecord(aRecord.Hdr.Ttl, a.dnsAdditionalTTL())

	a.recordsCache.AddAddress(domainName, aRecord.A, ttlDuration)

	names := a.recordsCache.GetAliases(domainName)
	for _, name := range names {
		group, found := a.searchDomain(name)
		if !found {
			continue
		}

		subnet := netfilterTools.IPv4Host([4]byte(aRecord.A))
		if err := group.AddIPv4Subnet(subnet, &ttlDuration); err != nil {
			log.Error().
				Err(err).
				Str("subnet", subnet.String()).
				Str("aRecordDomain", domainName).
				Str("cNameDomain", name).
				Msg("failed to add subnet")
		} else {
			log.Debug().
				Str("subnet", subnet.String()).
				Str("aRecordDomain", domainName).
				Str("cNameDomain", name).
				Msg("added subnet")
		}

		log.Info().
			Str("name", domainName).
			Str("groupId", group.ID.String()).
			Str("address", addrStr).
			Str("group", group.Name).
			Msg("added to routing")

		break
	}
}

func (a *App) processAAAARecord(aaaaRecord dns.AAAA, idStr, clientAddrStr, network string) {
	domainName := trimFQDN(aaaaRecord.Hdr.Name)
	addrStr := aaaaRecord.AAAA.String()

	if len(aaaaRecord.AAAA) != 16 {
		log.Warn().
			Str("id", idStr).
			Str("name", domainName).
			Str("address", addrStr).
			Int("ttl", int(aaaaRecord.Hdr.Ttl)).
			Str("client", clientAddrStr).
			Str("net", network).
			Msg("unprocessable AAAA response")
		return
	}

	log.Debug().
		Str("id", idStr).
		Str("name", domainName).
		Str("address", addrStr).
		Int("ttl", int(aaaaRecord.Hdr.Ttl)).
		Str("client", clientAddrStr).
		Str("net", network).
		Msg("processing AAAA record")

	ttlDuration := ipsetTTLFromRecord(aaaaRecord.Hdr.Ttl, a.dnsAdditionalTTL())

	a.recordsCache.AddAddress(domainName, aaaaRecord.AAAA, ttlDuration)

	names := a.recordsCache.GetAliases(domainName)
	for _, name := range names {
		group, found := a.searchDomain(name)
		if !found {
			continue
		}

		subnet := netfilterTools.IPv6Host([16]byte(aaaaRecord.AAAA))
		if err := group.AddIPv6Subnet(subnet, &ttlDuration); err != nil {
			log.Error().
				Err(err).
				Str("subnet", subnet.String()).
				Str("aaaaRecordDomain", domainName).
				Str("cNameDomain", name).
				Msg("failed to add subnet")
		} else {
			log.Debug().
				Str("subnet", subnet.String()).
				Str("aaaaRecordDomain", domainName).
				Str("cNameDomain", name).
				Msg("added subnet")
		}

		log.Info().
			Str("name", domainName).
			Str("groupId", group.ID.String()).
			Str("address", addrStr).
			Str("group", group.Name).
			Msg("added to routing")

		break
	}
}

func (a *App) processCNameRecord(cNameRecord dns.CNAME, idStr, clientAddrStr, network string) {
	domainName := trimFQDN(cNameRecord.Hdr.Name)
	targetName := trimFQDN(cNameRecord.Target)

	log.Debug().
		Str("id", idStr).
		Str("name", domainName).
		Str("cname", targetName).
		Int("ttl", int(cNameRecord.Hdr.Ttl)).
		Str("client", clientAddrStr).
		Str("net", network).
		Msg("processing CNAME record")

	ttlDuration := ipsetTTLFromRecord(cNameRecord.Hdr.Ttl, a.dnsAdditionalTTL())

	a.recordsCache.AddAlias(domainName, targetName, ttlDuration)

	now := time.Now()
	addresses := a.recordsCache.GetAddresses(domainName)
	aliases := a.recordsCache.GetAliases(domainName)
	for _, alias := range aliases {
		group, found := a.searchDomain(alias)
		if !found {
			continue
		}

		log.Info().
			Str("name", domainName).
			Str("groupId", group.ID.String()).
			Str("group", group.Name).
			Str("cname", targetName).
			Msg("added alias")

		for _, address := range addresses {
			ttl, ok := ipsetTTLFromDeadline(address.Deadline.Sub(now))
			if !ok {
				continue
			}

			if len(address.Address) == net.IPv4len {
				subnet := netfilterTools.IPv4Host([4]byte(address.Address))
				if err := group.AddIPv4Subnet(subnet, &ttl); err != nil {
					log.Error().
						Err(err).
						Str("subnet", subnet.String()).
						Str("cNameDomain", alias).
						Msg("failed to add subnet")
				}
				log.Debug().
					Str("subnet", subnet.String()).
					Str("cNameDomain", alias).
					Msg("added subnet")
			} else if len(address.Address) == net.IPv6len {
				subnet := netfilterTools.IPv6Host([16]byte(address.Address))
				if err := group.AddIPv6Subnet(subnet, &ttl); err != nil {
					log.Error().
						Err(err).
						Str("subnet", subnet.String()).
						Str("cNameDomain", alias).
						Msg("failed to add subnet")
				}
				log.Debug().
					Str("subnet", subnet.String()).
					Str("cNameDomain", alias).
					Msg("added subnet")
			}
		}
		break
	}
}
