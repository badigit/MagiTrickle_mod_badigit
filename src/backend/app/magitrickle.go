package app

import (
	"context"
	"errors"
	"net"
	"time"

	"magitrickle/config"
	"magitrickle/models"
	"magitrickle/utils/intID"
	"magitrickle/utils/netfilterTools"

	"github.com/vishvananda/netlink"
)

var ErrInvalidGroups = errors.New("invalid group set")

// CapturedDomain — захваченный домен с количеством запросов.
type CapturedDomain struct {
	Domain string `json:"domain"`
	Count  int    `json:"count"`
}

// CaptureStatus — текущий статус захвата DNS.
type CaptureStatus struct {
	Active    bool             `json:"active"`
	StartedAt *time.Time       `json:"started_at,omitempty"`
	Count     int              `json:"count"`
	Domains   []CapturedDomain `json:"domains,omitempty"`
}

// WarmupResult — итог прогрева ipset ре-резолвом (POST /api/v1/warmup).
type WarmupResult struct {
	Matched   int  `json:"matched"`   // имён из recordsCache, сматченных активными правилами
	Queried   int  `json:"queried"`   // реально переспрошено через DNS-путь
	Errors    int  `json:"errors"`    // из них завершились ошибкой
	Truncated bool `json:"truncated"` // список обрезан лимитом
}

// DNSCapturer — интерфейс для захвата DNS-запросов.
type DNSCapturer interface {
	Start(filterIP string)
	Stop()
	IsActive() bool
	Status(withDomains bool) CaptureStatus
}

type Main interface {
	Config() models.AppConfig
	Groups() []Group
	// RoutingGroups — набор, по которому реально строится роутинг: базовые
	// группы плюс рантайм-группы подписок (у них свои ipset).
	RoutingGroups() []Group
	// WithRoutingMutation сериализует операции, меняющие цепочки в ядре
	// (включение/выключение групп). API обязано оборачивать в него свои
	// Enable/Disable, иначе правка группы вклинивается в чужой teardown.
	// Внутри fn нельзя брать конфиг-лок: см. routingMutationMu.
	WithRoutingMutation(fn func() error) error
	// WithConfigWrite/WithConfigRead — критические секции конфига (см. app_config_lock.go).
	// Мутирующие ручки оборачивают резолв+мутацию+снимок в WithConfigWrite; читатели
	// изменяемого контента правил — в WithConfigRead. ClearGroups/AddGroup/
	// RemoveGroupByIndex/SyncAllGroups/Rebuild* НЕ лочат сами — вызывать под WithConfigWrite.
	WithConfigWrite(fn func())
	WithConfigRead(fn func())
	GroupByID(id intID.ID) (Group, bool)
	// SearchDomainVerdict — арбитраж домена ровно тот же, что решает роутинг:
	// группа-победитель и слой, которым выигран (models.LookupWhy*). API
	// обязано спрашивать исход здесь, а не пересчитывать его по своим
	// источникам, иначе объяснение разойдётся с фактическим поведением.
	SearchDomainVerdict(domain string) (Group, string, bool)
	// DirectPriority/SetDirectPriority — режим арбитража direct-групп (mt-n4b).
	// Смена режима переподнимает правила: позиция цепочки в PREROUTING задаётся
	// при её создании.
	DirectPriority() string
	SetDirectPriority(mode string) error
	ClearGroups()
	AddGroup(groupModel *models.Group) error
	// ReplaceGroups installs a complete user group set under WithConfigWrite.
	ReplaceGroups(groupModels []*models.Group) error
	RemoveGroupByIndex(idx int)
	ListInterfaces() ([]net.Interface, error)
	OutgoingLinkIndexes() map[int]bool
	InterfaceAliases() map[string]string
	SetInterfaceAliases(aliases map[string]string)
	DnsOverrider() *netfilterTools.PortRemap
	LoadConfig() error
	SaveConfig() error
	LoadInterfaceConfig() error
	SaveInterfaceConfig() error
	ImportConfig(cfg config.Config) error
	ExportConfig() config.Config
	Subscriptions() []*models.Subscription
	ClearSubscriptions()
	AddSubscription(subscription *models.Subscription) error
	RemoveSubscriptionByIndex(idx int)
	RebuildSubscriptionGroups() error
	ForceCommitIPTables(ctx context.Context) error
	RequestNetfilterCommit()
	SyncAllGroups()
	DNSCapture() DNSCapturer
	Start(ctx context.Context) (err error)
	Restart()
	StartedAt() time.Time
	IsRoutingActive() bool
	SetEnabled(enabled bool) error
	ClientRouting() models.AppConfigClientRouting
	SetClientRouting(cfg models.AppConfigClientRouting) error
	// Warmup ре-резолвит имена из recordsCache, сматченные активными правилами,
	// через штатный DNS-путь → наполняет ipset. Ручной прогон после простоя.
	Warmup(ctx context.Context) (WarmupResult, error)
}

type Group interface {
	Enabled() bool
	Model() *models.Group
	AddIPv4Subnet(subnet netfilterTools.IPv4Subnet, ttl netfilterTools.IPSetTimeout) error
	AddIPv6Subnet(subnet netfilterTools.IPv6Subnet, ttl netfilterTools.IPSetTimeout) error
	DelIPv4Subnet(subnet netfilterTools.IPv4Subnet) error
	DelIPv6Subnet(subnet netfilterTools.IPv6Subnet) error
	ListIPv4Subnets() (map[netfilterTools.IPv4Subnet]netfilterTools.IPSetTimeout, error)
	ListIPv6Subnets() (map[netfilterTools.IPv6Subnet]netfilterTools.IPSetTimeout, error)
	Enable() error
	Disable() error
	Sync() error
	LinkUpHook(event netlink.LinkUpdate) error
	AddrChangeHook(event netlink.AddrUpdate) error
}
