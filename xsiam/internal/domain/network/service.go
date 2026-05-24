package network

import (
	"context"
	"time"
	"xsiam/internal/model"
	"xsiam/internal/repository"
	"xsiam/pkg/statscache"
)

// Service implements the network security domain business logic.
type Service struct {
	repo  *repository.NetworkRepo
	cache *statscache.Client
}

func NewService(repo *repository.NetworkRepo, cache *statscache.Client) *Service {
	return &Service{repo: repo, cache: cache}
}

// Stats returns an aggregate network security summary for the tenant.
// Results are served from the Redis stats cache when available; on a
// miss the live AQL aggregation is used and the result is back-filled.
func (s *Service) Stats(ctx context.Context, tenantID string) (*model.NetworkStats, error) {
	key := statscache.Key(statscache.PfxNetworkStats, tenantID)
	if cached, ok := statscache.Get[model.NetworkStats](ctx, s.cache, key); ok {
		return &cached, nil
	}

	stats, err := s.computeStats(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	statscache.Set(ctx, s.cache, key, stats, statscache.TTLMedium)
	return stats, nil
}

// computeStats runs live AQL counts to build NetworkStats.
func (s *Service) computeStats(ctx context.Context, tenantID string) (*model.NetworkStats, error) {
	suspiciousConns, err := s.repo.CountConnections(ctx, tenantID, "")
	if err != nil {
		return nil, err
	}
	blockedConns, err := s.repo.CountConnections(ctx, tenantID, string(model.ConnStatusBlocked))
	if err != nil {
		return nil, err
	}
	blockedDomains, err := s.repo.CountDNS(ctx, tenantID, true)
	if err != nil {
		return nil, err
	}
	anomalousDomains, err := s.repo.CountDNS(ctx, tenantID, false)
	if err != nil {
		return nil, err
	}
	activeAlerts, err := s.repo.CountNetworkAlerts(ctx, tenantID, string(model.NetAlertActive))
	if err != nil {
		return nil, err
	}
	totalDevices, err := s.repo.CountNetworkDevices(ctx, tenantID, false, false)
	if err != nil {
		return nil, err
	}
	unknownDevices, err := s.repo.CountNetworkDevices(ctx, tenantID, true, false)
	if err != nil {
		return nil, err
	}
	newDevices, err := s.repo.CountNetworkDevices(ctx, tenantID, false, true)
	if err != nil {
		return nil, err
	}

	// TotalTrafficGB and ActiveConns require datalake aggregation.
	// When the datalake is unavailable, return 0 — no fake data.
	trafficGB, activeConns, dnsToday := s.repo.AggregateTrafficStats(ctx, tenantID)

	return &model.NetworkStats{
		TenantID:         tenantID,
		TotalTrafficGB:   trafficGB,
		ActiveConns:      activeConns,
		SuspiciousConns:  suspiciousConns,
		BlockedConns:     blockedConns,
		DNSQueriesToday:  dnsToday,
		AnomalousDomains: anomalousDomains,
		BlockedDomains:   blockedDomains,
		DevicesTotal:     totalDevices,
		DevicesUnknown:   unknownDevices,
		DevicesNew:       newDevices,
		ActiveAlerts:     activeAlerts,
		ComputedAt:       time.Now(),
	}, nil
}

func (s *Service) ListConnections(ctx context.Context, tenantID string, page, pageSize int, status, severity string) ([]model.NetworkConnection, model.PageMeta, error) {
	return s.repo.ListConnections(ctx, tenantID, page, pageSize, status, severity)
}

func (s *Service) BlockConnection(ctx context.Context, tenantID, key, operatorID string) error {
	now := time.Now()
	return s.repo.UpdateConnection(ctx, key, map[string]any{
		"status":     string(model.ConnStatusBlocked),
		"blocked_at": now,
		"blocked_by": operatorID,
	})
}

func (s *Service) ListDNS(ctx context.Context, tenantID string, page, pageSize int, risk, keyword string) ([]model.DNSRecord, model.PageMeta, error) {
	return s.repo.ListDNS(ctx, tenantID, page, pageSize, risk, keyword)
}

func (s *Service) AddDNSBlocklist(ctx context.Context, tenantID, domain, operatorID string) error {
	return s.repo.UpsertDNSBlocklist(ctx, tenantID, domain, operatorID)
}

func (s *Service) ListNetworkRules(ctx context.Context, tenantID string) ([]model.NetworkDetectionRule, error) {
	return s.repo.ListNetworkRules(ctx, tenantID)
}

func (s *Service) UpdateNetworkRule(ctx context.Context, tenantID, key string, patch map[string]any) error {
	return s.repo.UpdateNetworkRule(ctx, key, patch)
}

func (s *Service) ListNetworkAlerts(ctx context.Context, tenantID string, page, pageSize int, status string) ([]model.NetworkThreatAlert, model.PageMeta, error) {
	return s.repo.ListNetworkAlerts(ctx, tenantID, page, pageSize, status)
}

func (s *Service) UpdateNetworkAlert(ctx context.Context, key string, patch map[string]any) error {
	return s.repo.UpdateNetworkAlert(ctx, key, patch)
}

func (s *Service) ListNetworkDevices(ctx context.Context, tenantID string, page, pageSize int, deviceType, risk, keyword string) ([]model.NetworkDevice, model.PageMeta, error) {
	return s.repo.ListNetworkDevices(ctx, tenantID, page, pageSize, deviceType, risk, keyword)
}

// TrafficTimeline returns 24-hour hourly traffic buckets from the
// network_connections collection.  Each bucket sums bytes_transferred
// for connections whose detected_at falls within that hour.
// When no data is available for a bucket the value is 0.
func (s *Service) TrafficTimeline(ctx context.Context, tenantID string) ([]map[string]any, error) {
	key := statscache.Key(statscache.PfxTrafficTimeline, tenantID)
	if cached, ok := statscache.Get[[]map[string]any](ctx, s.cache, key); ok {
		return cached, nil
	}

	data, err := s.repo.HourlyTrafficBuckets(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	statscache.Set(ctx, s.cache, key, data, statscache.TTLMedium)
	return data, nil
}

// InvalidateStatsCache removes cached stats for a tenant so the next
// request triggers a fresh computation.
func (s *Service) InvalidateStatsCache(ctx context.Context, tenantID string) {
	statscache.Del(ctx, s.cache, statscache.Key(statscache.PfxNetworkStats, tenantID))
	statscache.Del(ctx, s.cache, statscache.Key(statscache.PfxTrafficTimeline, tenantID))
}
