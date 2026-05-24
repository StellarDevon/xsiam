// Package endpoint implements the Endpoint Security domain:
// endpoint overview stats, behaviour events, isolation management.
// It composes data from device, alert and vulnerability repositories.
package endpoint

import (
	"context"
	"time"
	"xsiam/internal/model"
	"xsiam/internal/repository"
	"xsiam/pkg/statscache"
)

// Service provides endpoint security business logic.
type Service struct {
	endpointRepo *repository.EndpointRepo
	alertRepo    *repository.AlertRepo
	cache        *statscache.Client
}

func NewService(
	endpointRepo *repository.EndpointRepo,
	alertRepo *repository.AlertRepo,
	cache *statscache.Client,
) *Service {
	return &Service{
		endpointRepo: endpointRepo,
		alertRepo:    alertRepo,
		cache:        cache,
	}
}

// Stats returns aggregated endpoint health metrics.
// Results are served from Redis cache when available; on a miss the live
// AQL aggregation is run and the result is back-filled into the cache.
func (s *Service) Stats(ctx context.Context, tenantID string) (*model.EndpointStats, error) {
	key := statscache.Key(statscache.PfxEndpointStats, tenantID)
	if cached, ok := statscache.Get[model.EndpointStats](ctx, s.cache, key); ok {
		return &cached, nil
	}

	stats, err := s.computeStats(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	statscache.Set(ctx, s.cache, key, stats, statscache.TTLMedium)
	return stats, nil
}

func (s *Service) computeStats(ctx context.Context, tenantID string) (*model.EndpointStats, error) {
	stats, err := s.endpointRepo.GetStats(ctx, tenantID)
	if err != nil {
		return nil, err
	}

	// Enrich with isolation counts from the isolation sub-collection.
	isoActive, _ := s.endpointRepo.CountIsolated(ctx, tenantID, string(model.IsolationActive))
	isoWeek, _ := s.endpointRepo.CountIsolationsInWindow(ctx, tenantID, 168) // 7 days

	// Alerts today: count alerts created in the last 24h for this tenant.
	alertsToday, _ := s.alertRepo.CountSince(ctx, tenantID, time.Now().Add(-24*time.Hour))

	stats.Isolated = isoActive
	stats.IsolationsWeek = isoWeek
	stats.AlertsToday = alertsToday
	stats.ComputedAt = time.Now()
	return stats, nil
}

// ListIsolated returns paged isolated endpoints from the DB.
func (s *Service) ListIsolated(ctx context.Context, tenantID string, page, pageSize int, status string) ([]model.IsolatedEndpoint, model.PageMeta, error) {
	return s.endpointRepo.ListIsolated(ctx, tenantID, page, pageSize, status)
}

// IsolateEndpoint records an isolation action for a device.
func (s *Service) IsolateEndpoint(ctx context.Context, tenantID, deviceKey, reason, operator string) (*model.IsolatedEndpoint, error) {
	iso := &model.IsolatedEndpoint{
		TenantID:  tenantID,
		DeviceKey: deviceKey,
		Reason:    reason,
		Operator:  operator,
		Status:    model.IsolationActive,
	}
	if err := s.endpointRepo.CreateIsolation(ctx, iso); err != nil {
		return nil, err
	}
	// Invalidate the stats cache so the next read picks up the new isolation.
	statscache.Del(ctx, s.cache, statscache.Key(statscache.PfxEndpointStats, tenantID))
	return iso, nil
}

// ReleaseIsolation lifts the isolation on an endpoint.
func (s *Service) ReleaseIsolation(ctx context.Context, key, operatorID string) error {
	return s.endpointRepo.ReleaseIsolation(ctx, key, operatorID)
}
