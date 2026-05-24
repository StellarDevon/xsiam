package device

import (
	"context"
	"xsiam/internal/model"
	"xsiam/pkg/statscache"
)

// DataSourceStats aggregates data source health metrics.
type DataSourceStats struct {
	Total         int64            `json:"total"`
	ByStatus      map[string]int64 `json:"by_status"`
	TotalEvents   int64            `json:"total_events"`
	ErrorSources  []string         `json:"error_sources"`
	ActiveSources int64            `json:"active_sources"`
}

// GetDataSourceStats returns aggregated stats across all data sources for a tenant.
// Results are cached in Redis for TTLMedium (30 min).
func (s *Service) GetDataSourceStats(ctx context.Context, tenantID string) (*DataSourceStats, error) {
	key := statscache.Key(statscache.PfxDatasourceStats, tenantID)
	if cached, ok := statscache.Get[DataSourceStats](ctx, s.cache, key); ok {
		return &cached, nil
	}

	items, _, err := s.dsRepo.List(ctx, tenantID, 1, 1000)
	if err != nil {
		return nil, err
	}
	result := &DataSourceStats{
		ByStatus: make(map[string]int64),
	}
	for _, ds := range items {
		result.Total++
		result.ByStatus[string(ds.Status)]++
		result.TotalEvents += ds.EventCount
		if ds.Status == model.DataSourceStatusError {
			result.ErrorSources = append(result.ErrorSources, ds.Name)
		}
		if ds.Status == model.DataSourceStatusActive {
			result.ActiveSources++
		}
	}

	statscache.Set(ctx, s.cache, key, result, statscache.TTLMedium)
	return result, nil
}
