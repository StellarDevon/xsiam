package device

import (
	"context"
	"xsiam/internal/model"
)

// DataSourceStats aggregates data source health metrics.
type DataSourceStats struct {
	Total            int64            `json:"total"`
	ByStatus         map[string]int64 `json:"by_status"`
	TotalEvents      int64            `json:"total_events"`
	ErrorSources     []string         `json:"error_sources"`
	// Extended fields returned by GET /api/datasources/stats
	TotalEventsToday int64  `json:"total_events_today"`
	AvgLatencyMs     int64  `json:"avg_latency_ms"`
	ActiveSources    int64  `json:"active_sources"`
}

// GetDataSourceStats returns aggregated stats across all data sources for a tenant.
func (s *Service) GetDataSourceStats(ctx context.Context, tenantID string) (*DataSourceStats, error) {
	items, _, err := s.dsRepo.List(ctx, tenantID, 1, 1000)
	if err != nil {
		return nil, err
	}
	stats := &DataSourceStats{
		ByStatus:         make(map[string]int64),
		TotalEventsToday: 1250000, // mock: rolling 24h event count
		AvgLatencyMs:     12,      // mock: pipeline ingestion latency
	}
	for _, ds := range items {
		stats.Total++
		stats.ByStatus[string(ds.Status)]++
		stats.TotalEvents += ds.EventCount
		if ds.Status == model.DataSourceStatusError {
			stats.ErrorSources = append(stats.ErrorSources, ds.Name)
		}
		if ds.Status == model.DataSourceStatusActive {
			stats.ActiveSources++
		}
	}
	return stats, nil
}
