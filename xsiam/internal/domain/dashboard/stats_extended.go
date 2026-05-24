package dashboard

import (
	"context"
)

// TopAsset represents an asset with high alert counts
type TopAsset struct {
	AssetName  string  `json:"asset_name"`
	AssetID    string  `json:"asset_id"`
	AlertCount int64   `json:"alert_count"`
	RiskScore  float64 `json:"risk_score"`
}

// SourceBreakdown counts alerts by source type
type SourceBreakdown struct {
	Source string `json:"source"`
	Count  int64  `json:"count"`
}

// ExtendedStats includes all Stats fields plus additional analytics
type ExtendedStats struct {
	*Stats
	SourceBreakdown    []SourceBreakdown `json:"source_breakdown"`
	TopAssets          []TopAsset        `json:"top_assets"`
	MitreCoverage      map[string]int    `json:"mitre_coverage"` // tactic -> technique count
	DetectionRuleCount int64             `json:"detection_rule_count"`
	ActiveRuleCount    int64             `json:"active_rule_count"`
	IOCCount           int64             `json:"ioc_count"`
}

// GetExtendedStats returns Stats plus source breakdown, top assets, MITRE coverage,
// detection-rule counts, and IOC count — all computed via AQL rather than in-process.
func (s *Service) GetExtendedStats(ctx context.Context, tenantID string) (*ExtendedStats, error) {
	base, err := s.GetStats(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	ext := &ExtendedStats{Stats: base}

	// --- Alerts by source type (AQL GROUP-BY) ---
	srcRows, err := s.alertRepo.AggregateBySourceType(ctx, tenantID)
	if err == nil {
		for _, row := range srcRows {
			ext.SourceBreakdown = append(ext.SourceBreakdown, SourceBreakdown{
				Source: row.SourceType,
				Count:  row.Count,
			})
		}
	}

	// --- Top assets by alert count (AQL GROUP-BY + SORT + LIMIT 10) ---
	assetRows, err := s.alertRepo.AggregateTopAssets(ctx, tenantID, 10)
	if err == nil {
		for _, row := range assetRows {
			ext.TopAssets = append(ext.TopAssets, TopAsset{
				AssetID:    row.AssetID,
				AssetName:  row.AssetName,
				AlertCount: row.AlertCount,
			})
		}
	}

	// --- MITRE coverage from detection_rules (tenant-scoped) ---
	// AggregateByMitreTenant returns tactic -> []technique; convert to tactic -> count.
	mitreMap, err := s.ruleRepo.AggregateByMitreTenant(ctx, tenantID)
	if err == nil {
		coverage := make(map[string]int, len(mitreMap))
		for tactic, techniques := range mitreMap {
			coverage[tactic] = len(techniques)
		}
		ext.MitreCoverage = coverage
	}

	// --- Detection rule counts ---
	if total, err := s.ruleRepo.CountByTenant(ctx, tenantID); err == nil {
		ext.DetectionRuleCount = total
	}
	if active, err := s.ruleRepo.CountActiveByTenant(ctx, tenantID); err == nil {
		ext.ActiveRuleCount = active
	}

	// --- IOC count ---
	if iocCount, err := s.iocRepo.CountByTenant(ctx, tenantID); err == nil {
		ext.IOCCount = iocCount
	}

	return ext, nil
}
