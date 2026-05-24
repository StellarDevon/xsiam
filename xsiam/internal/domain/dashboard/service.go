package dashboard

import (
	"context"
	"time"
	"xsiam/internal/repository"
)

type Stats struct {
	TotalAlerts           int64            `json:"total_alerts"`
	OpenAlerts            int64            `json:"open_alerts"`
	TotalIncidents        int64            `json:"total_incidents"`
	OpenIncidents         int64            `json:"open_incidents"`
	TotalAssets           int64            `json:"total_assets"`
	TotalVulns            int64            `json:"total_vulns"`
	// TotalVulnerabilities is an alias for TotalVulns for frontend compatibility.
	TotalVulnerabilities  int64            `json:"total_vulnerabilities"`
	CriticalVulns         int64            `json:"critical_vulns"`
	TotalIOCs             int64            `json:"total_iocs"`
	TotalRisks            int64            `json:"total_risks"`
	TotalReports          int64            `json:"total_reports"`
	AlertsByDay           []DayCount       `json:"alerts_by_day"`
	AlertsBySeverity      map[string]int64 `json:"alerts_by_severity"`
	IncidentsByStatus     map[string]int64 `json:"incidents_by_status"`
	TopTactics            []TacticCount    `json:"top_tactics"`
	RecentAlerts          []AlertSummary   `json:"recent_alerts"`
	MttrHours             float64          `json:"mttr_hours"`
}

type DayCount struct {
	Date  string `json:"date"`
	Count int64  `json:"count"`
}

type TacticCount struct {
	Tactic string `json:"tactic"`
	Count  int64  `json:"count"`
}

type AlertSummary struct {
	Key         string    `json:"_key"`
	Title       string    `json:"title"`
	Severity    string    `json:"severity"`
	Status      string    `json:"status"`
	TriggeredAt time.Time `json:"triggered_at"`
}

type Service struct {
	alertRepo        *repository.AlertRepo
	incidentRepo     *repository.IncidentRepo
	assetRepo        *repository.AssetRepo
	vulnRepo         *repository.VulnerabilityRepo
	ruleRepo         *repository.DetectionRuleRepo
	iocRepo          *repository.IocRepo
	identityRiskRepo *repository.IdentityRiskRepo
	reportRepo       *repository.ReportRepo
}

func NewService(
	alertRepo *repository.AlertRepo,
	incidentRepo *repository.IncidentRepo,
	assetRepo *repository.AssetRepo,
	vulnRepo *repository.VulnerabilityRepo,
	ruleRepo *repository.DetectionRuleRepo,
	iocRepo *repository.IocRepo,
	identityRiskRepo *repository.IdentityRiskRepo,
	reportRepo *repository.ReportRepo,
) *Service {
	return &Service{
		alertRepo:        alertRepo,
		incidentRepo:     incidentRepo,
		assetRepo:        assetRepo,
		vulnRepo:         vulnRepo,
		ruleRepo:         ruleRepo,
		iocRepo:          iocRepo,
		identityRiskRepo: identityRiskRepo,
		reportRepo:       reportRepo,
	}
}

func (s *Service) GetStats(ctx context.Context, tenantID string) (*Stats, error) {
	stats := &Stats{
		AlertsBySeverity:  make(map[string]int64),
		IncidentsByStatus: make(map[string]int64),
	}

	allAlerts, _, err := s.alertRepo.List(ctx, repository.AlertListFilter{TenantID: tenantID, PageSize: 10000, Page: 1})
	if err == nil {
		stats.TotalAlerts = int64(len(allAlerts))
		for _, a := range allAlerts {
			stats.AlertsBySeverity[string(a.Severity)]++
			if a.Status == "active" || a.Status == "investigating" {
				stats.OpenAlerts++
			}
		}
	}

	recent, _, _ := s.alertRepo.List(ctx, repository.AlertListFilter{
		TenantID: tenantID, PageSize: 5, Page: 1, SortBy: "triggered_at", SortDesc: true,
	})
	for _, a := range recent {
		stats.RecentAlerts = append(stats.RecentAlerts, AlertSummary{
			Key: a.Key, Title: a.Name, Severity: string(a.Severity),
			Status: string(a.Status), TriggeredAt: a.TriggeredAt,
		})
	}

	allIncidents, _, _ := s.incidentRepo.List(ctx, repository.IncidentListFilter{TenantID: tenantID, PageSize: 10000, Page: 1})
	stats.TotalIncidents = int64(len(allIncidents))
	var totalHours float64
	var resolvedCount int64
	for _, inc := range allIncidents {
		stats.IncidentsByStatus[string(inc.Status)]++
		if inc.Status == "new" || inc.Status == "investigating" || inc.Status == "contained" {
			stats.OpenIncidents++
		}
		if inc.Status == "resolved" && inc.ResolvedAt != nil {
			totalHours += inc.ResolvedAt.Sub(inc.CreatedAt).Hours()
			resolvedCount++
		}
	}
	if resolvedCount > 0 {
		stats.MttrHours = totalHours / float64(resolvedCount)
	}

	_, assetMeta, _ := s.assetRepo.List(ctx, repository.AssetListFilter{TenantID: tenantID, PageSize: 1, Page: 1})
	stats.TotalAssets = int64(assetMeta.Total)

	_, vulnMeta, _ := s.vulnRepo.List(ctx, repository.VulnerabilityListFilter{TenantID: tenantID, PageSize: 1, Page: 1})
	stats.TotalVulns = int64(vulnMeta.Total)
	stats.TotalVulnerabilities = stats.TotalVulns
	_, critMeta, _ := s.vulnRepo.List(ctx, repository.VulnerabilityListFilter{TenantID: tenantID, Severity: "critical", PageSize: 1, Page: 1})
	stats.CriticalVulns = int64(critMeta.Total)

	if iocCount, err := s.iocRepo.CountByTenant(ctx, tenantID); err == nil {
		stats.TotalIOCs = iocCount
	}
	if s.identityRiskRepo != nil {
		if riskCount, err := s.identityRiskRepo.CountByTenant(ctx, tenantID); err == nil {
			stats.TotalRisks = riskCount
		}
	}
	if s.reportRepo != nil {
		if reportCount, err := s.reportRepo.CountByTenant(ctx, tenantID); err == nil {
			stats.TotalReports = reportCount
		}
	}

	now := time.Now()
	dayMap := make(map[string]int64)
	for i := 6; i >= 0; i-- {
		day := now.AddDate(0, 0, -i).Format("2006-01-02")
		dayMap[day] = 0
		stats.AlertsByDay = append(stats.AlertsByDay, DayCount{Date: day, Count: 0})
	}
	sevenDaysAgo := now.AddDate(0, 0, -7)
	recentRange, _ := s.alertRepo.FindByTimeRange(ctx, sevenDaysAgo, now)
	for _, a := range recentRange {
		dayMap[a.TriggeredAt.Format("2006-01-02")]++
	}
	for i := range stats.AlertsByDay {
		stats.AlertsByDay[i].Count = dayMap[stats.AlertsByDay[i].Date]
	}

	mitreMap, _ := s.ruleRepo.AggregateByMitre(ctx)
	for tactic, techniques := range mitreMap {
		stats.TopTactics = append(stats.TopTactics, TacticCount{Tactic: tactic, Count: int64(len(techniques))})
	}

	return stats, nil
}
