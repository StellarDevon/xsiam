package report

import (
	"context"
	"fmt"
	"math/rand"
	"time"
	"xsiam/internal/domain/dashboard"
	"xsiam/internal/model"
	"xsiam/internal/repository"
)

// ReportStats holds aggregated report counts by status for a tenant.
type ReportStats struct {
	Total      int64 `json:"total"`
	Scheduled  int64 `json:"scheduled"`
	Generating int64 `json:"generating"`
	Ready      int64 `json:"ready"`
	Failed     int64 `json:"failed"`
	// Processing and Completed are legacy aliases retained for compatibility.
	Processing int64 `json:"processing"`
	Completed  int64 `json:"completed"`
}

// ReportStore is the minimal interface Service needs from the report repository.
type ReportStore interface {
	List(ctx context.Context, tenantID string, page, pageSize int) ([]model.Report, model.PageMeta, error)
	GetByID(ctx context.Context, key string) (*model.Report, error)
	Create(ctx context.Context, report *model.Report) error
	Update(ctx context.Context, key string, patch map[string]any) error
	Delete(ctx context.Context, key string) error
	Stats(ctx context.Context, tenantID string) (*repository.ReportStats, error)
}

// StatsProvider is the minimal interface Service needs to generate report data.
type StatsProvider interface {
	GetStats(ctx context.Context, tenantID string) (*dashboard.Stats, error)
}

type Service struct {
	reportRepo ReportStore
	dashSvc    StatsProvider
}

func NewService(reportRepo *repository.ReportRepo, dashSvc *dashboard.Service) *Service {
	return &Service{reportRepo: reportRepo, dashSvc: dashSvc}
}

// NewServiceWith accepts interfaces (used in tests).
func NewServiceWith(reportRepo ReportStore, dashSvc StatsProvider) *Service {
	return &Service{reportRepo: reportRepo, dashSvc: dashSvc}
}

func (s *Service) List(ctx context.Context, tenantID string, page, pageSize int) ([]model.Report, model.PageMeta, error) {
	return s.reportRepo.List(ctx, tenantID, page, pageSize)
}

func (s *Service) Get(ctx context.Context, key string) (*model.Report, error) {
	return s.reportRepo.GetByID(ctx, key)
}

// Create saves the report with status "generating" and immediately spawns a
// goroutine that simulates report generation (2-3 s delay) before marking it
// "ready". The caller receives the persisted report (with Key set) synchronously.
func (s *Service) Create(ctx context.Context, report *model.Report, operatorID string) error {
	report.Status = model.ReportStatusGenerating
	report.CreatedBy = operatorID
	if err := s.reportRepo.Create(ctx, report); err != nil {
		return err
	}
	go s.simulateGeneration(context.Background(), report.Key, report.TenantID)
	return nil
}

func (s *Service) Delete(ctx context.Context, key string) error {
	return s.reportRepo.Delete(ctx, key)
}

// Schedule sets the report status to "scheduled" and computes the next_run_at
// time based on the provided schedule string:
//   - "daily"   → same time tomorrow
//   - "weekly"  → next Monday (at midnight UTC)
//   - "monthly" → first day of next month (at midnight UTC)
//   - "once"    → now (triggers on the next ProcessPending run)
//
// The schedule string is also stored on the report for future recurrence.
func (s *Service) Schedule(ctx context.Context, r *model.Report, schedule string) error {
	now := time.Now().UTC()
	var nextRun time.Time
	switch schedule {
	case "daily":
		nextRun = now.AddDate(0, 0, 1).Truncate(24 * time.Hour)
	case "weekly":
		// Advance to next Monday
		daysUntilMonday := (int(time.Monday) - int(now.Weekday()) + 7) % 7
		if daysUntilMonday == 0 {
			daysUntilMonday = 7
		}
		nextRun = now.AddDate(0, 0, daysUntilMonday).Truncate(24 * time.Hour)
	case "monthly":
		// First day of next month
		nextRun = time.Date(now.Year(), now.Month()+1, 1, 0, 0, 0, 0, time.UTC)
	default: // "once" or unknown
		nextRun = now
	}
	patch := map[string]any{
		"status":      string(model.ReportStatusScheduled),
		"schedule":    schedule,
		"next_run_at": nextRun.Format(time.RFC3339),
	}
	if err := s.reportRepo.Update(ctx, r.Key, patch); err != nil {
		return err
	}
	r.Status = model.ReportStatusScheduled
	r.Schedule = schedule
	r.NextRunAt = &nextRun
	return nil
}

// ProcessPending finds reports that are either "scheduled" / "pending" and
// triggers generation for them, and also marks stuck "generating" reports that
// are older than 5 minutes as "failed".
// Called by the cron job every hour.
func (s *Service) ProcessPending(ctx context.Context, tenantID string) error {
	// Fetch a generous page; for large deployments a cursor-based approach
	// would be preferred, but 100 is sufficient for the cron batch size.
	reports, _, err := s.reportRepo.List(ctx, tenantID, 1, 100)
	if err != nil {
		return err
	}
	now := time.Now()
	stuckThreshold := now.Add(-5 * time.Minute)
	for _, r := range reports {
		switch r.Status {
		case model.ReportStatusPending:
			go s.simulateGeneration(ctx, r.Key, r.TenantID)
		case model.ReportStatusScheduled:
			// Only trigger generation when next_run_at has been reached.
			// A nil next_run_at (legacy records) is treated as immediately due.
			if r.NextRunAt == nil || !now.Before(*r.NextRunAt) {
				go s.simulateGeneration(ctx, r.Key, r.TenantID)
			}
		case model.ReportStatusGenerating:
			// Mark as failed if the report has been stuck in "generating" for
			// more than 5 minutes (CreatedAt is the best proxy available without
			// a dedicated generating_since field).
			if r.CreatedAt.Before(stuckThreshold) {
				_ = s.reportRepo.Update(ctx, r.Key, map[string]any{
					"status": string(model.ReportStatusFailed),
				})
			}
		}
	}
	return nil
}

// GetStats returns aggregated report counts by status for the given tenant.
func (s *Service) GetStats(ctx context.Context, tenantID string) (*ReportStats, error) {
	rs, err := s.reportRepo.Stats(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	return &ReportStats{
		Total:      rs.Total,
		Scheduled:  rs.Scheduled,
		Generating: rs.Generating,
		Ready:      rs.Ready,
		Failed:     rs.Failed,
		Processing: rs.Processing,
		Completed:  rs.Completed,
	}, nil
}

// simulateGeneration sleeps for a random 2-3 second window (mimicking real
// async PDF/data generation) then transitions the report to "ready".
func (s *Service) simulateGeneration(ctx context.Context, key, tenantID string) {
	delay := time.Duration(2000+rand.Intn(1001)) * time.Millisecond //nolint:gosec
	time.Sleep(delay)

	_, err := s.dashSvc.GetStats(ctx, tenantID)
	if err != nil {
		_ = s.reportRepo.Update(ctx, key, map[string]any{
			"status": string(model.ReportStatusFailed),
		})
		return
	}

	now := time.Now().UTC()
	_ = s.reportRepo.Update(ctx, key, map[string]any{
		"status":       string(model.ReportStatusReady),
		"generated_at": now.Format(time.RFC3339),
		"download_url": fmt.Sprintf("/api/reports/%s/download", key),
	})
}
