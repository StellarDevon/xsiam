package report

import (
	"context"
	"fmt"
	"time"
	"xsiam/internal/domain/dashboard"
	"xsiam/internal/model"
	"xsiam/internal/repository"
)

// ReportStore is the minimal interface Service needs from the report repository.
type ReportStore interface {
	List(ctx context.Context, tenantID string, page, pageSize int) ([]model.Report, model.PageMeta, error)
	GetByID(ctx context.Context, key string) (*model.Report, error)
	Create(ctx context.Context, report *model.Report) error
	Update(ctx context.Context, key string, patch map[string]any) error
	Delete(ctx context.Context, key string) error
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

func (s *Service) Create(ctx context.Context, report *model.Report, operatorID string) error {
	report.Status = model.ReportStatusPending
	report.CreatedBy = operatorID
	if err := s.reportRepo.Create(ctx, report); err != nil {
		return err
	}
	go s.generate(context.Background(), report.Key, report.TenantID)
	return nil
}

func (s *Service) Delete(ctx context.Context, key string) error {
	return s.reportRepo.Delete(ctx, key)
}

func (s *Service) generate(ctx context.Context, key, tenantID string) {
	_ = s.reportRepo.Update(ctx, key, map[string]any{"status": string(model.ReportStatusGenerating)})
	_, err := s.dashSvc.GetStats(ctx, tenantID)
	if err != nil {
		_ = s.reportRepo.Update(ctx, key, map[string]any{"status": string(model.ReportStatusFailed)})
		return
	}
	_ = s.reportRepo.Update(ctx, key, map[string]any{
		"status":       string(model.ReportStatusReady),
		"generated_at": time.Now(),
		"download_url": fmt.Sprintf("/api/reports/%s/download", key),
	})
}
