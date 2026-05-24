package report_test

import (
	"context"
	"testing"
	"time"
	"xsiam/internal/domain/dashboard"
	"xsiam/internal/domain/report"
	"xsiam/internal/model"
	"xsiam/internal/repository"
)

// ── stub repo ─────────────────────────────────────────────────────────────────

type stubReportRepo struct {
	reports map[string]*model.Report
	seq     int
}

func newStubReportRepo() *stubReportRepo {
	return &stubReportRepo{reports: make(map[string]*model.Report)}
}

func (r *stubReportRepo) Create(_ context.Context, rep *model.Report) error {
	r.seq++
	rep.Key = "rpt-" + rep.Name
	rep.CreatedAt = time.Now()
	r.reports[rep.Key] = rep
	return nil
}

func (r *stubReportRepo) GetByID(_ context.Context, key string) (*model.Report, error) {
	return r.reports[key], nil
}

func (r *stubReportRepo) Update(_ context.Context, key string, patch map[string]any) error {
	rep := r.reports[key]
	if rep == nil {
		return nil
	}
	if v, ok := patch["status"]; ok {
		rep.Status = model.ReportStatus(v.(string))
	}
	return nil
}

func (r *stubReportRepo) Delete(_ context.Context, key string) error {
	delete(r.reports, key)
	return nil
}

func (r *stubReportRepo) Stats(_ context.Context, _ string) (*repository.ReportStats, error) {
	return &repository.ReportStats{Total: int64(len(r.reports))}, nil
}

func (r *stubReportRepo) List(_ context.Context, tenantID string, _, _ int) ([]model.Report, model.PageMeta, error) {
	var out []model.Report
	for _, rep := range r.reports {
		if tenantID != "" && rep.TenantID != tenantID {
			continue
		}
		out = append(out, *rep)
	}
	return out, model.PageMeta{Total: int64(len(out)), Page: 1, PageSize: 20, Pages: 1}, nil
}

// ── stub stats provider ───────────────────────────────────────────────────────

type stubStats struct{ err error }

func (s *stubStats) GetStats(_ context.Context, _ string) (*dashboard.Stats, error) {
	if s.err != nil {
		return nil, s.err
	}
	return &dashboard.Stats{TotalAlerts: 5}, nil
}

// ── tests ────────────────────────────────────────────────────────────────────

func TestReportService_Create_SetsGeneratingStatus(t *testing.T) {
	repo := newStubReportRepo()
	svc := report.NewServiceWith(repo, &stubStats{})

	rep := &model.Report{TenantID: "t-1", Name: "weekly-report", TemplateType: model.ReportTemplateWeekly}
	if err := svc.Create(context.Background(), rep, "op-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	// Create sets status to "generating" immediately and kicks off async simulation.
	if rep.Status != model.ReportStatusGenerating {
		t.Errorf("expected status generating immediately after Create, got %s", rep.Status)
	}
	if rep.Key == "" {
		t.Error("Key should be set after Create")
	}
	if rep.CreatedBy != "op-1" {
		t.Errorf("expected created_by op-1, got %s", rep.CreatedBy)
	}
}

func TestReportService_Delete_RemovesEntry(t *testing.T) {
	repo := newStubReportRepo()
	svc := report.NewServiceWith(repo, &stubStats{})

	rep := &model.Report{TenantID: "t-1", Name: "to-delete"}
	_ = svc.Create(context.Background(), rep, "op")

	_ = svc.Delete(context.Background(), rep.Key)

	got, _ := svc.Get(context.Background(), rep.Key)
	if got != nil {
		t.Error("expected report to be deleted")
	}
}

func TestReportService_List_FiltersByTenant(t *testing.T) {
	repo := newStubReportRepo()
	svc := report.NewServiceWith(repo, &stubStats{})

	_ = svc.Create(context.Background(), &model.Report{TenantID: "t-1", Name: "r1"}, "op")
	_ = svc.Create(context.Background(), &model.Report{TenantID: "t-2", Name: "r2"}, "op")

	items, meta, err := svc.List(context.Background(), "t-1", 1, 20)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 1 {
		t.Errorf("expected 1 report for t-1, got %d", len(items))
	}
	if meta.Total != 1 {
		t.Errorf("expected total 1, got %d", meta.Total)
	}
}
