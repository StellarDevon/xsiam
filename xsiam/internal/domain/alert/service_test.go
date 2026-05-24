package alert_test

import (
	"context"
	"testing"
	"time"
	"xsiam/internal/domain/alert"
	"xsiam/internal/model"
	"xsiam/internal/repository"
)

// --- stub repos ---

type stubAlertRepo struct {
	alerts []*model.Alert
}

func (r *stubAlertRepo) Create(ctx context.Context, a *model.Alert) error {
	a.Key = "key-" + a.AlertID
	r.alerts = append(r.alerts, a)
	return nil
}
func (r *stubAlertRepo) GetByID(ctx context.Context, key string) (*model.Alert, error) {
	for _, a := range r.alerts {
		if a.Key == key {
			return a, nil
		}
	}
	return nil, nil
}
func (r *stubAlertRepo) Update(ctx context.Context, key string, patch map[string]any) error { return nil }
func (r *stubAlertRepo) Delete(ctx context.Context, key string) error                       { return nil }
func (r *stubAlertRepo) FindByAlertID(ctx context.Context, id string) (*model.Alert, error) {
	for _, a := range r.alerts {
		if a.AlertID == id {
			return a, nil
		}
	}
	return nil, nil
}
func (r *stubAlertRepo) List(ctx context.Context, f repository.AlertListFilter) ([]model.Alert, model.PageMeta, error) {
	var out []model.Alert
	for _, a := range r.alerts {
		out = append(out, *a)
	}
	return out, model.PageMeta{Total: int64(len(out)), Page: 1, PageSize: 20, Pages: 1}, nil
}
func (r *stubAlertRepo) FindByTimeRange(ctx context.Context, from, to time.Time) ([]model.Alert, error) {
	return nil, nil
}
func (r *stubAlertRepo) FindByAssetSince(ctx context.Context, id *string, since time.Time) ([]*model.Alert, error) {
	return nil, nil
}
func (r *stubAlertRepo) FindByIocValues(ctx context.Context, vals []string, since time.Time) ([]*model.Alert, error) {
	return nil, nil
}
func (r *stubAlertRepo) FindByUser(ctx context.Context, u *string, since time.Time) ([]*model.Alert, error) {
	return nil, nil
}
func (r *stubAlertRepo) GetStats(_ context.Context, _ string) (*alert.AlertStats, error) {
	return &alert.AlertStats{BySeverity: map[string]int64{}, ByStatus: map[string]int64{}}, nil
}

// --- tests ---

func TestAlertCreate_SetsAlertIDAndStatus(t *testing.T) {
	alertRepo := &stubAlertRepo{}
	svc := alert.NewServiceWithRepos(alertRepo, nil, nil, nil)

	req := alert.CreateAlertReq{
		Name:       "Suspicious powershell execution",
		Severity:   model.SeverityHigh,
		SourceType: model.SourceEndpoint,
		TenantID:   "t-001",
	}
	a, err := svc.Create(context.Background(), req, "op-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.AlertID == "" {
		t.Error("AlertID should be set")
	}
	if a.Status != model.AlertStatusActive {
		t.Errorf("expected status active, got %s", a.Status)
	}
	if a.TenantID != "t-001" {
		t.Errorf("expected tenant t-001, got %s", a.TenantID)
	}
}

func TestAlertCreate_TriggeredAtSet(t *testing.T) {
	svc := alert.NewServiceWithRepos(&stubAlertRepo{}, nil, nil, nil)
	before := time.Now().Add(-time.Second)
	a, _ := svc.Create(context.Background(), alert.CreateAlertReq{
		Name:       "test",
		Severity:   model.SeverityCritical,
		SourceType: model.SourceNetwork,
		TenantID:   "t-1",
	}, "op")
	after := time.Now().Add(time.Second)
	if a.TriggeredAt.Before(before) || a.TriggeredAt.After(after) {
		t.Errorf("triggered_at %v not within expected window", a.TriggeredAt)
	}
}

func TestAlertSeverityValues(t *testing.T) {
	for _, sev := range []model.Severity{
		model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow,
	} {
		repo := &stubAlertRepo{}
		svc := alert.NewServiceWithRepos(repo, nil, nil, nil)
		a, err := svc.Create(context.Background(), alert.CreateAlertReq{
			Name:       "test",
			Severity:   sev,
			SourceType: model.SourceEndpoint,
			TenantID:   "t-1",
		}, "op")
		if err != nil {
			t.Fatalf("sev %s: %v", sev, err)
		}
		if a.Severity != sev {
			t.Errorf("expected severity %s, got %s", sev, a.Severity)
		}
	}
}
