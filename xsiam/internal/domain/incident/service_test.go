package incident_test

import (
	"context"
	"testing"
	"xsiam/internal/domain/incident"
	"xsiam/internal/model"
	"xsiam/internal/repository"
)

type stubIncidentRepo struct{}

func (r *stubIncidentRepo) Create(ctx context.Context, inc *model.Incident) error {
	inc.Key = "inc-key"
	return nil
}
func (r *stubIncidentRepo) GetByID(ctx context.Context, key string) (*model.Incident, error) {
	return nil, nil
}
func (r *stubIncidentRepo) Update(ctx context.Context, key string, patch map[string]any) error {
	return nil
}
func (r *stubIncidentRepo) Delete(ctx context.Context, key string) error { return nil }
func (r *stubIncidentRepo) List(ctx context.Context, f repository.IncidentListFilter) ([]model.Incident, model.PageMeta, error) {
	return nil, model.PageMeta{}, nil
}
func (r *stubIncidentRepo) ListAlertKeys(ctx context.Context, incidentKey string) ([]string, error) {
	return nil, nil
}
func (r *stubIncidentRepo) Merge(ctx context.Context, primaryKey string, secondaryKeys []string) error {
	return nil
}

func TestIncidentCreate_SetsIncidentIDAndStatus(t *testing.T) {
	repo := &stubIncidentRepo{}
	svc := incident.NewServiceWithRepos(repo, nil, nil)

	req := incident.CreateIncidentReq{
		Name:     "Lateral movement detected",
		Severity: model.SeverityHigh,
		TenantID: "t-001",
	}
	inc, err := svc.Create(context.Background(), req, "op-1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inc.IncidentID == "" {
		t.Error("IncidentID should be set")
	}
	if inc.Status != model.IncidentStatusNew {
		t.Errorf("expected status new, got %s", inc.Status)
	}
	if inc.TenantID != "t-001" {
		t.Errorf("expected tenant t-001, got %s", inc.TenantID)
	}
}

func TestIncidentCreate_KeySetByRepo(t *testing.T) {
	repo := &stubIncidentRepo{}
	svc := incident.NewServiceWithRepos(repo, nil, nil)

	inc, err := svc.Create(context.Background(), incident.CreateIncidentReq{
		Name:     "test",
		Severity: model.SeverityCritical,
		TenantID: "t-1",
	}, "op")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inc.Key == "" {
		t.Error("Key should be set by repo stub")
	}
}

func TestIncidentCreate_TimestampsSet(t *testing.T) {
	svc := incident.NewServiceWithRepos(&stubIncidentRepo{}, nil, nil)
	inc, err := svc.Create(context.Background(), incident.CreateIncidentReq{
		Name:     "test",
		Severity: model.SeverityMedium,
		TenantID: "t-1",
	}, "op")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if inc.FirstSeen.IsZero() {
		t.Error("FirstSeen should be set")
	}
	if inc.LastActivity.IsZero() {
		t.Error("LastActivity should be set")
	}
}

func TestIncidentSeverityValues(t *testing.T) {
	for _, sev := range []model.Severity{
		model.SeverityCritical, model.SeverityHigh, model.SeverityMedium, model.SeverityLow,
	} {
		svc := incident.NewServiceWithRepos(&stubIncidentRepo{}, nil, nil)
		inc, err := svc.Create(context.Background(), incident.CreateIncidentReq{
			Name:     "test",
			Severity: sev,
			TenantID: "t-1",
		}, "op")
		if err != nil {
			t.Fatalf("sev %s: %v", sev, err)
		}
		if inc.Severity != sev {
			t.Errorf("expected severity %s, got %s", sev, inc.Severity)
		}
	}
}
