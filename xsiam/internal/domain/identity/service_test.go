package identity_test

import (
	"context"
	"testing"
	"time"
	"xsiam/internal/domain/identity"
	"xsiam/internal/model"
)

// NewRiskService with nil repos is valid for testing in-memory logic.
func newSvc() *identity.RiskService {
	return identity.NewRiskService(nil, nil)
}

func TestRiskService_AddSignal_AccumulatesScore(t *testing.T) {
	svc := newSvc()

	svc.AddSignal(context.Background(), "t-1", "u-1", "alice",
		model.RiskSignal{Type: model.SignalNewDevice, Score: 30, DetectedAt: time.Now()})
	svc.AddSignal(context.Background(), "t-1", "u-1", "alice",
		model.RiskSignal{Type: model.SignalTimeAnomaly, Score: 25, DetectedAt: time.Now()})

	risk := svc.Get(context.Background(), "u-1")
	if risk == nil {
		t.Fatal("expected risk entry, got nil")
	}
	if risk.RiskScore != 55 {
		t.Errorf("expected score 55, got %.1f", risk.RiskScore)
	}
}

func TestRiskService_ScoreCappedAt100(t *testing.T) {
	svc := newSvc()

	for i := 0; i < 5; i++ {
		svc.AddSignal(context.Background(), "t-1", "u-2", "bob",
			model.RiskSignal{Type: model.SignalActiveAlert, Score: 40, DetectedAt: time.Now()})
	}

	risk := svc.Get(context.Background(), "u-2")
	if risk.RiskScore != 100 {
		t.Errorf("score should be capped at 100, got %.1f", risk.RiskScore)
	}
}

func TestRiskService_Get_ReturnsNilForUnknownUser(t *testing.T) {
	svc := newSvc()
	if got := svc.Get(context.Background(), "nobody"); got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestRiskService_List_FiltersByTenant(t *testing.T) {
	svc := newSvc()

	svc.AddSignal(context.Background(), "t-1", "u-a", "alice",
		model.RiskSignal{Type: model.SignalPrivilegeAnomaly, Score: 20, DetectedAt: time.Now()})
	svc.AddSignal(context.Background(), "t-2", "u-b", "bob",
		model.RiskSignal{Type: model.SignalImpossibleTravel, Score: 50, DetectedAt: time.Now()})

	items, meta := svc.List(context.Background(), "t-1", "", 1, 20)
	if len(items) != 1 {
		t.Errorf("expected 1 result for t-1, got %d", len(items))
	}
	if meta.Total != 1 {
		t.Errorf("expected total 1, got %d", meta.Total)
	}
	if items[0].Username != "alice" {
		t.Errorf("expected alice, got %s", items[0].Username)
	}
}

func TestRiskService_List_SortedByScoreDescending(t *testing.T) {
	svc := newSvc()

	svc.AddSignal(context.Background(), "t-1", "u-low", "low_user",
		model.RiskSignal{Type: model.SignalNewDevice, Score: 15, DetectedAt: time.Now()})
	svc.AddSignal(context.Background(), "t-1", "u-high", "high_user",
		model.RiskSignal{Type: model.SignalActiveIncident, Score: 75, DetectedAt: time.Now()})

	items, _ := svc.List(context.Background(), "t-1", "", 1, 20)
	if len(items) < 2 {
		t.Fatalf("expected at least 2 items, got %d", len(items))
	}
	if items[0].RiskScore <= items[1].RiskScore {
		t.Errorf("expected descending order: first=%.1f second=%.1f", items[0].RiskScore, items[1].RiskScore)
	}
}

func TestRiskService_List_Pagination(t *testing.T) {
	svc := newSvc()

	for i := 0; i < 5; i++ {
		svc.AddSignal(context.Background(), "t-page", "u-"+string(rune('a'+i)), "user",
			model.RiskSignal{Type: model.SignalNewDevice, Score: float64(10 + i), DetectedAt: time.Now()})
	}

	items, meta := svc.List(context.Background(), "t-page", "", 1, 2)
	if len(items) != 2 {
		t.Errorf("expected 2 items on page 1, got %d", len(items))
	}
	if meta.Total != 5 {
		t.Errorf("expected total 5, got %d", meta.Total)
	}
	if meta.Pages != 3 {
		t.Errorf("expected 3 pages, got %d", meta.Pages)
	}
}

func TestRiskService_List_KeywordFiltersUsername(t *testing.T) {
	svc := newSvc()

	svc.AddSignal(context.Background(), "t-1", "u-alice", "alice",
		model.RiskSignal{Type: model.SignalNewDevice, Score: 20, DetectedAt: time.Now()})
	svc.AddSignal(context.Background(), "t-1", "u-bob", "bob",
		model.RiskSignal{Type: model.SignalTimeAnomaly, Score: 30, DetectedAt: time.Now()})

	items, _ := svc.List(context.Background(), "t-1", "ali", 1, 20)
	if len(items) != 1 {
		t.Fatalf("expected 1 result for keyword 'ali', got %d", len(items))
	}
	if items[0].Username != "alice" {
		t.Errorf("expected alice, got %s", items[0].Username)
	}
}

func TestRiskService_AddSignal_SetsUpdatedAt(t *testing.T) {
	svc := newSvc()
	before := time.Now().Add(-time.Second)

	svc.AddSignal(context.Background(), "t-1", "u-ts", "tsuser",
		model.RiskSignal{Type: model.SignalAuthFailureRate, Score: 10, DetectedAt: time.Now()})

	risk := svc.Get(context.Background(), "u-ts")
	if risk.UpdatedAt.Before(before) {
		t.Errorf("updated_at %v should be after %v", risk.UpdatedAt, before)
	}
}
