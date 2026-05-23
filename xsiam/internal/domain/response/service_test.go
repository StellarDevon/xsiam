package response_test

import (
	"context"
	"testing"
	"xsiam/internal/domain/response"
	"xsiam/internal/model"
	"xsiam/internal/repository"
)

// ── stub action repo ──────────────────────────────────────────────────────────

type stubActionRepo struct {
	actions map[string]*model.Action
	seq     int
}

func newStubActionRepo() *stubActionRepo {
	return &stubActionRepo{actions: make(map[string]*model.Action)}
}

func (r *stubActionRepo) Create(_ context.Context, a *model.Action) error {
	r.seq++
	a.Key = "action-" + string(rune('a'+r.seq))
	r.actions[a.Key] = a
	return nil
}

func (r *stubActionRepo) GetByID(_ context.Context, key string) (*model.Action, error) {
	return r.actions[key], nil
}

func (r *stubActionRepo) Update(_ context.Context, key string, patch map[string]any) error {
	a := r.actions[key]
	if a == nil {
		return nil
	}
	if v, ok := patch["status"]; ok {
		a.Status = model.ActionStatus(v.(string))
	}
	return nil
}

func (r *stubActionRepo) List(_ context.Context, f repository.ActionListFilter) ([]model.Action, model.PageMeta, error) {
	var out []model.Action
	for _, a := range r.actions {
		if f.TenantID != "" && a.TenantID != f.TenantID {
			continue
		}
		out = append(out, *a)
	}
	return out, model.PageMeta{Total: int64(len(out)), Page: 1, PageSize: 20, Pages: 1}, nil
}

// ── stub executor ─────────────────────────────────────────────────────────────

type stubExecutor struct{ called int }

func (e *stubExecutor) Execute(_ context.Context, _, _ string, _ map[string]any) (*response.ExecutionResult, error) {
	e.called++
	return &response.ExecutionResult{Success: true, ExecutionID: "exec-1", Message: "ok"}, nil
}

// ── stub playbook repo ────────────────────────────────────────────────────────

type stubPlaybookRepo struct {
	pbs map[string]*model.Playbook
	seq int
}

func newStubPlaybookRepo() *stubPlaybookRepo {
	return &stubPlaybookRepo{pbs: make(map[string]*model.Playbook)}
}

func (r *stubPlaybookRepo) Create(_ context.Context, pb *model.Playbook) error {
	r.seq++
	pb.Key = "pb-" + pb.Name
	r.pbs[pb.Key] = pb
	return nil
}

func (r *stubPlaybookRepo) GetByID(_ context.Context, key string) (*model.Playbook, error) {
	return r.pbs[key], nil
}

func (r *stubPlaybookRepo) Update(_ context.Context, key string, patch map[string]any) error {
	pb := r.pbs[key]
	if pb == nil {
		return nil
	}
	if v, ok := patch["run_count"]; ok {
		pb.RunCount = int64(v.(int64))
	}
	return nil
}

func (r *stubPlaybookRepo) Delete(_ context.Context, key string) error {
	delete(r.pbs, key)
	return nil
}

func (r *stubPlaybookRepo) List(_ context.Context, f response.PlaybookListFilter) ([]model.Playbook, model.PageMeta, error) {
	var out []model.Playbook
	for _, pb := range r.pbs {
		if f.TenantID != "" && pb.TenantID != f.TenantID {
			continue
		}
		out = append(out, *pb)
	}
	return out, model.PageMeta{Total: int64(len(out)), Page: 1, PageSize: 20, Pages: 1}, nil
}

// ── action service tests ──────────────────────────────────────────────────────

func TestActionService_Create_SetsKey(t *testing.T) {
	repo := newStubActionRepo()
	svc := response.NewActionServiceWith(repo, nil, nil)

	a := &model.Action{TenantID: "t-1", Type: model.ActionTypeIsolateHost, TargetAssetID: "host-1"}
	if err := svc.Create(context.Background(), a, "op-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.Key == "" {
		t.Error("Key should be set after Create")
	}
}

func TestActionService_List_FiltersByTenant(t *testing.T) {
	repo := newStubActionRepo()
	svc := response.NewActionServiceWith(repo, nil, nil)

	_ = svc.Create(context.Background(), &model.Action{TenantID: "t-1", Type: model.ActionTypeBlockIP}, "op")
	_ = svc.Create(context.Background(), &model.Action{TenantID: "t-2", Type: model.ActionTypeKillProcess}, "op")

	items, _, err := svc.List(context.Background(), repository.ActionListFilter{TenantID: "t-1", Page: 1, PageSize: 20})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 1 {
		t.Errorf("expected 1 action for t-1, got %d", len(items))
	}
}

func TestActionService_Execute_CallsExecutor(t *testing.T) {
	repo := newStubActionRepo()
	exec := &stubExecutor{}
	svc := response.NewActionServiceWith(repo, exec, nil)

	a := &model.Action{TenantID: "t-1", Type: model.ActionTypeIsolateHost, TargetAssetID: "host-1"}
	_ = svc.Create(context.Background(), a, "op")

	if err := svc.Execute(context.Background(), a.Key, "op"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exec.called != 1 {
		t.Errorf("expected executor called once, got %d", exec.called)
	}
}

// ── playbook service tests ────────────────────────────────────────────────────

func TestPlaybookService_Create_SetsKey(t *testing.T) {
	repo := newStubPlaybookRepo()
	svc := response.NewPlaybookServiceWith(repo, nil, nil)

	pb := &model.Playbook{TenantID: "t-1", Name: "isolate-and-alert"}
	if err := svc.Create(context.Background(), pb, "op"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if pb.Key == "" {
		t.Error("Key should be set after Create")
	}
}

func TestPlaybookService_Delete_RemovesEntry(t *testing.T) {
	repo := newStubPlaybookRepo()
	svc := response.NewPlaybookServiceWith(repo, nil, nil)

	pb := &model.Playbook{TenantID: "t-1", Name: "to-delete"}
	_ = svc.Create(context.Background(), pb, "op")

	_ = svc.Delete(context.Background(), pb.Key)

	got, _ := svc.Get(context.Background(), pb.Key)
	if got != nil {
		t.Error("expected playbook to be deleted")
	}
}

func TestPlaybookService_Execute_CallsExecutor(t *testing.T) {
	repo := newStubPlaybookRepo()
	exec := &stubExecutor{}
	svc := response.NewPlaybookServiceWith(repo, exec, nil)

	pb := &model.Playbook{TenantID: "t-1", Name: "run-me"}
	_ = svc.Create(context.Background(), pb, "op")

	if err := svc.Execute(context.Background(), pb.Key, "op"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if exec.called != 1 {
		t.Errorf("expected executor called once, got %d", exec.called)
	}
}
