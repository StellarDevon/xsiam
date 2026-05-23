package asset_test

import (
	"context"
	"testing"
	"xsiam/internal/domain/asset"
	"xsiam/internal/model"
	"xsiam/internal/repository"
)

// ── stub repo ────────────────────────────────────────────────────────────────

type stubAssetRepo struct {
	assets map[string]*model.Asset
}

func newStubAssetRepo() *stubAssetRepo {
	return &stubAssetRepo{assets: make(map[string]*model.Asset)}
}

func (r *stubAssetRepo) Create(ctx context.Context, a *model.Asset) error {
	a.Key = "asset-" + a.Name
	r.assets[a.Key] = a
	return nil
}
func (r *stubAssetRepo) GetByID(ctx context.Context, key string) (*model.Asset, error) {
	return r.assets[key], nil
}
func (r *stubAssetRepo) Update(ctx context.Context, key string, patch map[string]any) error {
	a := r.assets[key]
	if a == nil {
		return nil
	}
	if v, ok := patch["status"]; ok {
		a.Status = v.(string)
	}
	return nil
}
func (r *stubAssetRepo) Delete(ctx context.Context, key string) error {
	delete(r.assets, key)
	return nil
}
func (r *stubAssetRepo) List(ctx context.Context, f repository.AssetListFilter) ([]model.Asset, model.PageMeta, error) {
	var out []model.Asset
	for _, a := range r.assets {
		if f.TenantID != "" && a.TenantID != f.TenantID {
			continue
		}
		out = append(out, *a)
	}
	return out, model.PageMeta{Total: int64(len(out)), Page: 1, PageSize: 20, Pages: 1}, nil
}

// stub audit logger
type stubAudit struct{ calls int }

func (a *stubAudit) Record(_ context.Context, _, _, _, _, _ string, _, _ any) { a.calls++ }

// ── tests ────────────────────────────────────────────────────────────────────

func TestAssetCreate_SetsKey(t *testing.T) {
	repo := newStubAssetRepo()
	audit := &stubAudit{}
	svc := asset.NewServiceWithRepo(repo, audit)

	a := &model.Asset{Name: "web-server-01", TenantID: "t-1", Type: model.AssetTypeServer}
	if err := svc.Create(context.Background(), a, "op-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if a.Key == "" {
		t.Error("Key should be set after Create")
	}
}

func TestAssetCreate_RecordsAudit(t *testing.T) {
	repo := newStubAssetRepo()
	audit := &stubAudit{}
	svc := asset.NewServiceWithRepo(repo, audit)

	_ = svc.Create(context.Background(), &model.Asset{Name: "host", TenantID: "t-1"}, "op-1")
	if audit.calls != 1 {
		t.Errorf("expected 1 audit record, got %d", audit.calls)
	}
}

func TestAssetCreate_NilAudit_NoError(t *testing.T) {
	repo := newStubAssetRepo()
	svc := asset.NewServiceWithRepo(repo, nil)

	// Should not panic with nil auditRepo
	if err := svc.Create(context.Background(), &model.Asset{Name: "x", TenantID: "t-1"}, "op"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestAssetGet_ReturnsNilForMissing(t *testing.T) {
	repo := newStubAssetRepo()
	svc := asset.NewServiceWithRepo(repo, nil)

	got, err := svc.Get(context.Background(), "nonexistent")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestAssetDelete_RemovesAsset(t *testing.T) {
	repo := newStubAssetRepo()
	svc := asset.NewServiceWithRepo(repo, nil)

	a := &model.Asset{Name: "victim", TenantID: "t-1"}
	_ = svc.Create(context.Background(), a, "op")
	key := a.Key

	_ = svc.Delete(context.Background(), key, "op")

	got, _ := svc.Get(context.Background(), key)
	if got != nil {
		t.Errorf("expected asset to be deleted")
	}
}

func TestAssetList_FiltersByTenant(t *testing.T) {
	repo := newStubAssetRepo()
	svc := asset.NewServiceWithRepo(repo, nil)

	_ = svc.Create(context.Background(), &model.Asset{Name: "a1", TenantID: "t-1"}, "op")
	_ = svc.Create(context.Background(), &model.Asset{Name: "a2", TenantID: "t-2"}, "op")

	items, meta, err := svc.List(context.Background(), repository.AssetListFilter{TenantID: "t-1", Page: 1, PageSize: 20})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 1 {
		t.Errorf("expected 1 asset for t-1, got %d", len(items))
	}
	if meta.Total != 1 {
		t.Errorf("expected total 1, got %d", meta.Total)
	}
}
