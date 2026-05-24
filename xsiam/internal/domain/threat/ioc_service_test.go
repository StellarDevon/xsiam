package threat_test

import (
	"context"
	"testing"
	"xsiam/internal/domain/threat"
	"xsiam/internal/model"
	"xsiam/internal/repository"
)

// ── stub repo ─────────────────────────────────────────────────────────────────

type stubIocRepo struct {
	iocs map[string]*model.IOC
	seq  int
}

func newStubIocRepo() *stubIocRepo {
	return &stubIocRepo{iocs: make(map[string]*model.IOC)}
}

func (r *stubIocRepo) Create(_ context.Context, ioc *model.IOC) error {
	r.seq++
	ioc.Key = "ioc-" + ioc.Value
	r.iocs[ioc.Key] = ioc
	return nil
}

func (r *stubIocRepo) GetByID(_ context.Context, key string) (*model.IOC, error) {
	return r.iocs[key], nil
}

func (r *stubIocRepo) Search(_ context.Context, tenantID, value string, _ int) ([]model.IOC, error) {
	var out []model.IOC
	for _, ioc := range r.iocs {
		if ioc.TenantID == tenantID && len(ioc.Value) > 0 {
			out = append(out, *ioc)
		}
	}
	return out, nil
}

func (r *stubIocRepo) Update(_ context.Context, key string, patch map[string]any) error {
	ioc := r.iocs[key]
	if ioc == nil {
		return nil
	}
	if v, ok := patch["verdict"]; ok {
		ioc.Verdict = model.IOCVerdict(v.(string))
	}
	return nil
}

func (r *stubIocRepo) Delete(_ context.Context, key string) error {
	delete(r.iocs, key)
	return nil
}

func (r *stubIocRepo) List(_ context.Context, f repository.IocListFilter) ([]model.IOC, model.PageMeta, error) {
	var out []model.IOC
	for _, ioc := range r.iocs {
		if f.TenantID != "" && ioc.TenantID != f.TenantID {
			continue
		}
		if f.Verdict != "" && string(ioc.Verdict) != f.Verdict {
			continue
		}
		out = append(out, *ioc)
	}
	return out, model.PageMeta{Total: int64(len(out)), Page: 1, PageSize: 20, Pages: 1}, nil
}

func (r *stubIocRepo) FindByValues(_ context.Context, tenantID string, values []string) ([]model.IOC, error) {
	set := make(map[string]bool, len(values))
	for _, v := range values {
		set[v] = true
	}
	var out []model.IOC
	for _, ioc := range r.iocs {
		if ioc.TenantID != tenantID {
			continue
		}
		if set[ioc.Value] {
			out = append(out, *ioc)
		}
	}
	return out, nil
}

// ── tests ────────────────────────────────────────────────────────────────────

func TestIocService_Create_SetsKey(t *testing.T) {
	repo := newStubIocRepo()
	svc := threat.NewIocServiceWithStore(repo, nil)

	ioc := &model.IOC{TenantID: "t-1", Type: model.IOCTypeIP, Value: "1.2.3.4", Verdict: model.IOCVerdictMalicious}
	if err := svc.Create(context.Background(), ioc, "op-1"); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if ioc.Key == "" {
		t.Error("Key should be set after Create")
	}
}

func TestIocService_Get_ReturnsNilForMissing(t *testing.T) {
	repo := newStubIocRepo()
	svc := threat.NewIocServiceWithStore(repo, nil)

	got, err := svc.Get(context.Background(), "no-such-key")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != nil {
		t.Errorf("expected nil, got %+v", got)
	}
}

func TestIocService_Delete_RemovesEntry(t *testing.T) {
	repo := newStubIocRepo()
	svc := threat.NewIocServiceWithStore(repo, nil)

	ioc := &model.IOC{TenantID: "t-1", Type: model.IOCTypeDomain, Value: "evil.com", Verdict: model.IOCVerdictMalicious}
	_ = svc.Create(context.Background(), ioc, "op")
	key := ioc.Key

	_ = svc.Delete(context.Background(), key)

	got, _ := svc.Get(context.Background(), key)
	if got != nil {
		t.Error("expected IOC to be deleted")
	}
}

func TestIocService_List_FiltersByTenant(t *testing.T) {
	repo := newStubIocRepo()
	svc := threat.NewIocServiceWithStore(repo, nil)

	_ = svc.Create(context.Background(), &model.IOC{TenantID: "t-1", Value: "1.1.1.1", Verdict: model.IOCVerdictMalicious}, "op")
	_ = svc.Create(context.Background(), &model.IOC{TenantID: "t-2", Value: "2.2.2.2", Verdict: model.IOCVerdictSuspicious}, "op")

	items, meta, err := svc.List(context.Background(), repository.IocListFilter{TenantID: "t-1", Page: 1, PageSize: 20})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(items) != 1 {
		t.Errorf("expected 1 IOC for t-1, got %d", len(items))
	}
	if meta.Total != 1 {
		t.Errorf("expected total 1, got %d", meta.Total)
	}
}

func TestIocService_BulkImport_CreatesAll(t *testing.T) {
	repo := newStubIocRepo()
	svc := threat.NewIocServiceWithStore(repo, nil)

	iocs := []model.IOC{
		{TenantID: "t-1", Value: "a.com", Verdict: model.IOCVerdictMalicious},
		{TenantID: "t-1", Value: "b.com", Verdict: model.IOCVerdictSuspicious},
		{TenantID: "t-1", Value: "c.com", Verdict: model.IOCVerdictBenign},
	}
	if err := svc.BulkImport(context.Background(), iocs, "op"); err != nil {
		t.Fatalf("BulkImport error: %v", err)
	}

	items, _, _ := svc.List(context.Background(), repository.IocListFilter{TenantID: "t-1", Page: 1, PageSize: 20})
	if len(items) != 3 {
		t.Errorf("expected 3 IOCs after bulk import, got %d", len(items))
	}
}

func TestIocService_Update_ChangesVerdict(t *testing.T) {
	repo := newStubIocRepo()
	svc := threat.NewIocServiceWithStore(repo, nil)

	ioc := &model.IOC{TenantID: "t-1", Value: "suspicious.io", Verdict: model.IOCVerdictUnknown}
	_ = svc.Create(context.Background(), ioc, "op")

	_ = svc.Update(context.Background(), ioc.Key, map[string]any{"verdict": string(model.IOCVerdictMalicious)})

	got, _ := svc.Get(context.Background(), ioc.Key)
	if got.Verdict != model.IOCVerdictMalicious {
		t.Errorf("expected verdict malicious, got %s", got.Verdict)
	}
}
