package repository

import (
	"context"
	"fmt"
	"time"
	"xsiam/internal/model"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/arangodb/go-driver/v2/arangodb/shared"
)

const colIOCs = "iocs"

type IocRepo struct {
	db      arangodb.Database
	listVer listVersionCounter
}

func NewIocRepo(db arangodb.Database) *IocRepo {
	return &IocRepo{db: db}
}

type IocListFilter struct {
	TenantID string
	Type     string
	Verdict  string
	Keyword  string
	Page     int
	PageSize int
	SortBy   string
	SortDesc bool
}

func (r *IocRepo) List(ctx context.Context, f IocListFilter) ([]model.IOC, model.PageMeta, error) {
	var filters []string
	bindVars := map[string]any{}

	filters, bindVars = InjectTenantFilter(filters, bindVars, f.TenantID)

	if f.Type != "" {
		filters = append(filters, "doc.type == @type")
		bindVars["type"] = f.Type
	}
	if f.Verdict != "" {
		filters = append(filters, "doc.verdict == @verdict")
		bindVars["verdict"] = f.Verdict
	}
	if f.Keyword != "" {
		filters = append(filters, "CONTAINS(LOWER(doc.value), LOWER(@kw))")
		bindVars["kw"] = f.Keyword
	}

	var data []model.IOC
	meta, err := FindPaged(ctx, r.db, ListOptions{
		Collection: colIOCs,
		Filters:    filters,
		BindVars:   bindVars,
		SortBy:     f.SortBy,
		SortDesc:   f.SortDesc,
		Page:       f.Page,
		PageSize:   f.PageSize,
	}, &data)
	return data, meta, err
}

func (r *IocRepo) GetByID(ctx context.Context, key string) (*model.IOC, error) {
	col, _ := r.db.Collection(ctx, colIOCs)
	var ioc model.IOC
	if _, err := col.ReadDocument(ctx, key, &ioc); err != nil {
		if shared.IsNotFound(err) {
			return nil, fmt.Errorf("ioc %s not found", key)
		}
		return nil, err
	}
	return &ioc, nil
}

func (r *IocRepo) Search(ctx context.Context, tenantID, q string, limit int) ([]model.IOC, error) {
	if limit <= 0 {
		limit = 20
	}
	query := `FOR doc IN iocs
  FILTER doc.tenant_id == @tenant_id
  FILTER LOWER(doc.value) LIKE LOWER(CONCAT('%', @q, '%'))
     OR LOWER(doc.threat_name) LIKE LOWER(CONCAT('%', @q, '%'))
  LIMIT @limit
  RETURN doc`
	cursor, err := r.db.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]any{"tenant_id": tenantID, "q": q, "limit": limit},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()
	var results []model.IOC
	for cursor.HasMore() {
		var ioc model.IOC
		if _, err = cursor.ReadDocument(ctx, &ioc); err != nil {
			return nil, err
		}
		results = append(results, ioc)
	}
	return results, nil
}

// CountByTenant returns the total number of IOCs for the given tenant.
func (r *IocRepo) CountByTenant(ctx context.Context, tenantID string) (int64, error) {
	query := `FOR doc IN iocs FILTER doc.tenant_id == @tid COLLECT WITH COUNT INTO n RETURN n`
	cursor, err := r.db.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]any{"tid": tenantID},
	})
	if err != nil {
		return 0, err
	}
	defer cursor.Close()
	var n int64
	if cursor.HasMore() {
		if _, err = cursor.ReadDocument(ctx, &n); err != nil {
			return 0, err
		}
	}
	return n, nil
}

// FindByValues returns IOCs whose value field matches any of the supplied values
// (case-insensitive). Scoped to the given tenant.
func (r *IocRepo) FindByValues(ctx context.Context, tenantID string, values []string) ([]model.IOC, error) {
	if len(values) == 0 {
		return nil, nil
	}
	// Normalise to lower-case for comparison.
	lower := make([]string, len(values))
	for i, v := range values {
		lower[i] = v
	}
	query := `FOR doc IN iocs
  FILTER doc.tenant_id == @tenantID
  FILTER LOWER(doc.value) IN @values
  RETURN doc`
	cursor, err := r.db.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]any{"tenantID": tenantID, "values": lower},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()
	var results []model.IOC
	for cursor.HasMore() {
		var ioc model.IOC
		if _, err = cursor.ReadDocument(ctx, &ioc); err != nil {
			return nil, err
		}
		results = append(results, ioc)
	}
	return results, nil
}

func (r *IocRepo) Create(ctx context.Context, ioc *model.IOC) error {
	now := time.Now()
	ioc.CreatedAt = now
	ioc.UpdatedAt = now
	col, _ := r.db.Collection(ctx, colIOCs)
	meta, err := col.CreateDocument(ctx, ioc)
	if err != nil {
		return err
	}
	ioc.Key = meta.Key
	r.listVer.bump()
	return nil
}

func (r *IocRepo) Update(ctx context.Context, key string, patch map[string]any) error {
	patch[model.FieldUpdatedAt] = time.Now()
	col, _ := r.db.Collection(ctx, colIOCs)
	_, err := col.UpdateDocument(ctx, key, patch)
	if err == nil {
		r.listVer.bump()
	}
	return err
}

func (r *IocRepo) Delete(ctx context.Context, key string) error {
	col, _ := r.db.Collection(ctx, colIOCs)
	_, err := col.DeleteDocument(ctx, key)
	if err == nil {
		r.listVer.bump()
	}
	return err
}
