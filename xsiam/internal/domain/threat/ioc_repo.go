package threat

import (
	"context"
	"fmt"
	"time"
	"xsiam/internal/model"
	"xsiam/internal/repository"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/arangodb/go-driver/v2/arangodb/shared"
)

const colIOCs = "iocs"

// IocRepo is the ArangoDB-backed IOC repository.
type IocRepo struct {
	db arangodb.Database
}

func NewIocRepo(db arangodb.Database) *IocRepo {
	return &IocRepo{db: db}
}

func (r *IocRepo) List(ctx context.Context, f repository.IocListFilter) ([]model.IOC, model.PageMeta, error) {
	var filters []string
	bindVars := map[string]any{}

	filters, bindVars = repository.InjectTenantFilter(filters, bindVars, f.TenantID)

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
	meta, err := repository.FindPaged(ctx, r.db, repository.ListOptions{
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

func (r *IocRepo) Search(ctx context.Context, tenantID, value string) ([]model.IOC, error) {
	query := `FOR doc IN iocs FILTER doc.tenant_id == @tenantID AND CONTAINS(doc.value, @value) RETURN doc`
	cursor, err := r.db.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]any{"tenantID": tenantID, "value": value},
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
	return nil
}

func (r *IocRepo) Update(ctx context.Context, key string, patch map[string]any) error {
	patch[model.FieldUpdatedAt] = time.Now()
	col, _ := r.db.Collection(ctx, colIOCs)
	_, err := col.UpdateDocument(ctx, key, patch)
	return err
}

func (r *IocRepo) Delete(ctx context.Context, key string) error {
	col, _ := r.db.Collection(ctx, colIOCs)
	_, err := col.DeleteDocument(ctx, key)
	return err
}
