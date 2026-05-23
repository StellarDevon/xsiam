package device

import (
	"context"
	"fmt"
	"time"
	"xsiam/internal/model"
	"xsiam/internal/repository"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/arangodb/go-driver/v2/arangodb/shared"
)

const colDataSources = "datasources"

// DataSourceRepo is the ArangoDB-backed datasource repository.
type DataSourceRepo struct {
	db arangodb.Database
}

func NewDataSourceRepo(db arangodb.Database) *DataSourceRepo {
	return &DataSourceRepo{db: db}
}

func (r *DataSourceRepo) List(ctx context.Context, tenantID string, page, pageSize int) ([]model.DataSource, model.PageMeta, error) {
	var filters []string
	bindVars := map[string]any{}
	filters, bindVars = repository.InjectTenantFilter(filters, bindVars, tenantID)

	var data []model.DataSource
	meta, err := repository.FindPaged(ctx, r.db, repository.ListOptions{
		Collection: colDataSources,
		Filters:    filters,
		BindVars:   bindVars,
		Page:       page,
		PageSize:   pageSize,
	}, &data)
	return data, meta, err
}

func (r *DataSourceRepo) GetByID(ctx context.Context, key string) (*model.DataSource, error) {
	col, _ := r.db.Collection(ctx, colDataSources)
	var ds model.DataSource
	if _, err := col.ReadDocument(ctx, key, &ds); err != nil {
		if shared.IsNotFound(err) {
			return nil, fmt.Errorf("datasource %s not found", key)
		}
		return nil, err
	}
	return &ds, nil
}

func (r *DataSourceRepo) Create(ctx context.Context, ds *model.DataSource) error {
	now := time.Now()
	ds.CreatedAt = now
	ds.UpdatedAt = now
	col, _ := r.db.Collection(ctx, colDataSources)
	meta, err := col.CreateDocument(ctx, ds)
	if err != nil {
		return err
	}
	ds.Key = meta.Key
	return nil
}

func (r *DataSourceRepo) Update(ctx context.Context, key string, patch map[string]any) error {
	patch[model.FieldUpdatedAt] = time.Now()
	col, _ := r.db.Collection(ctx, colDataSources)
	_, err := col.UpdateDocument(ctx, key, patch)
	return err
}

func (r *DataSourceRepo) Delete(ctx context.Context, key string) error {
	col, _ := r.db.Collection(ctx, colDataSources)
	_, err := col.DeleteDocument(ctx, key)
	return err
}
