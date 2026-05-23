package asset

import (
	"context"
	"fmt"
	"time"
	"xsiam/internal/model"
	"xsiam/internal/repository"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/arangodb/go-driver/v2/arangodb/shared"
)

const colAssets = "assets"

// Repo is the ArangoDB-backed asset repository.
type Repo struct {
	db arangodb.Database
}

func NewRepo(db arangodb.Database) *Repo {
	return &Repo{db: db}
}

func (r *Repo) List(ctx context.Context, f repository.AssetListFilter) ([]model.Asset, model.PageMeta, error) {
	var filters []string
	bindVars := map[string]any{}

	filters, bindVars = repository.InjectTenantFilter(filters, bindVars, f.TenantID)

	if f.Type != "" {
		filters = append(filters, "doc.type == @type")
		bindVars["type"] = f.Type
	}
	if f.RiskLevel != "" {
		filters = append(filters, "doc.risk_level == @riskLevel")
		bindVars["riskLevel"] = f.RiskLevel
	}
	if f.Keyword != "" {
		filters = append(filters, "CONTAINS(LOWER(doc.name), LOWER(@kw))")
		bindVars["kw"] = f.Keyword
	}

	var data []model.Asset
	meta, err := repository.FindPaged(ctx, r.db, repository.ListOptions{
		Collection: colAssets,
		Filters:    filters,
		BindVars:   bindVars,
		SortBy:     f.SortBy,
		SortDesc:   f.SortDesc,
		Page:       f.Page,
		PageSize:   f.PageSize,
	}, &data)
	return data, meta, err
}

func (r *Repo) GetByID(ctx context.Context, key string) (*model.Asset, error) {
	col, _ := r.db.Collection(ctx, colAssets)
	var a model.Asset
	if _, err := col.ReadDocument(ctx, key, &a); err != nil {
		if shared.IsNotFound(err) {
			return nil, fmt.Errorf("asset %s not found", key)
		}
		return nil, err
	}
	return &a, nil
}

func (r *Repo) Create(ctx context.Context, a *model.Asset) error {
	now := time.Now()
	a.CreatedAt = now
	a.UpdatedAt = now
	col, _ := r.db.Collection(ctx, colAssets)
	meta, err := col.CreateDocument(ctx, a)
	if err != nil {
		return err
	}
	a.Key = meta.Key
	return nil
}

func (r *Repo) Update(ctx context.Context, key string, patch map[string]any) error {
	patch[model.FieldUpdatedAt] = time.Now()
	col, _ := r.db.Collection(ctx, colAssets)
	_, err := col.UpdateDocument(ctx, key, patch)
	return err
}

func (r *Repo) Delete(ctx context.Context, key string) error {
	col, _ := r.db.Collection(ctx, colAssets)
	_, err := col.DeleteDocument(ctx, key)
	return err
}
