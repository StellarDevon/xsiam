package repository

import (
	"context"
	"fmt"
	"time"
	"xsiam/internal/model"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/arangodb/go-driver/v2/arangodb/shared"
)

const colAssets = "assets"

type AssetRepo struct {
	db      arangodb.Database
	listVer listVersionCounter
}

func NewAssetRepo(db arangodb.Database) *AssetRepo {
	return &AssetRepo{db: db}
}

type AssetListFilter struct {
	TenantID  string
	Type      string
	Status    string
	RiskLevel string
	Tag       string
	Keyword   string
	Page      int
	PageSize  int
	SortBy    string
	SortDesc  bool
	SortOrder string // "asc" or "desc"; takes precedence over SortDesc when set
}

func (r *AssetRepo) List(ctx context.Context, f AssetListFilter) ([]model.Asset, model.PageMeta, error) {
	var filters []string
	bindVars := map[string]any{}

	filters, bindVars = InjectTenantFilter(filters, bindVars, f.TenantID)

	if f.Type != "" {
		filters = append(filters, "doc.type == @type")
		bindVars["type"] = f.Type
	}
	if f.Status != "" {
		filters = append(filters, "doc.status == @status")
		bindVars["status"] = f.Status
	}
	if f.RiskLevel != "" {
		filters = append(filters, "doc.risk_level == @riskLevel")
		bindVars["riskLevel"] = f.RiskLevel
	}
	if f.Tag != "" {
		filters = append(filters, "@tag IN doc.tags")
		bindVars["tag"] = f.Tag
	}
	if f.Keyword != "" {
		filters = append(filters, "CONTAINS(LOWER(doc.name), LOWER(@kw))")
		bindVars["kw"] = f.Keyword
	}

	sortBy := f.SortBy
	sortDesc := f.SortDesc
	if f.SortOrder != "" {
		sortDesc = f.SortOrder == "desc"
	}
	if sortBy == "" && f.SortOrder != "" {
		sortBy = "created_at"
	}

	var data []model.Asset
	meta, err := FindPaged(ctx, r.db, ListOptions{
		Collection: colAssets,
		Filters:    filters,
		BindVars:   bindVars,
		SortBy:     sortBy,
		SortDesc:   sortDesc,
		Page:       f.Page,
		PageSize:   f.PageSize,
	}, &data)
	return data, meta, err
}

func (r *AssetRepo) GetByID(ctx context.Context, key string) (*model.Asset, error) {
	col, _ := r.db.Collection(ctx, colAssets)
	var asset model.Asset
	if _, err := col.ReadDocument(ctx, key, &asset); err != nil {
		if shared.IsNotFound(err) {
			return nil, fmt.Errorf("asset %s not found", key)
		}
		return nil, err
	}
	return &asset, nil
}

func (r *AssetRepo) Create(ctx context.Context, asset *model.Asset) error {
	now := time.Now()
	asset.CreatedAt = now
	asset.UpdatedAt = now
	col, _ := r.db.Collection(ctx, colAssets)
	meta, err := col.CreateDocument(ctx, asset)
	if err != nil {
		return err
	}
	asset.Key = meta.Key
	r.listVer.bump()
	return nil
}

func (r *AssetRepo) Update(ctx context.Context, key string, patch map[string]any) error {
	patch[model.FieldUpdatedAt] = time.Now()
	col, _ := r.db.Collection(ctx, colAssets)
	_, err := col.UpdateDocument(ctx, key, patch)
	if err == nil {
		r.listVer.bump()
	}
	return err
}

func (r *AssetRepo) Delete(ctx context.Context, key string) error {
	col, _ := r.db.Collection(ctx, colAssets)
	_, err := col.DeleteDocument(ctx, key)
	if err == nil {
		r.listVer.bump()
	}
	return err
}

// FindByHostnameOrIP looks up an asset by its name (case-insensitive) or by
// one of its ip_addresses entries.  Returns nil, nil when not found.
// Used by the ETL lookup_asset action to enrich inbound log events.
func (r *AssetRepo) FindByHostnameOrIP(ctx context.Context, tenantID, target string) (*model.Asset, error) {
	aql := `FOR doc IN assets
	          FILTER doc.tenant_id == @tid
	          FILTER LOWER(doc.name) == LOWER(@target) OR @target IN doc.ip_addresses
	          LIMIT 1
	          RETURN doc`
	cursor, err := r.db.Query(ctx, aql, &arangodb.QueryOptions{
		BindVars: map[string]any{"tid": tenantID, "target": target},
	})
	if err != nil {
		return nil, fmt.Errorf("asset find by hostname/ip: %w", err)
	}
	defer cursor.Close()
	if !cursor.HasMore() {
		return nil, nil
	}
	var asset model.Asset
	if _, err = cursor.ReadDocument(ctx, &asset); err != nil {
		return nil, err
	}
	return &asset, nil
}
