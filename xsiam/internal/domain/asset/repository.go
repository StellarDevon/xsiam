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
	meta, err := repository.FindPaged(ctx, r.db, repository.ListOptions{
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

// Stats returns asset counts grouped by type and status, plus a high-risk count.
func (r *Repo) Stats(ctx context.Context, tenantID string) (*AssetStats, error) {
	// Group by type
	typeQuery := `
		FOR doc IN assets
		FILTER doc.tenant_id == @tenantID
		COLLECT t = doc.type WITH COUNT INTO cnt
		RETURN {type: t, count: cnt}
	`
	cursor, err := r.db.Query(ctx, typeQuery, &arangodb.QueryOptions{
		BindVars: map[string]any{"tenantID": tenantID},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	stats := &AssetStats{
		ByType:   make(map[string]int64),
		ByStatus: make(map[string]int64),
	}
	for cursor.HasMore() {
		var row struct {
			Type  string `json:"type"`
			Count int64  `json:"count"`
		}
		if _, err = cursor.ReadDocument(ctx, &row); err != nil {
			return nil, err
		}
		if row.Type != "" {
			stats.ByType[row.Type] = row.Count
		}
		stats.Total += row.Count
	}

	// Group by status
	statusQuery := `
		FOR doc IN assets
		FILTER doc.tenant_id == @tenantID
		COLLECT s = doc.status WITH COUNT INTO cnt
		RETURN {status: s, count: cnt}
	`
	cursor2, err := r.db.Query(ctx, statusQuery, &arangodb.QueryOptions{
		BindVars: map[string]any{"tenantID": tenantID},
	})
	if err != nil {
		return nil, err
	}
	defer cursor2.Close()

	for cursor2.HasMore() {
		var row struct {
			Status string `json:"status"`
			Count  int64  `json:"count"`
		}
		if _, err = cursor2.ReadDocument(ctx, &row); err != nil {
			return nil, err
		}
		if row.Status != "" {
			stats.ByStatus[row.Status] = row.Count
		}
	}

	// High-risk count (risk_level == "high" or "critical")
	riskQuery := `
		FOR doc IN assets
		FILTER doc.tenant_id == @tenantID AND doc.risk_level IN ["high", "critical"]
		COLLECT WITH COUNT INTO cnt
		RETURN cnt
	`
	cursor3, err := r.db.Query(ctx, riskQuery, &arangodb.QueryOptions{
		BindVars: map[string]any{"tenantID": tenantID},
	})
	if err != nil {
		return nil, err
	}
	defer cursor3.Close()

	if cursor3.HasMore() {
		if _, err = cursor3.ReadDocument(ctx, &stats.HighRiskCount); err != nil {
			return nil, err
		}
	}

	return stats, nil
}
