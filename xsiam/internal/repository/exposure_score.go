package repository

import (
	"context"
	"time"
	"xsiam/internal/model"

	"github.com/arangodb/go-driver/v2/arangodb"
)

const colExposureScores = "exposure_scores"

type ExposureScoreRepo struct {
	db arangodb.Database
}

func NewExposureScoreRepo(db arangodb.Database) *ExposureScoreRepo {
	return &ExposureScoreRepo{db: db}
}

type ExposureListFilter struct {
	TenantID     string
	Keyword      string
	FixStatus    string
	Reachability string
	InWild       string
	MinScore     float64
	MaxScore     float64
	CVEID        string
	AssetID      string
	Page         int
	PageSize     int
	SortBy       string
	SortDesc     bool
}

func (r *ExposureScoreRepo) List(ctx context.Context, f ExposureListFilter) ([]model.ExposureScore, model.PageMeta, error) {
	var filters []string
	bindVars := map[string]any{}

	filters, bindVars = InjectTenantFilter(filters, bindVars, f.TenantID)

	if f.Keyword != "" {
		filters = append(filters, "CONTAINS(LOWER(doc.asset_name), LOWER(@kw))")
		bindVars["kw"] = f.Keyword
	}
	if f.FixStatus != "" {
		filters = append(filters, "doc.fix_status == @fixStatus")
		bindVars["fixStatus"] = f.FixStatus
	}
	if f.Reachability != "" {
		// Map string category to reachability_factor threshold range
		switch f.Reachability {
		case "internet":
			filters = append(filters, "doc.reachability_factor >= 0.8")
		case "dmz":
			filters = append(filters, "doc.reachability_factor >= 0.6 AND doc.reachability_factor < 0.8")
		case "internal":
			filters = append(filters, "doc.reachability_factor >= 0.3 AND doc.reachability_factor < 0.6")
		case "isolated":
			filters = append(filters, "doc.reachability_factor < 0.3")
		}
	}
	if f.InWild == "true" {
		// in_wild_factor > 0.5 means actively exploited in the wild
		filters = append(filters, "doc.in_wild_factor > 0.5")
	}
	if f.MinScore > 0 {
		filters = append(filters, "doc.priority_score >= @min_score")
		bindVars["min_score"] = f.MinScore
	}
	if f.MaxScore > 0 {
		filters = append(filters, "doc.priority_score <= @max_score")
		bindVars["max_score"] = f.MaxScore
	}
	if f.CVEID != "" {
		filters = append(filters, "doc.cve_id == @cve_id")
		bindVars["cve_id"] = f.CVEID
	}
	if f.AssetID != "" {
		filters = append(filters, "doc.asset_id == @asset_id")
		bindVars["asset_id"] = f.AssetID
	}

	sortBy := "priority_score"
	if f.SortBy != "" {
		sortBy = f.SortBy
	}

	var data []model.ExposureScore
	meta, err := FindPaged(ctx, r.db, ListOptions{
		Collection: colExposureScores,
		Filters:    filters,
		BindVars:   bindVars,
		SortBy:     sortBy,
		SortDesc:   f.SortDesc,
		Page:       f.Page,
		PageSize:   f.PageSize,
	}, &data)
	return data, meta, err
}

func (r *ExposureScoreRepo) Upsert(ctx context.Context, score *model.ExposureScore) error {
	query := `FOR doc IN exposure_scores FILTER doc.asset_id == @assetID AND doc.cve_id == @cveID LIMIT 1 RETURN doc`
	cursor, err := r.db.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]any{"assetID": score.AssetID, "cveID": score.CveID},
	})
	if err != nil {
		return err
	}
	defer cursor.Close()

	if cursor.HasMore() {
		var existing model.ExposureScore
		if _, err = cursor.ReadDocument(ctx, &existing); err != nil {
			return err
		}
		patch := map[string]any{
			"priority_score":          score.PriorityScore,
			"in_wild_factor":          score.InWildFactor,
			"reachability_factor":     score.ReachabilityFactor,
			"asset_importance_factor": score.AssetImportanceFactor,
			"last_scored_at":          time.Now(),
			"updated_at":              time.Now(),
		}
		col, _ := r.db.Collection(ctx, colExposureScores)
		_, err = col.UpdateDocument(ctx, existing.Key, patch)
		return err
	}

	now := time.Now()
	score.CreatedAt = now
	score.UpdatedAt = now
	col, _ := r.db.Collection(ctx, colExposureScores)
	meta, err := col.CreateDocument(ctx, score)
	if err != nil {
		return err
	}
	score.Key = meta.Key
	return nil
}

func (r *ExposureScoreRepo) Update(ctx context.Context, key string, patch map[string]any) error {
	patch[model.FieldUpdatedAt] = time.Now()
	col, _ := r.db.Collection(ctx, colExposureScores)
	_, err := col.UpdateDocument(ctx, key, patch)
	return err
}
