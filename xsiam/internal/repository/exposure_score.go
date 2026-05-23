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
	TenantID    string
	Keyword     string
	FixStatus   string
	Reachability string
	InWild      string
	Page        int
	PageSize    int
	SortBy      string
	SortDesc    bool
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
		filters = append(filters, "doc.reachability == @reachability")
		bindVars["reachability"] = f.Reachability
	}
	if f.InWild == "true" {
		filters = append(filters, "doc.in_wild == true")
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
