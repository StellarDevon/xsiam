package repository

import (
	"context"
	"fmt"
	"time"
	"xsiam/internal/model"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/arangodb/go-driver/v2/arangodb/shared"
)

const colAlerts = "alerts"

type AlertRepo struct {
	db      arangodb.Database
	listVer listVersionCounter
}

func NewAlertRepo(db arangodb.Database) *AlertRepo {
	return &AlertRepo{db: db}
}

func (r *AlertRepo) EnsureIndexes(ctx context.Context) {
	col, err := r.db.Collection(ctx, colAlerts)
	if err != nil {
		return
	}
	col.EnsurePersistentIndex(ctx, []string{model.FieldSeverity, model.FieldStatus}, &arangodb.CreatePersistentIndexOptions{})
	col.EnsurePersistentIndex(ctx, []string{model.FieldTriggeredAt}, &arangodb.CreatePersistentIndexOptions{})
	col.EnsurePersistentIndex(ctx, []string{model.FieldIncidentID}, &arangodb.CreatePersistentIndexOptions{})
	col.EnsurePersistentIndex(ctx, []string{model.FieldAssetID}, &arangodb.CreatePersistentIndexOptions{})
	uniqueTrue := true
	col.EnsurePersistentIndex(ctx, []string{model.FieldAlertID}, &arangodb.CreatePersistentIndexOptions{Unique: &uniqueTrue})
	col.EnsureTTLIndex(ctx, []string{model.FieldTriggeredAt}, 32*24*3600, &arangodb.CreateTTLIndexOptions{})
}

type AlertListFilter struct {
	TenantID   string
	Severity   string
	Status     string
	SourceType string
	IncidentID string
	AssetID    string
	Host       string // filter by host name (exact match, case-insensitive)
	Keyword    string
	Unlinked   bool  // only alerts with no incident_id
	Linked     bool  // only alerts that have an incident_id
	HoursAgo   int   // if > 0, only return alerts triggered within last N hours
	After      *time.Time
	Before     *time.Time
	Page       int
	PageSize   int
	SortBy     string
	SortDesc   bool
}

func (r *AlertRepo) List(ctx context.Context, f AlertListFilter) ([]model.Alert, model.PageMeta, error) {
	var filters []string
	bindVars := map[string]any{}

	filters, bindVars = InjectTenantFilter(filters, bindVars, f.TenantID)

	if f.Severity != "" {
		filters = append(filters, "doc.severity == @severity")
		bindVars["severity"] = f.Severity
	}
	if f.Status != "" {
		filters = append(filters, "doc.status == @status")
		bindVars["status"] = f.Status
	}
	if f.SourceType != "" {
		filters = append(filters, "doc.source_type == @sourceType")
		bindVars["sourceType"] = f.SourceType
	}
	if f.IncidentID != "" {
		filters = append(filters, "doc.incident_id == @incidentId")
		bindVars["incidentId"] = f.IncidentID
	}
	if f.AssetID != "" {
		filters = append(filters, "doc.asset_id == @assetId")
		bindVars["assetId"] = f.AssetID
	}
	if f.Host != "" {
		filters = append(filters, "LOWER(doc.host) == LOWER(@host)")
		bindVars["host"] = f.Host
	}
	if f.Keyword != "" {
		filters = append(filters, "(CONTAINS(LOWER(doc.name), LOWER(@kw)) OR CONTAINS(LOWER(doc.asset_name), LOWER(@kw)) OR CONTAINS(LOWER(doc.host), LOWER(@kw)) OR CONTAINS(LOWER(doc.user), LOWER(@kw)))")
		bindVars["kw"] = f.Keyword
	}
	if f.Unlinked {
		filters = append(filters, "(doc.incident_id == null OR doc.incident_id == '' OR !HAS(doc, 'incident_id'))")
	}
	if f.Linked {
		filters = append(filters, "(doc.incident_id != null AND doc.incident_id != '')")
	}
	if f.HoursAgo > 0 {
		filters = append(filters, "doc.triggered_at >= DATE_SUBTRACT(DATE_NOW(), @hoursAgo, 'hour')")
		bindVars["hoursAgo"] = f.HoursAgo
	}
	if f.After != nil {
		filters = append(filters, "doc.triggered_at >= @after")
		bindVars["after"] = f.After
	}
	if f.Before != nil {
		filters = append(filters, "doc.triggered_at <= @before")
		bindVars["before"] = f.Before
	}

	sortBy := model.FieldTriggeredAt
	if f.SortBy != "" {
		sortBy = f.SortBy
	}

	var data []model.Alert
	meta, err := FindPaged(ctx, r.db, ListOptions{
		Collection: colAlerts,
		Filters:    filters,
		BindVars:   bindVars,
		SortBy:     sortBy,
		SortDesc:   f.SortDesc,
		Page:       f.Page,
		PageSize:   f.PageSize,
	}, &data)
	return data, meta, err
}

func (r *AlertRepo) GetByID(ctx context.Context, key string) (*model.Alert, error) {
	col, _ := r.db.Collection(ctx, colAlerts)
	var alert model.Alert
	if _, err := col.ReadDocument(ctx, key, &alert); err != nil {
		if shared.IsNotFound(err) {
			return nil, fmt.Errorf("alert %s not found", key)
		}
		return nil, err
	}
	return &alert, nil
}

func (r *AlertRepo) FindByAlertID(ctx context.Context, alertID string) (*model.Alert, error) {
	query := `FOR doc IN alerts FILTER doc.alert_id == @alertID LIMIT 1 RETURN doc`
	cursor, err := r.db.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]any{"alertID": alertID},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()
	if !cursor.HasMore() {
		return nil, fmt.Errorf("alert %s not found", alertID)
	}
	var alert model.Alert
	_, err = cursor.ReadDocument(ctx, &alert)
	return &alert, err
}

func (r *AlertRepo) FindByRuleID(ctx context.Context, ruleID string) (*model.DetectionRule, error) {
	return nil, nil
}

func (r *AlertRepo) FindByAssetSince(ctx context.Context, assetID *string, since time.Time) ([]*model.Alert, error) {
	if assetID == nil {
		return nil, nil
	}
	query := `FOR doc IN alerts FILTER doc.asset_id == @assetID AND doc.triggered_at >= @since RETURN doc`
	cursor, err := r.db.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]any{"assetID": *assetID, "since": since},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()
	var results []*model.Alert
	for cursor.HasMore() {
		var a model.Alert
		if _, err = cursor.ReadDocument(ctx, &a); err != nil {
			return nil, err
		}
		results = append(results, &a)
	}
	return results, nil
}

func (r *AlertRepo) FindByIocValues(ctx context.Context, values []string, since time.Time) ([]*model.Alert, error) {
	if len(values) == 0 {
		return nil, nil
	}
	query := `FOR doc IN alerts FILTER doc.triggered_at >= @since AND LENGTH(doc.iocs[* FILTER CURRENT.value IN @values]) > 0 RETURN doc`
	cursor, err := r.db.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]any{"values": values, "since": since},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()
	var results []*model.Alert
	for cursor.HasMore() {
		var a model.Alert
		if _, err = cursor.ReadDocument(ctx, &a); err != nil {
			return nil, err
		}
		results = append(results, &a)
	}
	return results, nil
}

func (r *AlertRepo) FindByUser(ctx context.Context, username *string, since time.Time) ([]*model.Alert, error) {
	if username == nil {
		return nil, nil
	}
	query := `FOR doc IN alerts FILTER doc.user_name == @username AND doc.triggered_at >= @since RETURN doc`
	cursor, err := r.db.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]any{"username": *username, "since": since},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()
	var results []*model.Alert
	for cursor.HasMore() {
		var a model.Alert
		if _, err = cursor.ReadDocument(ctx, &a); err != nil {
			return nil, err
		}
		results = append(results, &a)
	}
	return results, nil
}

func (r *AlertRepo) FindByTimeRange(ctx context.Context, from, to time.Time) ([]model.Alert, error) {
	query := `FOR doc IN alerts FILTER doc.triggered_at >= @from AND doc.triggered_at <= @to RETURN doc`
	cursor, err := r.db.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]any{"from": from, "to": to},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()
	var results []model.Alert
	for cursor.HasMore() {
		var a model.Alert
		if _, err = cursor.ReadDocument(ctx, &a); err != nil {
			return nil, err
		}
		results = append(results, a)
	}
	return results, nil
}

// AggregateBySourceType runs an AQL GROUP-BY on the alerts collection and returns
// per-source counts for the given tenant.
func (r *AlertRepo) AggregateBySourceType(ctx context.Context, tenantID string) ([]struct {
	SourceType string `json:"source_type"`
	Count      int64  `json:"count"`
}, error) {
	query := `FOR a IN alerts
FILTER a.tenant_id == @tid
COLLECT src = a.source_type WITH COUNT INTO n
RETURN {source_type: src, count: n}`
	cursor, err := r.db.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]any{"tid": tenantID},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()
	type row struct {
		SourceType string `json:"source_type"`
		Count      int64  `json:"count"`
	}
	var results []row
	for cursor.HasMore() {
		var rec row
		if _, err = cursor.ReadDocument(ctx, &rec); err != nil {
			return nil, err
		}
		results = append(results, rec)
	}
	out := make([]struct {
		SourceType string `json:"source_type"`
		Count      int64  `json:"count"`
	}, len(results))
	for i, r := range results {
		out[i].SourceType = r.SourceType
		out[i].Count = r.Count
	}
	return out, nil
}

// AggregateTopAssets returns the top `limit` assets by alert count for the given tenant.
// Each row contains the asset_id, asset_name (from the alert's stored asset_name field), and alert_count.
func (r *AlertRepo) AggregateTopAssets(ctx context.Context, tenantID string, limit int) ([]struct {
	AssetID    string `json:"asset_id"`
	AssetName  string `json:"asset_name"`
	AlertCount int64  `json:"alert_count"`
}, error) {
	if limit <= 0 {
		limit = 10
	}
	query := `FOR a IN alerts
FILTER a.tenant_id == @tid
COLLECT asset_id = a.asset_id, asset_name = a.asset_name WITH COUNT INTO cnt
SORT cnt DESC
LIMIT @limit
RETURN {asset_id: asset_id, asset_name: asset_name, alert_count: cnt}`
	cursor, err := r.db.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]any{"tid": tenantID, "limit": limit},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()
	type row struct {
		AssetID    string `json:"asset_id"`
		AssetName  string `json:"asset_name"`
		AlertCount int64  `json:"alert_count"`
	}
	var results []row
	for cursor.HasMore() {
		var rec row
		if _, err = cursor.ReadDocument(ctx, &rec); err != nil {
			return nil, err
		}
		results = append(results, rec)
	}
	out := make([]struct {
		AssetID    string `json:"asset_id"`
		AssetName  string `json:"asset_name"`
		AlertCount int64  `json:"alert_count"`
	}, len(results))
	for i, r := range results {
		out[i].AssetID = r.AssetID
		out[i].AssetName = r.AssetName
		out[i].AlertCount = r.AlertCount
	}
	return out, nil
}

func (r *AlertRepo) Create(ctx context.Context, alert *model.Alert) error {
	now := time.Now()
	alert.CreatedAt = now
	alert.UpdatedAt = now
	col, _ := r.db.Collection(ctx, colAlerts)
	meta, err := col.CreateDocument(ctx, alert)
	if err != nil {
		return err
	}
	alert.Key = meta.Key
	r.listVer.bump()
	return nil
}

func (r *AlertRepo) Update(ctx context.Context, key string, patch map[string]any) error {
	patch[model.FieldUpdatedAt] = time.Now()
	col, _ := r.db.Collection(ctx, colAlerts)
	_, err := col.UpdateDocument(ctx, key, patch)
	if err == nil {
		r.listVer.bump()
	}
	return err
}

func (r *AlertRepo) Delete(ctx context.Context, key string) error {
	col, _ := r.db.Collection(ctx, colAlerts)
	_, err := col.DeleteDocument(ctx, key)
	if err == nil {
		r.listVer.bump()
	}
	return err
}
