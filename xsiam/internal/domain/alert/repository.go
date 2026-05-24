package alert

import (
	"context"
	"fmt"
	"time"
	"xsiam/internal/model"
	"xsiam/internal/repository"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/arangodb/go-driver/v2/arangodb/shared"
)

const colAlerts = "alerts"

// Repo is the ArangoDB-backed alert repository.
type Repo struct {
	db arangodb.Database
}

func NewRepo(db arangodb.Database) *Repo {
	return &Repo{db: db}
}

func (r *Repo) EnsureIndexes(ctx context.Context) {
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

func (r *Repo) List(ctx context.Context, f repository.AlertListFilter) ([]model.Alert, model.PageMeta, error) {
	var filters []string
	bindVars := map[string]any{}

	filters, bindVars = repository.InjectTenantFilter(filters, bindVars, f.TenantID)

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
		filters = append(filters, "(CONTAINS(LOWER(doc.name), LOWER(@kw)) OR CONTAINS(LOWER(doc.asset_name), LOWER(@kw)))")
		bindVars["kw"] = f.Keyword
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
	meta, err := repository.FindPaged(ctx, r.db, repository.ListOptions{
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

func (r *Repo) GetByID(ctx context.Context, key string) (*model.Alert, error) {
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

func (r *Repo) FindByAlertID(ctx context.Context, alertID string) (*model.Alert, error) {
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

func (r *Repo) FindByAssetSince(ctx context.Context, assetID *string, since time.Time) ([]*model.Alert, error) {
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

func (r *Repo) FindByIocValues(ctx context.Context, values []string, since time.Time) ([]*model.Alert, error) {
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

func (r *Repo) FindByUser(ctx context.Context, username *string, since time.Time) ([]*model.Alert, error) {
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

func (r *Repo) FindByTimeRange(ctx context.Context, from, to time.Time) ([]model.Alert, error) {
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

func (r *Repo) Create(ctx context.Context, a *model.Alert) error {
	now := time.Now()
	a.CreatedAt = now
	a.UpdatedAt = now
	col, _ := r.db.Collection(ctx, colAlerts)
	meta, err := col.CreateDocument(ctx, a)
	if err != nil {
		return err
	}
	a.Key = meta.Key
	return nil
}

func (r *Repo) Update(ctx context.Context, key string, patch map[string]any) error {
	patch[model.FieldUpdatedAt] = time.Now()
	col, _ := r.db.Collection(ctx, colAlerts)
	_, err := col.UpdateDocument(ctx, key, patch)
	return err
}

func (r *Repo) Delete(ctx context.Context, key string) error {
	col, _ := r.db.Collection(ctx, colAlerts)
	_, err := col.DeleteDocument(ctx, key)
	return err
}

// GetStats returns aggregated alert statistics for a tenant.
func (r *Repo) GetStats(ctx context.Context, tenantID string) (*AlertStats, error) {
	stats := &AlertStats{
		BySeverity: make(map[string]int64),
		ByStatus:   make(map[string]int64),
	}

	// 1. Total count
	totalAQL := `RETURN COUNT(FOR doc IN alerts FILTER doc.tenant_id == @tenantID RETURN 1)`
	cur, err := r.db.Query(ctx, totalAQL, &arangodb.QueryOptions{BindVars: map[string]any{"tenantID": tenantID}})
	if err != nil {
		return nil, fmt.Errorf("alert stats total: %w", err)
	}
	if cur.HasMore() {
		cur.ReadDocument(ctx, &stats.Total)
	}
	cur.Close()

	// 2. GROUP BY severity
	sevAQL := `FOR doc IN alerts FILTER doc.tenant_id == @tenantID COLLECT sev = doc.severity WITH COUNT INTO cnt RETURN {sev, cnt}`
	cur, err = r.db.Query(ctx, sevAQL, &arangodb.QueryOptions{BindVars: map[string]any{"tenantID": tenantID}})
	if err != nil {
		return nil, fmt.Errorf("alert stats severity: %w", err)
	}
	for cur.HasMore() {
		var row struct {
			Sev string `json:"sev"`
			Cnt int64  `json:"cnt"`
		}
		if _, err2 := cur.ReadDocument(ctx, &row); err2 == nil && row.Sev != "" {
			stats.BySeverity[row.Sev] = row.Cnt
		}
	}
	cur.Close()

	// 3. GROUP BY status
	statusAQL := `FOR doc IN alerts FILTER doc.tenant_id == @tenantID COLLECT st = doc.status WITH COUNT INTO cnt RETURN {st, cnt}`
	cur, err = r.db.Query(ctx, statusAQL, &arangodb.QueryOptions{BindVars: map[string]any{"tenantID": tenantID}})
	if err != nil {
		return nil, fmt.Errorf("alert stats status: %w", err)
	}
	for cur.HasMore() {
		var row struct {
			St  string `json:"st"`
			Cnt int64  `json:"cnt"`
		}
		if _, err2 := cur.ReadDocument(ctx, &row); err2 == nil && row.St != "" {
			stats.ByStatus[row.St] = row.Cnt
		}
	}
	cur.Close()

	// 4. New in last 24h
	newAQL := `RETURN COUNT(FOR doc IN alerts FILTER doc.tenant_id == @tenantID AND DATE_DIFF(doc.created_at, DATE_NOW(), "hours") < 24 RETURN 1)`
	cur, err = r.db.Query(ctx, newAQL, &arangodb.QueryOptions{BindVars: map[string]any{"tenantID": tenantID}})
	if err != nil {
		return nil, fmt.Errorf("alert stats new_last_24h: %w", err)
	}
	if cur.HasMore() {
		cur.ReadDocument(ctx, &stats.NewLast24h)
	}
	cur.Close()

	// 5. Resolved in last 24h
	resolvedAQL := `RETURN COUNT(FOR doc IN alerts FILTER doc.tenant_id == @tenantID AND doc.resolved_at != null AND DATE_DIFF(doc.resolved_at, DATE_NOW(), "hours") < 24 RETURN 1)`
	cur, err = r.db.Query(ctx, resolvedAQL, &arangodb.QueryOptions{BindVars: map[string]any{"tenantID": tenantID}})
	if err != nil {
		return nil, fmt.Errorf("alert stats resolved_last_24h: %w", err)
	}
	if cur.HasMore() {
		cur.ReadDocument(ctx, &stats.ResolvedLast24h)
	}
	cur.Close()

	// 6. MTTR: avg hours from created_at to resolved_at for resolved alerts
	mttrAQL := `RETURN AVG(FOR doc IN alerts FILTER doc.tenant_id == @tenantID AND doc.resolved_at != null RETURN DATE_DIFF(doc.created_at, doc.resolved_at, "hours"))`
	cur, err = r.db.Query(ctx, mttrAQL, &arangodb.QueryOptions{BindVars: map[string]any{"tenantID": tenantID}})
	if err != nil {
		return nil, fmt.Errorf("alert stats mttr: %w", err)
	}
	if cur.HasMore() {
		var mttr *float64
		if _, err2 := cur.ReadDocument(ctx, &mttr); err2 == nil && mttr != nil {
			stats.MTTRHours = *mttr
		}
	}
	cur.Close()

	// 7. False positive rate
	fpAQL := `
		LET total = COUNT(FOR doc IN alerts FILTER doc.tenant_id == @tenantID AND doc.status IN ["resolved","false_positive","auto_closed"] RETURN 1)
		LET fp    = COUNT(FOR doc IN alerts FILTER doc.tenant_id == @tenantID AND doc.status == "false_positive" RETURN 1)
		RETURN total > 0 ? fp / total : 0`
	cur, err = r.db.Query(ctx, fpAQL, &arangodb.QueryOptions{BindVars: map[string]any{"tenantID": tenantID}})
	if err != nil {
		return nil, fmt.Errorf("alert stats false_positive_rate: %w", err)
	}
	if cur.HasMore() {
		cur.ReadDocument(ctx, &stats.FalsePositiveRate)
	}
	cur.Close()

	// 8. Top 5 hosts by alert count
	topHostsAQL := `FOR doc IN alerts FILTER doc.tenant_id == @tenantID AND doc.host != null AND doc.host != "" COLLECT host = doc.host WITH COUNT INTO cnt SORT cnt DESC LIMIT 5 RETURN {host, cnt}`
	cur, err = r.db.Query(ctx, topHostsAQL, &arangodb.QueryOptions{BindVars: map[string]any{"tenantID": tenantID}})
	if err != nil {
		return nil, fmt.Errorf("alert stats top_hosts: %w", err)
	}
	for cur.HasMore() {
		var row struct {
			Host string `json:"host"`
			Cnt  int64  `json:"cnt"`
		}
		if _, err2 := cur.ReadDocument(ctx, &row); err2 == nil {
			stats.TopHosts = append(stats.TopHosts, HostCount{Host: row.Host, Count: row.Cnt})
		}
	}
	cur.Close()

	return stats, nil
}
