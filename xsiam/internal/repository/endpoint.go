package repository

import (
	"context"
	"time"
	"xsiam/internal/model"

	"github.com/arangodb/go-driver/v2/arangodb"
)

const (
	colIsolatedEndpoints = "isolated_endpoints"
	colEndpointSummaries = "endpoint_summaries"
)

// EndpointRepo provides storage for endpoint isolation records and aggregated summaries.
type EndpointRepo struct {
	db arangodb.Database
}

func NewEndpointRepo(db arangodb.Database) *EndpointRepo {
	return &EndpointRepo{db: db}
}

// ─── Isolation ────────────────────────────────────────────────────────────────

func (r *EndpointRepo) ListIsolated(ctx context.Context, tenantID string, page, pageSize int, status string) ([]model.IsolatedEndpoint, model.PageMeta, error) {
	filters, bv := InjectTenantFilter(nil, map[string]any{}, tenantID)
	if status != "" {
		filters = append(filters, "doc.status == @status")
		bv["status"] = status
	}
	var data []model.IsolatedEndpoint
	meta, err := FindPaged(ctx, r.db, ListOptions{
		Collection: colIsolatedEndpoints,
		Filters:    filters,
		BindVars:   bv,
		SortBy:     "isolated_at",
		SortDesc:   true,
		Page:       page,
		PageSize:   pageSize,
	}, &data)
	return data, meta, err
}

func (r *EndpointRepo) CreateIsolation(ctx context.Context, iso *model.IsolatedEndpoint) error {
	now := time.Now()
	iso.CreatedAt = now
	iso.UpdatedAt = now
	iso.IsolatedAt = now
	col, _ := r.db.Collection(ctx, colIsolatedEndpoints)
	meta, err := col.CreateDocument(ctx, iso)
	if err != nil {
		return err
	}
	iso.Key = meta.Key
	return nil
}

func (r *EndpointRepo) ReleaseIsolation(ctx context.Context, key, operatorID string) error {
	now := time.Now()
	col, _ := r.db.Collection(ctx, colIsolatedEndpoints)
	_, err := col.UpdateDocument(ctx, key, map[string]any{
		"status":      string(model.IsolationReleased),
		"released_at": now,
		"released_by": operatorID,
		"updated_at":  now,
	})
	return err
}

func (r *EndpointRepo) CountIsolated(ctx context.Context, tenantID, status string) (int64, error) {
	q := `FOR doc IN isolated_endpoints FILTER doc.tenant_id == @tid AND doc.status == @status COLLECT WITH COUNT INTO n RETURN n`
	cursor, err := r.db.Query(ctx, q, &arangodb.QueryOptions{
		BindVars: map[string]any{"tid": tenantID, "status": status},
	})
	if err != nil {
		return 0, err
	}
	defer cursor.Close()
	var n int64
	if cursor.HasMore() {
		_, _ = cursor.ReadDocument(ctx, &n)
	}
	return n, nil
}

// CountIsolationsInWindow counts isolation events created within the past N hours.
func (r *EndpointRepo) CountIsolationsInWindow(ctx context.Context, tenantID string, hours int) (int64, error) {
	since := time.Now().Add(-time.Duration(hours) * time.Hour)
	q := `FOR doc IN isolated_endpoints FILTER doc.tenant_id == @tid AND doc.isolated_at >= @since COLLECT WITH COUNT INTO n RETURN n`
	cursor, err := r.db.Query(ctx, q, &arangodb.QueryOptions{
		BindVars: map[string]any{"tid": tenantID, "since": since},
	})
	if err != nil {
		return 0, err
	}
	defer cursor.Close()
	var n int64
	if cursor.HasMore() {
		_, _ = cursor.ReadDocument(ctx, &n)
	}
	return n, nil
}

// ─── Endpoint Stats ───────────────────────────────────────────────────────────

// GetStats aggregates endpoint health data from the devices collection.
// Health is approximated from agent_status; detailed health scoring would
// require a dedicated endpoint_summaries collection populated by the cron job.
func (r *EndpointRepo) GetStats(ctx context.Context, tenantID string) (*model.EndpointStats, error) {
	q := `
		LET total   = LENGTH(FOR d IN devices FILTER d.tenant_id == @tid RETURN 1)
		LET online  = LENGTH(FOR d IN devices FILTER d.tenant_id == @tid AND d.agent_status == "online" RETURN 1)
		LET offline = LENGTH(FOR d IN devices FILTER d.tenant_id == @tid AND d.agent_status == "offline" RETURN 1)
		LET isolatedList = (
			FOR iso IN isolated_endpoints
			FILTER iso.tenant_id == @tid AND iso.status == "active"
			COLLECT WITH COUNT INTO n
			RETURN n
		)
		LET isolated = LENGTH(isolatedList) > 0 ? isolatedList[0] : 0
		RETURN { total, online, offline, isolated }
	`
	cursor, err := r.db.Query(ctx, q, &arangodb.QueryOptions{
		BindVars: map[string]any{"tid": tenantID},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	var raw struct {
		Total    int64 `json:"total"`
		Online   int64 `json:"online"`
		Offline  int64 `json:"offline"`
		Isolated int64 `json:"isolated"`
	}
	if cursor.HasMore() {
		if _, err = cursor.ReadDocument(ctx, &raw); err != nil {
			return nil, err
		}
	}

	return &model.EndpointStats{
		TenantID:   tenantID,
		Total:      raw.Total,
		Online:     raw.Online,
		Isolated:   raw.Isolated,
		ComputedAt: time.Now(),
	}, nil
}
