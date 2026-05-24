package repository

import (
	"context"
	"fmt"
	"time"
	"xsiam/internal/model"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/arangodb/go-driver/v2/arangodb/shared"
)

// ReportStats holds aggregated counts by status for a tenant's reports.
type ReportStats struct {
	Total      int64 `json:"total"`
	Scheduled  int64 `json:"scheduled"`
	Generating int64 `json:"generating"`
	Ready      int64 `json:"ready"`
	Failed     int64 `json:"failed"`
	// Processing and Completed are legacy aliases retained for compatibility.
	Processing int64 `json:"processing"`
	Completed  int64 `json:"completed"`
}

const colReports = "reports"

type ReportRepo struct {
	db arangodb.Database
}

func NewReportRepo(db arangodb.Database) *ReportRepo {
	return &ReportRepo{db: db}
}

func (r *ReportRepo) List(ctx context.Context, tenantID string, page, pageSize int) ([]model.Report, model.PageMeta, error) {
	var filters []string
	bindVars := map[string]any{}
	filters, bindVars = InjectTenantFilter(filters, bindVars, tenantID)

	var data []model.Report
	meta, err := FindPaged(ctx, r.db, ListOptions{
		Collection: colReports,
		Filters:    filters,
		BindVars:   bindVars,
		Page:       page,
		PageSize:   pageSize,
	}, &data)
	return data, meta, err
}

func (r *ReportRepo) GetByID(ctx context.Context, key string) (*model.Report, error) {
	col, _ := r.db.Collection(ctx, colReports)
	var report model.Report
	if _, err := col.ReadDocument(ctx, key, &report); err != nil {
		if shared.IsNotFound(err) {
			return nil, fmt.Errorf("report %s not found", key)
		}
		return nil, err
	}
	return &report, nil
}

func (r *ReportRepo) Create(ctx context.Context, report *model.Report) error {
	now := time.Now()
	report.CreatedAt = now
	report.UpdatedAt = now
	col, _ := r.db.Collection(ctx, colReports)
	meta, err := col.CreateDocument(ctx, report)
	if err != nil {
		return err
	}
	report.Key = meta.Key
	return nil
}

func (r *ReportRepo) Update(ctx context.Context, key string, patch map[string]any) error {
	patch[model.FieldUpdatedAt] = time.Now()
	col, _ := r.db.Collection(ctx, colReports)
	_, err := col.UpdateDocument(ctx, key, patch)
	return err
}

func (r *ReportRepo) Delete(ctx context.Context, key string) error {
	col, _ := r.db.Collection(ctx, colReports)
	_, err := col.DeleteDocument(ctx, key)
	return err
}

// CountByTenant returns the total number of reports for the given tenant.
func (r *ReportRepo) CountByTenant(ctx context.Context, tenantID string) (int64, error) {
	query := `FOR doc IN reports FILTER doc.tenant_id == @tid COLLECT WITH COUNT INTO n RETURN n`
	cursor, err := r.db.Query(ctx, query, &arangodb.QueryOptions{
		BindVars: map[string]any{"tid": tenantID},
	})
	if err != nil {
		return 0, err
	}
	defer cursor.Close()
	var n int64
	if cursor.HasMore() {
		if _, err = cursor.ReadDocument(ctx, &n); err != nil {
			return 0, err
		}
	}
	return n, nil
}

// Stats runs a single AQL query that groups all reports for the tenant by status
// and returns an aggregate ReportStats. Statuses not present in the data are
// left as zero.
func (r *ReportRepo) Stats(ctx context.Context, tenantID string) (*ReportStats, error) {
	aql := `
FOR doc IN reports
  FILTER doc.tenant_id == @tenantID
  COLLECT st = doc.status WITH COUNT INTO cnt
  RETURN {st, cnt}`

	cursor, err := r.db.Query(ctx, aql, &arangodb.QueryOptions{
		BindVars: map[string]any{"tenantID": tenantID},
	})
	if err != nil {
		return nil, fmt.Errorf("report stats query: %w", err)
	}
	defer cursor.Close()

	stats := &ReportStats{}
	for cursor.HasMore() {
		var row struct {
			St  string `json:"st"`
			Cnt int64  `json:"cnt"`
		}
		if _, err2 := cursor.ReadDocument(ctx, &row); err2 != nil {
			continue
		}
		stats.Total += row.Cnt
		switch model.ReportStatus(row.St) {
		case model.ReportStatusScheduled:
			stats.Scheduled += row.Cnt
		case model.ReportStatusGenerating:
			stats.Generating += row.Cnt
			stats.Processing += row.Cnt // legacy alias
		case model.ReportStatusPending:
			stats.Processing += row.Cnt // legacy alias
		case model.ReportStatusReady:
			stats.Ready += row.Cnt
			stats.Completed += row.Cnt // legacy alias
		case model.ReportStatusFailed:
			stats.Failed += row.Cnt
		}
	}
	return stats, nil
}
