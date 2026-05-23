package repository

import (
	"context"
	"fmt"
	"time"
	"xsiam/internal/model"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/arangodb/go-driver/v2/arangodb/shared"
)

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
