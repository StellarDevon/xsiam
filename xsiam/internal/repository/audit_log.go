package repository

import (
	"context"
	"time"
	"xsiam/internal/model"

	"github.com/arangodb/go-driver/v2/arangodb"
)

const colAuditLogs = "audit_logs"

type AuditLogRepo struct {
	db arangodb.Database
}

func NewAuditLogRepo(db arangodb.Database) *AuditLogRepo {
	return &AuditLogRepo{db: db}
}

func (r *AuditLogRepo) Record(ctx context.Context, operatorID, action, resourceType, resourceID, resourceName string, oldValue, newValue any) {
	entry := model.AuditLog{
		OperatorID:   operatorID,
		Action:       action,
		ResourceType: resourceType,
		ResourceID:   resourceID,
		ResourceName: resourceName,
		OldValue:     oldValue,
		NewValue:     newValue,
		CreatedAt:    time.Now(),
	}
	col, err := r.db.Collection(ctx, colAuditLogs)
	if err != nil {
		return
	}
	_, _ = col.CreateDocument(ctx, entry)
}

type AuditLogListFilter struct {
	TenantID   string
	OperatorID string
	From       *time.Time
	To         *time.Time
	Page       int
	PageSize   int
}

func (r *AuditLogRepo) List(ctx context.Context, f AuditLogListFilter) ([]model.AuditLog, model.PageMeta, error) {
	var filters []string
	bindVars := map[string]any{}

	filters, bindVars = InjectTenantFilter(filters, bindVars, f.TenantID)

	if f.OperatorID != "" {
		filters = append(filters, "doc.operator_id == @operatorID")
		bindVars["operatorID"] = f.OperatorID
	}
	if f.From != nil {
		filters = append(filters, "doc.created_at >= @from")
		bindVars["from"] = f.From
	}
	if f.To != nil {
		filters = append(filters, "doc.created_at <= @to")
		bindVars["to"] = f.To
	}

	var data []model.AuditLog
	meta, err := FindPaged(ctx, r.db, ListOptions{
		Collection: colAuditLogs,
		Filters:    filters,
		BindVars:   bindVars,
		SortBy:     "created_at",
		SortDesc:   true,
		Page:       f.Page,
		PageSize:   f.PageSize,
	}, &data)
	return data, meta, err
}
