package alert

import (
	"context"
	"time"
	"xsiam/internal/model"
	"xsiam/internal/repository"
)

// AlertStore is the minimal interface AlertService needs from AlertRepo.
type AlertStore interface {
	Create(ctx context.Context, a *model.Alert) error
	GetByID(ctx context.Context, key string) (*model.Alert, error)
	Update(ctx context.Context, key string, patch map[string]any) error
	Delete(ctx context.Context, key string) error
	List(ctx context.Context, f repository.AlertListFilter) ([]model.Alert, model.PageMeta, error)
	FindByAlertID(ctx context.Context, id string) (*model.Alert, error)
	FindByTimeRange(ctx context.Context, from, to time.Time) ([]model.Alert, error)
	FindByAssetSince(ctx context.Context, assetID *string, since time.Time) ([]*model.Alert, error)
	FindByIocValues(ctx context.Context, values []string, since time.Time) ([]*model.Alert, error)
	FindByUser(ctx context.Context, username *string, since time.Time) ([]*model.Alert, error)
}

// IncidentStore is the minimal interface AlertService needs from IncidentRepo.
type IncidentStore interface {
	Create(ctx context.Context, inc *model.Incident) error
	GetByID(ctx context.Context, key string) (*model.Incident, error)
	Update(ctx context.Context, key string, patch map[string]any) error
	Delete(ctx context.Context, key string) error
	List(ctx context.Context, f repository.IncidentListFilter) ([]model.Incident, model.PageMeta, error)
	ListAlertKeys(ctx context.Context, incidentKey string) ([]string, error)
	Merge(ctx context.Context, primaryKey string, secondaryKeys []string) error
}

// AuditLogger is the minimal interface for recording audit events.
type AuditLogger interface {
	Record(ctx context.Context, operatorID, action, resourceType, resourceID, resourceName string, oldVal, newVal any)
}
