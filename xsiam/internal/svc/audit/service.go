package audit

import (
	"context"
	"xsiam/internal/model"
	"xsiam/internal/repository"
)

// Service provides audit log recording and listing.
type Service struct {
	repo *repository.AuditLogRepo
}

func New(repo *repository.AuditLogRepo) *Service {
	return &Service{repo: repo}
}

// Record writes an audit log entry. operatorID, action, resourceType, etc. come from the caller.
func (s *Service) Record(ctx context.Context, tenantID, operatorID, action, resourceType, resourceID, resourceName string, oldVal, newVal any) {
	s.repo.Record(ctx, operatorID, action, resourceType, resourceID, resourceName, oldVal, newVal)
}

// List returns paginated audit logs.
func (s *Service) List(ctx context.Context, f repository.AuditLogListFilter) ([]model.AuditLog, model.PageMeta, error) {
	return s.repo.List(ctx, f)
}
