package threat

import (
	"context"
	"xsiam/internal/model"
	"xsiam/internal/repository"
)

// AuditLogger is the minimal interface for recording audit events.
type AuditLogger interface {
	Record(ctx context.Context, operatorID, action, resourceType, resourceID, resourceName string, oldVal, newVal any)
}

// IocStore is the minimal interface IocService needs from the IOC repository.
type IocStore interface {
	List(ctx context.Context, f repository.IocListFilter) ([]model.IOC, model.PageMeta, error)
	GetByID(ctx context.Context, key string) (*model.IOC, error)
	Search(ctx context.Context, tenantID, q string, limit int) ([]model.IOC, error)
	FindByValues(ctx context.Context, tenantID string, values []string) ([]model.IOC, error)
	Create(ctx context.Context, ioc *model.IOC) error
	Update(ctx context.Context, key string, patch map[string]any) error
	Delete(ctx context.Context, key string) error
}

type IocService struct {
	iocRepo   IocStore
	auditRepo AuditLogger
}

func NewIocService(iocRepo *IocRepo, auditRepo AuditLogger) *IocService {
	return &IocService{iocRepo: iocRepo, auditRepo: auditRepo}
}

// NewIocServiceWithStore accepts any IocStore implementation (used in tests).
func NewIocServiceWithStore(iocRepo IocStore, auditRepo AuditLogger) *IocService {
	return &IocService{iocRepo: iocRepo, auditRepo: auditRepo}
}

func (s *IocService) List(ctx context.Context, f repository.IocListFilter) ([]model.IOC, model.PageMeta, error) {
	return s.iocRepo.List(ctx, f)
}

func (s *IocService) Get(ctx context.Context, key string) (*model.IOC, error) {
	return s.iocRepo.GetByID(ctx, key)
}

func (s *IocService) Search(ctx context.Context, tenantID, q string, limit int) ([]model.IOC, error) {
	return s.iocRepo.Search(ctx, tenantID, q, limit)
}

func (s *IocService) Create(ctx context.Context, ioc *model.IOC, operatorID string) error {
	return s.iocRepo.Create(ctx, ioc)
}

func (s *IocService) BulkImport(ctx context.Context, iocs []model.IOC, operatorID string) error {
	for i := range iocs {
		if err := s.iocRepo.Create(ctx, &iocs[i]); err != nil {
			return err
		}
	}
	return nil
}

func (s *IocService) Update(ctx context.Context, key string, patch map[string]any) error {
	return s.iocRepo.Update(ctx, key, patch)
}

func (s *IocService) Delete(ctx context.Context, key string) error {
	return s.iocRepo.Delete(ctx, key)
}

// Hunt searches for IOC records matching the supplied values (IPs, hashes, domains, etc.)
// within the given tenant. Empty or blank values are silently filtered out.
func (s *IocService) Hunt(ctx context.Context, tenantID string, values []string) ([]model.IOC, error) {
	// Filter out empty strings.
	clean := make([]string, 0, len(values))
	for _, v := range values {
		if v != "" {
			clean = append(clean, v)
		}
	}
	if len(clean) == 0 {
		return nil, nil
	}
	return s.iocRepo.FindByValues(ctx, tenantID, clean)
}
