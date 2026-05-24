package asset

import (
	"context"
	"xsiam/internal/model"
	"xsiam/internal/repository"
)

type VulnService struct {
	vulnRepo  *VulnRepo
	auditRepo AuditLogger
}

func NewVulnService(vulnRepo *VulnRepo, auditRepo AuditLogger) *VulnService {
	return &VulnService{vulnRepo: vulnRepo, auditRepo: auditRepo}
}

func (s *VulnService) List(ctx context.Context, f repository.VulnerabilityListFilter) ([]model.Vulnerability, model.PageMeta, error) {
	return s.vulnRepo.List(ctx, f)
}

func (s *VulnService) Get(ctx context.Context, key string) (*model.Vulnerability, error) {
	return s.vulnRepo.GetByID(ctx, key)
}

func (s *VulnService) Stats(ctx context.Context, tenantID string) (map[string]any, error) {
	return s.vulnRepo.Stats(ctx, tenantID)
}

func (s *VulnService) Create(ctx context.Context, v *model.Vulnerability, operatorID string) error {
	return s.vulnRepo.Create(ctx, v)
}

func (s *VulnService) Update(ctx context.Context, key string, patch map[string]any, operatorID string) error {
	// Normalise: frontend may send "status" (alias field); sync to "fix_status"
	// so AQL filters on fix_status remain accurate.
	if status, ok := patch["status"].(string); ok && status != "" {
		if _, hasFix := patch["fix_status"]; !hasFix {
			patch["fix_status"] = status
		}
	}
	return s.vulnRepo.Update(ctx, key, patch)
}

func (s *VulnService) Delete(ctx context.Context, key string, operatorID string) error {
	return s.vulnRepo.Delete(ctx, key)
}

func (s *VulnService) Bulk(ctx context.Context, keys []string, patch map[string]any) error {
	for _, key := range keys {
		if err := s.vulnRepo.Update(ctx, key, patch); err != nil {
			return err
		}
	}
	return nil
}
