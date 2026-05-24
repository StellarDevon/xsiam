package asset

import (
	"context"
	"fmt"
	"xsiam/internal/model"
	"xsiam/internal/repository"
)

// AuditLogger is the minimal interface for recording audit events.
type AuditLogger interface {
	Record(ctx context.Context, operatorID, action, resourceType, resourceID, resourceName string, oldVal, newVal any)
}

// AssetStats holds summary statistics for assets.
type AssetStats struct {
	Total         int64            `json:"total"`
	ByType        map[string]int64 `json:"by_type"`
	ByStatus      map[string]int64 `json:"by_status"`
	HighRiskCount int64            `json:"high_risk_count"`
}

// AssetStore is the minimal interface Service needs from the asset repository.
type AssetStore interface {
	Create(ctx context.Context, a *model.Asset) error
	GetByID(ctx context.Context, key string) (*model.Asset, error)
	Update(ctx context.Context, key string, patch map[string]any) error
	Delete(ctx context.Context, key string) error
	List(ctx context.Context, f repository.AssetListFilter) ([]model.Asset, model.PageMeta, error)
	Stats(ctx context.Context, tenantID string) (*AssetStats, error)
}

type Service struct {
	assetRepo AssetStore
	auditRepo AuditLogger
}

func NewService(assetRepo *Repo, auditRepo AuditLogger) *Service {
	return &Service{assetRepo: assetRepo, auditRepo: auditRepo}
}

// NewServiceWithRepo accepts any AssetStore implementation (used in tests).
func NewServiceWithRepo(assetRepo AssetStore, auditRepo AuditLogger) *Service {
	return &Service{assetRepo: assetRepo, auditRepo: auditRepo}
}

func (s *Service) List(ctx context.Context, f repository.AssetListFilter) ([]model.Asset, model.PageMeta, error) {
	return s.assetRepo.List(ctx, f)
}

func (s *Service) Get(ctx context.Context, key string) (*model.Asset, error) {
	a, err := s.assetRepo.GetByID(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("assetRepo.GetByID: %w", err)
	}
	return a, nil
}

func (s *Service) Create(ctx context.Context, a *model.Asset, operatorID string) error {
	if err := s.assetRepo.Create(ctx, a); err != nil {
		return fmt.Errorf("create asset: %w", err)
	}
	if s.auditRepo != nil {
		s.auditRepo.Record(ctx, operatorID, "create", "asset", a.Key, a.Name, nil, a)
	}
	return nil
}

func (s *Service) Update(ctx context.Context, key string, patch map[string]any, operatorID string) error {
	return s.assetRepo.Update(ctx, key, patch)
}

func (s *Service) Delete(ctx context.Context, key, operatorID string) error {
	return s.assetRepo.Delete(ctx, key)
}

// Stats returns aggregate statistics for assets belonging to the given tenant.
func (s *Service) Stats(ctx context.Context, tenantID string) (*AssetStats, error) {
	return s.assetRepo.Stats(ctx, tenantID)
}

// PushTag appends tag to an asset's tags slice (deduplicating).
func (s *Service) PushTag(ctx context.Context, tenantID, key, tag string) error {
	a, err := s.assetRepo.GetByID(ctx, key)
	if err != nil {
		return err
	}
	// deduplicate
	for _, t := range a.Tags {
		if t == tag {
			return nil
		}
	}
	return s.assetRepo.Update(ctx, key, map[string]any{"tags": append(a.Tags, tag)})
}
