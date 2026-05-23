package incident

import (
	"context"
	"fmt"
	"time"
	"xsiam/internal/model"
	"xsiam/internal/repository"
	"xsiam/pkg/utils"
)

// IncidentStore is the minimal interface Service needs from IncidentRepo.
type IncidentStore interface {
	Create(ctx context.Context, inc *model.Incident) error
	GetByID(ctx context.Context, key string) (*model.Incident, error)
	Update(ctx context.Context, key string, patch map[string]any) error
	Delete(ctx context.Context, key string) error
	List(ctx context.Context, f repository.IncidentListFilter) ([]model.Incident, model.PageMeta, error)
	ListAlertKeys(ctx context.Context, incidentKey string) ([]string, error)
	Merge(ctx context.Context, primaryKey string, secondaryKeys []string) error
}

// AlertStore is the minimal interface Service needs from AlertRepo.
type AlertStore interface {
	List(ctx context.Context, f repository.AlertListFilter) ([]model.Alert, model.PageMeta, error)
	Update(ctx context.Context, key string, patch map[string]any) error
}

// AuditLogger is the minimal interface for recording audit events.
type AuditLogger interface {
	Record(ctx context.Context, operatorID, action, resourceType, resourceID, resourceName string, oldVal, newVal any)
}

type Service struct {
	incRepo   IncidentStore
	alertRepo AlertStore
	auditRepo AuditLogger
}

func NewService(
	incRepo   *Repo,
	alertRepo AlertStore,
	auditRepo AuditLogger,
) *Service {
	return &Service{incRepo: incRepo, alertRepo: alertRepo, auditRepo: auditRepo}
}

func NewServiceWithRepos(
	incRepo   IncidentStore,
	alertRepo AlertStore,
	auditLog  AuditLogger,
) *Service {
	return &Service{incRepo: incRepo, alertRepo: alertRepo, auditRepo: auditLog}
}

func (s *Service) List(ctx context.Context, f repository.IncidentListFilter) ([]model.Incident, model.PageMeta, error) {
	return s.incRepo.List(ctx, f)
}

func (s *Service) Get(ctx context.Context, key string) (*model.Incident, error) {
	inc, err := s.incRepo.GetByID(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("incRepo.GetByID: %w", err)
	}
	return inc, nil
}

type CreateIncidentReq struct {
	Name        string         `json:"name"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Severity    model.Severity `json:"severity" binding:"required"`
	TenantID    string         `json:"tenant_id"`
}

func (r *CreateIncidentReq) effectiveName() string {
	if r.Title != "" {
		return r.Title
	}
	return r.Name
}

func (s *Service) Create(ctx context.Context, req CreateIncidentReq, operatorID string) (*model.Incident, error) {
	now := time.Now()
	name := req.effectiveName()
	inc := &model.Incident{
		IncidentID:   utils.NewIncidentID(),
		TenantID:     req.TenantID,
		Name:         name,
		Title:        name,
		Description:  req.Description,
		Severity:     req.Severity,
		Status:       model.IncidentStatusNew,
		FirstSeen:    now,
		LastActivity: now,
	}
	if err := s.incRepo.Create(ctx, inc); err != nil {
		return nil, fmt.Errorf("create incident: %w", err)
	}
	if s.auditRepo != nil {
		s.auditRepo.Record(ctx, operatorID, "create", "incident", inc.Key, inc.Name, nil, inc)
	}
	return inc, nil
}

func (s *Service) Update(ctx context.Context, key string, patch map[string]any, operatorID string) error {
	return s.incRepo.Update(ctx, key, patch)
}

func (s *Service) Delete(ctx context.Context, key, operatorID string) error {
	return s.incRepo.Delete(ctx, key)
}

func (s *Service) ListAlerts(ctx context.Context, incidentKey string) ([]model.Alert, error) {
	if s.alertRepo == nil {
		return nil, nil
	}
	data, _, err := s.alertRepo.List(ctx, repository.AlertListFilter{
		IncidentID: incidentKey,
		PageSize:   100,
	})
	return data, err
}

func (s *Service) AddNote(ctx context.Context, incidentKey string, content, authorID, authorName string) error {
	inc, err := s.incRepo.GetByID(ctx, incidentKey)
	if err != nil {
		return err
	}
	note := model.IncidentNote{
		NoteID:     utils.NewNodeID(),
		Content:    content,
		AuthorID:   authorID,
		AuthorName: authorName,
		CreatedAt:  time.Now(),
	}
	notes := append(inc.Notes, note)
	return s.incRepo.Update(ctx, incidentKey, map[string]any{"notes": notes})
}

func (s *Service) Merge(ctx context.Context, primaryKey string, secondaryKeys []string, operatorID string) error {
	primary, err := s.incRepo.GetByID(ctx, primaryKey)
	if err != nil {
		return err
	}
	for _, sk := range secondaryKeys {
		sec, err := s.incRepo.GetByID(ctx, sk)
		if err != nil {
			continue
		}
		if s.alertRepo != nil {
			for _, aid := range sec.AlertIDs {
				_ = s.alertRepo.Update(ctx, aid, map[string]any{"incident_id": primaryKey})
			}
		}
		primary.AlertIDs = append(primary.AlertIDs, sec.AlertIDs...)
		primary.AffectedAssets = append(primary.AffectedAssets, sec.AffectedAssets...)
		_ = s.incRepo.Delete(ctx, sk)
	}
	return s.incRepo.Update(ctx, primaryKey, map[string]any{
		"alert_ids":       primary.AlertIDs,
		"alert_count":     len(primary.AlertIDs),
		"affected_assets": primary.AffectedAssets,
	})
}

func (s *Service) Bulk(ctx context.Context, keys []string, action string, patch map[string]any, operatorID string) error {
	for _, key := range keys {
		if err := s.incRepo.Update(ctx, key, patch); err != nil {
			return fmt.Errorf("bulk update incident %s: %w", key, err)
		}
	}
	return nil
}
