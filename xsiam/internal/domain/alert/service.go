package alert

import (
	"context"
	"fmt"
	"time"
	"xsiam/internal/model"
	"xsiam/internal/repository"
	"xsiam/pkg/utils"
)

// AlertStats holds aggregated statistics for alerts.
type AlertStats struct {
	Total             int64            `json:"total"`
	BySeverity        map[string]int64 `json:"by_severity"`
	ByStatus          map[string]int64 `json:"by_status"`
	NewLast24h        int64            `json:"new_last_24h"`
	ResolvedLast24h   int64            `json:"resolved_last_24h"`
	MTTRHours         float64          `json:"mttr_hours"`
	FalsePositiveRate float64          `json:"false_positive_rate"`
	TopHosts          []HostCount      `json:"top_hosts"`
}

// HostCount associates a host name with an alert count.
type HostCount struct {
	Host  string `json:"host"`
	Count int64  `json:"count"`
}

// CorrelationSubmitter is the interface for submitting alerts to the correlation pool.
type CorrelationSubmitter interface {
	Submit(alertID string)
}

type Service struct {
	alertRepo       AlertStore
	incRepo         IncidentStore
	auditRepo       AuditLogger
	correlationPool CorrelationSubmitter
}

func NewService(
	alertRepo *Repo,
	incRepo   IncidentStore,
	auditRepo AuditLogger,
	pool      CorrelationSubmitter,
) *Service {
	return &Service{
		alertRepo:       alertRepo,
		incRepo:         incRepo,
		auditRepo:       auditRepo,
		correlationPool: pool,
	}
}

func NewServiceWithRepos(
	alertRepo AlertStore,
	incRepo   IncidentStore,
	auditLog  AuditLogger,
	pool      CorrelationSubmitter,
) *Service {
	return &Service{
		alertRepo:       alertRepo,
		incRepo:         incRepo,
		auditRepo:       auditLog,
		correlationPool: pool,
	}
}

func (s *Service) List(ctx context.Context, f repository.AlertListFilter) ([]model.Alert, model.PageMeta, error) {
	return s.alertRepo.List(ctx, f)
}

func (s *Service) Get(ctx context.Context, key string) (*model.Alert, error) {
	a, err := s.alertRepo.GetByID(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("alertRepo.GetByID: %w", err)
	}
	return a, nil
}

type CreateAlertReq struct {
	Name            string           `json:"name" binding:"required"`
	Description     string           `json:"description"`
	Severity        model.Severity   `json:"severity" binding:"required"`
	SourceType      model.SourceType `json:"source_type" binding:"required"`
	AssetName       string           `json:"asset_name"`
	AssetID         *string          `json:"asset_id"`
	TenantID        string           `json:"tenant_id"`
	TriggerSource   string           `json:"trigger_source"`
	ResultCount     uint64           `json:"result_count"`
	MitreTactics    []string         `json:"mitre_tactics"`
	MitreTechniques []string         `json:"mitre_techniques"`
	RuleID          string           `json:"rule_id"`
	RuleName        string           `json:"rule_name"`
}

func (s *Service) Create(ctx context.Context, req CreateAlertReq, operatorID string) (*model.Alert, error) {
	mitreTactic := ""
	if len(req.MitreTactics) > 0 {
		mitreTactic = req.MitreTactics[0]
	}
	a := &model.Alert{
		AlertID:         utils.NewAlertID(),
		TenantID:        req.TenantID,
		Name:            req.Name,
		Description:     req.Description,
		Severity:        req.Severity,
		SourceType:      req.SourceType,
		Source:          string(req.SourceType),
		Host:            req.AssetName,
		Status:          model.AlertStatusActive,
		AssetName:       req.AssetName,
		AssetID:         req.AssetID,
		TriggerSource:   req.TriggerSource,
		ResultCount:     req.ResultCount,
		MitreTactics:    req.MitreTactics,
		MitreTechniques: req.MitreTechniques,
		MitreTactic:     mitreTactic,
		DetectionRule:   req.RuleID,
		TriggeredAt:     time.Now(),
	}
	if err := s.alertRepo.Create(ctx, a); err != nil {
		return nil, fmt.Errorf("create alert: %w", err)
	}
	if s.auditRepo != nil {
		s.auditRepo.Record(ctx, operatorID, "create", "alert", a.Key, a.Name, nil, a)
	}
	if s.correlationPool != nil {
		s.correlationPool.Submit(a.AlertID)
	}
	return a, nil
}

func (s *Service) Update(ctx context.Context, key string, patch map[string]any, operatorID string) error {
	return s.alertRepo.Update(ctx, key, patch)
}

func (s *Service) Delete(ctx context.Context, key, operatorID string) error {
	return s.alertRepo.Delete(ctx, key)
}

func (s *Service) LinkIncident(ctx context.Context, alertKey, incidentKey, operatorID string) error {
	if s.incRepo != nil {
		if _, err := s.incRepo.GetByID(ctx, incidentKey); err != nil {
			return fmt.Errorf("incident not found: %w", err)
		}
	}
	return s.alertRepo.Update(ctx, alertKey, map[string]any{model.FieldIncidentID: incidentKey})
}

func (s *Service) GetStats(ctx context.Context, tenantID string) (*AlertStats, error) {
	return s.alertRepo.GetStats(ctx, tenantID)
}

func (s *Service) Bulk(ctx context.Context, keys []string, action string, patch map[string]any, operatorID string) error {
	for _, key := range keys {
		if err := s.alertRepo.Update(ctx, key, patch); err != nil {
			return fmt.Errorf("bulk update alert %s: %w", key, err)
		}
	}
	return nil
}
