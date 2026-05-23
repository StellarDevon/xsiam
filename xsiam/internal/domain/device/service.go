package device

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
	"xsiam/internal/model"
	"xsiam/internal/repository"
)

type Service struct {
	devRepo    *Repo
	policyRepo *PolicyRepo
	dsRepo     *DataSourceRepo
	agentCtrl  *AgentController
	auditRepo  *repository.AuditLogRepo
}

func NewService(
	devRepo *Repo,
	policyRepo *PolicyRepo,
	dsRepo *DataSourceRepo,
	agentCtrl *AgentController,
	auditRepo *repository.AuditLogRepo,
) *Service {
	return &Service{devRepo: devRepo, policyRepo: policyRepo, dsRepo: dsRepo, agentCtrl: agentCtrl, auditRepo: auditRepo}
}

func (s *Service) ListAgents(ctx context.Context, f repository.DeviceListFilter) ([]model.Device, model.PageMeta, error) {
	return s.devRepo.List(ctx, f)
}

func (s *Service) GetAgent(ctx context.Context, key string) (*model.Device, error) {
	return s.devRepo.GetByID(ctx, key)
}

func (s *Service) UpdateAgent(ctx context.Context, key string, patch map[string]any) error {
	return s.devRepo.Update(ctx, key, patch)
}

func (s *Service) UpgradeAgent(ctx context.Context, key, version, operatorID string) error {
	dev, err := s.devRepo.GetByID(ctx, key)
	if err != nil {
		return err
	}
	return s.agentCtrl.TriggerAgentUpgrade(ctx, dev.AgentID, version)
}

func (s *Service) UninstallAgent(ctx context.Context, key, operatorID string) error {
	dev, err := s.devRepo.GetByID(ctx, key)
	if err != nil {
		return err
	}
	return s.agentCtrl.TriggerAgentUninstall(ctx, dev.AgentID)
}

func (s *Service) GenerateEnrollmentToken(_ context.Context, _ string) (string, error) {
	b := make([]byte, 32)
	rand.Read(b)
	return hex.EncodeToString(b), nil
}

func (s *Service) ListPolicies(ctx context.Context, tenantID string, page, pageSize int) ([]model.AgentPolicy, model.PageMeta, error) {
	return s.policyRepo.List(ctx, tenantID, page, pageSize)
}

func (s *Service) CreatePolicy(ctx context.Context, policy *model.AgentPolicy, _ string) error {
	return s.policyRepo.Create(ctx, policy)
}

func (s *Service) UpdatePolicy(ctx context.Context, key string, patch map[string]any) error {
	return s.policyRepo.Update(ctx, key, patch)
}

func (s *Service) DeletePolicy(ctx context.Context, key string) error {
	return s.policyRepo.Delete(ctx, key)
}

func (s *Service) ListDataSources(ctx context.Context, tenantID string, page, pageSize int) ([]model.DataSource, model.PageMeta, error) {
	return s.dsRepo.List(ctx, tenantID, page, pageSize)
}

func (s *Service) CreateDataSource(ctx context.Context, ds *model.DataSource, _ string) error {
	return s.dsRepo.Create(ctx, ds)
}

func (s *Service) UpdateDataSource(ctx context.Context, key string, patch map[string]any) error {
	return s.dsRepo.Update(ctx, key, patch)
}

func (s *Service) DeleteDataSource(ctx context.Context, key string) error {
	return s.dsRepo.Delete(ctx, key)
}

// AgentEventType is the lifecycle event sent by fluent-bit / agent.
type AgentEventType string

const (
	AgentEventConnect    AgentEventType = "connect"
	AgentEventDisconnect AgentEventType = "disconnect"
	AgentEventHeartbeat  AgentEventType = "heartbeat"
)

// AgentEvent is the JSON body posted to POST /internal/agent/event.
type AgentEvent struct {
	AgentID      string         `json:"agent_id" binding:"required"`
	Event        AgentEventType `json:"event" binding:"required"`
	Hostname     string         `json:"hostname"`
	IPAddresses  []string       `json:"ip_addresses"`
	OSType       string         `json:"os_type"`
	OSVersion    string         `json:"os_version"`
	AgentVersion string         `json:"agent_version"`
	PolicyID     string         `json:"policy_id"`
	TenantID     string         `json:"tenant_id"`
	Timestamp    *time.Time     `json:"timestamp"`
}

// HandleAgentEvent processes a lifecycle event from an endpoint agent:
//   - connect    → upsert device record, set status=online, record liveness
//   - disconnect → set status=offline, clear liveness
//   - heartbeat  → refresh last_heartbeat + liveness, keep status unchanged
//
// The liveness registry is updated in-memory regardless of DB success.
func (s *Service) HandleAgentEvent(ctx context.Context, ev AgentEvent, reg *LivenessRegistry) error {
	now := time.Now()
	if ev.Timestamp != nil {
		now = *ev.Timestamp
	}

	switch ev.Event {
	case AgentEventConnect:
		reg.RecordHeartbeat(ev.AgentID)
		dev, err := s.devRepo.FindByAgentID(ctx, ev.AgentID)
		if err != nil {
			return fmt.Errorf("findByAgentID: %w", err)
		}
		if dev == nil {
			// Auto-register unknown agent (enrollment via token not required here)
			newDev := &model.Device{
				AgentID:      ev.AgentID,
				Hostname:     ev.Hostname,
				IPAddresses:  ev.IPAddresses,
				OSType:       ev.OSType,
				OSVersion:    ev.OSVersion,
				AgentVersion: ev.AgentVersion,
				PolicyID:     ev.PolicyID,
				TenantID:     ev.TenantID,
				AgentStatus:  model.AgentStatusOnline,
				EnrolledAt:   now,
			}
			if newDev.TenantID == "" {
				newDev.TenantID = "default"
			}
			return s.devRepo.Create(ctx, newDev)
		}
		return s.devRepo.UpdateStatusByKey(ctx, dev.Key, model.AgentStatusOnline, now)

	case AgentEventDisconnect:
		reg.mu.Lock()
		delete(reg.pings, ev.AgentID)
		reg.mu.Unlock()
		dev, err := s.devRepo.FindByAgentID(ctx, ev.AgentID)
		if err != nil || dev == nil {
			return err
		}
		// Only flip to offline if it was online; keep isolated/error unchanged
		if dev.AgentStatus == model.AgentStatusOnline {
			return s.devRepo.UpdateStatusByKey(ctx, dev.Key, model.AgentStatusOffline, now)
		}
		return nil

	case AgentEventHeartbeat:
		reg.RecordHeartbeat(ev.AgentID)
		dev, err := s.devRepo.FindByAgentID(ctx, ev.AgentID)
		if err != nil || dev == nil {
			return err
		}
		// Only update heartbeat ts; preserve agent_status (e.g. isolated stays isolated)
		patch := map[string]any{
			model.FieldDeviceHeartbeat: now,
			model.FieldUpdatedAt:       now,
		}
		return s.devRepo.Update(ctx, dev.Key, patch)

	default:
		return fmt.Errorf("unknown event type: %q", ev.Event)
	}
}
