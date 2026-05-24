package device

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"
	"xsiam/internal/model"
	"xsiam/internal/presence"
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
	AgentEventConnect     AgentEventType = "connect"
	AgentEventDisconnect  AgentEventType = "disconnect"
	AgentEventHeartbeat   AgentEventType = "heartbeat"
	AgentEventFBHeartbeat AgentEventType = "fb_heartbeat" // fb instance lease renewal (no agent_id)
)

// AgentEvent is the JSON body posted to POST /internal/agent/event.
// agent_id is required for connect/disconnect/heartbeat; optional for fb_heartbeat.
type AgentEvent struct {
	AgentID        string         `json:"agent_id"`
	Event          AgentEventType `json:"event" binding:"required"`
	Hostname       string         `json:"hostname"`
	IPAddresses    []string       `json:"ip_addresses"`
	OSType         string         `json:"os_type"`
	OSVersion      string         `json:"os_version"`
	AgentVersion   string         `json:"agent_version"`
	PolicyID       string         `json:"policy_id"`
	TenantID       string         `json:"tenant_id"`
	FBInstanceID   string         `json:"fb_instance_id"` // which fluent-bit forwarded this event
	Timestamp      *time.Time     `json:"timestamp"`
}

// HandleAgentEvent processes a lifecycle event from an endpoint agent.
//
// State machine:
//   - connect    → presence.Touch + upsert device (ArangoDB, async-safe)
//   - heartbeat  → presence.Touch + update last_heartbeat (ArangoDB, async-safe)
//   - disconnect → presence.Remove + flip status=offline if was online
//
// reg is the distributed presence registry (Redis-backed). It is updated
// before any ArangoDB writes so that online state is accurate even if DB
// is temporarily slow.
//
// fbID (ev.FBInstanceID) associates the agent to a fluent-bit instance lease,
// enabling the GC to sweep agents offline when a fb crashes.
func (s *Service) HandleAgentEvent(ctx context.Context, ev AgentEvent, reg *presence.Registry) error {
	now := time.Now()
	if ev.Timestamp != nil {
		now = *ev.Timestamp
	}

	tenantID := ev.TenantID
	if tenantID == "" {
		tenantID = "default"
	}
	fbID := ev.FBInstanceID
	if fbID == "" {
		fbID = "unknown"
	}

	// agent_id is required for all events except fb_heartbeat
	if ev.Event != AgentEventFBHeartbeat && ev.AgentID == "" {
		return fmt.Errorf("agent_id required for event %q", ev.Event)
	}

	switch ev.Event {
	case AgentEventConnect:
		// 1. Update distributed presence (Redis)
		_ = reg.Touch(ctx, tenantID, ev.AgentID, fbID)
		_ = reg.RenewFB(ctx, fbID)

		// 2. Persist / register in ArangoDB
		dev, err := s.devRepo.FindByAgentID(ctx, ev.AgentID)
		if err != nil {
			return fmt.Errorf("findByAgentID: %w", err)
		}
		if dev == nil {
			newDev := &model.Device{
				AgentID:      ev.AgentID,
				Hostname:     ev.Hostname,
				IPAddresses:  ev.IPAddresses,
				OSType:       ev.OSType,
				OSVersion:    ev.OSVersion,
				AgentVersion: ev.AgentVersion,
				PolicyID:     ev.PolicyID,
				TenantID:     tenantID,
				AgentStatus:  model.AgentStatusOnline,
				EnrolledAt:   now,
			}
			return s.devRepo.Create(ctx, newDev)
		}
		return s.devRepo.UpdateStatusByKey(ctx, dev.Key, model.AgentStatusOnline, now)

	case AgentEventDisconnect:
		// 1. Remove from presence immediately
		_ = reg.Remove(ctx, tenantID, ev.AgentID, fbID)

		// 2. Flip ArangoDB status
		dev, err := s.devRepo.FindByAgentID(ctx, ev.AgentID)
		if err != nil || dev == nil {
			return err
		}
		if dev.AgentStatus == model.AgentStatusOnline {
			return s.devRepo.UpdateStatusByKey(ctx, dev.Key, model.AgentStatusOffline, now)
		}
		return nil

	case AgentEventHeartbeat:
		// 1. Renew presence + fb lease
		_ = reg.Touch(ctx, tenantID, ev.AgentID, fbID)
		_ = reg.RenewFB(ctx, fbID)

		// 2. Update last_heartbeat in ArangoDB (non-blocking: error is non-fatal)
		dev, err := s.devRepo.FindByAgentID(ctx, ev.AgentID)
		if err != nil || dev == nil {
			return err
		}
		patch := map[string]any{
			model.FieldDeviceHeartbeat: now,
			model.FieldUpdatedAt:       now,
		}
		return s.devRepo.Update(ctx, dev.Key, patch)

	case AgentEventFBHeartbeat:
		// Fluent-bit instance lease renewal — just renew the fb lease in Redis.
		// No agent_id required; this event keeps the fb lease alive so the GC
		// knows the fb process is still running.
		_ = reg.RenewFB(ctx, fbID)
		return nil

	default:
		// Unknown events are silently ignored to allow forward compatibility.
		return nil
	}
}
