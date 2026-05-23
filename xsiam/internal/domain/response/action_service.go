package response

import (
	"context"
	"time"
	"xsiam/internal/model"
	"xsiam/internal/repository"
)

// AuditLogger is the minimal interface for recording audit events.
type AuditLogger interface {
	Record(ctx context.Context, operatorID, action, resourceType, resourceID, resourceName string, oldVal, newVal any)
}

// ActionStore is the minimal interface ActionService needs from the action repository.
type ActionStore interface {
	List(ctx context.Context, f repository.ActionListFilter) ([]model.Action, model.PageMeta, error)
	GetByID(ctx context.Context, key string) (*model.Action, error)
	Create(ctx context.Context, action *model.Action) error
	Update(ctx context.Context, key string, patch map[string]any) error
}

// Executor is the minimal interface ActionService needs for execution.
type Executor interface {
	Execute(ctx context.Context, actionType, targetID string, params map[string]any) (*ExecutionResult, error)
}

type ActionService struct {
	actionRepo ActionStore
	execClient Executor
	auditRepo  AuditLogger
}

func NewActionService(actionRepo *ActionRepo, execClient *ExecutionClient, auditRepo AuditLogger) *ActionService {
	return &ActionService{actionRepo: actionRepo, execClient: execClient, auditRepo: auditRepo}
}

// NewActionServiceWith accepts interfaces (used in tests).
func NewActionServiceWith(actionRepo ActionStore, execClient Executor, auditRepo AuditLogger) *ActionService {
	return &ActionService{actionRepo: actionRepo, execClient: execClient, auditRepo: auditRepo}
}

func (s *ActionService) List(ctx context.Context, f repository.ActionListFilter) ([]model.Action, model.PageMeta, error) {
	return s.actionRepo.List(ctx, f)
}

func (s *ActionService) Get(ctx context.Context, key string) (*model.Action, error) {
	return s.actionRepo.GetByID(ctx, key)
}

func (s *ActionService) Create(ctx context.Context, action *model.Action, operatorID string) error {
	return s.actionRepo.Create(ctx, action)
}

func (s *ActionService) Update(ctx context.Context, key string, patch map[string]any) error {
	return s.actionRepo.Update(ctx, key, patch)
}

func (s *ActionService) Execute(ctx context.Context, id, operatorID string) error {
	action, err := s.actionRepo.GetByID(ctx, id)
	if err != nil {
		return err
	}

	_ = s.actionRepo.Update(ctx, id, map[string]any{
		"status":     "running",
		"started_at": time.Now(),
	})

	result, _ := s.execClient.Execute(ctx, string(action.Type), action.TargetAssetID, nil)

	status := "completed"
	if result == nil || !result.Success {
		status = "failed"
	}
	_ = s.actionRepo.Update(ctx, id, map[string]any{
		"status":         status,
		"completed_at":   time.Now(),
		"result_summary": result.Message,
		"result_detail":  result.Detail,
		"execution_id":   result.ExecutionID,
	})

	if s.auditRepo != nil {
		s.auditRepo.Record(ctx, operatorID, "execute", "action", id, string(action.Type), nil, result)
	}
	return nil
}
