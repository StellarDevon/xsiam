package response

import (
	"context"
	"time"
	"xsiam/internal/model"
)

// PlaybookStore is the minimal interface PlaybookService needs from the playbook repository.
type PlaybookStore interface {
	List(ctx context.Context, f PlaybookListFilter) ([]model.Playbook, model.PageMeta, error)
	GetByID(ctx context.Context, key string) (*model.Playbook, error)
	Create(ctx context.Context, pb *model.Playbook) error
	Update(ctx context.Context, key string, patch map[string]any) error
	Delete(ctx context.Context, key string) error
}

type PlaybookService struct {
	pbRepo     PlaybookStore
	execClient Executor
	auditRepo  AuditLogger
}

func NewPlaybookService(pbRepo *PlaybookRepo, execClient *ExecutionClient, auditRepo AuditLogger) *PlaybookService {
	return &PlaybookService{pbRepo: pbRepo, execClient: execClient, auditRepo: auditRepo}
}

// NewPlaybookServiceWith accepts interfaces (used in tests).
func NewPlaybookServiceWith(pbRepo PlaybookStore, execClient Executor, auditRepo AuditLogger) *PlaybookService {
	return &PlaybookService{pbRepo: pbRepo, execClient: execClient, auditRepo: auditRepo}
}

func (s *PlaybookService) List(ctx context.Context, f PlaybookListFilter) ([]model.Playbook, model.PageMeta, error) {
	return s.pbRepo.List(ctx, f)
}

func (s *PlaybookService) Get(ctx context.Context, key string) (*model.Playbook, error) {
	return s.pbRepo.GetByID(ctx, key)
}

func (s *PlaybookService) Create(ctx context.Context, pb *model.Playbook, operatorID string) error {
	return s.pbRepo.Create(ctx, pb)
}

func (s *PlaybookService) Update(ctx context.Context, key string, patch map[string]any) error {
	return s.pbRepo.Update(ctx, key, patch)
}

func (s *PlaybookService) Delete(ctx context.Context, key string) error {
	return s.pbRepo.Delete(ctx, key)
}

func (s *PlaybookService) Execute(ctx context.Context, key, operatorID string) error {
	pb, err := s.pbRepo.GetByID(ctx, key)
	if err != nil {
		return err
	}
	_, err = s.execClient.Execute(ctx, "playbook_execute", pb.Key, map[string]any{"canvas": pb.Canvas})
	if err != nil {
		return err
	}
	now := time.Now()
	return s.pbRepo.Update(ctx, key, map[string]any{
		"run_count":   pb.RunCount + 1,
		"last_run_at": now,
	})
}
