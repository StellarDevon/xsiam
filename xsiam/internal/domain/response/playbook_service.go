package response

import (
	"context"
	"fmt"
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

// PlaybookExecResult holds the result of a playbook execution, including per-node results.
type PlaybookExecResult struct {
	Status      string               `json:"status"`
	PlaybookID  string               `json:"playbook_id"`
	ExecutionID string               `json:"execution_id"`
	StartedAt   time.Time            `json:"started_at"`
	CompletedAt time.Time            `json:"completed_at"`
	NodeResults []PlaybookNodeResult `json:"node_results"`
}

// PlaybookNodeResult holds the simulated result for a single canvas node.
type PlaybookNodeResult struct {
	NodeID  string `json:"node_id"`
	Type    string `json:"type"`
	Label   string `json:"label"`
	Status  string `json:"status"`
	Message string `json:"message"`
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

// Execute runs a playbook and returns a detailed execution result.
// It sets status="running" on the playbook, simulates node execution, calls the
// execution stub, then marks status="completed" with last_run_at and run_count+1.
func (s *PlaybookService) Execute(ctx context.Context, key, operatorID string) (*PlaybookExecResult, error) {
	pb, err := s.pbRepo.GetByID(ctx, key)
	if err != nil {
		return nil, err
	}

	startedAt := time.Now()

	// Mark playbook as running.
	_ = s.pbRepo.Update(ctx, key, map[string]any{
		"status": "running",
	})

	// Simulate node-level execution by iterating the canvas nodes.
	nodeResults := make([]PlaybookNodeResult, 0, len(pb.Canvas.Nodes))
	for _, node := range pb.Canvas.Nodes {
		nr := PlaybookNodeResult{
			NodeID:  node.ID,
			Type:    string(node.Type),
			Label:   node.Label,
			Status:  "completed",
			Message: fmt.Sprintf("[STUB] node %s (%s) executed", node.Label, node.Type),
		}
		nodeResults = append(nodeResults, nr)
	}

	// Call the execution stub (wraps the underlying engine / device action).
	execResult, err := s.execClient.Execute(ctx, "playbook_execute", pb.Key, map[string]any{"canvas": pb.Canvas})
	if err != nil {
		// Mark failed and surface error.
		_ = s.pbRepo.Update(ctx, key, map[string]any{"status": "failed"})
		return nil, err
	}

	completedAt := time.Now()

	// Persist completion state.
	_ = s.pbRepo.Update(ctx, key, map[string]any{
		"status":      "completed",
		"last_run_at": completedAt,
		"run_count":   pb.RunCount + 1,
	})

	if s.auditRepo != nil {
		s.auditRepo.Record(ctx, operatorID, "execute", "playbook", key, pb.Name, nil, execResult)
	}

	return &PlaybookExecResult{
		Status:      "completed",
		PlaybookID:  pb.Key,
		ExecutionID: execResult.ExecutionID,
		StartedAt:   startedAt,
		CompletedAt: completedAt,
		NodeResults: nodeResults,
	}, nil
}

// PlaybookExecutionSummary holds a summary row for execution history.
type PlaybookExecutionSummary struct {
	Key        string `json:"_key"`
	Status     string `json:"status"`
	Trigger    string `json:"trigger"`
	StartedAt  string `json:"started_at"`
	DurationMs int    `json:"duration_ms"`
	StepsTotal int    `json:"steps_total"`
	StepsOk    int    `json:"steps_ok"`
}

// GetExecutions returns recent execution history for a playbook.
// Returns a mock list of 5 executions for UI development.
func (s *PlaybookService) GetExecutions(ctx context.Context, key string) ([]PlaybookExecutionSummary, error) {
	// Verify playbook exists.
	pb, err := s.pbRepo.GetByID(ctx, key)
	if err != nil {
		return nil, err
	}

	stepsTotal := len(pb.Canvas.Nodes)
	if stepsTotal == 0 {
		stepsTotal = 4
	}

	statuses := []string{"completed", "completed", "completed", "failed", "completed"}
	triggers := []string{"manual", "alert", "manual", "schedule", "manual"}
	durations := []int{1420, 980, 2310, 510, 1750}

	now := time.Now()
	executions := make([]PlaybookExecutionSummary, 5)
	for i := 0; i < 5; i++ {
		stepsOk := stepsTotal
		if statuses[i] == "failed" {
			stepsOk = stepsTotal - 1
		}
		executions[i] = PlaybookExecutionSummary{
			Key:        fmt.Sprintf("exec-%s-%02d", key, i+1),
			Status:     statuses[i],
			Trigger:    triggers[i],
			StartedAt:  now.Add(-time.Duration((i+1)*2) * time.Hour).UTC().Format(time.RFC3339),
			DurationMs: durations[i],
			StepsTotal: stepsTotal,
			StepsOk:    stepsOk,
		}
	}
	return executions, nil
}
