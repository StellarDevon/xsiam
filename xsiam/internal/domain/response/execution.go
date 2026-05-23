package response

import (
	"context"
	"fmt"
	"time"

	"go.uber.org/zap"
)

type ExecutionResult struct {
	Success     bool           `json:"success"`
	ExecutionID string         `json:"execution_id"`
	Message     string         `json:"message"`
	Detail      map[string]any `json:"detail"`
}

type ExecutionClient struct {
	enabled bool
	logger  *zap.Logger
}

func NewExecutionClient(enabled bool) *ExecutionClient {
	return &ExecutionClient{enabled: enabled, logger: zap.L()}
}

func (s *ExecutionClient) Execute(_ context.Context, actionType, targetID string, params map[string]any) (*ExecutionResult, error) {
	s.logger.Info("[STUB] execution called", zap.String("action_type", actionType), zap.String("target_id", targetID))
	time.Sleep(200 * time.Millisecond)
	return &ExecutionResult{
		Success:     true,
		ExecutionID: fmt.Sprintf("EXEC-%d", time.Now().UnixMilli()),
		Message:     fmt.Sprintf("[STUB] %s 已提交（未实际联动设备）", actionType),
		Detail:      map[string]any{"stub": true, "action_type": actionType},
	}, nil
}
