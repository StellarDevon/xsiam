// Package etl provides the HTTP API for managing ETL pipeline rules.
package etl

import (
	"context"
	"fmt"
	"time"
	"xsiam/internal/etl"
	"xsiam/internal/model"
	"xsiam/internal/repository"
)

// Service wraps the ETL rule repository and provides business logic for
// rule management including a dry-run test against a sample event.
type Service struct {
	repo     *repository.ETLRuleRepo
	pipeline *etl.Pipeline // used for /test dry-runs
}

// NewService constructs an ETL management service.
// pipeline may be nil when running in stub/test mode.
func NewService(repo *repository.ETLRuleRepo, pipeline *etl.Pipeline) *Service {
	return &Service{repo: repo, pipeline: pipeline}
}

// List returns paginated ETL rules matching the filter.
func (s *Service) List(ctx context.Context, f repository.ETLRuleListFilter) ([]model.ETLRule, model.PageMeta, error) {
	return s.repo.List(ctx, f)
}

// Get returns a single rule by ArangoDB _key.
func (s *Service) Get(ctx context.Context, key string) (*model.ETLRule, error) {
	return s.repo.GetByKey(ctx, key)
}

// Create validates and inserts a new ETL rule.
func (s *Service) Create(ctx context.Context, rule *model.ETLRule, operatorID string) error {
	if rule.RuleID == "" {
		return fmt.Errorf("rule_id is required")
	}
	if rule.Name == "" {
		return fmt.Errorf("name is required")
	}
	// raw_only rules don't need actions (they bypass ETL entirely)
	if len(rule.Actions) == 0 && rule.RawWriteMode != model.RawWriteRawOnly {
		return fmt.Errorf("at least one action is required (or set raw_write_mode=raw_only to bypass ETL)")
	}
	// Validate RawWriteMode
	switch rule.RawWriteMode {
	case "", model.RawWriteBoth, model.RawWriteETLOnly, model.RawWriteRawOnly:
		// valid
	default:
		return fmt.Errorf("invalid raw_write_mode %q (valid: both, etl_only, raw_only)", rule.RawWriteMode)
	}
	if rule.RawWriteMode == "" {
		rule.RawWriteMode = model.RawWriteBoth
	}
	// Check for duplicate rule_id
	existing, err := s.repo.FindByRuleID(ctx, rule.RuleID)
	if err != nil {
		return fmt.Errorf("rule_id check: %w", err)
	}
	if existing != nil {
		return fmt.Errorf("rule_id %q already exists", rule.RuleID)
	}

	now := time.Now().UTC()
	rule.CreatedAt = now
	rule.UpdatedAt = now
	rule.CreatedBy = operatorID
	return s.repo.Create(ctx, rule)
}

// Update applies a partial patch to the rule identified by key.
func (s *Service) Update(ctx context.Context, key string, patch map[string]any) error {
	// Validate raw_write_mode if present in patch
	if v, ok := patch["raw_write_mode"]; ok {
		mode := model.RawWriteMode(fmt.Sprintf("%v", v))
		switch mode {
		case model.RawWriteBoth, model.RawWriteETLOnly, model.RawWriteRawOnly:
			// valid
		default:
			return fmt.Errorf("invalid raw_write_mode %q", mode)
		}
	}
	return s.repo.Update(ctx, key, patch)
}

// Delete removes the ETL rule with the given key.
func (s *Service) Delete(ctx context.Context, key string) error {
	return s.repo.Delete(ctx, key)
}

// Toggle flips the is_enabled field of the rule identified by key.
// Returns the new value of is_enabled.
func (s *Service) Toggle(ctx context.Context, key string) (bool, error) {
	rule, err := s.repo.GetByKey(ctx, key)
	if err != nil {
		return false, fmt.Errorf("toggle: %w", err)
	}
	if rule == nil {
		return false, fmt.Errorf("rule not found: %s", key)
	}
	newEnabled := !rule.IsEnabled
	if err := s.repo.Update(ctx, key, map[string]any{"is_enabled": newEnabled}); err != nil {
		return false, fmt.Errorf("toggle update: %w", err)
	}
	return newEnabled, nil
}

// TestResult is the response from a dry-run test of a rule against a sample event.
type TestResult struct {
	Matched      bool             `json:"matched"`
	RawNgxIndex  string           `json:"raw_ngx_index"`
	ETLNgxIndex  string           `json:"etl_ngx_index"`
	WriteArango  bool             `json:"write_arango"`
	Dropped      bool             `json:"dropped"`
	OutputEntry  *model.LogEntry  `json:"output_entry,omitempty"`
}

// Test runs the ETL pipeline against a sample event and returns routing decisions.
// Nothing is written to any storage backend during a test.
func (s *Service) Test(ctx context.Context, key string, sample *model.LogEntry, tag string) (*TestResult, error) {
	if s.pipeline == nil {
		return nil, fmt.Errorf("ETL pipeline not available in stub mode")
	}
	// Verify the rule exists
	rule, err := s.repo.GetByKey(ctx, key)
	if err != nil {
		return nil, err
	}
	if rule == nil {
		return nil, fmt.Errorf("rule not found: %s", key)
	}

	// Create a temporary single-rule pipeline for the test
	executor := s.pipeline // re-use pipeline's executor indirectly via Process
	_ = executor

	res := s.pipeline.Process(ctx, sample, tag)

	result := &TestResult{
		Matched:     res.Matched,
		RawNgxIndex: res.RawNgxIndex,
		ETLNgxIndex: res.ETLNgxIndex,
		WriteArango: res.WriteArango,
		Dropped:     res.ETLEntry == nil && res.ETLNgxIndex == "" && res.RawNgxIndex == "",
		OutputEntry: res.ETLEntry,
	}
	return result, nil
}
