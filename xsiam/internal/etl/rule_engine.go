package etl

import (
	"context"
	"time"
	"xsiam/internal/repository"

	"go.uber.org/zap"
)

// RuleEngine loads ETL rules from ArangoDB and hot-reloads them every 60s.
// It calls Pipeline.Replace after each successful load so the pipeline always
// runs the current rule set without any restart.
type RuleEngine struct {
	repo     *repository.ETLRuleRepo
	pipeline *Pipeline
	tenantID string // "" = load all tenants
	log      *zap.Logger
}

// NewRuleEngine constructs a RuleEngine that keeps pipeline up to date.
// Pass tenantID="" to load rules across all tenants (single-tenant / super-admin mode).
func NewRuleEngine(repo *repository.ETLRuleRepo, pipeline *Pipeline, tenantID string, log *zap.Logger) *RuleEngine {
	return &RuleEngine{repo: repo, pipeline: pipeline, tenantID: tenantID, log: log}
}

// LoadRules does the initial synchronous load.  Call once at startup before
// accepting any ingest traffic.
func (e *RuleEngine) LoadRules(ctx context.Context) error {
	return e.reload(ctx)
}

// StartHotReload launches a background goroutine that re-reads the etl_rules
// collection every 60 seconds.  The goroutine stops when ctx is cancelled.
func (e *RuleEngine) StartHotReload(ctx context.Context) {
	go func() {
		ticker := time.NewTicker(60 * time.Second)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				if err := e.reload(ctx); err != nil {
					e.log.Error("etl rule reload failed", zap.Error(err))
				}
			}
		}
	}()
}

func (e *RuleEngine) reload(ctx context.Context) error {
	raw, err := e.repo.FindEnabledForTenant(ctx, e.tenantID)
	if err != nil {
		return err
	}
	compiled := make([]compiledRule, 0, len(raw))
	for _, r := range raw {
		compiled = append(compiled, compileRule(r))
	}
	e.pipeline.Replace(compiled)
	e.log.Info("etl rules reloaded", zap.Int("count", len(compiled)), zap.String("tenant", e.tenantID))
	return nil
}
