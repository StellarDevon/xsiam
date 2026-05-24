package presence

import (
	"context"
	"time"

	"go.uber.org/zap"
)

// DeviceStatusUpdater is the minimal interface the GC needs to flip
// devices offline in ArangoDB. Implemented by device.Repo.
type DeviceStatusUpdater interface {
	// BulkOfflineByAgentKeys sets status=offline for all given agent_keys
	// under a tenant. Keys not found are silently skipped.
	BulkOfflineByAgentKeys(ctx context.Context, tenantID string, agentKeys []string) error

	// TenantForAgentKey resolves the tenant_id of a given agent_key.
	// Returns ("", nil) if not found.
	TenantForAgentKey(ctx context.Context, agentKey string) (string, error)
}

// GC sweeps crashed/stopped fluent-bit instances and marks their agents offline.
// Run as a cron job every 15 seconds.
type GC struct {
	reg    *Registry
	db     DeviceStatusUpdater
	log    *zap.Logger
}

// NewGC creates a GC. db may be nil in tests (GC skips DB update).
func NewGC(reg *Registry, db DeviceStatusUpdater, log *zap.Logger) *GC {
	return &GC{reg: reg, db: db, log: log}
}

// Run performs one GC sweep. Safe to call concurrently (Redis ops are atomic).
func (g *GC) Run(ctx context.Context) {
	deadFBs, err := g.reg.DeadFBInstances(ctx)
	if err != nil {
		g.log.Warn("presence gc: scan dead fb", zap.Error(err))
		return
	}
	if len(deadFBs) == 0 {
		return
	}

	g.log.Info("presence gc: dead fb instances found", zap.Int("count", len(deadFBs)))

	for _, fbID := range deadFBs {
		g.sweepFB(ctx, fbID)
	}
}

func (g *GC) sweepFB(ctx context.Context, fbID string) {
	agentKeys, err := g.reg.AgentsForFB(ctx, fbID)
	if err != nil {
		g.log.Warn("presence gc: SMEMBERS failed",
			zap.String("fb_id", fbID), zap.Error(err))
		return
	}

	if len(agentKeys) == 0 {
		_ = g.reg.DeleteFBSet(ctx, fbID)
		return
	}

	g.log.Info("presence gc: sweeping agents for dead fb",
		zap.String("fb_id", fbID), zap.Int("agents", len(agentKeys)))

	// Group agent_keys by tenant so we can do one ArangoDB call per tenant.
	// For simplicity and to avoid an extra Redis lookup per key, we resolve
	// tenant_id from ArangoDB in one batch call if db is available.
	if g.db != nil {
		// Resolve tenants in batch: fetch unique tenant for these agent keys.
		// Most deployments have one tenant per fb, so this is typically 1 call.
		tenantMap := map[string][]string{} // tenantID → []agentKey
		for _, ak := range agentKeys {
			tid, err := g.db.TenantForAgentKey(ctx, ak)
			if err != nil || tid == "" {
				continue
			}
			tenantMap[tid] = append(tenantMap[tid], ak)
		}
		for tid, keys := range tenantMap {
			// Remove from Redis presence
			if err := g.reg.BulkRemove(ctx, tid, keys); err != nil {
				g.log.Warn("presence gc: BulkRemove from redis",
					zap.String("tenant", tid), zap.Error(err))
			}
			// Update ArangoDB
			if err := g.db.BulkOfflineByAgentKeys(ctx, tid, keys); err != nil {
				g.log.Warn("presence gc: BulkOfflineByAgentKeys",
					zap.String("tenant", tid), zap.Error(err))
			}
		}
	}

	// Clean up the fb set key regardless of db success
	if err := g.reg.DeleteFBSet(ctx, fbID); err != nil {
		g.log.Warn("presence gc: DeleteFBSet",
			zap.String("fb_id", fbID), zap.Error(err))
	}
}

// StartLoop runs the GC sweep every interval in a background goroutine.
// Cancel ctx to stop it.
func (g *GC) StartLoop(ctx context.Context, interval time.Duration) {
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				g.Run(ctx)
			}
		}
	}()
}
