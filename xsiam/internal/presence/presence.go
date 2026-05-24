// Package presence implements distributed agent online-state tracking via Redis.
//
// # Architecture
//
// Each agent is tracked by two Redis structures:
//
//  1. Sorted Set  "agent:online:{tenant}"   member=agent_key  score=unix_ms
//     • ZADD on connect/heartbeat; ZREM on disconnect
//     • ZCOUNT with score >= (now-LeaseTTL) gives exact online count — one command, O(log N)
//     • Agents that die silently (fb crash) expire via the cron GC sweep
//
//  2. Set  "agent:fb:{fb_instance_id}"   members={agent_key, ...}
//     • Tracks which agents are owned by each fluent-bit instance
//     • Used by GC to bulk-offline all agents when a fb instance disappears
//     • Renewed every FBLeaseTTL seconds; if the key expires, the fb is dead
//
// # Lease Renewal (fluent-bit side)
//
// The in_xsiam_agent plugin posts  POST /internal/agent/event  on every
// connect / heartbeat / disconnect. The AgentEvent now carries fb_instance_id.
//
// # GC (cron, every 15s)
//
// Scans "agent:fb:*" keys that have no matching "agent:fb:lease:{id}" key.
// For each dead fb, SMEMBERs its agent list → ZREM from online sorted set →
// batch-update ArangoDB → delete the fb set key.
//
// # Query
//
//   registry.Count(ctx, tenantID)          → int64 (ZCOUNT, O(log N))
//   registry.OnlineKeys(ctx, tenantID)     → []string  (ZRANGEBYSCORE)
//   registry.IsOnline(ctx, tenantID, key)  → bool      (ZSCORE != nil)
package presence

import (
	"context"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	// LeaseTTL is the window after the last heartbeat within which an agent
	// is considered online. Must be > fluent-bit heartbeat interval × 2.
	LeaseTTL = 90 * time.Second

	// FBLeaseTTL is how long a fluent-bit instance's lease key lives without renewal.
	// The in_xsiam_agent plugin should renew every 10–15s.
	FBLeaseTTL = 30 * time.Second

	// keyOnline is the Sorted Set of online agents per tenant.
	// Score = unix-millisecond timestamp of last heartbeat.
	keyOnline = "agent:online:%s" // %s = tenant_id

	// keyFBSet tracks which agent_keys belong to each fluent-bit instance.
	keyFBSet = "agent:fb:%s" // %s = fb_instance_id

	// keyFBLease is the ephemeral key whose existence means the fb is alive.
	keyFBLease = "agent:fb:lease:%s" // %s = fb_instance_id
)

// Registry is the distributed in-online-state registry backed by Redis.
// It is safe for concurrent use and zero-allocation for hot-path queries.
type Registry struct {
	rdb *redis.Client
}

// New creates a Registry. rdb must already be connected and ping-able.
func New(rdb *redis.Client) *Registry {
	return &Registry{rdb: rdb}
}

// ─── Agent lifecycle ──────────────────────────────────────────────────────────

// Touch records a connect or heartbeat for agentKey in tenant tenantID,
// owned by fluent-bit instance fbID.
//
// Hot path: called on every HELLO / HEARTBEAT from every agent.
// Two Redis commands (ZADD + SADD) pipelined.
func (r *Registry) Touch(ctx context.Context, tenantID, agentKey, fbID string) error {
	now := float64(time.Now().UnixMilli())
	pipe := r.rdb.Pipeline()
	pipe.ZAdd(ctx, fmt.Sprintf(keyOnline, tenantID),
		redis.Z{Score: now, Member: agentKey})
	pipe.SAdd(ctx, fmt.Sprintf(keyFBSet, fbID), agentKey)
	_, err := pipe.Exec(ctx)
	return err
}

// Remove marks an agent as offline (explicit disconnect).
func (r *Registry) Remove(ctx context.Context, tenantID, agentKey, fbID string) error {
	pipe := r.rdb.Pipeline()
	pipe.ZRem(ctx, fmt.Sprintf(keyOnline, tenantID), agentKey)
	pipe.SRem(ctx, fmt.Sprintf(keyFBSet, fbID), agentKey)
	_, err := pipe.Exec(ctx)
	return err
}

// ─── Fluent-bit lease ─────────────────────────────────────────────────────────

// RenewFB refreshes the fluent-bit instance lease.
// Must be called every ~10s from in_xsiam_agent via the event endpoint.
func (r *Registry) RenewFB(ctx context.Context, fbID string) error {
	return r.rdb.Set(ctx, fmt.Sprintf(keyFBLease, fbID), 1, FBLeaseTTL).Err()
}

// DeadFBInstances returns fbIDs that have an agent:fb:{id} set but no
// matching agent:fb:lease:{id} key. These are crashed/stopped fb instances
// whose agents need to be swept offline.
func (r *Registry) DeadFBInstances(ctx context.Context) ([]string, error) {
	// Scan all fb set keys
	var fbSetKeys []string
	var cursor uint64
	for {
		keys, next, err := r.rdb.Scan(ctx, cursor, "agent:fb:[^l]*", 100).Result()
		if err != nil {
			return nil, err
		}
		// filter out lease keys
		for _, k := range keys {
			if len(k) > 9 && k[:9] == "agent:fb:" {
				// exclude "agent:fb:lease:*"
				if len(k) < 15 || k[9:14] != "lease" {
					fbSetKeys = append(fbSetKeys, k)
				}
			}
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}

	var dead []string
	for _, setKey := range fbSetKeys {
		fbID := setKey[len("agent:fb:"):]
		leaseKey := fmt.Sprintf(keyFBLease, fbID)
		exists, err := r.rdb.Exists(ctx, leaseKey).Result()
		if err != nil {
			continue
		}
		if exists == 0 {
			dead = append(dead, fbID)
		}
	}
	return dead, nil
}

// AgentsForFB returns all agent_keys registered under a fluent-bit instance.
func (r *Registry) AgentsForFB(ctx context.Context, fbID string) ([]string, error) {
	return r.rdb.SMembers(ctx, fmt.Sprintf(keyFBSet, fbID)).Result()
}

// DeleteFBSet removes the fb instance's agent-set after GC.
func (r *Registry) DeleteFBSet(ctx context.Context, fbID string) error {
	return r.rdb.Del(ctx, fmt.Sprintf(keyFBSet, fbID)).Err()
}

// BulkRemove removes a slice of agentKeys from the online sorted set.
func (r *Registry) BulkRemove(ctx context.Context, tenantID string, agentKeys []string) error {
	if len(agentKeys) == 0 {
		return nil
	}
	members := make([]any, len(agentKeys))
	for i, k := range agentKeys {
		members[i] = k
	}
	return r.rdb.ZRem(ctx, fmt.Sprintf(keyOnline, tenantID), members...).Err()
}

// ─── Query ────────────────────────────────────────────────────────────────────

// Count returns the number of agents that have touched within LeaseTTL.
// Single ZCOUNT command — O(log N), safe to call on every page load.
func (r *Registry) Count(ctx context.Context, tenantID string) (int64, error) {
	min := fmt.Sprintf("(%d", time.Now().Add(-LeaseTTL).UnixMilli())
	return r.rdb.ZCount(ctx, fmt.Sprintf(keyOnline, tenantID), min, "+inf").Result()
}

// OnlineKeys returns all agent_keys that touched within LeaseTTL.
// Returned keys can be used to JOIN against ArangoDB devices collection.
func (r *Registry) OnlineKeys(ctx context.Context, tenantID string) ([]string, error) {
	min := fmt.Sprintf("%d", time.Now().Add(-LeaseTTL).UnixMilli())
	return r.rdb.ZRangeByScore(ctx, fmt.Sprintf(keyOnline, tenantID),
		&redis.ZRangeBy{Min: min, Max: "+inf"}).Result()
}

// IsOnline returns true if agentKey has touched within LeaseTTL.
func (r *Registry) IsOnline(ctx context.Context, tenantID, agentKey string) (bool, error) {
	score, err := r.rdb.ZScore(ctx, fmt.Sprintf(keyOnline, tenantID), agentKey).Result()
	if err == redis.Nil {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	deadline := float64(time.Now().Add(-LeaseTTL).UnixMilli())
	return score >= deadline, nil
}

// CountAll returns counts across all tenants by scanning keyOnline keys.
// Use sparingly — for admin-level dashboards only.
func (r *Registry) CountAll(ctx context.Context) (map[string]int64, error) {
	result := map[string]int64{}
	var cursor uint64
	for {
		keys, next, err := r.rdb.Scan(ctx, cursor, "agent:online:*", 100).Result()
		if err != nil {
			return nil, err
		}
		for _, k := range keys {
			tenantID := k[len("agent:online:"):]
			n, err := r.Count(ctx, tenantID)
			if err == nil {
				result[tenantID] = n
			}
		}
		cursor = next
		if cursor == 0 {
			break
		}
	}
	return result, nil
}

// ─── Graceful degradation ─────────────────────────────────────────────────────

// Ping checks connectivity. Used at startup and by health endpoints.
func (r *Registry) Ping(ctx context.Context) error {
	return r.rdb.Ping(ctx).Err()
}
