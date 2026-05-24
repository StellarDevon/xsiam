// Package statscache provides a Redis-backed cache for per-tenant security
// aggregate statistics.  All keys are namespaced by tenant ID so cross-tenant
// leakage is impossible.
//
// Cache contract
//
//   - TTL = 10 minutes for dashboard/summary stats (refreshed by cron every 5 min)
//   - TTL = 30 minutes for heavier aggregations (network/endpoint/datasource)
//   - On a cache miss the caller falls back to a live AQL computation and
//     back-fills the cache.
//   - On Redis failure Get returns (zero, false) — the caller must handle a miss.
package statscache

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"
)

const (
	// Key prefixes — all contain tenant_id to prevent cross-tenant leakage.
	PfxDashboardStats  = "stats:dashboard:%s"   // %s = tenant_id
	PfxExtendedStats   = "stats:extended:%s"
	PfxNetworkStats    = "stats:network:%s"
	PfxEndpointStats   = "stats:endpoint:%s"
	PfxDatasourceStats = "stats:datasource:%s"
	PfxTrafficTimeline = "stats:traffic_timeline:%s"

	// TTLs
	TTLFast   = 10 * time.Minute // dashboard KPIs — cron refreshes every 5m
	TTLMedium = 30 * time.Minute // network/endpoint — cron refreshes every 15m
	TTLSlow   = 60 * time.Minute // heavy aggregations — cron refreshes every 30m
)

// Client wraps a Redis client with typed get/set helpers.
type Client struct {
	rdb *redis.Client
}

// New creates a cache Client from an existing redis.Client.
func New(rdb *redis.Client) *Client {
	return &Client{rdb: rdb}
}

// Key formats a namespaced cache key for the given tenant.
func Key(pattern, tenantID string) string {
	return fmt.Sprintf(pattern, tenantID)
}

// Set serialises val as JSON and stores it under key with the given TTL.
// Errors are silently swallowed; a failed write just means the next read
// will be a cache miss and fall back to a live query.
func Set[T any](ctx context.Context, c *Client, key string, val T, ttl time.Duration) {
	if c == nil {
		return
	}
	b, err := json.Marshal(val)
	if err != nil {
		return
	}
	_ = c.rdb.Set(ctx, key, b, ttl).Err()
}

// Get deserialises the cached value into *T.
// Returns (zero-value, false) on any miss or error.
func Get[T any](ctx context.Context, c *Client, key string) (T, bool) {
	var zero T
	if c == nil {
		return zero, false
	}
	b, err := c.rdb.Get(ctx, key).Bytes()
	if err != nil {
		return zero, false // miss or redis down
	}
	var v T
	if err := json.Unmarshal(b, &v); err != nil {
		return zero, false
	}
	return v, true
}

// Del removes a single key.
func Del(ctx context.Context, c *Client, key string) {
	if c == nil {
		return
	}
	_ = c.rdb.Del(ctx, key).Err()
}

// Ping tests connectivity; returns nil on success.
func (c *Client) Ping(ctx context.Context) error {
	if c == nil {
		return fmt.Errorf("statscache: nil client")
	}
	return c.rdb.Ping(ctx).Err()
}
