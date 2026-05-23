package device

// LivenessRegistry tracks real-time agent TCP connectivity.
//
// Architecture:
//   - Each endpoint agent runs fluent-bit, which forwards a periodic heartbeat
//     record to the server-side fluent-bit aggregator (Forward input).
//   - The aggregator's HTTP output (or a dedicated webhook) calls
//     POST /api/devices/:id/heartbeat — updating this registry.
//   - Alternatively, the fluent-bit HTTP Monitor endpoint (:2020) is polled
//     to extract per-agent record counts and infer liveness.
//   - GET /api/devices/liveness?ids=a,b,c returns the live status map.
//
// Fallback: if no heartbeat has been registered (registry empty),
// we fall back to last_heartbeat from ArangoDB (stale but better than nothing).

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

const (
	// livenessWindow is how long after the last heartbeat we consider an agent online.
	livenessWindow = 5 * time.Minute
	// fluentBitMonitorURL is the default fluent-bit HTTP Monitor API base URL.
	// Can be overridden via FLUENTBIT_MONITOR_URL env / config.
	fluentBitMonitorDefaultURL = "http://127.0.0.1:2020"
)

// LivenessRegistry stores per-agent last-ping timestamps in memory.
type LivenessRegistry struct {
	mu      sync.RWMutex
	pings   map[string]time.Time // agent_id → last ping time
	fbURL   string
	fbAlive bool // cached: was fluent-bit reachable on last poll?
}

// NewLivenessRegistry creates a registry. fbURL may be empty (disables fluent-bit polling).
func NewLivenessRegistry(fbURL string) *LivenessRegistry {
	if fbURL == "" {
		fbURL = fluentBitMonitorDefaultURL
	}
	r := &LivenessRegistry{
		pings: make(map[string]time.Time),
		fbURL: fbURL,
	}
	// Start background fluent-bit poller (non-fatal if FB is absent)
	go r.pollFluentBitLoop()
	return r
}

// RecordHeartbeat records a heartbeat for an agent (called from the webhook endpoint).
func (r *LivenessRegistry) RecordHeartbeat(agentID string) {
	r.mu.Lock()
	r.pings[agentID] = time.Now()
	r.mu.Unlock()
}

// IsOnline returns true if agentID sent a heartbeat within livenessWindow.
func (r *LivenessRegistry) IsOnline(agentID string) bool {
	r.mu.RLock()
	t, ok := r.pings[agentID]
	r.mu.RUnlock()
	return ok && time.Since(t) <= livenessWindow
}

// QueryBatch returns a map agentID→online for a slice of agent IDs.
func (r *LivenessRegistry) QueryBatch(agentIDs []string) map[string]bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	result := make(map[string]bool, len(agentIDs))
	for _, id := range agentIDs {
		t, ok := r.pings[id]
		result[id] = ok && time.Since(t) <= livenessWindow
	}
	return result
}

// HasAnyData returns true if at least one heartbeat has been registered.
func (r *LivenessRegistry) HasAnyData() bool {
	r.mu.RLock()
	n := len(r.pings)
	r.mu.RUnlock()
	return n > 0
}

// ─── Fluent-Bit HTTP Monitor poller ──────────────────────────────────────────

// fbMetricsResponse is the relevant portion of fluent-bit's /api/v1/metrics JSON.
// Fluent-bit tags heartbeat records with "heartbeat.<agent_id>".
type fbMetricsResponse struct {
	Input map[string]fbInputMetrics `json:"input"`
}

type fbInputMetrics struct {
	Records uint64 `json:"records"`
	Bytes   uint64 `json:"bytes"`
	// Extension: some builds expose last_received timestamp
	LastReceived *float64 `json:"last_received,omitempty"`
}

func (r *LivenessRegistry) pollFluentBitLoop() {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()
	for range ticker.C {
		r.pollFluentBit()
	}
}

func (r *LivenessRegistry) pollFluentBit() {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()

	url := fmt.Sprintf("%s/api/v1/metrics", r.fbURL)
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		r.fbAlive = false
		return
	}
	defer resp.Body.Close()
	r.fbAlive = true

	var metrics fbMetricsResponse
	if err := json.NewDecoder(resp.Body).Decode(&metrics); err != nil {
		return
	}

	now := time.Now()
	r.mu.Lock()
	defer r.mu.Unlock()

	// fluent-bit forward input tags: "heartbeat.<agent_id>"
	// We record a ping for any input whose tag contains an agent_id.
	for tag, m := range metrics.Input {
		if m.Records == 0 {
			continue
		}
		// Tag format: "heartbeat.agent-00001" → agent_id = "agent-00001"
		agentID := extractAgentIDFromTag(tag)
		if agentID == "" {
			continue
		}
		if m.LastReceived != nil {
			// Use the precise timestamp if the build exposes it
			r.pings[agentID] = time.Unix(int64(*m.LastReceived), 0)
		} else {
			// Otherwise just mark as "seen now" since records > 0
			if _, exists := r.pings[agentID]; !exists {
				r.pings[agentID] = now
			}
		}
	}
}

func extractAgentIDFromTag(tag string) string {
	// Expected formats:
	//   "heartbeat.agent-00001"
	//   "xsiam.agent-00001.heartbeat"
	//   "agent-00001"
	for i := len(tag) - 1; i >= 0; i-- {
		if tag[i] == '.' {
			suffix := tag[i+1:]
			if len(suffix) > 3 {
				return suffix
			}
		}
	}
	// No dot — treat entire tag as agent_id
	if len(tag) > 3 {
		return tag
	}
	return ""
}
