package model

import "time"

// ─── Endpoint Health & Isolation ─────────────────────────────────────────────

type EndpointStatus string
type IsolationStatus string

const (
	EndpointStatusNormal   EndpointStatus = "normal"   // 正常
	EndpointStatusAbnormal EndpointStatus = "abnormal" // 异常
	EndpointStatusIsolated EndpointStatus = "isolated" // 隔离
	EndpointStatusOffline  EndpointStatus = "offline"  // 离线
)

const (
	IsolationActive   IsolationStatus = "active"   // 隔离中
	IsolationReleased IsolationStatus = "released"  // 已解除
)

// EndpointSummary is a flattened, SOC-friendly view of a device's security posture.
// Derived at query time from Device + Alert + Vulnerability data.
type EndpointSummary struct {
	Key           string         `json:"_key,omitempty"`
	TenantID      string         `json:"tenant_id"`
	DeviceKey     string         `json:"device_key"`
	Hostname      string         `json:"hostname"`
	IP            string         `json:"ip"`
	OS            string         `json:"os"`
	AgentVersion  string         `json:"agent_version"`
	HealthScore   int            `json:"health_score"`
	Status        EndpointStatus `json:"status"`
	LastActive    time.Time      `json:"last_active"`
	OpenAlerts    int            `json:"open_alerts"`
	CriticalVulns int            `json:"critical_vulns"`
	UpdatedAt     time.Time      `json:"updated_at"`
}

// IsolatedEndpoint records a manual or automated endpoint isolation action.
type IsolatedEndpoint struct {
	Key         string          `json:"_key,omitempty"`
	TenantID    string          `json:"tenant_id"`
	DeviceKey   string          `json:"device_key"`
	Hostname    string          `json:"hostname"`
	IP          string          `json:"ip"`
	Reason      string          `json:"reason"`
	IsolatedAt  time.Time       `json:"isolated_at"`
	ReleasedAt  *time.Time      `json:"released_at,omitempty"`
	Operator    string          `json:"operator"`
	ReleasedBy  string          `json:"released_by,omitempty"`
	Status      IsolationStatus `json:"status"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// ─── Endpoint Stats (aggregate) ───────────────────────────────────────────────

type EndpointStats struct {
	TenantID         string    `json:"tenant_id"`
	Total            int64     `json:"total"`
	Online           int64     `json:"online"`
	Abnormal         int64     `json:"abnormal"`
	Isolated         int64     `json:"isolated"`
	NoAgent          int64     `json:"no_agent"`
	HealthyCount     int64     `json:"healthy_count"`    // score >= 80
	FairCount        int64     `json:"fair_count"`       // score 60-79
	PoorCount        int64     `json:"poor_count"`       // score < 60
	AvgHealthScore   float64   `json:"avg_health_score"`
	AlertsToday      int64     `json:"alerts_today"`
	PendingIncidents int64     `json:"pending_incidents"`
	IsolationsWeek   int64     `json:"isolations_week"`
	ComputedAt       time.Time `json:"computed_at"`
}

// ─── Behavior Event (endpoint telemetry) ─────────────────────────────────────

type BehaviorEventLevel string

const (
	BehaviorCritical BehaviorEventLevel = "critical"
	BehaviorWarning  BehaviorEventLevel = "warning"
	BehaviorInfo     BehaviorEventLevel = "info"
)

// BehaviorEvent is a single telemetry entry from an endpoint agent.
// Stored in the datalake, exposed here as a model for the /endpoint/behavior API.
type BehaviorEvent struct {
	ID         string             `json:"id"`
	TenantID   string             `json:"tenant_id"`
	Timestamp  time.Time          `json:"timestamp"`
	Level      BehaviorEventLevel `json:"level"`
	Endpoint   string             `json:"endpoint"` // hostname or device_id
	Category   string             `json:"category"` // process_create, network, file, registry, script
	Message    string             `json:"message"`
	MitreTech  string             `json:"mitre_technique,omitempty"`
}
