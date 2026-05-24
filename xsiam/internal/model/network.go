package model

import "time"

// ─── Network Connection ───────────────────────────────────────────────────────

type ConnStatus string
type ConnSeverity string

const (
	ConnStatusBlocked    ConnStatus = "blocked"
	ConnStatusAlerting   ConnStatus = "alerting"
	ConnStatusMonitoring ConnStatus = "monitoring"
	ConnStatusNormal     ConnStatus = "normal"
	ConnStatusClosed     ConnStatus = "closed"

	ConnSeverityCritical ConnSeverity = "critical"
	ConnSeverityHigh     ConnSeverity = "high"
	ConnSeverityMedium   ConnSeverity = "medium"
	ConnSeverityLow      ConnSeverity = "low"
)

// NetworkConnection represents a suspicious or notable network flow.
type NetworkConnection struct {
	Key              string       `json:"_key,omitempty"`
	TenantID         string       `json:"tenant_id"`
	SrcIP            string       `json:"src_ip"`
	DstIP            string       `json:"dst_ip"`
	Port             int          `json:"port"`
	Protocol         string       `json:"protocol"`
	// Byte counters — all stored as int64 (bytes); UI formats to human-readable.
	BytesInbound     int64        `json:"bytes_inbound"`
	BytesOutbound    int64        `json:"bytes_outbound"`
	BytesTransferred int64        `json:"bytes_transferred"` // = inbound + outbound
	BytesHuman       string       `json:"bytes_human,omitempty"` // deprecated alias, retained for compat
	ThreatType       string       `json:"threat_type"`
	Severity         ConnSeverity `json:"severity"`
	Status           ConnStatus   `json:"status"`
	DetectedAt       time.Time    `json:"detected_at"`
	BlockedAt        *time.Time   `json:"blocked_at,omitempty"`
	BlockedBy        string       `json:"blocked_by,omitempty"`
	CreatedAt        time.Time    `json:"created_at"`
	UpdatedAt        time.Time    `json:"updated_at,omitempty"`
}

// ─── DNS Record ───────────────────────────────────────────────────────────────

type DNSRiskLevel string

const (
	DNSRiskCritical DNSRiskLevel = "critical"
	DNSRiskHigh     DNSRiskLevel = "high"
	DNSRiskMedium   DNSRiskLevel = "medium"
	DNSRiskLow      DNSRiskLevel = "low"
	DNSRiskClean    DNSRiskLevel = "clean"
)

// DNSRecord captures DNS query statistics and reputation data per domain.
type DNSRecord struct {
	Key               string       `json:"_key,omitempty"`
	TenantID          string       `json:"tenant_id"`
	Domain            string       `json:"domain"`
	QueryCount        int64        `json:"query_count"`
	ResolvedIP        string       `json:"resolved_ip"`
	ResolutionHistory []string     `json:"resolution_history"`
	RiskLevel         DNSRiskLevel `json:"risk_level"`
	Category          string       `json:"category"`
	IsBlocklisted     bool         `json:"is_blocklisted"`
	BlocklistedAt     *time.Time   `json:"blocklisted_at,omitempty"`
	BlocklistedBy     string       `json:"blocklisted_by,omitempty"`
	// WHOIS / reputation detail
	Registrar string `json:"registrar,omitempty"`
	Created   string `json:"created,omitempty"`
	Expiry    string `json:"expiry,omitempty"`
	Verdict   string `json:"verdict,omitempty"`
	Whois     string `json:"whois,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// ─── Network Detection Rule ───────────────────────────────────────────────────

// NetworkDetectionRule is a network-layer rule (port scan, DNS tunnel, ARP spoof…)
// distinct from the endpoint-level DetectionRule.
type NetworkDetectionRule struct {
	Key        string    `json:"_key,omitempty"`
	TenantID   string    `json:"tenant_id"`
	Name       string    `json:"name"`
	Category   string    `json:"category"`
	Active     bool      `json:"active"`
	HitsToday  int64     `json:"hits_today"`
	HitsTotal  int64     `json:"hits_total"`
	CreatedBy  string    `json:"created_by"`
	CreatedAt  time.Time `json:"created_at"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// ─── Network Stats (aggregate view returned by GET /network/stats) ─────────────

type NetworkStats struct {
	TenantID         string    `json:"tenant_id"`
	TotalTrafficGB   float64   `json:"total_traffic_gb"`
	ActiveConns      int64     `json:"active_conns"`
	SuspiciousConns  int64     `json:"suspicious_conns"`
	BlockedConns     int64     `json:"blocked_conns"`
	DNSQueriesToday  int64     `json:"dns_queries_today"`
	AnomalousDomains int64     `json:"anomalous_domains"`
	BlockedDomains   int64     `json:"blocked_domains"`
	DevicesTotal     int64     `json:"devices_total"`
	DevicesUnknown   int64     `json:"devices_unknown"`
	DevicesNew       int64     `json:"devices_new"`
	ActiveAlerts     int64     `json:"active_alerts"`
	ComputedAt       time.Time `json:"computed_at"`
}

// ─── Network Device (layer-2/3 asset discovered via passive NTA) ─────────────

type NetworkDeviceType string

const (
	NetDevServer      NetworkDeviceType = "server"
	NetDevWorkstation NetworkDeviceType = "workstation"
	NetDevRouter      NetworkDeviceType = "router"
	NetDevSwitch      NetworkDeviceType = "switch"
	NetDevCamera      NetworkDeviceType = "camera"
	NetDevMobile      NetworkDeviceType = "mobile"
	NetDevIoT         NetworkDeviceType = "iot"
	NetDevUnknown     NetworkDeviceType = "unknown"
)

// NetworkDevice is a layer-2/3 device discovered by passive network analysis.
// (Distinct from Device which is an agent-managed endpoint.)
type NetworkDevice struct {
	Key        string            `json:"_key,omitempty"`
	TenantID   string            `json:"tenant_id"`
	IP         string            `json:"ip"`
	MAC        string            `json:"mac"`
	Hostname   string            `json:"hostname"`
	DeviceType NetworkDeviceType `json:"device_type"`
	Risk       ConnSeverity      `json:"risk"`
	IsNew      bool              `json:"is_new"`
	IsUnknown  bool              `json:"is_unknown"`
	FirstSeen  time.Time         `json:"first_seen"`
	LastActive time.Time         `json:"last_active"`
	CreatedAt  time.Time         `json:"created_at"`
	UpdatedAt  time.Time         `json:"updated_at"`
}

// ─── Network Threat Alert ─────────────────────────────────────────────────────

type NetAlertStatus string

const (
	NetAlertActive       NetAlertStatus = "active"
	NetAlertInvestigate  NetAlertStatus = "investigating"
	NetAlertResolved     NetAlertStatus = "resolved"
)

// NetworkThreatAlert is a threat event generated by network detection rules.
type NetworkThreatAlert struct {
	Key        string         `json:"_key,omitempty"`
	TenantID   string         `json:"tenant_id"`
	ThreatType string         `json:"threat_type"`
	SrcIP      string         `json:"src_ip"`
	Target     string         `json:"target"`
	Severity   ConnSeverity   `json:"severity"`
	Status     NetAlertStatus `json:"status"`
	RuleID     string         `json:"rule_id,omitempty"`
	DetectedAt time.Time      `json:"detected_at"`
	CreatedAt  time.Time      `json:"created_at"`
}
