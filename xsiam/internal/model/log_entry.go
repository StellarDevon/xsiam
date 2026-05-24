package model

import "time"

// LogEntry is a single structured event written to the ArangoDB log_entries
// collection.  Each row originates from one of two ingest paths:
//
//  1. WZCP agent events — fluent-bit in_xsiam_agent decodes event batches
//     and forwards them via out_xsiam_log to the ngx datalake (HEC), which
//     also writes a structured copy here for immediate XQL access.
//  2. Syslog lines — plain-text syslog received on TCP/514; stored as
//     dataset "syslog_raw".
//
// The Dataset field determines which XQL dataset the row belongs to;
// Kind is the WZCP event category (0 for syslog).
//
// ── WZCP event kinds (uint8 on the wire) ────────────────────────────────
//
//	KindProcess   = 1  — process create / terminate
//	KindFile      = 2  — file create / modify / delete / rename
//	KindRegistry  = 3  — registry key create / set / delete  (Windows)
//	KindNetwork   = 4  — endpoint-side TCP/UDP connection
//	KindDNS       = 5  — DNS query / response
//	KindAuth      = 6  — local logon / logoff / failure
//	KindVuln      = 7  — vulnerability scan result
//	KindIntegrity = 8  — FIM (file-integrity monitoring) change
//
// Kind 0 is reserved for syslog (no WZCP envelope).
const (
	LogKindSyslog    uint8 = 0
	LogKindProcess   uint8 = 1
	LogKindFile      uint8 = 2
	LogKindRegistry  uint8 = 3
	LogKindNetwork   uint8 = 4
	LogKindDNS       uint8 = 5
	LogKindAuth      uint8 = 6
	LogKindVuln      uint8 = 7
	LogKindIntegrity uint8 = 8
)

// ── Dataset names (match §4.8.1 of the product requirements) ────────────

const (
	DatasetEndpoint        = "xdr_data"           // WZCP endpoint telemetry
	DatasetNetwork         = "network_story"       // NetFlow / NGFW logs
	DatasetCloud           = "cloud_audit_log"     // AWS CloudTrail, Azure Monitor
	DatasetIdentity        = "identity_analytics"  // UEBA
	DatasetEmail           = "email_story"         // Mail security events
	DatasetIncident        = "xdr_incident"        // Incidents & alerts
	DatasetNGFW            = "ngfw_traffic"        // Firewall traffic
	DatasetIDP             = "idp_raw"             // IdP auth logs
	DatasetSyslog          = "syslog_raw"          // Raw syslog
	DatasetAsset           = "asset_inventory"     // Asset snapshots
)

// LogEntry is the ArangoDB document stored in the log_entries collection.
// TTL index on EventTimestamp keeps hot data for 90 days.
type LogEntry struct {
	Key            string         `json:"_key,omitempty"`
	TenantID       string         `json:"tenant_id"`
	Dataset        string         `json:"dataset"`           // DatasetXxx constant
	Kind           uint8          `json:"kind"`              // LogKindXxx constant
	AgentID        string         `json:"agent_id,omitempty"`
	SessionID      string         `json:"session_id,omitempty"`
	Hostname       string         `json:"hostname,omitempty"`
	SourceIP       string         `json:"src_ip,omitempty"`

	// Parsed event fields — populated for structured events; nil for syslog.
	Fields         map[string]any `json:"fields,omitempty"`

	// Raw log line — populated for syslog and as fallback for unstructured events.
	RawLog         string         `json:"raw_log,omitempty"`

	// EventTimestamp is the authoritative event time used by the TTL index.
	EventTimestamp time.Time `json:"event_timestamp"`
	IngestedAt     time.Time `json:"ingested_at"`
}

// KindName returns the human-readable name for a WZCP event kind.
func KindName(kind uint8) string {
	switch kind {
	case LogKindSyslog:
		return "syslog"
	case LogKindProcess:
		return "process"
	case LogKindFile:
		return "file"
	case LogKindRegistry:
		return "registry"
	case LogKindNetwork:
		return "network"
	case LogKindDNS:
		return "dns"
	case LogKindAuth:
		return "auth"
	case LogKindVuln:
		return "vuln"
	case LogKindIntegrity:
		return "integrity"
	default:
		return "unknown"
	}
}
