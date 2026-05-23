package model

import "time"

type AlertStatus string

const (
	AlertStatusActive      AlertStatus = "active"
	AlertStatusInvestigate AlertStatus = "investigating"
	AlertStatusResolved    AlertStatus = "resolved"
	AlertStatusFalsePos    AlertStatus = "false_positive"
	AlertStatusAutoClosed  AlertStatus = "auto_closed"
)

const (
	FieldAlertID         = "alert_id"
	FieldAlertName       = "name"
	FieldAlertSeverity   = FieldSeverity
	FieldAlertStatus     = FieldStatus
	FieldAlertSourceType = FieldSourceType
	FieldAlertIncidentID = FieldIncidentID
	FieldAlertAssetID    = FieldAssetID
)

type ProcessNode struct {
	PID         int    `json:"pid"`
	Name        string `json:"name"`
	Path        string `json:"path"`
	CommandLine string `json:"command_line"`
	ParentPID   *int   `json:"parent_pid"`
	IsRoot      bool   `json:"is_root"`
	IsAlertNode bool   `json:"is_alert_node"`
}

type IocEntry struct {
	Type    string `json:"type"`
	Value   string `json:"value"`
	Verdict string `json:"verdict"`
}

type Alert struct {
	Key             string         `json:"_key,omitempty"`
	AlertID         string         `json:"alert_id"`
	TenantID        string         `json:"tenant_id"`
	Name            string         `json:"name"`
	Description     string         `json:"description"`
	Severity        Severity       `json:"severity"`
	SourceType      SourceType     `json:"source_type"`
	// Source/host/user are stored + indexed by their canonical names; the
	// "source", "host", "user" aliases are extra JSON fields for the SPA.
	Source          string         `json:"source"`
	Host            string         `json:"host"`
	User            string         `json:"user"`
	MitreTactic     string         `json:"mitre_tactic"`
	Status          AlertStatus    `json:"status"`
	AssetID         *string        `json:"asset_id"`
	AssetName       string         `json:"asset_name"`
	UserName        *string        `json:"user_name"`
	IncidentID      *string        `json:"incident_id"`
	DetectionRule   string         `json:"detection_rule"`
	RuleType        string         `json:"rule_type"`
	TriggerSource   string         `json:"trigger_source"`
	ResultCount     uint64         `json:"result_count"`
	MitreTactics    []string       `json:"mitre_tactics"`
	MitreTechniques []string       `json:"mitre_techniques"`
	IOCs            []IocEntry     `json:"iocs"`
	ProcessTree     []ProcessNode  `json:"process_tree"`
	RawData         map[string]any `json:"raw_data"`
	AssigneeID      *string        `json:"assignee_id"`
	AssigneeName    *string        `json:"assignee_name"`
	ResolvedAt      *time.Time     `json:"resolved_at"`
	ResolutionNote  string         `json:"resolution_note"`
	TriggeredAt     time.Time      `json:"triggered_at"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}
