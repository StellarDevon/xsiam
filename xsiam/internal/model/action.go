package model

import "time"

type ActionType string

const (
	ActionTypeIsolateHost     ActionType = "isolate_host"
	ActionTypeBlockIP         ActionType = "block_ip"
	ActionTypeKillProcess     ActionType = "kill_process"
	ActionTypeResetPassword   ActionType = "reset_password"
	ActionTypeRunScript       ActionType = "run_script"
	ActionTypeCollectForensic ActionType = "collect_forensic"
	ActionTypeQuarantine      ActionType = "quarantine_file"
)

type ActionStatus string

const (
	ActionStatusPending   ActionStatus = "pending"
	ActionStatusApproved  ActionStatus = "approved"
	ActionStatusRunning   ActionStatus = "running"
	ActionStatusCompleted ActionStatus = "completed"
	ActionStatusFailed    ActionStatus = "failed"
	ActionStatusCancelled ActionStatus = "cancelled"
)

type TargetType string

const (
	TargetTypeHost    TargetType = "host"
	TargetTypeUser    TargetType = "user"
	TargetTypeIP      TargetType = "ip"
	TargetTypeProcess TargetType = "process"
)

const (
	FieldActionStatus     = "status"
	FieldActionIncidentID = "incident_id"
	FieldActionTargetAsset = "target_asset_id"
)

type Action struct {
	Key              string         `json:"_key,omitempty"`
	TenantID         string         `json:"tenant_id"`
	Type             ActionType     `json:"type"`
	TargetType       TargetType     `json:"target_type"`
	TargetAssetID    string         `json:"target_asset_id"`
	TargetValue      string         `json:"target_value"`
	IncidentID       string         `json:"incident_id"`
	TriggeredBy      string         `json:"triggered_by"`
	Status           ActionStatus   `json:"status"`
	RequiresApproval bool           `json:"requires_approval"`
	ApprovedBy       *string        `json:"approved_by"`
	ApprovedAt       *time.Time     `json:"approved_at"`
	StartedAt        *time.Time     `json:"started_at"`
	CompletedAt      *time.Time     `json:"completed_at"`
	ResultSummary    string         `json:"result_summary"`
	ResultDetail     map[string]any `json:"result_detail"`
	ExecutionID      string         `json:"execution_id"`
	Params           map[string]any `json:"params"`
	CreatedAt        time.Time      `json:"created_at"`
	UpdatedAt        time.Time      `json:"updated_at"`
	// Frontend alias fields
	Name        string `json:"name"`
	Description string `json:"description"`
	Result      string `json:"result"`
}

type Script struct {
	Key         string    `json:"_key,omitempty"`
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Content     string    `json:"content"`
	Language    string    `json:"language"`
	Tags        []string  `json:"tags"`
	CreatedBy   string    `json:"created_by"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}
