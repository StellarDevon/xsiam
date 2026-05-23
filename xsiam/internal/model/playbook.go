package model

import "time"

type PlaybookTriggerType string

const (
	TriggerTypeManual    PlaybookTriggerType = "manual"
	TriggerTypeAlert     PlaybookTriggerType = "alert"
	TriggerTypeIncident  PlaybookTriggerType = "incident"
	TriggerTypeScheduled PlaybookTriggerType = "scheduled"
)

type PlaybookTrigger struct {
	Type       PlaybookTriggerType `json:"type"`
	Conditions map[string]any      `json:"conditions"`
	CronExpr   string              `json:"cron_expr"`
}

type PlaybookNodeType string

const (
	NodeTypeCondition PlaybookNodeType = "condition"
	NodeTypeAction    PlaybookNodeType = "action"
	NodeTypeNotify    PlaybookNodeType = "notify"
	NodeTypeWait      PlaybookNodeType = "wait"
	NodeTypeStart     PlaybookNodeType = "start"
	NodeTypeEnd       PlaybookNodeType = "end"
)

type PlaybookNode struct {
	ID       string           `json:"id"`
	Type     PlaybookNodeType `json:"type"`
	Label    string           `json:"label"`
	Config   map[string]any   `json:"config"`
	Position map[string]float64 `json:"position"`
}

type PlaybookEdge struct {
	ID     string `json:"id"`
	Source string `json:"source"`
	Target string `json:"target"`
	Label  string `json:"label"`
}

type PlaybookCanvas struct {
	Nodes []PlaybookNode `json:"nodes"`
	Edges []PlaybookEdge `json:"edges"`
}

type Playbook struct {
	Key        string          `json:"_key,omitempty"`
	TenantID   string          `json:"tenant_id"`
	Name       string          `json:"name"`
	Description string         `json:"description"`
	Trigger    PlaybookTrigger `json:"trigger"`
	Canvas     PlaybookCanvas  `json:"canvas"`
	IsEnabled  bool            `json:"is_enabled"`
	RunCount   int64           `json:"run_count"`
	LastRunAt  *time.Time      `json:"last_run_at"`
	CreatedBy  string          `json:"created_by"`
	CreatedAt  time.Time       `json:"created_at"`
	UpdatedAt  time.Time       `json:"updated_at"`
	// Frontend alias fields
	TriggerType string `json:"trigger_type"`
	Status      string `json:"status"`
	LastRun     string `json:"last_run"`
}
