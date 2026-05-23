package model

import "time"

type IncidentStatus string

const (
	IncidentStatusNew         IncidentStatus = "new"
	IncidentStatusInvestigate IncidentStatus = "investigating"
	IncidentStatusInProgress  IncidentStatus = "in_progress"   // SPA alias for investigating
	IncidentStatusContained   IncidentStatus = "contained"
	IncidentStatusResolved    IncidentStatus = "resolved"
	IncidentStatusClosed      IncidentStatus = "closed"
)

const (
	FieldIncidentKey       = "incident_id"
	FieldIncidentSeverity  = FieldSeverity
	FieldIncidentStatus    = FieldStatus
	FieldIncidentSmartScore = "smart_score"
	FieldIncidentAssignee  = "assignee_id"
)

type ScoreFactor struct {
	Dimension string  `json:"dimension"`
	Name      string  `json:"name"`
	Value     float64 `json:"value"`
	Weight    float64 `json:"weight"`
}

type IncidentTimeline struct {
	EventType  string    `json:"event_type"`
	Detail     string    `json:"detail"`
	OperatorID string    `json:"operator_id"`
	OccurredAt time.Time `json:"occurred_at"`
}

type IncidentNote struct {
	NoteID     string    `json:"note_id"`
	Content    string    `json:"content"`
	AuthorID   string    `json:"author_id"`
	AuthorName string    `json:"author_name"`
	CreatedAt  time.Time `json:"created_at"`
}

type Incident struct {
	Key             string             `json:"_key,omitempty"`
	IncidentID      string             `json:"incident_id"`
	TenantID        string             `json:"tenant_id"`
	Name            string             `json:"name"`
	// Title mirrors Name — the SPA reads "title" for display.
	Title           string             `json:"title"`
	Description     string             `json:"description"`
	Severity        Severity           `json:"severity"`
	Status          IncidentStatus     `json:"status"`
	SmartScore      float64            `json:"smart_score"`
	ScoreFactors    []ScoreFactor      `json:"score_factors"`
	AlertIDs        []string           `json:"alert_ids"`
	AlertCount      int                `json:"alert_count"`
	AffectedAssets  []string           `json:"affected_assets"`
	HostCount       int                `json:"host_count"`
	MitreTactics    []string           `json:"mitre_tactics"`
	MitreTechniques []string           `json:"mitre_techniques"`
	// MitreTactic is the primary tactic shown in the table row.
	MitreTactic     string             `json:"mitre_tactic"`
	AssigneeID      *string            `json:"assignee_id"`
	AssigneeName    *string            `json:"assignee_name"`
	// AssignedTo is the display name read by the SPA table.
	AssignedTo      string             `json:"assigned_to"`
	Timeline        []IncidentTimeline `json:"timeline"`
	Notes           []IncidentNote     `json:"notes"`
	FirstSeen       time.Time          `json:"first_seen"`
	LastActivity    time.Time          `json:"last_activity"`
	ResolvedAt      *time.Time         `json:"resolved_at"`
	CreatedAt       time.Time          `json:"created_at"`
	UpdatedAt       time.Time          `json:"updated_at"`
}
