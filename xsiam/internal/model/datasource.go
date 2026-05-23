package model

import "time"

type DataSourceStatus string

const (
	DataSourceStatusActive   DataSourceStatus = "active"
	DataSourceStatusInactive DataSourceStatus = "inactive"
	DataSourceStatusError    DataSourceStatus = "error"
)

type DataSource struct {
	Key         string           `json:"_key,omitempty"`
	TenantID    string           `json:"tenant_id"`
	Name        string           `json:"name"`
	Description string           `json:"description"`
	Type        string           `json:"type"`
	Status      DataSourceStatus `json:"status"`
	Config      map[string]any   `json:"config"`
	Tags        []string         `json:"tags"`
	LastEventAt *time.Time       `json:"last_event_at"`
	EventCount  int64            `json:"event_count"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
}
