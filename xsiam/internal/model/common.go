package model

type Severity   string
type SourceType string
type RiskLevel  string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

const (
	SourceEndpoint SourceType = "endpoint"
	SourceNetwork  SourceType = "network"
	SourceIdentity SourceType = "identity"
	SourceCloud    SourceType = "cloud"
	SourceEmail    SourceType = "email"
	SourceSyslog   SourceType = "syslog"
)

const (
	FieldSeverity    = "severity"
	FieldStatus      = "status"
	FieldSourceType  = "source_type"
	FieldIncidentID  = "incident_id"
	FieldAssetID     = "asset_id"
	FieldTriggeredAt = "triggered_at"
	FieldCreatedAt   = "created_at"
	FieldUpdatedAt   = "updated_at"
	FieldTenantID    = "tenant_id"
)

type PageMeta struct {
	Total    int64 `json:"total"`
	Page     int   `json:"page"`
	PageSize int   `json:"page_size"`
	Pages    int   `json:"total_pages"`
}
