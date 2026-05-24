package model

import "time"

type ReportTemplateType string

const (
	ReportTemplateWeekly   ReportTemplateType = "weekly"
	ReportTemplateMonthly  ReportTemplateType = "monthly"
	ReportTemplateCustom   ReportTemplateType = "custom"
	ReportTemplateExec     ReportTemplateType = "executive"
)

type ReportStatus string

const (
	ReportStatusPending    ReportStatus = "pending"
	ReportStatusScheduled  ReportStatus = "scheduled"
	ReportStatusGenerating ReportStatus = "generating"
	ReportStatusReady      ReportStatus = "ready"
	ReportStatusFailed     ReportStatus = "failed"
)

type Report struct {
	Key          string             `json:"_key,omitempty"`
	TenantID     string             `json:"tenant_id"`
	Name         string             `json:"name"`
	Description  string             `json:"description"`
	TemplateType ReportTemplateType `json:"template_type"`
	Status       ReportStatus       `json:"status"`
	Schedule     string             `json:"schedule,omitempty"`  // "daily"|"weekly"|"monthly"|"once"
	NextRunAt    *time.Time         `json:"next_run_at,omitempty"`
	Config       map[string]any     `json:"config"`
	DownloadURL  string             `json:"download_url"`
	GeneratedAt  *time.Time         `json:"generated_at"`
	CreatedBy    string             `json:"created_by"`
	CreatedAt    time.Time          `json:"created_at"`
	UpdatedAt    time.Time          `json:"updated_at"`
}
