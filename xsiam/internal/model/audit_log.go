package model

import "time"

const (
	FieldAuditResourceType = "resource_type"
	FieldAuditResourceID   = "resource_id"
	FieldAuditCreatedAt    = "created_at"
)

type AuditLog struct {
	Key          string    `json:"_key,omitempty"`
	TenantID     string    `json:"tenant_id"`
	OperatorID   string    `json:"operator_id"`
	OperatorName string    `json:"operator_name"`
	Action       string    `json:"action"`
	Resource     string    `json:"resource"`
	ResourceType string    `json:"resource_type"`
	ResourceID   string    `json:"resource_id"`
	ResourceName string    `json:"resource_name"`
	OldValue     any       `json:"old_value"`
	NewValue     any       `json:"new_value"`
	Detail       any       `json:"detail"`
	IPAddress    string    `json:"ip_address"`
	UserAgent    string    `json:"user_agent"`
	CreatedAt    time.Time `json:"created_at"`
}
