package model

import "time"

type TenantTier string

const (
	TenantTierSuper TenantTier = "super"
	TenantTierChild TenantTier = "child"
)

const (
	FieldTenantCode     = "tenant_code"
	FieldTenantParentID = "parent_tenant_id"
)

type TenantSettings struct {
	LogRetentionDays int    `json:"log_retention_days"`
	MaxUsers         int    `json:"max_users"`
	AllowCustomRules bool   `json:"allow_custom_rules"`
	WhiteLabelName   string `json:"white_label_name"`
}

type Tenant struct {
	Key            string         `json:"_key,omitempty"`
	TenantID       string         `json:"tenant_id"`
	TenantCode     string         `json:"tenant_code"`
	Name           string         `json:"name"`
	Tier           TenantTier     `json:"tier"`
	ParentTenantID *string        `json:"parent_tenant_id"`
	IsEnabled      bool           `json:"is_enabled"`
	Settings       TenantSettings `json:"settings"`
	CreatedAt      time.Time      `json:"created_at"`
	UpdatedAt      time.Time      `json:"updated_at"`
}

type ResourceScope struct {
	RuleIDs        []string `json:"rule_ids"`
	PlaybookIDs    []string `json:"playbook_ids"`
	ReportIDs      []string `json:"report_ids"`
	AssetGroupIDs  []string `json:"asset_group_ids"`
	DatasetIDs     []string `json:"dataset_ids"`
	IntelSourceIDs []string `json:"intel_source_ids"`
}

type RBACRole struct {
	Key            string        `json:"_key,omitempty"`
	RoleID         string        `json:"role_id"`
	TenantID       string        `json:"tenant_id"`
	Name           string        `json:"name"`
	Permissions    []string      `json:"permissions"`
	ResourceScopes ResourceScope `json:"resource_scopes"`
	Members        []string      `json:"members"`
	IsBuiltin      bool          `json:"is_builtin"`
	CreatedAt      time.Time     `json:"created_at"`
	UpdatedAt      time.Time     `json:"updated_at"`
}
