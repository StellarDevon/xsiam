package model

import "time"

type FixStatus string

const (
	FixStatusUnplanned    FixStatus = "unplanned"
	FixStatusPlanned      FixStatus = "planned"
	FixStatusInProgress   FixStatus = "in_progress"
	FixStatusVerifying    FixStatus = "verifying"
	FixStatusFixed        FixStatus = "fixed"
	FixStatusAccepted     FixStatus = "accepted_risk"
	FixStatusCompensating FixStatus = "compensating_control"
)

const (
	FieldExposureAssetID   = "asset_id"
	FieldExposureCveID     = "cve_id"
	FieldExposurePriority  = "priority_score"
	FieldExposureFixStatus = "fix_status"
)

type ExposureScore struct {
	Key                   string     `json:"_key,omitempty"`
	TenantID              string     `json:"tenant_id"`
	AssetID               string     `json:"asset_id"`
	AssetName             string     `json:"asset_name"`
	CveID                 string     `json:"cve_id"`
	CvssScore             float64    `json:"cvss_score"`
	PriorityScore         float64    `json:"priority_score"`
	InWildFactor          float64    `json:"in_wild_factor"`
	ReachabilityFactor    float64    `json:"reachability_factor"`
	AssetImportanceFactor float64    `json:"asset_importance_factor"`
	FixStatus             FixStatus  `json:"fix_status"`
	FixDeadline           *time.Time `json:"fix_deadline"`
	LastScoredAt          time.Time  `json:"last_scored_at"`
	CreatedAt             time.Time  `json:"created_at"`
	UpdatedAt             time.Time  `json:"updated_at"`
}
