package model

import "time"

const (
	FieldRestrictionUserID  = "user_id"
	FieldRestrictionLevel   = "level"
	FieldRestrictionExpires = "expires_at"
)

var RestrictionThresholds = map[int]float64{1: 70, 2: 80, 3: 85, 4: 90, 5: 95}
var RestrictionExpiry = map[int]time.Duration{
	1: 24 * time.Hour,
	2: 24 * time.Hour,
	3: 8 * time.Hour,
	4: 0,
	5: 0,
}

type PrivilegeRestriction struct {
	Key           string     `json:"_key,omitempty"`
	TenantID      string     `json:"tenant_id"`
	UserID        string     `json:"user_id"`
	Level         int        `json:"level"`
	TriggerSignal string     `json:"trigger_signal"`
	TriggerScore  float64    `json:"trigger_score"`
	AppliedAt     time.Time  `json:"applied_at"`
	ExpiresAt     *time.Time `json:"expires_at"`
	ReleasedAt    *time.Time `json:"released_at"`
	ReleasedBy    *string    `json:"released_by"`
	IsActive      bool       `json:"is_active"`
}
