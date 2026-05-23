package model

import "time"

type RiskSignalType string

const (
	SignalImpossibleTravel     RiskSignalType = "impossible_travel"
	SignalTimeAnomaly          RiskSignalType = "time_anomaly"
	SignalNewDevice            RiskSignalType = "new_device"
	SignalAuthFailureRate      RiskSignalType = "auth_failure_rate"
	SignalSensitiveFirstAccess RiskSignalType = "sensitive_first_access"
	SignalPrivilegeAnomaly     RiskSignalType = "privilege_anomaly"
	SignalActiveAlert          RiskSignalType = "active_alert"
	SignalActiveIncident       RiskSignalType = "active_incident"
)

type RiskSignal struct {
	Type       RiskSignalType `json:"type"`
	Score      float64        `json:"score"`
	Detail     string         `json:"detail"`
	DetectedAt time.Time      `json:"detected_at"`
}

type IdentityBaseline struct {
	LoginHoursP95  [2]int    `json:"login_hours_p95"`
	TypicalCities  []string  `json:"typical_cities"`
	KnownDevices   []string  `json:"known_devices"`
	AvgDailyLogins float64   `json:"avg_daily_logins"`
	UpdatedAt      time.Time `json:"updated_at"`
}

const (
	FieldIdentityUserID    = "user_id"
	FieldIdentityRiskScore = "risk_score"
	FieldIdentityUpdatedAt = "updated_at"
)

type IdentityRisk struct {
	Key                  string           `json:"_key,omitempty"`
	UserID               string           `json:"user_id"`
	TenantID             string           `json:"tenant_id"`
	Username             string           `json:"username"`
	Domain               string           `json:"domain"`
	RiskScore            float64          `json:"risk_score"`
	RiskSignals          []RiskSignal     `json:"risk_signals"`
	ActiveRestrictions   []int            `json:"active_restrictions"`
	Baseline             IdentityBaseline `json:"baseline"`
	LastImpossibleTravel *time.Time       `json:"last_impossible_travel"`
	UpdatedAt            time.Time        `json:"updated_at"`
	CreatedAt            time.Time        `json:"created_at"`
}
