package model

import "time"

type RuleType   string
type RuleStatus string

const (
	RuleTypeBIOC RuleType = "bioc"
	RuleTypeIOC  RuleType = "ioc"
	RuleTypeUEBA RuleType = "ueba"

	RuleStatusDraft      RuleStatus = "draft"
	RuleStatusTesting    RuleStatus = "testing"
	RuleStatusActive     RuleStatus = "active"
	RuleStatusDisabled   RuleStatus = "disabled"
	RuleStatusDeprecated RuleStatus = "deprecated"
)

var RuleStatusTransitions = map[RuleStatus][]RuleStatus{
	RuleStatusDraft:      {RuleStatusTesting, RuleStatusDeprecated},
	RuleStatusTesting:    {RuleStatusActive, RuleStatusDraft},
	RuleStatusActive:     {RuleStatusDisabled},
	RuleStatusDisabled:   {RuleStatusActive, RuleStatusDeprecated},
	RuleStatusDeprecated: {},
}

const (
	FieldRuleID     = "rule_id"
	FieldRuleType   = "rule_type"
	FieldRuleStatus = "status"
	FieldMitreTech  = "mitre_technique"
)

type RuleDefinition struct {
	Sequence   []BIOCEvent       `json:"sequence,omitempty"`
	TimeWindow string            `json:"time_window,omitempty"`
	IocType    string            `json:"ioc_type,omitempty"`
	IocValues  []string          `json:"ioc_values,omitempty"`
	Metric     string            `json:"metric,omitempty"`
	Threshold  float64           `json:"threshold,omitempty"`
	Baseline   string            `json:"baseline,omitempty"`
	Source     string            `json:"source,omitempty"`
	Condition  string            `json:"condition,omitempty"`
	IOCPattern string            `json:"ioc_pattern,omitempty"`
}

type BIOCEvent struct {
	EventType  string            `json:"event_type"`
	Conditions map[string]string `json:"conditions"`
}

type RuleTestResult struct {
	RuleID         string    `json:"rule_id"`
	RuleName       string    `json:"rule_name"`
	Status         string    `json:"status"`
	MatchCount     int       `json:"matched_count"`
	SampleMatches  []string  `json:"sample_matches"`
	ReplayedAt     string    `json:"replayed_at"`
	FalsePositives int       `json:"false_positives"`
	TestedAt       time.Time `json:"tested_at"`
	TimeRangeH     int       `json:"time_range_h"`
	Note           string    `json:"note"`
}

type DetectionRule struct {
	Key               string          `json:"_key,omitempty"`
	RuleID            string          `json:"rule_id"`
	TenantID          string          `json:"tenant_id"`
	Name              string          `json:"name"`
	Description       string          `json:"description"`
	RuleType          RuleType        `json:"rule_type"`
	Status            RuleStatus      `json:"status"`
	Severity          Severity        `json:"severity"`
	MitreTactic       string          `json:"mitre_tactic"`
	MitreTechnique    string          `json:"mitre_technique"`
	Definition        RuleDefinition  `json:"definition"`
	TestResult        *RuleTestResult `json:"test_result"`
	HitCount          int64           `json:"hit_count"`
	FalsePositiveRate float64         `json:"false_positive_rate"`
	LastHitAt         *time.Time      `json:"last_hit_at"`
	CreatedBy         string          `json:"created_by"`
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`
	// Frontend alias fields
	MitreTactics    []string `json:"mitre_tactics"`
	MitreTechniques []string `json:"mitre_techniques"`
	Query           string   `json:"query"`
}
