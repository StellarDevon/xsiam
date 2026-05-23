package model

import "time"

type IOCType string

const (
	IOCTypeIP     IOCType = "ip"
	IOCTypeDomain IOCType = "domain"
	IOCTypeURL    IOCType = "url"
	IOCTypeHash   IOCType = "hash"
	IOCTypeEmail  IOCType = "email"
)

type IOCVerdict string

const (
	IOCVerdictMalicious  IOCVerdict = "malicious"
	IOCVerdictSuspicious IOCVerdict = "suspicious"
	IOCVerdictBenign     IOCVerdict = "benign"
	IOCVerdictUnknown    IOCVerdict = "unknown"
)

const (
	FieldIOCType    = "type"
	FieldIOCValue   = "value"
	FieldIOCVerdict = "verdict"
)

type IOC struct {
	Key        string     `json:"_key,omitempty"`
	TenantID   string     `json:"tenant_id"`
	Type       IOCType    `json:"type"`
	Value      string     `json:"value"`
	Verdict    IOCVerdict `json:"verdict"`
	Confidence float64    `json:"confidence"`
	SourceName string     `json:"source_name"`
	FeedID     string     `json:"feed_id"`
	HitCount   int64      `json:"hit_count"`
	LastHitAt  *time.Time `json:"last_hit_at"`
	ExpiresAt  *time.Time `json:"expires_at"`
	IsActive   bool       `json:"is_active"`
	Tags       []string   `json:"tags"`
	CreatedAt  time.Time  `json:"created_at"`
	UpdatedAt  time.Time  `json:"updated_at"`
	// Frontend alias fields
	ThreatName string `json:"threat_name"`
	Active     bool   `json:"active"`
	Severity   string `json:"severity"`
}
