package model

import "time"

type FeedStatus string

const (
	FeedStatusActive   FeedStatus = "active"
	FeedStatusInactive FeedStatus = "inactive"
	FeedStatusError    FeedStatus = "error"
)

type IntelFeed struct {
	Key          string     `json:"_key,omitempty"`
	TenantID     string     `json:"tenant_id"`
	Name         string     `json:"name"`
	Description  string     `json:"description"`
	URL          string     `json:"url"`
	FeedType     string     `json:"feed_type"`
	Status       FeedStatus `json:"status"`
	APIKey       string     `json:"api_key,omitempty"`
	LastSyncAt   *time.Time `json:"last_sync_at"`
	LastSyncJob  string     `json:"last_sync_job"`
	IOCCount     int64      `json:"ioc_count"`
	AutoSync     bool       `json:"auto_sync"`
	SyncInterval int        `json:"sync_interval_hours"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}
