package model

import "time"

// UserProfile stores per-user preferences: display_name, email, language, theme.
// One document per user, keyed by user _key (same as User._key).
type UserProfile struct {
	Key         string    `json:"_key,omitempty"`
	UserID      string    `json:"user_id"`       // same as User._key
	TenantID    string    `json:"tenant_id"`
	DisplayName string    `json:"display_name"`
	Email       string    `json:"email"`
	Lang        string    `json:"lang"`          // "zh" | "en"
	Theme       string    `json:"theme"`         // "dark" | "light"
	UpdatedAt   time.Time `json:"updated_at"`
}
