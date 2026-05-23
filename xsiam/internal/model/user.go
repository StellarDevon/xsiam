package model

import "time"

type UserRole string

const (
	UserRoleAdmin   UserRole = "admin"
	UserRoleAnalyst UserRole = "analyst"
	UserRoleViewer  UserRole = "viewer"
)

const (
	FieldUserEmail    = "email"
	FieldUserTenantID = "tenant_id"
)

type User struct {
	Key          string    `json:"_key,omitempty"`
	TenantID     string    `json:"tenant_id"`
	Username     string    `json:"username"`
	Email        string    `json:"email"`
	PasswordHash string    `json:"password_hash,omitempty"`
	Role         UserRole  `json:"role"`
	DisplayName  string    `json:"display_name"`
	IsEnabled    bool      `json:"is_enabled"`
	LastLoginAt  *time.Time `json:"last_login_at"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}
