package model

import "time"

type AgentPolicy struct {
	Key             string         `json:"_key,omitempty"`
	TenantID        string         `json:"tenant_id"`
	Name            string         `json:"name"`
	Description     string         `json:"description"`
	IsDefault       bool           `json:"is_default"`
	CollectionRules map[string]any `json:"collection_rules"`
	Settings        map[string]any `json:"settings"`
	AgentCount      int            `json:"agent_count"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
}
