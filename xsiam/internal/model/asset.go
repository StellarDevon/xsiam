package model

import "time"

type AssetType string

const (
	AssetTypeServer     AssetType = "server"
	AssetTypeWorkstation AssetType = "workstation"
	AssetTypeNetwork    AssetType = "network"
	AssetTypeCloud      AssetType = "cloud"
	AssetTypeIoT        AssetType = "iot"
)

const (
	FieldAssetType       = "type"
	FieldAssetRiskLevel  = "risk_level"
	FieldAssetRiskScore  = "risk_score"
	FieldAssetIdentifier = "identifier"
)

type OSInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    string `json:"arch"`
}

type AgentInfo struct {
	AgentID     string    `json:"agent_id"`
	Version     string    `json:"version"`
	Status      string    `json:"status"`
	LastSeen    time.Time `json:"last_seen"`
	PolicyID    string    `json:"policy_id"`
}

type Asset struct {
	Key                string    `json:"_key,omitempty"`
	TenantID           string    `json:"tenant_id"`
	Name               string    `json:"name"`
	Type               AssetType `json:"type"`
	Identifier         string    `json:"identifier"`
	IPAddresses        []string  `json:"ip_addresses"`
	OSInfo             OSInfo    `json:"os_info"`
	Agent              AgentInfo `json:"agent"`
	Department         string    `json:"department"`
	Owner              string    `json:"owner"`
	RiskScore          float64   `json:"risk_score"`
	RiskLevel          string    `json:"risk_level"`
	Importance         string    `json:"importance"`
	IsHoneypot         bool      `json:"is_honeypot"`
	ActiveIncidentCount int      `json:"active_incident_count"`
	OpenVulnCount      int       `json:"open_vuln_count"`
	Tags               []string  `json:"tags"`
	LastSeen           time.Time `json:"last_seen"`
	CreatedAt          time.Time `json:"created_at"`
	UpdatedAt          time.Time `json:"updated_at"`
	// Frontend alias fields
	Hostname string `json:"hostname"`
	IP       string `json:"ip"`
	OS       string `json:"os"`
	Status   string `json:"status"`
}
