package model

import "time"

type AgentStatus string
type DeviceHostType string

const (
	AgentStatusOnline       AgentStatus = "online"
	AgentStatusOffline      AgentStatus = "offline"
	AgentStatusInstalling   AgentStatus = "installing"
	AgentStatusUninstalling AgentStatus = "uninstalling"
	AgentStatusError        AgentStatus = "error"
)

const (
	DeviceHostTypeServer DeviceHostType = "server"
	DeviceHostTypePC     DeviceHostType = "pc"
)

const (
	DeviceProtocolWZCP = "wzcp"
)

const (
	FieldDeviceAgentID         = "agent_id"
	FieldDeviceAgentStatus     = "agent_status"
	FieldDeviceHeartbeat       = "last_heartbeat"
	FieldDeviceTenantStatus    = "tenant_id,agent_status"
	FieldDeviceIsConnected     = "is_connected"
	FieldDeviceLastHeartbeat   = "last_heartbeat"
	FieldDeviceTenantHeartbeat = "tenant_id,last_heartbeat"
	FieldDeviceAssetID         = "asset_id"
	FieldDevicePolicyID        = "policy_id"
	FieldDeviceGatewayID       = "gateway_id"
	FieldDeviceHostType        = "host_type"
	FieldDeviceInstalledAt     = "installed_at"
)

type Device struct {
	Key             string         `json:"_key,omitempty"`
	DeviceID        string         `json:"device_id"`
	TenantID        string         `json:"tenant_id"`
	Hostname        string         `json:"hostname"`
	HostType        DeviceHostType `json:"host_type"`
	IP              string         `json:"ip"`
	IPAddresses     []string       `json:"ip_addresses"`
	MacAddresses    []string       `json:"mac_addresses"`
	OSType          string         `json:"os_type"`
	OSVersion       string         `json:"os_version"`
	AgentVersion    string         `json:"agent_version"`
	AgentStatus     AgentStatus    `json:"agent_status"`
	IsConnected     bool           `json:"is_connected"`
	AgentID         string         `json:"agent_id"`
	PolicyID        string         `json:"policy_id"`
	AssetID         string         `json:"asset_id"`
	GatewayID       string         `json:"gateway_id"`
	Protocol        string         `json:"protocol"`
	ProtocolVersion int            `json:"protocol_version"`
	InstalledAt     time.Time      `json:"installed_at"`
	LastHeartbeat   *time.Time     `json:"last_heartbeat"`
	EnrolledAt      time.Time      `json:"enrolled_at"`
	CreatedAt       time.Time      `json:"created_at"`
	UpdatedAt       time.Time      `json:"updated_at"`
	// Frontend alias fields
	OS       string `json:"os"`
	Status   string `json:"status"`
	LastSeen string `json:"last_seen"`
}
