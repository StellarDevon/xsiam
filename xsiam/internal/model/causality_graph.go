package model

import "time"

type CausalityNodeType string
type CausalityEdgeType string

const (
	NodeTypeProcess  CausalityNodeType = "process"
	NodeTypeFile     CausalityNodeType = "file"
	NodeTypeNetwork  CausalityNodeType = "network"
	NodeTypeRegistry CausalityNodeType = "registry"
	NodeTypeAlert    CausalityNodeType = "alert"
	NodeTypeUser     CausalityNodeType = "user"
	NodeTypeAsset    CausalityNodeType = "asset"

	EdgeTypeSpawned       CausalityEdgeType = "spawned"
	EdgeTypeWroteFile     CausalityEdgeType = "wrote_file"
	EdgeTypeConnectedTo   CausalityEdgeType = "connected_to"
	EdgeTypeLateralMove   CausalityEdgeType = "lateral_move_to"
	EdgeTypeTriggered     CausalityEdgeType = "triggered_alert"
	EdgeTypeAuthenticated CausalityEdgeType = "authenticated_as"
	EdgeTypeAccessed      CausalityEdgeType = "accessed_resource"
)

const (
	FieldGraphIncidentID = "incident_id"
	FieldGraphCreatedAt  = "created_at"
	FieldGraphConfidence = "confidence"
)

type CausalityNode struct {
	Key         string            `json:"_key,omitempty"`
	NodeID      string            `json:"node_id"`
	IncidentID  string            `json:"incident_id"`
	Type        CausalityNodeType `json:"type"`
	Label       string            `json:"label"`
	Properties  map[string]any    `json:"properties"`
	AlertID     *string           `json:"alert_id"`
	AssetID     *string           `json:"asset_id"`
	IsRootCause bool              `json:"is_root"`
	Severity    *Severity         `json:"severity"`
	CreatedAt   time.Time         `json:"created_at"`
}

type CausalityEdge struct {
	Key        string            `json:"_key,omitempty"`
	From       string            `json:"_from"`
	To         string            `json:"_to"`
	IncidentID string            `json:"incident_id"`
	Type       CausalityEdgeType `json:"type"`
	Timestamp  *time.Time        `json:"timestamp"`
	Weight     float64           `json:"weight"`
}

type CausalityGraph struct {
	GraphID     string          `json:"graph_id"`
	IncidentID  string          `json:"incident_id"`
	TimeWindowH int             `json:"time_window_h"`
	Confidence  float64         `json:"confidence"`
	Nodes       []CausalityNode `json:"nodes"`
	Edges       []CausalityEdge `json:"edges"`
	NodeCount   int             `json:"node_count"`
	EdgeCount   int             `json:"edge_count"`
	GeneratedAt time.Time       `json:"generated_at"`
	CreatedAt   time.Time       `json:"created_at"`
}
