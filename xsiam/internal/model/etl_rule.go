package model

import "time"

// ── ETL action types ─────────────────────────────────────────────────────────

// ETLActionType enumerates all supported transformation action kinds.
type ETLActionType string

const (
	// Field manipulation
	ETLActionSetField    ETLActionType = "set_field"    // params: {field, value (template ok)}
	ETLActionRenameField ETLActionType = "rename_field" // params: {from, to}
	ETLActionDeleteField ETLActionType = "delete_field" // params: {field}

	// Parsing / extraction
	ETLActionParseJSON ETLActionType = "parse_json" // params: {src_field}
	ETLActionGrok      ETLActionType = "grok"       // params: {src_field, pattern (named-group regex)}

	// Enrichment (ArangoDB lookups)
	ETLActionLookupAsset  ETLActionType = "lookup_asset"  // no params — enriches from assets collection
	ETLActionLookupThreat ETLActionType = "lookup_threat" // no params — enriches from iocs collection

	// Routing overrides
	ETLActionSetDataset ETLActionType = "set_dataset" // params: {dataset}
	ETLActionSetKind    ETLActionType = "set_kind"    // params: {kind (uint8)}

	// Flow control
	ETLActionDropEvent ETLActionType = "drop_event" // no params — discards the event entirely
)

// ETLAction is one step in a rule's action list.
type ETLAction struct {
	Type   ETLActionType  `json:"type"`
	Params map[string]any `json:"params,omitempty"`
}

// ── ETL match criteria ────────────────────────────────────────────────────────

// ETLMatchCriteria defines when a rule fires. All non-empty fields are ANDed.
//
//   - TagPattern  : Go path.Match glob on the XLOG tag  (e.g. "sysmon*")
//   - Dataset     : whitelist of dataset names  (empty = any)
//   - Kind        : whitelist of uint8 kind values  (empty = any)
//   - FilterExpr  : "k=v AND k2=v2" field equality chain (XQL | filter syntax)
type ETLMatchCriteria struct {
	TagPattern string   `json:"tag_pattern,omitempty"`
	Dataset    []string `json:"dataset,omitempty"`
	Kind       []uint8  `json:"kind,omitempty"`
	FilterExpr string   `json:"filter_expr,omitempty"`
}

// ── Raw-write mode ────────────────────────────────────────────────────────────

// RawWriteMode controls whether the original (pre-ETL) event is also persisted
// to ngx alongside the ETL-transformed copy.
//
//	both      — write both the raw event (raw_<tag> index) AND the ETL result
//	etl_only  — write only the ETL-transformed result; discard the raw event
//	raw_only  — write only the raw event; bypass ETL processing entirely
//	            (equivalent to not matching the rule at all, but explicit)
type RawWriteMode string

const (
	RawWriteBoth    RawWriteMode = "both"     // default
	RawWriteETLOnly RawWriteMode = "etl_only" // raw suppressed after ETL
	RawWriteRawOnly RawWriteMode = "raw_only" // ETL skipped, only raw written
)

// ── Output target ─────────────────────────────────────────────────────────────

// ETLOutput describes where the ETL-processed event should be written.
//
//   - NgxIndex   : ngx HEC index name (customer-defined, e.g. "endpoint_enriched")
//                  If empty, defaults to "etl_<dataset>".
//   - WriteArango: whether to also write to ArangoDB log_entries (for XQL queries)
//                  Defaults to true.
type ETLOutput struct {
	NgxIndex    string `json:"ngx_index"`             // ngx target index name
	WriteArango bool   `json:"write_arango"`           // also write to ArangoDB log_entries
}

// ── ETL rule ──────────────────────────────────────────────────────────────────

// ETLRule is an ArangoDB document in the etl_rules collection.
// Each rule describes: which events to match, how to transform them, and
// where to write the result.
//
// Processing order:
//  1. Event arrives at :18090 from fluent-bit.
//  2. raw event is written to ngx  index "raw_<tag>"  (always, unless a matching
//     rule sets RawWriteMode to etl_only).
//  3. Enabled ETL rules are evaluated in ascending Priority order.
//  4. The first matching rule is applied (actions executed in order).
//  5. If the rule's RawWriteMode is raw_only, processing stops here.
//  6. The transformed event is written to  ngx index Output.NgxIndex
//     and optionally to ArangoDB log_entries if Output.WriteArango == true.
//
// Example — enrich Windows process events and store in a custom ngx index:
//
//	{
//	  "rule_id":       "win-process-enrich",
//	  "name":          "Windows Process Enrichment",
//	  "is_enabled":    true,
//	  "priority":      100,
//	  "match":         { "tag_pattern": "winevent.*", "kind": [1] },
//	  "raw_write_mode":"both",
//	  "actions":       [{"type":"lookup_asset"},{"type":"lookup_threat"}],
//	  "output":        { "ngx_index": "win_process_enriched", "write_arango": true }
//	}
type ETLRule struct {
	Key          string           `json:"_key,omitempty"`
	RuleID       string           `json:"rule_id"`              // unique, human-readable slug
	Name         string           `json:"name"`
	Description  string           `json:"description,omitempty"`
	TenantID     string           `json:"tenant_id"`
	IsEnabled    bool             `json:"is_enabled"`
	Priority     int              `json:"priority"`             // lower = applied earlier; first match wins
	Match        ETLMatchCriteria `json:"match"`
	RawWriteMode RawWriteMode     `json:"raw_write_mode"`       // controls raw event persistence
	Actions      []ETLAction      `json:"actions"`
	Output       ETLOutput        `json:"output"`
	CreatedAt    time.Time        `json:"created_at"`
	UpdatedAt    time.Time        `json:"updated_at"`
	CreatedBy    string           `json:"created_by,omitempty"`
}
