package model

import "time"

// ── ETL action types ─────────────────────────────────────────────────────────

// ETLActionType enumerates all supported transformation action kinds.
type ETLActionType string

const (
	// ── Field manipulation ────────────────────────────────────────────────────
	ETLActionSetField    ETLActionType = "set_field"    // params: {field, value (template ok)}
	ETLActionRenameField ETLActionType = "rename_field" // params: {from, to}
	ETLActionDeleteField ETLActionType = "delete_field" // params: {field}
	ETLActionCopyKey     ETLActionType = "copy_key"     // params: {from, to} — copies value, keeps original
	ETLActionHashKey     ETLActionType = "hash_key"     // params: {src_key, dst_key} — SHA-256 hex
	ETLActionParseNumber ETLActionType = "parse_number" // params: {key} — string → int64 / float64

	// ── Field filtering (regex-based batch) ──────────────────────────────────
	ETLActionAllowKeys ETLActionType = "allow_keys" // params: {regex} — keep matching keys, delete rest
	ETLActionBlockKeys ETLActionType = "block_keys" // params: {regex} — delete matching keys

	// ── Record filtering (conditional drop) ──────────────────────────────────
	ETLActionAllowRecords ETLActionType = "allow_records" // params: {key, regex, match_case?} — keep matching records
	ETLActionBlockRecords ETLActionType = "block_records" // params: {key, regex, match_case?} — drop matching records

	// ── Value transformation ──────────────────────────────────────────────────
	ETLActionRedactValue   ETLActionType = "redact_value"   // params: {key, regex, replacement?} — default "***"
	ETLActionSearchReplace ETLActionType = "search_replace" // params: {key, regex, replacement}

	// ── Structural transformations ────────────────────────────────────────────
	ETLActionFlattenSubrecord ETLActionType = "flatten_subrecord" // params: {key, prefix?} — nested map → top-level
	ETLActionNestKeys         ETLActionType = "nest_keys"         // params: {key_prefix, dest_key} — top-level → nested
	ETLActionDecodeCSV        ETLActionType = "decode_csv"        // params: {src_key, headers} — CSV string → fields
	ETLActionEncodeJSON       ETLActionType = "encode_json"       // params: {src_key?, dst_key} — object → JSON string
	ETLActionEncodeCSV        ETLActionType = "encode_csv"        // params: {src_key?, headers, dst_key?} — fields → CSV row string
	ETLActionMultilineJoin    ETLActionType = "multiline_join"    // params: {src_key, separator?} — []any → joined string
	ETLActionSplitRecord      ETLActionType = "split_record"      // params: {src_key, separator?} — string → parts slice + first segment
	ETLActionLiftSubmap       ETLActionType = "lift_submap"       // params: {src_key, prefix?, keep_src?} — promote Fields[src_key] (map) one level up
	ETLActionJoinRecords      ETLActionType = "join_records"      // params: {src_key, fields, separator?} — join named fields across []any sub-records

	// ── Parsing / extraction ──────────────────────────────────────────────────
	ETLActionParseJSON ETLActionType = "parse_json" // params: {src_field}
	ETLActionGrok      ETLActionType = "grok"       // params: {src_field, pattern (named-group regex)}

	// ── Sampling & deduplication ──────────────────────────────────────────────
	ETLActionRandomSample ETLActionType = "random_sample" // params: {percent} 0-100 — discard (100-percent)%
	ETLActionDedup        ETLActionType = "dedup"         // params: {key, window_seconds} — drop duplicates in window

	// ── Enrichment ────────────────────────────────────────────────────────────
	ETLActionLookupAsset  ETLActionType = "lookup_asset"  // no params — enriches from assets collection
	ETLActionLookupThreat ETLActionType = "lookup_threat" // no params — enriches from iocs collection
	ETLActionLookupGeoIP  ETLActionType = "lookup_geoip"  // params: {src_key?} default "src_ip" → geo_country/city/asn

	// ── Routing overrides ─────────────────────────────────────────────────────
	ETLActionSetDataset ETLActionType = "set_dataset" // params: {dataset}
	ETLActionSetKind    ETLActionType = "set_kind"    // params: {kind (uint8)}

	// ── Flow control ──────────────────────────────────────────────────────────
	ETLActionDropEvent  ETLActionType = "drop_event"  // no params — discards the event entirely
	ETLActionCustomLua  ETLActionType = "custom_lua"  // params: {script} — Lua 5.1 script via gopher-lua
)

// ETLAction is one step in a rule's action list.
type ETLAction struct {
	Type   ETLActionType  `json:"type"`
	Params map[string]any `json:"params,omitempty"`
}

// ── ETL match criteria ────────────────────────────────────────────────────────

// ETLMatchCriteria defines when a rule fires.
//
// TagPattern, Dataset, Kind are always ANDed together.
// FilterExpr conditions are combined according to FilterMode ("and" or "or").
//
//   - TagPattern  : Go path.Match glob on the XLOG tag  (e.g. "sysmon*")
//   - Dataset     : whitelist of dataset names  (empty = any)
//   - Kind        : whitelist of uint8 kind values  (empty = any)
//   - FilterExpr  : conditions joined by FilterMode. Supported operators:
//       k=v        equal (string)
//       k!=v       not equal
//       k~=pattern  regex match (RE2)
//       k>v        numeric greater-than
//       k<v        numeric less-than
//       k>=v       numeric greater-than-or-equal
//       k<=v       numeric less-than-or-equal
//     Conditions are separated by "AND" (case-insensitive).
//   - FilterMode  : "and" (default) — all conditions must match;
//                   "or"           — any condition suffices.
type ETLMatchCriteria struct {
	TagPattern string   `json:"tag_pattern,omitempty"`
	Dataset    []string `json:"dataset,omitempty"`
	Kind       []uint8  `json:"kind,omitempty"`
	FilterExpr string   `json:"filter_expr,omitempty"`
	FilterMode string   `json:"filter_mode,omitempty"` // "and" (default) | "or"
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

// ETLSink is one destination within an ETLOutput.
//
//   - NgxIndex        : ngx HEC index name (user-defined, e.g. "endpoint_enriched").
//                       If empty, this sink does not write to ngx.
//   - ArangoCollection: ArangoDB collection name (user-defined, e.g. "proc_events").
//                       Empty = do not write to ArangoDB for this sink.
//                       The collection is created automatically with a TTL index
//                       when first used.
//   - TTLDays         : time-to-live in days for ArangoDB documents (0 = no TTL).
//   - Condition       : optional filter expression (same syntax as ETLMatchCriteria.FilterExpr).
//                       When non-empty, the sink only receives records that satisfy
//                       the condition.  Empty = all records go to this sink.
type ETLSink struct {
	NgxIndex         string `json:"ngx_index,omitempty"`
	ArangoCollection string `json:"arango_collection,omitempty"`
	TTLDays          int    `json:"ttl_days,omitempty"`
	Condition        string `json:"condition,omitempty"` // k=v filter (same syntax as FilterExpr)
}

// ETLOutput holds one or more sinks for the ETL-processed event.
//
// Backward-compatible flat fields (NgxIndex, ArangoCollection, TTLDays) are
// still honoured: if Sinks is empty they are automatically promoted to a
// single ETLSink at compile time (see etl.compileRule).
type ETLOutput struct {
	// ── Preferred: multi-sink routing ────────────────────────────────────────
	Sinks []ETLSink `json:"sinks,omitempty"`

	// ── Legacy flat fields (single-sink shorthand, still accepted) ───────────
	NgxIndex         string `json:"ngx_index,omitempty"`
	ArangoCollection string `json:"arango_collection,omitempty"`
	TTLDays          int    `json:"ttl_days,omitempty"`
}

// ── ETL rule ──────────────────────────────────────────────────────────────────

// ProcessingMode controls how rules are applied during pipeline evaluation.
type ProcessingMode string

const (
	// ProcessingFirstMatch stops evaluation at the first matching rule (default).
	ProcessingFirstMatch ProcessingMode = "first_match"
	// ProcessingSequential applies ALL sequential-mode rules that match, in
	// priority order, chaining the output of each as input to the next.
	// Only the last sequential rule in the chain determines Output routing.
	ProcessingSequential ProcessingMode = "sequential"
)

// ETLRule is an ArangoDB document in the etl_rules collection.
// Each rule describes: which events to match, how to transform them, and
// where to write the result.
//
// Processing order:
//  1. Event arrives at :18090 from fluent-bit.
//  2. Raw event is ALWAYS written to ngx index "raw_<tag>"  (unconditional),
//     EXCEPT when the matching rule sets RawWriteMode to etl_only.
//  3. Enabled ETL rules are evaluated in ascending Priority order.
//  4. ProcessingMode governs evaluation:
//     • "first_match" (default): first matching rule is applied; rest skipped.
//     • "sequential": ALL sequential rules that match are applied in order,
//       each rule's output becoming the next rule's input.
//  5. If the rule's RawWriteMode is raw_only, processing stops after step 2.
//  6. The transformed event is written to Output.Sinks (multi-destination).
//     Each sink may carry an optional Condition to further filter the record.
//  7. If NO rule matches, ONLY the raw event is written to ngx "raw_<tag>".
//     Nothing is written to ArangoDB — there is no ArangoDB fallback.
//
// Example — enrich Windows process events with multi-sink output:
//
//	{
//	  "rule_id":         "win-process-enrich",
//	  "name":            "Windows Process Enrichment",
//	  "is_enabled":      true,
//	  "priority":        100,
//	  "processing_mode": "first_match",
//	  "match":           { "tag_pattern": "winevent.*", "kind": [1] },
//	  "raw_write_mode":  "both",
//	  "actions":         [{"type":"lookup_asset"},{"type":"lookup_threat"}],
//	  "output":          { "sinks": [
//	    { "ngx_index": "win_process_enriched", "arango_collection": "proc_events", "ttl_days": 90 },
//	    { "ngx_index": "win_process_raw",      "condition": "ioc_match = true" }
//	  ]}
//	}
type ETLRule struct {
	Key            string           `json:"_key,omitempty"`
	RuleID         string           `json:"rule_id"`                   // unique, human-readable slug
	Name           string           `json:"name"`
	Description    string           `json:"description,omitempty"`
	TenantID       string           `json:"tenant_id"`
	IsEnabled      bool             `json:"is_enabled"`
	Priority       int              `json:"priority"`                  // lower = applied earlier
	ProcessingMode ProcessingMode   `json:"processing_mode,omitempty"` // "first_match"(default) | "sequential"
	Match          ETLMatchCriteria `json:"match"`
	RawWriteMode   RawWriteMode     `json:"raw_write_mode"`            // controls raw event persistence
	Actions        []ETLAction      `json:"actions"`
	Output         ETLOutput        `json:"output"`
	CreatedAt      time.Time        `json:"created_at"`
	UpdatedAt      time.Time        `json:"updated_at"`
	CreatedBy      string           `json:"created_by,omitempty"`
}
