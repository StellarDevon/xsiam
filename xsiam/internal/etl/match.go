// Package etl implements the XSIAM Extract-Transform-Load pipeline.
//
// # Data flow
//
//	fluent-bit XLOG frame
//	        │
//	        ▼  POST /internal/agent/log  (:18090)
//	  ingest.Handler  ── decode XLOG → []model.LogEntry
//	        │
//	        ├─[always]──► ngx HEC  index = "raw_<tag>"   (raw, unmodified)
//	        │              unless a matching rule has RawWriteMode = etl_only
//	        │
//	        └─[per entry]──► etl.Pipeline.Process(entry, tag)
//	                                │
//	                         RuleEngine: find first enabled rule
//	                         whose Match criteria fire on (entry, tag)
//	                                │
//	                         ActionExecutor: apply rule.Actions in order
//	                                │
//	                         ┌──────┴──────────────────────────────┐
//	                         │                                      │
//	                    ngx HEC                            ArangoDB log_entries
//	               index = rule.Output.NgxIndex          (if rule.Output.WriteArango)
//
// Rules are loaded from the etl_rules ArangoDB collection and hot-reloaded
// every 60 seconds without restarting the server.
package etl

import (
	"fmt"
	"path"
	"strings"
	"xsiam/internal/model"
)

// compiledRule is a Rule with pre-parsed match expressions for fast evaluation.
type compiledRule struct {
	model.ETLRule
	tagGlob     string      // pre-validated glob pattern (empty = match all)
	filterPairs [][2]string // [{field,value},...] from FilterExpr; nil = match all
}

// matchesEntry reports whether rule r applies to entry e arriving with XLOG tag tag.
// All non-empty criteria must match (logical AND).
func matchesEntry(r compiledRule, e *model.LogEntry, tag string) bool {
	// 1. Dataset whitelist
	if len(r.Match.Dataset) > 0 && !containsStr(r.Match.Dataset, e.Dataset) {
		return false
	}
	// 2. Kind whitelist
	if len(r.Match.Kind) > 0 && !containsUint8(r.Match.Kind, e.Kind) {
		return false
	}
	// 3. Tag glob
	if r.tagGlob != "" {
		ok, _ := path.Match(r.tagGlob, tag)
		if !ok {
			return false
		}
	}
	// 4. FilterExpr  — k=v pairs evaluated against the entry
	for _, kv := range r.filterPairs {
		if !fieldEquals(e, kv[0], kv[1]) {
			return false
		}
	}
	return true
}

// fieldEquals checks whether field of e equals val (case-sensitive for values,
// case-insensitive for struct-level field names).
func fieldEquals(e *model.LogEntry, field, val string) bool {
	switch strings.ToLower(field) {
	case "hostname":
		return strings.EqualFold(e.Hostname, val)
	case "agent_id":
		return e.AgentID == val
	case "src_ip", "source_ip":
		return e.SourceIP == val
	case "session_id":
		return e.SessionID == val
	case "dataset":
		return e.Dataset == val
	case "kind":
		return kindNameMatches(e.Kind, val)
	}
	if e.Fields == nil {
		return false
	}
	v, ok := e.Fields[field]
	if !ok {
		return false
	}
	return fmt.Sprintf("%v", v) == val
}

func kindNameMatches(k uint8, s string) bool {
	switch strings.ToLower(s) {
	case "syslog", "0":
		return k == model.LogKindSyslog
	case "process", "1":
		return k == model.LogKindProcess
	case "file", "2":
		return k == model.LogKindFile
	case "registry", "3":
		return k == model.LogKindRegistry
	case "network", "4":
		return k == model.LogKindNetwork
	case "dns", "5":
		return k == model.LogKindDNS
	case "auth", "6":
		return k == model.LogKindAuth
	case "vuln", "7":
		return k == model.LogKindVuln
	case "integrity", "fim", "8":
		return k == model.LogKindIntegrity
	}
	return false
}

// compileRule parses the match expressions of a raw ETLRule into a compiledRule.
func compileRule(r model.ETLRule) compiledRule {
	cr := compiledRule{ETLRule: r}
	// Validate / store the tag glob (path.Match panics on malformed patterns, so
	// we validate up-front and fall back to empty = match-all on error).
	if r.Match.TagPattern != "" {
		if _, err := path.Match(r.Match.TagPattern, ""); err == nil {
			cr.tagGlob = r.Match.TagPattern
		}
	}
	cr.filterPairs = parseFilterExpr(r.Match.FilterExpr)

	// Default RawWriteMode
	if cr.RawWriteMode == "" {
		cr.RawWriteMode = model.RawWriteBoth
	}
	// Default output ngx index
	if cr.Output.NgxIndex == "" {
		cr.Output.NgxIndex = "etl_" + r.RuleID
	}
	return cr
}

// parseFilterExpr splits a "k=v AND k2=v2" expression into [{field,value}] pairs.
// Duplicated from domain/query/service.go to avoid an import cycle.
func parseFilterExpr(expr string) [][2]string {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil
	}
	var pairs [][2]string
	rest := expr
	for {
		idx := strings.Index(strings.ToLower(rest), " and ")
		var cond string
		if idx < 0 {
			cond = rest
			rest = ""
		} else {
			cond = rest[:idx]
			rest = rest[idx+5:]
		}
		cond = strings.TrimSpace(cond)
		if eqIdx := strings.Index(cond, "="); eqIdx > 0 {
			field := strings.TrimSpace(cond[:eqIdx])
			val := strings.Trim(strings.TrimSpace(cond[eqIdx+1:]), `"'`)
			pairs = append(pairs, [2]string{field, val})
		}
		if rest == "" {
			break
		}
	}
	return pairs
}

func containsStr(slice []string, s string) bool {
	for _, v := range slice {
		if v == s {
			return true
		}
	}
	return false
}

func containsUint8(slice []uint8, v uint8) bool {
	for _, x := range slice {
		if x == v {
			return true
		}
	}
	return false
}
