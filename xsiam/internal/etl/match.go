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
//	                    ngx HEC                            ArangoDB (user-defined collection)
//	               index = rule.Output.NgxIndex         (if rule.Output.ArangoCollection != "")
//
// Rules are loaded from the etl_rules ArangoDB collection and hot-reloaded
// every 60 seconds without restarting the server.
package etl

import (
	"fmt"
	"path"
	"regexp"
	"strconv"
	"strings"
	"xsiam/internal/model"
)

// ── filterCondition ───────────────────────────────────────────────────────────

// filterOp enumerates the supported filter operators.
type filterOp string

const (
	opEqual        filterOp = "="
	opNotEqual     filterOp = "!="
	opRegex        filterOp = "~="
	opGreater      filterOp = ">"
	opLess         filterOp = "<"
	opGreaterEqual filterOp = ">="
	opLessEqual    filterOp = "<="
)

// filterCondition is a single parsed filter condition from FilterExpr.
type filterCondition struct {
	field    string
	op       filterOp
	value    string
	compiled *regexp.Regexp // non-nil only for opRegex
}

// matches reports whether condition c is satisfied by entry e.
func (c filterCondition) matches(e *model.LogEntry) bool {
	raw := fieldStr(e, c.field)

	switch c.op {
	case opEqual:
		return raw == c.value

	case opNotEqual:
		return raw != c.value

	case opRegex:
		if c.compiled == nil {
			return false
		}
		return c.compiled.MatchString(raw)

	case opGreater, opLess, opGreaterEqual, opLessEqual:
		lhs, errL := strconv.ParseFloat(raw, 64)
		rhs, errR := strconv.ParseFloat(c.value, 64)
		if errL != nil || errR != nil {
			return false // non-numeric — skip
		}
		switch c.op {
		case opGreater:
			return lhs > rhs
		case opLess:
			return lhs < rhs
		case opGreaterEqual:
			return lhs >= rhs
		case opLessEqual:
			return lhs <= rhs
		}
	}
	return false
}

// ── compiledRule ─────────────────────────────────────────────────────────────

// compiledRule is a Rule with pre-parsed match expressions for fast evaluation.
type compiledRule struct {
	model.ETLRule
	tagGlob     string            // pre-validated glob pattern (empty = match all)
	filterConds []filterCondition // parsed FilterExpr conditions
	filterOrMode bool             // true when FilterMode == "or"
}

// ── matchesEntry ─────────────────────────────────────────────────────────────

// matchesEntry reports whether rule r applies to entry e arriving with XLOG tag tag.
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
	// 4. FilterExpr conditions
	if len(r.filterConds) > 0 {
		if r.filterOrMode {
			// OR: any condition must match
			anyMatch := false
			for _, c := range r.filterConds {
				if c.matches(e) {
					anyMatch = true
					break
				}
			}
			if !anyMatch {
				return false
			}
		} else {
			// AND (default): all conditions must match
			for _, c := range r.filterConds {
				if !c.matches(e) {
					return false
				}
			}
		}
	}
	return true
}

// ── compileRule ───────────────────────────────────────────────────────────────

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

	cr.filterConds = parseFilterExpr(r.Match.FilterExpr)
	cr.filterOrMode = strings.ToLower(r.Match.FilterMode) == "or"

	// Default RawWriteMode
	if cr.RawWriteMode == "" {
		cr.RawWriteMode = model.RawWriteBoth
	}
	// Default output ngx index (when Output is fully empty)
	if cr.Output.NgxIndex == "" && cr.Output.ArangoCollection == "" {
		cr.Output.NgxIndex = "etl_" + r.RuleID
	}
	return cr
}

// ── parseFilterExpr ───────────────────────────────────────────────────────────

// parseFilterExpr splits a filter expression into individual filterConditions.
//
// Grammar (conditions separated by " AND ", case-insensitive):
//
//	k=v       equal
//	k!=v      not equal
//	k~=pat    regex match (RE2)
//	k>v       numeric greater-than
//	k<v       numeric less-than
//	k>=v      numeric greater-than-or-equal
//	k<=v      numeric less-than-or-equal
//
// Values are stripped of surrounding quotes (' or ").
func parseFilterExpr(expr string) []filterCondition {
	expr = strings.TrimSpace(expr)
	if expr == "" {
		return nil
	}

	// Split on " AND " (case-insensitive)
	parts := splitAND(expr)
	var conds []filterCondition
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		c, err := parseCondition(part)
		if err != nil {
			continue // silently skip malformed conditions
		}
		conds = append(conds, c)
	}
	return conds
}

// parseCondition parses a single "field op value" condition string.
// Operators are checked longest-first to avoid ambiguity (>= before >).
func parseCondition(s string) (filterCondition, error) {
	ops := []filterOp{opGreaterEqual, opLessEqual, opNotEqual, opRegex, opGreater, opLess, opEqual}
	for _, op := range ops {
		idx := strings.Index(s, string(op))
		if idx <= 0 {
			continue
		}
		field := strings.TrimSpace(s[:idx])
		value := strings.TrimSpace(s[idx+len(op):])
		value = strings.Trim(value, `"'`)
		if field == "" {
			continue
		}
		c := filterCondition{field: field, op: op, value: value}
		if op == opRegex {
			re, err := regexp.Compile(value)
			if err != nil {
				return filterCondition{}, fmt.Errorf("invalid regex %q: %w", value, err)
			}
			c.compiled = re
		}
		return c, nil
	}
	return filterCondition{}, fmt.Errorf("no operator found in condition %q", s)
}

// splitAND splits expr on " AND " (case-insensitive boundaries).
func splitAND(expr string) []string {
	lower := strings.ToLower(expr)
	var parts []string
	start := 0
	for {
		idx := strings.Index(lower[start:], " and ")
		if idx < 0 {
			parts = append(parts, expr[start:])
			break
		}
		parts = append(parts, expr[start:start+idx])
		start += idx + 5 // len(" and ")
	}
	return parts
}

// ── field value helpers ───────────────────────────────────────────────────────

// fieldStr returns the string value of a named field from entry e.
// Struct-level fields are checked first (case-insensitive), then e.Fields.
func fieldStr(e *model.LogEntry, field string) string {
	switch strings.ToLower(field) {
	case "hostname":
		return e.Hostname
	case "agent_id":
		return e.AgentID
	case "src_ip", "source_ip":
		return e.SourceIP
	case "session_id":
		return e.SessionID
	case "dataset":
		return e.Dataset
	case "kind":
		return kindName(e.Kind)
	case "tenant_id":
		return e.TenantID
	}
	if e.Fields == nil {
		return ""
	}
	if v, ok := e.Fields[field]; ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

// fieldEquals is kept for backward compatibility with existing call sites.
func fieldEquals(e *model.LogEntry, field, val string) bool {
	return fieldStr(e, field) == val
}

func kindName(k uint8) string {
	switch k {
	case model.LogKindSyslog:
		return "syslog"
	case model.LogKindProcess:
		return "process"
	case model.LogKindFile:
		return "file"
	case model.LogKindRegistry:
		return "registry"
	case model.LogKindNetwork:
		return "network"
	case model.LogKindDNS:
		return "dns"
	case model.LogKindAuth:
		return "auth"
	case model.LogKindVuln:
		return "vuln"
	case model.LogKindIntegrity:
		return "integrity"
	}
	return fmt.Sprintf("%d", k)
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

// ── slice helpers ─────────────────────────────────────────────────────────────

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
