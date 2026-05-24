package datalake

import (
	"fmt"
	"strings"
)

// NgxTranslator converts XSIAM XQL queries to ngx SPL2 syntax.
//
// Mapping table:
//
//	XQL clause                      →  SPL2 output
//	──────────────────────────────────────────────────────────────
//	dataset = <name>                →  search index=<name>
//	| filter k = "v"               →  | where k="v"
//	| filter k=v AND k2=v2         →  | where k="v" AND k2="v2"
//	| fields f1, f2                →  | fields f1,f2
//	| sort desc <field>            →  | sort -<field>
//	| sort asc  <field>            →  | sort +<field>
//	| limit N                      →  | head N
//
// Unknown or unsupported XQL stages are silently dropped, consistent with
// how the ArangoDB-backed query.Service handles them.
type NgxTranslator struct{}

// NewNgxTranslator constructs an NgxTranslator.
func NewNgxTranslator() *NgxTranslator { return &NgxTranslator{} }

// Translate implements Translator for the ngx SPL2 backend.
func (t *NgxTranslator) Translate(xql string) (string, error) {
	p := parseXQLForNgx(xql)
	if p.dataset == "" {
		return "", fmt.Errorf("ngx translator: XQL must start with: dataset = <name>")
	}

	var sb strings.Builder

	// Base search clause
	sb.WriteString("search index=")
	sb.WriteString(p.dataset)

	// Filter stages → SPL2 where
	for _, cond := range p.conditions {
		sb.WriteString(fmt.Sprintf(` | where %s="%s"`, cond[0], cond[1]))
	}

	// Fields projection
	if len(p.fields) > 0 {
		sb.WriteString(" | fields ")
		sb.WriteString(strings.Join(p.fields, ","))
	}

	// Sort
	if p.sortBy != "" {
		if p.sortDesc {
			sb.WriteString(" | sort -")
		} else {
			sb.WriteString(" | sort +")
		}
		sb.WriteString(p.sortBy)
	}

	// Limit → head
	if p.limit > 0 {
		sb.WriteString(fmt.Sprintf(" | head %d", p.limit))
	}

	return sb.String(), nil
}

// ── Private XQL parser (scoped to datalake package) ──────────────────────────
//
// This mirrors the grammar in internal/domain/query/service.go but lives here
// to avoid a circular import (datalake ← domain/query ← datalake).
// The two parsers intentionally share the same grammar; changes to one should
// be reflected in the other.

type ngxParsed struct {
	dataset    string
	conditions [][2]string // [{field, value}, ...]  — ordered for deterministic output
	fields     []string
	sortBy     string
	sortDesc   bool
	limit      int
}

func parseXQLForNgx(q string) ngxParsed {
	p := ngxParsed{limit: 100}

	// Strip // comments
	var cleaned []string
	for _, line := range strings.Split(q, "\n") {
		if idx := strings.Index(line, "//"); idx >= 0 {
			line = line[:idx]
		}
		cleaned = append(cleaned, strings.TrimSpace(line))
	}
	q = strings.Join(cleaned, " ")

	parts := strings.Split(q, "|")
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if i == 0 {
			if idx := strings.Index(strings.ToLower(part), "dataset"); idx >= 0 {
				rest := strings.TrimSpace(part[idx+len("dataset"):])
				rest = strings.TrimPrefix(rest, "=")
				toks := strings.Fields(rest)
				if len(toks) > 0 {
					p.dataset = strings.Trim(toks[0], `"' `)
				}
			}
			continue
		}
		lower := strings.ToLower(part)
		switch {
		case strings.HasPrefix(lower, "filter"):
			expr := strings.TrimSpace(part[len("filter"):])
			for _, cond := range ngxSplitAnd(expr) {
				cond = strings.TrimSpace(cond)
				if eqIdx := strings.Index(cond, "="); eqIdx > 0 {
					field := strings.TrimSpace(cond[:eqIdx])
					val := strings.TrimSpace(cond[eqIdx+1:])
					val = strings.Trim(val, `"'`)
					p.conditions = append(p.conditions, [2]string{field, val})
				}
			}
		case strings.HasPrefix(lower, "fields"):
			rest := strings.TrimSpace(part[len("fields"):])
			for _, f := range strings.Split(rest, ",") {
				f = strings.TrimSpace(f)
				if f != "" {
					p.fields = append(p.fields, f)
				}
			}
		case strings.HasPrefix(lower, "sort"):
			rest := strings.Fields(strings.TrimSpace(part[len("sort"):]))
			for _, tok := range rest {
				tl := strings.ToLower(tok)
				if tl == "desc" {
					p.sortDesc = true
				} else if tl == "asc" {
					p.sortDesc = false
				} else {
					p.sortBy = tok
				}
			}
		case strings.HasPrefix(lower, "limit"):
			rest := strings.TrimSpace(part[len("limit"):])
			n := 0
			fmt.Sscanf(rest, "%d", &n)
			if n > 0 && n <= 1000 {
				p.limit = n
			}
		}
	}
	return p
}

func ngxSplitAnd(expr string) []string {
	var parts []string
	lower := strings.ToLower(expr)
	for {
		idx := strings.Index(lower, " and ")
		if idx < 0 {
			parts = append(parts, expr)
			break
		}
		parts = append(parts, expr[:idx])
		expr = expr[idx+5:]
		lower = lower[idx+5:]
	}
	return parts
}
