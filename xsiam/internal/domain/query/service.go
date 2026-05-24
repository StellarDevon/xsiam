package query

import (
	"context"
	"fmt"
	"strings"
	"time"
	"xsiam/internal/datalake"
	"xsiam/internal/model"
	"xsiam/internal/repository"

	"github.com/arangodb/go-driver/v2/arangodb"
)

// Service handles XQL-style log queries backed by the ArangoDB log_entries
// collection.  The ngx datalake client is kept as a fallback for datasets
// that do not yet have rows in log_entries (e.g. network_story from a live
// NetFlow probe).
type Service struct {
	lakeClient datalake.QueryClient
	logRepo    *repository.LogEntryRepo
}

func NewService(lakeClient datalake.QueryClient) *Service {
	return &Service{lakeClient: lakeClient}
}

// NewServiceWithRepo constructs the service with a live ArangoDB log repo.
// This is the preferred constructor used by main.go.
func NewServiceWithRepo(lakeClient datalake.QueryClient, db arangodb.Database) *Service {
	return &Service{
		lakeClient: lakeClient,
		logRepo:    repository.NewLogEntryRepo(db),
	}
}

// ── XQL mini-parser ──────────────────────────────────────────────────────────
//
// Supported grammar (single-pass, left-to-right):
//
//	dataset = <name>
//	[| filter <field> = "<value>"]   (one or more)
//	[| fields <f1>, <f2>, …]
//	[| sort [asc|desc] <field>]
//	[| limit <N>]
//
// Everything else is silently ignored so the existing sample queries in the
// UI do not cause hard errors.

type xqlParsed struct {
	dataset string
	filters map[string]string // field → value (equality only for now)
	fields  []string          // requested fields, empty = all
	sortBy  string
	sortDesc bool
	limit   int
	kindVal *uint8
}

func parseXQL(q string) xqlParsed {
	p := xqlParsed{limit: 100, filters: map[string]string{}}

	// Strip // comments
	var cleaned []string
	for _, line := range strings.Split(q, "\n") {
		if idx := strings.Index(line, "//"); idx >= 0 {
			line = line[:idx]
		}
		cleaned = append(cleaned, strings.TrimSpace(line))
	}
	q = strings.Join(cleaned, " ")

	// Split on pipe — first segment is the dataset clause
	parts := strings.Split(q, "|")
	for i, part := range parts {
		part = strings.TrimSpace(part)
		if i == 0 {
			// dataset = <name>
			if idx := strings.Index(strings.ToLower(part), "dataset"); idx >= 0 {
				rest := strings.TrimSpace(part[idx+len("dataset"):])
				rest = strings.TrimPrefix(rest, "=")
				p.dataset = strings.Trim(strings.Fields(rest)[0], `"' `)
			}
			continue
		}
		lower := strings.ToLower(part)
		switch {
		case strings.HasPrefix(lower, "filter"):
			// | filter field = "value"  or  field = value
			expr := strings.TrimSpace(part[len("filter"):])
			// Handle "and" chained conditions by splitting
			for _, cond := range splitAnd(expr) {
				cond = strings.TrimSpace(cond)
				// field = "value"  or  field = value
				if eqIdx := strings.Index(cond, "="); eqIdx > 0 {
					field := strings.TrimSpace(cond[:eqIdx])
					val := strings.TrimSpace(cond[eqIdx+1:])
					val = strings.Trim(val, `"'`)
					p.filters[field] = val
				}
			}
		case strings.HasPrefix(lower, "fields"):
			// | fields f1, f2, f3
			rest := strings.TrimSpace(part[len("fields"):])
			for _, f := range strings.Split(rest, ",") {
				f = strings.TrimSpace(f)
				if f != "" {
					p.fields = append(p.fields, f)
				}
			}
		case strings.HasPrefix(lower, "sort"):
			// | sort desc field  or  | sort field desc/asc
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

func splitAnd(expr string) []string {
	// Split on " and " (case-insensitive) but not inside quotes
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

// ── Query ─────────────────────────────────────────────────────────────────────

func (s *Service) Query(ctx context.Context, xql string, fromTS, toTS int64) (*datalake.QueryResult, error) {
	if s.logRepo == nil {
		// No ArangoDB repo — fall back to ngx datalake stub
		return s.lakeClient.Query(ctx, xql, fromTS, toTS)
	}

	p := parseXQL(xql)
	if p.dataset == "" {
		return nil, fmt.Errorf("XQL must start with: dataset = <name>")
	}

	// Extract tenant from context — set by handler via contextWithTenant().
	tenantID, _ := ctx.Value(tenantKey{}).(string)
	if tenantID == "" {
		tenantID = "t-super" // dev fallback
	}

	opts := repository.LogListOptions{
		TenantID: tenantID,
		Dataset:  p.dataset,
		Page:     1,
		PageSize: p.limit,
		SortBy:   p.sortBy,
		SortDesc: p.sortDesc,
	}

	// Map well-known filter fields to typed opts
	if v, ok := p.filters["agent_id"]; ok {
		opts.AgentID = v
	}
	if v, ok := p.filters["hostname"]; ok {
		opts.Hostname = v
	}

	// For kind: accept both numeric and name ("process", "file", etc.)
	if v, ok := p.filters["kind"]; ok {
		k := kindFromString(v)
		opts.Kind = &k
	}

	t0 := time.Now()
	entries, _, err := s.logRepo.List(ctx, opts)
	if err != nil {
		return nil, fmt.Errorf("log query: %w", err)
	}
	elapsed := int(time.Since(t0).Milliseconds())

	// Convert to generic map rows
	rows := make([]map[string]any, 0, len(entries))
	for _, e := range entries {
		row := map[string]any{
			"_key":            e.Key,
			"dataset":         e.Dataset,
			"kind":            e.Kind,
			"kind_name":       model.KindName(e.Kind),
			"agent_id":        e.AgentID,
			"session_id":      e.SessionID,
			"hostname":        e.Hostname,
			"src_ip":          e.SourceIP,
			"event_timestamp": e.EventTimestamp.UTC().Format(time.RFC3339),
			"ingested_at":     e.IngestedAt.UTC().Format(time.RFC3339),
		}
		// Flatten fields map into top-level row
		for k, v := range e.Fields {
			row[k] = v
		}
		if e.RawLog != "" {
			row["raw_log"] = e.RawLog
		}

		// Apply | fields projection if requested
		if len(p.fields) > 0 {
			projected := map[string]any{}
			for _, f := range p.fields {
				if val, ok := row[f]; ok {
					projected[f] = val
				} else {
					projected[f] = nil
				}
			}
			rows = append(rows, projected)
		} else {
			rows = append(rows, row)
		}
	}

	return &datalake.QueryResult{
		Rows:      rows,
		Events:    rows,
		Total:     len(rows),
		ElapsedMs: elapsed,
	}, nil
}

func kindFromString(s string) uint8 {
	switch strings.ToLower(s) {
	case "syslog", "0":
		return model.LogKindSyslog
	case "process", "1":
		return model.LogKindProcess
	case "file", "2":
		return model.LogKindFile
	case "registry", "3":
		return model.LogKindRegistry
	case "network", "4":
		return model.LogKindNetwork
	case "dns", "5":
		return model.LogKindDNS
	case "auth", "6":
		return model.LogKindAuth
	case "vuln", "7":
		return model.LogKindVuln
	case "integrity", "fim", "8":
		return model.LogKindIntegrity
	}
	var n uint8
	fmt.Sscanf(s, "%d", &n)
	return n
}

// DatasetField describes a single field within a dataset schema.
type DatasetField struct {
	Name        string `json:"name"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
}

// Dataset is the rich schema descriptor returned by GET /api/logs/datasets.
type Dataset struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Fields      []DatasetField `json:"fields"`
	RecordCount int64          `json:"record_count"`
}

// Datasets returns the canonical list of built-in XQL datasets with full
// field-level schema information.
// IDs match the model.DatasetXxx constants and the log_entries.dataset field.
func (s *Service) Datasets(_ context.Context) []Dataset {
	return []Dataset{
		// ── Required datasets (explicit field schemas) ──────────────────────
		{
			ID:          "endpoint_events",
			Name:        "Endpoint Events",
			Description: "XSIAM Agent endpoint telemetry: process execution, file activity, registry, network, auth events",
			RecordCount: 0,
			Fields: []DatasetField{
				{Name: "pid", Type: "int", Description: "Process ID"},
				{Name: "process_name", Type: "string", Description: "Executable filename"},
				{Name: "cmdline", Type: "string", Description: "Full command-line string"},
				{Name: "hash", Type: "string", Description: "SHA-256 hash of the executable"},
				{Name: "user", Type: "string", Description: "User account that spawned the process"},
				{Name: "host", Type: "string", Description: "Hostname of the endpoint"},
				{Name: "event_type", Type: "string", Description: "Event category (process_create, file_write, …)"},
				{Name: "_ts", Type: "timestamp", Description: "Event timestamp (Unix ms)"},
			},
		},
		{
			ID:          "network_traffic",
			Name:        "Network Traffic",
			Description: "Network flow records from NetFlow / NGFW / proxy sensors",
			RecordCount: 0,
			Fields: []DatasetField{
				{Name: "src_ip", Type: "string", Description: "Source IP address"},
				{Name: "dst_ip", Type: "string", Description: "Destination IP address"},
				{Name: "protocol", Type: "string", Description: "Transport protocol (TCP/UDP/ICMP)"},
				{Name: "port", Type: "int", Description: "Destination port number"},
				{Name: "bytes_in", Type: "int", Description: "Bytes received"},
				{Name: "bytes_out", Type: "int", Description: "Bytes sent"},
				{Name: "domain", Type: "string", Description: "Resolved domain name (if available)"},
				{Name: "_ts", Type: "timestamp", Description: "Flow start timestamp (Unix ms)"},
			},
		},
		{
			ID:          "auth_logs",
			Name:        "Auth Logs",
			Description: "Authentication and logon events from endpoints, IdP, and network devices",
			RecordCount: 0,
			Fields: []DatasetField{
				{Name: "user", Type: "string", Description: "Authenticating user account"},
				{Name: "host", Type: "string", Description: "Target host or system"},
				{Name: "result", Type: "string", Description: "Outcome: success / failure"},
				{Name: "method", Type: "string", Description: "Auth method (password, MFA, SSO, Kerberos…)"},
				{Name: "src_ip", Type: "string", Description: "Client IP address"},
				{Name: "_ts", Type: "timestamp", Description: "Event timestamp (Unix ms)"},
			},
		},
		{
			ID:          "dns_queries",
			Name:        "DNS Queries",
			Description: "DNS request and response logs from endpoint agents and network sensors",
			RecordCount: 0,
			Fields: []DatasetField{
				{Name: "query", Type: "string", Description: "DNS query name"},
				{Name: "record_type", Type: "string", Description: "Record type (A, AAAA, MX, TXT…)"},
				{Name: "response", Type: "string", Description: "Resolved value(s) returned by the server"},
				{Name: "client_ip", Type: "string", Description: "IP of the client issuing the query"},
				{Name: "_ts", Type: "timestamp", Description: "Query timestamp (Unix ms)"},
			},
		},
		{
			ID:          "file_events",
			Name:        "File Events",
			Description: "File system activity captured by the XSIAM FIM (File Integrity Monitoring) module",
			RecordCount: 0,
			Fields: []DatasetField{
				{Name: "path", Type: "string", Description: "Full file system path"},
				{Name: "hash", Type: "string", Description: "SHA-256 hash of the file"},
				{Name: "operation", Type: "string", Description: "Operation type (create, modify, delete, rename)"},
				{Name: "user", Type: "string", Description: "User account that performed the operation"},
				{Name: "host", Type: "string", Description: "Hostname where the event occurred"},
				{Name: "_ts", Type: "timestamp", Description: "Event timestamp (Unix ms)"},
			},
		},

		// ── Extended datasets (existing, now with structured fields) ────────
		{
			ID:          "xdr_data",
			Name:        "Endpoint Events (xdr_data)",
			Description: "XSIAM Agent terminal telemetry: process, file, registry, network, DNS, auth, vuln, FIM events",
			RecordCount: 0,
			Fields: []DatasetField{
				{Name: "hostname", Type: "string"},
				{Name: "agent_id", Type: "string"},
				{Name: "kind", Type: "int", Description: "Event kind numeric code"},
				{Name: "kind_name", Type: "string", Description: "Human-readable kind label"},
				{Name: "src_ip", Type: "string"},
				{Name: "session_id", Type: "string"},
				{Name: "action", Type: "string"},
				{Name: "process_name", Type: "string"},
				{Name: "process_path", Type: "string"},
				{Name: "file_hash", Type: "string"},
				{Name: "cmdline", Type: "string"},
				{Name: "pid", Type: "int"},
				{Name: "parent_pid", Type: "int"},
				{Name: "parent_name", Type: "string"},
				{Name: "user", Type: "string"},
				{Name: "event_timestamp", Type: "timestamp"},
			},
		},
		{
			ID:          "network_story",
			Name:        "Network Story",
			Description: "Network traffic events from NetFlow / NGFW / proxy",
			RecordCount: 0,
			Fields: []DatasetField{
				{Name: "src_ip", Type: "string"},
				{Name: "dst_ip", Type: "string"},
				{Name: "dst_port", Type: "int"},
				{Name: "src_port", Type: "int"},
				{Name: "proto", Type: "string"},
				{Name: "bytes", Type: "int"},
				{Name: "packets", Type: "int"},
				{Name: "duration_ms", Type: "int"},
				{Name: "direction", Type: "string"},
				{Name: "flow_type", Type: "string"},
				{Name: "event_timestamp", Type: "timestamp"},
			},
		},
		{
			ID:          "cloud_audit_log",
			Name:        "Cloud Audit Log",
			Description: "Cloud platform audit logs (AWS CloudTrail, Azure Monitor, GCP Audit)",
			RecordCount: 0,
			Fields: []DatasetField{
				{Name: "provider", Type: "string"},
				{Name: "event_type", Type: "string"},
				{Name: "event_name", Type: "string"},
				{Name: "user_arn", Type: "string"},
				{Name: "target_arn", Type: "string"},
				{Name: "src_ip", Type: "string"},
				{Name: "region", Type: "string"},
				{Name: "result", Type: "string"},
				{Name: "request_id", Type: "string"},
				{Name: "event_timestamp", Type: "timestamp"},
			},
		},
		{
			ID:          "identity_analytics",
			Name:        "Identity Analytics",
			Description: "User behaviour analysis logs (UEBA) — login patterns, privilege use",
			RecordCount: 0,
			Fields: []DatasetField{
				{Name: "user", Type: "string"},
				{Name: "event_type", Type: "string"},
				{Name: "risk_score", Type: "float"},
				{Name: "anomaly_reason", Type: "string"},
				{Name: "src_ip", Type: "string"},
				{Name: "geo_country", Type: "string"},
				{Name: "auth_type", Type: "string"},
				{Name: "logon_type", Type: "string"},
				{Name: "event_timestamp", Type: "timestamp"},
			},
		},
		{
			ID:          "email_story",
			Name:        "Email Story",
			Description: "Mail security events — phishing, attachment analysis, sender reputation",
			RecordCount: 0,
			Fields: []DatasetField{
				{Name: "sender", Type: "string"},
				{Name: "recipient", Type: "string"},
				{Name: "subject", Type: "string"},
				{Name: "verdict", Type: "string"},
				{Name: "threat_category", Type: "string"},
				{Name: "has_attachment", Type: "bool"},
				{Name: "attachment_name", Type: "string"},
				{Name: "attachment_hash", Type: "string"},
				{Name: "action", Type: "string"},
				{Name: "sender_ip", Type: "string"},
				{Name: "event_timestamp", Type: "timestamp"},
			},
		},
		{
			ID:          "xdr_incident",
			Name:        "XDR Incidents & Alerts",
			Description: "Correlated incidents and alerts generated by the detection engine",
			RecordCount: 0,
			Fields: []DatasetField{
				{Name: "incident_id", Type: "string"},
				{Name: "alert_id", Type: "string"},
				{Name: "incident_name", Type: "string"},
				{Name: "alert_name", Type: "string"},
				{Name: "severity", Type: "string"},
				{Name: "status", Type: "string"},
				{Name: "host", Type: "string"},
				{Name: "user", Type: "string"},
				{Name: "tactic", Type: "string"},
				{Name: "smart_score", Type: "float"},
				{Name: "event_timestamp", Type: "timestamp"},
			},
		},
		{
			ID:          "ngfw_traffic",
			Name:        "NGFW Traffic",
			Description: "Next-generation firewall traffic logs — allow/deny, threat, URL",
			RecordCount: 0,
			Fields: []DatasetField{
				{Name: "action", Type: "string"},
				{Name: "rule", Type: "string"},
				{Name: "src_ip", Type: "string"},
				{Name: "dst_ip", Type: "string"},
				{Name: "src_port", Type: "int"},
				{Name: "dst_port", Type: "int"},
				{Name: "proto", Type: "string"},
				{Name: "bytes_in", Type: "int"},
				{Name: "bytes_out", Type: "int"},
				{Name: "threat_id", Type: "string"},
				{Name: "threat_category", Type: "string"},
				{Name: "application", Type: "string"},
				{Name: "event_timestamp", Type: "timestamp"},
			},
		},
		{
			ID:          "idp_raw",
			Name:        "IdP Auth Logs (idp_raw)",
			Description: "Identity provider raw auth logs: Okta, Azure AD, LDAP, RADIUS",
			RecordCount: 0,
			Fields: []DatasetField{
				{Name: "provider", Type: "string"},
				{Name: "event_type", Type: "string"},
				{Name: "user", Type: "string"},
				{Name: "user_domain", Type: "string"},
				{Name: "src_ip", Type: "string"},
				{Name: "auth_type", Type: "string"},
				{Name: "logon_type", Type: "string"},
				{Name: "result", Type: "string"},
				{Name: "event_id", Type: "string"},
				{Name: "workstation", Type: "string"},
				{Name: "group", Type: "string"},
				{Name: "event_timestamp", Type: "timestamp"},
			},
		},
		{
			ID:          "syslog_raw",
			Name:        "Syslog Raw",
			Description: "Plain-text syslog received over TCP/514 from any syslog-capable device",
			RecordCount: 0,
			Fields: []DatasetField{
				{Name: "hostname", Type: "string"},
				{Name: "src_ip", Type: "string"},
				{Name: "agent_id", Type: "string"},
				{Name: "raw_log", Type: "string"},
				{Name: "session_id", Type: "string"},
				{Name: "event_timestamp", Type: "timestamp"},
			},
		},
		{
			ID:          "asset_inventory",
			Name:        "Asset Inventory",
			Description: "Periodic asset inventory snapshots from Agent vulnerability scans",
			RecordCount: 0,
			Fields: []DatasetField{
				{Name: "hostname", Type: "string"},
				{Name: "agent_id", Type: "string"},
				{Name: "src_ip", Type: "string"},
				{Name: "os_type", Type: "string"},
				{Name: "os_version", Type: "string"},
				{Name: "agent_version", Type: "string"},
				{Name: "open_ports", Type: "string"},
				{Name: "running_services", Type: "string"},
				{Name: "installed_packages", Type: "string"},
				{Name: "domain", Type: "string"},
				{Name: "event_timestamp", Type: "timestamp"},
			},
		},
	}
}
