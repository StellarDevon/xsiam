package etl

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"text/template"
	"xsiam/internal/model"
	"xsiam/internal/repository"

	"go.uber.org/zap"
)

// ActionExecutor applies individual ETL actions to a log entry.
type ActionExecutor struct {
	assetRepo *repository.AssetRepo
	iocRepo   *repository.IocRepo
	log       *zap.Logger
}

// NewActionExecutor constructs an ActionExecutor.
// assetRepo and iocRepo may be nil — the corresponding lookup actions will
// no-op silently rather than returning an error.
func NewActionExecutor(assetRepo *repository.AssetRepo, iocRepo *repository.IocRepo, log *zap.Logger) *ActionExecutor {
	return &ActionExecutor{assetRepo: assetRepo, iocRepo: iocRepo, log: log}
}

// ApplyActions executes all actions in order against entry.
// Returns (modified entry, drop).  drop==true means the event should be
// discarded and not written to any storage backend.
func (ex *ActionExecutor) ApplyActions(ctx context.Context, entry *model.LogEntry, actions []model.ETLAction) (*model.LogEntry, bool) {
	for _, a := range actions {
		var drop bool
		entry, drop = ex.apply(ctx, entry, a)
		if drop || entry == nil {
			return nil, true
		}
	}
	return entry, false
}

func (ex *ActionExecutor) apply(ctx context.Context, e *model.LogEntry, a model.ETLAction) (*model.LogEntry, bool) {
	if e.Fields == nil {
		e.Fields = make(map[string]any)
	}

	switch a.Type {

	case model.ETLActionSetField:
		field, _ := a.Params["field"].(string)
		if field == "" {
			break
		}
		value, _ := a.Params["value"].(string)
		if strings.Contains(value, "{{") {
			if tmpl, err := template.New("").Parse(value); err == nil {
				if rendered, err := renderTmpl(tmpl, e); err == nil {
					value = rendered
				}
			}
		}
		e.Fields[field] = value

	case model.ETLActionRenameField:
		from, _ := a.Params["from"].(string)
		to, _ := a.Params["to"].(string)
		if from != "" && to != "" {
			if v, ok := e.Fields[from]; ok {
				e.Fields[to] = v
				delete(e.Fields, from)
			}
		}

	case model.ETLActionDeleteField:
		field, _ := a.Params["field"].(string)
		if field != "" {
			delete(e.Fields, field)
		}

	case model.ETLActionParseJSON:
		srcField, _ := a.Params["src_field"].(string)
		if srcField == "" {
			srcField = "raw_log"
		}
		raw := entryFieldStr(e, srcField)
		if raw == "" {
			break
		}
		var parsed map[string]any
		if err := json.Unmarshal([]byte(raw), &parsed); err == nil {
			for k, v := range parsed {
				e.Fields[k] = v
			}
		}

	case model.ETLActionGrok:
		srcField, _ := a.Params["src_field"].(string)
		if srcField == "" {
			srcField = "raw_log"
		}
		raw := entryFieldStr(e, srcField)
		if raw == "" {
			break
		}
		pattern, _ := a.Params["pattern"].(string)
		if pattern == "" {
			break
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			ex.log.Warn("etl grok: invalid pattern", zap.String("pattern", pattern), zap.Error(err))
			break
		}
		names := re.SubexpNames()
		if matches := re.FindStringSubmatch(raw); matches != nil {
			for i, name := range names {
				if name != "" && i < len(matches) && matches[i] != "" {
					e.Fields[name] = matches[i]
				}
			}
		}

	case model.ETLActionLookupAsset:
		if ex.assetRepo == nil {
			break
		}
		target := e.Hostname
		if target == "" {
			target = e.SourceIP
		}
		if target == "" {
			break
		}
		asset, err := ex.assetRepo.FindByHostnameOrIP(ctx, e.TenantID, target)
		if err != nil || asset == nil {
			break
		}
		e.Fields["asset_key"] = asset.Key
		e.Fields["asset_type"] = string(asset.Type)
		e.Fields["asset_risk_score"] = asset.RiskScore
		e.Fields["asset_department"] = asset.Department
		e.Fields["asset_os"] = asset.OSInfo.Name

	case model.ETLActionLookupThreat:
		if ex.iocRepo == nil {
			break
		}
		candidates := collectIOCCandidates(e)
		for _, val := range candidates {
			if val == "" {
				continue
			}
			iocs, err := ex.iocRepo.Search(ctx, e.TenantID, val, 10)
			if err != nil || len(iocs) == 0 {
				continue
			}
			ioc := iocs[0] // first match wins
			e.Fields["ioc_match"] = true
			e.Fields["ioc_verdict"] = string(ioc.Verdict)
			e.Fields["ioc_type"] = string(ioc.Type)
			e.Fields["ioc_confidence"] = ioc.Confidence
			e.Fields["ioc_value"] = ioc.Value
			break
		}

	case model.ETLActionSetDataset:
		ds, _ := a.Params["dataset"].(string)
		if ds != "" {
			e.Dataset = ds
		}

	case model.ETLActionSetKind:
		switch v := a.Params["kind"].(type) {
		case float64:
			e.Kind = uint8(v)
		case int:
			e.Kind = uint8(v)
		}

	case model.ETLActionDropEvent:
		return nil, true
	}

	return e, false
}

// collectIOCCandidates returns the set of values to check against the IOC database.
func collectIOCCandidates(e *model.LogEntry) []string {
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		if v != "" && !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	add(e.SourceIP)
	if e.Fields != nil {
		add(fmt.Sprintf("%v", e.Fields["dst_ip"]))
		add(fmt.Sprintf("%v", e.Fields["file_hash"]))
		add(fmt.Sprintf("%v", e.Fields["domain"]))
		add(fmt.Sprintf("%v", e.Fields["url"]))
	}
	return out
}

// renderTmpl executes a pre-compiled template with the entry's fields as context.
// Template keys: all entry.Fields + hostname, src_ip, agent_id, session_id,
// dataset, kind, kind_name, tenant_id.
func renderTmpl(tmpl *template.Template, e *model.LogEntry) (string, error) {
	ctx := map[string]any{
		"hostname":   e.Hostname,
		"src_ip":     e.SourceIP,
		"agent_id":   e.AgentID,
		"session_id": e.SessionID,
		"dataset":    e.Dataset,
		"kind":       e.Kind,
		"kind_name":  model.KindName(e.Kind),
		"tenant_id":  e.TenantID,
	}
	for k, v := range e.Fields {
		ctx[k] = v
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, ctx); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// entryFieldStr returns the string value of a named field, checking struct-level
// fields first, then e.Fields.
func entryFieldStr(e *model.LogEntry, field string) string {
	switch strings.ToLower(field) {
	case "hostname":
		return e.Hostname
	case "src_ip", "source_ip":
		return e.SourceIP
	case "agent_id":
		return e.AgentID
	case "raw_log":
		return e.RawLog
	case "dataset":
		return e.Dataset
	}
	if e.Fields == nil {
		return ""
	}
	if v, ok := e.Fields[field]; ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}
