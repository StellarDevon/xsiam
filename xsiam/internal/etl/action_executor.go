package etl

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"maps"
	"math/rand/v2"
	"regexp"
	"strconv"
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
	geoipDB   *GeoIPDB     // optional — nil disables lookup_geoip
	dedup     *Deduplicator // optional — nil disables dedup
	luaEngine *LuaEngine   // optional — nil disables custom_lua
	log       *zap.Logger
}

// NewActionExecutor constructs an ActionExecutor.
// All repository/engine parameters may be nil — the corresponding actions
// will no-op silently rather than returning an error.
func NewActionExecutor(
	assetRepo *repository.AssetRepo,
	iocRepo *repository.IocRepo,
	geoipDB *GeoIPDB,
	dedup *Deduplicator,
	luaEngine *LuaEngine,
	log *zap.Logger,
) *ActionExecutor {
	return &ActionExecutor{
		assetRepo: assetRepo,
		iocRepo:   iocRepo,
		geoipDB:   geoipDB,
		dedup:     dedup,
		luaEngine: luaEngine,
		log:       log,
	}
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
			maps.Copy(e.Fields, parsed)
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

	// ── Field manipulation (new) ──────────────────────────────────────────────

	case model.ETLActionCopyKey:
		from, _ := a.Params["from"].(string)
		to, _ := a.Params["to"].(string)
		if from != "" && to != "" {
			if v, ok := e.Fields[from]; ok {
				e.Fields[to] = v
			}
		}

	case model.ETLActionHashKey:
		srcKey, _ := a.Params["src_key"].(string)
		dstKey, _ := a.Params["dst_key"].(string)
		if srcKey == "" || dstKey == "" {
			break
		}
		raw := entryFieldStr(e, srcKey)
		if raw == "" {
			break
		}
		sum := sha256.Sum256([]byte(raw))
		e.Fields[dstKey] = hex.EncodeToString(sum[:])

	case model.ETLActionParseNumber:
		key, _ := a.Params["key"].(string)
		if key == "" {
			break
		}
		raw := entryFieldStr(e, key)
		if raw == "" {
			break
		}
		if i, err := strconv.ParseInt(raw, 10, 64); err == nil {
			e.Fields[key] = i
		} else if f, err := strconv.ParseFloat(raw, 64); err == nil {
			e.Fields[key] = f
		}

	// ── Field filtering (new) ─────────────────────────────────────────────────

	case model.ETLActionAllowKeys:
		pattern, _ := a.Params["regex"].(string)
		if pattern == "" {
			break
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			ex.log.Warn("etl allow_keys: invalid regex", zap.String("regex", pattern), zap.Error(err))
			break
		}
		for k := range e.Fields {
			if !re.MatchString(k) {
				delete(e.Fields, k)
			}
		}

	case model.ETLActionBlockKeys:
		pattern, _ := a.Params["regex"].(string)
		if pattern == "" {
			break
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			ex.log.Warn("etl block_keys: invalid regex", zap.String("regex", pattern), zap.Error(err))
			break
		}
		for k := range e.Fields {
			if re.MatchString(k) {
				delete(e.Fields, k)
			}
		}

	// ── Record filtering (new) ────────────────────────────────────────────────

	case model.ETLActionAllowRecords:
		key, _ := a.Params["key"].(string)
		pattern, _ := a.Params["regex"].(string)
		if key == "" || pattern == "" {
			break
		}
		matchCase, _ := a.Params["match_case"].(bool)
		flags := ""
		if !matchCase {
			flags = "(?i)"
		}
		re, err := regexp.Compile(flags + pattern)
		if err != nil {
			ex.log.Warn("etl allow_records: invalid regex", zap.String("regex", pattern), zap.Error(err))
			break
		}
		val := entryFieldStr(e, key)
		if !re.MatchString(val) {
			return nil, true // does not match → drop
		}

	case model.ETLActionBlockRecords:
		key, _ := a.Params["key"].(string)
		pattern, _ := a.Params["regex"].(string)
		if key == "" || pattern == "" {
			break
		}
		matchCase, _ := a.Params["match_case"].(bool)
		flags := ""
		if !matchCase {
			flags = "(?i)"
		}
		re, err := regexp.Compile(flags + pattern)
		if err != nil {
			ex.log.Warn("etl block_records: invalid regex", zap.String("regex", pattern), zap.Error(err))
			break
		}
		val := entryFieldStr(e, key)
		if re.MatchString(val) {
			return nil, true // matches → drop
		}

	// ── Value transformation (new) ────────────────────────────────────────────

	case model.ETLActionRedactValue:
		key, _ := a.Params["key"].(string)
		pattern, _ := a.Params["regex"].(string)
		replacement, _ := a.Params["replacement"].(string)
		if key == "" || pattern == "" {
			break
		}
		if replacement == "" {
			replacement = "***"
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			ex.log.Warn("etl redact_value: invalid regex", zap.String("regex", pattern), zap.Error(err))
			break
		}
		val := entryFieldStr(e, key)
		if val == "" {
			break
		}
		e.Fields[key] = re.ReplaceAllString(val, replacement)

	case model.ETLActionSearchReplace:
		key, _ := a.Params["key"].(string)
		pattern, _ := a.Params["regex"].(string)
		replacement, _ := a.Params["replacement"].(string)
		if key == "" || pattern == "" {
			break
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			ex.log.Warn("etl search_replace: invalid regex", zap.String("regex", pattern), zap.Error(err))
			break
		}
		val := entryFieldStr(e, key)
		if val == "" {
			break
		}
		e.Fields[key] = re.ReplaceAllString(val, replacement)

	// ── Structural transformations (new) ──────────────────────────────────────

	case model.ETLActionFlattenSubrecord:
		key, _ := a.Params["key"].(string)
		prefix, _ := a.Params["prefix"].(string)
		if key == "" {
			break
		}
		sub, ok := e.Fields[key].(map[string]any)
		if !ok {
			break
		}
		delete(e.Fields, key)
		for k, v := range sub {
			e.Fields[prefix+k] = v
		}

	case model.ETLActionNestKeys:
		keyPrefix, _ := a.Params["key_prefix"].(string)
		destKey, _ := a.Params["dest_key"].(string)
		if keyPrefix == "" || destKey == "" {
			break
		}
		nested := map[string]any{}
		var toDelete []string
		for k, v := range e.Fields {
			if subKey, ok := strings.CutPrefix(k, keyPrefix); ok {
				nested[subKey] = v
				toDelete = append(toDelete, k)
			}
		}
		for _, k := range toDelete {
			delete(e.Fields, k)
		}
		if len(nested) > 0 {
			e.Fields[destKey] = nested
		}

	case model.ETLActionDecodeCSV:
		srcKey, _ := a.Params["src_key"].(string)
		if srcKey == "" {
			break
		}
		raw := entryFieldStr(e, srcKey)
		if raw == "" {
			break
		}
		headersRaw, _ := a.Params["headers"].(string)
		var headers []string
		if headersRaw != "" {
			for h := range strings.SplitSeq(headersRaw, ",") {
				headers = append(headers, strings.TrimSpace(h))
			}
		}
		r := csv.NewReader(strings.NewReader(raw))
		records, err := r.Read()
		if err != nil {
			ex.log.Warn("etl decode_csv: parse error", zap.Error(err))
			break
		}
		for i, val := range records {
			k := fmt.Sprintf("col_%d", i)
			if i < len(headers) && headers[i] != "" {
				k = headers[i]
			}
			e.Fields[k] = val
		}

	case model.ETLActionEncodeJSON:
		srcKey, _ := a.Params["src_key"].(string)
		dstKey, _ := a.Params["dst_key"].(string)
		if dstKey == "" {
			break
		}
		var toEncode any
		if srcKey != "" {
			toEncode = e.Fields[srcKey]
		} else {
			toEncode = e.Fields
		}
		b, err := json.Marshal(toEncode)
		if err != nil {
			ex.log.Warn("etl encode_json: marshal error", zap.Error(err))
			break
		}
		e.Fields[dstKey] = string(b)

	case model.ETLActionEncodeCSV:
		headersRaw, _ := a.Params["headers"].(string)
		if headersRaw == "" {
			break
		}
		headers := strings.Split(headersRaw, ",")
		for i, h := range headers {
			headers[i] = strings.TrimSpace(h)
		}
		srcKey, _ := a.Params["src_key"].(string)
		dstKey, _ := a.Params["dst_key"].(string)
		if dstKey == "" {
			dstKey = "csv_output"
		}
		var source map[string]any
		if srcKey != "" {
			sub, ok := e.Fields[srcKey].(map[string]any)
			if !ok {
				break
			}
			source = sub
		} else {
			source = e.Fields
		}
		row := make([]string, len(headers))
		for i, h := range headers {
			if v, ok := source[h]; ok {
				row[i] = fmt.Sprintf("%v", v)
			}
		}
		var buf bytes.Buffer
		w := csv.NewWriter(&buf)
		if err := w.Write(row); err != nil {
			ex.log.Warn("etl encode_csv: write error", zap.Error(err))
			break
		}
		w.Flush()
		e.Fields[dstKey] = strings.TrimRight(buf.String(), "\n")

	case model.ETLActionMultilineJoin:
		srcKey, _ := a.Params["src_key"].(string)
		if srcKey == "" {
			break
		}
		sep, _ := a.Params["separator"].(string)
		if sep == "" {
			sep = "\n"
		}
		val, ok := e.Fields[srcKey]
		if !ok {
			break
		}
		switch v := val.(type) {
		case string:
			// already a string — nothing to do
		case []string:
			e.Fields[srcKey] = strings.Join(v, sep)
		case []any:
			parts := make([]string, len(v))
			for i, item := range v {
				parts[i] = fmt.Sprintf("%v", item)
			}
			e.Fields[srcKey] = strings.Join(parts, sep)
		default:
			_ = v // other types: no-op
		}

	case model.ETLActionSplitRecord:
		srcKey, _ := a.Params["src_key"].(string)
		if srcKey == "" {
			break
		}
		sep, _ := a.Params["separator"].(string)
		if sep == "" {
			sep = ","
		}
		raw := entryFieldStr(e, srcKey)
		if raw == "" {
			break
		}
		segments := strings.Split(raw, sep)
		parts := make([]any, len(segments))
		for i, s := range segments {
			parts[i] = s
		}
		e.Fields[srcKey+"_parts"] = parts
		e.Fields[srcKey] = segments[0]

	case model.ETLActionLiftSubmap:
		srcKey, _ := a.Params["src_key"].(string)
		if srcKey == "" {
			break
		}
		sub, ok := e.Fields[srcKey].(map[string]any)
		if !ok {
			break
		}
		prefix, _ := a.Params["prefix"].(string)
		keepSrc, _ := a.Params["keep_src"].(string)
		for k, v := range sub {
			e.Fields[prefix+k] = v
		}
		if keepSrc != "true" {
			delete(e.Fields, srcKey)
		}

	case model.ETLActionJoinRecords:
		srcKey, _ := a.Params["src_key"].(string)
		fieldsRaw, _ := a.Params["fields"].(string)
		if srcKey == "" || fieldsRaw == "" {
			break
		}
		sep, _ := a.Params["separator"].(string)
		if sep == "" {
			sep = ","
		}
		dstKey, _ := a.Params["dst_key"].(string)
		arr, ok := e.Fields[srcKey].([]any)
		if !ok {
			break
		}
		fieldNames := strings.Fields(strings.ReplaceAll(fieldsRaw, ",", " "))
		for _, fieldName := range fieldNames {
			var joinParts []string
			for _, item := range arr {
				if m, ok := item.(map[string]any); ok {
					joinParts = append(joinParts, fmt.Sprintf("%v", m[fieldName]))
				}
			}
			if len(joinParts) > 0 {
				outKey := fieldName
				if dstKey != "" {
					outKey = dstKey
				}
				e.Fields[outKey] = strings.Join(joinParts, sep)
			}
		}

	// ── Sampling (new) ────────────────────────────────────────────────────────

	case model.ETLActionRandomSample:
		pctRaw, _ := a.Params["percent"]
		var percent float64
		switch v := pctRaw.(type) {
		case float64:
			percent = v
		case int:
			percent = float64(v)
		case string:
			percent, _ = strconv.ParseFloat(v, 64)
		}
		// Keep 'percent'% of records; drop the rest.
		if rand.Float64()*100 >= percent {
			return nil, true
		}

	// ── Deduplication (new, stateful) ─────────────────────────────────────────

	case model.ETLActionDedup:
		if ex.dedup == nil {
			break
		}
		key, _ := a.Params["key"].(string)
		if key == "" {
			break
		}
		windowSec := 60 // default window
		switch v := a.Params["window_seconds"].(type) {
		case float64:
			windowSec = int(v)
		case int:
			windowSec = v
		}
		keyVal := entryFieldStr(e, key)
		if ex.dedup.IsDuplicate(e.TenantID, keyVal, windowSec) {
			return nil, true
		}

	// ── GeoIP enrichment (new) ────────────────────────────────────────────────

	case model.ETLActionLookupGeoIP:
		if ex.geoipDB == nil {
			break
		}
		srcKey, _ := a.Params["src_key"].(string)
		if srcKey == "" {
			srcKey = "src_ip"
		}
		ip := entryFieldStr(e, srcKey)
		if ip == "" {
			break
		}
		rec := ex.geoipDB.Lookup(ip)
		if rec.Country != "" {
			e.Fields["geo_country"] = rec.Country
		}
		if rec.City != "" {
			e.Fields["geo_city"] = rec.City
		}
		if rec.ASN > 0 {
			e.Fields["geo_asn"] = rec.ASN
			e.Fields["geo_asn_org"] = rec.ASNOrg
		}

	// ── Custom Lua script (new) ───────────────────────────────────────────────

	case model.ETLActionCustomLua:
		if ex.luaEngine == nil {
			break
		}
		script, _ := a.Params["script"].(string)
		if script == "" {
			break
		}
		tag, _ := a.Params["_tag"].(string) // injected by pipeline before calling ApplyActions
		result, drop, err := ex.luaEngine.Run(script, e, tag)
		if err != nil {
			ex.log.Warn("etl custom_lua: script error", zap.Error(err))
			break // non-fatal: keep original entry
		}
		if drop {
			return nil, true
		}
		if result != nil {
			e = result
		}
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
	maps.Copy(ctx, e.Fields)
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
