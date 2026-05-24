package etl

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"xsiam/internal/model"
)

// ─── helpers ──────────────────────────────────────────────────────────────────

// newEntry creates a LogEntry with the given fields for use in action tests.
func newEntry(fields map[string]any) *model.LogEntry {
	if fields == nil {
		fields = map[string]any{}
	}
	return &model.LogEntry{
		TenantID: "tenant-test",
		Dataset:  "xdr_data",
		Kind:     model.LogKindProcess,
		Fields:   fields,
	}
}

// applyOne is a convenience wrapper: applies a single action and returns
// (entry, dropped).
func applyOne(t *testing.T, ex *ActionExecutor, entry *model.LogEntry, action model.ETLAction) (*model.LogEntry, bool) {
	t.Helper()
	return ex.ApplyActions(context.Background(), entry, []model.ETLAction{action})
}

// ─── allow_keys ───────────────────────────────────────────────────────────────

func TestActionExecutor_AllowKeys(t *testing.T) {
	ex := NewActionExecutor(nil, nil, nil, nil, nil, nopLog())

	t.Run("keeps_matching_deletes_rest", func(t *testing.T) {
		entry := newEntry(map[string]any{
			"src_ip":   "1.2.3.4",
			"src_port": 443,
			"msg":      "hello",
		})
		out, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionAllowKeys,
			Params: map[string]any{"regex": "^src_"},
		})
		if drop || out == nil {
			t.Fatal("allow_keys should not drop")
		}
		if _, ok := out.Fields["src_ip"]; !ok {
			t.Error("src_ip should be kept")
		}
		if _, ok := out.Fields["src_port"]; !ok {
			t.Error("src_port should be kept")
		}
		if _, ok := out.Fields["msg"]; ok {
			t.Error("msg should be deleted (does not match ^src_)")
		}
	})

	t.Run("empty_regex_noop", func(t *testing.T) {
		entry := newEntry(map[string]any{"a": 1, "b": 2})
		out, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionAllowKeys,
			Params: map[string]any{"regex": ""},
		})
		if drop || out == nil {
			t.Fatal("should not drop")
		}
		// empty regex → break → no fields removed
		if len(out.Fields) != 2 {
			t.Errorf("expected 2 fields unchanged, got %d", len(out.Fields))
		}
	})

	t.Run("invalid_regex_noop", func(t *testing.T) {
		entry := newEntry(map[string]any{"a": 1})
		out, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionAllowKeys,
			Params: map[string]any{"regex": "[invalid"},
		})
		if drop || out == nil {
			t.Fatal("invalid regex should not drop")
		}
		// Field should still be present — action was skipped.
		if _, ok := out.Fields["a"]; !ok {
			t.Error("field 'a' should be unchanged after invalid regex")
		}
	})

	t.Run("all_match_all_kept", func(t *testing.T) {
		entry := newEntry(map[string]any{"foo": 1, "foobar": 2})
		out, _ := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionAllowKeys,
			Params: map[string]any{"regex": "foo"},
		})
		if len(out.Fields) != 2 {
			t.Errorf("expected 2 fields, got %d", len(out.Fields))
		}
	})
}

// ─── block_keys ───────────────────────────────────────────────────────────────

func TestActionExecutor_BlockKeys(t *testing.T) {
	ex := NewActionExecutor(nil, nil, nil, nil, nil, nopLog())

	t.Run("deletes_matching_keeps_rest", func(t *testing.T) {
		entry := newEntry(map[string]any{
			"password":    "secret",
			"passwd_hash": "abc123",
			"username":    "alice",
		})
		out, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionBlockKeys,
			Params: map[string]any{"regex": "pass"},
		})
		if drop || out == nil {
			t.Fatal("block_keys should not drop")
		}
		if _, ok := out.Fields["password"]; ok {
			t.Error("password should be deleted")
		}
		if _, ok := out.Fields["passwd_hash"]; ok {
			t.Error("passwd_hash should be deleted")
		}
		if _, ok := out.Fields["username"]; !ok {
			t.Error("username should be kept")
		}
	})

	t.Run("no_match_all_kept", func(t *testing.T) {
		entry := newEntry(map[string]any{"a": 1, "b": 2})
		out, _ := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionBlockKeys,
			Params: map[string]any{"regex": "^zzz"},
		})
		if len(out.Fields) != 2 {
			t.Errorf("expected 2 fields unchanged, got %d", len(out.Fields))
		}
	})

	t.Run("empty_regex_noop", func(t *testing.T) {
		entry := newEntry(map[string]any{"secret": "val"})
		out, _ := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionBlockKeys,
			Params: map[string]any{"regex": ""},
		})
		if _, ok := out.Fields["secret"]; !ok {
			t.Error("field should be unchanged when regex is empty")
		}
	})

	t.Run("invalid_regex_noop", func(t *testing.T) {
		entry := newEntry(map[string]any{"x": 1})
		out, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionBlockKeys,
			Params: map[string]any{"regex": "[bad"},
		})
		if drop || out == nil {
			t.Fatal("invalid regex should not drop")
		}
		if _, ok := out.Fields["x"]; !ok {
			t.Error("field 'x' should survive invalid regex")
		}
	})
}

// ─── allow_records ────────────────────────────────────────────────────────────

func TestActionExecutor_AllowRecords(t *testing.T) {
	ex := NewActionExecutor(nil, nil, nil, nil, nil, nopLog())

	t.Run("matching_value_kept", func(t *testing.T) {
		entry := newEntry(map[string]any{"severity": "HIGH"})
		out, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionAllowRecords,
			Params: map[string]any{"key": "severity", "regex": "high"},
		})
		// case-insensitive by default
		if drop {
			t.Error("matching record should not be dropped")
		}
		if out == nil {
			t.Error("out should not be nil")
		}
	})

	t.Run("non_matching_value_dropped", func(t *testing.T) {
		entry := newEntry(map[string]any{"severity": "LOW"})
		_, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionAllowRecords,
			Params: map[string]any{"key": "severity", "regex": "^(high|critical)$"},
		})
		if !drop {
			t.Error("non-matching record should be dropped")
		}
	})

	t.Run("case_sensitive_no_match_drops", func(t *testing.T) {
		entry := newEntry(map[string]any{"level": "ERROR"})
		_, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionAllowRecords,
			Params: map[string]any{"key": "level", "regex": "error", "match_case": true},
		})
		// match_case=true → "ERROR" does not match "error"
		if !drop {
			t.Error("case-sensitive mismatch should drop")
		}
	})

	t.Run("missing_key_drops", func(t *testing.T) {
		entry := newEntry(map[string]any{"other": "value"})
		_, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionAllowRecords,
			Params: map[string]any{"key": "severity", "regex": "high"},
		})
		// missing field → empty string does not match → drop
		if !drop {
			t.Error("missing field should cause drop in allow_records")
		}
	})

	t.Run("empty_params_noop", func(t *testing.T) {
		entry := newEntry(map[string]any{"x": "y"})
		_, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionAllowRecords,
			Params: map[string]any{},
		})
		// key="" → break → not dropped
		if drop {
			t.Error("empty params should noop (not drop)")
		}
	})
}

// ─── block_records ────────────────────────────────────────────────────────────

func TestActionExecutor_BlockRecords(t *testing.T) {
	ex := NewActionExecutor(nil, nil, nil, nil, nil, nopLog())

	t.Run("matching_value_dropped", func(t *testing.T) {
		entry := newEntry(map[string]any{"action": "BLOCKED"})
		_, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionBlockRecords,
			Params: map[string]any{"key": "action", "regex": "blocked"},
		})
		// case-insensitive by default
		if !drop {
			t.Error("matching record should be dropped")
		}
	})

	t.Run("non_matching_value_kept", func(t *testing.T) {
		entry := newEntry(map[string]any{"action": "ALLOW"})
		out, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionBlockRecords,
			Params: map[string]any{"key": "action", "regex": "^blocked$"},
		})
		if drop || out == nil {
			t.Error("non-matching record should not be dropped")
		}
	})

	t.Run("case_sensitive_exact_match_drops", func(t *testing.T) {
		entry := newEntry(map[string]any{"status": "blocked"})
		_, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionBlockRecords,
			Params: map[string]any{"key": "status", "regex": "blocked", "match_case": true},
		})
		if !drop {
			t.Error("exact case-sensitive match should drop")
		}
	})

	t.Run("empty_params_noop", func(t *testing.T) {
		entry := newEntry(map[string]any{"x": "y"})
		_, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionBlockRecords,
			Params: map[string]any{},
		})
		if drop {
			t.Error("empty params should noop (not drop)")
		}
	})

	t.Run("missing_key_not_dropped", func(t *testing.T) {
		entry := newEntry(map[string]any{"other": "val"})
		_, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionBlockRecords,
			Params: map[string]any{"key": "nonexistent", "regex": ".*"},
		})
		// empty string matches ".*" — record IS dropped per spec (regex matches empty)
		// this verifies behaviour is consistent with implementation
		if !drop {
			t.Error("regex .* matches empty string → record should be dropped")
		}
	})
}

// ─── copy_key ─────────────────────────────────────────────────────────────────

func TestActionExecutor_CopyKey(t *testing.T) {
	ex := NewActionExecutor(nil, nil, nil, nil, nil, nopLog())

	t.Run("copies_existing_key", func(t *testing.T) {
		entry := newEntry(map[string]any{"original": "data"})
		out, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionCopyKey,
			Params: map[string]any{"from": "original", "to": "copy"},
		})
		if drop || out == nil {
			t.Fatal("copy_key should not drop")
		}
		if out.Fields["original"] != "data" {
			t.Error("original should be preserved")
		}
		if out.Fields["copy"] != "data" {
			t.Errorf("copy should equal 'data', got %v", out.Fields["copy"])
		}
	})

	t.Run("missing_source_no_op", func(t *testing.T) {
		entry := newEntry(map[string]any{})
		out, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionCopyKey,
			Params: map[string]any{"from": "missing", "to": "dest"},
		})
		if drop || out == nil {
			t.Fatal("should not drop")
		}
		if _, ok := out.Fields["dest"]; ok {
			t.Error("dest should not be created when source is missing")
		}
	})

	t.Run("empty_from_noop", func(t *testing.T) {
		entry := newEntry(map[string]any{"a": 1})
		out, _ := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionCopyKey,
			Params: map[string]any{"from": "", "to": "b"},
		})
		if _, ok := out.Fields["b"]; ok {
			t.Error("empty from should noop")
		}
	})
}

// ─── hash_key ─────────────────────────────────────────────────────────────────

func TestActionExecutor_HashKey(t *testing.T) {
	ex := NewActionExecutor(nil, nil, nil, nil, nil, nopLog())

	t.Run("sha256_hex_written_to_dst", func(t *testing.T) {
		const rawVal = "sensitive@example.com"
		entry := newEntry(map[string]any{"email": rawVal})
		out, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionHashKey,
			Params: map[string]any{"src_key": "email", "dst_key": "email_hash"},
		})
		if drop || out == nil {
			t.Fatal("hash_key should not drop")
		}
		sum := sha256.Sum256([]byte(rawVal))
		expected := hex.EncodeToString(sum[:])
		if out.Fields["email_hash"] != expected {
			t.Errorf("expected SHA-256 %q, got %v", expected, out.Fields["email_hash"])
		}
		// Original field should remain.
		if out.Fields["email"] != rawVal {
			t.Error("original field should be unchanged")
		}
	})

	t.Run("missing_src_noop", func(t *testing.T) {
		entry := newEntry(map[string]any{})
		out, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionHashKey,
			Params: map[string]any{"src_key": "nonexistent", "dst_key": "h"},
		})
		if drop || out == nil {
			t.Fatal("should not drop")
		}
		if _, ok := out.Fields["h"]; ok {
			t.Error("dst_key should not be created when src is missing")
		}
	})

	t.Run("empty_dst_key_noop", func(t *testing.T) {
		entry := newEntry(map[string]any{"val": "abc"})
		out, _ := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionHashKey,
			Params: map[string]any{"src_key": "val", "dst_key": ""},
		})
		// No hash field should appear.
		if _, ok := out.Fields[""]; ok {
			t.Error("empty dst_key should noop")
		}
	})
}

// ─── redact_value ─────────────────────────────────────────────────────────────

func TestActionExecutor_RedactValue(t *testing.T) {
	ex := NewActionExecutor(nil, nil, nil, nil, nil, nopLog())

	t.Run("replaces_match_with_default_stars", func(t *testing.T) {
		entry := newEntry(map[string]any{"token": "Bearer abc123xyz"})
		out, drop := applyOne(t, ex, entry, model.ETLAction{
			Type: model.ETLActionRedactValue,
			Params: map[string]any{
				"key":   "token",
				"regex": `[a-zA-Z0-9]{6,}`,
			},
		})
		if drop || out == nil {
			t.Fatal("redact_value should not drop")
		}
		val := out.Fields["token"].(string)
		if strings.Contains(val, "abc123xyz") {
			t.Errorf("original secret should be redacted, got: %q", val)
		}
		if !strings.Contains(val, "***") {
			t.Errorf("expected *** replacement, got: %q", val)
		}
	})

	t.Run("custom_replacement", func(t *testing.T) {
		entry := newEntry(map[string]any{"cc": "4111-1111-1111-1111"})
		out, _ := applyOne(t, ex, entry, model.ETLAction{
			Type: model.ETLActionRedactValue,
			Params: map[string]any{
				"key":         "cc",
				"regex":       `\d`,
				"replacement": "X",
			},
		})
		if out.Fields["cc"] != "XXXX-XXXX-XXXX-XXXX" {
			t.Errorf("expected all digits replaced with X, got %v", out.Fields["cc"])
		}
	})

	t.Run("missing_key_noop", func(t *testing.T) {
		entry := newEntry(map[string]any{})
		out, drop := applyOne(t, ex, entry, model.ETLAction{
			Type: model.ETLActionRedactValue,
			Params: map[string]any{
				"key":   "missing",
				"regex": ".*",
			},
		})
		if drop || out == nil {
			t.Fatal("should not drop for missing key")
		}
	})

	t.Run("empty_key_param_noop", func(t *testing.T) {
		entry := newEntry(map[string]any{"x": "data"})
		out, _ := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionRedactValue,
			Params: map[string]any{"key": "", "regex": "data"},
		})
		if out.Fields["x"] != "data" {
			t.Error("empty key param should noop")
		}
	})
}

// ─── search_replace ───────────────────────────────────────────────────────────

func TestActionExecutor_SearchReplace(t *testing.T) {
	ex := NewActionExecutor(nil, nil, nil, nil, nil, nopLog())

	t.Run("replaces_all_occurrences", func(t *testing.T) {
		entry := newEntry(map[string]any{"msg": "foo bar foo"})
		out, drop := applyOne(t, ex, entry, model.ETLAction{
			Type: model.ETLActionSearchReplace,
			Params: map[string]any{
				"key":         "msg",
				"regex":       "foo",
				"replacement": "baz",
			},
		})
		if drop || out == nil {
			t.Fatal("search_replace should not drop")
		}
		if out.Fields["msg"] != "baz bar baz" {
			t.Errorf("expected 'baz bar baz', got %v", out.Fields["msg"])
		}
	})

	t.Run("no_match_unchanged", func(t *testing.T) {
		entry := newEntry(map[string]any{"msg": "hello world"})
		out, _ := applyOne(t, ex, entry, model.ETLAction{
			Type: model.ETLActionSearchReplace,
			Params: map[string]any{
				"key":         "msg",
				"regex":       "xyz",
				"replacement": "ABC",
			},
		})
		if out.Fields["msg"] != "hello world" {
			t.Errorf("no-match should leave field unchanged, got %v", out.Fields["msg"])
		}
	})

	t.Run("empty_key_noop", func(t *testing.T) {
		entry := newEntry(map[string]any{"data": "abc"})
		out, _ := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionSearchReplace,
			Params: map[string]any{"key": "", "regex": "a", "replacement": "Z"},
		})
		if out.Fields["data"] != "abc" {
			t.Error("empty key should noop")
		}
	})

	t.Run("regex_capture_group_substitution", func(t *testing.T) {
		entry := newEntry(map[string]any{"date": "2024-01-15"})
		out, _ := applyOne(t, ex, entry, model.ETLAction{
			Type: model.ETLActionSearchReplace,
			Params: map[string]any{
				"key":         "date",
				"regex":       `(\d{4})-(\d{2})-(\d{2})`,
				"replacement": "$3/$2/$1",
			},
		})
		if out.Fields["date"] != "15/01/2024" {
			t.Errorf("capture group substitution failed, got %v", out.Fields["date"])
		}
	})
}

// ─── parse_number ─────────────────────────────────────────────────────────────

func TestActionExecutor_ParseNumber(t *testing.T) {
	ex := NewActionExecutor(nil, nil, nil, nil, nil, nopLog())

	t.Run("integer_string_to_int64", func(t *testing.T) {
		entry := newEntry(map[string]any{"count": "42"})
		out, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionParseNumber,
			Params: map[string]any{"key": "count"},
		})
		if drop || out == nil {
			t.Fatal("parse_number should not drop")
		}
		if out.Fields["count"] != int64(42) {
			t.Errorf("expected int64(42), got %T %v", out.Fields["count"], out.Fields["count"])
		}
	})

	t.Run("float_string_to_float64", func(t *testing.T) {
		entry := newEntry(map[string]any{"score": "3.14"})
		out, _ := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionParseNumber,
			Params: map[string]any{"key": "score"},
		})
		if out.Fields["score"] != float64(3.14) {
			t.Errorf("expected float64(3.14), got %T %v", out.Fields["score"], out.Fields["score"])
		}
	})

	t.Run("non_numeric_string_unchanged", func(t *testing.T) {
		entry := newEntry(map[string]any{"label": "abc"})
		out, _ := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionParseNumber,
			Params: map[string]any{"key": "label"},
		})
		// Neither ParseInt nor ParseFloat succeeds → field kept as-is.
		if out.Fields["label"] != "abc" {
			t.Errorf("non-numeric should be unchanged, got %v", out.Fields["label"])
		}
	})

	t.Run("empty_key_noop", func(t *testing.T) {
		entry := newEntry(map[string]any{"n": "1"})
		out, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionParseNumber,
			Params: map[string]any{"key": ""},
		})
		if drop || out == nil {
			t.Fatal("should not drop")
		}
		// Field should still be the original string.
		if out.Fields["n"] != "1" {
			t.Error("empty key should noop")
		}
	})

	t.Run("missing_key_noop", func(t *testing.T) {
		entry := newEntry(map[string]any{})
		out, _ := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionParseNumber,
			Params: map[string]any{"key": "missing"},
		})
		if _, ok := out.Fields["missing"]; ok {
			t.Error("missing key should not be created")
		}
	})
}

// ─── flatten_subrecord ────────────────────────────────────────────────────────

func TestActionExecutor_FlattenSubrecord(t *testing.T) {
	ex := NewActionExecutor(nil, nil, nil, nil, nil, nopLog())

	t.Run("flattens_nested_map_with_prefix", func(t *testing.T) {
		entry := newEntry(map[string]any{
			"proc": map[string]any{
				"name": "cmd.exe",
				"pid":  1234,
			},
		})
		out, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionFlattenSubrecord,
			Params: map[string]any{"key": "proc", "prefix": "proc_"},
		})
		if drop || out == nil {
			t.Fatal("flatten_subrecord should not drop")
		}
		if _, ok := out.Fields["proc"]; ok {
			t.Error("original key 'proc' should be deleted")
		}
		if out.Fields["proc_name"] != "cmd.exe" {
			t.Errorf("expected proc_name=cmd.exe, got %v", out.Fields["proc_name"])
		}
		if out.Fields["proc_pid"] != 1234 {
			t.Errorf("expected proc_pid=1234, got %v", out.Fields["proc_pid"])
		}
	})

	t.Run("no_prefix_flattens_bare", func(t *testing.T) {
		entry := newEntry(map[string]any{
			"net": map[string]any{"dst": "8.8.8.8"},
		})
		out, _ := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionFlattenSubrecord,
			Params: map[string]any{"key": "net", "prefix": ""},
		})
		if _, ok := out.Fields["net"]; ok {
			t.Error("original 'net' key should be removed")
		}
		if out.Fields["dst"] != "8.8.8.8" {
			t.Errorf("expected dst=8.8.8.8, got %v", out.Fields["dst"])
		}
	})

	t.Run("non_map_value_noop", func(t *testing.T) {
		entry := newEntry(map[string]any{"proc": "not_a_map"})
		out, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionFlattenSubrecord,
			Params: map[string]any{"key": "proc", "prefix": "proc_"},
		})
		if drop || out == nil {
			t.Fatal("should not drop for non-map value")
		}
		// key should remain unchanged
		if out.Fields["proc"] != "not_a_map" {
			t.Error("non-map field should be unchanged")
		}
	})

	t.Run("empty_key_noop", func(t *testing.T) {
		entry := newEntry(map[string]any{"x": map[string]any{"a": 1}})
		out, _ := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionFlattenSubrecord,
			Params: map[string]any{"key": "", "prefix": "p_"},
		})
		if _, ok := out.Fields["x"]; !ok {
			t.Error("empty key should noop — original field should remain")
		}
	})
}

// ─── nest_keys ────────────────────────────────────────────────────────────────

func TestActionExecutor_NestKeys(t *testing.T) {
	ex := NewActionExecutor(nil, nil, nil, nil, nil, nopLog())

	t.Run("groups_prefixed_keys_into_submap", func(t *testing.T) {
		entry := newEntry(map[string]any{
			"proc_name": "cmd.exe",
			"proc_pid":  4321,
			"src_ip":    "10.0.0.1",
		})
		out, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionNestKeys,
			Params: map[string]any{"key_prefix": "proc_", "dest_key": "process"},
		})
		if drop || out == nil {
			t.Fatal("nest_keys should not drop")
		}
		// Prefixed fields should be removed from top level.
		if _, ok := out.Fields["proc_name"]; ok {
			t.Error("proc_name should be moved into nested map")
		}
		if _, ok := out.Fields["proc_pid"]; ok {
			t.Error("proc_pid should be moved into nested map")
		}
		// Non-prefixed field should be untouched.
		if out.Fields["src_ip"] != "10.0.0.1" {
			t.Error("src_ip should be unchanged")
		}
		nested, ok := out.Fields["process"].(map[string]any)
		if !ok {
			t.Fatal("dest_key 'process' should be a map[string]any")
		}
		if nested["name"] != "cmd.exe" {
			t.Errorf("expected nested name=cmd.exe, got %v", nested["name"])
		}
		if nested["pid"] != 4321 {
			t.Errorf("expected nested pid=4321, got %v", nested["pid"])
		}
	})

	t.Run("no_matching_keys_no_dest_created", func(t *testing.T) {
		entry := newEntry(map[string]any{"src_ip": "1.1.1.1"})
		out, _ := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionNestKeys,
			Params: map[string]any{"key_prefix": "proc_", "dest_key": "process"},
		})
		if _, ok := out.Fields["process"]; ok {
			t.Error("dest_key should not be created when no keys match")
		}
	})

	t.Run("empty_params_noop", func(t *testing.T) {
		entry := newEntry(map[string]any{"a_foo": 1})
		out, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionNestKeys,
			Params: map[string]any{"key_prefix": "", "dest_key": ""},
		})
		if drop || out == nil {
			t.Fatal("should not drop")
		}
		// Empty params → break → field unchanged.
		if _, ok := out.Fields["a_foo"]; !ok {
			t.Error("field should remain unchanged")
		}
	})
}

// ─── decode_csv ───────────────────────────────────────────────────────────────

func TestActionExecutor_DecodeCSV(t *testing.T) {
	ex := NewActionExecutor(nil, nil, nil, nil, nil, nopLog())

	t.Run("named_headers_applied", func(t *testing.T) {
		entry := newEntry(map[string]any{"csv_line": "alice,30,engineering"})
		out, drop := applyOne(t, ex, entry, model.ETLAction{
			Type: model.ETLActionDecodeCSV,
			Params: map[string]any{
				"src_key": "csv_line",
				"headers": "name, age, dept",
			},
		})
		if drop || out == nil {
			t.Fatal("decode_csv should not drop")
		}
		if out.Fields["name"] != "alice" {
			t.Errorf("expected name=alice, got %v", out.Fields["name"])
		}
		if out.Fields["age"] != "30" {
			t.Errorf("expected age=30, got %v", out.Fields["age"])
		}
		if out.Fields["dept"] != "engineering" {
			t.Errorf("expected dept=engineering, got %v", out.Fields["dept"])
		}
	})

	t.Run("no_headers_uses_col_index", func(t *testing.T) {
		entry := newEntry(map[string]any{"row": "x,y,z"})
		out, _ := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionDecodeCSV,
			Params: map[string]any{"src_key": "row", "headers": ""},
		})
		if out.Fields["col_0"] != "x" {
			t.Errorf("expected col_0=x, got %v", out.Fields["col_0"])
		}
		if out.Fields["col_1"] != "y" {
			t.Errorf("expected col_1=y, got %v", out.Fields["col_1"])
		}
	})

	t.Run("partial_headers_fallback_to_col_index", func(t *testing.T) {
		entry := newEntry(map[string]any{"row": "a,b,c"})
		out, _ := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionDecodeCSV,
			Params: map[string]any{"src_key": "row", "headers": "first"},
		})
		if out.Fields["first"] != "a" {
			t.Errorf("expected first=a, got %v", out.Fields["first"])
		}
		if out.Fields["col_1"] != "b" {
			t.Errorf("expected col_1=b, got %v", out.Fields["col_1"])
		}
	})

	t.Run("missing_src_key_noop", func(t *testing.T) {
		entry := newEntry(map[string]any{})
		out, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionDecodeCSV,
			Params: map[string]any{"src_key": "missing", "headers": "a,b"},
		})
		if drop || out == nil {
			t.Fatal("missing src key should not drop")
		}
		if _, ok := out.Fields["a"]; ok {
			t.Error("no csv parsed — field should not be created")
		}
	})
}

// ─── encode_json ──────────────────────────────────────────────────────────────

func TestActionExecutor_EncodeJSON(t *testing.T) {
	ex := NewActionExecutor(nil, nil, nil, nil, nil, nopLog())

	t.Run("encodes_specific_field_to_json", func(t *testing.T) {
		entry := newEntry(map[string]any{
			"data": map[string]any{"k": "v"},
		})
		out, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionEncodeJSON,
			Params: map[string]any{"src_key": "data", "dst_key": "data_json"},
		})
		if drop || out == nil {
			t.Fatal("encode_json should not drop")
		}
		raw, ok := out.Fields["data_json"].(string)
		if !ok {
			t.Fatalf("data_json should be a string, got %T", out.Fields["data_json"])
		}
		var parsed map[string]any
		if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
			t.Errorf("data_json is not valid JSON: %v", err)
		}
		if parsed["k"] != "v" {
			t.Errorf("expected k=v inside JSON, got %v", parsed)
		}
	})

	t.Run("no_src_key_encodes_all_fields", func(t *testing.T) {
		entry := newEntry(map[string]any{"alpha": 1, "beta": 2})
		out, _ := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionEncodeJSON,
			Params: map[string]any{"src_key": "", "dst_key": "all_json"},
		})
		raw, ok := out.Fields["all_json"].(string)
		if !ok {
			t.Fatalf("all_json should be a string, got %T", out.Fields["all_json"])
		}
		if !strings.Contains(raw, "alpha") {
			t.Errorf("all_json should contain 'alpha', got %q", raw)
		}
	})

	t.Run("empty_dst_key_noop", func(t *testing.T) {
		entry := newEntry(map[string]any{"x": 1})
		out, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionEncodeJSON,
			Params: map[string]any{"src_key": "x", "dst_key": ""},
		})
		if drop || out == nil {
			t.Fatal("should not drop")
		}
		// No field with empty key should appear.
		if _, ok := out.Fields[""]; ok {
			t.Error("empty dst_key should produce no field")
		}
	})
}

// ─── random_sample ────────────────────────────────────────────────────────────

func TestActionExecutor_RandomSample(t *testing.T) {
	ex := NewActionExecutor(nil, nil, nil, nil, nil, nopLog())

	t.Run("100_percent_keeps_all", func(t *testing.T) {
		// At 100%, nothing should be dropped.
		dropped := 0
		for range 1000 {
			entry := newEntry(nil)
			_, drop := applyOne(t, ex, entry, model.ETLAction{
				Type:   model.ETLActionRandomSample,
				Params: map[string]any{"percent": float64(100)},
			})
			if drop {
				dropped++
			}
		}
		if dropped > 0 {
			t.Errorf("100%% sample: expected 0 drops, got %d", dropped)
		}
	})

	t.Run("0_percent_drops_all", func(t *testing.T) {
		// At 0%, all records should be dropped (rand.Float64()*100 >= 0 is always true
		// EXCEPT when rand returns exactly 0.0, which is astronomically rare).
		kept := 0
		for range 1000 {
			entry := newEntry(nil)
			_, drop := applyOne(t, ex, entry, model.ETLAction{
				Type:   model.ETLActionRandomSample,
				Params: map[string]any{"percent": float64(0)},
			})
			if !drop {
				kept++
			}
		}
		// Tolerate at most 1 "kept" due to float edge case (rand == 0.0).
		if kept > 1 {
			t.Errorf("0%% sample: expected ~0 kept, got %d", kept)
		}
	})

	t.Run("50_percent_roughly_half_kept", func(t *testing.T) {
		kept := 0
		const iterations = 10000
		for range iterations {
			entry := newEntry(nil)
			_, drop := applyOne(t, ex, entry, model.ETLAction{
				Type:   model.ETLActionRandomSample,
				Params: map[string]any{"percent": float64(50)},
			})
			if !drop {
				kept++
			}
		}
		// Allow ±15% tolerance for 50% sampling over 10k iterations.
		low, high := int(float64(iterations)*0.35), int(float64(iterations)*0.65)
		if kept < low || kept > high {
			t.Errorf("50%% sample: kept=%d out of %d, expected [%d, %d]", kept, iterations, low, high)
		}
	})

	t.Run("string_percent_parsed", func(t *testing.T) {
		dropped := 0
		for range 100 {
			entry := newEntry(nil)
			_, drop := applyOne(t, ex, entry, model.ETLAction{
				Type:   model.ETLActionRandomSample,
				Params: map[string]any{"percent": "100"},
			})
			if drop {
				dropped++
			}
		}
		if dropped > 0 {
			t.Errorf("string '100' percent: expected 0 drops, got %d", dropped)
		}
	})
}

// ─── dedup ────────────────────────────────────────────────────────────────────

func TestActionExecutor_Dedup(t *testing.T) {
	t.Run("first_occurrence_passes", func(t *testing.T) {
		dedup := NewDeduplicator()
		ex := NewActionExecutor(nil, nil, nil, dedup, nil, nopLog())
		entry := &model.LogEntry{
			TenantID: "t1",
			Fields:   map[string]any{"event_id": "ev-001"},
		}
		_, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionDedup,
			Params: map[string]any{"key": "event_id", "window_seconds": 60},
		})
		if drop {
			t.Error("first occurrence should not be dropped")
		}
	})

	t.Run("duplicate_within_window_dropped", func(t *testing.T) {
		dedup := NewDeduplicator()
		ex := NewActionExecutor(nil, nil, nil, dedup, nil, nopLog())
		action := model.ETLAction{
			Type:   model.ETLActionDedup,
			Params: map[string]any{"key": "event_id", "window_seconds": 60},
		}
		entry := func() *model.LogEntry {
			return &model.LogEntry{
				TenantID: "t1",
				Fields:   map[string]any{"event_id": "ev-dup"},
			}
		}
		// First pass through.
		_, drop1 := applyOne(t, ex, entry(), action)
		if drop1 {
			t.Error("first should not be dropped")
		}
		// Second pass through within window.
		_, drop2 := applyOne(t, ex, entry(), action)
		if !drop2 {
			t.Error("duplicate within window should be dropped")
		}
	})

	t.Run("different_tenant_not_deduped", func(t *testing.T) {
		dedup := NewDeduplicator()
		ex := NewActionExecutor(nil, nil, nil, dedup, nil, nopLog())
		action := model.ETLAction{
			Type:   model.ETLActionDedup,
			Params: map[string]any{"key": "event_id", "window_seconds": 60},
		}
		e1 := &model.LogEntry{TenantID: "tenantA", Fields: map[string]any{"event_id": "same-id"}}
		e2 := &model.LogEntry{TenantID: "tenantB", Fields: map[string]any{"event_id": "same-id"}}

		_, d1 := applyOne(t, ex, e1, action)
		_, d2 := applyOne(t, ex, e2, action)

		if d1 || d2 {
			t.Errorf("different tenants should not dedup each other: d1=%v d2=%v", d1, d2)
		}
	})

	t.Run("nil_dedup_noop", func(t *testing.T) {
		ex := NewActionExecutor(nil, nil, nil, nil, nil, nopLog())
		entry := &model.LogEntry{TenantID: "t1", Fields: map[string]any{"event_id": "x"}}
		_, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionDedup,
			Params: map[string]any{"key": "event_id", "window_seconds": 60},
		})
		if drop {
			t.Error("nil dedup should be a noop (no drop)")
		}
	})

	t.Run("empty_key_noop", func(t *testing.T) {
		dedup := NewDeduplicator()
		ex := NewActionExecutor(nil, nil, nil, dedup, nil, nopLog())
		entry := &model.LogEntry{TenantID: "t1", Fields: map[string]any{}}
		_, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionDedup,
			Params: map[string]any{"key": "", "window_seconds": 60},
		})
		if drop {
			t.Error("empty key should noop")
		}
	})
}

// ─── encode_csv ───────────────────────────────────────────────────────────────

func TestActionExecutor_EncodeCSV(t *testing.T) {
	ex := NewActionExecutor(nil, nil, nil, nil, nil, nopLog())

	t.Run("headers_picked_in_order", func(t *testing.T) {
		entry := newEntry(map[string]any{
			"name": "alice",
			"age":  "30",
			"city": "bj",
		})
		out, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionEncodeCSV,
			Params: map[string]any{"headers": "name,age,city"},
		})
		if drop || out == nil {
			t.Fatal("encode_csv should not drop")
		}
		got, ok := out.Fields["csv_output"].(string)
		if !ok {
			t.Fatalf("csv_output should be a string, got %T", out.Fields["csv_output"])
		}
		if got != "alice,30,bj" {
			t.Errorf("expected 'alice,30,bj', got %q", got)
		}
	})

	t.Run("missing_field_empty_col", func(t *testing.T) {
		entry := newEntry(map[string]any{
			"name": "bob",
			"city": "sh",
		})
		out, _ := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionEncodeCSV,
			Params: map[string]any{"headers": "name,missing,city"},
		})
		got, ok := out.Fields["csv_output"].(string)
		if !ok {
			t.Fatalf("csv_output should be a string, got %T", out.Fields["csv_output"])
		}
		// missing field → empty column → "bob,,sh"
		if got != "bob,,sh" {
			t.Errorf("expected 'bob,,sh', got %q", got)
		}
	})

	t.Run("custom_dst_key", func(t *testing.T) {
		entry := newEntry(map[string]any{"a": "1", "b": "2"})
		out, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionEncodeCSV,
			Params: map[string]any{"headers": "a,b", "dst_key": "out_csv"},
		})
		if drop || out == nil {
			t.Fatal("encode_csv should not drop")
		}
		if _, ok := out.Fields["out_csv"]; !ok {
			t.Error("custom dst_key 'out_csv' should be set")
		}
		if _, ok := out.Fields["csv_output"]; ok {
			t.Error("default 'csv_output' should not be set when dst_key is custom")
		}
	})

	t.Run("empty_headers_noop", func(t *testing.T) {
		entry := newEntry(map[string]any{"x": "y"})
		out, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionEncodeCSV,
			Params: map[string]any{"headers": ""},
		})
		if drop || out == nil {
			t.Fatal("empty headers should not drop")
		}
		// headers="" → break → csv_output not set
		if v, ok := out.Fields["csv_output"]; ok {
			// allow empty string as well
			if s, isStr := v.(string); isStr && s != "" {
				t.Errorf("csv_output should be unset or empty for empty headers, got %q", s)
			}
		}
	})
}

// ─── multiline_join ───────────────────────────────────────────────────────────

func TestActionExecutor_MultilineJoin(t *testing.T) {
	ex := NewActionExecutor(nil, nil, nil, nil, nil, nopLog())

	t.Run("joins_string_slice", func(t *testing.T) {
		entry := newEntry(map[string]any{
			"lines": []any{"foo", "bar", "baz"},
		})
		out, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionMultilineJoin,
			Params: map[string]any{"src_key": "lines", "separator": "\n"},
		})
		if drop || out == nil {
			t.Fatal("multiline_join should not drop")
		}
		if out.Fields["lines"] != "foo\nbar\nbaz" {
			t.Errorf("expected 'foo\\nbar\\nbaz', got %v", out.Fields["lines"])
		}
	})

	t.Run("joins_any_slice_fmt", func(t *testing.T) {
		entry := newEntry(map[string]any{
			"nums": []any{1, 2, 3},
		})
		out, _ := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionMultilineJoin,
			Params: map[string]any{"src_key": "nums", "separator": ","},
		})
		if out.Fields["nums"] != "1,2,3" {
			t.Errorf("expected '1,2,3', got %v", out.Fields["nums"])
		}
	})

	t.Run("already_string_noop", func(t *testing.T) {
		entry := newEntry(map[string]any{"text": "hello"})
		out, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionMultilineJoin,
			Params: map[string]any{"src_key": "text", "separator": "\n"},
		})
		if drop || out == nil {
			t.Fatal("should not drop")
		}
		// string value is unchanged — the case is a no-op
		if out.Fields["text"] != "hello" {
			t.Errorf("string field should be unchanged, got %v", out.Fields["text"])
		}
	})

	t.Run("default_separator_newline", func(t *testing.T) {
		entry := newEntry(map[string]any{
			"parts": []any{"a", "b", "c"},
		})
		out, _ := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionMultilineJoin,
			Params: map[string]any{"src_key": "parts"},
			// separator omitted → defaults to "\n"
		})
		if out.Fields["parts"] != "a\nb\nc" {
			t.Errorf("expected 'a\\nb\\nc' with default separator, got %v", out.Fields["parts"])
		}
	})

	t.Run("missing_key_noop", func(t *testing.T) {
		entry := newEntry(map[string]any{"other": "val"})
		out, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionMultilineJoin,
			Params: map[string]any{"src_key": "nonexistent", "separator": ","},
		})
		if drop || out == nil {
			t.Fatal("missing key should not drop")
		}
		// nonexistent key should not be created
		if _, ok := out.Fields["nonexistent"]; ok {
			t.Error("missing key should not be created")
		}
	})
}

// ─── split_record ─────────────────────────────────────────────────────────────

func TestActionExecutor_SplitRecord(t *testing.T) {
	ex := NewActionExecutor(nil, nil, nil, nil, nil, nopLog())

	t.Run("splits_by_comma", func(t *testing.T) {
		entry := newEntry(map[string]any{"tags": "a,b,c"})
		out, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionSplitRecord,
			Params: map[string]any{"src_key": "tags", "separator": ","},
		})
		if drop || out == nil {
			t.Fatal("split_record should not drop")
		}
		if out.Fields["tags"] != "a" {
			t.Errorf("expected first segment 'a', got %v", out.Fields["tags"])
		}
		parts, ok := out.Fields["tags_parts"].([]any)
		if !ok {
			t.Fatalf("tags_parts should be []any, got %T", out.Fields["tags_parts"])
		}
		if len(parts) != 3 {
			t.Errorf("expected 3 parts, got %d", len(parts))
		}
		if parts[0] != "a" || parts[1] != "b" || parts[2] != "c" {
			t.Errorf("unexpected parts: %v", parts)
		}
	})

	t.Run("custom_separator", func(t *testing.T) {
		entry := newEntry(map[string]any{"tags": "x|y|z"})
		out, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionSplitRecord,
			Params: map[string]any{"src_key": "tags", "separator": "|"},
		})
		if drop || out == nil {
			t.Fatal("split_record should not drop")
		}
		if out.Fields["tags"] != "x" {
			t.Errorf("expected first segment 'x', got %v", out.Fields["tags"])
		}
		parts, ok := out.Fields["tags_parts"].([]any)
		if !ok {
			t.Fatalf("tags_parts should be []any, got %T", out.Fields["tags_parts"])
		}
		if len(parts) != 3 {
			t.Errorf("expected 3 parts, got %d", len(parts))
		}
	})

	t.Run("single_value_no_split", func(t *testing.T) {
		entry := newEntry(map[string]any{"tags": "only"})
		out, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionSplitRecord,
			Params: map[string]any{"src_key": "tags", "separator": ","},
		})
		if drop || out == nil {
			t.Fatal("should not drop")
		}
		if out.Fields["tags"] != "only" {
			t.Errorf("expected 'only', got %v", out.Fields["tags"])
		}
		parts, ok := out.Fields["tags_parts"].([]any)
		if !ok {
			t.Fatalf("tags_parts should be []any, got %T", out.Fields["tags_parts"])
		}
		if len(parts) != 1 || parts[0] != "only" {
			t.Errorf("expected parts=[\"only\"], got %v", parts)
		}
	})

	t.Run("missing_key_noop", func(t *testing.T) {
		entry := newEntry(map[string]any{"other": "val"})
		out, drop := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionSplitRecord,
			Params: map[string]any{"src_key": "tags", "separator": ","},
		})
		if drop || out == nil {
			t.Fatal("missing src_key should not drop")
		}
		if _, ok := out.Fields["tags_parts"]; ok {
			t.Error("tags_parts should not be created for missing src_key")
		}
	})

	t.Run("default_separator_comma", func(t *testing.T) {
		entry := newEntry(map[string]any{"tags": "p,q,r"})
		out, _ := applyOne(t, ex, entry, model.ETLAction{
			Type:   model.ETLActionSplitRecord,
			Params: map[string]any{"src_key": "tags"},
			// separator omitted → defaults to ","
		})
		parts, ok := out.Fields["tags_parts"].([]any)
		if !ok {
			t.Fatalf("tags_parts should be []any, got %T", out.Fields["tags_parts"])
		}
		if len(parts) != 3 {
			t.Errorf("expected 3 parts with default comma separator, got %d", len(parts))
		}
		if out.Fields["tags"] != "p" {
			t.Errorf("expected first segment 'p', got %v", out.Fields["tags"])
		}
	})
}

// ─── allow_records + block_records: drop path chained ────────────────────────

func TestActionExecutor_DropPath_Chained(t *testing.T) {
	ex := NewActionExecutor(nil, nil, nil, nil, nil, nopLog())

	t.Run("allow_records_drop_stops_pipeline", func(t *testing.T) {
		// allow_records drops → subsequent set_field should never run
		entry := newEntry(map[string]any{"severity": "low", "enriched": false})
		actions := []model.ETLAction{
			{
				Type:   model.ETLActionAllowRecords,
				Params: map[string]any{"key": "severity", "regex": "^high$"},
			},
			{
				Type:   model.ETLActionSetField,
				Params: map[string]any{"field": "enriched", "value": "true"},
			},
		}
		out, drop := ex.ApplyActions(context.Background(), entry, actions)
		if !drop {
			t.Error("allow_records mismatch should drop the record")
		}
		if out != nil {
			t.Error("dropped record should return nil entry")
		}
	})

	t.Run("block_records_drop_stops_pipeline", func(t *testing.T) {
		entry := newEntry(map[string]any{"event_type": "heartbeat", "processed": false})
		actions := []model.ETLAction{
			{
				Type:   model.ETLActionBlockRecords,
				Params: map[string]any{"key": "event_type", "regex": "heartbeat"},
			},
			{
				Type:   model.ETLActionSetField,
				Params: map[string]any{"field": "processed", "value": "true"},
			},
		}
		out, drop := ex.ApplyActions(context.Background(), entry, actions)
		if !drop {
			t.Error("block_records match should drop the record")
		}
		if out != nil {
			t.Error("dropped record should return nil entry")
		}
	})

	t.Run("allow_then_transform_passes", func(t *testing.T) {
		entry := newEntry(map[string]any{"severity": "critical"})
		actions := []model.ETLAction{
			{
				Type:   model.ETLActionAllowRecords,
				Params: map[string]any{"key": "severity", "regex": "critical"},
			},
			{
				Type:   model.ETLActionSetField,
				Params: map[string]any{"field": "triaged", "value": "yes"},
			},
		}
		out, drop := ex.ApplyActions(context.Background(), entry, actions)
		if drop || out == nil {
			t.Fatal("matching allow_records should not drop")
		}
		if out.Fields["triaged"] != "yes" {
			t.Errorf("subsequent action should have run, got %v", out.Fields["triaged"])
		}
	})
}

func TestActionExecutor_LiftSubmap(t *testing.T) {
	ex := NewActionExecutor(nil, nil, nil, nil, nil, nopLog())

	t.Run("promotes_submap_to_top_level", func(t *testing.T) {
		entry := newEntry(map[string]any{
			"details": map[string]any{"foo": "bar", "baz": int64(42)},
		})
		actions := []model.ETLAction{
			{Type: model.ETLActionLiftSubmap, Params: map[string]any{"src_key": "details"}},
		}
		out, drop := ex.ApplyActions(context.Background(), entry, actions)
		if drop || out == nil {
			t.Fatal("unexpected drop")
		}
		if out.Fields["foo"] != "bar" {
			t.Errorf("expected foo=bar, got %v", out.Fields["foo"])
		}
		if out.Fields["baz"] != int64(42) {
			t.Errorf("expected baz=42, got %v", out.Fields["baz"])
		}
		if _, ok := out.Fields["details"]; ok {
			t.Error("src_key should be removed by default")
		}
	})

	t.Run("prefix_prepended", func(t *testing.T) {
		entry := newEntry(map[string]any{
			"sub": map[string]any{"x": "1"},
		})
		actions := []model.ETLAction{
			{Type: model.ETLActionLiftSubmap, Params: map[string]any{"src_key": "sub", "prefix": "p_"}},
		}
		out, drop := ex.ApplyActions(context.Background(), entry, actions)
		if drop || out == nil {
			t.Fatal("unexpected drop")
		}
		if out.Fields["p_x"] != "1" {
			t.Errorf("expected p_x=1, got %v", out.Fields["p_x"])
		}
	})

	t.Run("keep_src_retains_original", func(t *testing.T) {
		entry := newEntry(map[string]any{
			"meta": map[string]any{"k": "v"},
		})
		actions := []model.ETLAction{
			{Type: model.ETLActionLiftSubmap, Params: map[string]any{"src_key": "meta", "keep_src": "true"}},
		}
		out, drop := ex.ApplyActions(context.Background(), entry, actions)
		if drop || out == nil {
			t.Fatal("unexpected drop")
		}
		if _, ok := out.Fields["meta"]; !ok {
			t.Error("keep_src=true should retain original key")
		}
		if out.Fields["k"] != "v" {
			t.Errorf("expected k=v at top level, got %v", out.Fields["k"])
		}
	})

	t.Run("non_map_value_noop", func(t *testing.T) {
		entry := newEntry(map[string]any{"flat": "string_value"})
		actions := []model.ETLAction{
			{Type: model.ETLActionLiftSubmap, Params: map[string]any{"src_key": "flat"}},
		}
		out, drop := ex.ApplyActions(context.Background(), entry, actions)
		if drop || out == nil {
			t.Fatal("unexpected drop")
		}
		if out.Fields["flat"] != "string_value" {
			t.Error("non-map value should leave entry unchanged")
		}
	})

	t.Run("missing_key_noop", func(t *testing.T) {
		entry := newEntry(map[string]any{"other": "val"})
		actions := []model.ETLAction{
			{Type: model.ETLActionLiftSubmap, Params: map[string]any{"src_key": "missing"}},
		}
		out, drop := ex.ApplyActions(context.Background(), entry, actions)
		if drop || out == nil {
			t.Fatal("unexpected drop")
		}
		if _, ok := out.Fields["missing"]; ok {
			t.Error("missing key should not appear")
		}
	})

	t.Run("empty_src_key_noop", func(t *testing.T) {
		entry := newEntry(map[string]any{"a": "b"})
		actions := []model.ETLAction{
			{Type: model.ETLActionLiftSubmap, Params: map[string]any{"src_key": ""}},
		}
		out, drop := ex.ApplyActions(context.Background(), entry, actions)
		if drop || out == nil {
			t.Fatal("unexpected drop")
		}
		if out.Fields["a"] != "b" {
			t.Error("empty src_key should leave entry unchanged")
		}
	})
}

func TestActionExecutor_JoinRecords(t *testing.T) {
	ex := NewActionExecutor(nil, nil, nil, nil, nil, nopLog())

	t.Run("joins_named_fields_across_subrecords", func(t *testing.T) {
		entry := newEntry(map[string]any{
			"events": []any{
				map[string]any{"msg": "hello"},
				map[string]any{"msg": "world"},
			},
		})
		actions := []model.ETLAction{
			{Type: model.ETLActionJoinRecords, Params: map[string]any{
				"src_key": "events",
				"fields":  "msg",
				"dst_key": "joined_msg",
			}},
		}
		out, drop := ex.ApplyActions(context.Background(), entry, actions)
		if drop || out == nil {
			t.Fatal("unexpected drop")
		}
		if out.Fields["joined_msg"] != "hello,world" {
			t.Errorf("expected hello,world, got %v", out.Fields["joined_msg"])
		}
	})

	t.Run("custom_separator", func(t *testing.T) {
		entry := newEntry(map[string]any{
			"items": []any{
				map[string]any{"v": "a"},
				map[string]any{"v": "b"},
				map[string]any{"v": "c"},
			},
		})
		actions := []model.ETLAction{
			{Type: model.ETLActionJoinRecords, Params: map[string]any{
				"src_key":   "items",
				"fields":    "v",
				"dst_key":   "out",
				"separator": " | ",
			}},
		}
		out, drop := ex.ApplyActions(context.Background(), entry, actions)
		if drop || out == nil {
			t.Fatal("unexpected drop")
		}
		if out.Fields["out"] != "a | b | c" {
			t.Errorf("expected a | b | c, got %v", out.Fields["out"])
		}
	})

	t.Run("non_slice_src_noop", func(t *testing.T) {
		entry := newEntry(map[string]any{"data": "not a slice"})
		actions := []model.ETLAction{
			{Type: model.ETLActionJoinRecords, Params: map[string]any{
				"src_key": "data",
				"fields":  "x",
				"dst_key": "out",
			}},
		}
		out, drop := ex.ApplyActions(context.Background(), entry, actions)
		if drop || out == nil {
			t.Fatal("unexpected drop")
		}
		if _, ok := out.Fields["out"]; ok {
			t.Error("non-slice src should not write dst_key")
		}
	})

	t.Run("missing_src_key_noop", func(t *testing.T) {
		entry := newEntry(map[string]any{"other": "val"})
		actions := []model.ETLAction{
			{Type: model.ETLActionJoinRecords, Params: map[string]any{
				"src_key": "events",
				"fields":  "msg",
				"dst_key": "out",
			}},
		}
		out, drop := ex.ApplyActions(context.Background(), entry, actions)
		if drop || out == nil {
			t.Fatal("unexpected drop")
		}
		if _, ok := out.Fields["out"]; ok {
			t.Error("missing src_key should not write dst_key")
		}
	})

	t.Run("empty_fields_param_noop", func(t *testing.T) {
		entry := newEntry(map[string]any{
			"recs": []any{map[string]any{"x": "y"}},
		})
		actions := []model.ETLAction{
			{Type: model.ETLActionJoinRecords, Params: map[string]any{
				"src_key": "recs",
				"fields":  "",
				"dst_key": "out",
			}},
		}
		out, drop := ex.ApplyActions(context.Background(), entry, actions)
		if drop || out == nil {
			t.Fatal("unexpected drop")
		}
		if _, ok := out.Fields["out"]; ok {
			t.Error("empty fields param should not write dst_key")
		}
	})
}
