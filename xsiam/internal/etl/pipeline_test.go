package etl

import (
	"context"
	"testing"
	"xsiam/internal/model"

	"go.uber.org/zap"
)

// ─── matchesEntry unit tests ──────────────────────────────────────────────────

func TestMatchesEntry_TagGlob(t *testing.T) {
	rule := compileRule(model.ETLRule{
		RuleID: "test", IsEnabled: true, Priority: 1,
		Match:        model.ETLMatchCriteria{TagPattern: "winevent.*"},
		RawWriteMode: model.RawWriteBoth,
		Output:       model.ETLOutput{NgxIndex: "out"},
	})
	entry := &model.LogEntry{Kind: model.LogKindProcess, Dataset: "xdr_data"}
	if !matchesEntry(rule, entry, "winevent.security") {
		t.Error("should match winevent.security against winevent.*")
	}
	if matchesEntry(rule, entry, "syslog") {
		t.Error("should not match syslog against winevent.*")
	}
}

func TestMatchesEntry_Dataset(t *testing.T) {
	rule := compileRule(model.ETLRule{
		RuleID: "ds", IsEnabled: true, Priority: 1,
		Match:        model.ETLMatchCriteria{Dataset: []string{"syslog_raw"}},
		RawWriteMode: model.RawWriteRawOnly,
		Output:       model.ETLOutput{},
	})
	match := &model.LogEntry{Dataset: "syslog_raw"}
	noMatch := &model.LogEntry{Dataset: "xdr_data"}
	if !matchesEntry(rule, match, "syslog") {
		t.Error("should match syslog_raw dataset")
	}
	if matchesEntry(rule, noMatch, "syslog") {
		t.Error("should not match xdr_data dataset")
	}
}

func TestMatchesEntry_KindList(t *testing.T) {
	rule := compileRule(model.ETLRule{
		RuleID: "k", IsEnabled: true, Priority: 1,
		Match:        model.ETLMatchCriteria{Kind: []uint8{model.LogKindDNS}},
		RawWriteMode: model.RawWriteETLOnly,
		Output:       model.ETLOutput{NgxIndex: "out"},
	})
	dns := &model.LogEntry{Kind: model.LogKindDNS}
	proc := &model.LogEntry{Kind: model.LogKindProcess}
	if !matchesEntry(rule, dns, "dns") {
		t.Error("should match DNS kind")
	}
	if matchesEntry(rule, proc, "proc") {
		t.Error("should not match process kind")
	}
}

func TestMatchesEntry_FilterExpr(t *testing.T) {
	rule := compileRule(model.ETLRule{
		RuleID: "filter", IsEnabled: true, Priority: 1,
		Match:        model.ETLMatchCriteria{FilterExpr: `agent_id = "scanner-01"`},
		RawWriteMode: model.RawWriteETLOnly,
		Actions:      []model.ETLAction{{Type: "drop_event"}},
		Output:       model.ETLOutput{},
	})
	hit := &model.LogEntry{AgentID: "scanner-01"}
	miss := &model.LogEntry{AgentID: "prod-agent-01"}
	if !matchesEntry(rule, hit, "dns") {
		t.Error("should match agent_id=scanner-01")
	}
	if matchesEntry(rule, miss, "dns") {
		t.Error("should not match agent_id=prod-agent-01")
	}
}

func TestMatchesEntry_MultiCriteria(t *testing.T) {
	rule := compileRule(model.ETLRule{
		RuleID: "multi", IsEnabled: true, Priority: 1,
		Match: model.ETLMatchCriteria{
			TagPattern: "winevent.*",
			Kind:       []uint8{model.LogKindProcess},
		},
		RawWriteMode: model.RawWriteBoth,
		Output:       model.ETLOutput{NgxIndex: "out"},
	})
	// Must match both tag AND kind
	both := &model.LogEntry{Kind: model.LogKindProcess}
	if !matchesEntry(rule, both, "winevent.security") {
		t.Error("both criteria met — should match")
	}
	// Wrong kind
	wrongKind := &model.LogEntry{Kind: model.LogKindDNS}
	if matchesEntry(rule, wrongKind, "winevent.security") {
		t.Error("wrong kind — should not match")
	}
	// Wrong tag
	wrongTag := &model.LogEntry{Kind: model.LogKindProcess}
	if matchesEntry(rule, wrongTag, "syslog") {
		t.Error("wrong tag — should not match")
	}
}

// ─── Pipeline.Process tests ───────────────────────────────────────────────────

func newTestPipeline(rules []model.ETLRule) *Pipeline {
	p := NewPipeline(nil) // nil executor — no asset/ioc lookup
	compiled := make([]compiledRule, len(rules))
	for i, r := range rules {
		compiled[i] = compileRule(r)
	}
	p.Replace(compiled)
	return p
}

func TestPipeline_NoMatch_DefaultRouting(t *testing.T) {
	p := newTestPipeline(nil) // empty rule set
	entry := &model.LogEntry{Kind: model.LogKindProcess, Dataset: "xdr_data"}
	res := p.Process(context.Background(), entry, "winevent.security")
	if res.Matched {
		t.Error("empty pipeline should not match")
	}
	if res.RawNgxIndex != "raw_winevent.security" {
		t.Errorf("expected raw_winevent.security, got %q", res.RawNgxIndex)
	}
	if res.ETLEntry == nil {
		t.Error("default: ETLEntry should not be nil")
	}
	if res.WriteArango != true {
		t.Error("default: WriteArango should be true")
	}
}

func TestPipeline_RawOnly_SuppressesETL(t *testing.T) {
	p := newTestPipeline([]model.ETLRule{
		{
			RuleID: "raw-pass", IsEnabled: true, Priority: 1,
			Match:        model.ETLMatchCriteria{Dataset: []string{"syslog_raw"}},
			RawWriteMode: model.RawWriteRawOnly,
			Actions:      nil,
			Output:       model.ETLOutput{NgxIndex: "syslog_enriched"},
		},
	})
	entry := &model.LogEntry{Dataset: "syslog_raw"}
	res := p.Process(context.Background(), entry, "syslog")
	if !res.Matched {
		t.Error("should match syslog_raw rule")
	}
	if res.RawNgxIndex == "" {
		t.Error("raw_only: RawNgxIndex should be set")
	}
	if res.ETLEntry != nil {
		t.Error("raw_only: ETLEntry should be nil")
	}
	if res.ETLNgxIndex != "" {
		t.Error("raw_only: ETLNgxIndex should be empty")
	}
}

func TestPipeline_ETLOnly_SuppressesRaw(t *testing.T) {
	p := newTestPipeline([]model.ETLRule{
		{
			RuleID: "drop-dns", IsEnabled: true, Priority: 1,
			Match:        model.ETLMatchCriteria{Kind: []uint8{model.LogKindDNS}},
			RawWriteMode: model.RawWriteETLOnly,
			Actions:      []model.ETLAction{{Type: "drop_event"}},
			Output:       model.ETLOutput{NgxIndex: ""},
		},
	})
	entry := &model.LogEntry{Kind: model.LogKindDNS, Dataset: "dns_logs", Fields: map[string]any{}}
	res := p.Process(context.Background(), entry, "dns")
	if !res.Matched {
		t.Error("should match DNS rule")
	}
	if res.RawNgxIndex != "" {
		t.Errorf("etl_only: RawNgxIndex should be empty, got %q", res.RawNgxIndex)
	}
	// Dropped is signalled by all output fields being empty
	dropped := res.ETLEntry == nil && res.ETLNgxIndex == "" && res.RawNgxIndex == ""
	if !dropped {
		t.Errorf("drop_event: expected all outputs empty, got raw=%q etl=%q entry=%v",
			res.RawNgxIndex, res.ETLNgxIndex, res.ETLEntry)
	}
}

func TestPipeline_Both_WritesBothPaths(t *testing.T) {
	p := newTestPipeline([]model.ETLRule{
		{
			RuleID: "enrich", IsEnabled: true, Priority: 1,
			Match:        model.ETLMatchCriteria{Kind: []uint8{model.LogKindProcess}},
			RawWriteMode: model.RawWriteBoth,
			Actions: []model.ETLAction{
				{Type: "set_field", Params: map[string]any{"field": "etl_version", "value": "2.0"}},
			},
			Output: model.ETLOutput{NgxIndex: "proc_enriched", WriteArango: true},
		},
	})
	entry := &model.LogEntry{Kind: model.LogKindProcess, Dataset: "xdr_data", Fields: map[string]any{}}
	res := p.Process(context.Background(), entry, "winevent.security")
	if !res.Matched {
		t.Error("should match process rule")
	}
	if res.RawNgxIndex == "" {
		t.Error("both: RawNgxIndex should be set")
	}
	if res.ETLNgxIndex != "proc_enriched" {
		t.Errorf("both: ETLNgxIndex should be proc_enriched, got %q", res.ETLNgxIndex)
	}
	if res.ETLEntry == nil {
		t.Error("both: ETLEntry should not be nil")
	}
	if res.WriteArango != true {
		t.Error("both: WriteArango should be true")
	}
	// Note: set_field is not applied in nil-executor mode (test stub).
	// The action_executor unit tests verify field transformation.
}

// nopLog returns a no-op zap logger for tests.
func nopLog() *zap.Logger { return zap.NewNop() }

// TestActionExecutor_SetField verifies set_field action modifies the entry.
func TestActionExecutor_SetField(t *testing.T) {
	ex := NewActionExecutor(nil, nil, nopLog())
	entry := &model.LogEntry{Fields: map[string]any{}}
	actions := []model.ETLAction{
		{Type: model.ETLActionSetField, Params: map[string]any{"field": "env", "value": "prod"}},
	}
	out, drop := ex.ApplyActions(context.Background(), entry, actions)
	if drop {
		t.Error("set_field should not drop")
	}
	if out == nil {
		t.Fatal("out should not be nil")
	}
	if out.Fields["env"] != "prod" {
		t.Errorf("expected fields.env=prod, got %v", out.Fields["env"])
	}
}

// TestActionExecutor_DropEvent verifies drop_event discards the entry.
func TestActionExecutor_DropEvent(t *testing.T) {
	ex := NewActionExecutor(nil, nil, nopLog())
	entry := &model.LogEntry{Fields: map[string]any{}}
	actions := []model.ETLAction{{Type: model.ETLActionDropEvent}}
	out, drop := ex.ApplyActions(context.Background(), entry, actions)
	if !drop {
		t.Error("drop_event should set drop=true")
	}
	_ = out
}

// TestActionExecutor_RenameField verifies rename_field action.
func TestActionExecutor_RenameField(t *testing.T) {
	ex := NewActionExecutor(nil, nil, nopLog())
	entry := &model.LogEntry{Fields: map[string]any{"old_name": "hello"}}
	actions := []model.ETLAction{
		{Type: model.ETLActionRenameField, Params: map[string]any{"from": "old_name", "to": "new_name"}},
	}
	out, drop := ex.ApplyActions(context.Background(), entry, actions)
	if drop || out == nil {
		t.Fatal("should not drop")
	}
	if _, ok := out.Fields["old_name"]; ok {
		t.Error("old_name should be removed")
	}
	if out.Fields["new_name"] != "hello" {
		t.Errorf("new_name should be hello, got %v", out.Fields["new_name"])
	}
}

// TestActionExecutor_DeleteField verifies delete_field action.
func TestActionExecutor_DeleteField(t *testing.T) {
	ex := NewActionExecutor(nil, nil, nopLog())
	entry := &model.LogEntry{Fields: map[string]any{"tmp": "remove_me", "keep": "yes"}}
	actions := []model.ETLAction{
		{Type: model.ETLActionDeleteField, Params: map[string]any{"field": "tmp"}},
	}
	out, drop := ex.ApplyActions(context.Background(), entry, actions)
	if drop || out == nil {
		t.Fatal("should not drop")
	}
	if _, ok := out.Fields["tmp"]; ok {
		t.Error("tmp should be deleted")
	}
	if out.Fields["keep"] != "yes" {
		t.Error("keep field should be preserved")
	}
}

func TestPipeline_FirstMatchWins(t *testing.T) {
	p := newTestPipeline([]model.ETLRule{
		{
			RuleID: "first", IsEnabled: true, Priority: 1,
			Match:        model.ETLMatchCriteria{Kind: []uint8{model.LogKindProcess}},
			RawWriteMode: model.RawWriteETLOnly,
			Output:       model.ETLOutput{NgxIndex: "first_index"},
		},
		{
			RuleID: "second", IsEnabled: true, Priority: 2,
			Match:        model.ETLMatchCriteria{Kind: []uint8{model.LogKindProcess}},
			RawWriteMode: model.RawWriteBoth,
			Output:       model.ETLOutput{NgxIndex: "second_index"},
		},
	})
	entry := &model.LogEntry{Kind: model.LogKindProcess, Fields: map[string]any{}}
	res := p.Process(context.Background(), entry, "test")
	if res.ETLNgxIndex != "first_index" {
		t.Errorf("first-match-wins: expected first_index, got %q", res.ETLNgxIndex)
	}
}

// ─── parseFilterExpr tests ────────────────────────────────────────────────────

func TestParseFilterExpr_Empty(t *testing.T) {
	if parseFilterExpr("") != nil {
		t.Error("empty expr should return nil")
	}
}

func TestParseFilterExpr_Single(t *testing.T) {
	pairs := parseFilterExpr(`agent_id = "scanner-01"`)
	if len(pairs) != 1 {
		t.Fatalf("expected 1 pair, got %d", len(pairs))
	}
	if pairs[0][0] != "agent_id" || pairs[0][1] != "scanner-01" {
		t.Errorf("wrong pair: %v", pairs[0])
	}
}

func TestParseFilterExpr_MultipleAND(t *testing.T) {
	pairs := parseFilterExpr(`hostname = "host01" AND agent_id = "agent01"`)
	if len(pairs) != 2 {
		t.Fatalf("expected 2 pairs, got %d", len(pairs))
	}
}
