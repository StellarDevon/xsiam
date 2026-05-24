package etl

import (
	"context"
	"testing"
	"xsiam/internal/model"
)

// newTestPipelineWithExec creates a Pipeline with a real ActionExecutor (all
// deps nil — asset/ioc/geoip/dedup/lua are no-ops) so that set_field and
// other non-lookup actions are actually applied.
func newTestPipelineWithExec(rules []model.ETLRule) *Pipeline {
	exec := NewActionExecutor(nil, nil, nil, nil, nil, nopLog())
	p := NewPipeline(exec)
	compiled := make([]compiledRule, len(rules))
	for i, r := range rules {
		compiled[i] = compileRule(r)
	}
	p.Replace(compiled)
	return p
}

// ── A. Sequential mode ────────────────────────────────────────────────────────

// TestPipeline_Sequential_ChainTransforms verifies that two sequential rules
// fire in priority order and that the last rule's sink wins.  A real executor
// is used so set_field actions are actually applied.
func TestPipeline_Sequential_ChainTransforms(t *testing.T) {
	p := newTestPipelineWithExec([]model.ETLRule{
		{
			RuleID: "seq-chain-1", IsEnabled: true, Priority: 10,
			ProcessingMode: model.ProcessingSequential,
			Match:          model.ETLMatchCriteria{TagPattern: "chain.test"},
			RawWriteMode:   model.RawWriteBoth,
			Actions: []model.ETLAction{
				{Type: model.ETLActionSetField, Params: map[string]any{"field": "step", "value": "1"}},
			},
			Output: model.ETLOutput{NgxIndex: "chain_intermediate"},
		},
		{
			RuleID: "seq-chain-2", IsEnabled: true, Priority: 20,
			ProcessingMode: model.ProcessingSequential,
			Match:          model.ETLMatchCriteria{TagPattern: "chain.test"},
			RawWriteMode:   model.RawWriteBoth,
			Actions: []model.ETLAction{
				{Type: model.ETLActionSetField, Params: map[string]any{"field": "step", "value": "2"}},
			},
			Output: model.ETLOutput{
				Sinks: []model.ETLSink{
					{NgxIndex: "chain_out"},
				},
			},
		},
	})

	entry := &model.LogEntry{
		Kind:   model.LogKindProcess,
		Fields: map[string]any{},
	}
	res := p.Process(context.Background(), entry, "chain.test")

	if !res.Matched {
		t.Fatal("expected Matched=true for sequential chain")
	}
	if res.ETLEntry == nil {
		t.Fatal("ETLEntry should not be nil after sequential chain")
	}
	if got := res.ETLEntry.Fields["step"]; got != "2" {
		t.Errorf("expected Fields[step]=\"2\" (rule2 overwrites rule1), got %v", got)
	}
	if len(res.Sinks) == 0 {
		t.Fatal("expected at least one sink from rule2")
	}
	if res.Sinks[0].NgxIndex != "chain_out" {
		t.Errorf("expected Sinks[0].NgxIndex=chain_out, got %q", res.Sinks[0].NgxIndex)
	}
}

// TestPipeline_Sequential_DropInMiddle verifies that a drop_event in the
// sequential chain discards the event and returns nil ETLEntry.
func TestPipeline_Sequential_DropInMiddle(t *testing.T) {
	// nil executor: set_field no-ops, but drop_event is detected by the inline
	// loop in pipeline.go (lines 126-131) even without an executor.
	p := newTestPipeline([]model.ETLRule{
		{
			RuleID: "seq-drop-1", IsEnabled: true, Priority: 10,
			ProcessingMode: model.ProcessingSequential,
			Match:          model.ETLMatchCriteria{TagPattern: "drop.test"},
			RawWriteMode:   model.RawWriteBoth,
			Actions: []model.ETLAction{
				{Type: model.ETLActionSetField, Params: map[string]any{"field": "x", "value": "1"}},
			},
			Output: model.ETLOutput{NgxIndex: "drop_intermediate"},
		},
		{
			RuleID: "seq-drop-2", IsEnabled: true, Priority: 20,
			ProcessingMode: model.ProcessingSequential,
			Match:          model.ETLMatchCriteria{TagPattern: "drop.test"},
			RawWriteMode:   model.RawWriteBoth,
			Actions: []model.ETLAction{
				{Type: model.ETLActionDropEvent},
			},
			Output: model.ETLOutput{NgxIndex: "drop_final"},
		},
	})

	entry := &model.LogEntry{
		Kind:   model.LogKindProcess,
		Fields: map[string]any{},
	}
	res := p.Process(context.Background(), entry, "drop.test")

	if !res.Matched {
		t.Error("expected Matched=true (sequential rules did fire)")
	}
	if res.ETLEntry != nil {
		t.Errorf("expected ETLEntry=nil after drop_event, got %v", res.ETLEntry)
	}
}

// TestPipeline_Sequential_vs_FirstMatch verifies that a sequential rule and a
// first_match rule are evaluated independently: sending a tag that only
// matches the first_match rule should produce sinks from that rule only.
func TestPipeline_Sequential_vs_FirstMatch(t *testing.T) {
	p := newTestPipeline([]model.ETLRule{
		{
			RuleID: "seq-rule", IsEnabled: true, Priority: 5,
			ProcessingMode: model.ProcessingSequential,
			Match:          model.ETLMatchCriteria{TagPattern: "seq.*"},
			RawWriteMode:   model.RawWriteBoth,
			Output:         model.ETLOutput{NgxIndex: "seq_index"},
		},
		{
			RuleID: "fm-rule", IsEnabled: true, Priority: 10,
			ProcessingMode: model.ProcessingFirstMatch,
			Match:          model.ETLMatchCriteria{TagPattern: "fm.*"},
			RawWriteMode:   model.RawWriteBoth,
			Output:         model.ETLOutput{NgxIndex: "fm_index"},
		},
	})

	entry := &model.LogEntry{
		Kind:   model.LogKindProcess,
		Fields: map[string]any{},
	}
	// tag "fm.test" matches only fm-rule (first_match), not seq-rule (seq.*)
	res := p.Process(context.Background(), entry, "fm.test")

	if !res.Matched {
		t.Fatal("expected Matched=true for fm.test via first_match rule")
	}
	if res.ETLNgxIndex != "fm_index" {
		t.Errorf("expected ETLNgxIndex=fm_index (from first_match rule), got %q", res.ETLNgxIndex)
	}
}

// ── B. Multi-sink routing ─────────────────────────────────────────────────────

// TestPipeline_MultiSink_TwoSinks verifies that two unconditional sinks both
// receive the transformed entry.
func TestPipeline_MultiSink_TwoSinks(t *testing.T) {
	p := newTestPipeline([]model.ETLRule{
		{
			RuleID: "multi-sink-2", IsEnabled: true, Priority: 1,
			Match:        model.ETLMatchCriteria{TagPattern: "multi.test"},
			RawWriteMode: model.RawWriteBoth,
			Output: model.ETLOutput{
				Sinks: []model.ETLSink{
					{NgxIndex: "idx_a", TTLDays: 30},
					{ArangoCollection: "col_b", TTLDays: 90},
				},
			},
		},
	})

	entry := &model.LogEntry{
		Kind:   model.LogKindProcess,
		Fields: map[string]any{},
	}
	res := p.Process(context.Background(), entry, "multi.test")

	if !res.Matched {
		t.Fatal("expected Matched=true")
	}
	if len(res.Sinks) != 2 {
		t.Fatalf("expected 2 sinks, got %d", len(res.Sinks))
	}
	if res.Sinks[0].NgxIndex != "idx_a" {
		t.Errorf("Sinks[0].NgxIndex: want idx_a, got %q", res.Sinks[0].NgxIndex)
	}
	if res.Sinks[1].ArangoCollection != "col_b" {
		t.Errorf("Sinks[1].ArangoCollection: want col_b, got %q", res.Sinks[1].ArangoCollection)
	}
	if res.Sinks[0].Entry == nil {
		t.Error("Sinks[0].Entry should be non-nil (unconditional sink)")
	}
	if res.Sinks[1].Entry == nil {
		t.Error("Sinks[1].Entry should be non-nil (unconditional sink)")
	}
}

// TestPipeline_MultiSink_ConditionFilter verifies that a sink whose condition
// is not satisfied by the entry is omitted from the result.
// Sink0 has no condition (always fires); Sink1 requires severity=high but
// entry has severity=low — so only Sink0 appears in result.Sinks.
func TestPipeline_MultiSink_ConditionFilter(t *testing.T) {
	p := newTestPipeline([]model.ETLRule{
		{
			RuleID: "multi-sink-cond", IsEnabled: true, Priority: 1,
			Match:        model.ETLMatchCriteria{TagPattern: "cond.test"},
			RawWriteMode: model.RawWriteBoth,
			Output: model.ETLOutput{
				Sinks: []model.ETLSink{
					{NgxIndex: "always_sink"},               // condition="" — always triggers
					{NgxIndex: "high_only", Condition: "severity=high"}, // filtered out
				},
			},
		},
	})

	entry := &model.LogEntry{
		Kind:   model.LogKindProcess,
		Fields: map[string]any{"severity": "low"},
	}
	res := p.Process(context.Background(), entry, "cond.test")

	if !res.Matched {
		t.Fatal("expected Matched=true")
	}
	// Only sink0 (no condition) should survive; sink1 is filtered out entirely.
	if len(res.Sinks) != 1 {
		t.Fatalf("expected 1 sink (severity=high not satisfied), got %d", len(res.Sinks))
	}
	if res.Sinks[0].NgxIndex != "always_sink" {
		t.Errorf("Sinks[0].NgxIndex: want always_sink, got %q", res.Sinks[0].NgxIndex)
	}
	if res.Sinks[0].Entry == nil {
		t.Error("Sinks[0].Entry should be non-nil")
	}
}

// TestPipeline_MultiSink_LegacyFlatFields verifies that when Output.Sinks is
// empty, the legacy flat fields are promoted to a single SinkResult.
func TestPipeline_MultiSink_LegacyFlatFields(t *testing.T) {
	p := newTestPipeline([]model.ETLRule{
		{
			RuleID: "legacy-flat", IsEnabled: true, Priority: 1,
			Match:        model.ETLMatchCriteria{TagPattern: "legacy.test"},
			RawWriteMode: model.RawWriteBoth,
			Output: model.ETLOutput{
				NgxIndex:         "legacy_idx",
				ArangoCollection: "legacy_col",
				// Sinks intentionally omitted
			},
		},
	})

	entry := &model.LogEntry{
		Kind:   model.LogKindProcess,
		Fields: map[string]any{},
	}
	res := p.Process(context.Background(), entry, "legacy.test")

	if !res.Matched {
		t.Fatal("expected Matched=true")
	}
	if len(res.Sinks) != 1 {
		t.Fatalf("expected 1 sink (legacy promotion), got %d", len(res.Sinks))
	}
	if res.Sinks[0].NgxIndex != "legacy_idx" {
		t.Errorf("Sinks[0].NgxIndex: want legacy_idx, got %q", res.Sinks[0].NgxIndex)
	}
	if res.Sinks[0].ArangoCollection != "legacy_col" {
		t.Errorf("Sinks[0].ArangoCollection: want legacy_col, got %q", res.Sinks[0].ArangoCollection)
	}
}

// ── C. FilterMode OR ──────────────────────────────────────────────────────────

// TestPipeline_FilterModeOR_MatchesEither verifies that OR mode accepts an
// entry where only one of the two conditions is satisfied.
func TestPipeline_FilterModeOR_MatchesEither(t *testing.T) {
	// FilterExpr has two conditions separated by " and " (the AND keyword is
	// the condition separator — not a logical AND here, because FilterMode=or
	// means any single condition suffices).
	p := newTestPipeline([]model.ETLRule{
		{
			RuleID: "or-match", IsEnabled: true, Priority: 1,
			Match: model.ETLMatchCriteria{
				FilterExpr: "severity=high and env=prod",
				FilterMode: "or",
			},
			RawWriteMode: model.RawWriteBoth,
			Output:       model.ETLOutput{NgxIndex: "or_out"},
		},
	})

	// severity=high satisfies condition 1; env=dev does NOT satisfy condition 2.
	// OR mode: one match is enough.
	entry := &model.LogEntry{
		Kind:   model.LogKindProcess,
		Fields: map[string]any{"severity": "high", "env": "dev"},
	}
	res := p.Process(context.Background(), entry, "any.tag")

	if !res.Matched {
		t.Error("OR mode: severity=high should satisfy the rule even when env!=prod")
	}
}

// TestPipeline_FilterModeOR_NoMatch verifies that OR mode rejects an entry
// where neither condition is satisfied.
func TestPipeline_FilterModeOR_NoMatch(t *testing.T) {
	p := newTestPipeline([]model.ETLRule{
		{
			RuleID: "or-nomatch", IsEnabled: true, Priority: 1,
			Match: model.ETLMatchCriteria{
				FilterExpr: "severity=critical and env=staging",
				FilterMode: "or",
			},
			RawWriteMode: model.RawWriteBoth,
			Output:       model.ETLOutput{NgxIndex: "or_out2"},
		},
	})

	// Neither severity=critical nor env=staging is true.
	entry := &model.LogEntry{
		Kind:   model.LogKindProcess,
		Fields: map[string]any{"severity": "low", "env": "prod"},
	}
	res := p.Process(context.Background(), entry, "any.tag")

	if res.Matched {
		t.Error("OR mode: neither condition satisfied — should not match")
	}
}

// TestPipeline_FilterModeAND_RequiresAll verifies the default AND mode:
// all conditions must be satisfied for the rule to fire.
func TestPipeline_FilterModeAND_RequiresAll(t *testing.T) {
	p := newTestPipeline([]model.ETLRule{
		{
			RuleID: "and-partial", IsEnabled: true, Priority: 1,
			Match: model.ETLMatchCriteria{
				FilterExpr: "severity=high and env=prod",
				FilterMode: "", // default AND
			},
			RawWriteMode: model.RawWriteBoth,
			Output:       model.ETLOutput{NgxIndex: "and_out"},
		},
	})

	// severity=high is true but env=dev != prod — AND requires both.
	entry := &model.LogEntry{
		Kind:   model.LogKindProcess,
		Fields: map[string]any{"severity": "high", "env": "dev"},
	}
	res := p.Process(context.Background(), entry, "any.tag")

	if res.Matched {
		t.Error("AND mode: env!=prod — all conditions required but not all satisfied")
	}
}

// ── D. Raw write ──────────────────────────────────────────────────────────────

// TestPipeline_RawOnly_NoSinks verifies that a raw_only rule produces a
// non-empty RawNgxIndex and suppresses ETL output entirely.
func TestPipeline_RawOnly_NoSinks(t *testing.T) {
	p := newTestPipeline([]model.ETLRule{
		{
			RuleID: "rawonly-rule", IsEnabled: true, Priority: 1,
			Match:        model.ETLMatchCriteria{TagPattern: "rawonly.test"},
			RawWriteMode: model.RawWriteRawOnly,
			Output:       model.ETLOutput{NgxIndex: "etl_that_should_not_be_used"},
		},
	})

	entry := &model.LogEntry{
		Kind:   model.LogKindProcess,
		Fields: map[string]any{},
	}
	res := p.Process(context.Background(), entry, "rawonly.test")

	if !res.Matched {
		t.Error("expected Matched=true for raw_only rule")
	}
	if res.RawNgxIndex == "" {
		t.Error("raw_only: RawNgxIndex should be non-empty")
	}
	if res.ETLEntry != nil {
		t.Errorf("raw_only: ETLEntry should be nil, got %v", res.ETLEntry)
	}
	if len(res.Sinks) != 0 {
		t.Errorf("raw_only: expected 0 sinks, got %d", len(res.Sinks))
	}
}

// TestPipeline_NoMatch_RawStillWritten verifies that when no rule matches, the
// raw event is still routed to the raw ngx index.
func TestPipeline_NoMatch_RawStillWritten(t *testing.T) {
	// Pipeline has a rule that only matches tag "other.*" — our entry uses
	// "unmatched.tag" so no rule fires.
	p := newTestPipeline([]model.ETLRule{
		{
			RuleID: "irrelevant", IsEnabled: true, Priority: 1,
			Match:        model.ETLMatchCriteria{TagPattern: "other.*"},
			RawWriteMode: model.RawWriteBoth,
			Output:       model.ETLOutput{NgxIndex: "other_out"},
		},
	})

	entry := &model.LogEntry{
		Kind:   model.LogKindProcess,
		Fields: map[string]any{},
	}
	res := p.Process(context.Background(), entry, "unmatched.tag")

	if res.Matched {
		t.Error("expected Matched=false — no rule covers unmatched.tag")
	}
	if res.RawNgxIndex == "" {
		t.Error("no-match: RawNgxIndex should still be set to raw_<tag>")
	}
}
