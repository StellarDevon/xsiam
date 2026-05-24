package etl

import (
	"context"
	"sync"
	"xsiam/internal/model"
)

// ── SinkResult ────────────────────────────────────────────────────────────────

// SinkResult is one resolved output destination for an ETL-transformed event.
type SinkResult struct {
	NgxIndex         string          // ngx HEC index name (empty = no ngx write)
	ArangoCollection string          // ArangoDB collection name (empty = no arango write)
	TTLDays          int             // TTL for ArangoDB documents (0 = no TTL)
	Entry            *model.LogEntry // the entry to write (may be filtered by Sink.Condition)
}

// ── Result ────────────────────────────────────────────────────────────────────

// Result is returned by Pipeline.Process for each event.
// It carries the routing decisions the ingest handler needs to act on.
type Result struct {
	// RawNgxIndex is the ngx HEC index for the raw (pre-ETL) event.
	// Always "raw_<tag>" unless RawWriteMode == etl_only (which suppresses raw).
	// Empty string means: do not write raw event.
	RawNgxIndex string

	// ETLEntry is the final transformed log entry, or nil if the event was
	// dropped (drop_event) or RawWriteMode == raw_only.
	ETLEntry *model.LogEntry

	// Sinks holds the resolved output destinations derived from Output.Sinks.
	// Empty when no rule matched or the event was dropped.
	Sinks []SinkResult

	// Matched is true when at least one rule was found and applied.
	Matched bool

	// ── Backward-compat accessors (single-sink) ────────────────────────────
	// These are set from Sinks[0] when exactly one sink was resolved.
	// They allow callers that haven't migrated to Sinks to keep working.
	ETLNgxIndex      string // = Sinks[0].NgxIndex      (first non-empty)
	ArangoCollection string // = Sinks[0].ArangoCollection (first non-empty)
	TTLDays          int    // = Sinks[0].TTLDays
}

// ── Pipeline ──────────────────────────────────────────────────────────────────

// Pipeline holds the compiled rule set and applies it to incoming events.
// All methods are safe for concurrent use.
type Pipeline struct {
	mu       sync.RWMutex
	rules    []compiledRule
	executor *ActionExecutor
}

// NewPipeline constructs an empty Pipeline. Call RuleEngine.LoadRules to
// populate it before processing events.
func NewPipeline(executor *ActionExecutor) *Pipeline {
	return &Pipeline{executor: executor}
}

// Replace atomically swaps the active rule set.  Called by RuleEngine after
// each successful reload from ArangoDB.
func (p *Pipeline) Replace(rules []compiledRule) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.rules = rules
}

// ── Process ───────────────────────────────────────────────────────────────────

// Process evaluates all rules against entry+tag, applies matching rule(s), and
// returns routing instructions.  The caller (ingest.Handler) uses the Result
// to decide what to write where.
//
// Evaluation modes:
//
//	first_match  (default): stop at the first rule whose criteria match.
//	sequential           : apply ALL matching sequential-mode rules in order,
//	                       chaining entry transformations; last rule determines sinks.
//
// If no rule matches, only the raw event is written to ngx "raw_<tag>".
// There is no ArangoDB fallback for unmatched events.
func (p *Pipeline) Process(ctx context.Context, entry *model.LogEntry, tag string) Result {
	p.mu.RLock()
	rules := p.rules
	p.mu.RUnlock()

	rawIndex := "raw_" + tag

	// ── Sequential pass ──────────────────────────────────────────────────────
	// Collect all sequential rules that match, apply them in priority order,
	// chain transformed entries, and use the last rule's Output.
	var seqMatched []compiledRule
	for _, rule := range rules {
		if rule.ProcessingMode == model.ProcessingSequential && matchesEntry(rule, entry, tag) {
			seqMatched = append(seqMatched, rule)
		}
	}

	// If there are sequential rules, run them first and return combined result.
	if len(seqMatched) > 0 {
		current := cloneEntry(entry)
		var lastRule compiledRule
		var rawIdx string = rawIndex

		for _, rule := range seqMatched {
			// Honor raw write mode of the first sequential rule for raw suppression.
			if rule.RawWriteMode == model.RawWriteETLOnly {
				rawIdx = ""
			}
			if rule.RawWriteMode == model.RawWriteRawOnly {
				// Raw-only sequential rule: stops the chain.
				return Result{
					RawNgxIndex: rawIdx,
					Matched:     true,
				}
			}
			// Apply actions
			var drop bool
			if p.executor != nil {
				current, drop = p.executor.ApplyActions(ctx, current, rule.Actions)
			} else {
				for _, a := range rule.Actions {
					if a.Type == model.ETLActionDropEvent {
						drop = true
						break
					}
				}
			}
			if drop || current == nil {
				return Result{RawNgxIndex: "", Matched: true}
			}
			lastRule = rule
		}

		sinks := resolveSinks(lastRule.Output, current, tag)
		res := Result{
			RawNgxIndex: rawIdx,
			ETLEntry:    current,
			Sinks:       sinks,
			Matched:     true,
		}
		fillBackcompat(&res)
		return res
	}

	// ── First-match pass ─────────────────────────────────────────────────────
	for _, rule := range rules {
		if rule.ProcessingMode == model.ProcessingSequential {
			continue // already handled above
		}
		if !matchesEntry(rule, entry, tag) {
			continue
		}

		res := Result{Matched: true}

		switch rule.RawWriteMode {
		case model.RawWriteRawOnly:
			res.RawNgxIndex = rawIndex
			return res
		case model.RawWriteETLOnly:
			res.RawNgxIndex = ""
		default:
			res.RawNgxIndex = rawIndex
		}

		// Clone so the raw event stays unmodified (needed for RawWriteBoth).
		clone := cloneEntry(entry)
		var drop bool
		if p.executor != nil {
			clone, drop = p.executor.ApplyActions(ctx, clone, rule.Actions)
		} else {
			for _, a := range rule.Actions {
				if a.Type == model.ETLActionDropEvent {
					drop = true
					break
				}
			}
		}
		if drop || clone == nil {
			res.RawNgxIndex = ""
			return res
		}

		res.ETLEntry = clone
		res.Sinks = resolveSinks(rule.Output, clone, tag)
		fillBackcompat(&res)
		return res
	}

	// No rule matched.
	return Result{
		RawNgxIndex: rawIndex,
		Matched:     false,
	}
}

// ── resolveSinks ─────────────────────────────────────────────────────────────

// resolveSinks builds the []SinkResult from an ETLOutput.
//
// Priority:
//  1. If Output.Sinks is non-empty, each ETLSink is evaluated.
//  2. Otherwise, the legacy flat fields (NgxIndex, ArangoCollection, TTLDays)
//     are promoted to a single SinkResult for backward compatibility.
func resolveSinks(out model.ETLOutput, entry *model.LogEntry, tag string) []SinkResult {
	// ── Legacy flat-field promotion ──────────────────────────────────────────
	if len(out.Sinks) == 0 {
		if out.NgxIndex == "" && out.ArangoCollection == "" {
			return nil
		}
		return []SinkResult{{
			NgxIndex:         out.NgxIndex,
			ArangoCollection: out.ArangoCollection,
			TTLDays:          out.TTLDays,
			Entry:            entry,
		}}
	}

	// ── Multi-sink resolution ────────────────────────────────────────────────
	var results []SinkResult
	for _, sink := range out.Sinks {
		if sink.NgxIndex == "" && sink.ArangoCollection == "" {
			continue // no-op sink
		}
		// Evaluate optional per-sink condition
		if sink.Condition != "" {
			conds := parseFilterExpr(sink.Condition)
			// All conditions must match (AND)
			allMatch := true
			for _, c := range conds {
				if !c.matches(entry) {
					allMatch = false
					break
				}
			}
			if !allMatch {
				continue // this sink's condition not satisfied — skip
			}
		}
		results = append(results, SinkResult{
			NgxIndex:         sink.NgxIndex,
			ArangoCollection: sink.ArangoCollection,
			TTLDays:          sink.TTLDays,
			Entry:            entry,
		})
	}
	return results
}

// ── fillBackcompat ────────────────────────────────────────────────────────────

// fillBackcompat populates the legacy single-sink fields from res.Sinks[0]
// so that callers that haven't migrated to Sinks still work.
func fillBackcompat(res *Result) {
	for _, s := range res.Sinks {
		if s.NgxIndex != "" {
			res.ETLNgxIndex = s.NgxIndex
		}
		if s.ArangoCollection != "" {
			res.ArangoCollection = s.ArangoCollection
			res.TTLDays = s.TTLDays
		}
		if res.ETLNgxIndex != "" && res.ArangoCollection != "" {
			break
		}
	}
}

// ── cloneEntry ───────────────────────────────────────────────────────────────

// cloneEntry returns a shallow copy of e with a deep-copied Fields map.
func cloneEntry(e *model.LogEntry) *model.LogEntry {
	clone := *e
	if e.Fields != nil {
		clone.Fields = make(map[string]any, len(e.Fields))
		for k, v := range e.Fields {
			clone.Fields[k] = v
		}
	}
	return &clone
}
