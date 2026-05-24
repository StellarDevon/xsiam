package etl

import (
	"context"
	"sync"
	"xsiam/internal/model"
)

// Result is returned by Pipeline.Process for each event.
// It carries the routing decisions the ingest handler needs to act on.
type Result struct {
	// RawNgxIndex is the ngx HEC index for the raw (pre-ETL) event.
	// Always "raw_<tag>" regardless of the matched rule.
	// Empty string means: do not write raw event (RawWriteMode == etl_only).
	RawNgxIndex string

	// ETLEntry is the transformed log entry, or nil if the event was dropped
	// or RawWriteMode == raw_only.
	ETLEntry *model.LogEntry

	// ETLNgxIndex is the ngx HEC index for the ETL-transformed event.
	// Empty string means: do not write ETL event to ngx.
	ETLNgxIndex string

	// WriteArango indicates whether ETLEntry should also be written to
	// ArangoDB log_entries for XQL access.
	WriteArango bool

	// Matched is true when a rule was found and applied.
	Matched bool
}

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

// Process evaluates all rules against entry+tag, applies the first match, and
// returns routing instructions.  The caller (ingest.Handler) uses the Result
// to decide what to write where.
//
// If no rule matches, the event is treated as raw-only: it is written to
// ngx under "raw_<tag>" and to ArangoDB log_entries unchanged (so that at
// minimum everything is queryable via XQL).
func (p *Pipeline) Process(ctx context.Context, entry *model.LogEntry, tag string) Result {
	p.mu.RLock()
	rules := p.rules
	p.mu.RUnlock()

	rawIndex := "raw_" + tag

	// Find first matching rule
	for _, rule := range rules {
		if !matchesEntry(rule, entry, tag) {
			continue
		}

		// Matched — honour RawWriteMode
		res := Result{Matched: true}

		switch rule.RawWriteMode {
		case model.RawWriteRawOnly:
			// Skip ETL entirely; only write the raw event.
			res.RawNgxIndex = rawIndex
			return res

		case model.RawWriteETLOnly:
			// Suppress raw; only write the ETL result.
			res.RawNgxIndex = "" // do not write raw

		default: // RawWriteBoth or empty
			res.RawNgxIndex = rawIndex
		}

		// Clone the entry so the original is not mutated
		// (needed when RawWriteMode == both — raw must stay unmodified)
		clone := cloneEntry(entry)
		var transformed *model.LogEntry
		var drop bool
		if p.executor != nil {
			transformed, drop = p.executor.ApplyActions(ctx, clone, rule.Actions)
		} else {
			// Nil executor (test/stub mode): apply only built-in drop_event check
			transformed = clone
			for _, a := range rule.Actions {
				if a.Type == model.ETLActionDropEvent {
					drop = true
					break
				}
			}
		}
		if drop || transformed == nil {
			// drop_event action fired — discard everything including raw
			res.RawNgxIndex = ""
			return res
		}

		res.ETLEntry = transformed
		res.ETLNgxIndex = rule.Output.NgxIndex
		res.WriteArango = rule.Output.WriteArango
		return res
	}

	// No rule matched — default: write raw to ngx AND to ArangoDB
	return Result{
		RawNgxIndex: rawIndex,
		ETLEntry:    entry,   // unchanged entry goes to ArangoDB
		ETLNgxIndex: "",      // no separate ETL ngx index
		WriteArango: true,
		Matched:     false,
	}
}

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
