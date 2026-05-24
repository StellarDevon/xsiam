package etl

import (
	"sync"
	"time"
)

// Deduplicator is a thread-safe, in-memory sliding-window deduplicator.
//
// For each (tenantID, keyValue) pair, the first occurrence within the
// configured window is allowed through; subsequent identical occurrences
// within the same window are classified as duplicates and should be dropped.
//
// Expired entries are lazily evicted on every IsDuplicate call to prevent
// unbounded memory growth without requiring a background goroutine.
type Deduplicator struct {
	mu   sync.Mutex
	seen map[string]time.Time // key: "tenantID\x00keyVal" → first-seen time
}

// NewDeduplicator constructs an empty Deduplicator.
func NewDeduplicator() *Deduplicator {
	return &Deduplicator{
		seen: make(map[string]time.Time),
	}
}

// IsDuplicate reports whether (tenantID, keyVal) has been seen within the
// last windowSec seconds.
//
//   - First call for a key within the window: records the timestamp, returns false.
//   - Subsequent calls within the window: returns true (duplicate — caller should drop).
//   - Call after the window expires: treated as a new first occurrence, returns false.
//
// windowSec ≤ 0 disables deduplication (always returns false).
func (d *Deduplicator) IsDuplicate(tenantID, keyVal string, windowSec int) bool {
	if windowSec <= 0 || keyVal == "" {
		return false
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	now := time.Now()
	window := time.Duration(windowSec) * time.Second
	compositeKey := tenantID + "\x00" + keyVal

	// Lazy eviction: remove entries whose window has expired.
	// Only sweep a bounded set to keep the critical path fast.
	// Full sweep happens here to keep memory bounded.
	for k, t := range d.seen {
		if now.Sub(t) > window {
			delete(d.seen, k)
		}
	}

	if firstSeen, ok := d.seen[compositeKey]; ok {
		if now.Sub(firstSeen) <= window {
			return true // duplicate within window
		}
		// Window expired for this key — treat as new occurrence.
	}

	d.seen[compositeKey] = now
	return false
}

// Len returns the number of active (non-expired, approximately) entries.
// Primarily useful for testing and monitoring.
func (d *Deduplicator) Len() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.seen)
}
