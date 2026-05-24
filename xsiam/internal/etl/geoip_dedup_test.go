package etl

import (
	"context"
	"sync"
	"testing"
	"time"

	"xsiam/internal/model"
)

// ─── Deduplicator tests ───────────────────────────────────────────────────────

// TestDeduplicator_FirstPassAllowed verifies that the first occurrence of a
// (tenantID, keyVal) pair is allowed through (IsDuplicate returns false).
func TestDeduplicator_FirstPassAllowed(t *testing.T) {
	d := NewDeduplicator()
	got := d.IsDuplicate("tenant-1", "event-abc", 60)
	if got {
		t.Error("first occurrence should not be a duplicate (want false, got true)")
	}
}

// TestDeduplicator_SecondPassBlocked verifies that a second call with the same
// (tenantID, keyVal) within the window is classified as a duplicate.
func TestDeduplicator_SecondPassBlocked(t *testing.T) {
	d := NewDeduplicator()
	key := "event-xyz"
	tenant := "tenant-A"

	first := d.IsDuplicate(tenant, key, 60)
	if first {
		t.Fatal("first call must not be a duplicate")
	}

	second := d.IsDuplicate(tenant, key, 60)
	if !second {
		t.Error("second call within window should be a duplicate (want true, got false)")
	}
}

// TestDeduplicator_DifferentTenantIsolated verifies that the same keyVal for
// different tenant IDs does NOT interfere with each other.
func TestDeduplicator_DifferentTenantIsolated(t *testing.T) {
	d := NewDeduplicator()
	key := "shared-event"

	r1 := d.IsDuplicate("tenant-1", key, 60)
	r2 := d.IsDuplicate("tenant-2", key, 60)

	if r1 {
		t.Error("tenant-1 first call should not be duplicate")
	}
	if r2 {
		t.Error("tenant-2 first call should not be duplicate — different tenant")
	}

	// Second calls: each tenant's second occurrence must be flagged.
	if !d.IsDuplicate("tenant-1", key, 60) {
		t.Error("tenant-1 second call within window should be duplicate")
	}
	if !d.IsDuplicate("tenant-2", key, 60) {
		t.Error("tenant-2 second call within window should be duplicate")
	}
}

// TestDeduplicator_WindowExpiry verifies that after the dedup window expires,
// the same key is treated as a fresh first occurrence (IsDuplicate returns false).
func TestDeduplicator_WindowExpiry(t *testing.T) {
	d := NewDeduplicator()
	tenant := "tenant-exp"
	key := "expiring-event"

	// Use a 1-second window.
	windowSec := 1
	first := d.IsDuplicate(tenant, key, windowSec)
	if first {
		t.Fatal("first call must not be a duplicate")
	}

	// Second call within the window — must be duplicate.
	if !d.IsDuplicate(tenant, key, windowSec) {
		t.Error("second call within window should be a duplicate")
	}

	// Wait for the window to expire (1.1 s > 1 s window).
	time.Sleep(1100 * time.Millisecond)

	// After expiry the key should be treated as new.
	afterExpiry := d.IsDuplicate(tenant, key, windowSec)
	if afterExpiry {
		t.Error("after window expiry, key should be allowed (want false, got true)")
	}
}

// TestDeduplicator_Len verifies that Len() reflects the number of active entries
// currently tracked in the deduplicator.
func TestDeduplicator_Len(t *testing.T) {
	d := NewDeduplicator()
	if d.Len() != 0 {
		t.Errorf("empty deduplicator: expected Len()=0, got %d", d.Len())
	}

	d.IsDuplicate("t1", "key-A", 60)
	if d.Len() != 1 {
		t.Errorf("after 1 unique key: expected Len()=1, got %d", d.Len())
	}

	// Same key again — no new entry should be added.
	d.IsDuplicate("t1", "key-A", 60)
	if d.Len() != 1 {
		t.Errorf("after duplicate: expected Len()=1, got %d", d.Len())
	}

	// New key — a second distinct entry.
	d.IsDuplicate("t1", "key-B", 60)
	if d.Len() != 2 {
		t.Errorf("after 2 unique keys: expected Len()=2, got %d", d.Len())
	}

	// Different tenant same key — composite key differs, so 3 total.
	d.IsDuplicate("t2", "key-A", 60)
	if d.Len() != 3 {
		t.Errorf("after different tenant: expected Len()=3, got %d", d.Len())
	}
}

// TestDeduplicator_Concurrent verifies that concurrent calls to IsDuplicate do
// not cause data races or panics.  Run with -race for full validation.
func TestDeduplicator_Concurrent(t *testing.T) {
	d := NewDeduplicator()

	const goroutines = 100
	var wg sync.WaitGroup
	wg.Add(goroutines)

	for i := range goroutines {
		go func(n int) {
			defer wg.Done()
			tenant := "tenant-concurrent"
			// Half the goroutines share the same key (stress dedup path),
			// the other half use unique keys (stress insertion path).
			var key string
			if n%2 == 0 {
				key = "shared-key"
			} else {
				key = "unique-key-" + string(rune('A'+n%26))
			}
			// Must not panic — return value is intentionally ignored.
			_ = d.IsDuplicate(tenant, key, 60)
		}(i)
	}

	wg.Wait() // if no panic and -race passes, the test succeeds
}

// ─── GeoIPDB nil-safety tests ─────────────────────────────────────────────────

// TestGeoIPDB_NilLookupReturnsEmpty verifies that calling Lookup on a nil
// *GeoIPDB returns an empty GeoRecord without panicking.
func TestGeoIPDB_NilLookupReturnsEmpty(t *testing.T) {
	var g *GeoIPDB // nil
	rec := g.Lookup("1.2.3.4")
	if rec.Country != "" || rec.City != "" || rec.ASN != 0 || rec.ASNOrg != "" {
		t.Errorf("nil GeoIPDB.Lookup should return empty GeoRecord, got %+v", rec)
	}
}

// TestGeoIPDB_NilLookupInActionExecutor verifies that when geoipDB is nil in
// the ActionExecutor, executing a lookup_geoip action is a no-op: it neither
// panics nor adds geo_* fields to the entry.
func TestGeoIPDB_NilLookupInActionExecutor(t *testing.T) {
	// geoipDB is nil — lookup_geoip must silently no-op.
	ex := NewActionExecutor(nil, nil, nil, nil, nil, nopLog())

	entry := &model.LogEntry{
		TenantID: "tenant-geo",
		SourceIP: "8.8.8.8",
		Fields:   map[string]any{"src_ip": "8.8.8.8"},
	}

	actions := []model.ETLAction{
		{
			Type:   model.ETLActionLookupGeoIP,
			Params: map[string]any{"src_key": "src_ip"},
		},
	}

	out, drop := ex.ApplyActions(context.Background(), entry, actions)

	if drop {
		t.Error("lookup_geoip with nil db should not drop the entry")
	}
	if out == nil {
		t.Fatal("lookup_geoip with nil db should return the original entry, not nil")
	}

	// No geo_* fields should have been injected.
	for _, field := range []string{"geo_country", "geo_city", "geo_asn", "geo_asn_org"} {
		if _, exists := out.Fields[field]; exists {
			t.Errorf("nil geoipDB: unexpected field %q found in entry.Fields", field)
		}
	}
}

// TestGeoIPDB_NilClose verifies that calling Close on a nil *GeoIPDB does not
// panic (the method has an explicit nil guard).
func TestGeoIPDB_NilClose(t *testing.T) {
	var g *GeoIPDB
	// Must not panic.
	g.Close()
}

// ─── ActionExecutor dedup integration tests ───────────────────────────────────

// TestActionExecutor_Dedup_BlocksDuplicate verifies that with a real Deduplicator
// wired into the ActionExecutor, the second identical event is dropped.
func TestActionExecutor_Dedup_BlocksDuplicate(t *testing.T) {
	dedup := NewDeduplicator()
	ex := NewActionExecutor(nil, nil, nil, dedup, nil, nopLog())

	makeEntry := func() *model.LogEntry {
		return &model.LogEntry{
			TenantID: "tenant-dedup",
			Fields:   map[string]any{"event_id": "EVT-001"},
		}
	}

	actions := []model.ETLAction{
		{
			Type: model.ETLActionDedup,
			Params: map[string]any{
				"key":            "event_id",
				"window_seconds": 60,
			},
		},
	}

	// First pass — must be allowed.
	out1, drop1 := ex.ApplyActions(context.Background(), makeEntry(), actions)
	if drop1 || out1 == nil {
		t.Error("first occurrence should be allowed (drop1=false)")
	}

	// Second pass — must be dropped as duplicate.
	out2, drop2 := ex.ApplyActions(context.Background(), makeEntry(), actions)
	if !drop2 {
		t.Error("second occurrence within window should be dropped (drop2=true)")
	}
	_ = out2
}

// TestActionExecutor_Dedup_NilNoOp verifies that when the Deduplicator is nil,
// the dedup action is silently skipped and the entry is not dropped.
func TestActionExecutor_Dedup_NilNoOp(t *testing.T) {
	// dedup is nil — dedup action must no-op.
	ex := NewActionExecutor(nil, nil, nil, nil, nil, nopLog())

	entry := &model.LogEntry{
		TenantID: "tenant-nil-dedup",
		Fields:   map[string]any{"event_id": "EVT-002"},
	}

	actions := []model.ETLAction{
		{
			Type: model.ETLActionDedup,
			Params: map[string]any{
				"key":            "event_id",
				"window_seconds": 60,
			},
		},
	}

	// Call twice — with nil dedup neither should be dropped.
	for i := range 2 {
		out, drop := ex.ApplyActions(context.Background(), entry, actions)
		if drop || out == nil {
			t.Errorf("call %d: nil dedup should not drop entry", i+1)
		}
	}
}
