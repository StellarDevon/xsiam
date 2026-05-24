package repository

import (
	"context"
	"fmt"
	"time"
	"xsiam/internal/model"

	"github.com/arangodb/go-driver/v2/arangodb"
	"github.com/arangodb/go-driver/v2/arangodb/shared"
)

// Collection names
const (
	colNetworkConnections   = "network_connections"
	colDNSRecords           = "dns_records"
	colNetworkDetectRules   = "network_detection_rules"
	colNetworkAlerts        = "network_alerts"
	colNetworkDevices       = "network_devices"
)

// ─── NetworkRepo ──────────────────────────────────────────────────────────────

type NetworkRepo struct {
	db arangodb.Database
}

func NewNetworkRepo(db arangodb.Database) *NetworkRepo {
	return &NetworkRepo{db: db}
}

// ─── Connections ──────────────────────────────────────────────────────────────

func (r *NetworkRepo) ListConnections(ctx context.Context, tenantID string, page, pageSize int, status, severity string) ([]model.NetworkConnection, model.PageMeta, error) {
	filters, bv := InjectTenantFilter(nil, map[string]any{}, tenantID)
	if status != "" {
		filters = append(filters, "doc.status == @status")
		bv["status"] = status
	}
	if severity != "" {
		filters = append(filters, "doc.severity == @severity")
		bv["severity"] = severity
	}
	var data []model.NetworkConnection
	meta, err := FindPaged(ctx, r.db, ListOptions{
		Collection: colNetworkConnections,
		Filters:    filters,
		BindVars:   bv,
		SortBy:     "detected_at",
		SortDesc:   true,
		Page:       page,
		PageSize:   pageSize,
	}, &data)
	return data, meta, err
}

func (r *NetworkRepo) GetConnection(ctx context.Context, key string) (*model.NetworkConnection, error) {
	col, _ := r.db.Collection(ctx, colNetworkConnections)
	var conn model.NetworkConnection
	if _, err := col.ReadDocument(ctx, key, &conn); err != nil {
		if shared.IsNotFound(err) {
			return nil, fmt.Errorf("connection %s not found", key)
		}
		return nil, err
	}
	return &conn, nil
}

func (r *NetworkRepo) CreateConnection(ctx context.Context, conn *model.NetworkConnection) error {
	now := time.Now()
	conn.CreatedAt = now
	conn.UpdatedAt = now
	// Ensure BytesTransferred is the sum when not set explicitly.
	if conn.BytesTransferred == 0 {
		conn.BytesTransferred = conn.BytesInbound + conn.BytesOutbound
	}
	col, _ := r.db.Collection(ctx, colNetworkConnections)
	meta, err := col.CreateDocument(ctx, conn)
	if err != nil {
		return err
	}
	conn.Key = meta.Key
	return nil
}

func (r *NetworkRepo) UpdateConnection(ctx context.Context, key string, patch map[string]any) error {
	patch["updated_at"] = time.Now()
	col, _ := r.db.Collection(ctx, colNetworkConnections)
	_, err := col.UpdateDocument(ctx, key, patch)
	return err
}

func (r *NetworkRepo) CountConnections(ctx context.Context, tenantID, status string) (int64, error) {
	q := `FOR doc IN network_connections FILTER doc.tenant_id == @tid`
	bv := map[string]any{"tid": tenantID}
	if status != "" {
		q += ` AND doc.status == @status`
		bv["status"] = status
	}
	q += ` COLLECT WITH COUNT INTO n RETURN n`
	cursor, err := r.db.Query(ctx, q, &arangodb.QueryOptions{BindVars: bv})
	if err != nil {
		return 0, err
	}
	defer cursor.Close()
	var n int64
	if cursor.HasMore() {
		if _, err = cursor.ReadDocument(ctx, &n); err != nil {
			return 0, err
		}
	}
	return n, nil
}

// ─── DNS Records ──────────────────────────────────────────────────────────────

func (r *NetworkRepo) ListDNS(ctx context.Context, tenantID string, page, pageSize int, risk, keyword string) ([]model.DNSRecord, model.PageMeta, error) {
	filters, bv := InjectTenantFilter(nil, map[string]any{}, tenantID)
	if risk != "" {
		filters = append(filters, "doc.risk_level == @risk")
		bv["risk"] = risk
	}
	if keyword != "" {
		filters = append(filters, "CONTAINS(LOWER(doc.domain), LOWER(@q))")
		bv["q"] = keyword
	}
	var data []model.DNSRecord
	meta, err := FindPaged(ctx, r.db, ListOptions{
		Collection: colDNSRecords,
		Filters:    filters,
		BindVars:   bv,
		SortBy:     "query_count",
		SortDesc:   true,
		Page:       page,
		PageSize:   pageSize,
	}, &data)
	return data, meta, err
}

func (r *NetworkRepo) GetDNSByDomain(ctx context.Context, tenantID, domain string) (*model.DNSRecord, error) {
	q := `FOR doc IN dns_records FILTER doc.tenant_id == @tid AND doc.domain == @domain LIMIT 1 RETURN doc`
	cursor, err := r.db.Query(ctx, q, &arangodb.QueryOptions{
		BindVars: map[string]any{"tid": tenantID, "domain": domain},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()
	if !cursor.HasMore() {
		return nil, nil
	}
	var rec model.DNSRecord
	_, err = cursor.ReadDocument(ctx, &rec)
	return &rec, err
}

func (r *NetworkRepo) UpsertDNSBlocklist(ctx context.Context, tenantID, domain, operatorID string) error {
	now := time.Now()
	q := `
		UPSERT { tenant_id: @tid, domain: @domain }
		INSERT {
			tenant_id: @tid, domain: @domain,
			risk_level: "high", is_blocklisted: true,
			blocklisted_at: @now, blocklisted_by: @op,
			first_seen: @now, last_seen: @now,
			created_at: @now
		}
		UPDATE {
			is_blocklisted: true,
			blocklisted_at: @now, blocklisted_by: @op
		}
		IN dns_records
	`
	cursor, err := r.db.Query(ctx, q, &arangodb.QueryOptions{
		BindVars: map[string]any{
			"tid":    tenantID,
			"domain": domain,
			"op":     operatorID,
			"now":    now,
		},
	})
	if err != nil {
		return err
	}
	return cursor.Close()
}

func (r *NetworkRepo) CountDNS(ctx context.Context, tenantID string, onlyBlocklisted bool) (int64, error) {
	q := `FOR doc IN dns_records FILTER doc.tenant_id == @tid`
	bv := map[string]any{"tid": tenantID}
	if onlyBlocklisted {
		q += ` AND doc.is_blocklisted == true`
	}
	q += ` COLLECT WITH COUNT INTO n RETURN n`
	cursor, err := r.db.Query(ctx, q, &arangodb.QueryOptions{BindVars: bv})
	if err != nil {
		return 0, err
	}
	defer cursor.Close()
	var n int64
	if cursor.HasMore() {
		_, _ = cursor.ReadDocument(ctx, &n)
	}
	return n, nil
}

// ─── Network Detection Rules ──────────────────────────────────────────────────

func (r *NetworkRepo) ListNetworkRules(ctx context.Context, tenantID string) ([]model.NetworkDetectionRule, error) {
	q := `FOR doc IN network_detection_rules FILTER doc.tenant_id == @tid SORT doc.name ASC RETURN doc`
	cursor, err := r.db.Query(ctx, q, &arangodb.QueryOptions{
		BindVars: map[string]any{"tid": tenantID},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()
	var rules []model.NetworkDetectionRule
	for cursor.HasMore() {
		var rule model.NetworkDetectionRule
		if _, err = cursor.ReadDocument(ctx, &rule); err != nil {
			return nil, err
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

func (r *NetworkRepo) UpdateNetworkRule(ctx context.Context, key string, patch map[string]any) error {
	patch["updated_at"] = time.Now()
	col, _ := r.db.Collection(ctx, colNetworkDetectRules)
	_, err := col.UpdateDocument(ctx, key, patch)
	return err
}

func (r *NetworkRepo) CreateNetworkRule(ctx context.Context, rule *model.NetworkDetectionRule) error {
	now := time.Now()
	rule.CreatedAt = now
	rule.UpdatedAt = now
	col, _ := r.db.Collection(ctx, colNetworkDetectRules)
	meta, err := col.CreateDocument(ctx, rule)
	if err != nil {
		return err
	}
	rule.Key = meta.Key
	return nil
}

// ─── Network Threat Alerts ────────────────────────────────────────────────────

func (r *NetworkRepo) ListNetworkAlerts(ctx context.Context, tenantID string, page, pageSize int, status string) ([]model.NetworkThreatAlert, model.PageMeta, error) {
	filters, bv := InjectTenantFilter(nil, map[string]any{}, tenantID)
	if status != "" {
		filters = append(filters, "doc.status == @status")
		bv["status"] = status
	}
	var data []model.NetworkThreatAlert
	meta, err := FindPaged(ctx, r.db, ListOptions{
		Collection: colNetworkAlerts,
		Filters:    filters,
		BindVars:   bv,
		SortBy:     "detected_at",
		SortDesc:   true,
		Page:       page,
		PageSize:   pageSize,
	}, &data)
	return data, meta, err
}

func (r *NetworkRepo) UpdateNetworkAlert(ctx context.Context, key string, patch map[string]any) error {
	col, _ := r.db.Collection(ctx, colNetworkAlerts)
	_, err := col.UpdateDocument(ctx, key, patch)
	return err
}

func (r *NetworkRepo) CreateNetworkAlert(ctx context.Context, alert *model.NetworkThreatAlert) error {
	now := time.Now()
	alert.CreatedAt = now
	col, _ := r.db.Collection(ctx, colNetworkAlerts)
	meta, err := col.CreateDocument(ctx, alert)
	if err != nil {
		return err
	}
	alert.Key = meta.Key
	return nil
}

func (r *NetworkRepo) CreateNetworkDevice(ctx context.Context, dev *model.NetworkDevice) error {
	now := time.Now()
	dev.CreatedAt = now
	dev.UpdatedAt = now
	col, _ := r.db.Collection(ctx, colNetworkDevices)
	meta, err := col.CreateDocument(ctx, dev)
	if err != nil {
		return err
	}
	dev.Key = meta.Key
	return nil
}

func (r *NetworkRepo) CreateDNSRecord(ctx context.Context, rec *model.DNSRecord) error {
	col, _ := r.db.Collection(ctx, colDNSRecords)
	meta, err := col.CreateDocument(ctx, rec)
	if err != nil {
		return err
	}
	rec.Key = meta.Key
	return nil
}

func (r *NetworkRepo) CountNetworkAlerts(ctx context.Context, tenantID, status string) (int64, error) {
	q := `FOR doc IN network_alerts FILTER doc.tenant_id == @tid AND doc.status == @status COLLECT WITH COUNT INTO n RETURN n`
	cursor, err := r.db.Query(ctx, q, &arangodb.QueryOptions{
		BindVars: map[string]any{"tid": tenantID, "status": status},
	})
	if err != nil {
		return 0, err
	}
	defer cursor.Close()
	var n int64
	if cursor.HasMore() {
		_, _ = cursor.ReadDocument(ctx, &n)
	}
	return n, nil
}

// ─── Network Devices ──────────────────────────────────────────────────────────

func (r *NetworkRepo) ListNetworkDevices(ctx context.Context, tenantID string, page, pageSize int, deviceType, risk, keyword string) ([]model.NetworkDevice, model.PageMeta, error) {
	filters, bv := InjectTenantFilter(nil, map[string]any{}, tenantID)
	if deviceType != "" {
		filters = append(filters, "doc.device_type == @deviceType")
		bv["deviceType"] = deviceType
	}
	if risk != "" {
		filters = append(filters, "doc.risk == @risk")
		bv["risk"] = risk
	}
	if keyword != "" {
		filters = append(filters, "(CONTAINS(LOWER(doc.ip), LOWER(@q)) OR CONTAINS(LOWER(doc.hostname), LOWER(@q)) OR CONTAINS(LOWER(doc.mac), LOWER(@q)))")
		bv["q"] = keyword
	}
	var data []model.NetworkDevice
	meta, err := FindPaged(ctx, r.db, ListOptions{
		Collection: colNetworkDevices,
		Filters:    filters,
		BindVars:   bv,
		SortBy:     "last_active",
		SortDesc:   true,
		Page:       page,
		PageSize:   pageSize,
	}, &data)
	return data, meta, err
}

func (r *NetworkRepo) CountNetworkDevices(ctx context.Context, tenantID string, onlyUnknown, onlyNew bool) (int64, error) {
	q := `FOR doc IN network_devices FILTER doc.tenant_id == @tid`
	bv := map[string]any{"tid": tenantID}
	if onlyUnknown {
		q += ` AND doc.is_unknown == true`
	}
	if onlyNew {
		q += ` AND doc.is_new == true`
	}
	q += ` COLLECT WITH COUNT INTO n RETURN n`
	cursor, err := r.db.Query(ctx, q, &arangodb.QueryOptions{BindVars: bv})
	if err != nil {
		return 0, err
	}
	defer cursor.Close()
	var n int64
	if cursor.HasMore() {
		_, _ = cursor.ReadDocument(ctx, &n)
	}
	return n, nil
}

// ─── Traffic aggregations ─────────────────────────────────────────────────────

// AggregateTrafficStats returns (totalTrafficGB, activeConns, dnsQueriesToday)
// derived from the network_connections and dns_records collections.
// All three values default to 0 if the collections are empty.
func (r *NetworkRepo) AggregateTrafficStats(ctx context.Context, tenantID string) (float64, int64, int64) {
	// Total traffic: sum bytes_transferred across all connections for this tenant.
	tq := `
		LET bytes = (
			FOR doc IN network_connections FILTER doc.tenant_id == @tid
			RETURN doc.bytes_transferred
		)
		RETURN SUM(bytes) / 1073741824.0
	`
	var totalGB float64
	if cur, err := r.db.Query(ctx, tq, &arangodb.QueryOptions{BindVars: map[string]any{"tid": tenantID}}); err == nil {
		if cur.HasMore() {
			_, _ = cur.ReadDocument(ctx, &totalGB)
		}
		_ = cur.Close()
	}

	// Active connections: those not in blocked/closed state.
	aq := `FOR doc IN network_connections FILTER doc.tenant_id == @tid AND doc.status NOT IN ["blocked","closed"] COLLECT WITH COUNT INTO n RETURN n`
	var activeConns int64
	if cur, err := r.db.Query(ctx, aq, &arangodb.QueryOptions{BindVars: map[string]any{"tid": tenantID}}); err == nil {
		if cur.HasMore() {
			_, _ = cur.ReadDocument(ctx, &activeConns)
		}
		_ = cur.Close()
	}

	// DNS queries today: sum query_count for records updated in the last 24h.
	since := time.Now().Add(-24 * time.Hour)
	dq := `
		LET counts = (
			FOR doc IN dns_records FILTER doc.tenant_id == @tid AND doc.last_seen >= @since
			RETURN doc.query_count
		)
		RETURN SUM(counts)
	`
	var dnsToday int64
	if cur, err := r.db.Query(ctx, dq, &arangodb.QueryOptions{BindVars: map[string]any{"tid": tenantID, "since": since}}); err == nil {
		if cur.HasMore() {
			_, _ = cur.ReadDocument(ctx, &dnsToday)
		}
		_ = cur.Close()
	}

	return totalGB, activeConns, dnsToday
}

// HourlyTrafficBuckets returns 24 hourly traffic buckets for the last 24 hours.
// Each entry has "hour" (HH:00), "inbound_gb", "outbound_gb" derived from
// bytes_transferred split by direction stored on each connection record.
func (r *NetworkRepo) HourlyTrafficBuckets(ctx context.Context, tenantID string) ([]map[string]any, error) {
	since := time.Now().Truncate(time.Hour).Add(-23 * time.Hour)
	q := `
		FOR doc IN network_connections
		FILTER doc.tenant_id == @tid AND doc.detected_at >= @since
		LET h = DATE_HOUR(doc.detected_at)
		COLLECT hour = h INTO g
		RETURN {
			hour: hour,
			inbound_gb:  SUM(g[*].doc.bytes_inbound)  / 1073741824.0,
			outbound_gb: SUM(g[*].doc.bytes_outbound) / 1073741824.0
		}
	`
	cursor, err := r.db.Query(ctx, q, &arangodb.QueryOptions{
		BindVars: map[string]any{"tid": tenantID, "since": since},
	})
	if err != nil {
		return nil, err
	}
	defer cursor.Close()

	// Build a map of hour→bucket, fill all 24 slots.
	bucketMap := make(map[int]map[string]any, 24)
	for cursor.HasMore() {
		var row struct {
			Hour      int     `json:"hour"`
			InboundGB float64 `json:"inbound_gb"`
			OutboundGB float64 `json:"outbound_gb"`
		}
		if _, err = cursor.ReadDocument(ctx, &row); err != nil {
			continue
		}
		bucketMap[row.Hour] = map[string]any{
			"hour":        fmt.Sprintf("%02d:00", row.Hour),
			"inbound_gb":  row.InboundGB,
			"outbound_gb": row.OutboundGB,
		}
	}

	now := time.Now()
	data := make([]map[string]any, 24)
	for i := 0; i < 24; i++ {
		h := (now.Hour() - 23 + i + 24) % 24
		if b, ok := bucketMap[h]; ok {
			data[i] = b
		} else {
			data[i] = map[string]any{
				"hour":        fmt.Sprintf("%02d:00", h),
				"inbound_gb":  0.0,
				"outbound_gb": 0.0,
			}
		}
	}
	return data, nil
}
