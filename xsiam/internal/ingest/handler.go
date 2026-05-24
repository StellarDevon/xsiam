// Package ingest implements the XLOG binary framing receiver at
// POST /internal/agent/log (:18090).
//
// # Ingest pipeline
//
// Each XLOG batch received from fluent-bit goes through three stages:
//
//  1. Decode  — XLOG frame header + TLV body parsed; zstd TSV decompressed.
//  2. Route   — etl.Pipeline.Process() is called for every decoded LogEntry.
//     The pipeline returns a Result that specifies:
//     • RawNgxIndex   : ngx index for the raw event  ("raw_<tag>" or "")
//     • ETLEntry      : the transformed entry, or nil if dropped
//     • ETLNgxIndex   : ngx index for the ETL event  (customer name or "")
//     • WriteArango   : write ETLEntry to ArangoDB log_entries
//  3. Write   — results are fanned out to ngx HEC and/or ArangoDB.
//
// Default behaviour (no rule matches):
//   - raw event  → ngx  index "raw_<tag>"
//   - same entry → ArangoDB log_entries  (immediately queryable via XQL)
//
// With a matching ETL rule (example: RawWriteMode=both):
//   - raw event  → ngx  index "raw_<tag>"
//   - ETL entry  → ngx  index <rule.Output.NgxIndex>  (customer-defined)
//   - ETL entry  → ArangoDB log_entries  (if rule.Output.WriteArango)
package ingest

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/klauspost/compress/zstd"
	"go.uber.org/zap"
	"xsiam/internal/datalake"
	"xsiam/internal/etl"
	"xsiam/internal/model"
	"xsiam/internal/repository"
)

const maxBodyBytes = 32 << 20 // 32 MB hard cap per batch

// Handler handles POST /internal/agent/log.
type Handler struct {
	pipeline *etl.Pipeline               // nil disables ETL (raw-only mode)
	lakeClient *datalake.Client          // ngx HEC client for raw + ETL writes; nil = no ngx
	logRepo  *repository.LogEntryRepo    // ArangoDB log_entries repo; nil = no arango write
	tenantID string
	log      *zap.Logger
	dec      *zstd.Decoder
}

// NewHandler constructs an ingest Handler.
//
//   - pipeline   : ETL pipeline; pass nil to skip ETL (all events are raw-only)
//   - lakeClient : ngx HEC client; pass nil to skip ngx writes
//   - logRepo    : ArangoDB repo; pass nil to skip ArangoDB writes
//   - tenantID   : default tenant for agent-submitted data
func NewHandler(
	pipeline *etl.Pipeline,
	lakeClient *datalake.Client,
	logRepo *repository.LogEntryRepo,
	tenantID string,
	log *zap.Logger,
) (*Handler, error) {
	dec, err := zstd.NewReader(nil)
	if err != nil {
		return nil, fmt.Errorf("ingest: init zstd decoder: %w", err)
	}
	if tenantID == "" {
		tenantID = "t-super"
	}
	return &Handler{
		pipeline:   pipeline,
		lakeClient: lakeClient,
		logRepo:    logRepo,
		tenantID:   tenantID,
		log:        log,
		dec:        dec,
	}, nil
}

// Handle is the gin handler for POST /internal/agent/log.
func (h *Handler) Handle(c *gin.Context) {
	ct := c.GetHeader("Content-Type")
	if !strings.HasPrefix(ct, "application/x-xlog") {
		c.JSON(http.StatusUnsupportedMediaType, gin.H{"error": "expected Content-Type: application/x-xlog"})
		return
	}
	h.handleBinary(c)
}

func (h *Handler) handleBinary(c *gin.Context) {
	r := io.LimitReader(c.Request.Body, maxBodyBytes+1)

	hdr, err := ReadHeader(r)
	if err != nil {
		if IsMagicError(err) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "bad xlog magic"})
			return
		}
		c.JSON(http.StatusBadRequest, gin.H{"error": "malformed xlog header: " + err.Error()})
		return
	}
	if hdr.Version != Version {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported xlog version " + strconv.Itoa(int(hdr.Version))})
		return
	}
	if hdr.Type != TypeLogBatch {
		c.JSON(http.StatusBadRequest, gin.H{"error": "expected TypeLogBatch(0x01), got " + strconv.Itoa(int(hdr.Type))})
		return
	}
	if hdr.BodyLen > maxBodyBytes {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "body exceeds 32 MB"})
		return
	}

	body := make([]byte, hdr.BodyLen)
	if _, err := io.ReadFull(r, body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "truncated body: " + err.Error()})
		return
	}

	batch, err := DecodeBatch(body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "tlv decode: " + err.Error()})
		return
	}

	rows, err := h.decompress(batch)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "decompress: " + err.Error()})
		return
	}

	tag := hdr.Tag
	if tag == "" {
		tag = "agent_log"
	}
	agentID := strconv.FormatUint(hdr.AgentID, 10)

	stats, err := h.process(c.Request.Context(), agentID, tag, batch.Columns, rows)
	if err != nil {
		h.log.Error("ingest process failed",
			zap.String("agent_id", agentID),
			zap.String("tag", tag),
			zap.Error(err),
		)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ingest failed"})
		return
	}

	h.log.Info("xlog batch processed",
		zap.String("agent_id", agentID),
		zap.String("tag", tag),
		zap.Uint32("row_count", batch.RowCount),
		zap.Uint32("orig_bytes", batch.OrigSize),
		zap.Int("raw_ngx", stats.rawNgx),
		zap.Int("etl_ngx", stats.etlNgx),
		zap.Int("arango", stats.arango),
		zap.Int("dropped", stats.dropped),
	)

	c.JSON(http.StatusNoContent, nil)
}

type processStats struct {
	rawNgx  int
	etlNgx  int
	arango  int
	dropped int
}

// process decodes rows → LogEntry, routes each through the ETL pipeline,
// then fans out writes to ngx HEC and/or ArangoDB.
func (h *Handler) process(ctx context.Context, agentID, tag string, cols []string, rows [][]string) (processStats, error) {
	now := time.Now().UTC()
	dataset := tagToDataset(tag)
	colIdx := buildColIndex(cols)

	// Accumulate writes by destination to send in batches
	var rawNgxEvents []datalake.HECEvent       // raw_<tag>
	etlNgxEvents := map[string][]datalake.HECEvent{} // ngx_index → events
	var arangoEntries []*model.LogEntry

	var stats processStats

	for _, row := range rows {
		if len(row) == 0 {
			continue
		}

		entry := h.buildEntry(row, colIdx, agentID, tag, dataset, now)

		if h.pipeline != nil {
			res := h.pipeline.Process(ctx, entry, tag)

			if res.RawNgxIndex != "" && h.lakeClient != nil {
				rawNgxEvents = append(rawNgxEvents, entryToHEC(entry, res.RawNgxIndex, tag))
			}

			if res.ETLEntry == nil {
				stats.dropped++
				continue
			}

			if res.ETLNgxIndex != "" && h.lakeClient != nil {
				etlNgxEvents[res.ETLNgxIndex] = append(
					etlNgxEvents[res.ETLNgxIndex],
					entryToHEC(res.ETLEntry, res.ETLNgxIndex, tag),
				)
			}

			if res.WriteArango {
				arangoEntries = append(arangoEntries, res.ETLEntry)
			}
		} else {
			// No pipeline — raw-only: write to ngx raw_<tag> + ArangoDB
			if h.lakeClient != nil {
				rawNgxEvents = append(rawNgxEvents, entryToHEC(entry, "raw_"+tag, tag))
			}
			arangoEntries = append(arangoEntries, entry)
		}
	}

	// ── Flush raw ngx events ─────────────────────────────────────────────────
	if len(rawNgxEvents) > 0 && h.lakeClient != nil {
		if err := h.lakeClient.Ingest(ctx, rawNgxEvents); err != nil {
			h.log.Warn("ngx raw ingest failed", zap.String("tag", tag), zap.Error(err))
			// Non-fatal: continue to write ETL + ArangoDB
		} else {
			stats.rawNgx += len(rawNgxEvents)
		}
	}

	// ── Flush ETL ngx events (grouped by index) ──────────────────────────────
	for idx, events := range etlNgxEvents {
		if err := h.lakeClient.Ingest(ctx, events); err != nil {
			h.log.Warn("ngx etl ingest failed", zap.String("index", idx), zap.Error(err))
		} else {
			stats.etlNgx += len(events)
		}
	}

	// ── Flush ArangoDB entries ───────────────────────────────────────────────
	if len(arangoEntries) > 0 && h.logRepo != nil {
		if err := h.logRepo.BulkCreate(ctx, arangoEntries); err != nil {
			return stats, fmt.Errorf("arango bulk create: %w", err)
		}
		stats.arango += len(arangoEntries)
	}

	return stats, nil
}

// buildEntry converts a TSV row into a model.LogEntry.
func (h *Handler) buildEntry(row []string, colIdx map[string]int, agentID, tag, dataset string, now time.Time) *model.LogEntry {
	// Build fields map from all columns
	fields := make(map[string]any, len(colIdx))
	for col, i := range colIdx {
		if i < len(row) && row[i] != "" && col != "_time" && col != "event_timestamp" {
			fields[col] = row[i]
		}
	}

	hostname := getField(row, colIdx, "hostname")
	srcIP := getField(row, colIdx, "src_ip")
	if srcIP == "" {
		srcIP = getField(row, colIdx, "source_ip")
	}
	sessionID := getField(row, colIdx, "session_id")
	rawLog := getField(row, colIdx, "raw_log")
	kindVal := getField(row, colIdx, "kind")

	// Parse event timestamp
	eventTS := now
	for _, col := range []string{"_time", "event_timestamp"} {
		if t := getField(row, colIdx, col); t != "" {
			if parsed, err := time.Parse(time.RFC3339, t); err == nil {
				eventTS = parsed.UTC()
				break
			}
			if parsed, err := time.Parse(time.RFC3339Nano, t); err == nil {
				eventTS = parsed.UTC()
				break
			}
		}
	}

	kind := kindFromTag(tag, kindVal)
	ds := dataset
	if kind == model.LogKindSyslog && ds == model.DatasetEndpoint {
		ds = model.DatasetSyslog
	}

	// Remove top-level fields from Fields map to avoid duplication
	for _, k := range []string{"hostname", "src_ip", "source_ip", "session_id", "kind", "_time", "event_timestamp", "agent_id", "raw_log"} {
		delete(fields, k)
	}

	return &model.LogEntry{
		TenantID:       h.tenantID,
		Dataset:        ds,
		Kind:           kind,
		AgentID:        agentID,
		SessionID:      sessionID,
		Hostname:       hostname,
		SourceIP:       srcIP,
		Fields:         fields,
		RawLog:         rawLog,
		EventTimestamp: eventTS,
		IngestedAt:     now,
	}
}

// entryToHEC converts a LogEntry to a datalake.HECEvent for ngx ingestion.
func entryToHEC(e *model.LogEntry, index, sourcetype string) datalake.HECEvent {
	ev := map[string]any{
		"tenant_id":       e.TenantID,
		"dataset":         e.Dataset,
		"kind":            e.Kind,
		"kind_name":       model.KindName(e.Kind),
		"agent_id":        e.AgentID,
		"hostname":        e.Hostname,
		"src_ip":          e.SourceIP,
		"session_id":      e.SessionID,
		"event_timestamp": e.EventTimestamp.UTC().Format(time.RFC3339),
		"ingested_at":     e.IngestedAt.UTC().Format(time.RFC3339),
	}
	if e.RawLog != "" {
		ev["raw_log"] = e.RawLog
	}
	for k, v := range e.Fields {
		ev[k] = v
	}
	return datalake.HECEvent{
		Time:       e.EventTimestamp.UnixMilli(),
		Index:      index,
		Sourcetype: sourcetype,
		Event:      ev,
	}
}

// decompress decompresses the zstd TSV payload.
func (h *Handler) decompress(batch LogBatch) ([][]string, error) {
	raw, err := h.dec.DecodeAll(batch.CompressedTSV, nil)
	if err != nil {
		return nil, fmt.Errorf("zstd: %w", err)
	}
	if batch.OrigSize > 0 && uint32(len(raw)) != batch.OrigSize {
		return nil, fmt.Errorf("orig_size mismatch: declared %d, got %d", batch.OrigSize, len(raw))
	}
	lines := bytes.Split(raw, []byte("\n"))
	rows := make([][]string, 0, len(lines))
	for _, line := range lines {
		line = bytes.TrimRight(line, "\r")
		if len(line) == 0 {
			continue
		}
		rows = append(rows, strings.Split(string(line), "\t"))
	}
	return rows, nil
}

// tagToDataset maps fluent-bit tag strings to XQL dataset names.
func tagToDataset(tag string) string {
	switch {
	case strings.Contains(tag, "syslog"):
		return model.DatasetSyslog
	case strings.Contains(tag, "network"):
		return model.DatasetNetwork
	case strings.Contains(tag, "auth") || strings.Contains(tag, "idp"):
		return model.DatasetIDP
	case strings.Contains(tag, "ngfw") || strings.Contains(tag, "firewall"):
		return model.DatasetNGFW
	case strings.Contains(tag, "cloud"):
		return model.DatasetCloud
	case strings.Contains(tag, "email") || strings.Contains(tag, "mail"):
		return model.DatasetEmail
	default:
		return model.DatasetEndpoint
	}
}

// kindFromTag maps the "kind" column value (or tag name) to a LogKindXxx constant.
func kindFromTag(tag, kindVal string) uint8 {
	switch strings.ToLower(kindVal) {
	case "process", "1":
		return model.LogKindProcess
	case "file", "2":
		return model.LogKindFile
	case "registry", "3":
		return model.LogKindRegistry
	case "network", "4":
		return model.LogKindNetwork
	case "dns", "5":
		return model.LogKindDNS
	case "auth", "6":
		return model.LogKindAuth
	case "vuln", "7":
		return model.LogKindVuln
	case "integrity", "fim", "8":
		return model.LogKindIntegrity
	}
	switch {
	case strings.Contains(tag, "syslog"):
		return model.LogKindSyslog
	case strings.Contains(tag, "auth"):
		return model.LogKindAuth
	case strings.Contains(tag, "network"):
		return model.LogKindNetwork
	default:
		return model.LogKindSyslog
	}
}

func buildColIndex(cols []string) map[string]int {
	m := make(map[string]int, len(cols))
	for i, c := range cols {
		m[c] = i
	}
	return m
}

func getField(row []string, colIdx map[string]int, name string) string {
	if i, ok := colIdx[name]; ok && i < len(row) {
		return row[i]
	}
	return ""
}

// WriteAck writes a TypeAck XLOG frame back to w confirming seq.
func WriteAck(w io.Writer, agentID, seq uint64) error {
	body := make([]byte, 8)
	binary.BigEndian.PutUint64(body, seq)
	hdr := WriteHeader(FrameHeader{
		Magic:   Magic,
		Version: Version,
		Type:    TypeAck,
		AgentID: agentID,
		Seq:     seq,
		TsMs:    uint64(time.Now().UnixMilli()),
		BodyLen: 8,
	})
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	_, err := w.Write(body)
	return err
}
