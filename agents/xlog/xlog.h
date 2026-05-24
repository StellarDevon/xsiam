/*
 * xlog.h — XLOG binary framing + zstd-compressed TSV log uploader
 *
 * Endpoint agents use this library to batch event rows into an XLOG frame
 * and POST it to the XSIAM ingest endpoint over a plain TCP/HTTP connection.
 *
 * Protocol summary
 * ────────────────
 *
 *  Frame header  (fixed-width prefix, big-endian):
 *
 *    Offset  Size  Field
 *    ──────  ────  ─────────────────────────────────────────────────────────
 *    0       4     magic = 0x584C4F47  ("XLOG")
 *    4       1     version = 1
 *    5       1     type    (0x01=LogBatch  0x02=Ack  0x03=Heartbeat  0x04=Error)
 *    6       1     flags   (reserved, send 0)
 *    7       1     tag_len (0–255)
 *    8       N     tag     (UTF-8 source label, e.g. "winevent", "sysmon")
 *    8+N     8     agent_id  (u64, matches WZCP agent registration)
 *    16+N    8     seq       (monotonically increasing frame counter)
 *    24+N    8     ts_ms     (send timestamp, ms since Unix epoch)
 *    32+N    4     body_len  (byte count of TLV body following the header)
 *
 *  Frame body — TLV fields (T:1B  L:2B big-endian  V:L bytes):
 *
 *    Tag   Name            Type    Description
 *    ────  ──────────────  ──────  ────────────────────────────────────────
 *    0x01  schema_version  u16     log schema (currently 1)
 *    0x02  row_count       u32     number of TSV rows in this batch
 *    0x03  orig_size       u32     pre-compression byte count
 *    0x04  columns         bytes   comma-separated column names
 *    0x10  data            bytes   zstd-compressed TSV payload
 *
 *  TSV payload (after decompression):
 *    • Plain UTF-8, one row per line (\n), no header row.
 *    • Columns are in the same order as the "columns" TLV.
 *    • The "_time" column, when present, is RFC 3339.
 *
 * Magic disambiguation
 * ────────────────────
 *  First byte 0x58 ('X') does not collide with:
 *    HTTP     0x47/0x50/0x48  (GET / POST / HTTP)
 *    Syslog   0x3C            (<priority>)
 *    TLS      0x16            (record header)
 *    WZCP     0x57            ('W')
 *    SSH      0x53            (SSH-)
 *  Shared listeners can dispatch on first byte alone.
 *
 * Usage (minimal)
 * ───────────────
 *
 *    xlog_batch_t *b = xlog_batch_new("winevent", agent_id, seq++);
 *    xlog_batch_set_columns(b, "agent_id\t_time\tevent_id\tmessage");
 *    xlog_batch_append_row(b, "host-001\t2026-05-23T21:00:00Z\t4624\tLogon");
 *    xlog_batch_append_row(b, "host-001\t2026-05-23T21:00:05Z\t4634\tLogoff");
 *
 *    uint8_t *frame;
 *    size_t   frame_len;
 *    int rc = xlog_batch_encode(b, &frame, &frame_len);
 *    if (rc == XLOG_OK) {
 *        // send frame[0..frame_len) over TCP / HTTP POST body
 *        send(sock, frame, frame_len, 0);
 *        free(frame);
 *    }
 *    xlog_batch_free(b);
 */

#ifndef XLOG_H
#define XLOG_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ── Magic & constants ────────────────────────────────────────────────── */

#define XLOG_MAGIC          0x584C4F47UL   /* "XLOG"                      */
#define XLOG_VERSION        1
#define XLOG_MAX_TAG_LEN    255
#define XLOG_MAX_FRAME_BODY (32 * 1024 * 1024)  /* 32 MB hard cap         */

/* Frame types */
#define XLOG_TYPE_LOG_BATCH  0x01
#define XLOG_TYPE_ACK        0x02
#define XLOG_TYPE_HEARTBEAT  0x03
#define XLOG_TYPE_ERROR      0x04

/* TLV body tags */
#define XLOG_TAG_SCHEMA_VERSION  0x01   /* u16                            */
#define XLOG_TAG_ROW_COUNT       0x02   /* u32                            */
#define XLOG_TAG_ORIG_SIZE       0x03   /* u32                            */
#define XLOG_TAG_COLUMNS         0x04   /* comma-separated UTF-8 string   */
#define XLOG_TAG_DATA            0x10   /* zstd-compressed TSV bytes      */

/* Return codes */
#define XLOG_OK              0
#define XLOG_ERR_OOM        -1
#define XLOG_ERR_COMPRESS   -2
#define XLOG_ERR_TOO_LARGE  -3
#define XLOG_ERR_PARAM      -4

/* ── Types ────────────────────────────────────────────────────────────── */

typedef struct xlog_batch xlog_batch_t;

/* ── API ──────────────────────────────────────────────────────────────── */

/*
 * xlog_batch_new — allocate a new batch context.
 *
 *  tag       log source label (e.g. "winevent", "sysmon", "auth").
 *            Copied; caller may free after this call.
 *  agent_id  64-bit agent identifier (matches WZCP registration).
 *  seq       monotonically increasing frame sequence number.
 *
 * Returns NULL on allocation failure.
 */
xlog_batch_t *xlog_batch_new(const char *tag, uint64_t agent_id, uint64_t seq);

/*
 * xlog_batch_set_columns — set the column header for this batch.
 *
 *  columns   tab-separated column names matching the TSV row order.
 *            Example: "_time\tagent_id\tevent_id\tmessage"
 *            Internally stored as comma-separated for TLV encoding.
 *            NULL or empty string clears the column list.
 *
 * Call once per batch before appending rows.
 */
void xlog_batch_set_columns(xlog_batch_t *b, const char *columns);

/*
 * xlog_batch_append_row — append a single TSV row to the batch.
 *
 *  row   tab-separated field values.  A newline is appended automatically.
 *        Do not include a trailing newline in row.
 *
 * Returns XLOG_OK or XLOG_ERR_OOM / XLOG_ERR_TOO_LARGE.
 */
int xlog_batch_append_row(xlog_batch_t *b, const char *row);

/*
 * xlog_batch_encode — compress and serialise the batch into a single XLOG
 * frame ready for transmission.
 *
 *  out       receives a malloc'd frame buffer; caller must free(*out).
 *  out_len   receives the byte length of *out.
 *
 * Returns XLOG_OK on success, or a negative XLOG_ERR_* code.
 * On error *out is NULL and *out_len is 0.
 */
int xlog_batch_encode(xlog_batch_t *b, uint8_t **out, size_t *out_len);

/*
 * xlog_batch_row_count — number of rows appended so far.
 */
size_t xlog_batch_row_count(const xlog_batch_t *b);

/*
 * xlog_batch_free — release all memory owned by b.
 */
void xlog_batch_free(xlog_batch_t *b);

/*
 * xlog_strerror — human-readable description of an XLOG_ERR_* code.
 */
const char *xlog_strerror(int rc);

#ifdef __cplusplus
}
#endif

#endif /* XLOG_H */
