# XSIAM XLOG Protocol — Compressed TSV Log Uploader

XLOG is the binary framing used to deliver batched log events from endpoint
agents (via the Fluent Bit `out_xsiam_log` plugin) to the XSIAM ingest
endpoint at `POST /internal/agent/log`.

## Magic & First-Byte Disambiguation

```
Magic bytes: 0x58 0x4C 0x4F 0x47  →  ASCII "XLOG"
```

The first byte `0x58` ('X') does not appear as the first byte of any other
protocol running on the same listener:

| Protocol   | First byte(s)        |
|------------|----------------------|
| HTTP/1.x   | 0x47 / 0x50 / 0x48   | (G/P/H)
| Syslog     | 0x3C                 | (<)
| TLS        | 0x16                 | (record header)
| WZCP       | 0x57                 | (W)
| SSH        | 0x53                 | (S)
| **XLOG**   | **0x58**             | (X) ← unambiguous

A shared TCP gateway can dispatch on the first byte alone to route WZCP agent
connections vs XLOG log uploads vs syslog vs HTTP management traffic.

## Frame Layout

All multi-byte integers are **big-endian**.

```
┌──────────────────────────────────────────────────────────────────────────┐
│  Fixed prefix (8 bytes)                                                  │
│  ┌─────────┬───────┬───────┬───────┬──────────────────────────────────┐  │
│  │ magic   │  ver  │ type  │ flags │ tag_len                          │  │
│  │  4 B    │  1 B  │  1 B  │  1 B  │  1 B (0–255)                    │  │
│  └─────────┴───────┴───────┴───────┴──────────────────────────────────┘  │
├──────────────────────────────────────────────────────────────────────────┤
│  Variable tag  (tag_len bytes, UTF-8)                                    │
├──────────────────────────────────────────────────────────────────────────┤
│  Scalar tail (28 bytes, big-endian)                                      │
│  ┌───────────────┬───────────────┬───────────────┬─────────────────────┐ │
│  │ agent_id  8 B │   seq  8 B    │  ts_ms  8 B   │  body_len  4 B     │ │
│  └───────────────┴───────────────┴───────────────┴─────────────────────┘ │
├──────────────────────────────────────────────────────────────────────────┤
│  Body  (body_len bytes) — TLV-encoded fields                             │
└──────────────────────────────────────────────────────────────────────────┘
```

### Header fields

| Field     | Size | Description |
|-----------|------|-------------|
| magic     | 4 B  | `0x584C4F47` ("XLOG") |
| ver       | 1 B  | Protocol version. Currently `1`. |
| type      | 1 B  | Frame type (see below). |
| flags     | 1 B  | Reserved; send `0x00`. |
| tag_len   | 1 B  | Byte length of the following `tag` field (0–255). |
| tag       | var  | UTF-8 log-source label (e.g. `winevent`, `sysmon`, `auth`). Zero-length is valid; server defaults to `agent_log`. |
| agent_id  | 8 B  | uint64 agent identifier matching the WZCP HELLO `agent_id`. |
| seq       | 8 B  | Monotonically increasing frame counter per agent. |
| ts_ms     | 8 B  | Frame send timestamp (milliseconds since Unix epoch). |
| body_len  | 4 B  | Byte count of the TLV body that follows the header. Max 32 MB. |

### Frame types

| Value | Name       | Direction      | Description |
|-------|------------|----------------|-------------|
| 0x01  | LogBatch   | agent → server | Compressed TSV log batch |
| 0x02  | Ack        | server → agent | Confirms receipt of a `LogBatch` |
| 0x03  | Heartbeat  | both           | Keep-alive / channel probe |
| 0x04  | Error      | server → agent | Rejection with reason code |

## TLV Body (LogBatch)

The body is a sequence of TLV fields:

```
T (1 B)  +  L (2 B big-endian)  +  V (L bytes)
```

| Tag  | Name           | V type | Description |
|------|----------------|--------|-------------|
| 0x01 | schema_version | u16    | Log schema version (currently `1`). |
| 0x02 | row_count      | u32    | Number of TSV rows in this batch. |
| 0x03 | orig_size      | u32    | Pre-compression byte count of the TSV body. |
| 0x04 | columns        | bytes  | Comma-separated column names (UTF-8). |
| 0x10 | data           | bytes  | **zstd-compressed TSV payload.** |

Tags `0x01`–`0x03` SHOULD appear before `0x10`. Unknown tags MUST be ignored.

## TSV Payload (after decompression)

Plain UTF-8, tab-separated values:

- One row per line (`\n`); `\r\n` also accepted.
- No header row — column order is defined by the `columns` TLV (0x04).
- The `_time` column, when present, MUST be RFC 3339 (`2006-01-02T15:04:05Z`).
- Field values MAY contain tabs; the receiver splits on the first *N−1* tabs
  where N is the column count.

### Default column set (sent by `out_xsiam_log`)

```
agent_id  _time  event_id  kind  tag  log
```

## C Client Library

`agents/xlog/xlog.h` + `agents/xlog/xlog.c` — portable C99 implementation:

```c
xlog_batch_t *b = xlog_batch_new("winevent", agent_id, seq++);
xlog_batch_set_columns(b, "agent_id\t_time\tevent_id\tmessage");
xlog_batch_append_row(b, "host-001\t2026-05-23T21:00:00Z\t4624\tUser logged on");
xlog_batch_append_row(b, "host-001\t2026-05-23T21:00:05Z\t4634\tUser logged off");

uint8_t *frame;
size_t   frame_len;
int rc = xlog_batch_encode(b, &frame, &frame_len);
if (rc == XLOG_OK) {
    // POST frame[0..frame_len) to http://<server>/internal/agent/log
    // Content-Type: application/x-xlog
    free(frame);
}
xlog_batch_free(b);
```

## Fluent Bit Plugin

`gateway/plugins/out_xsiam_log/` — OUTPUT plugin for Fluent Bit:

```ini
[OUTPUT]
    Name             xsiam_log
    Match            xsiam_agent.*
    Ingest_URL       http://127.0.0.1:18090
    Tag_Field        session_protocol    # event field used as XLOG tag
    Compress_Level   3                   # zstd level 1-19
    Max_Batch_Rows   8192
```

## Go Ingest Endpoint

`POST /internal/agent/log`  (port `:18090`)

```
Content-Type: application/x-xlog
Body: XLOG frame bytes
```

Response `204 No Content` on success.

Handler: `xsiam/internal/ingest.Handler`
- Reads and validates XLOG header (magic, version, type)
- Decodes TLV body
- Decompresses zstd TSV
- Forwards rows as HEC events to the DataLake (`agent_logs` index)

## End-to-End Data Flow

```
Wazuh agent / C agent
    │  EVENT_BATCH (WZCP, TCP:1514)
    ▼
fluent-bit in_xsiam_agent
    │  msgpack log events
    ▼
fluent-bit out_xsiam_log
    │  XLOG frame (magic=XLOG, zstd TSV)
    │  HTTP POST /internal/agent/log
    │  Content-Type: application/x-xlog
    ▼
Go xsiam server :18090
  ingest.Handler
    │  DecodeBatch → zstd decompress → TSV rows
    │  HECEvent{index:"agent_logs", sourcetype:<tag>}
    ▼
DataLake (ngx HEC)
    └── XQL queryable via Query Center
```
