# XSIAM WZCP Agent Gateway Protocol

WZCP is the binary framing used between the Windows agent and the Fluent Bit
gateway input plugin `xsiam_agent`. It avoids JSON on the wire.

## Enable Agent Mode

Set the environment variable before starting the Windows agent service:

```bat
setx /M XSIAM_GATEWAY_PROTOCOL wzcp
```

The agent still uses the existing Wazuh server address and port settings. Point
that server entry at the gateway listener.

The logical `agent_id` sent in `HELLO` is a UUID string:

1. `XSIAM_AGENT_UUID` environment variable, if set.
2. `xsiam-agent.uuid` in the Agent home directory, if present.
3. A generated UUID-like value, persisted to `xsiam-agent.uuid` in the Agent
   home directory.

## Gateway

Example config:

```ini
[INPUT]
    Name         xsiam_agent
    Listen       127.0.0.1
    Port         1514
    Chunk_Size   32
    Buffer_Size  256
    Heartbeat_Min 60
    Heartbeat_Max 180
    DB_Sync true
    Arango_Host 127.0.0.1
    Arango_Port 8529
    Arango_User root
    Arango_Pass changeme
    Arango_Database xsiamdb
    DB_Flush_Interval 5
    Heartbeat_Flush_Interval 180

[OUTPUT]
    Name         stdout
    Match        *
```

Run:

```sh
cd /mnt/d/src/xsiam/gateway
./build-wsl/bin/fluent-bit -c conf/xsiam-agent-gateway.conf
```

Smoke test:

```sh
python3 tools/xsiam_wzcp_smoke.py --wait-heartbeat
tools/xsiam_wzcp_db_smoke.sh
```

## Device State Sync

The gateway keeps Agent/device state in memory and flushes dirty records to
ArangoDB `devices` in batches. This avoids writing every heartbeat directly to
the database.

State update policy:

- `HELLO`: upserts `devices` by UUID `agent_id`, marks `agent_status=online` and
  `is_connected=true`.
- `EVENT_BATCH`: updates `last_seen` in memory.
- Agent `HEARTBEAT`: updates `last_heartbeat`; it is marked dirty only after
  `Heartbeat_Flush_Interval`.
- Disconnect: marks `agent_status=offline` and `is_connected=false`.
- Flush: every `DB_Flush_Interval`, dirty device records are sent through one
  ArangoDB AQL `UPSERT` batch.

Current Agent builds send `HELLO` schema v2. `host_type` is detected on Windows
as `server` when the OS product type is not workstation; it can be overridden
with `XSIAM_HOST_TYPE=server` or `XSIAM_HOST_TYPE=pc`. MAC addresses are read
from Windows adapters and sent as a binary length-prefixed list.

## Listener Session Classification

The gateway listener is shared by Agent and device clients. Each TCP connection
starts as:

```text
session_protocol = "unknown"
client_group     = "unknown"
```

The first bytes are used for fast classification:

```text
WZCP magic/frame  -> session_protocol="agent_wzcp", client_group="agent"
syslog line       -> session_protocol="syslog",     client_group="device"
```

Classification is stored on the connection session and emitted with every event
as `session_id`, `session_protocol`, and `client_group`. If later bytes prove the
initial classification was wrong, the session label is overwritten with the
newly confirmed protocol and group.

## Frame Layout

Each TCP frame is:

```text
u32 frame_len_be
u32 magic_be        # "WZCP" / 0x575A4350
u8  version         # 1
u8  header_len      # 32
u8  flags
u8  msg_type
u32 agent_id_be
u64 seq_be
u64 timestamp_ms_be
u32 body_len_be
u8  body[body_len]
```

Message types:

```text
1 HELLO
2 EVENT_BATCH
3 ACK
4 HEARTBEAT
5 CONTROL
6 ERROR
```

## Bodies

`HELLO` schema v1:

```text
u16 schema_version_be
u16 reserved
u16 agent_id_len_be      bytes
u16 agent_name_len_be    bytes
u16 agent_version_len_be bytes
```

`HELLO` schema v2:

```text
u16 schema_version_be    # 2
u16 reserved
u16 agent_id_len_be      bytes  # UUID string
u16 agent_name_len_be    bytes  # hostname
u16 agent_version_len_be bytes
u16 host_type_len_be     bytes  # "pc" or "server"
u16 mac_count_be
repeat mac_count:
  u16 mac_len_be         bytes  # "AA:BB:CC:DD:EE:FF"
```

`EVENT_BATCH`:

```text
u16 event_count_be
repeat event_count:
  u8  kind
  u8  reserved
  u64 timestamp_ms_be
  u64 event_id_be
  u16 payload_len_be
  u8  payload[payload_len]
```

`ACK`:

```text
u64 highest_seq_be
```

`HEARTBEAT` currently has an empty body.

Heartbeat is bidirectional:

```text
gateway -> agent: HEARTBEAT every random Heartbeat_Min-Heartbeat_Max seconds
agent   -> gateway: ACK

agent   -> gateway: HEARTBEAT every random 30-120 seconds
gateway -> agent: ACK
```

The randomized intervals avoid heartbeat bursts when many agents reconnect at
the same time.

The body boundary is intentionally isolated so it can be replaced by generated
Cap'n Proto serialization later without changing the TCP framing or the
Fluent Bit connection model.
