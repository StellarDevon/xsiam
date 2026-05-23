#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_FILE="${LOG_FILE:-/tmp/xsiam-gateway-db-test.log}"
AGENT_KEY="${AGENT_KEY:-550e8400-e29b-41d4-a716-446655440000}"
AGENT_NAME="${AGENT_NAME:-UUID-SMOKE-001}"
AGENT_ID="${AGENT_ID:-42}"
SMOKE_HOLD_SECONDS="${SMOKE_HOLD_SECONDS:-0}"

cd "$ROOT_DIR"
rm -f "$LOG_FILE" /tmp/xsiam_check_agent.js

./build-wsl/bin/fluent-bit -c conf/xsiam-agent-gateway.conf >"$LOG_FILE" 2>&1 &
pid=$!

cleanup() {
    kill -9 "$pid" >/dev/null 2>&1 || true
    wait "$pid" >/dev/null 2>&1 || true
}
trap cleanup EXIT

for _ in $(seq 1 30); do
    if ss -ltn | grep -q ':1514'; then
        break
    fi
    sleep 0.2
done

python3 tools/xsiam_wzcp_smoke.py \
    --agent-id "$AGENT_ID" \
    --agent-key "$AGENT_KEY" \
    --agent-name "$AGENT_NAME" \
    --host-type "${HOST_TYPE:-server}" \
    --mac-address "${MAC_ADDRESS:-02:00:5E:10:00:01}" \
    --payload 'db sync uuid event' \
    --hold-seconds "$SMOKE_HOLD_SECONDS" &
client_pid=$!

sleep 7

cat >/tmp/xsiam_check_agent.js <<EOF
const db = require("@arangodb").db;
const key = "$AGENT_KEY";
const doc = db._query(
  "FOR d IN devices FILTER d.agent_id == @agent_id LIMIT 1 RETURN d",
  { agent_id: key }
).toArray()[0];
if (!doc) {
  throw new Error("device not found for agent_id " + key);
}
print(JSON.stringify({
  _key: doc._key,
  device_id: doc.device_id,
  tenant_id: doc.tenant_id,
  agent_id: doc.agent_id,
  hostname: doc.hostname,
  agent_version: doc.agent_version,
  agent_status: doc.agent_status,
  is_connected: doc.is_connected,
  protocol: doc.protocol,
  installed_at: doc.installed_at,
  last_seen: doc.last_seen,
  last_heartbeat: doc.last_heartbeat,
  host_type: doc.host_type,
  mac_addresses: doc.mac_addresses
}, null, 2));
EOF

arangosh \
    --server.endpoint tcp://127.0.0.1:8529 \
    --server.username root \
    --server.password changeme \
    --server.database xsiamdb \
    --javascript.execute /tmp/xsiam_check_agent.js

printf '\n--- gateway log tail ---\n'
tail -n 80 "$LOG_FILE"

wait "$client_pid"
