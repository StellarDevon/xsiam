#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LOG_FILE="${LOG_FILE:-/tmp/xsiam-multiproto.log}"

cd "$ROOT_DIR"
rm -f "$LOG_FILE"

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
    --agent-id 43 \
    --agent-key 550e8400-e29b-41d4-a716-446655440004 \
    --agent-name MULTIPROTO-WZCP \
    --host-type pc \
    --mac-address 02:00:5E:10:00:04 \
    --payload 'multiproto wzcp event'

python3 tools/xsiam_syslog_smoke.py \
    --message '<134>1 2026-05-23T09:00:00Z fw01 firewall - - - multiproto syslog event'

sleep 2
tail -n 120 "$LOG_FILE"
