# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Repository Status

Both the `xsiam/` Go module and `web/` React SPA are **implemented and building**.

- `xsiam/` — Go module (backend API + embedded SPA). Primary working directory.
- `web/` — React SPA (TypeScript/Vite). `pnpm build` outputs to `xsiam/dist/` for Go embed.
- `docs/` — Chinese-language product requirements (`XSIAM产品需求文档.md`) and technical design spec (`XSIAM技术设计文档.md`). Still the authoritative design reference.
- `third_party/` — Local offline copies of runtime dependencies (ArangoDB 3.12.9.2, Redis 8.6.3, etcd 3.6.11, Wazuh 4.14.5). MongoDB is NOT used.

## Binary Architecture

### All-in-one (preferred)

| Binary | Source | Port(s) | Description |
|--------|--------|---------|-------------|
| `xsiam` | `cmd/xsiam` | :8080 + :8090 | All-in-one: console + svc + cron in one process |

```bash
CGO_ENABLED=0 go build -ldflags="-s -w" -o xsiam.exe ./cmd/xsiam
./xsiam.exe                   # all subsystems
./xsiam.exe -mode console     # console only
./xsiam.exe -mode svc         # svc only
./xsiam.exe -mode cron        # cron only
```

### Individual binaries (legacy, still buildable)

| Binary | Port | Role |
|--------|------|------|
| `ngx_console` | :8080 | XSIAM console — business APIs + React SPA embedded |
| `ngx_svc` | :8090 | Auth/RBAC/Notify/Audit service |
| `ngx_cron` | — | Background job scheduler |

```bash
CGO_ENABLED=0 go build -o ngx_console.exe ./cmd/ngx_console
CGO_ENABLED=0 go build -o ngx_svc.exe     ./cmd/ngx_svc
CGO_ENABLED=0 go build -o ngx_cron.exe    ./cmd/ngx_cron
```

### Key design — in-process caller

`pkg/localclient` implements `svcclient.Caller` (the interface in `pkg/svcclient`) by calling svc services directly, removing the loopback HTTP round-trip used by the individual binaries. The `svcclient.Caller` interface is what `middleware/rbac.go`, `service/user.go`, and `router/router.go` accept — both `*svcclient.Client` (HTTP) and `*localclient.Client` (in-process) satisfy it.

### Build all + seed

```bash
# Seed database
go run ./cmd/seed

# Run tests
go test ./...
go test -run TestAlertCreate ./internal/service
```

### Frontend Commands (in `web/`)

```bash
pnpm install
pnpm dev      # Dev server :5173, proxies /api to localhost:8080
pnpm build    # Outputs to ../xsiam/dist/ for Go embed (xsiam/dist/)
pnpm tsc --noEmit
```

### Local Infrastructure (Windows)

```powershell
# Redis (community Windows build)
.\third_party\tools\redis-8.6.3-windows-x64-msys2-with-service\Redis-8.6.3-Windows-x64-msys2-with-Service\redis-server.exe

# etcd
.\third_party\tools\etcd-v3.6.11-windows-amd64\etcd-v3.6.11-windows-amd64\etcd.exe

# ArangoDB (requires Docker Desktop from third_party/downloads/)
docker pull arangodb:3.12.9.1
docker run --name xsiam-arangodb -e ARANGO_ROOT_PASSWORD=changeme -p 8529:8529 arangodb:3.12.9.1
```

## Architecture

### Go Layer Separation

Strict unidirectional dependency: **Handler → Service → Repository → Model**

- **Handler** (`internal/handler/`): HTTP parsing, binding, call Service, serialize response. No business logic, no DB access.
- **Service** (`internal/service/`): Business orchestration, multi-repo composition, async task submission. Uses `map[string]any` for AQL patches, not `bson.D`.
- **Repository** (`internal/repository/`): All ArangoDB operations via AQL. No business judgments.
- **Model** (`internal/model/`): Struct definitions with `json:` tags only (no `bson:` tags), enums, field name constants. ArangoDB document key stored in `_key` field (`json:"_key,omitempty"`). No methods.
- **DataLake** (`internal/datalake/`): ngx SPL2 query client + cold-data archiver. Not for real-time log collection.
- **Stub** (`internal/stub/`): Interface stubs for device execution, ETL, and AI Engine — not yet implemented.

### React SPA Embed

`pnpm build` outputs to `xsiam/dist/`. At compile time, `ngx_console` embeds it:

```go
//go:embed dist
var staticFiles embed.FS
```

Gin routes: `/api/*` → business handlers (registered first); `/*` → SPA fallback returning `index.html`.

### Alert Pipeline

```
ngx cron (every 5 min) → SPL2 rule query → threshold match
  → webhook POST /api/internal/alerts (IP whitelist auth)
  → ArangoDB alerts collection (30d TTL index)
  → correlationPool.Submit (non-blocking, 4 workers, 4096-item channel)
  → CAE → creates/updates Incidents + causality_nodes/causality_edges (Named Graph, 90d TTL)
```

### JWT Flow

ngx_svc issues JWTs (HS256, includes `uid`/`tid`/`role` claims). ngx_console validates locally using shared `JWT_SECRET` — no per-request callback to ngx_svc.

### ngx_svc Internal API

ngx_console and ngx_cron call ngx_svc over HTTP (network-isolated, no JWT required):

- `POST /auth/login`, `POST /auth/refresh`
- `POST /rbac/check` — permission format: `resource:action` (e.g. `alerts:read`)
- `POST /notify/send` — channels: email, dingtalk, slack, sms
- `POST /audit/record`, `GET /audit/logs`

### Multi-Tenancy

`tenant_id` is injected via middleware on every request. All repository queries filter by `tenant_id`. RBAC roles are tenant-scoped.

## Configuration

Primary: `config.yaml` in module root. Override via env vars (Viper `AutomaticEnv`).

Key env vars: `ARANGO_ENDPOINTS`, `ARANGO_USERNAME`, `ARANGO_PASSWORD`, `ARANGO_DATABASE`, `DATALAKE_QUERY_URL`, `DATALAKE_HEC_URL`, `SVC_URL` (default `http://localhost:8090`), `JWT_SECRET`.

## ArangoDB Collections

Database driver: `github.com/arangodb/go-driver/v2`. AQL replaces `bson.D`. Queries via `db.Query(ctx, aql, &QueryOptions{BindVars: ...})`.

Hot data with TTL index (`EnsureTTLIndex`): `alerts` (30d), `incidents` (90d), `causality_nodes` (90d), `causality_edges` (90d).  
Persistent: `assets`, `vulnerabilities`, `iocs`, `intel_feeds`, `actions`, `devices`, `agent_policies`, `datasources`, `playbooks`, `reports`, `users`, `audit_logs`, `tenants`, `rbac_roles`, `detection_rules`, `identity_risks`, `privilege_restrictions`, `exposure_scores`.

Named Graph `causality_graph` manages `causality_nodes` (document collection) and `causality_edges` (edge collection) for native AQL graph traversal.

Raw logs are stored in ngx (the custom C data lake), not in ArangoDB.

## Development Mode

```
Terminal 1: cd xsiam && go run ./cmd/xsiam        # API :8080 + internal :8090
Terminal 2: cd web && pnpm dev                    # HMR :5173 (proxies /api → :8080)
Browser: http://localhost:5173
```

Production: single binary at :8080 serves both API and static files.
