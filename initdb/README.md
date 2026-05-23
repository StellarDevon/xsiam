# XSIAM ArangoDB Initialization

This directory contains the idempotent initialization script for the local
`xsiamdb` ArangoDB database described in `docs/XDR技术设计文档.md`.

## Run

```powershell
.\initdb\run_init_xsiamdb.ps1
```

## Validate

```powershell
.\initdb\validate_xsiamdb.ps1
```

The script creates:

- Document collections: `alerts`, `incidents`, `assets`, `vulnerabilities`,
  `iocs`, `intel_feeds`, `actions`, `devices`, `agent_policies`,
  `datasources`, `playbooks`, `reports`, `users`, `audit_logs`, `tenants`,
  `rbac_roles`, `detection_rules`, `identity_risks`,
  `privilege_restrictions`, `exposure_scores`, `causality_nodes`
- Edge collection: `causality_edges`
- Named graph: `causality_graph`
- Persistent and TTL indexes from the technical design
- JSON schema validation for Agent/device runtime state in the `devices`
  collection
- Minimal seed data for tenant, RBAC, user, asset, detection rule, alert,
  incident, action, playbook, report, identity risk, exposure score, and
  causality graph traversal
- Default local admin user: `admin` / `admin`; the password
  is stored as a bcrypt `password_hash`, not plain text.

The initializer always drops and recreates `xsiamdb` before creating schema and
seed data. Every run is a clean database rebuild.

Notes:

- `log_entries` is intentionally not created. The latest design says raw logs
  are stored in ngx and queried through `/api/logs/query`.
- `causality_graphs` is intentionally not created. The latest design uses
  `causality_nodes`, `causality_edges`, and the `causality_graph` named graph.
- `alerts.triggered_at` TTL is 32 days to match the archiver design.
- `incidents.created_at` and causality graph `created_at` TTL are 90 days.

Connection assumptions:

- WSL distro: `Ubuntu-24.04`
- ArangoDB endpoint inside WSL: `tcp://127.0.0.1:8529`
- Username: `root`
- Password: `changeme`
- Database: `xsiamdb`
