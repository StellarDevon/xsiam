#!/usr/bin/env python3
"""Generate large XSIAM ArangoDB mock datasets as NDJSON files.

Default output is 1,000,000 documents across all non-system XSIAM collections.
The distribution is intentionally alert-heavy because alerts/incidents/assets
are the highest-volume hot data in the design.
"""

from __future__ import annotations

import argparse
import json
import random
import shutil
from datetime import datetime, timedelta, timezone
from pathlib import Path


COLLECTIONS = [
    "tenants",
    "rbac_roles",
    "users",
    "agent_policies",
    "assets",
    "devices",
    "vulnerabilities",
    "iocs",
    "intel_feeds",
    "datasources",
    "detection_rules",
    "alerts",
    "incidents",
    "actions",
    "playbooks",
    "reports",
    "identity_risks",
    "privilege_restrictions",
    "exposure_scores",
    "causality_nodes",
    "causality_edges",
    "audit_logs",
]

ADMIN_PASSWORD_HASH = "$2a$10$SPGQECUtGsqUWdV0eHRXYuMlxSfb4iPGWKWXh7BPuXYbuw3T7pY9W"  # Admin@123456
MOCK_USER_PASSWORD_HASH = "$2a$10$Dzmy.0sxLSr.D2lrPrEIVONeaVedWOjXm5ojaPXKpvDqU1M/A8hey"  # User@123456


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def clamp_counts(total: int) -> dict[str, int]:
    minimums = {
        "tenants": 50,
        "rbac_roles": 200,
        "users": 20_000,
        "agent_policies": 100,
        "assets": 50_000,
        "devices": 50_000,
        "vulnerabilities": 50_000,
        "iocs": 100_000,
        "intel_feeds": 50,
        "datasources": 500,
        "detection_rules": 5_000,
        "alerts": 400_000,
        "incidents": 80_000,
        "actions": 50_000,
        "playbooks": 500,
        "reports": 1_000,
        "identity_risks": 20_000,
        "privilege_restrictions": 10_000,
        "exposure_scores": 100_000,
        "causality_nodes": 50_000,
        "causality_edges": 30_000,
        "audit_logs": 1_600,
    }
    base_total = sum(minimums.values())
    if total <= base_total:
        return minimums

    weights = {
        "alerts": 40,
        "incidents": 10,
        "assets": 8,
        "devices": 8,
        "iocs": 10,
        "vulnerabilities": 6,
        "exposure_scores": 8,
        "audit_logs": 4,
        "causality_nodes": 4,
        "causality_edges": 3,
    }
    counts = dict(minimums)
    extra = total - base_total
    weight_total = sum(weights.values())
    assigned = 0
    for name, weight in weights.items():
        add = extra * weight // weight_total
        counts[name] += add
        assigned += add
    counts["alerts"] += extra - assigned
    return counts


class Generator:
    def __init__(self, out_dir: Path, total: int, seed: int) -> None:
        self.out_dir = out_dir
        self.total = total
        self.rng = random.Random(seed)
        self.now = datetime.now(timezone.utc)
        self.counts = clamp_counts(total)
        self.severities = ["critical", "high", "medium", "low", "info"]
        self.statuses = ["open", "assigned", "investigating", "closed", "false_positive"]
        self.asset_types = ["endpoint", "server", "identity", "cloud", "network"]
        self.departments = ["SOC", "IT", "Finance", "Engineering", "HR", "Operations"]
        self.mitre = [
            ("TA0001", "T1566"),
            ("TA0002", "T1059.001"),
            ("TA0003", "T1547"),
            ("TA0004", "T1068"),
            ("TA0005", "T1027"),
            ("TA0006", "T1110"),
            ("TA0007", "T1087"),
            ("TA0008", "T1021"),
            ("TA0011", "T1071"),
        ]

    def write_collection(self, name: str, iterator) -> None:
        path = self.out_dir / f"{name}.jsonl"
        count = 0
        with path.open("w", encoding="utf-8", newline="\n") as f:
            for doc in iterator:
                f.write(json.dumps(doc, ensure_ascii=False, separators=(",", ":")))
                f.write("\n")
                count += 1
        print(f"{name}: {count} -> {path}")

    def dt_back(self, max_days: int) -> str:
        return iso(self.now - timedelta(seconds=self.rng.randint(0, max_days * 86_400)))

    def dt_forward(self, max_days: int) -> str:
        return iso(self.now + timedelta(seconds=self.rng.randint(1, max_days * 86_400)))

    def tenant_id(self, i: int) -> str:
        return f"tenant-{i % self.counts['tenants']:05d}"

    def user_id(self, i: int) -> str:
        return f"user-{i % self.counts['users']:07d}"

    def asset_id(self, i: int) -> str:
        return f"asset-{i % self.counts['assets']:08d}"

    def incident_id(self, i: int) -> str:
        return f"INC-2026-{i % self.counts['incidents']:08d}"

    def alert_id(self, i: int) -> str:
        return f"ALERT-2026-{i:09d}"

    def tenants(self):
        for i in range(self.counts["tenants"]):
            yield {
                "_key": self.tenant_id(i),
                "tenant_id": self.tenant_id(i),
                "tenant_code": f"tenant{i:05d}",
                "name": f"Tenant {i:05d}",
                "tier": "super" if i == 0 else "child",
                "parent_tenant_id": None if i == 0 else "tenant-00000",
                "is_enabled": True,
                "settings": {"timezone": "Asia/Shanghai", "retention_days": 90},
                "created_at": self.dt_back(365),
                "updated_at": self.dt_back(30),
            }

    def rbac_roles(self):
        names = ["SOC Admin", "Analyst", "Viewer", "Auditor"]
        perms = {
            "SOC Admin": ["alerts:*", "incidents:*", "assets:*", "admin:*"],
            "Analyst": ["alerts:read", "alerts:write", "incidents:*", "assets:read"],
            "Viewer": ["alerts:read", "incidents:read", "assets:read"],
            "Auditor": ["audit_logs:read", "reports:read", "incidents:read"],
        }
        for i in range(self.counts["rbac_roles"]):
            name = names[i % len(names)]
            tid = self.tenant_id(i // len(names))
            yield {
                "_key": f"role-{i:07d}",
                "role_id": f"role-{i:07d}",
                "tenant_id": tid,
                "name": f"{name} {i // len(names):05d}",
                "permissions": perms[name],
                "resource_scopes": {"tenant_id": tid},
                "is_builtin": i < len(names),
                "created_at": self.dt_back(365),
                "updated_at": self.dt_back(30),
            }

    def users(self):
        for i in range(self.counts["users"]):
            tid = self.tenant_id(i)
            is_admin = i == 0
            yield {
                "_key": self.user_id(i),
                "user_id": self.user_id(i),
                "tenant_id": tid,
                "email": "admin@xsiam.local" if is_admin else f"user{i:07d}@example.local",
                "username": "admin" if is_admin else f"user{i:07d}",
                "password_hash": ADMIN_PASSWORD_HASH if is_admin else MOCK_USER_PASSWORD_HASH,
                "display_name": "XSIAM Administrator" if is_admin else f"User {i:07d}",
                "role_ids": [f"role-{i % self.counts['rbac_roles']:07d}"],
                "role": "admin" if is_admin else ["admin", "analyst", "viewer"][i % 3],
                "status": "active" if is_admin or i % 20 else "disabled",
                "is_enabled": is_admin or i % 20 != 0,
                "mfa_enabled": i % 3 != 0,
                "last_login_at": None,
                "created_at": self.dt_back(365),
                "updated_at": self.dt_back(30),
            }

    def agent_policies(self):
        for i in range(self.counts["agent_policies"]):
            yield {
                "_key": f"policy-{i:06d}",
                "policy_id": f"policy-{i:06d}",
                "tenant_id": self.tenant_id(i),
                "name": f"Endpoint Policy {i:06d}",
                "is_default": i < self.counts["tenants"],
                "platform": ["windows", "linux", "macos"][i % 3],
                "collection": {"process_events": True, "network_events": True, "file_events": i % 2 == 0},
                "response": {"process_kill": True, "host_isolation": i % 4 == 0},
                "created_at": self.dt_back(365),
                "updated_at": self.dt_back(30),
            }

    def assets(self):
        for i in range(self.counts["assets"]):
            risk = self.rng.randint(0, 100)
            yield {
                "_key": self.asset_id(i),
                "asset_id": self.asset_id(i),
                "tenant_id": self.tenant_id(i),
                "name": f"HOST-{i:08d}",
                "type": self.asset_types[i % len(self.asset_types)],
                "identifier": f"asset-{i:08d}.xsiam.local",
                "os": {"name": ["Windows", "Ubuntu", "macOS"][i % 3], "version": f"{10 + i % 15}", "arch": "x64"},
                "agent": {"id": f"agent-{i:08d}", "version": f"0.{i % 9}.{i % 20}", "status": "online" if i % 7 else "offline"},
                "department": self.departments[i % len(self.departments)],
                "risk_score": risk,
                "risk_level": "critical" if risk >= 90 else "high" if risk >= 70 else "medium" if risk >= 40 else "low",
                "active_incident_count": self.rng.randint(0, 4),
                "open_vuln_count": self.rng.randint(0, 12),
                "is_honeypot": i % 997 == 0,
                "tags": [self.asset_types[i % len(self.asset_types)], self.departments[i % len(self.departments)].lower()],
                "last_seen": self.dt_back(14),
                "created_at": self.dt_back(365),
                "updated_at": self.dt_back(14),
            }

    def devices(self):
        for i in range(self.counts["devices"]):
            aid = self.asset_id(i)
            yield {
                "_key": f"device-{i:08d}",
                "device_id": f"device-{i:08d}",
                "tenant_id": self.tenant_id(i),
                "hostname": f"HOST-{i:08d}",
                "ip_addresses": [f"10.{i % 250}.{(i // 250) % 250}.{(i // 62500) % 250 + 1}"],
                "os_type": ["windows", "linux", "macos"][i % 3],
                "agent_version": f"0.{i % 9}.{i % 20}",
                "agent_status": "online" if i % 7 else "offline",
                "agent_id": f"agent-{i:08d}",
                "policy_id": f"policy-{i % self.counts['agent_policies']:06d}",
                "last_heartbeat": self.dt_back(3),
                "asset_id": aid,
                "created_at": self.dt_back(365),
                "updated_at": self.dt_back(7),
            }

    def vulnerabilities(self):
        for i in range(self.counts["vulnerabilities"]):
            cvss = round(self.rng.uniform(1.0, 10.0), 1)
            yield {
                "_key": f"CVE-2026-{i:05d}",
                "tenant_id": self.tenant_id(i),
                "cve_id": f"CVE-2026-{i:05d}",
                "title": f"Mock vulnerability {i:05d}",
                "cvss_score": cvss,
                "severity": "critical" if cvss >= 9 else "high" if cvss >= 7 else "medium" if cvss >= 4 else "low",
                "priority_score": min(100, int(cvss * 10) + (20 if i % 13 == 0 else 0)),
                "exploited_in_wild": i % 13 == 0,
                "affected_asset_ids": [self.asset_id(i), self.asset_id(i + 17)],
                "fix_status": ["open", "in_progress", "fixed", "accepted_risk"][i % 4],
                "fix_deadline": self.dt_forward(90),
                "created_at": self.dt_back(180),
                "updated_at": self.dt_back(30),
            }

    def iocs(self):
        types = ["ip", "domain", "sha256", "url"]
        for i in range(self.counts["iocs"]):
            t = types[i % len(types)]
            value = {
                "ip": f"203.0.{(i // 255) % 255}.{i % 255}",
                "domain": f"malicious-{i:08d}.example.test",
                "sha256": f"{i:064x}"[-64:],
                "url": f"https://malicious-{i:08d}.example.test/payload",
            }[t]
            yield {
                "_key": f"ioc-{i:09d}",
                "tenant_id": self.tenant_id(i),
                "type": t,
                "value": value,
                "verdict": ["malicious", "suspicious", "benign"][i % 3],
                "confidence": self.rng.randint(30, 99),
                "source_name": f"Feed {i % self.counts['intel_feeds']:04d}",
                "hit_count": self.rng.randint(0, 500),
                "last_hit_at": self.dt_back(30),
                "expires_at": self.dt_forward(120),
                "is_active": i % 11 != 0,
                "created_at": self.dt_back(180),
                "updated_at": self.dt_back(30),
            }

    def intel_feeds(self):
        for i in range(self.counts["intel_feeds"]):
            yield {
                "_key": f"feed-{i:05d}",
                "tenant_id": self.tenant_id(i),
                "feed_id": f"feed-{i:05d}",
                "name": f"Feed {i:04d}",
                "type": ["stix-taxii", "csv", "api"][i % 3],
                "status": "enabled" if i % 5 else "disabled",
                "last_sync_at": self.dt_back(3),
                "created_at": self.dt_back(365),
                "updated_at": self.dt_back(30),
            }

    def datasources(self):
        for i in range(self.counts["datasources"]):
            yield {
                "_key": f"ds-{i:06d}",
                "tenant_id": self.tenant_id(i),
                "datasource_id": f"ds-{i:06d}",
                "name": f"Datasource {i:06d}",
                "type": ["agent", "syslog", "cloud", "identity", "edr"][i % 5],
                "status": "enabled" if i % 9 else "disabled",
                "ingest_mode": ["push", "pull"][i % 2],
                "last_event_at": self.dt_back(2),
                "created_at": self.dt_back(365),
                "updated_at": self.dt_back(30),
            }

    def detection_rules(self):
        for i in range(self.counts["detection_rules"]):
            tactic, technique = self.mitre[i % len(self.mitre)]
            yield {
                "_key": f"RULE-{i:08d}",
                "tenant_id": self.tenant_id(i),
                "rule_id": f"RULE-{i:08d}",
                "name": f"Detection Rule {i:08d}",
                "rule_type": ["bioc", "ioc", "ueba"][i % 3],
                "status": ["active", "testing", "draft", "disabled"][i % 4],
                "definition": {"query": f"dataset=xsiam_process | filter rule_id='{i:08d}'"},
                "mitre_tactic": tactic,
                "mitre_technique": technique,
                "severity": self.severities[i % len(self.severities)],
                "test_result": {"last_status": "passed" if i % 7 else "failed"},
                "hit_count": self.rng.randint(0, 10000),
                "false_positive_rate": round(self.rng.random() * 0.2, 4),
                "last_hit_at": self.dt_back(30),
                "created_at": self.dt_back(365),
                "updated_at": self.dt_back(30),
            }

    def alerts(self):
        for i in range(self.counts["alerts"]):
            tactic, technique = self.mitre[i % len(self.mitre)]
            yield {
                "_key": self.alert_id(i),
                "alert_id": self.alert_id(i),
                "tenant_id": self.tenant_id(i),
                "name": f"Mock Alert {i:09d}",
                "severity": self.severities[i % len(self.severities)],
                "source_type": ["detection_rule", "ioc", "ueba", "manual"][i % 4],
                "status": self.statuses[i % len(self.statuses)],
                "asset_id": self.asset_id(i),
                "asset_name": f"HOST-{i % self.counts['assets']:08d}",
                "incident_id": self.incident_id(i) if i % 4 != 0 else None,
                "detection_rule": {"rule_id": f"RULE-{i % self.counts['detection_rules']:08d}"},
                "mitre_tactics": [tactic],
                "mitre_techniques": [technique],
                "iocs": [{"type": "ip", "value": f"203.0.{(i // 255) % 255}.{i % 255}"}],
                "process_tree": [{"pid": 1000 + i % 5000, "process_name": "powershell.exe", "parent_pid": 500}],
                "raw_data": {"src_ip": f"10.{i % 250}.{(i // 250) % 250}.10", "event_id": i},
                "assignee_id": self.user_id(i) if i % 3 == 0 else None,
                "triggered_at": self.dt_back(31),
                "created_at": self.dt_back(31),
                "updated_at": self.dt_back(7),
            }

    def incidents(self):
        for i in range(self.counts["incidents"]):
            tactic, _ = self.mitre[i % len(self.mitre)]
            yield {
                "_key": self.incident_id(i),
                "incident_id": self.incident_id(i),
                "tenant_id": self.tenant_id(i),
                "name": f"Mock Incident {i:08d}",
                "severity": self.severities[i % len(self.severities)],
                "status": self.statuses[i % len(self.statuses)],
                "smart_score": self.rng.randint(0, 100),
                "score_factors": [{"name": "behavior", "score": self.rng.randint(0, 30)}],
                "alert_ids": [self.alert_id(i * 4 + j) for j in range(3)],
                "alert_count": 3,
                "affected_assets": [self.asset_id(i), self.asset_id(i + 1)],
                "mitre_tactics": [tactic],
                "assignee_id": self.user_id(i) if i % 2 == 0 else None,
                "timeline": [{"at": self.dt_back(30), "type": "alert_created"}],
                "notes": [],
                "first_seen": self.dt_back(89),
                "last_activity": self.dt_back(7),
                "created_at": self.dt_back(89),
                "updated_at": self.dt_back(7),
            }

    def actions(self):
        for i in range(self.counts["actions"]):
            yield {
                "_key": f"action-{i:08d}",
                "tenant_id": self.tenant_id(i),
                "action_id": f"action-{i:08d}",
                "type": ["isolate_host", "kill_process", "lock_account", "notify"][i % 4],
                "target_type": ["asset", "user", "ioc"][i % 3],
                "target_asset_id": self.asset_id(i),
                "incident_id": self.incident_id(i),
                "triggered_by": self.user_id(i),
                "status": ["pending_approval", "running", "success", "failed"][i % 4],
                "requires_approval": i % 3 == 0,
                "approved_by": self.user_id(i + 1) if i % 3 == 0 else None,
                "result_summary": "mock action",
                "result_detail": {"attempt": i % 5},
                "created_at": self.dt_back(90),
                "updated_at": self.dt_back(30),
            }

    def playbooks(self):
        for i in range(self.counts["playbooks"]):
            yield {
                "_key": f"playbook-{i:06d}",
                "tenant_id": self.tenant_id(i),
                "playbook_id": f"playbook-{i:06d}",
                "name": f"Playbook {i:06d}",
                "trigger": {"type": ["incident_severity", "alert_type", "manual"][i % 3]},
                "canvas": {"nodes": [{"id": "start", "type": "start"}], "edges": []},
                "is_enabled": i % 5 != 0,
                "run_count": self.rng.randint(0, 500),
                "last_run_at": self.dt_back(30) if i % 3 else None,
                "created_at": self.dt_back(365),
                "updated_at": self.dt_back(30),
            }

    def reports(self):
        for i in range(self.counts["reports"]):
            yield {
                "_key": f"report-{i:07d}",
                "tenant_id": self.tenant_id(i),
                "report_id": f"report-{i:07d}",
                "name": f"Report {i:07d}",
                "template_type": ["daily_summary", "incident_postmortem", "compliance"][i % 3],
                "schedule": {"cron": "0 8 * * *", "timezone": "Asia/Shanghai"},
                "recipients": [f"soc{i % 20}@example.local"],
                "last_generated_at": self.dt_back(30),
                "created_at": self.dt_back(365),
                "updated_at": self.dt_back(30),
            }

    def identity_risks(self):
        for i in range(self.counts["identity_risks"]):
            yield {
                "_key": f"identity-{i:08d}",
                "tenant_id": self.tenant_id(i),
                "user_id": self.user_id(i),
                "username": f"user{i % self.counts['users']:07d}",
                "domain": "xsiam.local",
                "risk_score": self.rng.randint(0, 100),
                "risk_signals": [{"type": "impossible_travel", "score": self.rng.randint(1, 40)}],
                "active_restrictions": [],
                "last_impossible_travel_at": self.dt_back(30) if i % 5 == 0 else None,
                "baseline": {"countries": ["CN"], "login_hours": [8, 9, 10, 14, 15, 16]},
                "updated_at": self.dt_back(7),
            }

    def privilege_restrictions(self):
        for i in range(self.counts["privilege_restrictions"]):
            yield {
                "_key": f"restriction-{i:08d}",
                "tenant_id": self.tenant_id(i),
                "user_id": self.user_id(i),
                "level": i % 5 + 1,
                "trigger_signal": ["impossible_travel", "privilege_escalation", "risky_login"][i % 3],
                "trigger_score": self.rng.randint(40, 100),
                "applied_at": self.dt_back(15),
                "expires_at": self.dt_forward(30),
                "released_at": None,
                "released_by": None,
                "action_log": [{"at": self.dt_back(15), "action": "created"}],
            }

    def exposure_scores(self):
        for i in range(self.counts["exposure_scores"]):
            cve_index = (i // self.counts["assets"]) % self.counts["vulnerabilities"]
            yield {
                "_key": f"exposure-{i:09d}",
                "tenant_id": self.tenant_id(i),
                "asset_id": self.asset_id(i),
                "cve_id": f"CVE-2026-{cve_index:05d}",
                "cvss_score": round(self.rng.uniform(1, 10), 1),
                "priority_score": self.rng.randint(0, 100),
                "in_wild_factor": round(self.rng.uniform(0.8, 1.5), 2),
                "reachability_factor": round(self.rng.uniform(0.8, 1.5), 2),
                "asset_importance_factor": round(self.rng.uniform(0.8, 1.5), 2),
                "fix_status": ["open", "in_progress", "fixed"][i % 3],
                "fix_deadline": self.dt_forward(90),
                "last_scored_at": self.dt_back(7),
            }

    def causality_nodes(self):
        node_types = ["alert", "asset", "process", "user", "ioc"]
        for i in range(self.counts["causality_nodes"]):
            yield {
                "_key": f"cnode-{i:09d}",
                "tenant_id": self.tenant_id(i),
                "incident_id": self.incident_id(i),
                "node_type": node_types[i % len(node_types)],
                "ref_id": self.alert_id(i) if i % 2 else self.asset_id(i),
                "label": f"Causality Node {i:09d}",
                "severity": self.severities[i % len(self.severities)],
                "timestamp": self.dt_back(89),
                "created_at": self.dt_back(89),
            }

    def causality_edges(self):
        node_count = self.counts["causality_nodes"]
        for i in range(self.counts["causality_edges"]):
            yield {
                "_key": f"cedge-{i:09d}",
                "tenant_id": self.tenant_id(i),
                "incident_id": self.incident_id(i),
                "_from": f"causality_nodes/cnode-{i % node_count:09d}",
                "_to": f"causality_nodes/cnode-{(i + 1) % node_count:09d}",
                "edge_type": ["parent_process", "same_asset", "network_connection", "temporal"][i % 4],
                "weight": round(self.rng.uniform(0.1, 1.0), 3),
                "evidence": ["mock", "time_window"],
                "created_at": self.dt_back(89),
            }

    def audit_logs(self):
        actions = ["create", "update", "delete", "login", "export", "execute"]
        resources = ["alert", "incident", "asset", "playbook", "rule", "user"]
        for i in range(self.counts["audit_logs"]):
            yield {
                "_key": f"audit-{i:09d}",
                "tenant_id": self.tenant_id(i),
                "operator": self.user_id(i),
                "action": actions[i % len(actions)],
                "resource_type": resources[i % len(resources)],
                "resource_id": f"{resources[i % len(resources)]}-{i:08d}",
                "result": "success" if i % 17 else "failed",
                "ip": f"10.200.{i % 250}.{(i // 250) % 250}",
                "detail": {"mock": True, "sequence": i},
                "created_at": self.dt_back(364),
            }

    def generate(self) -> None:
        if self.out_dir.exists():
            shutil.rmtree(self.out_dir)
        self.out_dir.mkdir(parents=True, exist_ok=True)

        manifest = {
            "generated_at": iso(self.now),
            "requested_total": self.total,
            "actual_total": sum(self.counts.values()),
            "collections": self.counts,
        }
        (self.out_dir / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")

        for name in COLLECTIONS:
            self.write_collection(name, getattr(self, name)())


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--out", default=str(Path(__file__).resolve().parent / "data"))
    parser.add_argument("--total", type=int, default=1_000_000)
    parser.add_argument("--seed", type=int, default=20260522)
    args = parser.parse_args()

    Generator(Path(args.out), args.total, args.seed).generate()


if __name__ == "__main__":
    main()
