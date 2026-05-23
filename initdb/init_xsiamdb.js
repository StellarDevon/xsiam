/* Initialize the XSIAM ArangoDB schema and seed data.
 *
 * Usage from WSL:
 *   arangosh --server.endpoint tcp://127.0.0.1:8529 \
 *     --server.username root --server.password changeme \
 *     --javascript.execute /mnt/d/src/xsiam/initdb/init_xsiamdb.js
 */

'use strict';

const db = require('@arangodb').db;
const graphModule = require('@arangodb/general-graph');

const databaseName = 'xsiamdb';
const resetDatabase = true;

function nowIso() {
  return new Date().toISOString();
}

function plusDays(days) {
  const d = new Date();
  d.setUTCDate(d.getUTCDate() + days);
  return d.toISOString();
}

function ensureDatabase(name) {
  db._useDatabase('_system');
  if (resetDatabase && db._databases().includes(name)) {
    db._dropDatabase(name);
  }
  if (!db._databases().includes(name)) {
    db._createDatabase(name);
  }
  db._useDatabase(name);
}

function ensureCollection(name, type) {
  let col = db._collection(name);
  if (!col) {
    col = type === 3 ? db._createEdgeCollection(name) : db._create(name);
  } else if (type && col.type && col.type() !== type) {
    if (col.count() !== 0) {
      throw new Error(`collection ${name} has type ${col.type()}, expected ${type}, and is not empty`);
    }
    db._drop(name);
    col = type === 3 ? db._createEdgeCollection(name) : db._create(name);
  }
  return col;
}

function ensureIndex(collectionName, spec) {
  const col = db._collection(collectionName);
  if (!col) {
    throw new Error(`collection not found: ${collectionName}`);
  }
  col.ensureIndex(spec);
}

function ensureSchema(collectionName, schema) {
  const col = db._collection(collectionName);
  if (!col) {
    throw new Error(`collection not found: ${collectionName}`);
  }
  col.properties({ schema });
}

function dropIndexesByFields(collectionName, fields) {
  const col = db._collection(collectionName);
  const expected = JSON.stringify(fields);
  col.getIndexes().forEach((idx) => {
    if (idx.type !== 'primary' && JSON.stringify(idx.fields || []) === expected) {
      col.dropIndex(idx.id);
    }
  });
}

function ensureGraph() {
  const graphName = 'causality_graph';
  if (graphModule._exists(graphName)) {
    return;
  }
  graphModule._create(
    graphName,
    [graphModule._relation('causality_edges', ['causality_nodes'], ['causality_nodes'])]
  );
}

function upsert(collectionName, doc) {
  const col = db._collection(collectionName);
  let current = null;
  try {
    current = col.document(doc._key);
  } catch (err) {
    current = null;
  }
  if (current) {
    col.update(doc._key, doc, { keepNull: false, mergeObjects: true });
  } else {
    col.insert(doc);
  }
}

ensureDatabase(databaseName);

const documentCollections = [
  'alerts',
  'incidents',
  'assets',
  'vulnerabilities',
  'iocs',
  'intel_feeds',
  'actions',
  'devices',
  'agent_policies',
  'datasources',
  'playbooks',
  'reports',
  'users',
  'audit_logs',
  'tenants',
  'rbac_roles',
  'detection_rules',
  'identity_risks',
  'privilege_restrictions',
  'exposure_scores',
  'causality_nodes'
];

documentCollections.forEach((name) => ensureCollection(name, 2));
ensureCollection('causality_edges', 3);
ensureGraph();

// Remove indexes created by older local init script revisions that went beyond
// the design document or used looser uniqueness semantics.
dropIndexesByFields('assets', ['identifier']);
dropIndexesByFields('incidents', ['first_seen']);
dropIndexesByFields('causality_edges', ['_from']);
dropIndexesByFields('causality_edges', ['_to']);

// Indexes from docs/XDR技术设计文档.md section 8.1, adjusted for ArangoDB.
[
  ['assets', { type: 'persistent', fields: ['type', 'risk_level'] }],
  ['assets', { type: 'persistent', fields: ['risk_score'] }],
  ['assets', { type: 'persistent', fields: ['agent.status'] }],
  ['assets', { type: 'persistent', fields: ['identifier'], unique: true }],

  ['alerts', { type: 'persistent', fields: ['severity', 'status'] }],
  ['alerts', { type: 'persistent', fields: ['triggered_at'] }],
  ['alerts', { type: 'persistent', fields: ['incident_id'], sparse: true }],
  ['alerts', { type: 'persistent', fields: ['alert_id'], unique: true }],
  ['alerts', { type: 'ttl', fields: ['triggered_at'], expireAfter: 2764800 }],

  ['incidents', { type: 'persistent', fields: ['severity', 'status'] }],
  ['incidents', { type: 'persistent', fields: ['smart_score'] }],
  ['incidents', { type: 'persistent', fields: ['assignee_id'], sparse: true }],
  ['incidents', { type: 'persistent', fields: ['incident_id'], unique: true }],
  ['incidents', { type: 'ttl', fields: ['created_at'], expireAfter: 7776000 }],

  ['vulnerabilities', { type: 'persistent', fields: ['cve_id'], unique: true }],
  ['vulnerabilities', { type: 'persistent', fields: ['severity', 'fix_status'] }],
  ['vulnerabilities', { type: 'persistent', fields: ['priority_score'] }],

  ['iocs', { type: 'persistent', fields: ['type', 'value'], unique: true }],
  ['iocs', { type: 'persistent', fields: ['verdict'] }],
  ['iocs', { type: 'ttl', fields: ['expires_at'], expireAfter: 0 }],

  ['intel_feeds', { type: 'persistent', fields: ['status'] }],

  ['actions', { type: 'persistent', fields: ['status'] }],
  ['actions', { type: 'persistent', fields: ['incident_id'], sparse: true }],
  ['actions', { type: 'persistent', fields: ['target_asset_id'], sparse: true }],
  ['actions', { type: 'persistent', fields: ['created_at'] }],

  ['devices', { type: 'persistent', fields: ['agent_id'], unique: true }],
  ['devices', { type: 'persistent', fields: ['agent_status'] }],
  ['devices', { type: 'persistent', fields: ['tenant_id', 'agent_status'] }],
  ['devices', { type: 'persistent', fields: ['tenant_id', 'is_connected'] }],
  ['devices', { type: 'persistent', fields: ['last_heartbeat'] }],
  ['devices', { type: 'persistent', fields: ['tenant_id', 'last_heartbeat'] }],
  ['devices', { type: 'persistent', fields: ['host_type'] }],
  ['devices', { type: 'persistent', fields: ['asset_id'], sparse: true }],
  ['devices', { type: 'persistent', fields: ['policy_id'], sparse: true }],
  ['devices', { type: 'persistent', fields: ['gateway_id'], sparse: true }],

  ['agent_policies', { type: 'persistent', fields: ['is_default'] }],
  ['datasources', { type: 'persistent', fields: ['status'] }],
  ['playbooks', { type: 'persistent', fields: ['is_enabled'] }],
  ['playbooks', { type: 'persistent', fields: ['trigger.type'] }],
  ['reports', { type: 'persistent', fields: ['template_type'] }],

  ['users', { type: 'persistent', fields: ['email'], unique: true }],
  ['users', { type: 'persistent', fields: ['tenant_id'] }],

  ['audit_logs', { type: 'persistent', fields: ['resource_type', 'resource_id'] }],
  ['audit_logs', { type: 'persistent', fields: ['created_at'] }],
  ['audit_logs', { type: 'ttl', fields: ['created_at'], expireAfter: 31536000 }],

  ['detection_rules', { type: 'persistent', fields: ['rule_type', 'status'] }],
  ['detection_rules', { type: 'persistent', fields: ['mitre_technique'], sparse: true }],
  ['detection_rules', { type: 'persistent', fields: ['rule_id'], unique: true }],

  ['identity_risks', { type: 'persistent', fields: ['user_id'], unique: true }],
  ['identity_risks', { type: 'persistent', fields: ['risk_score'] }],
  ['identity_risks', { type: 'persistent', fields: ['updated_at'] }],

  ['privilege_restrictions', { type: 'persistent', fields: ['user_id'] }],
  ['privilege_restrictions', { type: 'persistent', fields: ['level'] }],
  ['privilege_restrictions', { type: 'ttl', fields: ['expires_at'], expireAfter: 0 }],

  ['exposure_scores', { type: 'persistent', fields: ['asset_id', 'cve_id'], unique: true }],
  ['exposure_scores', { type: 'persistent', fields: ['priority_score'] }],

  ['tenants', { type: 'persistent', fields: ['tenant_code'], unique: true }],
  ['tenants', { type: 'persistent', fields: ['parent_tenant_id'], sparse: true }],

  ['rbac_roles', { type: 'persistent', fields: ['tenant_id', 'name'], unique: true }],

  ['causality_nodes', { type: 'persistent', fields: ['incident_id'] }],
  ['causality_nodes', { type: 'ttl', fields: ['created_at'], expireAfter: 7776000 }],
  ['causality_edges', { type: 'persistent', fields: ['incident_id'] }],
  ['causality_edges', { type: 'ttl', fields: ['created_at'], expireAfter: 7776000 }]
].forEach(([collectionName, spec]) => ensureIndex(collectionName, spec));

ensureSchema('devices', {
  level: 'strict',
  message: 'devices documents must match the XSIAM device runtime schema',
  rule: {
    type: 'object',
    required: [
      'tenant_id',
      'device_id',
      'agent_id',
      'agent_status',
      'is_connected',
      'hostname',
      'host_type',
      'mac_addresses',
      'agent_version',
      'protocol',
      'protocol_version',
      'enrolled_at',
      'installed_at',
      'last_heartbeat',
      'last_seen',
      'created_at',
      'updated_at'
    ],
    properties: {
      _key: { type: 'string' },
      tenant_id: { type: 'string' },
      device_id: { type: 'string' },
      agent_id: { type: 'string' },
      asset_id: { type: 'string' },
      policy_id: { type: 'string' },
      gateway_id: { type: 'string' },
      hostname: { type: 'string' },
      host_type: { type: 'string', enum: ['server', 'pc'] },
      ip: { type: 'string' },
      ip_addresses: { type: 'array', items: { type: 'string' } },
      mac_addresses: { type: 'array', items: { type: 'string' } },
      os_type: { type: 'string' },
      os_version: { type: 'string' },
      agent_version: { type: 'string' },
      agent_status: {
        type: 'string',
        enum: ['online', 'offline', 'installing', 'uninstalling', 'error']
      },
      is_connected: { type: 'boolean' },
      protocol: { type: 'string', enum: ['wzcp'] },
      protocol_version: { type: 'number' },
      installed_at: { type: 'string', format: 'date-time' },
      last_heartbeat: { type: 'string', format: 'date-time' },
      last_seen: { type: 'string', format: 'date-time' },
      status: { type: 'string' },
      os: { type: 'string' },
      enrolled_at: { type: 'string', format: 'date-time' },
      created_at: { type: 'string', format: 'date-time' },
      updated_at: { type: 'string', format: 'date-time' }
    },
    additionalProperties: false
  }
});

const now = nowIso();
const tenantId = 'tenant-default';
const assetId = 'asset-win-001';
const incidentId = 'INC-20260522-0001';
const alertId = 'ALERT-20260522-0001';
const userId = 'user-admin';
const roleId = 'role-soc-admin';
const ruleId = 'RULE-SUSPICIOUS-POWERSHELL';
const adminPasswordHash = '$2a$10$SPGQECUtGsqUWdV0eHRXYuMlxSfb4iPGWKWXh7BPuXYbuw3T7pY9W'; // Admin@123456

upsert('tenants', {
  _key: tenantId,
  tenant_id: tenantId,
  tenant_code: 'default',
  name: 'Default Tenant',
  tier: 'super',
  parent_tenant_id: null,
  is_enabled: true,
  settings: { timezone: 'Asia/Shanghai', retention_days: 90 },
  created_at: now,
  updated_at: now
});

upsert('rbac_roles', {
  _key: roleId,
  role_id: roleId,
  tenant_id: tenantId,
  name: 'SOC Admin',
  permissions: [
    'alerts:*',
    'incidents:*',
    'assets:*',
    'vulnerabilities:*',
    'threat_intel:*',
    'playbooks:*',
    'detection_rules:*',
    'reports:*',
    'admin:*'
  ],
  resource_scopes: { tenant_id: tenantId },
  is_builtin: true,
  created_at: now,
  updated_at: now
});

upsert('users', {
  _key: userId,
  user_id: userId,
  tenant_id: tenantId,
  email: 'admin@xsiam.local',
  username: 'admin',
  password_hash: adminPasswordHash,
  display_name: 'XSIAM Administrator',
  role_ids: [roleId],
  role: 'admin',
  status: 'active',
  is_enabled: true,
  mfa_enabled: false,
  last_login_at: null,
  created_at: now,
  updated_at: now
});

upsert('agent_policies', {
  _key: 'policy-default-windows',
  policy_id: 'policy-default-windows',
  tenant_id: tenantId,
  name: 'Default Windows Endpoint Policy',
  is_default: true,
  platform: 'windows',
  collection: {
    process_events: true,
    network_events: true,
    file_events: true,
    registry_events: true
  },
  response: {
    process_kill: true,
    host_isolation: true,
    file_quarantine: true
  },
  created_at: now,
  updated_at: now
});

upsert('assets', {
  _key: assetId,
  asset_id: assetId,
  tenant_id: tenantId,
  name: 'WIN-SOC-001',
  type: 'endpoint',
  identifier: 'win-soc-001.local',
  os: { name: 'Windows 11', version: '24H2', arch: 'x64' },
  agent: { id: 'agent-win-001', version: '0.1.0', status: 'online' },
  department: 'Security Operations',
  risk_score: 72,
  risk_level: 'high',
  active_incident_count: 1,
  open_vuln_count: 1,
  is_honeypot: false,
  tags: ['windows', 'endpoint', 'soc'],
  last_seen: now,
  created_at: now,
  updated_at: now
});

upsert('devices', {
  _key: 'device-agent-win-001',
  device_id: 'device-agent-win-001',
  tenant_id: tenantId,
  hostname: 'WIN-SOC-001',
  host_type: 'pc',
  ip: '10.10.20.15',
  ip_addresses: ['10.10.20.15'],
  mac_addresses: ['00:15:5D:10:20:15'],
  os_type: 'windows',
  os_version: '24H2',
  os: 'Windows 11',
  agent_version: '0.1.0',
  agent_status: 'online',
  status: 'online',
  is_connected: true,
  agent_id: 'agent-win-001',
  policy_id: 'policy-default-windows',
  asset_id: assetId,
  gateway_id: 'gateway-local-001',
  protocol: 'wzcp',
  protocol_version: 1,
  enrolled_at: now,
  installed_at: now,
  last_heartbeat: now,
  last_seen: now,
  created_at: now,
  updated_at: now
});

upsert('vulnerabilities', {
  _key: 'CVE-2025-0001',
  tenant_id: tenantId,
  cve_id: 'CVE-2025-0001',
  title: 'Sample endpoint privilege escalation exposure',
  cvss_score: 8.1,
  severity: 'high',
  priority_score: 83,
  exploited_in_wild: true,
  affected_asset_ids: [assetId],
  fix_status: 'open',
  fix_deadline: plusDays(14),
  created_at: now,
  updated_at: now
});

upsert('iocs', {
  _key: 'ioc-ip-203-0-113-10',
  tenant_id: tenantId,
  type: 'ip',
  value: '203.0.113.10',
  verdict: 'malicious',
  confidence: 92,
  source_name: 'Default Threat Feed',
  hit_count: 1,
  last_hit_at: now,
  expires_at: plusDays(30),
  is_active: true,
  created_at: now,
  updated_at: now
});

upsert('intel_feeds', {
  _key: 'feed-default-threat',
  tenant_id: tenantId,
  feed_id: 'feed-default-threat',
  name: 'Default Threat Feed',
  type: 'stix-taxii',
  status: 'enabled',
  last_sync_at: now,
  created_at: now,
  updated_at: now
});

upsert('datasources', {
  _key: 'ds-xsiam-agent',
  tenant_id: tenantId,
  datasource_id: 'ds-xsiam-agent',
  name: 'xsiam-agent endpoint telemetry',
  type: 'agent',
  status: 'enabled',
  ingest_mode: 'push',
  last_event_at: now,
  created_at: now,
  updated_at: now
});

upsert('detection_rules', {
  _key: ruleId,
  tenant_id: tenantId,
  rule_id: ruleId,
  name: 'Suspicious PowerShell Execution',
  rule_type: 'bioc',
  status: 'active',
  definition: {
    query: 'dataset=xsiam_process | filter process_name=\"powershell.exe\" and cmdline contains \"-enc\"',
    threshold: { comparator: '>=', value: 1, window_minutes: 5 }
  },
  mitre_tactic: 'TA0002',
  mitre_technique: 'T1059.001',
  severity: 'high',
  test_result: { last_status: 'passed', sample_hits: 1 },
  hit_count: 1,
  false_positive_rate: 0.02,
  last_hit_at: now,
  created_at: now,
  updated_at: now
});

upsert('alerts', {
  _key: alertId,
  alert_id: alertId,
  tenant_id: tenantId,
  name: 'Suspicious encoded PowerShell command',
  severity: 'high',
  source_type: 'detection_rule',
  status: 'open',
  asset_id: assetId,
  asset_name: 'WIN-SOC-001',
  incident_id: incidentId,
  detection_rule: { rule_id: ruleId, name: 'Suspicious PowerShell Execution' },
  mitre_tactics: ['TA0002'],
  mitre_techniques: ['T1059.001'],
  iocs: [{ type: 'ip', value: '203.0.113.10', verdict: 'malicious' }],
  process_tree: [
    { pid: 4321, process_name: 'winword.exe', parent_pid: 980 },
    { pid: 4388, process_name: 'powershell.exe', parent_pid: 4321 }
  ],
  raw_data: {
    process_name: 'powershell.exe',
    cmdline: 'powershell.exe -enc <redacted>',
    src_ip: '10.10.20.15',
    dst_ip: '203.0.113.10'
  },
  assignee_id: userId,
  triggered_at: now,
  created_at: now,
  updated_at: now
});

upsert('incidents', {
  _key: incidentId,
  incident_id: incidentId,
  tenant_id: tenantId,
  name: 'Potential script-based execution on endpoint',
  severity: 'high',
  status: 'investigating',
  smart_score: 82,
  score_factors: [
    { name: 'asset_importance', score: 20 },
    { name: 'threat_intel', score: 22 },
    { name: 'behavior', score: 25 },
    { name: 'urgency', score: 15 }
  ],
  alert_ids: [alertId],
  alert_count: 1,
  affected_assets: [assetId],
  mitre_tactics: ['TA0002'],
  assignee_id: userId,
  timeline: [
    { at: now, type: 'alert_created', message: 'Suspicious PowerShell alert created' }
  ],
  notes: [
    { at: now, author_id: userId, body: 'Seed incident for local development.' }
  ],
  first_seen: now,
  last_activity: now,
  created_at: now,
  updated_at: now
});

upsert('actions', {
  _key: 'action-isolate-sample',
  tenant_id: tenantId,
  action_id: 'action-isolate-sample',
  type: 'isolate_host',
  target_type: 'asset',
  target_asset_id: assetId,
  incident_id: incidentId,
  triggered_by: userId,
  status: 'pending_approval',
  requires_approval: true,
  approved_by: null,
  result_summary: null,
  result_detail: {},
  created_at: now,
  updated_at: now
});

upsert('playbooks', {
  _key: 'playbook-endpoint-containment',
  tenant_id: tenantId,
  playbook_id: 'playbook-endpoint-containment',
  name: 'Endpoint Containment',
  trigger: { type: 'incident_severity', severity: 'high' },
  canvas: {
    nodes: [
      { id: 'start', type: 'start', label: 'Incident Created' },
      { id: 'approve', type: 'approval', label: 'SOC Approval' },
      { id: 'isolate', type: 'action', label: 'Isolate Host' }
    ],
    edges: [
      { from: 'start', to: 'approve' },
      { from: 'approve', to: 'isolate' }
    ]
  },
  is_enabled: true,
  run_count: 0,
  last_run_at: null,
  created_at: now,
  updated_at: now
});

upsert('reports', {
  _key: 'report-daily-soc',
  tenant_id: tenantId,
  report_id: 'report-daily-soc',
  name: 'Daily SOC Summary',
  template_type: 'daily_summary',
  schedule: { cron: '0 8 * * *', timezone: 'Asia/Shanghai' },
  recipients: ['soc@example.local'],
  last_generated_at: null,
  created_at: now,
  updated_at: now
});

upsert('identity_risks', {
  _key: 'identity-admin',
  tenant_id: tenantId,
  user_id: userId,
  username: 'admin',
  domain: 'xsiam.local',
  risk_score: 45,
  risk_signals: [
    { type: 'new_device_login', score: 15, observed_at: now },
    { type: 'privileged_role', score: 30, observed_at: now }
  ],
  active_restrictions: [],
  last_impossible_travel_at: null,
  baseline: { login_hours: [8, 9, 10, 11, 13, 14, 15, 16, 17], countries: ['CN'] },
  updated_at: now
});

upsert('privilege_restrictions', {
  _key: 'restriction-admin-sample',
  tenant_id: tenantId,
  user_id: userId,
  level: 1,
  trigger_signal: 'new_device_login',
  trigger_score: 45,
  applied_at: now,
  expires_at: plusDays(7),
  released_at: null,
  released_by: null,
  action_log: [{ at: now, action: 'created', by: 'system' }]
});

upsert('exposure_scores', {
  _key: 'exposure-asset-win-001-cve-2025-0001',
  tenant_id: tenantId,
  asset_id: assetId,
  cve_id: 'CVE-2025-0001',
  cvss_score: 8.1,
  priority_score: 86,
  in_wild_factor: 1.2,
  reachability_factor: 1.1,
  asset_importance_factor: 1.3,
  fix_status: 'open',
  fix_deadline: plusDays(14),
  last_scored_at: now
});

upsert('causality_nodes', {
  _key: 'node-alert-0001',
  tenant_id: tenantId,
  incident_id: incidentId,
  node_type: 'alert',
  ref_id: alertId,
  label: 'Suspicious PowerShell',
  severity: 'high',
  timestamp: now,
  created_at: now
});

upsert('causality_nodes', {
  _key: 'node-asset-win-001',
  tenant_id: tenantId,
  incident_id: incidentId,
  node_type: 'asset',
  ref_id: assetId,
  label: 'WIN-SOC-001',
  severity: 'medium',
  timestamp: now,
  created_at: now
});

upsert('causality_edges', {
  _key: 'edge-asset-alert-0001',
  tenant_id: tenantId,
  incident_id: incidentId,
  _from: 'causality_nodes/node-asset-win-001',
  _to: 'causality_nodes/node-alert-0001',
  edge_type: 'generated',
  weight: 0.91,
  evidence: ['same_asset', 'same_time_window'],
  created_at: now
});

upsert('audit_logs', {
  _key: 'audit-initdb',
  tenant_id: tenantId,
  operator: 'initdb',
  action: 'initialize_database',
  resource_type: 'database',
  resource_id: databaseName,
  result: 'success',
  ip: '127.0.0.1',
  detail: {
    collections: documentCollections.concat(['causality_edges']),
    graph: 'causality_graph'
  },
  created_at: now
});

print(JSON.stringify({
  database: databaseName,
  document_collections: documentCollections.length,
  edge_collections: ['causality_edges'],
  graph: 'causality_graph',
  seeded: true
}, null, 2));
