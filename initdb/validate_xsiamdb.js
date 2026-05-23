/* Validate XSIAM ArangoDB schema against docs/XDR技术设计文档.md. */

'use strict';

const db = require('@arangodb').db;
const graphModule = require('@arangodb/general-graph');

db._useDatabase('xsiamdb');

const expectedCollections = {
  alerts: 2,
  incidents: 2,
  assets: 2,
  vulnerabilities: 2,
  iocs: 2,
  intel_feeds: 2,
  actions: 2,
  devices: 2,
  agent_policies: 2,
  datasources: 2,
  playbooks: 2,
  reports: 2,
  users: 2,
  audit_logs: 2,
  tenants: 2,
  rbac_roles: 2,
  detection_rules: 2,
  identity_risks: 2,
  privilege_restrictions: 2,
  exposure_scores: 2,
  causality_nodes: 2,
  causality_edges: 3
};

const expectedIndexes = {
  assets: [
    { fields: ['type', 'risk_level'] },
    { fields: ['risk_score'] },
    { fields: ['agent.status'] },
    { fields: ['identifier'], unique: true, sparse: false }
  ],
  alerts: [
    { fields: ['severity', 'status'] },
    { fields: ['triggered_at'] },
    { fields: ['incident_id'] },
    { fields: ['alert_id'], unique: true },
    { fields: ['triggered_at'], type: 'ttl', expireAfter: 2764800 }
  ],
  incidents: [
    { fields: ['severity', 'status'] },
    { fields: ['smart_score'] },
    { fields: ['assignee_id'] },
    { fields: ['incident_id'], unique: true },
    { fields: ['created_at'], type: 'ttl', expireAfter: 7776000 }
  ],
  vulnerabilities: [
    { fields: ['cve_id'], unique: true },
    { fields: ['severity', 'fix_status'] },
    { fields: ['priority_score'] }
  ],
  iocs: [
    { fields: ['type', 'value'], unique: true },
    { fields: ['verdict'] },
    { fields: ['expires_at'], type: 'ttl', expireAfter: 0 }
  ],
  intel_feeds: [{ fields: ['status'] }],
  actions: [
    { fields: ['status'] },
    { fields: ['incident_id'] },
    { fields: ['target_asset_id'] },
    { fields: ['created_at'] }
  ],
  devices: [
    { fields: ['agent_id'], unique: true },
    { fields: ['agent_status'] },
    { fields: ['tenant_id', 'agent_status'] },
    { fields: ['tenant_id', 'is_connected'] },
    { fields: ['last_heartbeat'] },
    { fields: ['tenant_id', 'last_heartbeat'] },
    { fields: ['host_type'] },
    { fields: ['asset_id'] },
    { fields: ['policy_id'] },
    { fields: ['gateway_id'] }
  ],
  agent_policies: [{ fields: ['is_default'] }],
  datasources: [{ fields: ['status'] }],
  playbooks: [{ fields: ['is_enabled'] }, { fields: ['trigger.type'] }],
  reports: [{ fields: ['template_type'] }],
  users: [{ fields: ['email'], unique: true }, { fields: ['tenant_id'] }],
  audit_logs: [
    { fields: ['resource_type', 'resource_id'] },
    { fields: ['created_at'] },
    { fields: ['created_at'], type: 'ttl', expireAfter: 31536000 }
  ],
  detection_rules: [
    { fields: ['rule_type', 'status'] },
    { fields: ['mitre_technique'] },
    { fields: ['rule_id'], unique: true }
  ],
  causality_nodes: [
    { fields: ['incident_id'] },
    { fields: ['created_at'], type: 'ttl', expireAfter: 7776000 }
  ],
  causality_edges: [
    { fields: ['incident_id'] },
    { fields: ['created_at'], type: 'ttl', expireAfter: 7776000 }
  ],
  identity_risks: [
    { fields: ['user_id'], unique: true },
    { fields: ['risk_score'] },
    { fields: ['updated_at'] }
  ],
  privilege_restrictions: [
    { fields: ['user_id'] },
    { fields: ['level'] },
    { fields: ['expires_at'], type: 'ttl', expireAfter: 0 }
  ],
  exposure_scores: [
    { fields: ['asset_id', 'cve_id'], unique: true },
    { fields: ['priority_score'] }
  ],
  tenants: [{ fields: ['tenant_code'], unique: true }, { fields: ['parent_tenant_id'] }],
  rbac_roles: [{ fields: ['tenant_id', 'name'], unique: true }]
};

function sameFields(a, b) {
  return JSON.stringify(a || []) === JSON.stringify(b || []);
}

function hasIndex(collectionName, expected) {
  return db._collection(collectionName).getIndexes().some((idx) => {
    if (expected.type && idx.type !== expected.type) return false;
    if (!expected.type && idx.type !== 'persistent') return false;
    if (!sameFields(idx.fields, expected.fields)) return false;
    if (expected.unique !== undefined && !!idx.unique !== expected.unique) return false;
    if (expected.sparse !== undefined && !!idx.sparse !== expected.sparse) return false;
    if (expected.expireAfter !== undefined && idx.expireAfter !== expected.expireAfter) return false;
    return true;
  });
}

const errors = [];

Object.keys(expectedCollections).forEach((name) => {
  const col = db._collection(name);
  if (!col) {
    errors.push(`missing collection ${name}`);
    return;
  }
  if (col.type() !== expectedCollections[name]) {
    errors.push(`collection ${name} type ${col.type()} != ${expectedCollections[name]}`);
  }
});

Object.keys(expectedIndexes).forEach((collectionName) => {
  expectedIndexes[collectionName].forEach((idx) => {
    if (!hasIndex(collectionName, idx)) {
      errors.push(`missing index ${collectionName} ${JSON.stringify(idx)}`);
    }
  });
});

['log_entries', 'causality_graphs', 'agents'].forEach((legacyName) => {
  if (db._collection(legacyName)) {
    errors.push(`legacy collection should not exist: ${legacyName}`);
  }
});

if (!graphModule._exists('causality_graph')) {
  errors.push('missing graph causality_graph');
}

if (errors.length > 0) {
  print(JSON.stringify({ ok: false, errors }, null, 2));
  throw new Error(`schema validation failed: ${errors.length} issue(s)`);
}

print(JSON.stringify({
  ok: true,
  collection_count: Object.keys(expectedCollections).length,
  graph: 'causality_graph'
}, null, 2));
