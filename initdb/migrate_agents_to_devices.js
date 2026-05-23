/* Move runtime Agent state into devices and remove the obsolete agents collection. */

'use strict';

const db = require('@arangodb').db;

db._useDatabase('xsiamdb');

function nowIso() {
  return new Date().toISOString();
}

function ensureCollection(name) {
  let col = db._collection(name);
  if (!col) {
    col = db._create(name);
  }
  return col;
}

function ensureIndex(collectionName, spec) {
  db._collection(collectionName).ensureIndex(spec);
}

function ensureSchema(collectionName, schema) {
  db._collection(collectionName).properties({ schema });
}

const devices = ensureCollection('devices');

[
  { type: 'persistent', fields: ['agent_id'], unique: true },
  { type: 'persistent', fields: ['agent_status'] },
  { type: 'persistent', fields: ['tenant_id', 'agent_status'] },
  { type: 'persistent', fields: ['tenant_id', 'is_connected'] },
  { type: 'persistent', fields: ['last_heartbeat'] },
  { type: 'persistent', fields: ['tenant_id', 'last_heartbeat'] },
  { type: 'persistent', fields: ['host_type'] },
  { type: 'persistent', fields: ['asset_id'], sparse: true },
  { type: 'persistent', fields: ['policy_id'], sparse: true },
  { type: 'persistent', fields: ['gateway_id'], sparse: true }
].forEach((spec) => ensureIndex('devices', spec));

const now = nowIso();

if (db._collection('agents')) {
  db._query(`
    FOR a IN agents
      LET clean = UNSET(a, '_id', '_rev')
      LET deviceKey = CONCAT('device-', a.agent_id)
      LET doc = MERGE(clean, {
        _key: deviceKey,
        device_id: HAS(a, 'device_id') && a.device_id != null && a.device_id != '' ? a.device_id : deviceKey,
        tenant_id: HAS(a, 'tenant_id') ? a.tenant_id : 'tenant-default',
        hostname: HAS(a, 'hostname') ? a.hostname : a.agent_id,
        host_type: HAS(a, 'host_type') ? a.host_type : 'pc',
        ip: HAS(a, 'ip') ? a.ip : '',
        ip_addresses: HAS(a, 'ip_addresses') ? a.ip_addresses : [],
        mac_addresses: HAS(a, 'mac_addresses') ? a.mac_addresses : [],
        os_type: HAS(a, 'os_type') ? a.os_type : 'windows',
        os_version: HAS(a, 'os_version') ? a.os_version : '',
        os: HAS(a, 'os') ? a.os : 'windows',
        agent_version: HAS(a, 'agent_version') ? a.agent_version : 'unknown',
        agent_status: HAS(a, 'agent_status') ? a.agent_status : 'offline',
        status: HAS(a, 'agent_status') ? a.agent_status : 'offline',
        is_connected: HAS(a, 'is_connected') ? a.is_connected : false,
        protocol: HAS(a, 'protocol') ? a.protocol : 'wzcp',
        protocol_version: HAS(a, 'protocol_version') ? a.protocol_version : 1,
        installed_at: HAS(a, 'installed_at') ? a.installed_at : @now,
        enrolled_at: HAS(a, 'enrolled_at') ? a.enrolled_at : (HAS(a, 'installed_at') ? a.installed_at : @now),
        last_heartbeat: HAS(a, 'last_heartbeat') ? a.last_heartbeat : @now,
        last_seen: HAS(a, 'last_seen') ? a.last_seen : @now,
        created_at: HAS(a, 'created_at') ? a.created_at : @now,
        updated_at: @now
      })
      UPSERT { agent_id: doc.agent_id }
      INSERT doc
      UPDATE MERGE(OLD, UNSET(doc, '_key'))
      IN devices
  `, { now });
}

db._query(`
  FOR d IN devices
    LET deviceKey = HAS(d, 'device_id') && d.device_id != null && d.device_id != '' ? d.device_id : d._key
    UPDATE d WITH {
      device_id: deviceKey,
      tenant_id: HAS(d, 'tenant_id') ? d.tenant_id : 'tenant-default',
      agent_id: HAS(d, 'agent_id') ? d.agent_id : d._key,
      agent_status: HAS(d, 'agent_status') ? d.agent_status : 'offline',
      status: HAS(d, 'status') ? d.status : (HAS(d, 'agent_status') ? d.agent_status : 'offline'),
      is_connected: HAS(d, 'is_connected') ? d.is_connected : false,
      hostname: HAS(d, 'hostname') ? d.hostname : d._key,
      host_type: HAS(d, 'host_type') ? d.host_type : 'pc',
      ip: HAS(d, 'ip') ? d.ip : '',
      ip_addresses: HAS(d, 'ip_addresses') ? d.ip_addresses : [],
      mac_addresses: HAS(d, 'mac_addresses') ? d.mac_addresses : [],
      os_type: HAS(d, 'os_type') ? d.os_type : 'windows',
      os_version: HAS(d, 'os_version') ? d.os_version : '',
      os: HAS(d, 'os') ? d.os : (HAS(d, 'os_type') ? d.os_type : 'windows'),
      agent_version: HAS(d, 'agent_version') ? d.agent_version : 'unknown',
      gateway_id: HAS(d, 'gateway_id') ? d.gateway_id : '',
      protocol: HAS(d, 'protocol') ? d.protocol : 'wzcp',
      protocol_version: HAS(d, 'protocol_version') ? d.protocol_version : 1,
      enrolled_at: HAS(d, 'enrolled_at') ? d.enrolled_at : @now,
      installed_at: HAS(d, 'installed_at') ? d.installed_at : (HAS(d, 'enrolled_at') ? d.enrolled_at : @now),
      last_heartbeat: HAS(d, 'last_heartbeat') ? d.last_heartbeat : @now,
      last_seen: HAS(d, 'last_seen') ? d.last_seen : @now,
      created_at: HAS(d, 'created_at') ? d.created_at : @now,
      updated_at: @now
    } IN devices
`, { now });

ensureSchema('devices', {
  level: 'strict',
  message: 'devices documents must match the XSIAM device runtime schema',
  rule: {
    type: 'object',
    required: [
      'tenant_id', 'device_id', 'agent_id', 'agent_status', 'is_connected',
      'hostname', 'host_type', 'mac_addresses', 'agent_version', 'protocol',
      'protocol_version', 'enrolled_at', 'installed_at', 'last_heartbeat',
      'last_seen', 'created_at', 'updated_at'
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
      os: { type: 'string' },
      agent_version: { type: 'string' },
      agent_status: { type: 'string', enum: ['online', 'offline', 'installing', 'uninstalling', 'error'] },
      status: { type: 'string' },
      is_connected: { type: 'boolean' },
      protocol: { type: 'string', enum: ['wzcp'] },
      protocol_version: { type: 'number' },
      enrolled_at: { type: 'string', format: 'date-time' },
      installed_at: { type: 'string', format: 'date-time' },
      last_heartbeat: { type: 'string', format: 'date-time' },
      last_seen: { type: 'string', format: 'date-time' },
      created_at: { type: 'string', format: 'date-time' },
      updated_at: { type: 'string', format: 'date-time' }
    },
    additionalProperties: false
  }
});

if (db._collection('agents')) {
  db._drop('agents');
}

print(JSON.stringify({
  ok: true,
  devices: devices.count(),
  agents_exists: !!db._collection('agents')
}, null, 2));
