import { useState, useEffect } from 'react'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, Cell, ResponsiveContainer, Legend,
  AreaChart, Area,
} from 'recharts'
import api from '@/lib/api'
import PageHeader from '@/components/PageHeader'

// ─── Types ────────────────────────────────────────────────────────────────────

interface Tenant {
  _key: string
  name: string
  display_name: string
  type: 'enterprise' | 'trial' | 'mssp'
  status: 'active' | 'suspended' | 'expired'
  user_count: number
  device_count: number
  storage_gb: number
  max_storage_gb: number
  expires_at: string
  created_at: string
  admin_email: string
}

interface CreateTenantForm {
  name: string
  display_name: string
  type: 'enterprise' | 'trial' | 'mssp'
  admin_email: string
  max_users: number
  storage_quota_gb: number
  expires_at: string
}

interface MockUser {
  username: string
  email: string
  role: string
  last_login: string
}

interface MockAuditEvent {
  ts: string
  action: string
  operator: string
  resource: string
}

// ─── Mock Data ────────────────────────────────────────────────────────────────

const MOCK_TENANTS: Tenant[] = [
  { _key: 't001', name: 'tencent-security', display_name: '腾讯安全', type: 'enterprise', status: 'active',   user_count: 45, device_count: 1284, storage_gb: 234, max_storage_gb: 500,  expires_at: '2027-01-01', created_at: '2024-03-15', admin_email: 'admin@tencent-sec.com' },
  { _key: 't002', name: 'alibaba-security', display_name: '阿里云安全',   type: 'enterprise', status: 'active',   user_count: 32, device_count: 876,  storage_gb: 178, max_storage_gb: 300,  expires_at: '2026-12-31', created_at: '2024-04-01', admin_email: 'admin@alibabacloud.com' },
  { _key: 't003', name: 'huawei-mssp',      display_name: '华为云MSSP', type: 'mssp',       status: 'active',   user_count: 18, device_count: 2100, storage_gb: 890, max_storage_gb: 2000, expires_at: '2027-06-30', created_at: '2023-11-20', admin_email: 'ops@huawei-mssp.com' },
  { _key: 't004', name: 'bytedance',        display_name: '字节跳动',   type: 'enterprise', status: 'active',   user_count: 28, device_count: 567,  storage_gb: 123, max_storage_gb: 300,  expires_at: '2026-09-15', created_at: '2024-06-10', admin_email: 'sec@bytedance.com' },
  { _key: 't005', name: 'meituan',          display_name: '美团安全',   type: 'enterprise', status: 'active',   user_count: 12, device_count: 234,  storage_gb: 45,  max_storage_gb: 100,  expires_at: '2027-03-20', created_at: '2024-08-05', admin_email: 'admin@meituan.com' },
  { _key: 't006', name: 'didi',             display_name: '滴滴出行',   type: 'trial',      status: 'active',   user_count: 3,  device_count: 12,   storage_gb: 2,   max_storage_gb: 10,   expires_at: '2026-06-01', created_at: '2026-04-20', admin_email: 'it@didiglobal.com' },
  { _key: 't007', name: 'kuaishou',         display_name: '快手安全',   type: 'enterprise', status: 'suspended',user_count: 8,  device_count: 89,   storage_gb: 34,  max_storage_gb: 100,  expires_at: '2026-11-30', created_at: '2024-09-01', admin_email: 'sec@kuaishou.com' },
  { _key: 't008', name: 'test-tenant',      display_name: '测试租户',   type: 'trial',      status: 'expired',  user_count: 1,  device_count: 0,    storage_gb: 0,   max_storage_gb: 5,    expires_at: '2026-03-01', created_at: '2026-01-15', admin_email: 'test@internal.com' },
]

const MOCK_USERS_BY_TENANT: Record<string, MockUser[]> = {
  t001: [
    { username: 'zhang_wei',  email: 'zw@tencent-sec.com', role: '管理员',   last_login: '2026-05-24 10:22' },
    { username: 'li_fang',    email: 'lf@tencent-sec.com', role: '分析师',   last_login: '2026-05-24 09:45' },
    { username: 'wang_lei',   email: 'wl@tencent-sec.com', role: '分析师',   last_login: '2026-05-23 16:30' },
    { username: 'chen_xia',   email: 'cx@tencent-sec.com', role: '只读',     last_login: '2026-05-22 14:10' },
    { username: 'liu_yang',   email: 'ly@tencent-sec.com', role: '响应员',   last_login: '2026-05-24 08:55' },
  ],
  default: [
    { username: 'admin',  email: 'admin@tenant.com',   role: '管理员', last_login: '2026-05-24 09:00' },
    { username: 'user01', email: 'user01@tenant.com',  role: '分析师', last_login: '2026-05-23 15:00' },
    { username: 'user02', email: 'user02@tenant.com',  role: '只读',   last_login: '2026-05-22 11:30' },
  ],
}

const MOCK_AUDIT_EVENTS: MockAuditEvent[] = [
  { ts: '2026-05-24 14:30', action: '数据备份',     operator: 'system',    resource: '全量备份' },
  { ts: '2026-05-24 11:15', action: '用户登录',     operator: 'zhang_wei', resource: '登录成功' },
  { ts: '2026-05-24 09:40', action: '策略更新',     operator: 'li_fang',   resource: '检测规则 #DR-0042' },
  { ts: '2026-05-23 18:00', action: '告警确认',     operator: 'wang_lei',  resource: 'ALT-00081ABF' },
  { ts: '2026-05-23 14:25', action: '用户创建',     operator: 'admin',     resource: 'user: liu_yang' },
]

const SYSTEM_EVENTS = [
  { ts: '2026-05-24 14:30', level: 'INFO', msg: '租户"腾讯安全"完成数据备份' },
  { ts: '2026-05-24 13:15', level: 'WARN', msg: '租户"华为云MSSP"存储使用率超过85%' },
  { ts: '2026-05-24 12:00', level: 'INFO', msg: '定时任务"告警统计"执行成功' },
  { ts: '2026-05-24 10:30', level: 'INFO', msg: '新租户"滴滴出行"创建成功' },
  { ts: '2026-05-23 23:00', level: 'INFO', msg: '系统夜间备份完成' },
]

// Generate mock 24h QPS trend
function gen24hQPS(): { hour: string; qps: number }[] {
  return Array.from({ length: 24 }, (_, i) => ({
    hour: `${String(i).padStart(2, '0')}:00`,
    qps: 200 + Math.round(Math.sin(i / 3) * 400 + Math.random() * 300 + (i > 8 && i < 20 ? 600 : 0)),
  }))
}
function gen24hMem(): { hour: string; mem: number }[] {
  return Array.from({ length: 24 }, (_, i) => ({
    hour: `${String(i).padStart(2, '0')}:00`,
    mem: 40 + Math.round(Math.sin(i / 6) * 12 + Math.random() * 8 + (i > 9 && i < 18 ? 15 : 0)),
  }))
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fmtDate(iso: string) {
  if (!iso) return '—'
  return iso.slice(0, 10)
}

function storagePct(used: number, max: number): number {
  if (max === 0) return 0
  return Math.round((used / max) * 100)
}

// ─── Badges ───────────────────────────────────────────────────────────────────

function TypeBadge({ type }: { type: Tenant['type'] }) {
  const cfg = {
    enterprise: { label: '企业版', bg: 'rgba(59,158,222,.16)', color: '#3b9ede' },
    trial:      { label: '试用版', bg: 'rgba(208,112,48,.18)',  color: '#dd7a30' },
    mssp:       { label: 'MSSP',   bg: 'rgba(140,100,220,.16)', color: '#a07ad8' },
  }[type]
  return (
    <span style={{
      display: 'inline-block', padding: '2px 8px', borderRadius: 3,
      background: cfg.bg, color: cfg.color,
      fontSize: 10.5, fontWeight: 700, letterSpacing: 0.3,
    }}>{cfg.label}</span>
  )
}

function StatusBadge({ status }: { status: Tenant['status'] }) {
  const cfg = {
    active:    { label: '活跃',   bg: 'rgba(47,176,122,.16)',  color: '#2fb07a' },
    suspended: { label: '已暂停', bg: 'rgba(208,160,32,.16)',  color: '#d0a020' },
    expired:   { label: '已过期', bg: 'rgba(217,64,64,.16)',   color: '#d94040' },
  }[status]
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 5,
      padding: '2px 8px', borderRadius: 3,
      background: cfg.bg, color: cfg.color,
      fontSize: 10.5, fontWeight: 600,
    }}>
      <span style={{
        width: 5, height: 5, borderRadius: '50%', background: cfg.color, flexShrink: 0,
        boxShadow: status === 'active' ? `0 0 4px ${cfg.color}` : undefined,
      }} />
      {cfg.label}
    </span>
  )
}

// ─── Storage Bar ──────────────────────────────────────────────────────────────

function StorageBar({ used, max }: { used: number; max: number }) {
  const pct = storagePct(used, max)
  const isHot = pct >= 80
  const barColor = isHot ? '#d94040' : pct >= 60 ? '#d0a020' : '#3b9ede'
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
      <div style={{ width: 60, height: 5, background: 'var(--border-light)', borderRadius: 3, overflow: 'hidden' }}>
        <div style={{ height: '100%', width: `${Math.min(pct, 100)}%`, background: barColor, borderRadius: 3, transition: 'width .3s' }} />
      </div>
      <span style={{ fontSize: 10.5, color: isHot ? '#d94040' : 'var(--text-muted)', whiteSpace: 'nowrap' }}>
        {used}/{max} GB
      </span>
    </div>
  )
}

// ─── Create Tenant Modal ──────────────────────────────────────────────────────

interface CreateModalProps {
  onClose: () => void
  onCreated: (t: Tenant) => void
}

function CreateTenantModal({ onClose, onCreated }: CreateModalProps) {
  const EMPTY: CreateTenantForm = {
    name: '', display_name: '', type: 'enterprise',
    admin_email: '', max_users: 50, storage_quota_gb: 100, expires_at: '',
  }
  const [form, setForm] = useState<CreateTenantForm>(EMPTY)
  const [saving, setSaving] = useState(false)
  const [err, setErr] = useState('')

  function set<K extends keyof CreateTenantForm>(k: K, v: CreateTenantForm[K]) {
    setForm(prev => ({ ...prev, [k]: v }))
  }

  function submit() {
    if (!form.name.trim() || !form.display_name.trim() || !form.admin_email.trim()) {
      setErr('租户名称、显示名称和管理员邮箱为必填项')
      return
    }
    setSaving(true)
    api.post('/tenants', {
      name: form.name.trim(),
      display_name: form.display_name.trim(),
      type: form.type,
      admin_email: form.admin_email.trim(),
      max_users: form.max_users,
      storage_quota_gb: form.storage_quota_gb,
      expires_at: form.expires_at || undefined,
    })
      .then(r => {
        const t: Tenant = r.data?.data ?? {
          _key: `t${Date.now()}`,
          name: form.name.trim(),
          display_name: form.display_name.trim(),
          type: form.type,
          status: 'active',
          user_count: 0, device_count: 0,
          storage_gb: 0, max_storage_gb: form.storage_quota_gb,
          expires_at: form.expires_at || '2027-01-01',
          created_at: new Date().toISOString().slice(0, 10),
          admin_email: form.admin_email.trim(),
        }
        onCreated(t)
      })
      .catch(() => {
        // Optimistic mock create
        const t: Tenant = {
          _key: `t${Date.now()}`,
          name: form.name.trim(),
          display_name: form.display_name.trim(),
          type: form.type,
          status: 'active',
          user_count: 0, device_count: 0,
          storage_gb: 0, max_storage_gb: form.storage_quota_gb,
          expires_at: form.expires_at || '2027-01-01',
          created_at: new Date().toISOString().slice(0, 10),
          admin_email: form.admin_email.trim(),
        }
        onCreated(t)
      })
      .finally(() => setSaving(false))
  }

  const inputStyle: React.CSSProperties = {
    background: 'var(--bg-card)', border: '1px solid var(--border-light)',
    color: 'var(--text-primary)', padding: '6px 10px',
    borderRadius: 4, fontSize: 12.5, outline: 'none', width: '100%',
  }
  const labelStyle: React.CSSProperties = {
    fontSize: 11, color: 'var(--text-muted)', marginBottom: 4, display: 'block',
  }

  return (
    <div
      style={{ position: 'fixed', inset: 0, zIndex: 9999, background: 'rgba(0,0,0,.55)', display: 'flex', alignItems: 'center', justifyContent: 'center' }}
      onClick={onClose}
    >
      <div
        style={{ width: 480, background: 'var(--bg-card)', border: '1px solid var(--border-light)', borderRadius: 8, boxShadow: '0 24px 64px rgba(0,0,0,.55)', display: 'flex', flexDirection: 'column' }}
        onClick={e => e.stopPropagation()}
      >
        {/* Header */}
        <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <span style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>新建租户</span>
          <button onClick={onClose} style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 16 }}>✕</button>
        </div>

        {/* Body */}
        <div style={{ padding: '20px', display: 'flex', flexDirection: 'column', gap: 14 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
            <div>
              <label style={labelStyle}>租户名称 *</label>
              <input style={inputStyle} placeholder="如 my-corp" value={form.name} onChange={e => set('name', e.target.value)} />
            </div>
            <div>
              <label style={labelStyle}>显示名称 *</label>
              <input style={inputStyle} placeholder="如 我的公司" value={form.display_name} onChange={e => set('display_name', e.target.value)} />
            </div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
            <div>
              <label style={labelStyle}>类型</label>
              <select
                style={{ ...inputStyle, cursor: 'pointer' }}
                value={form.type}
                onChange={e => set('type', e.target.value as CreateTenantForm['type'])}
              >
                <option value="enterprise">企业版</option>
                <option value="trial">试用版</option>
                <option value="mssp">MSSP</option>
              </select>
            </div>
            <div>
              <label style={labelStyle}>管理员邮箱 *</label>
              <input style={inputStyle} type="email" placeholder="admin@corp.com" value={form.admin_email} onChange={e => set('admin_email', e.target.value)} />
            </div>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
            <div>
              <label style={labelStyle}>最大用户数</label>
              <input style={inputStyle} type="number" min={1} value={form.max_users} onChange={e => set('max_users', parseInt(e.target.value) || 50)} />
            </div>
            <div>
              <label style={labelStyle}>存储配额 (GB)</label>
              <input style={inputStyle} type="number" min={1} value={form.storage_quota_gb} onChange={e => set('storage_quota_gb', parseInt(e.target.value) || 100)} />
            </div>
          </div>
          <div>
            <label style={labelStyle}>到期日</label>
            <input style={inputStyle} type="date" value={form.expires_at} onChange={e => set('expires_at', e.target.value)} />
          </div>
          {err && <div style={{ fontSize: 11.5, color: '#d94040', background: 'rgba(217,64,64,.08)', padding: '8px 12px', borderRadius: 4, border: '1px solid rgba(217,64,64,.2)' }}>{err}</div>}
        </div>

        {/* Footer */}
        <div style={{ padding: '12px 20px', borderTop: '1px solid var(--border)', display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
          <button className="btn-secondary" onClick={onClose}>取消</button>
          <button className="btn-primary" disabled={saving} onClick={submit}>{saving ? '创建中...' : '创建租户'}</button>
        </div>
      </div>
    </div>
  )
}

// ─── Tenant Detail Side Panel ─────────────────────────────────────────────────

interface DetailPanelProps {
  tenant: Tenant | null
  onClose: () => void
}

function TenantDetailPanel({ tenant, onClose }: DetailPanelProps) {
  const [tab, setTab] = useState<'overview' | 'users' | 'audit'>('overview')

  useEffect(() => { setTab('overview') }, [tenant?._key])

  if (!tenant) return null

  const users = MOCK_USERS_BY_TENANT[tenant._key] ?? MOCK_USERS_BY_TENANT['default']
  const pct = storagePct(tenant.storage_gb, tenant.max_storage_gb)
  const isHot = pct >= 80

  return (
    <div style={{ width: 380, flexShrink: 0, background: 'var(--bg-card)', borderLeft: '1px solid var(--border)', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      {/* Header */}
      <div style={{ padding: '14px 16px', borderBottom: '1px solid var(--border)', background: 'var(--bg-secondary)', flexShrink: 0 }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 8 }}>
          <div>
            <div style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 4 }}>{tenant.display_name}</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'monospace' }}>{tenant.name}</div>
          </div>
          <button onClick={onClose} style={{ background: 'none', border: '1px solid var(--border-light)', borderRadius: 4, color: 'var(--text-muted)', cursor: 'pointer', fontSize: 13, width: 26, height: 26, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>✕</button>
        </div>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          <TypeBadge type={tenant.type} />
          <StatusBadge status={tenant.status} />
        </div>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', background: 'var(--bg-secondary)', flexShrink: 0 }}>
        {([['overview', '概览'], ['users', '用户'], ['audit', '审计日志']] as const).map(([id, label]) => (
          <button key={id} className={`tab${tab === id ? ' active' : ''}`} style={{ padding: '8px 14px', fontSize: 11.5 }} onClick={() => setTab(id)}>
            {label}
          </button>
        ))}
      </div>

      {/* Content */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '16px' }}>
        {tab === 'overview' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            {/* Info rows */}
            {[
              { label: '管理员邮箱', value: tenant.admin_email },
              { label: '创建日期',   value: fmtDate(tenant.created_at) },
              { label: '到期日',     value: fmtDate(tenant.expires_at) },
            ].map(row => (
              <div key={row.label} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', paddingBottom: 10, borderBottom: '1px solid rgba(255,255,255,.04)', gap: 12 }}>
                <span style={{ fontSize: 11.5, color: 'var(--text-muted)', flexShrink: 0 }}>{row.label}</span>
                <span style={{ fontSize: 11.5, color: 'var(--text-secondary)', textAlign: 'right', wordBreak: 'break-all' }}>{row.value}</span>
              </div>
            ))}

            {/* KPI mini grid */}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              {[
                { label: '用户数',   value: tenant.user_count,   color: 'var(--accent-blue)' },
                { label: '设备数',   value: tenant.device_count, color: '#a07ad8' },
              ].map(k => (
                <div key={k.label} style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 5, padding: '10px 12px' }}>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: .4, marginBottom: 4 }}>{k.label}</div>
                  <div style={{ fontSize: 22, fontWeight: 700, color: k.color }}>{k.value.toLocaleString()}</div>
                </div>
              ))}
            </div>

            {/* Storage */}
            <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 5, padding: '12px' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'baseline', marginBottom: 8 }}>
                <span style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: .4 }}>存储用量</span>
                <span style={{ fontSize: 11, color: isHot ? '#d94040' : 'var(--text-muted)' }}>{pct}%</span>
              </div>
              <div style={{ height: 6, background: 'var(--border-light)', borderRadius: 3, overflow: 'hidden', marginBottom: 6 }}>
                <div style={{ height: '100%', width: `${Math.min(pct, 100)}%`, background: isHot ? '#d94040' : pct >= 60 ? '#d0a020' : '#3b9ede', borderRadius: 3, transition: 'width .4s' }} />
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{tenant.storage_gb} GB / {tenant.max_storage_gb} GB</div>
            </div>
          </div>
        )}

        {tab === 'users' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {users.map((u, i) => (
              <div key={i} style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 5, padding: '10px 12px', display: 'flex', alignItems: 'center', gap: 10 }}>
                <div style={{ width: 32, height: 32, borderRadius: '50%', background: 'rgba(59,158,222,.18)', display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                  <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--accent-blue)' }}>{u.username[0].toUpperCase()}</span>
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 2 }}>{u.username}</div>
                  <div style={{ fontSize: 10.5, color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{u.email}</div>
                </div>
                <div style={{ textAlign: 'right', flexShrink: 0 }}>
                  <div style={{ fontSize: 10.5, padding: '1px 7px', borderRadius: 3, background: 'rgba(59,158,222,.12)', color: 'var(--accent-blue)', marginBottom: 3, display: 'inline-block' }}>{u.role}</div>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>{u.last_login.slice(5)}</div>
                </div>
              </div>
            ))}
          </div>
        )}

        {tab === 'audit' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {MOCK_AUDIT_EVENTS.map((ev, i) => (
              <div key={i} style={{ padding: '8px 10px', background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderLeft: '3px solid rgba(59,158,222,.4)', borderRadius: 4 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                  <span style={{ fontSize: 10.5, fontWeight: 600, color: 'var(--accent-blue)' }}>{ev.action}</span>
                  <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>{ev.ts.slice(5)}</span>
                </div>
                <div style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>
                  <span style={{ color: 'var(--text-secondary)' }}>{ev.operator}</span> — {ev.resource}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Tab 1: Tenant List ───────────────────────────────────────────────────────

interface TenantListTabProps {
  tenants: Tenant[]
  setTenants: React.Dispatch<React.SetStateAction<Tenant[]>>
}

function TenantListTab({ tenants, setTenants }: TenantListTabProps) {
  const [search, setSearch] = useState('')
  const [filterType, setFilterType] = useState('')
  const [filterStatus, setFilterStatus] = useState('')
  const [selectedKey, setSelectedKey] = useState<string | null>(null)
  const [showCreate, setShowCreate] = useState(false)

  const selectedTenant = tenants.find(t => t._key === selectedKey) ?? null

  const filtered = tenants.filter(t => {
    const q = search.toLowerCase()
    const matchQ = !q || t.display_name.toLowerCase().includes(q) || t.name.toLowerCase().includes(q) || t.admin_email.toLowerCase().includes(q)
    const matchType = !filterType || t.type === filterType
    const matchStatus = !filterStatus || t.status === filterStatus
    return matchQ && matchType && matchStatus
  })

  const total = tenants.length
  const active = tenants.filter(t => t.status === 'active').length
  const trial = tenants.filter(t => t.type === 'trial').length
  const newThisMonth = tenants.filter(t => t.created_at >= '2026-05-01').length

  function toggleSuspend(t: Tenant) {
    const newStatus: Tenant['status'] = t.status === 'suspended' ? 'active' : 'suspended'
    api.patch(`/tenants/${t._key}`, { status: newStatus }).catch(() => {})
    setTenants(prev => prev.map(x => x._key === t._key ? { ...x, status: newStatus } : x))
  }

  return (
    <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', minWidth: 0 }}>
        {/* KPI Strip */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 1, background: 'var(--border)', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
          {[
            { label: '总租户数',  value: total,         color: 'var(--text-primary)', note: '全部租户' },
            { label: '活跃租户',  value: active,        color: '#2fb07a',             note: `占比 ${Math.round(active/total*100)}%` },
            { label: '试用租户',  value: trial,         color: '#dd7a30',             note: '有效期内' },
            { label: '本月新增',  value: newThisMonth,  color: 'var(--accent-blue)',  note: '本月创建' },
          ].map(k => (
            <div key={k.label} style={{ background: 'var(--bg-sidebar)', padding: '10px 18px' }}>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: .4, marginBottom: 4 }}>{k.label}</div>
              <div style={{ fontSize: 26, fontWeight: 700, color: k.color, lineHeight: 1, marginBottom: 3 }}>{k.value}</div>
              <div style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>{k.note}</div>
            </div>
          ))}
        </div>

        {/* Filter bar */}
        <div className="filter-bar">
          <input
            className="filter-input"
            placeholder="搜索租户名称 / 邮箱..."
            value={search}
            onChange={e => setSearch(e.target.value)}
            style={{ minWidth: 220 }}
          />
          <select className="filter-select" value={filterType} onChange={e => setFilterType(e.target.value)}>
            <option value="">所有类型</option>
            <option value="enterprise">企业版</option>
            <option value="trial">试用版</option>
            <option value="mssp">MSSP</option>
          </select>
          <select className="filter-select" value={filterStatus} onChange={e => setFilterStatus(e.target.value)}>
            <option value="">所有状态</option>
            <option value="active">活跃</option>
            <option value="suspended">已暂停</option>
            <option value="expired">已过期</option>
          </select>
          <span style={{ fontSize: 11, color: 'var(--text-muted)', marginLeft: 'auto' }}>{filtered.length} 个租户</span>
          <button className="btn-primary" onClick={() => setShowCreate(true)}>+ 新建租户</button>
        </div>

        {/* Table */}
        <div className="data-table-wrap">
          <table className="data-table">
            <thead>
              <tr>
                <th>租户名称</th>
                <th>租户ID</th>
                <th>类型</th>
                <th>状态</th>
                <th style={{ textAlign: 'right' }}>用户数</th>
                <th style={{ textAlign: 'right' }}>设备数</th>
                <th>存储用量</th>
                <th>到期日</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {filtered.map(t => (
                <tr
                  key={t._key}
                  className={selectedKey === t._key ? 'selected' : ''}
                  onClick={() => setSelectedKey(prev => prev === t._key ? null : t._key)}
                >
                  <td>
                    <div style={{ fontWeight: 600, color: 'var(--text-primary)', marginBottom: 1 }}>{t.display_name}</div>
                    <div style={{ fontSize: 10.5, color: 'var(--text-muted)', fontFamily: 'monospace' }}>{t.admin_email}</div>
                  </td>
                  <td>
                    <span style={{ fontSize: 10.5, fontFamily: 'monospace', color: 'var(--text-muted)' }}>{t.name}</span>
                  </td>
                  <td><TypeBadge type={t.type} /></td>
                  <td><StatusBadge status={t.status} /></td>
                  <td style={{ textAlign: 'right', fontWeight: 600, color: 'var(--text-primary)' }}>{t.user_count}</td>
                  <td style={{ textAlign: 'right', color: 'var(--text-secondary)' }}>{t.device_count.toLocaleString()}</td>
                  <td><StorageBar used={t.storage_gb} max={t.max_storage_gb} /></td>
                  <td style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>{fmtDate(t.expires_at)}</td>
                  <td onClick={e => e.stopPropagation()}>
                    <div style={{ display: 'flex', gap: 4 }}>
                      <button
                        className="btn-secondary"
                        style={{ fontSize: 10, padding: '2px 8px' }}
                        onClick={() => setSelectedKey(prev => prev === t._key ? null : t._key)}
                      >详情</button>
                      <button
                        className="btn-secondary"
                        style={{ fontSize: 10, padding: '2px 8px' }}
                        onClick={() => {}}
                      >编辑</button>
                      <button
                        className="btn-secondary"
                        style={{
                          fontSize: 10, padding: '2px 8px',
                          color: t.status === 'suspended' ? '#2fb07a' : '#d0a020',
                          borderColor: t.status === 'suspended' ? 'rgba(47,176,122,.3)' : 'rgba(208,160,32,.3)',
                        }}
                        onClick={() => toggleSuspend(t)}
                      >
                        {t.status === 'suspended' ? '恢复' : '暂停'}
                      </button>
                      <button
                        className="btn-secondary"
                        style={{ fontSize: 10, padding: '2px 8px', color: 'var(--accent-blue)', borderColor: 'rgba(59,158,222,.3)' }}
                        onClick={() => {}}
                      >切换</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Detail Side Panel */}
      {selectedTenant && (
        <TenantDetailPanel tenant={selectedTenant} onClose={() => setSelectedKey(null)} />
      )}

      {/* Create Modal */}
      {showCreate && (
        <CreateTenantModal
          onClose={() => setShowCreate(false)}
          onCreated={t => { setTenants(prev => [...prev, t]); setShowCreate(false) }}
        />
      )}
    </div>
  )
}

// ─── Tab 2: Usage Monitoring ──────────────────────────────────────────────────

function UsageMonitoringTab({ tenants }: { tenants: Tenant[] }) {
  const sorted = [...tenants].sort((a, b) => b.user_count - a.user_count)
  const top8 = sorted.slice(0, 8)

  const userChartData = top8.map(t => ({ name: t.display_name.slice(0, 4), users: t.user_count }))
  const deviceChartData = top8.map(t => ({ name: t.display_name.slice(0, 4), devices: t.device_count }))
  const storageData = top8.map(t => ({
    name: t.display_name.slice(0, 4),
    used: t.storage_gb,
    remaining: Math.max(0, t.max_storage_gb - t.storage_gb),
  }))
  const alertData = top8.map(t => ({
    name: t.display_name.slice(0, 4),
    alerts: Math.round(t.device_count * 0.15 + t.user_count * 2.3 + Math.random() * 50),
  }))

  const totalUsers = tenants.reduce((s, t) => s + t.user_count, 0)
  const totalDevices = tenants.reduce((s, t) => s + t.device_count, 0)
  const totalStorage = tenants.reduce((s, t) => s + t.storage_gb, 0)
  const totalAlerts = alertData.reduce((s, d) => s + d.alerts, 0)

  const quotaWarnings = tenants.filter(t => storagePct(t.storage_gb, t.max_storage_gb) >= 80)

  const chartStyle: React.CSSProperties = {
    background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 6, padding: '14px 16px',
  }
  const chartTitle: React.CSSProperties = {
    fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: .4, marginBottom: 12,
  }

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Platform Totals */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10 }}>
        {[
          { label: '总用户',      value: totalUsers,             unit: '人',  color: 'var(--accent-blue)' },
          { label: '总设备',      value: totalDevices,           unit: '台',  color: '#a07ad8' },
          { label: '总存储',      value: `${totalStorage} GB`,   unit: '',    color: '#2fb07a' },
          { label: '总告警(本月)', value: totalAlerts,            unit: '条',  color: '#dd7a30' },
        ].map(k => (
          <div key={k.label} style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 6, padding: '12px 14px' }}>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: .4, marginBottom: 6 }}>{k.label}</div>
            <div style={{ fontSize: 22, fontWeight: 700, color: k.color, lineHeight: 1 }}>
              {typeof k.value === 'number' ? k.value.toLocaleString() : k.value}
              {k.unit && <span style={{ fontSize: 12, marginLeft: 3, fontWeight: 400 }}>{k.unit}</span>}
            </div>
          </div>
        ))}
      </div>

      {/* Quota Warnings */}
      {quotaWarnings.length > 0 && (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: .4 }}>配额预警</div>
          {quotaWarnings.map(t => (
            <div key={t._key} style={{ padding: '10px 14px', background: 'rgba(208,160,32,.06)', border: '1px solid rgba(208,160,32,.25)', borderLeft: '3px solid #d0a020', borderRadius: 4, display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: 14 }}>⚠️</span>
              <span style={{ fontSize: 12, color: '#d0a020', fontWeight: 600 }}>{t.display_name}</span>
              <span style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>
                存储已使用 {storagePct(t.storage_gb, t.max_storage_gb)}%，建议扩容（当前 {t.storage_gb} GB / {t.max_storage_gb} GB）
              </span>
            </div>
          ))}
        </div>
      )}

      {/* 2x2 Chart Grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        {/* User count by tenant */}
        <div style={chartStyle}>
          <div style={chartTitle}>用户数 by 租户</div>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={userChartData} layout="vertical" margin={{ left: 0, right: 16, top: 0, bottom: 0 }}>
              <XAxis type="number" tick={{ fontSize: 10, fill: 'var(--text-muted)' }} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="name" width={36} tick={{ fontSize: 10, fill: 'var(--text-muted)' }} axisLine={false} tickLine={false} />
              <Tooltip
                contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 4, fontSize: 11 }}
                labelStyle={{ color: 'var(--text-primary)' }}
                itemStyle={{ color: 'var(--accent-blue)' }}
              />
              <Bar dataKey="users" name="用户数" radius={[0, 3, 3, 0]}>
                {userChartData.map((_, i) => <Cell key={i} fill="var(--accent-blue)" fillOpacity={0.7 + i * 0.03} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Device count by tenant */}
        <div style={chartStyle}>
          <div style={chartTitle}>设备数 by 租户</div>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={deviceChartData} layout="vertical" margin={{ left: 0, right: 16, top: 0, bottom: 0 }}>
              <XAxis type="number" tick={{ fontSize: 10, fill: 'var(--text-muted)' }} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="name" width={36} tick={{ fontSize: 10, fill: 'var(--text-muted)' }} axisLine={false} tickLine={false} />
              <Tooltip
                contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 4, fontSize: 11 }}
                labelStyle={{ color: 'var(--text-primary)' }}
                itemStyle={{ color: '#a07ad8' }}
              />
              <Bar dataKey="devices" name="设备数" radius={[0, 3, 3, 0]}>
                {deviceChartData.map((_, i) => <Cell key={i} fill="#a07ad8" fillOpacity={0.7 + i * 0.03} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Storage stacked */}
        <div style={chartStyle}>
          <div style={chartTitle}>存储用量 by 租户</div>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={storageData} layout="vertical" margin={{ left: 0, right: 16, top: 0, bottom: 0 }}>
              <XAxis type="number" tick={{ fontSize: 10, fill: 'var(--text-muted)' }} axisLine={false} tickLine={false} unit=" GB" />
              <YAxis type="category" dataKey="name" width={36} tick={{ fontSize: 10, fill: 'var(--text-muted)' }} axisLine={false} tickLine={false} />
              <Tooltip
                contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 4, fontSize: 11 }}
                labelStyle={{ color: 'var(--text-primary)' }}
              />
              <Legend wrapperStyle={{ fontSize: 10, color: 'var(--text-muted)' }} />
              <Bar dataKey="used"      name="已用"   stackId="s" fill="#3b9ede" radius={[0, 0, 0, 0]} />
              <Bar dataKey="remaining" name="剩余"   stackId="s" fill="rgba(59,158,222,.15)" radius={[0, 3, 3, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Monthly alerts */}
        <div style={chartStyle}>
          <div style={chartTitle}>告警数/月 by 租户</div>
          <ResponsiveContainer width="100%" height={180}>
            <BarChart data={alertData} layout="vertical" margin={{ left: 0, right: 16, top: 0, bottom: 0 }}>
              <XAxis type="number" tick={{ fontSize: 10, fill: 'var(--text-muted)' }} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="name" width={36} tick={{ fontSize: 10, fill: 'var(--text-muted)' }} axisLine={false} tickLine={false} />
              <Tooltip
                contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 4, fontSize: 11 }}
                labelStyle={{ color: 'var(--text-primary)' }}
                itemStyle={{ color: '#dd7a30' }}
              />
              <Bar dataKey="alerts" name="告警数" radius={[0, 3, 3, 0]}>
                {alertData.map((_, i) => <Cell key={i} fill="#dd7a30" fillOpacity={0.65 + i * 0.03} />)}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  )
}

// ─── Tab 3: System Health ─────────────────────────────────────────────────────

function SystemHealthTab() {
  const [healthStatus, setHealthStatus] = useState<'normal' | 'degraded'>('normal')

  useEffect(() => {
    api.get('/health').then(() => setHealthStatus('normal')).catch(() => setHealthStatus('degraded'))
  }, [])

  const qpsData = gen24hQPS()
  const memData = gen24hMem()

  const services = [
    { name: 'ArangoDB',   icon: '🗄️',  status: 'normal' as const, details: '延迟: 2ms | 连接数: 234' },
    { name: 'Redis',      icon: '⚡',  status: 'normal' as const, details: '内存: 4.2 GB / 16 GB' },
    { name: 'etcd',       icon: '🔗',  status: 'normal' as const, details: 'Leader: node-1' },
    { name: 'API Server', icon: '🌐',  status: healthStatus,       details: 'QPS: 1,234 | P99: 45ms' },
    { name: 'ETL Engine', icon: '⚙️',  status: 'normal' as const, details: '队列: 12 | 速率: 8,234/s' },
    { name: 'Scheduler',  icon: '⏰',  status: 'normal' as const, details: '下次任务: 2分钟后' },
  ]

  function svcDotColor(s: 'normal' | 'degraded') {
    return s === 'normal' ? '#2fb07a' : '#d94040'
  }

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Service Status Grid */}
      <div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: .4, marginBottom: 10 }}>服务状态</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8 }}>
          {services.map(svc => (
            <div key={svc.name} style={{ background: 'var(--bg-card)', border: `1px solid ${svc.status === 'normal' ? 'var(--border)' : 'rgba(217,64,64,.3)'}`, borderRadius: 6, padding: '12px 14px', display: 'flex', alignItems: 'flex-start', gap: 10 }}>
              <span style={{ fontSize: 20, flexShrink: 0, marginTop: 1 }}>{svc.icon}</span>
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                  <span style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--text-primary)' }}>{svc.name}</span>
                  <span style={{
                    display: 'inline-flex', alignItems: 'center', gap: 4,
                    fontSize: 10, padding: '1px 6px', borderRadius: 3,
                    background: svc.status === 'normal' ? 'rgba(47,176,122,.12)' : 'rgba(217,64,64,.12)',
                    color: svcDotColor(svc.status), fontWeight: 700,
                  }}>
                    <span style={{ width: 5, height: 5, borderRadius: '50%', background: svcDotColor(svc.status), flexShrink: 0, boxShadow: svc.status === 'normal' ? `0 0 4px ${svcDotColor(svc.status)}` : undefined }} />
                    {svc.status === 'normal' ? '正常' : '异常'}
                  </span>
                </div>
                <div style={{ fontSize: 10.5, color: 'var(--text-muted)', lineHeight: 1.5 }}>{svc.details}</div>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* System Metrics Charts */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 6, padding: '14px 16px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: .4, marginBottom: 12 }}>24h API QPS 趋势</div>
          <ResponsiveContainer width="100%" height={140}>
            <AreaChart data={qpsData} margin={{ left: -20, right: 0, top: 0, bottom: 0 }}>
              <defs>
                <linearGradient id="qpsGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="var(--accent-blue)" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="var(--accent-blue)" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="hour" tick={{ fontSize: 9, fill: 'var(--text-muted)' }} axisLine={false} tickLine={false} interval={3} />
              <YAxis tick={{ fontSize: 9, fill: 'var(--text-muted)' }} axisLine={false} tickLine={false} />
              <Tooltip
                contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 4, fontSize: 11 }}
                labelStyle={{ color: 'var(--text-primary)' }}
                itemStyle={{ color: 'var(--accent-blue)' }}
              />
              <Area type="monotone" dataKey="qps" name="QPS" stroke="var(--accent-blue)" fill="url(#qpsGrad)" strokeWidth={1.5} dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        </div>

        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 6, padding: '14px 16px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: .4, marginBottom: 12 }}>24h 内存占用 (%)</div>
          <ResponsiveContainer width="100%" height={140}>
            <AreaChart data={memData} margin={{ left: -20, right: 0, top: 0, bottom: 0 }}>
              <defs>
                <linearGradient id="memGrad" x1="0" y1="0" x2="0" y2="1">
                  <stop offset="5%"  stopColor="#2fb07a" stopOpacity={0.3} />
                  <stop offset="95%" stopColor="#2fb07a" stopOpacity={0} />
                </linearGradient>
              </defs>
              <XAxis dataKey="hour" tick={{ fontSize: 9, fill: 'var(--text-muted)' }} axisLine={false} tickLine={false} interval={3} />
              <YAxis tick={{ fontSize: 9, fill: 'var(--text-muted)' }} axisLine={false} tickLine={false} domain={[0, 100]} unit="%" />
              <Tooltip
                contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 4, fontSize: 11 }}
                labelStyle={{ color: 'var(--text-primary)' }}
                itemStyle={{ color: '#2fb07a' }}
                formatter={((v: unknown) => [`${Number(v ?? 0)}%`, '内存']) as any}
              />
              <Area type="monotone" dataKey="mem" name="内存" stroke="#2fb07a" fill="url(#memGrad)" strokeWidth={1.5} dot={false} />
            </AreaChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Recent System Events */}
      <div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: .4, marginBottom: 10 }}>近期系统事件</div>
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 6, overflow: 'hidden' }}>
          {SYSTEM_EVENTS.map((ev, i) => (
            <div
              key={i}
              style={{
                display: 'flex', alignItems: 'center', gap: 10,
                padding: '9px 14px',
                borderBottom: i < SYSTEM_EVENTS.length - 1 ? '1px solid var(--border)' : undefined,
                background: i % 2 === 0 ? 'transparent' : 'rgba(255,255,255,.015)',
              }}
            >
              <span style={{
                fontSize: 9.5, padding: '1px 6px', borderRadius: 3, fontWeight: 700, flexShrink: 0,
                background: ev.level === 'WARN' ? 'rgba(208,160,32,.15)' : 'rgba(59,158,222,.12)',
                color: ev.level === 'WARN' ? '#d0a020' : 'var(--accent-blue)',
              }}>{ev.level}</span>
              <span style={{ fontSize: 11, color: 'var(--text-muted)', flexShrink: 0, fontFamily: 'monospace' }}>{ev.ts}</span>
              <span style={{ fontSize: 12, color: ev.level === 'WARN' ? '#d0a020' : 'var(--text-secondary)', flex: 1 }}>{ev.msg}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function TenantAdmin() {
  const [tab, setTab] = useState<'list' | 'usage' | 'health'>('list')
  const [tenants, setTenants] = useState<Tenant[]>(MOCK_TENANTS)

  useEffect(() => {
    api.get('/tenants', { params: { limit: 100 } })
      .then(r => {
        const items: Tenant[] = r.data?.data?.items ?? r.data?.data ?? []
        if (items.length > 0) setTenants(items)
      })
      .catch(() => { /* use mock data */ })
  }, [])

  const activeCount = tenants.filter(t => t.status === 'active').length

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <PageHeader
        title="多租户管理控制台"
        subtitle={`${tenants.length} 个租户 · ${activeCount} 活跃`}
        actions={
          <span style={{ fontSize: 11, padding: '2px 10px', borderRadius: 12, background: 'rgba(217,64,64,.12)', color: '#d94040', fontWeight: 700, border: '1px solid rgba(217,64,64,.25)' }}>
            SUPERADMIN
          </span>
        }
      />

      {/* Tab Bar */}
      <div className="tab-bar">
        <button className={`tab${tab === 'list' ? ' active' : ''}`} onClick={() => setTab('list')}>
          租户列表
          <span className="tab-count">{tenants.length}</span>
        </button>
        <button className={`tab${tab === 'usage' ? ' active' : ''}`} onClick={() => setTab('usage')}>
          用量监控
        </button>
        <button className={`tab${tab === 'health' ? ' active' : ''}`} onClick={() => setTab('health')}>
          系统健康
        </button>
      </div>

      {/* Tab Content */}
      {tab === 'list' && (
        <TenantListTab tenants={tenants} setTenants={setTenants} />
      )}
      {tab === 'usage' && (
        <UsageMonitoringTab tenants={tenants} />
      )}
      {tab === 'health' && (
        <SystemHealthTab />
      )}
    </div>
  )
}
