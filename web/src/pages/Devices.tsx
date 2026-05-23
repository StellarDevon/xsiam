import { useEffect, useRef, useState } from 'react'
import api from '@/lib/api'
import type { PageMeta } from '@/lib/api'
import PageHeader from '@/components/PageHeader'

interface Device {
  _key: string
  hostname: string
  ip: string
  ip_addresses?: string[]
  os: string
  os_type?: string
  os_version: string
  agent_version: string
  agent_status?: string
  agent_id?: string
  status: string
  policy_id: string
  policy_name?: string
  group?: string
  asset_id?: string
  tenant_id: string
  last_heartbeat?: string
  last_seen: string
  enrolled_at: string
  created_at: string
  updated_at?: string
}

interface Policy {
  _key: string
  name: string
}

function fmtDate(iso: string | null | undefined) {
  if (!iso) return '-'
  return new Date(iso).toLocaleString('zh-CN', {
    month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', hour12: false,
  })
}

function fmtRelative(iso: string | null | undefined) {
  if (!iso) return '-'
  const diff = Date.now() - new Date(iso).getTime()
  if (diff < 60000) return '刚刚'
  if (diff < 3600000) return `${Math.floor(diff / 60000)}分钟前`
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}小时前`
  return `${Math.floor(diff / 86400000)}天前`
}

const OS_ICONS: Record<string, string> = {
  windows: '🪟', linux: '🐧', macos: '🍎', mac: '🍎',
}

function osIcon(os: string) {
  if (!os) return '🖥'
  const o = os.toLowerCase()
  for (const [k, v] of Object.entries(OS_ICONS)) {
    if (o.includes(k)) return v
  }
  return '🖥'
}

function osLabel(os: string, ver: string) {
  if (!os) return '-'
  const base = os.toLowerCase().includes('windows') ? 'Windows'
    : os.toLowerCase().includes('linux') || os.toLowerCase().includes('ubuntu') || os.toLowerCase().includes('centos') ? 'Linux'
    : os.toLowerCase().includes('mac') || os.toLowerCase().includes('darwin') ? 'macOS'
    : os
  return ver ? `${base} · ${ver}` : base
}

// ── Status helpers ───────────────────────────────────────────────────────────

const STATUS_COLORS: Record<string, string> = {
  online: 'var(--accent-green)',
  offline: 'var(--text-muted)',
  isolated: 'var(--critical)',
  installing: 'var(--accent-blue)',
  uninstalling: 'var(--medium)',
  error: 'var(--high)',
  pending: 'var(--high)',
}
const STATUS_LABELS: Record<string, string> = {
  online: '在线', offline: '离线', isolated: '已隔离',
  installing: '安装中', uninstalling: '卸载中', error: '异常', pending: '等待',
}

function getStatus(d: Device) {
  return d.agent_status || d.status || 'offline'
}

// ── Summary Card ─────────────────────────────────────────────────────────────

function SummaryBar({ items, liveness }: { items: Device[], liveness: LivenessMap }) {
  // Liveness-aware status: isolated/error come from DB; online/offline from liveness map
  function effectiveStatus(d: Device): string {
    const dbStatus = getStatus(d)
    // Isolated and error are controlled by DB, not TCP liveness
    if (dbStatus === 'isolated' || dbStatus === 'error' || dbStatus === 'installing' || dbStatus === 'uninstalling') return dbStatus
    const agentID = d.agent_id
    if (!agentID || !(agentID in liveness)) return dbStatus  // fallback to DB
    return liveness[agentID] === true ? 'online' : liveness[agentID] === false ? 'offline' : dbStatus
  }

  const counts = items.reduce((acc, d) => {
    const s = effectiveStatus(d)
    acc[s] = (acc[s] || 0) + 1
    return acc
  }, {} as Record<string, number>)

  const total = items.length
  const online = counts.online || 0
  const offline = counts.offline || 0
  const isolated = counts.isolated || 0
  const errors = (counts.error || 0) + (counts.installing || 0) + (counts.uninstalling || 0) + (counts.pending || 0)
  const coverage = total > 0 ? Math.round((online / total) * 100) : 0

  const stats = [
    { label: '在线终端', value: online, color: 'var(--accent-green)', icon: '●' },
    { label: '离线终端', value: offline, color: 'var(--text-muted)', icon: '●' },
    { label: '已隔离', value: isolated, color: 'var(--critical)', icon: '🔒' },
    { label: '异常 / 部署中', value: errors, color: 'var(--high)', icon: '⚠' },
    { label: 'Agent覆盖率', value: `${coverage}%`, color: coverage >= 90 ? 'var(--accent-green)' : coverage >= 70 ? 'var(--medium)' : 'var(--critical)', icon: '◎' },
  ]

  // OS breakdown
  const osBreak = items.reduce((acc, d) => {
    const t = (d.os_type || d.os || '').toLowerCase()
    const key = t.includes('windows') ? 'windows' : t.includes('linux') || t.includes('ubuntu') || t.includes('centos') ? 'linux' : t.includes('mac') || t.includes('darwin') ? 'macos' : 'other'
    acc[key] = (acc[key] || 0) + 1
    return acc
  }, {} as Record<string, number>)

  return (
    <div style={{
      flexShrink: 0, padding: '10px 20px',
      background: 'var(--bg-secondary)',
      borderBottom: '1px solid var(--border)',
      display: 'flex', alignItems: 'center', gap: 0,
    }}>
      {/* Status stats */}
      {stats.map((s, i) => (
        <div key={s.label} style={{
          display: 'flex', flexDirection: 'column', justifyContent: 'center',
          padding: '0 20px',
          borderRight: i < stats.length - 1 ? '1px solid var(--border)' : 'none',
          minWidth: 100,
        }}>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 2, whiteSpace: 'nowrap' }}>{s.label}</div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 5 }}>
            <span style={{ fontSize: 11, color: s.color }}>{s.icon}</span>
            <span style={{ fontSize: 20, fontWeight: 700, color: s.color, lineHeight: 1 }}>{s.value}</span>
          </div>
        </div>
      ))}

      {/* Spacer */}
      <div style={{ flex: 1 }} />

      {/* OS breakdown */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 14,
        padding: '0 20px', borderLeft: '1px solid var(--border)',
      }}>
        <span style={{ fontSize: 10, color: 'var(--text-muted)', marginRight: 4 }}>OS</span>
        {[
          { key: 'windows', icon: '🪟', label: 'Win' },
          { key: 'linux',   icon: '🐧', label: 'Linux' },
          { key: 'macos',   icon: '🍎', label: 'macOS' },
        ].map(({ key, icon, label }) => (
          osBreak[key] ? (
            <div key={key} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11 }}>
              <span>{icon}</span>
              <span style={{ color: 'var(--text-secondary)' }}>{label}</span>
              <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{osBreak[key]}</span>
            </div>
          ) : null
        ))}
      </div>

      {/* Online bar */}
      <div style={{ padding: '0 0 0 20px', borderLeft: '1px solid var(--border)', minWidth: 120 }}>
        <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 4 }}>在线率</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{ width: 80, height: 6, background: 'var(--bg-card2)', borderRadius: 3, overflow: 'hidden' }}>
            <div style={{
              width: `${coverage}%`, height: '100%', borderRadius: 3,
              background: coverage >= 90 ? 'var(--accent-green)' : coverage >= 70 ? 'var(--medium)' : 'var(--critical)',
              transition: 'width .4s ease',
            }} />
          </div>
          <span style={{ fontSize: 11, fontWeight: 600, color: coverage >= 90 ? 'var(--accent-green)' : 'var(--medium)' }}>{coverage}%</span>
        </div>
      </div>
    </div>
  )
}

// ── Detail Panel ─────────────────────────────────────────────────────────────

function DetailPanel({ d, liveness, onClose, onAction }: {
  d: Device
  liveness: LivenessMap
  onClose: () => void
  onAction: (action: 'isolate' | 'unisolate' | 'upgrade' | 'uninstall', d: Device) => void
}) {
  const dbStatus = getStatus(d)
  // Resolve effective status: isolated/error from DB; online/offline from liveness
  const agentID = d.agent_id
  const livenessVal = agentID ? liveness[agentID] : undefined
  let status = dbStatus
  if (dbStatus !== 'isolated' && dbStatus !== 'error' && dbStatus !== 'installing' && dbStatus !== 'uninstalling') {
    if (livenessVal === true) status = 'online'
    else if (livenessVal === false) status = 'offline'
  }
  const statusColor = STATUS_COLORS[status] ?? 'var(--text-muted)'
  const osStr = osLabel(d.os_type || d.os, d.os_version)

  // Simulated health score based on status / agent version
  const isLatest = d.agent_version?.startsWith('7.4.2')
  const isOnline = status === 'online'
  const healthScore = isOnline && isLatest ? 98 : isOnline ? 72 : status === 'isolated' ? 45 : 20
  const healthColor = healthScore >= 80 ? 'var(--accent-green)' : healthScore >= 50 ? 'var(--medium)' : 'var(--critical)'

  const ip = d.ip_addresses?.[0] || d.ip || '-'
  const lastSeen = d.last_heartbeat || d.last_seen

  return (
    <div style={{
      width: 340, flexShrink: 0, borderLeft: '1px solid var(--border)',
      background: 'var(--bg-card)', display: 'flex', flexDirection: 'column',
      overflow: 'hidden',
    }}>
      {/* Panel header */}
      <div style={{
        padding: '10px 14px', borderBottom: '1px solid var(--border)',
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        background: 'var(--bg-sidebar)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 18 }}>{osIcon(d.os_type || d.os)}</span>
          <div>
            <div style={{ fontSize: 13, fontWeight: 600, fontFamily: 'monospace' }}>{d.hostname}</div>
            <div style={{ display: 'inline-flex', alignItems: 'center', gap: 4, marginTop: 2 }}>
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: statusColor, display: 'inline-block', boxShadow: status === 'online' ? `0 0 5px ${statusColor}` : 'none' }} />
              <span style={{ fontSize: 10.5, color: statusColor }}>{STATUS_LABELS[status] ?? status}</span>
            </div>
          </div>
        </div>
        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px' }} onClick={onClose}>✕</button>
      </div>

      <div style={{ flex: 1, overflowY: 'auto', padding: 14, display: 'flex', flexDirection: 'column', gap: 12 }}>

        {/* Health score */}
        <div className="card" style={{ padding: '12px 14px' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
            <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', letterSpacing: 0.5, textTransform: 'uppercase' }}>安全健康度</span>
            <span style={{ fontSize: 18, fontWeight: 700, color: healthColor }}>{healthScore}</span>
          </div>
          <div style={{ width: '100%', height: 6, background: 'var(--bg-card2)', borderRadius: 3, overflow: 'hidden', marginBottom: 8 }}>
            <div style={{ width: `${healthScore}%`, height: '100%', background: healthColor, borderRadius: 3, transition: 'width .4s' }} />
          </div>
          <div style={{ display: 'flex', gap: 8 }}>
            {[
              { label: 'Agent', ok: isOnline },
              { label: '版本', ok: isLatest },
              { label: '策略', ok: !!d.policy_id },
              { label: '连通', ok: isOnline },
            ].map(({ label, ok }) => (
              <div key={label} style={{ flex: 1, textAlign: 'center', padding: '4px 0', background: ok ? 'rgba(67,160,71,.08)' : 'rgba(229,57,53,.08)', borderRadius: 4, border: `1px solid ${ok ? 'rgba(67,160,71,.2)' : 'rgba(229,57,53,.2)'}` }}>
                <div style={{ fontSize: 9.5, color: 'var(--text-muted)', marginBottom: 1 }}>{label}</div>
                <span style={{ fontSize: 12, color: ok ? 'var(--accent-green)' : 'var(--critical)' }}>{ok ? '✓' : '✗'}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Device info */}
        <div className="card" style={{ padding: '12px 14px' }}>
          <div className="card-title" style={{ marginBottom: 10 }}>设备信息</div>
          {[
            ['主机名', d.hostname || '-', 'monospace'],
            ['IP 地址', ip, 'monospace'],
            ['操作系统', osStr, undefined],
            ['Agent版本', d.agent_version || '-', 'monospace'],
            ['Agent ID', d.agent_id ? d.agent_id.slice(0, 18) + (d.agent_id.length > 18 ? '…' : '') : '-', 'monospace'],
            ['策略', d.policy_name || d.policy_id || 'Default', undefined],
            ['最近心跳', fmtRelative(lastSeen), undefined],
            ['注册时间', fmtDate(d.enrolled_at || d.created_at), undefined],
          ].map(([k, v, ff]) => (
            <div key={k as string} style={{
              display: 'flex', justifyContent: 'space-between', alignItems: 'baseline',
              fontSize: 11.5, paddingBottom: 5, marginBottom: 5,
              borderBottom: '1px solid rgba(255,255,255,.04)',
            }}>
              <span style={{ color: 'var(--text-muted)', flexShrink: 0, minWidth: 68 }}>{k}</span>
              <span style={{
                color: 'var(--text-secondary)', fontFamily: ff as any,
                textAlign: 'right', wordBreak: 'break-all',
              }}>{v}</span>
            </div>
          ))}
        </div>

        {/* Quick actions */}
        <div className="card" style={{ padding: '12px 14px' }}>
          <div className="card-title" style={{ marginBottom: 10 }}>快捷操作</div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
            {status === 'isolated' ? (
              <button className="btn-primary" style={{ fontSize: 11 }} onClick={() => onAction('unisolate', d)}>
                🔓 取消隔离
              </button>
            ) : (
              <button className="btn-secondary" style={{ fontSize: 11, color: 'var(--critical)' }} onClick={() => onAction('isolate', d)}>
                🔒 隔离终端
              </button>
            )}
            <button className="btn-secondary" style={{ fontSize: 11 }} onClick={() => onAction('upgrade', d)}>
              ↑ 升级 Agent
            </button>
            <button className="btn-secondary" style={{ fontSize: 11 }} onClick={() => window.open(`/actions?q=${encodeURIComponent(d.hostname)}`)}>
              📋 查看动作
            </button>
            <button className="btn-secondary" style={{ fontSize: 11, color: 'var(--high)' }} onClick={() => onAction('uninstall', d)}>
              ✕ 卸载 Agent
            </button>
          </div>
        </div>

        {/* Live status widget */}
        {status === 'online' && (
          <div style={{
            padding: '10px 12px', background: 'rgba(67,160,71,.06)',
            border: '1px solid rgba(67,160,71,.18)', borderRadius: 6,
            display: 'flex', alignItems: 'center', gap: 10,
          }}>
            <span style={{ fontSize: 16, animation: 'pulse-dot 2s infinite' }}>●</span>
            <div>
              <div style={{ fontSize: 11.5, color: 'var(--accent-green)', fontWeight: 600 }}>实时连接中</div>
              <div style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>
                心跳 · {fmtRelative(lastSeen)}
              </div>
            </div>
          </div>
        )}
        {status === 'isolated' && (
          <div style={{
            padding: '10px 12px', background: 'rgba(229,57,53,.06)',
            border: '1px solid rgba(229,57,53,.2)', borderRadius: 6,
          }}>
            <div style={{ fontSize: 11.5, color: 'var(--critical)', fontWeight: 600, marginBottom: 3 }}>🔒 终端已隔离</div>
            <div style={{ fontSize: 10.5, color: 'var(--text-muted)', lineHeight: 1.5 }}>
              该终端已从网络中隔离。仅与 XSIAM Agent 保持通信。<br />
              调查完成后可点击「取消隔离」恢复网络连接。
            </div>
          </div>
        )}
        {status === 'error' && (
          <div style={{
            padding: '10px 12px', background: 'rgba(239,108,0,.06)',
            border: '1px solid rgba(239,108,0,.2)', borderRadius: 6,
          }}>
            <div style={{ fontSize: 11.5, color: 'var(--high)', fontWeight: 600, marginBottom: 3 }}>⚠ Agent 异常</div>
            <div style={{ fontSize: 10.5, color: 'var(--text-muted)', lineHeight: 1.5 }}>
              Agent 报告错误状态。建议重新部署或检查网络连通性。
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Confirm Modal ─────────────────────────────────────────────────────────────

function ConfirmModal({ title, body, danger, onConfirm, onCancel }: {
  title: string; body: string; danger?: boolean
  onConfirm: () => void; onCancel: () => void
}) {
  return (
    <>
      <div onClick={onCancel} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.5)', zIndex: 400 }} />
      <div style={{
        position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
        width: 380, background: 'var(--bg-card)', border: '1px solid var(--border)',
        borderRadius: 8, zIndex: 500, padding: 24,
      }}>
        <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 10 }}>{title}</div>
        <div style={{ fontSize: 12.5, color: 'var(--text-secondary)', marginBottom: 20, lineHeight: 1.6 }}>{body}</div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button className="btn-secondary" style={{ flex: 1 }} onClick={onCancel}>取消</button>
          <button className="btn-primary" style={{ flex: 1, background: danger ? 'var(--critical)' : undefined }} onClick={onConfirm}>确认</button>
        </div>
      </div>
    </>
  )
}

// ── Liveness overlay ─────────────────────────────────────────────────────────

// null = unknown/loading, true = online, false = offline
type LivenessMap = Record<string, boolean | null>

// ── Main Page ─────────────────────────────────────────────────────────────────

type StatusTab = '' | 'online' | 'offline' | 'isolated' | 'error'

export default function Devices() {
  const [items, setItems] = useState<Device[]>([])
  const [allItems, setAllItems] = useState<Device[]>([]) // for summary stats
  const [meta, setMeta] = useState<PageMeta>({ page: 1, page_size: 20, total: 0, total_pages: 1 })
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [statusFilter, setStatusFilter] = useState<StatusTab>('')
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<Device | null>(null)
  const [showToken, setShowToken] = useState(false)
  const [token, setToken] = useState('')
  const [tokenLoading, setTokenLoading] = useState(false)
  const [policies, setPolicies] = useState<Policy[]>([])
  const [policyFilter, setPolicyFilter] = useState('')
  const [confirm, setConfirm] = useState<{ action: string; device: Device } | null>(null)
  // liveness: agent_id → true/false/null(unknown)
  const [liveness, setLiveness] = useState<LivenessMap>({})
  const [livenessLoading, setLivenessLoading] = useState(false)
  const livenessTimerRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const mountedRef = useRef(false)

  // Query liveness for a list of devices
  function fetchLiveness(devices: Device[]) {
    const agentIDs = devices.map(d => d.agent_id).filter(Boolean) as string[]
    if (agentIDs.length === 0) return

    // Set all to null (loading) first
    setLiveness(prev => {
      const next = { ...prev }
      agentIDs.forEach(id => { if (next[id] === undefined) next[id] = null })
      return next
    })
    setLivenessLoading(true)

    api.post('/devices/liveness', { agent_ids: agentIDs })
      .then(r => {
        const onlineMap: Record<string, boolean> = r.data.data?.online ?? {}
        setLiveness(prev => ({ ...prev, ...onlineMap }))
      })
      .catch(() => {
        // On error leave as null (unknown)
      })
      .finally(() => setLivenessLoading(false))
  }

  function load(p = page) {
    setLoading(true)
    const params: any = { page: p, page_size: 20 }
    if (statusFilter) params.status = statusFilter
    if (search) params.keyword = search
    if (policyFilter) params.policy_id = policyFilter
    api.get('/devices', { params })
      .then(r => {
        const data: Device[] = r.data.data?.items ?? []
        setItems(data)
        setMeta(r.data.data?.meta ?? meta)
        if (p === 1 && !statusFilter && !search && !policyFilter) setAllItems(data)
        // Async liveness check after list is rendered
        fetchLiveness(data)
      })
      .finally(() => setLoading(false))
  }

  // Load all devices (up to 200) for accurate stats
  function loadStats() {
    api.get('/devices', { params: { page: 1, page_size: 200 } })
      .then(r => {
        const data: Device[] = r.data.data?.items ?? []
        setAllItems(data)
        fetchLiveness(data)
      })
  }

  // Periodic liveness refresh every 30s
  function startLivenessPoller(devices: Device[]) {
    if (livenessTimerRef.current) clearInterval(livenessTimerRef.current)
    livenessTimerRef.current = setInterval(() => fetchLiveness(devices), 30_000)
  }

  useEffect(() => {
    api.get('/agent_policies', { params: { page: 1, page_size: 100 } })
      .then(r => setPolicies(r.data.data?.items ?? []))
    loadStats()
    return () => {
      if (livenessTimerRef.current) clearInterval(livenessTimerRef.current)
    }
  }, [])

  useEffect(() => { load(page) }, [page])
  useEffect(() => {
    if (!mountedRef.current) { mountedRef.current = true; return }
    setPage(1); load(1)
  }, [statusFilter, search, policyFilter])

  // Restart poller whenever items change
  useEffect(() => {
    if (items.length > 0) startLivenessPoller(items)
  }, [items])

  function generateToken() {
    setTokenLoading(true)
    api.post('/devices/enrollment_token')
      .then(r => { setToken(r.data.data?.token ?? ''); setShowToken(true) })
      .finally(() => setTokenLoading(false))
  }

  function doAction(action: 'isolate' | 'unisolate' | 'upgrade' | 'uninstall', d: Device) {
    const msgs: Record<string, { title: string; body: string; danger?: boolean }> = {
      isolate: {
        title: `隔离终端：${d.hostname}`,
        body: '该操作将立即切断该设备的网络连接，仅保留与 Agent 的通信通道。适用于发现主动攻击时的即时遏制。',
        danger: true,
      },
      unisolate: {
        title: `取消隔离：${d.hostname}`,
        body: '该操作将恢复设备网络访问权限。请确认已完成安全调查，确定该设备不再构成威胁。',
      },
      upgrade: {
        title: `升级 Agent：${d.hostname}`,
        body: `当前版本 ${d.agent_version || '-'}，将升级至最新版本。升级期间 Agent 短暂重启，不影响设备正常使用。`,
      },
      uninstall: {
        title: `卸载 Agent：${d.hostname}`,
        body: '卸载后该设备将不再受 XSIAM 保护，无法接收策略和威胁检测。此操作不可撤销（可重新注册）。',
        danger: true,
      },
    }
    setConfirm({ action: `${action}:${d._key}`, device: d })
    // store the modal config alongside
    ;(window as any).__confirmCfg = msgs[action]
  }

  function execAction(rawAction: string, d: Device) {
    const [action] = rawAction.split(':')
    if (action === 'isolate') {
      api.patch(`/devices/${d._key}`, { status: 'isolated', agent_status: 'isolated' })
        .then(() => { load(page); loadStats(); setSelected(prev => prev?._key === d._key ? { ...prev, status: 'isolated', agent_status: 'isolated' } : prev) })
    } else if (action === 'unisolate') {
      api.patch(`/devices/${d._key}`, { status: 'online', agent_status: 'online' })
        .then(() => { load(page); loadStats(); setSelected(prev => prev?._key === d._key ? { ...prev, status: 'online', agent_status: 'online' } : prev) })
    } else if (action === 'upgrade') {
      api.post(`/devices/${d._key}/upgrade`, { version: 'latest' })
        .then(() => load(page))
    } else if (action === 'uninstall') {
      api.delete ? api.delete(`/devices/${d._key}`)
        .then(() => { load(page); loadStats(); setSelected(null) }) : undefined
    }
    setConfirm(null)
  }

  const STATUS_TABS: [string, StatusTab][] = [
    ['全部', ''], ['在线', 'online'], ['离线', 'offline'], ['已隔离', 'isolated'], ['Error', 'error'],
  ]

  const statusColor = STATUS_COLORS

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <PageHeader
        title="终端管理"
        subtitle={`· ${meta.total} 台设备${livenessLoading ? ' · 刷新在线状态…' : ''}`}
        actions={<>
          <button className="btn-secondary" style={{ fontSize: 12 }} disabled={tokenLoading} onClick={generateToken}>
            {tokenLoading ? '生成中...' : '🔑 注册令牌'}
          </button>
          <button className="btn-primary" style={{ fontSize: 12 }} onClick={generateToken}>
            + 注册设备
          </button>
        </>}
      />

      {/* Summary stats bar */}
      <SummaryBar items={allItems} liveness={liveness} />

      {/* Status tabs */}
      <div className="tab-bar">
        {STATUS_TABS.map(([label, val]) => {
          // Always count isolated/error from DB status; they're not liveness-dependent
          const isolatedCount = allItems.filter(d => getStatus(d) === 'isolated').length
          const errorCount = allItems.filter(d => getStatus(d) === 'error').length
          return (
            <button
              key={val}
              className={`tab ${statusFilter === val ? 'active' : ''}`}
              onClick={() => setStatusFilter(val)}
            >
              {label}
              {val === 'isolated' && isolatedCount > 0 && (
                <span className="tab-count" style={{ background: 'var(--critical)' }}>
                  {isolatedCount}
                </span>
              )}
              {val === 'error' && errorCount > 0 && (
                <span className="tab-count" style={{ background: 'var(--high)' }}>
                  {errorCount}
                </span>
              )}
            </button>
          )
        })}
      </div>

      {/* Filter bar */}
      <div className="filter-bar">
        <input
          className="filter-input"
          placeholder="搜索主机名、IP地址..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && load(1)}
          style={{ minWidth: 220 }}
        />
        <select className="filter-select" value={policyFilter} onChange={e => setPolicyFilter(e.target.value)}>
          <option value="">全部策略</option>
          {policies.map(p => <option key={p._key} value={p._key}>{p.name}</option>)}
        </select>
      </div>

      {/* Content: table + detail panel */}
      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        <div className="data-table-wrap" style={{ flex: 1 }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>设备 / 主机名</th>
                <th>操作系统</th>
                <th>Agent 版本</th>
                <th>IP 地址</th>
                <th>状态</th>
                <th>最近心跳</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 32 }}>加载中...</td></tr>
              )}
              {!loading && items.length === 0 && (
                <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 32 }}>
                  {statusFilter ? `没有「${STATUS_LABELS[statusFilter]}」状态的设备` : '暂无注册设备'}
                </td></tr>
              )}
              {items.map(d => {
                const dbSt = getStatus(d)
                // Resolve effective status from liveness map
                const aid = d.agent_id
                const lv = aid ? liveness[aid] : undefined  // true/false/null/undefined
                let st = dbSt
                if (dbSt !== 'isolated' && dbSt !== 'error' && dbSt !== 'installing' && dbSt !== 'uninstalling') {
                  if (lv === true) st = 'online'
                  else if (lv === false) st = 'offline'
                  // lv === null (loading) or undefined (no agent_id): fall back to dbSt
                }
                const stColor = statusColor[st] ?? 'var(--text-muted)'
                const ip = d.ip_addresses?.[0] || d.ip || '-'
                const isSelected = selected?._key === d._key
                const isLatest = d.agent_version?.startsWith('7.4.2')
                const lastSeen = d.last_heartbeat || d.last_seen
                // Is liveness still loading for this agent?
                const livenessUnknown = aid && lv === undefined
                const livenessQuerying = aid && lv === null

                return (
                  <tr
                    key={d._key}
                    onClick={() => setSelected(isSelected ? null : d)}
                    className={isSelected ? 'selected' : ''}
                    style={{ cursor: 'pointer' }}
                  >
                    {/* 主机名 */}
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <span style={{ fontSize: 16 }}>{osIcon(d.os_type || d.os)}</span>
                        <div>
                          <div style={{ fontFamily: 'monospace', fontSize: 12.5, fontWeight: 600 }}>{d.hostname || '-'}</div>
                          {d.asset_id && (
                            <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>asset:{d.asset_id.slice(0, 8)}</div>
                          )}
                        </div>
                      </div>
                    </td>

                    {/* OS */}
                    <td>
                      <div style={{ fontSize: 11.5 }}>{osLabel(d.os_type || d.os, d.os_version)}</div>
                    </td>

                    {/* Agent */}
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                        <span style={{ fontFamily: 'monospace', fontSize: 11.5, color: 'var(--text-secondary)' }}>
                          {d.agent_version || '-'}
                        </span>
                        {!isLatest && d.agent_version && (
                          <span style={{ fontSize: 9.5, padding: '1px 5px', background: 'rgba(239,108,0,.12)', color: 'var(--high)', border: '1px solid rgba(239,108,0,.25)', borderRadius: 3 }}>
                            旧版
                          </span>
                        )}
                      </div>
                    </td>

                    {/* IP */}
                    <td style={{ fontFamily: 'monospace', fontSize: 11.5, color: 'var(--text-secondary)' }}>{ip}</td>

                    {/* Status — liveness-aware */}
                    <td>
                      {(livenessQuerying || livenessUnknown) && dbSt !== 'isolated' && dbSt !== 'error' ? (
                        // Still loading liveness: show dash placeholder
                        <span style={{ fontSize: 11.5, color: 'var(--text-muted)', letterSpacing: 1 }}>-</span>
                      ) : (
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11.5 }}>
                          <span style={{
                            width: 7, height: 7, borderRadius: '50%', display: 'inline-block',
                            background: stColor,
                            boxShadow: st === 'online' ? `0 0 5px ${stColor}` : 'none',
                            animation: st === 'installing' ? 'pulse-dot 1.2s infinite' : 'none',
                          }} />
                          <span style={{ color: stColor, fontWeight: st === 'isolated' ? 600 : undefined }}>
                            {STATUS_LABELS[st] ?? st}
                          </span>
                        </span>
                      )}
                    </td>

                    {/* Last seen */}
                    <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                      <span title={fmtDate(lastSeen)}>{fmtRelative(lastSeen)}</span>
                    </td>

                    {/* Actions */}
                    <td onClick={e => e.stopPropagation()}>
                      <div style={{ display: 'flex', gap: 5 }}>
                        {st === 'isolated' ? (
                          <button
                            className="btn-secondary"
                            style={{ fontSize: 11, padding: '2px 8px', color: 'var(--accent-green)' }}
                            onClick={() => doAction('unisolate', d)}
                          >取消隔离</button>
                        ) : (
                          <button
                            className="btn-secondary"
                            style={{ fontSize: 11, padding: '2px 8px', color: 'var(--critical)' }}
                            onClick={() => doAction('isolate', d)}
                          >🔒 隔离</button>
                        )}
                        {!isLatest && (
                          <button
                            className="btn-primary"
                            style={{ fontSize: 11, padding: '2px 8px' }}
                            onClick={() => doAction('upgrade', d)}
                          >↑ 升级</button>
                        )}
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>

        {/* Right detail panel */}
        {selected && (
          <DetailPanel
            d={selected}
            liveness={liveness}
            onClose={() => setSelected(null)}
            onAction={doAction}
          />
        )}
      </div>

      {/* Pagination */}
      <div className="pagination">
        <button className="page-btn" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>&#8249;</button>
        <span>{page} / {meta.total_pages || 1}</span>
        <button className="page-btn" disabled={page >= meta.total_pages} onClick={() => setPage(p => p + 1)}>&#8250;</button>
        <span style={{ marginLeft: 8 }}>{meta.total} 台</span>
      </div>

      {/* Enrollment Token Modal */}
      {showToken && (
        <>
          <div onClick={() => setShowToken(false)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.5)', zIndex: 400 }} />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 500, background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: 8, zIndex: 500, padding: 24,
          }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 6 }}>🔑 设备注册令牌</div>
            <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 16, lineHeight: 1.6 }}>
              使用以下令牌在新设备上部署 XSIAM Agent。令牌有效期 <strong>24 小时</strong>，用于初始注册后自动失效。
            </div>
            <div style={{
              fontFamily: 'monospace', fontSize: 11, padding: '12px 14px',
              background: 'var(--bg-card2)', border: '1px solid var(--border)',
              borderRadius: 4, wordBreak: 'break-all', color: 'var(--accent-green)',
              lineHeight: 1.7, marginBottom: 16,
            }}>
              {token || '正在生成...'}
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 16, padding: '8px 12px', background: 'rgba(0,120,212,.06)', border: '1px solid rgba(0,120,212,.15)', borderRadius: 4 }}>
              <strong>安装命令（Linux）：</strong><br />
              <code style={{ fontFamily: 'monospace', color: 'var(--accent-blue)' }}>
                curl -s https://agent.xsiam.local/install.sh | bash -s -- --token {token.slice(0, 12)}...
              </code>
            </div>
            <div style={{ display: 'flex', gap: 10 }}>
              <button className="btn-secondary" style={{ flex: 1 }} onClick={() => navigator.clipboard?.writeText(token)}>
                📋 复制令牌
              </button>
              <button className="btn-primary" style={{ flex: 1 }} onClick={() => setShowToken(false)}>关闭</button>
            </div>
          </div>
        </>
      )}

      {/* Confirm action modal */}
      {confirm && (
        <ConfirmModal
          title={(window as any).__confirmCfg?.title ?? '确认操作'}
          body={(window as any).__confirmCfg?.body ?? '确定执行此操作？'}
          danger={(window as any).__confirmCfg?.danger}
          onConfirm={() => execAction(confirm.action, confirm.device)}
          onCancel={() => setConfirm(null)}
        />
      )}
    </div>
  )
}
