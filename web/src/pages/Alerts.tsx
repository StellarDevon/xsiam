import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '@/lib/api'
import type { PageMeta } from '@/lib/api'
import PageHeader from '@/components/PageHeader'

// ─── Models ──────────────────────────────────────────────────────────────────

interface Alert {
  _key: string
  alert_id?: string
  name: string
  description?: string
  severity: string
  status: string
  source?: string
  source_type?: string
  host?: string
  asset_name?: string
  user?: string
  user_name?: string
  mitre_tactic?: string
  mitre_tactics?: string[]
  detection_rule?: string
  incident_id?: string
  iocs?: IocEntry[]
  process_tree?: ProcessNode[]
  raw_data?: Record<string, unknown>
  triggered_at?: string
  created_at: string
  updated_at?: string
}

interface ProcessNode {
  pid?: number
  name: string
  path?: string
  command_line?: string
  parent_pid?: number
  is_root?: boolean
  is_alert_node?: boolean
  cmd?: string
  verdict?: 'malicious' | 'suspicious' | 'clean'
  depth?: number
}

interface IocEntry {
  type: string
  value: string
  verdict: string
  note?: string
}

// ─── Constants ───────────────────────────────────────────────────────────────

const STATUS_LABELS: Record<string, string> = {
  active: '活跃', new: '活跃',
  investigating: '调查中', under_investigation: '调查中',
  resolved: '已解决',
  false_positive: '误报',
  auto_closed: '自动关闭',
}
const STATUS_COLORS: Record<string, string> = {
  active: '#4fa3e0', new: '#4fa3e0',
  investigating: '#f9a825', under_investigation: '#f9a825',
  resolved: '#2fb07a',
  false_positive: '#546e7a',
  auto_closed: '#546e7a',
}
const SEV_LABELS: Record<string, string> = {
  critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息',
}
const SEV_COLORS: Record<string, string> = {
  critical: '#e53935', high: '#ff6f00', medium: '#f9a825', low: '#2fb07a', info: '#546e7a',
}
const SOURCE_LABELS: Record<string, string> = {
  endpoint: '终端', network: '网络', cloud: '云', identity: '身份',
  email: '邮件', wazuh: 'Wazuh', siem: 'SIEM', manual: '手动',
}

// MITRE 战术 → 处置建议
const MITRE_ADVICE: Record<string, string> = {
  'Initial Access':      '检查对外暴露面，审查近期账号登录记录，隔离受影响端点',
  'Execution':           '终止可疑进程，审计脚本执行记录，检查计划任务/启动项',
  'Persistence':         '审查自启动项、注册表 Run 键、计划任务，清除持久化机制',
  'Privilege Escalation':'审查权限提升日志，检查 sudo/UAC 绕过，重置受影响账号',
  'Defense Evasion':     '检查安全工具状态，审查日志完整性，检测进程注入痕迹',
  'Credential Access':   '强制重置涉及账号密码，开启 MFA，检查凭证存储',
  'Discovery':           '分析扫描行为来源，审查内网访问记录',
  'Lateral Movement':    '隔离横向移动路径上的端点，审查共享凭证使用情况',
  'Collection':          '检查数据访问日志，审查文件压缩和打包行为',
  'Command and Control': '封堵 C2 域名/IP，检查 DNS 解析异常，审查代理设置',
  'Exfiltration':        '封堵外传通道，审查大量数据传输记录，检查 DLP 日志',
  'Impact':              '评估数据/系统损毁范围，启动业务连续性计划，隔离受损系统',
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function fmtDate(iso: string | undefined) {
  if (!iso) return '—'
  try {
    const d = new Date(iso)
    if (isNaN(d.getTime())) return '—'
    const p = (n: number) => n.toString().padStart(2, '0')
    return `${p(d.getMonth()+1)}/${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
  } catch { return '—' }
}

function fmtRelative(iso: string | undefined) {
  if (!iso) return ''
  const ms = Date.now() - new Date(iso).getTime()
  const m = Math.floor(ms / 60000)
  if (m < 1) return '刚刚'
  if (m < 60) return `${m} 分钟前`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h} 小时前`
  return `${Math.floor(h / 24)} 天前`
}

function alertTime(a: Alert) { return a.triggered_at ?? a.created_at }
function alertHost(a: Alert) { return a.host ?? a.asset_name ?? '' }
function alertUser(a: Alert) { return a.user ?? a.user_name ?? '' }
function alertSource(a: Alert) { return a.source ?? a.source_type ?? 'endpoint' }

// ─── Sub-components ──────────────────────────────────────────────────────────

function SevBadge({ sev }: { sev: string }) {
  const color = SEV_COLORS[sev] ?? '#546e7a'
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      padding: '2px 9px', borderRadius: 3,
      background: color + '22', color,
      fontSize: 10.5, fontWeight: 700, letterSpacing: 0.3,
    }}>
      <span style={{ width: 5, height: 5, borderRadius: '50%', background: color, flexShrink: 0 }} />
      {SEV_LABELS[sev] ?? sev}
    </span>
  )
}

function StatusBadge({ status }: { status: string }) {
  const c = STATUS_COLORS[status] ?? '#546e7a'
  const label = STATUS_LABELS[status] ?? status
  const pulsing = status === 'active' || status === 'new'
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 5,
      fontSize: 10.5, padding: '2px 8px', borderRadius: 3,
      background: c + '1a', color: c, fontWeight: pulsing ? 600 : 400,
    }}>
      <span style={{
        width: 5, height: 5, borderRadius: '50%', background: c, flexShrink: 0,
        boxShadow: pulsing ? `0 0 5px ${c}` : undefined,
        animation: pulsing ? 'none' : undefined,
      }} />
      {label}
    </span>
  )
}

function SourceBadge({ src }: { src: string }) {
  const label = SOURCE_LABELS[src] ?? src
  const color = src === 'endpoint' ? '#4fa3e0'
    : src === 'network' ? '#ab47bc'
    : src === 'cloud' ? '#26c6da'
    : src === 'identity' ? '#ef5350'
    : src === 'email' ? '#ff7043'
    : '#78909c'
  return (
    <span style={{
      fontSize: 10, padding: '2px 7px', borderRadius: 3,
      background: color + '18', color, border: `1px solid ${color}30`,
      fontWeight: 600, letterSpacing: 0.2, whiteSpace: 'nowrap',
    }}>
      {label}
    </span>
  )
}

// ─── Alert Detail Pane ───────────────────────────────────────────────────────

interface DetailPaneProps {
  alert: Alert | null
  onClose: () => void
  onUpdate: (key: string, patch: Partial<Alert>) => void
}

function AlertDetailPane({ alert, onClose, onUpdate }: DetailPaneProps) {
  const navigate = useNavigate()
  const [tab, setTab] = useState('overview')
  const [detail, setDetail] = useState<Alert | null>(null)
  const [loading, setLoading] = useState(false)
  const [acting, setActing] = useState(false)
  // Link mode: 'none' | 'existing' | 'new'
  const [linkMode, setLinkMode] = useState<'none' | 'existing' | 'new'>('none')
  const [linkInput, setLinkInput] = useState('')
  const prevKey = useRef<string | null>(null)

  useEffect(() => {
    if (!alert) { prevKey.current = null; setDetail(null); return }
    if (alert._key === prevKey.current) return
    prevKey.current = alert._key
    setTab('overview'); setLinkMode('none'); setLinkInput('')
    setLoading(true)
    api.get(`/alerts/${alert._key}`)
      .then(r => setDetail(r.data.data ?? alert))
      .catch(() => setDetail(alert))
      .finally(() => setLoading(false))
  }, [alert?._key])

  const a = detail ?? alert
  if (!a) return null

  const verdictColor: Record<string, string> = {
    malicious: '#e53935', suspicious: '#ff6f00', clean: '#2fb07a', unknown: '#546e7a',
  }

  function markStatus(newStatus: string) {
    if (newStatus === 'false_positive' && !confirm('确认将此告警标记为误报？')) return
    setActing(true)
    api.patch(`/alerts/${a!._key}`, { status: newStatus })
      .then(() => onUpdate(a!._key, { status: newStatus }))
      .finally(() => setActing(false))
  }

  function doLinkExisting() {
    const val = linkInput.trim()
    if (!val) return
    // Strip INC- prefix if present
    const key = val.replace(/^inc-/i, '').trim()
    setActing(true)
    api.post(`/alerts/${a!._key}/link_incident`, { incident_id: key })
      .then(() => { onUpdate(a!._key, { incident_id: key }); setLinkMode('none'); setLinkInput('') })
      .catch(() => {
        // Fallback: direct patch if link_incident endpoint not available
        api.patch(`/alerts/${a!._key}`, { incident_id: key })
          .then(() => { onUpdate(a!._key, { incident_id: key }); setLinkMode('none'); setLinkInput('') })
      })
      .finally(() => setActing(false))
  }

  function doCreateAndLink() {
    const val = linkInput.trim()
    if (!val) return
    setActing(true)
    api.post('/incidents', {
      title: val, name: val,
      severity: a!.severity, status: 'new',
      description: `来源告警：${a!.name}`,
    })
      .then(r => {
        const incKey = r.data.data?._key
        if (!incKey) return Promise.resolve()
        return api.patch(`/alerts/${a!._key}`, { incident_id: incKey })
          .then(() => onUpdate(a!._key, { incident_id: incKey }))
      })
      .then(() => { setLinkMode('none'); setLinkInput('') })
      .finally(() => setActing(false))
  }

  function viewCausality() {
    if (a!.incident_id) {
      navigate(`/incidents?highlight=${a!.incident_id}`)
    } else {
      window.open(`/causality?alert=${a!._key}`, '_blank')
    }
  }

  const iocs: IocEntry[] = [...(a.iocs ?? [])]
  if (iocs.length === 0) {
    const host = alertHost(a), user = alertUser(a)
    if (host) iocs.push({ type: '主机', value: host, verdict: 'unknown' })
    if (user) iocs.push({ type: '用户', value: user, verdict: 'unknown' })
    if (a.mitre_tactic) iocs.push({ type: 'MITRE 战术', value: a.mitre_tactic, verdict: 'unknown' })
  }

  const procs: ProcessNode[] = a.process_tree ?? []
  const canFP = a.status !== 'false_positive' && a.status !== 'resolved' && a.status !== 'auto_closed'
  const canInvestigate = a.status === 'active' || a.status === 'new'
  const canResolve = a.status === 'investigating' || a.status === 'active' || a.status === 'new'

  // Severity-based urgency
  const urgency = a.severity === 'critical' ? { label: '立即响应', color: '#e53935', bg: 'rgba(229,57,53,.08)' }
    : a.severity === 'high' ? { label: '优先处置', color: '#ff6f00', bg: 'rgba(255,111,0,.06)' }
    : a.severity === 'medium' ? { label: '尽快跟进', color: '#f9a825', bg: 'rgba(249,168,37,.06)' }
    : { label: '按序排期', color: '#2fb07a', bg: 'rgba(47,176,122,.06)' }

  const advice = a.mitre_tactic ? MITRE_ADVICE[a.mitre_tactic] : undefined

  const TABS = [
    { id: 'overview', label: '概览' },
    { id: 'process',  label: `进程树${procs.length ? ` (${procs.length})` : ''}` },
    { id: 'ioc',      label: `IOC (${iocs.length})` },
    { id: 'raw',      label: '原始数据' },
  ]

  return (
    <div style={{
      width: 460, flexShrink: 0,
      background: 'var(--bg-card)',
      borderLeft: '1px solid var(--border)',
      display: 'flex', flexDirection: 'column', overflow: 'hidden',
    }}>
      {/* ── Header ──────────────────────────── */}
      <div style={{
        padding: '12px 16px 10px',
        borderBottom: '1px solid var(--border)',
        background: 'var(--bg-secondary)',
        flexShrink: 0,
      }}>
        {/* Top row: badges + close */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <SevBadge sev={a.severity} />
            <StatusBadge status={a.status} />
            <span style={{ fontSize: 9.5, color: 'var(--text-muted)', fontFamily: 'monospace' }}>
              ALT-{a._key.slice(-8).toUpperCase()}
            </span>
          </div>
          <button onClick={onClose} style={{
            width: 26, height: 26, display: 'flex', alignItems: 'center', justifyContent: 'center',
            background: 'none', border: '1px solid var(--border-light)', borderRadius: 4,
            color: 'var(--text-muted)', cursor: 'pointer', fontSize: 13, flexShrink: 0,
          }}>✕</button>
        </div>

        {/* Urgency banner */}
        <div style={{
          padding: '6px 10px', borderRadius: 4, marginBottom: 8,
          background: urgency.bg, border: `1px solid ${urgency.color}30`,
          display: 'flex', alignItems: 'center', gap: 8,
        }}>
          <span style={{ fontSize: 11, fontWeight: 700, color: urgency.color }}>{urgency.label}</span>
          <span style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>·</span>
          <span style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>{fmtRelative(alertTime(a))}</span>
          {alertHost(a) && (
            <>
              <span style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>·</span>
              <span style={{ fontSize: 10.5, color: '#4fa3e0', fontFamily: 'monospace' }}>🖥 {alertHost(a)}</span>
            </>
          )}
        </div>

        {/* Alert name */}
        <div style={{
          fontSize: 13, fontWeight: 600, lineHeight: 1.45, marginBottom: 8,
          color: 'var(--text-primary)',
        }}>
          {a.name}
        </div>

        {/* Meta chips */}
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 10, alignItems: 'center' }}>
          <SourceBadge src={alertSource(a)} />
          {a.mitre_tactic && (
            <span style={{
              fontSize: 10, padding: '2px 7px', borderRadius: 3,
              background: 'rgba(59,158,222,.1)', color: 'var(--accent-blue)',
              border: '1px solid rgba(59,158,222,.2)', fontWeight: 600,
            }}>🎯 {a.mitre_tactic}</span>
          )}
          {alertUser(a) && (
            <span style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>👤 {alertUser(a)}</span>
          )}
        </div>

        {/* Incident association */}
        <div style={{
          padding: '6px 10px', borderRadius: 4, marginBottom: 10,
          background: a.incident_id ? 'rgba(79,163,224,.06)' : 'rgba(255,111,0,.06)',
          border: `1px solid ${a.incident_id ? 'rgba(79,163,224,.2)' : 'rgba(255,111,0,.2)'}`,
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        }}>
          {a.incident_id ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>关联事件</span>
              <span
                style={{ color: '#4fa3e0', fontFamily: 'monospace', fontSize: 10.5, cursor: 'pointer', textDecoration: 'underline' }}
                onClick={() => navigate(`/incidents?highlight=${a.incident_id}`)}
              >
                INC-{a.incident_id}
              </span>
            </div>
          ) : (
            <span style={{ fontSize: 10.5, color: '#ff6f00', fontWeight: 500 }}>⚠ 未关联任何事件</span>
          )}
          <button
            className="btn-secondary"
            style={{ fontSize: 10, padding: '2px 8px' }}
            onClick={() => setLinkMode(linkMode !== 'none' ? 'none' : 'existing')}
          >
            {a.incident_id ? '变更' : '关联'}
          </button>
        </div>

        {/* Inline link form */}
        {linkMode !== 'none' && (
          <div style={{ marginBottom: 10 }}>
            {/* Mode switcher */}
            <div style={{ display: 'flex', gap: 0, marginBottom: 8, borderRadius: 4, overflow: 'hidden', border: '1px solid var(--border-light)' }}>
              {(['existing', 'new'] as const).map(mode => (
                <button
                  key={mode}
                  onClick={() => { setLinkMode(mode); setLinkInput('') }}
                  style={{
                    flex: 1, padding: '5px 0', fontSize: 11, cursor: 'pointer', border: 'none',
                    background: linkMode === mode ? 'var(--accent-blue)' : 'var(--bg-card)',
                    color: linkMode === mode ? 'white' : 'var(--text-secondary)',
                    fontWeight: linkMode === mode ? 600 : 400,
                  }}
                >
                  {mode === 'existing' ? '关联已有事件' : '新建事件'}
                </button>
              ))}
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <input
                className="filter-input"
                placeholder={linkMode === 'existing' ? '输入事件编号，如 INC-00001A2B...' : '输入新事件标题...'}
                value={linkInput}
                onChange={e => setLinkInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && (linkMode === 'existing' ? doLinkExisting() : doCreateAndLink())}
                style={{ flex: 1, fontSize: 11 }}
                autoFocus
              />
              <button
                className="btn-primary"
                style={{ fontSize: 11 }}
                disabled={acting || !linkInput.trim()}
                onClick={linkMode === 'existing' ? doLinkExisting : doCreateAndLink}
              >
                {acting ? '...' : '确认'}
              </button>
              <button className="btn-secondary" style={{ fontSize: 11 }} onClick={() => { setLinkMode('none'); setLinkInput('') }}>✕</button>
            </div>
          </div>
        )}

        {/* Action buttons */}
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          <button
            className="btn-primary"
            style={{ fontSize: 10.5, padding: '4px 10px' }}
            onClick={viewCausality}
          >
            溯源图 →
          </button>
          {canInvestigate && (
            <button
              className="btn-secondary"
              style={{ fontSize: 10.5, padding: '4px 10px', color: '#f9a825', borderColor: 'rgba(249,168,37,.3)' }}
              disabled={acting}
              onClick={() => markStatus('investigating')}
            >
              开始调查
            </button>
          )}
          {canResolve && a.status === 'investigating' && (
            <button
              className="btn-secondary"
              style={{ fontSize: 10.5, padding: '4px 10px', color: '#2fb07a', borderColor: 'rgba(47,176,122,.3)' }}
              disabled={acting}
              onClick={() => markStatus('resolved')}
            >
              ✓ 标记解决
            </button>
          )}
          {canFP && (
            <button
              className="btn-secondary"
              style={{ fontSize: 10.5, padding: '4px 10px', color: 'var(--text-muted)' }}
              disabled={acting}
              onClick={() => markStatus('false_positive')}
            >
              标记误报
            </button>
          )}
        </div>
      </div>

      {/* ── Tabs ────────────────────────────── */}
      <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', background: 'var(--bg-secondary)', flexShrink: 0 }}>
        {TABS.map(t => (
          <button
            key={t.id}
            className={`tab${tab === t.id ? ' active' : ''}`}
            style={{ padding: '8px 12px', fontSize: 11.5 }}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* ── Tab content ─────────────────────── */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '14px 16px' }}>
        {loading && (
          <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24, fontSize: 12 }}>加载中...</div>
        )}

        {/* 概览 */}
        {!loading && tab === 'overview' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>

            {/* Advice card — most important for security value */}
            {advice && (
              <div style={{
                padding: '10px 12px', borderRadius: 5,
                background: 'rgba(249,168,37,.06)',
                border: '1px solid rgba(249,168,37,.25)',
                borderLeft: '3px solid #f9a825',
              }}>
                <div style={{ fontSize: 10, color: '#f9a825', fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 5 }}>
                  🛡 处置建议
                </div>
                <div style={{ fontSize: 11.5, color: 'var(--text-secondary)', lineHeight: 1.65 }}>
                  {advice}
                </div>
              </div>
            )}

            {/* Key fields */}
            {[
              { label: '来源', value: SOURCE_LABELS[alertSource(a)] ?? alertSource(a) },
              { label: '检测规则', value: a.detection_rule || '—' },
              { label: '触发时间', value: fmtDate(alertTime(a)) },
              ...(a.mitre_tactic ? [{ label: 'MITRE 战术', value: a.mitre_tactic, color: 'var(--accent-blue)' as string | undefined }] : []),
            ].map(row => (
              <div key={row.label} style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start',
                padding: '5px 0', borderBottom: '1px solid rgba(255,255,255,.04)', fontSize: 12,
                gap: 12,
              }}>
                <span style={{ color: 'var(--text-muted)', flexShrink: 0 }}>{row.label}</span>
                <span style={{ color: (row as any).color ?? 'var(--text-secondary)', textAlign: 'right', wordBreak: 'break-all' }}>{row.value}</span>
              </div>
            ))}

            {/* Description */}
            <div>
              <div style={{ fontSize: 10.5, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.4, marginBottom: 8 }}>
                告警描述
              </div>
              <div style={{
                fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.65,
                padding: '10px 12px', background: 'rgba(255,255,255,.03)',
                borderRadius: 4, border: '1px solid var(--border)',
              }}>
                {a.description
                  ? a.description
                  : alertHost(a)
                    ? `在主机 ${alertHost(a)} 上检测到异常行为，由「${a.detection_rule || '行为分析引擎'}」触发。来源：${SOURCE_LABELS[alertSource(a)] ?? alertSource(a)}。`
                    : `告警由「${a.detection_rule || '行为分析引擎'}」触发。来源：${SOURCE_LABELS[alertSource(a)] ?? alertSource(a)}。`
                }
              </div>
            </div>

            {/* MITRE tactic chain */}
            {a.mitre_tactics && a.mitre_tactics.length > 1 && (
              <div>
                <div style={{ fontSize: 10.5, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.4, marginBottom: 8 }}>
                  MITRE ATT&amp;CK 战术链
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {a.mitre_tactics.map(t => (
                    <span key={t} style={{
                      fontSize: 10.5, padding: '3px 8px', borderRadius: 3,
                      background: 'rgba(59,158,222,.1)', color: 'var(--accent-blue)',
                      border: '1px solid rgba(59,158,222,.2)',
                    }}>{t}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* 进程树 */}
        {!loading && tab === 'process' && (
          <div>
            <div style={{ fontSize: 10.5, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.4, marginBottom: 10 }}>
              进程执行树
            </div>
            {procs.length === 0 ? (
              <div style={{ fontSize: 12, color: 'var(--text-muted)', padding: '12px 0', lineHeight: 1.7 }}>
                <div>该告警暂无进程链路数据。</div>
                {alertSource(a) === 'endpoint' && (
                  <div style={{ marginTop: 6, fontSize: 11, color: 'var(--text-muted)' }}>
                    进程数据由 XSIAM 终端 Agent 采集，请确认 Agent 已部署并正常上报。
                  </div>
                )}
              </div>
            ) : (
              <div style={{
                background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                borderRadius: 4, padding: 12,
                fontFamily: 'Consolas,"JetBrains Mono",monospace',
                fontSize: 11.5, lineHeight: 2, overflowX: 'auto',
              }}>
                {procs.map((p, i) => {
                  const depth = p.depth ?? (p.is_root ? 0 : p.parent_pid != null ? 1 : 0)
                  const isMalicious = p.verdict === 'malicious' || p.is_alert_node
                  const isSuspicious = p.verdict === 'suspicious'
                  return (
                    <div key={i} style={{
                      color: isMalicious ? '#ef5350' : isSuspicious ? '#f9a825' : 'var(--text-secondary)',
                      background: isMalicious ? 'rgba(229,57,53,.08)' : isSuspicious ? 'rgba(249,168,37,.06)' : 'none',
                      borderRadius: 3, padding: `2px 4px 2px ${depth * 20 + 4}px`,
                    }}>
                      {depth > 0 ? '└ ' : ''}
                      {isMalicious ? '⚠ ' : isSuspicious ? '⚡ ' : ''}
                      {p.name}
                      {p.pid ? ` (PID: ${p.pid})` : ''}
                      {(p.cmd ?? p.command_line) ? `  ${p.cmd ?? p.command_line}` : ''}
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        )}

        {/* IOC */}
        {!loading && tab === 'ioc' && (
          <div>
            <div style={{ fontSize: 10.5, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.4, marginBottom: 10 }}>
              IOC 指标分析
            </div>
            {iocs.length === 0 ? (
              <div style={{ fontSize: 12, color: 'var(--text-muted)', padding: '12px 0' }}>该告警暂无 IOC 指标数据。</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {iocs.map((ioc, i) => {
                  const vColor = verdictColor[ioc.verdict] ?? '#546e7a'
                  const vLabel = ioc.verdict === 'malicious' ? '⚠ 恶意'
                    : ioc.verdict === 'suspicious' ? '⚡ 可疑'
                    : ioc.verdict === 'clean' ? '✓ 安全'
                    : '未知'
                  return (
                    <div key={i} style={{
                      padding: '8px 12px', background: 'var(--bg-secondary)',
                      border: `1px solid ${vColor}30`, borderLeft: `3px solid ${vColor}`,
                      borderRadius: 4,
                      display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 12,
                    }}>
                      <div style={{ minWidth: 0 }}>
                        <div style={{ fontSize: 9.5, color: 'var(--text-muted)', marginBottom: 2 }}>{ioc.type}</div>
                        <div style={{
                          fontSize: 11.5, fontFamily: 'monospace', color: 'var(--text-secondary)',
                          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                        }}>{ioc.value}</div>
                        {ioc.note && <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>{ioc.note}</div>}
                      </div>
                      <span style={{
                        fontSize: 10, color: vColor, flexShrink: 0,
                        fontWeight: ioc.verdict !== 'unknown' ? 600 : 400,
                      }}>{vLabel}</span>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        )}

        {/* 原始数据 */}
        {!loading && tab === 'raw' && (
          <div>
            <div style={{ fontSize: 10.5, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.4, marginBottom: 10 }}>
              原始告警数据
            </div>
            <pre style={{
              background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 4,
              padding: 12, fontSize: 10.5, fontFamily: 'Consolas,"JetBrains Mono",monospace',
              color: '#7ec8e3', overflow: 'auto', lineHeight: 1.7, whiteSpace: 'pre-wrap',
              maxHeight: 500,
            }}>
              {JSON.stringify(a, null, 2)}
            </pre>
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function Alerts() {
  const navigate = useNavigate()
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [meta, setMeta] = useState<PageMeta>({ page: 1, page_size: 20, total: 0, total_pages: 1 })
  const [page, setPage] = useState(1)
  const [severityFilter, setSeverityFilter] = useState('')
  const [sourceFilter, setSourceFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [incidentFilter, setIncidentFilter] = useState('')
  const [timeFilter, setTimeFilter] = useState('')
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<Alert | null>(null)
  const [loading, setLoading] = useState(false)
  const [checked, setChecked] = useState<Set<string>>(new Set())
  const [sortBy, setSortBy] = useState('triggered_at')
  const [sortDesc, setSortDesc] = useState(true)
  const [hovered, setHovered] = useState<string | null>(null)
  // Bulk investigate inline form
  const [bulkIncMode, setBulkIncMode] = useState(false)
  const [bulkIncTitle, setBulkIncTitle] = useState('')
  const [bulkActing, setBulkActing] = useState(false)

  const mountedRef = useRef(false)

  function load(p: number, opts?: {
    severity?: string; source?: string; status?: string; incident?: string
    time?: string; q?: string; sortBy?: string; sortDesc?: boolean
  }) {
    const v  = opts?.severity ?? severityFilter
    const sr = opts?.source   ?? sourceFilter
    const s  = opts?.status   ?? statusFilter
    const ic = opts?.incident ?? incidentFilter
    const t  = opts?.time     ?? timeFilter
    const q  = opts?.q        ?? search
    const sb = opts?.sortBy   ?? sortBy
    const sd = opts?.sortDesc ?? sortDesc
    setLoading(true)
    const params: Record<string, unknown> = { page: p, page_size: 20, sort_by: sb, sort_desc: sd }
    if (v)  params.severity = v
    if (sr) params.source = sr
    if (s)  params.status = s
    if (q)  params.q = q
    if (t)  params.hours = t
    if (ic === 'unlinked') params.unlinked = true
    if (ic === 'linked')   params.linked = true
    api.get('/alerts', { params })
      .then(r => {
        setAlerts(r.data.data?.items ?? [])
        setMeta(r.data.data?.meta ?? { page: p, page_size: 20, total: 0, total_pages: 1 })
      })
      .catch(() => {})
      .finally(() => setLoading(false))
  }

  useEffect(() => { load(page) }, [page])

  useEffect(() => {
    if (!mountedRef.current) { mountedRef.current = true; return }
    setPage(1); load(1)
  }, [severityFilter, sourceFilter, statusFilter, incidentFilter, timeFilter])

  function doSearch() { setPage(1); load(1) }

  function doSort(col: string) {
    const nd = col === sortBy ? !sortDesc : true
    setSortBy(col); setSortDesc(nd)
    setPage(1); load(1, { sortBy: col, sortDesc: nd })
  }

  function handleUpdate(key: string, patch: Partial<Alert>) {
    setAlerts(prev => prev.map(a => a._key === key ? { ...a, ...patch } : a))
    setSelected(prev => prev?._key === key ? { ...prev, ...patch } : prev)
  }

  function exportCSV() {
    const header = ['ID', '告警名称', '严重程度', '状态', '来源', '主机', '用户', 'MITRE 战术', '检测规则', '时间']
    const rows = [header.join(',')]
    alerts.forEach(a => rows.push([
      `ALT-${a._key.slice(-8).toUpperCase()}`,
      `"${a.name.replace(/"/g, '""')}"`,
      SEV_LABELS[a.severity] ?? a.severity,
      STATUS_LABELS[a.status] ?? a.status,
      SOURCE_LABELS[alertSource(a)] ?? alertSource(a),
      alertHost(a),
      alertUser(a),
      a.mitre_tactic ?? '',
      a.detection_rule ?? '',
      fmtDate(alertTime(a)),
    ].join(',')))
    const blob = new Blob(['﻿' + rows.join('\n')], { type: 'text/csv;charset=utf-8;' })
    const link = document.createElement('a')
    link.href = URL.createObjectURL(blob)
    link.download = `alerts_${new Date().toISOString().slice(0,10)}.csv`
    link.click()
  }

  const toggleCheck = (key: string) => setChecked(prev => {
    const n = new Set(prev)
    if (n.has(key)) n.delete(key); else n.add(key)
    return n
  })

  // Use bulk API (single request) instead of N individual PATCHes
  function bulkPatch(patch: Record<string, unknown>) {
    const keys = [...checked]
    return api.post('/alerts/bulk', { action: 'update', keys, patch })
  }

  function bulkFalsePositive() {
    if (!checked.size) return
    if (!confirm(`确认将 ${checked.size} 条告警标记为误报？`)) return
    bulkPatch({ status: 'false_positive' })
      .then(() => { setChecked(new Set()); load(page) })
  }

  function bulkClose() {
    if (!checked.size) return
    if (!confirm(`确认关闭 ${checked.size} 条告警？`)) return
    api.post('/alerts/bulk', { action: 'close', keys: [...checked] })
      .then(() => { setChecked(new Set()); load(page) })
  }

  function doCreateIncidentAndLink() {
    if (!bulkIncTitle.trim()) return
    setBulkActing(true)
    api.post('/incidents', {
      title: bulkIncTitle.trim(), name: bulkIncTitle.trim(),
      severity: 'high', status: 'new',
    })
      .then(r => {
        const incKey = r.data.data?._key
        if (!incKey) return
        return bulkPatch({ incident_id: incKey, status: 'investigating' })
      })
      .then(() => {
        setChecked(new Set()); setBulkIncMode(false); setBulkIncTitle('')
        load(page)
      })
      .finally(() => setBulkActing(false))
  }

  const sevCounts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 }
  alerts.forEach(a => { if (a.severity in sevCounts) sevCounts[a.severity]++ })
  const unlinkedCount = alerts.filter(a => !a.incident_id).length
  const allChecked = !!alerts.length && checked.size === alerts.length
  const hasFilters = !!(severityFilter || sourceFilter || statusFilter || incidentFilter || timeFilter || search)

  const sortArrow = (col: string) => sortBy === col
    ? <span style={{ marginLeft: 3, fontSize: 9, opacity: 0.7 }}>{sortDesc ? '▼' : '▲'}</span>
    : null

  const colCount = selected ? 9 : 11

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

      {/* ── Header ──────────────────────────────────────── */}
      <PageHeader
        title="告警管理"
        subtitle={meta.total > 0 ? `共 ${meta.total} 条` : undefined}
        actions={<>
          <button className="btn-secondary" style={{ fontSize: 11 }} onClick={exportCSV}>↓ 导出 CSV</button>
          <button className="btn-primary" style={{ fontSize: 11 }} onClick={() => navigate('/detection-rules?new=1')}>
            + 新建检测规则
          </button>
        </>}
      />

      {/* ── Severity + stats strip ───────────────────────── */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 10, padding: '7px 20px',
        borderBottom: '1px solid var(--border)', background: 'var(--bg-secondary)', flexShrink: 0,
        flexWrap: 'wrap',
      }}>
        {([
          ['critical', '严重', '#e53935'],
          ['high',     '高危', '#ff6f00'],
          ['medium',   '中危', '#f9a825'],
          ['low',      '低危', '#2fb07a'],
        ] as [string, string, string][]).map(([key, label, color]) => (
          <button
            key={key}
            onClick={() => setSeverityFilter(severityFilter === key ? '' : key)}
            style={{
              padding: '5px 14px', borderRadius: 4, cursor: 'pointer',
              background: severityFilter === key ? color + '30' : color + '12',
              border: `1px solid ${severityFilter === key ? color : color + '30'}`,
              color, fontSize: 11.5, fontWeight: 600, transition: 'all .12s',
            }}
          >
            {label} <strong style={{ fontVariantNumeric: 'tabular-nums' }}>{sevCounts[key]}</strong>
          </button>
        ))}
        {/* Unlinked alert nudge */}
        {unlinkedCount > 0 && (
          <button
            onClick={() => setIncidentFilter(incidentFilter === 'unlinked' ? '' : 'unlinked')}
            style={{
              padding: '5px 12px', borderRadius: 4, cursor: 'pointer',
              background: incidentFilter === 'unlinked' ? 'rgba(255,111,0,.2)' : 'rgba(255,111,0,.08)',
              border: `1px solid ${incidentFilter === 'unlinked' ? '#ff6f00' : 'rgba(255,111,0,.25)'}`,
              color: '#ff6f00', fontSize: 11, fontWeight: 600, transition: 'all .12s',
            }}
          >
            ⚠ 未关联 <strong>{unlinkedCount}</strong>
          </button>
        )}
        <div style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text-muted)' }}>
          当前页 {alerts.length} 条 / 全局 {meta.total} 条
        </div>
      </div>

      {/* ── Filter bar ──────────────────────────────────── */}
      <div className="filter-bar">
        <input
          className="filter-input"
          style={{ width: 210 }}
          placeholder="搜索告警名称、主机、用户..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && doSearch()}
        />
        <button className="btn-secondary" style={{ fontSize: 11 }} onClick={doSearch}>搜索</button>
        <select className="filter-select" value={sourceFilter} onChange={e => setSourceFilter(e.target.value)}>
          <option value="">全部来源</option>
          <option value="endpoint">终端</option>
          <option value="network">网络</option>
          <option value="cloud">云</option>
          <option value="identity">身份</option>
          <option value="email">邮件</option>
        </select>
        <select className="filter-select" value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
          <option value="">全部状态</option>
          <option value="active">活跃</option>
          <option value="investigating">调查中</option>
          <option value="resolved">已解决</option>
          <option value="false_positive">误报</option>
          <option value="auto_closed">自动关闭</option>
        </select>
        <select className="filter-select" value={timeFilter} onChange={e => setTimeFilter(e.target.value)}>
          <option value="">全部时间</option>
          <option value="24">近 24 小时</option>
          <option value="72">近 3 天</option>
          <option value="168">近 7 天</option>
          <option value="720">近 30 天</option>
        </select>
        <select className="filter-select" value={incidentFilter} onChange={e => setIncidentFilter(e.target.value)}>
          <option value="">全部关联状态</option>
          <option value="unlinked">未关联事件</option>
          <option value="linked">已关联事件</option>
        </select>
        {hasFilters && (
          <button className="btn-secondary" style={{ fontSize: 11 }} onClick={() => {
            setSeverityFilter(''); setSourceFilter(''); setStatusFilter('')
            setTimeFilter(''); setIncidentFilter(''); setSearch('')
          }}>✕ 清除</button>
        )}
      </div>

      {/* ── Bulk action bar ─────────────────────────────── */}
      {checked.size > 0 && (
        <div style={{
          flexShrink: 0, borderBottom: '1px solid rgba(59,158,222,.2)',
          background: 'rgba(59,158,222,.06)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '6px 20px', fontSize: 12 }}>
            <span style={{ color: 'var(--accent-blue)', fontWeight: 600 }}>已选 {checked.size} 条</span>
            <button className="btn-secondary" style={{ fontSize: 11 }} onClick={() => { setBulkIncMode(v => !v); setBulkIncTitle('') }}>
              升级为事件
            </button>
            <button className="btn-secondary" style={{ fontSize: 11 }} onClick={bulkFalsePositive}>
              批量误报
            </button>
            <button className="btn-secondary" style={{ fontSize: 11 }} onClick={bulkClose}>
              批量关闭
            </button>
            <button
              style={{ marginLeft: 'auto', background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 11 }}
              onClick={() => { setChecked(new Set()); setBulkIncMode(false) }}
            >取消</button>
          </div>
          {/* Inline create-incident form */}
          {bulkIncMode && (
            <div style={{ padding: '0 20px 10px', display: 'flex', gap: 8, alignItems: 'center' }}>
              <input
                className="filter-input"
                style={{ flex: 1 }}
                placeholder={`为选中的 ${checked.size} 条告警新建事件，输入事件标题...`}
                value={bulkIncTitle}
                onChange={e => setBulkIncTitle(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && doCreateIncidentAndLink()}
                autoFocus
              />
              <button
                className="btn-primary"
                style={{ fontSize: 11 }}
                disabled={bulkActing || !bulkIncTitle.trim()}
                onClick={doCreateIncidentAndLink}
              >
                {bulkActing ? '处理中...' : '确认创建'}
              </button>
              <button className="btn-secondary" style={{ fontSize: 11 }} onClick={() => setBulkIncMode(false)}>取消</button>
            </div>
          )}
        </div>
      )}

      {/* ── Table + detail pane ─────────────────────────── */}
      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          <div className="data-table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ width: 36 }}>
                    <input type="checkbox"
                      checked={allChecked}
                      onChange={() => setChecked(allChecked ? new Set() : new Set(alerts.map(a => a._key)))}
                    />
                  </th>
                  <th style={{ width: 68, cursor: 'pointer', userSelect: 'none' }} onClick={() => doSort('severity')}>
                    严重程度{sortArrow('severity')}
                  </th>
                  <th style={{ minWidth: 200 }}>告警名称</th>
                  <th style={{ width: 60 }}>来源</th>
                  <th style={{ width: 128 }}>主机 / 用户</th>
                  <th style={{ width: 88 }}>关联事件</th>
                  {!selected && <th style={{ width: 106 }}>MITRE 战术</th>}
                  {!selected && <th style={{ width: 108 }}>检测规则</th>}
                  <th style={{ width: 72 }}>状态</th>
                  <th style={{ width: 80, cursor: 'pointer', userSelect: 'none' }} onClick={() => doSort('triggered_at')}>
                    时间{sortArrow('triggered_at')}
                  </th>
                  <th style={{ width: 56 }}></th>
                </tr>
              </thead>
              <tbody>
                {loading && (
                  <tr><td colSpan={colCount} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 28 }}>加载中...</td></tr>
                )}
                {!loading && alerts.length === 0 && (
                  <tr>
                    <td colSpan={colCount} style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)', fontSize: 12 }}>
                      {hasFilters ? '没有符合条件的告警' : '暂无告警数据'}
                    </td>
                  </tr>
                )}
                {!loading && alerts.map(alert => {
                  const isHovered = hovered === alert._key
                  return (
                    <tr
                      key={alert._key}
                      className={[
                        selected?._key === alert._key ? 'selected' : '',
                        alert.severity === 'critical' ? 'row-critical' : '',
                      ].filter(Boolean).join(' ')}
                      onClick={() => setSelected(selected?._key === alert._key ? null : alert)}
                      onMouseEnter={() => setHovered(alert._key)}
                      onMouseLeave={() => setHovered(null)}
                      style={{ cursor: 'pointer' }}
                    >
                      <td onClick={e => e.stopPropagation()}>
                        <input type="checkbox" checked={checked.has(alert._key)} onChange={() => toggleCheck(alert._key)} />
                      </td>
                      <td><SevBadge sev={alert.severity} /></td>
                      <td style={{ maxWidth: selected ? 170 : 220 }}>
                        <div style={{ fontSize: 12.5, fontWeight: 500, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                          {alert.name}
                        </div>
                        {alert.detection_rule && !selected && (
                          <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {alert.detection_rule}
                          </div>
                        )}
                      </td>
                      <td><SourceBadge src={alertSource(alert)} /></td>
                      <td style={{ fontSize: 11 }}>
                        {alertHost(alert) && (
                          <span style={{ color: '#4fa3e0', fontFamily: 'monospace', fontSize: 10.5, display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            🖥 {alertHost(alert)}
                          </span>
                        )}
                        {alertUser(alert) && (
                          <span style={{ color: 'var(--text-muted)', fontSize: 10.5 }}>👤 {alertUser(alert)}</span>
                        )}
                        {!alertHost(alert) && !alertUser(alert) && <span style={{ color: 'var(--text-muted)' }}>—</span>}
                      </td>
                      <td style={{ fontSize: 11 }}>
                        {alert.incident_id ? (
                          <span
                            style={{ color: '#4fa3e0', fontFamily: 'monospace', fontSize: 10.5, cursor: 'pointer' }}
                            onClick={e => { e.stopPropagation(); navigate(`/incidents?highlight=${alert.incident_id}`) }}
                          >
                            INC-{alert.incident_id}
                          </span>
                        ) : (
                          <span style={{ color: '#ff6f00', fontSize: 10, fontWeight: 600 }}>未关联</span>
                        )}
                      </td>
                      {!selected && (
                        <td>
                          {alert.mitre_tactic ? (
                            <span style={{
                              fontSize: 10, color: 'var(--accent-blue)',
                              background: 'rgba(59,158,222,.1)', padding: '2px 6px', borderRadius: 3,
                              display: 'inline-block', maxWidth: 100,
                              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                            }}>
                              {alert.mitre_tactic}
                            </span>
                          ) : (
                            <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>—</span>
                          )}
                        </td>
                      )}
                      {!selected && (
                        <td style={{ fontSize: 10.5, color: 'var(--text-muted)', maxWidth: 108, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {alert.detection_rule || '—'}
                        </td>
                      )}
                      <td><StatusBadge status={alert.status} /></td>
                      <td style={{ fontSize: 10.5, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                        {fmtDate(alertTime(alert))}
                      </td>
                      <td onClick={e => e.stopPropagation()}>
                        {isHovered && (alert.status === 'active' || alert.status === 'new') ? (
                          <div style={{ display: 'flex', gap: 3 }}>
                            <button
                              className="btn-secondary"
                              style={{ fontSize: 9.5, padding: '2px 6px', color: '#f9a825', borderColor: 'rgba(249,168,37,.3)' }}
                              title="标记为调查中"
                              onClick={e => {
                                e.stopPropagation()
                                api.patch(`/alerts/${alert._key}`, { status: 'investigating' })
                                  .then(() => handleUpdate(alert._key, { status: 'investigating' }))
                              }}
                            >调查</button>
                            <button
                              className="btn-secondary"
                              style={{ fontSize: 9.5, padding: '2px 6px' }}
                              onClick={() => setSelected(alert)}
                            >详情</button>
                          </div>
                        ) : (
                          <button
                            className="btn-secondary"
                            style={{ fontSize: 10, padding: '2px 8px' }}
                            onClick={() => setSelected(alert)}
                          >
                            详情
                          </button>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>

          {/* ── Pagination ────────────────────────────── */}
          <div className="pagination">
            <span style={{ marginRight: 8 }}>
              {meta.total > 0
                ? `第 ${(page-1)*meta.page_size+1}–${Math.min(page*meta.page_size, meta.total)} 条，共 ${meta.total} 条`
                : '暂无结果'
              }
            </span>
            <button className="page-btn" disabled={page <= 1} onClick={() => setPage(p => p-1)}>‹</button>
            {(() => {
              const total = meta.total_pages
              if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1)
              const pages: (number | '...')[] = [1]
              if (page > 3) pages.push('...')
              for (let i = Math.max(2, page - 1); i <= Math.min(total - 1, page + 1); i++) pages.push(i)
              if (page < total - 2) pages.push('...')
              pages.push(total)
              return pages
            })().map((p, i) =>
              p === '...' ? (
                <span key={`dot${i}`} style={{ padding: '0 4px', color: 'var(--text-muted)', fontSize: 12 }}>…</span>
              ) : (
                <button key={p} className={`page-btn${p === page ? ' active' : ''}`} onClick={() => setPage(p as number)}>
                  {p}
                </button>
              )
            )}
            <button className="page-btn" disabled={page >= meta.total_pages} onClick={() => setPage(p => p+1)}>›</button>
          </div>
        </div>

        {/* ── Detail pane ─────────────────────────────── */}
        {selected && (
          <AlertDetailPane
            alert={selected}
            onClose={() => setSelected(null)}
            onUpdate={handleUpdate}
          />
        )}
      </div>
    </div>
  )
}
