import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { AreaChart, Area, XAxis, YAxis, Tooltip as ReTooltip, Legend, ResponsiveContainer } from 'recharts'
import api from '@/lib/api'
import type { PageMeta } from '@/lib/api'
import PageHeader from '@/components/PageHeader'
import ResizableTh from '@/components/ResizableTh'

// ─── Seeded PRNG (mulberry32) ────────────────────────────────────────────────

function seededRand(seed: number): () => number {
  let s = seed >>> 0
  return function () {
    s += 0x6d2b79f5
    let t = s
    t = Math.imul(t ^ (t >>> 15), t | 1)
    t ^= t + Math.imul(t ^ (t >>> 7), t | 61)
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

function hashKey(key: string): number {
  let h = 0x811c9dc5
  for (let i = 0; i < key.length; i++) {
    h ^= key.charCodeAt(i)
    h = Math.imul(h, 0x01000193)
  }
  return h >>> 0
}

// ─── Types ───────────────────────────────────────────────────────────────────

interface RiskSignal {
  type: string
  score: number
  detail: string
  description?: string
  severity?: string
  metadata?: Record<string, unknown>
  detected_at: string
}

interface IdentityBaseline {
  login_hours_p95: [number, number]
  typical_cities: string[]
  known_devices: string[]
  avg_daily_logins: number
}

interface IdentityRisk {
  _key: string
  user_id: string
  username: string
  domain: string
  risk_score: number
  risk_signals: RiskSignal[]
  baseline: IdentityBaseline
  last_impossible_travel?: string
  updated_at: string
  created_at: string
}

interface PrivilegeRestriction {
  _key: string
  user_id: string
  type: 'disable_login' | 'revoke_sessions' | 'read_only' | string
  reason: string
  expires_at?: string
  created_at?: string
}

// ─── Constants ───────────────────────────────────────────────────────────────

const SIGNAL_TYPE_OPTIONS = [
  'login_failure',
  'impossible_travel',
  'privilege_escalation',
  'lateral_movement',
  'data_exfiltration',
  'anomalous_hours',
  'anomalous_login',
  'brute_force',
  'credential_stuffing',
  'other',
]

const SEVERITY_OPTIONS = ['critical', 'high', 'medium', 'low', 'info']

const SIGNAL_TYPE_COLOR: Record<string, string> = {
  login_failure: 'var(--critical)',
  impossible_travel: 'var(--high)',
  privilege_escalation: 'var(--accent-blue)',
  lateral_movement: 'var(--medium)',
  data_exfiltration: 'var(--critical)',
  anomalous_hours: 'var(--accent-blue)',
}

function signalTypeColor(type: string): string {
  return SIGNAL_TYPE_COLOR[type] ?? 'var(--text-muted)'
}

const RESTRICTION_TYPE_LABEL: Record<string, string> = {
  disable_login: '禁止登录',
  revoke_sessions: '撤销会话',
  read_only: '只读',
}

// ─── Small helpers ────────────────────────────────────────────────────────────

function RiskScore({ score }: { score: number }) {
  const color =
    score >= 85
      ? 'var(--critical)'
      : score >= 70
        ? 'var(--high)'
        : score >= 40
          ? 'var(--medium)'
          : 'var(--accent-green)'
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ width: 56, height: 6, background: 'var(--bg-card2)', borderRadius: 3, overflow: 'hidden' }}>
        <div style={{ width: `${score}%`, height: '100%', background: color, borderRadius: 3, transition: 'width .3s' }} />
      </div>
      <span style={{ fontSize: 12, fontWeight: 600, color, minWidth: 28 }}>{score}</span>
    </div>
  )
}

function fmtDate(iso: string) {
  if (!iso) return '-'
  return new Date(iso).toLocaleString('zh-CN', {
    month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit',
    hour12: false,
  })
}

function relativeTime(iso: string): string {
  if (!iso) return ''
  const diffMs = Date.now() - new Date(iso).getTime()
  const diffSec = Math.floor(diffMs / 1000)
  if (diffSec < 60) return `${diffSec}秒前`
  const diffMin = Math.floor(diffSec / 60)
  if (diffMin < 60) return `${diffMin}分钟前`
  const diffHr = Math.floor(diffMin / 60)
  if (diffHr < 24) return `${diffHr}小时前`
  return `${Math.floor(diffHr / 24)}天前`
}

/** Dot color based on signal score */
function signalDotColor(score: number): string {
  if (score >= 80) return 'var(--critical)'
  if (score >= 60) return 'var(--high)'
  if (score >= 40) return 'var(--medium)'
  return 'var(--accent-green)'
}

// ─── ScoreBreakdown ────────────────────────────────────────────────────────────

interface ScoreFactor {
  label: string
  points: number
  max: number
}

function deriveScoreFactors(signals: RiskSignal[]): ScoreFactor[] {
  // Count by type to derive realistic mock values
  const counts: Record<string, number> = {}
  for (const s of signals) counts[s.type] = (counts[s.type] ?? 0) + 1

  const loginFail = Math.min(40, (counts['login_failure'] ?? 0) * 8 + (counts['brute_force'] ?? 0) * 10)
  const privEsc = Math.min(25, (counts['privilege_escalation'] ?? 0) * 12)
  const geoAnom = Math.min(15, (counts['impossible_travel'] ?? 0) * 15 + (counts['lateral_movement'] ?? 0) * 5)
  const timeAnom = Math.min(10, (counts['anomalous_hours'] ?? 0) * 5)
  const base = 5

  return [
    { label: '失败登录', points: loginFail || 0, max: 40 },
    { label: '权限提升', points: privEsc || 0, max: 25 },
    { label: '地理异常', points: geoAnom || 0, max: 15 },
    { label: '时间异常', points: timeAnom || 0, max: 10 },
    { label: '基础分', points: base, max: 5 },
  ]
}

function ScoreBreakdownBar({ points, max }: { points: number; max: number }) {
  const filled = max > 0 ? Math.round((points / max) * 10) : 0
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      <div style={{ display: 'flex', gap: 2, flex: 1 }}>
        {Array.from({ length: 10 }, (_, i) => (
          <div
            key={i}
            style={{
              flex: 1, height: 8, borderRadius: 2,
              background: i < filled ? 'var(--accent-orange)' : 'rgba(255,255,255,0.08)',
              transition: 'background .3s',
            }}
          />
        ))}
      </div>
      <span style={{ fontSize: 10.5, color: 'var(--text-muted)', minWidth: 32, textAlign: 'right' }}>{points}分</span>
    </div>
  )
}

function RiskScoreBreakdown({ signals }: { signals: RiskSignal[] }) {
  const factors = deriveScoreFactors(signals)
  return (
    <div className="card">
      <div className="card-title">评分因素分解</div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 4 }}>
        {factors.map(f => (
          <div key={f.label} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 11, color: 'var(--text-muted)', minWidth: 56 }}>{f.label}</span>
            <div style={{ flex: 1 }}>
              <ScoreBreakdownBar points={f.points} max={f.max} />
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── ImpossibleTravelBanner ───────────────────────────────────────────────────

function parseTravelInfo(signals: RiskSignal[]): { minutes: number; from: string; to: string } | null {
  const sig = signals.find(s => s.type === 'impossible_travel')
  if (!sig) return null

  // Try metadata first
  const meta = sig.metadata as Record<string, string> | undefined
  if (meta?.from_location && meta?.to_location) {
    return {
      minutes: Number(meta.travel_minutes ?? meta.minutes ?? 60),
      from: String(meta.from_location),
      to: String(meta.to_location),
    }
  }

  // Try parsing description: "N分钟内从X到Y" or "from X to Y in N minutes"
  const desc = sig.description ?? sig.detail ?? ''
  const zhMatch = desc.match(/(\d+)\s*分钟.+?从\s*(.+?)\s*到\s*(.+?)(?:[，,。\s]|$)/)
  if (zhMatch) return { minutes: Number(zhMatch[1]), from: zhMatch[2], to: zhMatch[3] }

  const enMatch = desc.match(/from\s+(.+?)\s+to\s+(.+?)\s+in\s+(\d+)\s*min/i)
  if (enMatch) return { minutes: Number(enMatch[3]), from: enMatch[1], to: enMatch[2] }

  return null
}

interface TravelBannerProps {
  signals: RiskSignal[]
  onDismiss: () => void
}

function ImpossibleTravelBanner({ signals, onDismiss }: TravelBannerProps) {
  const info = parseTravelInfo(signals)
  const message = info
    ? `检测到不可能旅行: 在 ${info.minutes} 分钟内从 ${info.from} 到 ${info.to}`
    : '检测到不可能旅行: 地理位置跳变异常'

  return (
    <div style={{
      background: 'rgba(249,115,22,0.12)',
      border: '1px solid rgba(249,115,22,0.35)',
      borderRadius: 6,
      padding: '8px 12px',
      display: 'flex',
      alignItems: 'flex-start',
      justifyContent: 'space-between',
      gap: 8,
      flexShrink: 0,
    }}>
      <span style={{ fontSize: 11.5, color: 'var(--high)', lineHeight: 1.5 }}>
        ⚠️ {message}
      </span>
      <button
        onClick={onDismiss}
        style={{
          background: 'none', border: 'none', cursor: 'pointer',
          color: 'var(--high)', fontSize: 15, lineHeight: 1, padding: '0 2px',
          flexShrink: 0, marginTop: 1,
        }}
        title="关闭"
      >×</button>
    </div>
  )
}

// ─── Signal Timeline ──────────────────────────────────────────────────────────

function SignalTimeline({ signals }: { signals: RiskSignal[] }) {
  if (signals.length === 0) {
    return (
      <div className="card">
        <div className="card-title">风险信号时间轴</div>
        <div style={{
          display: 'flex', flexDirection: 'column', alignItems: 'center',
          gap: 8, padding: '24px 0', color: 'var(--text-muted)',
        }}>
          <svg width="32" height="32" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.5">
            <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" />
          </svg>
          <span style={{ fontSize: 12 }}>暂无信号</span>
        </div>
      </div>
    )
  }

  return (
    <div className="card">
      <div className="card-title">风险信号时间轴 ({signals.length})</div>
      {/* Timeline container — border-left acts as the connecting line */}
      <div style={{ borderLeft: '2px solid rgba(255,255,255,0.08)', marginLeft: 7, marginTop: 8, paddingLeft: 0 }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {signals.map((s, i) => {
            const typeColor = signalTypeColor(s.type)
            const dotColor = s.severity
              ? signalDotColor(
                  s.severity === 'critical' ? 90 :
                  s.severity === 'high' ? 70 :
                  s.severity === 'medium' ? 50 : 30
                )
              : signalDotColor(s.score)

            return (
              <div key={i} style={{ position: 'relative', paddingLeft: 20 }}>
                {/* Connector dot */}
                <div style={{
                  position: 'absolute',
                  left: -5,
                  top: 10,
                  width: 8,
                  height: 8,
                  borderRadius: '50%',
                  background: typeColor,
                  boxShadow: `0 0 6px ${typeColor}88`,
                }} />

                {/* Signal card */}
                <div style={{
                  background: 'rgba(255,255,255,0.03)',
                  border: `1px solid rgba(255,255,255,0.07)`,
                  borderLeft: `3px solid ${typeColor}`,
                  borderRadius: '0 6px 6px 0',
                  padding: '8px 10px',
                }}>
                  {/* Top row: badge + severity dot + timestamp */}
                  <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 4 }}>
                    <span style={{
                      fontSize: 9.5, padding: '1px 6px', borderRadius: 3, fontWeight: 600,
                      background: `${typeColor}22`, color: typeColor,
                      border: `1px solid ${typeColor}44`,
                      letterSpacing: 0.2,
                    }}>
                      {s.type}
                    </span>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      {/* Severity dot */}
                      <div style={{ width: 7, height: 7, borderRadius: '50%', background: dotColor, boxShadow: `0 0 4px ${dotColor}88` }} />
                      <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>{relativeTime(s.detected_at)}</span>
                    </div>
                  </div>
                  {/* Description */}
                  <div style={{ fontSize: 11.5, color: 'var(--text-secondary)', lineHeight: 1.45 }}>
                    {s.description ?? s.detail ?? ''}
                  </div>
                  {/* Score */}
                  {s.score > 0 && (
                    <div style={{ fontSize: 10.5, color: dotColor, marginTop: 3, fontWeight: 600 }}>
                      +{s.score.toFixed(0)} 分
                    </div>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

// ─── PrivilegeRestrictions panel ──────────────────────────────────────────────

interface PrivilegeRestrictionsPanelProps {
  userId: string
}

function PrivilegeRestrictionsPanel({ userId }: PrivilegeRestrictionsPanelProps) {
  const [restrictions, setRestrictions] = useState<PrivilegeRestriction[]>([])
  const [loading, setLoading] = useState(true)
  const [releasing, setReleasing] = useState(false)
  const [showAddForm, setShowAddForm] = useState(false)
  const [addTypes, setAddTypes] = useState<string[]>([])
  const [addReason, setAddReason] = useState('')
  const [addExpiry, setAddExpiry] = useState('')
  const [addSubmitting, setAddSubmitting] = useState(false)
  const [toast, setToast] = useState('')

  function fetchRestrictions() {
    setLoading(true)
    api.get('/privilege_restrictions', { params: { user_id: userId } })
      .then(r => setRestrictions(r.data.data?.items ?? r.data.data ?? []))
      .catch(() => setRestrictions([]))
      .finally(() => setLoading(false))
  }

  useEffect(() => { fetchRestrictions() }, [userId])

  function showToast(msg: string) {
    setToast(msg)
    setTimeout(() => setToast(''), 3000)
  }

  function releaseAll() {
    setReleasing(true)
    api.put('/privilege_restrictions/release', { user_id: userId })
      .then(() => { fetchRestrictions(); showToast('已释放全部限制') })
      .finally(() => setReleasing(false))
  }

  function toggleType(t: string) {
    setAddTypes(prev => prev.includes(t) ? prev.filter(x => x !== t) : [...prev, t])
  }

  function submitAdd() {
    if (!addReason.trim() || addTypes.length === 0) return
    setAddSubmitting(true)
    api.post('/privilege_restrictions', {
      user_id: userId,
      types: addTypes,
      reason: addReason.trim(),
      expires_at: addExpiry || undefined,
    })
      .then(() => {
        setShowAddForm(false)
        setAddTypes([])
        setAddReason('')
        setAddExpiry('')
        fetchRestrictions()
        showToast('限制已添加')
      })
      .finally(() => setAddSubmitting(false))
  }

  const restrictionTypeChipStyle = (active: boolean): React.CSSProperties => ({
    fontSize: 10, padding: '2px 8px', borderRadius: 3, cursor: 'pointer',
    background: active ? 'rgba(168,85,247,0.25)' : 'rgba(255,255,255,0.06)',
    color: active ? 'var(--accent-blue)' : 'var(--text-muted)',
    border: `1px solid ${active ? 'rgba(168,85,247,0.4)' : 'rgba(255,255,255,0.1)'}`,
    userSelect: 'none',
  })

  return (
    <div className="card">
      {toast && (
        <div style={{
          position: 'absolute', bottom: 16, right: 16, zIndex: 100,
          background: 'rgba(34,197,94,0.15)', border: '1px solid rgba(34,197,94,0.35)',
          borderRadius: 6, padding: '6px 14px', fontSize: 12, color: 'var(--accent-green)',
        }}>
          {toast}
        </div>
      )}

      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <span className="card-title" style={{ margin: 0 }}>权限限制状态</span>
          {!loading && (
            <span style={{
              fontSize: 10, padding: '1px 6px', borderRadius: 10, fontWeight: 600,
              background: restrictions.length > 0 ? 'rgba(239,68,68,0.2)' : 'rgba(34,197,94,0.15)',
              color: restrictions.length > 0 ? 'var(--critical)' : 'var(--accent-green)',
            }}>
              {restrictions.length}
            </span>
          )}
        </div>
        <div style={{ display: 'flex', gap: 6 }}>
          {restrictions.length > 0 && (
            <button
              className="btn-secondary"
              style={{ fontSize: 10, padding: '2px 10px', color: 'var(--critical)', borderColor: 'rgba(239,68,68,0.3)' }}
              disabled={releasing}
              onClick={releaseAll}
            >
              {releasing ? '释放中...' : '释放全部限制'}
            </button>
          )}
          <button
            className="btn-secondary"
            style={{ fontSize: 10, padding: '2px 10px' }}
            onClick={() => setShowAddForm(v => !v)}
          >
            添加限制
          </button>
        </div>
      </div>

      {loading ? (
        <div style={{ fontSize: 11.5, color: 'var(--text-muted)', padding: '8px 0' }}>加载中...</div>
      ) : restrictions.length === 0 && !showAddForm ? (
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12, color: 'var(--accent-green)' }}>
          <span>✓</span>
          <span>当前无权限限制</span>
        </div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
          {restrictions.map(r => (
            <div key={r._key} style={{
              background: 'rgba(255,255,255,0.03)',
              border: '1px solid rgba(255,255,255,0.07)',
              borderRadius: 6,
              padding: '8px 10px',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 4, marginBottom: 4, flexWrap: 'wrap' }}>
                <span style={restrictionTypeChipStyle(true)}>
                  {RESTRICTION_TYPE_LABEL[r.type] ?? r.type}
                </span>
              </div>
              {r.reason && (
                <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 3 }}>{r.reason}</div>
              )}
              {r.expires_at && (
                <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>到期: {fmtDate(r.expires_at)}</div>
              )}
            </div>
          ))}
        </div>
      )}

      {/* Add restriction form */}
      {showAddForm && (
        <div style={{
          marginTop: 10, borderTop: '1px solid rgba(255,255,255,0.06)',
          paddingTop: 10, display: 'flex', flexDirection: 'column', gap: 8,
        }}>
          <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 2 }}>限制类型</div>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {(['disable_login', 'revoke_sessions', 'read_only'] as const).map(t => (
              <span
                key={t}
                style={restrictionTypeChipStyle(addTypes.includes(t))}
                onClick={() => toggleType(t)}
              >
                {RESTRICTION_TYPE_LABEL[t]}
              </span>
            ))}
          </div>
          <input
            className="filter-input"
            style={{ fontSize: 12 }}
            placeholder="限制原因（必填）"
            value={addReason}
            onChange={e => setAddReason(e.target.value)}
          />
          <input
            className="filter-input"
            style={{ fontSize: 12 }}
            type="datetime-local"
            placeholder="到期时间（可选）"
            value={addExpiry}
            onChange={e => setAddExpiry(e.target.value)}
          />
          <div style={{ display: 'flex', gap: 6, justifyContent: 'flex-end' }}>
            <button className="btn-secondary" style={{ fontSize: 11, padding: '3px 12px' }} onClick={() => setShowAddForm(false)}>取消</button>
            <button
              className="btn-primary"
              style={{ fontSize: 11, padding: '3px 12px' }}
              disabled={addSubmitting || addTypes.length === 0 || !addReason.trim()}
              onClick={submitAdd}
            >
              {addSubmitting ? '提交中...' : '确认添加'}
            </button>
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Add Signal form ──────────────────────────────────────────────────────────

interface AddSignalFormProps {
  userId: string
  onSuccess: () => void
}

function AddSignalForm({ userId, onSuccess }: AddSignalFormProps) {
  const [show, setShow] = useState(false)
  const [sigType, setSigType] = useState('')
  const [sigSeverity, setSigSeverity] = useState('medium')
  const [sigScore, setSigScore] = useState<number | ''>('')
  const [sigDesc, setSigDesc] = useState('')
  const [sigMeta, setSigMeta] = useState('')
  const [metaErr, setMetaErr] = useState('')
  const [submitting, setSubmitting] = useState(false)
  const [toast, setToast] = useState(false)

  function validateMeta(v: string): boolean {
    if (!v.trim()) return true
    try { JSON.parse(v); setMetaErr(''); return true }
    catch { setMetaErr('无效的 JSON 格式'); return false }
  }

  function submit() {
    if (!sigType || sigScore === '' || !sigDesc.trim()) return
    if (!validateMeta(sigMeta)) return
    setSubmitting(true)
    const payload: Record<string, unknown> = {
      type: sigType,
      score: Number(sigScore),
      severity: sigSeverity,
      description: sigDesc.trim(),
    }
    if (sigMeta.trim()) {
      try { payload.metadata = JSON.parse(sigMeta) } catch { /* validated above */ }
    }
    api.post(`/identity_risks/${userId}/signal`, payload)
      .then(() => {
        setShow(false)
        setSigType('')
        setSigSeverity('medium')
        setSigScore('')
        setSigDesc('')
        setSigMeta('')
        setToast(true)
        setTimeout(() => setToast(false), 3000)
        onSuccess()
      })
      .finally(() => setSubmitting(false))
  }

  return (
    <div className="card" style={{ padding: 0, overflow: 'hidden', position: 'relative' }}>
      {toast && (
        <div style={{
          position: 'absolute', top: -40, right: 0, zIndex: 100,
          background: 'rgba(34,197,94,0.15)', border: '1px solid rgba(34,197,94,0.35)',
          borderRadius: 6, padding: '5px 14px', fontSize: 12, color: 'var(--accent-green)',
          whiteSpace: 'nowrap',
        }}>
          ✓ 信号已添加
        </div>
      )}
      <button
        onClick={() => setShow(v => !v)}
        style={{
          width: '100%', background: 'none', border: 'none', cursor: 'pointer',
          padding: '10px 14px', display: 'flex', alignItems: 'center',
          justifyContent: 'space-between', color: 'var(--text-secondary)',
          fontSize: 12, fontWeight: 500,
        }}
      >
        <span>添加信号</span>
        <span style={{
          fontSize: 10, color: 'var(--text-muted)', transition: 'transform .2s',
          display: 'inline-block', transform: show ? 'rotate(180deg)' : 'rotate(0deg)',
        }}>▼</span>
      </button>

      {show && (
        <div style={{ padding: '0 14px 14px', display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div style={{ height: 1, background: 'rgba(255,255,255,0.06)', marginBottom: 2 }} />

          {/* Signal type select */}
          <select
            className="filter-input"
            style={{ fontSize: 12 }}
            value={sigType}
            onChange={e => setSigType(e.target.value)}
          >
            <option value="">-- 选择信号类型 --</option>
            {SIGNAL_TYPE_OPTIONS.map(t => (
              <option key={t} value={t}>{t}</option>
            ))}
          </select>

          {/* Severity select */}
          <select
            className="filter-input"
            style={{ fontSize: 12 }}
            value={sigSeverity}
            onChange={e => setSigSeverity(e.target.value)}
          >
            {SEVERITY_OPTIONS.map(s => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>

          {/* Score */}
          <input
            className="filter-input"
            style={{ fontSize: 12 }}
            type="number"
            min={0}
            max={100}
            placeholder="评分 0–100"
            value={sigScore}
            onChange={e => setSigScore(e.target.value === '' ? '' : Number(e.target.value))}
          />

          {/* Description textarea */}
          <textarea
            className="filter-input"
            style={{ fontSize: 12, resize: 'vertical', minHeight: 60, fontFamily: 'inherit' }}
            placeholder="详细描述..."
            value={sigDesc}
            onChange={e => setSigDesc(e.target.value)}
          />

          {/* Metadata JSON textarea */}
          <textarea
            className="filter-input"
            style={{
              fontSize: 12, resize: 'vertical', minHeight: 48, fontFamily: 'monospace',
              borderColor: metaErr ? 'rgba(239,68,68,0.5)' : undefined,
            }}
            placeholder='元数据（可选 JSON，如 {"from_location":"北京"}）'
            value={sigMeta}
            onChange={e => { setSigMeta(e.target.value); if (metaErr) validateMeta(e.target.value) }}
            onBlur={() => validateMeta(sigMeta)}
          />
          {metaErr && <div style={{ fontSize: 10.5, color: 'var(--critical)', marginTop: -4 }}>{metaErr}</div>}

          <button
            className="btn-primary"
            style={{ fontSize: 11, alignSelf: 'flex-end', padding: '4px 16px' }}
            disabled={submitting || !sigType || sigScore === '' || !sigDesc.trim()}
            onClick={submit}
          >
            {submitting ? '提交中...' : '提交'}
          </button>
        </div>
      )}
    </div>
  )
}

// ─── AnomalyDetectionSummary ──────────────────────────────────────────────────

interface AnomalyType {
  key: string
  label: string
  icon: string
  color: string
}

const ANOMALY_TYPES: AnomalyType[] = [
  { key: 'unusual_hours',      label: '异常时段',   icon: '🕐', color: 'var(--accent-blue)' },
  { key: 'impossible_travel',  label: '不可能旅行', icon: '🌍', color: 'var(--high)' },
  { key: 'new_device',         label: '新设备',     icon: '💻', color: 'var(--accent-blue)' },
  { key: 'data_exfiltration',  label: '数据渗漏',   icon: '📊', color: 'var(--critical)' },
]

function AnomalyDetectionSummary({ signals }: { signals: RiskSignal[] }) {
  const signalTypes = new Set(signals.map(s => s.type))
  const detected = ANOMALY_TYPES.filter(a => signalTypes.has(a.key))
  const count = detected.length

  return (
    <div className="card" style={{ background: 'rgba(59,130,246,0.06)', border: '1px solid rgba(59,130,246,0.2)' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
        <span style={{ fontSize: 12, fontWeight: 600, color: count > 0 ? 'var(--accent-blue)' : 'var(--text-secondary)' }}>
          {count > 0 ? `检测到 ${count} 个行为异常` : '未检测到行为异常'}
        </span>
        {count > 0 && (
          <span style={{
            fontSize: 10, padding: '1px 7px', borderRadius: 10, fontWeight: 700,
            background: 'rgba(239,68,68,0.2)', color: 'var(--critical)',
          }}>{count}</span>
        )}
      </div>
      <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
        {ANOMALY_TYPES.map(a => {
          const active = signalTypes.has(a.key)
          return (
            <div key={a.key} style={{
              display: 'flex', alignItems: 'center', gap: 5,
              padding: '5px 10px', borderRadius: 6,
              background: active ? `${a.color}18` : 'rgba(255,255,255,0.04)',
              border: `1px solid ${active ? `${a.color}44` : 'rgba(255,255,255,0.08)'}`,
              opacity: active ? 1 : 0.45,
              transition: 'opacity .2s',
            }}>
              <span style={{ fontSize: 14, filter: active ? 'none' : 'grayscale(1)' }}>{a.icon}</span>
              <span style={{ fontSize: 11, color: active ? a.color : 'var(--text-muted)', fontWeight: active ? 600 : 400 }}>
                {a.label}
              </span>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ─── RiskScoreHistoryChart ────────────────────────────────────────────────────

function scoreColor(score: number): string {
  if (score >= 85) return 'var(--critical)'
  if (score >= 70) return 'var(--high)'
  if (score >= 40) return 'var(--medium)'
  return 'var(--accent-green)'
}

function generateHistory(key: string, currentScore: number): number[] {
  const rand = seededRand(hashKey(key))
  const points: number[] = []
  // Start at a value close to current
  let val = Math.max(5, Math.min(95, currentScore + (rand() - 0.5) * 20))
  for (let i = 0; i < 29; i++) {
    points.push(Math.round(val))
    const delta = (rand() - 0.5) * 20
    val = Math.max(0, Math.min(100, val + delta))
  }
  points.push(currentScore) // last point is always current
  return points
}

interface TooltipState {
  x: number
  y: number
  day: number
  score: number
  visible: boolean
}

function RiskScoreHistoryChart({
  identity,
}: {
  identity: IdentityRisk
}) {
  const [tooltip, setTooltip] = useState<TooltipState>({ x: 0, y: 0, day: 0, score: 0, visible: false })
  const scores = generateHistory(identity._key, identity.risk_score ?? 0)

  const W = 300
  const H = 100
  const PAD = { top: 8, right: 8, bottom: 24, left: 28 }
  const chartW = W - PAD.left - PAD.right
  const chartH = H - PAD.top - PAD.bottom

  const xOf = (i: number) => PAD.left + (i / 29) * chartW
  const yOf = (v: number) => PAD.top + chartH - (v / 100) * chartH

  const polyline = scores.map((v, i) => `${xOf(i)},${yOf(v)}`).join(' ')

  // Gradient area path
  const areaPath =
    `M${xOf(0)},${yOf(scores[0])} ` +
    scores.slice(1).map((v, i) => `L${xOf(i + 1)},${yOf(v)}`).join(' ') +
    ` L${xOf(29)},${PAD.top + chartH} L${xOf(0)},${PAD.top + chartH} Z`

  const min = Math.min(...scores)
  const max = Math.max(...scores)
  const avg = Math.round(scores.reduce((a, b) => a + b, 0) / scores.length)
  const lineColor = scoreColor(identity.risk_score ?? 0)

  // Day the current score was set (last day = index 29)
  const scoreSetDay = 29

  // Y grid lines at 0, 25, 50, 75, 100
  const gridVals = [0, 25, 50, 75, 100]

  const today = new Date()
  function dayLabel(i: number): string {
    const d = new Date(today)
    d.setDate(d.getDate() - (29 - i))
    return `${d.getMonth() + 1}/${d.getDate()}`
  }

  function handleMouseMove(e: React.MouseEvent<SVGSVGElement>) {
    const rect = e.currentTarget.getBoundingClientRect()
    const mx = e.clientX - rect.left
    // Find closest point index
    const idx = Math.max(0, Math.min(29, Math.round(((mx - PAD.left) / chartW) * 29)))
    setTooltip({
      x: xOf(idx),
      y: yOf(scores[idx]),
      day: idx,
      score: scores[idx],
      visible: true,
    })
  }

  return (
    <div className="card">
      <div className="card-title" style={{ marginBottom: 8 }}>风险历史 (30天)</div>

      <div style={{ position: 'relative', display: 'inline-block' }}>
        <svg
          width={W}
          height={H}
          style={{ display: 'block', cursor: 'crosshair', userSelect: 'none' }}
          onMouseMove={handleMouseMove}
          onMouseLeave={() => setTooltip(t => ({ ...t, visible: false }))}
        >
          <defs>
            <linearGradient id={`histGrad-${identity._key}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={lineColor} stopOpacity="0.25" />
              <stop offset="100%" stopColor={lineColor} stopOpacity="0.02" />
            </linearGradient>
          </defs>

          {/* Grid lines */}
          {gridVals.map(v => (
            <g key={v}>
              <line
                x1={PAD.left} y1={yOf(v)}
                x2={PAD.left + chartW} y2={yOf(v)}
                stroke="rgba(255,255,255,0.06)" strokeWidth="1"
              />
              <text x={PAD.left - 4} y={yOf(v) + 3.5} textAnchor="end"
                fontSize="8" fill="rgba(255,255,255,0.3)">{v}</text>
            </g>
          ))}

          {/* X axis labels */}
          {[0, 7, 14, 21, 29].map(i => (
            <text key={i} x={xOf(i)} y={H - 4} textAnchor="middle"
              fontSize="8" fill="rgba(255,255,255,0.3)">{dayLabel(i)}</text>
          ))}

          {/* Area fill */}
          <path d={areaPath} fill={`url(#histGrad-${identity._key})`} />

          {/* Line */}
          <polyline
            points={polyline}
            fill="none"
            stroke={lineColor}
            strokeWidth="1.5"
            strokeLinejoin="round"
          />

          {/* Vertical red dashed line at score-set day */}
          <line
            x1={xOf(scoreSetDay)} y1={PAD.top}
            x2={xOf(scoreSetDay)} y2={PAD.top + chartH}
            stroke="#ef4444" strokeWidth="1"
            strokeDasharray="3,3" opacity="0.7"
          />
          <text x={xOf(scoreSetDay) - 3} y={PAD.top + 7}
            textAnchor="end" fontSize="8" fill="#ef4444" opacity="0.8">当前</text>

          {/* Hover crosshair + dot */}
          {tooltip.visible && (
            <g>
              <line
                x1={tooltip.x} y1={PAD.top}
                x2={tooltip.x} y2={PAD.top + chartH}
                stroke="rgba(255,255,255,0.2)" strokeWidth="1"
              />
              <circle cx={tooltip.x} cy={tooltip.y} r={3.5}
                fill={lineColor} stroke="white" strokeWidth="1.5" />
            </g>
          )}
        </svg>

        {/* Floating tooltip */}
        {tooltip.visible && (
          <div style={{
            position: 'absolute',
            left: Math.min(tooltip.x + 8, W - 90),
            top: Math.max(tooltip.y - 28, 0),
            background: 'rgba(15,20,30,0.92)',
            border: `1px solid ${lineColor}55`,
            borderRadius: 5,
            padding: '4px 8px',
            fontSize: 10.5,
            color: 'var(--text-secondary)',
            pointerEvents: 'none',
            whiteSpace: 'nowrap',
            zIndex: 10,
          }}>
            <span style={{ color: 'var(--text-muted)' }}>{dayLabel(tooltip.day)}</span>
            {' '}
            <span style={{ color: lineColor, fontWeight: 700 }}>{tooltip.score}</span>
          </div>
        )}
      </div>

      {/* Summary row */}
      <div style={{
        display: 'flex', gap: 16, marginTop: 8,
        fontSize: 11, color: 'var(--text-muted)',
      }}>
        <span>最高: <strong style={{ color: 'var(--critical)' }}>{max}</strong></span>
        <span>最低: <strong style={{ color: 'var(--accent-green)' }}>{min}</strong></span>
        <span>平均: <strong style={{ color: lineColor }}>{avg}</strong></span>
      </div>
    </div>
  )
}

// ─── PeerComparisonWidget ─────────────────────────────────────────────────────

function generatePeerScores(key: string, currentScore: number): Array<{ name: string; score: number; isSelf: boolean }> {
  const rand = seededRand(hashKey(key + '_peers'))
  const peerNames = ['User_A', 'User_B', 'User_C', 'User_D', 'User_E']
  const peers = peerNames.map(name => {
    const score = Math.round(Math.max(0, Math.min(100, currentScore + (rand() - 0.5) * 60)))
    return { name, score, isSelf: false }
  })
  // Insert self at a position based on score
  const self = { name: '当前用户', score: currentScore, isSelf: true }
  const all = [...peers, self].sort((a, b) => b.score - a.score)
  return all
}

function PeerComparisonWidget({ identity }: { identity: IdentityRisk }) {
  const currentScore = identity.risk_score ?? 0
  const peers = generatePeerScores(identity._key, currentScore)
  const maxScore = Math.max(...peers.map(p => p.score), 1)

  // What percentile is this user higher than?
  const peerScores = peers.filter(p => !p.isSelf).map(p => p.score)
  const lowerCount = peerScores.filter(s => s < currentScore).length
  const pct = Math.round((lowerCount / peerScores.length) * 100)

  return (
    <div className="card">
      <div className="card-title" style={{ marginBottom: 10 }}>与同组用户对比</div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {peers.map((p, i) => {
          const barW = maxScore > 0 ? (p.score / maxScore) * 100 : 0
          const color = p.isSelf ? 'var(--accent-blue, #3b82f6)' : scoreColor(p.score)
          return (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{
                fontSize: 10.5, minWidth: 52, textAlign: 'right',
                color: p.isSelf ? 'var(--accent-blue)' : 'var(--text-muted)',
                fontWeight: p.isSelf ? 700 : 400,
              }}>
                {p.name}
              </span>
              <div style={{ flex: 1, background: 'rgba(255,255,255,0.06)', borderRadius: 3, height: 8, overflow: 'hidden' }}>
                <div style={{
                  width: `${barW}%`, height: '100%',
                  background: color,
                  borderRadius: 3,
                  boxShadow: p.isSelf ? `0 0 6px ${color}99` : 'none',
                  transition: 'width .4s',
                }} />
              </div>
              <span style={{
                fontSize: 10.5, minWidth: 24, textAlign: 'right',
                color: p.isSelf ? 'var(--accent-blue)' : 'var(--text-muted)',
                fontWeight: p.isSelf ? 700 : 400,
              }}>
                {p.score}
              </span>
            </div>
          )
        })}
      </div>
      <div style={{
        marginTop: 10, fontSize: 11, color: 'var(--text-muted)',
        borderTop: '1px solid rgba(255,255,255,0.06)', paddingTop: 8,
      }}>
        该用户风险高于{' '}
        <strong style={{ color: pct >= 75 ? 'var(--critical)' : pct >= 50 ? 'var(--high)' : 'var(--accent-green)' }}>
          {pct}%
        </strong>
        {' '}的同组成员
      </div>
    </div>
  )
}

// ─── AutomatedResponsePanel ───────────────────────────────────────────────────

const AUTO_ACTIONS: Array<{ type: string; label: string }> = [
  { type: 'mfa_required',        label: '强制MFA' },
  { type: 'no_foreign_login',    label: '禁止境外登录' },
  { type: 'no_privileged_access', label: '限制特权访问' },
]

function AutomatedResponsePanel({ userId }: { userId: string }) {
  // Initial state: all false — no API call to load
  const [states, setStates] = useState<Record<string, boolean>>(() => {
    const m: Record<string, boolean> = {}
    for (const a of AUTO_ACTIONS) m[a.type] = false
    return m
  })
  const [collapsed, setCollapsed] = useState(false)

  function toggle(type: string) {
    const current = states[type] ?? false
    const next = !current
    setStates(s => ({ ...s, [type]: next }))
    api.post('/privilege_restrictions', {
      user_id: userId,
      restriction_type: type,
      enabled: next,
    }).catch(() => {
      // Revert on error
      setStates(s => ({ ...s, [type]: current }))
    })
  }

  return (
    <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
      {/* Collapsible header */}
      <button
        onClick={() => setCollapsed(v => !v)}
        style={{
          width: '100%', background: 'none', border: 'none', cursor: 'pointer',
          padding: '10px 14px', display: 'flex', alignItems: 'center',
          justifyContent: 'space-between', color: 'var(--text-secondary)',
          fontSize: 12, fontWeight: 500,
        }}
      >
        <span>自动响应</span>
        <span style={{
          fontSize: 10, color: 'var(--text-muted)', transition: 'transform .2s',
          display: 'inline-block', transform: collapsed ? 'rotate(0deg)' : 'rotate(180deg)',
        }}>▼</span>
      </button>

      {!collapsed && (
        <div style={{ padding: '0 14px 14px', display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div style={{ height: 1, background: 'rgba(255,255,255,0.06)', marginBottom: 2 }} />
          <style>{`
            .auto-toggle-input { display: none; }
            .auto-toggle-label {
              display: inline-block;
              width: 38px; height: 20px; border-radius: 10px;
              background: rgba(255,255,255,0.15);
              position: relative; cursor: pointer;
              transition: background .2s;
              flex-shrink: 0;
            }
            .auto-toggle-label::after {
              content: '';
              position: absolute;
              top: 2px; left: 2px;
              width: 16px; height: 16px;
              border-radius: 50%;
              background: white;
              box-shadow: 0 1px 3px rgba(0,0,0,0.4);
              transition: left .2s;
            }
            .auto-toggle-input:checked + .auto-toggle-label {
              background: var(--accent-green);
            }
            .auto-toggle-input:checked + .auto-toggle-label::after {
              left: 20px;
            }
          `}</style>
          {AUTO_ACTIONS.map(action => {
            const active = states[action.type] ?? false
            const id = `auto-toggle-${userId}-${action.type}`
            return (
              <div key={action.type} style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                padding: '8px 10px', borderRadius: 6,
                background: active ? 'rgba(34,197,94,0.07)' : 'rgba(255,255,255,0.03)',
                border: `1px solid ${active ? 'rgba(34,197,94,0.25)' : 'rgba(255,255,255,0.07)'}`,
                transition: 'background .2s, border-color .2s',
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                  <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{action.label}</span>
                  <span style={{
                    fontSize: 9.5, padding: '1px 6px', borderRadius: 10, fontWeight: 600,
                    background: active ? 'rgba(34,197,94,0.2)' : 'rgba(255,255,255,0.08)',
                    color: active ? 'var(--accent-green)' : 'var(--text-muted)',
                  }}>
                    {active ? '已激活' : '未激活'}
                  </span>
                </div>
                <input
                  type="checkbox"
                  id={id}
                  className="auto-toggle-input"
                  checked={active}
                  onChange={() => toggle(action.type)}
                />
                <label htmlFor={id} className="auto-toggle-label" title={active ? '点击关闭' : '点击开启'} />
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ─── UBA: Anomaly Timeline ────────────────────────────────────────────────────

interface AnomalyEvent {
  day: string      // e.g. "Mon"
  date: string     // e.g. "05/19"
  risk: 'high' | 'medium' | 'low'
  description: string
  offsetX: number  // 0..1 within that day column
}

const DAY_LABELS = ['Mon', 'Tue', 'Wed', 'Thu', 'Fri', 'Sat', 'Sun']

function generateAnomalyEvents(key: string): AnomalyEvent[] {
  const rand = seededRand(hashKey(key + '_uba_events'))
  const today = new Date()
  // Align to Monday of current week
  const dayOfWeek = today.getDay() === 0 ? 6 : today.getDay() - 1 // 0=Mon
  const events: AnomalyEvent[] = []

  for (let d = 0; d <= dayOfWeek; d++) {
    const numEvents = rand() < 0.4 ? 0 : rand() < 0.6 ? 1 : rand() < 0.8 ? 2 : 3
    for (let e = 0; e < numEvents; e++) {
      const r = rand()
      const risk: 'high' | 'medium' | 'low' = r < 0.25 ? 'high' : r < 0.6 ? 'medium' : 'low'
      const descriptions = {
        high: [
          '深夜特权操作被检测',
          '从未知IP访问管理系统',
          '批量数据导出 (>10k条)',
          '绕过MFA尝试',
        ],
        medium: [
          '非工作时间登录',
          '访问不常用资源',
          '多次密码错误',
          '从新设备登录',
        ],
        low: [
          '使用新浏览器登录',
          '短时间内多次API调用',
          '会话超时后重新登录',
          '读取敏感配置文件',
        ],
      }
      const descs = descriptions[risk]
      const desc = descs[Math.floor(rand() * descs.length)]
      const date = new Date(today)
      date.setDate(date.getDate() - (dayOfWeek - d))
      events.push({
        day: DAY_LABELS[d],
        date: `${date.getMonth() + 1}/${date.getDate()}`,
        risk,
        description: desc,
        offsetX: 0.15 + rand() * 0.7,
      })
    }
  }

  // Force a high-risk event 2 days ago (the anomaly spike)
  const twoDaysAgoIdx = Math.max(0, dayOfWeek - 2)
  const twoDaysAgo = new Date(today)
  twoDaysAgo.setDate(twoDaysAgo.getDate() - 2)
  events.push({
    day: DAY_LABELS[twoDaysAgoIdx],
    date: `${twoDaysAgo.getMonth() + 1}/${twoDaysAgo.getDate()}`,
    risk: 'high',
    description: '异常行为峰值: 大量特权操作集中发生',
    offsetX: 0.5,
  })

  return events
}

function AnomalyTimeline({ userKey }: { userKey: string }) {
  const [hoveredEvent, setHoveredEvent] = useState<(AnomalyEvent & { ex: number; ey: number }) | null>(null)
  const events = generateAnomalyEvents(userKey)
  const today = new Date()
  const dayOfWeek = today.getDay() === 0 ? 6 : today.getDay() - 1

  const riskColor = { high: 'var(--critical)', medium: 'var(--high)', low: 'var(--accent-blue)' }
  const COL_W = 100 / 7 // percent per day

  return (
    <div className="card">
      <div className="card-title" style={{ marginBottom: 12 }}>本周异常事件时间轴</div>
      <div style={{ position: 'relative', height: 64, marginBottom: 4 }}>
        {/* Base line */}
        <div style={{
          position: 'absolute', top: 28, left: 0, right: 0,
          height: 2, background: 'rgba(255,255,255,0.08)', borderRadius: 1,
        }} />

        {/* Day columns + labels */}
        {DAY_LABELS.map((day, di) => {
          const isPast = di <= dayOfWeek
          return (
            <div key={day} style={{
              position: 'absolute',
              left: `${di * COL_W}%`,
              width: `${COL_W}%`,
              top: 0,
              height: '100%',
            }}>
              {/* Day label */}
              <div style={{
                position: 'absolute', bottom: 0, left: 0, right: 0,
                textAlign: 'center', fontSize: 9.5,
                color: isPast ? 'var(--text-muted)' : 'rgba(255,255,255,0.18)',
              }}>
                {day}
              </div>
              {/* Tick mark */}
              <div style={{
                position: 'absolute', top: 24, left: '50%',
                width: 1, height: 8,
                background: isPast ? 'rgba(255,255,255,0.15)' : 'rgba(255,255,255,0.06)',
                transform: 'translateX(-50%)',
              }} />
            </div>
          )
        })}

        {/* Today marker */}
        <div style={{
          position: 'absolute',
          left: `${(dayOfWeek + 0.5) * COL_W}%`,
          top: 18,
          transform: 'translateX(-50%)',
          fontSize: 8,
          color: 'var(--accent-blue)',
          fontWeight: 700,
          pointerEvents: 'none',
        }}>今</div>

        {/* Event dots */}
        {events.map((ev, i) => {
          const dayIdx = DAY_LABELS.indexOf(ev.day)
          if (dayIdx < 0) return null
          const leftPct = (dayIdx + ev.offsetX) * COL_W
          return (
            <div
              key={i}
              onMouseEnter={e => {
                const rect = (e.currentTarget.closest('.card') as HTMLElement)?.getBoundingClientRect()
                setHoveredEvent({ ...ev, ex: e.clientX - (rect?.left ?? 0), ey: e.clientY - (rect?.top ?? 0) })
              }}
              onMouseLeave={() => setHoveredEvent(null)}
              style={{
                position: 'absolute',
                left: `${leftPct}%`,
                top: 22,
                width: ev.risk === 'high' ? 10 : ev.risk === 'medium' ? 8 : 7,
                height: ev.risk === 'high' ? 10 : ev.risk === 'medium' ? 8 : 7,
                borderRadius: '50%',
                background: riskColor[ev.risk],
                boxShadow: `0 0 6px ${riskColor[ev.risk]}99`,
                transform: 'translate(-50%, -50%)',
                cursor: 'pointer',
                zIndex: 2,
                transition: 'transform .15s',
              }}
            />
          )
        })}
      </div>

      {/* Legend */}
      <div style={{ display: 'flex', gap: 12, marginTop: 4 }}>
        {(['high', 'medium', 'low'] as const).map(r => (
          <div key={r} style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
            <div style={{ width: 7, height: 7, borderRadius: '50%', background: riskColor[r] }} />
            <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
              {r === 'high' ? '高风险' : r === 'medium' ? '中风险' : '低风险'}
            </span>
          </div>
        ))}
      </div>

      {/* Hover tooltip */}
      {hoveredEvent && (
        <div style={{
          position: 'absolute',
          left: Math.min(hoveredEvent.ex + 8, 300),
          top: hoveredEvent.ey - 42,
          background: 'rgba(15,20,30,0.95)',
          border: `1px solid ${riskColor[hoveredEvent.risk]}66`,
          borderRadius: 6,
          padding: '5px 10px',
          fontSize: 11,
          color: 'var(--text-secondary)',
          pointerEvents: 'none',
          zIndex: 20,
          maxWidth: 220,
          whiteSpace: 'normal' as React.CSSProperties['whiteSpace'],
        }}>
          <div style={{ color: riskColor[hoveredEvent.risk], fontWeight: 600, marginBottom: 2 }}>
            {hoveredEvent.day} {hoveredEvent.date}
          </div>
          <div>{hoveredEvent.description}</div>
        </div>
      )}
    </div>
  )
}

// ─── UBA: Baseline Deviation Chart ───────────────────────────────────────────

function generateBaselineData(key: string): Array<{ date: string; user: number; baseline: number }> {
  const rand = seededRand(hashKey(key + '_baseline'))
  const today = new Date()
  return Array.from({ length: 7 }, (_, i) => {
    const d = new Date(today)
    d.setDate(d.getDate() - (6 - i))
    const dateStr = `${d.getMonth() + 1}/${d.getDate()}`
    const baseline = Math.round(8 + rand() * 6)  // 8-14 normal activity
    // Day 5 (2 days ago, index 4) is the spike
    const isAnomaly = i === 4
    const user = isAnomaly
      ? Math.round(baseline * (2.8 + rand() * 1.2))  // large spike
      : Math.round(baseline * (0.6 + rand() * 0.9))
    return { date: dateStr, user, baseline }
  })
}

function BaselineDeviationChart({ userKey }: { userKey: string }) {
  const data = generateBaselineData(userKey)
  return (
    <div className="card">
      <div className="card-title" style={{ marginBottom: 8 }}>活动量 vs 基线 (近7天)</div>
      <ResponsiveContainer width="100%" height={140}>
        <AreaChart data={data} margin={{ top: 4, right: 8, left: -16, bottom: 0 }}>
          <defs>
            <linearGradient id={`ubaBL-${userKey}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#3b82f6" stopOpacity="0.3" />
              <stop offset="100%" stopColor="#3b82f6" stopOpacity="0.02" />
            </linearGradient>
            <linearGradient id={`ubaUser-${userKey}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor="#ef4444" stopOpacity="0.35" />
              <stop offset="100%" stopColor="#ef4444" stopOpacity="0.02" />
            </linearGradient>
          </defs>
          <XAxis dataKey="date" tick={{ fontSize: 9, fill: 'rgba(255,255,255,0.35)' }} tickLine={false} axisLine={false} />
          <YAxis tick={{ fontSize: 9, fill: 'rgba(255,255,255,0.35)' }} tickLine={false} axisLine={false} />
          <ReTooltip
            contentStyle={{ background: 'rgba(15,20,30,0.92)', border: '1px solid rgba(255,255,255,0.12)', borderRadius: 6, fontSize: 11 }}
            labelStyle={{ color: 'var(--text-muted)' }}
            itemStyle={{ color: 'var(--text-secondary)' }}
          />
          <Legend
            iconSize={8}
            wrapperStyle={{ fontSize: 10, paddingTop: 4 }}
            formatter={(v: string) => v === 'user' ? '该用户' : '基线'}
          />
          <Area type="monotone" dataKey="baseline" stroke="#3b82f6" strokeWidth={1.5}
            fill={`url(#ubaBL-${userKey})`} name="baseline" dot={false} />
          <Area type="monotone" dataKey="user" stroke="#ef4444" strokeWidth={1.5}
            fill={`url(#ubaUser-${userKey})`} name="user" dot={false} />
        </AreaChart>
      </ResponsiveContainer>
    </div>
  )
}

// ─── UBA: Peer Behavior Comparison ───────────────────────────────────────────

interface BehaviorMetric {
  label: string
  userVal: number
  peerAvg: number
  unit: string
}

function generateBehaviorMetrics(key: string): BehaviorMetric[] {
  const rand = seededRand(hashKey(key + '_behavior'))
  return [
    {
      label: '登录频率',
      userVal: Math.round(3 + rand() * 12),
      peerAvg: Math.round(2 + rand() * 5),
      unit: '次/天',
    },
    {
      label: '非工作时间访问',
      userVal: Math.round(rand() * 8),
      peerAvg: Math.round(rand() * 2),
      unit: '次/周',
    },
    {
      label: '访问资源数',
      userVal: Math.round(5 + rand() * 20),
      peerAvg: Math.round(3 + rand() * 8),
      unit: '个',
    },
    {
      label: '认证失败',
      userVal: Math.round(rand() * 6),
      peerAvg: Math.round(rand() * 1.5),
      unit: '次/天',
    },
    {
      label: '特权操作',
      userVal: Math.round(rand() * 15),
      peerAvg: Math.round(rand() * 4),
      unit: '次/周',
    },
  ]
}

function UBAPeerComparison({ userKey }: { userKey: string }) {
  const metrics = generateBehaviorMetrics(userKey)
  return (
    <div className="card">
      <div className="card-title" style={{ marginBottom: 10 }}>行为指标 vs 同组基准</div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {metrics.map((m) => {
          const maxVal = Math.max(m.userVal, m.peerAvg, 1)
          const userPct = (m.userVal / maxVal) * 100
          const peerPct = (m.peerAvg / maxVal) * 100
          const isHigh = m.userVal > m.peerAvg * 1.5
          return (
            <div key={m.label}>
              <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                <span style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>{m.label}</span>
                <span style={{ fontSize: 10.5, color: isHigh ? 'var(--critical)' : 'var(--text-secondary)' }}>
                  {m.userVal} vs {m.peerAvg} <span style={{ color: 'var(--text-muted)' }}>{m.unit}</span>
                </span>
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                  <span style={{ fontSize: 9, color: isHigh ? 'var(--critical)' : 'var(--accent-blue)', minWidth: 40 }}>该用户</span>
                  <div style={{ flex: 1, height: 6, background: 'rgba(255,255,255,0.06)', borderRadius: 3, overflow: 'hidden' }}>
                    <div style={{
                      width: `${userPct}%`, height: '100%',
                      background: isHigh ? 'var(--critical)' : 'var(--accent-blue)',
                      borderRadius: 3, transition: 'width .4s',
                    }} />
                  </div>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                  <span style={{ fontSize: 9, color: 'var(--text-muted)', minWidth: 40 }}>基准</span>
                  <div style={{ flex: 1, height: 6, background: 'rgba(255,255,255,0.06)', borderRadius: 3, overflow: 'hidden' }}>
                    <div style={{
                      width: `${peerPct}%`, height: '100%',
                      background: 'rgba(100,116,139,0.6)',
                      borderRadius: 3, transition: 'width .4s',
                    }} />
                  </div>
                </div>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ─── UBA Tab ─────────────────────────────────────────────────────────────────

function UBATab({ identity }: { identity: IdentityRisk }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <AnomalyTimeline userKey={identity._key} />
      <BaselineDeviationChart userKey={identity._key} />
      <UBAPeerComparison userKey={identity._key} />
    </div>
  )
}

// ─── Privileged Operation Log ─────────────────────────────────────────────────

const PRIV_OPS = [
  '修改防火墙规则',
  '导出用户数据',
  '重置账户密码',
  '创建管理员账号',
  '访问加密密钥',
  '删除审计日志',
  '修改安全策略',
  '导出访问令牌',
  '修改RBAC权限',
  '访问生产数据库',
]

const PRIV_TARGETS = [
  'firewall-prod-01',
  'user_database',
  'admin_console',
  'key_vault',
  'audit_system',
  'iam_service',
  'prod_db_cluster',
  'oauth_server',
]

function generatePrivOps(key: string): Array<{
  timestamp: string
  operation: string
  target: string
  risk_level: 'critical' | 'high' | 'medium'
}> {
  const rand = seededRand(hashKey(key + '_privops'))
  const now = Date.now()
  return Array.from({ length: 5 }, (_, i) => {
    const minsAgo = Math.round(10 + rand() * 2880) // up to 2 days ago
    const ts = new Date(now - minsAgo * 60000)
    const op = PRIV_OPS[Math.floor(rand() * PRIV_OPS.length)]
    const target = PRIV_TARGETS[Math.floor(rand() * PRIV_TARGETS.length)]
    const r = rand()
    const risk_level: 'critical' | 'high' | 'medium' = r < 0.25 ? 'critical' : r < 0.6 ? 'high' : 'medium'
    return {
      timestamp: ts.toISOString(),
      operation: op,
      target,
      risk_level,
      _sort: i, // keep order
    }
  }).sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())
   .map(({ _sort: _s, ...rest }) => rest)
}

function PrivilegedOpLog({ userKey }: { userKey: string }) {
  const ops = generatePrivOps(userKey)
  const riskColor = { critical: 'var(--critical)', high: 'var(--high)', medium: 'var(--medium)' }
  return (
    <div className="card">
      <div className="card-title" style={{ marginBottom: 8 }}>特权操作日志 (近5条)</div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
        {ops.map((op, i) => (
          <div key={i} style={{
            display: 'grid',
            gridTemplateColumns: '80px 1fr 80px 44px',
            gap: 6,
            alignItems: 'center',
            padding: '5px 8px',
            borderRadius: 5,
            background: 'rgba(255,255,255,0.025)',
            border: '1px solid rgba(255,255,255,0.06)',
          }}>
            <span style={{ fontSize: 9.5, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
              {fmtDate(op.timestamp)}
            </span>
            <span style={{ fontSize: 11, color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {op.operation}
            </span>
            <span style={{ fontSize: 9.5, color: 'rgba(148,163,184,0.7)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
              {op.target}
            </span>
            <span style={{
              fontSize: 9, padding: '1px 5px', borderRadius: 3, fontWeight: 600,
              background: `${riskColor[op.risk_level]}20`,
              color: riskColor[op.risk_level],
              border: `1px solid ${riskColor[op.risk_level]}40`,
              textAlign: 'center',
            }}>
              {op.risk_level === 'critical' ? '严重' : op.risk_level === 'high' ? '高危' : '中危'}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Session Detail Enhancement ───────────────────────────────────────────────

const GEO_MAP: Array<{ flag: string; country: string; city: string }> = [
  { flag: '🇨🇳', country: '中国', city: '北京' },
  { flag: '🇨🇳', country: '中国', city: '上海' },
  { flag: '🇨🇳', country: '中国', city: '深圳' },
  { flag: '🇺🇸', country: '美国', city: 'New York' },
  { flag: '🇺🇸', country: '美国', city: 'San Francisco' },
  { flag: '🇬🇧', country: '英国', city: 'London' },
  { flag: '🇩🇪', country: '德国', city: 'Berlin' },
  { flag: '🇯🇵', country: '日本', city: 'Tokyo' },
  { flag: '🇸🇬', country: '新加坡', city: 'Singapore' },
  { flag: '🇰🇷', country: '韩国', city: 'Seoul' },
]

const DEVICE_OS = ['Windows 11', 'macOS 14.2', 'Ubuntu 22.04', 'Windows 10', 'macOS 13.6']
const DEVICE_BROWSERS = ['Chrome 124', 'Firefox 125', 'Edge 123', 'Safari 17']
const DEVICE_TYPES = ['桌面端', '移动端', '平板', '服务器']

function getSessionGeo(key: string): { flag: string; country: string; city: string } {
  const seed = hashKey(key)
  return GEO_MAP[seed % GEO_MAP.length]
}

function getDeviceFingerprint(key: string): { os: string; browser: string; deviceType: string } {
  const rand = seededRand(hashKey(key + '_dev'))
  return {
    os: DEVICE_OS[Math.floor(rand() * DEVICE_OS.length)],
    browser: DEVICE_BROWSERS[Math.floor(rand() * DEVICE_BROWSERS.length)],
    deviceType: DEVICE_TYPES[Math.floor(rand() * DEVICE_TYPES.length)],
  }
}

function hasMFA(key: string): boolean {
  return hashKey(key + '_mfa') % 3 !== 0 // ~67% have MFA
}

function getSessionRiskFactors(key: string): Array<{ icon: string; label: string; color: string }> {
  const rand = seededRand(hashKey(key + '_srf'))
  const allFactors = [
    { icon: '🕒', label: '非常规登录时间', color: 'var(--accent-blue)' },
    { icon: '📍', label: '异常地理位置', color: 'var(--high)' },
    { icon: '🔑', label: '特权账户访问', color: 'var(--accent-blue)' },
    { icon: '💻', label: '未知设备', color: 'var(--medium)' },
    { icon: '🌐', label: '境外IP访问', color: 'var(--critical)' },
    { icon: '🔄', label: '频繁会话切换', color: 'var(--accent-blue)' },
  ]
  const count = 1 + Math.floor(rand() * 3)
  const shuffled = [...allFactors].sort(() => rand() - 0.5)
  return shuffled.slice(0, count)
}

function SessionDetailCard({ userKey }: { userKey: string }) {
  const geo = getSessionGeo(userKey)
  const device = getDeviceFingerprint(userKey)
  const mfa = hasMFA(userKey)
  const riskFactors = getSessionRiskFactors(userKey)

  return (
    <div className="card">
      <div className="card-title" style={{ marginBottom: 10 }}>活跃会话详情</div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>

        {/* Geo location */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 8px', borderRadius: 5, background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)' }}>
          <span style={{ fontSize: 18 }}>{geo.flag}</span>
          <div>
            <div style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>{geo.country} · {geo.city}</div>
            <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>登录地理位置</div>
          </div>
        </div>

        {/* Device fingerprint */}
        <div style={{ padding: '6px 8px', borderRadius: 5, background: 'rgba(255,255,255,0.03)', border: '1px solid rgba(255,255,255,0.07)' }}>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 4 }}>设备指纹</div>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {[device.os, device.browser, device.deviceType].map((v, i) => (
              <span key={i} style={{
                fontSize: 10, padding: '1px 7px', borderRadius: 3,
                background: 'rgba(100,116,139,0.15)',
                color: 'rgba(148,163,184,0.9)',
                border: '1px solid rgba(255,255,255,0.08)',
              }}>{v}</span>
            ))}
          </div>
        </div>

        {/* MFA status */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{
            fontSize: 10.5, padding: '2px 10px', borderRadius: 10, fontWeight: 600,
            background: mfa ? 'rgba(34,197,94,0.15)' : 'rgba(239,68,68,0.15)',
            color: mfa ? 'var(--accent-green)' : 'var(--critical)',
            border: `1px solid ${mfa ? 'rgba(34,197,94,0.3)' : 'rgba(239,68,68,0.3)'}`,
          }}>
            {mfa ? '✓ 已通过MFA' : '✗ 未使用MFA'}
          </span>
        </div>

        {/* Risk factors */}
        {riskFactors.length > 0 && (
          <div>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 5 }}>风险因素</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {riskFactors.map((f, i) => (
                <div key={i} style={{
                  display: 'flex', alignItems: 'center', gap: 6,
                  padding: '4px 8px', borderRadius: 4,
                  background: `${f.color}10`,
                  border: `1px solid ${f.color}30`,
                }}>
                  <span style={{ fontSize: 13 }}>{f.icon}</span>
                  <span style={{ fontSize: 11, color: f.color, fontWeight: 500 }}>{f.label}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ─── DetailPanel ─────────────────────────────────────────────────────────────

interface DetailPanelProps {
  selected: IdentityRisk
  levelColor: Record<string, string>
  riskLevel: (score: number) => string
  travelDismissedKey: string | null
  setTravelDismissedKey: (key: string) => void
  onClose: () => void
  onNavigate: () => void
  onSignalAdded: () => void
}

function DetailPanel({
  selected,
  levelColor,
  riskLevel,
  travelDismissedKey,
  setTravelDismissedKey,
  onClose,
  onNavigate,
  onSignalAdded,
}: DetailPanelProps) {
  const [detailTab, setDetailTab] = useState<'overview' | 'history' | 'uba'>('overview')

  const lvl = riskLevel(selected.risk_score ?? 0)
  const selSignals = selected.risk_signals ?? []
  const selActiveAlerts = selSignals.filter(s => s.type === 'active_alert' || s.type === 'active_incident').length

  const sortedSignals = [...selSignals].sort(
    (a, b) => new Date(b.detected_at).getTime() - new Date(a.detected_at).getTime()
  )

  const hasTravelSignal = sortedSignals.some(s => s.type === 'impossible_travel')
  const showTravelBanner = hasTravelSignal && travelDismissedKey !== selected._key

  return (
    <div style={{
      width: 380, borderLeft: '1px solid var(--border)', background: 'var(--bg-drawer)',
      display: 'flex', flexDirection: 'column', overflow: 'hidden', flexShrink: 0,
    }}>
      {/* Panel header */}
      <div style={{
        padding: '12px 16px', borderBottom: '1px solid var(--border)',
        display: 'flex', justifyContent: 'space-between', alignItems: 'center',
      }}>
        <span style={{ fontSize: 13, fontWeight: 600 }}>用户风险详情</span>
        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px' }} onClick={onClose}>✕</button>
      </div>

      {/* Detail sub-tabs */}
      <div style={{
        display: 'flex', borderBottom: '1px solid var(--border)',
        background: 'var(--bg-card)',
      }}>
        {([['overview', '概览'], ['history', '风险历史'], ['uba', '行为分析']] as const).map(([tab, label]) => (
          <button
            key={tab}
            onClick={() => setDetailTab(tab)}
            style={{
              flex: 1, background: 'none', border: 'none', cursor: 'pointer',
              padding: '8px 0', fontSize: 11, fontWeight: detailTab === tab ? 600 : 400,
              color: detailTab === tab ? 'var(--accent-blue, #3b82f6)' : 'var(--text-muted)',
              borderBottom: detailTab === tab ? '2px solid var(--accent-blue, #3b82f6)' : '2px solid transparent',
              transition: 'color .15s, border-color .15s',
            }}
          >
            {label}
          </button>
        ))}
      </div>

      <div style={{ flex: 1, overflowY: 'auto', padding: 16, display: 'flex', flexDirection: 'column', gap: 12, position: 'relative' }}>
        {detailTab === 'overview' ? (
          <>
            {/* ── Impossible travel banner ── */}
            {showTravelBanner && (
              <ImpossibleTravelBanner
                signals={sortedSignals}
                onDismiss={() => setTravelDismissedKey(selected._key)}
              />
            )}

            {/* ── Anomaly Detection Summary ── */}
            <AnomalyDetectionSummary signals={sortedSignals} />

            {/* ── User summary card ── */}
            <div className="card">
              <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12 }}>
                <div style={{
                  width: 40, height: 40, borderRadius: '50%',
                  background: `linear-gradient(135deg, ${levelColor[lvl]}88, ${levelColor[lvl]}44)`,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: 14, fontWeight: 700, color: 'white', flexShrink: 0,
                }}>
                  {(selected.username || '?').slice(0, 2).toUpperCase()}
                </div>
                <div>
                  <div style={{ fontSize: 14, fontWeight: 600 }}>{selected.username}</div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                    {selected.domain ? `${selected.username}@${selected.domain}` : selected.username}
                  </div>
                </div>
              </div>
              <RiskScore score={selected.risk_score ?? 0} />
              <div style={{ marginTop: 12, display: 'flex', flexDirection: 'column', gap: 6 }}>
                {[
                  ['域', selected.domain || '-'],
                  ['风险等级', lvl],
                  ['活跃告警/事件', String(selActiveAlerts)],
                  ['最后更新', fmtDate(selected.updated_at)],
                  ['登录时段 P95', selected.baseline ? `${selected.baseline.login_hours_p95[0]}:00 – ${selected.baseline.login_hours_p95[1]}:00` : '-'],
                  ['典型城市', (selected.baseline?.typical_cities ?? []).join(', ') || '-'],
                ].map(([k, v]) => (
                  <div key={k} style={{
                    display: 'flex', justifyContent: 'space-between', fontSize: 11.5,
                    borderBottom: '1px solid rgba(255,255,255,.04)', paddingBottom: 4,
                  }}>
                    <span style={{ color: 'var(--text-muted)' }}>{k}</span>
                    <span style={{ color: 'var(--text-secondary)' }}>{v}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* ── Risk Score Breakdown ── */}
            <RiskScoreBreakdown signals={sortedSignals} />

            {/* ── Signal Timeline ── */}
            <SignalTimeline signals={sortedSignals} />

            {/* ── Automated Response ── */}
            <AutomatedResponsePanel userId={selected.user_id} />

            {/* ── Privilege Restrictions ── */}
            <PrivilegeRestrictionsPanel userId={selected.user_id} />

            {/* ── Navigation button ── */}
            <div style={{ display: 'flex', gap: 8 }}>
              <button
                className="btn-secondary"
                style={{ flex: 1, fontSize: 11 }}
                onClick={onNavigate}
              >
                查看告警
              </button>
            </div>

            {/* ── Session Detail Card ── */}
            <SessionDetailCard userKey={selected._key} />

            {/* ── Privileged Operation Log ── */}
            <PrivilegedOpLog userKey={selected._key} />

            {/* ── Add Signal ── */}
            <AddSignalForm userId={selected.user_id} onSuccess={onSignalAdded} />
          </>
        ) : detailTab === 'history' ? (
          <>
            {/* ── Risk Score History Chart ── */}
            <RiskScoreHistoryChart identity={selected} />

            {/* ── Peer Comparison Widget ── */}
            <PeerComparisonWidget identity={selected} />
          </>
        ) : (
          /* ── UBA Tab ── */
          <UBATab identity={selected} />
        )}
      </div>
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function IdentityRisks() {
  const navigate = useNavigate()
  const [items, setItems] = useState<IdentityRisk[]>([])
  const [meta, setMeta] = useState<PageMeta>({ page: 1, page_size: 20, total: 0, total_pages: 1 })
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [levelFilter, setLevelFilter] = useState('')
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<IdentityRisk | null>(null)
  const [travelDismissedKey, setTravelDismissedKey] = useState<string | null>(null)
  const mountedRef = useRef(false)

  function load(p = page) {
    setLoading(true)
    const params: Record<string, unknown> = { page: p, page_size: 20 }
    if (levelFilter) params.risk_level = levelFilter
    if (search) params.keyword = search
    api.get('/identity_risks', { params })
      .then(r => { setItems(r.data.data?.items ?? []); setMeta(r.data.data?.meta ?? meta) })
      .finally(() => setLoading(false))
  }

  useEffect(() => { load(page) }, [page])
  useEffect(() => {
    if (!mountedRef.current) { mountedRef.current = true; return }
    setPage(1); load(1)
  }, [levelFilter])

  function riskLevel(score: number): string {
    if (score >= 85) return 'critical'
    if (score >= 70) return 'high'
    if (score >= 40) return 'medium'
    return 'low'
  }

  const levelColor: Record<string, string> = {
    critical: 'var(--critical)',
    high: 'var(--high)',
    medium: 'var(--medium)',
    low: 'var(--accent-green)',
  }

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <PageHeader
        title="Identity Risks"
      />

      <div className="tab-bar">
        {[['All', ''], ['严重 ≥85', 'critical'], ['高危 ≥70', 'high'], ['中危', 'medium'], ['Low', 'low']].map(([label, val]) => (
          <button key={label} className={`tab ${levelFilter === val ? 'active' : ''}`}
            onClick={() => setLevelFilter(val)}>
            {label}
          </button>
        ))}
      </div>

      <div className="filter-bar">
        <input
          className="filter-input"
          placeholder="搜索用户名、邮箱、部门..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && load(1)}
        />
      </div>

      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        {/* ── Table ── */}
        <div className="data-table-wrap" style={{ flex: 1 }}>
          <table className="data-table">
            <thead>
              <tr>
                <ResizableTh>用户</ResizableTh>
                <ResizableTh>风险评分</ResizableTh>
                <ResizableTh>风险等级</ResizableTh>
                <ResizableTh>信号数</ResizableTh>
                <ResizableTh>活跃告警</ResizableTh>
                <ResizableTh>最近活动</ResizableTh>
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>加载中...</td></tr>
              )}
              {!loading && items.length === 0 && (
                <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>暂无身份风险</td></tr>
              )}
              {items.map(r => {
                const lvl = riskLevel(r.risk_score ?? 0)
                const signals = r.risk_signals ?? []
                const activeAlerts = signals.filter(s => s.type === 'active_alert' || s.type === 'active_incident').length
                return (
                  <tr key={r._key} onClick={() => setSelected(r)} className={selected?._key === r._key ? 'selected' : ''}>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                        <div style={{
                          width: 28, height: 28, borderRadius: '50%', flexShrink: 0,
                          background: `linear-gradient(135deg, ${levelColor[lvl]}88, ${levelColor[lvl]}44)`,
                          display: 'flex', alignItems: 'center', justifyContent: 'center',
                          fontSize: 10, fontWeight: 700, color: 'white',
                        }}>
                          {(r.username || '?').slice(0, 2).toUpperCase()}
                        </div>
                        <div>
                          <div style={{ fontSize: 12.5, fontWeight: 500 }}>{r.username}</div>
                          <div style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>
                            {r.domain ? `${r.username}@${r.domain}` : r.username}
                          </div>
                        </div>
                      </div>
                    </td>
                    <td><RiskScore score={r.risk_score ?? 0} /></td>
                    <td>
                      <span style={{
                        fontSize: 10.5, padding: '2px 8px', borderRadius: 3, fontWeight: 600,
                        background: `${levelColor[lvl]}22`,
                        color: levelColor[lvl],
                        border: `1px solid ${levelColor[lvl]}44`,
                        textTransform: 'uppercase', letterSpacing: 0.3,
                      }}>
                        {lvl}
                      </span>
                    </td>
                    <td>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
                        {signals.slice(0, 3).map((s, i) => (
                          <span key={i} style={{
                            fontSize: 9.5, padding: '1px 5px',
                            background: `${signalTypeColor(s.type)}18`,
                            color: signalTypeColor(s.type),
                            border: `1px solid ${signalTypeColor(s.type)}33`,
                            borderRadius: 3,
                          }}>{s.type}</span>
                        ))}
                        {signals.length > 3 && <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>+{signals.length - 3}</span>}
                      </div>
                    </td>
                    <td style={{ fontSize: 12 }}>
                      {activeAlerts > 0
                        ? <span style={{ color: 'var(--critical)', fontWeight: 600 }}>{activeAlerts}</span>
                        : <span style={{ color: 'var(--text-muted)' }}>0</span>}
                    </td>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{fmtDate(r.updated_at)}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>

        {/* ── Detail panel ── */}
        {selected && (
          <DetailPanel
            selected={selected}
            levelColor={levelColor}
            riskLevel={riskLevel}
            travelDismissedKey={travelDismissedKey}
            setTravelDismissedKey={setTravelDismissedKey}
            onClose={() => setSelected(null)}
            onNavigate={() => navigate(`/alerts?q=${encodeURIComponent(selected.username)}`)}
            onSignalAdded={() => load(page)}
          />
        )}
      </div>

      <div className="pagination">
        <button className="page-btn" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>&#8249;</button>
        <span>{page} / {meta.total_pages || 1}</span>
        <button className="page-btn" disabled={page >= meta.total_pages} onClick={() => setPage(p => p + 1)}>&#8250;</button>
        <span style={{ marginLeft: 8 }}>{meta.total} 条</span>
      </div>
    </div>
  )
}
