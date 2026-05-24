import { useEffect, useState, useRef, useCallback } from 'react'
import ResizableTh from '@/components/ResizableTh'
import { useNavigate } from 'react-router-dom'
import api from '@/lib/api'
import type { PageMeta } from '@/lib/api'
import PageHeader from '@/components/PageHeader'

// ─── Models ──────────────────────────────────────────────────────────────────

interface Incident {
  _key: string
  title: string
  name?: string          // backend also emits name
  status: string
  severity: string
  alert_count: number
  assigned_to: string
  assignee_name?: string
  tenant_id: string
  created_at: string
  updated_at: string
  first_seen?: string
  last_activity?: string
  resolved_at?: string
  mitre_tactic?: string
  mitre_tactics?: string[]
  host_count?: number
  smart_score?: number
  root_cause?: string
  description?: string
  affected_assets?: string[]
}

interface TimelineEvent {
  _key?: string
  event_type: string
  description: string
  actor?: string
  created_at: string
}

interface PlaybookItem {
  _key: string
  name: string
  status: string
  trigger_type: string
}

interface SmartScoreEntry {
  score: number
  factors?: Record<string, number>
  computed_at?: string
}

// ─── Constants ───────────────────────────────────────────────────────────────

// Backend statuses: new | investigating | in_progress | contained | resolved | closed
const STATUS_LABELS: Record<string, string> = {
  new: '新建', investigating: '调查中', in_progress: '处理中',
  contained: '已遏制', resolved: '已解决', closed: '已关闭',
}
const STATUS_COLORS: Record<string, string> = {
  new: 'var(--critical)', investigating: 'var(--accent-blue)', in_progress: 'var(--accent-blue)',
  contained: 'var(--medium)', resolved: 'var(--accent-green)', closed: 'var(--text-muted)',
}
const SEV_LABELS: Record<string, string> = {
  critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息',
}
const SEV_COLORS: Record<string, string> = {
  critical: 'var(--critical)', high: 'var(--high)', medium: 'var(--medium)', low: 'var(--accent-green)', info: 'var(--text-muted)',
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function fmtDate(iso: string | undefined) {
  if (!iso) return '-'
  try {
    const d = new Date(iso)
    if (isNaN(d.getTime())) return '-'
    const p = (n: number) => n.toString().padStart(2, '0')
    return `${d.getFullYear()}-${p(d.getMonth()+1)}-${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
  } catch { return '-' }
}

function fmtDuration(isoStart: string | undefined) {
  if (!isoStart) return '-'
  try {
    const ms = Date.now() - new Date(isoStart).getTime()
    const mins = Math.floor(ms / 60000)
    if (mins < 60) return `${mins}分钟`
    const hours = Math.floor(mins / 60)
    if (hours < 24) return `${hours}小时${mins % 60 ? (mins % 60) + '分' : ''}`
    return `${Math.floor(hours/24)}天${hours % 24 ? (hours % 24) + '时' : ''}`
  } catch { return '-' }
}

function timeAgo(iso: string | undefined) {
  if (!iso) return '-'
  try {
    const ms = Date.now() - new Date(iso).getTime()
    if (ms < 0) return '刚刚'
    const mins = Math.floor(ms / 60000)
    if (mins < 1) return '刚刚'
    if (mins < 60) return `${mins}分钟前`
    const hours = Math.floor(mins / 60)
    if (hours < 24) return `${hours}小时前`
    return `${Math.floor(hours / 24)}天前`
  } catch { return '-' }
}

function fmtResolveTime(created_at: string | undefined, resolved_at: string | undefined) {
  if (!created_at || !resolved_at) return null
  try {
    const ms = new Date(resolved_at).getTime() - new Date(created_at).getTime()
    if (isNaN(ms) || ms < 0) return null
    const h = Math.floor(ms / 3600000)
    const m = Math.floor((ms % 3600000) / 60000)
    return `${h}h ${m}m`
  } catch { return null }
}

function incidentTitle(inc: Incident) {
  return inc.title || inc.name || '(无标题)'
}

// ─── SLA helpers ─────────────────────────────────────────────────────────────

const SLA_HOURS: Record<string, number> = { P1: 4, P2: 8, P3: 24 }
const SEV_PRIORITY: Record<string, string> = {
  critical: 'P1', high: 'P2', medium: 'P3', low: 'P4', info: 'P4',
}

function slaInfo(inc: Incident): { status: 'ok' | 'at-risk' | 'breached'; remainMs: number; deadlineMs: number } {
  const priority = SEV_PRIORITY[inc.severity] ?? 'P4'
  const hours = SLA_HOURS[priority] ?? 72
  const createdMs = new Date(inc.created_at).getTime()
  const deadlineMs = createdMs + hours * 3600_000
  const now = Date.now()
  const remainMs = deadlineMs - now
  const totalMs = hours * 3600_000
  if (remainMs <= 0) return { status: 'breached', remainMs, deadlineMs }
  if (remainMs / totalMs < 0.2) return { status: 'at-risk', remainMs, deadlineMs }
  return { status: 'ok', remainMs, deadlineMs }
}

function fmtSlaRemain(ms: number): string {
  if (ms <= 0) return '已超时'
  const h = Math.floor(ms / 3600_000)
  const m = Math.floor((ms % 3600_000) / 60_000)
  if (h > 0) return `剩余 ${h}h${m > 0 ? m + 'm' : ''}`
  return `剩余 ${m}m`
}

// ─── Sub-components ──────────────────────────────────────────────────────────

function SevBadge({ sev }: { sev: string }) {
  const color = SEV_COLORS[sev] ?? 'var(--text-muted)'
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
  const c = STATUS_COLORS[status] ?? 'var(--text-muted)'
  const pulsing = status === 'new' || status === 'in_progress' || status === 'investigating'
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11.5 }}>
      <span style={{
        width: 6, height: 6, borderRadius: '50%', background: c, flexShrink: 0,
        boxShadow: pulsing ? `0 0 5px ${c}` : undefined,
      }} />
      <span style={{ color: c, fontWeight: pulsing ? 600 : 400 }}>
        {STATUS_LABELS[status] ?? status}
      </span>
    </span>
  )
}

function ScoreBadge({ score }: { score?: number }) {
  const s = score ?? 0
  if (s === 0) return <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>-</span>
  const color = s >= 80 ? 'var(--critical)' : s >= 60 ? 'var(--high)' : s >= 40 ? 'var(--medium)' : 'var(--accent-green)'
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
      minWidth: 30, height: 22, borderRadius: 4,
      background: color + '22', color, fontSize: 12, fontWeight: 700,
      border: `1px solid ${color}40`,
    }}>
      {s}
    </span>
  )
}

// ─── SmartScore Arc Gauge ─────────────────────────────────────────────────────

function SmartScoreGauge({ score }: { score?: number }) {
  const s = score ?? 0
  const color = s >= 80 ? 'var(--critical)' : s >= 60 ? 'var(--high)' : s >= 40 ? 'var(--medium)' : s > 0 ? 'var(--accent-green)' : 'var(--border)'
  const TOOLTIP = '基于告警数量、严重程度、资产价值和MITRE战术加权计算'

  // SVG arc: center (60,60), radius 48, arc from 210° to 330° (240° sweep)
  const cx = 60, cy = 60, r = 48
  const startDeg = 210, totalDeg = 240
  const toRad = (deg: number) => (deg * Math.PI) / 180
  const arcX = (deg: number) => cx + r * Math.cos(toRad(deg))
  const arcY = (deg: number) => cy + r * Math.sin(toRad(deg))

  const bgPath = [
    `M ${arcX(startDeg)} ${arcY(startDeg)}`,
    `A ${r} ${r} 0 1 1 ${arcX(startDeg + totalDeg)} ${arcY(startDeg + totalDeg)}`,
  ].join(' ')

  const fillDeg = s > 0 ? (s / 100) * totalDeg : 0
  const fillPath = fillDeg > 0 ? [
    `M ${arcX(startDeg)} ${arcY(startDeg)}`,
    `A ${r} ${r} 0 ${fillDeg > 180 ? 1 : 0} 1 ${arcX(startDeg + fillDeg)} ${arcY(startDeg + fillDeg)}`,
  ].join(' ') : ''

  if (s === 0) {
    return (
      <div
        title={TOOLTIP}
        style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6 }}
      >
        <svg width={120} height={70} viewBox="0 0 120 80">
          <path d={bgPath} fill="none" stroke="var(--border)" strokeWidth={10} strokeLinecap="round" />
          <text x={cx} y={cy + 8} textAnchor="middle" fill="var(--text-muted)" fontSize={11}>计算中...</text>
        </svg>
        {/* Spinner */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          <svg width={14} height={14} viewBox="0 0 14 14" style={{ animation: 'spin 1s linear infinite' }}>
            <circle cx={7} cy={7} r={5} fill="none" stroke="var(--text-muted)" strokeWidth={2} strokeDasharray="18 8" />
          </svg>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>AI 风险评分</span>
        </div>
        <style>{`@keyframes spin { to { transform: rotate(360deg); transform-origin: 7px 7px; } }`}</style>
      </div>
    )
  }

  return (
    <div
      title={TOOLTIP}
      style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4, cursor: 'default' }}
    >
      <svg width={120} height={80} viewBox="0 0 120 80">
        {/* Track */}
        <path d={bgPath} fill="none" stroke="rgba(255,255,255,.08)" strokeWidth={10} strokeLinecap="round" />
        {/* Fill */}
        {fillPath && (
          <path d={fillPath} fill="none" stroke={color} strokeWidth={10} strokeLinecap="round"
            style={{ filter: `drop-shadow(0 0 5px ${color}80)` }} />
        )}
        {/* Score text */}
        <text x={cx} y={cy - 2} textAnchor="middle" fill={color} fontSize={22} fontWeight={800}
          fontFamily="system-ui, sans-serif">{s}</text>
        <text x={cx} y={cy + 14} textAnchor="middle" fill={color} fontSize={9} opacity={0.7}>/ 100</text>
      </svg>
      <span style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: -4 }}>AI 风险评分</span>
    </div>
  )
}

// ─── MITRE Heatmap (14 tactics) ───────────────────────────────────────────────

const ALL_TACTICS: string[] = [
  'Reconnaissance', 'Resource Development', 'Initial Access', 'Execution',
  'Persistence', 'Privilege Escalation', 'Defense Evasion', 'Credential Access',
  'Discovery', 'Lateral Movement', 'Collection', 'C&C',
  'Exfiltration', 'Impact',
]

function MitreHeatmap({ activeTactics }: { activeTactics?: string[] }) {
  const active = new Set((activeTactics ?? []).map(t => t.toLowerCase().replace(/\s+/g, '')))
  return (
    <div>
      <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 10 }}>
        ATT&amp;CK 战术覆盖 — 红色单元格表示本事件命中的战术
      </div>
      <div style={{
        display: 'grid',
        gridTemplateColumns: 'repeat(7, 1fr)',
        gap: 4,
      }}>
        {ALL_TACTICS.map(tactic => {
          const key = tactic.toLowerCase().replace(/\s+/g, '').replace(/&/g, '')
          const isActive = active.has(key) ||
            // also match partial / common aliases
            [...active].some(a => a.includes(key.slice(0, 6)) || key.includes(a.slice(0, 6)))
          const count = isActive ? 1 : 0
          return (
            <div
              key={tactic}
              title={`${tactic}${isActive ? ' — 已命中' : ''}`}
              style={{
                padding: '7px 5px 5px',
                borderRadius: 4,
                background: isActive ? 'rgba(224,80,80,.13)' : 'rgba(255,255,255,.04)',
                border: `1px solid ${isActive ? 'rgba(224,80,80,.33)' : 'rgba(255,255,255,.07)'}`,
                textAlign: 'center',
                cursor: 'default',
                transition: 'background .15s',
                position: 'relative',
              }}
            >
              {isActive && (
                <span style={{
                  position: 'absolute', top: -5, right: -5,
                  width: 14, height: 14, borderRadius: '50%',
                  background: 'var(--critical)', color: '#fff',
                  fontSize: 8, fontWeight: 800,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  boxShadow: '0 0 4px rgba(224,80,80,.6)',
                }}>
                  {count}
                </span>
              )}
              <div style={{
                width: '100%', height: 28, borderRadius: 3,
                background: isActive ? 'rgba(224,80,80,.25)' : 'var(--bg-card)',
                marginBottom: 5,
                display: 'flex', alignItems: 'center', justifyContent: 'center',
              }}>
                <span style={{ fontSize: 16 }}>
                  {isActive ? '🔴' : '⬛'}
                </span>
              </div>
              <div style={{
                fontSize: 8.5,
                color: isActive ? 'var(--critical)' : 'var(--text-muted)',
                fontWeight: isActive ? 700 : 400,
                lineHeight: 1.25,
                wordBreak: 'break-word',
              }}>
                {tactic}
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ─── SLA Dot ─────────────────────────────────────────────────────────────────

function SlaDot({ inc }: { inc: Incident }) {
  const { status, remainMs } = slaInfo(inc)
  const color = status === 'breached' ? 'var(--critical)' : status === 'at-risk' ? 'var(--high)' : 'var(--accent-green)'
  const tooltip = `SLA: ${fmtSlaRemain(remainMs)}`
  return (
    <span
      title={tooltip}
      style={{
        display: 'inline-block',
        width: 7, height: 7, borderRadius: '50%',
        background: color, flexShrink: 0,
        boxShadow: status !== 'ok' ? `0 0 5px ${color}` : undefined,
        cursor: 'default',
      }}
    />
  )
}

// ─── Incident Drawer ─────────────────────────────────────────────────────────

interface DrawerProps {
  inc: Incident | null
  onClose: () => void
  onRefresh: () => void
}

function IncidentDrawer({ inc, onClose, onRefresh }: DrawerProps) {
  const navigate = useNavigate()
  const [tab, setTab] = useState('overview')
  const [scoreData, setScoreData] = useState<SmartScoreEntry | null>(null)
  const [alerts, setAlerts] = useState<any[]>([])
  const [alertsLoading, setAlertsLoading] = useState(false)
  const [timeline, setTimeline] = useState<TimelineEvent[]>([])
  const [timelineLoading, setTimelineLoading] = useState(false)
  const [playbooks, setPlaybooks] = useState<PlaybookItem[]>([])
  const [playbooksLoading, setPlaybooksLoading] = useState(false)
  const [executingPb, setExecutingPb] = useState<string | null>(null)
  const [alertFeed, setAlertFeed] = useState<any[]>([])
  const [alertFeedLoading, setAlertFeedLoading] = useState(false)
  const [note, setNote] = useState('')
  const [savingNote, setSavingNote] = useState(false)
  const [assignInput, setAssignInput] = useState('')
  const [assigning, setAssigning] = useState(false)
  const [resolving, setResolving] = useState(false)
  const [recalcingScore, setRecalcingScore] = useState(false)
  const [aiSummary, setAiSummary] = useState<string | null>(null)
  const [aiSummaryLoading, setAiSummaryLoading] = useState(false)
  const [aiSummaryError, setAiSummaryError] = useState(false)

  // Reset state when incident changes
  const prevKey = useRef<string | null>(null)
  useEffect(() => {
    if (!inc) {
      prevKey.current = null
      setScoreData(null); setAlerts([]); setTimeline([]); setPlaybooks([])
      setAlertFeed([])
      setNote(''); setAssignInput(''); setAssigning(false)
    setAiSummary(null); setAiSummaryLoading(false); setAiSummaryError(false)
      return
    }
    if (inc._key === prevKey.current) return
    prevKey.current = inc._key
    setTab('overview')
    setScoreData(null); setAlerts([]); setTimeline([]); setPlaybooks([])
    setAlertFeed([])
    setNote(''); setAssignInput(''); setAssigning(false)
    setAiSummary(null); setAiSummaryLoading(false); setAiSummaryError(false)

    // Load score + alerts for overview
    api.get(`/incidents/${inc._key}/smart_score`)
      .then(r => setScoreData(r.data.data))
      .catch(() => setScoreData(null))

    setAlertsLoading(true)
    api.get(`/incidents/${inc._key}/alerts`)
      .then(r => setAlerts(r.data.data?.items ?? []))
      .catch(() => setAlerts([]))
      .finally(() => setAlertsLoading(false))
  }, [inc?._key])

  // Load timeline lazily (on first visit to tab)
  useEffect(() => {
    if (!inc || tab !== 'timeline') return
    if (timeline.length > 0 || timelineLoading) return
    setTimelineLoading(true)
    api.get(`/incidents/${inc._key}/timeline`)
      .then(r => {
        const items = r.data.data?.items ?? r.data.data ?? []
        setTimeline(items)
      })
      .catch(() => {
        // Build synthetic timeline from incident fields
        const evts: TimelineEvent[] = [{
          event_type: 'created',
          description: `事件创建，关联 ${inc.alert_count} 条告警`,
          created_at: inc.first_seen ?? inc.created_at,
        }]
        if (inc.assigned_to) evts.push({
          event_type: 'assigned',
          description: `分配给 ${inc.assigned_to}`,
          created_at: inc.updated_at,
        })
        if (inc.status !== 'new') evts.push({
          event_type: 'status',
          description: `状态变更为「${STATUS_LABELS[inc.status] ?? inc.status}」`,
          created_at: inc.last_activity ?? inc.updated_at,
        })
        setTimeline(evts)
      })
      .finally(() => setTimelineLoading(false))
  }, [inc?._key, tab])

  // Load playbooks lazily
  useEffect(() => {
    if (!inc || tab !== 'playbooks') return
    if (playbooks.length > 0 || playbooksLoading) return
    setPlaybooksLoading(true)
    api.get('/playbooks', { params: { page: 1, page_size: 50, status: 'active' } })
      .then(r => setPlaybooks(r.data.data?.items ?? []))
      .catch(() => setPlaybooks([]))
      .finally(() => setPlaybooksLoading(false))
  }, [inc?._key, tab])

  // Load alert-based feed for "时间线" tab
  useEffect(() => {
    if (!inc || tab !== 'alertfeed') return
    if (alertFeed.length > 0 || alertFeedLoading) return
    setAlertFeedLoading(true)
    api.get('/alerts', { params: { incident_id: inc._key, page_size: 20, sort_by: 'triggered_at', sort_desc: false } })
      .then(r => {
        const items = r.data.data?.items ?? r.data.data ?? []
        setAlertFeed(items)
      })
      .catch(() => setAlertFeed([]))
      .finally(() => setAlertFeedLoading(false))
  }, [inc?._key, tab])

  // Load AI summary lazily
  useEffect(() => {
    if (!inc || tab !== 'aisummary') return
    if (aiSummary !== null || aiSummaryLoading) return
    setAiSummaryLoading(true)
    setAiSummaryError(false)
    api.get(`/incidents/${inc._key}/summary`)
      .then(r => {
        const text: string = r.data.data?.summary ?? r.data.summary ?? ''
        setAiSummary(text || '暂无摘要内容')
      })
      .catch(() => {
        setAiSummaryError(true)
        setAiSummary(null)
      })
      .finally(() => setAiSummaryLoading(false))
  }, [inc?._key, tab])

  function resolve() {
    if (!inc || resolving) return
    setResolving(true)
    api.patch(`/incidents/${inc._key}`, { status: 'resolved' })
      .then(() => { onRefresh(); onClose() })
      .finally(() => setResolving(false))
  }

  function doAssign() {
    if (!assignInput.trim() || !inc) return
    api.patch(`/incidents/${inc._key}`, { assigned_to: assignInput.trim() })
      .then(() => { setAssigning(false); setAssignInput(''); onRefresh() })
  }

  function saveNote() {
    if (!note.trim() || !inc) return
    setSavingNote(true)
    api.post(`/incidents/${inc._key}/notes`, { content: note })
      .then(() => {
        const entry: TimelineEvent = {
          event_type: 'note',
          description: note.length > 80 ? note.slice(0, 80) + '...' : note,
          actor: '当前用户',
          created_at: new Date().toISOString(),
        }
        setTimeline(prev => [entry, ...prev])
        setNote('')
      })
      .finally(() => setSavingNote(false))
  }

  function executePlaybook(pb: PlaybookItem) {
    if (!inc || executingPb) return
    setExecutingPb(pb._key)
    api.post(`/playbooks/${pb._key}/run`, { incident_id: inc._key })
      .then(() => {
        const entry: TimelineEvent = {
          event_type: 'playbook',
          description: `剧本「${pb.name}」已触发执行`,
          created_at: new Date().toISOString(),
        }
        setTimeline(prev => [entry, ...prev])
        setTab('timeline')
      })
      .finally(() => setExecutingPb(null))
  }

  function recalcScore() {
    if (!inc || recalcingScore) return
    setRecalcingScore(true)
    api.post(`/incidents/${inc._key}/smart_score/recalc`)
      .then(() => {
        return api.get(`/incidents/${inc._key}/smart_score`)
          .then(r => setScoreData(r.data.data))
          .catch(() => {})
          .finally(() => onRefresh())
      })
      .finally(() => setRecalcingScore(false))
  }

  const open = !!inc
  const score = scoreData?.score ?? inc?.smart_score ?? 0
  const scoreColor = score >= 80 ? 'var(--critical)' : score >= 60 ? 'var(--high)' : score >= 40 ? 'var(--medium)' : score > 0 ? 'var(--accent-green)' : 'var(--border)'
  const scoreLabel = score >= 80 ? '立即响应' : score >= 60 ? '尽快调查' : score >= 40 ? '需关注' : score > 0 ? '低风险' : '待评分'

  // Unique hosts/users from alerts
  const alertHosts = [...new Set(alerts.map((a: any) => a.host ?? a.asset_name).filter(Boolean))]
  const alertUsers = [...new Set(alerts.map((a: any) => a.user ?? a.user_name).filter(Boolean))]

  // MITRE map — prefer incident's own tactic, fall back to a curated set
  const MITRE_TECH: Record<string, string[]> = {
    'Initial Access':       ['T1566 鱼叉式钓鱼', 'T1190 利用公开服务漏洞'],
    'Execution':            ['T1059 脚本解释器滥用', 'T1203 客户端漏洞利用'],
    'Persistence':          ['T1053 计划任务/作业', 'T1547 启动项自启'],
    'Credential Access':    ['T1110 暴力破解', 'T1003 操作系统凭证转储'],
    'Lateral Movement':     ['T1021 远程服务利用', 'T1078 合法账户滥用'],
    'Defense Evasion':      ['T1055 进程注入', 'T1036 伪装合法进程'],
    'Command and Control':  ['T1071 应用层协议', 'T1095 非应用层协议'],
    'Exfiltration':         ['T1041 通过C2通道外泄', 'T1048 通过替代协议外泄'],
  }
  const primaryTactic = inc?.mitre_tactic ?? (inc?.mitre_tactics?.[0] ?? '')
  const mitreMap = primaryTactic
    ? { [primaryTactic]: MITRE_TECH[primaryTactic] ?? ['T1059 脚本解释器滥用'] }
    : Object.fromEntries(Object.entries(MITRE_TECH).slice(0, score >= 60 ? 8 : 3))

  const SIDE_TABS = [
    { id: 'overview',   label: '概览' },
    { id: 'aisummary',  label: 'AI摘要' },
    { id: 'alerts',     label: `告警 (${alerts.length || inc?.alert_count || 0})` },
    { id: 'alertfeed',  label: '时间线' },
    { id: 'timeline',   label: '时间轴' },
    { id: 'mitre',      label: 'MITRE ATT&CK' },
    { id: 'causality',  label: '溯源图' },
    { id: 'playbooks',  label: '剧本' },
    { id: 'notes',      label: '备注' },
  ]

  // event_type from backend: 'created' | 'assigned' | 'status' | 'note'
  // from SPA local: 'playbook'
  const evtColor: Record<string, string> = {
    created: 'var(--accent-blue)', assigned: 'var(--accent-blue)',
    status: 'var(--medium)', status_change: 'var(--medium)',
    note: 'var(--medium)', playbook: 'var(--accent-orange)',
    resolved: 'var(--accent-green)', alert: 'var(--critical)',
  }
  const evtLabel: Record<string, string> = {
    created: '创建', assigned: '分配', status: '状态变更',
    status_change: '状态变更', note: '备注', playbook: '剧本执行',
    resolved: '已解决', alert: '新告警',
  }

  const canResolve = inc && inc.status !== 'resolved' && inc.status !== 'closed'

  return (
    <>
      {/* Backdrop */}
      {open && (
        <div
          onClick={onClose}
          style={{
            position: 'fixed', inset: 0,
            background: 'var(--bg-overlay)',
            backdropFilter: 'blur(2px)',
            zIndex: 400,
          }}
        />
      )}

      {/* Drawer panel */}
      <div style={{
        position: 'fixed', top: 0, bottom: 0,
        right: open ? 0 : '-61.8vw',
        width: '61.8vw',
        background: 'var(--bg-drawer)',
        borderLeft: '1px solid var(--border-light)',
        zIndex: 500,
        transition: 'right .26s cubic-bezier(.4,0,.2,1)',
        display: 'flex', flexDirection: 'column', overflow: 'hidden',
        boxShadow: open ? '-12px 0 40px rgba(0,0,0,.45)' : 'none',
      }}>
        {inc && (
          <>
            {/* ── Header ────────────────────────────────────────── */}
            <div style={{
              padding: '14px 20px 12px',
              background: 'var(--bg-card2)',
              flexShrink: 0,
            }}>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 14 }}>
                {/* Score tile */}
                <div style={{
                  width: 52, height: 52, borderRadius: 10, flexShrink: 0,
                  background: scoreColor + '18', border: `2px solid ${scoreColor}44`,
                  display: 'flex', flexDirection: 'column',
                  alignItems: 'center', justifyContent: 'center',
                }}>
                  <span style={{ fontSize: 20, fontWeight: 800, color: scoreColor, lineHeight: 1 }}>
                    {score > 0 ? score : '?'}
                  </span>
                  <span style={{ fontSize: 8, color: scoreColor, opacity: 0.7, marginTop: 1 }}>分</span>
                </div>

                {/* Title + meta */}
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 10.5, color: 'var(--text-muted)', fontFamily: 'monospace', marginBottom: 3 }}>
                    INC-{inc._key.slice(-6).padStart(6, '0')}
                    &nbsp;·&nbsp;{fmtDuration(inc.first_seen ?? inc.created_at)} 前
                  </div>
                  <div style={{
                    fontSize: 15, fontWeight: 700, marginBottom: 8,
                    overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                  }}>
                    {incidentTitle(inc)}
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                    <SevBadge sev={inc.severity} />
                    <StatusBadge status={inc.status} />
                    <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                      告警&nbsp;<span style={{ color: 'var(--accent-orange)', fontWeight: 600 }}>{inc.alert_count}</span>
                    </span>
                    {(inc.host_count ?? 0) > 0 && (
                      <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                        主机&nbsp;<span style={{ color: 'var(--accent-blue)', fontWeight: 600 }}>{inc.host_count}</span>
                      </span>
                    )}
                    {primaryTactic && (
                      <span style={{
                        fontSize: 10.5, color: 'var(--accent-blue)',
                        background: 'rgba(59,158,222,.12)',
                        padding: '2px 7px', borderRadius: 3,
                      }}>
                        {primaryTactic}
                      </span>
                    )}
                    {inc.assigned_to
                      ? <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                          负责人:&nbsp;<span style={{ color: 'var(--text-secondary)' }}>{inc.assigned_to}</span>
                        </span>
                      : <span style={{ fontSize: 11, color: 'var(--high)', fontWeight: 500 }}>未分配</span>
                    }
                  </div>
                </div>

                {/* Action buttons */}
                <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexShrink: 0 }}>
                  <button
                    className="btn-secondary"
                    style={{ fontSize: 11 }}
                    onClick={() => navigate('/causality', { state: { incidentId: inc._key } })}
                  >
                    攻击链 →
                  </button>
                  <button
                    className="btn-secondary"
                    style={{ fontSize: 11 }}
                    onClick={() => setTab('playbooks')}
                  >
                    ▶ 执行剧本
                  </button>
                  <button
                    className="btn-secondary"
                    style={{ fontSize: 11 }}
                    onClick={() => { setAssignInput(inc.assigned_to ?? ''); setAssigning(v => !v) }}
                  >
                    分配
                  </button>
                  {canResolve && (
                    <button
                      className="btn-primary"
                      style={{ fontSize: 11, background: 'var(--accent-green)', border: 'none' }}
                      disabled={resolving}
                      onClick={resolve}
                    >
                      {resolving ? '处理中...' : '✓ 标记解决'}
                    </button>
                  )}
                  <button
                    onClick={onClose}
                    style={{
                      width: 28, height: 28, display: 'flex', alignItems: 'center', justifyContent: 'center',
                      background: 'none', border: '1px solid var(--border-light)',
                      borderRadius: 4, color: 'var(--text-muted)', cursor: 'pointer', fontSize: 14, flexShrink: 0,
                    }}
                  >
                    &#x2715;
                  </button>
                </div>
              </div>

              {/* Inline assign form */}
              {assigning && (
                <div style={{ display: 'flex', gap: 8, marginTop: 10, alignItems: 'center' }}>
                  <input
                    className="filter-input"
                    placeholder="输入用户名分配事件..."
                    value={assignInput}
                    onChange={e => setAssignInput(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && doAssign()}
                    style={{ flex: 1 }}
                    autoFocus
                  />
                  <button className="btn-primary" style={{ fontSize: 11 }} onClick={doAssign}>确认</button>
                  <button className="btn-secondary" style={{ fontSize: 11 }} onClick={() => setAssigning(false)}>取消</button>
                </div>
              )}
            </div>

            {/* ── Side-nav + content ────────────────────────────── */}
            <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
              {/* Side nav tabs */}
              <div style={{
                width: 128, flexShrink: 0,
                borderRight: '1px solid var(--border)',
                padding: '8px 0', overflowY: 'auto',
                background: 'var(--bg-secondary)',
              }}>
                {SIDE_TABS.map(t => (
                  <div
                    key={t.id}
                    onClick={() => setTab(t.id)}
                    style={{
                      padding: '9px 14px', fontSize: 12, cursor: 'pointer',
                      color: tab === t.id ? 'var(--text-primary)' : 'var(--text-secondary)',
                      background: tab === t.id ? 'rgba(59,158,222,.08)' : 'none',
                      borderLeft: `2px solid ${tab === t.id ? 'var(--accent-blue)' : 'transparent'}`,
                      transition: 'all .12s',
                      userSelect: 'none',
                    }}
                  >
                    {t.label}
                  </div>
                ))}
              </div>

              {/* Tab content area */}
              <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px' }}>

                {/* ── 概览 ───────────────────────────────────── */}
                {tab === 'overview' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>

                    {/* Score + Assets row */}
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 14 }}>
                      {/* SmartScore */}
                      <div className="card" style={{ padding: '14px 16px' }}>
                        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
                          <div className="card-title">AI 风险评分</div>
                          <button
                            className="btn-secondary"
                            style={{ fontSize: 10, padding: '2px 8px' }}
                            disabled={recalcingScore}
                            onClick={recalcScore}
                          >
                            {recalcingScore ? '计算中...' : '重新计算'}
                          </button>
                        </div>
                        {/* SVG Arc Gauge */}
                        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 10 }}>
                          <SmartScoreGauge score={score > 0 ? score : undefined} />
                          <div style={{ flex: 1 }}>
                            <div style={{ fontSize: 13, fontWeight: 600, color: scoreColor, marginBottom: 4 }}>
                              {scoreLabel}
                            </div>
                            <div style={{ fontSize: 10.5, color: 'var(--text-muted)', lineHeight: 1.5 }}>
                              {score >= 80 ? '该事件需立即响应，建议优先处置'
                               : score >= 60 ? '存在高威胁指标，需尽快调查'
                               : score >= 40 ? '存在中等威胁，建议关注跟进'
                               : score > 0  ? '威胁程度较低，可按序排期'
                               :              '综合告警、主机、战术等因素评估'}
                            </div>
                          </div>
                        </div>
                        {scoreData?.factors && Object.keys(scoreData.factors).length > 0 ? (
                          Object.entries(scoreData.factors).map(([k, v]) => {
                            const val = Math.round(v * 100) / 100
                            const barColor = val > 70 ? 'var(--critical)' : val > 40 ? 'var(--high)' : 'var(--medium)'
                            return (
                              <div key={k} style={{ marginBottom: 7 }}>
                                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 3 }}>
                                  <span style={{ fontSize: 10.5, color: 'var(--text-secondary)', textTransform: 'capitalize' }}>
                                    {k.replace(/_/g, ' ')}
                                  </span>
                                  <span style={{ fontSize: 10.5, fontWeight: 600, color: barColor }}>{val}</span>
                                </div>
                                <div style={{ height: 3, background: 'var(--border)', borderRadius: 2 }}>
                                  <div style={{ height: 3, width: `${Math.min(val, 100)}%`, background: barColor, borderRadius: 2, transition: 'width .4s' }} />
                                </div>
                              </div>
                            )
                          })
                        ) : (
                          <div style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.5 }}>
                            {score > 0 ? '综合告警数量、严重程度、主机资产价值及 MITRE 战术评估' : '暂无评分因子数据'}
                          </div>
                        )}
                      </div>

                      {/* Affected assets */}
                      <div className="card" style={{ padding: '14px 16px' }}>
                        <div className="card-title" style={{ marginBottom: 10 }}>受影响资产</div>
                        {alertsLoading && (
                          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>加载中...</div>
                        )}
                        {!alertsLoading && alertHosts.length === 0 && alertUsers.length === 0 && (
                          <div style={{ fontSize: 11, color: 'var(--text-muted)', padding: '8px 0' }}>
                            {inc.affected_assets?.length
                              ? inc.affected_assets.slice(0, 5).map(a => (
                                  <div key={a} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '4px 0' }}>
                                    <span>🖥</span>
                                    <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{a}</span>
                                  </div>
                                ))
                              : '告警数据中暂无主机信息'
                            }
                          </div>
                        )}
                        {alertHosts.length > 0 && (
                          <>
                            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: 0.4 }}>主机</div>
                            {alertHosts.slice(0, 5).map((h: string) => (
                              <div key={h} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '5px 0', borderBottom: '1px solid var(--border)' }}>
                                <span style={{ fontSize: 13 }}>🖥</span>
                                <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{h}</span>
                              </div>
                            ))}
                            {alertHosts.length > 5 && (
                              <div style={{ fontSize: 10.5, color: 'var(--text-muted)', paddingTop: 4 }}>
                                +{alertHosts.length - 5} 台主机
                              </div>
                            )}
                          </>
                        )}
                        {alertUsers.length > 0 && (
                          <>
                            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 10, marginBottom: 6, textTransform: 'uppercase', letterSpacing: 0.4 }}>涉及用户</div>
                            {alertUsers.slice(0, 3).map((u: string) => (
                              <div key={u} style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '4px 0' }}>
                                <span style={{ fontSize: 13 }}>👤</span>
                                <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{u}</span>
                              </div>
                            ))}
                          </>
                        )}
                        <div style={{ marginTop: 10, paddingTop: 8, borderTop: '1px solid var(--border)', fontSize: 11, color: 'var(--text-muted)' }}>
                          {inc.host_count ?? alertHosts.length} 台主机
                          {alertUsers.length > 0 ? ` · ${alertUsers.length} 个用户` : ''}
                        </div>
                      </div>
                    </div>

                    {/* Alert chain */}
                    <div className="card" style={{ padding: '14px 16px' }}>
                      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
                        <div className="card-title">关联告警链</div>
                        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{alerts.length} 条告警</span>
                      </div>
                      {alertsLoading && (
                        <div style={{ fontSize: 11.5, color: 'var(--text-muted)', padding: '12px 0', textAlign: 'center' }}>加载中...</div>
                      )}
                      {!alertsLoading && alerts.length === 0 && (
                        <div style={{ fontSize: 11.5, color: 'var(--text-muted)', padding: '12px 0', textAlign: 'center' }}>暂无关联告警数据</div>
                      )}
                      {alerts.slice(0, 6).map((a: any) => (
                        <div key={a._key ?? a.alert_id} style={{
                          display: 'flex', alignItems: 'center', gap: 10, padding: '8px 0',
                          borderBottom: '1px solid rgba(255,255,255,.04)',
                        }}>
                          <SevBadge sev={a.severity} />
                          <span style={{ fontSize: 10.5, color: 'var(--text-muted)', fontFamily: 'monospace', flexShrink: 0 }}>
                            {fmtDate(a.triggered_at ?? a.created_at)}
                          </span>
                          <span style={{ flex: 1, fontSize: 12, color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {a.name}
                          </span>
                          {(a.host ?? a.asset_name) && (
                            <span style={{ fontSize: 10.5, color: 'var(--accent-blue)', flexShrink: 0 }}>{a.host ?? a.asset_name}</span>
                          )}
                        </div>
                      ))}
                      {alerts.length > 6 && (
                        <div
                          style={{ fontSize: 11, color: 'var(--accent-blue)', padding: '8px 0', cursor: 'pointer' }}
                          onClick={() => setTab('alerts')}
                        >
                          查看全部 {alerts.length} 条告警 →
                        </div>
                      )}
                    </div>

                    {/* Root cause */}
                    {inc.root_cause && (
                      <div className="card" style={{ padding: '14px 16px', borderLeft: '3px solid var(--critical)' }}>
                        <div className="card-title" style={{ marginBottom: 6 }}>根因分析</div>
                        <div style={{ fontSize: 12.5, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                          {inc.root_cause}
                        </div>
                      </div>
                    )}

                    {/* Description */}
                    {inc.description && (
                      <div className="card" style={{ padding: '14px 16px' }}>
                        <div className="card-title" style={{ marginBottom: 6 }}>事件描述</div>
                        <div style={{ fontSize: 12.5, color: 'var(--text-secondary)', lineHeight: 1.6 }}>
                          {inc.description}
                        </div>
                      </div>
                    )}

                    {/* Time to resolve */}
                    {inc.resolved_at && (() => {
                      const dur = fmtResolveTime(inc.created_at, inc.resolved_at)
                      if (!dur) return null
                      return (
                        <div className="card" style={{ padding: '12px 16px', display: 'flex', alignItems: 'center', gap: 10 }}>
                          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>处置耗时:</span>
                          <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--accent-green)' }}>{dur}</span>
                        </div>
                      )
                    })()}
                  </div>
                )}

                {/* ── AI摘要 ─────────────────────────────────── */}
                {tab === 'aisummary' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

                    {/* AI Summary card */}
                    <div style={{
                      padding: '16px 18px',
                      background: 'var(--bg-card)',
                      border: '1px solid rgba(79,163,224,.35)',
                      borderLeft: '3px solid #4fa3e0',
                      borderRadius: 6,
                    }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 10 }}>
                        <span style={{ fontSize: 18 }}>🤖</span>
                        <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--accent-blue)' }}>AI 事件摘要</span>
                        {aiSummaryLoading && (
                          <span style={{ fontSize: 10.5, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 4 }}>
                            <svg width={12} height={12} viewBox="0 0 12 12"
                              style={{ animation: 'spin 1s linear infinite', flexShrink: 0 }}>
                              <circle cx={6} cy={6} r={4} fill="none" stroke="var(--accent-blue)" strokeWidth={2} strokeDasharray="14 6" />
                            </svg>
                            分析中...
                          </span>
                        )}
                      </div>
                      {aiSummaryLoading && (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
                          {[90, 75, 85, 60].map((w, i) => (
                            <div key={i} style={{
                              height: 10, width: `${w}%`, borderRadius: 4,
                              background: 'rgba(79,163,224,.12)',
                              animation: 'pulse 1.4s ease-in-out infinite',
                              animationDelay: `${i * 0.15}s`,
                            }} />
                          ))}
                          <style>{`
                            @keyframes pulse { 0%,100%{opacity:.4} 50%{opacity:.9} }
                            @keyframes spin { to { transform: rotate(360deg); transform-origin: 6px 6px; } }
                          `}</style>
                        </div>
                      )}
                      {!aiSummaryLoading && aiSummaryError && (
                        <div style={{
                          padding: '12px 14px', borderRadius: 5,
                          background: 'rgba(224,80,80,.06)', border: '1px solid rgba(224,80,80,.20)',
                          fontSize: 12.5, color: 'var(--critical)', lineHeight: 1.6,
                        }}>
                          AI摘要暂时不可用，请稍后重试。
                        </div>
                      )}
                      {!aiSummaryLoading && !aiSummaryError && aiSummary && (
                        <div style={{ fontSize: 13, color: 'var(--text-secondary)', lineHeight: 1.75 }}>
                          {aiSummary}
                        </div>
                      )}
                    </div>

                    {/* SmartScore explanation */}
                    {inc && (() => {
                      const sev = inc.severity ?? 'medium'
                      const alertCnt = inc.alert_count ?? 0
                      const tactics = inc.mitre_tactics ?? (inc.mitre_tactic ? [inc.mitre_tactic] : [])
                      const tacticCnt = tactics.length

                      // Compute mock sub-scores from real fields
                      const sevScore   = sev === 'critical' ? 40 : sev === 'high' ? 32 : sev === 'medium' ? 20 : 10
                      const alertScore = Math.min(20, Math.round(Math.log2(alertCnt + 1) * 5))
                      // asset value: derive from host_count; servers = 15, workstation = 10, other = 6
                      const assetType  = (inc.host_count ?? 0) > 3 ? '服务器集群' : (inc.host_count ?? 0) > 0 ? '服务器' : '工作站'
                      const assetScore = (inc.host_count ?? 0) > 3 ? 15 : (inc.host_count ?? 0) > 0 ? 12 : 8
                      const mitreScore = Math.min(15, tacticCnt * 4 + (tacticCnt > 0 ? 4 : 0))
                      const ageMins    = Math.floor((Date.now() - new Date(inc.created_at).getTime()) / 60000)
                      const ageDays    = Math.floor(ageMins / 1440)
                      const timeScore  = ageDays <= 1 ? 10 : ageDays <= 3 ? 7 : ageDays <= 7 ? 5 : 3
                      const timeLabel  = ageDays === 0 ? '今天' : ageDays === 1 ? '1天前' : `${ageDays}天前`

                      const rows: { label: string; weight: string; detail: string; score: number; color: string }[] = [
                        {
                          label: '严重程度', weight: '40%',
                          detail: `${SEV_LABELS[sev] ?? sev} → +${sevScore}分`,
                          score: sevScore, color: SEV_COLORS[sev] ?? 'var(--medium)',
                        },
                        {
                          label: '告警数量', weight: '20%',
                          detail: `${alertCnt}个告警 → +${alertScore}分`,
                          score: alertScore, color: 'var(--high)',
                        },
                        {
                          label: '资产价值', weight: '15%',
                          detail: `${assetType} → +${assetScore}分`,
                          score: assetScore, color: 'var(--accent-blue)',
                        },
                        {
                          label: 'MITRE覆盖', weight: '15%',
                          detail: `${tacticCnt}个战术 → +${mitreScore}分`,
                          score: mitreScore, color: 'var(--accent-blue)',
                        },
                        {
                          label: '时间因素', weight: '10%',
                          detail: `${timeLabel} → +${timeScore}分`,
                          score: timeScore, color: 'var(--accent-green)',
                        },
                      ]

                      return (
                        <div style={{
                          padding: '16px 18px',
                          background: 'var(--bg-card)',
                          border: '1px solid var(--border)',
                          borderRadius: 6,
                        }}>
                          <div style={{ fontSize: 12.5, fontWeight: 600, marginBottom: 14, color: 'var(--text-secondary)' }}>
                            SmartScore 构成
                          </div>
                          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                            {rows.map(row => (
                              <div key={row.label}>
                                <div style={{ display: 'flex', alignItems: 'baseline', gap: 6, marginBottom: 4 }}>
                                  <span style={{ fontSize: 10, color: 'var(--text-muted)', width: 68 }}>
                                    {row.label}
                                  </span>
                                  <span style={{
                                    fontSize: 9.5, color: row.color,
                                    background: row.color + '18',
                                    padding: '1px 5px', borderRadius: 3, flexShrink: 0,
                                  }}>
                                    {row.weight}
                                  </span>
                                  <span style={{ fontSize: 11.5, color: 'var(--text-secondary)', flex: 1 }}>
                                    {row.detail}
                                  </span>
                                  <span style={{ fontSize: 12, fontWeight: 700, color: row.color, flexShrink: 0 }}>
                                    +{row.score}
                                  </span>
                                </div>
                                <div style={{ height: 3, background: 'var(--border)', borderRadius: 2 }}>
                                  <div style={{
                                    height: 3,
                                    width: `${Math.min(row.score / 40 * 100, 100)}%`,
                                    background: row.color,
                                    borderRadius: 2,
                                    transition: 'width .4s',
                                  }} />
                                </div>
                              </div>
                            ))}
                          </div>
                          <div style={{
                            marginTop: 14, paddingTop: 10,
                            borderTop: '1px solid var(--border)',
                            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                          }}>
                            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>综合得分</span>
                            <span style={{
                              fontSize: 16, fontWeight: 800,
                              color: score >= 80 ? 'var(--critical)' : score >= 60 ? 'var(--high)' : score >= 40 ? 'var(--medium)' : 'var(--accent-green)',
                            }}>
                              {sevScore + alertScore + assetScore + mitreScore + timeScore} 分
                            </span>
                          </div>
                        </div>
                      )
                    })()}
                  </div>
                )}

                {/* ── 告警 ───────────────────────────────────── */}
                {tab === 'alerts' && (
                  <div>
                    {alertsLoading && (
                      <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>加载中...</div>
                    )}
                    {!alertsLoading && alerts.length === 0 && (
                      <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>暂无关联告警</div>
                    )}
                    {alerts.map((a: any) => (
                      <div key={a._key ?? a.alert_id} style={{
                        padding: '10px 14px', background: 'var(--bg-card)',
                        border: '1px solid var(--border)', borderRadius: 5, marginBottom: 6,
                      }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 4 }}>
                          {/* Colored severity dot */}
                          <span style={{
                            width: 8, height: 8, borderRadius: '50%', flexShrink: 0,
                            background: SEV_COLORS[a.severity] ?? 'var(--text-muted)',
                            boxShadow: `0 0 4px ${SEV_COLORS[a.severity] ?? 'var(--text-muted)'}80`,
                          }} />
                          <SevBadge sev={a.severity} />
                          <span style={{ flex: 1, fontSize: 12.5, fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {a.name}
                          </span>
                          <StatusBadge status={a.status ?? 'new'} />
                          <span style={{ fontSize: 10.5, color: 'var(--text-muted)', flexShrink: 0 }}>
                            {timeAgo(a.triggered_at ?? a.created_at)}
                          </span>
                        </div>
                        <div style={{ display: 'flex', gap: 14, fontSize: 11, color: 'var(--text-muted)' }}>
                          {(a.host ?? a.asset_name) && <span>🖥 {a.host ?? a.asset_name}</span>}
                          {(a.user ?? a.user_name) && <span>👤 {a.user ?? a.user_name}</span>}
                          {a.mitre_tactic && <span style={{ color: 'var(--accent-blue)' }}>🎯 {a.mitre_tactic}</span>}
                          {a.source_type && <span>{a.source_type}</span>}
                        </div>
                      </div>
                    ))}
                  </div>
                )}

                {/* ── 时间线 (alert feed) ────────────────────── */}
                {tab === 'alertfeed' && (
                  <div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 14 }}>
                      按时间顺序展示关联告警 — 最多 20 条
                    </div>
                    {alertFeedLoading && (
                      <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>加载中...</div>
                    )}
                    {!alertFeedLoading && alertFeed.length === 0 && (
                      <div style={{ padding: 40, textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>
                        无关联告警
                      </div>
                    )}
                    {alertFeed.length > 0 && (
                      <div style={{ position: 'relative', paddingLeft: 30 }}>
                        {/* Vertical line */}
                        <div style={{
                          position: 'absolute', left: 9, top: 8, bottom: 8, width: 1,
                          background: 'linear-gradient(to bottom, rgba(224,80,80,.5), transparent)',
                        }} />
                        {alertFeed.map((a: any, i: number) => {
                          const sev = a.severity ?? 'info'
                          const sevColor = SEV_COLORS[sev] ?? 'var(--text-muted)'
                          const ts = a.triggered_at ?? a.created_at
                          return (
                            <div key={a._key ?? i} style={{ marginBottom: 16, position: 'relative' }}>
                              {/* Dot */}
                              <div style={{
                                position: 'absolute', left: -30, top: 4,
                                width: 16, height: 16, borderRadius: '50%',
                                background: sevColor + '28', border: `2px solid ${sevColor}`,
                                display: 'flex', alignItems: 'center', justifyContent: 'center',
                              }}>
                                <div style={{ width: 5, height: 5, borderRadius: '50%', background: sevColor }} />
                              </div>
                              {/* Content */}
                              <div style={{
                                padding: '9px 12px',
                                background: 'var(--bg-card)',
                                border: `1px solid ${sevColor}30`,
                                borderRadius: 5,
                              }}>
                                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                                  <SevBadge sev={sev} />
                                  <span style={{ fontSize: 12, fontWeight: 500, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                    {a.name ?? '(无名称)'}
                                  </span>
                                  <span style={{ fontSize: 10, color: 'var(--text-muted)', flexShrink: 0, fontFamily: 'monospace' }}>
                                    {fmtDate(ts)}
                                  </span>
                                </div>
                                <div style={{ display: 'flex', gap: 10, fontSize: 10.5, color: 'var(--text-muted)' }}>
                                  {(a.host ?? a.asset_name) && <span>🖥 {a.host ?? a.asset_name}</span>}
                                  {(a.user ?? a.user_name) && <span>👤 {a.user ?? a.user_name}</span>}
                                  {a.mitre_tactic && <span style={{ color: 'var(--accent-blue)' }}>🎯 {a.mitre_tactic}</span>}
                                </div>
                              </div>
                            </div>
                          )
                        })}
                      </div>
                    )}
                  </div>
                )}

                {/* ── 时间轴 ─────────────────────────────────── */}
                {tab === 'timeline' && (
                  <div>
                    {timelineLoading && (
                      <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>加载中...</div>
                    )}
                    {!timelineLoading && timeline.length === 0 && (
                      <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>暂无时间轴记录</div>
                    )}

                    {/* Attack chain narrative */}
                    {inc && !timelineLoading && (
                      <div style={{
                        marginBottom: 20, padding: '13px 16px',
                        background: 'rgba(224,80,80,.05)',
                        border: '1px solid rgba(224,80,80,.2)',
                        borderLeft: '3px solid var(--critical)',
                        borderRadius: 6,
                      }}>
                        <div style={{ fontSize: 11.5, fontWeight: 600, color: 'var(--critical)', marginBottom: 6 }}>
                          攻击链叙述
                        </div>
                        <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.75 }}>
                          {(() => {
                            const dt = fmtDate(inc.first_seen ?? inc.created_at)
                            const host = alertHosts[0] ?? '未知主机'
                            const tactics = inc.mitre_tactics ?? (inc.mitre_tactic ? [inc.mitre_tactic] : [])
                            const primaryTac = tactics[0] ?? '未知战术'
                            const tacticChain = tactics.length > 1
                              ? tactics.slice(0, 4).join(' → ')
                              : '初始访问 → 执行 → 权限提升 → 横向移动'
                            return `攻击者于 ${dt} 首次在 ${host} 上发现可疑活动，随后通过 ${primaryTac} 技术进行横向移动。共触发 ${inc.alert_count} 条告警，涉及 ${(inc.host_count ?? alertHosts.length) || 1} 个资产。攻击链显示 ${tacticChain} 的典型APT攻击模式。`
                          })()}
                        </div>
                      </div>
                    )}

                    <div style={{ position: 'relative', paddingLeft: 28 }}>
                      <div style={{ position: 'absolute', left: 7, top: 8, bottom: 8, width: 1, background: 'var(--border)' }} />
                      {timeline.map((item, i) => {
                        const color = evtColor[item.event_type] ?? 'var(--accent-blue)'
                        const label = evtLabel[item.event_type] ?? item.event_type.replace(/_/g, ' ')
                        // Icon per event type
                        const icon = item.event_type === 'alert' ? '🚨'
                          : item.event_type === 'note' ? '📝'
                          : item.event_type === 'resolved' ? '✅'
                          : item.event_type === 'assigned' ? '👤'
                          : item.event_type === 'playbook' ? '▶'
                          : item.event_type === 'created' ? '🆕'
                          : '🔄'
                        return (
                          <div key={i} style={{ marginBottom: 18, position: 'relative' }}>
                            {/* Colored dot */}
                            <div style={{
                              position: 'absolute', left: -28, top: 3,
                              width: 14, height: 14, borderRadius: '50%',
                              background: color + '28', border: `2px solid ${color}`,
                              display: 'flex', alignItems: 'center', justifyContent: 'center',
                              fontSize: 7,
                            }}>
                              <div style={{ width: 5, height: 5, borderRadius: '50%', background: color }} />
                            </div>
                            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3, flexWrap: 'wrap' }}>
                              <span style={{ fontSize: 12 }}>{icon}</span>
                              <span style={{ fontSize: 11, fontWeight: 600, color }}>
                                {label}
                              </span>
                              {/* Relative time (prominent) + absolute (tooltip) */}
                              <span
                                title={fmtDate(item.created_at)}
                                style={{ fontSize: 10.5, color: 'var(--text-muted)', cursor: 'default' }}
                              >
                                {timeAgo(item.created_at)}
                              </span>
                              {item.actor && (
                                <span style={{
                                  fontSize: 10, color: 'var(--text-muted)',
                                  background: 'rgba(255,255,255,.05)',
                                  padding: '1px 6px', borderRadius: 10, border: '1px solid var(--border)',
                                }}>
                                  👤 {item.actor}
                                </span>
                              )}
                            </div>
                            <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                              {item.description}
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                )}

                {/* ── MITRE ATT&CK ───────────────────────────── */}
                {tab === 'mitre' && (
                  <div>
                    <div style={{ marginBottom: 14 }}>
                      {primaryTactic && (
                        <div style={{
                          display: 'inline-flex', alignItems: 'center', gap: 6,
                          padding: '4px 10px', marginBottom: 12,
                          background: 'rgba(250,88,45,.1)', border: '1px solid rgba(250,88,45,.3)',
                          borderRadius: 4, fontSize: 12,
                        }}>
                          <span style={{ color: 'var(--text-muted)' }}>主要战术:</span>
                          <span style={{ color: 'var(--accent-orange)', fontWeight: 600 }}>{primaryTactic}</span>
                        </div>
                      )}
                    </div>
                    {/* 14-tactic heatmap */}
                    <MitreHeatmap activeTactics={inc?.mitre_tactics ?? (inc?.mitre_tactic ? [inc.mitre_tactic] : [])} />
                    {/* Technique detail cards */}
                    {Object.keys(mitreMap).length > 0 && (
                      <div style={{ marginTop: 20 }}>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 10 }}>关联技术详情</div>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                          {Object.entries(mitreMap).map(([tactic, techs]) => (
                            <div key={tactic} className="card" style={{ padding: '12px 14px' }}>
                              <div style={{
                                fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase',
                                letterSpacing: 0.6, marginBottom: 8, fontWeight: 600,
                              }}>
                                {tactic}
                              </div>
                              {(techs ?? []).map((t: string) => {
                                const [id, ...rest] = t.split(' ')
                                return (
                                  <div key={t} style={{
                                    display: 'flex', alignItems: 'center', gap: 10,
                                    padding: '6px 10px', marginBottom: 4,
                                    background: 'rgba(250,88,45,.06)', border: '1px solid rgba(250,88,45,.15)',
                                    borderRadius: 4,
                                  }}>
                                    <span style={{
                                      fontFamily: 'monospace', fontSize: 10.5, color: 'var(--text-muted)',
                                      background: 'rgba(255,255,255,.04)', padding: '1px 5px', borderRadius: 3, flexShrink: 0,
                                    }}>
                                      {id}
                                    </span>
                                    <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{rest.join(' ')}</span>
                                  </div>
                                )
                              })}
                            </div>
                          ))}
                        </div>
                      </div>
                    )}
                  </div>
                )}

                {/* ── 溯源图 ─────────────────────────────────── */}
                {tab === 'causality' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
                    <div style={{ padding: '14px 16px', background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 6 }}>
                      <div style={{ fontSize: 12.5, fontWeight: 600, marginBottom: 6 }}>攻击溯源分析</div>
                      <div style={{ fontSize: 11.5, color: 'var(--text-muted)', lineHeight: 1.6, marginBottom: 14 }}>
                        溯源图展示本事件的完整攻击链路，涵盖涉及主机、进程、网络连接、文件操作等节点关系，
                        可辅助分析攻击根因与横向移动路径。
                      </div>
                      <a
                        href={`/causality?incident=${inc._key}`}
                        target="_blank"
                        rel="noopener noreferrer"
                        style={{ textDecoration: 'none' }}
                      >
                        <button className="btn-primary" style={{ fontSize: 12 }}>
                          在溯源图中打开 →
                        </button>
                      </a>
                    </div>
                    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 10 }}>
                      {[
                        { label: '关联告警', value: inc.alert_count, color: 'var(--critical)' },
                        { label: '涉及主机', value: inc.host_count ?? (alertHosts.length || '-'), color: 'var(--accent-blue)' },
                        { label: '持续时间', value: fmtDuration(inc.first_seen ?? inc.created_at), color: 'var(--medium)' },
                      ].map(({ label, value, color }) => (
                        <div key={label} style={{
                          padding: '12px', background: 'var(--bg-card)',
                          border: '1px solid var(--border)', borderRadius: 6, textAlign: 'center',
                        }}>
                          <div style={{ fontSize: 18, fontWeight: 700, color }}>{value}</div>
                          <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginTop: 3 }}>{label}</div>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* ── 剧本 ───────────────────────────────────── */}
                {tab === 'playbooks' && (
                  <div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 12 }}>
                      选择剧本自动响应 — 触发后将在时间轴中记录执行情况
                    </div>
                    {playbooksLoading && (
                      <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>加载中...</div>
                    )}
                    {!playbooksLoading && playbooks.length === 0 && (
                      <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>
                        暂无活跃剧本，请先在「剧本管理」中创建
                      </div>
                    )}
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                      {playbooks.map(pb => (
                        <div key={pb._key} style={{
                          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                          padding: '12px 14px', background: 'var(--bg-card)',
                          border: '1px solid var(--border)', borderRadius: 5,
                        }}>
                          <div>
                            <div style={{ fontSize: 13, fontWeight: 500 }}>{pb.name}</div>
                            <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginTop: 2 }}>
                              {pb.trigger_type === 'auto' ? '自动触发' : pb.trigger_type === 'manual' ? '手动触发' : pb.trigger_type}
                              &nbsp;·&nbsp;
                              {pb.status === 'active' ? '活跃' : pb.status === 'draft' ? '草稿' : pb.status}
                            </div>
                          </div>
                          <button
                            className="btn-primary"
                            style={{ fontSize: 11, padding: '5px 14px' }}
                            disabled={executingPb === pb._key}
                            onClick={() => executePlaybook(pb)}
                          >
                            {executingPb === pb._key ? '执行中...' : '▶ 执行'}
                          </button>
                        </div>
                      ))}
                    </div>
                  </div>
                )}

                {/* ── 备注 ───────────────────────────────────── */}
                {tab === 'notes' && (
                  <div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 10 }}>
                      调查备注会同步写入时间轴，便于团队协作追溯
                    </div>
                    <textarea
                      placeholder="添加调查备注、处置思路或进展更新..."
                      value={note}
                      onChange={e => setNote(e.target.value)}
                      style={{
                        width: '100%', minHeight: 130, boxSizing: 'border-box',
                        background: 'var(--bg-card)', border: '1px solid var(--border-light)',
                        borderRadius: 5, color: 'var(--text-primary)',
                        padding: '10px 12px', fontSize: 12.5, lineHeight: 1.6,
                        resize: 'vertical', outline: 'none', transition: 'border-color .15s',
                      }}
                      onFocus={e => (e.target.style.borderColor = 'var(--accent-blue)')}
                      onBlur={e => (e.target.style.borderColor = 'var(--border-light)')}
                    />
                    <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 8 }}>
                      <button
                        className="btn-primary"
                        style={{ minWidth: 90 }}
                        disabled={savingNote || !note.trim()}
                        onClick={saveNote}
                      >
                        {savingNote ? '保存中...' : '保存备注'}
                      </button>
                    </div>
                  </div>
                )}

              </div>
            </div>
          </>
        )}
      </div>
    </>
  )
}

// ─── Main List Page ───────────────────────────────────────────────────────────

export default function Incidents() {
  const [incidents, setIncidents] = useState<Incident[]>([])
  const [meta, setMeta] = useState<PageMeta>({ page: 1, page_size: 20, total: 0, total_pages: 1 })
  const [page, setPage] = useState(1)
  const [statusFilter, setStatusFilter] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')
  const [assigneeFilter, setAssigneeFilter] = useState('')
  const [timeFilter, setTimeFilter] = useState('')
  const [search, setSearch] = useState('')
  const [keyword, setKeyword] = useState('')
  const [keywordInput, setKeywordInput] = useState('')
  const [mitreTacticFilter, setMitreTacticFilter] = useState('')
  const [assignedToInput, setAssignedToInput] = useState('')
  const [assignedToFilter, setAssignedToFilter] = useState('')
  const [selected, setSelected] = useState<Incident | null>(null)
  const [loading, setLoading] = useState(false)
  const [checked, setChecked] = useState<Set<string>>(new Set())
  const [showNew, setShowNew] = useState(false)
  const [newTitle, setNewTitle] = useState('')
  const [newSev, setNewSev] = useState('high')
  const [newDesc, setNewDesc] = useState('')
  const [creating, setCreating] = useState(false)
  const [sortBy, setSortBy] = useState('last_activity')
  const [sortDesc, setSortDesc] = useState(true)

  // Stable load function — page/filters come in as args to avoid stale-closure re-creation
  function load(p: number, opts?: {
    status?: string; severity?: string; assignee?: string; time?: string; q?: string
    sortBy?: string; sortDesc?: boolean
    keyword?: string; mitreTactic?: string; assignedTo?: string
  }) {
    const s   = opts?.status      ?? statusFilter
    const v   = opts?.severity    ?? severityFilter
    const a   = opts?.assignee    ?? assigneeFilter
    const t   = opts?.time        ?? timeFilter
    const q   = opts?.q           ?? search
    const kw  = opts?.keyword     ?? keyword
    const mt  = opts?.mitreTactic ?? mitreTacticFilter
    const at  = opts?.assignedTo  ?? assignedToFilter
    const sb  = opts?.sortBy      ?? sortBy
    const sd  = opts?.sortDesc    ?? sortDesc
    setLoading(true)
    const params: Record<string, unknown> = { page: p, page_size: 20, sort_by: sb, sort_desc: sd }
    if (s) params.status = s
    if (v) params.severity = v
    if (q) params.q = q
    if (kw) params.keyword = kw
    if (mt) params.mitre_tactic = mt
    if (a === 'unassigned') params.unassigned = true
    else if (a) params.assigned_to = a
    if (at) params.assigned_to = at
    if (t) params.hours = t
    api.get('/incidents', { params })
      .then(r => {
        setIncidents(r.data.data?.items ?? [])
        setMeta(r.data.data?.meta ?? { page: p, page_size: 20, total: 0, total_pages: 1 })
      })
      .catch(() => {})
      .finally(() => setLoading(false))
  }

  // Track whether initial mount load has fired
  const mountedRef = useRef(false)

  // Initial load + page changes
  useEffect(() => {
    load(page)
  }, [page])

  // Filter changes → reset to page 1 (skip on first mount — page effect already covers it)
  useEffect(() => {
    if (!mountedRef.current) { mountedRef.current = true; return }
    setPage(1); load(1)
  }, [statusFilter, severityFilter, assigneeFilter, timeFilter, mitreTacticFilter, assignedToFilter])

  // Debounce keyword input → commit to `keyword` state after 400ms
  const keywordDebounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const handleKeywordChange = useCallback((val: string) => {
    setKeywordInput(val)
    if (keywordDebounceRef.current) clearTimeout(keywordDebounceRef.current)
    keywordDebounceRef.current = setTimeout(() => {
      setKeyword(val)
      setPage(1)
      // load with explicit keyword to avoid stale closure on `keyword` state
      load(1, { keyword: val })
    }, 400)
  }, [statusFilter, severityFilter, assigneeFilter, timeFilter, mitreTacticFilter, assignedToFilter, search, sortBy, sortDesc])

  function doSearch() { setPage(1); load(1) }

  function doSort(col: string) {
    const newDesc = col === sortBy ? !sortDesc : true
    setSortBy(col); setSortDesc(newDesc)
    setPage(1); load(1, { sortBy: col, sortDesc: newDesc })
  }

  function bulkAssign() {
    if (!checked.size) return
    const who = prompt(`批量分配 ${checked.size} 条事件给（输入用户名）：`)
    if (!who?.trim()) return
    Promise.all([...checked].map(key => api.patch(`/incidents/${key}`, { assigned_to: who.trim() })))
      .then(() => { setChecked(new Set()); load(page) })
  }

  function bulkStatus(status: string, label: string) {
    if (!checked.size) return
    if (!confirm(`确认将 ${checked.size} 条事件标记为「${label}」？`)) return
    Promise.all([...checked].map(key => api.patch(`/incidents/${key}`, { status })))
      .then(() => { setChecked(new Set()); load(page) })
  }

  function mergeIncidents() {
    if (checked.size < 2) return
    const keys = [...checked]
    const primaryKey = keys[0]
    const secondaryKeys = keys.slice(1)
    if (!confirm(`确认将 ${secondaryKeys.length} 条事件合并到 INC-${primaryKey.slice(-6).padStart(6, '0')}？合并后次要事件将关闭。`)) return
    api.post(`/incidents/${primaryKey}/merge`, { secondary_ids: secondaryKeys })
      .then(() => { setChecked(new Set()); load(1) })
  }

  function createIncident() {
    if (!newTitle.trim()) return
    setCreating(true)
    api.post('/incidents', { title: newTitle, name: newTitle, severity: newSev, status: 'new', description: newDesc })
      .then(() => { setShowNew(false); setNewTitle(''); setNewDesc(''); load(1) })
      .finally(() => setCreating(false))
  }

  function exportCSV() {
    const header = ['ID', '标题', '严重程度', '状态', '告警数', '评分', '负责人', 'MITRE战术', '首次发现', '最近更新']
    const rows = [header.join(',')]
    incidents.forEach(inc => rows.push([
      `INC-${inc._key.slice(-6).padStart(6, '0')}`,
      `"${incidentTitle(inc).replace(/"/g, '""')}"`,
      SEV_LABELS[inc.severity] ?? inc.severity,
      STATUS_LABELS[inc.status] ?? inc.status,
      inc.alert_count,
      inc.smart_score ?? '',
      inc.assigned_to ?? '',
      inc.mitre_tactic ?? '',
      inc.first_seen ?? inc.created_at,
      inc.updated_at,
    ].join(',')))
    const blob = new Blob(['﻿' + rows.join('\n')], { type: 'text/csv;charset=utf-8;' })
    const a = document.createElement('a')
    a.href = URL.createObjectURL(blob)
    a.download = `incidents_${new Date().toISOString().slice(0,10)}.csv`
    a.click()
  }

  const toggleCheck = (key: string) => setChecked(prev => {
    const n = new Set(prev)
    if (n.has(key)) n.delete(key); else n.add(key)
    return n
  })

  const allChecked = !!incidents.length && checked.size === incidents.length
  const hasFilters = !!(statusFilter || severityFilter || assigneeFilter || timeFilter || search || keyword || mitreTacticFilter || assignedToFilter)

  // Summary stats from current page
  const pageStats = {
    new:        incidents.filter(i => i.status === 'new').length,
    active:     incidents.filter(i => i.status === 'investigating' || i.status === 'in_progress' || i.status === 'contained').length,
    critical:   incidents.filter(i => i.severity === 'critical').length,
    unassigned: incidents.filter(i => !i.assigned_to).length,
  }

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

      {/* ── Header ──────────────────────────────────────────── */}
      <PageHeader
        title="事件管理"
        actions={<>
          <button className="btn-secondary" style={{ fontSize: 11 }} onClick={exportCSV}>
            ↓ 导出 CSV
          </button>
          <button className="btn-primary" style={{ fontSize: 11 }} onClick={() => setShowNew(true)}>
            + 新建事件
          </button>
        </>}
      />

      {/* ── Stats strip ─────────────────────────────────────── */}
      {incidents.length > 0 && (
        <div style={{
          display: 'flex',
          background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)',
          flexShrink: 0,
        }}>
          {[
            { label: '新建', value: pageStats.new,        color: 'var(--critical)' },
            { label: '处理中', value: pageStats.active,   color: 'var(--accent-blue)' },
            { label: '严重', value: pageStats.critical,   color: 'var(--critical)' },
            { label: '未分配', value: pageStats.unassigned, color: 'var(--high)' },
          ].map(({ label, value, color }) => (
            <div key={label} style={{
              padding: '6px 18px', fontSize: 11.5, borderRight: '1px solid var(--border)',
            }}>
              <span style={{ color: 'var(--text-muted)' }}>{label} </span>
              <span style={{ fontWeight: 700, color: value > 0 ? color : 'var(--text-muted)' }}>{value}</span>
            </div>
          ))}
          <div style={{ padding: '6px 18px', fontSize: 11.5, color: 'var(--text-muted)', marginLeft: 'auto' }}>
            当前页 {incidents.length} 条 / 全局 {meta.total} 条
          </div>
        </div>
      )}

      {/* ── Filter bar ──────────────────────────────────────── */}
      <div className="filter-bar">
        {/* Unified search box */}
        <div style={{ position: 'relative', display: 'inline-flex', alignItems: 'center' }}>
          <input
            className="filter-input"
            style={{ width: 220, paddingRight: (keyword || search) ? 24 : undefined }}
            placeholder="搜索事件 / 标题"
            value={keywordInput || search}
            onChange={e => {
              const val = e.target.value
              setSearch(val)
              handleKeywordChange(val)
            }}
            onKeyDown={e => e.key === 'Enter' && doSearch()}
          />
          {(keyword || search) && (
            <button
              onClick={() => {
                setKeywordInput(''); setKeyword(''); setSearch('')
                setPage(1); load(1, { keyword: '', q: '' })
              }}
              style={{
                position: 'absolute', right: 6,
                background: 'none', border: 'none', cursor: 'pointer',
                color: 'var(--text-muted)', fontSize: 13, lineHeight: 1, padding: 0,
              }}
              title="清除搜索"
            >&#x2715;</button>
          )}
        </div>
        <button className="btn-secondary" style={{ fontSize: 11 }} onClick={doSearch}>搜索</button>
        <select className="filter-select" value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}>
          <option value="">全部严重程度</option>
          <option value="critical">严重</option>
          <option value="high">高危</option>
          <option value="medium">中危</option>
          <option value="low">低危</option>
        </select>
        <select className="filter-select" value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
          <option value="">全部状态</option>
          <option value="new">新建</option>
          <option value="investigating">调查中</option>
          <option value="in_progress">处理中</option>
          <option value="contained">已遏制</option>
          <option value="resolved">已解决</option>
          <option value="closed">已关闭</option>
        </select>
        {/* MITRE tactic filter */}
        <select className="filter-select" value={mitreTacticFilter} onChange={e => setMitreTacticFilter(e.target.value)}>
          <option value="">战术</option>
          <option value="initial_access">Initial Access</option>
          <option value="execution">Execution</option>
          <option value="persistence">Persistence</option>
          <option value="privilege_escalation">Privilege Escalation</option>
          <option value="defense_evasion">Defense Evasion</option>
          <option value="credential_access">Credential Access</option>
          <option value="discovery">Discovery</option>
          <option value="lateral_movement">Lateral Movement</option>
          <option value="collection">Collection</option>
          <option value="command_and_control">Command and Control</option>
          <option value="exfiltration">Exfiltration</option>
          <option value="impact">Impact</option>
        </select>
        <select className="filter-select" value={assigneeFilter} onChange={e => setAssigneeFilter(e.target.value)}>
          <option value="">全部负责人</option>
          <option value="unassigned">未分配</option>
          {[...new Set(incidents.map(i => i.assigned_to).filter(Boolean))].map(u => (
            <option key={u} value={u}>{u}</option>
          ))}
        </select>
        {/* Assigned-to free-text filter */}
        <input
          className="filter-input"
          style={{ width: 140 }}
          placeholder="处理人"
          value={assignedToInput}
          onChange={e => setAssignedToInput(e.target.value)}
          onKeyDown={e => {
            if (e.key === 'Enter') { setAssignedToFilter(assignedToInput.trim()); setPage(1) }
          }}
          onBlur={() => { setAssignedToFilter(assignedToInput.trim()); setPage(1) }}
        />
        <select className="filter-select" value={timeFilter} onChange={e => setTimeFilter(e.target.value)}>
          <option value="">全部时间</option>
          <option value="24">近 24 小时</option>
          <option value="72">近 3 天</option>
          <option value="168">近 7 天</option>
          <option value="720">近 30 天</option>
        </select>
        {hasFilters && (
          <button className="btn-secondary" style={{ fontSize: 11 }} onClick={() => {
            setStatusFilter(''); setSeverityFilter(''); setAssigneeFilter('')
            setTimeFilter(''); setSearch('')
            setKeywordInput(''); setKeyword('')
            setMitreTacticFilter('')
            setAssignedToInput(''); setAssignedToFilter('')
          }}>
            ✕ 清除
          </button>
        )}
      </div>

      {/* ── Bulk action bar ─────────────────────────────────── */}
      {checked.size > 0 && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 12, padding: '6px 20px',
          background: 'rgba(59,158,222,.08)', borderBottom: '1px solid rgba(59,158,222,.2)',
          fontSize: 12, flexShrink: 0,
        }}>
          <span style={{ color: 'var(--accent-blue)', fontWeight: 600 }}>已选 {checked.size} 条</span>
          <button className="btn-secondary" style={{ fontSize: 11 }} onClick={bulkAssign}>批量分配</button>
          <button className="btn-secondary" style={{ fontSize: 11, color: 'var(--accent-green)', borderColor: 'var(--accent-green)' }}
            onClick={() => bulkStatus('resolved', '已解决')}>批量解决</button>
          <button className="btn-secondary" style={{ fontSize: 11 }}
            onClick={() => bulkStatus('closed', '已关闭')}>批量关闭</button>
          {checked.size >= 2 && (
            <button className="btn-secondary" style={{ fontSize: 11, color: 'var(--accent-blue)', borderColor: 'var(--accent-blue)' }}
              onClick={mergeIncidents}>合并事件</button>
          )}
          <button
            style={{ marginLeft: 'auto', background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 11 }}
            onClick={() => setChecked(new Set())}
          >
            取消选择
          </button>
        </div>
      )}

      {/* ── Table ───────────────────────────────────────────── */}
      <style>{`.incidents-table td { padding: 6px 16px !important; }`}</style>
      <div className="data-table-wrap">
        <table className="data-table incidents-table">
          <thead>
            <tr>
              <ResizableTh style={{ width: 36 }}>
                <input
                  type="checkbox"
                  checked={allChecked}
                  onChange={() => setChecked(allChecked ? new Set() : new Set(incidents.map(i => i._key)))}
                />
              </ResizableTh>
              <ResizableTh style={{ width: 92 }}>事件编号</ResizableTh>
              <ResizableTh>事件名称</ResizableTh>
              {/* Sortable columns */}
              {([
                ['severity', '严重程度', 68],
                ['smart_score', '评分', 50],
                ['status', '状态', 82],
                ['alert_count', '告警', 48],
              ] as [string, string, number][]).map(([col, label, w]) => (
                <ResizableTh
                  key={col}
                  style={{ width: w, cursor: 'pointer', userSelect: 'none', whiteSpace: 'nowrap' }}
                  onClick={() => doSort(col)}
                >
                  {label}
                  {sortBy === col && (
                    <span style={{ marginLeft: 3, fontSize: 9, opacity: 0.7 }}>
                      {sortDesc ? '▼' : '▲'}
                    </span>
                  )}
                </ResizableTh>
              ))}
              <ResizableTh style={{ width: 88 }}>负责人</ResizableTh>
              <ResizableTh style={{ width: 108 }}>MITRE 战术</ResizableTh>
              <ResizableTh
                style={{ width: 78, cursor: 'pointer', userSelect: 'none' }}
                onClick={() => doSort('first_seen')}
              >
                首次发现{sortBy === 'first_seen' && <span style={{ marginLeft: 3, fontSize: 9, opacity: 0.7 }}>{sortDesc ? '▼' : '▲'}</span>}
              </ResizableTh>
              <ResizableTh
                style={{ width: 78, cursor: 'pointer', userSelect: 'none' }}
                onClick={() => doSort('last_activity')}
              >
                最近更新{sortBy === 'last_activity' && <span style={{ marginLeft: 3, fontSize: 9, opacity: 0.7 }}>{sortDesc ? '▼' : '▲'}</span>}
              </ResizableTh>
              <ResizableTh style={{ width: 44 }}></ResizableTh>
            </tr>
          </thead>
          <tbody>
            {loading && (
              <tr>
                <td colSpan={12} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 32 }}>
                  加载中...
                </td>
              </tr>
            )}
            {!loading && incidents.length === 0 && (
              <tr>
                <td colSpan={12} style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)', fontSize: 12 }}>
                  {hasFilters ? '没有符合条件的事件' : '暂无事件数据'}
                </td>
              </tr>
            )}
            {incidents.map(inc => (
              <tr
                key={inc._key}
                className={[
                  selected?._key === inc._key ? 'selected' : '',
                  inc.severity === 'critical' ? 'row-critical' : '',
                ].filter(Boolean).join(' ')}
                onClick={() => setSelected(inc)}
                style={{ cursor: 'pointer', height: 44 }}
              >
                <td onClick={e => e.stopPropagation()}>
                  <input type="checkbox" checked={checked.has(inc._key)} onChange={() => toggleCheck(inc._key)} />
                </td>
                <td>
                  <span style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--accent-blue)', fontWeight: 600 }}>
                    INC-{inc._key.slice(-6).padStart(6, '0')}
                  </span>
                </td>
                <td style={{ maxWidth: 260 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                    <SlaDot inc={inc} />
                    <div style={{ fontSize: 12.5, fontWeight: 500, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                      {incidentTitle(inc)}
                    </div>
                  </div>
                  {(inc.host_count || inc.mitre_tactic) && (
                    <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginTop: 1 }}>
                      {inc.host_count ? `${inc.host_count} 台主机` : ''}
                      {inc.host_count && inc.mitre_tactic ? ' · ' : ''}
                      {inc.mitre_tactic ?? ''}
                    </div>
                  )}
                </td>
                <td>
                  <div style={{ display: 'inline-flex', alignItems: 'center', gap: 5, flexWrap: 'wrap' }}>
                    <SevBadge sev={inc.severity} />
                    {(inc.smart_score ?? 0) > 0 && (() => {
                      const ss = inc.smart_score!
                      const ssColor = ss >= 80 ? 'var(--critical)' : ss >= 60 ? 'var(--high)' : 'var(--medium)'
                      return (
                        <span style={{
                          display: 'inline-flex', alignItems: 'center',
                          padding: '2px 6px', borderRadius: 3,
                          background: ssColor + '22', color: ssColor,
                          fontSize: 10, fontWeight: 700, letterSpacing: 0.2,
                          border: `1px solid ${ssColor}44`,
                        }}>
                          SS: {ss}
                        </span>
                      )
                    })()}
                  </div>
                </td>
                <td><ScoreBadge score={inc.smart_score} /></td>
                <td><StatusBadge status={inc.status} /></td>
                <td>
                  <span style={{ color: 'var(--accent-orange)', fontWeight: 600, fontSize: 12 }}>
                    {inc.alert_count}
                  </span>
                </td>
                <td style={{ fontSize: 11.5 }}>
                  {inc.assigned_to
                    ? <span style={{ color: 'var(--text-secondary)' }}>{inc.assigned_to}</span>
                    : <span style={{ fontSize: 11, color: 'var(--high)' }}>未分配</span>
                  }
                </td>
                <td>
                  {inc.mitre_tactic ? (
                    <span style={{
                      fontSize: 10.5, color: 'var(--accent-blue)',
                      background: 'rgba(59,158,222,.1)', padding: '2px 6px', borderRadius: 3, whiteSpace: 'nowrap',
                    }}>
                      {inc.mitre_tactic}
                    </span>
                  ) : (
                    <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>-</span>
                  )}
                </td>
                <td style={{ fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                  {fmtDate(inc.first_seen ?? inc.created_at)}
                </td>
                <td style={{ fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                  {fmtDate(inc.last_activity ?? inc.updated_at)}
                </td>
                <td>
                  <button
                    className="btn-secondary"
                    style={{ fontSize: 10, padding: '2px 8px' }}
                    onClick={e => { e.stopPropagation(); setSelected(inc) }}
                  >
                    详情
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* ── Pagination ──────────────────────────────────────── */}
      <div className="pagination" style={{ justifyContent: 'center' }}>
        <span style={{ marginRight: 8 }}>
          {meta.total > 0
            ? `第 ${(page-1)*meta.page_size + 1}–${Math.min(page*meta.page_size, meta.total)} 条，共 ${meta.total} 条`
            : '暂无结果'
          }
        </span>
        <button className="page-btn" disabled={page <= 1} onClick={() => setPage(p => p-1)}>&#8249;</button>
        {(() => {
          const total = meta.total_pages
          if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1)
          // Smart window: always show 1, last, and 2 around current
          const pages: (number | '...')[] = []
          pages.push(1)
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
        <button className="page-btn" disabled={page >= meta.total_pages} onClick={() => setPage(p => p+1)}>&#8250;</button>
      </div>

      {/* ── Drawer ──────────────────────────────────────────── */}
      <IncidentDrawer
        inc={selected}
        onClose={() => setSelected(null)}
        onRefresh={() => load(page)}
      />

      {/* ── New Incident Modal ───────────────────────────────── */}
      {showNew && (
        <>
          <div
            onClick={() => setShowNew(false)}
            onKeyDown={e => e.key === 'Escape' && setShowNew(false)}
            style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }}
          />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 460, background: 'var(--bg-modal)',
            border: '1px solid var(--border-light)', borderRadius: 8,
            zIndex: 600, padding: '24px 24px 20px',
            boxShadow: '0 8px 32px rgba(0,0,0,.4)',
          }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 20 }}>新建事件</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>事件标题 *</div>
                <input
                  className="filter-input"
                  style={{ width: '100%', boxSizing: 'border-box' }}
                  placeholder="描述安全事件的核心内容..."
                  value={newTitle}
                  onChange={e => setNewTitle(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && createIncident()}
                  autoFocus
                />
              </div>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>严重程度</div>
                <select className="filter-select" style={{ width: '100%' }} value={newSev} onChange={e => setNewSev(e.target.value)}>
                  <option value="critical">严重</option>
                  <option value="high">高危</option>
                  <option value="medium">中危</option>
                  <option value="low">低危</option>
                </select>
              </div>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>描述（可选）</div>
                <textarea
                  className="filter-input"
                  style={{ width: '100%', minHeight: 72, boxSizing: 'border-box', resize: 'vertical' }}
                  placeholder="补充事件背景、初步判断等信息..."
                  value={newDesc}
                  onChange={e => setNewDesc(e.target.value)}
                />
              </div>
              <div style={{ display: 'flex', gap: 10, marginTop: 4 }}>
                <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setShowNew(false)}>取消</button>
                <button
                  className="btn-primary"
                  style={{ flex: 1 }}
                  disabled={creating || !newTitle.trim()}
                  onClick={createIncident}
                >
                  {creating ? '创建中...' : '创建事件'}
                </button>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
