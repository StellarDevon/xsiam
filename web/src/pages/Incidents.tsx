import { useEffect, useState, useRef } from 'react'
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
  new: '#e53935', investigating: '#4fa3e0', in_progress: '#4fa3e0',
  contained: '#f9a825', resolved: '#2fb07a', closed: '#546e7a',
}
const SEV_LABELS: Record<string, string> = {
  critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息',
}
const SEV_COLORS: Record<string, string> = {
  critical: '#e53935', high: '#ff6f00', medium: '#f9a825', low: '#2fb07a', info: '#546e7a',
}

// ─── Helpers ─────────────────────────────────────────────────────────────────

function fmtDate(iso: string | undefined) {
  if (!iso) return '-'
  try {
    const d = new Date(iso)
    if (isNaN(d.getTime())) return '-'
    const p = (n: number) => n.toString().padStart(2, '0')
    return `${p(d.getMonth()+1)}/${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
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

function incidentTitle(inc: Incident) {
  return inc.title || inc.name || '(无标题)'
}

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
  const color = s >= 80 ? '#e53935' : s >= 60 ? '#ff6f00' : s >= 40 ? '#f9a825' : '#2fb07a'
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

// ─── Incident Drawer ─────────────────────────────────────────────────────────

interface DrawerProps {
  inc: Incident | null
  onClose: () => void
  onRefresh: () => void
}

function IncidentDrawer({ inc, onClose, onRefresh }: DrawerProps) {
  const [tab, setTab] = useState('overview')
  const [scoreData, setScoreData] = useState<SmartScoreEntry | null>(null)
  const [alerts, setAlerts] = useState<any[]>([])
  const [alertsLoading, setAlertsLoading] = useState(false)
  const [timeline, setTimeline] = useState<TimelineEvent[]>([])
  const [timelineLoading, setTimelineLoading] = useState(false)
  const [playbooks, setPlaybooks] = useState<PlaybookItem[]>([])
  const [playbooksLoading, setPlaybooksLoading] = useState(false)
  const [executingPb, setExecutingPb] = useState<string | null>(null)
  const [note, setNote] = useState('')
  const [savingNote, setSavingNote] = useState(false)
  const [assignInput, setAssignInput] = useState('')
  const [assigning, setAssigning] = useState(false)
  const [resolving, setResolving] = useState(false)

  // Reset state when incident changes
  const prevKey = useRef<string | null>(null)
  useEffect(() => {
    if (!inc) {
      prevKey.current = null
      setScoreData(null); setAlerts([]); setTimeline([]); setPlaybooks([])
      setNote(''); setAssignInput(''); setAssigning(false)
      return
    }
    if (inc._key === prevKey.current) return
    prevKey.current = inc._key
    setTab('overview')
    setScoreData(null); setAlerts([]); setTimeline([]); setPlaybooks([])
    setNote(''); setAssignInput(''); setAssigning(false)

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

  const open = !!inc
  const score = scoreData?.score ?? inc?.smart_score ?? 0
  const scoreColor = score >= 80 ? '#e53935' : score >= 60 ? '#ff6f00' : score >= 40 ? '#f9a825' : score > 0 ? '#2fb07a' : '#3f4e6a'
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
    { id: 'alerts',     label: `告警 (${alerts.length || inc?.alert_count || 0})` },
    { id: 'timeline',   label: '时间轴' },
    { id: 'mitre',      label: 'MITRE ATT&CK' },
    { id: 'causality',  label: '溯源图' },
    { id: 'playbooks',  label: '剧本' },
    { id: 'notes',      label: '备注' },
  ]

  // event_type from backend: 'created' | 'assigned' | 'status' | 'note'
  // from SPA local: 'playbook'
  const evtColor: Record<string, string> = {
    created: '#4fa3e0', assigned: '#9b59b6',
    status: '#f9a825', status_change: '#f9a825',
    note: '#f9a825', playbook: '#e67e22',
    resolved: '#2fb07a', alert: '#e53935',
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
            background: 'rgba(0,0,0,.52)',
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
        background: 'var(--bg-primary)',
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
              borderBottom: '1px solid var(--border)',
              background: 'var(--bg-secondary)',
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
                        主机&nbsp;<span style={{ color: '#4fa3e0', fontWeight: 600 }}>{inc.host_count}</span>
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
                      : <span style={{ fontSize: 11, color: '#ff6f00', fontWeight: 500 }}>未分配</span>
                    }
                  </div>
                </div>

                {/* Action buttons */}
                <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexShrink: 0 }}>
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
                      style={{ fontSize: 11, background: '#2fb07a', border: 'none' }}
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
                        <div className="card-title" style={{ marginBottom: 10 }}>AI 风险评分</div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 12 }}>
                          <div style={{
                            width: 56, height: 56, borderRadius: 10, flexShrink: 0,
                            background: scoreColor + '18', border: `2px solid ${scoreColor}40`,
                            display: 'flex', flexDirection: 'column',
                            alignItems: 'center', justifyContent: 'center',
                          }}>
                            <span style={{ fontSize: 22, fontWeight: 800, color: scoreColor, lineHeight: 1 }}>
                              {score > 0 ? score : '-'}
                            </span>
                          </div>
                          <div>
                            <div style={{ fontSize: 13, fontWeight: 600, color: scoreColor, marginBottom: 3 }}>
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
                            const barColor = val > 70 ? '#e53935' : val > 40 ? '#ff6f00' : '#f9a825'
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
                            <span style={{ fontSize: 10.5, color: '#4fa3e0', flexShrink: 0 }}>{a.host ?? a.asset_name}</span>
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
                      <div className="card" style={{ padding: '14px 16px', borderLeft: '3px solid #e53935' }}>
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
                          <SevBadge sev={a.severity} />
                          <span style={{ flex: 1, fontSize: 12.5, fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {a.name}
                          </span>
                          <span style={{ fontSize: 10.5, color: 'var(--text-muted)', flexShrink: 0 }}>
                            {fmtDate(a.triggered_at ?? a.created_at)}
                          </span>
                        </div>
                        <div style={{ display: 'flex', gap: 14, fontSize: 11, color: 'var(--text-muted)' }}>
                          {(a.host ?? a.asset_name) && <span>🖥 {a.host ?? a.asset_name}</span>}
                          {(a.user ?? a.user_name) && <span>👤 {a.user ?? a.user_name}</span>}
                          {a.mitre_tactic && <span style={{ color: '#4fa3e0' }}>🎯 {a.mitre_tactic}</span>}
                          {a.source_type && <span>{a.source_type}</span>}
                        </div>
                      </div>
                    ))}
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
                    <div style={{ position: 'relative', paddingLeft: 28 }}>
                      <div style={{ position: 'absolute', left: 7, top: 8, bottom: 8, width: 1, background: 'var(--border)' }} />
                      {timeline.map((item, i) => {
                        const color = evtColor[item.event_type] ?? '#4fa3e0'
                        const label = evtLabel[item.event_type] ?? item.event_type.replace(/_/g, ' ')
                        return (
                          <div key={i} style={{ marginBottom: 18, position: 'relative' }}>
                            <div style={{
                              position: 'absolute', left: -28, top: 3,
                              width: 14, height: 14, borderRadius: '50%',
                              background: color + '28', border: `2px solid ${color}`,
                            }} />
                            <div style={{ display: 'flex', alignItems: 'baseline', gap: 8, marginBottom: 3 }}>
                              <span style={{ fontSize: 11, fontWeight: 600, color }}>
                                {label}
                              </span>
                              <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                                {fmtDate(item.created_at)}
                              </span>
                              {item.actor && (
                                <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>by {item.actor}</span>
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
                      <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 8 }}>
                        MITRE ATT&amp;CK 技术映射 — 本事件关联战术
                      </div>
                      {primaryTactic && (
                        <div style={{
                          display: 'inline-flex', alignItems: 'center', gap: 6,
                          padding: '4px 10px',
                          background: 'rgba(250,88,45,.1)', border: '1px solid rgba(250,88,45,.3)',
                          borderRadius: 4, fontSize: 12,
                        }}>
                          <span style={{ color: 'var(--text-muted)' }}>主要战术:</span>
                          <span style={{ color: 'var(--accent-orange)', fontWeight: 600 }}>{primaryTactic}</span>
                        </div>
                      )}
                    </div>
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
                        { label: '关联告警', value: inc.alert_count, color: '#e53935' },
                        { label: '涉及主机', value: inc.host_count ?? (alertHosts.length || '-'), color: '#4fa3e0' },
                        { label: '持续时间', value: fmtDuration(inc.first_seen ?? inc.created_at), color: '#f9a825' },
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
  }) {
    const s  = opts?.status    ?? statusFilter
    const v  = opts?.severity  ?? severityFilter
    const a  = opts?.assignee  ?? assigneeFilter
    const t  = opts?.time      ?? timeFilter
    const q  = opts?.q         ?? search
    const sb = opts?.sortBy    ?? sortBy
    const sd = opts?.sortDesc  ?? sortDesc
    setLoading(true)
    const params: Record<string, unknown> = { page: p, page_size: 20, sort_by: sb, sort_desc: sd }
    if (s) params.status = s
    if (v) params.severity = v
    if (q) params.q = q
    if (a === 'unassigned') params.unassigned = true
    else if (a) params.assigned_to = a
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
  }, [statusFilter, severityFilter, assigneeFilter, timeFilter])

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
  const hasFilters = !!(statusFilter || severityFilter || assigneeFilter || timeFilter || search)

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
        subtitle={meta.total > 0 ? `共 ${meta.total} 条` : undefined}
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
            { label: '新建', value: pageStats.new,        color: '#e53935' },
            { label: '处理中', value: pageStats.active,   color: '#4fa3e0' },
            { label: '严重', value: pageStats.critical,   color: '#e53935' },
            { label: '未分配', value: pageStats.unassigned, color: '#ff6f00' },
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
        <input
          className="filter-input"
          style={{ width: 200 }}
          placeholder="搜索事件标题..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && doSearch()}
        />
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
        <select className="filter-select" value={assigneeFilter} onChange={e => setAssigneeFilter(e.target.value)}>
          <option value="">全部负责人</option>
          <option value="unassigned">未分配</option>
          {[...new Set(incidents.map(i => i.assigned_to).filter(Boolean))].map(u => (
            <option key={u} value={u}>{u}</option>
          ))}
        </select>
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
          <button className="btn-secondary" style={{ fontSize: 11, color: '#2fb07a', borderColor: '#2fb07a' }}
            onClick={() => bulkStatus('resolved', '已解决')}>批量解决</button>
          <button className="btn-secondary" style={{ fontSize: 11 }}
            onClick={() => bulkStatus('closed', '已关闭')}>批量关闭</button>
          <button
            style={{ marginLeft: 'auto', background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 11 }}
            onClick={() => setChecked(new Set())}
          >
            取消选择
          </button>
        </div>
      )}

      {/* ── Table ───────────────────────────────────────────── */}
      <div className="data-table-wrap">
        <table className="data-table">
          <thead>
            <tr>
              <th style={{ width: 36 }}>
                <input
                  type="checkbox"
                  checked={allChecked}
                  onChange={() => setChecked(allChecked ? new Set() : new Set(incidents.map(i => i._key)))}
                />
              </th>
              <th style={{ width: 92 }}>事件编号</th>
              <th>事件名称</th>
              {/* Sortable columns */}
              {([
                ['severity', '严重程度', 68],
                ['smart_score', '评分', 50],
                ['status', '状态', 82],
                ['alert_count', '告警', 48],
              ] as [string, string, number][]).map(([col, label, w]) => (
                <th
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
                </th>
              ))}
              <th style={{ width: 88 }}>负责人</th>
              <th style={{ width: 108 }}>MITRE 战术</th>
              <th
                style={{ width: 78, cursor: 'pointer', userSelect: 'none' }}
                onClick={() => doSort('first_seen')}
              >
                首次发现{sortBy === 'first_seen' && <span style={{ marginLeft: 3, fontSize: 9, opacity: 0.7 }}>{sortDesc ? '▼' : '▲'}</span>}
              </th>
              <th
                style={{ width: 78, cursor: 'pointer', userSelect: 'none' }}
                onClick={() => doSort('last_activity')}
              >
                最近更新{sortBy === 'last_activity' && <span style={{ marginLeft: 3, fontSize: 9, opacity: 0.7 }}>{sortDesc ? '▼' : '▲'}</span>}
              </th>
              <th style={{ width: 44 }}></th>
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
                style={{ cursor: 'pointer' }}
              >
                <td onClick={e => e.stopPropagation()}>
                  <input type="checkbox" checked={checked.has(inc._key)} onChange={() => toggleCheck(inc._key)} />
                </td>
                <td>
                  <span style={{ fontFamily: 'monospace', fontSize: 11, color: '#4fa3e0', fontWeight: 600 }}>
                    INC-{inc._key.slice(-6).padStart(6, '0')}
                  </span>
                </td>
                <td style={{ maxWidth: 260 }}>
                  <div style={{ fontSize: 12.5, fontWeight: 500, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                    {incidentTitle(inc)}
                  </div>
                  {(inc.host_count || inc.mitre_tactic) && (
                    <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginTop: 1 }}>
                      {inc.host_count ? `${inc.host_count} 台主机` : ''}
                      {inc.host_count && inc.mitre_tactic ? ' · ' : ''}
                      {inc.mitre_tactic ?? ''}
                    </div>
                  )}
                </td>
                <td><SevBadge sev={inc.severity} /></td>
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
                    : <span style={{ fontSize: 11, color: '#ff6f00' }}>未分配</span>
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
      <div className="pagination">
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
            style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.55)', zIndex: 400 }}
          />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 460, background: 'var(--bg-card)',
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
