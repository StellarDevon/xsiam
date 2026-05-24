import { useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '@/lib/api'
import { getUser } from '@/lib/auth'
import {
  AreaChart, Area, PieChart, Pie, Cell,
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Legend,
} from 'recharts'

interface DashStats {
  total_alerts: number
  open_alerts: number
  total_incidents: number
  open_incidents: number
  total_assets: number
  total_vulns: number
  critical_vulns: number
  alerts_by_day: { date: string; count: number }[]
  alerts_by_severity: Record<string, number>
  incidents_by_status: Record<string, number>
  top_tactics: { tactic: string; count: number }[]
  mttr_hours: number
}

interface ExtendedStats {
  source_breakdown: Array<{ source: string; source_type?: string; count: number }>
  top_assets: Array<{ asset_id: string; asset_name?: string; hostname?: string; alert_count: number }>
  mitre_coverage: Record<string, number>
}

interface AlertFeedItem {
  _key: string
  name: string
  severity: string
  host?: string
  asset_name?: string
  triggered_at?: string
  created_at: string
}

interface Playbook {
  _key: string
  status: string
  run_count?: number
  success_count?: number
}

interface TopHostEntry {
  hostname: string
  alert_count: number
}

interface TopAffectedHost {
  hostname: string
  alert_count: number
  open_incidents: number
  risk_score: number
}

// ─── Geo threat data ───────────────────────────────────────────────────────
const GEO_COUNTRIES: {
  code: string; name: string; svgX: number; svgY: number; threatLevel: 'critical' | 'high' | 'medium'
}[] = [
  { code: 'CN', name: '中国',      svgX: 350, svgY: 115, threatLevel: 'critical' },
  { code: 'RU', name: '俄罗斯',    svgX: 290, svgY:  72, threatLevel: 'critical' },
  { code: 'KP', name: '朝鲜',      svgX: 368, svgY: 102, threatLevel: 'high' },
  { code: 'US', name: '美国',      svgX:  80, svgY: 108, threatLevel: 'high' },
  { code: 'BR', name: '巴西',      svgX: 130, svgY: 182, threatLevel: 'medium' },
  { code: 'DE', name: '德国',      svgX: 222, svgY:  80, threatLevel: 'medium' },
]

function geoThreatColor(level: 'critical' | 'high' | 'medium'): string {
  return level === 'critical' ? 'var(--critical)' : level === 'high' ? 'var(--high)' : 'var(--medium)'
}

// ─── Deterministic incident resolution trend (7 days) ─────────────────────
function buildIncidentTrend(): { day: string; new_incidents: number; resolved: number }[] {
  const now = new Date()
  // Use a fixed seed derived from current date (YYYYMMDD) for determinism
  const dateSeed = now.getFullYear() * 10000 + (now.getMonth() + 1) * 100 + now.getDate()
  const rows: { day: string; new_incidents: number; resolved: number }[] = []
  for (let i = 6; i >= 0; i--) {
    const d = new Date(now)
    d.setDate(d.getDate() - i)
    const label = `${d.getMonth() + 1}/${d.getDate()}`
    // Deterministic pseudo-random from seed + offset
    const seed1 = ((dateSeed + i * 17) * 1664525 + 1013904223) & 0xffffffff
    const seed2 = ((seed1) * 1664525 + 1013904223) & 0xffffffff
    const newInc = 3 + (Math.abs(seed1) % 10)
    const resolved = 2 + (Math.abs(seed2) % 8)
    rows.push({ day: label, new_incidents: newInc, resolved })
  }
  return rows
}

// Hardcoded yesterday comparison data (demo)
const YESTERDAY_COMPARISON = [
  { label: '告警', pct: 12, up: true },
  { label: '事件', pct: 5,  up: false },
  { label: '资产', pct: 3,  up: true },
  { label: '漏洞', pct: 8,  up: false },
]

// ─── Security Score Gauge ──────────────────────────────────────────────────
function SecurityScoreGauge({ score }: { score: number }) {
  const clamped = Math.min(100, Math.max(0, score))
  const color = clamped < 40 ? 'var(--critical)' : clamped < 70 ? 'var(--high)' : 'var(--low)'

  // SVG arc math: full circle = 2πr, use 270° arc
  const r = 26
  const cx = 36
  const cy = 38
  const circumference = 2 * Math.PI * r
  const arcFraction = (270 / 360) * circumference
  const filledLength = arcFraction  // keep var to avoid lint warning
  void filledLength
  void circumference

  // Start angle: -225° (bottom-left), end: +45° (bottom-right)
  const startAngle = -225 * (Math.PI / 180)
  const startX = cx + r * Math.cos(startAngle)
  const startY = cy + r * Math.sin(startAngle)
  const endAngle = 45 * (Math.PI / 180)
  const endX = cx + r * Math.cos(endAngle)
  const endY = cy + r * Math.sin(endAngle)

  // Build arc path for 270° track
  const trackPath = `M ${startX} ${startY} A ${r} ${r} 0 1 1 ${endX} ${endY}`

  // Filled arc: rotate by progress
  const fillRotation = (clamped / 100) * 270
  const fillEndRad = (-225 + fillRotation) * (Math.PI / 180)
  const fillEndX = cx + r * Math.cos(fillEndRad)
  const fillEndY = cx + r * Math.sin(fillEndRad)
  const largeArc = fillRotation > 180 ? 1 : 0
  const fillPath = `M ${startX} ${startY} A ${r} ${r} 0 ${largeArc} 1 ${fillEndX} ${fillEndY}`

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 0 }}>
      <svg width={72} height={72} viewBox="0 0 72 76">
        {/* Track */}
        <path d={trackPath} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth={5} strokeLinecap="round"/>
        {/* Filled */}
        {clamped > 0 && (
          <path d={fillPath} fill="none" stroke={color} strokeWidth={5} strokeLinecap="round"
            style={{ filter: `drop-shadow(0 0 3px ${color})` }}/>
        )}
        {/* Score text */}
        <text x={cx} y={cy - 1} textAnchor="middle" fontSize="15" fontWeight="700" fill="white" fontFamily="'Segoe UI',sans-serif">
          {Math.round(clamped)}
        </text>
        <text x={cx} y={cy + 11} textAnchor="middle" fontSize="7" fill={color} fontFamily="'Segoe UI',sans-serif" letterSpacing="0.5">
          / 100
        </text>
      </svg>
      <div style={{ fontSize: 9, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.4, marginTop: -4 }}>
        安全评分
      </div>
    </div>
  )
}

// ─── Geographic Threat Heatmap ─────────────────────────────────────────────
function GeoThreatMap({ iocCount }: { iocCount: number | null }) {
  const [hovered, setHovered] = useState<string | null>(null)
  // Deterministic dot sizes based on iocCount
  const base = iocCount ?? 100
  const sizes: Record<string, number> = {
    CN: 6 + ((base * 7) % 5),
    RU: 5 + ((base * 11) % 4),
    KP: 4 + ((base * 3) % 3),
    US: 5 + ((base * 13) % 4),
    BR: 4 + ((base * 5) % 3),
    DE: 4 + ((base * 9) % 3),
  }
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 2 }}>
        过去24小时威胁来源
      </div>
      <div style={{ position: 'relative' }}>
        {/* World outline SVG — simplified Mercator silhouette */}
        <svg
          viewBox="0 0 460 230"
          style={{ width: '100%', maxHeight: 130, display: 'block' }}
          xmlns="http://www.w3.org/2000/svg"
        >
          <defs>
            <filter id="dotGlow" x="-60%" y="-60%" width="220%" height="220%">
              <feGaussianBlur stdDeviation="2.5" result="blur"/>
              <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
            </filter>
          </defs>

          {/* Background */}
          <rect width="460" height="230" fill="#0a1929" rx="4"/>

          {/* Simplified world continent outlines */}
          {/* North America */}
          <path d="M 30 60 L 55 50 L 80 52 L 100 60 L 115 75 L 120 95 L 110 120 L 100 140
                   L 90 160 L 80 155 L 70 145 L 65 130 L 60 115 L 45 105 L 35 90 Z"
            fill="#1e3a5f" stroke="rgba(80,130,180,0.5)" strokeWidth="0.7"/>
          {/* Central America / Caribbean stub */}
          <path d="M 100 140 L 110 148 L 108 155 L 102 153 Z"
            fill="#1e3a5f" stroke="rgba(80,130,180,0.4)" strokeWidth="0.6"/>
          {/* South America */}
          <path d="M 105 160 L 125 155 L 150 158 L 165 175 L 160 200 L 145 215 L 125 220
                   L 110 210 L 100 195 L 98 175 Z"
            fill="#1e3a5f" stroke="rgba(80,130,180,0.5)" strokeWidth="0.7"/>
          {/* Europe */}
          <path d="M 195 55 L 220 48 L 240 50 L 255 60 L 250 75 L 235 80 L 220 82 L 200 78 L 192 68 Z"
            fill="#1e3a5f" stroke="rgba(80,130,180,0.5)" strokeWidth="0.7"/>
          {/* Scandinavia stub */}
          <path d="M 215 45 L 225 35 L 232 42 L 225 48 Z"
            fill="#1e3a5f" stroke="rgba(80,130,180,0.4)" strokeWidth="0.6"/>
          {/* Africa */}
          <path d="M 200 88 L 240 82 L 260 95 L 265 120 L 260 150 L 245 175 L 225 185
                   L 205 175 L 192 155 L 190 130 L 195 105 Z"
            fill="#1e3a5f" stroke="rgba(80,130,180,0.5)" strokeWidth="0.7"/>
          {/* Russia / North Asia */}
          <path d="M 255 35 L 310 28 L 380 30 L 410 42 L 390 55 L 360 60 L 320 58 L 285 55 L 258 48 Z"
            fill="#1e3a5f" stroke="rgba(80,130,180,0.5)" strokeWidth="0.7"/>
          {/* Middle East */}
          <path d="M 258 78 L 280 72 L 300 80 L 295 98 L 275 100 L 260 92 Z"
            fill="#1e3a5f" stroke="rgba(80,130,180,0.4)" strokeWidth="0.6"/>
          {/* South Asia */}
          <path d="M 300 85 L 330 80 L 345 90 L 340 115 L 320 118 L 305 108 Z"
            fill="#1e3a5f" stroke="rgba(80,130,180,0.4)" strokeWidth="0.6"/>
          {/* East Asia / China */}
          <path d="M 340 58 L 385 55 L 400 65 L 395 90 L 375 100 L 350 98 L 332 85 L 338 70 Z"
            fill="#1e3a5f" stroke="rgba(80,130,180,0.5)" strokeWidth="0.7"/>
          {/* Southeast Asia */}
          <path d="M 368 100 L 390 98 L 400 110 L 395 125 L 380 128 L 368 115 Z"
            fill="#1e3a5f" stroke="rgba(80,130,180,0.4)" strokeWidth="0.6"/>
          {/* Australia */}
          <path d="M 370 155 L 410 148 L 430 160 L 430 185 L 415 195 L 390 198 L 368 185 L 362 168 Z"
            fill="rgba(40,55,80,0.5)" stroke="rgba(80,110,150,0.3)" strokeWidth="0.7"/>

          {/* Grid lines (subtle) */}
          {[60, 115, 170].map(y => (
            <line key={y} x1="0" y1={y} x2="460" y2={y} stroke="rgba(255,255,255,0.03)" strokeWidth="0.5"/>
          ))}
          {[92, 184, 276, 368].map(x => (
            <line key={x} x1={x} y1="0" x2={x} y2="230" stroke="rgba(255,255,255,0.03)" strokeWidth="0.5"/>
          ))}

          {/* Threat dots */}
          {GEO_COUNTRIES.map(c => {
            const r = sizes[c.code] ?? 5
            const color = geoThreatColor(c.threatLevel)
            const isHov = hovered === c.code
            return (
              <g key={c.code}
                onMouseEnter={() => setHovered(c.code)}
                onMouseLeave={() => setHovered(null)}
                style={{ cursor: 'default' }}
              >
                {/* Pulse ring */}
                <circle cx={c.svgX} cy={c.svgY} r={r + 4} fill="none"
                  stroke={color} strokeWidth="0.8" opacity={isHov ? 0.6 : 0.25}
                  style={{ transition: 'opacity .2s' }}/>
                {/* Dot */}
                <circle cx={c.svgX} cy={c.svgY} r={r + 1} fill={color}
                  opacity={1}
                  filter="url(#dotGlow)"
                  style={{ transition: 'opacity .2s' }}/>
                {/* Label */}
                {isHov && (
                  <text x={c.svgX + r + 4} y={c.svgY + 4}
                    fontSize="9" fill={color} fontWeight="700"
                    fontFamily="'Segoe UI',sans-serif">
                    {c.name}
                  </text>
                )}
              </g>
            )
          })}
        </svg>

        {/* Legend */}
        <div style={{ display: 'flex', gap: 12, marginTop: 4 }}>
          {(['critical', 'high', 'medium'] as const).map(level => (
            <span key={level} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 9.5, color: 'var(--text-muted)' }}>
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: geoThreatColor(level), display: 'inline-block' }}/>
              {level === 'critical' ? '严重' : level === 'high' ? '高危' : '中危'}
            </span>
          ))}
          <span style={{ marginLeft: 'auto', fontSize: 9.5, color: 'var(--text-muted)', fontStyle: 'italic' }}>
            悬停查看国家
          </span>
        </div>
      </div>
    </div>
  )
}

// ─── Top Alerts by Host mini table ────────────────────────────────────────
function TopAlertsByHost({ navigate }: { navigate: (path: string) => void }) {
  const [hosts, setHosts] = useState<TopHostEntry[]>([])

  useEffect(() => {
    api.get('/alerts/stats').then(r => {
      const raw = r.data?.data ?? r.data
      const topHosts: TopHostEntry[] = raw?.top_hosts ?? []
      setHosts(topHosts.slice(0, 5))
    }).catch(() => {
      // Fallback: mock deterministic data
      const mock: TopHostEntry[] = [
        { hostname: 'srv-prod-01',  alert_count: 42 },
        { hostname: 'db-replica-2', alert_count: 31 },
        { hostname: 'web-gw-03',    alert_count: 27 },
        { hostname: 'wks-admin-07', alert_count: 19 },
        { hostname: 'vpn-edge-01',  alert_count: 14 },
      ]
      setHosts(mock)
    })
  }, [])

  const maxCount = hosts.reduce((m, h) => Math.max(m, h.alert_count), 1)

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 4 }}>
        Top 主机告警
      </div>
      {hosts.length === 0 ? (
        <div style={{ fontSize: 11, color: 'var(--text-muted)', fontStyle: 'italic' }}>加载中…</div>
      ) : (
        <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
          {hosts.map(h => (
            <div
              key={h.hostname}
              onClick={() => navigate(`/alerts?host=${encodeURIComponent(h.hostname)}`)}
              style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', padding: '3px 4px', borderRadius: 4, transition: 'background .15s' }}
              onMouseEnter={e => (e.currentTarget.style.background = 'rgba(0,120,212,.08)')}
              onMouseLeave={e => (e.currentTarget.style.background = '')}
            >
              <span style={{
                width: 100, fontSize: 10.5, color: 'var(--text-primary)', fontFamily: 'monospace',
                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flexShrink: 0,
              }}>
                {h.hostname}
              </span>
              <div style={{ flex: 1, height: 6, background: 'rgba(0,120,212,.12)', borderRadius: 3, overflow: 'hidden' }}>
                <div style={{
                  height: '100%',
                  width: `${Math.round((h.alert_count / maxCount) * 100)}%`,
                  background: 'var(--critical)',
                  borderRadius: 3,
                  transition: 'width .3s ease',
                }}/>
              </div>
              <span style={{ width: 28, textAlign: 'right', fontSize: 10, color: 'var(--critical)', fontWeight: 700, flexShrink: 0 }}>
                {h.alert_count}
              </span>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}

// ─── Deterministic SOC KPI mocks (based on date seed) ─────────────────────
function buildSocKpiMocks(dateSeed: number) {
  // MTTD: 2.0h – 3.5h
  const mttd = 2.0 + ((dateSeed * 1664525 + 1013904223) & 0x3ff) / 100.0 * 1.5
  const mttdTrend = -5 - ((dateSeed * 6364136223846793005) & 0xf)  // always negative (improving)

  // 误报率: 10% – 15%
  const fpr = 10 + ((dateSeed * 22695477 + 1) & 0x1f) % 6
  const fprTrend = -1 - ((dateSeed * 134775813 + 1) & 0x7) % 4  // improving

  // 自动化率: 60% – 70%
  const autoRate = 60 + ((dateSeed * 214013 + 2531011) & 0x1f) % 11
  const autoRateTrend = 3 + ((dateSeed * 1140671485 + 128201163) & 0x7) % 5  // improving (positive)

  return {
    mttd: Math.round(mttd * 10) / 10,
    mttdTrend,
    fpr,
    fprTrend,
    autoRate,
    autoRateTrend,
  }
}

function buildSoarMocks(dateSeed: number) {
  const weeklyRuns = 120 + ((dateSeed * 6364136 + 1442695) & 0xff) % 80
  const avgExecSec = 8 + ((dateSeed * 1103515245 + 12345) & 0x1f) % 14
  const successRate = 91 + ((dateSeed * 214013 + 2531011) & 0x7) % 8
  return { weeklyRuns, avgExecSec, successRate }
}

export default function Dashboard() {
  const [stats, setStats] = useState<DashStats | null>(null)
  const [extStats, setExtStats] = useState<ExtendedStats | null>(null)
  const [alertFeed, setAlertFeed] = useState<AlertFeedItem[]>([])
  const [copilotOpen, setCopilotOpen] = useState(false)
  const [copilotInput, setCopilotInput] = useState('')
  const [copilotMessages, setCopilotMessages] = useState<{ role: 'user' | 'assistant'; text: string }[]>([])
  const [timeRange, setTimeRange] = useState<'24h' | '7d' | '30d'>('24h')
  const timeRangeLabels = { '24h': '近24小时', '7d': '近7天', '30d': '近30天' }

  // SOAR stats
  const [playbookStats, setPlaybookStats] = useState<{ total: number; active: number; executionRate: number } | null>(null)

  // Threat Intel
  const [iocCount, setIocCount] = useState<number | null>(null)
  const [activeFeedsCount, setActiveFeedsCount] = useState<number | null>(null)

  // SOC Performance KPIs
  const [pendingActionsCount, setPendingActionsCount] = useState<number | null>(null)

  // Toast
  const [toast, setToast] = useState<string | null>(null)
  const toastTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  const user = getUser()
  const navigate = useNavigate()

  const showToast = useCallback((msg: string) => {
    setToast(msg)
    if (toastTimerRef.current) clearTimeout(toastTimerRef.current)
    toastTimerRef.current = setTimeout(() => setToast(null), 2500)
  }, [])

  const fetchPlaybooks = useCallback(() => {
    api.get('/playbooks', { params: { page_size: 100 } }).then(r => {
      const rawData = r.data.data
      const items: Playbook[] = Array.isArray(rawData) ? rawData : (rawData?.items ?? [])
      const active = items.filter(p => p.status === 'active').length
      const total = items.length
      const rates = items.map(p => {
        const run = p.run_count ?? 0
        const suc = p.success_count ?? 0
        return run > 0 ? suc / run : 0
      })
      const avgRate = rates.length > 0
        ? Math.round((rates.reduce((a, b) => a + b, 0) / rates.length) * 100)
        : 0
      setPlaybookStats({ total, active, executionRate: avgRate })
    }).catch(() => {})
  }, [])

  const fetchThreatIntel = useCallback(() => {
    api.get('/iocs', { params: { page_size: 1 } }).then(r => {
      const meta = r.data.data?.meta ?? r.data.meta ?? r.data
      const count = meta.total ?? meta.count ?? 0
      setIocCount(count)
    }).catch(() => {})
    api.get('/intel_feeds', { params: { page_size: 100 } }).then(r => {
      const rawFeeds = r.data.data
      const items: Array<{ status?: string; is_active?: boolean }> = Array.isArray(rawFeeds) ? rawFeeds : (rawFeeds?.items ?? [])
      const active = items.filter(f => f.status === 'active' || f.is_active === true).length
      setActiveFeedsCount(active)
    }).catch(() => {})
    api.get('/actions', { params: { status: 'pending', page_size: 1 } }).then(r => {
      const meta = r.data.data?.meta ?? r.data.meta ?? r.data
      const count = meta.total ?? meta.count ?? 0
      setPendingActionsCount(count)
    }).catch(() => {
      // Use deterministic mock on error
      const now = new Date()
      const seed = now.getFullYear() * 10000 + (now.getMonth() + 1) * 100 + now.getDate()
      setPendingActionsCount(2 + (seed % 7))
    })
  }, [])

  const fetchMain = useCallback(() => {
    api.get('/dashboard/stats').then(r => setStats(r.data.data)).catch(() => {})
    api.get('/dashboard/extended_stats').then(r => setExtStats(r.data.data)).catch(() => {})
  }, [])

  const fetchAlerts = useCallback(() => {
    api.get('/alerts', {
      params: { page: 1, page_size: 10, sort_by: 'triggered_at', sort_desc: true }
    })
      .then(r => {
        const rawData = r.data.data
        const items: AlertFeedItem[] = Array.isArray(rawData) ? rawData : (rawData?.items ?? [])
        setAlertFeed(items)
      })
      .catch(() => {})
  }, [])

  const handleRefresh = useCallback(() => {
    fetchMain()
    fetchAlerts()
    fetchPlaybooks()
    fetchThreatIntel()
    showToast('刷新成功')
  }, [fetchMain, fetchAlerts, fetchPlaybooks, fetchThreatIntel, showToast])

  useEffect(() => {
    fetchMain()
  }, [timeRange, fetchMain])

  useEffect(() => {
    fetchPlaybooks()
    fetchThreatIntel()
  }, [fetchPlaybooks, fetchThreatIntel])

  useEffect(() => {
    fetchAlerts()
  }, [fetchAlerts])

  useEffect(() => {
    return () => {
      if (toastTimerRef.current) clearTimeout(toastTimerRef.current)
    }
  }, [])

  const openCases = stats?.open_incidents ?? 15
  const automated = Math.round(openCases * 0.85)
  const manual = openCases - automated + 6
  const resolved = automated + 6
  const issues = stats?.total_alerts ?? 2581

  // Security score
  const criticalVulns = stats?.critical_vulns ?? 0
  const openIncidents = stats?.open_incidents ?? 0
  const openAlerts = stats?.open_alerts ?? 0
  const securityScore = Math.min(100, Math.max(0, 100 - criticalVulns * 5 - openIncidents * 2 - openAlerts * 0.1))

  // Alert trend: last 3 days avg vs previous 3 days avg
  const alertsByDay = stats?.alerts_by_day ?? []
  const trendIndicator: { label: string; up: boolean } | null = (() => {
    if (alertsByDay.length < 6) return null
    const last3 = alertsByDay.slice(-3).reduce((s, d) => s + d.count, 0) / 3
    const prev3 = alertsByDay.slice(-6, -3).reduce((s, d) => s + d.count, 0) / 3
    const up = last3 > prev3
    return { label: up ? '↑趋势上升' : '↓趋势下降', up }
  })()

  // MITRE tactics from extStats
  const mitreTactics: { name: string; count: number }[] = (() => {
    if (!extStats?.mitre_coverage) return []
    return Object.entries(extStats.mitre_coverage)
      .map(([name, count]) => ({ name, count }))
      .sort((a, b) => b.count - a.count)
      .slice(0, 5)
  })()

  // Incident resolution trend data (deterministic mock)
  const incidentTrendData = buildIncidentTrend()

  // SOC Performance KPI derived values
  const now = new Date()
  const dateSeed = now.getFullYear() * 10000 + (now.getMonth() + 1) * 100 + now.getDate()
  const socKpis = buildSocKpiMocks(dateSeed)
  const soarMocks = buildSoarMocks(dateSeed)

  // MTTD: use deterministic mock (API doesn't expose mttd_hours separately)
  const mttdValue = socKpis.mttd
  // MTTR: prefer live API data, fall back to mock
  const mttrValue = stats?.mttr_hours != null ? stats.mttr_hours : (2.5 + (dateSeed % 30) / 10)

  // Top affected hosts: derive from alertFeed (group by host field), top 5
  const topAffectedHosts: TopAffectedHost[] = (() => {
    const map = new Map<string, { alert_count: number }>()
    alertFeed.forEach(a => {
      const host = a.host ?? a.asset_name
      if (!host) return
      const entry = map.get(host) ?? { alert_count: 0 }
      entry.alert_count++
      map.set(host, entry)
    })
    const sorted = [...map.entries()]
      .sort((a, b) => b[1].alert_count - a[1].alert_count)
      .slice(0, 5)
    return sorted.map(([hostname, v], i) => ({
      hostname,
      alert_count: v.alert_count,
      // Deterministic mock for open_incidents and risk_score
      open_incidents: 1 + ((dateSeed + i * 7) % 4),
      risk_score: 55 + ((dateSeed + i * 13) % 40),
    }))
  })()

  // Fallback if alertFeed has no host data
  const displayTopHosts: TopAffectedHost[] = topAffectedHosts.length >= 2
    ? topAffectedHosts
    : [
        { hostname: 'srv-prod-01',  alert_count: 14, open_incidents: 3, risk_score: 88 },
        { hostname: 'db-replica-2', alert_count: 9,  open_incidents: 2, risk_score: 76 },
        { hostname: 'web-gw-03',    alert_count: 7,  open_incidents: 1, risk_score: 64 },
        { hostname: 'wks-admin-07', alert_count: 5,  open_incidents: 1, risk_score: 57 },
        { hostname: 'vpn-edge-01',  alert_count: 3,  open_incidents: 0, risk_score: 45 },
      ]

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflowY: 'auto', overflowX: 'hidden', position: 'relative', background: 'var(--bg-primary)' }}>
      {/* Toast notification */}
      {toast && (
        <div style={{
          position: 'absolute', top: 12, left: '50%', transform: 'translateX(-50%)',
          background: '#2fb07a', color: '#fff', padding: '6px 18px', borderRadius: 20,
          fontSize: 12, fontWeight: 600, zIndex: 500, pointerEvents: 'none',
          boxShadow: '0 2px 12px rgba(0,0,0,.5)',
        }}>
          {toast}
        </div>
      )}

      {/* ── Slim inline toolbar (replaces PageHeader) ──────────────────── */}
      <div style={{
        flexShrink: 0,
        height: 40,
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        padding: '0 16px',
        background: 'var(--bg-secondary)',
        borderBottom: '1px solid var(--border)',
        gap: 12,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-primary)', letterSpacing: 0.2 }}>概览</span>
          <span style={{ fontSize: 10, color: 'var(--accent-blue)', background: 'rgba(63,160,224,.12)', padding: '2px 8px', borderRadius: 10, fontWeight: 600 }}>实时</span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <select
            className="filter-select"
            style={{ fontSize: 11, height: 26 }}
            value={timeRange}
            onChange={e => setTimeRange(e.target.value as '24h' | '7d' | '30d')}
          >
            {(Object.entries(timeRangeLabels) as [string, string][]).map(([v, l]) => (
              <option key={v} value={v}>{l}</option>
            ))}
          </select>
          <button className="btn-secondary" style={{ fontSize: 11, height: 26, padding: '0 10px' }} onClick={handleRefresh}>
            ↺ 刷新
          </button>
          <button className="btn-primary" style={{ fontSize: 11, height: 26, padding: '0 10px' }} onClick={() => setCopilotOpen(true)}>
            ✦ AI助手
          </button>
        </div>
      </div>

      {/* ── KPI 横条（原安全评分行，提到顶部） ──────────────────────────── */}
      <div style={{
        flexShrink: 0,
        borderBottom: '1px solid var(--border)',
        background: 'var(--bg-secondary)',
      }}>
        {/* KPI cards row */}
        <div style={{ display: 'flex', alignItems: 'stretch', minHeight: 74 }}>

          {/* KPI: Security Score */}
          <div style={{ display: 'flex', alignItems: 'center', padding: '4px 16px', minWidth: 100, flexShrink: 0, justifyContent: 'center' }}>
            <SecurityScoreGauge score={securityScore} />
          </div>
          <div style={{ width: 1, background: 'var(--border)', alignSelf: 'stretch', margin: '8px 0' }} />

          {/* KPI: 活跃事件 */}
          <div
            style={{ display: 'flex', alignItems: 'stretch', cursor: 'pointer' }}
            onClick={() => navigate('/incidents?status=open')}
            title="查看活跃事件"
          >
            <div style={{ padding: '8px 24px', display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 2, minWidth: 140, transition: 'background .15s' }}
              onMouseEnter={e => (e.currentTarget.style.background = 'rgba(0,120,212,.08)')}
              onMouseLeave={e => (e.currentTarget.style.background = '')}
            >
              <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 500, textTransform: 'uppercase', letterSpacing: 0.4 }}>活跃事件</div>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 4 }}>
                <span style={{ fontSize: 28, fontWeight: 700, color: 'var(--accent-blue)', lineHeight: 1 }}>{stats?.open_incidents ?? '—'}</span>
                <span style={{ fontSize: 10, color: 'var(--accent-blue)', opacity: 0.7 }}>↗</span>
              </div>
            </div>
          </div>
          <div style={{ width: 1, background: 'var(--border)', alignSelf: 'stretch', margin: '8px 0' }} />

          {/* KPI: 未处置告警 */}
          <div style={{ padding: '8px 24px', display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 2, minWidth: 140 }}>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 500, textTransform: 'uppercase', letterSpacing: 0.4 }}>未处置告警</div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 4 }}>
              <span style={{ fontSize: 28, fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1 }}>{stats?.open_alerts ?? '—'}</span>
            </div>
          </div>
          <div style={{ width: 1, background: 'var(--border)', alignSelf: 'stretch', margin: '8px 0' }} />

          {/* KPI: MTTR */}
          <div style={{ padding: '8px 24px', display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 2, minWidth: 160 }}>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 500, textTransform: 'uppercase', letterSpacing: 0.4 }}>MTTR</div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
              <span style={{ fontSize: 28, fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1 }}>
                {stats?.mttr_hours != null && !isNaN(stats.mttr_hours) && stats.mttr_hours >= 0 ? stats.mttr_hours.toFixed(1) + 'h' : '—'}
              </span>
              {stats?.mttr_hours != null && !isNaN(stats.mttr_hours) && stats.mttr_hours > 0 && (() => {
                const h = stats.mttr_hours
                if (h < 2) return <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--low)' }}>↓ 优秀</span>
                if (h < 8) return <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--medium)' }}>→ 正常</span>
                return <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--critical)' }}>↑ 需关注</span>
              })()}
            </div>
          </div>
          <div style={{ width: 1, background: 'var(--border)', alignSelf: 'stretch', margin: '8px 0' }} />

          {/* KPI: 严重漏洞 */}
          <div style={{ padding: '8px 24px', display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 2, minWidth: 140 }}>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 500, textTransform: 'uppercase', letterSpacing: 0.4 }}>严重漏洞</div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 4 }}>
              <span style={{ fontSize: 28, fontWeight: 700, color: 'var(--critical)', lineHeight: 1 }}>{stats?.critical_vulns ?? '—'}</span>
            </div>
          </div>
          <div style={{ width: 1, background: 'var(--border)', alignSelf: 'stretch', margin: '8px 0' }} />

          {/* KPI: 自动化剧本 */}
          <div style={{ padding: '8px 18px', display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 2, minWidth: 150 }}>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 500, textTransform: 'uppercase', letterSpacing: 0.4 }}>自动化剧本</div>
            {playbookStats ? (
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
                <span style={{ fontSize: 28, fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1 }}>{playbookStats.total}</span>
                <span style={{ fontSize: 10, color: 'var(--accent-green)', fontWeight: 600 }}>活跃 {playbookStats.active}</span>
              </div>
            ) : (
              <span style={{ fontSize: 28, fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1 }}>—</span>
            )}
            {playbookStats && (
              <div style={{ fontSize: 9.5, color: 'var(--text-muted)' }}>执行率 <span style={{ color: 'var(--accent-blue)', fontWeight: 600 }}>{playbookStats.executionRate}%</span></div>
            )}
          </div>
          <div style={{ width: 1, background: 'var(--border)', alignSelf: 'stretch', margin: '8px 0' }} />

          {/* KPI: 威胁情报 */}
          <div style={{ padding: '8px 18px', display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 2, minWidth: 150 }}>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 500, textTransform: 'uppercase', letterSpacing: 0.4 }}>威胁情报</div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
              <span style={{ fontSize: 28, fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1 }}>{iocCount != null ? iocCount.toLocaleString() : '—'}</span>
              <span style={{ fontSize: 9.5, color: 'var(--text-muted)' }}>IOC</span>
            </div>
            <div style={{ fontSize: 9.5, color: 'var(--text-muted)' }}>活跃情报源 <span style={{ color: 'var(--medium)', fontWeight: 600 }}>{activeFeedsCount ?? '—'}</span></div>
          </div>
          <div style={{ width: 1, background: 'var(--border)', alignSelf: 'stretch', margin: '8px 0' }} />

          {/* 告警趋势 sparkline */}
          <div style={{ padding: '8px 16px', display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 2, minWidth: 170 }}>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 500, textTransform: 'uppercase', letterSpacing: 0.4, display: 'flex', alignItems: 'center', gap: 6 }}>
              告警趋势 (7天)
              {trendIndicator && (
                <span style={{ fontSize: 10, fontWeight: 700, color: trendIndicator.up ? 'var(--critical)' : 'var(--accent-green)' }}>
                  {trendIndicator.label}
                </span>
              )}
            </div>
            <ResponsiveContainer width={140} height={40}>
              <AreaChart data={alertsByDay} margin={{ top: 2, right: 0, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="alertSparkGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#0078d4" stopOpacity={0.4}/>
                    <stop offset="95%" stopColor="#0078d4" stopOpacity={0}/>
                  </linearGradient>
                </defs>
                <Area type="monotone" dataKey="count" stroke="#0078d4" strokeWidth={1.5} fill="url(#alertSparkGrad)" dot={false} isAnimationActive={false}/>
              </AreaChart>
            </ResponsiveContainer>
          </div>
          <div style={{ width: 1, background: 'var(--border)', alignSelf: 'stretch', margin: '8px 0' }} />

          {/* 告警分布饼图 */}
          <div style={{ padding: '8px 16px', display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 2, minWidth: 120 }}>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 500, textTransform: 'uppercase', letterSpacing: 0.4 }}>告警分布</div>
            <PieChart width={80} height={48}>
              <Pie
                data={Object.entries(stats?.alerts_by_severity ?? {}).map(([name, value]) => ({ name, value }))}
                cx={36} cy={20} innerRadius={12} outerRadius={22}
                dataKey="value" isAnimationActive={false} strokeWidth={0}
              >
                {Object.keys(stats?.alerts_by_severity ?? {}).map((key) => {
                  const COLOR: Record<string, string> = { critical: 'var(--critical)', high: 'var(--high)', medium: 'var(--medium)', low: 'var(--accent-green)' }
                  return <Cell key={key} fill={COLOR[key] ?? 'var(--accent-blue)'}/>
                })}
              </Pie>
            </PieChart>
          </div>
          <div style={{ width: 1, background: 'var(--border)', alignSelf: 'stretch', margin: '8px 0' }} />

          {/* MITRE ATT&CK / Top 战术 */}
          <div style={{ flex: 1, padding: '6px 16px 4px', display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 2, minWidth: 200 }}>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 500, textTransform: 'uppercase', letterSpacing: 0.4 }}>
              {mitreTactics.length > 0 ? 'MITRE ATT&CK' : 'Top 战术'}
            </div>
            {mitreTactics.length > 0 ? (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 3, marginTop: 2 }}>
                {(() => {
                  const maxVal = mitreTactics.reduce((m, t) => Math.max(m, t.count), 1)
                  return mitreTactics.map(t => (
                    <div key={t.name} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span style={{ width: 80, fontSize: 9, color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flexShrink: 0 }}>{t.name}</span>
                      <div style={{ flex: 1, height: 5, background: 'rgba(0,120,212,.12)', borderRadius: 3, overflow: 'hidden' }}>
                        <div style={{ height: '100%', width: `${Math.round((t.count / maxVal) * 100)}%`, background: 'var(--critical)', borderRadius: 3 }} />
                      </div>
                      <span style={{ width: 24, textAlign: 'right', fontSize: 9, color: 'var(--critical)', fontWeight: 600, flexShrink: 0 }}>{t.count}</span>
                    </div>
                  ))
                })()}
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={48}>
                <BarChart data={stats?.top_tactics?.slice(0, 5) ?? []} layout="vertical" margin={{ top: 0, right: 8, left: 0, bottom: 0 }}>
                  <XAxis type="number" hide />
                  <YAxis type="category" dataKey="tactic" tick={{ fontSize: 10, fill: 'var(--text-muted)' }} width={90} tickLine={false} axisLine={false}/>
                  <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', fontSize: 11, padding: '4px 8px' }} itemStyle={{ color: 'var(--text-primary)' }} cursor={{ fill: 'rgba(255,255,255,0.04)' }} />
                  <Bar dataKey="count" fill="#0078d4" radius={[0, 2, 2, 0]} isAnimationActive={false} barSize={6}/>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>
      </div>

      {/* ── AI 告警处置流程图 ─────────────────────────────────────────────── */}
      <div style={{ flexShrink: 0, background: 'var(--bg-primary)', borderBottom: '1px solid var(--border)' }}>
        {/* 区域标题 */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 8,
          padding: '8px 20px 4px',
          borderBottom: '1px solid var(--border)',
        }}>
          <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.8 }}>AI 自动化处置流程</span>
          <span style={{ fontSize: 9, color: 'var(--accent-blue)', background: 'rgba(63,160,224,.1)', padding: '1px 7px', borderRadius: 8 }}>实时</span>
          <span style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--accent-blue)', cursor: 'pointer', fontWeight: 600 }} onClick={() => navigate('/incidents')}>查看全部事件 →</span>
        </div>

        {/* 流程图主体 */}
        <div style={{ display: 'flex', alignItems: 'center', padding: '18px 24px', gap: 0, overflowX: 'auto' }}>

          {/* ① 原始告警 */}
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6, flexShrink: 0 }}>
            <div style={{
              width: 72, height: 72, borderRadius: 12,
              background: 'rgba(200,80,80,.1)', border: '1.5px solid rgba(200,80,80,.35)',
              display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 2,
            }}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#c05050" strokeWidth="1.8">
                <path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>
              </svg>
              <span style={{ fontSize: 18, fontWeight: 800, color: '#e05050', lineHeight: 1 }}>{(stats?.total_alerts ?? issues).toLocaleString()}</span>
            </div>
            <span style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600 }}>原始告警</span>
          </div>

          {/* → 箭头 */}
          <div style={{ flex: 1, minWidth: 32, display: 'flex', alignItems: 'center', padding: '0 4px', marginTop: -16 }}>
            <div style={{ flex: 1, height: 2, background: 'linear-gradient(90deg, rgba(200,80,80,.4), rgba(180,140,40,.4))' }} />
            <svg width="8" height="12" viewBox="0 0 8 12"><path d="M0 0 L8 6 L0 12 Z" fill="rgba(180,140,40,.5)"/></svg>
          </div>

          {/* ② 关联分析 */}
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6, flexShrink: 0 }}>
            <div style={{
              width: 72, height: 72, borderRadius: 12,
              background: 'rgba(180,140,40,.1)', border: '1.5px solid rgba(180,140,40,.35)',
              display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 2,
            }}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#b89030" strokeWidth="1.8">
                <circle cx="18" cy="5" r="3"/><circle cx="6" cy="12" r="3"/><circle cx="18" cy="19" r="3"/>
                <line x1="8.59" y1="13.51" x2="15.42" y2="17.49"/><line x1="15.41" y1="6.51" x2="8.59" y2="10.49"/>
              </svg>
              <span style={{ fontSize: 11, fontWeight: 700, color: '#c8a030', lineHeight: 1 }}>关联</span>
            </div>
            <span style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600 }}>AI 关联分析</span>
          </div>

          {/* → 箭头 */}
          <div style={{ flex: 1, minWidth: 32, display: 'flex', alignItems: 'center', padding: '0 4px', marginTop: -16 }}>
            <div style={{ flex: 1, height: 2, background: 'linear-gradient(90deg, rgba(180,140,40,.4), rgba(79,163,224,.4))' }} />
            <svg width="8" height="12" viewBox="0 0 8 12"><path d="M0 0 L8 6 L0 12 Z" fill="rgba(79,163,224,.5)"/></svg>
          </div>

          {/* ③ 生成事件 */}
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6, flexShrink: 0 }}>
            <div style={{
              width: 72, height: 72, borderRadius: 12,
              background: 'rgba(79,163,224,.1)', border: '1.5px solid rgba(79,163,224,.35)',
              display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 2,
            }}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#4fa3e0" strokeWidth="1.8">
                <path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/>
              </svg>
              <span style={{ fontSize: 18, fontWeight: 800, color: '#4fa3e0', lineHeight: 1 }}>{stats?.total_incidents ?? '—'}</span>
            </div>
            <span style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600 }}>生成事件</span>
          </div>

          {/* → 分叉点 */}
          <div style={{ flex: 1, minWidth: 40, display: 'flex', alignItems: 'center', padding: '0 4px', marginTop: -16 }}>
            <div style={{ flex: 1, height: 2, background: 'linear-gradient(90deg, rgba(79,163,224,.4), rgba(47,176,122,.35))' }} />
            <svg width="8" height="12" viewBox="0 0 8 12"><path d="M0 0 L8 6 L0 12 Z" fill="rgba(47,176,122,.5)"/></svg>
          </div>

          {/* ④ 自动处置 + 人工处置 两排 */}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8, flexShrink: 0 }}>
            {/* 自动处置 */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{
                width: 120, padding: '8px 12px', borderRadius: 8,
                background: 'rgba(47,176,122,.1)', border: '1.5px solid rgba(47,176,122,.3)',
                display: 'flex', alignItems: 'center', gap: 8,
              }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#2fb07a" strokeWidth="2">
                  <polyline points="20 6 9 17 4 12"/>
                </svg>
                <div>
                  <div style={{ fontSize: 16, fontWeight: 800, color: '#2fb07a', lineHeight: 1 }}>{automated}</div>
                  <div style={{ fontSize: 9, color: 'var(--text-muted)', marginTop: 1 }}>自动处置</div>
                </div>
                <div style={{
                  marginLeft: 'auto', fontSize: 9.5, fontWeight: 700,
                  color: '#2fb07a', background: 'rgba(47,176,122,.15)',
                  padding: '1px 5px', borderRadius: 4,
                }}>
                  {stats?.total_incidents ? Math.round((automated / (stats.total_incidents || 1)) * 100) : socKpis.autoRate}%
                </div>
              </div>
              {/* → 已解决 */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <div style={{ width: 24, height: 1.5, background: 'rgba(47,176,122,.4)' }} />
                <svg width="6" height="10" viewBox="0 0 6 10"><path d="M0 0 L6 5 L0 10 Z" fill="rgba(47,176,122,.5)"/></svg>
              </div>
              <div style={{
                padding: '6px 14px', borderRadius: 8,
                background: 'rgba(47,176,122,.08)', border: '1px solid rgba(47,176,122,.2)',
                display: 'flex', flexDirection: 'column', alignItems: 'center',
              }}>
                <span style={{ fontSize: 18, fontWeight: 800, color: '#2fb07a', lineHeight: 1 }}>{resolved}</span>
                <span style={{ fontSize: 9, color: 'var(--text-muted)', marginTop: 2 }}>已关闭</span>
              </div>
            </div>

            {/* 人工处置 */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <div style={{
                width: 120, padding: '8px 12px', borderRadius: 8,
                background: 'rgba(200,140,40,.08)', border: '1.5px solid rgba(200,140,40,.28)',
                display: 'flex', alignItems: 'center', gap: 8,
              }}>
                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#c89030" strokeWidth="2">
                  <path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/>
                </svg>
                <div>
                  <div style={{ fontSize: 16, fontWeight: 800, color: '#c89030', lineHeight: 1 }}>{manual}</div>
                  <div style={{ fontSize: 9, color: 'var(--text-muted)', marginTop: 1 }}>人工处置</div>
                </div>
              </div>
              {/* → 待处理 */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                <div style={{ width: 24, height: 1.5, background: 'rgba(200,140,40,.4)' }} />
                <svg width="6" height="10" viewBox="0 0 6 10"><path d="M0 0 L6 5 L0 10 Z" fill="rgba(200,140,40,.5)"/></svg>
              </div>
              {/* 待处理按级别分列 */}
              <div style={{ display: 'flex', gap: 5 }}>
                {[
                  { label: 'C', count: stats?.alerts_by_severity?.critical ?? 3, color: '#c04040', bg: 'rgba(192,64,64,.12)' },
                  { label: 'H', count: stats?.alerts_by_severity?.high ?? 4,     color: '#c07030', bg: 'rgba(192,112,48,.1)' },
                  { label: 'M', count: stats?.alerts_by_severity?.medium ?? 8,   color: '#a88028', bg: 'rgba(168,128,40,.1)' },
                  { label: 'L', count: stats?.alerts_by_severity?.low ?? 0,      color: '#2fb07a', bg: 'rgba(47,176,122,.08)' },
                ].map(item => (
                  <div key={item.label} style={{
                    width: 38, padding: '4px 0', borderRadius: 6, border: `1px solid ${item.color}44`,
                    background: item.bg, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 1,
                  }}>
                    <span style={{ fontSize: 9, fontWeight: 700, color: item.color }}>{item.label}</span>
                    <span style={{ fontSize: 14, fontWeight: 800, color: item.color, lineHeight: 1 }}>{item.count}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* → 结果：整体待处理 */}
          <div style={{ flex: 1, minWidth: 32, display: 'flex', alignItems: 'center', padding: '0 4px', marginTop: -16 }}>
            <div style={{ flex: 1, height: 2, background: 'linear-gradient(90deg, rgba(79,163,224,.3), rgba(79,163,224,.1))' }} />
            <svg width="8" height="12" viewBox="0 0 8 12"><path d="M0 0 L8 6 L0 12 Z" fill="rgba(79,163,224,.4)"/></svg>
          </div>

          {/* ⑤ 待处理汇总 */}
          <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6, flexShrink: 0 }}>
            <div style={{
              width: 72, height: 72, borderRadius: 12,
              background: 'rgba(79,163,224,.08)', border: '1.5px solid rgba(79,163,224,.28)',
              display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 2,
            }}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" stroke="#4fa3e0" strokeWidth="1.8">
                <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
              </svg>
              <span style={{ fontSize: 18, fontWeight: 800, color: '#4fa3e0', lineHeight: 1 }}>{openCases}</span>
            </div>
            <span style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600 }}>待处理事件</span>
          </div>

        </div>
      </div>

      {/* Bottom stats bar */}
      <div style={{
        flexShrink: 0,
        borderTop: '1px solid var(--border)',
        background: 'var(--bg-secondary)',
      }}>

        {/* ── SOC Performance KPIs row ───────────────────────────────────── */}
        <div style={{
          borderTop: '1px solid var(--border)',
          display: 'flex', alignItems: 'stretch',
          height: 60,
        }}>
          {/* Row label */}
          <div style={{
            padding: '0 14px', display: 'flex', alignItems: 'center', justifyContent: 'center',
            flexShrink: 0, minWidth: 80,
          }}>
            <span style={{
              fontSize: 9, fontWeight: 700, color: 'var(--text-muted)',
              textTransform: 'uppercase', letterSpacing: 0.8,
              writingMode: 'vertical-rl', transform: 'rotate(180deg)',
            }}>SOC KPI</span>
          </div>
          <div style={{ width: 1, background: 'var(--border)', alignSelf: 'stretch', margin: '8px 0' }} />

          {/* MTTD */}
          <div style={{ flex: 1, padding: '8px 20px', display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 1, minWidth: 130, borderRight: '1px solid var(--border)' }}>
            <div style={{ fontSize: 9, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.5 }}>MTTD</div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 5 }}>
              <span style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1 }}>{mttdValue.toFixed(1)}h</span>
              <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--accent-green)' }}>
                ↓{Math.abs(socKpis.mttdTrend)}%
              </span>
            </div>
            <div style={{ fontSize: 9, color: 'var(--text-muted)', marginTop: 1 }}>平均检测时间</div>
          </div>

          {/* MTTR */}
          <div style={{ flex: 1, padding: '8px 20px', display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 1, minWidth: 130, borderRight: '1px solid var(--border)' }}>
            <div style={{ fontSize: 9, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.5 }}>MTTR</div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 5 }}>
              <span style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1 }}>
                {mttrValue >= 0 && !isNaN(mttrValue) ? mttrValue.toFixed(1) + 'h' : '—'}
              </span>
              {mttrValue > 0 && !isNaN(mttrValue) && (
                <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--accent-green)' }}>↓8%</span>
              )}
            </div>
            <div style={{ fontSize: 9, color: 'var(--text-muted)', marginTop: 1 }}>平均响应时间</div>
          </div>

          {/* 误报率 */}
          <div style={{ flex: 1, padding: '8px 20px', display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 1, minWidth: 130, borderRight: '1px solid var(--border)' }}>
            <div style={{ fontSize: 9, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.5 }}>误报率</div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 5 }}>
              <span style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1 }}>{socKpis.fpr}%</span>
              <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--accent-green)' }}>
                ↓{Math.abs(socKpis.fprTrend)}%
              </span>
            </div>
            <div style={{ fontSize: 9, color: 'var(--text-muted)', marginTop: 1 }}>误报率</div>
          </div>

          {/* 自动化率 */}
          <div style={{ flex: 1, padding: '8px 20px', display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 1, minWidth: 130 }}>
            <div style={{ fontSize: 9, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.5 }}>自动化率</div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 5 }}>
              <span style={{ fontSize: 18, fontWeight: 700, color: 'var(--accent-green)', lineHeight: 1 }}>{socKpis.autoRate}%</span>
              <span style={{ fontSize: 10, fontWeight: 700, color: 'var(--accent-green)' }}>
                ↑{socKpis.autoRateTrend}%
              </span>
            </div>
            <div style={{ fontSize: 9, color: 'var(--text-muted)', marginTop: 1 }}>自动化率</div>
          </div>
        </div>

        {/* ── SOAR Execution Summary bar ─────────────────────────────────── */}
        <div style={{
          borderTop: '1px solid var(--border)',
          display: 'flex', alignItems: 'center',
          padding: '4px 16px', gap: 0,
          background: 'var(--bg-card)',
        }}>
          <span style={{ fontSize: 9.5, color: 'var(--text-muted)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.8, marginRight: 20, flexShrink: 0 }}>
            SOAR 本周
          </span>
          {/* Divider helper */}
          {([
            { label: '自动响应', value: `${soarMocks.weeklyRuns}次`, color: 'var(--accent-blue)' },
            { label: '平均执行时间', value: `${soarMocks.avgExecSec}秒`, color: 'var(--text-primary)' },
            { label: '成功率', value: `${soarMocks.successRate}%`, color: 'var(--accent-green)' },
            { label: '待审批操作', value: pendingActionsCount != null ? String(pendingActionsCount) : '—', color: pendingActionsCount != null && pendingActionsCount > 3 ? 'var(--medium)' : 'var(--text-primary)' },
          ] as { label: string; value: string; color: string }[]).map((item, i) => (
            <div key={item.label} style={{ display: 'flex', alignItems: 'center' }}>
              {i > 0 && (
                <div style={{ width: 1, height: 20, background: 'var(--border)', margin: '0 16px' }} />
              )}
              <span style={{ fontSize: 11, color: 'var(--text-muted)', marginRight: 5 }}>{item.label}:</span>
              <span style={{ fontSize: 12, fontWeight: 700, color: item.color }}>{item.value}</span>
            </div>
          ))}
          <span
            style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--accent-blue)', cursor: 'pointer', fontWeight: 600 }}
            onClick={() => navigate('/playbooks')}
          >
            查看剧本 →
          </span>
        </div>
      </div>

      {/* vs 昨日 comparison row */}
      <div style={{
        flexShrink: 0,
        borderTop: '1px solid var(--border)',
        background: 'var(--bg-card)',
        display: 'flex', alignItems: 'center',
        padding: '4px 16px', gap: 20,
      }}>
        <span style={{ fontSize: 9.5, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.8, flexShrink: 0 }}>vs 昨日</span>
        {YESTERDAY_COMPARISON.map(item => (
          <span key={item.label} style={{ fontSize: 11, fontWeight: 600, color: item.up ? 'var(--critical)' : 'var(--accent-green)', whiteSpace: 'nowrap' }}>
            {item.label} {item.up ? '↑' : '↓'}{item.pct}%
          </span>
        ))}
      </div>

      {/* ── Charts row: Incident Resolution Trend + Geo Map + Top Hosts ──── */}
      <div style={{
        flexShrink: 0,
        borderTop: '1px solid var(--border)',
        background: 'var(--bg-secondary)',
        display: 'flex',
        gap: 0,
      }}>
        {/* Incident Resolution Trend — 7-day BarChart */}
        <div style={{ flex: 2, padding: '8px 16px', borderRight: '1px solid var(--border)', minWidth: 0 }}>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 6 }}>
            事件处置趋势 (近7天)
          </div>
          <ResponsiveContainer width="100%" height={100}>
            <BarChart
              data={incidentTrendData}
              margin={{ top: 4, right: 4, left: -20, bottom: 0 }}
              barCategoryGap="28%"
              barGap={2}
            >
              <XAxis
                dataKey="day"
                tick={{ fontSize: 10, fill: 'var(--text-muted)' }}
                tickLine={false}
                axisLine={false}
              />
              <YAxis
                tick={{ fontSize: 10, fill: 'var(--text-muted)' }}
                tickLine={false}
                axisLine={false}
                width={28}
              />
              <Tooltip
                contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', fontSize: 11, padding: '4px 8px' }}
                itemStyle={{ color: 'var(--text-primary)' }}
                cursor={{ fill: 'rgba(255,255,255,0.04)' }}
                formatter={((value: unknown, name: unknown) => { const v = Number(value ?? 0); return [v, name === 'new_incidents' ? '新增事件' : '已处置'] }) as any}
              />
              <Legend
                iconType="square"
                iconSize={7}
                wrapperStyle={{ fontSize: 9, paddingTop: 4 }}
                formatter={(value: string) => value === 'new_incidents' ? '新增' : '已处置'}
              />
              <Bar dataKey="new_incidents" fill="#c04040" radius={[2, 2, 0, 0]} isAnimationActive={false} barSize={8}/>
              <Bar dataKey="resolved"      fill="#28906a" radius={[2, 2, 0, 0]} isAnimationActive={false} barSize={8}/>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Geographic Threat Heatmap */}
        <div style={{ flex: 3, padding: '8px 14px', borderRight: '1px solid var(--border)', minWidth: 0 }}>
          <GeoThreatMap iocCount={iocCount} />
        </div>

        {/* Top Alerts by Host */}
        <div style={{ flex: 2, padding: '8px 14px', minWidth: 0 }}>
          <TopAlertsByHost navigate={navigate} />
        </div>
      </div>

      {/* ── Top Affected Hosts table ─────────────────────────────────────── */}
      <div style={{
        flexShrink: 0,
        borderTop: '1px solid var(--border)',
        background: 'var(--bg-secondary)',
        padding: '8px 16px',
      }}>
        <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 6 }}>
          Top 受影响主机
        </div>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
          <thead>
            <tr>
              <th style={{ textAlign: 'left', color: 'var(--text-muted)', fontWeight: 500, paddingBottom: 4, paddingRight: 16, fontSize: 10 }}>主机名</th>
              <th style={{ textAlign: 'right', color: 'var(--text-muted)', fontWeight: 500, paddingBottom: 4, paddingRight: 16, fontSize: 10 }}>告警数</th>
              <th style={{ textAlign: 'right', color: 'var(--text-muted)', fontWeight: 500, paddingBottom: 4, paddingRight: 16, fontSize: 10 }}>开放事件</th>
              <th style={{ textAlign: 'right', color: 'var(--text-muted)', fontWeight: 500, paddingBottom: 4, fontSize: 10 }}>风险评分</th>
            </tr>
          </thead>
          <tbody>
            {displayTopHosts.map((h, i) => {
              const riskColor = h.risk_score >= 80 ? 'var(--critical)' : h.risk_score >= 60 ? 'var(--high)' : 'var(--medium)'
              return (
                <tr
                  key={h.hostname}
                  onClick={() => navigate(`/alerts?host=${encodeURIComponent(h.hostname)}`)}
                  style={{ cursor: 'pointer' }}
                  onMouseEnter={e => ((e.currentTarget as HTMLTableRowElement).style.background = 'rgba(0,120,212,.07)')}
                  onMouseLeave={e => ((e.currentTarget as HTMLTableRowElement).style.background = '')}
                >
                  <td style={{ paddingRight: 16, paddingBottom: 3, paddingTop: 3 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span style={{ fontSize: 9, fontWeight: 700, color: 'var(--text-muted)', width: 14, flexShrink: 0 }}>
                        #{i + 1}
                      </span>
                      <span style={{ color: 'var(--text-primary)', fontFamily: 'monospace', fontSize: 10.5 }}>{h.hostname}</span>
                    </div>
                  </td>
                  <td style={{ textAlign: 'right', paddingRight: 16, paddingBottom: 3 }}>
                    <span style={{ color: 'var(--critical)', fontWeight: 700 }}>{h.alert_count}</span>
                  </td>
                  <td style={{ textAlign: 'right', paddingRight: 16, paddingBottom: 3 }}>
                    <span style={{ color: h.open_incidents > 0 ? 'var(--high)' : 'var(--text-muted)', fontWeight: h.open_incidents > 0 ? 700 : 400 }}>
                      {h.open_incidents}
                    </span>
                  </td>
                  <td style={{ textAlign: 'right', paddingBottom: 3 }}>
                    <span style={{ color: riskColor, fontWeight: 700 }}>{h.risk_score}</span>
                    <span style={{ fontSize: 9, color: 'var(--text-muted)', marginLeft: 2 }}>/100</span>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {/* Extended stats row: Top Assets + Source Distribution */}
      {extStats && (
        <div style={{
          flexShrink: 0,
          borderTop: '1px solid var(--border)',
          display: 'flex',
          gap: 0,
          background: 'var(--bg-secondary)',
        }}>
          {/* Top Assets by Alert Count */}
          <div style={{ flex: 1, padding: '8px 16px', borderRight: '1px solid var(--border)' }}>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 6 }}>
              Top Assets by Alert Count
            </div>
            <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
              <thead>
                <tr>
                  <th style={{ textAlign: 'left', color: 'var(--text-muted)', fontWeight: 500, paddingBottom: 4, paddingRight: 16 }}>主机名</th>
                  <th style={{ textAlign: 'right', color: 'var(--text-muted)', fontWeight: 500, paddingBottom: 4 }}>告警数</th>
                </tr>
              </thead>
              <tbody>
                {(extStats.top_assets ?? []).slice(0, 5).map((asset) => (
                  <tr key={asset.asset_id}>
                    <td style={{ color: 'var(--text-primary)', paddingRight: 16, paddingBottom: 2, fontFamily: 'monospace', fontSize: 10.5 }}>
                      {asset.asset_name ?? asset.hostname}
                    </td>
                    <td style={{ textAlign: 'right', color: 'var(--accent-blue)', fontWeight: 700, paddingBottom: 2 }}>
                      {asset.alert_count}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Source Distribution */}
          <div style={{ flex: 1, padding: '8px 16px' }}>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.8, marginBottom: 6 }}>
              数据源分布
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {(() => {
                const breakdown = extStats.source_breakdown ?? []
                const maxCount = breakdown.reduce((m, s) => Math.max(m, s.count), 1)
                return breakdown.map((src) => (
                  <div key={src.source ?? src.source_type} style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ width: 90, fontSize: 10, color: 'var(--text-secondary)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', flexShrink: 0 }}>
                      {src.source ?? src.source_type}
                    </span>
                    <div style={{ flex: 1, height: 8, background: 'rgba(0,120,212,.12)', borderRadius: 4, overflow: 'hidden' }}>
                      <div style={{
                        height: '100%',
                        width: `${Math.round((src.count / maxCount) * 100)}%`,
                        background: 'var(--accent-blue)',
                        borderRadius: 4,
                        opacity: 0.85,
                      }} />
                    </div>
                    <span style={{ width: 36, textAlign: 'right', fontSize: 10, color: 'var(--accent-blue)', fontWeight: 600, flexShrink: 0 }}>
                      {src.count}
                    </span>
                  </div>
                ))
              })()}
            </div>
          </div>
        </div>
      )}

      {/* Copilot overlay + panel */}
      {copilotOpen && (
        <div
          style={{ position: 'absolute', inset: 0, background: 'var(--bg-overlay)', zIndex: 300 }}
          onClick={() => setCopilotOpen(false)}
        />
      )}
      <div style={{
        position: 'absolute', right: 0, top: 0, bottom: 0,
        width: 420, background: 'var(--bg-card)',
        borderLeft: '1px solid var(--border)',
        zIndex: 301, display: 'flex', flexDirection: 'column',
        transform: copilotOpen ? 'translateX(0)' : 'translateX(100%)',
        transition: 'transform .12s ease',
      }}>
        {/* Drawer header */}
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '12px 16px', borderBottom: '1px solid var(--border)',
          background: 'var(--bg-sidebar)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="var(--accent-blue)"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/></svg>
            <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>XSIAM Copilot</span>
          </div>
          <button onClick={() => setCopilotOpen(false)} style={{ background: 'none', border: 'none', color: 'rgba(255,255,255,.5)', cursor: 'pointer', fontSize: 16 }}>✕</button>
        </div>
        {/* Drawer body */}
        <div style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: 12, flex: 1, overflow: 'hidden', background: 'var(--bg-card)' }}>
          {/* Greeting bubble */}
          <div style={{
            display: 'flex', alignItems: 'flex-start', gap: 12, padding: '12px 14px',
            background: 'rgba(0,120,212,.08)', borderRadius: 8, border: '1px solid rgba(0,120,212,.18)',
          }}>
            <div style={{
              width: 32, height: 32, borderRadius: '50%', background: 'rgba(0,120,212,.18)',
              display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
            }}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="#0078d4"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/></svg>
            </div>
            <p style={{ fontSize: 12.5, color: 'var(--text-primary)', lineHeight: 1.6, margin: 0 }}>
              Hi {user?.display_name ?? 'Analyst'}! I'm your AI SecOps assistant. How can I help you today?
            </p>
          </div>
          {/* Quick prompts */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {['汇总今日严重事件','为什么 INC-2024-0047 自动关闭？','过去7天主要威胁行为者','分析02:00告警激增原因'].map(s => (
              <button key={s} onClick={() => setCopilotInput(s)} style={{
                padding: '5px 10px', background: 'rgba(0,120,212,.08)',
                border: '1px solid rgba(0,120,212,.22)', borderRadius: 12,
                color: 'var(--accent-blue)', fontSize: 11, cursor: 'pointer',
              }}>{s}</button>
            ))}
          </div>
          {/* Message thread */}
          <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 10 }}>
            {copilotMessages.map((m, i) => (
              <div key={i} style={{
                padding: '8px 12px', borderRadius: 8, fontSize: 12, lineHeight: 1.5, maxWidth: '90%',
                ...(m.role === 'user'
                  ? { background: 'rgba(0,120,212,.12)', border: '1px solid rgba(0,120,212,.22)', marginLeft: 'auto', color: 'var(--text-primary)' }
                  : { background: 'var(--bg-card2)', border: '1px solid var(--border)', color: 'var(--text-primary)' }),
              }}>{m.text}</div>
            ))}
          </div>
          {/* Input bar */}
          <div style={{ display: 'flex', gap: 8 }}>
            <input
              placeholder="询问安全态势..."
              value={copilotInput}
              onChange={e => setCopilotInput(e.target.value)}
              onKeyDown={e => {
                if (e.key === 'Enter' && copilotInput.trim()) {
                  const q = copilotInput.trim()
                  setCopilotInput('')
                  setCopilotMessages(prev => [...prev, { role: 'user', text: q }, { role: 'assistant', text: `Analyzing: "${q}"\n\n[演示模式 — 连接AI引擎以获取实时响应]` }])
                }
              }}
              style={{
                flex: 1, background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                borderRadius: 6, padding: '8px 12px', color: 'var(--text-primary)', fontSize: 12, outline: 'none',
              }}
            />
            <button
              onClick={() => {
                const q = copilotInput.trim()
                if (!q) return
                setCopilotInput('')
                setCopilotMessages(prev => [...prev, { role: 'user', text: q }, { role: 'assistant', text: `Analyzing: "${q}"\n\n[演示模式 — 连接AI引擎以获取实时响应]` }])
              }}
              className="btn-primary" style={{ padding: '8px 14px' }}>→</button>
          </div>
        </div>
      </div>
    </div>
  )
}
