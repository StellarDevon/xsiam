import { useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '@/lib/api'
import { getUser } from '@/lib/auth'
import PageHeader from '@/components/PageHeader'
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
  return level === 'critical' ? '#e53935' : level === 'high' ? '#ff6f00' : '#f9a825'
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

// ─── Helper: truncate string ───────────────────────────────────────────────
function truncate(s: string, max: number): string {
  return s.length > max ? s.slice(0, max) + '…' : s
}

function severityDotColor(severity: string): string {
  const m: Record<string, string> = { critical: '#e53935', high: '#ff6f00', medium: '#f9a825', low: '#2a9060' }
  return m[severity?.toLowerCase()] ?? '#9ea3b0'
}

function timeAgo(isoStr: string): string {
  const diff = Math.floor((Date.now() - new Date(isoStr).getTime()) / 1000)
  if (diff < 60) return `${diff}秒前`
  if (diff < 3600) return `${Math.floor(diff / 60)}分钟前`
  if (diff < 86400) return `${Math.floor(diff / 3600)}小时前`
  return `${Math.floor(diff / 86400)}天前`
}

// Hardcoded yesterday comparison data (demo)
const YESTERDAY_COMPARISON = [
  { label: '告警', pct: 12, up: true },
  { label: '事件', pct: 5,  up: false },
  { label: '资产', pct: 3,  up: true },
  { label: '漏洞', pct: 8,  up: false },
]

const SOURCES = [
  { label: '// NGFW', color: '#e05a2b' },
  { label: 'Google Cloud', color: '#4285f4' },
  { label: '▶ amazon webservices', color: '#ff9900' },
  { label: '◼ Azure', color: '#0078d4' },
  { label: '▶ Office 365', color: '#d83b01' },
  { label: 'okta', color: '#009bde' },
  { label: '▶ Proofpoint', color: '#1a73e8' },
  { label: '✦ PRISMA CLOUD', color: '#fa582d' },
  { label: '/ APACHE', color: '#d22128' },
]

// ─── Security Score Gauge ──────────────────────────────────────────────────
function SecurityScoreGauge({ score }: { score: number }) {
  const clamped = Math.min(100, Math.max(0, score))
  const color = clamped < 40 ? '#e53935' : clamped < 70 ? '#ff6f00' : '#2a9060'

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
                  background: '#e53935',
                  borderRadius: 3,
                  transition: 'width .3s ease',
                }}/>
              </div>
              <span style={{ width: 28, textAlign: 'right', fontSize: 10, color: '#e53935', fontWeight: 700, flexShrink: 0 }}>
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

// ─── CSS for yellow-flash animation (injected once) ───────────────────────
const FLASH_STYLE_ID = 'alert-feed-flash-style'
function ensureFlashStyle() {
  if (typeof document !== 'undefined' && !document.getElementById(FLASH_STYLE_ID)) {
    const style = document.createElement('style')
    style.id = FLASH_STYLE_ID
    style.textContent = `
@keyframes alertFlash {
  0%   { background-color: rgba(249,168,37,0.35); border-color: #f9a825; }
  60%  { background-color: rgba(249,168,37,0.15); border-color: rgba(249,168,37,0.5); }
  100% { background-color: transparent; border-color: var(--border); }
}
.alert-feed-new {
  animation: alertFlash 1.2s ease forwards;
}
    `
    document.head.appendChild(style)
  }
}

export default function Dashboard() {
  const [stats, setStats] = useState<DashStats | null>(null)
  const [extStats, setExtStats] = useState<ExtendedStats | null>(null)
  const [alertFeed, setAlertFeed] = useState<AlertFeedItem[]>([])
  const [newAlertKeys, setNewAlertKeys] = useState<Set<string>>(new Set())
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
  const alertTimerRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const prevAlertKeysRef = useRef<Set<string>>(new Set())

  // Inject flash animation CSS once
  useEffect(() => { ensureFlashStyle() }, [])

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
      params: {
        page: 1,
        page_size: 10,
        sort_by: 'triggered_at',
        sort_desc: true,
      }
    })
      .then(r => {
        const rawData = r.data.data
        const items: AlertFeedItem[] = Array.isArray(rawData) ? rawData : (rawData?.items ?? [])
        setAlertFeed(items)
        // Detect new keys vs previous fetch
        const incomingKeys = new Set(items.map(a => a._key))
        const freshKeys = new Set<string>()
        incomingKeys.forEach(k => {
          if (!prevAlertKeysRef.current.has(k)) freshKeys.add(k)
        })
        if (freshKeys.size > 0) setNewAlertKeys(freshKeys)
        prevAlertKeysRef.current = incomingKeys
        // Clear flash class after animation
        setTimeout(() => setNewAlertKeys(new Set()), 1400)
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
    alertTimerRef.current = setInterval(fetchAlerts, 30000)
    return () => {
      if (alertTimerRef.current) clearInterval(alertTimerRef.current)
    }
  }, [fetchAlerts])

  useEffect(() => {
    return () => {
      if (toastTimerRef.current) clearTimeout(toastTimerRef.current)
    }
  }, [])

  const hour = new Date().getHours()
  const greeting = hour < 12 ? '早上好' : hour < 18 ? '下午好' : '晚上好'

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
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden', position: 'relative' }}>
      {/* Toast notification */}
      {toast && (
        <div style={{
          position: 'absolute', top: 12, left: '50%', transform: 'translateX(-50%)',
          background: '#2a9060', color: '#fff', padding: '6px 18px', borderRadius: 20,
          fontSize: 12, fontWeight: 600, zIndex: 500, pointerEvents: 'none',
          boxShadow: '0 2px 12px rgba(0,0,0,.35)',
        }}>
          {toast}
        </div>
      )}

      <PageHeader
        title="仪表盘"
        subtitle="· 概览"
        actions={<>
          <select
            className="filter-select"
            style={{ fontSize: 11 }}
            value={timeRange}
            onChange={e => setTimeRange(e.target.value as '24h' | '7d' | '30d')}
          >
            {(Object.entries(timeRangeLabels) as [string, string][]).map(([v, l]) => (
              <option key={v} value={v}>{l}</option>
            ))}
          </select>
          <button className="btn-secondary" style={{ fontSize: 11 }} onClick={handleRefresh}>
            🔄 刷新
          </button>
          <button className="btn-secondary" style={{ fontSize: 11 }} onClick={() => setCopilotOpen(true)}>
            ✦ AI助手
          </button>
        </>}
      />

      {/* Title + Greeting */}
      <div style={{ padding: '10px 20px 0', flexShrink: 0 }}>
        <div style={{ fontSize: 18, fontWeight: 700, letterSpacing: -.3 }}>
          XSIAM 指挥中心 <span style={{ fontSize: 14, color: 'var(--text-muted)' }}>▶</span>
        </div>
        <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 2, fontStyle: 'italic' }}>
          {greeting}, {user?.display_name ?? 'Analyst'}
        </div>
      </div>

      {/* ── Real-time Alert Feed Ticker ─────────────────────────────────── */}
      <div style={{
        flexShrink: 0,
        borderTop: '1px solid var(--border)',
        background: 'var(--bg-secondary)',
        padding: '6px 20px',
        marginTop: 8,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 6 }}>
          <span style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.8 }}>
            实时告警
          </span>
          {/* Live pulse indicator */}
          <span style={{
            width: 6, height: 6, borderRadius: '50%', background: '#e53935',
            boxShadow: '0 0 6px #e53935',
            animation: 'none',
            display: 'inline-block',
          }}/>
          <span style={{ fontSize: 9.5, color: 'var(--text-muted)' }}>每30秒自动刷新</span>
          <span
            style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--accent-blue)', cursor: 'pointer', fontWeight: 600 }}
            onClick={() => navigate('/alerts')}
          >
            查看全部 →
          </span>
        </div>
        {alertFeed.length === 0 ? (
          <div style={{ fontSize: 12, color: 'var(--text-muted)', fontStyle: 'italic' }}>暂无新告警</div>
        ) : (
          <div style={{
            display: 'flex', gap: 8, overflowX: 'auto', paddingBottom: 4,
            // Custom scrollbar
            scrollbarWidth: 'thin',
          }}>
            {alertFeed.map(alert => {
              const isNew = newAlertKeys.has(alert._key)
              const ts = alert.triggered_at ?? alert.created_at
              return (
                <div
                  key={alert._key}
                  className={isNew ? 'alert-feed-new' : ''}
                  onClick={() => navigate('/alerts')}
                  style={{
                    flexShrink: 0,
                    display: 'flex', alignItems: 'center', gap: 7,
                    padding: '5px 11px',
                    background: 'var(--bg-card)',
                    border: '1px solid var(--border)',
                    borderRadius: 6,
                    cursor: 'pointer',
                    minWidth: 230, maxWidth: 290,
                    transition: 'border-color .15s',
                  }}
                  onMouseEnter={e => (e.currentTarget.style.borderColor = 'var(--accent-blue)')}
                  onMouseLeave={e => (e.currentTarget.style.borderColor = isNew ? '' : 'var(--border)')}
                >
                  {/* Severity dot */}
                  <span style={{
                    width: 8, height: 8, borderRadius: '50%', flexShrink: 0,
                    background: severityDotColor(alert.severity),
                    boxShadow: `0 0 4px ${severityDotColor(alert.severity)}`,
                  }}/>
                  {/* Name + host */}
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {truncate(alert.name, 40)}
                    </div>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {alert.host ?? alert.asset_name ?? '—'}
                    </div>
                  </div>
                  {/* Relative time */}
                  <span style={{ fontSize: 9.5, color: 'var(--text-muted)', flexShrink: 0, whiteSpace: 'nowrap' }}>
                    {timeAgo(ts)}
                  </span>
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* Sankey + Sources */}
      <div style={{ flex: 1, display: 'flex', overflow: 'hidden', minHeight: 0 }}>

        {/* Left sources column */}
        <div style={{
          width: 180, flexShrink: 0, borderRight: '1px solid var(--border)',
          display: 'flex', flexDirection: 'column', padding: '10px 0', overflow: 'hidden',
        }}>
          {/* Endpoints row */}
          <div style={{
            display: 'flex', alignItems: 'center', gap: 6,
            padding: '6px 14px', marginBottom: 4,
            borderBottom: '1px solid var(--border)',
          }}>
            <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>41.7K</span>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#8a8fa0" strokeWidth="1.8">
              <rect x="2" y="3" width="20" height="14" rx="2"/>
              <line x1="8" y1="21" x2="16" y2="21"/>
              <line x1="12" y1="17" x2="12" y2="21"/>
            </svg>
            <span style={{ fontSize: 9, fontWeight: 600, letterSpacing: 1, color: 'var(--text-muted)', textTransform: 'uppercase' }}>终端</span>
            <span style={{ width: 5, height: 5, borderRadius: '50%', background: '#0078d4', boxShadow: '0 0 4px #0078d4', marginLeft: 'auto', flexShrink: 0 }} />
          </div>

          {/* Vendor list */}
          <div style={{ flex: 1, overflowY: 'auto' }}>
            {SOURCES.map((src, i) => (
              <div key={i} style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                padding: '5px 14px', fontSize: 10.5,
              }}>
                <span style={{ color: src.color, fontWeight: 600, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 130 }}>{src.label}</span>
                <span style={{ width: 5, height: 5, borderRadius: '50%', background: src.color, opacity: 0.7, flexShrink: 0 }} />
              </div>
            ))}
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '5px 14px', fontSize: 10.5, color: 'var(--text-muted)' }}>
              <span style={{ width: 4, height: 4, borderRadius: '50%', background: 'var(--text-muted)' }} />
              <span>+68 个数据源</span>
            </div>
          </div>
        </div>

        {/* Sankey SVG */}
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', overflow: 'hidden', padding: '0 0 0 0' }}>
          <svg viewBox="0 0 780 420" preserveAspectRatio="xMidYMid meet"
            style={{ width: '100%', height: '100%', maxHeight: 380 }}>
            <defs>
              <radialGradient id="circleGrad" cx="50%" cy="50%" r="50%">
                <stop offset="0%" stopColor="#0d1e3c"/>
                <stop offset="100%" stopColor="#060a14"/>
              </radialGradient>
              <filter id="glow" x="-30%" y="-30%" width="160%" height="160%">
                <feGaussianBlur stdDeviation="4" result="blur"/>
                <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
              </filter>
              <filter id="glow2" x="-50%" y="-50%" width="200%" height="200%">
                <feGaussianBlur stdDeviation="6" result="blur"/>
                <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
              </filter>
              <marker id="arr" markerWidth="6" markerHeight="6" refX="3" refY="3" orient="auto">
                <path d="M0,0 L6,3 L0,6 Z" fill="#0078d4" opacity="0.8"/>
              </marker>
            </defs>

            {/* Left funnel streams */}
            <path d="M0,15 C90,15 140,195 205,205" stroke="#6b8fa8" strokeWidth="22" fill="none" opacity="0.25"/>
            <path d="M0,65 C90,65 140,198 205,207" stroke="#e05a2b" strokeWidth="10" fill="none" opacity="0.3"/>
            <path d="M0,100 C90,100 140,200 205,208" stroke="#4285f4" strokeWidth="8" fill="none" opacity="0.3"/>
            <path d="M0,132 C90,132 140,202 205,209" stroke="#ff9900" strokeWidth="8" fill="none" opacity="0.3"/>
            <path d="M0,162 C90,162 140,204 205,210" stroke="#0078d4" strokeWidth="7" fill="none" opacity="0.3"/>
            <path d="M0,190 C90,190 140,206 205,211" stroke="#d83b01" strokeWidth="5" fill="none" opacity="0.3"/>
            <path d="M0,215 C90,215 140,208 205,212" stroke="#009bde" strokeWidth="5" fill="none" opacity="0.25"/>
            <path d="M0,238 C90,238 140,210 205,212" stroke="#1a73e8" strokeWidth="4" fill="none" opacity="0.25"/>
            <path d="M0,260 C90,258 140,212 205,213" stroke="#fa582d" strokeWidth="4" fill="none" opacity="0.25"/>
            <path d="M0,280 C90,275 140,214 205,213" stroke="#d22128" strokeWidth="3" fill="none" opacity="0.2"/>
            <path d="M0,298 C90,290 140,215 205,214" stroke="#6b7280" strokeWidth="2.5" fill="none" opacity="0.15"/>

            {/* 告警数 count */}
            <text x="210" y="196" fontSize="26" fontWeight="700" fill="white" fontFamily="'Segoe UI',sans-serif" opacity="0.95">{issues.toLocaleString()}</text>
            <text x="218" y="214" fontSize="10" fill="#9ea3b0" fontFamily="'Segoe UI',sans-serif" letterSpacing="1">ISSUES</text>
            {/* Spark dots */}
            <circle cx="260" cy="200" r="3" fill="#e53935" opacity="0.8"/>
            <circle cx="268" cy="192" r="2" fill="#ff9900" opacity="0.7"/>
            <circle cx="275" cy="205" r="2.5" fill="#4fa3e0" opacity="0.7"/>
            <circle cx="255" cy="210" r="2" fill="#0078d4" opacity="0.6"/>

            {/* Arrow to CASES */}
            <path d="M306,210 L345,210" stroke="#0078d4" strokeWidth="2" markerEnd="url(#arr)" opacity="0.7"/>

            {/* Center circle */}
            <circle cx="390" cy="210" r="110" fill="none" stroke="#0078d4" strokeWidth="0.5" opacity="0.12"/>
            <circle cx="390" cy="210" r="95" fill="none" stroke="#0078d4" strokeWidth="0.5" opacity="0.18"/>
            <circle cx="390" cy="210" r="82" fill="url(#circleGrad)" stroke="#0d2a4a" strokeWidth="1.5"/>
            <circle cx="390" cy="210" r="76" fill="none" stroke="#1a3d6e" strokeWidth="1" strokeDasharray="3,3" opacity="0.5"/>
            {/* Orbit dots */}
            <circle cx="390" cy="134" r="4" fill="#0078d4" opacity="0.9" filter="url(#glow)"/>
            <circle cx="448" cy="148" r="3.5" fill="#0078d4" opacity="0.7"/>
            <circle cx="466" cy="210" r="3" fill="#0078d4" opacity="0.5"/>
            <circle cx="448" cy="272" r="3.5" fill="#0078d4" opacity="0.7"/>
            <circle cx="390" cy="286" r="4" fill="#0078d4" opacity="0.9" filter="url(#glow)"/>
            <circle cx="332" cy="272" r="3.5" fill="#0078d4" opacity="0.7"/>
            <circle cx="314" cy="210" r="3" fill="#0078d4" opacity="0.5"/>
            <circle cx="332" cy="148" r="3.5" fill="#0078d4" opacity="0.7"/>
            {/* Alert dots */}
            <circle cx="420" cy="136" r="3" fill="#e53935" opacity="0.85" filter="url(#glow)"/>
            <circle cx="460" cy="170" r="2.5" fill="#ff6f00" opacity="0.7"/>
            <circle cx="360" cy="284" r="2.5" fill="#f9a825" opacity="0.7"/>
            {/* Inner arrows */}
            <path d="M350,210 L380,210" stroke="#0078d4" strokeWidth="1.5" opacity="0.4" markerEnd="url(#arr)"/>

            {/* Cases count right of circle */}
            <text x="488" y="202" fontSize="28" fontWeight="700" fill="white" fontFamily="'Segoe UI',sans-serif">{openCases + manual + 95}</text>
            <text x="492" y="219" fontSize="10" fill="#9ea3b0" fontFamily="'Segoe UI',sans-serif" letterSpacing="1">CASES</text>

            {/* Top branch: AUTOMATED */}
            <path d="M475,205 C530,205 545,145 590,135" stroke="#0078d4" strokeWidth="14" fill="none" opacity="0.55" filter="url(#glow2)"/>
            <circle cx="592" cy="133" r="16" fill="#0a1e3c" stroke="#0078d4" strokeWidth="1.5"/>
            <text x="592" y="138" textAnchor="middle" fontSize="13" fill="#0078d4">◯</text>
            <path d="M608,133 L720,133" stroke="#0078d4" strokeWidth="10" fill="none" opacity="0.7"/>
            <text x="635" y="116" fontSize="20" fontWeight="700" fill="white" fontFamily="'Segoe UI',sans-serif">{automated}</text>
            <text x="635" y="128" fontSize="9" fill="#9ea3b0" fontFamily="'Segoe UI',sans-serif" letterSpacing="1">AUTOMATED</text>
            <text x="730" y="122" fontSize="22" fontWeight="700" fill="white" fontFamily="'Segoe UI',sans-serif">{resolved}</text>
            <text x="730" y="136" fontSize="9" fill="#9ea3b0" fontFamily="'Segoe UI',sans-serif">RESOLVED</text>
            <text x="730" y="147" fontSize="9" fill="#9ea3b0" fontFamily="'Segoe UI',sans-serif">CASES</text>

            {/* Bottom branch: MANUAL */}
            <path d="M475,215 C530,215 545,285 590,295" stroke="#5a6a7a" strokeWidth="6" fill="none" opacity="0.4"/>
            <circle cx="592" cy="295" r="16" fill="#0d1520" stroke="#4a5568" strokeWidth="1.5"/>
            <text x="592" y="300" textAnchor="middle" fontSize="13" fill="#8a9ab0">&#9654;</text>
            <text x="635" y="283" fontSize="20" fontWeight="700" fill="white" fontFamily="'Segoe UI',sans-serif">{manual}</text>
            <text x="635" y="295" fontSize="9" fill="#9ea3b0" fontFamily="'Segoe UI',sans-serif" letterSpacing="1">MANUAL</text>

            {/* Open cases severity */}
            <path d="M608,295 C640,295 645,270 670,265" stroke="#5a6a7a" strokeWidth="3" fill="none" opacity="0.4"/>
            <path d="M608,295 C640,295 645,300 670,308" stroke="#5a6a7a" strokeWidth="2" fill="none" opacity="0.3"/>
            <rect x="672" y="255" width="14" height="14" rx="3" fill="#e53935"/>
            <text x="679" y="265" textAnchor="middle" fontSize="8" fontWeight="700" fill="white">C</text>
            <text x="690" y="265" fontSize="10" fill="#e8e9ed" fontFamily="'Segoe UI',sans-serif">3</text>
            <rect x="672" y="273" width="14" height="14" rx="3" fill="#ff6f00"/>
            <text x="679" y="283" textAnchor="middle" fontSize="8" fontWeight="700" fill="white">H</text>
            <text x="690" y="283" fontSize="10" fill="#e8e9ed" fontFamily="'Segoe UI',sans-serif">4</text>
            <rect x="672" y="291" width="14" height="14" rx="3" fill="#f9a825"/>
            <text x="679" y="301" textAnchor="middle" fontSize="8" fontWeight="700" fill="white">M</text>
            <text x="690" y="301" fontSize="10" fill="#e8e9ed" fontFamily="'Segoe UI',sans-serif">8</text>
            <rect x="672" y="309" width="14" height="14" rx="3" fill="#00897b"/>
            <text x="679" y="319" textAnchor="middle" fontSize="8" fontWeight="700" fill="white">L</text>
            <text x="690" y="319" fontSize="10" fill="#e8e9ed" fontFamily="'Segoe UI',sans-serif">0</text>
            <text x="718" y="285" fontSize="22" fontWeight="700" fill="white" fontFamily="'Segoe UI',sans-serif">{openCases}</text>
            <text x="718" y="299" fontSize="9" fill="#9ea3b0" fontFamily="'Segoe UI',sans-serif">OPEN</text>
            <text x="718" y="310" fontSize="9" fill="#9ea3b0" fontFamily="'Segoe UI',sans-serif">CASES</text>
          </svg>
        </div>
      </div>

      {/* Bottom stats bar */}
      <div style={{
        flexShrink: 0,
        borderTop: '1px solid var(--border)',
        background: 'var(--bg-secondary)',
      }}>
        {/* KPI cards row */}
        <div style={{ display: 'flex', alignItems: 'stretch', minHeight: 80 }}>

          {/* KPI: Security Score */}
          <div style={{ display: 'flex', alignItems: 'center', padding: '4px 16px', minWidth: 100, flexShrink: 0, justifyContent: 'center' }}>
            <SecurityScoreGauge score={securityScore} />
          </div>
          <div style={{ width: 1, background: 'var(--border)', alignSelf: 'stretch', margin: '8px 0' }} />

          {/* KPI: 活跃事件 — clickable → /incidents?status=open */}
          <div
            style={{ display: 'flex', alignItems: 'stretch', cursor: 'pointer' }}
            onClick={() => navigate('/incidents?status=open')}
            title="查看活跃事件"
          >
            <div style={{
              padding: '8px 24px', display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 2, minWidth: 140,
              transition: 'background .15s',
            }}
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
          <div style={{ display: 'flex', alignItems: 'stretch' }}>
            <div style={{ padding: '8px 24px', display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 2, minWidth: 140 }}>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 500, textTransform: 'uppercase', letterSpacing: 0.4 }}>未处置告警</div>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 4 }}>
                <span style={{ fontSize: 28, fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1 }}>{stats?.open_alerts ?? '—'}</span>
              </div>
            </div>
          </div>
          <div style={{ width: 1, background: 'var(--border)', alignSelf: 'stretch', margin: '8px 0' }} />

          {/* KPI: MTTR */}
          <div style={{ display: 'flex', alignItems: 'stretch' }}>
            <div style={{ padding: '8px 24px', display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 2, minWidth: 160 }}>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 500, textTransform: 'uppercase', letterSpacing: 0.4 }}>MTTR</div>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
                <span style={{ fontSize: 28, fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1 }}>
                  {stats?.mttr_hours != null && !isNaN(stats.mttr_hours) && stats.mttr_hours >= 0 ? stats.mttr_hours.toFixed(1) + 'h' : '—'}
                </span>
                {stats?.mttr_hours != null && !isNaN(stats.mttr_hours) && stats.mttr_hours > 0 && (() => {
                  const h = stats.mttr_hours
                  if (h < 2) return <span style={{ fontSize: 11, fontWeight: 600, color: '#2a9060' }}>↓ 优秀</span>
                  if (h < 8) return <span style={{ fontSize: 11, fontWeight: 600, color: '#f9a825' }}>→ 正常</span>
                  return <span style={{ fontSize: 11, fontWeight: 600, color: '#e53935' }}>↑ 需关注</span>
                })()}
              </div>
            </div>
          </div>
          <div style={{ width: 1, background: 'var(--border)', alignSelf: 'stretch', margin: '8px 0' }} />

          {/* KPI: 严重漏洞 */}
          <div style={{ display: 'flex', alignItems: 'stretch' }}>
            <div style={{ padding: '8px 24px', display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 2, minWidth: 140 }}>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 500, textTransform: 'uppercase', letterSpacing: 0.4 }}>严重漏洞</div>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 4 }}>
                <span style={{ fontSize: 28, fontWeight: 700, color: '#e53935', lineHeight: 1 }}>{stats?.critical_vulns ?? '—'}</span>
              </div>
            </div>
          </div>
          <div style={{ width: 1, background: 'var(--border)', alignSelf: 'stretch', margin: '8px 0' }} />

          {/* KPI: SOAR 自动化剧本 */}
          <div style={{ display: 'flex', alignItems: 'stretch' }}>
            <div style={{ padding: '8px 18px', display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 2, minWidth: 150 }}>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 500, textTransform: 'uppercase', letterSpacing: 0.4 }}>自动化剧本</div>
              {playbookStats ? (
                <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
                  <span style={{ fontSize: 28, fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1 }}>{playbookStats.total}</span>
                  <span style={{ fontSize: 10, color: '#2a9060', fontWeight: 600 }}>
                    活跃 {playbookStats.active}
                  </span>
                </div>
              ) : (
                <span style={{ fontSize: 28, fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1 }}>—</span>
              )}
              {playbookStats && (
                <div style={{ fontSize: 9.5, color: 'var(--text-muted)' }}>
                  执行率 <span style={{ color: '#4fa3e0', fontWeight: 600 }}>{playbookStats.executionRate}%</span>
                </div>
              )}
            </div>
          </div>
          <div style={{ width: 1, background: 'var(--border)', alignSelf: 'stretch', margin: '8px 0' }} />

          {/* KPI: Threat Intel */}
          <div style={{ display: 'flex', alignItems: 'stretch' }}>
            <div style={{ padding: '8px 18px', display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 2, minWidth: 150 }}>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 500, textTransform: 'uppercase', letterSpacing: 0.4 }}>威胁情报</div>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
                <span style={{ fontSize: 28, fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1 }}>
                  {iocCount != null ? iocCount.toLocaleString() : '—'}
                </span>
                <span style={{ fontSize: 9.5, color: 'var(--text-muted)' }}>IOC</span>
              </div>
              <div style={{ fontSize: 9.5, color: 'var(--text-muted)' }}>
                活跃情报源 <span style={{ color: '#f9a825', fontWeight: 600 }}>{activeFeedsCount ?? '—'}</span>
              </div>
            </div>
          </div>
          <div style={{ width: 1, background: 'var(--border)', alignSelf: 'stretch', margin: '8px 0' }} />

          {/* Alert trend sparkline */}
          <div style={{ padding: '8px 16px', display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 2, minWidth: 170 }}>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 500, textTransform: 'uppercase', letterSpacing: 0.4, display: 'flex', alignItems: 'center', gap: 6 }}>
              告警趋势 (7天)
              {trendIndicator && (
                <span style={{ fontSize: 10, fontWeight: 700, color: trendIndicator.up ? '#e53935' : '#2a9060' }}>
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

          {/* Severity donut */}
          <div style={{ padding: '8px 16px', display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 2, minWidth: 120 }}>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 500, textTransform: 'uppercase', letterSpacing: 0.4 }}>告警分布</div>
            <PieChart width={80} height={48}>
              <Pie
                data={Object.entries(stats?.alerts_by_severity ?? {}).map(([name, value]) => ({ name, value }))}
                cx={36} cy={20} innerRadius={12} outerRadius={22}
                dataKey="value" isAnimationActive={false} strokeWidth={0}
              >
                {Object.keys(stats?.alerts_by_severity ?? {}).map((key) => {
                  const COLOR: Record<string, string> = { critical: '#e53935', high: '#ff6f00', medium: '#f9a825', low: '#2a9060' }
                  return <Cell key={key} fill={COLOR[key] ?? '#4fa3e0'}/>
                })}
              </Pie>
            </PieChart>
          </div>
          <div style={{ width: 1, background: 'var(--border)', alignSelf: 'stretch', margin: '8px 0' }} />

          {/* Top tactics bar — MITRE coverage if available, else top_tactics */}
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
                      <span style={{ width: 80, fontSize: 9, color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flexShrink: 0 }}>
                        {t.name}
                      </span>
                      <div style={{ flex: 1, height: 5, background: 'rgba(0,120,212,.12)', borderRadius: 3, overflow: 'hidden' }}>
                        <div style={{
                          height: '100%',
                          width: `${Math.round((t.count / maxVal) * 100)}%`,
                          background: '#e53935',
                          borderRadius: 3,
                        }} />
                      </div>
                      <span style={{ width: 24, textAlign: 'right', fontSize: 9, color: '#e53935', fontWeight: 600, flexShrink: 0 }}>{t.count}</span>
                    </div>
                  ))
                })()}
              </div>
            ) : (
              <ResponsiveContainer width="100%" height={48}>
                <BarChart
                  data={stats?.top_tactics?.slice(0, 5) ?? []}
                  layout="vertical"
                  margin={{ top: 0, right: 8, left: 0, bottom: 0 }}
                >
                  <XAxis type="number" hide />
                  <YAxis type="category" dataKey="tactic" tick={{ fontSize: 10, fill: 'var(--text-muted)' }} width={90} tickLine={false} axisLine={false}/>
                  <Tooltip
                    contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', fontSize: 11, padding: '4px 8px' }}
                    itemStyle={{ color: 'var(--text-primary)' }}
                    cursor={{ fill: 'rgba(255,255,255,0.04)' }}
                  />
                  <Bar dataKey="count" fill="#0078d4" radius={[0, 2, 2, 0]} isAnimationActive={false} barSize={6}/>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* ── SOC Performance KPIs row ───────────────────────────────────── */}
        <div style={{
          borderTop: '1px solid var(--border)',
          display: 'flex', alignItems: 'stretch',
          height: 68,
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
              <span style={{ fontSize: 10, fontWeight: 700, color: '#2a9060' }}>
                ↓{Math.abs(socKpis.mttdTrend)}%
              </span>
            </div>
            <div style={{ fontSize: 9, color: 'var(--text-muted)', marginTop: 1 }}>Mean time to Detect</div>
          </div>

          {/* MTTR */}
          <div style={{ flex: 1, padding: '8px 20px', display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 1, minWidth: 130, borderRight: '1px solid var(--border)' }}>
            <div style={{ fontSize: 9, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.5 }}>MTTR</div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 5 }}>
              <span style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1 }}>
                {mttrValue >= 0 && !isNaN(mttrValue) ? mttrValue.toFixed(1) + 'h' : '—'}
              </span>
              {mttrValue > 0 && !isNaN(mttrValue) && (
                <span style={{ fontSize: 10, fontWeight: 700, color: '#2a9060' }}>↓8%</span>
              )}
            </div>
            <div style={{ fontSize: 9, color: 'var(--text-muted)', marginTop: 1 }}>Mean time to Respond</div>
          </div>

          {/* 误报率 */}
          <div style={{ flex: 1, padding: '8px 20px', display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 1, minWidth: 130, borderRight: '1px solid var(--border)' }}>
            <div style={{ fontSize: 9, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.5 }}>误报率</div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 5 }}>
              <span style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1 }}>{socKpis.fpr}%</span>
              <span style={{ fontSize: 10, fontWeight: 700, color: '#2a9060' }}>
                ↓{Math.abs(socKpis.fprTrend)}%
              </span>
            </div>
            <div style={{ fontSize: 9, color: 'var(--text-muted)', marginTop: 1 }}>False Positive Rate</div>
          </div>

          {/* 自动化率 */}
          <div style={{ flex: 1, padding: '8px 20px', display: 'flex', flexDirection: 'column', justifyContent: 'center', gap: 1, minWidth: 130 }}>
            <div style={{ fontSize: 9, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.5 }}>自动化率</div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 5 }}>
              <span style={{ fontSize: 18, fontWeight: 700, color: '#2a9060', lineHeight: 1 }}>{socKpis.autoRate}%</span>
              <span style={{ fontSize: 10, fontWeight: 700, color: '#2a9060' }}>
                ↑{socKpis.autoRateTrend}%
              </span>
            </div>
            <div style={{ fontSize: 9, color: 'var(--text-muted)', marginTop: 1 }}>Automation Rate</div>
          </div>
        </div>

        {/* ── SOAR Execution Summary bar ─────────────────────────────────── */}
        <div style={{
          borderTop: '1px solid var(--border)',
          display: 'flex', alignItems: 'center',
          padding: '5px 20px', gap: 0,
          background: 'rgba(0,0,0,.12)',
        }}>
          <span style={{ fontSize: 9.5, color: 'var(--text-muted)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.8, marginRight: 20, flexShrink: 0 }}>
            SOAR 本周
          </span>
          {/* Divider helper */}
          {([
            { label: '自动响应', value: `${soarMocks.weeklyRuns}次`, color: '#4fa3e0' },
            { label: '平均执行时间', value: `${soarMocks.avgExecSec}秒`, color: 'var(--text-primary)' },
            { label: '成功率', value: `${soarMocks.successRate}%`, color: '#2a9060' },
            { label: '待审批操作', value: pendingActionsCount != null ? String(pendingActionsCount) : '—', color: pendingActionsCount != null && pendingActionsCount > 3 ? '#f9a825' : 'var(--text-primary)' },
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
        background: 'var(--bg-secondary)',
        display: 'flex', alignItems: 'center',
        padding: '5px 20px', gap: 24,
      }}>
        <span style={{ fontSize: 9.5, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.8, flexShrink: 0 }}>vs 昨日</span>
        {YESTERDAY_COMPARISON.map(item => (
          <span key={item.label} style={{ fontSize: 11, fontWeight: 600, color: item.up ? '#e53935' : '#2a9060', whiteSpace: 'nowrap' }}>
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
        <div style={{ flex: 2, padding: '10px 20px', borderRight: '1px solid var(--border)', minWidth: 0 }}>
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
              <Bar dataKey="new_incidents" fill="#e53935" radius={[2, 2, 0, 0]} isAnimationActive={false} barSize={8}/>
              <Bar dataKey="resolved"      fill="#43a047" radius={[2, 2, 0, 0]} isAnimationActive={false} barSize={8}/>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* Geographic Threat Heatmap */}
        <div style={{ flex: 3, padding: '10px 16px', borderRight: '1px solid var(--border)', minWidth: 0 }}>
          <GeoThreatMap iocCount={iocCount} />
        </div>

        {/* Top Alerts by Host */}
        <div style={{ flex: 2, padding: '10px 20px', minWidth: 0 }}>
          <TopAlertsByHost navigate={navigate} />
        </div>
      </div>

      {/* ── Top Affected Hosts table ─────────────────────────────────────── */}
      <div style={{
        flexShrink: 0,
        borderTop: '1px solid var(--border)',
        background: 'var(--bg-secondary)',
        padding: '10px 20px',
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
              const riskColor = h.risk_score >= 80 ? '#e53935' : h.risk_score >= 60 ? '#ff6f00' : '#f9a825'
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
                    <span style={{ color: '#e53935', fontWeight: 700 }}>{h.alert_count}</span>
                  </td>
                  <td style={{ textAlign: 'right', paddingRight: 16, paddingBottom: 3 }}>
                    <span style={{ color: h.open_incidents > 0 ? '#ff6f00' : 'var(--text-muted)', fontWeight: h.open_incidents > 0 ? 700 : 400 }}>
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
          <div style={{ flex: 1, padding: '10px 20px', borderRight: '1px solid var(--border)' }}>
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
          <div style={{ flex: 1, padding: '10px 20px' }}>
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
          style={{ position: 'absolute', inset: 0, background: 'rgba(0,0,0,.4)', zIndex: 300 }}
          onClick={() => setCopilotOpen(false)}
        />
      )}
      <div style={{
        position: 'absolute', right: 0, top: 0, bottom: 0,
        width: 420, background: 'var(--bg-card)',
        borderLeft: '1px solid var(--border)',
        zIndex: 301, display: 'flex', flexDirection: 'column',
        transform: copilotOpen ? 'translateX(0)' : 'translateX(100%)',
        transition: 'transform .25s ease',
      }}>
        {/* Drawer header */}
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '12px 16px', borderBottom: '1px solid var(--border)',
          background: 'var(--bg-sidebar)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="#4fa3e0"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/></svg>
            <span style={{ fontSize: 13, fontWeight: 700, color: '#ffffff' }}>XSIAM Copilot</span>
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
            {['Summarize today\'s critical incidents','Why did INC-2024-0047 auto-close?','Top threat actors in last 7 days','Investigate alert spike at 02:00'].map(s => (
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
