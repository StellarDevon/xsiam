import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '@/lib/api'
import type { PageMeta } from '@/lib/api'
import ResizableTh from '@/components/ResizableTh'

interface IOC {
  _key: string
  type: string
  value: string
  threat_name: string
  confidence: number
  severity: string
  verdict: string
  tags: string[]
  active: boolean
  source: string
  description: string
  tenant_id: string
  first_seen: string
  last_seen: string
  created_at: string
}

interface RelatedIncident {
  _key: string
  title: string
  severity: string
  status: string
}

interface RelatedAlert {
  _key: string
  title: string
  severity: string
  status: string
}

interface IntelFeed {
  _key: string
  name: string
  source: string
  feed_type: string
  last_sync_at?: string
  confidence?: number
}

interface FeedCorrelation {
  feed_name: string
  last_sync_at: string
  confidence: number
}


const TYPE_COLORS: Record<string, string> = {
  ip: 'var(--accent-blue)', domain: 'var(--accent-blue)', url: 'var(--accent-green)',
  hash: 'var(--medium)', email: 'var(--high)', cve: 'var(--high)',
  cidr: 'var(--accent-blue)', registry: 'var(--high)', user_agent: 'var(--accent-green)', mutex: 'var(--accent-blue)',
}

const VERDICT_CONFIG: Record<string, { bg: string; color: string; label: string }> = {
  malicious:  { bg: 'rgba(224,80,80,.18)',   color: 'var(--critical)',  label: '恶意' },
  suspicious: { bg: 'rgba(224,128,64,.15)',  color: 'var(--high)',  label: '可疑' },
  benign:     { bg: 'rgba(47,176,122,.15)',  color: 'var(--accent-green)',  label: '无害' },
  unknown:    { bg: 'rgba(84,110,122,.15)',  color: 'var(--text-muted)',  label: '未知' },
  false_positive: { bg: 'rgba(120,144,156,.15)', color: 'var(--text-muted)', label: '误报' },
}

// Mock geo data for IP IOCs
const GEO_COUNTRIES = ['美国', '中国', '俄罗斯', '德国', '荷兰', '英国', '法国', '新加坡', '巴西', '印度']
function mockGeoForIP(value: string): string {
  let hash = 0
  for (let i = 0; i < value.length; i++) hash = (hash * 31 + value.charCodeAt(i)) | 0
  return GEO_COUNTRIES[Math.abs(hash) % GEO_COUNTRIES.length]
}

function VerdictBadge({ verdict }: { verdict: string }) {
  const cfg = VERDICT_CONFIG[verdict] ?? VERDICT_CONFIG.unknown
  return (
    <span className="verdict-badge" style={{ background: cfg.bg, color: cfg.color }}>
      {cfg.label}
    </span>
  )
}

function confColor(conf: number): string {
  if (conf >= 81) return 'var(--accent-green)'  // green
  if (conf >= 61) return 'var(--medium)'        // amber
  if (conf >= 31) return 'var(--high)'          // orange
  return 'var(--critical)'                       // red
}

function ConfBadge({ conf }: { conf: number }) {
  const color = confColor(conf)
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      <div style={{ flex: 1, height: 3, background: 'var(--border)', borderRadius: 2, maxWidth: 60 }}>
        <div style={{ height: 3, width: `${conf}%`, background: color, borderRadius: 2 }} />
      </div>
      <span style={{ fontSize: 11, color, fontWeight: 600 }}>{conf}%</span>
    </div>
  )
}

/** Wider confidence bar for the detail panel */
function ConfBar({ conf }: { conf: number }) {
  const color = confColor(conf)
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ flex: 1, height: 4, background: 'var(--border)', borderRadius: 2 }}>
        <div style={{ height: 4, width: `${conf}%`, background: color, borderRadius: 2, transition: 'width .3s' }} />
      </div>
      <span style={{ fontSize: 12, color, fontWeight: 700, minWidth: 32, textAlign: 'right' }}>{conf}%</span>
    </div>
  )
}

/** SVG gauge for reputation score 0-100 */
function ReputationGauge({ score }: { score: number }) {
  const clamped = Math.min(100, Math.max(0, score))
  const color = clamped < 40 ? 'var(--critical)' : clamped < 70 ? 'var(--high)' : 'var(--accent-green)'
  const r = 26, cx = 36, cy = 38
  const startAngle = -225 * (Math.PI / 180)
  const startX = cx + r * Math.cos(startAngle)
  const startY = cy + r * Math.sin(startAngle)
  const endAngle = 45 * (Math.PI / 180)
  const endX = cx + r * Math.cos(endAngle)
  const endY = cy + r * Math.sin(endAngle)
  const trackPath = `M ${startX} ${startY} A ${r} ${r} 0 1 1 ${endX} ${endY}`
  const fillRotation = (clamped / 100) * 270
  const fillEndRad = (-225 + fillRotation) * (Math.PI / 180)
  const fillEndX = cx + r * Math.cos(fillEndRad)
  const fillEndY = cy + r * Math.sin(fillEndRad)
  const largeArc = fillRotation > 180 ? 1 : 0
  const fillPath = `M ${startX} ${startY} A ${r} ${r} 0 ${largeArc} 1 ${fillEndX} ${fillEndY}`
  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 0 }}>
      <svg width={72} height={72} viewBox="0 0 72 76">
        <path d={trackPath} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth={5} strokeLinecap="round" />
        {clamped > 0 && (
          <path d={fillPath} fill="none" stroke={color} strokeWidth={5} strokeLinecap="round"
            style={{ filter: `drop-shadow(0 0 3px ${color})` }} />
        )}
        <text x={cx} y={cy - 1} textAnchor="middle" fontSize="15" fontWeight="700" fill="white" fontFamily="'Segoe UI',sans-serif">
          {Math.round(clamped)}
        </text>
        <text x={cx} y={cy + 11} textAnchor="middle" fontSize="7" fill={color} fontFamily="'Segoe UI',sans-serif" letterSpacing="0.5">
          / 100
        </text>
      </svg>
      <div style={{ fontSize: 9, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.4, marginTop: -4 }}>
        信誉评分
      </div>
    </div>
  )
}

/** Force-directed relationship graph using SVG */
function RelationshipGraph({ ioc, alerts, incidents, onNavigateAlert, onNavigateIncident }: {
  ioc: IOC
  alerts: RelatedAlert[]
  incidents: RelatedIncident[]
  onNavigateAlert: (key: string) => void
  onNavigateIncident: (key: string) => void
}) {
  const W = 260, H = 220
  const cx = W / 2, cy = H / 2
  const r = 80

  // Build surrounding nodes
  const surrounding: Array<{ key: string; label: string; type: 'alert' | 'incident'; severity?: string }> = [
    ...alerts.map(a => ({ key: a._key, label: a.title, type: 'alert' as const, severity: a.severity })),
    ...incidents.map(i => ({ key: i._key, label: i.title, type: 'incident' as const, severity: i.severity })),
  ]

  const total = surrounding.length
  const nodes = surrounding.map((n, idx) => {
    const angle = (2 * Math.PI * idx) / Math.max(total, 1) - Math.PI / 2
    return {
      ...n,
      x: cx + r * Math.cos(angle),
      y: cy + r * Math.sin(angle),
    }
  })

  const [hovered, setHovered] = useState<string | null>(null)

  return (
    <svg width={W} height={H} style={{ display: 'block', margin: '0 auto' }}>
      {/* Lines from center to each node */}
      {nodes.map(n => (
        <line
          key={`line-${n.key}`}
          x1={cx} y1={cy}
          x2={n.x} y2={n.y}
          stroke="rgba(255,255,255,0.12)"
          strokeWidth={1.5}
          strokeDasharray="4 3"
        />
      ))}

      {/* Central IOC node */}
      <circle cx={cx} cy={cy} r={22} fill="rgba(79,163,224,0.18)" stroke="var(--accent-blue)" strokeWidth={2} />
      <text x={cx} y={cy - 4} textAnchor="middle" fontSize="7" fill="var(--accent-blue)" fontWeight="700" fontFamily="'Segoe UI',sans-serif">
        {ioc.type.toUpperCase()}
      </text>
      <text x={cx} y={cy + 7} textAnchor="middle" fontSize="6.5" fill="rgba(255,255,255,0.7)" fontFamily="monospace">
        {ioc.value.length > 14 ? ioc.value.slice(0, 13) + '…' : ioc.value}
      </text>

      {/* Surrounding nodes */}
      {nodes.map(n => {
        const isHovered = hovered === n.key
        const isAlert = n.type === 'alert'
        const fillColor = isAlert ? 'rgba(224,80,80,0.18)' : 'rgba(167,139,250,0.18)'
        const strokeColor = isAlert ? 'var(--critical)' : 'var(--accent-blue)'
        const bw = 64, bh = 28

        // Alerts: rectangle, Incidents: hexagon path
        const hexPath = (() => {
          const hw = 34, hh = 18
          const pts = [0, 1, 2, 3, 4, 5].map(i => {
            const a = (Math.PI / 3) * i - Math.PI / 6
            return `${n.x + hw * Math.cos(a)},${n.y + hh * Math.sin(a)}`
          })
          return `M ${pts.join(' L ')} Z`
        })()

        return (
          <g
            key={n.key}
            style={{ cursor: 'pointer' }}
            onClick={() => isAlert ? onNavigateAlert(n.key) : onNavigateIncident(n.key)}
            onMouseEnter={() => setHovered(n.key)}
            onMouseLeave={() => setHovered(null)}
          >
            {isAlert ? (
              <rect
                x={n.x - bw / 2} y={n.y - bh / 2}
                width={bw} height={bh}
                rx={4} ry={4}
                fill={isHovered ? 'rgba(224,80,80,0.35)' : fillColor}
                stroke={strokeColor} strokeWidth={isHovered ? 2 : 1.5}
              />
            ) : (
              <path
                d={hexPath}
                fill={isHovered ? 'rgba(167,139,250,0.35)' : fillColor}
                stroke={strokeColor} strokeWidth={isHovered ? 2 : 1.5}
              />
            )}
            <text x={n.x} y={n.y - 3} textAnchor="middle" fontSize="6" fill={strokeColor} fontWeight="600" fontFamily="'Segoe UI',sans-serif">
              {isAlert ? 'Alert' : 'Incident'}
            </text>
            <text x={n.x} y={n.y + 6} textAnchor="middle" fontSize="5.5" fill="rgba(255,255,255,0.65)" fontFamily="'Segoe UI',sans-serif">
              {n.label.length > 14 ? n.label.slice(0, 13) + '…' : n.label}
            </text>
          </g>
        )
      })}

      {/* Legend */}
      <g transform={`translate(${W - 100}, ${H - 32})`}>
        <rect x={0} y={0} width={8} height={8} rx={1} fill="none" stroke="#c04040" strokeWidth={1.5} />
        <text x={11} y={7.5} fontSize="7" fill="var(--text-muted)" fontFamily="'Segoe UI',sans-serif">告警</text>
        <path d="M 36 4 L 39 1 L 44 1 L 47 4 L 44 7 L 39 7 Z" fill="none" stroke="#a78bfa" strokeWidth={1.5} />
        <text x={50} y={7.5} fontSize="7" fill="var(--text-muted)" fontFamily="'Segoe UI',sans-serif">事件</text>
      </g>
    </svg>
  )
}

function fmtDate(iso: string) {
  if (!iso) return '-'
  return new Date(iso).toLocaleDateString('zh-CN')
}

/** Parse textarea content into IOC rows. Each line: type,value,verdict,confidence */
function parseBulkText(text: string, defaultType: string): Array<{ type: string; value: string; verdict: string; confidence: number }> {
  return text
    .split('\n')
    .map(l => l.trim())
    .filter(Boolean)
    .map(line => {
      const parts = line.split(',').map(s => s.trim())
      if (parts.length === 1) {
        return { type: defaultType, value: parts[0], verdict: 'malicious', confidence: 70 }
      }
      if (parts.length === 2) {
        return { type: parts[0] || defaultType, value: parts[1], verdict: 'malicious', confidence: 70 }
      }
      return {
        type: parts[0] || defaultType,
        value: parts[1] || '',
        verdict: parts[2] || 'malicious',
        confidence: parseInt(parts[3]) || 70,
      }
    })
    .filter(i => i.value)
}

/** Generate and download a CSV file */
function downloadCSV(iocs: IOC[], filename = 'iocs.csv') {
  const header = ['type', 'value', 'verdict', 'tags', 'created_at']
  const rows = [header.join(',')]
  iocs.forEach(i => rows.push([
    i.type,
    `"${i.value}"`,
    i.verdict,
    `"${(i.tags ?? []).join(';')}"`,
    i.created_at,
  ].join(',')))
  const blob = new Blob([rows.join('\n')], { type: 'text/csv' })
  const a = document.createElement('a')
  a.href = URL.createObjectURL(blob)
  a.download = filename
  a.click()
}

// IOCsTab — embeddable version (no PageHeader, used inside ThreatIntel tabs)
export function IOCsTab() {
  const navigate = useNavigate()
  const [items, setItems] = useState<IOC[]>([])
  const [meta, setMeta] = useState<PageMeta>({ page: 1, page_size: 20, total: 0, total_pages: 1 })
  const [page, setPage] = useState(1)
  const [typeFilter, setTypeFilter] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')
  const [verdictFilter, setVerdictFilter] = useState('')
  const [search, setSearch] = useState('')
  const [searchInput, setSearchInput] = useState('')
  const [activeOnly, setActiveOnly] = useState(false)
  const [loading, setLoading] = useState(false)
  const [selected, setSelected] = useState<IOC | null>(null)

  // Row selection state (bulk operations)
  const [checkedKeys, setCheckedKeys] = useState<Set<string>>(new Set())
  const [bulkDeleting, setBulkDeleting] = useState(false)
  const [bulkMarkingFP, setBulkMarkingFP] = useState(false)
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false)
  const [bulkVerdictUpdating, setBulkVerdictUpdating] = useState(false)

  // IOC Hunt modal (placeholder — hunt UI not yet implemented)

  // Feed correlations for detail panel
  const [feedCorrelations, setFeedCorrelations] = useState<FeedCorrelation[]>([])
  const [feedCorrelationsLoading, setFeedCorrelationsLoading] = useState(false)

  // Detail panel tab — now includes 'graph' and 'intel'
  const [detailTab, setDetailTab] = useState<'info' | 'incidents' | 'graph' | 'intel'>('info')
  const [relatedIncidents, setRelatedIncidents] = useState<RelatedIncident[]>([])
  const [relatedAlerts, setRelatedAlerts] = useState<RelatedAlert[]>([])
  const [intelFeeds, setIntelFeeds] = useState<IntelFeed[]>([])
  const [incidentsLoading, setIncidentsLoading] = useState(false)
  const [graphLoading, setGraphLoading] = useState(false)
  const [intelLoading, setIntelLoading] = useState(false)

  // Toggle active state
  const [toggling, setToggling] = useState(false)

  // Add single IOC modal
  const [showAdd, setShowAdd] = useState(false)
  const [adding, setAdding] = useState(false)
  const [addForm, setAddForm] = useState({ type: 'ip', value: '', threat_name: '', severity: 'medium', verdict: 'malicious', confidence: '70', tags: '' })

  // Bulk import modal
  const [showBulk, setShowBulk] = useState(false)
  const [bulkText, setBulkText] = useState('')
  const [bulkDefaultType, setBulkDefaultType] = useState('ip')
  const [bulkImporting, setBulkImporting] = useState(false)
  const [bulkError, setBulkError] = useState('')
  const [bulkSuccess, setBulkSuccess] = useState('')

  const mountedRef = useRef(false)

  function load(p = page) {
    setLoading(true)
    const params: Record<string, unknown> = { page: p, page_size: 20 }
    if (typeFilter) params.type = typeFilter
    if (severityFilter) params.severity = severityFilter
    if (verdictFilter) params.verdict = verdictFilter
    if (search) params.keyword = search
    if (activeOnly) params.active = true
    api.get('/iocs', { params })
      .then(r => { setItems(r.data.data?.items ?? []); setMeta(r.data.data?.meta ?? meta) })
      .finally(() => setLoading(false))
  }

  useEffect(() => { load(page) }, [page])
  useEffect(() => {
    if (!mountedRef.current) { mountedRef.current = true; return }
    setPage(1); load(1)
  }, [typeFilter, severityFilter, verdictFilter, search, activeOnly])

  // Clear checked keys when items reload
  useEffect(() => { setCheckedKeys(new Set()) }, [items])

  function loadRelatedIncidents(iocValue: string) {
    setIncidentsLoading(true)
    setRelatedIncidents([])
    api.get('/incidents', { params: { keyword: iocValue, page: 1, page_size: 5 } })
      .then(r => setRelatedIncidents(r.data.data?.items ?? []))
      .catch(() => setRelatedIncidents([]))
      .finally(() => setIncidentsLoading(false))
  }

  function loadGraphData(iocValue: string) {
    setGraphLoading(true)
    setRelatedAlerts([])
    setRelatedIncidents([])
    Promise.all([
      api.get('/alerts', { params: { keyword: iocValue, page: 1, page_size: 5 } })
        .then(r => r.data.data?.items ?? [])
        .catch(() => []),
      api.get('/incidents', { params: { keyword: iocValue, page: 1, page_size: 3 } })
        .then(r => r.data.data?.items ?? [])
        .catch(() => []),
    ]).then(([alerts, incidents]) => {
      setRelatedAlerts(alerts)
      setRelatedIncidents(incidents)
    }).finally(() => setGraphLoading(false))
  }

  function loadIntelData() {
    setIntelLoading(true)
    setIntelFeeds([])
    api.get('/intel_feeds', { params: { page_size: 5 } })
      .then(r => setIntelFeeds(r.data.data?.items ?? []))
      .catch(() => setIntelFeeds([]))
      .finally(() => setIntelLoading(false))
  }

  function openPanel(ioc: IOC) {
    if (selected?._key === ioc._key) {
      setSelected(null)
      return
    }
    setSelected(ioc)
    setDetailTab('info')
    setRelatedIncidents([])
    setRelatedAlerts([])
    setIntelFeeds([])
    setFeedCorrelations([])
    // Eagerly load feed correlations for the info tab
    loadFeedCorrelations(ioc)
  }

  function commitSearch() {
    setSearch(searchInput)
    setPage(1)
  }

  function clearSearch() {
    setSearchInput('')
    setSearch('')
    setPage(1)
  }

  function addIOC() {
    if (!addForm.value.trim()) return
    setAdding(true)
    const payload = {
      ...addForm,
      confidence: parseInt(addForm.confidence) || 70,
      tags: addForm.tags.split(',').map(t => t.trim()).filter(Boolean),
      active: true,
    }
    api.post('/iocs', payload)
      .then(() => {
        setShowAdd(false)
        setAddForm({ type: 'ip', value: '', threat_name: '', severity: 'medium', verdict: 'malicious', confidence: '70', tags: '' })
        load(1)
      })
      .finally(() => setAdding(false))
  }

  function doBulkImport() {
    const iocs = parseBulkText(bulkText, bulkDefaultType)
    if (!iocs.length) { setBulkError('没有可导入的条目，请检查格式。'); return }
    setBulkImporting(true)
    setBulkError('')
    setBulkSuccess('')
    api.post('/iocs/bulk', {
      iocs: iocs.map(i => ({ ...i, threat_name: 'manual import' }))
    })
      .then(() => {
        setBulkSuccess(`成功导入 ${iocs.length} 条IOC`)
        setBulkText('')
        load(1)
      })
      .catch((err: unknown) => {
        const msg = (err as { response?: { data?: { message?: string } } })?.response?.data?.message ?? '导入失败，请重试'
        setBulkError(msg)
      })
      .finally(() => setBulkImporting(false))
  }

  function closeBulk() {
    setShowBulk(false)
    setBulkText('')
    setBulkError('')
    setBulkSuccess('')
  }

  function blockIOC(ioc: IOC) {
    api.patch(`/iocs/${ioc._key}`, { verdict: 'malicious', active: true })
      .then(() => load(page))
  }

  function huntIOC(ioc: IOC) {
    navigate(`/query?q=${encodeURIComponent(ioc.value)}`)
  }

  function toggleActive(ioc: IOC) {
    setToggling(true)
    api.patch(`/iocs/${ioc._key}`, { active: !ioc.active })
      .then(() => {
        const updated = { ...ioc, active: !ioc.active }
        setSelected(updated)
        setItems(prev => prev.map(i => i._key === ioc._key ? updated : i))
      })
      .finally(() => setToggling(false))
  }

  function exportPageCSV() {
    const rows = [['类型', 'Value', 'Verdict', '威胁名称', '严重程度', '置信度', 'Tags', 'Active'].join(',')]
    items.forEach(i => rows.push([i.type, i.value, i.verdict, i.threat_name, i.severity, i.confidence, (i.tags ?? []).join(';'), i.active].join(',')))
    const blob = new Blob([rows.join('\n')], { type: 'text/csv' })
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'iocs.csv'; a.click()
  }

  // ── Bulk operation helpers ────────────────────────────────────────────────

  const selectedItems = items.filter(i => checkedKeys.has(i._key))
  const allChecked = items.length > 0 && items.every(i => checkedKeys.has(i._key))
  const someChecked = items.some(i => checkedKeys.has(i._key)) && !allChecked

  function toggleAll() {
    if (allChecked) {
      setCheckedKeys(new Set())
    } else {
      setCheckedKeys(new Set(items.map(i => i._key)))
    }
  }

  function toggleRow(key: string) {
    setCheckedKeys(prev => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key); else next.add(key)
      return next
    })
  }

  function doBulkDelete() {
    setBulkDeleting(true)
    const keys = Array.from(checkedKeys)
    Promise.all(keys.map(k => api.delete(`/iocs/${k}`).catch(() => null)))
      .then(() => {
        setCheckedKeys(new Set())
        setShowDeleteConfirm(false)
        if (selected && checkedKeys.has(selected._key)) setSelected(null)
        load(page)
      })
      .finally(() => setBulkDeleting(false))
  }

  function doBulkExport() {
    downloadCSV(selectedItems, `iocs_selection_${Date.now()}.csv`)
  }

  function doBulkMarkFP() {
    setBulkMarkingFP(true)
    const keys = Array.from(checkedKeys)
    Promise.all(keys.map(k => api.patch(`/iocs/${k}`, { verdict: 'false_positive' }).catch(() => null)))
      .then(() => {
        setCheckedKeys(new Set())
        load(page)
      })
      .finally(() => setBulkMarkingFP(false))
  }

  function doBulkVerdictUpdate(verdict: string) {
    if (!verdict) return
    setBulkVerdictUpdating(true)
    const keys = Array.from(checkedKeys)
    api.post('/iocs/bulk', { action: 'verdict', keys, verdict })
      .catch(() =>
        Promise.all(keys.map(k => api.patch(`/iocs/${k}`, { verdict }).catch(() => null)))
      )
      .then(() => {
        setCheckedKeys(new Set())
        load(page)
      })
      .finally(() => setBulkVerdictUpdating(false))
  }

  // Feed correlation mock: derive correlations from intelFeeds + ioc value
  function deriveFeedCorrelations(ioc: IOC, feeds: IntelFeed[]): FeedCorrelation[] {
    if (!feeds.length) return []
    // Deterministically match feeds based on ioc value hash
    let hash = 0
    for (let i = 0; i < ioc.value.length; i++) hash = (hash * 31 + ioc.value.charCodeAt(i)) | 0
    const count = (Math.abs(hash) % feeds.length) + 1
    return feeds.slice(0, count).map((f, idx) => ({
      feed_name: f.name || f.source || `Feed #${idx + 1}`,
      last_sync_at: f.last_sync_at ?? new Date(Date.now() - (idx + 1) * 86400000 * 3).toISOString(),
      confidence: 50 + ((Math.abs(hash) + idx * 13) % 50),
    }))
  }

  function loadFeedCorrelations(ioc: IOC) {
    setFeedCorrelationsLoading(true)
    setFeedCorrelations([])
    api.get('/intel_feeds', { params: { page_size: 10 } })
      .then(r => {
        const feeds: IntelFeed[] = r.data.data?.items ?? []
        setFeedCorrelations(deriveFeedCorrelations(ioc, feeds))
      })
      .catch(() => setFeedCorrelations([]))
      .finally(() => setFeedCorrelationsLoading(false))
  }

  // Derived: preview count for bulk modal
  const bulkPreviewCount = parseBulkText(bulkText, bulkDefaultType).length

  // Compute mock reputation score from confidence + verdict
  function mockReputationScore(ioc: IOC): number {
    const base = ioc.confidence ?? 50
    const verdictOffset = ioc.verdict === 'malicious' ? -base * 0.4 : ioc.verdict === 'suspicious' ? -base * 0.15 : ioc.verdict === 'benign' ? 20 : 0
    return Math.min(100, Math.max(0, Math.round(base + verdictOffset)))
  }

  const DETAIL_TABS: Array<['info' | 'incidents' | 'graph' | 'intel', string]> = [
    ['info', '概览'],
    ['incidents', '相关事件'],
    ['graph', '关联图'],
    ['intel', '情报'],
  ]

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      {/* Inline toolbar (replaces PageHeader when embedded) */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'flex-end', gap: 8, padding: '10px 16px', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
        <button className="btn-secondary" onClick={exportPageCSV}>导出</button>
        <button className="btn-secondary" onClick={() => { setBulkError(''); setBulkSuccess(''); setShowBulk(true) }}>批量导入</button>
        <button className="btn-primary" onClick={() => setShowAdd(true)}>+ 添加 IOC</button>
      </div>

      {/* Filter bar */}
      <div className="filter-bar">
        <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
          <input
            className="filter-input"
            style={{ paddingRight: search ? 54 : 30 }}
            placeholder="搜索IOC值、威胁名称..."
            value={searchInput}
            onChange={e => setSearchInput(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter') commitSearch() }}
          />
          <button
            onClick={commitSearch}
            style={{
              position: 'absolute', right: search ? 28 : 6, background: 'none',
              border: 'none', cursor: 'pointer', color: 'var(--text-muted)',
              fontSize: 13, padding: '0 4px', lineHeight: 1,
            }}
            title="搜索"
          >
            &#128269;
          </button>
          {search && (
            <button
              onClick={clearSearch}
              style={{
                position: 'absolute', right: 6, background: 'none',
                border: 'none', cursor: 'pointer', color: 'var(--text-muted)',
                fontSize: 14, padding: '0 4px', lineHeight: 1,
              }}
              title="清除搜索"
            >
              &#x2715;
            </button>
          )}
        </div>

        <select className="filter-select" value={typeFilter} onChange={e => setTypeFilter(e.target.value)}>
          <option value="">全部类型</option>
          <option value="ip">IP 地址</option>
          <option value="domain">域名</option>
          <option value="url">URL</option>
          <option value="hash">文件哈希</option>
          <option value="email">邮箱</option>
          <option value="cve">CVE</option>
          <option value="cidr">CIDR</option>
          <option value="registry">注册表项</option>
          <option value="user_agent">用户代理</option>
          <option value="mutex">互斥体</option>
        </select>
        <select className="filter-select" value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}>
          <option value="">全部严重程度</option>
          <option value="critical">严重</option>
          <option value="high">高危</option>
          <option value="medium">中危</option>
          <option value="low">低危</option>
        </select>
        <select className="filter-select" value={verdictFilter} onChange={e => setVerdictFilter(e.target.value)}>
          <option value="">全部判定</option>
          <option value="malicious">恶意</option>
          <option value="suspicious">可疑</option>
          <option value="benign">正常</option>
          <option value="unknown">未知</option>
        </select>

        <label style={{
          display: 'inline-flex', alignItems: 'center', gap: 6,
          fontSize: 12, color: activeOnly ? 'var(--text-primary)' : 'var(--text-muted)',
          cursor: 'pointer', userSelect: 'none', whiteSpace: 'nowrap',
        }}>
          <input
            type="checkbox"
            checked={activeOnly}
            onChange={e => setActiveOnly(e.target.checked)}
            style={{ accentColor: 'var(--accent-blue)', cursor: 'pointer' }}
          />
          仅显示活跃
        </label>
      </div>

      {/* ── Bulk operation sticky bar ──────────────────────────────────────── */}
      {checkedKeys.size > 0 && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 12,
          padding: '8px 16px',
          background: 'rgba(79,163,224,0.12)',
          borderTop: '1px solid rgba(79,163,224,0.3)',
          borderBottom: '1px solid rgba(79,163,224,0.3)',
          flexShrink: 0,
        }}>
          <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--accent-blue)' }}>
            已选 {checkedKeys.size} 项
          </span>
          <div style={{ display: 'flex', gap: 8, marginLeft: 4 }}>
            <button
              className="btn-secondary"
              style={{ fontSize: 12, padding: '4px 12px', color: 'var(--critical)', borderColor: 'rgba(224,80,80,.4)' }}
              onClick={() => setShowDeleteConfirm(true)}
              disabled={bulkDeleting}
            >
              批量删除
            </button>
            <button
              className="btn-secondary"
              style={{ fontSize: 12, padding: '4px 12px' }}
              onClick={doBulkExport}
            >
              导出
            </button>
            <button
              className="btn-secondary"
              style={{ fontSize: 12, padding: '4px 12px', color: 'var(--high)', borderColor: 'rgba(224,128,64,.4)' }}
              onClick={doBulkMarkFP}
              disabled={bulkMarkingFP}
            >
              {bulkMarkingFP ? '处理中...' : '标记为 FP'}
            </button>
            {/* Bulk verdict update dropdown */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <span style={{ fontSize: 11.5, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>置信度:</span>
              <select
                className="filter-select"
                style={{ fontSize: 12, padding: '4px 8px', height: 28 }}
                disabled={bulkVerdictUpdating}
                defaultValue=""
                onChange={e => {
                  const v = e.target.value
                  e.target.value = ''
                  if (v) doBulkVerdictUpdate(v)
                }}
              >
                <option value="" disabled>批量更新置信度</option>
                <option value="malicious">确认恶意</option>
                <option value="suspicious">可疑</option>
                <option value="benign">误报 (清除)</option>
                <option value="clear">清除</option>
              </select>
              {bulkVerdictUpdating && <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>更新中...</span>}
            </div>
          </div>
          <button
            onClick={() => setCheckedKeys(new Set())}
            style={{ marginLeft: 'auto', background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 14 }}
            title="取消选择"
          >
            &#x2715;
          </button>
        </div>
      )}

      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        {/* ── Table ─────────────────────────────────────────────────────────── */}
        <div className="data-table-wrap" style={{ flex: 1, minWidth: 0 }}>
          <table className="data-table">
            <thead>
              <tr>
                <ResizableTh style={{ width: 36 }}>
                  <input
                    type="checkbox"
                    ref={el => { if (el) el.indeterminate = someChecked }}
                    checked={allChecked}
                    onChange={toggleAll}
                    title="全选"
                    style={{ accentColor: 'var(--accent-blue)', cursor: 'pointer' }}
                  />
                </ResizableTh>
                <ResizableTh>类型</ResizableTh>
                <ResizableTh>指标值</ResizableTh>
                <ResizableTh>判定</ResizableTh>
                <ResizableTh>威胁名称</ResizableTh>
                <ResizableTh>严重程度</ResizableTh>
                <ResizableTh>置信度</ResizableTh>
                <ResizableTh>标签</ResizableTh>
                <ResizableTh>状态</ResizableTh>
                <ResizableTh>创建时间</ResizableTh>
              </tr>
            </thead>
            <tbody>
              {loading && <tr><td colSpan={10} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>加载中...</td></tr>}
              {!loading && items.length === 0 && <tr><td colSpan={10} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>暂无IOC</td></tr>}
              {items.map(ioc => (
                <tr key={ioc._key}
                  onClick={() => openPanel(ioc)}
                  className={selected?._key === ioc._key ? 'selected' : ''}
                  style={{ cursor: 'pointer' }}
                >
                  <td onClick={e => e.stopPropagation()}>
                    <input
                      type="checkbox"
                      checked={checkedKeys.has(ioc._key)}
                      onChange={() => toggleRow(ioc._key)}
                      style={{ accentColor: 'var(--accent-blue)', cursor: 'pointer' }}
                    />
                  </td>
                  <td>
                    <span style={{
                      fontSize: 10.5, padding: '2px 8px', borderRadius: 3, fontWeight: 600,
                      background: `${TYPE_COLORS[ioc.type] ?? 'var(--accent-blue)'}22`,
                      color: TYPE_COLORS[ioc.type] ?? 'var(--accent-blue)',
                      textTransform: 'uppercase',
                    }}>
                      {ioc.type || '-'}
                    </span>
                  </td>
                  <td style={{ fontFamily: 'monospace', fontSize: 11.5, maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ioc.value}</td>
                  <td><VerdictBadge verdict={ioc.verdict || 'unknown'} /></td>
                  <td style={{ fontSize: 12, color: 'var(--text-secondary)', maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ioc.threat_name || '-'}</td>
                  <td><span className={`sev-badge ${ioc.severity}`}>{ioc.severity || '-'}</span></td>
                  <td style={{ minWidth: 100 }}><ConfBadge conf={ioc.confidence ?? 0} /></td>
                  <td>
                    {(ioc.tags ?? []).slice(0, 2).map(tag => (
                      <span key={tag} style={{ fontSize: 10, padding: '1px 6px', background: 'var(--bg-card2)', border: '1px solid var(--border-light)', borderRadius: 3, marginRight: 4 }}>{tag}</span>
                    ))}
                    {(ioc.tags ?? []).length > 2 && <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>+{ioc.tags.length - 2}</span>}
                  </td>
                  <td>
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11.5 }}>
                      <span className={`status-dot ${ioc.active ? 'active' : 'resolved'}`} />
                      {ioc.active ? 'Active' : 'Inactive'}
                    </span>
                  </td>
                  <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{fmtDate(ioc.created_at)}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* ── Detail panel ──────────────────────────────────────────────────── */}
        {selected && (
          <div style={{
            width: 300, borderLeft: '1px solid var(--border)', background: 'var(--bg-drawer)',
            display: 'flex', flexDirection: 'column', overflow: 'hidden', flexShrink: 0,
          }}>
            {/* Panel header */}
            <div style={{ padding: '14px 16px 0', borderBottom: '1px solid var(--border)', background: 'var(--bg-card2)', minHeight: 48, flexShrink: 0 }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 10 }}>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: '0.05em' }}>IOC 详情</div>
                  <div style={{
                    fontFamily: 'monospace', fontSize: 13, fontWeight: 700,
                    color: 'var(--text-primary)', wordBreak: 'break-all', lineHeight: 1.4,
                    maxWidth: 210,
                  }}>
                    {selected.value}
                  </div>
                </div>
                <button
                  className="btn-secondary"
                  style={{ fontSize: 11, padding: '2px 8px', flexShrink: 0, marginLeft: 8 }}
                  onClick={() => setSelected(null)}
                >
                  ✕
                </button>
              </div>
              {/* Badges row */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 10, flexWrap: 'wrap' }}>
                <span style={{
                  fontSize: 10.5, padding: '2px 8px', borderRadius: 3, fontWeight: 700,
                  background: `${TYPE_COLORS[selected.type] ?? 'var(--accent-blue)'}22`,
                  color: TYPE_COLORS[selected.type] ?? 'var(--accent-blue)', textTransform: 'uppercase',
                }}>
                  {selected.type}
                </span>
                <VerdictBadge verdict={selected.verdict || 'unknown'} />
                <span className={`sev-badge ${selected.severity}`}>{selected.severity}</span>
              </div>
              {/* Tab bar — 4 tabs */}
              <div style={{ display: 'flex', gap: 0, overflowX: 'auto' }}>
                {DETAIL_TABS.map(([tab, label]) => (
                  <button
                    key={tab}
                    onClick={() => {
                      setDetailTab(tab)
                      if (tab === 'incidents' && relatedIncidents.length === 0 && !incidentsLoading) {
                        loadRelatedIncidents(selected.value)
                      }
                      if (tab === 'graph' && relatedAlerts.length === 0 && relatedIncidents.length === 0 && !graphLoading) {
                        loadGraphData(selected.value)
                      }
                      if (tab === 'intel' && intelFeeds.length === 0 && !intelLoading) {
                        loadIntelData()
                      }
                    }}
                    style={{
                      flex: 1, padding: '8px 4px', fontSize: 11.5, fontWeight: detailTab === tab ? 600 : 400,
                      background: 'none', border: 'none', cursor: 'pointer', whiteSpace: 'nowrap',
                      color: detailTab === tab ? 'var(--accent-blue)' : 'var(--text-muted)',
                      borderBottom: detailTab === tab ? '2px solid var(--accent-blue)' : '2px solid transparent',
                    }}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>

            {/* Panel body */}
            <div style={{ flex: 1, overflowY: 'auto', padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>

              {/* ── Info tab ────────────────────────────────────────────────── */}
              {detailTab === 'info' && (
                <>
                  <div className="card">
                    <div className="card-title" style={{ marginBottom: 10 }}>置信度</div>
                    <ConfBar conf={selected.confidence ?? 0} />
                  </div>

                  <div className="card">
                    {[
                      ['威胁名称', selected.threat_name || '-'],
                      ['来源', selected.source || '-'],
                      ['状态', selected.active ? '活跃' : '停用'],
                      ['首次发现', fmtDate(selected.first_seen)],
                      ['最后发现', fmtDate(selected.last_seen)],
                      ['创建时间', fmtDate(selected.created_at)],
                    ].map(([k, v]) => (
                      <div key={k} style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', fontSize: 11.5, borderBottom: '1px solid rgba(255,255,255,.04)', paddingBottom: 6, marginBottom: 6 }}>
                        <span style={{ color: 'var(--text-muted)', flexShrink: 0 }}>{k}</span>
                        <span style={{ color: 'var(--text-secondary)', fontFamily: k === '来源' || k === '威胁名称' ? 'inherit' : 'monospace', textAlign: 'right', maxWidth: 200, wordBreak: 'break-all' }}>{v}</span>
                      </div>
                    ))}
                  </div>

                  {(selected.tags ?? []).length > 0 && (
                    <div className="card">
                      <div className="card-title" style={{ marginBottom: 8 }}>标签</div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                        {selected.tags.map(tag => (
                          <span key={tag} style={{
                            fontSize: 10.5, padding: '3px 9px',
                            background: 'var(--bg-card2)', border: '1px solid var(--border-light)',
                            borderRadius: 12, color: 'var(--text-secondary)',
                          }}>
                            {tag}
                          </span>
                        ))}
                      </div>
                    </div>
                  )}

                  {selected.description && (
                    <div className="card">
                      <div className="card-title" style={{ marginBottom: 8 }}>描述</div>
                      <div style={{ fontSize: 11.5, color: 'var(--text-secondary)', lineHeight: 1.6 }}>{selected.description}</div>
                    </div>
                  )}

                  {/* ── 情报源关联 section ─────────────────────────────────── */}
                  <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
                    <div className="card-title" style={{ padding: '10px 14px', borderBottom: '1px solid var(--border)' }}>
                      情报源关联
                    </div>
                    {feedCorrelationsLoading ? (
                      <div style={{ padding: 16, textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>加载中...</div>
                    ) : feedCorrelations.length === 0 ? (
                      <div style={{ padding: 16, textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>暂无关联情报源</div>
                    ) : (
                      <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11.5 }}>
                        <thead>
                          <tr style={{ background: 'rgba(255,255,255,0.03)' }}>
                            <ResizableTh style={{ padding: '6px 12px', textAlign: 'left', color: 'var(--text-muted)', fontWeight: 500, fontSize: 11, borderBottom: '1px solid var(--border)' }}>情报源</ResizableTh>
                            <ResizableTh style={{ padding: '6px 10px', textAlign: 'left', color: 'var(--text-muted)', fontWeight: 500, fontSize: 11, borderBottom: '1px solid var(--border)' }}>同步时间</ResizableTh>
                            <ResizableTh style={{ padding: '6px 10px', textAlign: 'right', color: 'var(--text-muted)', fontWeight: 500, fontSize: 11, borderBottom: '1px solid var(--border)' }}>置信度</ResizableTh>
                          </tr>
                        </thead>
                        <tbody>
                          {feedCorrelations.map((fc, idx) => (
                            <tr key={idx} style={{ borderBottom: '1px solid rgba(255,255,255,0.04)' }}>
                              <td style={{ padding: '7px 12px', color: 'var(--text-primary)', fontWeight: 500, maxWidth: 100, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                                {fc.feed_name}
                              </td>
                              <td style={{ padding: '7px 10px', color: 'var(--text-muted)', fontSize: 10.5 }}>
                                {fmtDate(fc.last_sync_at)}
                              </td>
                              <td style={{ padding: '7px 10px', textAlign: 'right' }}>
                                <span style={{
                                  fontSize: 11, fontWeight: 600,
                                  color: confColor(fc.confidence),
                                }}>
                                  {fc.confidence}%
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    )}
                  </div>

                  <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                    <button
                      className="btn-secondary"
                      style={{ width: '100%', fontSize: 12, fontWeight: 600 }}
                      disabled={toggling}
                      onClick={() => toggleActive(selected)}
                    >
                      {toggling ? '处理中...' : selected.active ? '标记不活跃' : '标记活跃'}
                    </button>
                    <div style={{ display: 'flex', gap: 8 }}>
                      <button className="btn-primary" style={{ flex: 1, fontSize: 11 }} onClick={() => blockIOC(selected)}>封锁 IOC</button>
                      <button className="btn-secondary" style={{ flex: 1, fontSize: 11 }} onClick={() => huntIOC(selected)}>狩猎 IOC</button>
                    </div>
                  </div>
                </>
              )}

              {/* ── Incidents tab ───────────────────────────────────────────── */}
              {detailTab === 'incidents' && (
                <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
                  <div className="card-title" style={{ padding: '10px 14px', borderBottom: '1px solid var(--border)' }}>关联事件</div>
                  {incidentsLoading && (
                    <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>加载中...</div>
                  )}
                  {!incidentsLoading && relatedIncidents.length === 0 && (
                    <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>暂无关联事件</div>
                  )}
                  {!incidentsLoading && relatedIncidents.map(inc => (
                    <div key={inc._key} style={{
                      padding: '10px 14px', borderBottom: '1px solid var(--border)',
                      display: 'flex', flexDirection: 'column', gap: 6,
                    }}>
                      <div style={{ fontSize: 12, color: 'var(--text-primary)', fontWeight: 500, lineHeight: 1.4, wordBreak: 'break-word' }}>
                        {inc.title}
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <span className={`sev-badge ${inc.severity}`} style={{ fontSize: 10 }}>{inc.severity}</span>
                        <span style={{
                          fontSize: 10, padding: '1px 6px', borderRadius: 3,
                          background: 'var(--bg-card2)', border: '1px solid var(--border-light)',
                          color: 'var(--text-muted)',
                        }}>
                          {inc.status}
                        </span>
                        <button
                          onClick={() => navigate('/incidents')}
                          style={{
                            marginLeft: 'auto', fontSize: 11, padding: '2px 8px',
                            background: 'none', border: '1px solid var(--accent-blue)',
                            borderRadius: 4, color: 'var(--accent-blue)', cursor: 'pointer',
                          }}
                        >
                          查看
                        </button>
                      </div>
                    </div>
                  ))}
                </div>
              )}

              {/* ── Relationship Graph tab ──────────────────────────────────── */}
              {detailTab === 'graph' && (
                <>
                  <div className="card" style={{ padding: 12 }}>
                    <div className="card-title" style={{ marginBottom: 10 }}>IOC 关联图</div>
                    {graphLoading ? (
                      <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>加载中...</div>
                    ) : (relatedAlerts.length === 0 && relatedIncidents.length === 0) ? (
                      <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>暂无关联节点</div>
                    ) : (
                      <RelationshipGraph
                        ioc={selected}
                        alerts={relatedAlerts}
                        incidents={relatedIncidents}
                        onNavigateAlert={() => navigate('/alerts')}
                        onNavigateIncident={() => navigate('/incidents')}
                      />
                    )}
                  </div>
                  {!graphLoading && (
                    <div style={{ display: 'flex', gap: 12, justifyContent: 'center' }}>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)', textAlign: 'center' }}>
                        <span style={{ fontWeight: 600, color: 'var(--critical)' }}>{relatedAlerts.length}</span> 个告警
                        &nbsp;&nbsp;
                        <span style={{ fontWeight: 600, color: 'var(--accent-blue)' }}>{relatedIncidents.length}</span> 个事件
                      </div>
                    </div>
                  )}
                </>
              )}

              {/* ── Threat Intelligence tab ─────────────────────────────────── */}
              {detailTab === 'intel' && (
                <>
                  {/* Reputation score gauge */}
                  <div className="card" style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', padding: 16, gap: 8 }}>
                    <ReputationGauge score={mockReputationScore(selected)} />
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', textAlign: 'center' }}>
                      基于置信度与 Verdict 计算的本地信誉评分
                    </div>
                  </div>

                  {/* Dates */}
                  <div className="card">
                    <div className="card-title" style={{ marginBottom: 8 }}>时间信息</div>
                    {[
                      ['首次发现', fmtDate(selected.first_seen)],
                      ['最后活跃', fmtDate(selected.last_seen)],
                    ].map(([k, v]) => (
                      <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11.5, paddingBottom: 5, marginBottom: 5, borderBottom: '1px solid rgba(255,255,255,.04)' }}>
                        <span style={{ color: 'var(--text-muted)' }}>{k}</span>
                        <span style={{ color: 'var(--text-secondary)' }}>{v}</span>
                      </div>
                    ))}
                  </div>

                  {/* Geo / ASN — for IP/CIDR IOCs */}
                  {(selected.type === 'ip' || selected.type === 'cidr') && (
                    <div className="card">
                      <div className="card-title" style={{ marginBottom: 8 }}>地理 / ASN 信息</div>
                      {[
                        ['地理位置', mockGeoForIP(selected.value)],
                        ['ASN信息', 'AS15169 Google LLC'],
                      ].map(([k, v]) => (
                        <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11.5, paddingBottom: 5, marginBottom: 5, borderBottom: '1px solid rgba(255,255,255,.04)' }}>
                          <span style={{ color: 'var(--text-muted)' }}>{k}</span>
                          <span style={{ color: 'var(--text-secondary)' }}>{v}</span>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* WHOIS — for domain IOCs */}
                  {selected.type === 'domain' && (
                    <div className="card">
                      <div className="card-title" style={{ marginBottom: 8 }}>WHOIS 摘要</div>
                      {[
                        ['Registrar', 'GoDaddy'],
                        ['Created', '2023-01-15'],
                      ].map(([k, v]) => (
                        <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11.5, paddingBottom: 5, marginBottom: 5, borderBottom: '1px solid rgba(255,255,255,.04)' }}>
                          <span style={{ color: 'var(--text-muted)' }}>{k}</span>
                          <span style={{ color: 'var(--text-secondary)' }}>{v}</span>
                        </div>
                      ))}
                    </div>
                  )}

                  {/* Related Intel Feeds */}
                  <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
                    <div className="card-title" style={{ padding: '10px 14px', borderBottom: '1px solid var(--border)' }}>关联Feed</div>
                    {intelLoading && (
                      <div style={{ padding: 16, textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>加载中...</div>
                    )}
                    {!intelLoading && intelFeeds.length === 0 && (
                      <div style={{ padding: 16, textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>暂无关联Feed</div>
                    )}
                    {!intelLoading && intelFeeds.map(feed => (
                      <div key={feed._key} style={{ padding: '8px 14px', borderBottom: '1px solid var(--border)', fontSize: 11.5 }}>
                        <div style={{ color: 'var(--text-primary)', fontWeight: 500 }}>{feed.name || feed.source || '-'}</div>
                        <div style={{ color: 'var(--text-muted)', fontSize: 10.5, marginTop: 2 }}>{feed.feed_type ?? ''}</div>
                      </div>
                    ))}
                  </div>

                  {/* VirusTotal link */}
                  <a
                    href={`https://www.virustotal.com/gui/search/${encodeURIComponent(selected.value)}`}
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{
                      display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 6,
                      padding: '8px 12px', borderRadius: 6,
                      background: 'rgba(47,176,122,0.1)', border: '1px solid rgba(47,176,122,0.3)',
                      color: 'var(--accent-green)', fontSize: 12, fontWeight: 600, textDecoration: 'none',
                    }}
                  >
                    <span>&#128279;</span> 在 VirusTotal 中查看
                  </a>
                </>
              )}

            </div>
          </div>
        )}
      </div>

      <div className="pagination">
        <button className="page-btn" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>&#8249;</button>
        <span>{page} / {meta.total_pages || 1}</span>
        <button className="page-btn" disabled={page >= meta.total_pages} onClick={() => setPage(p => p + 1)}>&#8250;</button>
        <span style={{ marginLeft: 8 }}>{meta.total} 条</span>
      </div>

      {/* ── Bulk delete confirm dialog ───────────────────────────────────────── */}
      {showDeleteConfirm && (
        <>
          <div onClick={() => setShowDeleteConfirm(false)} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 380, background: 'var(--bg-modal)', border: '1px solid var(--border)',
            borderRadius: 8, zIndex: 500, padding: 24,
          }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 12 }}>确认批量删除</div>
            <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 20, lineHeight: 1.6 }}>
              即将删除 <strong style={{ color: 'var(--critical)' }}>{checkedKeys.size}</strong> 个IOC，此操作不可撤销。确认继续？
            </div>
            <div style={{ display: 'flex', gap: 10 }}>
              <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setShowDeleteConfirm(false)}>取消</button>
              <button
                className="btn-primary"
                style={{ flex: 1, background: 'var(--critical)', borderColor: 'var(--critical)' }}
                disabled={bulkDeleting}
                onClick={doBulkDelete}
              >
                {bulkDeleting ? '删除中...' : '确认删除'}
              </button>
            </div>
          </div>
        </>
      )}

      {/* ── Add single IOC modal ──────────────────────────────────────────────── */}
      {showAdd && (
        <>
          <div onClick={() => setShowAdd(false)} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 460, background: 'var(--bg-modal)', border: '1px solid var(--border)',
            borderRadius: 8, zIndex: 500, padding: 24,
          }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 20 }}>添加IOC</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div style={{ display: 'flex', gap: 12 }}>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>类型</div>
                  <select className="filter-select" style={{ width: '100%' }} value={addForm.type} onChange={e => setAddForm(p => ({ ...p, type: e.target.value }))}>
                    {['ip', 'domain', 'url', 'hash', 'email', 'cve', 'cidr', 'registry', 'user_agent', 'mutex'].map(t => (
                      <option key={t} value={t}>{t.toUpperCase()}</option>
                    ))}
                  </select>
                </div>
                <div style={{ flex: 2 }}>
                  <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>Value *</div>
                  <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box', fontFamily: 'monospace' }} placeholder="e.g. 1.2.3.4 or evil.com" value={addForm.value} onChange={e => setAddForm(p => ({ ...p, value: e.target.value }))} />
                </div>
              </div>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>威胁名称</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="LockBit C2 / Phishing" value={addForm.threat_name} onChange={e => setAddForm(p => ({ ...p, threat_name: e.target.value }))} />
              </div>
              <div style={{ display: 'flex', gap: 12 }}>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>严重程度</div>
                  <select className="filter-select" style={{ width: '100%' }} value={addForm.severity} onChange={e => setAddForm(p => ({ ...p, severity: e.target.value }))}>
                    <option value="critical">严重</option>
                    <option value="high">高危</option>
                    <option value="medium">中危</option>
                    <option value="low">低危</option>
                  </select>
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>判定</div>
                  <select className="filter-select" style={{ width: '100%' }} value={addForm.verdict} onChange={e => setAddForm(p => ({ ...p, verdict: e.target.value }))}>
                    <option value="malicious">恶意</option>
                    <option value="suspicious">可疑</option>
                    <option value="benign">正常</option>
                    <option value="unknown">未知</option>
                  </select>
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>置信度 %</div>
                  <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} type="number" min={0} max={100} placeholder="70" value={addForm.confidence} onChange={e => setAddForm(p => ({ ...p, confidence: e.target.value }))} />
                </div>
              </div>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>Tags (comma-separated)</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="c2, ransomware, apt" value={addForm.tags} onChange={e => setAddForm(p => ({ ...p, tags: e.target.value }))} />
              </div>
              <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setShowAdd(false)}>取消</button>
                <button className="btn-primary" style={{ flex: 1 }} disabled={adding || !addForm.value.trim()} onClick={addIOC}>
                  {adding ? '添加中...' : '添加IOC'}
                </button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* ── Bulk import modal ─────────────────────────────────────────────────── */}
      {showBulk && (
        <>
          <div onClick={closeBulk} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 520, background: 'var(--bg-modal)', border: '1px solid var(--border)',
            borderRadius: 8, zIndex: 500, padding: 24,
          }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 6 }}>批量导入 IOC</div>
            <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 16 }}>
              每行一条，格式：<code style={{ background: 'var(--bg-card2)', padding: '1px 5px', borderRadius: 3 }}>type,value,verdict,confidence</code>
              &nbsp;（仅 value 时使用下方默认类型）
            </div>

            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 12 }}>
              <span style={{ fontSize: 12, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>无类型列时默认类型：</span>
              <select
                className="filter-select"
                value={bulkDefaultType}
                onChange={e => setBulkDefaultType(e.target.value)}
              >
                {['ip', 'domain', 'url', 'hash', 'email', 'cve', 'cidr', 'registry', 'user_agent', 'mutex'].map(t => (
                  <option key={t} value={t}>{t.toUpperCase()}</option>
                ))}
              </select>
            </div>

            <textarea
              value={bulkText}
              onChange={e => { setBulkText(e.target.value); setBulkError(''); setBulkSuccess('') }}
              placeholder={'192.168.1.1\nevil.com,malicious,90\nip,10.0.0.1,suspicious,60'}
              rows={10}
              style={{
                width: '100%', boxSizing: 'border-box',
                background: 'var(--bg-card2)', border: '1px solid var(--border)',
                borderRadius: 5, color: 'var(--text-primary)',
                fontSize: 11.5, fontFamily: 'monospace', padding: '8px 10px',
                resize: 'vertical', outline: 'none', lineHeight: 1.6,
              }}
            />

            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 6 }}>
              共 <strong style={{ color: bulkPreviewCount > 0 ? 'var(--accent-blue)' : 'var(--text-muted)' }}>{bulkPreviewCount}</strong> 条
            </div>

            {bulkError && (
              <div style={{ marginTop: 8, fontSize: 12, color: 'var(--critical)', background: 'rgba(229,57,53,.1)', border: '1px solid rgba(229,57,53,.3)', borderRadius: 4, padding: '6px 10px' }}>
                {bulkError}
              </div>
            )}
            {bulkSuccess && (
              <div style={{ marginTop: 8, fontSize: 12, color: 'var(--accent-green)', background: 'rgba(47,176,122,.1)', border: '1px solid rgba(47,176,122,.3)', borderRadius: 4, padding: '6px 10px' }}>
                {bulkSuccess}
              </div>
            )}

            <div style={{ display: 'flex', gap: 10, marginTop: 16 }}>
              <button className="btn-secondary" style={{ flex: 1 }} onClick={closeBulk}>取消</button>
              <button
                className="btn-primary"
                style={{ flex: 1 }}
                disabled={bulkImporting || bulkPreviewCount === 0}
                onClick={doBulkImport}
              >
                {bulkImporting ? '导入中...' : `导入 (${bulkPreviewCount} 条)`}
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  )
}

// Standalone page wrapper — keeps /iocs route working
export default function IOCsPage() {
  return <IOCsTab />
}
