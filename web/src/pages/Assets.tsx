import { useEffect, useRef, useState } from 'react'
import api from '@/lib/api'
import type { PageMeta } from '@/lib/api'
import PageHeader from '@/components/PageHeader'

interface Vulnerability {
  _key: string
  cve_id: string
  severity: string
  cvss_score: number
  fix_status: string
  title: string
}

interface Asset {
  _key: string
  hostname: string
  name: string
  ip: string
  ip_addresses?: string[]
  mac?: string
  os: string
  os_version?: string
  type: string
  status: string
  department?: string
  owner?: string
  risk_score: number
  tags?: string[]
  active_incident_count: number   // API field
  open_vuln_count: number         // API field
  last_seen: string
  created_at: string
}

function AssetScoreBadge({ score }: { score: number }) {
  const [bg, color] = score >= 80
    ? ['rgba(229,57,53,.2)', '#ef5350']
    : score >= 60
      ? ['rgba(255,111,0,.2)', '#ffa726']
      : score >= 30
        ? ['rgba(249,168,37,.2)', '#f9a825']
        : ['rgba(67,160,71,.2)', '#66bb6a']
  return (
    <span className="asset-score-badge" style={{ background: bg, color }}>
      {score}
    </span>
  )
}

function fmtDate(iso: string) {
  if (!iso) return '-'
  return new Date(iso).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false })
}

const osIcon = (os: string) => {
  if (!os) return '🖥'
  const o = os.toLowerCase()
  if (o.includes('windows')) return '🏴'
  if (o.includes('linux') || o.includes('ubuntu') || o.includes('centos') || o.includes('rhel')) return '🐧'
  if (o.includes('mac') || o.includes('darwin')) return '🍎'
  return '🖥'
}

interface AssetStats {
  total: number
  critical_risk: number
  total_endpoints: number
  active_users: number    // API field (was active_用户)
  cloud_assets: number
  critical_vulns?: number
}

type AssetTab = 'all' | 'endpoint' | 'user' | 'cloud' | 'network' | 'vuln'
type DetailTab = 'info' | 'vulns' | 'topology' | 'trend'

const BLANK_FORM = { name: '', hostname: '', type: 'workstation', status: 'online', ip_addresses: '', os_info: { name: '', version: '', arch: '' }, department: '', owner: '' }

// --- CSV export utility ---
function exportCSV(items: Asset[], filename: string) {
  const headers: (keyof Asset)[] = ['_key', 'hostname', 'ip', 'os', 'type', 'status', 'risk_score', 'department', 'owner', 'last_seen']
  const rows = items.map(a => headers.map(h => JSON.stringify(a[h] ?? '')).join(','))
  const csv = [headers.join(','), ...rows].join('\n')
  const blob = new Blob(['﻿' + csv], { type: 'text/csv' })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url; link.download = filename; link.click()
  URL.revokeObjectURL(url)
}

function exportAssetsWithDate(items: Asset[]) {
  exportCSV(items, `assets_export_${new Date().toISOString().slice(0, 10)}.csv`)
}

type SortOrder = 'asc' | 'desc' | null

// --- Risk color utility ---
function riskColor(score: number): string {
  if (score >= 80) return '#ef5350'
  if (score >= 60) return '#ffa726'
  if (score >= 40) return '#f9a825'
  return '#66bb6a'
}

// --- Deterministic mock history from asset key ---
function mockRiskHistory(key: string): number[] {
  const seed = key.split('').reduce((acc, c) => acc + c.charCodeAt(0), 0)
  return Array.from({ length: 7 }, (_, i) => {
    const v = ((seed * (i + 3) * 7919) % 60) + 20
    return Math.min(100, Math.max(0, v))
  })
}

function last7DayLabels(): string[] {
  const labels: string[] = []
  for (let i = 6; i >= 0; i--) {
    const d = new Date()
    d.setDate(d.getDate() - i)
    labels.push(`${d.getMonth() + 1}/${d.getDate()}`)
  }
  return labels
}

// --- Risk Score Timeline SVG ---
function RiskTrendChart({ asset }: { asset: Asset }) {
  const [tooltip, setTooltip] = useState<{ x: number; y: number; date: string; score: number } | null>(null)
  const scores = mockRiskHistory(asset._key)
  const labels = last7DayLabels()
  const W = 300, H = 120, padL = 30, padR = 10, padT = 10, padB = 24
  const innerW = W - padL - padR
  const innerH = H - padT - padB
  const maxScore = Math.max(...scores)
  const minScore = Math.min(...scores)

  const toX = (i: number) => padL + (i / 6) * innerW
  const toY = (v: number) => padT + innerH - (v / 100) * innerH

  const pathD = scores.map((s, i) => `${i === 0 ? 'M' : 'L'} ${toX(i).toFixed(1)} ${toY(s).toFixed(1)}`).join(' ')
  const areaD = pathD + ` L ${toX(6).toFixed(1)} ${(padT + innerH).toFixed(1)} L ${toX(0).toFixed(1)} ${(padT + innerH).toFixed(1)} Z`

  const lineCol = riskColor(asset.risk_score ?? 0)
  const areaCol = lineCol + '33'

  return (
    <div style={{ position: 'relative' }}>
      <svg width={W} height={H} style={{ overflow: 'visible', display: 'block', margin: '0 auto' }}>
        {/* Y-axis grid lines */}
        {[0, 25, 50, 75, 100].map(v => (
          <g key={v}>
            <line x1={padL} y1={toY(v)} x2={W - padR} y2={toY(v)}
              stroke="rgba(255,255,255,.06)" strokeWidth={1} />
            <text x={padL - 4} y={toY(v) + 4} textAnchor="end"
              fontSize={8} fill="rgba(255,255,255,.3)">{v}</text>
          </g>
        ))}
        {/* Area fill */}
        <path d={areaD} fill={areaCol} />
        {/* Line */}
        <path d={pathD} fill="none" stroke={lineCol} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
        {/* Dots + hover targets */}
        {scores.map((s, i) => (
          <circle
            key={i}
            cx={toX(i)} cy={toY(s)} r={4}
            fill={lineCol} stroke="var(--bg-card)" strokeWidth={1.5}
            style={{ cursor: 'pointer' }}
            onMouseEnter={() => setTooltip({ x: toX(i), y: toY(s), date: labels[i], score: s })}
            onMouseLeave={() => setTooltip(null)}
          />
        ))}
        {/* X-axis labels */}
        {labels.map((l, i) => (
          <text key={i} x={toX(i)} y={H - 4} textAnchor="middle"
            fontSize={8.5} fill="rgba(255,255,255,.35)">{l}</text>
        ))}
        {/* Tooltip */}
        {tooltip && (
          <g>
            <rect
              x={tooltip.x - 28} y={tooltip.y - 28} width={56} height={20}
              rx={4} fill="var(--bg-card)" stroke="var(--border)" strokeWidth={1}
            />
            <text x={tooltip.x} y={tooltip.y - 14} textAnchor="middle"
              fontSize={9} fill="var(--text-primary)" fontWeight={600}>
              {tooltip.date} · {tooltip.score}
            </text>
          </g>
        )}
      </svg>
      <div style={{ display: 'flex', gap: 16, justifyContent: 'center', marginTop: 8, fontSize: 11 }}>
        <span style={{ color: '#ef5350' }}>最高风险: <strong>{maxScore}</strong></span>
        <span style={{ color: '#66bb6a' }}>最低风险: <strong>{minScore}</strong></span>
      </div>
    </div>
  )
}

// --- Network Topology Mini-Map ---
type NodeType = 'center' | 'server' | 'endpoint' | 'network' | 'mobile' | 'unknown'

interface TopoNode {
  asset: Asset
  nodeType: NodeType
  x: number
  y: number
  zone: ZoneName | null
}

type ZoneName = 'DMZ' | '内网' | '管理网' | '其他'

interface ZoneInfo {
  name: ZoneName
  prefix: string
  label: string
  fillColor: string
  borderColor: string
}

const ZONES: ZoneInfo[] = [
  { name: 'DMZ',  prefix: '10.0.1',  label: 'DMZ (10.0.1.x)',  fillColor: 'rgba(255,111,0,.07)',  borderColor: 'rgba(255,111,0,.35)' },
  { name: '内网',  prefix: '192.168', label: '内网 (192.168.x.x)', fillColor: 'rgba(59,130,246,.07)', borderColor: 'rgba(59,130,246,.35)' },
  { name: '管理网', prefix: '10.0.0',  label: '管理网 (10.0.0.x)', fillColor: 'rgba(38,166,154,.07)', borderColor: 'rgba(38,166,154,.35)' },
]

// Maps segment filter name → zone prefix used in IP matching
const SEGMENT_PREFIXES: Record<string, string> = {
  'DMZ':  '10.0.1',
  '内网':  '192.168',
  '管理网': '10.0.0',
}

function getZone(ip: string): ZoneName | null {
  if (!ip) return null
  // Check DMZ and 管理网 before 内网 so 10.0.x is not caught by a shorter prefix
  for (const z of ZONES) {
    if (ip.startsWith(z.prefix + '.')) return z.name
  }
  return null
}

/** Client-side IP subnet filter — returns true when asset matches the chosen segment */
function matchesSegment(ip: string, seg: NetSegment): boolean {
  if (seg === '全部') return true
  const prefix = SEGMENT_PREFIXES[seg]
  if (!prefix) return true
  return ip ? ip.startsWith(prefix + '.') : false
}

function getNodeType(a: Asset): NodeType {
  const t = (a.type || '').toLowerCase()
  if (t.includes('server')) return 'server'
  if (t.includes('network') || t.includes('router') || t.includes('switch')) return 'network'
  if (t.includes('mobile') || t.includes('phone')) return 'mobile'
  if (t.includes('workstation') || t.includes('endpoint') || t.includes('laptop')) return 'endpoint'
  return 'unknown'
}

// Type icons as SVG text glyphs
function NodeShape({ nodeType, cx, cy, r, fill, stroke, strokeWidth }: {
  nodeType: NodeType | 'center'; cx: number; cy: number; r: number
  fill: string; stroke: string; strokeWidth?: number
}) {
  const sw = strokeWidth ?? (nodeType === 'center' ? 2.5 : 1.5)
  if (nodeType === 'server') {
    return <rect x={cx - r} y={cy - r * 0.75} width={r * 2} height={r * 1.5} rx={3}
      fill={fill} stroke={stroke} strokeWidth={sw} />
  }
  if (nodeType === 'network') {
    const pts = [[cx, cy - r], [cx + r, cy], [cx, cy + r], [cx - r, cy]]
      .map(p => p.join(',')).join(' ')
    return <polygon points={pts} fill={fill} stroke={stroke} strokeWidth={sw} />
  }
  if (nodeType === 'mobile') {
    return <rect x={cx - r * 0.65} y={cy - r} width={r * 1.3} height={r * 2} rx={4}
      fill={fill} stroke={stroke} strokeWidth={sw} />
  }
  return <circle cx={cx} cy={cy} r={r} fill={fill} stroke={stroke} strokeWidth={sw} />
}

interface TopoTooltip { x: number; y: number; ip: string; os: string; hostname: string }

function TopologyMap({ center, neighbors, onSelect }: { center: Asset; neighbors: Asset[]; onSelect: (a: Asset) => void }) {
  const W = 320, H = 260
  const CX = W / 2, CY = (H - 30) / 2 + 10  // shift down a bit for zone labels
  const ORBIT = 90

  const allAssets = [center, ...neighbors.slice(0, 5)]

  // Group assets by zone to compute zone bounding boxes
  const zoneGroups: Record<ZoneName, TopoNode[]> = { DMZ: [], '内网': [], '管理网': [], '其他': [] }

  const nodes: TopoNode[] = allAssets.map((a, i) => {
    if (i === 0) return { asset: a, nodeType: 'center' as NodeType, x: CX, y: CY, zone: getZone(a.ip) }
    const angle = ((i - 1) / Math.min(neighbors.length, 5)) * Math.PI * 2 - Math.PI / 2
    const node: TopoNode = {
      asset: a,
      nodeType: getNodeType(a),
      x: CX + Math.cos(angle) * ORBIT,
      y: CY + Math.sin(angle) * ORBIT,
      zone: getZone(a.ip),
    }
    return node
  })

  // Populate zone groups
  nodes.forEach(n => {
    const z = n.zone ?? '其他'
    if (z in zoneGroups) zoneGroups[z].push(n)
  })

  const [hovered, setHovered] = useState<string | null>(null)
  const [tooltip, setTooltip] = useState<TopoTooltip | null>(null)

  // Compute zone background rects
  const zoneRects = ZONES.map(z => {
    const members = zoneGroups[z.name]
    if (members.length === 0) return null
    const PAD = 18
    const xs = members.map(n => n.x)
    const ys = members.map(n => n.y)
    const x1 = Math.min(...xs) - PAD
    const y1 = Math.min(...ys) - PAD
    const x2 = Math.max(...xs) + PAD
    const y2 = Math.max(...ys) + PAD
    return { ...z, x: x1, y: y1, width: x2 - x1, height: y2 - y1 }
  }).filter(Boolean) as (ZoneInfo & { x: number; y: number; width: number; height: number })[]

  return (
    <div style={{ position: 'relative' }}>
      <svg width={W} height={H} style={{ display: 'block', margin: '0 auto', overflow: 'visible' }}>
        <defs>
          <filter id="topo-glow" x="-50%" y="-50%" width="200%" height="200%">
            <feGaussianBlur stdDeviation="2" result="blur" />
            <feMerge><feMergeNode in="blur" /><feMergeNode in="SourceGraphic" /></feMerge>
          </filter>
        </defs>

        {/* Zone background rectangles */}
        {zoneRects.map(z => (
          <g key={z.name}>
            <rect x={z.x} y={z.y} width={z.width} height={z.height} rx={8}
              fill={z.fillColor} stroke={z.borderColor} strokeWidth={1} strokeDasharray="4 3" />
            <text x={z.x + 6} y={z.y + 13} fontSize={8.5} fill={z.borderColor} fontWeight={600}
              style={{ pointerEvents: 'none' }}>
              {z.label}
            </text>
          </g>
        ))}

        {/* Orbit ring hint */}
        <circle cx={CX} cy={CY} r={ORBIT} fill="none"
          stroke="rgba(255,255,255,.04)" strokeWidth={1} strokeDasharray="4 4" />

        {/* Edges */}
        {nodes.slice(1).map(n => (
          <line key={n.asset._key}
            x1={CX} y1={CY} x2={n.x} y2={n.y}
            stroke="rgba(255,255,255,.10)" strokeWidth={1.2} />
        ))}

        {/* Nodes */}
        {nodes.map((n, idx) => {
          const isCenter = idx === 0
          const score = n.asset.risk_score ?? 0
          const nodeFill = isCenter ? 'rgba(59,130,246,.22)' : riskColor(score) + '28'
          const nodeStroke = isCenter ? '#3b82f6' : riskColor(score)
          const r = isCenter ? 19 : 14
          const isHov = hovered === n.asset._key
          return (
            <g key={n.asset._key}
              style={{ cursor: isCenter ? 'default' : 'pointer' }}
              onMouseEnter={_e => {
                setHovered(n.asset._key)
                setTooltip({ x: n.x, y: n.y, ip: n.asset.ip || '-', os: n.asset.os || '-', hostname: n.asset.hostname || n.asset._key })
              }}
              onMouseLeave={() => { setHovered(null); setTooltip(null) }}
              onClick={() => !isCenter && onSelect(n.asset)}
            >
              {/* Glow ring on hover */}
              {isHov && !isCenter && (
                <circle cx={n.x} cy={n.y} r={r + 5}
                  fill="none" stroke={nodeStroke} strokeWidth={1} opacity={0.4}
                  filter="url(#topo-glow)" />
              )}
              <NodeShape nodeType={n.nodeType} cx={n.x} cy={n.y} r={r}
                fill={isHov ? nodeStroke + '44' : nodeFill}
                stroke={nodeStroke}
                strokeWidth={isCenter ? 2.5 : isHov ? 2 : 1.5} />
              {/* Risk score label */}
              <text x={n.x} y={n.y + 3.5} textAnchor="middle"
                fontSize={isCenter ? 9 : 8} fill={isCenter ? '#93c5fd' : nodeStroke}
                fontWeight={600} style={{ pointerEvents: 'none' }}>
                {score}
              </text>
              {/* Hostname below node */}
              <text x={n.x} y={n.y + r + 13} textAnchor="middle"
                fontSize={8.5} fill={isHov ? 'var(--text-primary)' : 'rgba(255,255,255,.45)'}
                style={{ pointerEvents: 'none' }}>
                {(n.asset.hostname || n.asset._key).slice(0, 11)}
              </text>
            </g>
          )
        })}

        {/* IP/OS Tooltip */}
        {tooltip && (() => {
          const TW = 130, TH = 36
          const tx = Math.min(tooltip.x - TW / 2, W - TW - 4)
          const ty = tooltip.y - TH - 20
          return (
            <g style={{ pointerEvents: 'none' }}>
              <rect x={tx} y={ty} width={TW} height={TH} rx={5}
                fill="var(--bg-card)" stroke="var(--border)" strokeWidth={1} opacity={0.97} />
              <text x={tx + 7} y={ty + 13} fontSize={9} fill="var(--accent-blue)" fontWeight={600}>
                {tooltip.hostname}
              </text>
              <text x={tx + 7} y={ty + 25} fontSize={8.5} fill="rgba(255,255,255,.5)">
                {tooltip.ip} · {tooltip.os.slice(0, 14)}
              </text>
            </g>
          )
        })()}

        {/* Legend — bottom-left */}
        <g transform={`translate(4, ${H - 62})`}>
          <rect width={148} height={58} rx={5} fill="rgba(0,0,0,.45)" stroke="rgba(255,255,255,.08)" strokeWidth={1} />
          {/* Risk level legend */}
          <text x={6} y={12} fontSize={7.5} fill="rgba(255,255,255,.4)" fontWeight={600}>风险等级</text>
          {[
            { label: 'Critical', color: '#ef5350' },
            { label: 'High',     color: '#ffa726' },
            { label: 'Medium',   color: '#f9a825' },
            { label: 'Low',      color: '#66bb6a' },
          ].map((b, i) => (
            <g key={b.label} transform={`translate(${6 + i * 34}, 17)`}>
              <rect width={8} height={8} rx={2} fill={b.color} />
              <text x={10} y={8} fontSize={7} fill={b.color}>{b.label.slice(0, 3)}</text>
            </g>
          ))}
          {/* Zone legend */}
          <text x={6} y={38} fontSize={7.5} fill="rgba(255,255,255,.4)" fontWeight={600}>网络区域</text>
          {[
            { label: 'DMZ',  color: 'rgba(255,111,0,.7)' },
            { label: '内网',  color: 'rgba(59,130,246,.7)' },
            { label: '管理网', color: 'rgba(38,166,154,.7)' },
          ].map((b, i) => (
            <g key={b.label} transform={`translate(${6 + i * 46}, 43)`}>
              <rect width={8} height={8} rx={2} fill={b.color} />
              <text x={10} y={8} fontSize={7} fill={b.color}>{b.label}</text>
            </g>
          ))}
        </g>
      </svg>
    </div>
  )
}

// --- CVE count badge (per-row, lazy via useEffect) ---
function CveBadge({ assetKey }: { assetKey: string }) {
  const [count, setCount] = useState<number | null>(null)
  const ref = useRef<HTMLSpanElement>(null)
  const loaded = useRef(false)

  useEffect(() => {
    if (loaded.current) return
    loaded.current = true
    api.get('/vulnerabilities', { params: { asset_id: assetKey, page_size: 1 } })
      .then(r => {
        const total = r.data.data?.meta?.total ?? 0
        setCount(total)
      })
      .catch(() => setCount(0))
  }, [assetKey])

  const n = count ?? 0
  const bg = count === null ? 'rgba(255,255,255,.06)'
    : n > 5 ? 'rgba(229,57,53,.18)'
      : n > 0 ? 'rgba(255,111,0,.18)'
        : 'rgba(255,255,255,.06)'
  const color = count === null ? 'var(--text-muted)'
    : n > 5 ? '#ef5350'
      : n > 0 ? '#ffa726'
        : 'var(--text-muted)'

  return (
    <span ref={ref} style={{
      display: 'inline-block', padding: '1px 7px', borderRadius: 10,
      fontSize: 10, fontWeight: 600, background: bg, color,
      border: '1px solid rgba(255,255,255,.06)', whiteSpace: 'nowrap',
    }}>
      {count === null ? 'CVE…' : `CVE: ${n}`}
    </span>
  )
}

// Network segment filter (IP-based)
const NET_SEGMENTS = ['全部', 'DMZ', '内网', '管理网'] as const
type NetSegment = typeof NET_SEGMENTS[number]

export default function Assets() {
  const [items, setItems] = useState<Asset[]>([])
  const [meta, setMeta] = useState<PageMeta>({ page: 1, page_size: 20, total: 0, total_pages: 1 })
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [assetTab, setAssetTab] = useState<AssetTab>('all')
  const [typeFilter, set类型Filter] = useState('')
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<Asset | null>(null)
  const [kpi, setKpi] = useState<AssetStats | null>(null)

  // Create / Edit modal
  const [showModal, setShowModal] = useState(false)
  const [editTarget, setEditTarget] = useState<Asset | null>(null)
  const [form, setForm] = useState(BLANK_FORM)
  const [saving, setSaving] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [statusFilter, set状态Filter] = useState('')
  const [tagFilter, setTagFilter] = useState('')
  const mountedRef = useRef(false)

  // Network segment filter (IP-based client-side)
  const [netSegment, setNetSegment] = useState<NetSegment>('全部')

  // Bulk selection state
  const [checkedKeys, setCheckedKeys] = useState<Set<string>>(new Set())

  // Bulk tag modal state
  const [showTagModal, setShowTagModal] = useState(false)
  const [bulkTagInput, setBulkTagInput] = useState('')
  const [bulkTagging, setBulkTagging] = useState(false)

  // Sort state
  const [riskSort, setRiskSort] = useState<SortOrder>(null)

  function load(p = page) {
    setLoading(true)
    const params: any = { page: p, page_size: 20 }
    const t = assetTab !== 'all' && assetTab !== 'vuln' ? assetTab : typeFilter
    if (t) params.type = t
    if (search) params.keyword = search
    if (statusFilter) params.status = statusFilter
    if (tagFilter) params.tag = tagFilter
    if (riskSort) { params.sort = 'risk_score'; params.order = riskSort }
    api.get('/assets', { params })
      .then(r => { setItems(r.data.data?.items ?? []); setMeta(r.data.data?.meta ?? meta) })
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    api.get('/assets/stats').then(r => setKpi(r.data.data)).catch(() => {})
  }, [])

  // Vulnerability panel state
  const [detailTab, setDetailTab] = useState<DetailTab>('info')
  const [vulns, setVulns] = useState<Vulnerability[]>([])
  const [vulnsLoading, setVulnsLoading] = useState(false)

  // Topology neighbor state
  const [topoNeighbors, setTopoNeighbors] = useState<Asset[]>([])
  const [topoLoading, setTopoLoading] = useState(false)

  useEffect(() => { load(page) }, [page])
  useEffect(() => {
    if (!mountedRef.current) { mountedRef.current = true; return }
    setPage(1); load(1)
  }, [typeFilter, assetTab, statusFilter, tagFilter, riskSort])

  useEffect(() => {
    if (!selected) return
    setDetailTab('info')
    setVulns([])
    setTopoNeighbors([])
  }, [selected?._key])

  // Clear selection when items change (page/filter change)
  useEffect(() => {
    setCheckedKeys(new Set())
  }, [items])

  function openCreate() {
    setEditTarget(null)
    setForm(BLANK_FORM)
    setShowModal(true)
  }

  function openEdit(a: Asset) {
    setEditTarget(a)
    setForm({
      name: a.name || a.hostname || '',
      hostname: a.hostname || '',
      type: a.type || 'workstation',
      status: a.status || 'online',
      ip_addresses: a.ip || '',
      os_info: { name: a.os || '', version: a.os_version || '', arch: '' },
      department: a.department || '',
      owner: a.owner || '',
    })
    setShowModal(true)
  }

  function saveAsset() {
    if (!form.hostname.trim()) return
    setSaving(true)
    const body = {
      name: form.name || form.hostname,
      hostname: form.hostname,
      type: form.type,
      status: form.status,
      ip_addresses: form.ip_addresses ? [form.ip_addresses] : [],
      os_info: form.os_info,
      department: form.department,
      owner: form.owner,
    }
    const req = editTarget
      ? api.patch(`/assets/${editTarget._key}`, body)
      : api.post('/assets', body)
    req.then(() => { setShowModal(false); load(1) }).finally(() => setSaving(false))
  }

  const [deleteTarget, setDeleteTarget] = useState<Asset | null>(null)

  function confirmDelete(a: Asset) { setDeleteTarget(a) }
  function doDelete() {
    if (!deleteTarget) return
    setDeleting(true)
    api.delete(`/assets/${deleteTarget._key}`).then(() => { setSelected(null); setDeleteTarget(null); load(1) }).finally(() => setDeleting(false))
  }

  function loadVulns(assetKey: string) {
    setVulnsLoading(true)
    api.get('/vulnerabilities', { params: { asset_id: assetKey, page: 1, page_size: 10 } })
      .then(r => setVulns(r.data.data?.items ?? []))
      .catch(() => setVulns([]))
      .finally(() => setVulnsLoading(false))
  }

  function loadTopoNeighbors() {
    setTopoLoading(true)
    api.get('/assets', { params: { page: 1, page_size: 10 } })
      .then(r => {
        const all: Asset[] = r.data.data?.items ?? []
        // Exclude the selected asset itself, take up to 5
        setTopoNeighbors(all.filter(a => a._key !== selected?._key).slice(0, 5))
      })
      .catch(() => setTopoNeighbors([]))
      .finally(() => setTopoLoading(false))
  }

  const checkedItems = items.filter(a => checkedKeys.has(a._key))

  // Client-side subnet filtering
  const visibleItems = netSegment === '全部'
    ? items
    : items.filter(a => matchesSegment(a.ip || '', netSegment))

  // Checkbox helpers — operate on visibleItems
  const allChecked = visibleItems.length > 0 && visibleItems.every(a => checkedKeys.has(a._key))
  const someChecked = visibleItems.some(a => checkedKeys.has(a._key)) && !allChecked

  function toggleAll() {
    if (allChecked) {
      setCheckedKeys(new Set())
    } else {
      setCheckedKeys(new Set(visibleItems.map(a => a._key)))
    }
  }

  function toggleRow(key: string) {
    setCheckedKeys(prev => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key); else next.add(key)
      return next
    })
  }

  // Bulk tag apply
  function applyBulkTag() {
    const tag = bulkTagInput.trim()
    if (!tag || checkedItems.length === 0) return
    setBulkTagging(true)
    const requests = checkedItems.map(a =>
      api.patch(`/assets/${a._key}`, { tags: [...(a.tags ?? []), tag] })
    )
    Promise.all(requests)
      .then(() => { setShowTagModal(false); setBulkTagInput(''); load(page) })
      .finally(() => setBulkTagging(false))
  }

  // Toggle risk score sort
  function toggleRiskSort() {
    setRiskSort(prev => prev === null ? 'desc' : prev === 'desc' ? 'asc' : null)
  }

  const statusColor: Record<string, string> = {
    online: 'var(--accent-green)',
    offline: 'var(--text-muted)',
    isolated: 'var(--critical)',
    uninstalled: 'var(--text-muted)',
  }

  // Detail tab definitions
  const detailTabs: [DetailTab, string][] = [
    ['info', '概览'],
    ['vulns', '漏洞'],
    ['topology', '拓扑图'],
    ['trend', '风险趋势'],
  ]

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <PageHeader
        title="资产管理"
        subtitle={`统一资产清单 · ${(kpi?.total_endpoints ?? 0).toLocaleString()} 终端 · ${(kpi?.active_users ?? 0).toLocaleString()} 用户 · ${(kpi?.cloud_assets ?? 0).toLocaleString()} 云资产`}
        actions={<>
          <button className="btn-secondary" onClick={() => exportAssetsWithDate(visibleItems)}>&#8659; 导出 CSV</button>
          <button className="btn-primary" onClick={openCreate}>+ 添加资产</button>
        </>}
      />

      {/* KPI bar */}
      <div className="kpi-row" style={{ gridTemplateColumns: 'repeat(5,1fr)' }}>
        {[
          { label: '高危资产', value: kpi?.critical_risk ?? 0, color: 'var(--critical)', note: '需立即处置' },
          { label: '终端总数', value: (kpi?.total_endpoints ?? 0).toLocaleString(), note: `${Math.round(((kpi?.total_endpoints ?? 0) / Math.max(kpi?.total ?? 1, 1)) * 100)}% Agent 覆盖` },
          { label: '活跃用户', value: (kpi?.active_users ?? 0).toLocaleString(), note: '已身份关联' },
          { label: '云资产', value: (kpi?.cloud_assets ?? 0).toLocaleString(), note: 'AWS / Azure / GCP' },
          { label: '资产总数', value: (kpi?.total ?? 0).toLocaleString(), note: '全部受管资产' },
        ].map(k => (
          <div key={k.label} className="kpi-card-flat">
            <div className="kpi-label">{k.label}</div>
            <div className="kpi-value" style={{ color: k.color ?? 'var(--text-primary)' }}>{k.value}</div>
            <div className="kpi-note">{k.note}</div>
          </div>
        ))}
      </div>

      {/* Risk distribution badges */}
      {visibleItems.length > 0 && (() => {
        const critical = visibleItems.filter(a => (a.risk_score ?? 0) >= 80).length
        const high = visibleItems.filter(a => (a.risk_score ?? 0) >= 60 && (a.risk_score ?? 0) < 80).length
        const medium = visibleItems.filter(a => (a.risk_score ?? 0) >= 30 && (a.risk_score ?? 0) < 60).length
        const low = visibleItems.filter(a => (a.risk_score ?? 0) < 30).length
        return (
          <div style={{ display: 'flex', gap: 8, padding: '6px 20px', alignItems: 'center', fontSize: 11.5 }}>
            <span style={{ color: 'var(--text-muted)', marginRight: 4 }}>风险分布:</span>
            {[
              { label: 'Critical', count: critical, bg: 'rgba(229,57,53,.15)', color: '#ef5350' },
              { label: 'High',     count: high,     bg: 'rgba(255,111,0,.15)', color: '#ffa726' },
              { label: 'Medium',   count: medium,   bg: 'rgba(249,168,37,.15)', color: '#f9a825' },
              { label: 'Low',      count: low,      bg: 'rgba(67,160,71,.15)',  color: '#66bb6a' },
            ].map(b => (
              <span key={b.label} style={{
                display: 'inline-flex', alignItems: 'center', gap: 4,
                padding: '2px 10px', borderRadius: 12,
                background: b.bg, color: b.color, fontWeight: 600,
              }}>
                {b.label} <span style={{ fontWeight: 400, opacity: 0.85 }}>{b.count}</span>
              </span>
            ))}
          </div>
        )
      })()}

      {/* Asset sub-tabs */}
      <div className="tab-bar">
        {([
          ['all', '全部资产', null],
          ['endpoint', '终端', kpi?.total_endpoints],
          ['user', '用户', kpi?.active_users],
          ['cloud', '云资产', kpi?.cloud_assets],
          ['network', '网络设备', null],
          ['vuln', '漏洞视图', null],
        ] as [AssetTab, string, number | null | undefined][]).map(([val, label, count]) => (
          <button key={val} className={`tab ${assetTab === val ? 'active' : ''}`} onClick={() => setAssetTab(val)}>
            {label}
            {count != null && <span className="tab-count">{count.toLocaleString()}</span>}
          </button>
        ))}
      </div>

      {/* Network segment filter chips (client-side IP-based) */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '6px 20px', flexShrink: 0, borderBottom: '1px solid var(--border)' }}>
        <span style={{ fontSize: 11.5, color: 'var(--text-muted)', marginRight: 4 }}>网络段:</span>
        {NET_SEGMENTS.map(seg => {
          const accentColor = seg === 'DMZ' ? 'rgba(255,111,0,.8)'
            : seg === '内网' ? 'rgba(59,130,246,.8)'
            : seg === '管理网' ? 'rgba(38,166,154,.8)'
            : 'var(--accent-blue)'
          const isActive = netSegment === seg
          return (
            <button
              key={seg}
              onClick={() => setNetSegment(seg)}
              style={{
                padding: '2px 12px', borderRadius: 12, fontSize: 11.5, cursor: 'pointer',
                border: isActive ? `1px solid ${accentColor}` : '1px solid var(--border)',
                background: isActive ? `${accentColor.replace('.8)', '.12)')}` : 'var(--bg-secondary)',
                color: isActive ? accentColor : 'var(--text-muted)',
                fontWeight: isActive ? 600 : 400,
                transition: 'all .15s',
              }}
            >
              {seg}
            </button>
          )
        })}
        {netSegment !== '全部' && (
          <span style={{ fontSize: 10.5, color: 'var(--text-muted)', marginLeft: 4 }}>
            {visibleItems.length} / {items.length} 条
          </span>
        )}
      </div>

      <div className="filter-bar">
        <input
          className="filter-input"
          placeholder="搜索主机名、IP、部门..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && load(1)}
        />
        <select className="filter-select" value={typeFilter} onChange={e => set类型Filter(e.target.value)}>
          <option value="">全部类型</option>
          <option value="workstation">Workstation</option>
          <option value="server">Server</option>
          <option value="network">Network Device</option>
          <option value="cloud">Cloud Instance</option>
          <option value="iot">IoT</option>
        </select>
        <select className="filter-select" value={statusFilter} onChange={e => set状态Filter(e.target.value)}>
          <option value="">全部状态</option>
          <option value="online">Online</option>
          <option value="offline">Offline</option>
          <option value="isolated">Isolated</option>
        </select>
        <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
          <input
            className="filter-input"
            placeholder="标签过滤"
            value={tagFilter}
            style={{ paddingRight: tagFilter ? 24 : undefined }}
            onChange={e => setTagFilter(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && load(1)}
          />
          {tagFilter && (
            <button
              onClick={() => setTagFilter('')}
              style={{
                position: 'absolute', right: 6, background: 'none', border: 'none',
                cursor: 'pointer', color: 'var(--text-muted)', fontSize: 13, lineHeight: 1, padding: 0,
              }}
            >&#x2715;</button>
          )}
        </div>
      </div>

      {/* Bulk action bar */}
      {checkedKeys.size > 0 && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 10, padding: '6px 20px',
          background: 'rgba(59,130,246,.08)', borderBottom: '1px solid var(--border)',
          flexShrink: 0,
        }}>
          <span style={{ fontSize: 12.5, color: 'var(--accent-blue)', fontWeight: 600 }}>
            已选 {checkedKeys.size} 条
          </span>
          <button
            className="btn-secondary"
            style={{ fontSize: 12, padding: '3px 12px' }}
            onClick={() => { setBulkTagInput(''); setShowTagModal(true) }}
          >
            批量标签
          </button>
          <button
            className="btn-secondary"
            style={{ fontSize: 12, padding: '3px 12px' }}
            onClick={() => exportCSV(checkedItems, 'assets-selected.csv')}
          >
            导出 CSV
          </button>
          <button
            style={{
              marginLeft: 'auto', background: 'none', border: 'none', cursor: 'pointer',
              color: 'var(--text-muted)', fontSize: 13, padding: '2px 4px',
            }}
            onClick={() => setCheckedKeys(new Set())}
          >&#x2715; 取消</button>
        </div>
      )}

      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        {assetTab === 'vuln' ? (
          <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>
            <div style={{ display: 'grid', gridTemplateColumns: '300px 1fr', gap: 16 }}>
              <div className="card">
                <div className="card-title">CVE 严重程度分布</div>
                {[
                  { label: 'Critical', color: '#e53935', pct: 12, count: kpi?.critical_vulns ?? 0 },
                  { label: 'High', color: '#ff6f00', pct: 25, count: null },
                  { label: 'Medium', color: '#f9a825', pct: 56, count: null },
                  { label: 'Low', color: '#00897b', pct: 16, count: null },
                ].map(s => (
                  <div key={s.label} style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                    <span style={{ width: 60, fontSize: 11, color: s.color }}>{s.label}</span>
                    <div style={{ flex: 1, height: 16, background: 'var(--bg-secondary)', borderRadius: 3, overflow: 'hidden' }}>
                      <div style={{ width: `${s.pct}%`, height: '100%', background: s.color, borderRadius: 3 }} />
                    </div>
                    <span style={{ fontSize: 11, color: s.color, fontWeight: 700, minWidth: 30 }}>
                      {s.count != null ? s.count : '-'}
                    </span>
                  </div>
                ))}
              </div>
              <div className="card">
                <div className="card-title">Top 个严重CVE</div>
                <div className="data-table-wrap" style={{ margin: -16, marginTop: 0 }}>
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>CVE</th><th>CVSS</th><th>描述</th><th>Affected</th><th>状态</th>
                      </tr>
                    </thead>
                    <tbody>
                      {loading && <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 16 }}>加载中...</td></tr>}
                      {!loading && <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 16 }}>暂无数据</td></tr>}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="data-table-wrap" style={{ flex: 1 }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ width: 36, padding: '0 8px' }}>
                    <input
                      type="checkbox"
                      checked={allChecked}
                      ref={el => { if (el) el.indeterminate = someChecked }}
                      onChange={toggleAll}
                      style={{ cursor: 'pointer' }}
                    />
                  </th>
                  <th>资产</th>
                  <th>IP / 平台</th>
                  <th>类型</th>
                  <th>漏洞</th>
                  <th>资产评分</th>
                  <th
                    onClick={toggleRiskSort}
                    style={{ cursor: 'pointer', userSelect: 'none', whiteSpace: 'nowrap' }}
                  >
                    风险
                    {riskSort === 'desc' && ' ▼'}
                    {riskSort === 'asc' && ' ▲'}
                    {riskSort === null && ' ⇅'}
                  </th>
                  <th>未关闭事件</th>
                  <th>Agent状态</th>
                  <th>部门/负责人</th>
                  <th>最近活跃</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {loading && <tr><td colSpan={12} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>加载中...</td></tr>}
                {!loading && visibleItems.length === 0 && <tr><td colSpan={12} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>暂无资产</td></tr>}
                {visibleItems.map(a => (
                  <tr key={a._key}
                    onClick={() => setSelected(selected?._key === a._key ? null : a)}
                    className={[selected?._key === a._key ? 'selected' : '', (a.risk_score ?? 0) >= 80 ? 'row-critical' : ''].join(' ').trim()}
                  >
                    <td style={{ width: 36, padding: '0 8px' }} onClick={e => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        checked={checkedKeys.has(a._key)}
                        onChange={() => toggleRow(a._key)}
                        style={{ cursor: 'pointer' }}
                      />
                    </td>
                    <td>
                      <div style={{ fontFamily: 'monospace', fontSize: 12.5, fontWeight: 500, color: 'var(--accent-blue)' }}>{a.hostname || '-'}</div>
                      {a.owner && <div style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>{a.owner}</div>}
                    </td>
                    <td>
                      <div style={{ fontFamily: 'monospace', fontSize: 11.5 }}>{a.ip || '-'}</div>
                      <div style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>{osIcon(a.os)} {a.os || '-'}</div>
                    </td>
                    <td>
                      <span style={{ fontSize: 10.5, padding: '2px 8px', background: 'var(--bg-card2)', border: '1px solid var(--border-light)', borderRadius: 3, textTransform: 'capitalize' }}>
                        {a.type || 'endpoint'}
                      </span>
                    </td>
                    <td onClick={e => e.stopPropagation()}>
                      <CveBadge assetKey={a.hostname || a._key} />
                    </td>
                    <td><AssetScoreBadge score={a.risk_score ?? 0} /></td>
                    <td>
                      <span className={`sev-badge ${(a.risk_score ?? 0) >= 80 ? 'critical' : (a.risk_score ?? 0) >= 60 ? 'high' : (a.risk_score ?? 0) >= 30 ? 'medium' : 'low'}`}>
                        {(a.risk_score ?? 0) >= 80 ? 'Critical' : (a.risk_score ?? 0) >= 60 ? 'High' : (a.risk_score ?? 0) >= 30 ? 'Medium' : 'Low'}
                      </span>
                    </td>
                    <td style={{ fontSize: 12 }}>
                      {(a.active_incident_count ?? 0) > 0
                        ? <span style={{ color: 'var(--critical)', fontWeight: 600 }}>{a.active_incident_count} active</span>
                        : <span style={{ color: 'var(--text-muted)' }}>-</span>}
                    </td>
                    <td>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11.5 }}>
                        <span style={{
                          width: 6, height: 6, borderRadius: '50%', display: 'inline-block',
                          background: statusColor[a.status] ?? 'var(--text-muted)',
                          boxShadow: a.status === 'online' ? `0 0 4px ${statusColor.online}` : 'none',
                        }} />
                        {a.status === 'isolated' ? <span style={{ color: 'var(--high)' }}>⚠ Isolated</span> : (a.status || 'unknown')}
                      </span>
                    </td>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{a.department || '-'}</td>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{fmtDate(a.last_seen)}</td>
                    <td onClick={e => e.stopPropagation()}>
                      <div style={{ display: 'flex', gap: 4 }}>
                        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 7px' }} onClick={() => openEdit(a)}>编辑</button>
                        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 7px', color: 'var(--critical)' }} onClick={() => confirmDelete(a)}>删</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Detail panel */}
        {selected && (
          <div style={{
            width: 360, borderLeft: '1px solid var(--border)', background: 'var(--bg-card)',
            display: 'flex', flexDirection: 'column', overflow: 'hidden', flexShrink: 0,
          }}>
            <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 13, fontWeight: 600, fontFamily: 'monospace' }}>{selected.hostname || selected._key}</span>
              <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px' }} onClick={() => setSelected(null)}>&#x2715;</button>
            </div>

            {/* Detail sub-tabs */}
            <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
              {detailTabs.map(([tab, label]) => (
                <button
                  key={tab}
                  onClick={() => {
                    setDetailTab(tab)
                    if (tab === 'vulns' && vulns.length === 0 && !vulnsLoading) {
                      loadVulns(selected._key)
                    }
                    if (tab === 'topology' && topoNeighbors.length === 0 && !topoLoading) {
                      loadTopoNeighbors()
                    }
                  }}
                  style={{
                    flex: 1, padding: '8px 0', fontSize: 11.5, fontWeight: detailTab === tab ? 600 : 400,
                    background: 'none', border: 'none', cursor: 'pointer',
                    color: detailTab === tab ? 'var(--accent-blue)' : 'var(--text-muted)',
                    borderBottom: detailTab === tab ? '2px solid var(--accent-blue)' : '2px solid transparent',
                  }}
                >
                  {label}
                </button>
              ))}
            </div>

            <div style={{ flex: 1, overflowY: 'auto', padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
              {detailTab === 'info' && (
                <>
                  <div className="card">
                    <div className="card-title">安全状态</div>
                    <div style={{ marginBottom: 12, display: 'flex', alignItems: 'center', gap: 10 }}>
                      <AssetScoreBadge score={selected.risk_score ?? 0} />
                      <span style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>资产评分</span>
                    </div>
                    <div style={{ display: 'flex', gap: 16 }}>
                      <div style={{ textAlign: 'center' }}>
                        <div style={{ fontSize: 20, fontWeight: 700, color: (selected.active_incident_count ?? 0) > 0 ? 'var(--critical)' : 'var(--text-muted)' }}>
                          {selected.active_incident_count ?? 0}
                        </div>
                        <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>事件</div>
                      </div>
                      <div style={{ textAlign: 'center' }}>
                        <div style={{ fontSize: 20, fontWeight: 700, color: (selected.open_vuln_count ?? 0) > 0 ? 'var(--high)' : 'var(--text-muted)' }}>
                          {selected.open_vuln_count ?? 0}
                        </div>
                        <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>未修复CVE</div>
                      </div>
                    </div>
                  </div>

                  <div className="card">
                    <div className="card-title">资产信息</div>
                    {[
                      ['主机名', selected.hostname || '-'],
                      ['IP地址', selected.ip || '-'],
                      ['MAC', selected.mac || '-'],
                      ['操作系统', `${osIcon(selected.os)} ${selected.os || '-'}${selected.os_version ? ' ' + selected.os_version : ''}`],
                      ['类型', selected.type || '-'],
                      ['部门', selected.department || '-'],
                      ['负责人', selected.owner || '-'],
                      ['最近活跃', fmtDate(selected.last_seen)],
                    ].map(([k, v]) => (
                      <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11.5, borderBottom: '1px solid rgba(255,255,255,.04)', paddingBottom: 4, marginBottom: 4 }}>
                        <span style={{ color: 'var(--text-muted)', flexShrink: 0, marginRight: 8 }}>{k}</span>
                        <span style={{ color: 'var(--text-secondary)', fontFamily: k === 'IP地址' || k === 'MAC' ? 'monospace' : undefined, textAlign: 'right' }}>{v}</span>
                      </div>
                    ))}
                  </div>

                  <div style={{ display: 'flex', gap: 8 }}>
                    <button className="btn-secondary" style={{ flex: 1, fontSize: 11 }} onClick={() => openEdit(selected)}>编辑资产</button>
                    <button className="btn-secondary" style={{ flex: 1, fontSize: 11, color: 'var(--critical)' }} disabled={deleting} onClick={() => confirmDelete(selected)}>删除</button>
                  </div>
                </>
              )}

              {detailTab === 'vulns' && (
                <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
                  <div className="card-title" style={{ padding: '10px 14px', borderBottom: '1px solid var(--border)' }}>漏洞列表</div>
                  {vulnsLoading && (
                    <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>加载中...</div>
                  )}
                  {!vulnsLoading && vulns.length === 0 && (
                    <div style={{ padding: 24, textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>暂无漏洞数据</div>
                  )}
                  {!vulnsLoading && vulns.length > 0 && (
                    <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11 }}>
                      <thead>
                        <tr style={{ background: 'var(--bg-secondary)' }}>
                          <th style={{ padding: '6px 10px', textAlign: 'left', color: 'var(--text-muted)', fontWeight: 500, borderBottom: '1px solid var(--border)' }}>CVE ID</th>
                          <th style={{ padding: '6px 6px', textAlign: 'center', color: 'var(--text-muted)', fontWeight: 500, borderBottom: '1px solid var(--border)' }}>危险度</th>
                          <th style={{ padding: '6px 6px', textAlign: 'center', color: 'var(--text-muted)', fontWeight: 500, borderBottom: '1px solid var(--border)' }}>CVSS</th>
                          <th style={{ padding: '6px 6px', textAlign: 'center', color: 'var(--text-muted)', fontWeight: 500, borderBottom: '1px solid var(--border)' }}>修复</th>
                          <th style={{ padding: '6px 10px', textAlign: 'left', color: 'var(--text-muted)', fontWeight: 500, borderBottom: '1px solid var(--border)' }}>标题</th>
                        </tr>
                      </thead>
                      <tbody>
                        {vulns.map(v => {
                          const sevColor = v.severity === 'critical' ? '#ef5350'
                            : v.severity === 'high' ? '#ffa726'
                            : v.severity === 'medium' ? '#f9a825'
                            : '#66bb6a'
                          const sevBg = v.severity === 'critical' ? 'rgba(229,57,53,.15)'
                            : v.severity === 'high' ? 'rgba(255,111,0,.15)'
                            : v.severity === 'medium' ? 'rgba(249,168,37,.15)'
                            : 'rgba(67,160,71,.15)'
                          const fixColor = v.fix_status === 'fixed' ? 'var(--accent-green)' : 'var(--text-muted)'
                          return (
                            <tr key={v._key} style={{ borderBottom: '1px solid rgba(255,255,255,.04)' }}>
                              <td style={{ padding: '6px 10px', fontFamily: 'monospace', fontSize: 10.5, color: 'var(--accent-blue)', whiteSpace: 'nowrap' }}>
                                {v.cve_id || '-'}
                              </td>
                              <td style={{ padding: '6px 6px', textAlign: 'center' }}>
                                <span style={{ background: sevBg, color: sevColor, borderRadius: 4, padding: '1px 6px', fontWeight: 600, fontSize: 10, textTransform: 'capitalize' }}>
                                  {v.severity || '-'}
                                </span>
                              </td>
                              <td style={{ padding: '6px 6px', textAlign: 'center', fontWeight: 600, color: sevColor }}>
                                {v.cvss_score != null ? v.cvss_score.toFixed(1) : '-'}
                              </td>
                              <td style={{ padding: '6px 6px', textAlign: 'center', color: fixColor, fontSize: 10.5 }}>
                                {v.fix_status === 'fixed' ? '已修复' : v.fix_status === 'in_progress' ? '处理中' : '未修复'}
                              </td>
                              <td style={{ padding: '6px 10px', color: 'var(--text-secondary)', maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}
                                title={v.title}>
                                {v.title || '-'}
                              </td>
                            </tr>
                          )
                        })}
                      </tbody>
                    </table>
                  )}
                </div>
              )}

              {detailTab === 'topology' && (
                <div className="card" style={{ padding: 12 }}>
                  <div className="card-title" style={{ marginBottom: 8 }}>网络拓扑</div>
                  {topoLoading ? (
                    <div style={{ textAlign: 'center', padding: 24, color: 'var(--text-muted)', fontSize: 12 }}>加载中...</div>
                  ) : (
                    <>
                      <TopologyMap
                        center={selected}
                        neighbors={topoNeighbors}
                        onSelect={a => setSelected(a)}
                      />
                      {/* Legend */}
                      <div style={{ display: 'flex', gap: 12, justifyContent: 'center', marginTop: 10, fontSize: 10, color: 'var(--text-muted)' }}>
                        <span>
                          <svg width={14} height={14} style={{ verticalAlign: 'middle', marginRight: 3 }}>
                            <circle cx={7} cy={7} r={6} fill="rgba(255,255,255,.1)" stroke="#aaa" strokeWidth={1.5} />
                          </svg>
                          终端
                        </span>
                        <span>
                          <svg width={14} height={14} style={{ verticalAlign: 'middle', marginRight: 3 }}>
                            <rect x={1} y={2} width={12} height={10} rx={2} fill="rgba(255,255,255,.1)" stroke="#aaa" strokeWidth={1.5} />
                          </svg>
                          服务器
                        </span>
                        <span>
                          <svg width={14} height={14} style={{ verticalAlign: 'middle', marginRight: 3 }}>
                            <polygon points="7,1 13,7 7,13 1,7" fill="rgba(255,255,255,.1)" stroke="#aaa" strokeWidth={1.5} />
                          </svg>
                          网络设备
                        </span>
                      </div>
                      <div style={{ display: 'flex', gap: 10, justifyContent: 'center', marginTop: 8, fontSize: 10, color: 'var(--text-muted)' }}>
                        {[{ label: '≥80', color: '#ef5350' }, { label: '≥60', color: '#ffa726' }, { label: '≥40', color: '#f9a825' }, { label: '<40', color: '#66bb6a' }].map(b => (
                          <span key={b.label} style={{ display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                            <span style={{ width: 8, height: 8, borderRadius: 2, background: b.color, display: 'inline-block' }} />
                            {b.label}
                          </span>
                        ))}
                      </div>
                    </>
                  )}
                </div>
              )}

              {detailTab === 'trend' && (
                <div className="card" style={{ padding: 12 }}>
                  <div className="card-title" style={{ marginBottom: 10 }}>风险评分趋势（近7天）</div>
                  <RiskTrendChart asset={selected} />
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      <div className="pagination">
        <button className="page-btn" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>&#8249;</button>
        {(()=>{
          const total = meta.total_pages || 1
          if (total <= 7) return Array.from({length: total},(_,i)=>i+1)
          const pages:(number|'...')[]=[1]
          if (page>3) pages.push('...')
          for(let i=Math.max(2,page-1);i<=Math.min(total-1,page+1);i++) pages.push(i)
          if(page<total-2) pages.push('...')
          pages.push(total)
          return pages
        })().map((p,i)=>
          p==='...' ? <span key={`e${i}`} style={{padding:'0 4px',color:'var(--text-muted)'}}>…</span>
          : <button key={p} className={`page-btn${page===p?' active':''}`} onClick={()=>setPage(p as number)}>{p}</button>
        )}
        <button className="page-btn" disabled={page >= meta.total_pages} onClick={() => setPage(p => p + 1)}>&#8250;</button>
        <span style={{ marginLeft: 8 }}>{meta.total} 条</span>
      </div>

      {/* Create / Edit Modal */}
      {showModal && (
        <>
          <div onClick={() => setShowModal(false)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.5)', zIndex: 400 }} />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 480, background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: 8, zIndex: 500, padding: 24,
          }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 20 }}>{editTarget ? '编辑资产' : '添加资产'}</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                {[
                  { label: '主机名 *', key: 'hostname', ph: 'WKSTN-001' },
                  { label: '名称/标签', key: 'name', ph: 'Finance Workstation' },
                  { label: 'IP地址', key: 'ip_addresses', ph: '10.0.0.1' },
                  { label: '负责人', key: 'owner', ph: 'john.doe' },
                  { label: '操作系统 Name', key: 'os_info.name', ph: 'Windows 11' },
                  { label: '部门', key: 'department', ph: 'Finance' },
                ].map(f => (
                  <div key={f.key}>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>{f.label}</div>
                    <input
                      className="filter-input"
                      style={{ width: '100%', boxSizing: 'border-box' }}
                      placeholder={f.ph}
                      value={f.key.startsWith('os_info.') ? (form.os_info as any)[f.key.split('.')[1]] : (form as any)[f.key]}
                      onChange={e => {
                        if (f.key.startsWith('os_info.')) {
                          const sub = f.key.split('.')[1]
                          setForm(prev => ({ ...prev, os_info: { ...prev.os_info, [sub]: e.target.value } }))
                        } else {
                          setForm(prev => ({ ...prev, [f.key]: e.target.value }))
                        }
                      }}
                    />
                  </div>
                ))}
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>类型</div>
                  <select className="filter-select" style={{ width: '100%' }} value={form.type} onChange={e => setForm(p => ({ ...p, type: e.target.value }))}>
                    <option value="workstation">Workstation</option>
                    <option value="server">Server</option>
                    <option value="network">Network Device</option>
                    <option value="cloud">Cloud Instance</option>
                    <option value="iot">IoT</option>
                  </select>
                </div>
                <div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>状态</div>
                  <select className="filter-select" style={{ width: '100%' }} value={form.status} onChange={e => setForm(p => ({ ...p, status: e.target.value }))}>
                    <option value="online">Online</option>
                    <option value="offline">Offline</option>
                    <option value="isolated">Isolated</option>
                  </select>
                </div>
              </div>
              <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setShowModal(false)}>取消</button>
                <button className="btn-primary" style={{ flex: 1 }} disabled={saving || !form.hostname.trim()} onClick={saveAsset}>
                  {saving ? '保存中...' : editTarget ? '保存修改' : '添加资产'}
                </button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* Delete Confirm Modal */}
      {deleteTarget && (
        <>
          <div onClick={() => setDeleteTarget(null)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.5)', zIndex: 400 }} />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 380, background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: 8, zIndex: 500, padding: 24,
          }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 12 }}>确认删除</div>
            <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 20 }}>
              确定要删除资产 <strong style={{ color: 'var(--text-primary)', fontFamily: 'monospace' }}>{deleteTarget.hostname}</strong> 吗？此操作不可撤销。
            </div>
            <div style={{ display: 'flex', gap: 10 }}>
              <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setDeleteTarget(null)}>取消</button>
              <button className="btn-primary" style={{ flex: 1, background: 'var(--critical)', borderColor: 'var(--critical)' }} disabled={deleting} onClick={doDelete}>
                {deleting ? '删除中...' : '确认删除'}
              </button>
            </div>
          </div>
        </>
      )}

      {/* Bulk Tag Modal */}
      {showTagModal && (
        <>
          <div onClick={() => setShowTagModal(false)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.5)', zIndex: 400 }} />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 380, background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: 8, zIndex: 500, padding: 24,
          }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 8 }}>批量添加标签</div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 16 }}>
              将为已选的 <strong style={{ color: 'var(--text-primary)' }}>{checkedKeys.size}</strong> 条资产追加标签
            </div>
            <div style={{ marginBottom: 16 }}>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>标签名称</div>
              <input
                className="filter-input"
                style={{ width: '100%', boxSizing: 'border-box' }}
                placeholder="例如: production, patched, high-value"
                value={bulkTagInput}
                autoFocus
                onChange={e => setBulkTagInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && applyBulkTag()}
              />
            </div>
            <div style={{ display: 'flex', gap: 10 }}>
              <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setShowTagModal(false)}>取消</button>
              <button
                className="btn-primary"
                style={{ flex: 1 }}
                disabled={bulkTagging || !bulkTagInput.trim()}
                onClick={applyBulkTag}
              >
                {bulkTagging ? '应用中...' : '确认添加'}
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
