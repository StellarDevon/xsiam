import { useEffect, useState, useRef, useCallback, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '@/lib/api'
import PageHeader from '@/components/PageHeader'

// ── Incident list shape ───────────────────────────────────────────────────────
interface IncidentItem {
  _key: string
  title: string
}

// ── API model shapes (match Go model/causality_graph.go) ─────────────────────
interface ApiNode {
  _key?: string
  node_id: string
  incident_id: string
  type: string
  label: string
  properties: Record<string, unknown>
  alert_id?: string
  asset_id?: string
  is_root: boolean
  severity?: string
  created_at: string
}

interface ApiEdge {
  _key?: string
  _from: string  // "causality_nodes/<node_id>"
  _to: string    // "causality_nodes/<node_id>"
  incident_id: string
  type: string   // EdgeType: spawned, wrote_file, etc.
  timestamp?: string
  weight: number
}

interface ApiGraph {
  graph_id: string
  incident_id: string
  time_window_h: number
  confidence: number
  nodes: ApiNode[]
  edges: ApiEdge[]
  node_count: number
  edge_count: number
  generated_at: string
  created_at: string
}

// ── Internal view model ───────────────────────────────────────────────────────
interface GraphNode {
  id: string
  type: string
  label: string
  detail: Record<string, unknown>
  is_root: boolean
  severity?: string
  created_at: string
  mitre_technique?: string
}

interface GraphEdge {
  id: string
  from: string
  to: string
  relation: string
  timestamp?: string
}

interface Graph {
  nodes: GraphNode[]
  edges: GraphEdge[]
  incident_id: string
  confidence: number
  node_count: number
  edge_count: number
}

// Extract node_id from ArangoDB edge endpoint "causality_nodes/<id>"
function extractNodeId(arangoRef: string): string {
  const slash = arangoRef.lastIndexOf('/')
  return slash >= 0 ? arangoRef.slice(slash + 1) : arangoRef
}

function toViewModel(apiData: ApiGraph): Graph {
  return {
    incident_id: apiData.incident_id,
    confidence: apiData.confidence,
    node_count: apiData.node_count,
    edge_count: apiData.edge_count,
    nodes: (apiData.nodes ?? []).map(n => ({
      id: n.node_id,
      type: n.type,
      label: n.label,
      detail: n.properties ?? {},
      is_root: n.is_root,
      severity: n.severity,
      created_at: n.created_at,
      mitre_technique: (n.properties?.mitre_technique as string | undefined),
    })),
    edges: (apiData.edges ?? []).map(e => ({
      id: e._key ?? `${e._from}-${e._to}`,
      from: extractNodeId(e._from),
      to: extractNodeId(e._to),
      relation: e.type,
      timestamp: e.timestamp,
    })),
  }
}

function formatDate(iso: string): string {
  if (!iso) return '—'
  try {
    return new Date(iso).toLocaleString('zh-CN', { hour12: false })
  } catch {
    return iso
  }
}

// ── Severity colors ───────────────────────────────────────────────────────────
const SEVERITY_BORDER: Record<string, string> = {
  critical: 'var(--critical)',
  high:     'var(--high)',
  medium:   'var(--medium)',
  low:      'var(--accent-green)',
}

// ── Node type colors & icons ──────────────────────────────────────────────────
const NODE_COLORS: Record<string, string> = {
  process:  'var(--accent-blue)',
  file:     'var(--medium)',
  network:  'var(--accent-green)',
  registry: 'var(--high)',
  user:     'var(--accent-blue)',
  alert:    'var(--critical)',
  asset:    'var(--text-muted)',
  host:     'var(--accent-blue)',
  Process:  'var(--accent-blue)',
  File:     'var(--medium)',
  Network:  'var(--accent-green)',
  Registry: 'var(--high)',
  User:     'var(--accent-blue)',
  Alert:    'var(--critical)',
  Asset:    'var(--text-muted)',
  Host:     'var(--accent-blue)',
}

const NODE_ICONS: Record<string, string> = {
  process: '🔧', file: '📄', network: '🌐',
  registry: '🔑', user: '👤', alert: '⚠️', asset: '🏢', host: '🖥️',
  Process: '🔧', File: '📄', Network: '🌐',
  Registry: '🔑', User: '👤', Alert: '⚠️', Asset: '🏢', Host: '🖥️',
}

// Node type icons for the detail panel (per-spec emojis)
function panelTypeIcon(type: string): string {
  const t = type.toLowerCase()
  if (t === 'process') return '🔴'
  if (t === 'network') return '🌐'
  if (t === 'file') return '📄'
  if (t === 'user') return '👤'
  return '📦'
}

const EDGE_COLORS: Record<string, string> = {
  spawned:           'var(--accent-blue)',
  wrote_file:        'var(--medium)',
  executed_file:     'var(--high)',
  connected_to:      'var(--accent-green)',
  modified_registry: 'var(--high)',
  lateral_move_to:   'var(--critical)',
  triggered_alert:   '#c0404088',
  logged_in_as:      'var(--accent-blue)',
  authenticated_as:  'var(--accent-blue)',
  accessed_resource: 'var(--text-muted)',
}

// ── Node type stat colors ─────────────────────────────────────────────────────
const STAT_CHIP_COLORS: Record<string, { bg: string; text: string; label: string }> = {
  process: { bg: '#4fa3e022', text: 'var(--accent-blue)', label: '进程' },
  file:    { bg: '#c8a03022', text: 'var(--medium)', label: '文件' },
  network: { bg: '#28906a22', text: 'var(--accent-green)', label: '网络' },
  other:   { bg: '#60607822', text: 'var(--text-muted)', label: '其他' },
}

// ── DAG layout (BFS level assignment) ────────────────────────────────────────
function dagLayout(
  nodes: GraphNode[],
  edges: GraphEdge[],
  svgW: number,
  svgH: number
): Record<string, { x: number; y: number }> {
  if (nodes.length === 0) return {}

  // Build adjacency
  const inEdges: Record<string, string[]> = {}
  const outEdges: Record<string, string[]> = {}
  nodes.forEach(n => { inEdges[n.id] = []; outEdges[n.id] = [] })
  edges.forEach(e => {
    if (inEdges[e.to] !== undefined) inEdges[e.to].push(e.from)
    if (outEdges[e.from] !== undefined) outEdges[e.from].push(e.to)
  })

  // Root nodes: is_root flag OR no incoming edges
  const roots = nodes.filter(n => n.is_root || inEdges[n.id].length === 0)
  const startIds = roots.length > 0 ? roots.map(n => n.id) : [nodes[0].id]

  // BFS level assignment
  const level: Record<string, number> = {}
  const queue = [...startIds]
  startIds.forEach(id => { level[id] = 0 })

  while (queue.length > 0) {
    const cur = queue.shift()!
    const curLevel = level[cur]
    for (const nxt of (outEdges[cur] ?? [])) {
      if (level[nxt] === undefined || level[nxt] < curLevel + 1) {
        level[nxt] = curLevel + 1
        queue.push(nxt)
      }
    }
  }
  // Nodes not reached get level based on in-edge depth (fallback)
  nodes.forEach(n => {
    if (level[n.id] === undefined) level[n.id] = 0
  })

  // Group by level
  const byLevel: Record<number, string[]> = {}
  nodes.forEach(n => {
    const lv = level[n.id]
    if (!byLevel[lv]) byLevel[lv] = []
    byLevel[lv].push(n.id)
  })

  const levels = Object.keys(byLevel).map(Number).sort((a, b) => a - b)
  const maxLevelCount = Math.max(...levels.map(l => byLevel[l].length))
  const levelCount = levels.length

  const xStep = Math.min(200, (svgW - 120) / Math.max(levelCount, 1))
  const yStep = Math.min(100, (svgH - 120) / Math.max(maxLevelCount, 1))

  const totalW = (levelCount - 1) * xStep
  const pos: Record<string, { x: number; y: number }> = {}

  levels.forEach((lv, li) => {
    const group = byLevel[lv]
    const totalH = (group.length - 1) * yStep
    group.forEach((id, idx) => {
      pos[id] = {
        x: 60 + li * xStep + (svgW - 120 - totalW) / 2,
        y: 60 + idx * yStep + (svgH - 120 - totalH) / 2,
      }
    })
  })

  return pos
}

// ── Topological sort for attack chain narrative ───────────────────────────────
function topoSort(nodes: GraphNode[], edges: GraphEdge[]): GraphNode[] {
  if (nodes.length === 0) return []
  const inDeg: Record<string, number> = {}
  const adj: Record<string, string[]> = {}
  nodes.forEach(n => { inDeg[n.id] = 0; adj[n.id] = [] })
  edges.forEach(e => {
    if (adj[e.from] !== undefined) adj[e.from].push(e.to)
    if (inDeg[e.to] !== undefined) inDeg[e.to]++
  })
  const queue: string[] = nodes.filter(n => inDeg[n.id] === 0).map(n => n.id)
  const result: string[] = []
  while (queue.length > 0) {
    const cur = queue.shift()!
    result.push(cur)
    for (const nxt of (adj[cur] ?? [])) {
      inDeg[nxt]--
      if (inDeg[nxt] === 0) queue.push(nxt)
    }
  }
  // Add any remaining (cycle fallback)
  nodes.forEach(n => { if (!result.includes(n.id)) result.push(n.id) })
  const nodeMap: Record<string, GraphNode> = {}
  nodes.forEach(n => { nodeMap[n.id] = n })
  return result.map(id => nodeMap[id]).filter(Boolean)
}

// ── Node shape renderers ──────────────────────────────────────────────────────
function NodeShape({
  type, color, isSelected, isRoot, isHighlighted, severity, size, isSuspect,
}: {
  type: string
  color: string
  isSelected: boolean
  isRoot: boolean
  isHighlighted: boolean
  severity?: string
  size: number
  isSuspect?: boolean
}) {
  const borderColor = isSuspect
    ? 'var(--critical)'
    : isSelected
    ? '#fff'
    : (severity && SEVERITY_BORDER[severity] ? SEVERITY_BORDER[severity] : color)
  const strokeW = isSuspect ? 3 : isSelected ? 2.5 : severity && SEVERITY_BORDER[severity] ? 2 : 1.5
  const fill = color + '33'
  const glow = isRoot || isHighlighted ? `drop-shadow(0 0 8px ${color})` : isSuspect ? 'drop-shadow(0 0 10px #ef4444)' : undefined
  const t = type.toLowerCase()

  if (t === 'process') {
    return (
      <rect
        x={-size} y={-size * 0.7}
        width={size * 2} height={size * 1.4}
        rx={4} ry={4}
        fill={fill} stroke={borderColor} strokeWidth={strokeW}
        filter={glow}
      />
    )
  }
  if (t === 'file') {
    const fold = size * 0.45
    const w = size * 1.8
    const h = size * 1.6
    const pts = [
      [-w / 2, -h / 2],
      [w / 2 - fold, -h / 2],
      [w / 2, -h / 2 + fold],
      [w / 2, h / 2],
      [-w / 2, h / 2],
    ].map(([x, y]) => `${x},${y}`).join(' ')
    return (
      <polygon
        points={pts}
        fill={fill} stroke={borderColor} strokeWidth={strokeW}
        filter={glow}
      />
    )
  }
  if (t === 'network') {
    return (
      <polygon
        points={`0,${-size * 1.1} ${size * 1.1},0 0,${size * 1.1} ${-size * 1.1},0`}
        fill={fill} stroke={borderColor} strokeWidth={strokeW}
        filter={glow}
      />
    )
  }
  if (t === 'alert') {
    return (
      <polygon
        points={`0,${-size * 1.2} ${size * 1.1},${size * 0.8} ${-size * 1.1},${size * 0.8}`}
        fill={fill} stroke={borderColor} strokeWidth={strokeW}
        filter={glow}
      />
    )
  }
  if (t === 'host') {
    const w = size * 2.2
    const h = size * 1.6
    return (
      <g filter={glow}>
        <rect x={-w / 2} y={-h / 2} width={w} height={h}
          rx={3} fill={fill} stroke={borderColor} strokeWidth={strokeW} />
        <line x1={-w / 2 + 4} y1={-h / 4} x2={w / 2 - 4} y2={-h / 4}
          stroke={borderColor} strokeWidth={0.7} strokeOpacity={0.4} />
        <line x1={-w / 2 + 4} y1={h / 4} x2={w / 2 - 4} y2={h / 4}
          stroke={borderColor} strokeWidth={0.7} strokeOpacity={0.4} />
      </g>
    )
  }
  return (
    <circle
      r={isRoot ? size * 1.2 : size}
      fill={fill} stroke={borderColor} strokeWidth={strokeW}
      filter={glow}
    />
  )
}

// ── Replay speed options ──────────────────────────────────────────────────────
const REPLAY_SPEEDS = [
  { label: '1x', ms: 800 },
  { label: '2x', ms: 400 },
  { label: '5x', ms: 160 },
]

// ── Process Tree types ────────────────────────────────────────────────────────
interface NetworkConn {
  proto: string
  localPort: number
  remoteIp: string
  remotePort: number
  state: string
}

interface ProcessNode {
  pid: number
  name: string
  path: string
  cmdline: string
  sha256: string
  parentPid: number
  startTime: string
  risk: 'clean' | 'suspicious' | 'malicious'
  mitre?: string
  mitreDesc?: string
  netConns: NetworkConn[]
  children: ProcessNode[]
}

// Seeded pseudo-random (LCG) for deterministic mock data
function mkRand(seed: number) {
  let s = seed | 0
  return () => {
    s = (s * 1664525 + 1013904223) & 0xffffffff
    return (s >>> 0) / 0xffffffff
  }
}

function seedFromKey(key: string): number {
  let h = 0x811c9dc5
  for (let i = 0; i < key.length; i++) {
    h ^= key.charCodeAt(i)
    h = Math.imul(h, 0x01000193)
  }
  return h >>> 0
}

function buildProcessTree(incidentKey: string): ProcessNode {
  const rand = mkRand(seedFromKey(incidentKey || 'default'))

  const baseTs = new Date('2025-03-15T08:12:00Z').getTime()
  function ts(offsetMin: number) {
    return new Date(baseTs + offsetMin * 60000).toISOString()
  }

  // net connections generator
  function mkNet(n: number): NetworkConn[] {
    const conns: NetworkConn[] = []
    const remoteIps = ['192.168.10.1', '10.0.0.254', '185.220.101.42', '91.108.4.11']
    const states = ['ESTABLISHED', 'CLOSE_WAIT', 'TIME_WAIT']
    for (let i = 0; i < n; i++) {
      conns.push({
        proto: rand() > 0.3 ? 'TCP' : 'UDP',
        localPort: 1024 + Math.floor(rand() * 60000),
        remoteIp: remoteIps[Math.floor(rand() * remoteIps.length)],
        remotePort: [80, 443, 4444, 8080, 6667][Math.floor(rand() * 5)],
        state: states[Math.floor(rand() * states.length)],
      })
    }
    return conns
  }

  // Hash snippet based on seed
  const hexChars = '0123456789abcdef'
  function fakeHash() {
    let h = ''
    for (let i = 0; i < 64; i++) h += hexChars[Math.floor(rand() * 16)]
    return h
  }

  const r1 = fakeHash(); const r2 = fakeHash(); const r3 = fakeHash()
  const r4 = fakeHash(); const r5 = fakeHash(); const r6 = fakeHash()
  const r7 = fakeHash()

  return {
    pid: 4,
    name: 'System',
    path: '',
    cmdline: '',
    sha256: r1,
    parentPid: 0,
    startTime: ts(-120),
    risk: 'clean',
    netConns: [],
    children: [
      {
        pid: 872,
        name: 'svchost.exe',
        path: 'C:\\Windows\\System32\\svchost.exe',
        cmdline: 'C:\\Windows\\System32\\svchost.exe -k netsvcs -p -s Schedule',
        sha256: r2,
        parentPid: 4,
        startTime: ts(-60),
        risk: 'clean',
        netConns: mkNet(Math.floor(rand() * 2)),
        children: [
          {
            pid: 3344,
            name: 'cmd.exe',
            path: 'C:\\Windows\\System32\\cmd.exe',
            cmdline: 'cmd.exe /c "whoami && net user /domain"',
            sha256: r3,
            parentPid: 872,
            startTime: ts(-5),
            risk: 'suspicious',
            mitre: 'T1059.003',
            mitreDesc: 'Command and Scripting Interpreter: Windows Command Shell',
            netConns: [],
            children: [
              {
                pid: 5120,
                name: 'powershell.exe',
                path: 'C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe',
                cmdline: 'powershell.exe -NoP -NonI -W Hidden -Enc JABjAGwAaQBlAG4AdAA=',
                sha256: r4,
                parentPid: 3344,
                startTime: ts(-4),
                risk: 'malicious',
                mitre: 'T1059.001',
                mitreDesc: 'Command and Scripting Interpreter: PowerShell',
                netConns: mkNet(1 + Math.floor(rand() * 2)),
                children: [
                  {
                    pid: 7890,
                    name: 'whoami.exe',
                    path: 'C:\\Windows\\System32\\whoami.exe',
                    cmdline: 'whoami /all',
                    sha256: r5,
                    parentPid: 5120,
                    startTime: ts(-3),
                    risk: 'suspicious',
                    mitre: 'T1033',
                    mitreDesc: 'System Owner/User Discovery',
                    netConns: [],
                    children: [],
                  },
                  {
                    pid: 8012,
                    name: 'net.exe',
                    path: 'C:\\Windows\\System32\\net.exe',
                    cmdline: 'net user /domain',
                    sha256: r6,
                    parentPid: 5120,
                    startTime: ts(-2),
                    risk: 'suspicious',
                    mitre: 'T1087.002',
                    mitreDesc: 'Account Discovery: Domain Account',
                    netConns: [],
                    children: [],
                  },
                ],
              },
            ],
          },
        ],
      },
      {
        pid: 1024,
        name: 'explorer.exe',
        path: 'C:\\Windows\\explorer.exe',
        cmdline: 'C:\\Windows\\explorer.exe',
        sha256: r7,
        parentPid: 4,
        startTime: ts(-110),
        risk: 'clean',
        netConns: [],
        children: [],
      },
    ],
  }
}

// Risk styling helpers
const RISK_COLORS: Record<string, { bg: string; border: string; text: string; label: string }> = {
  malicious:  { bg: '#ef444418', border: 'var(--critical)', text: 'var(--critical)',  label: '恶意' },
  suspicious: { bg: '#f9731618', border: 'var(--high)', text: 'var(--high)',  label: '可疑' },
  clean:      { bg: '#ffffff08', border: '#ffffff22', text: 'var(--text-muted)', label: '正常' },
}

const PROC_ICONS: Record<string, string> = {
  'powershell.exe': '⚡',
  'cmd.exe':        '⬛',
  'system':         '🖥️',
  'svchost.exe':    '⚙️',
  'explorer.exe':   '📂',
  'whoami.exe':     '👤',
  'net.exe':        '🌐',
}
function procIcon(name: string): string {
  return PROC_ICONS[name.toLowerCase()] ?? '🔧'
}

// ── ProcessTreeView component ─────────────────────────────────────────────────
function ProcessTreeView({ incidentId }: { incidentId: string }) {
  const tree = useMemo(() => buildProcessTree(incidentId), [incidentId])
  const [collapsed, setCollapsed] = useState<Set<number>>(new Set())
  const [selectedProc, setSelectedProc] = useState<ProcessNode | null>(null)

  function toggleCollapse(pid: number) {
    setCollapsed(prev => {
      const next = new Set(prev)
      if (next.has(pid)) next.delete(pid)
      else next.add(pid)
      return next
    })
  }

  function renderNode(node: ProcessNode, depth: number, isLast: boolean, prefix: string): React.ReactNode {
    const hasChildren = node.children.length > 0
    const isCollapsed = collapsed.has(node.pid)
    const isSelected = selectedProc?.pid === node.pid
    const risk = RISK_COLORS[node.risk]
    const connector = depth === 0 ? '' : isLast ? '└─ ' : '├─ '
    const childPrefix = depth === 0 ? '' : isLast ? '   ' : '│  '

    return (
      <div key={node.pid}>
        {/* Node row */}
        <div
          style={{
            display: 'flex', alignItems: 'center', gap: 0,
            cursor: 'pointer',
            userSelect: 'none',
            padding: '2px 0',
          }}
          onClick={() => setSelectedProc(isSelected ? null : node)}
        >
          {/* Tree lines prefix */}
          <span style={{
            fontFamily: 'monospace', fontSize: 12,
            color: '#ffffff25', whiteSpace: 'pre', flexShrink: 0,
          }}>{prefix + connector}</span>

          {/* Collapse triangle */}
          {hasChildren ? (
            <span
              style={{
                fontSize: 9, color: '#4fa3e088', marginRight: 4, flexShrink: 0,
                transition: 'transform 0.15s',
                display: 'inline-block',
                transform: isCollapsed ? 'rotate(-90deg)' : 'rotate(0deg)',
              }}
              onClick={e => { e.stopPropagation(); toggleCollapse(node.pid) }}
            >▼</span>
          ) : (
            <span style={{ width: 13, flexShrink: 0 }} />
          )}

          {/* Process pill */}
          <div style={{
            display: 'flex', alignItems: 'center', gap: 6,
            padding: '3px 10px',
            borderRadius: 5,
            background: isSelected ? (risk.bg === '#ffffff08' ? '#4fa3e018' : risk.bg) : risk.bg,
            border: `1px solid ${isSelected ? (node.risk === 'clean' ? '#4fa3e055' : risk.border) : risk.border + (node.risk === 'clean' ? '' : '88')}`,
            transition: 'all 0.15s',
            minWidth: 0,
            flex: 1,
            maxWidth: 440,
          }}>
            <span style={{ fontSize: 13, lineHeight: 1, flexShrink: 0 }}>{procIcon(node.name)}</span>
            <span style={{
              fontSize: 12.5, fontWeight: node.risk !== 'clean' ? 600 : 400,
              color: node.risk !== 'clean' ? risk.text : 'var(--text-primary)',
              fontFamily: 'monospace', flexShrink: 0,
            }}>{node.name}</span>
            <span style={{
              fontSize: 10.5, color: 'var(--text-muted)', fontFamily: 'monospace', flexShrink: 0,
            }}>PID {node.pid}</span>
            {node.risk !== 'clean' && (
              <span style={{
                fontSize: 10, fontWeight: 700,
                background: risk.border + '22',
                border: `1px solid ${risk.border}88`,
                color: risk.text,
                borderRadius: 3, padding: '0 5px', flexShrink: 0,
              }}>
                {node.risk === 'malicious' ? '🔴' : '🟠'} {risk.label}
              </span>
            )}
            {node.mitre && (
              <span style={{
                fontSize: 9.5,
                background: '#7c3aed22', border: '1px solid #7c3aed55',
                color: 'var(--accent-blue)', borderRadius: 3, padding: '0 5px', flexShrink: 0,
              }}>{node.mitre}</span>
            )}
          </div>
        </div>

        {/* Children */}
        {hasChildren && !isCollapsed && (
          <div>
            {node.children.map((child, idx) =>
              renderNode(child, depth + 1, idx === node.children.length - 1, prefix + childPrefix)
            )}
          </div>
        )}
      </div>
    )
  }

  return (
    <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
      {/* Tree panel */}
      <div style={{
        flex: 1, overflowY: 'auto', padding: '20px 24px',
        background: 'var(--bg-secondary)',
        backgroundImage: 'radial-gradient(circle, #1a1b24 1px, transparent 1px)',
        backgroundSize: '32px 32px',
      }}>
        {/* Header hint */}
        <div style={{
          display: 'flex', alignItems: 'center', gap: 12, marginBottom: 20,
          padding: '8px 14px',
          background: 'rgba(79,163,224,0.06)',
          border: '1px solid rgba(79,163,224,0.15)',
          borderRadius: 6,
        }}>
          <span style={{ fontSize: 12, color: 'var(--accent-blue)' }}>🌲 进程树</span>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>点击进程查看详情 · 点击 ▼ 折叠分支</span>
          <div style={{ flex: 1 }} />
          <span style={{ fontSize: 10.5, color: 'var(--critical)', fontWeight: 600 }}>🔴 恶意</span>
          <span style={{ fontSize: 10.5, color: 'var(--high)', fontWeight: 600, marginLeft: 8 }}>🟠 可疑</span>
          <span style={{ fontSize: 10.5, color: 'var(--text-muted)', marginLeft: 8 }}>⚪ 正常</span>
        </div>

        {/* Tree */}
        <div style={{
          background: 'rgba(10,11,18,0.7)',
          border: '1px solid var(--border)',
          borderRadius: 8,
          padding: '16px 14px',
        }}>
          {renderNode(tree, 0, true, '')}
        </div>

        {/* Legend note */}
        <div style={{ marginTop: 12, fontSize: 10.5, color: 'var(--text-muted)', fontFamily: 'monospace' }}>
          * 模拟数据，基于事件 ID 确定性生成
        </div>
      </div>

      {/* Process detail side panel */}
      {selectedProc && (
        <div style={{
          width: 320, flexShrink: 0,
          borderLeft: '1px solid var(--border)',
          background: 'var(--bg-card)',
          display: 'flex', flexDirection: 'column',
          overflow: 'hidden',
          animation: 'slideInRight 0.2s ease-out',
        }}>
          {/* Panel header */}
          <div style={{
            padding: '12px 16px',
            borderBottom: '1px solid var(--border)',
            display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between',
          }}>
            <div style={{ flex: 1, minWidth: 0 }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                <span style={{ fontSize: 22, lineHeight: 1 }}>{procIcon(selectedProc.name)}</span>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{
                    fontSize: 14, fontWeight: 700,
                    color: 'var(--text-primary)', fontFamily: 'monospace',
                    wordBreak: 'break-all',
                  }}>{selectedProc.name}</div>
                  <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginTop: 2 }}>PID {selectedProc.pid}</div>
                </div>
              </div>
              {selectedProc.risk !== 'clean' && (
                <span style={{
                  display: 'inline-flex', alignItems: 'center', gap: 4,
                  fontSize: 11, fontWeight: 700,
                  background: RISK_COLORS[selectedProc.risk].border + '22',
                  border: `1px solid ${RISK_COLORS[selectedProc.risk].border}88`,
                  color: RISK_COLORS[selectedProc.risk].text,
                  borderRadius: 4, padding: '2px 8px',
                }}>
                  {selectedProc.risk === 'malicious' ? '🔴 恶意进程' : '🟠 可疑进程'}
                </span>
              )}
            </div>
            <button
              className="btn-secondary"
              style={{ fontSize: 11, padding: '2px 8px', flexShrink: 0, marginLeft: 8 }}
              onClick={() => setSelectedProc(null)}
            >✕</button>
          </div>

          {/* Scrollable content */}
          <div style={{ flex: 1, overflowY: 'auto', padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>

            {/* Full path */}
            <div className="card">
              <div className="card-title">路径 &amp; 命令行</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <div style={{
                  fontSize: 11, color: 'var(--text-muted)',
                  borderBottom: '1px solid rgba(255,255,255,.04)', paddingBottom: 5,
                }}>路径</div>
                <div style={{
                  fontSize: 10.5, fontFamily: 'monospace', color: 'var(--text-secondary)',
                  wordBreak: 'break-all', lineHeight: 1.5,
                  background: 'var(--bg-code)', borderRadius: 4, padding: '5px 8px',
                }}>
                  {selectedProc.path || '—'}
                </div>
                <div style={{
                  fontSize: 11, color: 'var(--text-muted)', marginTop: 4,
                  borderBottom: '1px solid rgba(255,255,255,.04)', paddingBottom: 5,
                }}>命令行</div>
                <div style={{
                  fontSize: 10.5, fontFamily: 'monospace', color: 'var(--accent-blue)',
                  wordBreak: 'break-all', lineHeight: 1.5,
                  background: 'var(--bg-code)', borderRadius: 4, padding: '5px 8px',
                }}>
                  {selectedProc.cmdline || '—'}
                </div>
              </div>
            </div>

            {/* Process metadata */}
            <div className="card">
              <div className="card-title">进程信息</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                {([
                  ['父进程 PID', String(selectedProc.parentPid || '—')],
                  ['启动时间', new Date(selectedProc.startTime).toLocaleString('zh-CN', { hour12: false })],
                ] as [string, string][]).map(([label, val]) => (
                  <div key={label} style={{
                    display: 'flex', justifyContent: 'space-between', fontSize: 11,
                    borderBottom: '1px solid rgba(255,255,255,.04)', paddingBottom: 3,
                  }}>
                    <span style={{ color: 'var(--text-muted)', flexShrink: 0, marginRight: 8 }}>{label}</span>
                    <span style={{
                      color: 'var(--text-secondary)', fontFamily: 'monospace',
                      fontSize: 10.5, textAlign: 'right',
                    }}>{val}</span>
                  </div>
                ))}
                <div style={{
                  fontSize: 11, color: 'var(--text-muted)', paddingBottom: 3,
                }}>SHA256</div>
                <div style={{
                  fontSize: 9.5, fontFamily: 'monospace', color: 'var(--text-muted)',
                  wordBreak: 'break-all', lineHeight: 1.4,
                  background: 'var(--bg-code)', borderRadius: 3, padding: '4px 6px',
                }}>{selectedProc.sha256}</div>
              </div>
            </div>

            {/* MITRE */}
            {selectedProc.mitre && (
              <div className="card">
                <div className="card-title">MITRE ATT&amp;CK</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  <span style={{
                    display: 'inline-flex', alignItems: 'center', gap: 6,
                    background: '#7c3aed22', border: '1px solid #7c3aed66',
                    color: 'var(--accent-blue)', borderRadius: 4, padding: '3px 10px',
                    fontSize: 12, fontWeight: 700, width: 'fit-content',
                  }}>{selectedProc.mitre}</span>
                  <span style={{ fontSize: 11.5, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                    {selectedProc.mitreDesc}
                  </span>
                </div>
              </div>
            )}

            {/* Network connections */}
            {selectedProc.netConns.length > 0 && (
              <div className="card">
                <div className="card-title">网络连接 ({selectedProc.netConns.length})</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {selectedProc.netConns.map((conn, idx) => (
                    <div key={idx} style={{
                      padding: '5px 8px',
                      background: 'var(--bg-code)', borderRadius: 4,
                      border: '1px solid rgba(255,255,255,0.06)',
                      fontSize: 10.5, fontFamily: 'monospace',
                      display: 'flex', flexDirection: 'column', gap: 3,
                    }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between' }}>
                        <span style={{ color: 'var(--accent-blue)', fontWeight: 600 }}>{conn.proto}</span>
                        <span style={{ color: conn.state === 'ESTABLISHED' ? 'var(--accent-green)' : 'var(--text-muted)' }}>
                          {conn.state}
                        </span>
                      </div>
                      <div style={{ color: 'var(--critical)' }}>
                        → {conn.remoteIp}:{conn.remotePort}
                      </div>
                      <div style={{ color: 'var(--text-muted)' }}>
                        local :{conn.localPort}
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {selectedProc.netConns.length === 0 && (
              <div className="card">
                <div className="card-title">网络连接</div>
                <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>无网络连接</span>
              </div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

// ── Main component ────────────────────────────────────────────────────────────
export default function CausalityGraph() {
  const navigate = useNavigate()
  const [incidentId, setIncidentId] = useState('')
  const [graph, setGraph] = useState<Graph | null>(null)
  const [pos, setPos] = useState<Record<string, { x: number; y: number }>>({})
  const [loading, setLoading] = useState(false)
  const [selected, setSelected] = useState<GraphNode | null>(null)
  const [incidentList, setIncidentList] = useState<IncidentItem[]>([])
  const [hoveredEdge, setHoveredEdge] = useState<{
    id: string; label: string; x: number; y: number
  } | null>(null)
  const svgRef = useRef<SVGSVGElement>(null)
  const svgWrapRef = useRef<HTMLDivElement>(null)
  const [pan, setPan] = useState({ x: 0, y: 0 })
  const [zoom, setZoom] = useState(1)
  const dragging = useRef(false)
  const lastMouse = useRef({ x: 0, y: 0 })
  const [svgSize, setSvgSize] = useState({ w: 900, h: 560 })

  // ── Search
  const [searchQuery, setSearchQuery] = useState('')

  // ── Replay animation
  const [replayActive, setReplayActive] = useState(false)
  const [replayIndex, setReplayIndex] = useState(-1)
  const [replaySpeedIdx, setReplaySpeedIdx] = useState(0)
  const replayTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  // ── Mini-map
  const minimapRef = useRef<HTMLCanvasElement>(null)

  // ── Generate attack chain status
  const [generating, setGenerating] = useState(false)

  // ── Node detail panel: suspect nodes & slide-in animation
  const [suspectNodes, setSuspectNodes] = useState<Set<string>>(new Set())
  // ── Cmdline expand toggle in node detail panel
  const [cmdlineExpanded, setCmdlineExpanded] = useState(false)

  // ── View tab: 'graph' | 'processtree'
  const [viewTab, setViewTab] = useState<'graph' | 'processtree'>('graph')

  // ── Attack chain narrative panel
  const [showNarrative, setShowNarrative] = useState(false)
  const [showAiSummary, setShowAiSummary] = useState(false)
  const [aiSummaryLoading, setAiSummaryLoading] = useState(false)

  // Track SVG container size
  useEffect(() => {
    const el = svgWrapRef.current
    if (!el) return
    const ro = new ResizeObserver(entries => {
      const rect = entries[0].contentRect
      setSvgSize({ w: rect.width || 900, h: rect.height || 560 })
    })
    ro.observe(el)
    return () => ro.disconnect()
  }, [])

  useEffect(() => {
    api.get('/incidents', { params: { page: 1, page_size: 50 } })
      .then(r => setIncidentList(r.data.data?.items ?? []))
      .catch(() => { /* silently ignore */ })
  }, [])

  function loadGraph(id: string) {
    if (!id) return
    setLoading(true)
    setSelected(null)
    setSearchQuery('')
    stopReplay()
    setShowNarrative(false)
    setShowAiSummary(false)
    setSuspectNodes(new Set())
    api.get(`/incidents/${id}/graph`)
      .then(r => {
        const apiData: ApiGraph = r.data.data
        const g = toViewModel(apiData)
        setGraph(g)
        const p = dagLayout(g.nodes, g.edges, svgSize.w, svgSize.h)
        setPos(p)
        setPan({ x: 0, y: 0 })
        setZoom(1)
      })
      .catch(() => setGraph({
        nodes: [], edges: [],
        incident_id: id, confidence: 0, node_count: 0, edge_count: 0,
      }))
      .finally(() => setLoading(false))
  }

  function generateGraph(id: string) {
    if (!id) return
    setGenerating(true)
    api.post(`/incidents/${id}/graph`)
      .then(r => {
        const apiData: ApiGraph = r.data.data
        const g = toViewModel(apiData)
        setGraph(g)
        const p = dagLayout(g.nodes, g.edges, svgSize.w, svgSize.h)
        setPos(p)
        setPan({ x: 0, y: 0 })
        setZoom(1)
      })
      .catch(() => loadGraph(id))
      .finally(() => setGenerating(false))
  }

  // ── Search: highlighted node ids
  const highlightedNodes = useMemo<Set<string>>(() => {
    if (!graph || !searchQuery.trim()) return new Set()
    const q = searchQuery.toLowerCase()
    const hits = new Set<string>()
    graph.nodes.forEach(n => {
      if (
        n.label.toLowerCase().includes(q) ||
        n.type.toLowerCase().includes(q) ||
        Object.values(n.detail).some(v => String(v).toLowerCase().includes(q))
      ) {
        hits.add(n.id)
      }
    })
    return hits
  }, [graph, searchQuery])

  // ── Replay (time-ordered edges)
  const sortedEdges = useMemo<GraphEdge[]>(() => {
    if (!graph) return []
    return [...graph.edges].sort((a, b) => {
      if (!a.timestamp && !b.timestamp) return 0
      if (!a.timestamp) return 1
      if (!b.timestamp) return -1
      return a.timestamp.localeCompare(b.timestamp)
    })
  }, [graph])

  // ── Earliest / latest timestamps
  const { earliest, latest } = useMemo(() => {
    const stamps = sortedEdges.map(e => e.timestamp).filter(Boolean) as string[]
    return {
      earliest: stamps.length > 0 ? stamps[0] : null,
      latest: stamps.length > 0 ? stamps[stamps.length - 1] : null,
    }
  }, [sortedEdges])

  const replaySpeed = REPLAY_SPEEDS[replaySpeedIdx] ?? REPLAY_SPEEDS[0]

  function stopReplay() {
    if (replayTimer.current) clearTimeout(replayTimer.current)
    setReplayActive(false)
    setReplayIndex(-1)
  }

  function startReplay() {
    if (sortedEdges.length === 0) return
    stopReplay()
    setReplayActive(true)
    setReplayIndex(0)
  }

  function jumpToStart() {
    if (sortedEdges.length === 0) return
    if (replayTimer.current) clearTimeout(replayTimer.current)
    setReplayActive(false)
    setReplayIndex(0)
  }

  function jumpToEnd() {
    if (sortedEdges.length === 0) return
    if (replayTimer.current) clearTimeout(replayTimer.current)
    setReplayActive(false)
    setReplayIndex(sortedEdges.length - 1)
  }

  useEffect(() => {
    if (!replayActive || replayIndex < 0) return
    if (replayIndex >= sortedEdges.length) {
      replayTimer.current = setTimeout(() => stopReplay(), 600)
      return
    }
    replayTimer.current = setTimeout(() => {
      setReplayIndex(i => i + 1)
    }, replaySpeed.ms)
    return () => { if (replayTimer.current) clearTimeout(replayTimer.current) }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [replayActive, replayIndex, sortedEdges.length, replaySpeed.ms])

  const replayHighlightEdgeId = (replayActive || replayIndex >= 0) && replayIndex >= 0 && replayIndex < sortedEdges.length
    ? sortedEdges[replayIndex]?.id
    : null
  const replayActiveEdge = replayHighlightEdgeId
    ? sortedEdges.find(e => e.id === replayHighlightEdgeId) ?? null
    : null
  const replayDimmedEdges = replayActive
    ? new Set(sortedEdges.slice(replayIndex + 1).map(e => e.id))
    : null

  // ── Graph statistics
  const graphStats = useMemo(() => {
    if (!graph) return null
    const counts: Record<string, number> = { process: 0, file: 0, network: 0, other: 0 }
    graph.nodes.forEach(n => {
      const t = n.type.toLowerCase()
      if (t === 'process') counts.process++
      else if (t === 'file') counts.file++
      else if (t === 'network') counts.network++
      else counts.other++
    })
    return counts
  }, [graph])

  // ── Attack chain narrative
  const narrativeSteps = useMemo(() => {
    if (!graph || graph.nodes.length === 0) return []
    const ordered = topoSort(graph.nodes, graph.edges)
    return ordered.map((n, i) => {
      const t = n.type.toLowerCase()
      let text = ''
      if (t === 'process') {
        const name = (n.detail.name as string | undefined) ?? n.label
        text = `执行进程: ${name}`
      } else if (t === 'network') {
        const ip = (n.detail.ip as string | undefined) ?? n.label
        const port = (n.detail.port as string | number | undefined) ?? ''
        text = `发起网络连接: ${ip}${port ? ':' + port : ''}`
      } else if (t === 'file') {
        const path = (n.detail.path as string | undefined) ?? n.label
        text = `访问文件: ${path}`
      } else {
        text = `${n.type}: ${n.label}`
      }
      return {
        step: i + 1,
        text,
        node: n,
        mitre: n.mitre_technique ?? (n.detail.mitre_technique as string | undefined) ?? null,
      }
    })
  }, [graph])

  const mockAiSummary = useMemo(() => {
    if (!graph) return ''
    const nodeCount = graph.nodes.length
    const edgeCount = graph.edges.length
    const rootNodes = graph.nodes.filter(n => n.is_root).map(n => n.label).join(', ') || '未知'
    const processNodes = graph.nodes.filter(n => n.type.toLowerCase() === 'process').length
    const networkNodes = graph.nodes.filter(n => n.type.toLowerCase() === 'network').length
    const fileNodes = graph.nodes.filter(n => n.type.toLowerCase() === 'file').length
    return `【AI攻击链摘要】
分析完成，共涉及 ${nodeCount} 个节点，${edgeCount} 条关系边。

攻击入口: ${rootNodes}

攻击路径概述:
  - 攻击者首先通过初始访问手段建立立足点
  - 随后执行了 ${processNodes} 个进程节点，进行横向移动
  - 期间建立了 ${networkNodes} 次网络连接，疑似数据外渗或C2通信
  - 共访问/修改 ${fileNodes} 个文件对象

风险研判:
  攻击链呈现多阶段特征，建议立即隔离相关主机并对
  IOC指标进行全局扫描。置信度: ${graph.confidence > 0 ? (graph.confidence * 100).toFixed(0) + '%' : 'N/A'}

[此摘要为AI模拟生成，仅供参考]`
  }, [graph])

  function handleAiSummary() {
    setShowAiSummary(false)
    setAiSummaryLoading(true)
    setTimeout(() => {
      setAiSummaryLoading(false)
      setShowAiSummary(true)
    }, 1200)
  }

  // ── Suspect node toggle
  function toggleSuspect(nodeId: string) {
    setSuspectNodes(prev => {
      const next = new Set(prev)
      if (next.has(nodeId)) next.delete(nodeId)
      else next.add(nodeId)
      return next
    })
  }

  // ── Pan & zoom
  const onMouseDown = useCallback((e: React.MouseEvent) => {
    if ((e.target as Element).closest('.graph-node')) return
    dragging.current = true
    lastMouse.current = { x: e.clientX, y: e.clientY }
  }, [])

  const onMouseMove = useCallback((e: React.MouseEvent) => {
    if (!dragging.current) return
    const dx = e.clientX - lastMouse.current.x
    const dy = e.clientY - lastMouse.current.y
    lastMouse.current = { x: e.clientX, y: e.clientY }
    setPan(p => ({ x: p.x + dx, y: p.y + dy }))
  }, [])

  const onMouseUp = useCallback(() => { dragging.current = false }, [])

  const onWheel = useCallback((e: React.WheelEvent) => {
    e.preventDefault()
    setZoom(z => Math.max(0.2, Math.min(3, z - e.deltaY * 0.001)))
  }, [])

  function fitScreen() {
    if (!graph || graph.nodes.length === 0) return
    const ps = Object.values(pos)
    if (ps.length === 0) return
    const xs = ps.map(p => p.x)
    const ys = ps.map(p => p.y)
    const minX = Math.min(...xs), maxX = Math.max(...xs)
    const minY = Math.min(...ys), maxY = Math.max(...ys)
    const contentW = maxX - minX + 120
    const contentH = maxY - minY + 120
    const scaleX = svgSize.w / contentW
    const scaleY = svgSize.h / contentH
    const newZoom = Math.max(0.2, Math.min(2, Math.min(scaleX, scaleY) * 0.9))
    const cx = (minX + maxX) / 2
    const cy = (minY + maxY) / 2
    setPan({
      x: svgSize.w / 2 - cx * newZoom,
      y: svgSize.h / 2 - cy * newZoom,
    })
    setZoom(newZoom)
  }

  // ── Mini-map rendering
  useEffect(() => {
    const canvas = minimapRef.current
    if (!canvas || !graph || graph.nodes.length === 0) return
    const ctx = canvas.getContext('2d')
    if (!ctx) return
    const W = canvas.width, H = canvas.height
    ctx.clearRect(0, 0, W, H)
    ctx.fillStyle = 'rgba(16,17,26,0.85)'
    ctx.fillRect(0, 0, W, H)

    const ps = Object.values(pos)
    if (ps.length === 0) return
    const xs = ps.map(p => p.x), ys = ps.map(p => p.y)
    const minX = Math.min(...xs), maxX = Math.max(...xs)
    const minY = Math.min(...ys), maxY = Math.max(...ys)
    const rangeX = Math.max(maxX - minX, 1)
    const rangeY = Math.max(maxY - minY, 1)
    const pad = 8
    const scX = (W - pad * 2) / rangeX
    const scY = (H - pad * 2) / rangeY
    const sc = Math.min(scX, scY)

    function mmX(x: number) { return pad + (x - minX) * sc }
    function mmY(y: number) { return pad + (y - minY) * sc }

    ctx.strokeStyle = 'rgba(255,255,255,0.15)'
    ctx.lineWidth = 0.8
    graph.edges.forEach(e => {
      const f = pos[e.from], t = pos[e.to]
      if (!f || !t) return
      ctx.beginPath()
      ctx.moveTo(mmX(f.x), mmY(f.y))
      ctx.lineTo(mmX(t.x), mmY(t.y))
      ctx.stroke()
    })

    graph.nodes.forEach(n => {
      const p = pos[n.id]
      if (!p) return
      ctx.beginPath()
      ctx.arc(mmX(p.x), mmY(p.y), 3, 0, Math.PI * 2)
      ctx.fillStyle = n.is_root ? 'var(--critical)' : (NODE_COLORS[n.type] ?? 'var(--text-muted)')
      ctx.fill()
    })

    const vpX1 = (-pan.x) / zoom
    const vpY1 = (-pan.y) / zoom
    const vpW = svgSize.w / zoom
    const vpH = svgSize.h / zoom
    ctx.strokeStyle = 'rgba(255,255,255,0.4)'
    ctx.lineWidth = 1
    ctx.strokeRect(
      mmX(vpX1), mmY(vpY1),
      vpW * sc, vpH * sc
    )
  }, [graph, pos, pan, zoom, svgSize])

  // ── PNG export
  function exportPng() {
    const svgEl = svgRef.current
    if (!svgEl) return
    const svgData = new XMLSerializer().serializeToString(svgEl)
    const canvas = document.createElement('canvas')
    canvas.width = svgSize.w * 2
    canvas.height = svgSize.h * 2
    const ctx = canvas.getContext('2d')
    if (!ctx) return
    ctx.scale(2, 2)
    ctx.fillStyle = 'var(--bg-primary)'
    ctx.fillRect(0, 0, svgSize.w, svgSize.h)
    const img = new Image()
    const blob = new Blob([svgData], { type: 'image/svg+xml;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    img.onload = () => {
      ctx.drawImage(img, 0, 0)
      URL.revokeObjectURL(url)
      const a = document.createElement('a')
      a.download = `causality-graph-${incidentId || 'export'}.png`
      a.href = canvas.toDataURL('image/png')
      a.click()
    }
    img.src = url
  }

  // ── Edge animation keyframes (injected once)
  useEffect(() => {
    if (document.getElementById('cg-edge-anim')) return
    const style = document.createElement('style')
    style.id = 'cg-edge-anim'
    style.textContent = `
      @keyframes dashFlow {
        from { stroke-dashoffset: 20; }
        to   { stroke-dashoffset: 0; }
      }
      @keyframes slideInRight {
        from { transform: translateX(100%); opacity: 0; }
        to   { transform: translateX(0); opacity: 1; }
      }
    `
    document.head.appendChild(style)
  }, [])

  const hasGraph = graph && !loading && graph.nodes.length > 0

  // ── Node detail panel helpers ─────────────────────────────────────────────
  function renderNodeTypeFields(node: GraphNode) {
    const t = node.type.toLowerCase()
    const d = node.detail

    if (t === 'process') {
      const cmdlineRaw = (d.cmdline ?? d.command_line) as string | undefined
      const cmdlineFull = cmdlineRaw != null ? String(cmdlineRaw) : null
      const cmdlineTruncated = cmdlineFull && cmdlineFull.length > 60 && !cmdlineExpanded
        ? cmdlineFull.slice(0, 60) + '…'
        : cmdlineFull
      return (
        <div className="card" style={{ marginTop: 12 }}>
          <div className="card-title">进程详情</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
            {([
              ['PID', d.pid],
              ['用户', d.user ?? d.username],
              ['父进程', d.parent_process ?? d.parent_name],
            ] as [string, unknown][]).map(([label, val]) => val != null && (
              <div key={label} style={{
                display: 'flex', justifyContent: 'space-between', fontSize: 11,
                borderBottom: '1px solid rgba(255,255,255,.04)', paddingBottom: 3,
              }}>
                <span style={{ color: 'var(--text-muted)', flexShrink: 0, marginRight: 8 }}>{label}</span>
                <span style={{
                  color: 'var(--text-secondary)', fontFamily: 'monospace',
                  wordBreak: 'break-all', textAlign: 'right',
                  maxWidth: 170, fontSize: 10.5,
                }} title={String(val)}>
                  {String(val).length > 60 ? String(val).slice(0, 60) + '…' : String(val)}
                </span>
              </div>
            ))}
            {cmdlineFull != null && (
              <div style={{
                display: 'flex', flexDirection: 'column', fontSize: 11,
                borderBottom: '1px solid rgba(255,255,255,.04)', paddingBottom: 3, gap: 3,
              }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                  <span style={{ color: 'var(--text-muted)', flexShrink: 0, marginRight: 8 }}>命令行</span>
                  {cmdlineFull.length > 60 && (
                    <button
                      className="btn-secondary"
                      style={{ fontSize: 9.5, padding: '1px 5px', flexShrink: 0 }}
                      onClick={() => setCmdlineExpanded(v => !v)}
                    >{cmdlineExpanded ? '收起' : '展开'}</button>
                  )}
                </div>
                <span style={{
                  color: 'var(--text-secondary)', fontFamily: 'monospace',
                  wordBreak: 'break-all', fontSize: 10.5,
                }} title={cmdlineFull}>
                  {cmdlineTruncated}
                </span>
              </div>
            )}
          </div>
        </div>
      )
    }

    if (t === 'network') {
      const direction = (d.direction as string | undefined)
      return (
        <div className="card" style={{ marginTop: 12 }}>
          <div className="card-title">网络详情</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
            {[
              ['IP', d.ip ?? d.remote_ip ?? d.dst_ip],
              ['端口', d.port ?? d.remote_port ?? d.dst_port],
              ['协议', d.protocol],
              ['方向', direction],
            ].map(([label, val]) => val != null && (
              <div key={String(label)} style={{
                display: 'flex', justifyContent: 'space-between', fontSize: 11,
                borderBottom: '1px solid rgba(255,255,255,.04)', paddingBottom: 3,
              }}>
                <span style={{ color: 'var(--text-muted)', flexShrink: 0, marginRight: 8 }}>{label as React.ReactNode}</span>
                <span style={{
                  color: label === '方向'
                    ? (String(val) === 'inbound' ? 'var(--accent-green)' : 'var(--high)')
                    : 'var(--text-secondary)',
                  fontFamily: 'monospace', textAlign: 'right', fontSize: 10.5,
                }}>
                  {label === '方向'
                    ? (String(val) === 'inbound' ? '⬇ 入站' : '⬆ 出站')
                    : String(val)}
                </span>
              </div>
            ))}
          </div>
        </div>
      )
    }

    if (t === 'file') {
      const verdict = (d.verdict as string | undefined)
      const hash = (d.hash ?? d.md5 ?? d.sha256) as string | undefined
      const size = d.size as string | number | undefined
      return (
        <div className="card" style={{ marginTop: 12 }}>
          <div className="card-title">文件详情</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
            {([
              ['路径', (d.path ?? d.file_path) as string | undefined],
              ['哈希', hash],
              ['大小', size != null ? String(size) + ' bytes' : undefined],
              ['判定', verdict],
            ] as [string, string | undefined][]).map(([label, val]) => val != null && (
              <div key={label} style={{
                display: 'flex', justifyContent: 'space-between', fontSize: 11,
                borderBottom: '1px solid rgba(255,255,255,.04)', paddingBottom: 3,
              }}>
                <span style={{ color: 'var(--text-muted)', flexShrink: 0, marginRight: 8 }}>{label}</span>
                {label === '判定' ? (
                  <span style={{
                    color: val === 'malicious' ? 'var(--critical)' : 'var(--accent-green)',
                    fontWeight: 600, fontSize: 11,
                  }}>
                    {val === 'malicious' ? '🔴 恶意' : '🟢 正常'}
                  </span>
                ) : (
                  <span style={{
                    color: 'var(--text-secondary)', fontFamily: 'monospace',
                    textAlign: 'right', maxWidth: 170, fontSize: 10.5,
                    wordBreak: 'break-all',
                  }} title={val}>
                    {val.length > 50 ? val.slice(0, 50) + '…' : val}
                  </span>
                )}
              </div>
            ))}
          </div>
        </div>
      )
    }

    return null
  }

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <PageHeader
        title="溯源图"
        subtitle={graph
          ? `· ${graph.nodes.length} 节点, ${graph.edges.length} 边${graph.confidence ? `  置信度 ${(graph.confidence * 100).toFixed(0)}%` : ''}`
          : undefined}
        actions={<>
          <select
            className="filter-select"
            style={{ minWidth: 240 }}
            value={incidentId}
            onChange={e => { setIncidentId(e.target.value); loadGraph(e.target.value) }}
          >
            <option value="">— 选择事件 —</option>
            {incidentList.map(inc => (
              <option key={inc._key} value={inc._key}>
                {inc.title ? `${inc.title} (${inc._key})` : inc._key}
              </option>
            ))}
          </select>

          <input
            className="filter-input"
            style={{ width: 140 }}
            placeholder="事件ID..."
            value={incidentId}
            onChange={e => setIncidentId(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && loadGraph(incidentId)}
          />

          <button
            className="btn-primary"
            onClick={() => loadGraph(incidentId)}
            disabled={loading || !incidentId}
          >
            {loading ? '加载中...' : '加载图谱'}
          </button>

          <button
            className="btn-secondary"
            onClick={() => generateGraph(incidentId)}
            disabled={generating || !incidentId}
            style={{ fontSize: 12 }}
          >
            {generating ? '生成中...' : '⚡ 生成攻击链'}
          </button>

          {hasGraph && (
            <button
              className="btn-secondary"
              onClick={exportPng}
              style={{ fontSize: 12 }}
            >
              📥 导出 PNG
            </button>
          )}
        </>}
      />

      {/* ── Graph statistics bar ──────────────────────────────────────────── */}
      {hasGraph && graphStats && (
        <div style={{
          display: 'flex', alignItems: 'center', gap: 10,
          padding: '6px 16px', borderBottom: '1px solid var(--border)',
          background: 'var(--bg-card)', flexShrink: 0, flexWrap: 'wrap',
        }}>
          {/* Total node count with type breakdown */}
          <span style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>
            节点:{' '}
            <strong style={{ color: 'var(--text-primary)' }}>{graph.nodes.length}</strong>
          </span>
          <span style={{ opacity: 0.3 }}>|</span>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            进程 <strong style={{ color: STAT_CHIP_COLORS.process.text }}>{graphStats.process}</strong>
            {' / '}
            网络 <strong style={{ color: STAT_CHIP_COLORS.network.text }}>{graphStats.network}</strong>
            {' / '}
            文件 <strong style={{ color: STAT_CHIP_COLORS.file.text }}>{graphStats.file}</strong>
            {graphStats.other > 0 && <> / 其他 <strong style={{ color: STAT_CHIP_COLORS.other.text }}>{graphStats.other}</strong></>}
          </span>
          <span style={{ opacity: 0.4, marginLeft: 4 }}>·</span>
          <span style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>
            边: <strong style={{ color: 'var(--text-secondary)' }}>{graph.edges.length}</strong>
          </span>
          {(earliest || latest) && (
            <>
              <span style={{ opacity: 0.4 }}>·</span>
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                时间跨度:{' '}
                <span style={{ color: 'var(--text-secondary)' }}>{earliest ? formatDate(earliest) : '—'}</span>
                {'–'}
                <span style={{ color: 'var(--text-secondary)' }}>{latest ? formatDate(latest) : '—'}</span>
              </span>
            </>
          )}
          <div style={{ flex: 1 }} />
          <button
            className="btn-secondary"
            style={{ fontSize: 11 }}
            onClick={() => setShowNarrative(v => !v)}
          >
            {showNarrative ? '▲ 隐藏攻击链' : '▼ 攻击链分析'}
          </button>
        </div>
      )}

      {/* ── View tab switcher ─────────────────────────────────────────────── */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 0,
        borderBottom: '1px solid var(--border)',
        background: 'var(--bg-card)',
        flexShrink: 0, paddingLeft: 16,
      }}>
        {([
          ['graph',       '因果图',  '🕸️'],
          ['processtree', '进程树', '🌲'],
        ] as ['graph' | 'processtree', string, string][]).map(([tab, label, icon]) => (
          <button
            key={tab}
            onClick={() => setViewTab(tab)}
            style={{
              padding: '8px 18px',
              fontSize: 12.5, fontWeight: 600,
              background: 'transparent',
              border: 'none',
              borderBottom: viewTab === tab
                ? '2px solid #4fa3e0'
                : '2px solid transparent',
              color: viewTab === tab ? 'var(--accent-blue)' : 'var(--text-muted)',
              cursor: 'pointer',
              transition: 'all 0.15s',
              display: 'flex', alignItems: 'center', gap: 6,
            }}
          >
            <span>{icon}</span>
            <span>{label}</span>
          </button>
        ))}
      </div>

      <div style={{ flex: 1, display: 'flex', overflow: 'hidden', flexDirection: 'column' }}>
        {/* ── Process Tree View ──────────────────────────────────────────── */}
        {viewTab === 'processtree' && (
          <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
            {incidentId ? (
              <ProcessTreeView incidentId={incidentId} />
            ) : (
              <div style={{
                flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center',
                flexDirection: 'column', gap: 12,
                background: 'var(--bg-secondary)',
              }}>
                <span style={{ fontSize: 40, opacity: 0.2 }}>🌲</span>
                <span style={{ color: 'var(--text-muted)', fontSize: 13 }}>选择一个事件以查看其进程树</span>
              </div>
            )}
          </div>
        )}

        {/* ── Causality Graph View ───────────────────────────────────────── */}
        {viewTab === 'graph' && (
        <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
          {/* Graph canvas + stats bar column */}
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
            {/* Toolbar row: search + replay */}
            {hasGraph && (
              <div style={{
                display: 'flex', alignItems: 'center', gap: 8,
                padding: '6px 14px', borderBottom: '1px solid var(--border)',
                background: 'var(--bg-card)', flexShrink: 0, flexWrap: 'wrap',
              }}>
                <input
                  className="filter-input"
                  style={{ width: 220, fontSize: 12 }}
                  placeholder="🔍 搜索节点（标签/类型/属性）..."
                  value={searchQuery}
                  onChange={e => setSearchQuery(e.target.value)}
                />
                {searchQuery && (
                  <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                    {highlightedNodes.size} 匹配
                  </span>
                )}
                <div style={{ flex: 1 }} />

                {/* Jump buttons */}
                <button
                  className="btn-secondary"
                  style={{ fontSize: 11, padding: '3px 8px' }}
                  onClick={jumpToStart}
                  disabled={sortedEdges.length === 0}
                  title="跳到开始"
                >⏮ 跳到开始</button>
                <button
                  className="btn-secondary"
                  style={{ fontSize: 11, padding: '3px 8px' }}
                  onClick={jumpToEnd}
                  disabled={sortedEdges.length === 0}
                  title="跳到结束"
                >⏭ 跳到结束</button>

                {/* Speed selector */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>速度</span>
                  <select
                    className="filter-select"
                    style={{ fontSize: 11, padding: '2px 6px', height: 24 }}
                    value={replaySpeedIdx}
                    onChange={e => setReplaySpeedIdx(Number(e.target.value))}
                  >
                    {REPLAY_SPEEDS.map((s, idx) => (
                      <option key={s.label} value={idx}>{s.label}</option>
                    ))}
                  </select>
                </div>

                <button
                  className={replayActive ? 'btn-primary' : 'btn-secondary'}
                  style={{ fontSize: 12 }}
                  onClick={replayActive ? stopReplay : startReplay}
                >
                  {replayActive ? `⏹ 停止回放 (${replayIndex}/${sortedEdges.length})` : '▶ 时间回放'}
                </button>

                {/* Active edge timestamp during replay */}
                {replayActiveEdge && replayActiveEdge.timestamp && (
                  <span style={{
                    fontSize: 11, color: 'var(--accent-blue)',
                    background: '#4fa3e022', border: '1px solid #4fa3e044',
                    borderRadius: 4, padding: '2px 8px',
                  }}>
                    🕒 {formatDate(replayActiveEdge.timestamp)}
                  </span>
                )}
              </div>
            )}

            {/* Graph canvas */}
            <div
              ref={svgWrapRef}
              style={{
                flex: 1, position: 'relative', overflow: 'hidden',
                background: 'var(--bg-secondary)',
                backgroundImage: 'radial-gradient(circle, #1a1b24 1px, transparent 1px)',
                backgroundSize: '32px 32px',
              }}
            >
              {!graph && !loading && (
                <div style={{
                  position: 'absolute', inset: 0,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  flexDirection: 'column', gap: 12,
                }}>
                  <span style={{ fontSize: 40, opacity: 0.2 }}>📡</span>
                  <span style={{ color: 'var(--text-muted)', fontSize: 13 }}>选择一个事件以加载其溯源图</span>
                </div>
              )}
              {loading && (
                <div style={{
                  position: 'absolute', inset: 0,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                }}>
                  <span style={{ color: 'var(--text-muted)', fontSize: 13 }}>计算图布局中...</span>
                </div>
              )}
              {graph && !loading && graph.nodes.length === 0 && (
                <div style={{
                  position: 'absolute', inset: 0,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  flexDirection: 'column', gap: 8,
                }}>
                  <span style={{ fontSize: 32, opacity: 0.2 }}>🕸️</span>
                  <span style={{ color: 'var(--text-muted)', fontSize: 13 }}>该事件暂无溯源图数据</span>
                </div>
              )}

              {hasGraph && (
                <svg
                  ref={svgRef}
                  style={{ width: '100%', height: '100%', cursor: 'grab', userSelect: 'none' }}
                  onMouseDown={onMouseDown}
                  onMouseMove={onMouseMove}
                  onMouseUp={onMouseUp}
                  onMouseLeave={onMouseUp}
                  onWheel={onWheel}
                >
                  <defs>
                    <marker id="arrowhead" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
                      <polygon points="0 0, 8 3, 0 6" fill="#ffffff40" />
                    </marker>
                    <marker id="arrowhead-active" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
                      <polygon points="0 0, 8 3, 0 6" fill="#fff" />
                    </marker>
                    <marker id="arrowhead-replay" markerWidth="8" markerHeight="6" refX="8" refY="3" orient="auto">
                      <polygon points="0 0, 8 3, 0 6" fill="var(--accent-blue)" />
                    </marker>
                  </defs>

                  <g transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>
                    {/* Edges */}
                    {graph.edges.map(e => {
                      const from = pos[e.from]
                      const to = pos[e.to]
                      if (!from || !to) return null

                      const isActive = e.id === replayHighlightEdgeId
                      const isDimmed = replayDimmedEdges ? replayDimmedEdges.has(e.id) : false
                      const color = isActive ? 'var(--accent-blue)' : (EDGE_COLORS[e.relation] ?? '#ffffff30')
                      const opacity = isDimmed ? 0.1 : isActive ? 1 : 0.5
                      const mx = (from.x + to.x) / 2
                      const my = (from.y + to.y) / 2

                      return (
                        <g key={e.id}>
                          <line
                            x1={from.x} y1={from.y} x2={to.x} y2={to.y}
                            stroke={color}
                            strokeWidth={isActive ? 3 : 1.5}
                            strokeOpacity={opacity}
                            strokeDasharray={isActive ? '6 4' : undefined}
                            style={isActive ? {
                              animation: 'dashFlow 0.4s linear infinite',
                            } : undefined}
                            markerEnd={isActive ? 'url(#arrowhead-replay)' : 'url(#arrowhead)'}
                          />
                          {/* Invisible wider hit area */}
                          <line
                            x1={from.x} y1={from.y} x2={to.x} y2={to.y}
                            stroke="transparent" strokeWidth={10}
                            style={{ cursor: 'crosshair' }}
                            onMouseEnter={_ev => {
                              const svgRect = svgRef.current?.getBoundingClientRect()
                              if (!svgRect) return
                              setHoveredEdge({
                                id: e.id,
                                label: e.relation,
                                x: pan.x + mx * zoom + svgRect.left,
                                y: pan.y + my * zoom + svgRect.top,
                              })
                            }}
                            onMouseLeave={() => setHoveredEdge(null)}
                          />
                          <text
                            x={mx} y={my - 4}
                            fontSize={9} fill={color} textAnchor="middle" opacity={opacity * 0.7}
                            style={{ pointerEvents: 'none' }}
                          >{e.relation}</text>
                        </g>
                      )
                    })}

                    {/* Nodes */}
                    {graph.nodes.map(n => {
                      const p = pos[n.id]
                      if (!p) return null
                      const isSuspect = suspectNodes.has(n.id)
                      const baseColor = isSuspect ? 'var(--critical)' : n.is_root ? 'var(--critical)' : (NODE_COLORS[n.type] ?? 'var(--text-muted)')
                      const isSelected = selected?.id === n.id
                      const isHighlighted = highlightedNodes.size > 0 && highlightedNodes.has(n.id)
                      const isDimmed = highlightedNodes.size > 0 && !highlightedNodes.has(n.id)
                      const size = n.is_root ? 20 : 16

                      return (
                        <g
                          key={n.id}
                          className="graph-node"
                          transform={`translate(${p.x},${p.y})`}
                          style={{
                            cursor: 'pointer',
                            opacity: isDimmed ? 0.3 : 1,
                            transition: 'opacity 0.2s',
                          }}
                          onClick={() => { setSelected(isSelected ? null : n); setCmdlineExpanded(false) }}
                        >
                          <NodeShape
                            type={n.type}
                            color={baseColor}
                            isSelected={isSelected}
                            isRoot={n.is_root}
                            isHighlighted={isHighlighted}
                            severity={n.severity}
                            size={size}
                            isSuspect={isSuspect}
                          />

                          {/* Icon */}
                          <text
                            fontSize={n.is_root ? 12 : 10}
                            textAnchor="middle"
                            dominantBaseline="middle"
                            style={{ pointerEvents: 'none' }}
                          >
                            {NODE_ICONS[n.type] ?? '◻'}
                          </text>

                          {/* Root star decoration */}
                          {n.is_root && (
                            <text
                              x={size * 0.8} y={-size * 0.9}
                              fontSize={10}
                              textAnchor="middle"
                              style={{ pointerEvents: 'none' }}
                            >⭐</text>
                          )}

                          {/* Suspect indicator */}
                          {isSuspect && (
                            <text
                              x={-size * 0.8} y={-size * 0.9}
                              fontSize={10}
                              textAnchor="middle"
                              style={{ pointerEvents: 'none' }}
                            >🚩</text>
                          )}

                          {/* Label */}
                          <text
                            y={size + 14}
                            fontSize={9.5}
                            fill={isHighlighted ? '#fff' : 'var(--text-secondary)'}
                            textAnchor="middle"
                            style={{ pointerEvents: 'none' }}
                          >
                            {n.label?.slice(0, 18)}{(n.label?.length ?? 0) > 18 ? '…' : ''}
                          </text>

                          {/* Highlight ring */}
                          {isHighlighted && (
                            <circle
                              r={size + 6}
                              fill="none"
                              stroke="#fff"
                              strokeWidth={1.5}
                              strokeDasharray="4 3"
                              style={{ pointerEvents: 'none' }}
                            />
                          )}
                        </g>
                      )
                    })}
                  </g>
                </svg>
              )}

              {/* Zoom controls */}
              {hasGraph && (
                <div style={{
                  position: 'absolute', bottom: 128, right: 16,
                  display: 'flex', flexDirection: 'column', gap: 4,
                }}>
                  <button
                    className="btn-secondary"
                    style={{ width: 28, height: 28, padding: 0, fontSize: 16, lineHeight: 1 }}
                    onClick={() => setZoom(z => Math.min(3, z + 0.2))}
                    title="放大"
                  >+</button>
                  <button
                    className="btn-secondary"
                    style={{ width: 28, height: 28, padding: 0, fontSize: 11 }}
                    onClick={fitScreen}
                    title="适应屏幕"
                  >⊡</button>
                  <button
                    className="btn-secondary"
                    style={{ width: 28, height: 28, padding: 0, fontSize: 11 }}
                    onClick={() => { setZoom(1); setPan({ x: 0, y: 0 }) }}
                    title="重置"
                  >⌂</button>
                  <button
                    className="btn-secondary"
                    style={{ width: 28, height: 28, padding: 0, fontSize: 16, lineHeight: 1 }}
                    onClick={() => setZoom(z => Math.max(0.2, z - 0.2))}
                    title="缩小"
                  >−</button>
                </div>
              )}

              {/* Mini-map */}
              {hasGraph && (
                <canvas
                  ref={minimapRef}
                  width={160}
                  height={100}
                  style={{
                    position: 'absolute', bottom: 16, right: 16,
                    borderRadius: 6,
                    border: '1px solid var(--border)',
                    pointerEvents: 'none',
                  }}
                />
              )}

              {/* Legend */}
              {hasGraph && (
                <div style={{
                  position: 'absolute', bottom: 16, left: 16,
                  background: 'rgba(16,17,26,.85)',
                  border: '1px solid var(--border)',
                  borderRadius: 6, padding: '8px 12px',
                  display: 'flex', flexDirection: 'column', gap: 4,
                }}>
                  {([
                    ['process', '进程'], ['file', '文件'], ['network', '网络'],
                    ['registry', '注册表'], ['user', '用户'],
                    ['alert', '告警'], ['host', '主机'], ['asset', '资产'],
                  ] as [string, string][]).map(([type, label]) => (
                    <div key={type} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 10.5 }}>
                      <span style={{
                        width: 10, height: 10, borderRadius: '50%',
                        background: NODE_COLORS[type], display: 'inline-block', flexShrink: 0,
                      }} />
                      <span style={{ color: 'var(--text-muted)' }}>{label}</span>
                    </div>
                  ))}
                  <div style={{
                    display: 'flex', alignItems: 'center', gap: 6, fontSize: 10.5,
                    marginTop: 4, borderTop: '1px solid var(--border)', paddingTop: 4,
                  }}>
                    <span style={{
                      width: 10, height: 10, borderRadius: '50%',
                      background: 'var(--critical)', boxShadow: '0 0 6px rgba(192,64,64,.6)',
                      display: 'inline-block', flexShrink: 0,
                    }} />
                    <span style={{ color: 'var(--text-muted)' }}>⭐ 根因节点</span>
                  </div>
                  <div style={{
                    display: 'flex', flexDirection: 'column', gap: 2,
                    marginTop: 4, borderTop: '1px solid var(--border)', paddingTop: 4,
                  }}>
                    <span style={{ fontSize: 9.5, color: 'var(--text-muted)', marginBottom: 2 }}>严重程度边框</span>
                    {([
                      ['critical', '严重'], ['high', '高'], ['medium', '中'], ['low', '低'],
                    ] as [string, string][]).map(([sev, label]) => (
                      <div key={sev} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 10 }}>
                        <span style={{
                          width: 10, height: 10, borderRadius: 2,
                          border: `2px solid ${SEVERITY_BORDER[sev]}`,
                          display: 'inline-block', flexShrink: 0,
                        }} />
                        <span style={{ color: 'var(--text-muted)' }}>{label}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Edge tooltip */}
              {hoveredEdge && (
                <div style={{
                  position: 'fixed',
                  left: hoveredEdge.x + 8,
                  top: hoveredEdge.y - 28,
                  background: 'rgba(16,17,26,0.95)',
                  border: '1px solid var(--border)',
                  borderRadius: 4, padding: '4px 10px',
                  fontSize: 11.5,
                  color: EDGE_COLORS[hoveredEdge.label] ?? 'var(--text-secondary)',
                  pointerEvents: 'none', zIndex: 100, whiteSpace: 'nowrap',
                }}>
                  {hoveredEdge.label}
                </div>
              )}
            </div>

            {/* Bottom stats bar */}
            {graph && !loading && (
              <div style={{
                borderTop: '1px solid var(--border)',
                background: 'var(--bg-card)',
                padding: '6px 16px',
                display: 'flex', alignItems: 'center', gap: 16,
                fontSize: 12, color: 'var(--text-muted)', flexShrink: 0,
              }}>
                <span>
                  <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                    {graph.node_count || graph.nodes.length}
                  </span>{' 节点'}
                </span>
                <span style={{ opacity: 0.4 }}>·</span>
                <span>
                  <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>
                    {graph.edge_count || graph.edges.length}
                  </span>{' 边'}
                </span>
                {graph.confidence > 0 && <>
                  <span style={{ opacity: 0.4 }}>·</span>
                  <span>
                    {'置信度 '}
                    <span style={{
                      color: graph.confidence >= 0.8 ? 'var(--accent-green)'
                        : graph.confidence >= 0.5 ? 'var(--medium)' : 'var(--critical)',
                      fontWeight: 600,
                    }}>
                      {(graph.confidence * 100).toFixed(0)}%
                    </span>
                  </span>
                </>}
                {(replayActive || replayIndex >= 0) && (
                  <>
                    <span style={{ opacity: 0.4 }}>·</span>
                    <span style={{ color: 'var(--accent-blue)' }}>
                      {replayActive ? '▶' : '⏸'} 时间回放 {Math.max(replayIndex, 0)}/{sortedEdges.length}
                      {replayActiveEdge?.timestamp && ` · ${formatDate(replayActiveEdge.timestamp)}`}
                    </span>
                  </>
                )}
                {suspectNodes.size > 0 && (
                  <>
                    <span style={{ opacity: 0.4 }}>·</span>
                    <span style={{ color: 'var(--critical)' }}>🚩 {suspectNodes.size} 个可疑节点</span>
                  </>
                )}
              </div>
            )}
          </div>

          {/* ── Node detail side panel backdrop + slide-in panel ───────────── */}
          {selected && (
            <div
              style={{
                position: 'fixed', inset: 0, zIndex: 200,
                background: 'var(--bg-overlay)',
                pointerEvents: 'auto',
              }}
              onClick={() => { setSelected(null); setCmdlineExpanded(false) }}
            >
              {/* Panel — stops propagation so clicks inside don't close */}
              <div
                style={{
                  position: 'fixed', top: 0, right: 0, bottom: 0,
                  width: 280,
                  borderLeft: '1px solid var(--border)',
                  background: 'var(--bg-drawer)',
                  display: 'flex', flexDirection: 'column',
                  overflow: 'hidden',
                  animation: 'slideInRight 0.2s ease-out',
                  zIndex: 201,
                }}
                onClick={e => e.stopPropagation()}
              >
              {/* Header */}
              <div style={{
                padding: '12px 16px', borderBottom: '1px solid var(--border)',
                background: 'var(--bg-card2)',
                display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start',
                flexShrink: 0, minHeight: 48,
              }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4, flex: 1, minWidth: 0 }}>
                  {/* Type icon (large) + label */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <span style={{ fontSize: 22, lineHeight: 1 }}>{panelTypeIcon(selected.type)}</span>
                    <div style={{ flex: 1, minWidth: 0 }}>
                      <div style={{
                        fontSize: 14, fontWeight: 700,
                        color: 'var(--text-primary)', wordBreak: 'break-all', lineHeight: 1.3,
                      }}>
                        {selected.label}
                      </div>
                    </div>
                  </div>
                  {/* node_type badge row */}
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap', marginTop: 4 }}>
                    <span style={{
                      display: 'inline-flex', alignItems: 'center', gap: 4,
                      background: (NODE_COLORS[selected.type] ?? 'var(--text-muted)') + '22',
                      border: `1px solid ${NODE_COLORS[selected.type] ?? 'var(--text-muted)'}`,
                      color: NODE_COLORS[selected.type] ?? 'var(--text-muted)',
                      borderRadius: 4, padding: '1px 7px', fontSize: 11, fontWeight: 600,
                    }}>
                      {NODE_ICONS[selected.type] ?? '◻'} {selected.type}
                    </span>
                    {selected.is_root && (
                      <span style={{ fontSize: 11, color: 'var(--critical)', fontWeight: 700 }}>⭐ 根节点</span>
                    )}
                    {suspectNodes.has(selected.id) && (
                      <span style={{ fontSize: 11, color: 'var(--critical)', fontWeight: 700 }}>🚩 可疑</span>
                    )}
                  </div>
                </div>
                <button
                  className="btn-secondary"
                  style={{ fontSize: 11, padding: '2px 8px', flexShrink: 0, marginLeft: 8 }}
                  onClick={() => { setSelected(null); setCmdlineExpanded(false) }}
                >✕</button>
              </div>

              {/* Scrollable content */}
              <div style={{ flex: 1, overflowY: 'auto', padding: 16 }}>
                {/* Basic node info */}
                <div className="card">
                  <div className="card-title">节点信息</div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                    <div style={{
                      display: 'flex', justifyContent: 'space-between', fontSize: 11.5,
                      borderBottom: '1px solid rgba(255,255,255,.04)', paddingBottom: 4,
                    }}>
                      <span style={{ color: 'var(--text-muted)' }}>ID</span>
                      <span style={{
                        color: 'var(--text-secondary)', fontFamily: 'monospace',
                        fontSize: 10, wordBreak: 'break-all', textAlign: 'right', maxWidth: 180,
                      }}>{selected.id}</span>
                    </div>
                    {selected.severity && (
                      <div style={{
                        display: 'flex', justifyContent: 'space-between', fontSize: 11.5,
                        borderBottom: '1px solid rgba(255,255,255,.04)', paddingBottom: 4,
                      }}>
                        <span style={{ color: 'var(--text-muted)' }}>严重程度</span>
                        <span className={`sev-badge ${selected.severity}`}>{selected.severity}</span>
                      </div>
                    )}
                    {selected.created_at && (
                      <div style={{
                        display: 'flex', justifyContent: 'space-between', fontSize: 11.5,
                        borderBottom: '1px solid rgba(255,255,255,.04)', paddingBottom: 4,
                      }}>
                        <span style={{ color: 'var(--text-muted)' }}>创建时间</span>
                        <span style={{ color: 'var(--text-secondary)', fontSize: 10.5, textAlign: 'right' }}>
                          {formatDate(selected.created_at)}
                        </span>
                      </div>
                    )}
                    {selected.mitre_technique && (
                      <div style={{
                        display: 'flex', justifyContent: 'space-between', fontSize: 11.5,
                        borderBottom: '1px solid rgba(255,255,255,.04)', paddingBottom: 4,
                      }}>
                        <span style={{ color: 'var(--text-muted)' }}>MITRE</span>
                        <span style={{
                          background: '#7c3aed22', border: '1px solid #7c3aed66',
                          color: 'var(--accent-blue)', borderRadius: 4, padding: '1px 6px', fontSize: 10.5,
                        }}>{selected.mitre_technique}</span>
                      </div>
                    )}
                  </div>
                </div>

                {/* Type-specific fields */}
                {renderNodeTypeFields(selected)}

                {/* Remaining raw properties */}
                {selected.detail && Object.keys(selected.detail).length > 0 && (
                  <div className="card" style={{ marginTop: 12 }}>
                    <div className="card-title">属性详情</div>
                    <dl style={{ margin: 0, display: 'flex', flexDirection: 'column', gap: 5 }}>
                      {Object.entries(selected.detail).map(([k, v]) => v != null && (
                        <div key={k} style={{
                          display: 'flex', justifyContent: 'space-between', fontSize: 11,
                          borderBottom: '1px solid rgba(255,255,255,.04)', paddingBottom: 3,
                        }}>
                          <dt style={{ color: 'var(--text-muted)', flexShrink: 0, marginRight: 8, fontStyle: 'normal' }}>{k}</dt>
                          <dd style={{
                            color: 'var(--text-secondary)', fontFamily: 'monospace',
                            wordBreak: 'break-all', textAlign: 'right', margin: 0,
                          }}>{String(v).slice(0, 80)}</dd>
                        </div>
                      ))}
                    </dl>
                  </div>
                )}

                {/* Connected edges */}
                {graph && (() => {
                  const connectedEdges = graph.edges.filter(
                    e => e.from === selected.id || e.to === selected.id
                  )
                  if (connectedEdges.length === 0) return null
                  return (
                    <div className="card" style={{ marginTop: 12 }}>
                      <div className="card-title">关联关系 ({connectedEdges.length})</div>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                        {connectedEdges.map(e => {
                          const isOut = e.from === selected.id
                          const other = isOut ? e.to : e.from
                          const otherNode = graph.nodes.find(n => n.id === other)
                          return (
                            <div key={e.id} style={{
                              display: 'flex', alignItems: 'center', gap: 6, fontSize: 11,
                              padding: '3px 0', borderBottom: '1px solid rgba(255,255,255,.04)',
                            }}>
                              <span style={{
                                color: isOut ? 'var(--accent-blue)' : 'var(--medium)',
                                fontFamily: 'monospace', fontSize: 9,
                              }}>{isOut ? '→' : '←'}</span>
                              <span style={{
                                color: EDGE_COLORS[e.relation] ?? 'var(--text-muted)',
                                fontSize: 9.5, minWidth: 80,
                              }}>{e.relation}</span>
                              <span style={{
                                color: 'var(--text-muted)', fontSize: 10, wordBreak: 'break-all',
                              }}>{otherNode?.label ?? other}</span>
                            </div>
                          )
                        })}
                      </div>
                    </div>
                  )
                })()}

                {/* Action buttons */}
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8, marginTop: 16 }}>
                  <button
                    className="btn-secondary"
                    style={{ fontSize: 12, width: '100%', textAlign: 'left' }}
                    onClick={() => navigate(`/alerts?keyword=${encodeURIComponent(selected.label)}`)}
                  >
                    🔍 在告警中搜索 →
                  </button>
                  <button
                    className="btn-secondary"
                    style={{ fontSize: 12, width: '100%', textAlign: 'left' }}
                    onClick={() => navigate(`/iocs?q=${encodeURIComponent(selected.label)}`)}
                  >
                    🛡 在IOC库中查找 →
                  </button>
                  <button
                    className={suspectNodes.has(selected.id) ? 'btn-primary' : 'btn-secondary'}
                    style={{
                      fontSize: 12, width: '100%', textAlign: 'left',
                      borderColor: suspectNodes.has(selected.id) ? 'var(--critical)' : undefined,
                      color: suspectNodes.has(selected.id) ? 'var(--critical)' : undefined,
                      background: suspectNodes.has(selected.id) ? '#ef444422' : undefined,
                    }}
                    onClick={() => toggleSuspect(selected.id)}
                  >
                    {suspectNodes.has(selected.id) ? '🚩 取消标记可疑' : '标记可疑 🚩'}
                  </button>
                </div>
              </div>
              </div>
            </div>
          )}
        </div>
        )}

        {/* ── Attack chain narrative panel ──────────────────────────────────── */}
        {hasGraph && showNarrative && (
          <div style={{
            borderTop: '1px solid var(--border)',
            background: 'var(--bg-card)',
            flexShrink: 0,
            maxHeight: 320,
            display: 'flex', flexDirection: 'column',
            overflow: 'hidden',
          }}>
            <div style={{
              padding: '8px 16px', borderBottom: '1px solid var(--border)',
              display: 'flex', alignItems: 'center', gap: 10,
            }}>
              <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>
                🔗 攻击链分析
              </span>
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                ({narrativeSteps.length} 步骤 · 拓扑序)
              </span>
              <div style={{ flex: 1 }} />
              <button
                className={aiSummaryLoading ? 'btn-secondary' : 'btn-primary'}
                style={{ fontSize: 11 }}
                onClick={handleAiSummary}
                disabled={aiSummaryLoading}
              >
                {aiSummaryLoading ? '⏳ 生成中...' : '🤖 AI生成摘要'}
              </button>
              <button
                className="btn-secondary"
                style={{ fontSize: 11 }}
                onClick={() => { setShowNarrative(false); setShowAiSummary(false) }}
              >✕</button>
            </div>

            <div style={{ flex: 1, overflowY: 'auto', padding: '10px 16px', display: 'flex', gap: 16, flexWrap: 'nowrap' }}>
              {/* Step list */}
              <div style={{ flex: 1, minWidth: 0 }}>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {narrativeSteps.length === 0 ? (
                    <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>无节点数据</span>
                  ) : narrativeSteps.map(step => (
                    <div
                      key={step.node.id}
                      style={{
                        display: 'flex', alignItems: 'flex-start', gap: 10,
                        padding: '6px 10px',
                        background: selected?.id === step.node.id ? 'rgba(79,163,224,0.1)' : 'rgba(255,255,255,0.02)',
                        border: `1px solid ${selected?.id === step.node.id ? '#4fa3e044' : 'transparent'}`,
                        borderRadius: 6, cursor: 'pointer',
                        transition: 'background 0.15s',
                      }}
                      onClick={() => { setSelected(step.node); setCmdlineExpanded(false) }}
                    >
                      <span style={{
                        flexShrink: 0,
                        width: 22, height: 22,
                        borderRadius: '50%',
                        background: (NODE_COLORS[step.node.type] ?? 'var(--text-muted)') + '33',
                        border: `1px solid ${NODE_COLORS[step.node.type] ?? 'var(--text-muted)'}`,
                        color: NODE_COLORS[step.node.type] ?? 'var(--text-muted)',
                        fontSize: 10, fontWeight: 700,
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                      }}>
                        {step.step}
                      </span>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ fontSize: 12, color: 'var(--text-primary)', lineHeight: 1.4 }}>
                          {step.text}
                        </div>
                        {step.mitre && (
                          <span style={{
                            display: 'inline-block', marginTop: 3,
                            background: '#7c3aed22', border: '1px solid #7c3aed55',
                            color: 'var(--accent-blue)', borderRadius: 3,
                            padding: '0 5px', fontSize: 10,
                          }}>
                            MITRE {step.mitre}
                          </span>
                        )}
                      </div>
                      <span style={{
                        fontSize: 11, color: 'var(--text-muted)', flexShrink: 0,
                        marginLeft: 4,
                      }}>
                        {NODE_ICONS[step.node.type] ?? '◻'}
                      </span>
                    </div>
                  ))}
                </div>
              </div>

              {/* AI summary block */}
              {showAiSummary && (
                <div style={{
                  width: 380, flexShrink: 0,
                  background: 'rgba(16,17,26,0.8)',
                  border: '1px solid #4fa3e044',
                  borderRadius: 8, padding: 14,
                  display: 'flex', flexDirection: 'column', gap: 8,
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
                    <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--accent-blue)' }}>🤖 AI摘要</span>
                    <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>— 模拟生成</span>
                    <button
                      className="btn-secondary"
                      style={{ fontSize: 10, padding: '1px 6px', marginLeft: 'auto' }}
                      onClick={() => setShowAiSummary(false)}
                    >✕</button>
                  </div>
                  <pre style={{
                    margin: 0, fontSize: 11,
                    color: 'var(--accent-blue)',
                    fontFamily: 'monospace',
                    whiteSpace: 'pre-wrap', wordBreak: 'break-word',
                    lineHeight: 1.6,
                    background: 'rgba(0,0,0,0.3)',
                    borderRadius: 6, padding: 10,
                    border: '1px solid rgba(79,163,224,0.15)',
                  }}>
                    {mockAiSummary}
                  </pre>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
