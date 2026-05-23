import { useEffect, useState, useRef, useCallback } from 'react'
import api from '@/lib/api'
import PageHeader from '@/components/PageHeader'

interface GraphNode {
  id: string
  type: string
  label: string
  detail: Record<string, any>
  is_root?: boolean
  severity?: string
}

interface GraphEdge {
  id: string
  from: string
  to: string
  relation: string
}

interface Graph {
  节点: GraphNode[]
  边: GraphEdge[]
  incident_id: string
}

// Node type colors
const NODE_COLORS: Record<string, string> = {
  Process: '#4fa3e0',
  File: '#f9a825',
  Network: '#43a047',
  Registry: '#ff7043',
  User: '#9c27b0',
  Alert: '#e53935',
  Asset: '#546e7a',
}

const NODE_ICONS: Record<string, string> = {
  Process: '⚠️', File: '📋', Network: '🌐',
  Registry: '🔑', User: '💁', Alert: '⚠️', Asset: '🗼',
}

// Minimal force-directed layout (no external lib needed)
function simpleLayout(节点: GraphNode[], 边: GraphEdge[]) {
  const W = 900, H = 560
  const pos: Record<string, { x: number; y: number }> = {}

  // Start with random positions
  节点.forEach((n, i) => {
    pos[n.id] = { x: 80 + (i % 8) * 100, y: 80 + Math.floor(i / 8) * 120 }
  })

  // Very simple force: repel 节点, attract connected pairs
  for (let iter = 0; iter < 60; iter++) {
    const force: Record<string, { fx: number; fy: number }> = {}
    节点.forEach(n => { force[n.id] = { fx: 0, fy: 0 } })

    // Repulsion
    for (let i = 0; i < 节点.length; i++) {
      for (let j = i + 1; j < 节点.length; j++) {
        const dx = pos[节点[i].id].x - pos[节点[j].id].x
        const dy = pos[节点[i].id].y - pos[节点[j].id].y
        const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1)
        const rep = 3000 / (dist * dist)
        force[节点[i].id].fx += (dx / dist) * rep
        force[节点[i].id].fy += (dy / dist) * rep
        force[节点[j].id].fx -= (dx / dist) * rep
        force[节点[j].id].fy -= (dy / dist) * rep
      }
    }

    // Attraction along 边
    边.forEach(e => {
      if (!pos[e.from] || !pos[e.to]) return
      const dx = pos[e.to].x - pos[e.from].x
      const dy = pos[e.to].y - pos[e.from].y
      const dist = Math.max(Math.sqrt(dx * dx + dy * dy), 1)
      const att = (dist - 160) * 0.04
      force[e.from].fx += (dx / dist) * att
      force[e.from].fy += (dy / dist) * att
      force[e.to].fx -= (dx / dist) * att
      force[e.to].fy -= (dy / dist) * att
    })

    // Apply
    节点.forEach(n => {
      pos[n.id].x = Math.max(40, Math.min(W - 40, pos[n.id].x + force[n.id].fx * 0.3))
      pos[n.id].y = Math.max(40, Math.min(H - 40, pos[n.id].y + force[n.id].fy * 0.3))
    })
  }

  return pos
}

export default function CausalityGraph() {
  const [incidentId, setIncidentId] = useState('')
  const [graph, setGraph] = useState<Graph | null>(null)
  const [pos, setPos] = useState<Record<string, { x: number; y: number }>>({})
  const [loading, setLoading] = useState(false)
  const [selected, setSelected] = useState<GraphNode | null>(null)
  const [recentIncidents, setRecentIncidents] = useState<Array<{ _key: string; title: string }>>([])
  const svgRef = useRef<SVGSVGElement>(null)
  const [pan, setPan] = useState({ x: 0, y: 0 })
  const [zoom, setZoom] = useState(1)
  const dragging = useRef(false)
  const lastMouse = useRef({ x: 0, y: 0 })

  useEffect(() => {
    api.get('/incidents', { params: { page: 1, page_size: 10, status: 'active' } })
      .then(r => setRecentIncidents(r.data.data?.items ?? []))
  }, [])

  function loadGraph(id: string) {
    if (!id) return
    setLoading(true)
    setSelected(null)
    api.get(`/incidents/${id}/graph`)
      .then(r => {
        const g: Graph = r.data.data
        setGraph(g)
        const p = simpleLayout(g.节点 ?? [], g.边 ?? [])
        setPos(p)
        setPan({ x: 0, y: 0 })
        setZoom(1)
      })
      .catch(() => setGraph({ 节点: [], 边: [], incident_id: id }))
      .finally(() => setLoading(false))
  }

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
    setZoom(z => Math.max(0.3, Math.min(2.5, z - e.deltaY * 0.001)))
  }, [])

  const EDGE_COLORS: Record<string, string> = {
    spawned: '#4fa3e0', wrote_file: '#f9a825', executed_file: '#ff7043',
    connected_to: '#43a047', modified_registry: '#ff7043',
    lateral_move_to: '#e53935', triggered_alert: '#e5393588',
    logged_in_as: '#9c27b0',
  }

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <PageHeader
        title="溯源图"
        subtitle={graph ? `· ${graph.节点?.length ?? 0} 节点, ${graph.边?.length ?? 0} 边` : undefined}
        actions={<>
          <select
            className="filter-select"
            style={{ minWidth: 240 }}
            value={incidentId}
            onChange={e => { setIncidentId(e.target.value); loadGraph(e.target.value) }}
          >
            <option value="">...Select Incident ...</option>
            {recentIncidents.map(inc => (
              <option key={inc._key} value={inc._key}>{inc.title || inc._key}</option>
            ))}
          </select>
          <input
            className="filter-input"
            style={{ width: 160 }}
            placeholder="事件ID..."
            value={incidentId}
            onChange={e => setIncidentId(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && loadGraph(incidentId)}
          />
          <button className="btn-primary" onClick={() => loadGraph(incidentId)} disabled={loading || !incidentId}>
            {loading ? '加载中...' : '加载图谱'}
          </button>
        </>}
      />

      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        {/* Graph canvas */}
        <div style={{
          flex: 1, position: 'relative', overflow: 'hidden', background: 'var(--bg-secondary)',
          backgroundImage: 'radial-gradient(circle, #1a1b24 1px, transparent 1px)',
          backgroundSize: '32px 32px',
        }}>
          {!graph && !loading && (
            <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 12 }}>
              <span style={{ fontSize: 40, opacity: 0.2 }}>📩</span>
              <span style={{ color: 'var(--text-muted)', fontSize: 13 }}>选择一个事件以加载其溯源图</span>
            </div>
          )}
          {loading && (
            <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              <span style={{ color: 'var(--text-muted)', fontSize: 13 }}>Computing graph layout...</span>
            </div>
          )}
          {graph && !loading && (
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
                  <polygon points="0 0, 8 3, 0 6" fill="#ffffff30" />
                </marker>
              </defs>
              <g transform={`translate(${pan.x},${pan.y}) scale(${zoom})`}>
                {/* Edges */}
                {(graph.边 ?? []).map(e => {
                  const from = pos[e.from]
                  const to = pos[e.to]
                  if (!from || !to) return null
                  const color = EDGE_COLORS[e.relation] ?? '#ffffff30'
                  return (
                    <g key={e.id}>
                      <line
                        x1={from.x} y1={from.y} x2={to.x} y2={to.y}
                        stroke={color} strokeWidth={1.5} strokeOpacity={0.5}
                        markerEnd="url(#arrowhead)"
                      />
                      <text
                        x={(from.x + to.x) / 2} y={(from.y + to.y) / 2 - 4}
                        fontSize={9} fill={color} textAnchor="middle" opacity={0.7}
                        style={{ pointerEvents: 'none' }}
                      >{e.relation}</text>
                    </g>
                  )
                })}

                {/* Nodes */}
                {(graph.节点 ?? []).map(n => {
                  const p = pos[n.id]
                  if (!p) return null
                  const color = n.is_root ? '#e53935' : (NODE_COLORS[n.type] ?? '#607d8b')
                  const isSelected = selected?.id === n.id
                  return (
                    <g
                      key={n.id}
                      className="graph-node"
                      transform={`translate(${p.x},${p.y})`}
                      style={{ cursor: 'pointer' }}
                      onClick={() => setSelected(isSelected ? null : n)}
                    >
                      <circle
                        r={n.is_root ? 22 : 18}
                        fill={color + '33'}
                        stroke={isSelected ? '#fff' : color}
                        strokeWidth={isSelected ? 2.5 : 1.5}
                        filter={n.is_root ? `drop-shadow(0 0 8px ${color})` : undefined}
                      />
                      <text fontSize={n.is_root ? 14 : 12} textAnchor="middle" dominantBaseline="middle" style={{ pointerEvents: 'none' }}>
                        {NODE_ICONS[n.type] ?? '◻'}
                      </text>
                      <text
                        y={28} fontSize={9.5} fill="var(--text-secondary)" textAnchor="middle"
                        style={{ pointerEvents: 'none' }}
                      >{n.label?.slice(0, 18)}{(n.label?.length ?? 0) > 18 ? '...' : ''}</text>
                    </g>
                  )
                })}
              </g>
            </svg>
          )}

          {/* Zoom controls */}
          {graph && !loading && (
            <div style={{ position: 'absolute', bottom: 16, right: 16, display: 'flex', flexDirection: 'column', gap: 4 }}>
              <button className="btn-secondary" style={{ width: 28, height: 28, padding: 0, fontSize: 16, lineHeight: 1 }} onClick={() => setZoom(z => Math.min(2.5, z + 0.1))}>+</button>
              <button className="btn-secondary" style={{ width: 28, height: 28, padding: 0, fontSize: 12 }} onClick={() => { setZoom(1); setPan({ x: 0, y: 0 }) }}>+</button>
              <button className="btn-secondary" style={{ width: 28, height: 28, padding: 0, fontSize: 16, lineHeight: 1 }} onClick={() => setZoom(z => Math.max(0.3, z - 0.1))}>-</button>
            </div>
          )}

          {/* Legend */}
          {graph && !loading && (
            <div style={{
              position: 'absolute', bottom: 16, left: 16,
              background: 'rgba(16,17,26,.85)', border: '1px solid var(--border)',
              borderRadius: 6, padding: '8px 12px', display: 'flex', flexDirection: 'column', gap: 4,
            }}>
              {Object.entries(NODE_COLORS).map(([type, color]) => (
                <div key={type} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 10.5 }}>
                  <span style={{ width: 10, height: 10, borderRadius: '50%', background: color, display: 'inline-block', flexShrink: 0 }} />
                  <span style={{ color: 'var(--text-muted)' }}>{type}</span>
                </div>
              ))}
              <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 10.5, marginTop: 4, borderTop: '1px solid var(--border)', paddingTop: 4 }}>
                <span style={{ width: 10, height: 10, borderRadius: '50%', background: '#e53935', boxShadow: '0 0 6px #e53935', display: 'inline-block', flexShrink: 0 }} />
                <span style={{ color: 'var(--text-muted)' }}>Root Cause</span>
              </div>
            </div>
          )}
        </div>

        {/* Node detail panel */}
        {selected && (
          <div style={{
            width: 300, borderLeft: '1px solid var(--border)', background: 'var(--bg-card)',
            display: 'flex', flexDirection: 'column', overflow: 'hidden', flexShrink: 0,
          }}>
            <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontSize: 16 }}>{NODE_ICONS[selected.type] ?? '◻'}</span>
                <span style={{ fontSize: 12.5, fontWeight: 600 }}>{selected.type}</span>
              </div>
              <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px' }} onClick={() => setSelected(null)}>✕</button>
            </div>
            <div style={{ flex: 1, overflowY: 'auto', padding: 16 }}>
              <div className="card">
                <div className="card-title">节点信息</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11.5, borderBottom: '1px solid rgba(255,255,255,.04)', paddingBottom: 4 }}>
                    <span style={{ color: 'var(--text-muted)' }}>标签</span>
                    <span style={{ color: 'var(--text-secondary)', fontFamily: 'monospace', wordBreak: 'break-all', textAlign: 'right', maxWidth: 160 }}>{selected.label}</span>
                  </div>
                  {selected.is_root && (
                    <div style={{ fontSize: 11, color: 'var(--critical)', fontWeight: 600, display: 'flex', alignItems: 'center', gap: 4 }}>
                      <span>⚠️</span> 根因节点
                    </div>
                  )}
                  {selected.severity && (
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11.5 }}>
                      <span style={{ color: 'var(--text-muted)' }}>严重程度</span>
                      <span className={`sev-badge ${selected.severity}`}>{selected.severity}</span>
                    </div>
                  )}
                </div>
              </div>

              {selected.detail && Object.keys(selected.detail).length > 0 && (
                <div className="card" style={{ marginTop: 12 }}>
                  <div className="card-title">详情s</div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                    {Object.entries(selected.detail).map(([k, v]) => v != null && (
                      <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, borderBottom: '1px solid rgba(255,255,255,.04)', paddingBottom: 3 }}>
                        <span style={{ color: 'var(--text-muted)', flexShrink: 0, marginRight: 8 }}>{k}</span>
                        <span style={{ color: 'var(--text-secondary)', fontFamily: 'monospace', wordBreak: 'break-all', textAlign: 'right' }}>{String(v).slice(0, 80)}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
