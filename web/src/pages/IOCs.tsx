import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '@/lib/api'
import type { PageMeta } from '@/lib/api'
import PageHeader from '@/components/PageHeader'

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

const TYPE_COLORS: Record<string, string> = {
  ip: '#4fa3e0', domain: '#a78bfa', url: '#00c896',
  hash: '#f9a825', email: '#fa582d', cve: '#ff7043',
  cidr: '#4fa3e0', registry: '#ff7043', user_agent: '#00c896', mutex: '#a78bfa',
}

const VERDICT_CONFIG: Record<string, { bg: string; color: string; label: string }> = {
  malicious:  { bg: 'rgba(229,57,53,.18)',   color: '#ef5350',  label: 'Malicious' },
  suspicious: { bg: 'rgba(255,111,0,.15)',   color: '#ffa726',  label: 'Suspicious' },
  benign:     { bg: 'rgba(67,160,71,.15)',   color: '#66bb6a',  label: 'Benign' },
  unknown:    { bg: 'rgba(84,110,122,.15)',  color: '#90a4ae',  label: 'Unknown' },
}

function VerdictBadge({ verdict }: { verdict: string }) {
  const cfg = VERDICT_CONFIG[verdict] ?? VERDICT_CONFIG.unknown
  return (
    <span className="verdict-badge" style={{ background: cfg.bg, color: cfg.color }}>
      {cfg.label}
    </span>
  )
}

function ConfBadge({ conf }: { conf: number }) {
  const color = conf >= 80 ? 'var(--critical)' : conf >= 60 ? 'var(--high)' : conf >= 40 ? 'var(--medium)' : 'var(--text-muted)'
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      <div style={{ flex: 1, height: 3, background: 'var(--border)', borderRadius: 2, maxWidth: 60 }}>
        <div style={{ height: 3, width: `${conf}%`, background: color, borderRadius: 2 }} />
      </div>
      <span style={{ fontSize: 11, color, fontWeight: 600 }}>{conf}%</span>
    </div>
  )
}

function fmtDate(iso: string) {
  if (!iso) return '-'
  return new Date(iso).toLocaleDateString('zh-CN')
}

export default function IOCs() {
  const navigate = useNavigate()
  const [items, setItems] = useState<IOC[]>([])
  const [meta, setMeta] = useState<PageMeta>({ page: 1, page_size: 20, total: 0, total_pages: 1 })
  const [page, setPage] = useState(1)
  const [typeFilter, setTypeFilter] = useState('')
  const [severityFilter, setSeverityFilter] = useState('')
  const [verdictFilter, setVerdictFilter] = useState('')
  const [search, setSearch] = useState('')
  const [loading, setLoading] = useState(false)
  const [selected, setSelected] = useState<IOC | null>(null)
  const [showAdd, setShowAdd] = useState(false)
  const [adding, setAdding] = useState(false)
  const [addForm, setAddForm] = useState({ type: 'ip', value: '', threat_name: '', severity: 'medium', verdict: 'malicious', confidence: '70', tags: '' })
  const mountedRef = useRef(false)

  function load(p = page) {
    setLoading(true)
    const params: any = { page: p, page_size: 20 }
    if (typeFilter) params.type = typeFilter
    if (severityFilter) params.severity = severityFilter
    if (verdictFilter) params.verdict = verdictFilter
    if (search) params.keyword = search
    api.get('/iocs', { params })
      .then(r => { setItems(r.data.data?.items ?? []); setMeta(r.data.data?.meta ?? meta) })
      .finally(() => setLoading(false))
  }

  useEffect(() => { load(page) }, [page])
  useEffect(() => {
    if (!mountedRef.current) { mountedRef.current = true; return }
    setPage(1); load(1)
  }, [typeFilter, severityFilter, verdictFilter])

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
      .then(() => { setShowAdd(false); setAddForm({ type: 'ip', value: '', threat_name: '', severity: 'medium', verdict: 'malicious', confidence: '70', tags: '' }); load(1) })
      .finally(() => setAdding(false))
  }

  function blockIOC(ioc: IOC) {
    api.patch(`/iocs/${ioc._key}`, { verdict: 'malicious', active: true })
      .then(() => load(page))
  }

  function huntIOC(ioc: IOC) {
    navigate(`/query?q=${encodeURIComponent(ioc.value)}`)
  }

  function exportCSV() {
    const rows = [['类型', 'Value', 'Verdict', '威胁名称', '严重程度', '置信度', 'Tags', 'Active'].join(',')]
    items.forEach(i => rows.push([i.type, i.value, i.verdict, i.threat_name, i.severity, i.confidence, (i.tags ?? []).join(';'), i.active].join(',')))
    const blob = new Blob([rows.join('\n')], { type: 'text/csv' })
    const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'iocs.csv'; a.click()
  }

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <PageHeader
        title="IOC 管理"
        subtitle={`· ${meta.total.toLocaleString()} indicators`}
        actions={<>
          <button className="btn-secondary" onClick={exportCSV}>导出</button>
          <button className="btn-secondary" onClick={() => {
            const input = document.createElement('input')
            input.type = 'file'; input.accept = '.csv,.json,.txt'
            input.onchange = (e) => {
              const file = (e.target as HTMLInputElement).files?.[0]
              if (!file) return
              const reader = new FileReader()
              reader.onload = (ev) => {
                const text = ev.target?.result as string
                const lines = text.split('\n').filter(Boolean)
                const iocs = lines.slice(1).map(l => {
                  const parts = l.split(',')
                  return { type: parts[0]?.trim() || 'ip', value: parts[1]?.trim() || '', verdict: parts[2]?.trim() || 'malicious', threat_name: parts[3]?.trim() || '', severity: parts[4]?.trim() || 'medium', confidence: parseInt(parts[5]) || 70, active: true }
                }).filter(i => i.value)
                if (iocs.length) api.post('/iocs/bulk', { iocs }).then(() => load(1))
              }
              reader.readAsText(file)
            }
            input.click()
          }}>批量导入</button>
          <button className="btn-primary" onClick={() => setShowAdd(true)}>+ 添加IOC</button>
        </>}
      />

      <div className="filter-bar">
        <input
          className="filter-input"
          placeholder="搜索IOC值、威胁名称..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && load(1)}
        />
        <select className="filter-select" value={typeFilter} onChange={e => setTypeFilter(e.target.value)}>
          <option value="">全部类型</option>
          <option value="ip">IP Address</option>
          <option value="domain">Domain</option>
          <option value="url">URL</option>
          <option value="hash">File Hash</option>
          <option value="email">Email</option>
          <option value="cve">CVE</option>
          <option value="cidr">CIDR</option>
          <option value="registry">Registry Key</option>
          <option value="user_agent">User Agent</option>
          <option value="mutex">Mutex</option>
        </select>
        <select className="filter-select" value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}>
          <option value="">全部严重程度</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
        <select className="filter-select" value={verdictFilter} onChange={e => setVerdictFilter(e.target.value)}>
          <option value="">All Verdict</option>
          <option value="malicious">Malicious</option>
          <option value="suspicious">Suspicious</option>
          <option value="benign">Benign</option>
          <option value="unknown">Unknown</option>
        </select>
      </div>

      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        <div className="data-table-wrap" style={{ flex: 1 }}>
          <table className="data-table">
            <thead>
              <tr>
                <th style={{ width: 36 }}><input type="checkbox" /></th>
                <th>类型</th>
                <th>Value</th>
                <th>Verdict</th>
                <th>威胁名称</th>
                <th>严重程度</th>
                <th>置信度</th>
                <th>标签</th>
                <th>状态</th>
                <th>创建时间</th>
              </tr>
            </thead>
            <tbody>
              {loading && <tr><td colSpan={10} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>加载中...</td></tr>}
              {!loading && items.length === 0 && <tr><td colSpan={10} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>暂无IOC</td></tr>}
              {items.map(ioc => (
                <tr key={ioc._key}
                  onClick={() => setSelected(selected?._key === ioc._key ? null : ioc)}
                  className={selected?._key === ioc._key ? 'selected' : ''}
                >
                  <td onClick={e => e.stopPropagation()}><input type="checkbox" /></td>
                  <td>
                    <span style={{
                      fontSize: 10.5, padding: '2px 8px', borderRadius: 3, fontWeight: 600,
                      background: `${TYPE_COLORS[ioc.type] ?? '#4fa3e0'}22`,
                      color: TYPE_COLORS[ioc.type] ?? '#4fa3e0',
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

        {selected && (
          <div style={{
            width: 360, borderLeft: '1px solid var(--border)', background: 'var(--bg-card)',
            display: 'flex', flexDirection: 'column', overflow: 'hidden', flexShrink: 0,
          }}>
            <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 4 }}>IOC Detail</div>
                <div style={{ fontFamily: 'monospace', fontSize: 12, color: 'var(--text-primary)', wordBreak: 'break-all', maxWidth: 270 }}>{selected.value}</div>
              </div>
              <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px', flexShrink: 0 }} onClick={() => setSelected(null)}>✕</button>
            </div>
            <div style={{ flex: 1, overflowY: 'auto', padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div className="card">
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 12, flexWrap: 'wrap' }}>
                  <span style={{
                    fontSize: 10.5, padding: '2px 8px', borderRadius: 3, fontWeight: 600,
                    background: `${TYPE_COLORS[selected.type] ?? '#4fa3e0'}22`,
                    color: TYPE_COLORS[selected.type] ?? '#4fa3e0', textTransform: 'uppercase',
                  }}>{selected.type}</span>
                  <VerdictBadge verdict={selected.verdict || 'unknown'} />
                  <span className={`sev-badge ${selected.severity}`}>{selected.severity}</span>
                </div>
                {[
                  ['威胁名称', selected.threat_name || '-'],
                  ['Source', selected.source || '-'],
                  ['置信度', `${selected.confidence ?? 0}%`],
                  ['状态', selected.active ? 'Active' : 'Inactive'],
                  ['First Seen', fmtDate(selected.first_seen)],
                  ['Last Seen', fmtDate(selected.last_seen)],
                  ['创建时间', fmtDate(selected.created_at)],
                ].map(([k, v]) => (
                  <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11.5, borderBottom: '1px solid rgba(255,255,255,.04)', paddingBottom: 4, marginBottom: 4 }}>
                    <span style={{ color: 'var(--text-muted)' }}>{k}</span>
                    <span style={{ color: 'var(--text-secondary)', fontFamily: 'monospace' }}>{v}</span>
                  </div>
                ))}
              </div>

              {selected.description && (
                <div className="card">
                  <div className="card-title">描述</div>
                  <div style={{ fontSize: 11.5, color: 'var(--text-secondary)', lineHeight: 1.6 }}>{selected.description}</div>
                </div>
              )}

              {(selected.tags ?? []).length > 0 && (
                <div className="card">
                  <div className="card-title">标签</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                    {selected.tags.map(tag => (
                      <span key={tag} style={{ fontSize: 10.5, padding: '2px 8px', background: 'var(--bg-card2)', border: '1px solid var(--border-light)', borderRadius: 3 }}>{tag}</span>
                    ))}
                  </div>
                </div>
              )}

              <div style={{ display: 'flex', gap: 8 }}>
                <button className="btn-primary" style={{ flex: 1, fontSize: 11 }} onClick={() => blockIOC(selected)}>Block IOC</button>
                <button className="btn-secondary" style={{ flex: 1, fontSize: 11 }} onClick={() => huntIOC(selected)}>Hunt for IOC</button>
              </div>
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

      {showAdd && (
        <>
          <div onClick={() => setShowAdd(false)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.5)', zIndex: 400 }} />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 460, background: 'var(--bg-card)', border: '1px solid var(--border)',
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
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>Verdict</div>
                  <select className="filter-select" style={{ width: '100%' }} value={addForm.verdict} onChange={e => setAddForm(p => ({ ...p, verdict: e.target.value }))}>
                    <option value="malicious">Malicious</option>
                    <option value="suspicious">Suspicious</option>
                    <option value="benign">Benign</option>
                    <option value="unknown">Unknown</option>
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
    </div>
  )
}
