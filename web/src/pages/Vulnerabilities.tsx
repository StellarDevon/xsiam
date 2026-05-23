import { useEffect, useRef, useState } from 'react'
import api from '@/lib/api'
import type { PageMeta } from '@/lib/api'
import PageHeader from '@/components/PageHeader'

interface Vuln {
  _key: string
  cve_id: string
  title: string
  severity: string
  cvss_score: number
  status: string
  affected_assets: string[]
  description: string
  fix: string
  published_at: string
  created_at: string
}

interface VulnStats {
  total: number
  critical: number
  high: number
  medium: number
  low: number
  patched: number
}

const BLANK_FORM = { cve_id: '', title: '', severity: 'high', cvss_score: '', description: '', fix: '', affected_assets: '' }

export default function Vulnerabilities() {
  const [items, setItems] = useState<Vuln[]>([])
  const [meta, setMeta] = useState<PageMeta>({ page:1, page_size:20, total:0, total_pages:1 })
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [severityFilter, setSeverityFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<Vuln | null>(null)
  const [stats, setStats] = useState<VulnStats | null>(null)

  const [showModal, setShowModal] = useState(false)
  const [editTarget, setEditTarget] = useState<Vuln | null>(null)
  const [form, setForm] = useState(BLANK_FORM)
  const [saving, setSaving] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<Vuln | null>(null)
  const mountedRef = useRef(false)

  function load(p = page) {
    setLoading(true)
    const params: any = { page: p, page_size: 20 }
    if (severityFilter) params.severity = severityFilter
    if (statusFilter) params.fix_status = statusFilter
    if (search) params.keyword = search
    api.get('/vulnerabilities', { params })
      .then(r => { setItems(r.data.data?.items ?? []); setMeta(r.data.data?.meta ?? meta) })
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    api.get('/vulnerabilities/stats').then(r => setStats(r.data.data)).catch(() => {})
  }, [])

  useEffect(() => { load(page) }, [page])
  useEffect(() => {
    if (!mountedRef.current) { mountedRef.current = true; return }
    setPage(1); load(1)
  }, [severityFilter, statusFilter])

  function cvssColor(score: number) {
    if (score >= 9) return 'var(--critical)'
    if (score >= 7) return 'var(--high)'
    if (score >= 4) return 'var(--medium)'
    return 'var(--low)'
  }

  function patchStatus(v: Vuln, status: string) {
    api.patch(`/vulnerabilities/${v._key}`, { status }).then(() => {
      setItems(prev => prev.map(x => x._key === v._key ? { ...x, status } : x))
      if (selected?._key === v._key) setSelected({ ...v, status })
    })
  }

  function deleteVuln(v: Vuln) { setDeleteTarget(v) }
  function doDelete() {
    if (!deleteTarget) return
    api.delete(`/vulnerabilities/${deleteTarget._key}`).then(() => { setSelected(null); setDeleteTarget(null); load(1) })
  }

  function openCreate() {
    setEditTarget(null)
    setForm(BLANK_FORM)
    setShowModal(true)
  }

  function openEdit(v: Vuln) {
    setEditTarget(v)
    setForm({
      cve_id: v.cve_id || '',
      title: v.title || '',
      severity: v.severity || 'high',
      cvss_score: String(v.cvss_score ?? ''),
      description: v.description || '',
      fix: v.fix || '',
      affected_assets: (v.affected_assets ?? []).join(', '),
    })
    setShowModal(true)
  }

  function saveVuln() {
    if (!form.title.trim()) return
    setSaving(true)
    const body = {
      cve_id: form.cve_id,
      title: form.title,
      severity: form.severity,
      cvss_score: parseFloat(form.cvss_score) || 0,
      description: form.description,
      fix: form.fix,
      affected_assets: form.affected_assets ? form.affected_assets.split(',').map(s => s.trim()).filter(Boolean) : [],
      status: 'open',
    }
    const req = editTarget
      ? api.patch(`/vulnerabilities/${editTarget._key}`, body)
      : api.post('/vulnerabilities', body)
    req.then(() => { setShowModal(false); load(1); api.get('/vulnerabilities/stats').then(r => setStats(r.data.data)).catch(() => {}) })
      .finally(() => setSaving(false))
  }

  const critSevCount = (stats?.critical ?? 0) + (stats?.high ?? 0) + (stats?.medium ?? 0) + (stats?.low ?? 0) || 1

  return (
    <div style={{ height:'100%', display:'flex', flexDirection:'column', overflow:'hidden' }}>
      <PageHeader
        title="漏洞管理"
        subtitle={`${meta.total.toLocaleString()} 条 · ${(stats?.critical ?? 0)} 个严重 · ${(stats?.patched ?? 0)} 已修复`}
        actions={<>
          <button className="btn-secondary" onClick={() => {
            const rows = [['CVE ID', 'Title', '严重程度', 'CVSS', '状态', '受影响资产'].join(',')]
            items.forEach(v => rows.push([v.cve_id, `"${v.title}"`, v.severity, v.cvss_score, v.status, (v.affected_assets ?? []).join(';')].join(',')))
            const blob = new Blob([rows.join('\n')], { type: 'text/csv' })
            const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'vuln_assessment.csv'; a.click()
          }}>&#8659;Vuln Assessment</button>
          <button className="btn-primary" onClick={openCreate}>+ Add CVE</button>
        </>}
      />

      {/* Severity distribution bar */}
      {stats && (
        <div style={{ padding:'10px 20px', borderBottom:'1px solid var(--border)', background:'var(--bg-sidebar)', flexShrink:0 }}>
          <div style={{ display:'flex', gap:16, alignItems:'center' }}>
            {[
              { label:'严重', count: stats.critical, color:'#e53935' },
              { label:'高危',     count: stats.high,     color:'#ff6f00' },
              { label:'中危',   count: stats.medium,   color:'#f9a825' },
              { label:'低危',      count: stats.low,      color:'#00897b' },
            ].map(s => (
              <div key={s.label} style={{ display:'flex', alignItems:'center', gap:8, flex:1 }}>
                <span style={{ fontSize:10.5, color:s.color, minWidth:44 }}>{s.label}</span>
                <div style={{ flex:1, height:12, background:'var(--bg-secondary)', borderRadius:2, overflow:'hidden' }}>
                  <div style={{ width:`${(s.count / critSevCount)*100}%`, height:'100%', background:s.color, borderRadius:2 }} />
                </div>
                <span style={{ fontSize:11.5, fontWeight:700, color:s.color, minWidth:28 }}>{s.count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      <div className="filter-bar">
        <input
          className="filter-input"
          placeholder="搜索CVE编号、标题..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && load(1)}
        />
        <select className="filter-select" value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}>
          <option value="">全部严重程度</option>
          <option value="critical">严重</option>
          <option value="high">高危</option>
          <option value="medium">中危</option>
          <option value="low">低危</option>
        </select>
        <select className="filter-select" value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
          <option value="">全部状态</option>
          <option value="open">待修复</option>
          <option value="in_progress">修复中</option>
          <option value="patched">已修复</option>
          <option value="mitigated">已缓解</option>
          <option value="accepted">接受风险</option>
        </select>
      </div>

      <div style={{ display:'flex', flex:1, overflow:'hidden' }}>
        <div className="data-table-wrap" style={{ flex:1 }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>CVE编号</th>
                <th>标题</th>
                <th>严重程度</th>
                <th>CVSS</th>
                <th>状态</th>
                <th>受影响资产</th>
                <th>发布时间</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {loading && <tr><td colSpan={8} style={{ textAlign:'center', color:'var(--text-muted)', padding:24 }}>加载中...</td></tr>}
              {!loading && items.length === 0 && <tr><td colSpan={8} style={{ textAlign:'center', color:'var(--text-muted)', padding:24 }}>暂无漏洞</td></tr>}
              {items.map(v => (
                <tr key={v._key} onClick={() => setSelected(selected?._key === v._key ? null : v)} className={selected?._key === v._key ? 'selected' : ''}>
                  <td style={{ fontFamily:'monospace', fontSize:12, color:'var(--accent-orange)', whiteSpace:'nowrap' }}>{v.cve_id || '-'}</td>
                  <td style={{ fontSize:12.5, maxWidth:300, overflow:'hidden', textOverflow:'ellipsis', whiteSpace:'nowrap' }}>{v.title}</td>
                  <td><span className={`sev-badge ${v.severity}`}>{v.severity}</span></td>
                  <td>
                    <span style={{ fontSize:12, fontWeight:700, color: cvssColor(v.cvss_score ?? 0) }}>
                      {v.cvss_score?.toFixed(1) ?? '-'}
                    </span>
                  </td>
                  <td>
                    <span style={{ fontSize:11.5, textTransform:'capitalize', color:
                      v.status === 'open' ? 'var(--critical)' :
                      v.status === 'patched' ? 'var(--accent-green)' :
                      v.status === 'in_progress' ? 'var(--accent-blue)' :
                      'var(--text-muted)'
                    }}>
                      {(v.status || 'open').replace('_', ' ')}
                    </span>
                  </td>
                  <td style={{ fontSize:11, color:'var(--text-secondary)' }}>
                    {v.affected_assets?.length ? `${v.affected_assets.length} asset${v.affected_assets.length > 1 ? 's' : ''}` : '-'}
                  </td>
                  <td style={{ fontSize:11, color:'var(--text-muted)' }}>
                    {v.published_at ? new Date(v.published_at).toLocaleDateString('zh-CN') : '-'}
                  </td>
                  <td onClick={e => e.stopPropagation()}>
                    <div style={{ display:'flex', gap:4 }}>
                      <button className="btn-secondary" style={{ fontSize:11, padding:'2px 7px' }} onClick={() => openEdit(v)}>编辑</button>
                      <button className="btn-secondary" style={{ fontSize:11, padding:'2px 7px', color:'var(--critical)' }} onClick={() => deleteVuln(v)}>删</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {selected && (
          <div style={{ width:360, borderLeft:'1px solid var(--border)', background:'var(--bg-card)', display:'flex', flexDirection:'column', overflow:'hidden', flexShrink:0 }}>
            <div style={{ padding:'12px 16px', borderBottom:'1px solid var(--border)', display:'flex', justifyContent:'space-between', alignItems:'center' }}>
              <span style={{ fontSize:12, fontWeight:600, fontFamily:'monospace', color:'var(--accent-orange)' }}>{selected.cve_id}</span>
              <button className="btn-secondary" style={{ fontSize:11, padding:'2px 8px' }} onClick={() => setSelected(null)}>✕</button>
            </div>
            <div style={{ flex:1, overflowY:'auto', padding:16, display:'flex', flexDirection:'column', gap:12 }}>
              <div className="card">
                <div style={{ display:'flex', gap:8, marginBottom:10, flexWrap:'wrap' }}>
                  <span className={`sev-badge ${selected.severity}`}>{selected.severity}</span>
                  <span style={{ fontSize:12, fontWeight:700, color:cvssColor(selected.cvss_score ?? 0) }}>CVSS {selected.cvss_score?.toFixed(1)}</span>
                  <span style={{ fontSize:11.5, color:
                    selected.status === 'open' ? 'var(--critical)' :
                    selected.status === '已修复' ? 'var(--accent-green)' :
                    selected.status === 'in_progress' ? 'var(--accent-blue)' : 'var(--text-muted)',
                    textTransform:'capitalize',
                  }}>{(selected.status || 'open').replace('_', ' ')}</span>
                </div>
                <div style={{ fontSize:13, fontWeight:600, marginBottom:8 }}>{selected.title}</div>
                {selected.description && (
                  <div style={{ fontSize:11.5, color:'var(--text-secondary)', lineHeight:1.6 }}>{selected.description}</div>
                )}
              </div>
              {selected.fix && (
                <div className="card">
                  <div className="card-title">Remediation</div>
                  <div style={{ fontSize:11.5, color:'var(--text-secondary)', lineHeight:1.6 }}>{selected.fix}</div>
                </div>
              )}
              {(selected.affected_assets?.length ?? 0) > 0 && (
                <div className="card">
                  <div className="card-title">受影响资产 ({selected.affected_assets.length})</div>
                  <div style={{ display:'flex', flexDirection:'column', gap:4 }}>
                    {selected.affected_assets.slice(0, 8).map(a => (
                      <div key={a} style={{ fontFamily:'monospace', fontSize:11, color:'var(--text-secondary)' }}>{a}</div>
                    ))}
                    {selected.affected_assets.length > 8 && (
                      <div style={{ fontSize:11, color:'var(--text-muted)' }}>+{selected.affected_assets.length - 8} more</div>
                    )}
                  </div>
                </div>
              )}
              <div style={{ display:'flex', gap:8 }}>
                {selected.status !== 'in_progress' && (
                  <button className="btn-primary" style={{ flex:1, fontSize:11 }} onClick={() => patchStatus(selected, 'in_progress')}>Mark In Progress</button>
                )}
                {selected.status !== 'accepted' && (
                  <button className="btn-secondary" style={{ flex:1, fontSize:11 }} onClick={() => patchStatus(selected, 'accepted')}>Accept Risk</button>
                )}
                {selected.status !== '已修复' && (
                  <button className="btn-secondary" style={{ flex:1, fontSize:11, color:'var(--accent-green)' }} onClick={() => patchStatus(selected, 'patched')}>Mark Patched</button>
                )}
              </div>
              <div style={{ display:'flex', gap:8 }}>
                <button className="btn-secondary" style={{ flex:1, fontSize:11 }} onClick={() => openEdit(selected)}>编辑</button>
                <button className="btn-secondary" style={{ flex:1, fontSize:11, color:'var(--critical)' }} onClick={() => deleteVuln(selected)}>删除</button>
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="pagination">
        <button className="page-btn" disabled={page <= 1} onClick={() => setPage(p => p-1)}>&#8249;</button>
        <span>{page} / {meta.total_pages || 1}</span>
        <button className="page-btn" disabled={page >= meta.total_pages} onClick={() => setPage(p => p+1)}>&#8250;</button>
        <span style={{ marginLeft:8 }}>{meta.total} 条</span>
      </div>

      {/* Create / Edit Modal */}
      {showModal && (
        <>
          <div onClick={() => setShowModal(false)} style={{ position:'fixed', inset:0, background:'rgba(0,0,0,.5)', zIndex:400 }} />
          <div style={{
            position:'fixed', top:'50%', left:'50%', transform:'translate(-50%,-50%)',
            width:520, background:'var(--bg-card)', border:'1px solid var(--border)',
            borderRadius:8, zIndex:500, padding:24,
          }}>
            <div style={{ fontSize:15, fontWeight:600, marginBottom:20 }}>{editTarget ? '编辑漏洞' : '添加漏洞'}</div>
            <div style={{ display:'flex', flexDirection:'column', gap:12 }}>
              <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:12 }}>
                {[
                  { label:'CVE ID', key:'cve_id', ph:'CVE-2024-1234' },
                  { label:'CVSS评分', key:'cvss_score', ph:'9.8' },
                ].map(f => (
                  <div key={f.key}>
                    <div style={{ fontSize:11, color:'var(--text-muted)', marginBottom:4 }}>{f.label}</div>
                    <input className="filter-input" style={{ width:'100%', boxSizing:'border-box' }} placeholder={f.ph}
                      value={(form as any)[f.key]} onChange={e => setForm(p => ({ ...p, [f.key]: e.target.value }))} />
                  </div>
                ))}
              </div>
              <div>
                <div style={{ fontSize:11, color:'var(--text-muted)', marginBottom:4 }}>标题 *</div>
                <input className="filter-input" style={{ width:'100%', boxSizing:'border-box' }} placeholder="如：远程代码执行..."
                  value={form.title} onChange={e => setForm(p => ({ ...p, title: e.target.value }))} />
              </div>
              <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:12 }}>
                <div>
                  <div style={{ fontSize:11, color:'var(--text-muted)', marginBottom:4 }}>严重程度</div>
                  <select className="filter-select" style={{ width:'100%' }} value={form.severity} onChange={e => setForm(p => ({ ...p, severity: e.target.value }))}>
                    <option value="critical">严重</option>
                    <option value="high">高危</option>
                    <option value="medium">中危</option>
                    <option value="low">低危</option>
                  </select>
                </div>
                <div>
                  <div style={{ fontSize:11, color:'var(--text-muted)', marginBottom:4 }}>受影响资产 (comma-sep)</div>
                  <input className="filter-input" style={{ width:'100%', boxSizing:'border-box' }} placeholder="WKSTN-001, SRV-DB-01"
                    value={form.affected_assets} onChange={e => setForm(p => ({ ...p, affected_assets: e.target.value }))} />
                </div>
              </div>
              <div>
                <div style={{ fontSize:11, color:'var(--text-muted)', marginBottom:4 }}>描述</div>
                <textarea className="filter-input" style={{ width:'100%', boxSizing:'border-box', minHeight:60, resize:'vertical' }}
                  placeholder="漏洞描述..." value={form.description}
                  onChange={e => setForm(p => ({ ...p, description: e.target.value }))} />
              </div>
              <div>
                <div style={{ fontSize:11, color:'var(--text-muted)', marginBottom:4 }}>Remediation / Fix</div>
                <textarea className="filter-input" style={{ width:'100%', boxSizing:'border-box', minHeight:60, resize:'vertical' }}
                  placeholder="应用补丁KB..." value={form.fix}
                  onChange={e => setForm(p => ({ ...p, fix: e.target.value }))} />
              </div>
              <div style={{ display:'flex', gap:10, marginTop:8 }}>
                <button className="btn-secondary" style={{ flex:1 }} onClick={() => setShowModal(false)}>取消</button>
                <button className="btn-primary" style={{ flex:1 }} disabled={saving || !form.title.trim()} onClick={saveVuln}>
                  {saving ? '保存中...' : editTarget ? '保存修改' : '添加漏洞'}
                </button>
              </div>
            </div>
          </div>
        </>
      )}

      {deleteTarget && (
        <>
          <div onClick={() => setDeleteTarget(null)} style={{ position:'fixed', inset:0, background:'rgba(0,0,0,.5)', zIndex:400 }} />
          <div style={{ position:'fixed', top:'50%', left:'50%', transform:'translate(-50%,-50%)', width:360, background:'var(--bg-card)', border:'1px solid var(--border)', borderRadius:8, zIndex:500, padding:24 }}>
            <div style={{ fontSize:15, fontWeight:600, marginBottom:12 }}>确认删除</div>
            <div style={{ fontSize:13, color:'var(--text-secondary)', marginBottom:20 }}>
              确定要删除漏洞 <strong style={{ color:'var(--accent-orange)', fontFamily:'monospace' }}>{deleteTarget.cve_id || deleteTarget.title}</strong> 吗？
            </div>
            <div style={{ display:'flex', gap:10 }}>
              <button className="btn-secondary" style={{ flex:1 }} onClick={() => setDeleteTarget(null)}>取消</button>
              <button className="btn-primary" style={{ flex:1, background:'var(--critical)', borderColor:'var(--critical)' }} onClick={doDelete}>确认删除</button>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
