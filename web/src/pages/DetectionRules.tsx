import { useEffect, useRef, useState } from 'react'
import api from '@/lib/api'
import type { PageMeta } from '@/lib/api'
import PageHeader from '@/components/PageHeader'

interface Rule {
  _key: string
  name: string
  description: string
  rule_type: string
  severity: string
  status: string
  query: string
  mitre_tactics: string[]
  mitre_techniques: string[]
  hit_count_7d: number
  hit_count_30d: number
  false_positive_rate: number
  created_at: string
  updated_at: string
}

function fmtDate(iso: string) {
  if (!iso) return '-'
  return new Date(iso).toLocaleDateString('zh-CN')
}

const BLANK_FORM = { name: '', description: '', rule_type: 'bioc', severity: 'high', status: 'draft', query: '', mitre_tactics: '', mitre_techniques: '' }

export default function DetectionRules() {
  const [items, setItems] = useState<Rule[]>([])
  const [meta, setMeta] = useState<PageMeta>({ page:1, page_size:20, total:0, total_pages:1 })
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [statusFilter, setStatusFilter] = useState('')
  const [typeFilter, setTypeFilter] = useState('')
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<Rule | null>(null)

  const [severityFilter, setSeverityFilter] = useState('')
  const [showModal, setShowModal] = useState(false)
  const [editTarget, setEditTarget] = useState<Rule | null>(null)
  const [form, setForm] = useState(BLANK_FORM)
  const [saving, setSaving] = useState(false)
  const [mitreModal, setMitreModal] = useState<Record<string, number> | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<Rule | null>(null)
  const mountedRef = useRef(false)

  function load(p = page) {
    setLoading(true)
    const params: any = { page: p, page_size: 20 }
    if (statusFilter) params.status = statusFilter
    if (typeFilter) params.rule_type = typeFilter
    if (severityFilter) params.severity = severityFilter
    if (search) params.keyword = search
    api.get('/detection_rules', { params })
      .then(r => { setItems(r.data.data?.items ?? []); setMeta(r.data.data?.meta ?? meta) })
      .finally(() => setLoading(false))
  }

  useEffect(() => { load(page) }, [page])
  useEffect(() => {
    if (!mountedRef.current) { mountedRef.current = true; return }
    setPage(1); load(1)
  }, [statusFilter, typeFilter, severityFilter])

  const statusColor: Record<string, string> = {
    active: 'var(--accent-green)',
    inactive: 'var(--text-muted)',
    testing: 'var(--accent-blue)',
    draft: 'var(--medium)',
    disabled: 'var(--text-muted)',
    deprecated: 'rgba(100,100,100,.6)',
  }

  function toggleStatus(rule: Rule) {
    const newStatus = rule.status === 'active' ? 'inactive' : 'active'
    api.patch(`/detection_rules/${rule._key}`, { status: newStatus }).then(() => load(page))
  }

  function deleteRule(rule: Rule) { setDeleteTarget(rule) }
  function doDeleteRule() {
    if (!deleteTarget) return
    api.delete(`/detection_rules/${deleteTarget._key}`).then(() => { setSelected(null); setDeleteTarget(null); load(1) })
  }

  function openCreate() {
    setEditTarget(null)
    setForm(BLANK_FORM)
    setShowModal(true)
  }

  function openEdit(rule: Rule) {
    setEditTarget(rule)
    setForm({
      name: rule.name,
      description: rule.description || '',
      rule_type: rule.rule_type || 'bioc',
      severity: rule.severity || 'high',
      status: rule.status || 'draft',
      query: rule.query || '',
      mitre_tactics: (rule.mitre_tactics ?? []).join(', '),
      mitre_techniques: (rule.mitre_techniques ?? []).join(', '),
    })
    setShowModal(true)
  }

  function saveRule() {
    if (!form.name.trim()) return
    setSaving(true)
    const body = {
      name: form.name,
      description: form.description,
      rule_type: form.rule_type,
      severity: form.severity,
      status: form.status,
      query: form.query,
      mitre_tactics: form.mitre_tactics ? form.mitre_tactics.split(',').map(s => s.trim()).filter(Boolean) : [],
      mitre_techniques: form.mitre_techniques ? form.mitre_techniques.split(',').map(s => s.trim()).filter(Boolean) : [],
    }
    const req = editTarget ? api.patch(`/detection_rules/${editTarget._key}`, body) : api.post('/detection_rules', body)
    req.then(() => { setShowModal(false); load(1) }).finally(() => setSaving(false))
  }

  return (
    <div style={{ height:'100%', display:'flex', flexDirection:'column', overflow:'hidden' }}>
      <PageHeader
        title="检测规则"
        subtitle={`· ${meta.total} rules`}
        actions={<>
          <button className="btn-secondary" onClick={() => api.get('/detection_rules/mitre_coverage').then(r => setMitreModal(r.data.data ?? {})).catch(() => setMitreModal({}))}>MITRE覆盖率</button>
          <button className="btn-primary" onClick={openCreate}>+ 新建规则</button>
        </>}
      />

      <div className="tab-bar">
        {[['全部',''],['活跃','active'],['测试中','testing'],['草稿','draft'],['停用','inactive']].map(([label, val]) => (
          <button key={label} className={`tab ${statusFilter === val ? 'active' : ''}`}
            onClick={() => setStatusFilter(val)}>
            {label}
          </button>
        ))}
      </div>

      <div className="filter-bar">
        <input
          className="filter-input"
          placeholder="Search rules—"
          value={search}
          onChange={e => setSearch(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && load(1)}
        />
        <select className="filter-select" value={typeFilter} onChange={e => setTypeFilter(e.target.value)}>
          <option value="">全部类型</option>
          <option value="bioc">BIOC (Behavioral)</option>
          <option value="ioc">IOC Match</option>
          <option value="ueba">UEBA (Anomaly)</option>
        </select>
        <select className="filter-select" value={severityFilter ?? ''} onChange={e => setSeverityFilter(e.target.value)}>
          <option value="">全部严重程度</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
        </select>
      </div>

      <div style={{ display:'flex', flex:1, overflow:'hidden' }}>
        <div className="data-table-wrap" style={{ flex:1 }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>名称</th>
                <th>类型</th>
                <th>严重程度</th>
                <th>状态</th>
                <th>MITRE战术</th>
                <th>命中 7天/30天</th>
                <th>创建时间</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {loading && <tr><td colSpan={8} style={{ textAlign:'center', color:'var(--text-muted)', padding:24 }}>加载中...</td></tr>}
              {!loading && items.length === 0 && <tr><td colSpan={8} style={{ textAlign:'center', color:'var(--text-muted)', padding:24 }}>暂无规则</td></tr>}
              {items.map(rule => (
                <tr key={rule._key} onClick={() => setSelected(selected?._key === rule._key ? null : rule)} className={selected?._key === rule._key ? 'selected' : ''}>
                  <td>
                    <div style={{ fontSize:12.5, fontWeight:500 }}>{rule.name}</div>
                    {rule.description && <div style={{ fontSize:11, color:'var(--text-muted)', marginTop:2 }}>{rule.description.slice(0,70)}{rule.description.length > 70 ? '...' : ''}</div>}
                  </td>
                  <td>
                    <span style={{
                      fontSize:10, padding:'2px 7px', borderRadius:3, fontFamily:'monospace', fontWeight:600,
                      background: rule.rule_type === 'bioc' ? 'rgba(79,163,224,.12)' : rule.rule_type === 'ioc' ? 'rgba(250,88,45,.1)' : 'rgba(167,139,250,.12)',
                      color: rule.rule_type === 'bioc' ? '#4fa3e0' : rule.rule_type === 'ioc' ? 'var(--accent-orange)' : '#a78bfa',
                    }}>
                      {(rule.rule_type || 'bioc').toUpperCase()}
                    </span>
                  </td>
                  <td><span className={`sev-badge ${rule.severity}`}>{rule.severity}</span></td>
                  <td>
                    <span style={{ display:'inline-flex', alignItems:'center', gap:5, fontSize:11.5 }}>
                      <span style={{
                        width:6, height:6, borderRadius:'50%', display:'inline-block',
                        background: statusColor[rule.status] ?? 'var(--text-muted)',
                        boxShadow: rule.status === 'active' ? '0 0 4px var(--accent-green)' : 'none',
                      }} />
                      {rule.status || 'draft'}
                    </span>
                  </td>
                  <td>
                    {(rule.mitre_tactics ?? []).slice(0,2).map(t => (
                      <span key={t} style={{ fontSize:9.5, padding:'1px 5px', background:'rgba(250,88,45,.1)', color:'var(--accent-orange)', border:'1px solid rgba(250,88,45,.2)', borderRadius:3, marginRight:3, fontFamily:'monospace' }}>{t}</span>
                    ))}
                    {(rule.mitre_tactics ?? []).length > 2 && <span style={{ fontSize:10, color:'var(--text-muted)' }}>+{rule.mitre_tactics.length-2}</span>}
                  </td>
                  <td style={{ fontSize:11.5, color:'var(--text-secondary)', fontFamily:'monospace' }}>
                    <span style={{ color: (rule.hit_count_7d ?? 0) > 0 ? 'var(--high)' : 'var(--text-muted)' }}>{rule.hit_count_7d ?? 0}</span>
                    <span style={{ color:'var(--text-muted)' }}> / {rule.hit_count_30d ?? 0}</span>
                  </td>
                  <td style={{ fontSize:11, color:'var(--text-muted)' }}>{fmtDate(rule.created_at)}</td>
                  <td onClick={e => e.stopPropagation()}>
                    <div style={{ display:'flex', gap:4 }}>
                      <button
                        className="btn-secondary"
                        style={{ fontSize:11, padding:'2px 8px', color: rule.status === 'active' ? 'var(--accent-green)' : 'var(--text-muted)' }}
                        onClick={() => toggleStatus(rule)}
                      >
                        {rule.status === 'active' ? 'Disable' : 'Enable'}
                      </button>
                      <button className="btn-secondary" style={{ fontSize:11, padding:'2px 7px' }} onClick={() => openEdit(rule)}>编辑</button>
                      <button className="btn-secondary" style={{ fontSize:11, padding:'2px 7px', color:'var(--critical)' }} onClick={() => deleteRule(rule)}>删</button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {selected && (
          <div style={{ width:400, borderLeft:'1px solid var(--border)', background:'var(--bg-card)', display:'flex', flexDirection:'column', overflow:'hidden', flexShrink:0 }}>
            <div style={{ padding:'12px 16px', borderBottom:'1px solid var(--border)', display:'flex', justifyContent:'space-between', alignItems:'center', flexShrink:0 }}>
              <div>
                <div style={{ fontSize:13, fontWeight:600, marginBottom:4 }}>{selected.name}</div>
                <div style={{ display:'flex', gap:6, alignItems:'center' }}>
                  <span className={`sev-badge ${selected.severity}`}>{selected.severity}</span>
                  <span style={{ fontSize:10.5, color: statusColor[selected.status], textTransform:'capitalize' }}>{selected.status}</span>
                </div>
              </div>
              <button className="btn-secondary" style={{ fontSize:11, padding:'2px 8px' }} onClick={() => setSelected(null)}>&#x2715;</button>
            </div>
            <div style={{ flex:1, overflowY:'auto', padding:16, display:'flex', flexDirection:'column', gap:12 }}>
              {selected.description && (
                <div className="card">
                  <div className="card-title">描述</div>
                  <p style={{ fontSize:12, color:'var(--text-secondary)', lineHeight:1.6 }}>{selected.description}</p>
                </div>
              )}
              <div className="card">
                <div className="card-title">统计</div>
                {[
                  ['规则类型', (selected.rule_type || 'bioc').toUpperCase()],
                  ['命中(7天)', String(selected.hit_count_7d ?? 0)],
                  ['命中(30天)', String(selected.hit_count_30d ?? 0)],
                  ['误报率', selected.false_positive_rate != null ? `${selected.false_positive_rate.toFixed(1)}%` : '-'],
                  ['创建时间', fmtDate(selected.created_at)],
                  ['更新时间', fmtDate(selected.updated_at)],
                ].map(([k, v]) => (
                  <div key={k} style={{ display:'flex', justifyContent:'space-between', fontSize:11.5, borderBottom:'1px solid rgba(255,255,255,.04)', paddingBottom:4, marginBottom:4 }}>
                    <span style={{ color:'var(--text-muted)' }}>{k}</span>
                    <span style={{ color:'var(--text-secondary)', fontFamily:'monospace' }}>{v}</span>
                  </div>
                ))}
              </div>
              {selected.query && (
                <div className="card">
                  <div className="card-title">SPL2 查询</div>
                  <pre style={{ background:'var(--bg-secondary)', borderRadius:4, padding:12, margin:0, fontSize:11.5, color:'var(--accent-blue)', fontFamily:'Consolas,monospace', overflow:'auto', whiteSpace:'pre-wrap', lineHeight:1.6 }}>{selected.query}</pre>
                </div>
              )}
              {((selected.mitre_tactics ?? []).length > 0 || (selected.mitre_techniques ?? []).length > 0) && (
                <div className="card">
                  <div className="card-title">MITRE ATT&amp;CK</div>
                  {(selected.mitre_tactics ?? []).length > 0 && (
                    <div style={{ marginBottom:8 }}>
                      <div style={{ fontSize:10, color:'var(--text-muted)', marginBottom:4 }}>TACTICS</div>
                      <div style={{ display:'flex', flexWrap:'wrap', gap:4 }}>
                        {selected.mitre_tactics.map(t => (
                          <span key={t} style={{ fontSize:10, padding:'2px 6px', background:'rgba(250,88,45,.1)', color:'var(--accent-orange)', border:'1px solid rgba(250,88,45,.2)', borderRadius:3, fontFamily:'monospace' }}>{t}</span>
                        ))}
                      </div>
                    </div>
                  )}
                  {(selected.mitre_techniques ?? []).length > 0 && (
                    <div>
                      <div style={{ fontSize:10, color:'var(--text-muted)', marginBottom:4 }}>TECHNIQUES</div>
                      <div style={{ display:'flex', flexWrap:'wrap', gap:4 }}>
                        {selected.mitre_techniques.map(t => (
                          <span key={t} style={{ fontSize:10, padding:'2px 6px', background:'rgba(79,163,224,.1)', color:'var(--accent-blue)', border:'1px solid rgba(79,163,224,.2)', borderRadius:3, fontFamily:'monospace' }}>{t}</span>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
              <div style={{ display:'flex', gap:8 }}>
                <button className="btn-primary" style={{ flex:1, fontSize:11 }} onClick={() => openEdit(selected)}>Edit Rule</button>
                <button className="btn-secondary" style={{ flex:1, fontSize:11 }} onClick={() => {
                  api.get(`/detection_rules/${selected._key}/test_replay`).then(r => {
                    const d = r.data.data ?? {}
                    const cov: Record<string, number> = {}
                    ;(selected.mitre_tactics ?? []).forEach(t => { cov[t] = d.match_count ?? 0 })
                    if (Object.keys(cov).length === 0) cov[`命中次数`] = d.match_count ?? 0
                    setMitreModal(cov)
                  }).catch(() => setMitreModal({ '测试失败或无数据': 0 }))
                }}>Test Rule</button>
              </div>
              <button className="btn-secondary" style={{ fontSize:11, color:'var(--critical)' }} onClick={() => deleteRule(selected)}>Delete Rule</button>
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

      {/* MITRE Coverage Modal */}
      {mitreModal !== null && (
        <>
          <div onClick={() => setMitreModal(null)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.5)', zIndex: 400 }} />
          <div style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: 560, maxHeight: '75vh', overflowY: 'auto', background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, zIndex: 500, padding: 24 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <span style={{ fontSize: 15, fontWeight: 600 }}>MITRE ATT&amp;CK 覆盖率</span>
              <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px' }} onClick={() => setMitreModal(null)}>✕</button>
            </div>
            {Object.keys(mitreModal).length === 0 ? (
              <div style={{ color: 'var(--text-muted)', fontSize: 12, textAlign: 'center', padding: 24 }}>暂无覆盖数据</div>
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {Object.entries(mitreModal).sort(([,a],[,b]) => (b as number)-(a as number)).map(([tactic, count]) => {
                  const pct = Math.min(100, Math.round(((count as number) / Math.max(...Object.values(mitreModal) as number[])) * 100))
                  return (
                    <div key={tactic} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <span style={{ width: 180, fontSize: 11.5, color: 'var(--accent-orange)', fontFamily: 'monospace', flexShrink: 0 }}>{tactic}</span>
                      <div style={{ flex: 1, height: 14, background: 'var(--bg-secondary)', borderRadius: 2, overflow: 'hidden' }}>
                        <div style={{ width: `${pct}%`, height: '100%', background: 'rgba(250,88,45,.6)', borderRadius: 2 }} />
                      </div>
                      <span style={{ fontSize: 11.5, fontWeight: 600, color: 'var(--text-secondary)', minWidth: 28, textAlign: 'right' }}>{count as number}</span>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        </>
      )}

      {/* Create / Edit Modal */}
      {showModal && (
        <>
          <div onClick={() => setShowModal(false)} style={{ position:'fixed', inset:0, background:'rgba(0,0,0,.5)', zIndex:400 }} />
          <div style={{ position:'fixed', top:'50%', left:'50%', transform:'translate(-50%,-50%)', width:560, background:'var(--bg-card)', border:'1px solid var(--border)', borderRadius:8, zIndex:500, padding:24, maxHeight:'85vh', overflowY:'auto' }}>
            <div style={{ fontSize:15, fontWeight:600, marginBottom:20 }}>{editTarget ? '编辑检测规则' : '新建检测规则'}</div>
            <div style={{ display:'flex', flexDirection:'column', gap:12 }}>
              <div>
                <div style={{ fontSize:11, color:'var(--text-muted)', marginBottom:4 }}>规则名称 *</div>
                <input className="filter-input" style={{ width:'100%', boxSizing:'border-box' }} placeholder="Suspicious PowerShell Execution" value={form.name} onChange={e => setForm(p => ({ ...p, name: e.target.value }))} />
              </div>
              <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr 1fr', gap:12 }}>
                <div>
                  <div style={{ fontSize:11, color:'var(--text-muted)', marginBottom:4 }}>类型</div>
                  <select className="filter-select" style={{ width:'100%' }} value={form.rule_type} onChange={e => setForm(p => ({ ...p, rule_type: e.target.value }))}>
                    <option value="bioc">BIOC</option>
                    <option value="ioc">IOC Match</option>
                    <option value="ueba">UEBA</option>
                  </select>
                </div>
                <div>
                  <div style={{ fontSize:11, color:'var(--text-muted)', marginBottom:4 }}>严重程度</div>
                  <select className="filter-select" style={{ width:'100%' }} value={form.severity} onChange={e => setForm(p => ({ ...p, severity: e.target.value }))}>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
                  </select>
                </div>
                <div>
                  <div style={{ fontSize:11, color:'var(--text-muted)', marginBottom:4 }}>状态</div>
                  <select className="filter-select" style={{ width:'100%' }} value={form.status} onChange={e => setForm(p => ({ ...p, status: e.target.value }))}>
                    <option value="draft">草稿</option>
                    <option value="testing">测试中</option>
                    <option value="active">活跃</option>
                    <option value="inactive">停用</option>
                  </select>
                </div>
              </div>
              <div>
                <div style={{ fontSize:11, color:'var(--text-muted)', marginBottom:4 }}>描述</div>
                <textarea className="filter-input" style={{ width:'100%', boxSizing:'border-box', minHeight:56, resize:'vertical' }} placeholder="规则检测目标描述..." value={form.description} onChange={e => setForm(p => ({ ...p, description: e.target.value }))} />
              </div>
              <div>
                <div style={{ fontSize:11, color:'var(--text-muted)', marginBottom:4 }}>SPL2 查询</div>
                <textarea className="filter-input" style={{ width:'100%', boxSizing:'border-box', minHeight:80, resize:'vertical', fontFamily:'monospace', fontSize:11.5 }} placeholder={`dataset = xdr_data\n| filter event_type = "PROCESS"\n| filter action_process_image_name = "powershell.exe"`} value={form.query} onChange={e => setForm(p => ({ ...p, query: e.target.value }))} />
              </div>
              <div style={{ display:'grid', gridTemplateColumns:'1fr 1fr', gap:12 }}>
                <div>
                  <div style={{ fontSize:11, color:'var(--text-muted)', marginBottom:4 }}>MITRE战术 (comma-sep)</div>
                  <input className="filter-input" style={{ width:'100%', boxSizing:'border-box' }} placeholder="Execution, Defense Evasion" value={form.mitre_tactics} onChange={e => setForm(p => ({ ...p, mitre_tactics: e.target.value }))} />
                </div>
                <div>
                  <div style={{ fontSize:11, color:'var(--text-muted)', marginBottom:4 }}>MITRE技术 (comma-sep)</div>
                  <input className="filter-input" style={{ width:'100%', boxSizing:'border-box' }} placeholder="T1059.001, T1055" value={form.mitre_techniques} onChange={e => setForm(p => ({ ...p, mitre_techniques: e.target.value }))} />
                </div>
              </div>
              <div style={{ display:'flex', gap:10, marginTop:8 }}>
                <button className="btn-secondary" style={{ flex:1 }} onClick={() => setShowModal(false)}>取消</button>
                <button className="btn-primary" style={{ flex:1 }} disabled={saving || !form.name.trim()} onClick={saveRule}>
                  {saving ? '保存中...' : editTarget ? '保存修改' : '创建规则'}
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
            <div style={{ fontSize:15, fontWeight:600, marginBottom:12 }}>确认删除规则</div>
            <div style={{ fontSize:13, color:'var(--text-secondary)', marginBottom:20 }}>
              确定要删除规则 <strong style={{ color:'var(--text-primary)' }}>「{deleteTarget.name}」</strong>？
            </div>
            <div style={{ display:'flex', gap:10 }}>
              <button className="btn-secondary" style={{ flex:1 }} onClick={() => setDeleteTarget(null)}>取消</button>
              <button className="btn-primary" style={{ flex:1, background:'var(--critical)', borderColor:'var(--critical)' }} onClick={doDeleteRule}>确认删除</button>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
