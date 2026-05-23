import { useEffect, useRef, useState } from 'react'
import api from '@/lib/api'
import type { PageMeta } from '@/lib/api'
import PageHeader from '@/components/PageHeader'

interface Playbook {
  _key: string
  name: string
  description: string
  trigger_type: string
  trigger_conditions: Record<string, any>
  steps: any[]
  status: string
  run_count: number
  success_count: number
  fail_count: number
  last_run: string
  last_run_status: string
  dry_run: boolean
  created_by: string
  created_at: string
  updated_at: string
}

interface RunHistory {
  run_id: string
  status: string
  started_at: string
  duration_ms: number
  trigger: string
  steps_total: number
  steps_done: number
}

function fmtDate(iso: string) {
  if (!iso) return '-'
  return new Date(iso).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false })
}

function fmt耗时(ms: number) {
  if (!ms) return '-'
  if (ms < 1000) return `${ms}ms`
  if (ms < 60000) return `${(ms / 1000).toFixed(1)}s`
  return `${Math.floor(ms / 60000)}m ${Math.floor((ms % 60000) / 1000)}s`
}

const BLANK_PB = { name: '', description: '', trigger_type: '手动', status: 'draft' }

const triggerColor: Record<string, string> = {
  手动: 'var(--text-muted)',
  alert: 'var(--high)',
  incident: 'var(--critical)',
  schedule: 'var(--accent-blue)',
  webhook: 'var(--medium)',
}

const runStatusColor: Record<string, string> = {
  success: 'var(--accent-green)',
  failed: 'var(--critical)',
  running: 'var(--accent-blue)',
  partial: 'var(--medium)',
}

export default function Playbooks() {
  const [items, setItems] = useState<Playbook[]>([])
  const [meta, setMeta] = useState<PageMeta>({ page: 1, page_size: 20, total: 0, total_pages: 1 })
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [triggerFilter, setTriggerFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [selected, setSelected] = useState<Playbook | null>(null)
  const [history, setHistory] = useState<RunHistory[]>([])
  const [histLoading, setHistLoading] = useState(false)
  const [running, setRunning] = useState<string | null>(null)

  const [search, setSearch] = useState('')
  const [showModal, setShowModal] = useState(false)
  const [editTarget, setEditTarget] = useState<Playbook | null>(null)
  const [form, setForm] = useState(BLANK_PB)
  const [saving, setSaving] = useState(false)
  const mountedRef = useRef(false)
  const [deleteTarget, setDeleteTarget] = useState<Playbook | null>(null)

  function load(p = page) {
    setLoading(true)
    const params: any = { page: p, page_size: 20 }
    if (triggerFilter) params.trigger_type = triggerFilter
    if (statusFilter) params.status = statusFilter
    if (search) params.keyword = search
    api.get('/playbooks', { params })
      .then(r => { setItems(r.data.data?.items ?? []); setMeta(r.data.data?.meta ?? meta) })
      .finally(() => setLoading(false))
  }

  useEffect(() => { load(page) }, [page])
  useEffect(() => {
    if (!mountedRef.current) { mountedRef.current = true; return }
    setPage(1); load(1)
  }, [triggerFilter, statusFilter])

  function loadHistory(pb: Playbook) {
    setHistLoading(true)
    api.get(`/playbooks/${pb._key}/runs`, { params: { page: 1, page_size: 10 } })
      .then(r => setHistory(r.data.data?.items ?? []))
      .finally(() => setHistLoading(false))
  }

  function selectPlaybook(pb: Playbook) {
    const next = selected?._key === pb._key ? null : pb
    setSelected(next)
    if (next) loadHistory(next)
  }

  function run(pb: Playbook, dry: boolean) {
    setRunning(pb._key)
    api.post(`/playbooks/${pb._key}/run`, { dry_run: dry })
      .then(() => load(page))
      .finally(() => setRunning(null))
  }

  function openCreate() { setEditTarget(null); setForm(BLANK_PB); setShowModal(true) }
  function openEdit(pb: Playbook) {
    setEditTarget(pb)
    setForm({ name: pb.name, description: pb.description || '', trigger_type: pb.trigger_type || '手动', status: pb.status || 'draft' })
    setShowModal(true)
  }
  function savePlaybook() {
    if (!form.name.trim()) return
    setSaving(true)
    const req = editTarget ? api.patch(`/playbooks/${editTarget._key}`, form) : api.post('/playbooks', form)
    req.then(() => { setShowModal(false); load(1) }).finally(() => setSaving(false))
  }
  function deletePlaybook(pb: Playbook) { setDeleteTarget(pb) }
  function doDeletePlaybook() {
    if (!deleteTarget) return
    api.delete(`/playbooks/${deleteTarget._key}`).then(() => { setSelected(null); setDeleteTarget(null); load(1) })
  }

  function toggle活跃(pb: Playbook) {
    const newStatus = pb.status === 'active' ? 'inactive' : 'active'
    api.patch(`/playbooks/${pb._key}`, { status: newStatus }).then(() => load(page))
  }

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <PageHeader
        title="Playbooks"
        subtitle={`· ${meta.total} 条`}
        actions={<button className="btn-primary" onClick={openCreate}>+ 新建剧本</button>}
      />

      <div className="filter-bar">
        <input className="filter-input" placeholder="搜索剧本..." value={search} onChange={e => setSearch(e.target.value)} onKeyDown={e => { if (e.key === 'Enter') { setPage(1); load(1) } }} />
        <select className="filter-select" value={triggerFilter} onChange={e => setTriggerFilter(e.target.value)}>
          <option value="">All Triggers</option>
          <option value="手动">Manual</option>
          <option value="alert">Alert</option>
          <option value="incident">Incident</option>
          <option value="schedule">Schedule</option>
          <option value="webhook">Webhook</option>
        </select>
        <select className="filter-select" value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
          <option value="">全部状态</option>
          <option value="active">活跃</option>
          <option value="inactive">Inactive</option>
          <option value="draft">草稿</option>
        </select>
      </div>

      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        <div className="data-table-wrap" style={{ flex: 1 }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>名称</th>
                <th>触发方式</th>
                <th>状态</th>
                <th>步骤</th>
                <th>执行次数</th>
                <th>Success Rate</th>
                <th>最近运行</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {loading && <tr><td colSpan={8} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>加载中...</td></tr>}
              {!loading && items.length === 0 && <tr><td colSpan={8} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>暂无剧本</td></tr>}
              {items.map(pb => {
                const successRate = pb.run_count > 0 ? Math.round((pb.success_count / pb.run_count) * 100) : null
                return (
                  <tr key={pb._key} onClick={() => selectPlaybook(pb)} className={selected?._key === pb._key ? 'selected' : ''}>
                    <td>
                      <div style={{ fontSize: 12.5, fontWeight: 500 }}>{pb.name}</div>
                      {pb.description && <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginTop: 2 }}>{pb.description.slice(0, 55)}</div>}
                    </td>
                    <td>
                      <span style={{ fontSize: 11, padding: '2px 8px', borderRadius: 3,
                        background: `${triggerColor[pb.trigger_type] ?? 'var(--text-muted)'}22`,
                        color: triggerColor[pb.trigger_type] ?? 'var(--text-muted)',
                        border: `1px solid ${triggerColor[pb.trigger_type] ?? 'var(--border)'}44`,
                        textTransform: 'capitalize',
                      }}>{pb.trigger_type || '手动'}</span>
                    </td>
                    <td>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11.5 }}>
                        <span style={{
                          width: 6, height: 6, borderRadius: '50%', display: 'inline-block',
                          background: pb.status === 'active' ? 'var(--accent-green)' : 'var(--text-muted)',
                          boxShadow: pb.status === 'active' ? '0 0 4px var(--accent-green)' : 'none',
                        }} />
                        {pb.status || 'inactive'}
                      </span>
                    </td>
                    <td style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{pb.steps?.length ?? 0}</td>
                    <td style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{pb.run_count ?? 0}</td>
                    <td>
                      {successRate !== null
                        ? <span style={{ fontSize: 11.5, fontWeight: 600, color: successRate >= 80 ? 'var(--accent-green)' : successRate >= 50 ? 'var(--medium)' : 'var(--critical)' }}>{successRate}%</span>
                        : <span style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>...</span>}
                    </td>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{fmtDate(pb.last_run)}</td>
                    <td onClick={e => e.stopPropagation()}>
                      <div style={{ display: 'flex', gap: 4 }}>
                        <button className="btn-primary" style={{ fontSize: 11, padding: '2px 8px' }} disabled={running === pb._key || pb.status === 'draft'} onClick={() => run(pb, false)}>
                          {running === pb._key ? '...' : '▶ 运行'}
                        </button>
                        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 7px' }} onClick={() => openEdit(pb)}>编辑</button>
                        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 7px', color: 'var(--critical)' }} onClick={() => deletePlaybook(pb)}>删</button>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>

        {selected && (
          <div style={{
            width: 360, borderLeft: '1px solid var(--border)', background: 'var(--bg-card)',
            display: 'flex', flexDirection: 'column', overflow: 'hidden', flexShrink: 0,
          }}>
            <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 13, fontWeight: 600 }}>{selected.name}</span>
              <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px' }} onClick={() => setSelected(null)}>✕</button>
            </div>
            <div style={{ flex: 1, overflowY: 'auto', padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div className="card">
                <div className="card-title">Metadata</div>
                {[
                  ['Trigger', selected.trigger_type || '手动'],
                  ['状态', selected.status || 'inactive'],
                  ['步骤', String(selected.steps?.length ?? 0)],
                  ['Total Runs', String(selected.run_count ?? 0)],
                  ['Successes', String(selected.success_count ?? 0)],
                  ['Failures', String(selected.fail_count ?? 0)],
                  ['创建者', selected.created_by || '-'],
                  ['Updated', fmtDate(selected.updated_at)],
                ].map(([k, v]) => (
                  <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11.5, borderBottom: '1px solid rgba(255,255,255,.04)', paddingBottom: 4, marginBottom: 4 }}>
                    <span style={{ color: 'var(--text-muted)' }}>{k}</span>
                    <span style={{ color: 'var(--text-secondary)', textTransform: k === '状态' || k === 'Trigger' ? 'capitalize' : undefined }}>{v}</span>
                  </div>
                ))}
              </div>

              <div className="card">
                <div className="card-title" style={{ marginBottom: 8 }}>执行历史</div>
                {histLoading && <div style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>加载中...</div>}
                {!histLoading && history.length === 0 && <div style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>No runs yet</div>}
                {history.map((r, i) => (
                  <div key={r.run_id ?? i} style={{
                    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                    padding: '5px 0', borderBottom: '1px solid rgba(255,255,255,.04)', fontSize: 11,
                  }}>
                    <div>
                      <span style={{ color: runStatusColor[r.status] ?? 'var(--text-muted)', fontWeight: 600, marginRight: 6, textTransform: 'capitalize' }}>{r.status}</span>
                      <span style={{ color: 'var(--text-muted)' }}>{fmtDate(r.started_at)}</span>
                    </div>
                    <div style={{ color: 'var(--text-muted)' }}>
                      {r.steps_done}/{r.steps_total} · {fmt耗时(r.duration_ms)}
                    </div>
                  </div>
                ))}
              </div>

              <div style={{ display: 'flex', gap: 8 }}>
                <button
                  className="btn-primary"
                  style={{ flex: 1, fontSize: 11 }}
                  disabled={running === selected._key}
                  onClick={() => run(selected, false)}
                >
                  {running === selected._key ? '执行中...' : '▶ 运行 Now'}
                </button>
                <button
                  className="btn-secondary"
                  style={{ flex: 1, fontSize: 11 }}
                  disabled={running === selected._key}
                  onClick={() => run(selected, true)}
                >
                  Dry Run
                </button>
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                <button className="btn-secondary" style={{ flex: 1, fontSize: 11 }} onClick={() => openEdit(selected)}>编辑</button>
                <button
                  className="btn-secondary"
                  style={{ flex: 1, fontSize: 11, color: selected.status === 'active' ? 'var(--critical)' : 'var(--accent-green)' }}
                  onClick={() => toggle活跃(selected)}
                >
                  {selected.status === 'active' ? 'Deactivate' : 'Activate'}
                </button>
              </div>
              <button className="btn-secondary" style={{ fontSize: 11, color: 'var(--critical)' }} onClick={() => deletePlaybook(selected)}>Delete Playbook</button>
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

      {/* Create / Edit Modal */}
      {showModal && (
        <>
          <div onClick={() => setShowModal(false)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.5)', zIndex: 400 }} />
          <div style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: 480, background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, zIndex: 500, padding: 24 }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 20 }}>{editTarget ? '编辑剧本' : 'New Playbook'}</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Name *</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="Endpoint Isolation Response" value={form.name} onChange={e => setForm(p => ({ ...p, name: e.target.value }))} />
              </div>
              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>描述</div>
                <textarea className="filter-input" style={{ width: '100%', boxSizing: 'border-box', minHeight: 64, resize: 'vertical' }} placeholder="剧本功能描述..." value={form.description} onChange={e => setForm(p => ({ ...p, description: e.target.value }))} />
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>触发方式</div>
                  <select className="filter-select" style={{ width: '100%' }} value={form.trigger_type} onChange={e => setForm(p => ({ ...p, trigger_type: e.target.value }))}>
                    <option value="手动">Manual</option>
                    <option value="alert">Alert</option>
                    <option value="incident">Incident</option>
                    <option value="schedule">Schedule</option>
                    <option value="webhook">Webhook</option>
                  </select>
                </div>
                <div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>状态</div>
                  <select className="filter-select" style={{ width: '100%' }} value={form.status} onChange={e => setForm(p => ({ ...p, status: e.target.value }))}>
                    <option value="draft">草稿</option>
                    <option value="active">活跃</option>
                    <option value="inactive">Inactive</option>
                  </select>
                </div>
              </div>
              <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setShowModal(false)}>取消</button>
                <button className="btn-primary" style={{ flex: 1 }} disabled={saving || !form.name.trim()} onClick={savePlaybook}>
                  {saving ? '保存中...' : editTarget ? '保存修改' : '创建剧本'}
                </button>
              </div>
            </div>
          </div>
        </>
      )}

      {deleteTarget && (
        <>
          <div onClick={() => setDeleteTarget(null)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.5)', zIndex: 400 }} />
          <div style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: 360, background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, zIndex: 500, padding: 24 }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 12 }}>确认删除剧本</div>
            <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 20 }}>
              确定要删除剧本 <strong style={{ color: 'var(--text-primary)' }}>「{deleteTarget.name}」</strong>？已有执行历史将一并删除。
            </div>
            <div style={{ display: 'flex', gap: 10 }}>
              <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setDeleteTarget(null)}>取消</button>
              <button className="btn-primary" style={{ flex: 1, background: 'var(--critical)', borderColor: 'var(--critical)' }} onClick={doDeletePlaybook}>确认删除</button>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
