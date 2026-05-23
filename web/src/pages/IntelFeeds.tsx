import { useEffect, useRef, useState } from 'react'
import api from '@/lib/api'
import type { PageMeta } from '@/lib/api'
import PageHeader from '@/components/PageHeader'

interface Feed {
  _key: string
  name: string
  description: string
  feed_type: string
  url: string
  status: string
  ioc_count: number
  last_synced: string
  sync_interval: number
  created_at: string
}

function fmtDate(iso: string) {
  if (!iso) return '-'
  return new Date(iso).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false })
}

export default function IntelFeeds() {
  const [items, setItems] = useState<Feed[]>([])
  const [meta, setMeta] = useState<PageMeta>({ page: 1, page_size: 20, total: 0, total_pages: 1 })
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [syncing, setSyncing] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [showModal, setShowModal] = useState(false)
  const [editFeed, setEditFeed] = useState<Feed | null>(null)
  const [form, setForm] = useState({ name: '', description: '', feed_type: 'stix_taxii', url: '', sync_interval: '60', status: 'active' })
  const [saving, setSaving] = useState(false)
  const mountedRef = useRef(false)

  function load(p = page) {
    setLoading(true)
    const params: any = { page: p, page_size: 20 }
    if (search) params.search = search
    if (typeFilter) params.feed_type = typeFilter
    if (statusFilter) params.status = statusFilter
    api.get('/intel_feeds', { params })
      .then(r => { setItems(r.data.data?.items ?? []); setMeta(r.data.data?.meta ?? meta) })
      .finally(() => setLoading(false))
  }

  useEffect(() => { load(page) }, [page])
  useEffect(() => {
    if (!mountedRef.current) { mountedRef.current = true; return }
    setPage(1); load(1)
  }, [typeFilter, statusFilter])

  function openAdd() {
    setEditFeed(null)
    setForm({ name: '', description: '', feed_type: 'stix_taxii', url: '', sync_interval: '60', status: 'active' })
    setShowModal(true)
  }

  function openEdit(f: Feed) {
    setEditFeed(f)
    setForm({ name: f.name, description: f.description || '', feed_type: f.feed_type || 'custom', url: f.url || '', sync_interval: String(f.sync_interval || 60), status: f.status || 'active' })
    setShowModal(true)
  }

  function saveFeed() {
    if (!form.name.trim()) return
    setSaving(true)
    const payload = { ...form, sync_interval: parseInt(form.sync_interval) || 60 }
    const req = editFeed
      ? api.patch(`/intel_feeds/${editFeed._key}`, payload)
      : api.post('/intel_feeds', payload)
    req.then(() => { setShowModal(false); load(1) }).finally(() => setSaving(false))
  }

  function triggerSync(key: string) {
    setSyncing(key)
    api.post(`/intel_feeds/${key}/sync`)
      .then(() => load(page))
      .finally(() => setSyncing(null))
  }

  const statusColor: Record<string, string> = {
    active: 'var(--accent-green)',
    inactive: 'var(--text-muted)',
    error: 'var(--critical)',
    syncing: 'var(--accent-blue)',
  }

  const typeIcon: Record<string, string> = {
    stix_taxii: '⚠',
    misp: '🔗',
    custom: '⚙️',
    mitre: '🛡️',
    virustotal: '🔍',
  }

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <PageHeader
        title="Intel Feeds"
        subtitle={`· ${meta.total} feeds`}
        actions={<button className="btn-primary" onClick={openAdd}>+ 添加订阅源</button>}
      />

      <div className="filter-bar">
        <input
          className="filter-input"
          placeholder="搜索订阅源..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && load(1)}
        />
        <select className="filter-select" value={typeFilter} onChange={e => setTypeFilter(e.target.value)}>
          <option value="">全部类型</option>
          <option value="stix_taxii">STIX/TAXII</option>
          <option value="misp">MISP</option>
          <option value="mitre">MITRE ATT&CK</option>
          <option value="virustotal">VirusTotal</option>
          <option value="custom">Custom</option>
        </select>
        <select className="filter-select" value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
          <option value="">全部状态</option>
          <option value="active">活跃</option>
          <option value="inactive">停用</option>
          <option value="error">Error</option>
        </select>
      </div>

      <div className="data-table-wrap">
        <table className="data-table">
          <thead>
            <tr>
              <th>订阅源名称</th>
              <th>类型</th>
              <th>状态</th>
              <th>IOC数量</th>
              <th>最后同步</th>
              <th>Interval</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            {loading && <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>加载中...</td></tr>}
            {!loading && items.length === 0 && <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>No intel feeds configured</td></tr>}
            {items.map(f => (
              <tr key={f._key}>
                <td>
                  <div style={{ fontSize: 12.5, fontWeight: 500 }}>
                    {typeIcon[f.feed_type] ?? '📄'} {f.name}
                  </div>
                  {f.description && <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{f.description.slice(0, 60)}</div>}
                </td>
                <td>
                  <span style={{ fontSize: 11, padding: '2px 8px', background: 'var(--bg-card2)', border: '1px solid var(--border-light)', borderRadius: 3, textTransform: 'uppercase', fontFamily: 'monospace', letterSpacing: 0.3 }}>
                    {f.feed_type || 'custom'}
                  </span>
                </td>
                <td>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11.5 }}>
                    <span style={{
                      width: 6, height: 6, borderRadius: '50%', display: 'inline-block',
                      background: statusColor[f.status] ?? 'var(--text-muted)',
                      boxShadow: f.status === 'active' ? `0 0 4px ${statusColor.active}` : 'none',
                    }} />
                    {f.status || 'inactive'}
                  </span>
                </td>
                <td style={{ fontSize: 12, color: 'var(--text-secondary)', fontFamily: 'monospace' }}>
                  {f.ioc_count?.toLocaleString() ?? '0'}
                </td>
                <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{fmtDate(f.last_synced)}</td>
                <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                  {f.sync_interval ? `${f.sync_interval}m` : 'manual'}
                </td>
                <td>
                  <div style={{ display: 'flex', gap: 6 }}>
                    <button
                      className="btn-primary"
                      style={{ fontSize: 11, padding: '2px 10px' }}
                      disabled={syncing === f._key}
                      onClick={() => triggerSync(f._key)}
                    >
                      {syncing === f._key ? '...' : '→ 同步'}
                    </button>
                    <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px' }} onClick={() => openEdit(f)}>编辑</button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      <div className="pagination">
        <button className="page-btn" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>&#8249;</button>
        <span>{page} / {meta.total_pages || 1}</span>
        <button className="page-btn" disabled={page >= meta.total_pages} onClick={() => setPage(p => p + 1)}>&#8250;</button>
        <span style={{ marginLeft: 8 }}>{meta.total} 条</span>
      </div>

      {showModal && (
        <>
          <div onClick={() => setShowModal(false)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.5)', zIndex: 400 }} />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 460, background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: 8, zIndex: 500, padding: 24,
          }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 20 }}>{editFeed ? '编辑订阅源' : 'Add Intel Feed'}</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>Name *</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="Unit 42 Threat Feed" value={form.name} onChange={e => setForm(p => ({ ...p, name: e.target.value }))} />
              </div>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>描述</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="简要描述..." value={form.description} onChange={e => setForm(p => ({ ...p, description: e.target.value }))} />
              </div>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>订阅类型</div>
                <select className="filter-select" style={{ width: '100%' }} value={form.feed_type} onChange={e => setForm(p => ({ ...p, feed_type: e.target.value }))}>
                  <option value="stix_taxii">STIX/TAXII</option>
                  <option value="misp">MISP</option>
                  <option value="mitre">MITRE ATT&CK</option>
                  <option value="virustotal">VirusTotal</option>
                  <option value="custom">Custom</option>
                </select>
              </div>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>URL</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="https://feed.example.com/indicators" value={form.url} onChange={e => setForm(p => ({ ...p, url: e.target.value }))} />
              </div>
              <div style={{ display: 'flex', gap: 12 }}>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>Sync Interval (min)</div>
                  <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} type="number" min={0} placeholder="60" value={form.sync_interval} onChange={e => setForm(p => ({ ...p, sync_interval: e.target.value }))} />
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>状态</div>
                  <select className="filter-select" style={{ width: '100%' }} value={form.status} onChange={e => setForm(p => ({ ...p, status: e.target.value }))}>
                    <option value="active">活跃</option>
                    <option value="inactive">停用</option>
                  </select>
                </div>
              </div>
              <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setShowModal(false)}>取消</button>
                <button className="btn-primary" style={{ flex: 1 }} disabled={saving || !form.name.trim()} onClick={saveFeed}>
                  {saving ? '保存中...' : editFeed ? '保存修改' : '添加订阅源'}
                </button>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
