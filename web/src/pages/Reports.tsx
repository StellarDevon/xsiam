import { useEffect, useRef, useState } from 'react'
import api from '@/lib/api'
import type { PageMeta } from '@/lib/api'
import PageHeader from '@/components/PageHeader'

interface Report {
  _key: string
  name: string
  report_type: string
  period: string
  status: string
  format: string
  file_url: string
  generated_at: string
  created_at: string
}

function fmtDate(iso: string) {
  if (!iso) return '-'
  return new Date(iso).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false })
}

const REPORT_TYPES = [
  { value: 'soc_daily', label: 'SOC Daily' },
  { value: 'soc_weekly', label: 'SOC Weekly' },
  { value: 'soc_monthly', label: 'SOC Monthly' },
  { value: 'executive', label: 'Executive Brief' },
  { value: 'asset_security', label: 'Asset Security' },
  { value: 'vuln_remediation', label: 'Vuln Remediation' },
  { value: 'threat_intel', label: 'Threat Intel Activity' },
  { value: 'compliance_audit', label: 'Compliance Audit' },
  { value: 'mitre_coverage', label: 'MITRE ATT&CK Coverage' },
]

export default function Reports() {
  const [items, setItems] = useState<Report[]>([])
  const [meta, setMeta] = useState<PageMeta>({ page: 1, page_size: 20, total: 0, total_pages: 1 })
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [showNew, setShowNew] = useState(false)
  const [newName, setNewName] = useState('')
  const [newType, setNewType] = useState('soc_weekly')
  const [creating, setCreating] = useState(false)
  const [typeFilter, setTypeFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const mountedRef = useRef(false)

  function load(p = page) {
    setLoading(true)
    const params: any = { page: p, page_size: 20 }
    if (typeFilter) params.report_type = typeFilter
    if (statusFilter) params.status = statusFilter
    api.get('/reports', { params })
      .then(r => { setItems(r.data.data?.items ?? []); setMeta(r.data.data?.meta ?? meta) })
      .finally(() => setLoading(false))
  }

  useEffect(() => { load(page) }, [page])
  useEffect(() => {
    if (!mountedRef.current) { mountedRef.current = true; return }
    setPage(1); load(1)
  }, [typeFilter, statusFilter])

  function createReport() {
    if (!newName.trim()) return
    setCreating(true)
    api.post('/reports', { name: newName, report_type: newType })
      .then(() => { setShowNew(false); setNewName(''); load(1) })
      .finally(() => setCreating(false))
  }

  const statusColor: Record<string, string> = {
    generating: 'var(--accent-blue)',
    ready: 'var(--accent-green)',
    failed: 'var(--critical)',
    scheduled: 'var(--medium)',
  }

  const typeIcon: Record<string, string> = {
    soc_daily: '📆', soc_weekly: '📳', soc_monthly: '📱',
    executive: '💯', asset_security: '🗼️', vuln_remediation: '🔧',
    threat_intel: '🛡️', compliance_audit: '📅', mitre_coverage: '🎯',
  }

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <PageHeader
        title="报表中心"
        subtitle={`· ${meta.total} reports`}
        actions={<button className="btn-primary" onClick={() => setShowNew(true)}>+ 生成报表</button>}
      />

      <div className="filter-bar">
        <select className="filter-select" value={typeFilter} onChange={e => setTypeFilter(e.target.value)}>
          <option value="">全部类型</option>
          {REPORT_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
        </select>
        <select className="filter-select" value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
          <option value="">全部状态</option>
          <option value="ready">Ready</option>
          <option value="generating">Generating</option>
          <option value="failed">Failed</option>
        </select>
      </div>

      <div className="data-table-wrap">
        <table className="data-table">
          <thead>
            <tr>
              <th>报表名称</th>
              <th>类型</th>
              <th>时间段</th>
              <th>状态</th>
              <th>Format</th>
              <th>Generated</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            {loading && <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>加载中...</td></tr>}
            {!loading && items.length === 0 && <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>No reports generated yet</td></tr>}
            {items.map(r => (
              <tr key={r._key}>
                <td>
                  <div style={{ fontSize: 12.5, fontWeight: 500 }}>
                    {typeIcon[r.report_type] ?? '📋'} {r.name}
                  </div>
                </td>
                <td>
                  <span style={{ fontSize: 11, padding: '2px 8px', background: 'var(--bg-card2)', border: '1px solid var(--border-light)', borderRadius: 3 }}>
                    {REPORT_TYPES.find(t => t.value === r.report_type)?.label ?? r.report_type}
                  </span>
                </td>
                <td style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>{r.period || '-'}</td>
                <td>
                  <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11.5 }}>
                    <span style={{
                      width: 6, height: 6, borderRadius: '50%', display: 'inline-block',
                      background: statusColor[r.status] ?? 'var(--text-muted)',
                      animation: r.status === 'generating' ? 'pulse-dot 1s infinite' : 'none',
                    }} />
                    {r.status || 'scheduled'}
                  </span>
                </td>
                <td>
                  <span style={{ fontSize: 10.5, padding: '2px 6px', background: 'var(--bg-card2)', border: '1px solid var(--border-light)', borderRadius: 3, textTransform: 'uppercase', fontFamily: 'monospace', letterSpacing: 0.3 }}>
                    {r.format || 'PDF'}
                  </span>
                </td>
                <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{fmtDate(r.generated_at || r.created_at)}</td>
                <td>
                  <div style={{ display: 'flex', gap: 6 }}>
                    {r.status === 'ready' && r.file_url && (
                      <a href={r.file_url} target="_blank" rel="noreferrer">
                        <button className="btn-primary" style={{ fontSize: 11, padding: '2px 10px' }}>→ 下载</button>
                      </a>
                    )}
                    <button
                      className="btn-secondary"
                      style={{ fontSize: 11, padding: '2px 8px', color: 'var(--critical)' }}
                      onClick={() => api.delete(`/reports/${r._key}`).then(() => load(page))}
                    >
                      Delete
                    </button>
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

      {/* New Report Modal */}
      {showNew && (
        <>
          <div onClick={() => setShowNew(false)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.5)', zIndex: 400 }} />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 420, background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: 8, zIndex: 500, padding: 24,
          }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 20 }}>Generate Report</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>报表名称</div>
                <input
                  className="filter-input"
                  style={{ width: '100%', boxSizing: 'border-box' }}
                  placeholder="e.g. SOC Weekly Report 2026-W21"
                  value={newName}
                  onChange={e => setNewName(e.target.value)}
                />
              </div>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>Report Type</div>
                <select className="filter-select" style={{ width: '100%' }} value={newType} onChange={e => setNewType(e.target.value)}>
                  {REPORT_TYPES.map(t => <option key={t.value} value={t.value}>{t.label}</option>)}
                </select>
              </div>
              <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setShowNew(false)}>取消</button>
                <button className="btn-primary" style={{ flex: 1 }} disabled={creating || !newName.trim()} onClick={createReport}>
                  {creating ? '生成中...' : 'Generate'}
                </button>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
