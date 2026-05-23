import { useEffect, useRef, useState } from 'react'
import api from '@/lib/api'
import type { PageMeta } from '@/lib/api'
import PageHeader from '@/components/PageHeader'

interface Exposure {
  _key: string
  asset_id: string
  hostname: string
  cve_id: string
  cvss_score: number
  in_wild: boolean
  reachability: string
  priority_score: number
  status: string
  assigned_to: string
  due_date: string
  updated_at: string
}

function PriorityBar({ score }: { score: number }) {
  const color = score >= 70 ? 'var(--critical)' : score >= 40 ? 'var(--high)' : 'var(--medium)'
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ width: 60, height: 5, background: 'var(--bg-card2)', borderRadius: 3, overflow: 'hidden' }}>
        <div style={{ width: `${Math.min(score, 100)}%`, height: '100%', background: color, borderRadius: 3 }} />
      </div>
      <span style={{ fontSize: 11.5, fontWeight: 600, color, minWidth: 28 }}>{score.toFixed(0)}</span>
    </div>
  )
}

function fmtDate(iso: string) {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString('zh-CN')
}

const STATUS_OPTIONS = ['planned', 'in_progress', 'fixed', 'accepted', 'compensated']
const STATUS_LABELS: Record<string, string> = {
  unplanned: '未计划', planned: '已计划', in_progress: '处理中',
  validating: '验证中', fixed: '已修复', accepted: '接受风险', compensated: '已补偿',
}

export default function ExposureScores() {
  const [items, setItems] = useState<Exposure[]>([])
  const [meta, setMeta] = useState<PageMeta>({ page: 1, page_size: 20, total: 0, total_pages: 1 })
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [statusFilter, setStatusFilter] = useState('')
  const [search, setSearch] = useState('')
  const [reachFilter, setReachFilter] = useState('')
  const [inWildFilter, setInWildFilter] = useState('')
  const [recalcing, setRecalcing] = useState(false)
  const [editKey, setEditKey] = useState<string | null>(null)
  const [editStatus, setEditStatus] = useState('')
  const mountedRef = useRef(false)

  function load(p = page) {
    setLoading(true)
    const params: any = { page: p, page_size: 20 }
    if (statusFilter) params.status = statusFilter
    if (search) params.keyword = search
    if (reachFilter) params.reachability = reachFilter
    if (inWildFilter) params.in_wild = inWildFilter
    api.get('/exposure_scores', { params })
      .then(r => { setItems(r.data.data?.items ?? []); setMeta(r.data.data?.meta ?? meta) })
      .finally(() => setLoading(false))
  }

  useEffect(() => { load(page) }, [page])
  useEffect(() => {
    if (!mountedRef.current) { mountedRef.current = true; return }
    setPage(1); load(1)
  }, [statusFilter, reachFilter, inWildFilter])

  function recalcAll() {
    setRecalcing(true)
    api.post('/exposure_scores/recalc').then(() => load(page)).finally(() => setRecalcing(false))
  }

  function doUpdate(key: string, status: string) {
    api.patch(`/exposure_scores/${key}`, { status }).then(() => { setEditKey(null); load(page) })
  }

  const statusColor: Record<string, string> = {
    unplanned: 'var(--text-muted)',
    planned: 'var(--accent-blue)',
    in_progress: 'var(--medium)',
    validating: 'var(--accent-blue)',
    fixed: 'var(--accent-green)',
    accepted: 'var(--text-muted)',
    compensated: 'var(--accent-blue)',
  }

  const reachColor: Record<string, string> = {
    internet: 'var(--critical)',
    dmz: 'var(--high)',
    internal: 'var(--medium)',
    isolated: 'var(--accent-green)',
  }

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <PageHeader
        title="暴露面管理"
        subtitle={`· ${meta.total} 条`}
        actions={
          <button className="btn-secondary" disabled={recalcing} onClick={recalcAll}>
            {recalcing ? '重算中...' : '↻ 重新计算优先级'}
          </button>
        }
      />

      <div className="tab-bar">
        {([['全部', ''], ['高优先级 ≥70', 'high'], ['未计划', 'unplanned'], ['处理中', 'in_progress'], ['已修复', 'fixed'], ['接受风险', 'accepted']] as [string,string][]).map(([label, val]) => (
          <button key={label} className={`tab ${statusFilter === val ? 'active' : ''}`}
            onClick={() => setStatusFilter(val)}>
            {label}
          </button>
        ))}
      </div>

      <div className="filter-bar">
        <input
          className="filter-input"
          placeholder="搜索CVE编号、主机名..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          onKeyDown={e => { if (e.key === 'Enter') { setPage(1); load(1) } }}
        />
        <select className="filter-select" value={reachFilter} onChange={e => setReachFilter(e.target.value)}>
          <option value="">全部可达性</option>
          <option value="internet">互联网暴露</option>
          <option value="dmz">DMZ区</option>
          <option value="internal">内部网络</option>
          <option value="isolated">隔离</option>
        </select>
        <select className="filter-select" value={inWildFilter} onChange={e => setInWildFilter(e.target.value)}>
          <option value="">全部</option>
          <option value="true">在野利用</option>
        </select>
      </div>

      <div className="data-table-wrap">
        <table className="data-table">
          <thead>
            <tr>
              <th>CVE编号</th>
              <th>受影响资产</th>
              <th>CVSS</th>
              <th>可达性</th>
              <th>在野利用</th>
              <th>优先级评分</th>
              <th>状态</th>
              <th>截止日期</th>
              <th></th>
            </tr>
          </thead>
          <tbody>
            {loading && <tr><td colSpan={9} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>加载中...</td></tr>}
            {!loading && items.length === 0 && <tr><td colSpan={9} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>暂无暴露记录</td></tr>}
            {items.map(e => (
              <tr key={e._key} className={(e.priority_score ?? 0) >= 70 ? 'row-critical' : ''}>
                <td>
                  <span style={{ fontFamily: 'monospace', fontSize: 12, color: 'var(--accent-orange)' }}>{e.cve_id || '—'}</span>
                </td>
                <td style={{ fontFamily: 'monospace', fontSize: 11.5 }}>{e.hostname || e.asset_id || '—'}</td>
                <td>
                  <span style={{
                    fontSize: 11.5, fontWeight: 600,
                    color: e.cvss_score >= 9 ? 'var(--critical)' : e.cvss_score >= 7 ? 'var(--high)' : e.cvss_score >= 4 ? 'var(--medium)' : 'var(--accent-green)',
                  }}>{e.cvss_score?.toFixed(1) ?? '—'}</span>
                </td>
                <td>
                  <span style={{ fontSize: 10.5, padding: '2px 6px', borderRadius: 3,
                    background: `${reachColor[e.reachability] ?? 'var(--text-muted)'}22`,
                    color: reachColor[e.reachability] ?? 'var(--text-muted)',
                    border: `1px solid ${reachColor[e.reachability] ?? 'var(--border)'}44`,
                  }}>{e.reachability === 'internet' ? '互联网' : e.reachability === 'dmz' ? 'DMZ' : e.reachability === 'internal' ? '内网' : e.reachability === 'isolated' ? '隔离' : e.reachability || '未知'}</span>
                </td>
                <td>
                  {e.in_wild
                    ? <span style={{ fontSize: 11, color: 'var(--critical)', fontWeight: 600 }}>⚡ 在野</span>
                    : <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>—</span>}
                </td>
                <td><PriorityBar score={e.priority_score ?? 0} /></td>
                <td>
                  {editKey === e._key ? (
                    <div style={{ display: 'flex', gap: 4 }}>
                      <select
                        className="filter-select"
                        style={{ fontSize: 11, padding: '2px 4px' }}
                        value={editStatus}
                        onChange={ev => setEditStatus(ev.target.value)}
                      >
                        {STATUS_OPTIONS.map(s => <option key={s} value={s}>{STATUS_LABELS[s] ?? s}</option>)}
                      </select>
                      <button className="btn-primary" style={{ fontSize: 10, padding: '1px 6px' }} onClick={() => doUpdate(e._key, editStatus)}>✓</button>
                      <button className="btn-secondary" style={{ fontSize: 10, padding: '1px 6px' }} onClick={() => setEditKey(null)}>✕</button>
                    </div>
                  ) : (
                    <span style={{ fontSize: 10.5, padding: '2px 6px', borderRadius: 3, cursor: 'pointer',
                      color: statusColor[e.status] ?? 'var(--text-muted)',
                      background: `${statusColor[e.status] ?? 'var(--text-muted)'}18`,
                      border: `1px solid ${statusColor[e.status] ?? 'var(--border)'}44`,
                    }} onClick={() => { setEditKey(e._key); setEditStatus(e.status || 'planned') }}>
                      {STATUS_LABELS[e.status] ?? e.status ?? '未计划'}
                    </span>
                  )}
                </td>
                <td style={{ fontSize: 11, color: e.due_date && new Date(e.due_date) < new Date() ? 'var(--critical)' : 'var(--text-muted)' }}>
                  {fmtDate(e.due_date)}
                </td>
                <td>
                  <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px' }} onClick={() => { setEditKey(e._key); setEditStatus(e.status || 'planned') }}>
                    更新
                  </button>
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
    </div>
  )
}
