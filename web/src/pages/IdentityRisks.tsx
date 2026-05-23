import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '@/lib/api'
import type { PageMeta } from '@/lib/api'
import PageHeader from '@/components/PageHeader'

interface IdentityRisk {
  _key: string
  user_id: string
  username: string
  display_name: string
  email: string
  department: string
  risk_score: number
  risk_level: string
  signals: string[]
  active_alerts: number
  last_activity: string
  updated_at: string
}

function RiskScore({ score }: { score: number }) {
  const color = score >= 85 ? 'var(--critical)' : score >= 70 ? 'var(--high)' : score >= 40 ? 'var(--medium)' : 'var(--accent-green)'
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{
        width: 56, height: 6, background: 'var(--bg-card2)', borderRadius: 3, overflow: 'hidden',
      }}>
        <div style={{ width: `${score}%`, height: '100%', background: color, borderRadius: 3, transition: 'width .3s' }} />
      </div>
      <span style={{ fontSize: 12, fontWeight: 600, color, minWidth: 28 }}>{score}</span>
    </div>
  )
}

function fmtDate(iso: string) {
  if (!iso) return '-'
  return new Date(iso).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false })
}

export default function IdentityRisks() {
  const navigate = useNavigate()
  const [items, setItems] = useState<IdentityRisk[]>([])
  const [meta, setMeta] = useState<PageMeta>({ page: 1, page_size: 20, total: 0, total_pages: 1 })
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [levelFilter, setLevelFilter] = useState('')
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<IdentityRisk | null>(null)
  const [addingSignal, setAddingSignal] = useState(false)
  const [signalInput, setSignalInput] = useState('')
  const [showSignalInput, setShowSignalInput] = useState(false)
  const mountedRef = useRef(false)

  function load(p = page) {
    setLoading(true)
    const params: any = { page: p, page_size: 20 }
    if (levelFilter) params.risk_level = levelFilter
    if (search) params.keyword = search
    api.get('/identity_risks', { params })
      .then(r => { setItems(r.data.data?.items ?? []); setMeta(r.data.data?.meta ?? meta) })
      .finally(() => setLoading(false))
  }

  useEffect(() => { load(page) }, [page])
  useEffect(() => {
    if (!mountedRef.current) { mountedRef.current = true; return }
    setPage(1); load(1)
  }, [levelFilter])

  const levelColor: Record<string, string> = {
    critical: 'var(--critical)',
    high: 'var(--high)',
    medium: 'var(--medium)',
    low: 'var(--accent-green)',
  }

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <PageHeader
        title="Identity Risks"
        subtitle={`· ${meta.total} users tracked`}
      />

      <div className="tab-bar">
        {[['All', ''], ['严重 ≥85', 'critical'], ['高危 ≥70', 'high'], ['中危', 'medium'], ['Low', 'low']].map(([label, val]) => (
          <button key={label} className={`tab ${levelFilter === val ? 'active' : ''}`}
            onClick={() => setLevelFilter(val)}>
            {label}
          </button>
        ))}
      </div>

      <div className="filter-bar">
        <input
          className="filter-input"
          placeholder="搜索用户名、邮箱、部门..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && load(1)}
        />
      </div>

      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        <div className="data-table-wrap" style={{ flex: 1 }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>用户</th>
                <th>风险评分</th>
                <th>Level</th>
                <th>Signals</th>
                <th>Active Alerts</th>
                <th>Last Activity</th>
              </tr>
            </thead>
            <tbody>
              {loading && <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>加载中...</td></tr>}
              {!loading && items.length === 0 && <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>No identity risks found</td></tr>}
              {items.map(r => (
                <tr key={r._key} onClick={() => setSelected(r)} className={selected?._key === r._key ? 'selected' : ''}>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <div style={{
                        width: 28, height: 28, borderRadius: '50%', flexShrink: 0,
                        background: `linear-gradient(135deg, ${levelColor[r.risk_level] ?? 'var(--accent-blue)'}88, ${levelColor[r.risk_level] ?? 'var(--accent-blue)'}44)`,
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        fontSize: 10, fontWeight: 700, color: 'white',
                      }}>
                        {(r.display_name || r.username || '?').slice(0, 2).toUpperCase()}
                      </div>
                      <div>
                        <div style={{ fontSize: 12.5, fontWeight: 500 }}>{r.display_name || r.username}</div>
                        <div style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>{r.email || r.username}</div>
                      </div>
                    </div>
                  </td>
                  <td><RiskScore score={r.risk_score ?? 0} /></td>
                  <td>
                    <span style={{
                      fontSize: 10.5, padding: '2px 8px', borderRadius: 3, fontWeight: 600,
                      background: `${levelColor[r.risk_level] ?? 'var(--text-muted)'}22`,
                      color: levelColor[r.risk_level] ?? 'var(--text-muted)',
                      border: `1px solid ${levelColor[r.risk_level] ?? 'var(--border)'}44`,
                      textTransform: 'uppercase', letterSpacing: 0.3,
                    }}>
                      {r.risk_level || 'low'}
                    </span>
                  </td>
                  <td>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
                      {(r.signals ?? []).slice(0, 3).map(s => (
                        <span key={s} style={{ fontSize: 9.5, padding: '1px 5px', background: 'rgba(250,88,45,.1)', color: 'var(--accent-orange)', border: '1px solid rgba(250,88,45,.2)', borderRadius: 3 }}>{s}</span>
                      ))}
                      {(r.signals ?? []).length > 3 && <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>+{r.signals.length - 3}</span>}
                    </div>
                  </td>
                  <td style={{ fontSize: 12 }}>
                    {r.active_alerts > 0
                      ? <span style={{ color: 'var(--critical)', fontWeight: 600 }}>{r.active_alerts}</span>
                      : <span style={{ color: 'var(--text-muted)' }}>0</span>}
                  </td>
                  <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{fmtDate(r.last_activity)}</td>
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
            <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 13, fontWeight: 600 }}>User Risk Detail</span>
              <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px' }} onClick={() => setSelected(null)}>✕</button>
            </div>
            <div style={{ flex: 1, overflowY: 'auto', padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div className="card">
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12 }}>
                  <div style={{
                    width: 40, height: 40, borderRadius: '50%',
                    background: `linear-gradient(135deg, ${levelColor[selected.risk_level] ?? 'var(--accent-blue)'}88, ${levelColor[selected.risk_level] ?? 'var(--accent-blue)'}44)`,
                    display: 'flex', alignItems: 'center', justifyContent: 'center',
                    fontSize: 14, fontWeight: 700, color: 'white', flexShrink: 0,
                  }}>
                    {(selected.display_name || selected.username || '?').slice(0, 2).toUpperCase()}
                  </div>
                  <div>
                    <div style={{ fontSize: 14, fontWeight: 600 }}>{selected.display_name || selected.username}</div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{selected.email}</div>
                  </div>
                </div>
                <RiskScore score={selected.risk_score ?? 0} />
                <div style={{ marginTop: 12, display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {[
                    ['部门', selected.department || '-'],
                    ['风险等级', selected.risk_level || '-'],
                    ['Active Alerts', String(selected.active_alerts ?? 0)],
                    ['Last Activity', fmtDate(selected.last_activity)],
                  ].map(([k, v]) => (
                    <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11.5, borderBottom: '1px solid rgba(255,255,255,.04)', paddingBottom: 4 }}>
                      <span style={{ color: 'var(--text-muted)' }}>{k}</span>
                      <span style={{ color: 'var(--text-secondary)' }}>{v}</span>
                    </div>
                  ))}
                </div>
              </div>

              {(selected.signals ?? []).length > 0 && (
                <div className="card">
                  <div className="card-title">Risk Signals</div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {selected.signals.map(s => (
                      <div key={s} style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11.5 }}>
                        <span style={{ color: 'var(--high)', flexShrink: 0 }}>▶</span>
                        <span style={{ color: 'var(--text-secondary)' }}>{s}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              <div style={{ display: 'flex', gap: 8 }}>
                <button className="btn-secondary" style={{ flex: 1, fontSize: 11 }} onClick={() => navigate(`/alerts?q=${encodeURIComponent(selected.username)}`)}>查看告警</button>
                <button className="btn-primary" style={{ flex: 1, fontSize: 11 }} onClick={() => setShowSignalInput(v => !v)}>添加信号</button>
              </div>
              {showSignalInput && (
                <div style={{ display: 'flex', gap: 8 }}>
                  <input
                    className="filter-input"
                    style={{ flex: 1, fontSize: 12 }}
                    placeholder="信号描述，如：异常登录地点"
                    value={signalInput}
                    onChange={e => setSignalInput(e.target.value)}
                    onKeyDown={e => e.key === 'Escape' && setShowSignalInput(false)}
                  />
                  <button className="btn-primary" style={{ fontSize: 11, padding: '4px 12px' }} disabled={addingSignal || !signalInput.trim()} onClick={() => {
                    setAddingSignal(true)
                    api.post(`/identity_risks/${selected.user_id}/signal`, {
                      username: selected.username,
                      signal: { type: 'active_alert', score: 20, detail: signalInput, detected_at: new Date().toISOString() },
                    })
                      .then(() => { setShowSignalInput(false); setSignalInput(''); load(page) })
                      .finally(() => setAddingSignal(false))
                  }}>{addingSignal ? '...' : '提交'}</button>
                </div>
              )}
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
    </div>
  )
}
