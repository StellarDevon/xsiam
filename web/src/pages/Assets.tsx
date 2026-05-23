import { useEffect, useRef, useState } from 'react'
import api from '@/lib/api'
import type { PageMeta } from '@/lib/api'
import PageHeader from '@/components/PageHeader'

interface Asset {
  _key: string
  hostname: string
  name: string
  ip: string
  mac: string
  os: string
  os_version: string
  type: string
  status: string
  department: string
  owner: string
  risk_score: number
  agent_version: string
  active_incidents: number
  open_vulns: number
  last_seen: string
  created_at: string
}

function AssetScoreBadge({ score }: { score: number }) {
  const [bg, color] = score >= 80
    ? ['rgba(229,57,53,.2)', '#ef5350']
    : score >= 60
      ? ['rgba(255,111,0,.2)', '#ffa726']
      : score >= 30
        ? ['rgba(249,168,37,.2)', '#f9a825']
        : ['rgba(67,160,71,.2)', '#66bb6a']
  return (
    <span className="asset-score-badge" style={{ background: bg, color }}>
      {score}
    </span>
  )
}

function fmtDate(iso: string) {
  if (!iso) return '-'
  return new Date(iso).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false })
}

const osIcon = (os: string) => {
  if (!os) return '🖥'
  const o = os.toLowerCase()
  if (o.includes('windows')) return '🏴'
  if (o.includes('linux') || o.includes('ubuntu') || o.includes('centos') || o.includes('rhel')) return '🐧'
  if (o.includes('mac') || o.includes('darwin')) return '🍎'
  return '🖥'
}

interface AssetStats {
  total: number
  critical_risk: number
  total_endpoints: number
  active_用户: number
  cloud_assets: number
  open_vulns: number
  critical_vulns: number
}

type AssetTab = 'all' | 'endpoint' | 'user' | 'cloud' | 'network' | 'vuln'

const BLANK_FORM = { name: '', hostname: '', type: 'workstation', status: 'online', ip_addresses: '', os_info: { name: '', version: '', arch: '' }, department: '', owner: '' }

export default function Assets() {
  const [items, setItems] = useState<Asset[]>([])
  const [meta, setMeta] = useState<PageMeta>({ page: 1, page_size: 20, total: 0, total_pages: 1 })
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [assetTab, setAssetTab] = useState<AssetTab>('all')
  const [typeFilter, set类型Filter] = useState('')
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<Asset | null>(null)
  const [kpi, setKpi] = useState<AssetStats | null>(null)

  // Create / Edit modal
  const [showModal, setShowModal] = useState(false)
  const [editTarget, setEditTarget] = useState<Asset | null>(null)
  const [form, setForm] = useState(BLANK_FORM)
  const [saving, setSaving] = useState(false)
  const [deleting, setDeleting] = useState(false)
  const [statusFilter, set状态Filter] = useState('')
  const mountedRef = useRef(false)

  function load(p = page) {
    setLoading(true)
    const params: any = { page: p, page_size: 20 }
    const t = assetTab !== 'all' && assetTab !== 'vuln' ? assetTab : typeFilter
    if (t) params.type = t
    if (search) params.keyword = search
    if (statusFilter) params.status = statusFilter
    api.get('/assets', { params })
      .then(r => { setItems(r.data.data?.items ?? []); setMeta(r.data.data?.meta ?? meta) })
      .finally(() => setLoading(false))
  }

  useEffect(() => {
    api.get('/assets/stats').then(r => setKpi(r.data.data)).catch(() => {})
  }, [])

  useEffect(() => { load(page) }, [page])
  useEffect(() => {
    if (!mountedRef.current) { mountedRef.current = true; return }
    setPage(1); load(1)
  }, [typeFilter, assetTab, statusFilter])

  function openCreate() {
    setEditTarget(null)
    setForm(BLANK_FORM)
    setShowModal(true)
  }

  function openEdit(a: Asset) {
    setEditTarget(a)
    setForm({
      name: a.name || a.hostname || '',
      hostname: a.hostname || '',
      type: a.type || 'workstation',
      status: a.status || 'online',
      ip_addresses: a.ip || '',
      os_info: { name: a.os || '', version: a.os_version || '', arch: '' },
      department: a.department || '',
      owner: a.owner || '',
    })
    setShowModal(true)
  }

  function saveAsset() {
    if (!form.hostname.trim()) return
    setSaving(true)
    const body = {
      name: form.name || form.hostname,
      hostname: form.hostname,
      type: form.type,
      status: form.status,
      ip_addresses: form.ip_addresses ? [form.ip_addresses] : [],
      os_info: form.os_info,
      department: form.department,
      owner: form.owner,
    }
    const req = editTarget
      ? api.patch(`/assets/${editTarget._key}`, body)
      : api.post('/assets', body)
    req.then(() => { setShowModal(false); load(1) }).finally(() => setSaving(false))
  }

  const [deleteTarget, setDeleteTarget] = useState<Asset | null>(null)

  function confirmDelete(a: Asset) { setDeleteTarget(a) }
  function doDelete() {
    if (!deleteTarget) return
    setDeleting(true)
    api.delete(`/assets/${deleteTarget._key}`).then(() => { setSelected(null); setDeleteTarget(null); load(1) }).finally(() => setDeleting(false))
  }

  const statusColor: Record<string, string> = {
    online: 'var(--accent-green)',
    offline: 'var(--text-muted)',
    isolated: 'var(--critical)',
    uninstalled: 'var(--text-muted)',
  }

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <PageHeader
        title="资产管理"
        subtitle={`统一资产清单 · ${(kpi?.total_endpoints ?? 0).toLocaleString()} 终端 · ${(kpi?.active_用户 ?? 0).toLocaleString()} 用户 · ${(kpi?.cloud_assets ?? 0).toLocaleString()} 云资产`}
        actions={<>
          <button className="btn-secondary" onClick={() => {
            const rows = [['主机名', 'IP', '操作系统', '类型', '状态', '部门', '负责人'].join(',')]
            items.forEach(a => rows.push([a.hostname, a.ip, a.os, a.type, a.status, a.department, a.owner].join(',')))
            const blob = new Blob([rows.join('\n')], { type: 'text/csv' })
            const el = document.createElement('a'); el.href = URL.createObjectURL(blob); el.download = 'assets.csv'; el.click()
          }}>&#8659; 导出</button>
          <button className="btn-primary" onClick={openCreate}>+ 添加资产</button>
        </>}
      />

      {/* KPI bar */}
      <div className="kpi-row" style={{ gridTemplateColumns: 'repeat(5,1fr)' }}>
        {[
          { label: '高危资产', value: kpi?.critical_risk ?? 0, color: 'var(--critical)', note: '需立即处置' },
          { label: '终端总数', value: (kpi?.total_endpoints ?? 0).toLocaleString(), note: `${Math.round(((kpi?.total_endpoints ?? 0) / Math.max(kpi?.total ?? 1, 1)) * 100)}% Agent 覆盖` },
          { label: '活跃用户', value: (kpi?.active_用户 ?? 0).toLocaleString(), note: '已身份关联' },
          { label: '云资产', value: (kpi?.cloud_assets ?? 0).toLocaleString(), note: 'AWS / Azure / GCP' },
          { label: '未修复漏洞', value: (kpi?.open_vulns ?? 0).toLocaleString(), color: kpi && kpi.open_vulns > 0 ? 'var(--high)' : undefined, note: kpi?.critical_vulns ? `${kpi.critical_vulns} 个严重CVE` : '无严重CVE' },
        ].map(k => (
          <div key={k.label} className="kpi-card-flat">
            <div className="kpi-label">{k.label}</div>
            <div className="kpi-value" style={{ color: k.color ?? 'var(--text-primary)' }}>{k.value}</div>
            <div className="kpi-note">{k.note}</div>
          </div>
        ))}
      </div>

      {/* Asset sub-tabs */}
      <div className="tab-bar">
        {([
          ['all', '全部资产', null],
          ['endpoint', '终端', kpi?.total_endpoints],
          ['user', '用户', kpi?.active_用户],
          ['cloud', '云资产', kpi?.cloud_assets],
          ['network', '网络设备', null],
          ['vuln', '漏洞视图', null],
        ] as [AssetTab, string, number | null | undefined][]).map(([val, label, count]) => (
          <button key={val} className={`tab ${assetTab === val ? 'active' : ''}`} onClick={() => setAssetTab(val)}>
            {label}
            {count != null && <span className="tab-count">{count.toLocaleString()}</span>}
          </button>
        ))}
      </div>

      <div className="filter-bar">
        <input
          className="filter-input"
          placeholder="搜索主机名、IP、部门..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && load(1)}
        />
        <select className="filter-select" value={typeFilter} onChange={e => set类型Filter(e.target.value)}>
          <option value="">全部类型</option>
          <option value="workstation">Workstation</option>
          <option value="server">Server</option>
          <option value="network">Network Device</option>
          <option value="cloud">Cloud Instance</option>
          <option value="iot">IoT</option>
        </select>
        <select className="filter-select" value={statusFilter} onChange={e => set状态Filter(e.target.value)}>
          <option value="">全部状态</option>
          <option value="online">Online</option>
          <option value="offline">Offline</option>
          <option value="isolated">Isolated</option>
        </select>
      </div>

      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        {assetTab === 'vuln' ? (
          <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>
            <div style={{ display: 'grid', gridTemplateColumns: '300px 1fr', gap: 16 }}>
              <div className="card">
                <div className="card-title">CVE 严重程度分布</div>
                {[
                  { label: 'Critical', color: '#e53935', pct: 12, count: kpi?.critical_vulns ?? 0 },
                  { label: 'High', color: '#ff6f00', pct: 25, count: null },
                  { label: 'Medium', color: '#f9a825', pct: 56, count: null },
                  { label: 'Low', color: '#00897b', pct: 16, count: null },
                ].map(s => (
                  <div key={s.label} style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 8 }}>
                    <span style={{ width: 60, fontSize: 11, color: s.color }}>{s.label}</span>
                    <div style={{ flex: 1, height: 16, background: 'var(--bg-secondary)', borderRadius: 3, overflow: 'hidden' }}>
                      <div style={{ width: `${s.pct}%`, height: '100%', background: s.color, borderRadius: 3 }} />
                    </div>
                    <span style={{ fontSize: 11, color: s.color, fontWeight: 700, minWidth: 30 }}>
                      {s.count != null ? s.count : '-'}
                    </span>
                  </div>
                ))}
              </div>
              <div className="card">
                <div className="card-title">Top 个严重CVE</div>
                <div className="data-table-wrap" style={{ margin: -16, marginTop: 0 }}>
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>CVE</th><th>CVSS</th><th>描述</th><th>Affected</th><th>状态</th>
                      </tr>
                    </thead>
                    <tbody>
                      {loading && <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 16 }}>加载中...</td></tr>}
                      {!loading && <tr><td colSpan={5} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 16 }}>暂无数据</td></tr>}
                    </tbody>
                  </table>
                </div>
              </div>
            </div>
          </div>
        ) : (
          <div className="data-table-wrap" style={{ flex: 1 }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>资产</th>
                  <th>IP / 平台</th>
                  <th>类型</th>
                  <th>资产评分</th>
                  <th>风险</th>
                  <th>未关闭事件</th>
                  <th>Agent状态</th>
                  <th>部门/负责人</th>
                  <th>最近活跃</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {loading && <tr><td colSpan={10} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>加载中...</td></tr>}
                {!loading && items.length === 0 && <tr><td colSpan={10} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>暂无资产</td></tr>}
                {items.map(a => (
                  <tr key={a._key}
                    onClick={() => setSelected(selected?._key === a._key ? null : a)}
                    className={[selected?._key === a._key ? 'selected' : '', (a.risk_score ?? 0) >= 80 ? 'row-critical' : ''].join(' ').trim()}
                  >
                    <td>
                      <div style={{ fontFamily: 'monospace', fontSize: 12.5, fontWeight: 500, color: 'var(--accent-blue)' }}>{a.hostname || '-'}</div>
                      {a.owner && <div style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>{a.owner}</div>}
                    </td>
                    <td>
                      <div style={{ fontFamily: 'monospace', fontSize: 11.5 }}>{a.ip || '-'}</div>
                      <div style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>{osIcon(a.os)} {a.os || '-'}</div>
                    </td>
                    <td>
                      <span style={{ fontSize: 10.5, padding: '2px 8px', background: 'var(--bg-card2)', border: '1px solid var(--border-light)', borderRadius: 3, textTransform: 'capitalize' }}>
                        {a.type || 'endpoint'}
                      </span>
                    </td>
                    <td><AssetScoreBadge score={a.risk_score ?? 0} /></td>
                    <td>
                      <span className={`sev-badge ${(a.risk_score ?? 0) >= 80 ? 'critical' : (a.risk_score ?? 0) >= 60 ? 'high' : (a.risk_score ?? 0) >= 30 ? 'medium' : 'low'}`}>
                        {(a.risk_score ?? 0) >= 80 ? 'Critical' : (a.risk_score ?? 0) >= 60 ? 'High' : (a.risk_score ?? 0) >= 30 ? 'Medium' : 'Low'}
                      </span>
                    </td>
                    <td style={{ fontSize: 12 }}>
                      {(a.active_incidents ?? 0) > 0
                        ? <span style={{ color: 'var(--critical)', fontWeight: 600 }}>{a.active_incidents} active</span>
                        : <span style={{ color: 'var(--text-muted)' }}>-</span>}
                    </td>
                    <td>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11.5 }}>
                        <span style={{
                          width: 6, height: 6, borderRadius: '50%', display: 'inline-block',
                          background: statusColor[a.status] ?? 'var(--text-muted)',
                          boxShadow: a.status === 'online' ? `0 0 4px ${statusColor.online}` : 'none',
                        }} />
                        {a.status === 'isolated' ? <span style={{ color: 'var(--high)' }}>⚠ Isolated</span> : (a.status || 'unknown')}
                      </span>
                    </td>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{a.department || '-'}</td>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{fmtDate(a.last_seen)}</td>
                    <td onClick={e => e.stopPropagation()}>
                      <div style={{ display: 'flex', gap: 4 }}>
                        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 7px' }} onClick={() => openEdit(a)}>编辑</button>
                        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 7px', color: 'var(--critical)' }} onClick={() => confirmDelete(a)}>删</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Detail panel */}
        {selected && (
          <div style={{
            width: 340, borderLeft: '1px solid var(--border)', background: 'var(--bg-card)',
            display: 'flex', flexDirection: 'column', overflow: 'hidden', flexShrink: 0,
          }}>
            <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 13, fontWeight: 600, fontFamily: 'monospace' }}>{selected.hostname || selected._key}</span>
              <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px' }} onClick={() => setSelected(null)}>&#x2715;</button>
            </div>
            <div style={{ flex: 1, overflowY: 'auto', padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div className="card">
                <div className="card-title">安全状态</div>
                <div style={{ marginBottom: 12, display: 'flex', alignItems: 'center', gap: 10 }}>
                  <AssetScoreBadge score={selected.risk_score ?? 0} />
                  <span style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>资产评分</span>
                </div>
                <div style={{ display: 'flex', gap: 16 }}>
                  <div style={{ textAlign: 'center' }}>
                    <div style={{ fontSize: 20, fontWeight: 700, color: selected.active_incidents > 0 ? 'var(--critical)' : 'var(--text-muted)' }}>
                      {selected.active_incidents ?? 0}
                    </div>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>事件</div>
                  </div>
                  <div style={{ textAlign: 'center' }}>
                    <div style={{ fontSize: 20, fontWeight: 700, color: selected.open_vulns > 0 ? 'var(--high)' : 'var(--text-muted)' }}>
                      {selected.open_vulns ?? 0}
                    </div>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>未修复CVE</div>
                  </div>
                </div>
              </div>

              <div className="card">
                <div className="card-title">资产信息</div>
                {[
                  ['主机名', selected.hostname || '-'],
                  ['IP地址', selected.ip || '-'],
                  ['MAC', selected.mac || '-'],
                  ['操作系统', `${osIcon(selected.os)} ${selected.os || '-'}${selected.os_version ? ' ' + selected.os_version : ''}`],
                  ['类型', selected.type || '-'],
                  ['部门', selected.department || '-'],
                  ['负责人', selected.owner || '-'],
                  ['Agent', selected.agent_version || '-'],
                  ['最近活跃', fmtDate(selected.last_seen)],
                ].map(([k, v]) => (
                  <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11.5, borderBottom: '1px solid rgba(255,255,255,.04)', paddingBottom: 4, marginBottom: 4 }}>
                    <span style={{ color: 'var(--text-muted)', flexShrink: 0, marginRight: 8 }}>{k}</span>
                    <span style={{ color: 'var(--text-secondary)', fontFamily: k === 'IP地址' || k === 'MAC' || k === 'Agent' ? 'monospace' : undefined, textAlign: 'right' }}>{v}</span>
                  </div>
                ))}
              </div>

              <div style={{ display: 'flex', gap: 8 }}>
                <button className="btn-secondary" style={{ flex: 1, fontSize: 11 }} onClick={() => openEdit(selected)}>编辑资产</button>
                <button className="btn-secondary" style={{ flex: 1, fontSize: 11, color: 'var(--critical)' }} disabled={deleting} onClick={() => confirmDelete(selected)}>删除</button>
              </div>
            </div>
          </div>
        )}
      </div>

      <div className="pagination">
        <button className="page-btn" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>&#8249;</button>
        {(()=>{
          const total = meta.total_pages || 1
          if (total <= 7) return Array.from({length: total},(_,i)=>i+1)
          const pages:(number|'...')[]=[1]
          if (page>3) pages.push('...')
          for(let i=Math.max(2,page-1);i<=Math.min(total-1,page+1);i++) pages.push(i)
          if(page<total-2) pages.push('...')
          pages.push(total)
          return pages
        })().map((p,i)=>
          p==='...' ? <span key={`e${i}`} style={{padding:'0 4px',color:'var(--text-muted)'}}>…</span>
          : <button key={p} className={`page-btn${page===p?' active':''}`} onClick={()=>setPage(p as number)}>{p}</button>
        )}
        <button className="page-btn" disabled={page >= meta.total_pages} onClick={() => setPage(p => p + 1)}>&#8250;</button>
        <span style={{ marginLeft: 8 }}>{meta.total} 条</span>
      </div>

      {/* Create / Edit Modal */}
      {showModal && (
        <>
          <div onClick={() => setShowModal(false)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.5)', zIndex: 400 }} />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 480, background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: 8, zIndex: 500, padding: 24,
          }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 20 }}>{editTarget ? '编辑资产' : '添加资产'}</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                {[
                  { label: '主机名 *', key: 'hostname', ph: 'WKSTN-001' },
                  { label: '名称/标签', key: 'name', ph: 'Finance Workstation' },
                  { label: 'IP地址', key: 'ip_addresses', ph: '10.0.0.1' },
                  { label: '负责人', key: 'owner', ph: 'john.doe' },
                  { label: '操作系统 Name', key: 'os_info.name', ph: 'Windows 11' },
                  { label: '部门', key: 'department', ph: 'Finance' },
                ].map(f => (
                  <div key={f.key}>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>{f.label}</div>
                    <input
                      className="filter-input"
                      style={{ width: '100%', boxSizing: 'border-box' }}
                      placeholder={f.ph}
                      value={f.key.startsWith('os_info.') ? (form.os_info as any)[f.key.split('.')[1]] : (form as any)[f.key]}
                      onChange={e => {
                        if (f.key.startsWith('os_info.')) {
                          const sub = f.key.split('.')[1]
                          setForm(prev => ({ ...prev, os_info: { ...prev.os_info, [sub]: e.target.value } }))
                        } else {
                          setForm(prev => ({ ...prev, [f.key]: e.target.value }))
                        }
                      }}
                    />
                  </div>
                ))}
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>类型</div>
                  <select className="filter-select" style={{ width: '100%' }} value={form.type} onChange={e => setForm(p => ({ ...p, type: e.target.value }))}>
                    <option value="workstation">Workstation</option>
                    <option value="server">Server</option>
                    <option value="network">Network Device</option>
                    <option value="cloud">Cloud Instance</option>
                    <option value="iot">IoT</option>
                  </select>
                </div>
                <div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>状态</div>
                  <select className="filter-select" style={{ width: '100%' }} value={form.status} onChange={e => setForm(p => ({ ...p, status: e.target.value }))}>
                    <option value="online">Online</option>
                    <option value="offline">Offline</option>
                    <option value="isolated">Isolated</option>
                  </select>
                </div>
              </div>
              <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setShowModal(false)}>取消</button>
                <button className="btn-primary" style={{ flex: 1 }} disabled={saving || !form.hostname.trim()} onClick={saveAsset}>
                  {saving ? '保存中...' : editTarget ? '保存修改' : '添加资产'}
                </button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* Delete Confirm Modal */}
      {deleteTarget && (
        <>
          <div onClick={() => setDeleteTarget(null)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.5)', zIndex: 400 }} />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 380, background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: 8, zIndex: 500, padding: 24,
          }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 12 }}>确认删除</div>
            <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 20 }}>
              确定要删除资产 <strong style={{ color: 'var(--text-primary)', fontFamily: 'monospace' }}>{deleteTarget.hostname}</strong> 吗？此操作不可撤销。
            </div>
            <div style={{ display: 'flex', gap: 10 }}>
              <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setDeleteTarget(null)}>取消</button>
              <button className="btn-primary" style={{ flex: 1, background: 'var(--critical)', borderColor: 'var(--critical)' }} disabled={deleting} onClick={doDelete}>
                {deleting ? '删除中...' : '确认删除'}
              </button>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
