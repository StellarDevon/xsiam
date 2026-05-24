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
  last_sync_at?: string
  sync_interval_hours: number
  auto_sync?: boolean
  created_at: string
}

interface SyncHistoryRow {
  date: string
  duration: number
  ioc_added: number
  status: 'success' | 'error'
}

// ─── Indicator Rules types ────────────────────────────────────────────────────

interface IndicatorRule {
  id: string
  name: string
  ioc_type: 'ip' | 'domain' | 'hash' | 'url'
  confidence_threshold: number
  auto_block: boolean
  action: 'alert' | 'block' | 'monitor'
  hit_count: number
  status: 'active' | 'inactive'
}

const MOCK_INDICATOR_RULES: IndicatorRule[] = [
  { id: '1', name: '高危IP自动封锁', ioc_type: 'ip', confidence_threshold: 90, auto_block: true, action: 'block', hit_count: 23, status: 'active' },
  { id: '2', name: '恶意域名告警', ioc_type: 'domain', confidence_threshold: 75, auto_block: false, action: 'alert', hit_count: 156, status: 'active' },
  { id: '3', name: '文件哈希检测', ioc_type: 'hash', confidence_threshold: 85, auto_block: false, action: 'alert', hit_count: 8, status: 'active' },
  { id: '4', name: '可疑URL监控', ioc_type: 'url', confidence_threshold: 60, auto_block: false, action: 'monitor', hit_count: 44, status: 'active' },
  { id: '5', name: '僵尸网络IP封锁', ioc_type: 'ip', confidence_threshold: 95, auto_block: true, action: 'block', hit_count: 12, status: 'active' },
]

// ─── Sample Analysis types ────────────────────────────────────────────────────

interface SampleResult {
  id: string
  filename: string
  sha256: string
  verdict: 'malicious' | 'suspicious' | 'clean'
  score: number
  analyzed_at: string
  file_size: string
  file_type: string
  mitre_techniques?: string[]
  behaviors: {
    network_connections: string[]
    registry_changes: string[]
    file_operations: string[]
  }
}

const MOCK_SAMPLES: SampleResult[] = [
  {
    id: '1',
    filename: 'malware.exe',
    sha256: 'a3f2c1d8e94b5f6a7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b',
    verdict: 'malicious',
    score: 95,
    analyzed_at: '2026-05-24 14:30',
    file_size: '2.4 MB',
    file_type: 'PE32 executable',
    mitre_techniques: ['T1059', 'T1071', 'T1055', 'T1082'],
    behaviors: {
      network_connections: ['185.220.101.47:443 (C2)', '10.0.0.1:80 (内网横向)', 'dns-query: update.evil.cc'],
      registry_changes: ['HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run → malware.exe', 'HKLM\\SYSTEM\\CurrentControlSet\\Services → svc_host_32'],
      file_operations: ['写入 %TEMP%\\payload.dll', '删除 %APPDATA%\\logs\\*.log', '创建 C:\\Windows\\System32\\drivers\\rootkit.sys'],
    },
  },
  {
    id: '2',
    filename: 'document.pdf',
    sha256: 'b1e9f2a3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1',
    verdict: 'suspicious',
    score: 62,
    analyzed_at: '2026-05-24 12:15',
    file_size: '842 KB',
    file_type: 'PDF document',
    mitre_techniques: ['T1204', 'T1566'],
    behaviors: {
      network_connections: ['pdf-viewer-stats.track.io:80 (遥测)'],
      registry_changes: [],
      file_operations: ['读取 %USERPROFILE%\\Documents\\*.docx', '访问剪贴板内容'],
    },
  },
  {
    id: '3',
    filename: 'installer.msi',
    sha256: 'c8d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b2c3d4',
    verdict: 'clean',
    score: 12,
    analyzed_at: '2026-05-23 09:45',
    file_size: '15.7 MB',
    file_type: 'MSI installer',
    mitre_techniques: [],
    behaviors: {
      network_connections: ['software-updates.example.com:443 (升级检查)'],
      registry_changes: ['HKLM\\SOFTWARE\\ExampleApp → 安装路径'],
      file_operations: ['创建 C:\\Program Files\\ExampleApp\\'],
    },
  },
]

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fmtDate(iso: string) {
  if (!iso) return '-'
  return new Date(iso).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false })
}

function relTime(iso: string | undefined): string {
  if (!iso) return '-'
  const diffMs = Date.now() - new Date(iso).getTime()
  if (isNaN(diffMs) || diffMs < 0) return fmtDate(iso)
  const diffSec = Math.floor(diffMs / 1000)
  if (diffSec < 60) return '刚刚'
  const diffMin = Math.floor(diffSec / 60)
  if (diffMin < 60) return `${diffMin}分钟前`
  const diffHour = Math.floor(diffMin / 60)
  if (diffHour < 24) return `${diffHour}小时前`
  const diffDay = Math.floor(diffHour / 24)
  if (diffDay < 30) return `${diffDay}天前`
  const diffMonth = Math.floor(diffDay / 30)
  if (diffMonth < 12) return `${diffMonth}个月前`
  return `${Math.floor(diffMonth / 12)}年前`
}

function nextSyncTime(last_sync_at: string | undefined, interval_hours: number): string {
  if (!last_sync_at || !interval_hours) return '-'
  const next = new Date(new Date(last_sync_at).getTime() + interval_hours * 3600 * 1000)
  const diffMs = next.getTime() - Date.now()
  if (diffMs <= 0) return '即将同步'
  const diffMin = Math.floor(diffMs / 60000)
  if (diffMin < 60) return `${diffMin}分钟后`
  const diffHour = Math.floor(diffMin / 60)
  return `${diffHour}小时后`
}

function mockSyncHistory(feed: Feed): SyncHistoryRow[] {
  const rows: SyncHistoryRow[] = []
  const base = feed.last_sync_at ? new Date(feed.last_sync_at).getTime() : Date.now()
  const interval = (feed.sync_interval_hours || 6) * 3600 * 1000
  for (let i = 0; i < 5; i++) {
    const ts = new Date(base - i * interval)
    const seed = feed._key.charCodeAt(0) + i * 7
    rows.push({
      date: ts.toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }),
      duration: 2 + ((seed * 13) % 14),
      ioc_added: 10 + ((seed * 31) % 190),
      status: i === 2 && feed.status === 'error' ? 'error' : 'success',
    })
  }
  return rows
}

// ─── CSS ──────────────────────────────────────────────────────────────────────

const cssStyles = `
@keyframes xsiam-syncing-pulse {
  0%, 100% { opacity: 1; transform: scale(1); }
  50%       { opacity: 0.4; transform: scale(1.5); }
}
@keyframes xsiam-bulk-progress {
  0%   { width: 0%; }
  100% { width: 100%; }
}
@keyframes xsiam-fadein {
  from { opacity: 0; transform: translateY(4px); }
  to   { opacity: 1; transform: translateY(0); }
}
.xsiam-stat-tile {
  flex: 1;
  min-width: 150px;
  background: var(--bg-card);
  border: 1px solid var(--border-light);
  border-radius: 6px;
  padding: 12px 16px;
  position: relative;
  overflow: hidden;
  transition: border-color 0.2s;
}
.xsiam-stat-tile:hover { border-color: var(--border); }
.xsiam-stat-tile-border {
  position: absolute;
  left: 0; top: 0; bottom: 0;
  width: 3px;
  border-radius: 3px 0 0 3px;
}
.xsiam-detail-panel {
  position: fixed;
  top: 0; right: 0; bottom: 0;
  width: 420px;
  background: var(--bg-drawer);
  border-left: 1px solid var(--border);
  z-index: 300;
  display: flex;
  flex-direction: column;
  box-shadow: -4px 0 24px rgba(0,0,0,.35);
  overflow: hidden;
}
.xsiam-detail-overlay {
  position: fixed;
  inset: 0;
  background: var(--bg-overlay);
  z-index: 299;
}
.xsiam-toggle {
  position: relative;
  display: inline-flex;
  align-items: center;
  width: 36px;
  height: 20px;
  border-radius: 10px;
  border: none;
  cursor: pointer;
  padding: 0;
  transition: background 0.2s;
  flex-shrink: 0;
}
.xsiam-toggle-knob {
  position: absolute;
  width: 16px;
  height: 16px;
  border-radius: 50%;
  background: var(--text-primary, #fff);
  transition: left 0.2s;
  box-shadow: 0 1px 3px rgba(0,0,0,0.3);
}
.xsiam-bulk-bar {
  height: 3px;
  border-radius: 2px;
  background: 'var(--accent-blue)';
  transition: width 0.4s ease;
}
/* Indicator Rules */
.xsiam-rule-row {
  animation: xsiam-fadein 0.2s ease both;
}
.xsiam-rule-row:hover td { background: rgba(59,158,222,0.04); }
.xsiam-conf-track {
  position: relative;
  width: 80px;
  height: 4px;
  background: var(--bg-card2);
  border-radius: 2px;
  overflow: hidden;
  display: inline-block;
  vertical-align: middle;
}
.xsiam-conf-fill {
  position: absolute;
  left: 0; top: 0; bottom: 0;
  border-radius: 2px;
  transition: width 0.3s ease;
}
/* Sample analysis */
.xsiam-upload-zone {
  border: 2px dashed 'var(--border-light)';
  border-radius: 8px;
  padding: 32px 20px;
  text-align: center;
  cursor: pointer;
  transition: border-color 0.2s, background 0.2s;
}
.xsiam-upload-zone:hover {
  border-color: 'var(--accent-blue)';
  background: rgba(59,158,222,0.04);
}
.xsiam-sample-row {
  display: flex;
  align-items: center;
  gap: 14px;
  padding: 10px 14px;
  border-radius: 6px;
  cursor: pointer;
  transition: background 0.15s;
  border: 1px solid transparent;
  margin-bottom: 6px;
}
.xsiam-sample-row:hover {
  background: var(--bg-card2);
  border-color: 'var(--border-light)';
}
.xsiam-sample-row.selected {
  background: rgba(59,158,222,0.07);
  border-color: rgba(59,158,222,0.3);
}
.xsiam-sample-detail {
  animation: xsiam-fadein 0.18s ease both;
}
.xsiam-mitre-tag {
  display: inline-block;
  padding: 2px 8px;
  border-radius: 3px;
  font-size: 11px;
  font-family: monospace;
  background: rgba(208,112,48,0.14);
  color: 'var(--high)';
  border: 1px solid rgba(208,112,48,0.25);
  margin: 2px;
}
`

const FEED_TYPE_ICON: Record<string, string> = {
  stix_taxii: '🔗',
  csv: '📊',
  json: '📋',
  misp: '🛡',
  otx: '🔭',
  custom: '⚙',
  mitre: '🛡️',
  virustotal: '🔍',
}

const STATUS_COLOR: Record<string, string> = {
  active: 'var(--accent-green)',
  inactive: 'var(--text-muted)',
  error: 'var(--critical)',
  failed: 'var(--critical)',
  syncing: 'var(--accent-blue)',
}

// ─── Tab constants ────────────────────────────────────────────────────────────

type TabId = 'feeds' | 'rules' | 'sandbox'

const TABS: { id: TabId; label: string }[] = [
  { id: 'feeds', label: '订阅源' },
  { id: 'rules', label: '指标规则' },
  { id: 'sandbox', label: '样本分析' },
]

// ─── Main component ───────────────────────────────────────────────────────────

export default function IntelFeeds() {
  const [activeTab, setActiveTab] = useState<TabId>('feeds')

  const [items, setItems] = useState<Feed[]>([])
  const [meta, setMeta] = useState<PageMeta>({ page: 1, page_size: 20, total: 0, total_pages: 1 })
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [syncing, setSyncing] = useState<string | null>(null)
  const [togglingAutoSync, setTogglingAutoSync] = useState<string | null>(null)
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [showModal, setShowModal] = useState(false)
  const [editFeed, setEditFeed] = useState<Feed | null>(null)
  const [form, setForm] = useState({ name: '', description: '', feed_type: 'stix_taxii', url: '', sync_interval: '60', status: 'active' })
  const [saving, setSaving] = useState(false)
  const [detailFeed, setDetailFeed] = useState<Feed | null>(null)
  const [detailSyncing, setDetailSyncing] = useState(false)
  const [bulkSyncing, setBulkSyncing] = useState(false)
  const [bulkProgress, setBulkProgress] = useState(0)
  const [bulkTotal, setBulkTotal] = useState(0)
  const mountedRef = useRef(false)

  function load(p = page) {
    setLoading(true)
    const params: Record<string, unknown> = { page: p, page_size: 20 }
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

  const now = Date.now()
  const statsActiveCount = items.filter(f => f.status === 'active').length
  const statsTodaySyncs = items.filter(f => f.last_sync_at && (now - new Date(f.last_sync_at).getTime()) < 86400000).length
  const statsTotalIoc = items.reduce((s, f) => s + (f.ioc_count || 0), 0)
  const statsErrorCount = items.filter(f => f.status === 'error' || f.status === 'failed').length
  const statsSyncingCount = items.filter(f => f.status === 'syncing').length

  function openAdd() {
    setEditFeed(null)
    setForm({ name: '', description: '', feed_type: 'stix_taxii', url: '', sync_interval: '60', status: 'active' })
    setShowModal(true)
  }

  function openEdit(f: Feed) {
    setEditFeed(f)
    setForm({ name: f.name, description: f.description || '', feed_type: f.feed_type || 'custom', url: f.url || '', sync_interval: String(f.sync_interval_hours || 60), status: f.status || 'active' })
    setShowModal(true)
  }

  function saveFeed() {
    if (!form.name.trim()) return
    setSaving(true)
    const payload = { ...form, sync_interval_hours: parseInt(form.sync_interval) || 60 }
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

  function triggerDetailSync(feed: Feed) {
    setDetailSyncing(true)
    setItems(prev => prev.map(f => f._key === feed._key ? { ...f, status: 'syncing' } : f))
    if (detailFeed && detailFeed._key === feed._key) {
      setDetailFeed(prev => prev ? { ...prev, status: 'syncing' } : prev)
    }
    api.post(`/intel_feeds/${feed._key}/sync`)
      .then(() => { load(page) })
      .finally(() => setDetailSyncing(false))
  }

  function toggleAutoSync(feed: Feed) {
    setTogglingAutoSync(feed._key)
    api.patch(`/intel_feeds/${feed._key}`, { auto_sync: !feed.auto_sync })
      .then(() => {
        load(page)
        if (detailFeed && detailFeed._key === feed._key) {
          setDetailFeed(prev => prev ? { ...prev, auto_sync: !prev.auto_sync } : prev)
        }
      })
      .finally(() => setTogglingAutoSync(null))
  }

  async function bulkSyncActive() {
    const activeFeeds = items.filter(f => f.status === 'active')
    if (!activeFeeds.length) return
    setBulkSyncing(true)
    setBulkTotal(activeFeeds.length)
    setBulkProgress(0)
    for (let i = 0; i < activeFeeds.length; i++) {
      try {
        await api.post(`/intel_feeds/${activeFeeds[i]._key}/sync`)
      } catch {
        // continue
      }
      setBulkProgress(i + 1)
    }
    setBulkSyncing(false)
    setBulkProgress(0)
    setBulkTotal(0)
    load(page)
  }

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <style>{cssStyles}</style>
      <PageHeader
        title="Intel Feeds"
        actions={
          activeTab === 'feeds' ? (
            <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
              {bulkSyncing && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, fontSize: 11.5, color: 'var(--text-muted)' }}>
                  <div style={{ width: 100, height: 3, background: 'var(--bg-card2)', borderRadius: 2, overflow: 'hidden' }}>
                    <div
                      className="xsiam-bulk-bar"
                      style={{ width: bulkTotal > 0 ? `${(bulkProgress / bulkTotal) * 100}%` : '0%' }}
                    />
                  </div>
                  <span>{bulkProgress}/{bulkTotal}</span>
                </div>
              )}
              <button
                className="btn-secondary"
                disabled={bulkSyncing || statsActiveCount === 0}
                onClick={bulkSyncActive}
                style={{ fontSize: 12 }}
              >
                {bulkSyncing ? '批量同步中...' : `批量同步活跃Feed (${statsActiveCount})`}
              </button>
              <button className="btn-primary" onClick={openAdd}>+ 添加订阅源</button>
            </div>
          ) : activeTab === 'rules' ? (
            <button className="btn-primary" onClick={() => {/* handled inside tab */}}>+ 添加规则</button>
          ) : null
        }
      />

      {/* Tab Bar */}
      <div className="tab-bar">
        {TABS.map(t => (
          <button
            key={t.id}
            className={`tab${activeTab === t.id ? ' active' : ''}`}
            onClick={() => setActiveTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* ── Tab: Feeds ─────────────────────────────────────────────────────── */}
      {activeTab === 'feeds' && (
        <>
          {/* Feed Health Stats Bar */}
          <div style={{ display: 'flex', gap: 10, padding: '12px 0', flexWrap: 'wrap' }}>
            <StatTile
              label="活跃Feed数"
              value={statsActiveCount}
              borderColor="var(--accent-green)"
              pulse={statsSyncingCount > 0}
              pulseColor="var(--accent-green)"
              subLabel={statsSyncingCount > 0 ? `${statsSyncingCount} 正在同步` : undefined}
            />
            <StatTile
              label="今日同步次数"
              value={statsTodaySyncs}
              borderColor="var(--accent-blue)"
              pulse={false}
              subLabel="过去24小时"
            />
            <StatTile
              label="总IOC数"
              value={statsTotalIoc.toLocaleString()}
              borderColor="var(--accent-yellow, #f0a500)"
              pulse={false}
              subLabel="全部订阅源累计"
            />
            <StatTile
              label="同步失败"
              value={statsErrorCount}
              borderColor="var(--critical)"
              pulse={statsErrorCount > 0}
              pulseColor="var(--critical)"
              subLabel={statsErrorCount > 0 ? '需要检查' : '无异常'}
              danger={statsErrorCount > 0}
            />
          </div>

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
              <option value="csv">CSV</option>
              <option value="json">JSON</option>
              <option value="misp">MISP</option>
              <option value="otx">OTX</option>
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
                  <th>IOC数</th>
                  <th>最后同步</th>
                  <th>自动同步</th>
                  <th>操作</th>
                </tr>
              </thead>
              <tbody>
                {loading && <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>加载中...</td></tr>}
                {!loading && items.length === 0 && <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>No intel feeds configured</td></tr>}
                {items.map(f => (
                  <tr
                    key={f._key}
                    style={{ cursor: 'pointer' }}
                    onClick={e => {
                      const target = e.target as HTMLElement
                      if (target.closest('button') || target.closest('[role="switch"]')) return
                      setDetailFeed(f)
                    }}
                  >
                    <td>
                      <div style={{ fontSize: 12.5, fontWeight: 500 }}>
                        {FEED_TYPE_ICON[f.feed_type] ?? '📄'} {f.name}
                      </div>
                      {f.description && <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{f.description.slice(0, 60)}</div>}
                    </td>
                    <td>
                      <span style={{ fontSize: 11, padding: '2px 8px', background: 'var(--bg-card2)', border: '1px solid var(--border-light)', borderRadius: 3, textTransform: 'uppercase', fontFamily: 'monospace', letterSpacing: 0.3 }}>
                        {FEED_TYPE_ICON[f.feed_type] ?? ''} {f.feed_type || 'custom'}
                      </span>
                    </td>
                    <td>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11.5 }}>
                        <span style={{
                          width: 6, height: 6, borderRadius: '50%', display: 'inline-block',
                          background: STATUS_COLOR[f.status] ?? 'var(--text-muted)',
                          boxShadow: f.status === 'active' ? `0 0 4px ${STATUS_COLOR.active}` : f.status === 'syncing' ? `0 0 4px ${STATUS_COLOR.syncing}` : 'none',
                          animation: (f.status === 'syncing' || syncing === f._key) ? 'xsiam-syncing-pulse 1.2s ease-in-out infinite' : 'none',
                        }} />
                        {f.status || 'inactive'}
                      </span>
                    </td>
                    <td>
                      <span style={{ display: 'inline-block', background: 'var(--bg-card2)', border: '1px solid var(--border-light)', borderRadius: 3, padding: '2px 8px', fontSize: 11, fontFamily: 'monospace' }}>
                        {f.ioc_count?.toLocaleString() ?? '0'}
                      </span>
                    </td>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                      <div>{relTime(f.last_sync_at)}</div>
                      {f.sync_interval_hours > 0 && (
                        <div style={{ fontSize: 10, color: 'var(--text-muted)', opacity: 0.7, marginTop: 1 }}>
                          下次: {nextSyncTime(f.last_sync_at, f.sync_interval_hours)}
                        </div>
                      )}
                    </td>
                    <td>
                      <AutoSyncToggle
                        feed={f}
                        toggling={togglingAutoSync === f._key}
                        onToggle={() => toggleAutoSync(f)}
                      />
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
        </>
      )}

      {/* ── Tab: Indicator Rules ───────────────────────────────────────────── */}
      {activeTab === 'rules' && (
        <IndicatorRulesTab />
      )}

      {/* ── Tab: Sample Analysis ───────────────────────────────────────────── */}
      {activeTab === 'sandbox' && (
        <SampleAnalysisTab />
      )}

      {/* Add/Edit Feed Modal */}
      {showModal && (
        <>
          <div onClick={() => setShowModal(false)} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 460, background: 'var(--bg-modal)', border: '1px solid var(--border)',
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
                  <option value="stix_taxii">🔗 STIX/TAXII</option>
                  <option value="csv">📊 CSV</option>
                  <option value="json">📋 JSON</option>
                  <option value="misp">🛡 MISP</option>
                  <option value="otx">🔭 OTX</option>
                  <option value="mitre">🛡️ MITRE ATT&CK</option>
                  <option value="virustotal">🔍 VirusTotal</option>
                  <option value="custom">⚙ Custom</option>
                </select>
              </div>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>URL</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="https://feed.example.com/indicators" value={form.url} onChange={e => setForm(p => ({ ...p, url: e.target.value }))} />
              </div>
              <div style={{ display: 'flex', gap: 12 }}>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>Sync Interval (h)</div>
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

      {/* Detail Panel */}
      {detailFeed && (
        <>
          <div className="xsiam-detail-overlay" onClick={() => setDetailFeed(null)} />
          <div className="xsiam-detail-panel">
            <FeedDetailPanel
              feed={detailFeed}
              syncing={detailSyncing}
              togglingAutoSync={togglingAutoSync === detailFeed._key}
              onClose={() => setDetailFeed(null)}
              onSync={() => triggerDetailSync(detailFeed)}
              onToggleAutoSync={() => toggleAutoSync(detailFeed)}
              onEdit={() => { openEdit(detailFeed); setDetailFeed(null) }}
            />
          </div>
        </>
      )}
    </div>
  )
}

// ─── Indicator Rules Tab ──────────────────────────────────────────────────────

function IndicatorRulesTab() {
  const [rules, setRules] = useState<IndicatorRule[]>(MOCK_INDICATOR_RULES)
  const [showRuleModal, setShowRuleModal] = useState(false)
  const [editRule, setEditRule] = useState<IndicatorRule | null>(null)
  const [ruleForm, setRuleForm] = useState<Omit<IndicatorRule, 'id' | 'hit_count'>>({
    name: '',
    ioc_type: 'ip',
    confidence_threshold: 80,
    auto_block: false,
    action: 'alert',
    status: 'active',
  })

  function openAddRule() {
    setEditRule(null)
    setRuleForm({ name: '', ioc_type: 'ip', confidence_threshold: 80, auto_block: false, action: 'alert', status: 'active' })
    setShowRuleModal(true)
  }

  function openEditRule(r: IndicatorRule) {
    setEditRule(r)
    setRuleForm({ name: r.name, ioc_type: r.ioc_type, confidence_threshold: r.confidence_threshold, auto_block: r.auto_block, action: r.action, status: r.status })
    setShowRuleModal(true)
  }

  function saveRule() {
    if (!ruleForm.name.trim()) return
    if (editRule) {
      setRules(prev => prev.map(r => r.id === editRule.id ? { ...r, ...ruleForm } : r))
    } else {
      const newRule: IndicatorRule = { ...ruleForm, id: String(Date.now()), hit_count: 0 }
      setRules(prev => [...prev, newRule])
    }
    setShowRuleModal(false)
  }

  function toggleRuleStatus(id: string) {
    setRules(prev => prev.map(r => r.id === id ? { ...r, status: r.status === 'active' ? 'inactive' : 'active' } : r))
  }

  const iocTypeBadge = (t: IndicatorRule['ioc_type']) => {
    const colors: Record<string, string> = {
      ip: 'rgba(59,158,222,0.15)',
      domain: 'rgba(47,176,122,0.15)',
      hash: 'rgba(192,144,32,0.15)',
      url: 'rgba(208,112,48,0.15)',
    }
    const textColors: Record<string, string> = {
      ip: 'var(--accent-blue)',
      domain: 'var(--accent-green)',
      hash: 'var(--medium)',
      url: 'var(--high)',
    }
    return (
      <span style={{
        fontSize: 10.5, padding: '2px 8px', borderRadius: 3,
        background: colors[t] ?? 'var(--bg-card2)',
        color: textColors[t] ?? 'var(--text-muted)',
        border: `1px solid ${textColors[t] ?? 'var(--border-light)'}`,
        fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.3,
        fontFamily: 'monospace',
      }}>{t}</span>
    )
  }

  const actionBadge = (a: IndicatorRule['action']) => {
    const cfg = {
      block:   { bg: 'rgba(217,64,64,0.14)',   color: 'var(--critical)', label: '拦截' },
      alert:   { bg: 'rgba(192,144,32,0.14)',  color: 'var(--medium)',   label: '告警' },
      monitor: { bg: 'rgba(59,158,222,0.12)',  color: 'var(--accent-blue)', label: '监控' },
    }
    const c = cfg[a]
    return (
      <span style={{ fontSize: 10.5, padding: '2px 8px', borderRadius: 3, background: c.bg, color: c.color, border: `1px solid ${c.color}`, fontWeight: 600 }}>
        {c.label}
      </span>
    )
  }

  const confColor = (v: number) => v >= 90 ? 'var(--critical)' : v >= 75 ? 'var(--medium)' : 'var(--accent-blue)'

  return (
    <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 0 8px 0', flexShrink: 0 }}>
        <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{rules.length} 条规则</span>
        <button className="btn-primary" style={{ fontSize: 12 }} onClick={openAddRule}>+ 添加规则</button>
      </div>

      <div className="data-table-wrap">
        <table className="data-table">
          <thead>
            <tr>
              <th>规则名称</th>
              <th>指标类型</th>
              <th>置信度阈值</th>
              <th>处置动作</th>
              <th>自动封锁</th>
              <th>命中次数</th>
              <th>状态</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            {rules.map(r => (
              <tr key={r.id} className="xsiam-rule-row">
                <td style={{ fontWeight: 500, fontSize: 12.5 }}>{r.name}</td>
                <td>{iocTypeBadge(r.ioc_type)}</td>
                <td>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <div className="xsiam-conf-track" style={{ width: 72 }}>
                      <div
                        className="xsiam-conf-fill"
                        style={{ width: `${r.confidence_threshold}%`, background: confColor(r.confidence_threshold) }}
                      />
                    </div>
                    <span style={{ fontSize: 11.5, fontFamily: 'monospace', color: confColor(r.confidence_threshold), minWidth: 28 }}>
                      {r.confidence_threshold}
                    </span>
                  </div>
                </td>
                <td>{actionBadge(r.action)}</td>
                <td>
                  <span style={{
                    display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 11.5,
                    color: r.auto_block ? 'var(--critical)' : 'var(--text-muted)',
                  }}>
                    <span style={{
                      width: 14, height: 14, borderRadius: 3,
                      border: `1.5px solid ${r.auto_block ? 'var(--critical)' : 'var(--border-light)'}`,
                      background: r.auto_block ? 'rgba(217,64,64,0.2)' : 'transparent',
                      display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                      fontSize: 9, flexShrink: 0,
                    }}>
                      {r.auto_block ? '✓' : ''}
                    </span>
                    {r.auto_block ? '是' : '否'}
                  </span>
                </td>
                <td>
                  <span style={{ fontSize: 12, fontFamily: 'monospace', color: r.hit_count > 0 ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                    {r.hit_count}
                  </span>
                </td>
                <td>
                  <button
                    role="switch"
                    aria-checked={r.status === 'active'}
                    onClick={() => toggleRuleStatus(r.id)}
                    className="xsiam-toggle"
                    style={{
                      background: r.status === 'active' ? 'var(--accent-green)' : 'var(--bg-card2)',
                      boxShadow: r.status === 'active' ? '0 0 4px var(--accent-green)' : 'inset 0 0 0 1px var(--border-light)',
                    }}
                  >
                    <span className="xsiam-toggle-knob" style={{ left: r.status === 'active' ? 18 : 2 }} />
                  </button>
                </td>
                <td>
                  <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px' }} onClick={() => openEditRule(r)}>编辑</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Add/Edit Rule Modal */}
      {showRuleModal && (
        <>
          <div onClick={() => setShowRuleModal(false)} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 480, background: 'var(--bg-modal)', border: '1px solid var(--border)',
            borderRadius: 8, zIndex: 500, padding: 24,
          }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 20 }}>
              {editRule ? '编辑指标规则' : '添加指标规则'}
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>规则名称 *</div>
                <input
                  className="filter-input"
                  style={{ width: '100%', boxSizing: 'border-box' }}
                  placeholder="例: 高危IP自动封锁"
                  value={ruleForm.name}
                  onChange={e => setRuleForm(p => ({ ...p, name: e.target.value }))}
                />
              </div>
              <div style={{ display: 'flex', gap: 12 }}>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>指标类型</div>
                  <select
                    className="filter-select"
                    style={{ width: '100%' }}
                    value={ruleForm.ioc_type}
                    onChange={e => setRuleForm(p => ({ ...p, ioc_type: e.target.value as IndicatorRule['ioc_type'] }))}
                  >
                    <option value="ip">IP地址</option>
                    <option value="domain">域名</option>
                    <option value="hash">文件哈希</option>
                    <option value="url">URL</option>
                  </select>
                </div>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>处置动作</div>
                  <select
                    className="filter-select"
                    style={{ width: '100%' }}
                    value={ruleForm.action}
                    onChange={e => setRuleForm(p => ({ ...p, action: e.target.value as IndicatorRule['action'] }))}
                  >
                    <option value="alert">告警</option>
                    <option value="block">拦截</option>
                    <option value="monitor">监控</option>
                  </select>
                </div>
              </div>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>
                  置信度阈值: <span style={{ color: confColor(ruleForm.confidence_threshold), fontWeight: 600 }}>{ruleForm.confidence_threshold}</span>
                </div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <input
                    type="range"
                    min={0} max={100}
                    value={ruleForm.confidence_threshold}
                    onChange={e => setRuleForm(p => ({ ...p, confidence_threshold: parseInt(e.target.value) }))}
                    style={{ flex: 1, accentColor: confColor(ruleForm.confidence_threshold) }}
                  />
                  <div className="xsiam-conf-track" style={{ width: 60 }}>
                    <div className="xsiam-conf-fill" style={{ width: `${ruleForm.confidence_threshold}%`, background: confColor(ruleForm.confidence_threshold) }} />
                  </div>
                </div>
              </div>
              <div style={{ display: 'flex', gap: 12 }}>
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>状态</div>
                  <select
                    className="filter-select"
                    style={{ width: '100%' }}
                    value={ruleForm.status}
                    onChange={e => setRuleForm(p => ({ ...p, status: e.target.value as 'active' | 'inactive' }))}
                  >
                    <option value="active">启用</option>
                    <option value="inactive">停用</option>
                  </select>
                </div>
                <div style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
                  <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>自动封锁</div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, paddingTop: 4 }}>
                    <button
                      role="switch"
                      aria-checked={ruleForm.auto_block}
                      onClick={() => setRuleForm(p => ({ ...p, auto_block: !p.auto_block }))}
                      className="xsiam-toggle"
                      style={{
                        background: ruleForm.auto_block ? 'var(--critical)' : 'var(--bg-card2)',
                        boxShadow: ruleForm.auto_block ? '0 0 4px var(--critical)' : 'inset 0 0 0 1px var(--border-light)',
                      }}
                    >
                      <span className="xsiam-toggle-knob" style={{ left: ruleForm.auto_block ? 18 : 2 }} />
                    </button>
                    <span style={{ fontSize: 11.5, color: ruleForm.auto_block ? 'var(--critical)' : 'var(--text-muted)' }}>
                      {ruleForm.auto_block ? '开启' : '关闭'}
                    </span>
                  </div>
                </div>
              </div>
              <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setShowRuleModal(false)}>取消</button>
                <button
                  className="btn-primary"
                  style={{ flex: 1 }}
                  disabled={!ruleForm.name.trim()}
                  onClick={saveRule}
                >
                  {editRule ? '保存修改' : '添加规则'}
                </button>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  )
}

// ─── Sample Analysis Tab ──────────────────────────────────────────────────────

function SampleAnalysisTab() {
  const [selectedSample, setSelectedSample] = useState<SampleResult | null>(null)
  const [dragOver, setDragOver] = useState(false)

  const verdictConfig = {
    malicious:  { label: '恶意', dot: '🔴', color: 'var(--critical)',      bg: 'rgba(217,64,64,0.12)'  },
    suspicious: { label: '可疑', dot: '🟡', color: 'var(--medium)',        bg: 'rgba(192,144,32,0.12)' },
    clean:      { label: '正常', dot: '🟢', color: 'var(--accent-green)', bg: 'rgba(47,176,122,0.12)' },
  }

  const scoreBarColor = (score: number) =>
    score >= 80 ? 'var(--critical)' : score >= 50 ? 'var(--medium)' : 'var(--accent-green)'

  return (
    <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
      {/* Upload Zone */}
      <div style={{ flexShrink: 0, padding: '12px 0' }}>
        <div
          className="xsiam-upload-zone"
          style={{ borderColor: dragOver ? 'var(--accent-blue)' : undefined, background: dragOver ? 'rgba(59,158,222,0.06)' : undefined }}
          onDragOver={e => { e.preventDefault(); setDragOver(true) }}
          onDragLeave={() => setDragOver(false)}
          onDrop={e => { e.preventDefault(); setDragOver(false) }}
        >
          <div style={{ fontSize: 28, marginBottom: 8, opacity: 0.5 }}>📂</div>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 4 }}>拖放文件或点击上传</div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 12 }}>支持 EXE, DLL, PDF, DOC, ZIP 等格式 · 最大 50 MB</div>
          <button className="btn-secondary" style={{ fontSize: 12 }}>Browse</button>
        </div>
      </div>

      {/* Results area */}
      <div style={{ flex: 1, overflow: 'hidden', display: 'flex', gap: 16 }}>
        {/* Sample list */}
        <div style={{ width: selectedSample ? 340 : '100%', flexShrink: 0, overflow: 'auto' }}>
          <div style={{ fontSize: 11.5, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 8, letterSpacing: 0.3, textTransform: 'uppercase' }}>
            最近分析记录
          </div>
          {MOCK_SAMPLES.map(s => {
            const vc = verdictConfig[s.verdict]
            return (
              <div
                key={s.id}
                className={`xsiam-sample-row${selectedSample?.id === s.id ? ' selected' : ''}`}
                onClick={() => setSelectedSample(selectedSample?.id === s.id ? null : s)}
              >
                <div style={{
                  width: 36, height: 36, borderRadius: 6, flexShrink: 0,
                  background: vc.bg,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: 18,
                }}>
                  {vc.dot}
                </div>
                <div style={{ flex: 1, minWidth: 0 }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 3 }}>
                    <span style={{ fontSize: 12.5, fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'monospace' }}>{s.filename}</span>
                    <span style={{
                      fontSize: 10.5, padding: '1px 7px', borderRadius: 3,
                      background: vc.bg, color: vc.color,
                      border: `1px solid ${vc.color}`, fontWeight: 600,
                    }}>{vc.label}</span>
                  </div>
                  <div style={{ fontSize: 10.5, color: 'var(--text-muted)', fontFamily: 'monospace', marginBottom: 3, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    SHA256: {s.sha256.slice(0, 24)}...
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    {/* Score bar */}
                    <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                      <div style={{ width: 60, height: 3, background: 'var(--bg-card2)', borderRadius: 2, overflow: 'hidden' }}>
                        <div style={{ width: `${s.score}%`, height: '100%', background: scoreBarColor(s.score), borderRadius: 2, transition: 'width 0.4s ease' }} />
                      </div>
                      <span style={{ fontSize: 11, fontFamily: 'monospace', color: scoreBarColor(s.score), fontWeight: 600 }}>{s.score}/100</span>
                    </div>
                    <span style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>{s.analyzed_at}</span>
                  </div>
                </div>
                <span style={{ fontSize: 11, color: 'var(--text-muted)', flexShrink: 0 }}>›</span>
              </div>
            )
          })}
        </div>

        {/* Detail panel */}
        {selectedSample && (
          <div className="xsiam-sample-detail" style={{ flex: 1, overflow: 'auto', borderLeft: '1px solid var(--border-light)', paddingLeft: 16 }}>
            <SampleDetailPanel sample={selectedSample} onClose={() => setSelectedSample(null)} />
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Sample Detail Panel ──────────────────────────────────────────────────────

function SampleDetailPanel({ sample, onClose }: { sample: SampleResult; onClose: () => void }) {
  const verdictConfig = {
    malicious:  { label: '恶意', color: 'var(--critical)',      bg: 'rgba(217,64,64,0.12)',  dot: '🔴' },
    suspicious: { label: '可疑', color: 'var(--medium)',        bg: 'rgba(192,144,32,0.12)', dot: '🟡' },
    clean:      { label: '正常', color: 'var(--accent-green)', bg: 'rgba(47,176,122,0.12)', dot: '🟢' },
  }
  const vc = verdictConfig[sample.verdict]
  const scoreBarColor = (s: number) => s >= 80 ? 'var(--critical)' : s >= 50 ? 'var(--medium)' : 'var(--accent-green)'

  return (
    <div>
      {/* Header */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', marginBottom: 16 }}>
        <div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
            <span style={{ fontSize: 16 }}>{vc.dot}</span>
            <span style={{ fontSize: 14, fontWeight: 700, fontFamily: 'monospace' }}>{sample.filename}</span>
            <span style={{
              fontSize: 11, padding: '2px 8px', borderRadius: 3,
              background: vc.bg, color: vc.color, border: `1px solid ${vc.color}`, fontWeight: 600,
            }}>{vc.label}</span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <div style={{ width: 100, height: 5, background: 'var(--bg-card2)', borderRadius: 3, overflow: 'hidden' }}>
              <div style={{ width: `${sample.score}%`, height: '100%', background: scoreBarColor(sample.score), borderRadius: 3 }} />
            </div>
            <span style={{ fontSize: 13, fontWeight: 700, fontFamily: 'monospace', color: scoreBarColor(sample.score) }}>
              {sample.score}/100
            </span>
          </div>
        </div>
        <button className="btn-secondary" style={{ fontSize: 15, padding: '2px 8px', lineHeight: 1 }} onClick={onClose}>×</button>
      </div>

      {/* File info */}
      <Section title="文件信息">
        <InfoGrid items={[
          { label: '文件名', value: sample.filename },
          { label: '文件大小', value: sample.file_size },
          { label: '文件类型', value: sample.file_type },
          { label: '分析时间', value: sample.analyzed_at },
        ]} />
        <div style={{ marginTop: 8, padding: '8px 10px', background: 'var(--bg-card2)', borderRadius: 4, fontFamily: 'monospace', fontSize: 10.5, color: 'var(--text-muted)', wordBreak: 'break-all' }}>
          SHA256: {sample.sha256}
        </div>
      </Section>

      {/* MITRE ATT&CK */}
      {sample.mitre_techniques && sample.mitre_techniques.length > 0 && (
        <Section title="MITRE ATT&CK 技术">
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
            {sample.mitre_techniques.map(t => (
              <span key={t} className="xsiam-mitre-tag">{t}</span>
            ))}
          </div>
        </Section>
      )}

      {/* Behavior */}
      <Section title="行为摘要">
        {sample.behaviors.network_connections.length > 0 && (
          <BehaviorGroup icon="🌐" label="网络连接" items={sample.behaviors.network_connections} />
        )}
        {sample.behaviors.registry_changes.length > 0 && (
          <BehaviorGroup icon="🔑" label="注册表修改" items={sample.behaviors.registry_changes} />
        )}
        {sample.behaviors.file_operations.length > 0 && (
          <BehaviorGroup icon="📁" label="文件操作" items={sample.behaviors.file_operations} />
        )}
      </Section>

      {/* Screenshots placeholder */}
      <Section title="沙箱截图">
        <div style={{
          height: 100, borderRadius: 6,
          background: 'var(--bg-card2)',
          border: '1px solid var(--border-light)',
          display: 'flex', alignItems: 'center', justifyContent: 'center',
          flexDirection: 'column', gap: 6,
          color: 'var(--text-muted)',
        }}>
          <span style={{ fontSize: 22, opacity: 0.35 }}>🖥</span>
          <span style={{ fontSize: 11.5 }}>沙箱截图</span>
        </div>
      </Section>
    </div>
  )
}

function Section({ title, children }: { title: string; children: React.ReactNode }) {
  return (
    <div style={{ marginBottom: 16 }}>
      <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 8, paddingBottom: 4, borderBottom: '1px solid var(--border-light)' }}>
        {title}
      </div>
      {children}
    </div>
  )
}

function InfoGrid({ items }: { items: { label: string; value: string }[] }) {
  return (
    <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: '6px 12px' }}>
      {items.map(it => (
        <div key={it.label}>
          <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginBottom: 2 }}>{it.label}</div>
          <div style={{ fontSize: 12, fontFamily: 'monospace', color: 'var(--text-primary)' }}>{it.value}</div>
        </div>
      ))}
    </div>
  )
}

function BehaviorGroup({ icon, label, items }: { icon: string; label: string; items: string[] }) {
  return (
    <div style={{ marginBottom: 8 }}>
      <div style={{ fontSize: 11.5, color: 'var(--text-secondary)', marginBottom: 4, display: 'flex', alignItems: 'center', gap: 5 }}>
        <span>{icon}</span> {label}
      </div>
      {items.map((item, i) => (
        <div key={i} style={{
          fontSize: 11, fontFamily: 'monospace', color: 'var(--text-muted)',
          padding: '3px 8px', borderLeft: '2px solid var(--border-light)',
          marginBottom: 2, wordBreak: 'break-word',
        }}>
          {item}
        </div>
      ))}
    </div>
  )
}

// ─── Sub-components ───────────────────────────────────────────────────────────

interface StatTileProps {
  label: string
  value: string | number
  borderColor: string
  pulse: boolean
  pulseColor?: string
  subLabel?: string
  danger?: boolean
}

function StatTile({ label, value, borderColor, pulse, pulseColor, subLabel, danger }: StatTileProps) {
  return (
    <div className="xsiam-stat-tile">
      <div className="xsiam-stat-tile-border" style={{ background: borderColor }} />
      <div style={{ paddingLeft: 8 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 4 }}>
          <span style={{ fontSize: 11, color: 'var(--text-muted)', letterSpacing: 0.3 }}>{label}</span>
          {pulse && pulseColor && (
            <span style={{
              width: 6, height: 6, borderRadius: '50%', display: 'inline-block',
              background: pulseColor,
              animation: 'xsiam-syncing-pulse 1.2s ease-in-out infinite',
              flexShrink: 0,
            }} />
          )}
        </div>
        <div style={{
          fontSize: 22, fontWeight: 700, fontFamily: 'monospace',
          color: danger ? 'var(--critical)' : 'var(--text-primary)',
          lineHeight: 1.1,
        }}>
          {value}
        </div>
        {subLabel && (
          <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginTop: 3 }}>{subLabel}</div>
        )}
      </div>
    </div>
  )
}

interface AutoSyncToggleProps {
  feed: Feed
  toggling: boolean
  onToggle: () => void
}

function AutoSyncToggle({ feed, toggling, onToggle }: AutoSyncToggleProps) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
      <button
        role="switch"
        aria-checked={!!feed.auto_sync}
        disabled={toggling}
        onClick={onToggle}
        className="xsiam-toggle"
        style={{
          background: feed.auto_sync ? 'var(--accent-blue)' : 'var(--bg-card2)',
          boxShadow: feed.auto_sync ? '0 0 4px var(--accent-blue)' : 'inset 0 0 0 1px var(--border-light)',
          cursor: toggling ? 'wait' : 'pointer',
          opacity: toggling ? 0.5 : 1,
        }}
      >
        <span className="xsiam-toggle-knob" style={{ left: feed.auto_sync ? 18 : 2 }} />
      </button>
      {feed.auto_sync && feed.sync_interval_hours > 0 && (
        <span style={{ fontSize: 10.5, color: 'var(--accent-blue)', whiteSpace: 'nowrap' }}>
          每{feed.sync_interval_hours}h
        </span>
      )}
    </div>
  )
}

interface FeedDetailPanelProps {
  feed: Feed
  syncing: boolean
  togglingAutoSync: boolean
  onClose: () => void
  onSync: () => void
  onToggleAutoSync: () => void
  onEdit: () => void
}

function FeedDetailPanel({ feed, syncing, togglingAutoSync, onClose, onSync, onToggleAutoSync, onEdit }: FeedDetailPanelProps) {
  const history = mockSyncHistory(feed)
  const typeIcon = FEED_TYPE_ICON[feed.feed_type] ?? '📄'

  const truncateUrl = (url: string, max = 48) =>
    url.length > max ? url.slice(0, max) + '…' : url

  return (
    <>
      {/* Panel Header */}
      <div style={{
        padding: '16px 18px',
        borderBottom: '1px solid var(--border-light)',
        display: 'flex',
        alignItems: 'flex-start',
        gap: 12,
      }}>
        <div style={{ flex: 1, minWidth: 0 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
            <span style={{ fontSize: 20 }}>{typeIcon}</span>
            <span style={{ fontSize: 14, fontWeight: 600, color: 'var(--text-primary)' }}>{feed.name}</span>
            <span style={{
              fontSize: 10, padding: '2px 7px', background: 'var(--bg-card2)',
              border: '1px solid var(--border-light)', borderRadius: 3,
              textTransform: 'uppercase', fontFamily: 'monospace', letterSpacing: 0.4, color: 'var(--text-muted)',
            }}>
              {feed.feed_type || 'custom'}
            </span>
            <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 11 }}>
              <span style={{
                width: 7, height: 7, borderRadius: '50%', display: 'inline-block',
                background: STATUS_COLOR[feed.status] ?? 'var(--text-muted)',
                boxShadow: feed.status === 'syncing' ? `0 0 5px ${STATUS_COLOR.syncing}` : 'none',
                animation: feed.status === 'syncing' ? 'xsiam-syncing-pulse 1.2s ease-in-out infinite' : 'none',
              }} />
              <span style={{ color: STATUS_COLOR[feed.status] ?? 'var(--text-muted)' }}>{feed.status}</span>
            </span>
          </div>
          {feed.description && (
            <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>{feed.description}</div>
          )}
          {feed.url && (
            <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'monospace', wordBreak: 'break-all' }}>
              {truncateUrl(feed.url)}
            </div>
          )}
        </div>
        <button className="btn-secondary" style={{ fontSize: 16, padding: '2px 8px', lineHeight: 1 }} onClick={onClose}>×</button>
      </div>

      {/* Sync Info */}
      <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border-light)', display: 'flex', gap: 20, flexWrap: 'wrap' }}>
        <InfoBlock label="最后同步" value={relTime(feed.last_sync_at)} sub={feed.last_sync_at ? fmtDate(feed.last_sync_at) : undefined} />
        <InfoBlock label="下次同步" value={nextSyncTime(feed.last_sync_at, feed.sync_interval_hours)} sub={`间隔 ${feed.sync_interval_hours || '-'}h`} />
        <InfoBlock label="IOC总数" value={feed.ioc_count?.toLocaleString() ?? '0'} />
        <div>
          <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginBottom: 6 }}>自动同步</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
            <button
              role="switch"
              aria-checked={!!feed.auto_sync}
              disabled={togglingAutoSync}
              onClick={onToggleAutoSync}
              className="xsiam-toggle"
              style={{
                background: feed.auto_sync ? 'var(--accent-blue)' : 'var(--bg-card2)',
                boxShadow: feed.auto_sync ? '0 0 4px var(--accent-blue)' : 'inset 0 0 0 1px var(--border-light)',
                cursor: togglingAutoSync ? 'wait' : 'pointer',
                opacity: togglingAutoSync ? 0.5 : 1,
              }}
            >
              <span className="xsiam-toggle-knob" style={{ left: feed.auto_sync ? 18 : 2 }} />
            </button>
            <span style={{ fontSize: 11, color: feed.auto_sync ? 'var(--accent-blue)' : 'var(--text-muted)' }}>
              {feed.auto_sync ? `自动同步: 每${feed.sync_interval_hours || '-'}h` : '手动'}
            </span>
          </div>
        </div>
      </div>

      {/* Action Buttons */}
      <div style={{ padding: '12px 18px', borderBottom: '1px solid var(--border-light)', display: 'flex', gap: 8 }}>
        <button className="btn-primary" disabled={syncing} onClick={onSync} style={{ fontSize: 12.5, flex: 1 }}>
          {syncing ? (
            <span style={{ display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 7 }}>
              <span style={{ width: 8, height: 8, borderRadius: '50%', background: 'var(--accent-blue)', animation: 'xsiam-syncing-pulse 1.2s ease-in-out infinite', display: 'inline-block' }} />
              同步中...
            </span>
          ) : '立即同步'}
        </button>
        <button className="btn-secondary" style={{ fontSize: 12.5 }} onClick={onEdit}>编辑</button>
      </div>

      {/* Sync History Timeline */}
      <div style={{ flex: 1, overflow: 'auto', padding: '14px 18px' }}>
        <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 10 }}>同步历史 (最近5次)</div>
        <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11.5 }}>
          <thead>
            <tr style={{ borderBottom: '1px solid var(--border-light)' }}>
              <th style={{ textAlign: 'left', padding: '4px 8px 6px 0', color: 'var(--text-muted)', fontWeight: 500 }}>时间</th>
              <th style={{ textAlign: 'right', padding: '4px 8px 6px', color: 'var(--text-muted)', fontWeight: 500 }}>耗时</th>
              <th style={{ textAlign: 'right', padding: '4px 8px 6px', color: 'var(--text-muted)', fontWeight: 500 }}>新增IOC</th>
              <th style={{ textAlign: 'center', padding: '4px 0 6px 8px', color: 'var(--text-muted)', fontWeight: 500 }}>状态</th>
            </tr>
          </thead>
          <tbody>
            {history.map((row, i) => (
              <tr key={i} style={{ borderBottom: '1px solid var(--border-light)', opacity: i === 0 ? 1 : 0.7 + i * 0.05 }}>
                <td style={{ padding: '6px 8px 6px 0', fontFamily: 'monospace', fontSize: 11 }}>{row.date}</td>
                <td style={{ padding: '6px 8px', textAlign: 'right', fontFamily: 'monospace' }}>{row.duration}s</td>
                <td style={{ padding: '6px 8px', textAlign: 'right', fontFamily: 'monospace', color: 'var(--accent-green)' }}>+{row.ioc_added}</td>
                <td style={{ padding: '6px 0 6px 8px', textAlign: 'center' }}>
                  <span style={{
                    fontSize: 10, padding: '2px 7px', borderRadius: 3,
                    background: row.status === 'success' ? 'rgba(var(--accent-green-rgb, 52,199,89), 0.12)' : 'rgba(var(--critical-rgb, 255,59,48), 0.12)',
                    color: row.status === 'success' ? 'var(--accent-green)' : 'var(--critical)',
                    border: `1px solid ${row.status === 'success' ? 'var(--accent-green)' : 'var(--critical)'}`,
                    fontWeight: 500,
                  }}>
                    {row.status === 'success' ? '成功' : '失败'}
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </>
  )
}

function InfoBlock({ label, value, sub }: { label: string; value: string | number; sub?: string }) {
  return (
    <div>
      <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginBottom: 3 }}>{label}</div>
      <div style={{ fontSize: 13.5, fontWeight: 600, color: 'var(--text-primary)', fontFamily: 'monospace' }}>{value}</div>
      {sub && <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>{sub}</div>}
    </div>
  )
}
