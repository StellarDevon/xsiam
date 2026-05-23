import { useEffect, useState } from 'react'
import api from '@/lib/api'
import type { PageMeta } from '@/lib/api'
import PageHeader from '@/components/PageHeader'

interface IOC {
  _key: string
  type: string
  value: string
  verdict: string
  threat_name: string
  confidence: number
  reliability: string
  severity: string
  source: string
  source_name: string
  tags: string[]
  related_incidents: string[]
  active: boolean
  expiry: string
  last_seen: string
  created_at: string
}

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

interface IndicatorRule {
  _key: string
  name: string
  trigger_type: string
  ioc_types: string[]
  action: string
  status: string
  hits_30d: number
  created_at: string
}

interface 样本 {
  _key: string
  filename: string
  sha256: string
  verdict: string
  file_type: string
  size: number
  submitted_at: string
  completed_at: string
  score: number
}

interface TIMReport {
  _key: string
  title: string
  report_type: string
  status: string
  created_by: string
  created_at: string
  period_start: string
  period_end: string
}

type Tab = 'indicators' | 'feeds' | 'rules' | 'samples' | 'sessions' | 'reports' | 'trc'

const IOC_TYPES = ['ip', 'domain', 'url', 'hash', 'email', 'cve', 'cidr', 'registry', 'user_agent', 'mutex']

const IOC_LABELS: Record<string, string> = {
  ip: 'IP Address', domain: 'Domain', url: 'URL', hash: 'File Hash',
  email: 'Email', cve: 'CVE', cidr: 'CIDR', registry: 'Registry Key',
  user_agent: 'User Agent', mutex: 'Mutex',
}

const typeColor: Record<string, string> = {
  ip: '#4fa3e0', domain: '#a78bfa', url: '#00c896',
  hash: '#f9a825', email: '#fa582d', cve: '#90a4ae',
  cidr: '#4fa3e0', registry: '#ff6f00', user_agent: '#26a69a', mutex: '#ce93d8',
}

const verdictConfig: Record<string, { bg: string; color: string; label: string }> = {
  malicious:  { bg: 'rgba(229,57,53,.18)',   color: '#ef5350', label: '恶意' },
  suspicious: { bg: 'rgba(255,111,0,.15)',   color: '#ffa726', label: '可疑' },
  benign:     { bg: 'rgba(67,160,71,.15)',   color: '#66bb6a', label: '无害' },
  unknown:    { bg: 'rgba(84,110,122,.15)',  color: '#90a4ae', label: '未知' },
}

const feedStatusColor: Record<string, string> = {
  active: 'var(--accent-green)', inactive: 'var(--text-muted)',
  error: 'var(--critical)', syncing: 'var(--accent-blue)',
}

const feedTypeIcon: Record<string, string> = {
  stix_taxii: '⚠', misp: '🔗', custom: '⚙️', mitre: '🛡️',
  virustotal: '🔍', unit42: '🦅', wildfire: '🔥',
}

function fmtDate(iso: string) {
  if (!iso) return '-'
  return new Date(iso).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false })
}

function fmtBytes(n: number) {
  if (!n) return '-'
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
}

function 判定结论Badge({ verdict }: { verdict: string }) {
  const cfg = verdictConfig[verdict?.toLowerCase()] ?? verdictConfig.unknown
  return (
    <span style={{ padding: '2px 8px', borderRadius: 3, fontSize: 10.5, fontWeight: 700, background: cfg.bg, color: cfg.color }}>
      {cfg.label}
    </span>
  )
}

const BLANK_IOC = { type: 'ip', value: '', verdict: 'unknown', confidence: '50', source_name: '', threat_name: '', tags: '' }
const BLANK_FEED = { name: '', description: '', feed_type: 'custom', url: '', sync_interval: '60', status: 'active' }
const BLANK_RULE = { name: '', trigger_type: 'match', ioc_types: 'ip,domain', action: 'alert', status: 'active' }
const BLANK_REPORT = { title: '', report_type: 'weekly', period_start: '', period_end: '' }

export default function ThreatIntel() {
  const [tab, setTab] = useState<Tab>('indicators')

  // IOC state
  const [iocs, setIocs] = useState<IOC[]>([])
  const [iocMeta, setIocMeta] = useState<PageMeta>({ page: 1, page_size: 20, total: 0, total_pages: 1 })
  const [iocPage, setIocPage] = useState(1)
  const [iocLoading, setIocLoading] = useState(false)
  const [typeFilter, setTypeFilter] = useState('')
  const [verdictFilter, set判定结论Filter] = useState('')
  const [search, setSearch] = useState('')
  const [verdictCounts, set判定结论Counts] = useState<Record<string, number>>({})

  // Feed state
  const [feeds, set订阅源] = useState<Feed[]>([])
  const [feedMeta, setFeedMeta] = useState<PageMeta>({ page: 1, page_size: 20, total: 0, total_pages: 1 })
  const [feedPage, setFeedPage] = useState(1)
  const [feedLoading, setFeedLoading] = useState(false)
  const [syncing, setSyncing] = useState<string | null>(null)
  const [feedSearch, setFeedSearch] = useState('')
  const [feedTypeFilter, setFeedTypeFilter] = useState('')
  const [feedStatusFilter, setFeedStatusFilter] = useState('')

  // Indicator Rules state
  const [rules, setRules] = useState<IndicatorRule[]>([])
  const [rulesLoading, setRulesLoading] = useState(false)
  const [showRuleModal, setShowRuleModal] = useState(false)
  const [editRule, setEditRule] = useState<IndicatorRule | null>(null)
  const [ruleForm, setRuleForm] = useState(BLANK_RULE)
  const [savingRule, setSavingRule] = useState(false)

  // 样本 state
  const [samples, set样本s] = useState<样本[]>([])
  const [samplesLoading, set样本sLoading] = useState(false)
  const [show提交Modal, setShow提交Modal] = useState(false)
  const [submitFile, set提交File] = useState('')
  const [submitUrl, set提交Url] = useState('')
  const [submitting, set提交ting] = useState(false)

  // 报告 state
  const [reports, set报告] = useState<TIMReport[]>([])
  const [reportsLoading, set报告Loading] = useState(false)
  const [showReportModal, setShowReportModal] = useState(false)
  const [reportForm, setReportForm] = useState(BLANK_REPORT)
  const [savingReport, setSavingReport] = useState(false)

  // IOC modal
  const [showIocModal, setShowIocModal] = useState(false)
  const [editIoc, setEditIoc] = useState<IOC | null>(null)
  const [iocForm, setIocForm] = useState(BLANK_IOC)
  const [savingIoc, setSavingIoc] = useState(false)

  // Feed modal
  const [showFeedModal, setShowFeedModal] = useState(false)
  const [editFeed, setEditFeed] = useState<Feed | null>(null)
  const [feedForm, setFeedForm] = useState(BLANK_FEED)
  const [savingFeed, setSavingFeed] = useState(false)

  // 威胁响应中心 block state
  const [blockingTrc, setBlockingTrc] = useState<string | null>(null)

  function loadIocs(p = iocPage) {
    setIocLoading(true)
    const params: any = { page: p, page_size: 20 }
    if (typeFilter) params.type = typeFilter
    if (verdictFilter) params.verdict = verdictFilter
    if (search) params.keyword = search
    api.get('/iocs', { params })
      .then(r => {
        setIocs(r.data.data?.items ?? [])
        setIocMeta(r.data.data?.meta ?? iocMeta)
        const counts = r.data.data?.verdict_counts ?? {}
        if (Object.keys(counts).length) set判定结论Counts(counts)
      })
      .finally(() => setIocLoading(false))
  }

  function load订阅源(p = feedPage) {
    setFeedLoading(true)
    const params: any = { page: p, page_size: 20 }
    if (feedSearch) params.keyword = feedSearch
    if (feedTypeFilter) params.feed_type = feedTypeFilter
    if (feedStatusFilter) params.status = feedStatusFilter
    api.get('/intel_feeds', { params })
      .then(r => { set订阅源(r.data.data?.items ?? []); setFeedMeta(r.data.data?.meta ?? feedMeta) })
      .finally(() => setFeedLoading(false))
  }

  function loadRules() {
    setRulesLoading(true)
    api.get('/threat_intel/rules', { params: { page: 1, page_size: 50 } })
      .then(r => setRules(r.data.data?.items ?? []))
      .catch(() => setRules([]))
      .finally(() => setRulesLoading(false))
  }

  function load样本s() {
    set样本sLoading(true)
    api.get('/threat_intel/samples', { params: { page: 1, page_size: 20 } })
      .then(r => set样本s(r.data.data?.items ?? []))
      .catch(() => set样本s([]))
      .finally(() => set样本sLoading(false))
  }

  function load报告() {
    set报告Loading(true)
    api.get('/threat_intel/reports', { params: { page: 1, page_size: 20 } })
      .then(r => set报告(r.data.data?.items ?? []))
      .catch(() => set报告([]))
      .finally(() => set报告Loading(false))
  }

  useEffect(() => { loadIocs(1); setIocPage(1) }, [typeFilter, verdictFilter])
  useEffect(() => { loadIocs(iocPage) }, [iocPage])
  useEffect(() => { loadIocs(1) }, [])
  useEffect(() => { if (tab === 'feeds') load订阅源(feedPage) }, [feedPage, tab])
  useEffect(() => { if (tab === 'feeds') load订阅源(1) }, [feedSearch, feedTypeFilter, feedStatusFilter])
  useEffect(() => { if (tab === 'rules' && rules.length === 0) loadRules() }, [tab])
  useEffect(() => { if (tab === 'samples' && samples.length === 0) load样本s() }, [tab])
  useEffect(() => { if (tab === 'reports' && reports.length === 0) load报告() }, [tab])

  function syncFeed(key: string) {
    setSyncing(key)
    api.post(`/intel_feeds/${key}/sync`).then(() => load订阅源(feedPage)).finally(() => setSyncing(null))
  }

  // IOC CRUD
  function openCreateIoc() { setEditIoc(null); setIocForm(BLANK_IOC); setShowIocModal(true) }
  function openEditIoc(ioc: IOC) {
    setEditIoc(ioc)
    setIocForm({ type: ioc.type, value: ioc.value, verdict: ioc.verdict, confidence: String(ioc.confidence ?? 50), source_name: ioc.source_name || ioc.source || '', threat_name: ioc.threat_name || '', tags: (ioc.tags ?? []).join(', ') })
    setShowIocModal(true)
  }
  function saveIoc() {
    if (!iocForm.value.trim()) return
    setSavingIoc(true)
    const body = { type: iocForm.type, value: iocForm.value, verdict: iocForm.verdict, confidence: parseInt(iocForm.confidence) || 50, source_name: iocForm.source_name, threat_name: iocForm.threat_name, tags: iocForm.tags ? iocForm.tags.split(',').map(s => s.trim()).filter(Boolean) : [], is_active: true }
    const req = editIoc ? api.patch(`/iocs/${editIoc._key}`, body) : api.post('/iocs', body)
    req.then(() => { setShowIocModal(false); loadIocs(1) }).finally(() => setSavingIoc(false))
  }
  function deleteIoc(ioc: IOC) {
    if (!confirm(`Delete IOC ${ioc.value}?`)) return
    api.delete(`/iocs/${ioc._key}`).then(() => loadIocs(1))
  }

  // Feed CRUD
  function openCreateFeed() { setEditFeed(null); setFeedForm(BLANK_FEED); setShowFeedModal(true) }
  function openEditFeed(f: Feed) {
    setEditFeed(f)
    setFeedForm({ name: f.name, description: f.description || '', feed_type: f.feed_type || 'custom', url: f.url || '', sync_interval: String(f.sync_interval ?? 60), status: f.status || 'active' })
    setShowFeedModal(true)
  }
  function saveFeed() {
    if (!feedForm.name.trim()) return
    setSavingFeed(true)
    const body = { name: feedForm.name, description: feedForm.description, feed_type: feedForm.feed_type, url: feedForm.url, sync_interval: parseInt(feedForm.sync_interval) || 60, status: feedForm.status }
    const req = editFeed ? api.patch(`/intel_feeds/${editFeed._key}`, body) : api.post('/intel_feeds', body)
    req.then(() => { setShowFeedModal(false); load订阅源(1) }).finally(() => setSavingFeed(false))
  }
  function deleteFeed(f: Feed) {
    if (!confirm(`Delete feed "${f.name}"?`)) return
    api.delete(`/intel_feeds/${f._key}`).then(() => load订阅源(1))
  }

  // Indicator Rules CRUD
  function openCreateRule() { setEditRule(null); setRuleForm(BLANK_RULE); setShowRuleModal(true) }
  function openEditRule(r: IndicatorRule) {
    setEditRule(r)
    setRuleForm({ name: r.name, trigger_type: r.trigger_type, ioc_types: (r.ioc_types ?? []).join(','), action: r.action, status: r.status })
    setShowRuleModal(true)
  }
  function saveRule() {
    if (!ruleForm.name.trim()) return
    setSavingRule(true)
    const body = { name: ruleForm.name, trigger_type: ruleForm.trigger_type, ioc_types: ruleForm.ioc_types.split(',').map(s => s.trim()).filter(Boolean), action: ruleForm.action, status: ruleForm.status }
    const req = editRule ? api.patch(`/threat_intel/rules/${editRule._key}`, body) : api.post('/threat_intel/rules', body)
    req.then(() => { setShowRuleModal(false); loadRules() }).finally(() => setSavingRule(false))
  }
  function deleteRule(r: IndicatorRule) {
    if (!confirm(`Delete rule "${r.name}"?`)) return
    api.delete(`/threat_intel/rules/${r._key}`).then(() => loadRules())
  }
  function toggleRule(r: IndicatorRule) {
    const newStatus = r.status === 'active' ? 'inactive' : 'active'
    api.patch(`/threat_intel/rules/${r._key}`, { status: newStatus }).then(() => loadRules())
  }

  // 样本s
  function submit样本() {
    if (!submitFile.trim() && !submitUrl.trim()) return
    set提交ting(true)
    api.post('/threat_intel/samples', { filename: submitFile || undefined, url: submitUrl || undefined })
      .then(() => { setShow提交Modal(false); set提交File(''); set提交Url(''); load样本s() })
      .finally(() => set提交ting(false))
  }
  function delete样本(s: 样本) {
    if (!confirm(`Delete sample ${s.filename || s.sha256}?`)) return
    api.delete(`/threat_intel/samples/${s._key}`).then(() => load样本s())
  }

  // 报告
  function createReport() {
    if (!reportForm.title.trim()) return
    setSavingReport(true)
    api.post('/threat_intel/reports', reportForm)
      .then(() => { setShowReportModal(false); setReportForm(BLANK_REPORT); load报告() })
      .finally(() => setSavingReport(false))
  }
  function deleteReport(r: TIMReport) {
    if (!confirm(`Delete report "${r.title}"?`)) return
    api.delete(`/threat_intel/reports/${r._key}`).then(() => load报告())
  }

  // 威胁响应中心 actions
  function trcBlockIOCs(title: string) {
    setBlockingTrc(title)
    api.post('/threat_intel/trc/block', { campaign: title })
      .finally(() => setBlockingTrc(null))
  }
  function trcInvestigate(title: string) {
    api.post('/incidents', { title: `威胁响应中心 Investigation: ${title}`, severity: 'high', status: 'new' })
  }
  function trcCreateRule(title: string) {
    setRuleForm({ name: `Auto: ${title.slice(0, 40)}`, trigger_type: 'match', ioc_types: 'ip,domain,hash', action: 'alert', status: 'active' })
    setEditRule(null)
    setShowRuleModal(true)
    setTab('rules')
  }

  const 威胁响应中心_EVENTS = [
    { title: 'Zero-Day: MOVEit Transfer RCE (CVE-2024-5806)', sev: 'critical' as const, desc: 'Actively exploited zero-day in MOVEit Transfer. SQL injection leading to unauthorized access and data exfiltration. Nation-state actors confirmed.', iocs: 47, assets: 3, date: '2026-05-14' },
    { title: 'LockBit 3.0 Ransomware Campaign — Financial Sector', sev: 'high' as const, desc: 'LockBit 3.0 actors targeting financial institutions with updated TTPs. Lateral movement via valid credentials observed before encryption.', iocs: 128, assets: 0, date: '2026-05-12' },
    { title: 'APT29 Spear Phishing — Government Targets', sev: 'high' as const, desc: 'Cozy Bear credential harvesting campaign targeting government contractors. 恶意 OAuth consent grant phishing observed.', iocs: 34, assets: 0, date: '2026-05-10' },
  ]

  const verdictSummary = (() => {
    const mc = verdictCounts.malicious || 0
    const sc = verdictCounts.suspicious || 0
    const uc = verdictCounts.unknown || 0
    const bc = verdictCounts.benign || 0
    return { mc, sc, uc, bc }
  })()

  const headerBtn = () => {
    if (tab === 'feeds') return <button className="btn-primary" onClick={openCreateFeed}>+ Add Feed</button>
    if (tab === 'indicators') return <button className="btn-primary" onClick={openCreateIoc}>+ Add Indicator</button>
    if (tab === 'rules') return <button className="btn-primary" onClick={openCreateRule}>+ New Rule</button>
    if (tab === 'samples') return <button className="btn-primary" onClick={() => setShow提交Modal(true)}>+ 提交样本</button>
    if (tab === 'reports') return <button className="btn-primary" onClick={() => setShowReportModal(true)}>+ 创建报告</button>
    return null
  }

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <PageHeader
        title="Threat Intel Management"
        subtitle={`· ${iocMeta.total.toLocaleString()} indicators active`}
        actions={<div style={{ display: 'flex', gap: 8 }}>{headerBtn()}</div>}
      />

      {/* Tabs */}
      <div className="tab-bar">
        <button className={`tab ${tab === 'indicators' ? 'active' : ''}`} onClick={() => setTab('indicators')}>
          指标 <span className="tab-count">{iocMeta.total}</span>
        </button>
        <button className={`tab ${tab === 'feeds' ? 'active' : ''}`} onClick={() => setTab('feeds')}>
          订阅源 <span className="tab-count">{feedMeta.total}</span>
        </button>
        <button className={`tab ${tab === 'rules' ? 'active' : ''}`} onClick={() => setTab('rules')}>
          Indicator Rules <span className="tab-count">{rules.length}</span>
        </button>
        <button className={`tab ${tab === 'samples' ? 'active' : ''}`} onClick={() => setTab('samples')}>
          样本 Analysis <span className="tab-count">{samples.length}</span>
        </button>
        <button className={`tab ${tab === 'sessions' ? 'active' : ''}`} onClick={() => setTab('sessions')}>Sessions</button>
        <button className={`tab ${tab === 'reports' ? 'active' : ''}`} onClick={() => setTab('reports')}>
          TIM 报告 <span className="tab-count">{reports.length}</span>
        </button>
        <button className={`tab ${tab === 'trc' ? 'active' : ''}`} onClick={() => setTab('trc')}>威胁响应中心</button>
      </div>

      {/* 判定结论 summary pills — indicators tab only */}
      {tab === 'indicators' && (
        <div style={{ display: 'flex', gap: 8, padding: '8px 20px', borderBottom: '1px solid var(--border)', flexShrink: 0, background: 'var(--bg-primary)', alignItems: 'center' }}>
          {[
            { emoji: '🔴', label: '恶意', count: verdictSummary.mc, bg: 'rgba(229,57,53,.1)', border: 'rgba(229,57,53,.3)', color: '#ef5350' },
            { emoji: '🟠', label: '可疑', count: verdictSummary.sc, bg: 'rgba(255,111,0,.1)', border: 'rgba(255,111,0,.3)', color: '#ffa726' },
            { emoji: '⚪', label: '未知', count: verdictSummary.uc, bg: 'rgba(84,110,122,.1)', border: 'rgba(84,110,122,.3)', color: '#90a4ae' },
            { emoji: '🟢', label: '无害', count: verdictSummary.bc, bg: 'rgba(67,160,71,.1)', border: 'rgba(67,160,71,.3)', color: '#66bb6a' },
          ].map(v => (
            <div key={v.label}
              style={{ padding: '5px 14px', background: v.bg, border: `1px solid ${verdictFilter === v.label.toLowerCase() ? v.color : v.border}`, borderRadius: 6, fontSize: 12, color: v.color, cursor: 'pointer', fontWeight: verdictFilter === v.label.toLowerCase() ? 700 : 400 }}
              onClick={() => set判定结论Filter(verdictFilter === v.label.toLowerCase() ? '' : v.label.toLowerCase())}>
              {v.emoji} {v.label}: <strong>{v.count.toLocaleString()}</strong>
            </div>
          ))}
          <div style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text-muted)', display: 'flex', alignItems: 'center' }}>
            Total: <strong style={{ color: 'var(--text-primary)', marginLeft: 4 }}>{(verdictSummary.mc + verdictSummary.sc + verdictSummary.uc + verdictSummary.bc).toLocaleString()}</strong> indicators
          </div>
        </div>
      )}

      {/* ===== INDICATORS ===== */}
      {tab === 'indicators' && (
        <>
          <div className="filter-bar">
            <input className="filter-input" placeholder="搜索指标：IP、域名、哈希、URL..."
          value={search} onChange={e => setSearch(e.target.value)} onKeyDown={e => e.key === 'Enter' && loadIocs(1)} />
            <select className="filter-select" value={verdictFilter} onChange={e => set判定结论Filter(e.target.value)}>
              <option value="">All 判定结论s</option>
              <option value="malicious">恶意</option>
              <option value="suspicious">可疑</option>
              <option value="benign">无害</option>
              <option value="unknown">未知</option>
            </select>
          </div>
          <div style={{ display: 'flex', gap: 6, padding: '6px 20px', flexWrap: 'wrap', borderBottom: '1px solid var(--border)', flexShrink: 0, background: 'var(--bg-primary)' }}>
            {(['', ...IOC_TYPES] as string[]).map(t => (
              <button key={t || 'all'} onClick={() => setTypeFilter(t)} style={{
                padding: '3px 12px', borderRadius: 20, fontSize: 11, cursor: 'pointer',
                border: `1px solid ${typeFilter === t ? 'var(--accent-orange)' : 'var(--border)'}`,
                background: typeFilter === t ? 'rgba(250,88,45,.1)' : 'none',
                color: typeFilter === t ? 'var(--accent-orange)' : 'var(--text-secondary)', transition: 'all .15s',
              }}>{t ? (IOC_LABELS[t] ?? t.toUpperCase()) : 'All Types'}</button>
            ))}
          </div>
          <div className="data-table-wrap">
            <table className="data-table">
              <thead>
                <tr><th>类型</th><th style={{ minWidth: 220 }}>Indicator Value</th><th>判定结论</th><th>置信度</th><th>Source / Feed</th><th>Related Incidents</th><th>最近发现</th><th></th></tr>
              </thead>
              <tbody>
                {iocLoading && <tr><td colSpan={8} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>加载中...</td></tr>}
                {!iocLoading && iocs.length === 0 && <tr><td colSpan={8} style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>No indicators</td></tr>}
                {iocs.map(ioc => (
                  <tr key={ioc._key}>
                    <td><span style={{ fontSize: 10, padding: '2px 7px', borderRadius: 3, fontWeight: 600, textTransform: 'uppercase', background: `${typeColor[ioc.type] ?? '#4fa3e0'}22`, color: typeColor[ioc.type] ?? '#4fa3e0' }}>{ioc.type}</span></td>
                    <td style={{ fontFamily: 'monospace', fontSize: 11.5, maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: verdictConfig[ioc.verdict?.toLowerCase()]?.color ?? 'var(--text-secondary)' }}>{ioc.value}</td>
                    <td><判定结论Badge verdict={ioc.verdict} /></td>
                    <td style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>{ioc.confidence ?? 0}%</td>
                    <td style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{ioc.source_name || ioc.source || ioc.tags?.[0] || '-'}</td>
                    <td style={{ fontSize: 11.5 }}>
                      {(ioc.related_incidents ?? []).length > 0
                        ? <span style={{ color: 'var(--accent-blue)', cursor: 'pointer' }}>{ioc.related_incidents.slice(0, 2).join(', ')}</span>
                        : <span style={{ color: 'var(--text-muted)' }}>...</span>}
                    </td>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{fmtDate(ioc.last_seen || ioc.created_at)}</td>
                    <td onClick={e => e.stopPropagation()}>
                      <div style={{ display: 'flex', gap: 4 }}>
                        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 7px' }} onClick={() => openEditIoc(ioc)}>编辑</button>
                        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 7px', color: 'var(--critical)' }} onClick={() => deleteIoc(ioc)}>删</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="pagination">
            <button className="page-btn" disabled={iocPage <= 1} onClick={() => setIocPage(p => p - 1)}>...</button>
            <span>{iocPage} / {iocMeta.total_pages || 1}</span>
            <button className="page-btn" disabled={iocPage >= iocMeta.total_pages} onClick={() => setIocPage(p => p + 1)}>...</button>
            <span style={{ marginLeft: 8 }}>{iocMeta.total.toLocaleString()} 条</span>
          </div>
        </>
      )}

      {/* ===== FEEDS ===== */}
      {tab === 'feeds' && (
        <>
          <div className="filter-bar">
            <input className="filter-input" placeholder="搜索订阅源..." value={feedSearch} onChange={e => setFeedSearch(e.target.value)} onKeyDown={e => e.key === 'Enter' && load订阅源(1)} />
            <select className="filter-select" value={feedTypeFilter} onChange={e => setFeedTypeFilter(e.target.value)}>
              <option value="">全部类型</option>
              <option value="stix_taxii">STIX/TAXII</option>
              <option value="misp">MISP</option>
              <option value="mitre">MITRE ATT&CK</option>
              <option value="virustotal">VirusTotal</option>
              <option value="unit42">Unit 42</option>
              <option value="wildfire">WildFire</option>
              <option value="custom">Custom</option>
            </select>
            <select className="filter-select" value={feedStatusFilter} onChange={e => setFeedStatusFilter(e.target.value)}>
              <option value="">全部状态</option>
              <option value="active">Active</option>
              <option value="inactive">Inactive</option>
              <option value="error">Error</option>
            </select>
          </div>
          <div className="data-table-wrap">
            <table className="data-table">
              <thead><tr><th>Feed Name</th><th>类型</th><th>状态</th><th>指标</th><th>Last Synced</th><th>Interval</th><th></th></tr></thead>
              <tbody>
                {feedLoading && <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>加载中...</td></tr>}
                {!feedLoading && feeds.length === 0 && <tr><td colSpan={7} style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>No feeds configured</td></tr>}
                {feeds.map(f => (
                  <tr key={f._key}>
                    <td>
                      <div style={{ fontSize: 12.5, fontWeight: 500 }}>{feedTypeIcon[f.feed_type] ?? '📗'} {f.name}</div>
                      {f.description && <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{f.description.slice(0, 60)}</div>}
                    </td>
                    <td><span style={{ fontSize: 10.5, padding: '2px 8px', background: 'var(--bg-card2)', border: '1px solid var(--border-light)', borderRadius: 3, textTransform: 'uppercase', fontFamily: 'monospace', letterSpacing: .3 }}>{f.feed_type || 'custom'}</span></td>
                    <td>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11.5 }}>
                        <span style={{ width: 6, height: 6, borderRadius: '50%', display: 'inline-block', background: feedStatusColor[f.status] ?? 'var(--text-muted)', boxShadow: f.status === 'active' ? `0 0 4px ${feedStatusColor.active}` : 'none' }} />
                        {f.status || 'inactive'}
                      </span>
                    </td>
                    <td style={{ fontSize: 12, color: 'var(--text-secondary)', fontFamily: 'monospace' }}>{(f.ioc_count ?? 0).toLocaleString()}</td>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{fmtDate(f.last_synced)}</td>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{f.sync_interval ? `${f.sync_interval}m` : 'manual'}</td>
                    <td>
                      <div style={{ display: 'flex', gap: 5 }}>
                        <button className="btn-primary" style={{ fontSize: 11, padding: '2px 10px' }} disabled={syncing === f._key} onClick={() => syncFeed(f._key)}>{syncing === f._key ? '...' : '→ 同步'}</button>
                        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px' }} onClick={() => openEditFeed(f)}>编辑</button>
                        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px', color: 'var(--critical)' }} onClick={() => deleteFeed(f)}>删</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="pagination">
            <button className="page-btn" disabled={feedPage <= 1} onClick={() => setFeedPage(p => p - 1)}>...</button>
            <span>{feedPage} / {feedMeta.total_pages || 1}</span>
            <button className="page-btn" disabled={feedPage >= feedMeta.total_pages} onClick={() => setFeedPage(p => p + 1)}>...</button>
            <span style={{ marginLeft: 8 }}>{feedMeta.total} 条</span>
          </div>
        </>
      )}

      {/* ===== INDICATOR RULES ===== */}
      {tab === 'rules' && (
        <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 16 }}>
            Automatically act on matched indicators ...封锁、告警或丰富上下文 based on verdict and IOC type.
          </div>
          <div className="data-table-wrap" style={{ flex: 'unset' }}>
            <table className="data-table">
              <thead><tr><th>Rule Name</th><th>Trigger</th><th>IOC Types</th><th>Action</th><th>状态</th><th>Hits (30d)</th><th></th></tr></thead>
              <tbody>
                {rulesLoading && <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 40 }}>加载中...</td></tr>}
                {!rulesLoading && rules.length === 0 && <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 40 }}>No indicator rules configured. Click "+ New Rule" to create one.</td></tr>}
                {rules.map(r => (
                  <tr key={r._key}>
                    <td style={{ fontSize: 12.5, fontWeight: 500 }}>{r.name}</td>
                    <td><span style={{ fontSize: 10.5, padding: '2px 7px', borderRadius: 3, background: 'rgba(79,163,224,.12)', color: '#4fa3e0', textTransform: 'capitalize' }}>{r.trigger_type}</span></td>
                    <td style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{(r.ioc_types ?? []).join(', ') || '-'}</td>
                    <td>
                      <span style={{ fontSize: 10.5, padding: '2px 7px', borderRadius: 3, textTransform: 'capitalize',
                        background: r.action === 'block' ? 'rgba(229,57,53,.12)' : r.action === 'alert' ? 'rgba(249,168,37,.12)' : 'rgba(79,163,224,.12)',
                        color: r.action === 'block' ? '#ef5350' : r.action === 'alert' ? '#f9a825' : '#4fa3e0',
                      }}>{r.action}</span>
                    </td>
                    <td>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11.5 }}>
                        <span style={{ width: 6, height: 6, borderRadius: '50%', background: r.status === 'active' ? 'var(--accent-green)' : 'var(--text-muted)', boxShadow: r.status === 'active' ? '0 0 4px var(--accent-green)' : 'none' }} />
                        {r.status}
                      </span>
                    </td>
                    <td style={{ fontSize: 12, color: 'var(--text-secondary)', fontFamily: 'monospace' }}>{r.hits_30d ?? 0}</td>
                    <td>
                      <div style={{ display: 'flex', gap: 4 }}>
                        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 7px', color: r.status === 'active' ? 'var(--high)' : 'var(--accent-green)' }} onClick={() => toggleRule(r)}>{r.status === 'active' ? 'Disable' : 'Enable'}</button>
                        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 7px' }} onClick={() => openEditRule(r)}>编辑</button>
                        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 7px', color: 'var(--critical)' }} onClick={() => deleteRule(r)}>删</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ===== SAMPLE ANALYSIS ===== */}
      {tab === 'samples' && (
        <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 16 }}>
            提交 files and URLs for dynamic and static analysis in an isolated sandbox environment.
          </div>
          <div className="data-table-wrap" style={{ flex: 'unset' }}>
            <table className="data-table">
              <thead><tr><th>样本</th><th>类型</th><th>SHA256</th><th>判定结论</th><th>评分</th><th>大小</th><th>提交ted</th><th>完成时间</th><th></th></tr></thead>
              <tbody>
                {samplesLoading && <tr><td colSpan={9} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 40 }}>加载中...</td></tr>}
                {!samplesLoading && samples.length === 0 && <tr><td colSpan={9} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 40 }}>No samples submitted. Click "+ 提交样本" to analyze a file or URL.</td></tr>}
                {samples.map(s => (
                  <tr key={s._key}>
                    <td style={{ fontSize: 12.5, fontWeight: 500 }}>{s.filename || 'URL提交'}</td>
                    <td><span style={{ fontSize: 10.5, padding: '2px 7px', background: 'var(--bg-card2)', border: '1px solid var(--border-light)', borderRadius: 3 }}>{s.file_type || '-'}</span></td>
                    <td style={{ fontFamily: 'monospace', fontSize: 10.5, color: 'var(--text-muted)', maxWidth: 140, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{s.sha256 ? s.sha256.slice(0, 16) + '...' : '-'}</td>
                    <td><判定结论Badge verdict={s.verdict || 'unknown'} /></td>
                    <td style={{ fontSize: 12, fontWeight: 600, color: s.score >= 80 ? '#ef5350' : s.score >= 50 ? '#ffa726' : 'var(--accent-green)' }}>{s.score ?? '-'}</td>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{fmtBytes(s.size)}</td>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{fmtDate(s.submitted_at)}</td>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{fmtDate(s.completed_at)}</td>
                    <td><button className="btn-secondary" style={{ fontSize: 11, padding: '2px 7px', color: 'var(--critical)' }} onClick={() => delete样本(s)}>删</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ===== SESSIONS ===== */}
      {tab === 'sessions' && (
        <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 16 }}>
            沙箱分析 detonation history and submission sessions from all analysts.
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
            {samples.length === 0 && (
              <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 40, fontSize: 12 }}>
                No sessions yet. 提交 samples in the 样本 Analysis tab to see detonation history here.
              </div>
            )}
            {samples.map(s => (
              <div key={s._key} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '10px 14px', background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 5 }}>
                <判定结论Badge verdict={s.verdict || 'unknown'} />
                <div style={{ flex: 1 }}>
                  <div style={{ fontSize: 12.5, fontWeight: 500 }}>{s.filename || 'URL提交'}</div>
                  <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginTop: 2 }}>{s.sha256 ? `SHA256: ${s.sha256.slice(0, 32)}...` : ''} · 提交ted: {fmtDate(s.submitted_at)}</div>
                </div>
                <div style={{ textAlign: 'right', fontSize: 11 }}>
                  <div style={{ color: s.score >= 80 ? '#ef5350' : s.score >= 50 ? '#ffa726' : 'var(--accent-green)', fontWeight: 600 }}>评分: {s.score ?? '-'}</div>
                  <div style={{ color: 'var(--text-muted)', marginTop: 2 }}>{fmtDate(s.completed_at)}</div>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ===== TIM REPORTS ===== */}
      {tab === 'reports' && (
        <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>
          <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 16 }}>
            Threat intelligence reports, executive summaries, indicator trends, and feed health metrics.
          </div>
          <div className="data-table-wrap" style={{ flex: 'unset' }}>
            <table className="data-table">
              <thead><tr><th>Title</th><th>类型</th><th>状态</th><th>Period</th><th>Created By</th><th>创建时间</th><th></th></tr></thead>
              <tbody>
                {reportsLoading && <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 40 }}>加载中...</td></tr>}
                {!reportsLoading && reports.length === 0 && <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 40 }}>暂无报告 yet. Click "+ 创建报告" to generate one.</td></tr>}
                {reports.map(r => (
                  <tr key={r._key}>
                    <td style={{ fontSize: 12.5, fontWeight: 500 }}>{r.title}</td>
                    <td><span style={{ fontSize: 10.5, padding: '2px 7px', background: 'var(--bg-card2)', border: '1px solid var(--border-light)', borderRadius: 3, textTransform: 'capitalize' }}>{r.report_type || 'custom'}</span></td>
                    <td><span style={{ fontSize: 11, color: r.status === 'ready' ? 'var(--accent-green)' : r.status === 'generating' ? 'var(--accent-blue)' : 'var(--text-muted)', textTransform: 'capitalize' }}>{r.status || 'draft'}</span></td>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{r.period_start ? `${r.period_start} to ${r.period_end}` : '-'}</td>
                    <td style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{r.created_by || '-'}</td>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{fmtDate(r.created_at)}</td>
                    <td><button className="btn-secondary" style={{ fontSize: 11, padding: '2px 7px', color: 'var(--critical)' }} onClick={() => deleteReport(r)}>删</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ===== THREAT RESPONSE CENTER ===== */}
      {tab === 'trc' && (
        <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 16 }}>Active global threat events requiring assessment and response</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {威胁响应中心_EVENTS.map(t => (
              <div key={t.title} style={{ padding: 16, background: 'var(--bg-card)', borderRadius: 8, border: `1px solid ${t.sev === 'critical' ? 'rgba(229,57,53,.3)' : 'rgba(255,111,0,.3)'}`, borderLeft: `3px solid ${t.sev === 'critical' ? 'var(--critical)' : 'var(--high)'}` }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
                  <div style={{ fontSize: 13, fontWeight: 600 }}>{t.title}</div>
                  <span className={`sev-badge ${t.sev}`}>{t.sev}</span>
                </div>
                <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 10 }}>{t.desc}</div>
                <div style={{ display: 'flex', gap: 12, fontSize: 11, color: 'var(--text-muted)', marginBottom: 10 }}>
                  <span>IOCs: <strong style={{ color: 'var(--text-primary)' }}>{t.iocs}</strong></span>
                  <span>Affected Assets: <strong style={{ color: t.assets > 0 ? '#ef5350' : 'var(--text-primary)' }}>{t.assets} detected</strong></span>
                  <span>Published: {t.date}</span>
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                  <button className="btn-primary" style={{ fontSize: 11 }} onClick={() => trcInvestigate(t.title)}>调查分析 →</button>
                  <button className="btn-secondary" style={{ fontSize: 11 }} disabled={blockingTrc === t.title} onClick={() => trcBlockIOCs(t.title)}>
                    {blockingTrc === t.title ? '封锁中...' : '封锁IOC'}
                  </button>
                  <button className="btn-secondary" style={{ fontSize: 11 }} onClick={() => trcCreateRule(t.title)}>Create Rule</button>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ===== MODALS ===== */}

      {/* IOC Modal */}
      {showIocModal && (
        <>
          <div onClick={() => setShowIocModal(false)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.5)', zIndex: 400 }} />
          <div style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: 480, background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, zIndex: 500, padding: 24 }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 20 }}>{editIoc ? 'Edit Indicator' : 'Add Indicator'}</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>IOC Type</div>
                  <select className="filter-select" style={{ width: '100%' }} value={iocForm.type} onChange={e => setIocForm(p => ({ ...p, type: e.target.value }))}>
                    {IOC_TYPES.map(t => <option key={t} value={t}>{IOC_LABELS[t] ?? t}</option>)}
                  </select></div>
                <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>判定结论</div>
                  <select className="filter-select" style={{ width: '100%' }} value={iocForm.verdict} onChange={e => setIocForm(p => ({ ...p, verdict: e.target.value }))}>
                    <option value="malicious">恶意</option>
                    <option value="suspicious">可疑</option>
                    <option value="benign">无害</option>
                    <option value="unknown">未知</option>
                  </select></div>
              </div>
              <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Indicator Value *</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="e.g. 1.2.3.4 or evil.com" value={iocForm.value} onChange={e => setIocForm(p => ({ ...p, value: e.target.value }))} /></div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>置信度 (0-100)</div>
                  <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} type="number" min="0" max="100" value={iocForm.confidence} onChange={e => setIocForm(p => ({ ...p, confidence: e.target.value }))} /></div>
                <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Source Name</div>
                  <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="Unit 42 / Manual" value={iocForm.source_name} onChange={e => setIocForm(p => ({ ...p, source_name: e.target.value }))} /></div>
              </div>
              <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Threat Name</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="LockBit C2 / Phishing" value={iocForm.threat_name} onChange={e => setIocForm(p => ({ ...p, threat_name: e.target.value }))} /></div>
              <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Tags (comma-separated)</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="c2, ransomware, apt" value={iocForm.tags} onChange={e => setIocForm(p => ({ ...p, tags: e.target.value }))} /></div>
              <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setShowIocModal(false)}>取消</button>
                <button className="btn-primary" style={{ flex: 1 }} disabled={savingIoc || !iocForm.value.trim()} onClick={saveIoc}>{savingIoc ? '保存中...' : editIoc ? '保存修改' : 'Add Indicator'}</button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* Feed Modal */}
      {showFeedModal && (
        <>
          <div onClick={() => setShowFeedModal(false)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.5)', zIndex: 400 }} />
          <div style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: 480, background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, zIndex: 500, padding: 24 }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 20 }}>{editFeed ? 'Edit Feed' : 'Add Feed'}</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>订阅源名称 *</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="Unit 42 Threat Feed" value={feedForm.name} onChange={e => setFeedForm(p => ({ ...p, name: e.target.value }))} /></div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>类型</div>
                  <select className="filter-select" style={{ width: '100%' }} value={feedForm.feed_type} onChange={e => setFeedForm(p => ({ ...p, feed_type: e.target.value }))}>
                    <option value="unit42">Unit 42</option><option value="wildfire">WildFire</option><option value="misp">MISP</option>
                    <option value="stix_taxii">STIX/TAXII</option><option value="mitre">MITRE ATT&CK</option><option value="virustotal">VirusTotal</option><option value="custom">Custom</option>
                  </select></div>
                <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>状态</div>
                  <select className="filter-select" style={{ width: '100%' }} value={feedForm.status} onChange={e => setFeedForm(p => ({ ...p, status: e.target.value }))}>
                    <option value="active">Active</option><option value="inactive">Inactive</option>
                  </select></div>
              </div>
              <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>订阅URL</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="https://feed.example.com/indicators" value={feedForm.url} onChange={e => setFeedForm(p => ({ ...p, url: e.target.value }))} /></div>
              <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>描述</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="简要描述..." value={feedForm.description} onChange={e => setFeedForm(p => ({ ...p, description: e.target.value }))} /></div>
              <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Sync Interval (minutes)</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} type="number" min="0" value={feedForm.sync_interval} onChange={e => setFeedForm(p => ({ ...p, sync_interval: e.target.value }))} /></div>
              <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setShowFeedModal(false)}>取消</button>
                <button className="btn-primary" style={{ flex: 1 }} disabled={savingFeed || !feedForm.name.trim()} onClick={saveFeed}>{savingFeed ? '保存中...' : editFeed ? '保存修改' : 'Add Feed'}</button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* Indicator Rule Modal */}
      {showRuleModal && (
        <>
          <div onClick={() => setShowRuleModal(false)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.5)', zIndex: 400 }} />
          <div style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: 460, background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, zIndex: 500, padding: 24 }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 20 }}>{editRule ? 'Edit Rule' : 'New Indicator Rule'}</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>规则名称 *</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="Block 恶意 IPs" value={ruleForm.name} onChange={e => setRuleForm(p => ({ ...p, name: e.target.value }))} /></div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
                <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Trigger</div>
                  <select className="filter-select" style={{ width: '100%' }} value={ruleForm.trigger_type} onChange={e => setRuleForm(p => ({ ...p, trigger_type: e.target.value }))}>
                    <option value="match">Match</option><option value="threshold">Threshold</option><option value="schedule">Schedule</option>
                  </select></div>
                <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Action</div>
                  <select className="filter-select" style={{ width: '100%' }} value={ruleForm.action} onChange={e => setRuleForm(p => ({ ...p, action: e.target.value }))}>
                    <option value="alert">Alert</option><option value="block">Block</option><option value="enrich">Enrich</option><option value="quarantine">Quarantine</option>
                  </select></div>
                <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>状态</div>
                  <select className="filter-select" style={{ width: '100%' }} value={ruleForm.status} onChange={e => setRuleForm(p => ({ ...p, status: e.target.value }))}>
                    <option value="active">Active</option><option value="inactive">Inactive</option>
                  </select></div>
              </div>
              <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>IOC Types (comma-separated)</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="ip, domain, hash" value={ruleForm.ioc_types} onChange={e => setRuleForm(p => ({ ...p, ioc_types: e.target.value }))} /></div>
              <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setShowRuleModal(false)}>取消</button>
                <button className="btn-primary" style={{ flex: 1 }} disabled={savingRule || !ruleForm.name.trim()} onClick={saveRule}>{savingRule ? '保存中...' : editRule ? '保存修改' : 'Create Rule'}</button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* 提交 样本 Modal */}
      {show提交Modal && (
        <>
          <div onClick={() => setShow提交Modal(false)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.5)', zIndex: 400 }} />
          <div style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: 440, background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, zIndex: 500, padding: 24 }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 20 }}>提交样本进行分析</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>文件路径/名称</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="如：suspicious.exe" value={submitFile} onChange={e => set提交File(e.target.value)} /></div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', textAlign: 'center' }}>...或...</div>
              <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>待分析URL</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="https://suspicious-site.com/payload" value={submitUrl} onChange={e => set提交Url(e.target.value)} /></div>
              <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setShow提交Modal(false)}>取消</button>
                <button className="btn-primary" style={{ flex: 1 }} disabled={submitting || (!submitFile.trim() && !submitUrl.trim())} onClick={submit样本}>{submitting ? '提交中...' : '提交'}</button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* 创建报告 Modal */}
      {showReportModal && (
        <>
          <div onClick={() => setShowReportModal(false)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.5)', zIndex: 400 }} />
          <div style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: 440, background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8, zIndex: 500, padding: 24 }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 20 }}>创建威胁情报报告</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>标题 *</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="每周威胁摘要" value={reportForm.title} onChange={e => setReportForm(p => ({ ...p, title: e.target.value }))} /></div>
              <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>报告类型</div>
                <select className="filter-select" style={{ width: '100%' }} value={reportForm.report_type} onChange={e => setReportForm(p => ({ ...p, report_type: e.target.value }))}>
                  <option value="daily">Daily</option><option value="weekly">Weekly</option><option value="monthly">Monthly</option><option value="executive">Executive Summary</option><option value="custom">Custom</option>
                </select></div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>起始日期</div>
                  <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} type="date" value={reportForm.period_start} onChange={e => setReportForm(p => ({ ...p, period_start: e.target.value }))} /></div>
                <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>结束日期</div>
                  <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} type="date" value={reportForm.period_end} onChange={e => setReportForm(p => ({ ...p, period_end: e.target.value }))} /></div>
              </div>
              <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setShowReportModal(false)}>取消</button>
                <button className="btn-primary" style={{ flex: 1 }} disabled={savingReport || !reportForm.title.trim()} onClick={createReport}>{savingReport ? '创建中...' : '创建报告'}</button>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
