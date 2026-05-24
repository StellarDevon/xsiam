import { useEffect, useRef, useState } from 'react'
import api from '@/lib/api'
import type { PageMeta } from '@/lib/api'
import PageHeader from '@/components/PageHeader'

interface Report {
  _key: string
  name: string
  template_type: string
  description?: string
  status: string
  download_url: string
  generated_at: string
  created_at: string
  completed_at?: string
  file_size?: number
  schedule?: string
  next_run_at?: string
  config?: Record<string, any>
}

interface ReportStats {
  total: number
  scheduled: number
  generating: number
  ready: number
  failed: number
}

function fmtDate(iso: string) {
  if (!iso) return '-'
  return new Date(iso).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false })
}

function fmtFileSize(bytes?: number) {
  if (!bytes) return null
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / (1024 * 1024)).toFixed(1)} MB`
}

/** Compute next run date string given schedule type and HH:MM time */
function computeNextRun(scheduleType: string, time: string): string {
  const [hh, mm] = time.split(':').map(Number)
  const now = new Date()
  const candidate = new Date(now)
  candidate.setHours(hh, mm, 0, 0)

  if (scheduleType === 'daily') {
    if (candidate <= now) candidate.setDate(candidate.getDate() + 1)
    return candidate.toLocaleString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false })
  }
  if (scheduleType === 'weekly') {
    // Next Monday
    const dayOfWeek = candidate.getDay()
    const daysUntilMonday = dayOfWeek === 0 ? 1 : (8 - dayOfWeek) % 7 || 7
    candidate.setDate(candidate.getDate() + daysUntilMonday)
    candidate.setHours(hh, mm, 0, 0)
    return candidate.toLocaleString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false })
  }
  if (scheduleType === 'monthly') {
    // First day of next month
    candidate.setDate(1)
    candidate.setMonth(candidate.getMonth() + 1)
    candidate.setHours(hh, mm, 0, 0)
    return candidate.toLocaleString('zh-CN', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false })
  }
  return '—'
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

const PERIOD_OPTIONS = [
  { value: '7d', label: 'Last 7 days' },
  { value: '30d', label: 'Last 30 days' },
  { value: '90d', label: 'Last 90 days' },
  { value: 'custom', label: 'Custom' },
]

const FORMAT_OPTIONS = [
  { value: 'pdf', label: 'PDF' },
  { value: 'xlsx', label: 'Excel' },
  { value: 'html', label: 'HTML' },
]

const SCHEDULE_TYPES = [
  { value: 'daily', label: '每日' },
  { value: 'weekly', label: '每周' },
  { value: 'monthly', label: '每月' },
  { value: 'custom', label: '自定义 (cron)' },
]

interface QuickTemplate {
  label: string
  type: string
  period: string
  format: string
  scheduleType: string
  namePrefix: string
}

const QUICK_TEMPLATES: QuickTemplate[] = [
  { label: '安全周报', type: 'soc_weekly', period: '7d', format: 'pdf', scheduleType: 'weekly', namePrefix: '安全周报' },
  { label: '合规报告', type: 'compliance_audit', period: '30d', format: 'pdf', scheduleType: 'monthly', namePrefix: '合规报告' },
  { label: '漏洞报告', type: 'vuln_remediation', period: '30d', format: 'xlsx', scheduleType: 'weekly', namePrefix: '漏洞报告' },
  { label: '威胁情报', type: 'threat_intel', period: '7d', format: 'pdf', scheduleType: 'daily', namePrefix: '威胁情报' },
]

// Template gallery definitions
interface GalleryTemplate {
  id: string
  name: string
  icon: string
  description: string
  pages: string
  reportType: string
  period: string
  format: string
}

const GALLERY_TEMPLATES: GalleryTemplate[] = [
  {
    id: 'executive',
    name: '执行摘要报告',
    icon: '📊',
    description: '面向管理层的安全态势概览',
    pages: '~5页',
    reportType: 'executive',
    period: '30d',
    format: 'pdf',
  },
  {
    id: 'threat_intel',
    name: '威胁态势报告',
    icon: '🛡️',
    description: '当前威胁趋势与攻击向量分析',
    pages: '~12页',
    reportType: 'threat_intel',
    period: '7d',
    format: 'pdf',
  },
  {
    id: 'vuln_remediation',
    name: '漏洞扫描报告',
    icon: '🔍',
    description: '资产漏洞详情与修复优先级建议',
    pages: '~18页',
    reportType: 'vuln_remediation',
    period: '30d',
    format: 'xlsx',
  },
  {
    id: 'compliance_audit',
    name: '合规审计报告',
    icon: '✅',
    description: '合规指标、审计日志与差距分析',
    pages: '~15页',
    reportType: 'compliance_audit',
    period: '30d',
    format: 'pdf',
  },
  {
    id: 'incident_response',
    name: '事件响应报告',
    icon: '🚨',
    description: '安全事件处置流程与时间线回溯',
    pages: '~8页',
    reportType: 'soc_weekly',
    period: '7d',
    format: 'pdf',
  },
  {
    id: 'soc_performance',
    name: 'SOC绩效报告',
    icon: '📈',
    description: 'SOC团队响应效率与KPI指标统计',
    pages: '~10页',
    reportType: 'soc_monthly',
    period: '30d',
    format: 'pdf',
  },
  {
    id: 'asset_inventory',
    name: '资产清单报告',
    icon: '🖥️',
    description: '全量资产分布、风险评分与暴露面',
    pages: '~20页',
    reportType: 'asset_security',
    period: '90d',
    format: 'xlsx',
  },
  {
    id: 'ioc_intelligence',
    name: 'IOC情报报告',
    icon: '🔗',
    description: 'IOC命中记录与威胁情报Feed摘要',
    pages: '~7页',
    reportType: 'threat_intel',
    period: '7d',
    format: 'pdf',
  },
]

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

function StatusIcon({ status }: { status: string }) {
  if (status === 'ready') return <span style={{ color: 'var(--accent-green)', fontWeight: 700 }}>✓</span>
  if (status === 'failed') return <span style={{ color: 'var(--critical)', fontWeight: 700 }}>✗</span>
  if (status === 'generating') return (
    <span style={{ color: 'var(--accent-blue)', animation: 'spin 1.2s linear infinite', display: 'inline-block' }}>⟳</span>
  )
  return null
}

// ── Stats bar ────────────────────────────────────────────────────────────────

interface StatsTileProps {
  label: string
  value: number
  color?: string
  pulsing?: boolean
  badge?: string
}

function StatsTile({ label, value, color, pulsing, badge }: StatsTileProps) {
  return (
    <div style={{
      flex: 1,
      minWidth: 90,
      background: 'var(--bg-card)',
      border: `1px solid ${pulsing && value > 0 ? 'var(--accent-blue)' : 'var(--border)'}`,
      borderRadius: 8,
      padding: '10px 14px',
      display: 'flex',
      flexDirection: 'column',
      gap: 4,
      transition: 'border-color 0.3s',
    }}>
      <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{label}</div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
        <span style={{ fontSize: 22, fontWeight: 700, color: color ?? 'var(--text-primary)', lineHeight: 1 }}>
          {value}
        </span>
        {pulsing && value > 0 && (
          <span style={{
            width: 8, height: 8, borderRadius: '50%',
            background: 'var(--accent-blue)',
            display: 'inline-block',
            animation: 'pulse-dot 1s ease-in-out infinite',
            flexShrink: 0,
          }} />
        )}
        {badge && value > 0 && (
          <span style={{
            fontSize: 10,
            background: 'rgba(59,130,246,.15)',
            border: '1px solid rgba(59,130,246,.35)',
            color: 'var(--accent-blue)',
            borderRadius: 10,
            padding: '1px 6px',
            fontWeight: 600,
          }}>{badge}</span>
        )}
      </div>
    </div>
  )
}

// ── Download status message ──────────────────────────────────────────────────

interface DownloadMsgProps {
  status: string
}

function DownloadNotReadyMsg({ status }: DownloadMsgProps) {
  return (
    <div style={{
      marginTop: 6,
      padding: '6px 10px',
      background: 'rgba(255,160,0,.08)',
      border: '1px solid rgba(255,160,0,.3)',
      borderRadius: 5,
      fontSize: 11.5,
      color: 'var(--medium)',
      lineHeight: 1.4,
    }}>
      报告尚未就绪，当前状态: <strong>{status}</strong>
    </div>
  )
}

// ── Recipient chip input ──────────────────────────────────────────────────────

interface RecipientInputProps {
  recipients: string[]
  onChange: (list: string[]) => void
}

function RecipientInput({ recipients, onChange }: RecipientInputProps) {
  const [draft, setDraft] = useState('')

  function commit() {
    const trimmed = draft.trim()
    if (!trimmed) return
    // Split by comma to allow pasting multiple at once
    const parts = trimmed.split(',').map(s => s.trim()).filter(Boolean)
    const next = [...recipients]
    parts.forEach(p => { if (!next.includes(p)) next.push(p) })
    onChange(next)
    setDraft('')
  }

  function remove(email: string) {
    onChange(recipients.filter(r => r !== email))
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Enter' || e.key === ',') {
      e.preventDefault()
      commit()
    } else if (e.key === 'Backspace' && draft === '' && recipients.length > 0) {
      onChange(recipients.slice(0, -1))
    }
  }

  return (
    <div style={{
      display: 'flex',
      flexWrap: 'wrap',
      gap: 4,
      padding: '6px 8px',
      border: '1px solid var(--border)',
      borderRadius: 5,
      background: 'var(--bg-card)',
      minHeight: 36,
      cursor: 'text',
    }} onClick={() => {
      const el = document.getElementById('recipient-input')
      if (el) el.focus()
    }}>
      {recipients.map(r => (
        <span key={r} style={{
          display: 'inline-flex',
          alignItems: 'center',
          gap: 4,
          background: 'rgba(59,130,246,.15)',
          border: '1px solid rgba(59,130,246,.3)',
          borderRadius: 12,
          padding: '1px 8px',
          fontSize: 11,
          color: 'var(--accent-blue)',
        }}>
          {r}
          <button
            type="button"
            onClick={e => { e.stopPropagation(); remove(r) }}
            style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--accent-blue)', padding: 0, lineHeight: 1, fontSize: 13 }}
          >×</button>
        </span>
      ))}
      <input
        id="recipient-input"
        type="email"
        value={draft}
        onChange={e => setDraft(e.target.value)}
        onKeyDown={handleKeyDown}
        onBlur={commit}
        placeholder={recipients.length === 0 ? '输入邮箱，Enter或逗号确认' : ''}
        style={{
          flex: 1,
          minWidth: 160,
          background: 'transparent',
          border: 'none',
          outline: 'none',
          fontSize: 12,
          color: 'var(--text-primary)',
          padding: '0 2px',
        }}
      />
    </div>
  )
}

export default function Reports() {
  const [items, setItems] = useState<Report[]>([])
  const [meta, setMeta] = useState<PageMeta>({ page: 1, page_size: 20, total: 0, total_pages: 1 })
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [showNew, setShowNew] = useState(false)
  const [newName, setNewName] = useState('')
  const [newType, setNewType] = useState('soc_weekly')
  const [newPeriod, setNewPeriod] = useState('30d')
  const [newFormat, setNewFormat] = useState('pdf')
  const [creating, setCreating] = useState(false)
  const [typeFilter, setTypeFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [selectedReport, setSelectedReport] = useState<Report | null>(null)
  const [downloadingKey, setDownloadingKey] = useState<string | null>(null)
  const [downloadNotReady, setDownloadNotReady] = useState<string | null>(null)
  const [toast, setToast] = useState<string | null>(null)
  const [deleteConfirmKey, setDeleteConfirmKey] = useState<string | null>(null)

  // Active tab: 'list' | 'templates'
  const [activeTab, setActiveTab] = useState<'list' | 'templates'>('list')

  // Stats bar state
  const [stats, setStats] = useState<ReportStats | null>(null)
  const [statsStale, setStatsStale] = useState(false)

  // Scheduling state
  const [scheduleMode, setScheduleMode] = useState<'immediate' | 'scheduled'>('immediate')
  const [scheduleType, setScheduleType] = useState('daily')
  const [scheduleTime, setScheduleTime] = useState('09:00')
  const [customCron, setCustomCron] = useState('')
  const [scheduleRecipients, setScheduleRecipients] = useState<string[]>([])
  const [scheduleFormat, setScheduleFormat] = useState('pdf')

  // Cancel-schedule in progress
  const [cancellingScheduleKey, setCancellingScheduleKey] = useState<string | null>(null)

  const mountedRef = useRef(false)
  const statsTimerRef = useRef<ReturnType<typeof setInterval> | null>(null)

  function showToast(msg: string, ms = 3500) {
    setToast(msg)
    setTimeout(() => setToast(null), ms)
  }

  // ── Stats fetch ────────────────────────────────────────────────────────────

  function loadStats() {
    api.get('/reports/stats')
      .then(r => {
        const d = r.data.data ?? r.data
        setStats({
          total: d.total ?? 0,
          scheduled: d.scheduled ?? 0,
          generating: d.generating ?? 0,
          ready: d.ready ?? 0,
          failed: d.failed ?? 0,
        })
        setStatsStale(false)
      })
      .catch(() => {
        // Keep last known data but flag as stale
        setStatsStale(true)
      })
  }

  // Bootstrap stats and set up 10s auto-refresh
  useEffect(() => {
    loadStats()
    statsTimerRef.current = setInterval(loadStats, 10000)
    return () => {
      if (statsTimerRef.current) clearInterval(statsTimerRef.current)
    }
  }, [])

  // ── Report list fetch ──────────────────────────────────────────────────────

  function load(p = page) {
    setLoading(true)
    const params: Record<string, any> = { page: p, page_size: 20 }
    if (typeFilter) params.template_type = typeFilter
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

  // Auto-refresh every 10s when any report is generating
  const hasGenerating = items.some(r => r.status === 'generating')
  useEffect(() => {
    if (!hasGenerating) return
    const id = setInterval(() => load(page), 10000)
    return () => clearInterval(id)
  }, [hasGenerating, page, typeFilter, statusFilter])

  // ── Modal helpers ──────────────────────────────────────────────────────────

  function resetModal() {
    setNewName('')
    setNewType('soc_weekly')
    setNewPeriod('30d')
    setNewFormat('pdf')
    setScheduleMode('immediate')
    setScheduleType('daily')
    setScheduleTime('09:00')
    setCustomCron('')
    setScheduleRecipients([])
    setScheduleFormat('pdf')
  }

  function openNew() {
    resetModal()
    setShowNew(true)
  }

  function applyTemplate(tpl: QuickTemplate) {
    const datePart = new Date().toISOString().slice(0, 10)
    setNewName(`${tpl.namePrefix} ${datePart}`)
    setNewType(tpl.type)
    setNewPeriod(tpl.period)
    setNewFormat(tpl.format)
    setScheduleMode('scheduled')
    setScheduleType(tpl.scheduleType)
    setScheduleTime('09:00')
    setCustomCron('')
    setScheduleRecipients([])
    setScheduleFormat(tpl.format)
    setShowNew(true)
  }

  function applyGalleryTemplate(tpl: GalleryTemplate) {
    const datePart = new Date().toISOString().slice(0, 10)
    setNewName(`${tpl.name} ${datePart}`)
    setNewType(tpl.reportType)
    setNewPeriod(tpl.period)
    setNewFormat(tpl.format)
    setScheduleMode('immediate')
    setScheduleType('daily')
    setScheduleTime('09:00')
    setCustomCron('')
    setScheduleRecipients([])
    setScheduleFormat(tpl.format)
    setShowNew(true)
  }

  function createReport() {
    if (!newName.trim()) return
    setCreating(true)
    api.post('/reports', {
      name: newName,
      template_type: newType,
      config: { period: newPeriod, format: newFormat },
    })
      .then(r => {
        const createdId = r.data.data?._key ?? r.data.data?.id
        const doSchedule = scheduleMode === 'scheduled' && createdId
        if (doSchedule) {
          const schedulePayload: Record<string, any> = {
            schedule_type: scheduleType === 'custom' ? 'daily' : scheduleType,
            time: scheduleTime,
            recipients: scheduleRecipients,
            format: scheduleFormat,
          }
          if (scheduleType === 'custom') {
            schedulePayload.cron = customCron
          }
          return api.post(`/reports/${createdId}/schedule`, schedulePayload)
        }
      })
      .then(() => {
        setShowNew(false)
        resetModal()
        load(1)
        loadStats()
      })
      .finally(() => setCreating(false))
  }

  // ── Template gallery "使用模板" ────────────────────────────────────────────

  function handleGalleryUseTemplate(tpl: GalleryTemplate) {
    applyGalleryTemplate(tpl)
  }

  // ── Download ───────────────────────────────────────────────────────────────

  function handleDownload(r: Report) {
    if (downloadingKey === r._key) return
    setDownloadNotReady(null)
    setDownloadingKey(r._key)

    const doDownload = () => {
      if (r.download_url) {
        // Direct URL available
        const a = document.createElement('a')
        a.href = r.download_url
        a.download = r.name
        document.body.appendChild(a)
        a.click()
        document.body.removeChild(a)
        setDownloadingKey(null)
        return
      }

      api.get(`/reports/${r._key}/download`, {
        responseType: 'blob',
        maxRedirects: 5,
        validateStatus: (s) => s < 500,
      })
        .then(resp => {
          if (resp.status === 409) {
            // Not ready — show inline status message
            const statusFromHeader = resp.headers['x-report-status'] as string | undefined
            setDownloadNotReady(statusFromHeader ?? r.status ?? 'generating')
            return
          }
          if (resp.status === 302) {
            const redirect = resp.headers['location']
            if (redirect) window.open(redirect, '_blank')
            return
          }
          // Success — trigger Blob download
          const blob = new Blob([resp.data], { type: String(resp.headers['content-type'] ?? 'application/octet-stream') })
          const url = URL.createObjectURL(blob)
          const a = document.createElement('a')
          a.href = url
          a.download = r.name
          document.body.appendChild(a)
          a.click()
          document.body.removeChild(a)
          setTimeout(() => URL.revokeObjectURL(url), 10000)
        })
        .catch(() => showToast('下载失败'))
        .finally(() => setDownloadingKey(null))
    }

    doDownload()
  }

  // ── Delete ─────────────────────────────────────────────────────────────────

  function handleDelete(r: Report) {
    if (deleteConfirmKey !== r._key) {
      setDeleteConfirmKey(r._key)
      setTimeout(() => setDeleteConfirmKey(null), 3000)
      return
    }
    setDeleteConfirmKey(null)
    api.delete(`/reports/${r._key}`).then(() => {
      if (selectedReport?._key === r._key) setSelectedReport(null)
      load(page)
      loadStats()
    })
  }

  // ── Regenerate ─────────────────────────────────────────────────────────────

  function handleRegenerate(r: Report) {
    api.patch(`/reports/${r._key}`, { status: 'pending' })
      .then(() => {
        showToast('重新生成已启动')
        load(page)
        loadStats()
      })
      .catch(() => showToast('重新生成请求失败'))
  }

  // ── Cancel schedule ────────────────────────────────────────────────────────

  function handleCancelSchedule(r: Report) {
    setCancellingScheduleKey(r._key)
    api.patch(`/reports/${r._key}`, { schedule: '' })
      .then(() => {
        showToast('计划已取消')
        load(page)
        // Update selected panel if open
        if (selectedReport?._key === r._key) {
          setSelectedReport(prev => prev ? { ...prev, schedule: '', next_run_at: undefined } : null)
        }
      })
      .catch(() => showToast('取消计划失败'))
      .finally(() => setCancellingScheduleKey(null))
  }

  // ── Derived values ─────────────────────────────────────────────────────────

  const nextRun = scheduleMode === 'scheduled' && scheduleType !== 'custom'
    ? computeNextRun(scheduleType, scheduleTime)
    : null

  const generatingCount = stats?.generating ?? 0

  // ── Render ─────────────────────────────────────────────────────────────────

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <style>{`
        @keyframes spin { from { transform: rotate(0deg); } to { transform: rotate(360deg); } }
        @keyframes pulse-dot { 0%,100% { opacity:1; transform:scale(1); } 50% { opacity:0.4; transform:scale(1.6); } }
        @keyframes gallery-card-hover { to { border-color: 'var(--accent-blue)'; } }
        .gallery-card { transition: border-color 0.15s, box-shadow 0.15s; }
        .gallery-card:hover { border-color: 'var(--accent-blue)' !important; box-shadow: 0 4px 16px rgba(59,130,246,.12); }
      `}</style>

      <PageHeader
        title="报表中心"
        actions={
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            {hasGenerating && (
              <span style={{ fontSize: 11, color: 'var(--accent-blue)', display: 'flex', alignItems: 'center', gap: 4 }}>
                <span style={{ animation: 'spin 1.2s linear infinite', display: 'inline-block' }}>⟳</span>
                自动刷新中
              </span>
            )}
            <button className="btn-primary" onClick={openNew}>+ 新建报告</button>
          </div>
        }
      />

      {/* ── Stats bar ──────────────────────────────────────────────────────── */}
      <div style={{ padding: '8px 16px 4px', flexShrink: 0 }}>
        {statsStale && (
          <div style={{ fontSize: 11, color: 'var(--medium)', marginBottom: 4, display: 'flex', alignItems: 'center', gap: 4 }}>
            ⚠ 数据可能过时
          </div>
        )}
        <div style={{ display: 'flex', gap: 8 }}>
          <StatsTile label="总报告数" value={stats?.total ?? 0} />
          <StatsTile label="已计划" value={stats?.scheduled ?? 0} color="var(--medium)" />
          <StatsTile
            label="生成中"
            value={generatingCount}
            color="var(--accent-blue)"
            pulsing
            badge={generatingCount > 0 ? `生成中: ${generatingCount}` : undefined}
          />
          <StatsTile label="已完成" value={stats?.ready ?? 0} color="var(--accent-green)" />
          <StatsTile
            label="失败"
            value={stats?.failed ?? 0}
            color={(stats?.failed ?? 0) > 0 ? 'var(--critical)' : undefined}
          />
        </div>
      </div>

      {/* ── Tab bar ────────────────────────────────────────────────────────── */}
      <div style={{ display: 'flex', gap: 0, padding: '6px 16px 0', flexShrink: 0, borderBottom: '1px solid var(--border)' }}>
        {(['list', 'templates'] as const).map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            style={{
              background: 'none',
              border: 'none',
              borderBottom: activeTab === tab ? '2px solid var(--accent-blue)' : '2px solid transparent',
              padding: '6px 14px',
              cursor: 'pointer',
              fontSize: 13,
              fontWeight: activeTab === tab ? 600 : 400,
              color: activeTab === tab ? 'var(--accent-blue)' : 'var(--text-muted)',
              marginBottom: -1,
            }}
          >
            {tab === 'list' ? '报告列表' : '模板库'}
          </button>
        ))}
      </div>

      {/* ════════════════════════════════════════════════════════════════════ */}
      {/* TAB: Template gallery                                               */}
      {/* ════════════════════════════════════════════════════════════════════ */}
      {activeTab === 'templates' && (
        <div style={{ flex: 1, overflow: 'auto', padding: '20px 16px' }}>
          <div style={{ marginBottom: 18, fontSize: 13, color: 'var(--text-muted)' }}>
            从内置模板快速创建报告，点击"使用模板"将预填报告配置。
          </div>
          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(4, 1fr)',
            gap: 16,
          }}>
            {GALLERY_TEMPLATES.map(tpl => (
              <div
                key={tpl.id}
                className="gallery-card"
                style={{
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border)',
                  borderRadius: 10,
                  padding: '20px 18px 16px',
                  display: 'flex',
                  flexDirection: 'column',
                  gap: 10,
                }}
              >
                {/* Icon — large, centered */}
                <div style={{ textAlign: 'center', fontSize: 36, lineHeight: 1, marginBottom: 4 }}>
                  {tpl.icon}
                </div>

                {/* Name */}
                <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', textAlign: 'center', lineHeight: 1.3 }}>
                  {tpl.name}
                </div>

                {/* Description */}
                <div style={{ fontSize: 11.5, color: 'var(--text-secondary)', lineHeight: 1.5, textAlign: 'center', flex: 1 }}>
                  {tpl.description}
                </div>

                {/* Page count badge */}
                <div style={{ textAlign: 'center' }}>
                  <span style={{
                    fontSize: 10.5,
                    padding: '2px 8px',
                    background: 'var(--bg-card2)',
                    border: '1px solid var(--border-light)',
                    borderRadius: 10,
                    color: 'var(--text-muted)',
                  }}>{tpl.pages}</span>
                </div>

                {/* Use template button */}
                <button
                  className="btn-primary"
                  style={{ width: '100%', fontSize: 12, padding: '6px 0', marginTop: 2 }}
                  onClick={() => handleGalleryUseTemplate(tpl)}
                >
                  使用模板
                </button>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* ════════════════════════════════════════════════════════════════════ */}
      {/* TAB: Report list                                                    */}
      {/* ════════════════════════════════════════════════════════════════════ */}
      {activeTab === 'list' && (
        <>
          {/* Quick create template buttons */}
          <div style={{ display: 'flex', gap: 6, padding: '6px 16px 4px', flexShrink: 0, flexWrap: 'wrap' }}>
            <span style={{ fontSize: 11, color: 'var(--text-muted)', alignSelf: 'center', marginRight: 2 }}>快速创建:</span>
            {QUICK_TEMPLATES.map(tpl => (
              <button
                key={tpl.label}
                className="btn-secondary"
                style={{ fontSize: 11, padding: '2px 10px' }}
                onClick={() => applyTemplate(tpl)}
              >{tpl.label}</button>
            ))}
          </div>

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

          {/* Main content: table + optional detail panel */}
          <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
            <div className="data-table-wrap" style={{ flex: 1, overflow: 'auto' }}>
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
                    <tr
                      key={r._key}
                      style={{ cursor: 'pointer', background: selectedReport?._key === r._key ? 'var(--bg-card2)' : undefined }}
                      onClick={() => {
                        setSelectedReport(prev => prev?._key === r._key ? null : r)
                        setDownloadNotReady(null)
                      }}
                    >
                      <td>
                        <div style={{ fontSize: 12.5, fontWeight: 500 }}>
                          {typeIcon[r.template_type] ?? '📋'} {r.name}
                        </div>
                      </td>
                      <td>
                        <span style={{ fontSize: 11, padding: '2px 8px', background: 'var(--bg-card2)', border: '1px solid var(--border-light)', borderRadius: 3 }}>
                          {REPORT_TYPES.find(t => t.value === r.template_type)?.label ?? r.template_type}
                        </span>
                      </td>
                      <td style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>{r.config?.period || '-'}</td>
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
                          {r.config?.format || 'PDF'}
                        </span>
                      </td>
                      <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{fmtDate(r.generated_at || r.created_at)}</td>
                      <td>
                        <div style={{ display: 'flex', gap: 6 }} onClick={e => e.stopPropagation()}>
                          {r.status === 'ready' && (
                            <button
                              className="btn-primary"
                              style={{ fontSize: 11, padding: '2px 10px', minWidth: 56, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 4 }}
                              disabled={downloadingKey === r._key}
                              onClick={() => handleDownload(r)}
                            >
                              {downloadingKey === r._key
                                ? <span style={{ animation: 'spin 1s linear infinite', display: 'inline-block' }}>⟳</span>
                                : '⬇ 下载'}
                            </button>
                          )}
                          <button
                            className="btn-secondary"
                            style={{ fontSize: 11, padding: '2px 8px', color: deleteConfirmKey === r._key ? 'var(--accent-orange, orange)' : 'var(--critical)' }}
                            onClick={() => handleDelete(r)}
                          >
                            {deleteConfirmKey === r._key ? '确认?' : '删除'}
                          </button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* ── Detail panel ─────────────────────────────────────────────── */}
            {selectedReport && (
              <div style={{
                width: 300,
                flexShrink: 0,
                borderLeft: '1px solid var(--border)',
                background: 'var(--bg-card)',
                display: 'flex',
                flexDirection: 'column',
                overflow: 'hidden',
              }}>
                {/* Panel header */}
                <div style={{ padding: '14px 16px 10px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8 }}>
                  <div style={{ fontSize: 13.5, fontWeight: 600, lineHeight: 1.3, wordBreak: 'break-word' }}>
                    {typeIcon[selectedReport.template_type] ?? '📋'} {selectedReport.name}
                  </div>
                  <button
                    onClick={() => setSelectedReport(null)}
                    style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', fontSize: 16, lineHeight: 1, flexShrink: 0, padding: '0 2px' }}
                  >×</button>
                </div>

                {/* Panel body */}
                <div style={{ flex: 1, overflow: 'auto', padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: 14 }}>
                  {/* Badges */}
                  <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                    <span style={{ fontSize: 11, padding: '2px 8px', background: 'var(--bg-card2)', border: '1px solid var(--border-light)', borderRadius: 3 }}>
                      {REPORT_TYPES.find(t => t.value === selectedReport.template_type)?.label ?? selectedReport.template_type}
                    </span>
                    <span style={{ fontSize: 10.5, padding: '2px 6px', background: 'var(--bg-card2)', border: '1px solid var(--border-light)', borderRadius: 3, textTransform: 'uppercase', fontFamily: 'monospace', letterSpacing: 0.3 }}>
                      {selectedReport.config?.format || 'PDF'}
                    </span>
                  </div>

                  {/* Status */}
                  <div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>状态</div>
                    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 12.5 }}>
                      <StatusIcon status={selectedReport.status} />
                      <span style={{
                        color: statusColor[selectedReport.status] ?? 'var(--text-secondary)',
                      }}>
                        {selectedReport.status === 'ready' && '就绪'}
                        {selectedReport.status === 'generating' && '生成中'}
                        {selectedReport.status === 'failed' && '失败'}
                        {selectedReport.status === 'scheduled' && '已计划'}
                        {!['ready', 'generating', 'failed', 'scheduled'].includes(selectedReport.status) && selectedReport.status}
                      </span>
                      {selectedReport.status === 'generating' && (
                        <span style={{ fontSize: 11, color: 'var(--accent-blue)' }}>（处理中...）</span>
                      )}
                    </span>
                  </div>

                  {/* Config details */}
                  <div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>配置</div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
                        <span style={{ color: 'var(--text-muted)' }}>时间段</span>
                        <span>{PERIOD_OPTIONS.find(p => p.value === selectedReport.config?.period)?.label ?? selectedReport.config?.period ?? '-'}</span>
                      </div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
                        <span style={{ color: 'var(--text-muted)' }}>格式</span>
                        <span style={{ textTransform: 'uppercase' }}>{selectedReport.config?.format || 'PDF'}</span>
                      </div>
                    </div>
                  </div>

                  {/* Timestamps */}
                  <div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>时间</div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
                        <span style={{ color: 'var(--text-muted)' }}>创建于</span>
                        <span>{fmtDate(selectedReport.created_at)}</span>
                      </div>
                      {selectedReport.completed_at && (
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
                          <span style={{ color: 'var(--text-muted)' }}>完成于</span>
                          <span>{fmtDate(selectedReport.completed_at)}</span>
                        </div>
                      )}
                      {selectedReport.generated_at && (
                        <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
                          <span style={{ color: 'var(--text-muted)' }}>生成时间</span>
                          <span>{fmtDate(selectedReport.generated_at)}</span>
                        </div>
                      )}
                    </div>
                  </div>

                  {/* File size */}
                  {selectedReport.file_size != null && (
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
                      <span style={{ color: 'var(--text-muted)' }}>文件大小</span>
                      <span>{fmtFileSize(selectedReport.file_size)}</span>
                    </div>
                  )}

                  {/* Schedule info with next_run_at badge + cancel button */}
                  {selectedReport.schedule && (
                    <div>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>计划信息</div>
                      <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 6 }}>
                        {SCHEDULE_TYPES.find(s => s.value === selectedReport.schedule)?.label ?? selectedReport.schedule}
                      </div>
                      {selectedReport.next_run_at && (
                        <div style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: 4,
                          background: 'rgba(34,197,94,.1)',
                          border: '1px solid rgba(34,197,94,.3)',
                          borderRadius: 4,
                          padding: '3px 8px',
                          fontSize: 11,
                          color: 'var(--accent-green)',
                          marginBottom: 8,
                        }}>
                          <span>下次运行:</span>
                          <strong>{fmtDate(selectedReport.next_run_at)}</strong>
                        </div>
                      )}
                      <div>
                        <button
                          className="btn-secondary"
                          style={{ fontSize: 11, padding: '3px 10px', color: 'var(--medium)' }}
                          disabled={cancellingScheduleKey === selectedReport._key}
                          onClick={() => handleCancelSchedule(selectedReport)}
                        >
                          {cancellingScheduleKey === selectedReport._key ? '取消中...' : '取消计划'}
                        </button>
                      </div>
                    </div>
                  )}

                  {/* Description */}
                  {selectedReport.description && (
                    <div>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>描述</div>
                      <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.5 }}>{selectedReport.description}</div>
                    </div>
                  )}

                  {/* Download not-ready inline message */}
                  {downloadNotReady && selectedReport && downloadingKey === null && (
                    <DownloadNotReadyMsg status={downloadNotReady} />
                  )}
                </div>

                {/* Panel footer: actions */}
                <div style={{ padding: '10px 16px', borderTop: '1px solid var(--border)', display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {/* Download button — available for all statuses, shows not-ready message for 409 */}
                  <button
                    className="btn-primary"
                    style={{ width: '100%', fontSize: 12, display: 'flex', alignItems: 'center', justifyContent: 'center', gap: 4 }}
                    disabled={downloadingKey === selectedReport._key}
                    onClick={() => handleDownload(selectedReport)}
                  >
                    {downloadingKey === selectedReport._key
                      ? <><span style={{ animation: 'spin 1s linear infinite', display: 'inline-block' }}>⟳</span> 下载中...</>
                      : '⬇ 下载报告'}
                  </button>
                  <button
                    className="btn-secondary"
                    style={{ width: '100%', fontSize: 12 }}
                    onClick={() => handleRegenerate(selectedReport)}
                  >⟳ 重新生成</button>
                  <button
                    className="btn-secondary"
                    style={{ width: '100%', fontSize: 12, color: deleteConfirmKey === selectedReport._key ? 'var(--accent-orange, orange)' : 'var(--critical)' }}
                    onClick={() => handleDelete(selectedReport)}
                  >
                    {deleteConfirmKey === selectedReport._key ? '确认删除?' : '删除报告'}
                  </button>
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
        </>
      )}

      {/* Toast */}
      {toast && (
        <div style={{
          position: 'fixed', bottom: 24, left: '50%', transform: 'translateX(-50%)',
          background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 6,
          padding: '8px 18px', fontSize: 13, zIndex: 1000, boxShadow: '0 4px 16px rgba(0,0,0,.3)',
          color: 'var(--text-primary)',
        }}>
          {toast}
        </div>
      )}

      {/* New Report Modal */}
      {showNew && (
        <>
          <div onClick={() => setShowNew(false)} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 500, maxHeight: '90vh', overflowY: 'auto',
            background: 'var(--bg-modal)', border: '1px solid var(--border)',
            borderRadius: 8, zIndex: 500, padding: 24,
          }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 20 }}>新建报告</div>
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
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>时间段</div>
                <select className="filter-select" style={{ width: '100%' }} value={newPeriod} onChange={e => setNewPeriod(e.target.value)}>
                  {PERIOD_OPTIONS.map(p => <option key={p.value} value={p.value}>{p.label}</option>)}
                </select>
              </div>

              {/* ── Scheduling section ─────────────────────────────────────── */}
              <div style={{ borderTop: '1px solid var(--border)', paddingTop: 14 }}>
                <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 10 }}>执行计划</div>

                {/* Immediate vs Scheduled radio */}
                <div style={{ display: 'flex', gap: 16, marginBottom: 12 }}>
                  {(['immediate', 'scheduled'] as const).map(mode => (
                    <label key={mode} style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer', fontSize: 12.5 }}>
                      <input
                        type="radio"
                        checked={scheduleMode === mode}
                        onChange={() => setScheduleMode(mode)}
                        style={{ accentColor: 'var(--accent-blue)' }}
                      />
                      {mode === 'immediate' ? '立即生成' : '定时生成'}
                    </label>
                  ))}
                </div>

                {scheduleMode === 'scheduled' && (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 12, background: 'var(--bg-card2)', borderRadius: 6, padding: '14px 16px' }}>

                    {/* Frequency radio buttons */}
                    <div>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8 }}>频率</div>
                      <div style={{ display: 'flex', gap: 20 }}>
                        {[
                          { value: 'daily', label: '每日' },
                          { value: 'weekly', label: '每周' },
                          { value: 'monthly', label: '每月' },
                        ].map(opt => (
                          <label key={opt.value} style={{ display: 'flex', alignItems: 'center', gap: 5, cursor: 'pointer', fontSize: 12.5 }}>
                            <input
                              type="radio"
                              checked={scheduleType === opt.value}
                              onChange={() => setScheduleType(opt.value)}
                              style={{ accentColor: 'var(--accent-blue)' }}
                            />
                            {opt.label}
                          </label>
                        ))}
                        <label style={{ display: 'flex', alignItems: 'center', gap: 5, cursor: 'pointer', fontSize: 12.5 }}>
                          <input
                            type="radio"
                            checked={scheduleType === 'custom'}
                            onChange={() => setScheduleType('custom')}
                            style={{ accentColor: 'var(--accent-blue)' }}
                          />
                          自定义
                        </label>
                      </div>
                    </div>

                    {/* Time picker or cron expression */}
                    {scheduleType === 'custom' ? (
                      <div>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>Cron 表达式</div>
                        <input
                          className="filter-input"
                          style={{ width: '100%', boxSizing: 'border-box', fontFamily: 'monospace' }}
                          placeholder="e.g. 0 9 * * 1"
                          value={customCron}
                          onChange={e => setCustomCron(e.target.value)}
                        />
                      </div>
                    ) : (
                      <div>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>执行时间</div>
                        <input
                          type="time"
                          className="filter-input"
                          style={{ width: 130, boxSizing: 'border-box' }}
                          value={scheduleTime}
                          onChange={e => setScheduleTime(e.target.value)}
                        />
                      </div>
                    )}

                    {/* Format radio buttons */}
                    <div>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8 }}>输出格式</div>
                      <div style={{ display: 'flex', gap: 20 }}>
                        {FORMAT_OPTIONS.map(opt => (
                          <label key={opt.value} style={{ display: 'flex', alignItems: 'center', gap: 5, cursor: 'pointer', fontSize: 12.5 }}>
                            <input
                              type="radio"
                              checked={scheduleFormat === opt.value}
                              onChange={() => setScheduleFormat(opt.value)}
                              style={{ accentColor: 'var(--accent-blue)' }}
                            />
                            {opt.label}
                          </label>
                        ))}
                      </div>
                    </div>

                    {/* Recipients chip input */}
                    <div>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>收件人 <span style={{ opacity: 0.6 }}>(邮箱，Enter或逗号分隔)</span></div>
                      <RecipientInput
                        recipients={scheduleRecipients}
                        onChange={setScheduleRecipients}
                      />
                    </div>

                    {/* Next run preview */}
                    {nextRun && (
                      <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                        <div style={{
                          display: 'inline-flex',
                          alignItems: 'center',
                          gap: 4,
                          background: 'rgba(34,197,94,.1)',
                          border: '1px solid rgba(34,197,94,.3)',
                          borderRadius: 4,
                          padding: '4px 10px',
                          fontSize: 11,
                          color: 'var(--accent-green)',
                        }}>
                          <span>下次运行:</span>
                          <strong>{nextRun}</strong>
                        </div>
                      </div>
                    )}
                  </div>
                )}
              </div>

              <div style={{ display: 'flex', gap: 10, marginTop: 4 }}>
                <button className="btn-secondary" style={{ flex: 1 }} onClick={() => { setShowNew(false); resetModal() }}>取消</button>
                <button className="btn-primary" style={{ flex: 1 }} disabled={creating || !newName.trim()} onClick={createReport}>
                  {creating ? '创建中...' : scheduleMode === 'scheduled' ? '创建并计划' : '立即生成'}
                </button>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
