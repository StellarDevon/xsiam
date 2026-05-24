import { useState, useRef, useEffect, useCallback } from 'react'
import api from '@/lib/api'

interface QueryTab {
  id: string
  name: string
  query: string
}

interface DatasetField {
  name: string
  type: string
  description: string
}

interface DatasetMeta {
  id: string
  name: string
  description: string
  fields?: string | DatasetField[]   // comma-separated string OR rich array from API
  kinds?: string
  retention?: string
  fieldList?: DatasetField[]  // rich field list loaded on demand
}

interface SavedQuery {
  id: string
  name: string
  query: string
  createdAt: number
  /** @deprecated legacy field – kept for backwards-compat with old localStorage data */
  xql?: string
  /** @deprecated legacy field */
  savedAt?: number
}

interface HistoryEntry {
  query: string
  timestamp: number
  resultCount: number
}

// ─── Query history (localStorage) ─────────────────────────────────────────────

const HISTORY_KEY = 'xsiam_query_history'
const SAVED_KEY   = 'xsiam_saved_queries'

function loadHistory(): HistoryEntry[] {
  try {
    const raw = JSON.parse(localStorage.getItem(HISTORY_KEY) ?? '[]')
    // Migrate old string-array format
    if (Array.isArray(raw) && raw.length > 0 && typeof raw[0] === 'string') {
      return (raw as string[]).map(q => ({ query: q, timestamp: Date.now(), resultCount: 0 }))
    }
    return raw as HistoryEntry[]
  } catch { return [] }
}

function saveHistory(entries: HistoryEntry[]) {
  localStorage.setItem(HISTORY_KEY, JSON.stringify(entries.slice(0, 20)))
}

function addToHistory(query: string, resultCount: number): HistoryEntry[] {
  const history = loadHistory()
  const deduped = [
    { query, timestamp: Date.now(), resultCount },
    ...history.filter(h => h.query !== query),
  ]
  saveHistory(deduped)
  return deduped
}

// ─── Saved queries (localStorage) ─────────────────────────────────────────────

function loadSavedQueries(): SavedQuery[] {
  try {
    const raw = JSON.parse(localStorage.getItem(SAVED_KEY) ?? '[]')
    // Migrate legacy format { name, xql, savedAt }
    return (raw as SavedQuery[]).map(q => ({
      id: q.id ?? String(q.savedAt ?? Date.now()),
      name: q.name,
      query: q.query ?? q.xql ?? '',
      createdAt: q.createdAt ?? q.savedAt ?? Date.now(),
    }))
  } catch { return [] }
}

function persistSavedQueries(queries: SavedQuery[]) {
  localStorage.setItem(SAVED_KEY, JSON.stringify(queries))
}

// ─── CSV Export ────────────────────────────────────────────────────────────────

function exportCSV(rows: Record<string, unknown>[], filename: string) {
  if (!rows.length) return
  const cols = Object.keys(rows[0])
  const csv = [cols.join(','), ...rows.map(r => cols.map(k => JSON.stringify(r[k] ?? '')).join(','))].join('\n')
  const blob = new Blob([csv], { type: 'text/csv' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a'); a.href = url; a.download = filename; a.click()
  URL.revokeObjectURL(url)
}

// ─── JSON Export ───────────────────────────────────────────────────────────────

function exportJSON(rows: Record<string, unknown>[], filename: string) {
  if (!rows.length) return
  const blob = new Blob([JSON.stringify(rows, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a'); a.href = url; a.download = filename; a.click()
  URL.revokeObjectURL(url)
}

// ─── Copy as table (tab-separated) ────────────────────────────────────────────

function copyAsTable(rows: Record<string, unknown>[]) {
  if (!rows.length) return
  const cols = Object.keys(rows[0])
  const lines = [
    cols.join('\t'),
    ...rows.map(r => cols.map(k => String(r[k] ?? '')).join('\t')),
  ]
  navigator.clipboard.writeText(lines.join('\n')).catch(() => {
    // fallback: execCommand
    const ta = document.createElement('textarea')
    ta.value = lines.join('\n')
    document.body.appendChild(ta); ta.select()
    document.execCommand('copy')
    document.body.removeChild(ta)
  })
}

// ─── Field list parsed from DatasetMeta.fields string ─────────────────────────

function parseFields(ds: DatasetMeta): DatasetField[] {
  // Prefer rich fieldList if available
  if (ds.fieldList && ds.fieldList.length > 0) return ds.fieldList
  if (!ds.fields) return []
  // API may return fields as an array of DatasetField objects
  if (Array.isArray(ds.fields)) {
    return (ds.fields as DatasetField[]).map(f => ({
      name: f.name ?? String(f),
      type: f.type ?? 'string',
      description: f.description ?? '',
    }))
  }
  // Legacy: comma-separated string
  return (ds.fields as string).split(',').map(f => {
    const name = f.trim()
    let type = 'string'
    let description = ''
    if (name.includes('timestamp') || name.includes('_at') || name.includes('_time') || name === '_ts') {
      type = 'timestamp'
      description = '时间戳字段'
    } else if (['pid','port','count','bytes','size','score','kind'].some(k => name.includes(k))) {
      type = 'number'
      description = '数值字段'
    } else if (name.includes('is_') || name === 'ioc_match') {
      type = 'boolean'
      description = '布尔字段'
    }
    return { name, type, description }
  })
}

// ─── LIMIT injection ───────────────────────────────────────────────────────────

function applyRowLimit(xql: string, limit: number): string {
  const trimmed = xql.trimEnd()
  const replaced = trimmed.replace(/\|\s*limit\s+\d+\s*$/i, `| limit ${limit}`)
  if (replaced !== trimmed) return replaced
  return trimmed + `\n| limit ${limit}`
}

// ─── Value type detection helpers ─────────────────────────────────────────────

function isISODate(val: unknown): boolean {
  if (typeof val !== 'string') return false
  // ISO 8601 pattern
  return /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(val)
}

// ─── Static data ───────────────────────────────────────────────────────────────

const SAMPLE_QUERIES = [
  {
    name: 'All Endpoint Events', tag: 'Endpoint',
    query: 'dataset = xdr_data\n| sort desc event_timestamp\n| limit 50',
  },
  {
    name: 'Process Events Only', tag: 'Process',
    query: 'dataset = xdr_data\n| filter kind = "process"\n| fields hostname, process_name, cmdline, user, event_timestamp\n| sort desc event_timestamp\n| limit 50',
  },
  {
    name: 'File Events Only', tag: 'File',
    query: 'dataset = xdr_data\n| filter kind = "file"\n| fields hostname, action, src_ip, event_timestamp\n| sort desc event_timestamp\n| limit 50',
  },
  {
    name: 'Auth Events', tag: 'Auth',
    query: 'dataset = xdr_data\n| filter kind = "auth"\n| fields hostname, user, auth_type, result, src_ip, event_timestamp\n| sort desc event_timestamp',
  },
  {
    name: 'Network Connections', tag: 'Network',
    query: 'dataset = xdr_data\n| filter kind = "network"\n| fields hostname, src_ip, dst_ip, dst_port, proto, bytes_out, process_name, event_timestamp\n| sort desc event_timestamp',
  },
  {
    name: 'DNS Queries', tag: 'DNS',
    query: 'dataset = xdr_data\n| filter kind = "dns"\n| fields hostname, query, query_type, response_ip, entropy, event_timestamp\n| sort desc event_timestamp',
  },
  {
    name: 'Registry Changes', tag: 'Registry',
    query: 'dataset = xdr_data\n| filter kind = "registry"\n| fields hostname, action, key, value_name, value_data, process_name, event_timestamp\n| sort desc event_timestamp',
  },
  {
    name: 'FIM Changes', tag: 'Integrity',
    query: 'dataset = xdr_data\n| filter kind = "integrity"\n| fields hostname, action, path, new_hash, changed_fields, event_timestamp\n| sort desc event_timestamp',
  },
  {
    name: 'Vulnerabilities (Scanned)', tag: 'Vuln',
    query: 'dataset = xdr_data\n| filter kind = "vuln"\n| fields hostname, cve_id, severity, package_name, package_version, fixed_version, event_timestamp\n| sort desc event_timestamp',
  },
  {
    name: 'Syslog Raw', tag: 'Syslog',
    query: 'dataset = syslog_raw\n| sort desc event_timestamp\n| limit 50',
  },
  {
    name: 'NGFW Traffic', tag: 'Firewall',
    query: 'dataset = ngfw_traffic\n| sort desc event_timestamp\n| limit 50',
  },
  {
    name: 'Cloud Audit', tag: 'Cloud',
    query: 'dataset = cloud_audit_log\n| sort desc event_timestamp\n| limit 50',
  },
  {
    name: 'IdP Auth Logs', tag: 'Identity',
    query: 'dataset = idp_raw\n| sort desc event_timestamp\n| limit 50',
  },
  {
    name: 'UEBA Events', tag: 'UEBA',
    query: 'dataset = identity_analytics\n| sort desc event_timestamp\n| limit 50',
  },
  {
    name: 'Email Events', tag: 'Email',
    query: 'dataset = email_story\n| sort desc event_timestamp\n| limit 50',
  },
  {
    name: 'Asset Inventory', tag: 'Asset',
    query: 'dataset = asset_inventory\n| sort desc event_timestamp\n| limit 20',
  },
]

// ─── Hard-coded schema for 3 well-known datasets ──────────────────────────────

const HARDCODED_SCHEMAS: Record<string, DatasetField[]> = {
  xsiam_endpoint: [
    { name: 'hostname',     type: 'string',    description: '主机名称' },
    { name: 'event_type',   type: 'string',    description: '事件类型' },
    { name: 'process_name', type: 'string',    description: '进程名称' },
    { name: 'pid',          type: 'number',    description: '进程ID' },
    { name: 'timestamp',    type: 'timestamp', description: '事件时间戳' },
    { name: 'severity',     type: 'string',    description: '严重程度' },
    { name: 'user_name',    type: 'string',    description: '用户名' },
  ],
  xsiam_network: [
    { name: 'src_ip',    type: 'string',    description: '源IP地址' },
    { name: 'dst_ip',    type: 'string',    description: '目标IP地址' },
    { name: 'protocol',  type: 'string',    description: '网络协议' },
    { name: 'port',      type: 'number',    description: '目标端口' },
    { name: 'bytes',     type: 'number',    description: '传输字节数' },
    { name: 'timestamp', type: 'timestamp', description: '事件时间戳' },
  ],
  xsiam_identity: [
    { name: 'user_name',   type: 'string',    description: '用户名' },
    { name: 'action',      type: 'string',    description: '操作类型' },
    { name: 'resource',    type: 'string',    description: '操作资源' },
    { name: 'result',      type: 'string',    description: '操作结果' },
    { name: 'timestamp',   type: 'timestamp', description: '事件时间戳' },
    { name: 'ip_address',  type: 'string',    description: 'IP地址' },
  ],
}

const SCHEMA_DATASET_OPTIONS = [
  { id: 'xsiam_endpoint', label: 'xsiam_endpoint — 终端事件' },
  { id: 'xsiam_network',  label: 'xsiam_network — 网络流量' },
  { id: 'xsiam_identity', label: 'xsiam_identity — 身份认证' },
]

// ─── Security query templates ──────────────────────────────────────────────────

const SECURITY_TEMPLATES = [
  {
    icon: '🔧',
    name: '进程执行',
    query: 'dataset = endpoint_events | filter event_type = "process" | sort _ts desc | limit 100',
  },
  {
    icon: '🔐',
    name: '异常登录',
    query: 'dataset = auth_logs | filter result = "failure" | stats count() by user, src_ip | filter count > 5',
  },
  {
    icon: '🌐',
    name: 'DNS查询',
    query: 'dataset = dns_queries | sort _ts desc | limit 200',
  },
  {
    icon: '📡',
    name: '大流量传输',
    query: 'dataset = network_traffic | filter bytes_out > 1000000 | sort bytes_out desc | limit 50',
  },
  {
    icon: '📄',
    name: 'System32文件操作',
    query: 'dataset = file_events | filter operation = "write" | filter path contains "System32" | limit 100',
  },
  {
    icon: '🏔️',
    name: '高危漏洞事件',
    query: 'dataset = xdr_data | filter event_type = "vuln" | filter cvss_score > 7.0 | sort cvss_score desc',
  },
  {
    icon: '🎯',
    name: 'IOC命中',
    query: 'dataset = xdr_data | filter ioc_match = true | sort _ts desc | limit 100',
  },
  {
    icon: '👤',
    name: '高风险用户',
    query: 'dataset = identity_analytics | filter risk_score > 0.7 | sort risk_score desc | limit 50',
  },
]

const XQL_STAGES = ['dataset', '| filter', '| fields', '| sort', '| limit', '| dedup', '| comp', '| join', '| union', '| alter', '| arrayexpand', '| tstats']
const XQL_FUNCTIONS = ['count()', 'sum()', 'avg()', 'min()', 'max()', 'now()', 'to_epoch()', 'coalesce()', 'if()', 'concat()']
const XQL_OPERATORS = ['=', '!=', '>', '<', '>=', '<=', 'in', 'not in', 'contains', 'startswith', 'endswith', 'and', 'or', 'not']

// Kind badge colours and name map
const KIND_COLORS: Record<string, string> = {
  process:   'var(--accent-blue)',
  file:      'var(--high)',
  registry:  'var(--accent-blue)',
  network:   'var(--accent-blue)',
  dns:       'var(--accent-blue)',
  auth:      'var(--accent-green)',
  vuln:      'var(--critical)',
  integrity: 'var(--medium)',
  syslog:    'var(--text-muted)',
}

const KIND_NAMES_BY_NUM: Record<number, string> = {
  0: 'syslog', 1: 'process', 2: 'file', 3: 'registry',
  4: 'network', 5: 'dns', 6: 'auth', 7: 'vuln', 8: 'integrity',
}

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'var(--critical)',
  high:     'var(--high)',
  medium:   'var(--medium)',
  low:      'var(--accent-green)',
  info:     'var(--accent-blue)',
}

// Type badge color
const TYPE_BADGE_COLORS: Record<string, { bg: string; color: string }> = {
  string:    { bg: 'rgba(173,219,103,.12)', color: 'var(--accent-green)' },
  number:    { bg: 'rgba(130,170,255,.12)', color: 'var(--accent-blue)' },
  boolean:   { bg: 'rgba(250,88,93,.12)',   color: 'var(--critical)' },
  timestamp: { bg: 'rgba(137,221,255,.12)', color: 'var(--accent-blue)' },
}

// ─── Timestamp formatter ───────────────────────────────────────────────────────

function fmtTimestamp(val: unknown): string {
  if (!val) return String(val)
  const num = typeof val === 'number' ? val : Number(val)
  if (!isNaN(num) && num > 0) {
    const ms = num > 1e10 ? num : num * 1000
    return new Date(ms).toLocaleString('zh-CN', { hour12: false })
  }
  const d = new Date(String(val))
  if (!isNaN(d.getTime())) return d.toLocaleString('zh-CN', { hour12: false })
  return String(val)
}

// ─── Schema tooltip component ──────────────────────────────────────────────────

interface SchemaTooltipState {
  visible: boolean
  x: number
  y: number
  field: DatasetField | null
}

export default function QueryCenter() {
  const [tabs, setTabs] = useState<QueryTab[]>([
    { id: '1', name: SAMPLE_QUERIES[0].name, query: SAMPLE_QUERIES[0].query },
    { id: '2', name: SAMPLE_QUERIES[9].name, query: SAMPLE_QUERIES[9].query },
  ])
  const [activeTab, setActiveTab] = useState('1')
  const [results, setResults] = useState<Record<string, unknown>[]>([])
  const [columns, setColumns] = useState<string[]>([])
  const [loading, setLoading] = useState(false)
  const [isRunning, setIsRunning] = useState(false)
  const [showRef, setShowRef] = useState(false)
  const [error, setError] = useState('')
  const [elapsed, setElapsed] = useState<number | null>(null)
  const [expandedDatasets, setExpandedDatasets] = useState<Set<string>>(new Set(['xdr_data']))
  const [savedSearch, setSavedSearch] = useState('')
  const [timeRange, setTimeRange] = useState('24h')
  const [datasets, setDatasets] = useState<DatasetMeta[]>([])
  const [rowLimit, setRowLimit] = useState<number>(500)

  // History state
  const [history, setHistory] = useState<HistoryEntry[]>(() => loadHistory())
  const [showHistory, setShowHistory] = useState(false)

  // Saved queries state
  const [savedQueries, setSavedQueries] = useState<SavedQuery[]>(() => loadSavedQueries())
  const [showSavedPanel, setShowSavedPanel] = useState(false)

  // NL2XQL modal state
  const [showNl2Xql, setShowNl2Xql] = useState(false)
  const [nl2xqlInput, setNl2xqlInput] = useState('')
  const [nl2xqlLoading, setNl2xqlLoading] = useState(false)
  const [nl2xqlError, setNl2xqlError] = useState('')
  const nl2xqlRef = useRef<HTMLDivElement>(null)

  // Export dropdown state
  const [showExportMenu, setShowExportMenu] = useState(false)
  const exportMenuRef = useRef<HTMLDivElement>(null)

  // Copy feedback state
  const [copyFeedback, setCopyFeedback] = useState(false)

  // Schema browser dataset selector
  const [schemaBrowserDataset, setSchemaBrowserDataset] = useState<string>('')

  // Field browser state
  const [activeDatasetId, setActiveDatasetId] = useState<string | null>(null)
  const [fieldSearch, setFieldSearch] = useState('')
  const [showTemplates, setShowTemplates] = useState(true)

  // Column pinning state
  const [pinnedColumns, setPinnedColumns] = useState<string[]>([])

  // Expanded row state
  const [expandedRows, setExpandedRows] = useState<Set<number>>(new Set())

  // Context menu state for column header right-click
  const [colMenu, setColMenu] = useState<{ col: string; x: number; y: number } | null>(null)

  // Column sort state
  const [sortCol, setSortCol] = useState<string | null>(null)
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc')

  // Field browser collapse state
  const [fieldsBrowserOpen, setFieldsBrowserOpen] = useState(true)

  // Schema tooltip state
  const [schemaTooltip, setSchemaTooltip] = useState<SchemaTooltipState>({ visible: false, x: 0, y: 0, field: null })

  const textareaRef = useRef<HTMLTextAreaElement>(null)
  const historyRef = useRef<HTMLDivElement>(null)
  const savedRef   = useRef<HTMLDivElement>(null)
  const colMenuRef = useRef<HTMLDivElement>(null)

  const currentTab = tabs.find(t => t.id === activeTab)

  // ─── Load datasets from API on mount ────────────────────────────────────────

  useEffect(() => {
    api.get('/logs/datasets').then(res => {
      const data: DatasetMeta[] = res.data?.data ?? []
      if (data.length > 0) setDatasets(data)
    }).catch(() => {/* use empty list, no crash */})
  }, [])

  // ─── Load rich field data when dataset is clicked in browser ────────────────

  const loadDatasetFields = useCallback(async (dsId: string) => {
    // Check if already loaded
    const existing = datasets.find(d => d.id === dsId)
    if (existing?.fieldList) return  // already loaded

    try {
      const res = await api.get('/logs/datasets')
      const allDs: DatasetMeta[] = res.data?.data ?? []
      const matched = allDs.find((d: DatasetMeta) => d.id === dsId)
      if (matched) {
        const richFields = parseFields(matched)
        setDatasets(prev => prev.map(d =>
          d.id === dsId ? { ...d, fieldList: richFields } : d
        ))
      }
    } catch {
      // silently ignore
    }
  }, [datasets])

  // ─── Close dropdowns on outside click ───────────────────────────────────────

  useEffect(() => {
    function handler(e: MouseEvent) {
      if (historyRef.current && !historyRef.current.contains(e.target as Node)) {
        setShowHistory(false)
      }
      if (savedRef.current && !savedRef.current.contains(e.target as Node)) {
        setShowSavedPanel(false)
      }
      if (colMenuRef.current && !colMenuRef.current.contains(e.target as Node)) {
        setColMenu(null)
      }
      if (exportMenuRef.current && !exportMenuRef.current.contains(e.target as Node)) {
        setShowExportMenu(false)
      }
      // Close NL2XQL modal on backdrop click (the modal overlay itself)
      if (nl2xqlRef.current && !nl2xqlRef.current.contains(e.target as Node)) {
        const overlay = document.getElementById('nl2xql-overlay')
        if (overlay && overlay.contains(e.target as Node)) {
          setShowNl2Xql(false)
        }
      }
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [])

  function updateQuery(query: string) {
    setTabs(prev => prev.map(t => t.id === activeTab ? { ...t, query } : t))
  }

  // ─── Insert field at cursor position ────────────────────────────────────────

  function insertFieldAtCursor(fieldName: string) {
    const ta = textareaRef.current
    if (!ta) {
      updateQuery((currentTab?.query ?? '') + fieldName)
      return
    }
    const start = ta.selectionStart
    const end = ta.selectionEnd
    const val = ta.value
    const newVal = val.substring(0, start) + fieldName + val.substring(end)
    updateQuery(newVal)
    requestAnimationFrame(() => {
      if (textareaRef.current) {
        const pos = start + fieldName.length
        textareaRef.current.selectionStart = textareaRef.current.selectionEnd = pos
        textareaRef.current.focus()
      }
    })
  }

  function addTab() {
    const id = Date.now().toString()
    setTabs(prev => [...prev, { id, name: `Query ${prev.length + 1}`, query: 'dataset = xdr_data\n| sort desc event_timestamp\n| limit 50' }])
    setActiveTab(id)
  }

  function closeTab(id: string, e: React.MouseEvent) {
    e.stopPropagation()
    if (tabs.length === 1) return
    const idx = tabs.findIndex(t => t.id === id)
    const newTabs = tabs.filter(t => t.id !== id)
    setTabs(newTabs)
    if (activeTab === id) setActiveTab(newTabs[Math.max(0, idx - 1)].id)
  }

  // ─── Save current query ──────────────────────────────────────────────────────

  function saveCurrentQuery() {
    if (!currentTab?.query?.trim()) return
    const name = window.prompt('保存当前查询 — 请输入名称：', currentTab.name)
    if (!name) return
    const entry: SavedQuery = {
      id: `sq_${Date.now()}_${Math.random().toString(36).slice(2, 7)}`,
      name,
      query: currentTab.query,
      createdAt: Date.now(),
    }
    setSavedQueries(prev => {
      // Replace if same name already exists
      const filtered = prev.filter(q => q.name !== name)
      const next = [entry, ...filtered].slice(0, 50)
      persistSavedQueries(next)
      return next
    })
  }

  function deleteSavedQuery(id: string) {
    setSavedQueries(prev => {
      const next = prev.filter(q => q.id !== id)
      persistSavedQueries(next)
      return next
    })
  }

  // ─── NL2XQL: convert natural language to XQL via Copilot API ──────────────

  async function runNl2Xql() {
    const input = nl2xqlInput.trim()
    if (!input) return
    setNl2xqlLoading(true)
    setNl2xqlError('')
    try {
      const res = await api.post('/copilot/chat', {
        messages: [
          {
            role: 'user',
            content: `Convert this natural language query to XQL. Return ONLY the XQL query with no explanation:\n${input}`,
          },
        ],
      })
      // Accept various shapes the API might return
      const data = res.data
      const generated: string =
        data?.reply ??
        data?.message ??
        data?.content ??
        data?.data?.reply ??
        data?.data?.message ??
        data?.data?.content ??
        ''
      if (!generated) throw new Error('API 未返回有效的 XQL 内容')
      updateQuery(generated.trim())
      setShowNl2Xql(false)
      setNl2xqlInput('')
    } catch (e: unknown) {
      const err = e as { response?: { data?: { error?: { message?: string } } }; message?: string }
      setNl2xqlError(err.response?.data?.error?.message ?? err.message ?? '请求失败，请重试')
    } finally {
      setNl2xqlLoading(false)
    }
  }

  // ─── Run query ───────────────────────────────────────────────────────────────

  async function runQuery() {
    if (!currentTab) return
    setLoading(true)
    setIsRunning(true)
    setError('')
    setResults([])
    setExpandedRows(new Set())
    setSortCol(null)
    const t0 = Date.now()
    try {
      const rangeSeconds: Record<string, number> = { '24h': 86400, '7d': 604800, '30d': 2592000 }
      const nowSec = Math.floor(Date.now() / 1000)
      const fromSec = nowSec - (rangeSeconds[timeRange] ?? 86400)
      const xqlWithLimit = applyRowLimit(currentTab.query, rowLimit)
      const res = await api.get('/logs/query', {
        params: { q: xqlWithLimit, limit: rowLimit, from_ts: fromSec, to_ts: nowSec },
      })
      const payload = res.data.data ?? {}
      const rows: Record<string, unknown>[] = payload.rows ?? payload.events ?? (Array.isArray(payload) ? payload : [])
      setResults(rows)
      setColumns(rows.length > 0 ? Object.keys(rows[0]) : [])
      setElapsed(Date.now() - t0)
      const newHistory = addToHistory(currentTab.query, rows.length)
      setHistory(newHistory)
    } catch (e: unknown) {
      const err = e as { response?: { data?: { error?: { message?: string } } }; message?: string }
      setError(err.response?.data?.error?.message ?? err.message ?? 'Query failed')
    } finally {
      setLoading(false)
      setIsRunning(false)
    }
  }

  // ─── Ctrl+Enter handler ──────────────────────────────────────────────────────

  function handleKeyDown(e: React.KeyboardEvent<HTMLTextAreaElement>) {
    if (e.ctrlKey && e.key === 'Enter') {
      e.preventDefault()
      runQuery()
      return
    }
    if (e.key === 'Tab') {
      e.preventDefault()
      const s = e.currentTarget.selectionStart
      const end = e.currentTarget.selectionEnd
      const v = e.currentTarget.value
      updateQuery(v.substring(0, s) + '  ' + v.substring(end))
      requestAnimationFrame(() => {
        if (textareaRef.current) {
          textareaRef.current.selectionStart = textareaRef.current.selectionEnd = s + 2
        }
      })
    }
  }

  // ─── Schema tooltip on textarea hover ────────────────────────────────────────

  function getFieldsForCurrentQuery(): DatasetField[] {
    if (!currentTab) return []
    const match = /dataset\s*=\s*(\S+)/.exec(currentTab.query)
    if (!match) return []
    const dsId = match[1]
    const ds = datasets.find(d => d.id === dsId)
    if (!ds) return []
    return parseFields(ds)
  }

  function handleTextareaMouseMove(e: React.MouseEvent<HTMLTextAreaElement>) {
    const ta = textareaRef.current
    if (!ta) return
    const fields = getFieldsForCurrentQuery()
    if (fields.length === 0) {
      if (schemaTooltip.visible) setSchemaTooltip(s => ({ ...s, visible: false }))
      return
    }

    // Approximate word under cursor using a temporary selection trick isn't available
    // Instead use the mouse position to find character offset via caretRangeFromPoint
    const doc = ta.ownerDocument
    let charIdx = -1
    if (doc.caretPositionFromPoint) {
      const pos = doc.caretPositionFromPoint(e.clientX, e.clientY)
      charIdx = pos ? pos.offset : -1
    } else if ((doc as Document & { caretRangeFromPoint?: (x: number, y: number) => Range | null }).caretRangeFromPoint) {
      const range = (doc as Document & { caretRangeFromPoint: (x: number, y: number) => Range | null }).caretRangeFromPoint(e.clientX, e.clientY)
      charIdx = range ? range.startOffset : -1
    }

    if (charIdx < 0) {
      setSchemaTooltip(s => ({ ...s, visible: false }))
      return
    }

    const text = ta.value
    // Walk left and right to extract word boundaries
    let left = charIdx
    while (left > 0 && /\w/.test(text[left - 1])) left--
    let right = charIdx
    while (right < text.length && /\w/.test(text[right])) right++
    const word = text.slice(left, right)
    if (!word) {
      setSchemaTooltip(s => ({ ...s, visible: false }))
      return
    }

    const matched = fields.find(f => f.name === word)
    if (matched) {
      setSchemaTooltip({
        visible: true,
        x: e.clientX + 12,
        y: e.clientY - 40,
        field: matched,
      })
    } else {
      setSchemaTooltip(s => ({ ...s, visible: false }))
    }
  }

  function handleTextareaMouseLeave() {
    setSchemaTooltip(s => ({ ...s, visible: false }))
  }

  const queryLines = (currentTab?.query ?? '').split('\n')

  // ─── Ordered columns (pinned first) ──────────────────────────────────────────

  function getOrderedColumns(): string[] {
    const pinned = pinnedColumns.filter(c => columns.includes(c))
    const rest = columns.filter(c => !pinnedColumns.includes(c))
    return [...pinned, ...rest]
  }

  // ─── Pin/unpin column ─────────────────────────────────────────────────────────

  function pinColumn(col: string) {
    setPinnedColumns(prev =>
      prev.includes(col) ? prev.filter(c => c !== col) : [...prev, col]
    )
    setColMenu(null)
  }

  // ─── Column right-click handler ───────────────────────────────────────────────

  function handleColHeaderContextMenu(e: React.MouseEvent, col: string) {
    e.preventDefault()
    setColMenu({ col, x: e.clientX, y: e.clientY })
  }

  // ─── Toggle row expansion ─────────────────────────────────────────────────────

  function toggleRow(idx: number) {
    setExpandedRows(prev => {
      const next = new Set(prev)
      if (next.has(idx)) next.delete(idx); else next.add(idx)
      return next
    })
  }

  // ─── Cell renderer with column-aware logic ─────────────────────────────────

  function renderCell(col: string, val: unknown) {
    if (val === null || val === undefined) {
      return <span style={{ color: 'var(--text-muted)', fontSize: 10 }}>—</span>
    }

    // Boolean values
    if (typeof val === 'boolean') {
      return (
        <span style={{ fontSize: 12, color: val ? 'var(--accent-green)' : 'var(--critical)', fontWeight: 700 }}>
          {val ? '✓' : '✗'}
        </span>
      )
    }

    // Timestamp columns
    if (col === 'event_timestamp' || col === '_ts' || col.includes('timestamp') || col.includes('_at')) {
      return (
        <span style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--accent-blue)' }}>
          {fmtTimestamp(val)}
        </span>
      )
    }

    // ISO date string values (even if column isn't obviously a timestamp) — format MM-DD HH:mm
    if (isISODate(val)) {
      const d = new Date(val as string)
      const mm = String(d.getMonth() + 1).padStart(2, '0')
      const dd = String(d.getDate()).padStart(2, '0')
      const hh = String(d.getHours()).padStart(2, '0')
      const min = String(d.getMinutes()).padStart(2, '0')
      return (
        <span style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--accent-blue)' }}>
          {mm}-{dd} {hh}:{min}
        </span>
      )
    }

    // Numeric values — right-align handled at td level, style here
    if (typeof val === 'number') {
      return (
        <span style={{ fontFamily: 'monospace', fontSize: 11.5, color: 'var(--accent-green)' }}>
          {val.toLocaleString()}
        </span>
      )
    }

    // Severity column
    if (col === 'severity') {
      const s = String(val).toLowerCase()
      const color = SEVERITY_COLORS[s] ?? 'var(--text-secondary)'
      return (
        <span style={{
          padding: '1px 6px', borderRadius: 3, fontSize: 10,
          background: `${color}22`, color,
          fontWeight: 700, letterSpacing: 0.3, textTransform: 'uppercase',
          border: `1px solid ${color}44`,
        }}>{s}</span>
      )
    }

    // Kind column (numeric or string)
    if (col === 'kind') {
      const numVal = typeof val === 'number' ? val : parseInt(String(val), 10)
      const kindStr = !isNaN(numVal) ? (KIND_NAMES_BY_NUM[numVal] ?? String(val)) : String(val).toLowerCase()
      const color = KIND_COLORS[kindStr] ?? 'var(--text-secondary)'
      return (
        <span style={{
          padding: '1px 6px', borderRadius: 3, fontSize: 10,
          background: `${color}22`, color,
          fontWeight: 600, letterSpacing: 0.3,
        }}>{kindStr}</span>
      )
    }

    if (typeof val === 'object') {
      return (
        <span style={{ fontFamily: 'monospace', color: 'var(--accent-blue)', fontSize: 10.5 }}>
          {JSON.stringify(val)}
        </span>
      )
    }

    const s = String(val)

    // Kind name badges (string kind values)
    if (KIND_COLORS[s]) {
      return (
        <span style={{
          padding: '1px 6px', borderRadius: 3, fontSize: 10,
          background: `${KIND_COLORS[s]}22`,
          color: KIND_COLORS[s],
          fontWeight: 600, letterSpacing: 0.3,
        }}>{s}</span>
      )
    }

    // Truncate long strings with tooltip (max 120 chars)
    if (s.length > 120) {
      return (
        <span title={s} style={{ cursor: 'default' }}>
          {s.slice(0, 120)}…
        </span>
      )
    }

    return s
  }

  // ─── Dataset card click: insert query ──────────────────────────────────────

  function insertDatasetQuery(dsId: string) {
    const q = `dataset = ${dsId}\n| limit 50`
    updateQuery(q)
  }

  // ─── Active dataset fields (field browser) ────────────────────────────────

  const activeDsMeta = datasets.find(d => d.id === activeDatasetId)
  const activeFields: DatasetField[] = (() => {
    // Prefer hard-coded schema for known datasets
    if (activeDatasetId && HARDCODED_SCHEMAS[activeDatasetId]) return HARDCODED_SCHEMAS[activeDatasetId]
    return activeDsMeta ? parseFields(activeDsMeta) : []
  })()
  const filteredFields = fieldSearch
    ? activeFields.filter(f => f.name.toLowerCase().includes(fieldSearch.toLowerCase()) || f.description.toLowerCase().includes(fieldSearch.toLowerCase()))
    : activeFields

  const orderedColumns = getOrderedColumns()

  // ─── Column sort handler ──────────────────────────────────────────────────────

  function handleColHeaderClick(col: string) {
    if (sortCol === col) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc')
    } else {
      setSortCol(col)
      setSortDir('asc')
    }
  }

  // ─── Sorted results ───────────────────────────────────────────────────────────

  const sortedResults = (() => {
    if (!sortCol) return results
    return [...results].sort((a, b) => {
      const av = a[sortCol]
      const bv = b[sortCol]
      if (av === null || av === undefined) return 1
      if (bv === null || bv === undefined) return -1
      let cmp = 0
      if (typeof av === 'number' && typeof bv === 'number') {
        cmp = av - bv
      } else {
        cmp = String(av).localeCompare(String(bv), 'zh-CN', { numeric: true })
      }
      return sortDir === 'asc' ? cmp : -cmp
    })
  })()

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      {/* Schema tooltip (portal-style, positioned fixed) */}
      {schemaTooltip.visible && schemaTooltip.field && (
        <div style={{
          position: 'fixed',
          left: schemaTooltip.x,
          top: schemaTooltip.y,
          zIndex: 9999,
          background: 'var(--bg-card)',
          border: '1px solid var(--border)',
          borderRadius: 6,
          padding: '7px 10px',
          boxShadow: '0 4px 16px rgba(0,0,0,.45)',
          fontSize: 11,
          color: 'var(--text-secondary)',
          pointerEvents: 'none',
          maxWidth: 260,
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginBottom: 3 }}>
            <code style={{ fontSize: 12, fontFamily: 'monospace', color: 'var(--accent-blue)' }}>{schemaTooltip.field.name}</code>
            {schemaTooltip.field.type && (
              <span style={{
                padding: '1px 5px', borderRadius: 3, fontSize: 9.5,
                ...(TYPE_BADGE_COLORS[schemaTooltip.field.type] ?? { bg: 'rgba(255,255,255,.08)', color: 'var(--text-muted)' }),
                background: (TYPE_BADGE_COLORS[schemaTooltip.field.type] ?? { bg: 'rgba(255,255,255,.08)' }).bg,
              }}>
                {schemaTooltip.field.type}
              </span>
            )}
          </div>
          {schemaTooltip.field.description && (
            <div style={{ fontSize: 10.5, color: 'var(--text-muted)', lineHeight: 1.4 }}>
              {schemaTooltip.field.description}
            </div>
          )}
        </div>
      )}

      {/* Column context menu */}
      {colMenu && (
        <div
          ref={colMenuRef}
          style={{
            position: 'fixed',
            left: colMenu.x,
            top: colMenu.y,
            zIndex: 9000,
            background: 'var(--bg-card)',
            border: '1px solid var(--border)',
            borderRadius: 6,
            boxShadow: '0 4px 16px rgba(0,0,0,.45)',
            overflow: 'hidden',
            minWidth: 160,
          }}
        >
          <div
            onClick={() => pinColumn(colMenu.col)}
            style={{
              padding: '8px 14px', fontSize: 12, cursor: 'pointer',
              color: pinnedColumns.includes(colMenu.col) ? 'var(--accent-orange)' : 'var(--text-secondary)',
              display: 'flex', alignItems: 'center', gap: 6,
            }}
            onMouseEnter={e => (e.currentTarget.style.background = 'rgba(255,255,255,.06)')}
            onMouseLeave={e => (e.currentTarget.style.background = 'none')}
          >
            <span style={{ fontSize: 14 }}>{pinnedColumns.includes(colMenu.col) ? '📌' : '📌'}</span>
            {pinnedColumns.includes(colMenu.col) ? '取消固定' : '固定到左侧'}
          </div>
        </div>
      )}

      {/* NL2XQL modal overlay */}
      {showNl2Xql && (
        <div
          id="nl2xql-overlay"
          style={{
            position: 'fixed', inset: 0, zIndex: 10000,
            background: 'var(--bg-overlay)', backdropFilter: 'blur(2px)',
            display: 'flex', alignItems: 'center', justifyContent: 'center',
          }}
          onClick={e => { if (e.target === e.currentTarget) { setShowNl2Xql(false); setNl2xqlInput('') } }}
        >
          <div
            ref={nl2xqlRef}
            style={{
              width: 520, background: 'var(--bg-card)',
              border: '1px solid var(--border)', borderRadius: 10,
              boxShadow: '0 8px 40px rgba(0,0,0,.65)',
              overflow: 'hidden',
            }}
          >
            {/* Modal header */}
            <div style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              padding: '14px 18px 12px',
              borderBottom: '1px solid var(--border)',
              background: 'rgba(79,163,224,.06)',
            }}>
              <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                <span style={{ fontSize: 18, lineHeight: 1 }}>🤖</span>
                <div>
                  <div style={{ fontSize: 13.5, fontWeight: 600, color: 'var(--text-primary)' }}>AI 自然语言转 XQL</div>
                  <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginTop: 1 }}>用中文描述您的查询意图，AI 将自动生成 XQL</div>
                </div>
              </div>
              <button
                onClick={() => { setShowNl2Xql(false); setNl2xqlInput(''); setNl2xqlError('') }}
                style={{
                  background: 'none', border: 'none', cursor: 'pointer',
                  color: 'var(--text-muted)', fontSize: 18, lineHeight: 1, padding: '2px 6px', borderRadius: 4,
                }}
                onMouseEnter={e => { e.currentTarget.style.color = 'var(--text-primary)'; e.currentTarget.style.background = 'rgba(255,255,255,.08)' }}
                onMouseLeave={e => { e.currentTarget.style.color = 'var(--text-muted)'; e.currentTarget.style.background = 'none' }}
              >✕</button>
            </div>

            {/* Modal body */}
            <div style={{ padding: '16px 18px' }}>
              {/* Example hints */}
              <div style={{ marginBottom: 10 }}>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 6, fontWeight: 600 }}>示例</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {[
                    '查找过去24小时内所有Windows系统的登录失败事件',
                    '显示包含恶意IP 1.2.3.4的网络连接',
                    '列出最近7天内执行过 cmd.exe 的所有进程及主机名',
                    '统计每个用户的认证失败次数，按次数降序排列',
                  ].map(hint => (
                    <div
                      key={hint}
                      onClick={() => setNl2xqlInput(hint)}
                      style={{
                        fontSize: 11, color: 'var(--accent-blue)', cursor: 'pointer',
                        padding: '4px 9px', borderRadius: 4,
                        border: '1px solid rgba(79,163,224,.2)',
                        background: 'rgba(79,163,224,.06)',
                        transition: 'background .1s',
                        whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
                      }}
                      onMouseEnter={e => { e.currentTarget.style.background = 'rgba(79,163,224,.14)' }}
                      onMouseLeave={e => { e.currentTarget.style.background = 'rgba(79,163,224,.06)' }}
                      title={hint}
                    >
                      {hint}
                    </div>
                  ))}
                </div>
              </div>

              {/* Text input */}
              <div style={{ marginBottom: 12 }}>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 6, fontWeight: 600 }}>
                  您的查询描述
                </div>
                <textarea
                  value={nl2xqlInput}
                  onChange={e => setNl2xqlInput(e.target.value)}
                  onKeyDown={e => { if (e.ctrlKey && e.key === 'Enter') { e.preventDefault(); runNl2Xql() } }}
                  placeholder="例如：查找过去24小时内所有登录失败超过5次的用户..."
                  rows={4}
                  style={{
                    width: '100%', boxSizing: 'border-box',
                    background: 'var(--bg-primary)', border: '1px solid var(--border-light)',
                    borderRadius: 6, padding: '10px 12px',
                    color: 'var(--text-primary)', fontSize: 12.5,
                    resize: 'vertical', outline: 'none', lineHeight: 1.6,
                    fontFamily: 'inherit',
                  }}
                  autoFocus
                />
                <div style={{ fontSize: 9.5, color: 'var(--text-muted)', marginTop: 4 }}>
                  点击上方示例快速填入，或直接输入 · Ctrl+Enter 生成
                </div>
              </div>

              {/* Error message */}
              {nl2xqlError && (
                <div style={{
                  padding: '8px 12px', borderRadius: 5, marginBottom: 10,
                  background: 'rgba(250,88,93,.1)', border: '1px solid rgba(250,88,93,.3)',
                  fontSize: 11.5, color: 'var(--critical)',
                }}>
                  {nl2xqlError}
                </div>
              )}

              {/* Action buttons */}
              <div style={{ display: 'flex', justifyContent: 'flex-end', gap: 8 }}>
                <button
                  className="btn-secondary"
                  style={{ fontSize: 11.5, padding: '6px 14px' }}
                  onClick={() => { setShowNl2Xql(false); setNl2xqlInput(''); setNl2xqlError('') }}
                >
                  取消
                </button>
                <button
                  className="btn-primary"
                  style={{ fontSize: 11.5, padding: '6px 18px', display: 'flex', alignItems: 'center', gap: 6 }}
                  onClick={runNl2Xql}
                  disabled={nl2xqlLoading || !nl2xqlInput.trim()}
                >
                  {nl2xqlLoading
                    ? <><span style={{ display: 'inline-block', animation: 'spin 1s linear infinite', fontSize: 13 }}>⟳</span> 生成中…</>
                    : <>✨ 生成 XQL</>
                  }
                </button>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* Query tabs bar */}
      <div style={{
        display: 'flex', alignItems: 'center',
        borderBottom: '1px solid var(--border)',
        background: 'var(--bg-card)', flexShrink: 0,
        padding: '0 8px',
      }}>
        {tabs.map(t => (
          <div
            key={t.id}
            onClick={() => setActiveTab(t.id)}
            style={{
              display: 'flex', alignItems: 'center', gap: 6,
              padding: '10px 14px', fontSize: 12.5, cursor: 'pointer',
              color: activeTab === t.id ? 'var(--text-primary)' : 'var(--text-secondary)',
              borderBottom: `2px solid ${activeTab === t.id ? 'var(--accent-orange)' : 'transparent'}`,
              marginBottom: -1,
              background: activeTab === t.id ? 'rgba(255,255,255,.02)' : 'none',
              whiteSpace: 'nowrap',
            }}
          >
            {t.name}
            <span onClick={e => closeTab(t.id, e)} style={{
              width: 16, height: 16, display: 'flex', alignItems: 'center', justifyContent: 'center',
              borderRadius: 3, fontSize: 10, color: 'var(--text-muted)', background: 'none',
            }}
              onMouseEnter={e => (e.currentTarget.style.background = 'rgba(255,255,255,.1)')}
              onMouseLeave={e => (e.currentTarget.style.background = 'none')}
            >✕</span>
          </div>
        ))}
        <button onClick={addTab} style={{
          padding: '8px 12px', fontSize: 14, color: 'var(--text-muted)',
          background: 'none', border: 'none', cursor: 'pointer',
          borderBottom: '2px solid transparent', marginBottom: -1,
        }}
          onMouseEnter={e => (e.currentTarget.style.color = 'var(--text-primary)')}
          onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-muted)')}
        >+</button>
        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6, padding: '0 8px' }}>
          <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
            XQL · ArangoDB · {datasets.length} datasets
          </span>
        </div>
      </div>

      {/* 3-column body */}
      <div style={{ flex: 1, display: 'flex', overflow: 'hidden', minHeight: 0 }}>

        {/* LEFT: sidebar (180px) */}
        <div style={{
          width: 180, flexShrink: 0, borderRight: '1px solid var(--border)',
          display: 'flex', flexDirection: 'column', overflow: 'hidden',
          background: 'var(--bg-secondary)',
        }}>

          {/* ── 我的查询 (保存的查询) section ── */}
          <div style={{ flexShrink: 0 }}>
            <div style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              padding: '10px 14px 6px',
            }}>
              <span style={{
                fontSize: 10, fontWeight: 600, color: 'var(--text-muted)',
                textTransform: 'uppercase', letterSpacing: 0.5,
                display: 'flex', alignItems: 'center', gap: 4,
              }}>
                我的查询
                <span style={{
                  minWidth: 16, height: 16, padding: '0 5px',
                  background: 'rgba(250,88,45,.18)', color: 'var(--accent-orange)',
                  borderRadius: 8, fontSize: 9.5, fontWeight: 700,
                  display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                }}>{savedQueries.length}</span>
              </span>
              <button
                style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 13, lineHeight: 1, padding: '0 2px' }}
                onClick={() => setShowSavedPanel(p => !p)}
                title={showSavedPanel ? '收起' : '展开'}
              >{showSavedPanel ? '▲' : '▼'}</button>
            </div>
            {showSavedPanel && (
              <div style={{ maxHeight: 200, overflowY: 'auto', paddingBottom: 4 }}>
                {savedQueries.length === 0 ? (
                  <div style={{ padding: '6px 14px', fontSize: 11, color: 'var(--text-muted)', fontStyle: 'italic' }}>
                    暂无保存的查询
                  </div>
                ) : (
                  savedQueries.map(sq => (
                    <div
                      key={sq.id}
                      style={{
                        display: 'flex', alignItems: 'center', gap: 4,
                        padding: '5px 8px 5px 10px',
                        borderLeft: `2px solid ${currentTab?.query === sq.query ? 'var(--accent-orange)' : 'transparent'}`,
                        background: currentTab?.query === sq.query ? 'rgba(250,88,45,.05)' : 'none',
                        transition: 'background .1s',
                      }}
                      onMouseEnter={e => { if (currentTab?.query !== sq.query) e.currentTarget.style.background = 'rgba(255,255,255,.03)' }}
                      onMouseLeave={e => { e.currentTarget.style.background = currentTab?.query === sq.query ? 'rgba(250,88,45,.05)' : 'none' }}
                    >
                      <div
                        onClick={() => updateQuery(sq.query)}
                        style={{ flex: 1, minWidth: 0, cursor: 'pointer' }}
                      >
                        <div style={{ fontSize: 11.5, fontWeight: 500, color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{sq.name}</div>
                        <div style={{ fontSize: 9.5, color: 'var(--text-muted)', marginTop: 1 }}>
                          {new Date(sq.createdAt).toLocaleDateString('zh-CN')}
                        </div>
                      </div>
                      {/* 运行 button — loads query then executes after state flush */}
                      <button
                        onClick={e => { e.stopPropagation(); updateQuery(sq.query); setTimeout(() => runQuery(), 0) }}
                        title="运行此查询"
                        style={{
                          background: 'rgba(79,163,224,.1)', border: '1px solid rgba(79,163,224,.25)',
                          cursor: 'pointer', color: 'var(--accent-blue)', fontSize: 9.5, lineHeight: 1,
                          padding: '2px 5px', flexShrink: 0, borderRadius: 3,
                        }}
                        onMouseEnter={e => { e.currentTarget.style.background = 'rgba(79,163,224,.22)' }}
                        onMouseLeave={e => { e.currentTarget.style.background = 'rgba(79,163,224,.1)' }}
                      >运行</button>
                      {/* 删除 button */}
                      <button
                        onClick={e => { e.stopPropagation(); deleteSavedQuery(sq.id) }}
                        title="删除"
                        style={{
                          background: 'none', border: 'none', cursor: 'pointer',
                          color: 'var(--text-muted)', fontSize: 11, lineHeight: 1,
                          padding: '2px 4px', flexShrink: 0, borderRadius: 3,
                        }}
                        onMouseEnter={e => { e.currentTarget.style.color = 'var(--critical)'; e.currentTarget.style.background = 'rgba(250,88,45,.12)' }}
                        onMouseLeave={e => { e.currentTarget.style.color = 'var(--text-muted)'; e.currentTarget.style.background = 'none' }}
                      >×</button>
                    </div>
                  ))
                )}
              </div>
            )}
          </div>

          <div style={{ height: 1, background: 'var(--border)', margin: '2px 0' }} />

          {/* ── 模板 section ── */}
          <div style={{ flexShrink: 0 }}>
            <div style={{
              display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              padding: '10px 14px 6px',
            }}>
              <span style={{
                fontSize: 10, fontWeight: 600, color: 'var(--text-muted)',
                textTransform: 'uppercase', letterSpacing: 0.5,
              }}>
                模板
                <span style={{ marginLeft: 4, color: 'var(--accent-blue)' }}>({SECURITY_TEMPLATES.length})</span>
              </span>
              <button
                style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 13, lineHeight: 1, padding: '0 2px' }}
                onClick={() => setShowTemplates(p => !p)}
                title={showTemplates ? '收起' : '展开'}
              >{showTemplates ? '▲' : '▼'}</button>
            </div>
            {showTemplates && (
              <div style={{ maxHeight: 220, overflowY: 'auto', paddingBottom: 4 }}>
                {SECURITY_TEMPLATES.map(tpl => (
                  <div
                    key={tpl.name}
                    onClick={() => updateQuery(tpl.query)}
                    style={{
                      padding: '6px 14px', fontSize: 11.5, cursor: 'pointer',
                      borderLeft: `2px solid ${currentTab?.query === tpl.query ? 'var(--accent-blue)' : 'transparent'}`,
                      background: currentTab?.query === tpl.query ? 'rgba(130,170,255,.07)' : 'none',
                      color: 'var(--text-secondary)', transition: 'background .1s',
                      display: 'flex', alignItems: 'center', gap: 6,
                    }}
                    onMouseEnter={e => { if (currentTab?.query !== tpl.query) e.currentTarget.style.background = 'rgba(255,255,255,.03)' }}
                    onMouseLeave={e => { e.currentTarget.style.background = currentTab?.query === tpl.query ? 'rgba(130,170,255,.07)' : 'none' }}
                    title={tpl.query}
                  >
                    <span style={{ fontSize: 13, flexShrink: 0, lineHeight: 1 }}>{tpl.icon}</span>
                    <span style={{ fontWeight: 500, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{tpl.name}</span>
                  </div>
                ))}
              </div>
            )}
          </div>

          <div style={{ height: 1, background: 'var(--border)', margin: '2px 0' }} />

          {/* ── 历史 section ── */}
          {history.length > 0 && (
            <div style={{ flexShrink: 0 }}>
              <div style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                padding: '10px 14px 6px',
              }}>
                <span style={{
                  fontSize: 10, fontWeight: 600, color: 'var(--text-muted)',
                  textTransform: 'uppercase', letterSpacing: 0.5,
                  display: 'flex', alignItems: 'center', gap: 4,
                }}>
                  历史
                  <span style={{
                    minWidth: 16, height: 16, padding: '0 5px',
                    background: 'rgba(130,170,255,.15)', color: 'var(--accent-blue)',
                    borderRadius: 8, fontSize: 9.5, fontWeight: 700,
                    display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                  }}>{history.length}</span>
                </span>
                <button
                  onClick={() => { saveHistory([]); setHistory([]) }}
                  style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 9.5, padding: '1px 4px', borderRadius: 3 }}
                  title="清空历史"
                  onMouseEnter={e => (e.currentTarget.style.color = 'var(--critical)')}
                  onMouseLeave={e => (e.currentTarget.style.color = 'var(--text-muted)')}
                >清空</button>
              </div>
              <div style={{ maxHeight: 200, overflowY: 'auto', paddingBottom: 4 }}>
                {history.map((entry, i) => {
                  const preview = entry.query.replace(/\n/g, ' ').slice(0, 60)
                  const truncated = entry.query.replace(/\n/g, ' ').length > 60
                  return (
                    <div
                      key={i}
                      style={{
                        padding: '5px 10px 5px 10px',
                        borderLeft: '2px solid transparent',
                        transition: 'background .1s',
                      }}
                      onMouseEnter={e => (e.currentTarget.style.background = 'rgba(255,255,255,.03)')}
                      onMouseLeave={e => (e.currentTarget.style.background = 'none')}
                    >
                      <div
                        onClick={() => updateQuery(entry.query)}
                        style={{ cursor: 'pointer', marginBottom: 2 }}
                        title={entry.query}
                      >
                        <div style={{
                          fontSize: 10.5, color: 'var(--text-secondary)',
                          fontFamily: 'Consolas,monospace',
                          overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                        }}>
                          {preview}{truncated ? '…' : ''}
                        </div>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 2 }}>
                          <span style={{ fontSize: 9, color: 'var(--text-muted)' }}>
                            {new Date(entry.timestamp).toLocaleString('zh-CN', { hour12: false, month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })}
                          </span>
                          {entry.resultCount > 0 && (
                            <span style={{ fontSize: 9, color: 'var(--accent-green)', background: 'rgba(173,219,103,.1)', padding: '0 4px', borderRadius: 2 }}>
                              {entry.resultCount}行
                            </span>
                          )}
                        </div>
                      </div>
                      <button
                        onClick={() => { updateQuery(entry.query); setTimeout(() => runQuery(), 0) }}
                        style={{
                          background: 'rgba(79,163,224,.1)', border: '1px solid rgba(79,163,224,.25)',
                          cursor: 'pointer', color: 'var(--accent-blue)', fontSize: 9.5, lineHeight: 1,
                          padding: '2px 6px', borderRadius: 3, marginTop: 1,
                        }}
                        onMouseEnter={e => (e.currentTarget.style.background = 'rgba(79,163,224,.22)')}
                        onMouseLeave={e => (e.currentTarget.style.background = 'rgba(79,163,224,.1)')}
                      >加载</button>
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          <div style={{ height: 1, background: 'var(--border)', margin: '2px 0' }} />

          {/* Sample Queries */}
          <div style={{ flexShrink: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 14px 6px' }}>
              <span style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5 }}>Sample Queries</span>
              <button style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 14, lineHeight: 1 }} onClick={addTab}>+</button>
            </div>
            <input
              value={savedSearch}
              onChange={e => setSavedSearch(e.target.value)}
              placeholder="Filter…"
              style={{
                margin: '0 10px 6px', display: 'block', width: 'calc(100% - 20px)',
                background: 'var(--bg-card)', border: '1px solid var(--border-light)',
                borderRadius: 4, padding: '4px 9px', color: 'var(--text-primary)',
                fontSize: 11.5, outline: 'none',
              }}
            />
            <div style={{ maxHeight: 180, overflowY: 'auto' }}>
              {SAMPLE_QUERIES
                .filter(sq => !savedSearch || sq.name.toLowerCase().includes(savedSearch.toLowerCase()) || sq.tag.toLowerCase().includes(savedSearch.toLowerCase()))
                .map(sq => (
                  <div
                    key={sq.name}
                    onClick={() => updateQuery(sq.query)}
                    style={{
                      padding: '6px 14px', fontSize: 11.5, cursor: 'pointer',
                      borderLeft: `2px solid ${currentTab?.query === sq.query ? 'var(--accent-orange)' : 'transparent'}`,
                      background: currentTab?.query === sq.query ? 'rgba(250,88,45,.05)' : 'none',
                      color: 'var(--text-secondary)', transition: 'background .1s',
                    }}
                    onMouseEnter={e => { if (currentTab?.query !== sq.query) e.currentTarget.style.background = 'rgba(255,255,255,.03)' }}
                    onMouseLeave={e => { e.currentTarget.style.background = currentTab?.query === sq.query ? 'rgba(250,88,45,.05)' : 'none' }}
                  >
                    <div style={{ fontWeight: 500, marginBottom: 2 }}>{sq.name}</div>
                    <span style={{ fontSize: 9.5, padding: '1px 5px', background: 'rgba(250,88,45,.12)', color: 'var(--accent-orange)', borderRadius: 3 }}>{sq.tag}</span>
                  </div>
                ))}
            </div>
          </div>

          <div style={{ height: 1, background: 'var(--border)', margin: '4px 0' }} />

          {/* Datasets from API */}
          <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', minHeight: 0 }}>
            <div style={{ padding: '8px 14px 6px', fontSize: 10, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5, flexShrink: 0 }}>
              数据集 {datasets.length > 0 && <span style={{ color: 'var(--accent-orange)' }}>({datasets.length})</span>}
            </div>
            <div style={{ flex: 1, overflowY: 'auto' }}>
              {datasets.map(ds => {
                const isExpanded = expandedDatasets.has(ds.id)
                const isActive = activeDatasetId === ds.id
                return (
                  <div key={ds.id}>
                    <div
                      style={{
                        display: 'flex', alignItems: 'flex-start', gap: 6, padding: '7px 14px',
                        cursor: 'pointer', fontSize: 11.5, color: 'var(--text-secondary)',
                        background: isActive ? 'rgba(79,163,224,.07)' : 'none',
                        borderLeft: `2px solid ${isActive ? 'var(--accent-blue)' : 'transparent'}`,
                        transition: 'background .1s',
                      }}
                      onMouseEnter={e => { if (!isActive) e.currentTarget.style.background = 'rgba(255,255,255,.03)' }}
                      onMouseLeave={e => { e.currentTarget.style.background = isActive ? 'rgba(79,163,224,.07)' : 'none' }}
                    >
                      {/* Expand arrow */}
                      <span
                        onClick={e => {
                          e.stopPropagation()
                          setExpandedDatasets(prev => {
                            const next = new Set(prev)
                            if (next.has(ds.id)) next.delete(ds.id); else next.add(ds.id)
                            return next
                          })
                        }}
                        style={{
                          fontSize: 9, color: 'var(--text-muted)',
                          transform: isExpanded ? 'rotate(90deg)' : 'none',
                          display: 'inline-block', transition: 'transform .15s',
                          marginTop: 2, flexShrink: 0, padding: '0 2px',
                        }}
                      >▶</span>
                      {/* DB icon */}
                      <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="var(--accent-blue)" strokeWidth="1.8" style={{ flexShrink: 0, marginTop: 1 }}>
                        <ellipse cx="12" cy="5" rx="9" ry="3" />
                        <path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3" />
                        <path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5" />
                      </svg>
                      {/* Name + description + field count */}
                      <div style={{ minWidth: 0, flex: 1 }} onClick={() => {
                        insertDatasetQuery(ds.id)
                        // Also activate this dataset for the field browser
                        setActiveDatasetId(prev => prev === ds.id ? null : ds.id)
                        loadDatasetFields(ds.id)
                      }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                          <span style={{ fontWeight: 500, fontFamily: 'monospace', fontSize: 11 }}>{ds.id}</span>
                          {ds.fields && (
                            <span style={{ fontSize: 9, padding: '0 4px', borderRadius: 2, background: 'rgba(79,163,224,.12)', color: 'var(--accent-blue)' }}>
                              {Array.isArray(ds.fields) ? ds.fields.length : (ds.fields as string).split(',').length}字段
                            </span>
                          )}
                        </div>
                        <div style={{ fontSize: 9.5, color: 'var(--text-muted)', marginTop: 1, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{ds.description}</div>
                      </div>
                      {/* Field browser toggle */}
                      <button
                        onClick={e => {
                          e.stopPropagation()
                          setActiveDatasetId(prev => prev === ds.id ? null : ds.id)
                          loadDatasetFields(ds.id)
                        }}
                        title="浏览字段"
                        style={{
                          background: 'none', border: 'none', cursor: 'pointer',
                          color: isActive ? 'var(--accent-blue)' : 'var(--text-muted)', fontSize: 11,
                          lineHeight: 1, padding: '2px 3px', borderRadius: 3, flexShrink: 0,
                        }}
                        onMouseEnter={e => { e.currentTarget.style.color = 'var(--accent-blue)' }}
                        onMouseLeave={e => { e.currentTarget.style.color = isActive ? 'var(--accent-blue)' : 'var(--text-muted)' }}
                      >⊞</button>
                    </div>
                    {isExpanded && ds.fields && (
                      <div style={{ paddingLeft: 28, background: 'rgba(0,0,0,.15)', paddingBottom: 4 }}>
                        {parseFields(ds).map(f => (
                          <div key={f.name} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '2px 14px', fontSize: 10.5 }}>
                            <span style={{ color: 'var(--text-muted)', fontSize: 9, width: 52, flexShrink: 0 }}>{f.type}</span>
                            <span
                              style={{ color: 'var(--accent-blue)', fontFamily: 'monospace', cursor: 'pointer' }}
                              onClick={() => insertFieldAtCursor(f.name)}
                              title="点击插入字段名"
                            >{f.name}</span>
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>

            {/* Field browser panel — shown when a dataset is active */}
            {activeDatasetId && (
              <div style={{
                borderTop: '1px solid var(--border)',
                background: 'rgba(79,163,224,.04)',
                flexShrink: 0,
              }}>
                {/* DatasetSelector — pick the active dataset from known schemas */}
                <div style={{ padding: '6px 8px 0' }}>
                  <select
                    className="filter-select"
                    value={schemaBrowserDataset || activeDatasetId}
                    onChange={e => {
                      const val = e.target.value
                      setSchemaBrowserDataset(val)
                      if (HARDCODED_SCHEMAS[val]) {
                        // inject hard-coded schema into datasets list or use directly
                        setDatasets(prev => {
                          const existing = prev.find(d => d.id === val)
                          if (existing) {
                            return prev.map(d => d.id === val ? { ...d, fieldList: HARDCODED_SCHEMAS[val] } : d)
                          }
                          return [...prev, { id: val, name: val, description: '', fieldList: HARDCODED_SCHEMAS[val] }]
                        })
                        setActiveDatasetId(val)
                      } else {
                        setActiveDatasetId(val)
                        loadDatasetFields(val)
                      }
                    }}
                    style={{ width: '100%', fontSize: 10.5, padding: '3px 6px' }}
                    title="选择数据集查看字段"
                  >
                    <option value="" disabled>— 选择数据集 —</option>
                    {/* Hard-coded schema datasets */}
                    <optgroup label="内置数据集">
                      {SCHEMA_DATASET_OPTIONS.map(opt => (
                        <option key={opt.id} value={opt.id}>{opt.label}</option>
                      ))}
                    </optgroup>
                    {/* API datasets */}
                    {datasets.filter(d => !HARDCODED_SCHEMAS[d.id]).length > 0 && (
                      <optgroup label="API 数据集">
                        {datasets.filter(d => !HARDCODED_SCHEMAS[d.id]).map(d => (
                          <option key={d.id} value={d.id}>{d.id}</option>
                        ))}
                      </optgroup>
                    )}
                  </select>
                </div>

                {/* 字段详情 section header with collapse toggle */}
                <div style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  padding: '8px 12px 4px', cursor: 'pointer',
                }}
                  onClick={() => setFieldsBrowserOpen(o => !o)}
                >
                  <span style={{ fontSize: 10, fontWeight: 600, color: 'var(--accent-blue)', textTransform: 'uppercase', letterSpacing: 0.5, display: 'flex', alignItems: 'center', gap: 4 }}>
                    字段详情
                    <code style={{ fontFamily: 'monospace', fontSize: 9.5, color: 'var(--accent-blue)', textTransform: 'none', letterSpacing: 0 }}>{activeDatasetId}</code>
                  </span>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                    <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{fieldsBrowserOpen ? '▲' : '▼'}</span>
                    <button
                      onClick={e => { e.stopPropagation(); setActiveDatasetId(null) }}
                      style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', fontSize: 12, lineHeight: 1, padding: '0 2px' }}
                      title="关闭字段面板"
                    >✕</button>
                  </div>
                </div>
                {fieldsBrowserOpen && (
                  <>
                    <div style={{ padding: '0 8px 4px' }}>
                      <input
                        value={fieldSearch}
                        onChange={e => setFieldSearch(e.target.value)}
                        placeholder="搜索字段…"
                        style={{
                          width: '100%', boxSizing: 'border-box',
                          background: 'var(--bg-card)', border: '1px solid var(--border-light)',
                          borderRadius: 4, padding: '4px 8px', color: 'var(--text-primary)',
                          fontSize: 11, outline: 'none',
                        }}
                        onClick={e => e.stopPropagation()}
                      />
                    </div>
                    <div style={{ maxHeight: 220, overflowY: 'auto', paddingBottom: 6 }}>
                      {filteredFields.length === 0 ? (
                        <div style={{ padding: '8px 12px', fontSize: 11, color: 'var(--text-muted)', fontStyle: 'italic' }}>
                          {activeFields.length === 0 ? '该数据集无字段信息' : '无匹配字段'}
                        </div>
                      ) : (
                        filteredFields.map(f => {
                          const badgeStyle = TYPE_BADGE_COLORS[f.type] ?? { bg: 'rgba(255,255,255,.08)', color: 'var(--text-muted)' }
                          return (
                            <div
                              key={f.name}
                              onClick={() => insertFieldAtCursor(f.name)}
                              style={{
                                display: 'flex', alignItems: 'flex-start', gap: 6,
                                padding: '4px 12px', cursor: 'pointer',
                                transition: 'background .1s',
                              }}
                              onMouseEnter={e => (e.currentTarget.style.background = 'rgba(79,163,224,.08)')}
                              onMouseLeave={e => (e.currentTarget.style.background = 'none')}
                              title={f.description ? `${f.name}: ${f.description}` : `点击插入 ${f.name}`}
                            >
                              <code style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--accent-blue)', flexShrink: 0 }}>
                                {f.name}
                              </code>
                              <span style={{
                                padding: '1px 5px', borderRadius: 3, fontSize: 9,
                                background: badgeStyle.bg, color: badgeStyle.color,
                                flexShrink: 0, whiteSpace: 'nowrap',
                              }}>
                                {f.type}
                              </span>
                              {f.description && (
                                <span style={{ fontSize: 9.5, color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', flex: 1 }}>
                                  {f.description}
                                </span>
                              )}
                            </div>
                          )
                        })
                      )}
                    </div>
                    {activeFields.length > 0 && filteredFields.length < activeFields.length && (
                      <div style={{ padding: '2px 12px 6px', fontSize: 9.5, color: 'var(--text-muted)' }}>
                        显示 {filteredFields.length} / {activeFields.length} 字段
                      </div>
                    )}
                  </>
                )}
              </div>
            )}
          </div>
        </div>

        {/* CENTER: Editor + Results */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0, overflow: 'hidden' }}>
          {/* Editor toolbar */}
          <div style={{
            display: 'flex', alignItems: 'center', gap: 8, padding: '6px 12px',
            borderBottom: '1px solid var(--border)', background: 'var(--bg-card2)', flexShrink: 0,
          }}>
            <select className="filter-select" style={{ fontSize: 11 }} value={timeRange} onChange={e => setTimeRange(e.target.value)}>
              <option value="24h">Last 24H</option>
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
            </select>

            {/* History dropdown */}
            {history.length > 0 && (
              <div style={{ position: 'relative' }} ref={historyRef}>
                <button
                  className="btn-secondary"
                  style={{ fontSize: 11, padding: '4px 10px' }}
                  onClick={() => setShowHistory(p => !p)}
                  title="查询历史"
                >
                  历史 ▾
                </button>
                {showHistory && (
                  <div style={{
                    position: 'absolute', top: '100%', left: 0, marginTop: 2,
                    background: 'var(--bg-card)', border: '1px solid var(--border)',
                    borderRadius: 6, zIndex: 200, minWidth: 340, maxHeight: 280,
                    overflowY: 'auto', boxShadow: '0 4px 16px rgba(0,0,0,.4)',
                  }}>
                    <div style={{ padding: '6px 12px 4px', fontSize: 9.5, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5, borderBottom: '1px solid var(--border)' }}>
                      最近 {history.length} 条查询
                    </div>
                    {history.map((entry, i) => {
                      const flat = entry.query.replace(/\n/g, ' ')
                      const preview = flat.slice(0, 80)
                      return (
                        <div
                          key={i}
                          style={{
                            padding: '7px 12px', fontSize: 11,
                            color: 'var(--text-secondary)', borderBottom: '1px solid rgba(255,255,255,.04)',
                            transition: 'background .1s',
                          }}
                          onMouseEnter={e => (e.currentTarget.style.background = 'rgba(255,255,255,.05)')}
                          onMouseLeave={e => (e.currentTarget.style.background = 'none')}
                        >
                          <div
                            onClick={() => { updateQuery(entry.query); setShowHistory(false) }}
                            style={{ fontFamily: 'Consolas,monospace', cursor: 'pointer', marginBottom: 3 }}
                            title={entry.query}
                          >
                            {flat.length > 80 ? preview + '…' : preview}
                          </div>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                            <span style={{ fontSize: 9.5, color: 'var(--text-muted)' }}>
                              {new Date(entry.timestamp).toLocaleString('zh-CN', { hour12: false, month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })}
                            </span>
                            {entry.resultCount > 0 && (
                              <span style={{ fontSize: 9.5, color: 'var(--accent-green)', background: 'rgba(173,219,103,.1)', padding: '0 4px', borderRadius: 2 }}>
                                {entry.resultCount}行
                              </span>
                            )}
                            <button
                              onClick={e => { e.stopPropagation(); updateQuery(entry.query); setShowHistory(false); setTimeout(() => runQuery(), 0) }}
                              style={{
                                background: 'rgba(79,163,224,.1)', border: '1px solid rgba(79,163,224,.25)',
                                cursor: 'pointer', color: 'var(--accent-blue)', fontSize: 9.5, lineHeight: 1,
                                padding: '1px 6px', borderRadius: 3,
                              }}
                              onMouseEnter={e => (e.currentTarget.style.background = 'rgba(79,163,224,.22)')}
                              onMouseLeave={e => (e.currentTarget.style.background = 'rgba(79,163,224,.1)')}
                            >加载</button>
                          </div>
                        </div>
                      )
                    })}
                    <div style={{ padding: '5px 12px' }}>
                      <button
                        style={{ fontSize: 10, color: 'var(--text-muted)', background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}
                        onClick={() => { saveHistory([]); setHistory([]); setShowHistory(false) }}
                      >清空历史</button>
                    </div>
                  </div>
                )}
              </div>
            )}

            {/* Already-saved dropdown */}
            <div style={{ position: 'relative' }} ref={savedRef}>
              <button
                className="btn-secondary"
                style={{ fontSize: 11, padding: '4px 10px' }}
                onClick={() => setShowSavedPanel(p => !p)}
                title="已保存的查询"
              >
                已保存 {savedQueries.length > 0 && <span style={{ color: 'var(--accent-orange)' }}>({savedQueries.length})</span>} ▾
              </button>
              {showSavedPanel && (
                <div style={{
                  position: 'absolute', top: '100%', left: 0, marginTop: 2,
                  background: 'var(--bg-card)', border: '1px solid var(--border)',
                  borderRadius: 6, zIndex: 200, minWidth: 300, maxHeight: 280,
                  overflowY: 'auto', boxShadow: '0 4px 16px rgba(0,0,0,.4)',
                }}>
                  <div style={{ padding: '6px 12px 4px', fontSize: 9.5, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5, borderBottom: '1px solid var(--border)' }}>
                    我的查询 ({savedQueries.length})
                  </div>
                  {savedQueries.length === 0 ? (
                    <div style={{ padding: '12px', fontSize: 11, color: 'var(--text-muted)', textAlign: 'center' }}>
                      暂无保存的查询<br />
                      <span style={{ fontSize: 10, opacity: 0.7 }}>点击"保存当前查询"按钮保存</span>
                    </div>
                  ) : (
                    savedQueries.map(sq => (
                      <div
                        key={sq.id}
                        style={{
                          display: 'flex', alignItems: 'center',
                          padding: '6px 10px 6px 12px',
                          borderBottom: '1px solid rgba(255,255,255,.04)',
                          transition: 'background .1s',
                        }}
                        onMouseEnter={e => (e.currentTarget.style.background = 'rgba(255,255,255,.05)')}
                        onMouseLeave={e => (e.currentTarget.style.background = 'none')}
                      >
                        <div
                          style={{ flex: 1, minWidth: 0, cursor: 'pointer' }}
                          onClick={() => { updateQuery(sq.query); setShowSavedPanel(false) }}
                        >
                          <div style={{ fontSize: 11.5, fontWeight: 500, color: 'var(--text-primary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{sq.name}</div>
                          <div style={{ fontSize: 9.5, color: 'var(--text-muted)', marginTop: 1 }}>
                            {sq.query.replace(/\n/g, ' ').slice(0, 50)}{sq.query.length > 50 ? '…' : ''}
                          </div>
                        </div>
                        {/* 运行 button in toolbar dropdown */}
                        <button
                          onClick={e => { e.stopPropagation(); updateQuery(sq.query); setShowSavedPanel(false); setTimeout(() => runQuery(), 0) }}
                          title="运行此查询"
                          style={{
                            background: 'rgba(79,163,224,.1)', border: '1px solid rgba(79,163,224,.25)',
                            cursor: 'pointer', color: 'var(--accent-blue)', fontSize: 9.5, lineHeight: 1,
                            padding: '2px 6px', flexShrink: 0, borderRadius: 3, marginRight: 4,
                          }}
                          onMouseEnter={e => (e.currentTarget.style.background = 'rgba(79,163,224,.22)')}
                          onMouseLeave={e => (e.currentTarget.style.background = 'rgba(79,163,224,.1)')}
                        >运行</button>
                        <button
                          onClick={e => { e.stopPropagation(); deleteSavedQuery(sq.id) }}
                          title="删除"
                          style={{
                            background: 'none', border: 'none', cursor: 'pointer',
                            color: 'var(--text-muted)', fontSize: 14, lineHeight: 1,
                            padding: '2px 6px', flexShrink: 0, borderRadius: 3,
                          }}
                          onMouseEnter={e => { e.currentTarget.style.color = 'var(--critical)'; e.currentTarget.style.background = 'rgba(250,88,45,.12)' }}
                          onMouseLeave={e => { e.currentTarget.style.color = 'var(--text-muted)'; e.currentTarget.style.background = 'none' }}
                        >×</button>
                      </div>
                    ))
                  )}
                </div>
              )}
            </div>

            <div style={{ flex: 1 }} />

            {/* Save current query button */}
            <button
              className="btn-secondary"
              style={{ fontSize: 11, padding: '4px 10px' }}
              onClick={saveCurrentQuery}
              title="保存当前查询到我的查询"
            >
              保存当前查询
            </button>

            {/* Row limit selector — in toolbar next to Run */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <span style={{ fontSize: 10, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>行数</span>
              <select
                className="filter-select"
                style={{ fontSize: 11, padding: '2px 6px' }}
                value={rowLimit}
                onChange={e => setRowLimit(Number(e.target.value))}
              >
                <option value={100}>100</option>
                <option value={500}>500</option>
                <option value={1000}>1000</option>
                <option value={5000}>5000</option>
              </select>
            </div>

            {/* NL2XQL AI Convert button */}
            <button
              className="btn-secondary"
              style={{ fontSize: 11, padding: '4px 11px', display: 'flex', alignItems: 'center', gap: 4 }}
              onClick={() => { setShowNl2Xql(true); setNl2xqlError('') }}
              title="用自然语言描述查询，AI 自动转换为 XQL"
            >
              🤖 AI 转换
            </button>

            {/* Run button with Ctrl+Enter hint */}
            <button
              className="btn-primary"
              style={{ padding: '4px 18px', fontSize: 12, opacity: isRunning ? 0.7 : 1 }}
              onClick={runQuery}
              disabled={isRunning}
              title="运行查询 (Ctrl+Enter)"
            >
              {isRunning ? '⏳ 执行中…' : '▶ Run'}
            </button>
            <span style={{ fontSize: 10, color: 'var(--text-muted)', marginLeft: 2 }} title="键盘快捷键">Ctrl+Enter 运行</span>
            {/* 参考面板切换按钮 */}
            <button
              className="btn-secondary"
              style={{ fontSize: 11, padding: '4px 10px', marginLeft: 4 }}
              onClick={() => setShowRef(p => !p)}
              title="切换 XQL 参考面板"
            >
              {showRef ? '参考 ◂' : '参考 ▸'}
            </button>
          </div>

          {/* XQL Editor with line numbers */}
          <div style={{ position: 'relative', flexShrink: 0, background: 'var(--bg-code)' }}>
            <pre style={{
              position: 'absolute', top: 0, left: 0,
              width: 40, height: '100%',
              background: 'var(--bg-code)', borderRight: '1px solid rgba(79,163,224,.15)',
              color: 'rgba(230,237,243,.35)', fontSize: 12, lineHeight: '1.7em',
              fontFamily: 'Consolas,"JetBrains Mono",monospace',
              padding: '12px 0', textAlign: 'right', paddingRight: 8,
              userSelect: 'none', pointerEvents: 'none',
              overflow: 'hidden',
            }}>
              {queryLines.map((_, i) => i + 1).join('\n')}
            </pre>
            <textarea
              ref={textareaRef}
              value={currentTab?.query ?? ''}
              onChange={e => updateQuery(e.target.value)}
              onKeyDown={handleKeyDown}
              onMouseMove={handleTextareaMouseMove}
              onMouseLeave={handleTextareaMouseLeave}
              style={{
                width: '100%', minHeight: 140, maxHeight: 260,
                resize: 'vertical', paddingLeft: 52, paddingTop: 12, paddingBottom: 12, paddingRight: 16,
                background: 'var(--bg-code)', color: 'var(--text-primary)',
                border: '1px solid rgba(79,163,224,.15)', outline: 'none',
                fontFamily: 'Consolas,"JetBrains Mono",monospace',
                fontSize: 12.5, lineHeight: '1.7em',
                caretColor: 'var(--accent-blue)',
              }}
              spellCheck={false}
            />
          </div>

          {/* Results area */}
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', borderTop: '2px solid var(--border)' }}>
            {/* Result stats bar */}
            <div style={{
              display: 'flex', alignItems: 'center', gap: 16, padding: '5px 14px',
              borderBottom: '1px solid var(--border)', background: 'var(--bg-card2)', flexShrink: 0,
            }}>
              {error ? (
                <span style={{ fontSize: 12, color: 'var(--critical)' }}>错误: {error}</span>
              ) : (
                <>
                  <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                    {loading ? '…' : (
                      results.length > 0
                        ? <><span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{results.length}</span> 条结果</>
                        : '无结果'
                    )}
                  </span>
                  {elapsed !== null && !loading && (
                    <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                      耗时: <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{elapsed}ms</span>
                    </span>
                  )}
                </>
              )}

              {/* Pinned column indicator */}
              {pinnedColumns.length > 0 && (
                <span style={{ fontSize: 10, color: 'var(--accent-blue)' }}>
                  📌 {pinnedColumns.length} 列已固定
                  <button
                    onClick={() => setPinnedColumns([])}
                    style={{ marginLeft: 6, background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', fontSize: 10 }}
                  >清除</button>
                </span>
              )}

              {results.length > 0 && (
                <div style={{ position: 'relative' }} ref={exportMenuRef}>
                  <button
                    className="btn-secondary"
                    style={{ fontSize: 10, padding: '2px 8px', display: 'flex', alignItems: 'center', gap: 4 }}
                    onClick={() => setShowExportMenu(p => !p)}
                  >
                    导出 ▾
                  </button>
                  {showExportMenu && (
                    <div style={{
                      position: 'absolute', bottom: '100%', right: 0, marginBottom: 4,
                      background: 'var(--bg-card)', border: '1px solid var(--border)',
                      borderRadius: 6, zIndex: 500, minWidth: 140,
                      boxShadow: '0 4px 16px rgba(0,0,0,.45)',
                      overflow: 'hidden',
                    }}>
                      {[
                        { label: '导出 CSV', action: () => { exportCSV(results, `query_results_${Date.now()}.csv`); setShowExportMenu(false) } },
                        { label: '导出 JSON', action: () => { exportJSON(results, `query_results_${Date.now()}.json`); setShowExportMenu(false) } },
                        {
                          label: copyFeedback ? '已复制 ✓' : '复制为表格',
                          action: () => {
                            copyAsTable(results)
                            setCopyFeedback(true)
                            setShowExportMenu(false)
                            setTimeout(() => setCopyFeedback(false), 2000)
                          },
                        },
                      ].map(item => (
                        <div
                          key={item.label}
                          onClick={item.action}
                          style={{
                            padding: '8px 14px', fontSize: 11.5, cursor: 'pointer',
                            color: copyFeedback && item.label.startsWith('已复制') ? 'var(--accent-green)' : 'var(--text-secondary)',
                            borderBottom: '1px solid rgba(255,255,255,.04)',
                            transition: 'background .1s',
                          }}
                          onMouseEnter={e => (e.currentTarget.style.background = 'rgba(255,255,255,.06)')}
                          onMouseLeave={e => (e.currentTarget.style.background = 'none')}
                        >
                          {item.label}
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* Results table */}
            <div style={{ flex: 1, overflowY: 'auto', overflowX: 'auto' }}>
              {sortedResults.length > 0 ? (
                <table className="data-table" style={{ minWidth: 'max-content' }}>
                  <thead>
                    <tr>
                      {/* expand toggle column */}
                      <th style={{ width: 28, padding: '0 6px', textAlign: 'center', userSelect: 'none' }} title="展开/折叠行">⊕</th>
                      {orderedColumns.map(c => (
                        <th
                          key={c}
                          onContextMenu={e => handleColHeaderContextMenu(e, c)}
                          onClick={() => handleColHeaderClick(c)}
                          style={{
                            cursor: 'pointer',
                            whiteSpace: 'nowrap',
                            color: pinnedColumns.includes(c) ? 'var(--accent-blue)' : undefined,
                            userSelect: 'none',
                          }}
                          title="点击排序 · 右键固定列"
                        >
                          {pinnedColumns.includes(c) && (
                            <span style={{ marginRight: 3, fontSize: 9 }}>📌</span>
                          )}
                          {c}
                          {sortCol === c && (
                            <span style={{ marginLeft: 3, fontSize: 9, color: 'var(--accent-blue)' }}>
                              {sortDir === 'asc' ? '▲' : '▼'}
                            </span>
                          )}
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {sortedResults.map((row, i) => (
                      <>
                        <tr
                          key={`row-${i}`}
                          style={{ cursor: 'pointer' }}
                          onClick={() => toggleRow(i)}
                        >
                          {/* expand indicator */}
                          <td style={{ textAlign: 'center', fontSize: 10, color: 'var(--text-muted)', padding: '0 6px' }}>
                            <span style={{
                              display: 'inline-block',
                              transform: expandedRows.has(i) ? 'rotate(90deg)' : 'none',
                              transition: 'transform .15s',
                            }}>▶</span>
                          </td>
                          {orderedColumns.map(c => (
                            <td key={c} style={{
                              fontFamily: typeof row[c] === 'number' ? 'monospace' : undefined,
                              textAlign: typeof row[c] === 'number' ? 'right' : undefined,
                              fontSize: 11.5,
                              maxWidth: 280,
                              overflow: 'hidden',
                              textOverflow: 'ellipsis',
                              whiteSpace: 'nowrap',
                            }}>
                              {renderCell(c, row[c])}
                            </td>
                          ))}
                        </tr>
                        {expandedRows.has(i) && (
                          <tr key={`row-${i}-expanded`} style={{ background: 'rgba(79,163,224,.04)' }}>
                            <td />
                            <td colSpan={orderedColumns.length} style={{ padding: '8px 16px' }}>
                              <div style={{
                                display: 'grid',
                                gridTemplateColumns: 'repeat(auto-fill, minmax(280px, 1fr))',
                                gap: '4px 16px',
                              }}>
                                {Object.entries(row).map(([k, v]) => (
                                  <div key={k} style={{ display: 'flex', gap: 8, alignItems: 'flex-start', padding: '2px 0', fontSize: 11 }}>
                                    <span style={{ color: 'var(--accent-blue)', fontFamily: 'monospace', fontSize: 10.5, flexShrink: 0, minWidth: 100 }}>{k}</span>
                                    <span style={{ color: 'var(--text-secondary)', fontFamily: 'monospace', fontSize: 10.5, wordBreak: 'break-all' }}>
                                      {v === null || v === undefined
                                        ? <span style={{ color: 'var(--text-muted)', fontStyle: 'italic' }}>null</span>
                                        : typeof v === 'boolean'
                                          ? <span style={{ color: v ? 'var(--accent-green)' : 'var(--critical)', fontWeight: 700 }}>{v ? '✓ true' : '✗ false'}</span>
                                          : typeof v === 'object'
                                            ? JSON.stringify(v)
                                            : String(v)
                                      }
                                    </span>
                                  </div>
                                ))}
                              </div>
                            </td>
                          </tr>
                        )}
                      </>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>
                  {loading
                    ? 'Executing query…'
                    : error
                      ? ''
                      : <span>
                        Run a query to see results<br />
                        <span style={{ fontSize: 11, marginTop: 6, display: 'block', opacity: 0.7 }}>
                          Try: <code style={{ background: 'rgba(255,255,255,.07)', padding: '1px 6px', borderRadius: 3 }}>dataset = xdr_data | limit 20</code>
                        </span>
                      </span>
                  }
                </div>
              )}
            </div>
          </div>
        </div>

        {/* RIGHT: XQL Reference (280px, hidden by default) */}
        <div style={{
          width: showRef ? 280 : 0, flexShrink: 0,
          borderLeft: showRef ? '1px solid var(--border)' : 'none',
          display: showRef ? 'flex' : 'none', flexDirection: 'column', overflow: 'hidden',
          background: 'var(--bg-sidebar)',
        }}>
          <div style={{ padding: '10px 14px 6px', fontSize: 10, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5, flexShrink: 0 }}>
            XQL Reference
          </div>
          <div style={{ flex: 1, overflowY: 'auto', padding: '0 0 12px' }}>
            {/* Event kinds */}
            <div style={{ padding: '6px 14px 4px', fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.4 }}>Event Kinds (xdr_data)</div>
            <div style={{ padding: '4px 14px 8px', display: 'flex', flexWrap: 'wrap', gap: 4 }}>
              {Object.entries(KIND_COLORS).map(([k, color]) => (
                <span
                  key={k}
                  onClick={() => updateQuery((currentTab?.query ?? '') + `\n| filter kind = "${k}"`)}
                  style={{
                    padding: '2px 7px', borderRadius: 3, fontSize: 10,
                    background: `${color}22`, color, cursor: 'pointer',
                    border: `1px solid ${color}44`, fontWeight: 600,
                  }}
                  title={`Click to filter by kind=${k}`}
                >{k}</span>
              ))}
            </div>

            <div style={{ height: 1, background: 'var(--border)', margin: '2px 14px 6px' }} />

            {/* Stages */}
            <div style={{ padding: '4px 14px 4px', fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.4 }}>Stages</div>
            {XQL_STAGES.map(s => (
              <div key={s} style={{
                padding: '4px 14px', fontSize: 12, fontFamily: 'Consolas,"JetBrains Mono",monospace',
                color: 'var(--accent-blue)', cursor: 'pointer',
              }}
                onMouseEnter={e => (e.currentTarget.style.background = 'rgba(255,255,255,.03)')}
                onMouseLeave={e => (e.currentTarget.style.background = 'none')}
                onClick={() => updateQuery((currentTab?.query ?? '') + '\n' + s + ' ')}
              >{s}</div>
            ))}

            <div style={{ height: 1, background: 'var(--border)', margin: '8px 14px' }} />

            {/* Functions */}
            <div style={{ padding: '4px 14px 4px', fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.4 }}>Functions</div>
            {XQL_FUNCTIONS.map(f => (
              <div key={f} style={{
                padding: '4px 14px', fontSize: 12, fontFamily: 'Consolas,"JetBrains Mono",monospace',
                color: 'var(--accent-blue)', cursor: 'pointer',
              }}
                onMouseEnter={e => (e.currentTarget.style.background = 'rgba(255,255,255,.03)')}
                onMouseLeave={e => (e.currentTarget.style.background = 'none')}
              >{f}</div>
            ))}

            <div style={{ height: 1, background: 'var(--border)', margin: '8px 14px' }} />

            {/* Operators */}
            <div style={{ padding: '4px 14px 4px', fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.4 }}>Operators</div>
            <div style={{ padding: '4px 14px', display: 'flex', flexWrap: 'wrap', gap: 4 }}>
              {XQL_OPERATORS.map(op => (
                <span key={op} style={{
                  padding: '2px 8px', background: 'var(--bg-card2)', border: '1px solid var(--border-light)',
                  borderRadius: 3, fontSize: 11, fontFamily: 'monospace', color: 'var(--text-secondary)',
                  cursor: 'pointer',
                }}>{op}</span>
              ))}
            </div>

            <div style={{ height: 1, background: 'var(--border)', margin: '8px 14px' }} />

            <div style={{
              margin: '8px 14px', padding: '10px 12px',
              background: 'rgba(79,163,224,.06)', border: '1px solid rgba(79,163,224,.2)',
              borderRadius: 6, fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.6,
            }}>
              <div style={{ fontWeight: 600, color: 'var(--accent-blue)', marginBottom: 4 }}>语法</div>
              <code style={{ display: 'block', fontFamily: 'monospace', fontSize: 10.5, lineHeight: 1.8, background: 'rgba(0,0,0,.2)', padding: 8, borderRadius: 4, color: 'var(--text-primary)' }}>
                dataset = xdr_data{'\n'}| filter kind = "process"{'\n'}| fields hostname, process_name,{'\n'}{'  '}cmdline, event_timestamp{'\n'}| sort desc event_timestamp{'\n'}| limit 50
              </code>
              <div style={{ marginTop: 6 }}>Press <code style={{ background: 'rgba(255,255,255,.08)', padding: '1px 4px', borderRadius: 3, fontSize: 10.5 }}>Ctrl+Enter</code> to run.</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
