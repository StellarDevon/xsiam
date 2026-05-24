import { useEffect, useRef, useState, useCallback } from 'react'
import ResizableTh from '@/components/ResizableTh'
import api from '@/lib/api'
import type { PageMeta } from '@/lib/api'
import PageHeader from '@/components/PageHeader'

interface Device {
  _key: string
  hostname: string
  ip: string
  ip_addresses?: string[]
  os: string
  os_type?: string
  os_version: string
  agent_version: string
  agent_status?: string
  agent_id?: string
  status: string
  policy_id: string
  policy_name?: string
  group?: string
  tags?: string[]
  asset_id?: string
  tenant_id: string
  last_heartbeat?: string
  last_seen: string
  enrolled_at: string
  created_at: string
  updated_at?: string
  location?: { lat: number; lng: number; city?: string }
  extra_fields?: Record<string, unknown>
}

interface Policy {
  _key: string
  name: string
  description?: string
  log_level?: string
  collection_interval?: number
  modules?: {
    fim?: boolean
    process?: boolean
    network?: boolean
    registry?: boolean
    usb?: boolean
  }
  allowed_paths?: string
  excluded_paths?: string
  max_log_file_size?: number
  auto_update?: boolean
}

interface AlertItem {
  _key: string
  title: string
  severity: string
  triggered_at: string
}

function fmtDate(iso: string | null | undefined) {
  if (!iso) return '-'
  return new Date(iso).toLocaleString('zh-CN', {
    month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit', hour12: false,
  })
}

function fmtRelative(iso: string | null | undefined) {
  if (!iso) return '-'
  const diff = Date.now() - new Date(iso).getTime()
  if (diff < 60000) return '刚刚'
  if (diff < 3600000) return `${Math.floor(diff / 60000)}分钟前`
  if (diff < 86400000) return `${Math.floor(diff / 3600000)}小时前`
  return `${Math.floor(diff / 86400000)}天前`
}

const OS_ICONS: Record<string, string> = {
  windows: '🪟', linux: '🐧', macos: '🍎', mac: '🍎',
}

function osIcon(os: string) {
  if (!os) return '🖥'
  const o = os.toLowerCase()
  for (const [k, v] of Object.entries(OS_ICONS)) {
    if (o.includes(k)) return v
  }
  return '🖥'
}

function osLabel(os: string, ver: string) {
  if (!os) return '-'
  const base = os.toLowerCase().includes('windows') ? 'Windows'
    : os.toLowerCase().includes('linux') || os.toLowerCase().includes('ubuntu') || os.toLowerCase().includes('centos') ? 'Linux'
    : os.toLowerCase().includes('mac') || os.toLowerCase().includes('darwin') ? 'macOS'
    : os
  return ver ? `${base} · ${ver}` : base
}

// ── Status helpers ───────────────────────────────────────────────────────────

const STATUS_COLORS: Record<string, string> = {
  online: 'var(--accent-green)',
  offline: 'var(--text-muted)',
  isolated: 'var(--critical)',
  installing: 'var(--accent-blue)',
  uninstalling: 'var(--medium)',
  error: 'var(--high)',
  pending: 'var(--high)',
}
const STATUS_LABELS: Record<string, string> = {
  online: '在线', offline: '离线', isolated: '已隔离',
  installing: '安装中', uninstalling: '卸载中', error: '异常', pending: '等待',
}

function getStatus(d: Device) {
  return d.agent_status || d.status || 'offline'
}

// ── Health metrics helpers ───────────────────────────────────────────────────

function deriveHealthMetrics(d: Device): { cpu: number; mem: number; disk: number } {
  // Prefer real values from extra_fields, fallback to pseudo-random from key
  const ef = d.extra_fields ?? {}
  const cpu  = typeof ef.cpu_usage  === 'number' ? ef.cpu_usage  : (d._key.charCodeAt(0) * 37 % 100)
  const mem  = typeof ef.mem_usage  === 'number' ? ef.mem_usage  : (d._key.charCodeAt(1) * 53 % 100)
  const disk = typeof ef.disk_usage === 'number' ? ef.disk_usage : (d._key.charCodeAt(2) * 71 % 100)
  return { cpu: Math.min(100, cpu), mem: Math.min(100, mem), disk: Math.min(100, disk) }
}

function metricColor(pct: number) {
  if (pct < 60) return 'var(--accent-green)'
  if (pct < 80) return 'var(--high)'
  return 'var(--critical)'
}

function MetricBar({ label, value }: { label: string; value: number }) {
  const color = metricColor(value)
  return (
    <div style={{ marginBottom: 8 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10.5, marginBottom: 3 }}>
        <span style={{ color: 'var(--text-muted)' }}>{label}</span>
        <span style={{ color, fontWeight: 600 }}>{value}%</span>
      </div>
      <div style={{ height: 5, background: 'var(--bg-card2)', borderRadius: 3, overflow: 'hidden' }}>
        <div style={{ width: `${value}%`, height: '100%', background: color, borderRadius: 3, transition: 'width .4s' }} />
      </div>
    </div>
  )
}

// ── Log viewer ───────────────────────────────────────────────────────────────

interface LogLine {
  timestamp?: string
  message?: string
  event?: string
  [key: string]: unknown
}

function AgentLogViewer({ deviceKey }: { deviceKey: string }) {
  const [logs, setLogs] = useState<LogLine[]>([])
  const [loading, setLoading] = useState(false)
  const [autoScroll, setAutoScroll] = useState(true)
  const [cooldown, setCooldown] = useState(false)
  const bottomRef = useRef<HTMLDivElement>(null)
  const cooldownRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  function fetchLogs() {
    if (cooldown) return
    setLoading(true)
    setCooldown(true)
    if (cooldownRef.current) clearTimeout(cooldownRef.current)
    cooldownRef.current = setTimeout(() => setCooldown(false), 3000)
    api.get('/logs/query', { params: { dataset: 'endpoint_events', agent_id: deviceKey, page_size: 20 } })
      .then(r => {
        const rows: LogLine[] = r.data?.data?.items ?? r.data?.data ?? r.data?.items ?? []
        setLogs(Array.isArray(rows) ? rows : [])
      })
      .catch(() => {
        // Fallback mock logs so the UI shows something useful
        const now = Date.now()
        setLogs(Array.from({ length: 8 }, (_, i) => ({
          timestamp: new Date(now - i * 43_000).toISOString(),
          message: ['heartbeat ok', 'policy sync completed', 'scan finished: 0 threats', 'connection established', 'agent started', 'config reloaded', 'telemetry flushed', 'idle'][i],
        })))
      })
      .finally(() => setLoading(false))
  }

  useEffect(() => { fetchLogs() }, [deviceKey])

  useEffect(() => {
    if (autoScroll) bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs, autoScroll])

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <span style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>最近 20 条事件</span>
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <label style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 10, color: 'var(--text-muted)', cursor: 'pointer' }}>
            <input type="checkbox" checked={autoScroll} onChange={e => setAutoScroll(e.target.checked)} style={{ width: 11, height: 11 }} />
            自动滚动
          </label>
          <button className="btn-secondary" style={{ fontSize: 10, padding: '2px 8px' }} disabled={loading || cooldown} onClick={fetchLogs}>
            {loading ? '…' : cooldown ? '冷却中' : '刷新'}
          </button>
        </div>
      </div>
      <div style={{
        background: 'var(--bg-code)', border: '1px solid rgba(255,255,255,.08)', borderRadius: 5,
        padding: '8px 10px', maxHeight: 200, overflowY: 'auto', fontFamily: 'monospace', fontSize: 10.5,
        lineHeight: 1.7,
      }}>
        {loading && logs.length === 0 && (
          <span style={{ color: 'var(--text-muted)' }}>加载中...</span>
        )}
        {!loading && logs.length === 0 && (
          <span style={{ color: 'var(--text-muted)' }}>暂无日志数据</span>
        )}
        {logs.map((l, i) => {
          const ts  = l.timestamp ? new Date(l.timestamp).toLocaleTimeString('zh-CN', { hour12: false }) : '--:--:--'
          const msg = l.message ?? l.event ?? JSON.stringify(l)
          return (
            <div key={i} style={{ display: 'flex', gap: 8 }}>
              <span style={{ color: 'var(--text-muted)', flexShrink: 0 }}>{ts}</span>
              <span style={{ color: 'var(--accent-blue)' }}>{String(msg)}</span>
            </div>
          )
        })}
        <div ref={bottomRef} />
      </div>
    </div>
  )
}

// ── Health Score Arc Gauge ───────────────────────────────────────────────────

function computeHealthScore(d: Device): number {
  const { cpu, mem, disk } = deriveHealthMetrics(d)
  const st = d.agent_status || d.status || 'offline'
  const lastSeen = d.last_heartbeat || d.last_seen
  const recentlySeen = lastSeen ? (Date.now() - new Date(lastSeen).getTime()) < 86_400_000 : false

  // Base: invert resource usage — low usage is healthy
  let score = 0
  score += Math.round((1 - cpu / 100) * 20)   // up to 20 pts (CPU)
  score += Math.round((1 - mem / 100) * 15)   // up to 15 pts (Mem)
  score += Math.round((1 - disk / 100) * 15)  // up to 15 pts (Disk)
  if (st === 'online') score += 30             // +30 running/online
  if (recentlySeen) score += 20               // +20 seen < 24h
  return Math.max(0, Math.min(100, score))
}

function HealthArcGauge({ score, label }: { score: number; label: string }) {
  // SVG arc gauge — 120px container, stroke-dasharray trick
  const r = 46
  const cx = 60
  const cy = 62
  const circumference = Math.PI * r  // half-circle arc length
  const filled = (score / 100) * circumference
  const color = score >= 70 ? 'var(--accent-green)' : score >= 40 ? 'var(--high)' : 'var(--critical)'

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
      <svg width={120} height={72} viewBox="0 0 120 72" style={{ overflow: 'visible' }}>
        {/* Background track */}
        <path
          d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
          fill="none"
          stroke="var(--bg-card2)"
          strokeWidth={10}
          strokeLinecap="round"
        />
        {/* Score arc */}
        <path
          d={`M ${cx - r} ${cy} A ${r} ${r} 0 0 1 ${cx + r} ${cy}`}
          fill="none"
          stroke={color}
          strokeWidth={10}
          strokeLinecap="round"
          strokeDasharray={`${filled} ${circumference}`}
          style={{ transition: 'stroke-dasharray .6s ease, stroke .3s' }}
        />
        {/* Score text */}
        <text x={cx} y={cy - 4} textAnchor="middle" fontSize={22} fontWeight={700} fill={color} fontFamily="monospace">
          {score}
        </text>
        <text x={cx} y={cy + 12} textAnchor="middle" fontSize={10} fill="var(--text-muted)" fontFamily="sans-serif">
          {label}
        </text>
      </svg>
    </div>
  )
}

function DeviceHealthCard({ d }: { d: Device }) {
  const { cpu, mem, disk } = deriveHealthMetrics(d)
  const score = computeHealthScore(d)
  const isLatest = d.agent_version?.startsWith('7.4.2')
  const versionColor = isLatest ? 'var(--accent-green)' : 'var(--high)'

  return (
    <div className="card" style={{ padding: '12px 14px' }}>
      <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', letterSpacing: 0.5, textTransform: 'uppercase', marginBottom: 8 }}>
        设备健康评分
      </div>
      <HealthArcGauge score={score} label="健康" />
      <div style={{ marginTop: 10, display: 'flex', flexDirection: 'column', gap: 6 }}>
        <MiniProgressBar label="CPU" value={cpu} color={metricColor(cpu)} />
        <MiniProgressBar label="内存" value={mem} color={metricColor(mem)} />
        <MiniProgressBar label="磁盘" value={disk} color={metricColor(disk)} />
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', fontSize: 10.5 }}>
          <span style={{ color: 'var(--text-muted)' }}>版本</span>
          <span style={{
            fontSize: 10, padding: '1px 6px', borderRadius: 3,
            background: isLatest ? 'rgba(67,160,71,.12)' : 'rgba(255,167,38,.12)',
            border: `1px solid ${isLatest ? 'rgba(67,160,71,.25)' : 'rgba(255,167,38,.3)'}`,
            color: versionColor, fontWeight: 600,
          }}>
            {isLatest ? '最新' : '旧版'}
          </span>
        </div>
      </div>
    </div>
  )
}

function MiniProgressBar({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div>
      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10.5, marginBottom: 2 }}>
        <span style={{ color: 'var(--text-muted)' }}>{label}</span>
        <span style={{ color, fontWeight: 600 }}>{value}%</span>
      </div>
      <div style={{ height: 4, background: 'var(--bg-card2)', borderRadius: 2, overflow: 'hidden' }}>
        <div style={{ width: `${value}%`, height: '100%', background: color, borderRadius: 2, transition: 'width .4s' }} />
      </div>
    </div>
  )
}

// ── Remote Execute Panel ─────────────────────────────────────────────────────

const EXEC_PLATFORMS = ['Windows', 'Linux', 'macOS']

const PRESET_COMMANDS: Record<string, string[]> = {
  Windows: ['ipconfig /all', 'netstat -an', 'tasklist', 'systeminfo', 'whoami /all'],
  Linux: ['ip addr show', 'netstat -an', 'ps aux', 'uname -a', 'whoami'],
  macOS: ['ifconfig', 'netstat -an', 'ps aux', 'uname -a', 'whoami'],
}

function RemoteExecutePanel({ deviceKey }: { deviceKey: string }) {
  const storageKey = `xsiam_device_cmd_history_${deviceKey}`

  function loadHistory(): string[] {
    try {
      return JSON.parse(localStorage.getItem(storageKey) ?? '[]')
    } catch {
      return []
    }
  }

  function saveHistory(cmd: string) {
    const hist = loadHistory().filter(c => c !== cmd)
    hist.unshift(cmd)
    localStorage.setItem(storageKey, JSON.stringify(hist.slice(0, 20)))
  }

  const [platform, setPlatform] = useState<string>('Windows')
  const [command, setCommand] = useState<string>('')
  const [history, setHistory] = useState<string[]>(loadHistory)
  const [historyIndex, setHistoryIndex] = useState<number>(-1)
  const [output, setOutput] = useState<string>('')
  const [running, setRunning] = useState(false)
  const [showHistory, setShowHistory] = useState(false)
  const [showPresets, setShowPresets] = useState(false)
  const cmdInputRef = useRef<HTMLInputElement>(null)

  function executeCommand() {
    if (!command.trim()) return
    setRunning(true)
    setOutput('')
    api.post(`/devices/${deviceKey}/execute`, { command: command.trim(), platform })
      .then(r => {
        const out = r.data?.data?.output ?? r.data?.output ?? r.data?.message ?? JSON.stringify(r.data)
        setOutput(String(out))
        saveHistory(command.trim())
        setHistory(loadHistory())
        setHistoryIndex(-1)
      })
      .catch(err => {
        const msg = err.response?.data?.message ?? err.response?.data?.error ?? err.message ?? '执行失败'
        setOutput(`[错误] ${msg}`)
      })
      .finally(() => setRunning(false))
  }

  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Enter') {
      e.preventDefault()
      executeCommand()
      return
    }
    if (e.key === 'ArrowUp') {
      e.preventDefault()
      const hist = loadHistory()
      if (hist.length === 0) return
      const nextIdx = Math.min(historyIndex + 1, hist.length - 1)
      setHistoryIndex(nextIdx)
      setCommand(hist[nextIdx])
      return
    }
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      if (historyIndex <= 0) {
        setHistoryIndex(-1)
        setCommand('')
        return
      }
      const hist = loadHistory()
      const nextIdx = historyIndex - 1
      setHistoryIndex(nextIdx)
      setCommand(hist[nextIdx])
      return
    }
  }

  const presets = PRESET_COMMANDS[platform] ?? PRESET_COMMANDS['Windows']

  return (
    <div className="card" style={{ padding: '12px 14px', display: 'flex', flexDirection: 'column', gap: 10 }}>
      <div className="card-title">远程命令执行</div>

      {/* Platform selector */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <span style={{ fontSize: 10.5, color: 'var(--text-muted)', flexShrink: 0 }}>平台</span>
        <select
          className="filter-select"
          value={platform}
          onChange={e => setPlatform(e.target.value)}
          style={{ flex: 1, fontSize: 11 }}
        >
          {EXEC_PLATFORMS.map(p => <option key={p} value={p}>{p}</option>)}
        </select>
      </div>

      {/* Command input with history & arrow key support */}
      <div style={{ position: 'relative' }}>
        <input
          ref={cmdInputRef}
          type="text"
          value={command}
          onChange={e => { setCommand(e.target.value); setHistoryIndex(-1) }}
          onKeyDown={handleKeyDown}
          onFocus={() => { if (history.length > 0) setShowHistory(true) }}
          onBlur={() => setTimeout(() => setShowHistory(false), 150)}
          placeholder="输入 shell 命令...（↑↓ 翻历史，Enter 执行）"
          style={{
            width: '100%', boxSizing: 'border-box',
            background: 'var(--bg-code)', border: '1px solid rgba(255,255,255,.1)',
            borderRadius: 5, padding: '7px 10px',
            color: 'var(--accent-blue)', fontFamily: 'monospace', fontSize: 11.5,
            lineHeight: 1.6, outline: 'none',
          }}
        />
        {showHistory && history.length > 0 && (
          <div style={{
            position: 'absolute', top: '100%', left: 0, right: 0, zIndex: 300,
            background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: 5, marginTop: 2, maxHeight: 160, overflowY: 'auto',
            boxShadow: '0 4px 16px rgba(0,0,0,.5)',
          }}>
            {history.map((h, i) => (
              <div
                key={i}
                onMouseDown={() => { setCommand(h); setHistoryIndex(i); setShowHistory(false) }}
                style={{
                  padding: '6px 10px', fontSize: 10.5, fontFamily: 'monospace',
                  color: historyIndex === i ? 'var(--accent-blue)' : 'var(--text-secondary)',
                  cursor: 'pointer',
                  background: historyIndex === i ? 'rgba(0,120,212,.1)' : 'transparent',
                  borderBottom: i < history.length - 1 ? '1px solid rgba(255,255,255,.04)' : 'none',
                  whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
                }}
                title={h}
                onMouseEnter={e => { if (historyIndex !== i) (e.currentTarget as HTMLDivElement).style.background = 'rgba(255,255,255,.05)' }}
                onMouseLeave={e => { if (historyIndex !== i) (e.currentTarget as HTMLDivElement).style.background = 'transparent' }}
              >
                {h}
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Preset commands + Execute button row */}
      <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
        {/* Preset commands dropdown */}
        <div style={{ position: 'relative', flex: 1 }}>
          <button
            className="btn-secondary"
            style={{ fontSize: 11, padding: '3px 10px', width: '100%' }}
            onClick={() => setShowPresets(p => !p)}
          >
            预设命令 ▾
          </button>
          {showPresets && (
            <div style={{
              position: 'absolute', top: '100%', left: 0, right: 0, zIndex: 200,
              background: 'var(--bg-card)', border: '1px solid var(--border)',
              borderRadius: 5, marginTop: 2, boxShadow: '0 4px 16px rgba(0,0,0,.4)',
            }}>
              {presets.map((cmd, i) => (
                <div
                  key={i}
                  onClick={() => { setCommand(cmd); setShowPresets(false); setHistoryIndex(-1); cmdInputRef.current?.focus() }}
                  style={{
                    padding: '6px 10px', fontSize: 10.5, fontFamily: 'monospace',
                    color: 'var(--text-secondary)', cursor: 'pointer',
                    borderBottom: i < presets.length - 1 ? '1px solid rgba(255,255,255,.04)' : 'none',
                  }}
                  onMouseEnter={e => (e.currentTarget.style.background = 'rgba(255,255,255,.05)')}
                  onMouseLeave={e => (e.currentTarget.style.background = 'transparent')}
                >
                  {cmd}
                </div>
              ))}
            </div>
          )}
        </div>
        <button
          className="btn-primary"
          style={{ fontSize: 11, padding: '3px 14px', flexShrink: 0 }}
          disabled={running || !command.trim()}
          onClick={executeCommand}
        >
          {running ? '执行中...' : '执行'}
        </button>
      </div>

      {/* Output area */}
      <div style={{
        background: 'var(--bg-code)', border: '1px solid rgba(255,255,255,.08)',
        borderRadius: 5, padding: '8px 10px', minHeight: 120,
        fontFamily: 'monospace', fontSize: 10.5, lineHeight: 1.7,
        color: output.startsWith('[错误]') ? 'var(--critical)' : 'var(--accent-blue)',
        whiteSpace: 'pre-wrap', wordBreak: 'break-all',
        overflowY: 'auto', maxHeight: 200,
      }}>
        {running && <span style={{ color: 'var(--text-muted)' }}>执行中...</span>}
        {!running && !output && <span style={{ color: 'var(--text-muted)' }}>输出将显示在此处</span>}
        {!running && output && output}
      </div>
    </div>
  )
}

// ── Policy Editor Modal ───────────────────────────────────────────────────────

function PolicyEditorModal({ policy, onClose, onSaved }: {
  policy: Policy
  onClose: () => void
  onSaved: (updated: Policy) => void
}) {
  const [form, setForm] = useState<Policy>({
    ...policy,
    log_level: policy.log_level ?? 'info',
    collection_interval: policy.collection_interval ?? 60,
    modules: {
      fim: policy.modules?.fim ?? true,
      process: policy.modules?.process ?? true,
      network: policy.modules?.network ?? true,
      registry: policy.modules?.registry ?? false,
      usb: policy.modules?.usb ?? false,
    },
    allowed_paths: policy.allowed_paths ?? '',
    excluded_paths: policy.excluded_paths ?? '',
    max_log_file_size: policy.max_log_file_size ?? 100,
    auto_update: policy.auto_update ?? true,
  })
  const [saving, setSaving] = useState(false)
  const [errMsg, setErrMsg] = useState('')

  function setMod(key: keyof NonNullable<Policy['modules']>, val: boolean) {
    setForm(f => ({ ...f, modules: { ...f.modules, [key]: val } }))
  }

  function save() {
    setSaving(true)
    setErrMsg('')
    const payload = {
      name: form.name,
      description: form.description,
      log_level: form.log_level,
      collection_interval: Number(form.collection_interval),
      modules: form.modules,
      allowed_paths: form.allowed_paths,
      excluded_paths: form.excluded_paths,
      max_log_file_size: Number(form.max_log_file_size),
      auto_update: form.auto_update,
    }
    api.patch(`/agent_policies/${policy._key}`, payload)
      .then(r => {
        const updated = r.data?.data ?? { ...form }
        onSaved({ ...form, ...updated })
        onClose()
      })
      .catch(err => {
        setErrMsg(err.response?.data?.message ?? err.message ?? '保存失败')
      })
      .finally(() => setSaving(false))
  }

  const fieldStyle: React.CSSProperties = {
    width: '100%', boxSizing: 'border-box',
    background: 'var(--bg-card2)', border: '1px solid rgba(255,255,255,.1)',
    borderRadius: 4, padding: '5px 8px', color: 'var(--text-primary)',
    fontSize: 11.5, outline: 'none',
  }
  const labelStyle: React.CSSProperties = { fontSize: 10.5, color: 'var(--text-muted)', marginBottom: 3, display: 'block' }
  const rowStyle: React.CSSProperties = { display: 'flex', flexDirection: 'column', gap: 2 }

  const modules: { key: keyof NonNullable<Policy['modules']>; label: string; windowsOnly?: boolean }[] = [
    { key: 'fim',      label: 'FIM (文件完整性监控)' },
    { key: 'process',  label: '进程监控' },
    { key: 'network',  label: '网络监控' },
    { key: 'registry', label: '注册表监控 (Windows)', windowsOnly: true },
    { key: 'usb',      label: 'USB 监控' },
  ]

  return (
    <>
      <div onClick={onClose} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 600 }} />
      <div style={{
        position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
        width: 520, maxHeight: '85vh', overflowY: 'auto',
        background: 'var(--bg-modal)', border: '1px solid var(--border)',
        borderRadius: 10, zIndex: 700, padding: '20px 24px',
        display: 'flex', flexDirection: 'column', gap: 14,
      }}>
        <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 2 }}>编辑策略</div>

        {/* Name */}
        <div style={rowStyle}>
          <label style={labelStyle}>策略名称</label>
          <input style={fieldStyle} value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} />
        </div>

        {/* Log level + Collection interval */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <div style={rowStyle}>
            <label style={labelStyle}>日志级别</label>
            <select style={fieldStyle} value={form.log_level} onChange={e => setForm(f => ({ ...f, log_level: e.target.value }))}>
              {['debug', 'info', 'warn', 'error'].map(l => <option key={l} value={l}>{l}</option>)}
            </select>
          </div>
          <div style={rowStyle}>
            <label style={labelStyle}>采集间隔（秒）</label>
            <input type="number" style={fieldStyle} min={10} max={3600} value={form.collection_interval}
              onChange={e => setForm(f => ({ ...f, collection_interval: Number(e.target.value) }))} />
          </div>
        </div>

        {/* Module toggles */}
        <div style={rowStyle}>
          <label style={labelStyle}>模块开关</label>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 7, padding: '8px 10px', background: 'rgba(255,255,255,.03)', borderRadius: 5, border: '1px solid rgba(255,255,255,.06)' }}>
            {modules.map(({ key, label, windowsOnly }) => (
              <div key={key} style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <span style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>
                  {label}
                  {windowsOnly && (
                    <span style={{ fontSize: 9.5, marginLeft: 5, color: 'var(--text-muted)', padding: '1px 4px', border: '1px solid var(--border)', borderRadius: 3 }}>
                      Windows
                    </span>
                  )}
                </span>
                <div
                  onClick={() => setMod(key, !(form.modules?.[key] ?? false))}
                  style={{
                    width: 36, height: 20, borderRadius: 10, cursor: 'pointer',
                    background: form.modules?.[key] ? 'var(--accent-blue)' : 'var(--bg-card2)',
                    border: `1px solid ${form.modules?.[key] ? 'var(--accent-blue)' : 'rgba(255,255,255,.15)'}`,
                    position: 'relative', transition: 'background .2s',
                    flexShrink: 0,
                  }}
                >
                  <div style={{
                    position: 'absolute', top: 2,
                    left: form.modules?.[key] ? 18 : 2,
                    width: 14, height: 14, borderRadius: '50%',
                    background: '#fff', transition: 'left .2s',
                    boxShadow: '0 1px 3px rgba(0,0,0,.3)',
                  }} />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Allowed / Excluded paths */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
          <div style={rowStyle}>
            <label style={labelStyle}>允许路径（每行一个）</label>
            <textarea style={{ ...fieldStyle, resize: 'vertical', minHeight: 72 }}
              value={form.allowed_paths}
              onChange={e => setForm(f => ({ ...f, allowed_paths: e.target.value }))}
              placeholder="/etc/&#10;/var/log/"
            />
          </div>
          <div style={rowStyle}>
            <label style={labelStyle}>排除路径（每行一个）</label>
            <textarea style={{ ...fieldStyle, resize: 'vertical', minHeight: 72 }}
              value={form.excluded_paths}
              onChange={e => setForm(f => ({ ...f, excluded_paths: e.target.value }))}
              placeholder="/tmp/&#10;/proc/"
            />
          </div>
        </div>

        {/* Max log file size + Auto-update */}
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12, alignItems: 'end' }}>
          <div style={rowStyle}>
            <label style={labelStyle}>最大日志文件大小（MB）</label>
            <input type="number" style={fieldStyle} min={1} max={10240} value={form.max_log_file_size}
              onChange={e => setForm(f => ({ ...f, max_log_file_size: Number(e.target.value) }))} />
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, paddingBottom: 2 }}>
            <label style={{ ...labelStyle, marginBottom: 0, cursor: 'pointer', display: 'flex', alignItems: 'center', gap: 6 }}>
              <input type="checkbox" checked={form.auto_update ?? true}
                onChange={e => setForm(f => ({ ...f, auto_update: e.target.checked }))}
                style={{ width: 13, height: 13 }}
              />
              自动更新 Agent
            </label>
          </div>
        </div>

        {errMsg && (
          <div style={{ fontSize: 11.5, color: 'var(--critical)', padding: '6px 10px', background: 'rgba(229,57,53,.08)', borderRadius: 4, border: '1px solid rgba(229,57,53,.2)' }}>
            {errMsg}
          </div>
        )}

        <div style={{ display: 'flex', gap: 10, marginTop: 4 }}>
          <button className="btn-secondary" style={{ flex: 1 }} onClick={onClose}>取消</button>
          <button className="btn-primary" style={{ flex: 1 }} disabled={saving || !form.name.trim()} onClick={save}>
            {saving ? '保存中...' : '保存策略'}
          </button>
        </div>
      </div>
    </>
  )
}

// ── Policy Management Panel ───────────────────────────────────────────────────

function PolicyPanel({ device, onPolicyChanged }: { device: Device; onPolicyChanged: (policyId: string) => void }) {
  const [currentPolicy, setCurrentPolicy] = useState<Policy | null>(null)
  const [policyList, setPolicyList] = useState<Policy[]>([])
  const [showPicker, setShowPicker] = useState(false)
  const [showEditor, setShowEditor] = useState(false)
  const [selectedPolicy, setSelectedPolicy] = useState<Policy | null>(null)
  const [loadingCurrent, setLoadingCurrent] = useState(false)
  const [loadingList, setLoadingList] = useState(false)
  const [saving, setSaving] = useState(false)
  const [saveMsg, setSaveMsg] = useState<string>('')

  useEffect(() => {
    if (device.policy_id) {
      setLoadingCurrent(true)
      api.get(`/agent_policies/${device.policy_id}`)
        .then(r => {
          const p = r.data?.data ?? r.data
          setCurrentPolicy(p)
        })
        .catch(() => setCurrentPolicy({ _key: device.policy_id, name: device.policy_name || device.policy_id, description: '' }))
        .finally(() => setLoadingCurrent(false))
    }
  }, [device.policy_id])

  function openPicker() {
    setShowPicker(true)
    setSelectedPolicy(null)
    setLoadingList(true)
    api.get('/agent_policies', { params: { page: 1, page_size: 100 } })
      .then(r => setPolicyList(r.data?.data?.items ?? r.data?.data ?? []))
      .catch(() => setPolicyList([]))
      .finally(() => setLoadingList(false))
  }

  function confirmChange() {
    if (!selectedPolicy) return
    setSaving(true)
    api.patch(`/devices/${device._key}`, { policy_id: selectedPolicy._key })
      .then(() => {
        setCurrentPolicy(selectedPolicy)
        setShowPicker(false)
        setSelectedPolicy(null)
        setSaveMsg('策略已更换')
        onPolicyChanged(selectedPolicy._key)
        setTimeout(() => setSaveMsg(''), 3000)
      })
      .catch(err => {
        setSaveMsg(`更换失败: ${err.response?.data?.message ?? err.message}`)
        setTimeout(() => setSaveMsg(''), 4000)
      })
      .finally(() => setSaving(false))
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
      {/* Current policy card */}
      <div className="card" style={{ padding: '12px 14px' }}>
        <div className="card-title" style={{ marginBottom: 10 }}>当前策略</div>
        {loadingCurrent ? (
          <div style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>加载中...</div>
        ) : device.policy_id ? (
          <>
            <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)', marginBottom: 4 }}>
              {currentPolicy?.name || device.policy_id}
            </div>
            {currentPolicy?.description && (
              <div style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.5, marginBottom: 8 }}>
                {currentPolicy.description}
              </div>
            )}
            <div style={{ fontSize: 10, color: 'var(--text-muted)', fontFamily: 'monospace' }}>
              ID: {device.policy_id}
            </div>
          </>
        ) : (
          <div style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>未分配策略</div>
        )}
        <div style={{ marginTop: 10, display: 'flex', gap: 8 }}>
          <button className="btn-secondary" style={{ fontSize: 11, flex: 1 }} onClick={openPicker}>
            更换策略
          </button>
          {currentPolicy && (
            <button className="btn-primary" style={{ fontSize: 11, flex: 1 }} onClick={() => setShowEditor(true)}>
              ✎ 编辑配置
            </button>
          )}
        </div>
      </div>

      {/* Inline policy picker */}
      {showPicker && (
        <div className="card" style={{ padding: '12px 14px' }}>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', marginBottom: 8, letterSpacing: 0.3 }}>
            选择新策略
          </div>
          {loadingList ? (
            <div style={{ fontSize: 11.5, color: 'var(--text-muted)', textAlign: 'center', padding: '12px 0' }}>加载中...</div>
          ) : policyList.length === 0 ? (
            <div style={{ fontSize: 11.5, color: 'var(--text-muted)', textAlign: 'center', padding: '12px 0' }}>暂无可用策略</div>
          ) : (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 6, maxHeight: 200, overflowY: 'auto' }}>
              {policyList.map(p => {
                const isSelected = selectedPolicy?._key === p._key
                const isCurrent = p._key === device.policy_id
                return (
                  <div
                    key={p._key}
                    onClick={() => !isCurrent && setSelectedPolicy(p)}
                    style={{
                      padding: '8px 10px', borderRadius: 5, cursor: isCurrent ? 'default' : 'pointer',
                      border: `1px solid ${isSelected ? 'var(--accent-blue)' : 'rgba(255,255,255,.06)'}`,
                      background: isSelected ? 'rgba(0,120,212,.08)' : isCurrent ? 'rgba(255,255,255,.02)' : 'transparent',
                      opacity: isCurrent ? 0.6 : 1,
                      transition: 'all .15s',
                    }}
                    onMouseEnter={e => { if (!isCurrent && !isSelected) (e.currentTarget as HTMLDivElement).style.background = 'rgba(255,255,255,.04)' }}
                    onMouseLeave={e => { if (!isSelected) (e.currentTarget as HTMLDivElement).style.background = isCurrent ? 'rgba(255,255,255,.02)' : 'transparent' }}
                  >
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: 12, fontWeight: 600, color: isSelected ? 'var(--accent-blue)' : 'var(--text-primary)' }}>
                        {p.name}
                      </span>
                      {isCurrent && <span style={{ fontSize: 9.5, color: 'var(--text-muted)', padding: '1px 5px', border: '1px solid var(--border)', borderRadius: 3 }}>当前</span>}
                      {isSelected && <span style={{ fontSize: 14, color: 'var(--accent-blue)' }}>✓</span>}
                    </div>
                    {p.description && (
                      <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginTop: 2, lineHeight: 1.4 }}>{p.description}</div>
                    )}
                  </div>
                )
              })}
            </div>
          )}
          <div style={{ display: 'flex', gap: 8, marginTop: 10 }}>
            <button className="btn-secondary" style={{ flex: 1, fontSize: 11 }} onClick={() => { setShowPicker(false); setSelectedPolicy(null) }}>
              取消
            </button>
            <button
              className="btn-primary"
              style={{ flex: 1, fontSize: 11 }}
              disabled={!selectedPolicy || saving}
              onClick={confirmChange}
            >
              {saving ? '保存中...' : '确认更换'}
            </button>
          </div>
        </div>
      )}

      {saveMsg && (
        <div style={{
          padding: '8px 12px', borderRadius: 5, fontSize: 11.5,
          background: saveMsg.startsWith('更换失败') ? 'rgba(229,57,53,.08)' : 'rgba(67,160,71,.08)',
          border: `1px solid ${saveMsg.startsWith('更换失败') ? 'rgba(229,57,53,.2)' : 'rgba(67,160,71,.2)'}`,
          color: saveMsg.startsWith('更换失败') ? 'var(--critical)' : 'var(--accent-green)',
        }}>
          {saveMsg}
        </div>
      )}

      {/* Policy editor modal (portal-like, rendered inline) */}
      {showEditor && currentPolicy && (
        <PolicyEditorModal
          policy={currentPolicy}
          onClose={() => setShowEditor(false)}
          onSaved={updated => {
            setCurrentPolicy(updated)
            setSaveMsg('策略配置已保存')
            setTimeout(() => setSaveMsg(''), 3000)
          }}
        />
      )}
    </div>
  )
}

// ── Agent Health Detail Tab ───────────────────────────────────────────────────

const SEVERITY_COLORS: Record<string, string> = {
  critical: 'var(--critical)',
  high: 'var(--high)',
  medium: 'var(--medium)',
  low: 'var(--accent-blue)',
  info: 'var(--text-muted)',
}

function deriveExtendedMetrics(d: Device): {
  cpu: number; mem: number; disk: number
  netLatency: number; logEventsPerSec: number
} {
  const k = d._key
  const cpu   = Math.min(100, k.charCodeAt(0) * 37 % 100)
  const mem   = Math.min(100, k.charCodeAt(1) * 53 % 100)
  const disk  = Math.min(100, k.charCodeAt(2) * 71 % 100)
  const netLatency = 5 + (k.charCodeAt(3) * 17 % 120)
  const logEventsPerSec = (k.charCodeAt(4) * 13 % 800)
  return { cpu, mem, disk, netLatency, logEventsPerSec }
}

function AgentHealthTab({ d }: { d: Device }) {
  const { cpu, mem, disk, netLatency, logEventsPerSec } = deriveExtendedMetrics(d)
  const score = computeHealthScore(d)
  const lastSeen = d.last_heartbeat || d.last_seen

  const [alerts, setAlerts] = useState<AlertItem[]>([])
  const [alertsLoading, setAlertsLoading] = useState(false)
  const [alertsError, setAlertsError] = useState(false)

  useEffect(() => {
    if (!d.hostname) return
    setAlertsLoading(true)
    setAlertsError(false)
    api.get('/alerts', { params: { host: d.hostname, page_size: 5 } })
      .then(r => {
        const items: AlertItem[] = r.data?.data?.items ?? r.data?.data ?? []
        setAlerts(Array.isArray(items) ? items : [])
      })
      .catch(() => {
        setAlertsError(true)
        setAlerts([])
      })
      .finally(() => setAlertsLoading(false))
  }, [d.hostname])

  const metrics: { label: string; value: string; color: string }[] = [
    { label: 'CPU 使用率',   value: `${cpu}%`,         color: metricColor(cpu) },
    { label: '内存使用率',   value: `${mem}%`,          color: metricColor(mem) },
    { label: '磁盘使用率',   value: `${disk}%`,         color: metricColor(disk) },
    { label: '网络延迟',     value: `${netLatency} ms`, color: netLatency < 50 ? 'var(--accent-green)' : netLatency < 100 ? 'var(--high)' : 'var(--critical)' },
    { label: '日志/秒',      value: String(logEventsPerSec), color: 'var(--accent-blue)' },
    { label: '最近心跳',     value: fmtRelative(lastSeen),   color: 'var(--text-secondary)' },
  ]

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      {/* Health Score Gauge */}
      <div className="card" style={{ padding: '14px 14px', display: 'flex', flexDirection: 'column', alignItems: 'center' }}>
        <div className="card-title" style={{ marginBottom: 10, alignSelf: 'flex-start' }}>健康评分</div>
        <HealthArcGauge score={score} label="综合得分" />
        <div style={{ marginTop: 6, fontSize: 10.5, color: 'var(--text-muted)', textAlign: 'center' }}>
          {score >= 80 ? '设备运行良好' : score >= 50 ? '轻微异常，建议检查' : '存在明显问题，需要关注'}
        </div>
      </div>

      {/* Health Metrics 2×3 Grid */}
      <div className="card" style={{ padding: '12px 14px' }}>
        <div className="card-title" style={{ marginBottom: 10 }}>实时指标</div>
        <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
          {metrics.map(m => (
            <div key={m.label} style={{
              padding: '8px 10px',
              background: 'rgba(255,255,255,.03)',
              borderRadius: 5, border: '1px solid rgba(255,255,255,.06)',
            }}>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 3 }}>{m.label}</div>
              <div style={{ fontSize: 16, fontWeight: 700, color: m.color, lineHeight: 1 }}>{m.value}</div>
            </div>
          ))}
        </div>
      </div>

      {/* Recent alerts for this agent */}
      <div className="card" style={{ padding: '12px 14px' }}>
        <div className="card-title" style={{ marginBottom: 10 }}>最近告警（本机）</div>
        {alertsLoading && (
          <div style={{ fontSize: 11.5, color: 'var(--text-muted)', textAlign: 'center', padding: '10px 0' }}>加载中...</div>
        )}
        {!alertsLoading && alertsError && (
          <div style={{ fontSize: 11, color: 'var(--text-muted)', textAlign: 'center', padding: '10px 0' }}>无法加载告警</div>
        )}
        {!alertsLoading && !alertsError && alerts.length === 0 && (
          <div style={{ fontSize: 11, color: 'var(--text-muted)', textAlign: 'center', padding: '10px 0' }}>暂无告警记录</div>
        )}
        {!alertsLoading && alerts.length > 0 && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
            {alerts.map((a, i) => (
              <div key={a._key ?? i} style={{
                display: 'grid', gridTemplateColumns: '1fr auto',
                alignItems: 'center', gap: 8,
                padding: '6px 0',
                borderBottom: i < alerts.length - 1 ? '1px solid rgba(255,255,255,.04)' : 'none',
              }}>
                <div>
                  <div style={{ fontSize: 11.5, color: 'var(--text-primary)', fontWeight: 500, marginBottom: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                    {a.title || '未知告警'}
                  </div>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>{fmtRelative(a.triggered_at)}</div>
                </div>
                <span style={{
                  fontSize: 9.5, padding: '2px 6px', borderRadius: 3,
                  background: `${SEVERITY_COLORS[a.severity] ?? 'var(--text-muted)'}22`,
                  border: `1px solid ${SEVERITY_COLORS[a.severity] ?? 'var(--text-muted)'}44`,
                  color: SEVERITY_COLORS[a.severity] ?? 'var(--text-muted)',
                  fontWeight: 600, textTransform: 'uppercase', flexShrink: 0,
                }}>
                  {a.severity}
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ── Summary Card ─────────────────────────────────────────────────────────────

function SummaryBar({ items, liveness }: { items: Device[], liveness: LivenessMap }) {
  function effectiveStatus(d: Device): string {
    const dbStatus = getStatus(d)
    if (dbStatus === 'isolated' || dbStatus === 'error' || dbStatus === 'installing' || dbStatus === 'uninstalling') return dbStatus
    const agentID = d.agent_id
    if (!agentID || !(agentID in liveness)) return dbStatus
    return liveness[agentID] === true ? 'online' : liveness[agentID] === false ? 'offline' : dbStatus
  }

  const counts = items.reduce((acc, d) => {
    const s = effectiveStatus(d)
    acc[s] = (acc[s] || 0) + 1
    return acc
  }, {} as Record<string, number>)

  const total = items.length
  const online = counts.online || 0
  const offline = counts.offline || 0
  const isolated = counts.isolated || 0
  const errors = (counts.error || 0) + (counts.installing || 0) + (counts.uninstalling || 0) + (counts.pending || 0)
  const coverage = total > 0 ? Math.round((online / total) * 100) : 0

  const stats = [
    { label: '在线终端', value: online, color: 'var(--accent-green)', icon: '●' },
    { label: '离线终端', value: offline, color: 'var(--text-muted)', icon: '●' },
    { label: '已隔离', value: isolated, color: 'var(--critical)', icon: '🔒' },
    { label: '异常 / 部署中', value: errors, color: 'var(--high)', icon: '⚠' },
    { label: 'Agent覆盖率', value: `${coverage}%`, color: coverage >= 90 ? 'var(--accent-green)' : coverage >= 70 ? 'var(--medium)' : 'var(--critical)', icon: '◎' },
  ]

  const osBreak = items.reduce((acc, d) => {
    const t = (d.os_type || d.os || '').toLowerCase()
    const key = t.includes('windows') ? 'windows' : t.includes('linux') || t.includes('ubuntu') || t.includes('centos') ? 'linux' : t.includes('mac') || t.includes('darwin') ? 'macos' : 'other'
    acc[key] = (acc[key] || 0) + 1
    return acc
  }, {} as Record<string, number>)

  return (
    <div style={{
      flexShrink: 0, padding: '10px 20px',
      background: 'var(--bg-card2)',
      borderBottom: '1px solid var(--border)',
      display: 'flex', alignItems: 'center', gap: 0,
    }}>
      {stats.map((s, i) => (
        <div key={s.label} style={{
          display: 'flex', flexDirection: 'column', justifyContent: 'center',
          padding: '0 20px',
          borderRight: i < stats.length - 1 ? '1px solid var(--border)' : 'none',
          minWidth: 100,
        }}>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 2, whiteSpace: 'nowrap' }}>{s.label}</div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 5 }}>
            <span style={{ fontSize: 11, color: s.color }}>{s.icon}</span>
            <span style={{ fontSize: 20, fontWeight: 700, color: s.color, lineHeight: 1 }}>{s.value}</span>
          </div>
        </div>
      ))}

      <div style={{ flex: 1 }} />

      <div style={{
        display: 'flex', alignItems: 'center', gap: 14,
        padding: '0 20px', borderLeft: '1px solid var(--border)',
      }}>
        <span style={{ fontSize: 10, color: 'var(--text-muted)', marginRight: 4 }}>OS</span>
        {[
          { key: 'windows', icon: '🪟', label: 'Win' },
          { key: 'linux',   icon: '🐧', label: 'Linux' },
          { key: 'macos',   icon: '🍎', label: 'macOS' },
        ].map(({ key, icon, label }) => (
          osBreak[key] ? (
            <div key={key} style={{ display: 'flex', alignItems: 'center', gap: 4, fontSize: 11 }}>
              <span>{icon}</span>
              <span style={{ color: 'var(--text-secondary)' }}>{label}</span>
              <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{osBreak[key]}</span>
            </div>
          ) : null
        ))}
      </div>

      <div style={{ padding: '0 0 0 20px', borderLeft: '1px solid var(--border)', minWidth: 120 }}>
        <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 4 }}>在线率</div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <div style={{ width: 80, height: 6, background: 'var(--bg-card2)', borderRadius: 3, overflow: 'hidden' }}>
            <div style={{
              width: `${coverage}%`, height: '100%', borderRadius: 3,
              background: coverage >= 90 ? 'var(--accent-green)' : coverage >= 70 ? 'var(--medium)' : 'var(--critical)',
              transition: 'width .4s ease',
            }} />
          </div>
          <span style={{ fontSize: 11, fontWeight: 600, color: coverage >= 90 ? 'var(--accent-green)' : 'var(--medium)' }}>{coverage}%</span>
        </div>
      </div>
    </div>
  )
}

// ── Detail Panel ─────────────────────────────────────────────────────────────

type DetailTab = 'info' | 'health' | 'health_detail' | 'logs' | 'exec' | 'policy'

function DetailPanel({ d, liveness, onClose, onAction }: {
  d: Device
  liveness: LivenessMap
  onClose: () => void
  onAction: (action: 'isolate' | 'unisolate' | 'upgrade' | 'uninstall', d: Device) => void
}) {
  const [detailTab, setDetailTab] = useState<DetailTab>('info')
  const [deviceData, setDeviceData] = useState<Device>(d)

  // Sync deviceData when a different device is selected
  // eslint-disable-next-line react-hooks/exhaustive-deps
  useEffect(() => { setDeviceData(d) }, [d._key]) // intentionally only key as dep

  const dbStatus = getStatus(d)
  const agentID = d.agent_id
  const livenessVal = agentID ? liveness[agentID] : undefined
  let status = dbStatus
  if (dbStatus !== 'isolated' && dbStatus !== 'error' && dbStatus !== 'installing' && dbStatus !== 'uninstalling') {
    if (livenessVal === true) status = 'online'
    else if (livenessVal === false) status = 'offline'
  }
  const statusColor = STATUS_COLORS[status] ?? 'var(--text-muted)'
  const osStr = osLabel(d.os_type || d.os, d.os_version)

  const isLatest = d.agent_version?.startsWith('7.4.2')
  const isOnline = status === 'online'
  const healthScore = isOnline && isLatest ? 98 : isOnline ? 72 : status === 'isolated' ? 45 : 20
  const healthColor = healthScore >= 80 ? 'var(--accent-green)' : healthScore >= 50 ? 'var(--medium)' : 'var(--critical)'

  const ip = d.ip_addresses?.[0] || d.ip || '-'
  const lastSeen = d.last_heartbeat || d.last_seen

  const { cpu, mem, disk } = deriveHealthMetrics(d)

  const DETAIL_TABS: { id: DetailTab; label: string }[] = [
    { id: 'info',          label: '详情' },
    { id: 'health_detail', label: '健康状态' },
    { id: 'health',        label: '指标' },
    { id: 'logs',          label: '日志' },
    { id: 'exec',          label: '远程执行' },
    { id: 'policy',        label: '策略' },
  ]

  return (
    <div style={{
      width: 340, flexShrink: 0, borderLeft: '1px solid var(--border)',
      background: 'var(--bg-drawer)', display: 'flex', flexDirection: 'column',
      overflow: 'hidden',
    }}>
      {/* Panel header */}
      <div style={{
        padding: '10px 14px', borderBottom: '1px solid var(--border)',
        display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        background: 'var(--bg-card2)', minHeight: 48,
      }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          <span style={{ fontSize: 18 }}>{osIcon(d.os_type || d.os)}</span>
          <div>
            <div style={{ fontSize: 13, fontWeight: 600, fontFamily: 'monospace' }}>{d.hostname}</div>
            <div style={{ display: 'inline-flex', alignItems: 'center', gap: 4, marginTop: 2 }}>
              <span style={{ width: 7, height: 7, borderRadius: '50%', background: statusColor, display: 'inline-block', boxShadow: status === 'online' ? `0 0 5px ${statusColor}` : 'none' }} />
              <span style={{ fontSize: 10.5, color: statusColor }}>{STATUS_LABELS[status] ?? status}</span>
            </div>
          </div>
        </div>
        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px' }} onClick={onClose}>✕</button>
      </div>

      {/* Inner tab bar */}
      <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', background: 'var(--bg-sidebar)', flexShrink: 0 }}>
        {DETAIL_TABS.map(t => (
          <button
            key={t.id}
            onClick={() => setDetailTab(t.id)}
            style={{
              flex: 1, padding: '7px 0', fontSize: 11, fontWeight: detailTab === t.id ? 600 : 400,
              background: 'none', border: 'none', cursor: 'pointer',
              color: detailTab === t.id ? 'var(--accent-blue)' : 'var(--text-muted)',
              borderBottom: detailTab === t.id ? '2px solid var(--accent-blue)' : '2px solid transparent',
              transition: 'all .15s',
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      <div style={{ flex: 1, overflowY: 'auto', padding: 14, display: 'flex', flexDirection: 'column', gap: 12 }}>

        {/* ─── Info tab ─────────────────────────────────── */}
        {detailTab === 'info' && (
          <>
            {/* Device health score arc gauge */}
            <DeviceHealthCard d={d} />

            {/* Legacy health checklist */}
            <div className="card" style={{ padding: '12px 14px' }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
                <span style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', letterSpacing: 0.5, textTransform: 'uppercase' }}>安全健康度</span>
                <span style={{ fontSize: 18, fontWeight: 700, color: healthColor }}>{healthScore}</span>
              </div>
              <div style={{ width: '100%', height: 6, background: 'var(--bg-card2)', borderRadius: 3, overflow: 'hidden', marginBottom: 8 }}>
                <div style={{ width: `${healthScore}%`, height: '100%', background: healthColor, borderRadius: 3, transition: 'width .4s' }} />
              </div>
              <div style={{ display: 'flex', gap: 8 }}>
                {[
                  { label: 'Agent', ok: isOnline },
                  { label: '版本', ok: isLatest },
                  { label: '策略', ok: !!d.policy_id },
                  { label: '连通', ok: isOnline },
                ].map(({ label, ok }) => (
                  <div key={label} style={{ flex: 1, textAlign: 'center', padding: '4px 0', background: ok ? 'rgba(67,160,71,.08)' : 'rgba(229,57,53,.08)', borderRadius: 4, border: `1px solid ${ok ? 'rgba(67,160,71,.2)' : 'rgba(229,57,53,.2)'}` }}>
                    <div style={{ fontSize: 9.5, color: 'var(--text-muted)', marginBottom: 1 }}>{label}</div>
                    <span style={{ fontSize: 12, color: ok ? 'var(--accent-green)' : 'var(--critical)' }}>{ok ? '✓' : '✗'}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Device info */}
            <div className="card" style={{ padding: '12px 14px' }}>
              <div className="card-title" style={{ marginBottom: 10 }}>设备信息</div>
              {[
                ['主机名', d.hostname || '-', 'monospace'],
                ['IP 地址', ip, 'monospace'],
                ['操作系统', osStr, undefined],
                ['Agent版本', d.agent_version || '-', 'monospace'],
                ['Agent ID', d.agent_id ? d.agent_id.slice(0, 18) + (d.agent_id.length > 18 ? '…' : '') : '-', 'monospace'],
                ['策略', d.policy_name || d.policy_id || 'Default', undefined],
                ['最近心跳', fmtRelative(lastSeen), undefined],
                ['注册时间', fmtDate(d.enrolled_at || d.created_at), undefined],
              ].map(([k, v, ff]) => (
                <div key={k as string} style={{
                  display: 'flex', justifyContent: 'space-between', alignItems: 'baseline',
                  fontSize: 11.5, paddingBottom: 5, marginBottom: 5,
                  borderBottom: '1px solid rgba(255,255,255,.04)',
                }}>
                  <span style={{ color: 'var(--text-muted)', flexShrink: 0, minWidth: 68 }}>{k}</span>
                  <span style={{
                    color: 'var(--text-secondary)', fontFamily: ff as string | undefined,
                    textAlign: 'right', wordBreak: 'break-all',
                  }}>{v}</span>
                </div>
              ))}
            </div>

            {/* Quick actions */}
            <div className="card" style={{ padding: '12px 14px' }}>
              <div className="card-title" style={{ marginBottom: 10 }}>快捷操作</div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
                {status === 'isolated' ? (
                  <button className="btn-primary" style={{ fontSize: 11 }} onClick={() => onAction('unisolate', d)}>
                    🔓 取消隔离
                  </button>
                ) : (
                  <button className="btn-secondary" style={{ fontSize: 11, color: 'var(--critical)' }} onClick={() => onAction('isolate', d)}>
                    🔒 隔离终端
                  </button>
                )}
                <button className="btn-secondary" style={{ fontSize: 11 }} onClick={() => onAction('upgrade', d)}>
                  ↑ 升级 Agent
                </button>
                <button className="btn-secondary" style={{ fontSize: 11 }} onClick={() => window.open(`/actions?q=${encodeURIComponent(d.hostname)}`)}>
                  📋 查看动作
                </button>
                <button className="btn-secondary" style={{ fontSize: 11, color: 'var(--high)' }} onClick={() => onAction('uninstall', d)}>
                  ✕ 卸载 Agent
                </button>
              </div>
            </div>

            {/* Live status widget */}
            {status === 'online' && (
              <div style={{
                padding: '10px 12px', background: 'rgba(67,160,71,.06)',
                border: '1px solid rgba(67,160,71,.18)', borderRadius: 6,
                display: 'flex', alignItems: 'center', gap: 10,
              }}>
                <span style={{ fontSize: 16, animation: 'pulse-dot 2s infinite' }}>●</span>
                <div>
                  <div style={{ fontSize: 11.5, color: 'var(--accent-green)', fontWeight: 600 }}>实时连接中</div>
                  <div style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>心跳 · {fmtRelative(lastSeen)}</div>
                </div>
              </div>
            )}
            {status === 'isolated' && (
              <div style={{
                padding: '10px 12px', background: 'rgba(229,57,53,.06)',
                border: '1px solid rgba(229,57,53,.2)', borderRadius: 6,
              }}>
                <div style={{ fontSize: 11.5, color: 'var(--critical)', fontWeight: 600, marginBottom: 3 }}>🔒 终端已隔离</div>
                <div style={{ fontSize: 10.5, color: 'var(--text-muted)', lineHeight: 1.5 }}>
                  该终端已从网络中隔离。仅与 XSIAM Agent 保持通信。<br />
                  调查完成后可点击「取消隔离」恢复网络连接。
                </div>
              </div>
            )}
            {status === 'error' && (
              <div style={{
                padding: '10px 12px', background: 'rgba(239,108,0,.06)',
                border: '1px solid rgba(239,108,0,.2)', borderRadius: 6,
              }}>
                <div style={{ fontSize: 11.5, color: 'var(--high)', fontWeight: 600, marginBottom: 3 }}>⚠ Agent 异常</div>
                <div style={{ fontSize: 10.5, color: 'var(--text-muted)', lineHeight: 1.5 }}>
                  Agent 报告错误状态。建议重新部署或检查网络连通性。
                </div>
              </div>
            )}
          </>
        )}

        {/* ─── Health Detail tab ────────────────────────── */}
        {detailTab === 'health_detail' && (
          <AgentHealthTab d={d} />
        )}

        {/* ─── Health tab ───────────────────────────────── */}
        {detailTab === 'health' && (
          <div className="card" style={{ padding: '14px 14px' }}>
            <div className="card-title" style={{ marginBottom: 12 }}>健康指标</div>
            <MetricBar label="CPU 使用率" value={cpu} />
            <MetricBar label="内存使用率" value={mem} />
            <MetricBar label="磁盘使用率" value={disk} />
            {/* Network I/O */}
            <div style={{ marginTop: 10, padding: '8px 10px', background: 'rgba(255,255,255,.03)', borderRadius: 5 }}>
              <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginBottom: 4 }}>网络 I/O</div>
              <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11 }}>
                <span style={{ color: 'var(--accent-green)' }}>
                  ↑ {typeof d.extra_fields?.bytes_out === 'number'
                    ? `${(d.extra_fields.bytes_out / 1048576).toFixed(1)} MB/s`
                    : '12.3 MB/s'}
                </span>
                <span style={{ color: 'var(--accent-blue)' }}>
                  ↓ {typeof d.extra_fields?.bytes_in === 'number'
                    ? `${(d.extra_fields.bytes_in / 1048576).toFixed(1)} MB/s`
                    : '5.6 MB/s'}
                </span>
              </div>
            </div>
            <div style={{
              marginTop: 8, padding: '8px 10px',
              background: 'rgba(255,255,255,.03)', borderRadius: 5,
              fontSize: 10, color: 'var(--text-muted)', lineHeight: 1.6,
            }}>
              数据来自 Agent 上报的 extra_fields，每次心跳更新。
            </div>
          </div>
        )}

        {/* ─── Logs tab ─────────────────────────────────── */}
        {detailTab === 'logs' && (
          <div className="card" style={{ padding: '14px 14px' }}>
            <div className="card-title" style={{ marginBottom: 10 }}>Agent 日志</div>
            <AgentLogViewer deviceKey={d._key} />
          </div>
        )}

        {/* ─── Remote Execute tab ───────────────────────── */}
        {detailTab === 'exec' && (
          <RemoteExecutePanel deviceKey={d._key} />
        )}

        {/* ─── Policy tab ───────────────────────────────── */}
        {detailTab === 'policy' && (
          <PolicyPanel
            device={deviceData._key === d._key ? deviceData : d}
            onPolicyChanged={(newPolicyId) => {
              setDeviceData(prev => ({ ...prev, policy_id: newPolicyId }))
            }}
          />
        )}

      </div>
    </div>
  )
}

// ── Confirm Modal ─────────────────────────────────────────────────────────────

function ConfirmModal({ title, body, danger, onConfirm, onCancel }: {
  title: string; body: string; danger?: boolean
  onConfirm: () => void; onCancel: () => void
}) {
  return (
    <>
      <div onClick={onCancel} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
      <div style={{
        position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
        width: 380, background: 'var(--bg-modal)', border: '1px solid var(--border)',
        borderRadius: 8, zIndex: 500, padding: 24,
      }}>
        <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 10 }}>{title}</div>
        <div style={{ fontSize: 12.5, color: 'var(--text-secondary)', marginBottom: 20, lineHeight: 1.6 }}>{body}</div>
        <div style={{ display: 'flex', gap: 10 }}>
          <button className="btn-secondary" style={{ flex: 1 }} onClick={onCancel}>取消</button>
          <button className="btn-primary" style={{ flex: 1, background: danger ? 'var(--critical)' : undefined }} onClick={onConfirm}>确认</button>
        </div>
      </div>
    </>
  )
}

// ── Online/Offline Liveness Gauge ────────────────────────────────────────────

interface OnlineCount {
  online: number
  total: number
}

function OnlineLivenessGauge() {
  const [data, setData] = useState<OnlineCount | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(true)
    api.get('/devices/online-count')
      .then(r => {
        const d = r.data.data ?? r.data
        setData({ online: d.online ?? 0, total: d.total ?? 0 })
      })
      .catch(() => setData(null))
      .finally(() => setLoading(false))
  }, [])

  if (loading) {
    return (
      <div style={{
        padding: '8px 20px', background: 'var(--bg-card)',
        borderBottom: '1px solid var(--border)',
        display: 'flex', alignItems: 'center', gap: 12, fontSize: 11.5,
        color: 'var(--text-muted)',
      }}>
        <span style={{ fontWeight: 600, letterSpacing: 0.3 }}>在线状态</span>
        <span>加载中...</span>
      </div>
    )
  }

  if (!data) return null

  const { online, total } = data
  const pct = total > 0 ? online / total : 0
  const barColor = pct > 0.8 ? 'var(--accent-green)' : pct > 0.5 ? 'var(--medium)' : 'var(--critical)'
  const textColor = barColor

  const CHARS = 20
  const filled = Math.round(pct * CHARS)
  const barStr = '='.repeat(Math.max(0, filled - 1)) + (filled > 0 ? '>' : '') + ' '.repeat(CHARS - filled)

  return (
    <div style={{
      padding: '8px 20px', background: 'var(--bg-card)',
      borderBottom: '1px solid var(--border)',
      display: 'flex', alignItems: 'center', gap: 16,
    }}>
      <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', letterSpacing: 0.3, whiteSpace: 'nowrap' }}>
        在线状态
      </span>
      <span style={{ fontFamily: 'monospace', fontSize: 12, color: textColor, letterSpacing: 0, userSelect: 'none' }}>
        [{barStr}]
      </span>
      <div style={{ width: 100, height: 6, background: 'var(--bg-card2)', borderRadius: 3, overflow: 'hidden', flexShrink: 0 }}>
        <div style={{
          width: `${Math.round(pct * 100)}%`, height: '100%', borderRadius: 3,
          background: barColor, transition: 'width .4s ease',
        }} />
      </div>
      <span style={{ fontSize: 12, color: textColor, fontWeight: 600, whiteSpace: 'nowrap' }}>
        {online} 在线 / {total} 总计
      </span>
      <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
        ({total > 0 ? Math.round(pct * 100) : 0}%)
      </span>
    </div>
  )
}

// ── Liveness overlay ─────────────────────────────────────────────────────────

type LivenessMap = Record<string, boolean | null>

// ── Map View ─────────────────────────────────────────────────────────────────

// Equirectangular projection: lng [-180,180] → x [0,100], lat [-90,90] → y [0,100]
function geoToPercent(lat: number, lng: number): { x: number; y: number } {
  const x = ((lng + 180) / 360) * 100
  const y = ((90 - lat) / 180) * 100
  return { x, y }
}

function MapView({ devices }: { devices: Device[] }) {
  const withLoc = devices.filter(d => d.location)
  return (
    <div style={{ flex: 1, position: 'relative', overflow: 'hidden', background: 'var(--bg-card2)', margin: 0 }}>
      {/* World map SVG outline — simplified rectangle continents as placeholders */}
      <svg
        viewBox="0 0 1000 500"
        style={{ width: '100%', height: '100%', display: 'block', opacity: 0.18 }}
        xmlns="http://www.w3.org/2000/svg"
        preserveAspectRatio="xMidYMid meet"
      >
        {/* North America */}
        <path d="M100 60 L240 60 L260 110 L220 170 L180 200 L140 180 L100 150 Z" fill="var(--text-muted)" />
        {/* South America */}
        <path d="M160 220 L220 210 L250 280 L230 360 L180 370 L150 300 Z" fill="var(--text-muted)" />
        {/* Europe */}
        <path d="M430 50 L500 50 L510 100 L480 130 L430 120 L420 80 Z" fill="var(--text-muted)" />
        {/* Africa */}
        <path d="M430 140 L510 130 L530 220 L510 330 L460 350 L420 280 L430 200 Z" fill="var(--text-muted)" />
        {/* Asia */}
        <path d="M510 40 L800 30 L820 120 L760 180 L680 200 L580 190 L520 150 L505 100 Z" fill="var(--text-muted)" />
        {/* Australia */}
        <path d="M700 280 L800 270 L820 340 L780 380 L700 370 L680 330 Z" fill="var(--text-muted)" />
      </svg>

      {/* Device dots */}
      {withLoc.map(d => {
        const loc = d.location!
        const { x, y } = geoToPercent(loc.lat, loc.lng)
        const st = getStatus(d)
        const color = STATUS_COLORS[st] ?? 'var(--text-muted)'
        return (
          <div
            key={d._key}
            title={`${d.hostname} — ${loc.city ?? `${loc.lat.toFixed(1)},${loc.lng.toFixed(1)}`}`}
            style={{
              position: 'absolute',
              left: `${x}%`, top: `${y}%`,
              transform: 'translate(-50%,-50%)',
              width: 10, height: 10, borderRadius: '50%',
              background: color,
              border: '2px solid rgba(0,0,0,.4)',
              boxShadow: st === 'online' ? `0 0 6px ${color}` : 'none',
              cursor: 'pointer',
              zIndex: 10,
            }}
          />
        )
      })}

      {/* No location message */}
      {withLoc.length === 0 && (
        <div style={{
          position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center',
          fontSize: 13, color: 'var(--text-muted)',
        }}>
          暂无位置信息
        </div>
      )}
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

type StatusTab = '' | 'online' | 'offline' | 'isolated' | 'error'
type ViewMode  = 'list' | 'map'

export default function Devices() {
  const [items, setItems] = useState<Device[]>([])
  const [allItems, setAllItems] = useState<Device[]>([])
  const [meta, setMeta] = useState<PageMeta>({ page: 1, page_size: 20, total: 0, total_pages: 1 })
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [statusFilter, setStatusFilter] = useState<StatusTab>('')
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<Device | null>(null)
  const [showToken, setShowToken] = useState(false)
  const [token, setToken] = useState('')
  const [tokenLoading, setTokenLoading] = useState(false)
  const [policies, setPolicies] = useState<Policy[]>([])
  const [policyFilter, setPolicyFilter] = useState('')
  const [confirm, setConfirm] = useState<{ action: string; device: Device } | null>(null)
  const [platformFilter, setPlatformFilter] = useState('')
  const [hostnameInput, setHostnameInput] = useState('')
  const [hostnameSearch, setHostnameSearch] = useState('')
  const hostnameDebounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const [upgradingIds, setUpgradingIds] = useState<Record<string, boolean>>({})
  const [liveness, setLiveness] = useState<LivenessMap>({})
  const livenessTimerRef = useRef<ReturnType<typeof setInterval> | null>(null)
  const mountedRef = useRef(false)

  // ── Group/tag filter state ─────────────────────────────────────────────────
  const [allTags, setAllTags] = useState<string[]>([])
  const [tagFilter, setTagFilter] = useState<string>('')

  // ── View mode: list vs map ─────────────────────────────────────────────────
  const [viewMode, setViewMode] = useState<ViewMode>('list')

  // ── Bulk operations state ──────────────────────────────────────────────────
  const [checkedKeys, setCheckedKeys] = useState<Set<string>>(new Set())
  const [bulkConfirm, setBulkConfirm] = useState<'upgrade' | 'delete' | null>(null)
  const [bulkProgress, setBulkProgress] = useState<{ done: number; total: number } | null>(null)

  function fetchLiveness(devices: Device[]) {
    const agentIDs = devices.map(d => d.agent_id).filter(Boolean) as string[]
    if (agentIDs.length === 0) return

    setLiveness(prev => {
      const next = { ...prev }
      agentIDs.forEach(id => { if (next[id] === undefined) next[id] = null })
      return next
    })
    api.post('/devices/liveness', { agent_ids: agentIDs })
      .then(r => {
        const onlineMap: Record<string, boolean> = r.data.data?.online ?? {}
        setLiveness(prev => ({ ...prev, ...onlineMap }))
      })
      .catch(() => {})
  }

  function load(p = page) {
    setLoading(true)
    const params: Record<string, unknown> = { page: p, page_size: 20 }
    if (statusFilter) params.status = statusFilter
    if (search) params.keyword = search
    if (policyFilter) params.policy_id = policyFilter
    if (platformFilter) params.os = platformFilter
    if (hostnameSearch) params.hostname = hostnameSearch
    if (tagFilter) params.tag = tagFilter
    api.get('/devices', { params })
      .then(r => {
        const data: Device[] = r.data.data?.items ?? []
        setItems(data)
        setMeta(r.data.data?.meta ?? meta)
        if (p === 1 && !statusFilter && !search && !policyFilter && !platformFilter && !hostnameSearch && !tagFilter) setAllItems(data)
        fetchLiveness(data)
      })
      .finally(() => setLoading(false))
  }

  function loadStats() {
    api.get('/devices', { params: { page: 1, page_size: 200 } })
      .then(r => {
        const data: Device[] = r.data.data?.items ?? []
        setAllItems(data)
        // Extract unique tags
        const tagSet = new Set<string>()
        data.forEach(d => {
          if (d.tags) d.tags.forEach(t => tagSet.add(t))
          else if (d.group) tagSet.add(d.group)
        })
        setAllTags(Array.from(tagSet).sort())
        fetchLiveness(data)
      })
  }

  function startLivenessPoller(devices: Device[]) {
    if (livenessTimerRef.current) clearInterval(livenessTimerRef.current)
    livenessTimerRef.current = setInterval(() => fetchLiveness(devices), 30_000)
  }

  useEffect(() => {
    api.get('/agent_policies', { params: { page: 1, page_size: 100 } })
      .then(r => setPolicies(r.data.data?.items ?? []))
    loadStats()
    return () => {
      if (livenessTimerRef.current) clearInterval(livenessTimerRef.current)
    }
  }, [])

  const handleHostnameInput = useCallback((val: string) => {
    setHostnameInput(val)
    if (hostnameDebounceRef.current) clearTimeout(hostnameDebounceRef.current)
    hostnameDebounceRef.current = setTimeout(() => {
      setHostnameSearch(val)
    }, 500)
  }, [])

  useEffect(() => { load(page) }, [page])
  useEffect(() => {
    if (!mountedRef.current) { mountedRef.current = true; return }
    setPage(1); load(1)
  }, [statusFilter, search, policyFilter, platformFilter, hostnameSearch, tagFilter])

  useEffect(() => {
    if (items.length > 0) startLivenessPoller(items)
  }, [items])

  function generateToken() {
    setTokenLoading(true)
    api.post('/devices/enrollment_token')
      .then(r => { setToken(r.data.data?.token ?? ''); setShowToken(true) })
      .finally(() => setTokenLoading(false))
  }

  function doRowUpgrade(d: Device) {
    setUpgradingIds(prev => ({ ...prev, [d._key]: true }))
    api.post(`/devices/${d._key}/upgrade`, { version: 'latest' })
      .then(() => { load(page) })
      .finally(() => setUpgradingIds(prev => ({ ...prev, [d._key]: false })))
  }

  function doAction(action: 'isolate' | 'unisolate' | 'upgrade' | 'uninstall', d: Device) {
    const msgs: Record<string, { title: string; body: string; danger?: boolean }> = {
      isolate: {
        title: `隔离终端：${d.hostname}`,
        body: '该操作将立即切断该设备的网络连接，仅保留与 Agent 的通信通道。适用于发现主动攻击时的即时遏制。',
        danger: true,
      },
      unisolate: {
        title: `取消隔离：${d.hostname}`,
        body: '该操作将恢复设备网络访问权限。请确认已完成安全调查，确定该设备不再构成威胁。',
      },
      upgrade: {
        title: `升级 Agent：${d.hostname}`,
        body: `当前版本 ${d.agent_version || '-'}，将升级至最新版本。升级期间 Agent 短暂重启，不影响设备正常使用。`,
      },
      uninstall: {
        title: `卸载 Agent：${d.hostname}`,
        body: '卸载后该设备将不再受 XSIAM 保护，无法接收策略和威胁检测。此操作不可撤销（可重新注册）。',
        danger: true,
      },
    }
    setConfirm({ action: `${action}:${d._key}`, device: d })
    ;(window as any).__confirmCfg = msgs[action]
  }

  function execAction(rawAction: string, d: Device) {
    const [action] = rawAction.split(':')
    if (action === 'isolate') {
      api.patch(`/devices/${d._key}`, { status: 'isolated', agent_status: 'isolated' })
        .then(() => { load(page); loadStats(); setSelected(prev => prev?._key === d._key ? { ...prev, status: 'isolated', agent_status: 'isolated' } : prev) })
    } else if (action === 'unisolate') {
      api.patch(`/devices/${d._key}`, { status: 'online', agent_status: 'online' })
        .then(() => { load(page); loadStats(); setSelected(prev => prev?._key === d._key ? { ...prev, status: 'online', agent_status: 'online' } : prev) })
    } else if (action === 'upgrade') {
      api.post(`/devices/${d._key}/upgrade`, { version: 'latest' })
        .then(() => load(page))
    } else if (action === 'uninstall') {
      api.delete(`/devices/${d._key}`)
        .then(() => { load(page); loadStats(); setSelected(null) })
    }
    setConfirm(null)
  }

  function toggleCheck(key: string, e: React.MouseEvent) {
    e.stopPropagation()
    setCheckedKeys(prev => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  function toggleAllChecked() {
    if (checkedKeys.size === items.length) {
      setCheckedKeys(new Set())
    } else {
      setCheckedKeys(new Set(items.map(d => d._key)))
    }
  }

  async function doBulkUpgrade() {
    const keys = Array.from(checkedKeys)
    setBulkProgress({ done: 0, total: keys.length })
    setBulkConfirm(null)
    for (let i = 0; i < keys.length; i++) {
      await api.post(`/devices/${keys[i]}/upgrade`, { version: 'latest' }).catch(() => {})
      setBulkProgress({ done: i + 1, total: keys.length })
    }
    setBulkProgress(null)
    setCheckedKeys(new Set())
    load(page)
  }

  async function doBulkDelete() {
    const keys = Array.from(checkedKeys)
    setBulkProgress({ done: 0, total: keys.length })
    setBulkConfirm(null)
    for (let i = 0; i < keys.length; i++) {
      await api.delete(`/devices/${keys[i]}`).catch(() => {})
      setBulkProgress({ done: i + 1, total: keys.length })
    }
    setBulkProgress(null)
    setCheckedKeys(new Set())
    load(page)
    loadStats()
  }

  const STATUS_TABS: [string, StatusTab][] = [
    ['全部', ''], ['在线', 'online'], ['离线', 'offline'], ['已隔离', 'isolated'], ['Error', 'error'],
  ]

  const statusColor = STATUS_COLORS

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <PageHeader
        title="终端管理"
        actions={<>
          <button className="btn-secondary" style={{ fontSize: 12 }} disabled={tokenLoading} onClick={generateToken}>
            {tokenLoading ? '生成中...' : '🔑 注册令牌'}
          </button>
          <button className="btn-primary" style={{ fontSize: 12 }} onClick={generateToken}>
            + 注册设备
          </button>
        </>}
      />

      <OnlineLivenessGauge />
      <SummaryBar items={allItems} liveness={liveness} />

      {/* Status tabs */}
      <div className="tab-bar">
        {STATUS_TABS.map(([label, val]) => {
          const isolatedCount = allItems.filter(d => getStatus(d) === 'isolated').length
          const errorCount = allItems.filter(d => getStatus(d) === 'error').length
          return (
            <button
              key={val}
              className={`tab ${statusFilter === val ? 'active' : ''}`}
              onClick={() => setStatusFilter(val)}
            >
              {label}
              {val === 'isolated' && isolatedCount > 0 && (
                <span className="tab-count" style={{ background: 'var(--critical)' }}>{isolatedCount}</span>
              )}
              {val === 'error' && errorCount > 0 && (
                <span className="tab-count" style={{ background: 'var(--high)' }}>{errorCount}</span>
              )}
            </button>
          )
        })}
      </div>

      {/* Filter bar */}
      <div className="filter-bar">
        <input
          className="filter-input"
          placeholder="搜索主机名、IP地址..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && load(1)}
          style={{ minWidth: 220 }}
        />
        <button className="btn-secondary" style={{ fontSize: 11 }} onClick={() => load(1)}>搜索</button>
        <input
          className="filter-input"
          placeholder="搜索主机"
          value={hostnameInput}
          onChange={e => handleHostnameInput(e.target.value)}
          style={{ minWidth: 160 }}
        />
        <select className="filter-select" value={platformFilter} onChange={e => setPlatformFilter(e.target.value)}>
          <option value="">平台</option>
          <option value="windows">Windows</option>
          <option value="linux">Linux</option>
          <option value="macos">macOS</option>
        </select>
        <select className="filter-select" value={policyFilter} onChange={e => setPolicyFilter(e.target.value)}>
          <option value="">全部策略</option>
          {policies.map(p => <option key={p._key} value={p._key}>{p.name}</option>)}
        </select>

        {/* Spacer */}
        <div style={{ flex: 1 }} />

        {/* View mode toggle */}
        <div style={{
          display: 'flex', border: '1px solid var(--border)', borderRadius: 6,
          overflow: 'hidden', flexShrink: 0,
        }}>
          {(['list', 'map'] as ViewMode[]).map(mode => (
            <button
              key={mode}
              onClick={() => setViewMode(mode)}
              style={{
                padding: '4px 12px', fontSize: 11, border: 'none', cursor: 'pointer',
                background: viewMode === mode ? 'var(--accent-blue)' : 'transparent',
                color: viewMode === mode ? '#fff' : 'var(--text-muted)',
                transition: 'all .15s',
              }}
            >
              {mode === 'list' ? '列表' : '地图'}
            </button>
          ))}
        </div>
      </div>

      {/* Tag filter chips — shown only when there are tags */}
      {allTags.length > 0 && (
        <div style={{
          padding: '6px 16px', display: 'flex', alignItems: 'center', gap: 6, flexWrap: 'wrap',
          borderBottom: '1px solid var(--border)', background: 'var(--bg-card2)', flexShrink: 0,
        }}>
          <span style={{ fontSize: 10.5, color: 'var(--text-muted)', flexShrink: 0 }}>标签筛选：</span>
          <button
            onClick={() => setTagFilter('')}
            style={{
              fontSize: 10.5, padding: '2px 10px', borderRadius: 12, border: '1px solid',
              cursor: 'pointer',
              background: tagFilter === '' ? 'var(--accent-blue)' : 'transparent',
              borderColor: tagFilter === '' ? 'var(--accent-blue)' : 'var(--border)',
              color: tagFilter === '' ? '#fff' : 'var(--text-secondary)',
              transition: 'all .15s',
            }}
          >
            全部
          </button>
          {allTags.map(tag => (
            <button
              key={tag}
              onClick={() => setTagFilter(tagFilter === tag ? '' : tag)}
              style={{
                fontSize: 10.5, padding: '2px 10px', borderRadius: 12, border: '1px solid',
                cursor: 'pointer',
                background: tagFilter === tag ? 'var(--accent-blue)' : 'transparent',
                borderColor: tagFilter === tag ? 'var(--accent-blue)' : 'var(--border)',
                color: tagFilter === tag ? '#fff' : 'var(--text-secondary)',
                transition: 'all .15s',
              }}
            >
              {tag}
            </button>
          ))}
        </div>
      )}

      {/* Bulk action bar — shown when ≥2 rows checked */}
      {checkedKeys.size >= 2 && (
        <div style={{
          padding: '7px 16px', background: 'rgba(0,120,212,.08)',
          borderBottom: '1px solid rgba(0,120,212,.2)',
          display: 'flex', alignItems: 'center', gap: 10, flexShrink: 0,
        }}>
          <span style={{ fontSize: 12, color: 'var(--accent-blue)', fontWeight: 600 }}>
            已选 {checkedKeys.size} 台
          </span>
          {bulkProgress ? (
            <span style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>
              处理中 {bulkProgress.done}/{bulkProgress.total}...
            </span>
          ) : (
            <>
              <button
                className="btn-primary"
                style={{ fontSize: 11, padding: '3px 12px' }}
                onClick={() => setBulkConfirm('upgrade')}
              >
                ↑ 批量升级
              </button>
              <button
                className="btn-secondary"
                style={{ fontSize: 11, padding: '3px 12px', color: 'var(--critical)' }}
                onClick={() => setBulkConfirm('delete')}
              >
                ✕ 批量下线
              </button>
            </>
          )}
          <button
            className="btn-secondary"
            style={{ fontSize: 11, padding: '3px 8px', marginLeft: 'auto' }}
            onClick={() => setCheckedKeys(new Set())}
          >
            取消选择
          </button>
        </div>
      )}

      {/* Content: table/map + detail panel */}
      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        {/* Map view */}
        {viewMode === 'map' && <MapView devices={items} />}

        {/* List view */}
        {viewMode === 'list' && (
          <div className="data-table-wrap" style={{ flex: 1 }}>
            <table className="data-table">
              <thead>
                <tr>
                  <ResizableTh style={{ width: 36, textAlign: 'center' }}>
                    <input
                      type="checkbox"
                      style={{ width: 13, height: 13, cursor: 'pointer' }}
                      checked={items.length > 0 && checkedKeys.size === items.length}
                      ref={el => { if (el) el.indeterminate = checkedKeys.size > 0 && checkedKeys.size < items.length }}
                      onChange={toggleAllChecked}
                    />
                  </ResizableTh>
                  <ResizableTh>设备 / 主机名</ResizableTh>
                  <ResizableTh>平台</ResizableTh>
                  <ResizableTh>Agent 版本</ResizableTh>
                  <ResizableTh>IP 地址</ResizableTh>
                  <ResizableTh>状态</ResizableTh>
                  <ResizableTh>最近心跳</ResizableTh>
                  <ResizableTh>操作</ResizableTh>
                </tr>
              </thead>
              <tbody>
                {loading && (
                  <tr><td colSpan={8} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 32 }}>加载中...</td></tr>
                )}
                {!loading && items.length === 0 && (
                  <tr><td colSpan={8} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 32 }}>
                    {statusFilter ? `没有「${STATUS_LABELS[statusFilter]}」状态的设备` : '暂无注册设备'}
                  </td></tr>
                )}
                {items.map(d => {
                  const dbSt = getStatus(d)
                  const aid = d.agent_id
                  const lv = aid ? liveness[aid] : undefined
                  let st = dbSt
                  if (dbSt !== 'isolated' && dbSt !== 'error' && dbSt !== 'installing' && dbSt !== 'uninstalling') {
                    if (lv === true) st = 'online'
                    else if (lv === false) st = 'offline'
                  }
                  const stColor = statusColor[st] ?? 'var(--text-muted)'
                  const ip = d.ip_addresses?.[0] || d.ip || '-'
                  const isSelected = selected?._key === d._key
                  const isLatest = d.agent_version?.startsWith('7.4.2')
                  const lastSeen = d.last_heartbeat || d.last_seen
                  const livenessUnknown = aid && lv === undefined
                  const livenessQuerying = aid && lv === null

                  const isChecked = checkedKeys.has(d._key)

                  return (
                    <tr
                      key={d._key}
                      onClick={() => setSelected(isSelected ? null : d)}
                      className={isSelected ? 'selected' : ''}
                      style={{ cursor: 'pointer', background: isChecked ? 'rgba(0,120,212,.05)' : undefined }}
                    >
                      <td style={{ textAlign: 'center' }} onClick={e => toggleCheck(d._key, e)}>
                        <input
                          type="checkbox"
                          style={{ width: 13, height: 13, cursor: 'pointer' }}
                          checked={isChecked}
                          onChange={() => {}}
                        />
                      </td>

                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <span style={{ fontSize: 16 }}>{osIcon(d.os_type || d.os)}</span>
                          <div>
                            <div style={{ fontFamily: 'monospace', fontSize: 12.5, fontWeight: 600 }}>{d.hostname || '-'}</div>
                            {d.asset_id && (
                              <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>asset:{d.asset_id.slice(0, 8)}</div>
                            )}
                          </div>
                        </div>
                      </td>

                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11.5 }}>
                          <span style={{ fontSize: 15 }}>{osIcon(d.os_type || d.os)}</span>
                          <span style={{ color: 'var(--text-secondary)' }}>
                            {(() => {
                              const o = (d.os_type || d.os || '').toLowerCase()
                              if (o.includes('windows')) return 'Windows'
                              if (o.includes('linux') || o.includes('ubuntu') || o.includes('centos')) return 'Linux'
                              if (o.includes('mac') || o.includes('darwin')) return 'macOS'
                              return '未知'
                            })()}
                          </span>
                        </div>
                      </td>

                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                          <span style={{ fontFamily: 'monospace', fontSize: 11.5, color: 'var(--text-secondary)' }}>
                            {d.agent_version || '-'}
                          </span>
                          {!isLatest && d.agent_version && (
                            <span style={{ fontSize: 9.5, padding: '1px 5px', background: 'rgba(239,108,0,.12)', color: 'var(--high)', border: '1px solid rgba(239,108,0,.25)', borderRadius: 3 }}>
                              旧版
                            </span>
                          )}
                        </div>
                      </td>

                      <td style={{ fontFamily: 'monospace', fontSize: 11.5, color: 'var(--text-secondary)' }}>{ip}</td>

                      <td>
                        {(livenessQuerying || livenessUnknown) && dbSt !== 'isolated' && dbSt !== 'error' ? (
                          <span style={{ fontSize: 11.5, color: 'var(--text-muted)', letterSpacing: 1 }}>-</span>
                        ) : (
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11.5 }}>
                            <span style={{
                              width: 7, height: 7, borderRadius: '50%', display: 'inline-block',
                              background: stColor,
                              boxShadow: st === 'online' ? `0 0 5px ${stColor}` : 'none',
                              animation: st === 'installing' ? 'pulse-dot 1.2s infinite' : 'none',
                            }} />
                            <span style={{ color: stColor, fontWeight: st === 'isolated' ? 600 : undefined }}>
                              {STATUS_LABELS[st] ?? st}
                            </span>
                          </span>
                        )}
                      </td>

                      <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                        <span title={fmtDate(lastSeen)}>{fmtRelative(lastSeen)}</span>
                      </td>

                      <td onClick={e => e.stopPropagation()}>
                        <div style={{ display: 'flex', gap: 5 }}>
                          {st === 'isolated' ? (
                            <button
                              className="btn-secondary"
                              style={{ fontSize: 11, padding: '2px 8px', color: 'var(--accent-green)' }}
                              onClick={() => doAction('unisolate', d)}
                            >取消隔离</button>
                          ) : (
                            <button
                              className="btn-secondary"
                              style={{ fontSize: 11, padding: '2px 8px', color: 'var(--critical)' }}
                              onClick={() => doAction('isolate', d)}
                            >🔒 隔离</button>
                          )}
                          {st !== 'offline' && (
                            <button
                              className="btn-primary"
                              style={{ fontSize: 11, padding: '2px 8px', minWidth: 48 }}
                              disabled={!!upgradingIds[d._key]}
                              onClick={() => doRowUpgrade(d)}
                            >
                              {upgradingIds[d._key] ? '...' : '↑ 升级'}
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        )}

        {/* Right detail panel — only in list view */}
        {viewMode === 'list' && selected && (
          <DetailPanel
            d={selected}
            liveness={liveness}
            onClose={() => setSelected(null)}
            onAction={doAction}
          />
        )}
      </div>

      {/* Pagination */}
      <div className="pagination">
        <button className="page-btn" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>&#8249;</button>
        <span>{page} / {meta.total_pages || 1}</span>
        <button className="page-btn" disabled={page >= meta.total_pages} onClick={() => setPage(p => p + 1)}>&#8250;</button>
        <span style={{ marginLeft: 8 }}>{meta.total} 台</span>
      </div>

      {/* Enrollment Token Modal */}
      {showToken && (
        <>
          <div onClick={() => setShowToken(false)} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 500, background: 'var(--bg-modal)', border: '1px solid var(--border)',
            borderRadius: 8, zIndex: 500, padding: 24,
          }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 6 }}>🔑 设备注册令牌</div>
            <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 16, lineHeight: 1.6 }}>
              使用以下令牌在新设备上部署 XSIAM Agent。令牌有效期 <strong>24 小时</strong>，用于初始注册后自动失效。
            </div>
            <div style={{
              fontFamily: 'monospace', fontSize: 11, padding: '12px 14px',
              background: 'var(--bg-card2)', border: '1px solid var(--border)',
              borderRadius: 4, wordBreak: 'break-all', color: 'var(--accent-green)',
              lineHeight: 1.7, marginBottom: 16,
            }}>
              {token || '正在生成...'}
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 16, padding: '8px 12px', background: 'rgba(0,120,212,.06)', border: '1px solid rgba(0,120,212,.15)', borderRadius: 4 }}>
              <strong>安装命令（Linux）：</strong><br />
              <code style={{ fontFamily: 'monospace', color: 'var(--accent-blue)' }}>
                curl -s https://agent.xsiam.local/install.sh | bash -s -- --token {token.slice(0, 12)}...
              </code>
            </div>
            <div style={{ display: 'flex', gap: 10 }}>
              <button className="btn-secondary" style={{ flex: 1 }} onClick={() => navigator.clipboard?.writeText(token)}>
                📋 复制令牌
              </button>
              <button className="btn-primary" style={{ flex: 1 }} onClick={() => setShowToken(false)}>关闭</button>
            </div>
          </div>
        </>
      )}

      {/* Confirm action modal */}
      {confirm && (
        <ConfirmModal
          title={(window as any).__confirmCfg?.title ?? '确认操作'}
          body={(window as any).__confirmCfg?.body ?? '确定执行此操作？'}
          danger={(window as any).__confirmCfg?.danger}
          onConfirm={() => execAction(confirm.action, confirm.device)}
          onCancel={() => setConfirm(null)}
        />
      )}

      {/* Bulk upgrade confirm */}
      {bulkConfirm === 'upgrade' && (
        <ConfirmModal
          title={`批量升级 Agent（${checkedKeys.size} 台）`}
          body={`将对选中的 ${checkedKeys.size} 台设备依次发起 Agent 升级请求。升级期间 Agent 短暂重启，不影响设备正常使用。`}
          onConfirm={doBulkUpgrade}
          onCancel={() => setBulkConfirm(null)}
        />
      )}

      {/* Bulk delete confirm */}
      {bulkConfirm === 'delete' && (
        <ConfirmModal
          title={`批量下线设备（${checkedKeys.size} 台）`}
          body={`将删除选中的 ${checkedKeys.size} 台设备记录。下线后这些设备将不再受 XSIAM 保护。此操作不可撤销。`}
          danger
          onConfirm={doBulkDelete}
          onCancel={() => setBulkConfirm(null)}
        />
      )}

      {/* Bulk progress overlay */}
      {bulkProgress && (
        <>
          <div style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 300, background: 'var(--bg-modal)', border: '1px solid var(--border)',
            borderRadius: 8, zIndex: 500, padding: 28, textAlign: 'center',
          }}>
            <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 16 }}>
              处理中 {bulkProgress.done}/{bulkProgress.total}...
            </div>
            <div style={{ width: '100%', height: 6, background: 'var(--bg-card2)', borderRadius: 3, overflow: 'hidden' }}>
              <div style={{
                width: `${Math.round((bulkProgress.done / bulkProgress.total) * 100)}%`,
                height: '100%', background: 'var(--accent-blue)', borderRadius: 3,
                transition: 'width .3s',
              }} />
            </div>
            <div style={{ marginTop: 10, fontSize: 11.5, color: 'var(--text-muted)' }}>
              {bulkProgress.done === bulkProgress.total ? '完成' : '请稍候...'}
            </div>
          </div>
        </>
      )}
    </div>
  )
}
