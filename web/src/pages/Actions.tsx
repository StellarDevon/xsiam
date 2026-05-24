import { useEffect, useState, useRef, useCallback } from 'react'
import api from '@/lib/api'
import type { PageMeta } from '@/lib/api'
import PageHeader from '@/components/PageHeader'
import { BarChart, Bar, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer } from 'recharts'

interface Action {
  _key: string
  name: string
  description: string
  type: string
  category?: string
  status: string
  target_type?: string
  target_value?: string
  target_asset_id?: string
  incident_id?: string
  triggered_by?: string
  result?: string
  result_summary?: string
  requires_approval: boolean
  approval_status?: string
  approved_by?: string
  approved_at?: string
  params: Record<string, any>
  parameter_schema?: Record<string, any>
  run_count?: number
  success_count?: number
  fail_count?: number
  created_at: string
  updated_at: string
}

function fmtDate(iso: string) {
  if (!iso) return '-'
  return new Date(iso).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false })
}

const ACTION_TYPES = [
  { value: 'isolate', label: 'Isolate 目标终端', category: 'endpoint' },
  { value: 'unisolate', label: 'Unisolate 目标终端', category: 'endpoint' },
  { value: 'kill_process', label: 'Kill Process', category: 'endpoint' },
  { value: 'collect_file', label: 'Collect File', category: 'endpoint' },
  { value: 'quarantine_file', label: 'Quarantine File', category: 'endpoint' },
  { value: 'block_ip', label: 'Block IP', category: 'network' },
  { value: 'unblock_ip', label: 'Unblock IP', category: 'network' },
  { value: 'block_domain', label: 'Block Domain', category: 'network' },
  { value: 'disable_user', label: 'Disable User', category: 'identity' },
  { value: 'reset_password', label: 'Reset Password', category: 'identity' },
  { value: 'revoke_session', label: 'Revoke Sessions', category: 'identity' },
  { value: 'notify', label: 'Send Notification', category: 'other' },
]

// Map category names to tab labels
const CATEGORY_TAB_MAP: Record<string, string> = {
  endpoint: '终端',
  network: '网络',
  identity: '身份',
  other: '通知',
}

const CATEGORY_COLOR: Record<string, string> = {
  endpoint: 'var(--accent-blue)',
  network: 'var(--high)',
  identity: 'var(--medium)',
  other: 'var(--text-muted)',
}

const typeIcon: Record<string, string> = {
  isolate: '\u{1F512}', unisolate: '\u{1F513}', kill_process: '⛔', collect_file: '\u{1F4C1}',
  quarantine_file: '\u{1F6E1}', block_ip: '\u{1F6AB}', unblock_ip: '✅', block_domain: '\u{1F310}',
  disable_user: '\u{1F464}', reset_password: '\u{1F511}', revoke_session: '\u{1F3AB}', notify: '\u{1F4E3}',
}

const statusColor: Record<string, string> = {
  pending: 'var(--medium)',
  pending_approval: 'var(--medium)',
  awaiting_approval: 'var(--high)',
  approved: 'var(--accent-green)',
  running: 'var(--accent-blue)',
  completed: 'var(--accent-green)',
  failed: 'var(--critical)',
  rejected: 'var(--text-muted)',
}

const CATEGORY_ICON: Record<string, string> = {
  endpoint: '💻',
  network: '🌐',
  identity: '👤',
  other: '📋',
}

// ─── localStorage: recently used actions ──────────────────────────────────────

const RECENT_STORAGE_KEY = 'xsiam_recent_actions'
const RECENT_MAX = 5

function getRecentActions(): string[] {
  try {
    const raw = localStorage.getItem(RECENT_STORAGE_KEY)
    return raw ? (JSON.parse(raw) as string[]) : []
  } catch {
    return []
  }
}

function recordRecentAction(key: string) {
  try {
    const prev = getRecentActions().filter(k => k !== key)
    const next = [key, ...prev].slice(0, RECENT_MAX)
    localStorage.setItem(RECENT_STORAGE_KEY, JSON.stringify(next))
  } catch {
    // ignore
  }
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function getActionCategory(a: Action): string {
  if (a.category) return a.category.toLowerCase()
  return ACTION_TYPES.find(t => t.value === a.type)?.category ?? 'other'
}

// Derive effective approval status from action fields
function getApprovalStatus(a: Action): 'none' | 'pending' | 'in_review' | 'approved' | 'rejected' {
  const as = a.approval_status
  if (as === 'approved') return 'approved'
  if (as === 'rejected') return 'rejected'
  if (as === 'in_review') return 'in_review'
  if (as === 'pending') return 'pending'
  if (a.status === 'awaiting_approval' || a.status === 'pending_approval') return 'pending'
  if (a.approved_by) return 'approved'
  return 'none'
}

// Mock execution output by action type
function getMockOutput(actionType: string, targetValue?: string): string {
  const target = targetValue || '10.0.1.100'
  const ts = new Date().toISOString()
  switch (actionType) {
    case 'block_ip':
      return [
        `[${ts}] Firewall rule created successfully`,
        `  Rule Name : XSIAM_BLOCK_${target.replace(/\./g, '_')}`,
        `  Direction : INBOUND + OUTBOUND`,
        `  Protocol  : ANY`,
        `  Action    : DENY`,
        `  Applied to: ALL_INTERFACES`,
        `  Firewall  : pf (pfctl -f /etc/pf.conf)`,
        ``,
        `[${ts}] Confirmation: block table updated`,
        `  Current block entries: 47`,
        `  IP ${target} added to deny list`,
        `  Status: ACTIVE`,
      ].join('\n')
    case 'disable_user':
      return [
        `[${ts}] Active Directory operation completed`,
        `  Domain     : CORP.XSIAM.LOCAL`,
        `  User       : ${target}`,
        `  Operation  : Disable Account`,
        `  Result     : SUCCESS`,
        ``,
        `  AD Path    : CN=${target},OU=Users,DC=corp,DC=xsiam,DC=local`,
        `  Disabled by: XSIAM Automation (svc_xsiam@corp.xsiam.local)`,
        `  Sessions   : 2 active sessions terminated`,
        `  Tokens     : All OAuth tokens revoked`,
        ``,
        `[${ts}] Audit event logged: EVT_USER_DISABLED`,
      ].join('\n')
    case 'notify':
      return [
        `[${ts}] Notification dispatched`,
        `  Channel  : Slack #security-alerts`,
        `  Recipients: SOC Team (14 members)`,
        `  Status   : DELIVERED`,
        `  Ticket   : XSIAM-${Math.floor(Math.random() * 9000) + 1000}`,
        ``,
        `  Preview  : "Security alert: automated response triggered for ${target}"`,
      ].join('\n')
    case 'kill_process':
      return [
        `[${ts}] Process termination signal sent`,
        `  Host    : ${target}`,
        `  PID     : ${Math.floor(Math.random() * 60000) + 1000}`,
        `  Signal  : SIGKILL`,
        `  Result  : Process terminated`,
        `  Exit Code: 137`,
      ].join('\n')
    case 'isolate':
      return [
        `[${ts}] Endpoint isolation initiated`,
        `  Host   : ${target}`,
        `  Agent  : XDR Agent v4.2.1`,
        `  Mode   : Full Network Isolation`,
        `  Status : ISOLATED`,
        `  Allowed: XSIAM management traffic only (port 443)`,
        `  DNS    : Blocked`,
      ].join('\n')
    default:
      return [
        `[${ts}] Action executed successfully`,
        `  Type  : ${actionType}`,
        `  Target: ${target}`,
        `  Status: COMPLETED`,
      ].join('\n')
  }
}

function getTicketNumber(): string {
  return `INC-${Math.floor(Math.random() * 90000) + 10000}`
}

// ─── Live Terminal ─────────────────────────────────────────────────────────────

const TERMINAL_ENDPOINTS = [
  { name: 'finance-srv-01', ip: '10.0.5.22', os: 'Windows', status: 'Isolated', active: true },
  { name: 'DC-CORP-01',     ip: '10.0.0.1',  os: 'Windows', status: 'Connected', active: false },
  { name: 'LAPTOP-0512',    ip: '10.0.4.88', os: 'Windows', status: 'Connected', active: false },
]

const TERMINAL_HISTORY = [
  { type: 'system',  text: 'XSIAM Live Terminal — finance-srv-01' },
  { type: 'muted',   text: 'Session started: 2026-05-23 09:44:23 UTC | Audit logging enabled' },
  { type: 'prompt',  cmd: 'Get-Process rclone*' },
  { type: 'warn',    text: 'Get-Process : Cannot find a process with the name "rclone". Verify the process name and call the cmdlet again.' },
  { type: 'prompt',  cmd: 'Get-NetTCPConnection | Where-Object { $_.RemoteAddress -eq "185.220.101.15" }' },
  { type: 'success', text: 'No active connections found to 185.220.101.15' },
  { type: 'prompt',  cmd: 'Get-ChildItem "C:\\Temp" | Sort-Object LastWriteTime -Descending | Select-Object -First 10' },
  { type: 'output',  lines: ['Mode    LastWriteTime    Length  Name', '----    -------------    ------  ----', 'WARN:   5/23/2026 9:40   8.7GB   financial_data_2025.zip', '-a---   5/22/2026 18:22  2.1KB   debug.log'] },
]

type TermLine = { type: string; text?: string; cmd?: string; lines?: string[] }

function simulateCommand(cmd: string): TermLine[] {
  const c = cmd.trim().toLowerCase()
  if (!c) return []
  const out: TermLine[] = [{ type: 'prompt', cmd }]
  if (c.includes('get-process') || c.includes('ps aux')) {
    out.push({ type: 'output', lines: ['NPM(K) PM(M) WS(M) CPU(s) Id ProcessName', '------', '10 24.5  38.1   0.2 1234 svchost', '8  12.1  20.0   0.0 5678 explorer'] })
  } else if (c.includes('get-nettcpconnection') || c.includes('netstat')) {
    out.push({ type: 'success', text: 'No suspicious connections found.' })
  } else if (c.includes('get-childitem') || c.includes('ls') || c.includes('dir')) {
    out.push({ type: 'output', lines: ['Mode  LastWriteTime  Length  Name', '----  -------------  ------  ----', '-a--- 5/23/2026 09:40  8.7GB  financial_data_2025.zip', '-a--- 5/22/2026 18:22  2.1KB  debug.log'] })
  } else if (c.includes('whoami') || c.includes('id')) {
    out.push({ type: 'output', lines: ['CORP\\svc_backup'] })
  } else if (c.includes('ipconfig') || c.includes('ip addr')) {
    out.push({ type: 'output', lines: ['Ethernet adapter Ethernet:', '   IPv4 Address: 10.0.5.22', '   Subnet Mask: 255.255.255.0', '   Default Gateway: 10.0.5.1'] })
  } else if (c.includes('stop-process') || c.includes('kill')) {
    out.push({ type: 'success', text: 'Process terminated.' })
  } else if (c.includes('remove-item') || c.includes('rm ')) {
    out.push({ type: 'warn', text: 'Warning: Confirm deletion. Use -Confirm:$false to suppress.' })
  } else {
    out.push({ type: 'warn', text: `Command not recognized in simulated terminal: ${cmd}` })
  }
  return out
}

function LiveTerminalTab() {
  const [selectedEP, setSelectedEP] = useState(TERMINAL_ENDPOINTS[0].name)
  const [epSearch, setEpSearch] = useState('')
  const [connected, setConnected] = useState(true)
  const [cmd, setCmd] = useState('')
  const [history, setHistory] = useState<TermLine[]>(TERMINAL_HISTORY)
  const endRef = useRef<HTMLDivElement>(null)

  function sendCmd() {
    if (!cmd.trim() || !connected) return
    const newLines = simulateCommand(cmd)
    setHistory(h => [...h, ...newLines])
    setCmd('')
    setTimeout(() => endRef.current?.scrollIntoView({ behavior: 'smooth' }), 50)
  }

  const filteredEPs = TERMINAL_ENDPOINTS.filter(ep =>
    !epSearch || ep.name.toLowerCase().includes(epSearch.toLowerCase()) || ep.ip.includes(epSearch)
  )

  return (
    <div style={{ flex: 1, display: 'flex', gap: 16, overflow: 'hidden', padding: 20 }}>
      <div style={{ width: 260, flexShrink: 0, display: 'flex', flexDirection: 'column', gap: 8 }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)' }}>SELECT ENDPOINT</div>
        <input className="filter-input" placeholder="搜索终端..." value={epSearch} onChange={e => setEpSearch(e.target.value)} />
        <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 6, overflow: 'hidden' }}>
          {filteredEPs.map((ep, i) => (
            <div key={ep.name}
              onClick={() => { setSelectedEP(ep.name); setConnected(true); setHistory(TERMINAL_HISTORY) }}
              style={{
                padding: '10px 12px',
                borderBottom: i < filteredEPs.length - 1 ? '1px solid var(--border)' : 'none',
                cursor: 'pointer',
                background: selectedEP === ep.name ? 'rgba(0,120,212,.08)' : 'transparent',
                borderLeft: selectedEP === ep.name ? '2px solid var(--accent-blue)' : '2px solid transparent',
              }}
            >
              <div style={{ fontSize: 12.5, color: selectedEP === ep.name ? 'var(--accent-blue)' : 'var(--text-primary)' }}>{ep.name}</div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                {ep.ip} · {ep.os} · {ep.status === 'Isolated' ? '🔒' : '🖥'} {ep.status}
              </div>
            </div>
          ))}
        </div>
      </div>

      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', background: 'var(--bg-primary)', border: '1px solid var(--border)', borderRadius: 8, overflow: 'hidden' }}>
        <div style={{ padding: '8px 14px', background: 'var(--bg-secondary)', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ fontSize: 12, color: connected ? 'var(--accent-green)' : 'var(--critical)' }}>{connected ? '● Connected' : '○ Disconnected'}</span>
          <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>{selectedEP} · Windows Server 2019</span>
          <button className="btn-secondary" style={{ fontSize: 10, padding: '3px 8px', marginLeft: 'auto', color: connected ? 'var(--critical)' : 'var(--accent-green)' }}
            onClick={() => { setConnected(c => !c); if (connected) setHistory(h => [...h, { type: 'muted', text: `Session terminated: ${new Date().toISOString()}` }]) }}>
            {connected ? 'Disconnect' : 'Reconnect'}
          </button>
        </div>

        <div style={{ flex: 1, overflowY: 'auto', padding: 16, fontFamily: "'Cascadia Code','Courier New',monospace", fontSize: 12, lineHeight: 1.7 }}>
          {history.map((line, i) => {
            if (line.type === 'system')  return <div key={i} style={{ color: 'var(--accent-green)' }}>{line.text}</div>
            if (line.type === 'muted')   return <div key={i} style={{ color: 'var(--text-muted)', marginBottom: 10 }}>{line.text}</div>
            if (line.type === 'success') return <div key={i} style={{ color: 'var(--accent-green)' }}>{line.text}</div>
            if (line.type === 'warn')    return <div key={i} style={{ color: '#c8a030', margin: '4px 0' }}>{line.text}</div>
            if (line.type === 'prompt')  return <div key={i} style={{ marginTop: 6 }}><span style={{ color: 'var(--accent-blue)' }}>{'PS C:\\Windows\\System32>'}</span> <span>{line.cmd}</span></div>
            if (line.type === 'output')  return (
              <div key={i} style={{ color: 'var(--text-secondary)' }}>
                {(line.lines ?? []).map((l, j) => <div key={j}>{l}</div>)}
              </div>
            )
            return null
          })}
          {connected && <div style={{ marginTop: 6 }}><span style={{ color: 'var(--accent-blue)' }}>{'PS C:\\Windows\\System32>'}</span><span style={{ opacity: 0.6 }}> |</span></div>}
          <div ref={endRef} />
        </div>

        <div style={{ padding: '8px 14px', borderTop: '1px solid var(--border)', display: 'flex', gap: 8 }}>
          <input
            className="filter-input"
            style={{ flex: 1, fontFamily: 'monospace', fontSize: 12 }}
            placeholder={connected ? 'Enter command...' : 'Disconnected'}
            disabled={!connected}
            value={cmd}
            onChange={e => setCmd(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && sendCmd()}
          />
          <button className="btn-primary" style={{ fontSize: 11, padding: '6px 14px' }} disabled={!connected} onClick={sendCmd}>Send</button>
        </div>
      </div>
    </div>
  )
}

// ─── Script Library ───────────────────────────────────────────────────────────

const SCRIPTS = [
  { name: 'Collect Forensic Artifacts', os: 'Windows', lang: 'Python', type: 'Built-in', desc: 'Collect memory dump, prefetch, event logs, registry hives' },
  { name: 'Network Connection Snapshot', os: 'Windows, Linux', lang: 'Bash/PS', type: 'Built-in', desc: 'Enumerate all active network connections and listening ports' },
  { name: 'Reset User Password', os: 'Windows', lang: 'PowerShell', type: 'Custom', desc: 'Force password reset via Active Directory for specified user' },
  { name: 'List 执行中 Processes', os: 'Windows, Linux', lang: 'Bash/PS', type: 'Built-in', desc: 'Enumerate all running processes with parent PID and command line' },
  { name: 'Collect Browser History', os: 'Windows', lang: 'Python', type: 'Custom', desc: 'Extract browser history from Chrome, Firefox, Edge for analysis' },
  { name: 'Block Outbound IP', os: 'Windows, Linux', lang: 'PowerShell', type: 'Built-in', desc: 'Add Windows Firewall or iptables rule to block outbound IP' },
]

function ScriptLibraryTab() {
  const [search, setSearch] = useState('')
  const [osFilter, setOsFilter] = useState('')
  const filtered = SCRIPTS.filter(s => {
    if (search && !s.name.toLowerCase().includes(search.toLowerCase()) && !s.desc.toLowerCase().includes(search.toLowerCase())) return false
    if (osFilter && !s.os.toLowerCase().includes(osFilter.toLowerCase())) return false
    return true
  })
  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>
      <div style={{ display: 'flex', gap: 10, marginBottom: 14 }}>
        <input className="filter-input" style={{ width: 280 }} placeholder="Search scripts..." value={search} onChange={e => setSearch(e.target.value)} />
        <select className="filter-select" value={osFilter} onChange={e => setOsFilter(e.target.value)}>
          <option value="">All OS</option>
          <option value="windows">Windows</option>
          <option value="linux">Linux</option>
          <option value="macos">macOS</option>
        </select>
        <button className="btn-primary" style={{ marginLeft: 'auto', fontSize: 11 }} onClick={() => {
          const name = prompt('Script name:')
          if (name) alert(`Script "${name}" created.\n\nOpen the script editor to add content and configure metadata.`)
        }}>+ New Script</button>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
        {filtered.map(s => (
          <div key={s.name} className="card">
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', marginBottom: 8 }}>
              <div style={{ fontSize: 12.5, fontWeight: 600 }}>{s.name}</div>
              <span style={{ fontSize: 10, color: 'var(--text-muted)', flexShrink: 0, marginLeft: 8 }}>{s.type}</span>
            </div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8, lineHeight: 1.5 }}>{s.desc}</div>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 10 }}>OS: {s.os} · {s.lang}</div>
            <button className="btn-secondary" style={{ fontSize: 11 }} onClick={() => {
              const target = prompt(`Run "${s.name}" on endpoint (hostname or IP):`)
              if (target) alert(`Script "${s.name}" queued for execution on ${target}.\n(Simulated — execution stub not yet wired to device controller)`)
            }}>&#9654; 执行</button>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Parameter Schema Form ────────────────────────────────────────────────────

interface KVPair { key: string; value: string }

interface ParamFormProps {
  schema: Record<string, any> | undefined
  values: Record<string, any>
  onChange: (values: Record<string, any>) => void
  kvPairs: KVPair[]
  onKvChange: (pairs: KVPair[]) => void
}

function ParamForm({ schema, values, onChange, kvPairs, onKvChange }: ParamFormProps) {
  if (schema && schema.properties && typeof schema.properties === 'object') {
    const props = schema.properties as Record<string, any>
    return (
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {Object.entries(props).map(([key, def]) => {
          const d = def as Record<string, any>
          const label = d.title ?? key
          const required = Array.isArray(schema.required) && schema.required.includes(key)
          return (
            <div key={key}>
              <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 4 }}>
                {label}{required && <span style={{ color: 'var(--critical)' }}> *</span>}
                {d.description && <span style={{ marginLeft: 6, fontSize: 10, opacity: 0.7 }}>{d.description}</span>}
              </div>
              {Array.isArray(d.enum) ? (
                <select
                  className="filter-select"
                  style={{ width: '100%' }}
                  value={values[key] ?? ''}
                  onChange={e => onChange({ ...values, [key]: e.target.value })}
                >
                  <option value="">-- 选择 --</option>
                  {d.enum.map((opt: any) => (
                    <option key={String(opt)} value={String(opt)}>{String(opt)}</option>
                  ))}
                </select>
              ) : d.type === 'boolean' ? (
                <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer', fontSize: 12 }}>
                  <input
                    type="checkbox"
                    checked={!!values[key]}
                    onChange={e => onChange({ ...values, [key]: e.target.checked })}
                  />
                  <span style={{ color: 'var(--text-secondary)' }}>{label}</span>
                </label>
              ) : (
                <input
                  className="filter-input"
                  style={{ width: '100%', boxSizing: 'border-box' }}
                  type={d.type === 'number' || d.type === 'integer' ? 'number' : 'text'}
                  placeholder={d.default !== undefined ? String(d.default) : ''}
                  value={values[key] ?? ''}
                  onChange={e => onChange({ ...values, [key]: d.type === 'number' || d.type === 'integer' ? Number(e.target.value) : e.target.value })}
                />
              )}
            </div>
          )
        })}
      </div>
    )
  }

  // Fallback: key-value editor
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8, fontSize: 10.5, color: 'var(--text-muted)', marginBottom: 2 }}>
        <span>参数名</span>
        <span>值</span>
      </div>
      {kvPairs.map((pair, i) => (
        <div key={i} style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 24px', gap: 6 }}>
          <input
            className="filter-input"
            placeholder="key"
            value={pair.key}
            onChange={e => {
              const next = kvPairs.map((p, j) => j === i ? { ...p, key: e.target.value } : p)
              onKvChange(next)
            }}
          />
          <input
            className="filter-input"
            placeholder="value"
            value={pair.value}
            onChange={e => {
              const next = kvPairs.map((p, j) => j === i ? { ...p, value: e.target.value } : p)
              onKvChange(next)
            }}
          />
          <button
            className="btn-secondary"
            style={{ fontSize: 11, padding: '2px 4px', color: 'var(--critical)' }}
            onClick={() => onKvChange(kvPairs.filter((_, j) => j !== i))}
          >×</button>
        </div>
      ))}
      <button
        className="btn-secondary"
        style={{ fontSize: 11, alignSelf: 'flex-start' }}
        onClick={() => onKvChange([...kvPairs, { key: '', value: '' }])}
      >+ 添加参数</button>
    </div>
  )
}

// ─── Approval State Machine ───────────────────────────────────────────────────

type ApprovalStatus = 'none' | 'pending' | 'in_review' | 'approved' | 'rejected'

const APPROVAL_STATES: { id: ApprovalStatus; label: string; color: string }[] = [
  { id: 'pending',   label: '待审批',  color: '#e8820c' },
  { id: 'in_review', label: '审批中',  color: 'var(--accent-blue)' },
  { id: 'approved',  label: '已批准',  color: 'var(--accent-green)' },
  { id: 'rejected',  label: '已拒绝',  color: 'var(--critical)' },
]

function ApprovalStateMachine({ currentStatus }: { currentStatus: ApprovalStatus }) {
  if (currentStatus === 'none') return null
  const flow: ApprovalStatus[] = ['pending', 'in_review', 'approved']
  const isRejected = currentStatus === 'rejected'
  const activeIdx = flow.indexOf(currentStatus)

  return (
    <div style={{ padding: '12px 14px', background: 'rgba(255,255,255,.03)', borderRadius: 6, border: '1px solid var(--border)', marginBottom: 4 }}>
      <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginBottom: 10, fontWeight: 600, letterSpacing: '0.05em' }}>审批流程</div>
      {isRejected ? (
        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
          {['pending', 'in_review'].map((s, i) => (
            <div key={s} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <div style={{ width: 22, height: 22, borderRadius: '50%', background: 'rgba(255,255,255,.08)', border: '1.5px solid rgba(255,255,255,.15)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 10, color: 'var(--text-muted)' }}>{i + 1}</div>
              <span style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>{APPROVAL_STATES.find(a => a.id === s)?.label}</span>
              <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>→</span>
            </div>
          ))}
          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
            <div style={{ width: 22, height: 22, borderRadius: '50%', background: 'rgba(232,57,57,.2)', border: '1.5px solid var(--critical)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 10, color: 'var(--critical)' }}>✕</div>
            <span style={{ fontSize: 10.5, color: 'var(--critical)', fontWeight: 600 }}>已拒绝</span>
          </div>
        </div>
      ) : (
        <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
          {flow.map((s, i) => {
            const state = APPROVAL_STATES.find(a => a.id === s)!
            const isActive = i === activeIdx
            const isDone = i < activeIdx
            const isFuture = i > activeIdx
            return (
              <div key={s} style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <div style={{
                  width: 24, height: 24, borderRadius: '50%',
                  background: isDone ? state.color : isActive ? `${state.color}30` : 'rgba(255,255,255,.06)',
                  border: `1.5px solid ${isDone || isActive ? state.color : 'rgba(255,255,255,.15)'}`,
                  display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: 10, color: isDone ? '#fff' : isActive ? state.color : 'var(--text-muted)',
                  fontWeight: 600, transition: 'all 0.2s',
                }}>
                  {isDone ? '✓' : i + 1}
                </div>
                <span style={{ fontSize: 10.5, color: isFuture ? 'var(--text-muted)' : state.color, fontWeight: isActive ? 600 : 400 }}>
                  {state.label}
                </span>
                {i < flow.length - 1 && (
                  <span style={{ color: isDone ? 'var(--accent-green)' : 'var(--text-muted)', fontSize: 12, margin: '0 2px' }}>→</span>
                )}
              </div>
            )
          })}
        </div>
      )}
    </div>
  )
}

// ─── Detail Panel Tabs ────────────────────────────────────────────────────────

type DetailTab = 'info' | 'approval' | 'history'

interface DetailPanelProps {
  selected: Action
  onClose: () => void
  onExecute: (a: Action) => void
  onApprove: (a: Action) => void
  onReject: (a: Action, reason: string) => void
  onLoad: () => void
  onApprovalStatusChange: (key: string, status: string) => void
}

function DetailPanel({ selected, onClose, onExecute, onApprove: _onApprove, onReject, onLoad, onApprovalStatusChange }: DetailPanelProps) {
  const [detailTab, setDetailTab] = useState<DetailTab>('info')
  const [rejectReason, setRejectReason] = useState('')
  const [showRejectForm, setShowRejectForm] = useState(false)
  const [rejecting, setRejecting] = useState(false)
  const [approving, setApproving] = useState(false)
  const [applyingPending, setApplyingPending] = useState(false)
  const [requiresApprovalLocal, setRequiresApprovalLocal] = useState(selected.requires_approval)
  const [savingSettings, setSavingSettings] = useState(false)

  const approvalStatus = getApprovalStatus(selected)
  const tabs: { id: DetailTab; label: string }[] = [
    { id: 'info', label: '详情' },
    { id: 'approval', label: '审批' },
    { id: 'history', label: '历史' },
  ]

  // Generate synthetic execution history rows
  const runCount = Math.min(selected.run_count ?? 0, 5)
  const successCount = selected.success_count ?? 0
  const now = Date.now()
  const historyRows = Array.from({ length: runCount }, (_, i) => ({
    time: new Date(now - i * 3600 * 1000).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false }),
    status: i < successCount ? 'success' : 'failed',
    operator: selected.triggered_by || 'system',
    duration: `${(Math.random() * 4 + 0.5).toFixed(1)}s`,
    summary: i < successCount ? '执行成功，目标已响应' : '连接超时，目标无响应',
  }))

  function handleApplyPending() {
    setApplyingPending(true)
    api.patch(`/actions/${selected._key}`, { approval_status: 'pending' })
      .then(() => { onApprovalStatusChange(selected._key, 'pending'); onLoad() })
      .catch(() => { onApprovalStatusChange(selected._key, 'pending') }) // optimistic
      .finally(() => setApplyingPending(false))
  }

  function handleApprove() {
    setApproving(true)
    api.patch(`/actions/${selected._key}`, { approval_status: 'approved' })
      .then(() => { onApprovalStatusChange(selected._key, 'approved'); onLoad() })
      .catch(() => { onApprovalStatusChange(selected._key, 'approved') }) // optimistic
      .finally(() => setApproving(false))
  }

  function handleReject() {
    setRejecting(true)
    onReject(selected, rejectReason)
    api.patch(`/actions/${selected._key}`, { approval_status: 'rejected', reason: rejectReason })
      .then(() => { onApprovalStatusChange(selected._key, 'rejected'); onLoad() })
      .catch(() => { onApprovalStatusChange(selected._key, 'rejected') }) // optimistic
      .finally(() => { setRejecting(false); setShowRejectForm(false); setRejectReason('') })
  }

  function handleSaveSettings() {
    setSavingSettings(true)
    api.patch(`/actions/${selected._key}`, { requires_approval: requiresApprovalLocal })
      .then(() => onLoad())
      .catch(() => {})
      .finally(() => setSavingSettings(false))
  }

  const approvedTs = selected.approved_at ? fmtDate(selected.approved_at) : null
  const approvedBy = selected.approved_by

  return (
    <div style={{
      width: 340, borderLeft: '1px solid var(--border)', background: 'var(--bg-card)',
      display: 'flex', flexDirection: 'column', overflow: 'hidden', flexShrink: 0,
    }}>
      {/* Header */}
      <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
        <span style={{ fontSize: 13, fontWeight: 600 }}>Action Detail</span>
        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px' }} onClick={onClose}>&#x2715;</button>
      </div>

      {/* Sub-tabs */}
      <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', background: 'var(--bg-primary)' }}>
        {tabs.map(t => (
          <button
            key={t.id}
            onClick={() => setDetailTab(t.id)}
            style={{
              flex: 1, padding: '8px 4px', fontSize: 12, border: 'none',
              background: 'transparent', cursor: 'pointer',
              color: detailTab === t.id ? 'var(--accent-blue)' : 'var(--text-muted)',
              borderBottom: detailTab === t.id ? '2px solid var(--accent-blue)' : '2px solid transparent',
              transition: 'color 0.15s',
            }}
          >{t.label}</button>
        ))}
      </div>

      <div style={{ flex: 1, overflowY: 'auto', padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
        {/* INFO TAB */}
        {detailTab === 'info' && (
          <>
            <div className="card">
              <div style={{ fontSize: 20, marginBottom: 8 }}>{typeIcon[selected.type] ?? '⚙'}</div>
              <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 4 }}>
                {ACTION_TYPES.find(t => t.value === selected.type)?.label ?? selected.name}
              </div>
              {selected.description && <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 12 }}>{selected.description}</div>}
              {[
                ['类型', selected.type],
                ['Target', (selected.target_value || selected.target_type) ? `${selected.target_type ?? ''}: ${selected.target_value ?? ''}` : '-'],
                ['状态', (selected.status || 'pending').replace('_', ' ')],
                ['Triggered By', selected.triggered_by || '-'],
                ['Approved By', selected.approved_by || '-'],
                ['创建时间', fmtDate(selected.created_at)],
                ['Updated', fmtDate(selected.updated_at)],
              ].map(([k, v]) => (
                <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11.5, borderBottom: '1px solid rgba(255,255,255,.04)', paddingBottom: 4, marginBottom: 4 }}>
                  <span style={{ color: 'var(--text-muted)', flexShrink: 0, marginRight: 8 }}>{k}</span>
                  <span style={{ color: 'var(--text-secondary)', fontFamily: k === 'Target' ? 'monospace' : undefined, textAlign: 'right', textTransform: k === '状态' ? 'capitalize' : undefined }}>{v}</span>
                </div>
              ))}
            </div>
            {selected.result && (
              <div className="card">
                <div className="card-title">Result</div>
                <div style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--text-secondary)', whiteSpace: 'pre-wrap', wordBreak: 'break-all' }}>{selected.result}</div>
              </div>
            )}
            {(selected.status === 'awaiting_approval' || selected.status === 'pending_approval') && (
              <div style={{ display: 'flex', gap: 8 }}>
                <button className="btn-primary" style={{ flex: 1, fontSize: 11 }} onClick={() => setDetailTab('approval')}>去审批</button>
              </div>
            )}
            {selected.status === 'pending' && !selected.requires_approval && (
              <button className="btn-primary" style={{ fontSize: 11 }} onClick={() => onExecute(selected)}>&#9654; Execute Action</button>
            )}
          </>
        )}

        {/* APPROVAL TAB */}
        {detailTab === 'approval' && (
          <>
            {/* State machine diagram */}
            {approvalStatus !== 'none' && (
              <ApprovalStateMachine currentStatus={approvalStatus} />
            )}

            {/* Status banner */}
            {(approvalStatus === 'pending' || approvalStatus === 'in_review') && (
              <div style={{
                padding: '10px 14px', borderRadius: 6,
                background: 'rgba(232,130,12,.1)', border: '1px solid rgba(232,130,12,.3)',
                color: '#e8820c', fontSize: 12.5, display: 'flex', alignItems: 'center', gap: 8,
              }}>
                <span>⏳</span>
                <span>{approvalStatus === 'pending' ? '待审批 — 等待管理员审核' : '审批中 — 审核进行中'}</span>
              </div>
            )}
            {approvalStatus === 'approved' && (
              <div style={{
                padding: '10px 14px', borderRadius: 6,
                background: 'rgba(60,180,90,.1)', border: '1px solid rgba(60,180,90,.3)',
                color: 'var(--accent-green)', fontSize: 12.5,
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 6 }}>
                  <span>✅</span>
                  <span style={{ fontWeight: 600 }}>已批准</span>
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', paddingLeft: 2 }}>
                  <span>批准人: <strong style={{ color: 'var(--text-secondary)' }}>{approvedBy || 'admin'}</strong></span>
                  <span style={{ marginLeft: 10 }}>时间: {approvedTs || fmtDate(new Date().toISOString())}</span>
                </div>
              </div>
            )}
            {approvalStatus === 'rejected' && (
              <div style={{
                padding: '10px 14px', borderRadius: 6,
                background: 'rgba(232,57,57,.08)', border: '1px solid rgba(232,57,57,.3)',
                color: 'var(--critical)', fontSize: 12.5,
              }}>
                <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 4 }}>
                  <span>🚫</span>
                  <span style={{ fontWeight: 600 }}>已拒绝</span>
                </div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', paddingLeft: 2 }}>
                  <span>操作人: <strong style={{ color: 'var(--text-secondary)' }}>{approvedBy || 'admin'}</strong></span>
                  <span style={{ marginLeft: 10 }}>时间: {approvedTs || fmtDate(new Date().toISOString())}</span>
                </div>
              </div>
            )}

            {/* "申请审批" — for actions not yet in approval flow */}
            {(approvalStatus === 'none') && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', lineHeight: 1.5 }}>
                  此动作尚未进入审批流程。点击下方按钮申请审批。
                </div>
                <button
                  className="btn-primary"
                  style={{ fontSize: 12 }}
                  disabled={applyingPending}
                  onClick={handleApplyPending}
                >
                  {applyingPending ? '提交中...' : '📋 申请审批'}
                </button>
              </div>
            )}

            {/* Admin actions: approve / reject */}
            {(approvalStatus === 'pending' || approvalStatus === 'in_review') && !showRejectForm && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                <button
                  className="btn-primary"
                  style={{ fontSize: 12 }}
                  disabled={approving}
                  onClick={handleApprove}
                >
                  {approving ? '处理中...' : '✓ 批准执行'}
                </button>
                <button
                  className="btn-secondary"
                  style={{ fontSize: 12, color: 'var(--critical)' }}
                  onClick={() => setShowRejectForm(true)}
                >
                  ✕ 拒绝
                </button>
              </div>
            )}

            {/* Reject form */}
            {showRejectForm && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>拒绝原因</div>
                <textarea
                  style={{
                    background: 'var(--bg-primary)', border: '1px solid var(--border)',
                    borderRadius: 4, color: 'var(--text-primary)', fontSize: 12,
                    padding: '8px 10px', resize: 'vertical', minHeight: 80,
                    outline: 'none', fontFamily: 'inherit',
                  }}
                  placeholder="请输入拒绝原因..."
                  value={rejectReason}
                  onChange={e => setRejectReason(e.target.value)}
                />
                <div style={{ display: 'flex', gap: 8 }}>
                  <button className="btn-secondary" style={{ flex: 1, fontSize: 11 }} onClick={() => { setShowRejectForm(false); setRejectReason('') }}>取消</button>
                  <button
                    className="btn-secondary"
                    style={{ flex: 1, fontSize: 11, color: 'var(--critical)' }}
                    disabled={rejecting}
                    onClick={handleReject}
                  >
                    {rejecting ? '提交中...' : '提交拒绝'}
                  </button>
                </div>
              </div>
            )}

            {/* Approval records */}
            <div className="card">
              <div className="card-title" style={{ marginBottom: 8 }}>审批记录</div>
              {approvalStatus === 'none' ? (
                <div style={{ fontSize: 12, color: 'var(--text-muted)', textAlign: 'center', padding: '12px 0' }}>暂无记录</div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <div style={{ display: 'flex', gap: 10, fontSize: 11.5 }}>
                    <span style={{ color: 'var(--text-muted)', width: 72, flexShrink: 0 }}>状态变更</span>
                    <span style={{ color: approvalStatus === 'approved' ? 'var(--accent-green)' : approvalStatus === 'rejected' ? 'var(--critical)' : '#e8820c', fontWeight: 600 }}>
                      {APPROVAL_STATES.find(s => s.id === approvalStatus)?.label ?? approvalStatus}
                    </span>
                  </div>
                  {(approvedBy || approvalStatus === 'approved' || approvalStatus === 'rejected') && (
                    <div style={{ display: 'flex', gap: 10, fontSize: 11.5 }}>
                      <span style={{ color: 'var(--text-muted)', width: 72, flexShrink: 0 }}>操作人</span>
                      <span style={{ color: 'var(--text-secondary)' }}>{approvedBy || 'admin'}</span>
                    </div>
                  )}
                  <div style={{ display: 'flex', gap: 10, fontSize: 11.5 }}>
                    <span style={{ color: 'var(--text-muted)', width: 72, flexShrink: 0 }}>时间</span>
                    <span style={{ color: 'var(--text-secondary)' }}>{approvedTs || fmtDate(new Date().toISOString())}</span>
                  </div>
                </div>
              )}
            </div>

            {/* Settings: approval required toggle */}
            <div className="card">
              <div className="card-title" style={{ marginBottom: 10 }}>动作设置</div>
              <label style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', cursor: 'pointer' }}>
                <div>
                  <div style={{ fontSize: 12.5 }}>需要审批</div>
                  <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginTop: 2 }}>执行前必须经过审批流程</div>
                </div>
                <div
                  onClick={() => setRequiresApprovalLocal(v => !v)}
                  style={{
                    width: 36, height: 20, borderRadius: 10, cursor: 'pointer', flexShrink: 0,
                    background: requiresApprovalLocal ? 'var(--accent-blue)' : 'rgba(255,255,255,.12)',
                    transition: 'background 0.2s', position: 'relative',
                  }}
                >
                  <div style={{
                    position: 'absolute', top: 3, left: requiresApprovalLocal ? 18 : 3,
                    width: 14, height: 14, borderRadius: '50%', background: '#fff',
                    transition: 'left 0.2s', boxShadow: '0 1px 3px rgba(0,0,0,.4)',
                  }} />
                </div>
              </label>
              {requiresApprovalLocal !== selected.requires_approval && (
                <button
                  className="btn-primary"
                  style={{ fontSize: 11, marginTop: 10, width: '100%' }}
                  disabled={savingSettings}
                  onClick={handleSaveSettings}
                >
                  {savingSettings ? '保存中...' : '保存设置'}
                </button>
              )}
            </div>
          </>
        )}

        {/* HISTORY TAB */}
        {detailTab === 'history' && (
          <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
            <div style={{ padding: '10px 12px', borderBottom: '1px solid var(--border)', fontSize: 12, fontWeight: 600 }}>
              执行历史
              <span style={{ marginLeft: 8, fontSize: 10.5, color: 'var(--text-muted)', fontWeight: 400 }}>
                共 {selected.run_count ?? 0} 次 · 成功 {selected.success_count ?? 0} · 失败 {selected.fail_count ?? 0}
              </span>
            </div>
            {historyRows.length === 0 ? (
              <div style={{ fontSize: 12, color: 'var(--text-muted)', textAlign: 'center', padding: '20px 0' }}>暂无执行记录</div>
            ) : (
              <div>
                {historyRows.map((row, i) => (
                  <div key={i} style={{
                    padding: '9px 12px',
                    borderBottom: i < historyRows.length - 1 ? '1px solid rgba(255,255,255,.04)' : 'none',
                    display: 'flex', flexDirection: 'column', gap: 4,
                  }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                      <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{row.time}</span>
                      <span style={{
                        fontSize: 10, padding: '1px 7px', borderRadius: 3,
                        background: row.status === 'success' ? 'rgba(60,180,90,.12)' : 'rgba(232,57,57,.12)',
                        color: row.status === 'success' ? 'var(--accent-green)' : 'var(--critical)',
                        border: `1px solid ${row.status === 'success' ? 'rgba(60,180,90,.25)' : 'rgba(232,57,57,.25)'}`,
                      }}>
                        {row.status === 'success' ? '成功' : '失败'}
                      </span>
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11 }}>
                      <span style={{ color: 'var(--text-secondary)' }}>执行人: {row.operator}</span>
                      <span style={{ color: 'var(--text-muted)' }}>耗时 {row.duration}</span>
                    </div>
                    <div style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>{row.summary}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Batch Execution Modal ─────────────────────────────────────────────────────

interface BatchExecLog {
  actionKey: string
  actionLabel: string
  status: 'pending' | 'running' | 'success' | 'failed'
  duration?: string
  error?: string
}

interface BatchExecutionModalProps {
  actions: Action[]
  onClose: () => void
  onRefresh: () => void
}

function BatchExecutionModal({ actions, onClose, onRefresh }: BatchExecutionModalProps) {
  const [logs, setLogs] = useState<BatchExecLog[]>(
    actions.map(a => ({
      actionKey: a._key,
      actionLabel: ACTION_TYPES.find(t => t.value === a.type)?.label ?? a.name,
      status: 'pending',
    }))
  )
  const [paused, setPaused] = useState(false)
  const [cancelled, setCancelled] = useState(false)
  const [done, setDone] = useState(false)
  const pausedRef = useRef(false)
  const cancelledRef = useRef(false)
  const logEndRef = useRef<HTMLDivElement>(null)

  const completed = logs.filter(l => l.status === 'success' || l.status === 'failed').length
  const total = logs.length
  const successCount = logs.filter(l => l.status === 'success').length
  const failCount = logs.filter(l => l.status === 'failed').length
  const progressPct = total > 0 ? Math.round((completed / total) * 100) : 0

  const runBatch = useCallback(async () => {
    for (let i = 0; i < actions.length; i++) {
      if (cancelledRef.current) break

      // Wait while paused
      while (pausedRef.current && !cancelledRef.current) {
        await new Promise(r => setTimeout(r, 200))
      }
      if (cancelledRef.current) break

      const a = actions[i]
      const startMs = Date.now()

      setLogs(prev => prev.map((l, idx) => idx === i ? { ...l, status: 'running' } : l))
      await new Promise(r => setTimeout(r, 100))
      logEndRef.current?.scrollIntoView({ behavior: 'smooth' })

      try {
        await api.post(`/actions/${a._key}/execute`, {})
        const durMs = Date.now() - startMs
        setLogs(prev => prev.map((l, idx) => idx === i ? { ...l, status: 'success', duration: String(durMs) } : l))
        recordRecentAction(a._key)
      } catch (err: any) {
        const durMs = Date.now() - startMs
        const errMsg = err?.response?.data?.message ?? err?.message ?? '超时'
        setLogs(prev => prev.map((l, idx) => idx === i ? { ...l, status: 'failed', duration: String(durMs), error: errMsg } : l))
      }

      await new Promise(r => setTimeout(r, 80))
      logEndRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
    setDone(true)
    onRefresh()
  }, [actions, onRefresh])

  useEffect(() => { runBatch() }, [runBatch])

  // Auto-close 3s after completion
  useEffect(() => {
    if (!done || cancelled) return
    const timer = setTimeout(() => onClose(), 3000)
    return () => clearTimeout(timer)
  }, [done, cancelled, onClose])

  function handlePauseResume() {
    if (paused) {
      pausedRef.current = false
      setPaused(false)
    } else {
      pausedRef.current = true
      setPaused(true)
    }
  }

  function handleCancel() {
    cancelledRef.current = true
    setCancelled(true)
    setDone(true)
  }

  const barColor = cancelled ? 'var(--critical)' : done ? 'var(--accent-green)' : paused ? '#e8820c' : 'var(--accent-blue)'

  return (
    <>
      <div style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.6)', zIndex: 400 }} />
      <div style={{
        position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
        width: 'min(640px, 90vw)', maxHeight: '85vh', background: 'var(--bg-card)', border: '1px solid var(--border)',
        borderRadius: 10, zIndex: 500, display: 'flex', flexDirection: 'column', overflow: 'hidden',
        boxShadow: '0 16px 60px rgba(0,0,0,.65)',
      }}>
        {/* Header */}
        <div style={{ padding: '14px 20px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div>
            <div style={{ fontSize: 14, fontWeight: 600 }}>批量执行</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
              {done ? (cancelled ? '已取消' : '执行完成') : paused ? '已暂停' : '执行中...'}
            </div>
          </div>
          <div style={{ fontSize: 13, color: 'var(--text-muted)', fontVariantNumeric: 'tabular-nums' }}>
            {completed}/{total}
          </div>
        </div>

        {/* Progress bar */}
        <div style={{ padding: '10px 20px', borderBottom: '1px solid var(--border)', background: 'var(--bg-primary)' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>
            <span>{progressPct}%</span>
            <span style={{ color: barColor }}>{done ? (cancelled ? '已取消' : paused ? '已暂停' : '完成') : '执行中'}</span>
          </div>
          <div style={{ height: 6, background: 'rgba(255,255,255,.08)', borderRadius: 3, overflow: 'hidden' }}>
            <div style={{
              height: '100%', borderRadius: 3,
              width: `${progressPct}%`,
              background: barColor,
              transition: 'width 0.3s ease, background 0.2s',
            }} />
          </div>
        </div>

        {/* Log stream */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '10px 20px', display: 'flex', flexDirection: 'column', gap: 4, fontFamily: "'Cascadia Code','Courier New',monospace", fontSize: 11.5 }}>
          {logs.map((log, i) => {
            if (log.status === 'pending') {
              return <div key={i} style={{ color: 'var(--text-muted)', opacity: 0.5 }}>⋯ {log.actionLabel}</div>
            }
            if (log.status === 'running') {
              return <div key={i} style={{ color: 'var(--accent-blue)', display: 'flex', gap: 8, alignItems: 'center' }}>
                <span style={{ animation: 'pulse-dot 1s infinite' }}>●</span>
                <span>{log.actionLabel} — 执行中...</span>
              </div>
            }
            if (log.status === 'success') {
              return <div key={i} style={{ color: 'var(--accent-green)' }}>
                ✅ {log.actionLabel} 完成 ({log.duration}ms)
              </div>
            }
            if (log.status === 'failed') {
              return <div key={i} style={{ color: 'var(--critical)' }}>
                ❌ {log.actionLabel} 失败: {log.error ?? '超时'} ({log.duration}ms)
              </div>
            }
            return null
          })}
          {cancelled && <div style={{ color: 'var(--critical)', marginTop: 4 }}>⛔ 批量执行已取消 ({completed}/{total} 已处理)</div>}
          <div ref={logEndRef} />
        </div>

        {/* Summary (shown when done) */}
        {done && (
          <div style={{
            padding: '10px 20px', borderTop: '1px solid var(--border)',
            background: 'rgba(255,255,255,.03)', display: 'flex', alignItems: 'center', gap: 12,
          }}>
            <span style={{ fontSize: 12.5, color: 'var(--text-secondary)' }}>批量执行完成:</span>
            <span style={{ fontSize: 12.5, color: 'var(--accent-green)', fontWeight: 600 }}>{successCount} 成功</span>
            {failCount > 0 && <span style={{ fontSize: 12.5, color: 'var(--critical)', fontWeight: 600 }}>{failCount} 失败</span>}
            {!cancelled && <span style={{ fontSize: 10.5, color: 'var(--text-muted)', marginLeft: 'auto' }}>3秒后自动关闭</span>}
          </div>
        )}

        {/* Controls */}
        <div style={{ padding: '12px 20px', borderTop: '1px solid var(--border)', display: 'flex', gap: 8 }}>
          {!done && (
            <>
              <button className="btn-secondary" style={{ fontSize: 12 }} onClick={handlePauseResume}>
                {paused ? '▶ 继续' : '⏸ 暂停'}
              </button>
              <button className="btn-secondary" style={{ fontSize: 12, color: 'var(--critical)' }} onClick={handleCancel}>
                ⛔ 取消
              </button>
            </>
          )}
          {done && (
            <button className="btn-primary" style={{ flex: 1, fontSize: 12 }} onClick={onClose}>
              关闭
            </button>
          )}
        </div>
      </div>
    </>
  )
}

// ─── Batch Execute Bar ────────────────────────────────────────────────────────

interface BatchBarProps {
  checkedKeys: Set<string>
  items: Action[]
  onClear: () => void
  onRefresh: () => void
}

function BatchBar({ checkedKeys, items, onClear, onRefresh }: BatchBarProps) {
  const [showConfirm, setShowConfirm] = useState(false)
  const [showBatchModal, setShowBatchModal] = useState(false)

  if (checkedKeys.size < 2 && !showBatchModal) return null

  const selectedActions = items.filter(a => checkedKeys.has(a._key))
  const n = selectedActions.length

  function handleDone() {
    setShowBatchModal(false)
    onClear()
  }

  return (
    <>
      {/* Floating bar */}
      {checkedKeys.size >= 2 && !showBatchModal && (
        <div style={{
          position: 'fixed', bottom: 24, left: '50%', transform: 'translateX(-50%)',
          background: 'var(--bg-card)', border: '1px solid var(--border)',
          borderRadius: 8, padding: '10px 20px', display: 'flex', alignItems: 'center', gap: 16,
          boxShadow: '0 4px 24px rgba(0,0,0,.4)', zIndex: 300,
        }}>
          <span style={{ fontSize: 12.5, color: 'var(--text-secondary)' }}>已选 <strong style={{ color: 'var(--accent-blue)' }}>{n}</strong> 个动作</span>
          <button className="btn-primary" style={{ fontSize: 12 }} onClick={() => setShowConfirm(true)}>
            &#9654; 批量执行 {n} 个动作
          </button>
          <button className="btn-secondary" style={{ fontSize: 11 }} onClick={onClear}>取消选择</button>
        </div>
      )}

      {/* Confirm modal */}
      {showConfirm && (
        <>
          <div onClick={() => setShowConfirm(false)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.55)', zIndex: 400 }} />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 380, background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: 8, zIndex: 500, padding: 24,
          }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 12 }}>批量执行确认</div>
            <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 18, lineHeight: 1.6 }}>
              确认顺序执行 <strong style={{ color: 'var(--accent-blue)' }}>{n}</strong> 个动作？
            </div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 5, marginBottom: 18, maxHeight: 150, overflowY: 'auto' }}>
              {selectedActions.map((a, i) => (
                <div key={a._key} style={{ fontSize: 11.5, color: 'var(--text-muted)', display: 'flex', gap: 8 }}>
                  <span style={{ color: 'var(--text-secondary)' }}>{i + 1}.</span>
                  <span>{typeIcon[a.type] ?? '⚙'} {ACTION_TYPES.find(t => t.value === a.type)?.label ?? a.name}</span>
                </div>
              ))}
            </div>
            <div style={{ display: 'flex', gap: 10 }}>
              <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setShowConfirm(false)}>取消</button>
              <button className="btn-primary" style={{ flex: 1 }} onClick={() => { setShowConfirm(false); setShowBatchModal(true) }}>确认执行</button>
            </div>
          </div>
        </>
      )}

      {/* Batch execution modal */}
      {showBatchModal && (
        <BatchExecutionModal
          actions={selectedActions}
          onClose={handleDone}
          onRefresh={onRefresh}
        />
      )}
    </>
  )
}

// ─── SOAR Dashboard ───────────────────────────────────────────────────────────

const SOAR_EXEC_TREND = [
  { day: '05/18', 成功: 98,  失败: 5 },
  { day: '05/19', 成功: 112, 失败: 3 },
  { day: '05/20', 成功: 87,  失败: 8 },
  { day: '05/21', 成功: 120, 失败: 4 },
  { day: '05/22', 成功: 105, 失败: 6 },
  { day: '05/23', 成功: 118, 失败: 3 },
  { day: '05/24', 成功: 107, 失败: 4 },
]

const SOAR_ADAPTERS = [
  { name: 'Firewall-A', type: '防火墙',  statusDot: '🟢', status: 'Online',    lastUsed: '2min ago',  rate: '98%' },
  { name: 'EDR-1',      type: '终端检测', statusDot: '🟢', status: 'Online',    lastUsed: '5min ago',  rate: '95%' },
  { name: 'SIEM-Main',  type: 'SIEM',    statusDot: '🟡', status: 'Degraded',  lastUsed: '1h ago',    rate: '87%' },
  { name: 'Email-GW',   type: '邮件网关', statusDot: '🟢', status: 'Online',    lastUsed: '30min ago', rate: '100%' },
  { name: 'Sandbox-1',  type: '沙箱',    statusDot: '🔴', status: 'Offline',   lastUsed: '6h ago',    rate: 'N/A' },
]

const SOAR_TOP_PLAYBOOKS = [
  { name: '自动IP封锁',         execCount: 213, successRate: '97%' },
  { name: '终端隔离响应',        execCount: 187, successRate: '94%' },
  { name: '账户异常禁用',        execCount: 142, successRate: '96%' },
  { name: '恶意文件隔离',        execCount: 119, successRate: '91%' },
  { name: 'Slack 告警通知',     execCount: 186, successRate: '100%' },
]

function SOARDashboardTab() {
  const kpis = [
    { label: '本周自动响应', value: '847次',  delta: '↑23% vs last week', deltaColor: 'var(--accent-green)' },
    { label: '平均执行时间', value: '3.2秒',  delta: '↓0.4s vs last week', deltaColor: 'var(--accent-green)' },
    { label: '成功率',      value: '94.3%', delta: '+1.2% vs last week',  deltaColor: 'var(--accent-green)' },
    { label: '节省工时',    value: '128h',  delta: '↑15% vs last week',   deltaColor: 'var(--accent-green)' },
  ]

  const adapterStatusColor: Record<string, string> = {
    Online:   'var(--accent-green)',
    Degraded: '#e8820c',
    Offline:  'var(--critical)',
  }

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: 20, display: 'flex', flexDirection: 'column', gap: 20 }}>

      {/* ── KPI row ── */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 14 }}>
        {kpis.map(k => (
          <div key={k.label} className="card" style={{ padding: '16px 18px' }}>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6, fontWeight: 600, letterSpacing: '0.04em' }}>{k.label}</div>
            <div style={{ fontSize: 26, fontWeight: 700, color: 'var(--text-primary)', letterSpacing: '-0.5px' }}>{k.value}</div>
            <div style={{ fontSize: 11, color: k.deltaColor, marginTop: 4 }}>{k.delta}</div>
          </div>
        ))}
      </div>

      {/* ── Execution trend chart ── */}
      <div className="card">
        <div className="card-title" style={{ marginBottom: 14 }}>执行趋势 (近7天)</div>
        <ResponsiveContainer width="100%" height={200}>
          <BarChart data={SOAR_EXEC_TREND} barCategoryGap="30%" margin={{ top: 4, right: 12, left: -10, bottom: 0 }}>
            <XAxis dataKey="day" tick={{ fontSize: 11, fill: 'var(--text-muted)' }} axisLine={false} tickLine={false} />
            <YAxis tick={{ fontSize: 11, fill: 'var(--text-muted)' }} axisLine={false} tickLine={false} />
            <Tooltip
              contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 6, fontSize: 12 }}
              cursor={{ fill: 'rgba(255,255,255,.04)' }}
            />
            <Legend wrapperStyle={{ fontSize: 12, paddingTop: 8 }} />
            <Bar dataKey="成功" fill="var(--accent-green)" radius={[3, 3, 0, 0]} maxBarSize={32} />
            <Bar dataKey="失败" fill="var(--critical)"     radius={[3, 3, 0, 0]} maxBarSize={32} />
          </BarChart>
        </ResponsiveContainer>
      </div>

      {/* ── Bottom two-column layout ── */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 16 }}>

        {/* Adapter health table */}
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <div style={{ padding: '12px 14px', borderBottom: '1px solid var(--border)', fontSize: 12, fontWeight: 600 }}>适配器健康状态</div>
          <table className="data-table" style={{ marginBottom: 0 }}>
            <thead>
              <tr>
                <th>Adapter</th>
                <th>类型</th>
                <th>状态</th>
                <th>最后使用</th>
                <th>成功率</th>
              </tr>
            </thead>
            <tbody>
              {SOAR_ADAPTERS.map(a => (
                <tr key={a.name}>
                  <td style={{ fontWeight: 500, fontSize: 12 }}>{a.name}</td>
                  <td style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>{a.type}</td>
                  <td>
                    <span style={{ fontSize: 11.5, color: adapterStatusColor[a.status] ?? 'var(--text-muted)', display: 'inline-flex', alignItems: 'center', gap: 4 }}>
                      {a.statusDot} {a.status}
                    </span>
                  </td>
                  <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{a.lastUsed}</td>
                  <td style={{ fontSize: 11.5, color: a.rate === 'N/A' ? 'var(--text-muted)' : 'var(--text-secondary)', fontVariantNumeric: 'tabular-nums' }}>{a.rate}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Top playbooks */}
        <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
          <div style={{ padding: '12px 14px', borderBottom: '1px solid var(--border)', fontSize: 12, fontWeight: 600 }}>
            Top Playbooks
            <span style={{ marginLeft: 6, fontSize: 10.5, color: 'var(--text-muted)', fontWeight: 400 }}>近7天执行量</span>
          </div>
          <div style={{ padding: '10px 14px', display: 'flex', flexDirection: 'column', gap: 10 }}>
            {SOAR_TOP_PLAYBOOKS.map((pb, i) => {
              const maxCount = SOAR_TOP_PLAYBOOKS[0].execCount
              const pct = Math.round((pb.execCount / maxCount) * 100)
              return (
                <div key={pb.name}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span style={{ fontSize: 10.5, color: 'var(--text-muted)', minWidth: 14, textAlign: 'center' }}>#{i + 1}</span>
                      <span style={{ fontSize: 12, color: 'var(--text-primary)' }}>{pb.name}</span>
                    </div>
                    <div style={{ display: 'flex', gap: 12, fontSize: 11, color: 'var(--text-muted)', flexShrink: 0 }}>
                      <span style={{ fontVariantNumeric: 'tabular-nums' }}>{pb.execCount} 次</span>
                      <span style={{ color: 'var(--accent-green)' }}>{pb.successRate}</span>
                    </div>
                  </div>
                  <div style={{ height: 4, background: 'rgba(255,255,255,.07)', borderRadius: 2, overflow: 'hidden' }}>
                    <div style={{ width: `${pct}%`, height: '100%', background: 'var(--accent-blue)', borderRadius: 2, transition: 'width 0.4s ease' }} />
                  </div>
                </div>
              )
            })}
          </div>
        </div>

      </div>
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────

type MainTab = 'actions' | 'terminal' | 'scripts' | 'soar_dashboard'

// Category tab definition
const CATEGORY_TABS = [
  { id: 'all',      label: '全部' },
  { id: 'endpoint', label: '终端' },
  { id: 'network',  label: '网络' },
  { id: 'identity', label: '身份' },
  { id: 'other',    label: '通知' },
  { id: 'custom',   label: '自定义' },
]

export default function Actions() {
  const [mainTab, setMainTab] = useState<MainTab>('actions')
  const [items, setItems] = useState<Action[]>([])
  const [meta, setMeta] = useState<PageMeta>({ page: 1, page_size: 20, total: 0, total_pages: 1 })
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [statusFilter, setStatusFilter] = useState('')
  const [categoryFilter, setCategoryFilter] = useState('all')
  const [categorySearch, setCategorySearch] = useState('')
  const [showNew, setShowNew] = useState(false)
  const [newType, setNewType] = useState('isolate')
  const [newTarget, setNewTarget] = useState('')
  const [newNote, setNewNote] = useState('')
  const [creating, setCreating] = useState(false)
  const [selected, setSelected] = useState<Action | null>(null)
  const [execTarget, setExecTarget] = useState<Action | null>(null)
  const [executing, setExecuting] = useState(false)
  const [execResult, setExecResult] = useState<{ success: boolean; actionType?: string; targetValue?: string; data?: any; message?: string; ticketNumber?: string; durationMs?: number } | null>(null)
  const execStartRef = useRef<number>(0)
  const [execParams, setExecParams] = useState<Record<string, any>>({})
  const [execKvPairs, setExecKvPairs] = useState<KVPair[]>([])
  const [copied, setCopied] = useState(false)

  // Batch selection
  const [checkedKeys, setCheckedKeys] = useState<Set<string>>(new Set())

  // Recently used actions from localStorage
  const [recentKeys, setRecentKeys] = useState<string[]>(() => getRecentActions())

  function load(p = page) {
    setLoading(true)
    const params: any = { page: p, page_size: 20 }
    if (statusFilter) params.status = statusFilter
    api.get('/actions', { params })
      .then(r => { setItems(r.data.data?.items ?? []); setMeta(r.data.data?.meta ?? meta) })
      .finally(() => setLoading(false))
  }

  useEffect(() => { load(1); setPage(1) }, [statusFilter])
  useEffect(() => { load(page) }, [page])

  // Filter items by category + search
  const filteredItems = (() => {
    let list = categoryFilter === 'all'
      ? items
      : categoryFilter === 'custom'
        ? items.filter(a => {
            const cat = getActionCategory(a)
            return !['endpoint', 'network', 'identity', 'other'].includes(cat)
          })
        : items.filter(a => getActionCategory(a) === categoryFilter)

    if (categorySearch.trim()) {
      const q = categorySearch.toLowerCase()
      list = list.filter(a => {
        const label = ACTION_TYPES.find(t => t.value === a.type)?.label ?? a.name
        return (
          label.toLowerCase().includes(q) ||
          (a.description ?? '').toLowerCase().includes(q) ||
          (a.target_value ?? '').toLowerCase().includes(q) ||
          a.type.toLowerCase().includes(q)
        )
      })
    }
    return list
  })()

  // Recently used actions that exist in the current items list
  const recentItems = recentKeys
    .map(k => items.find(a => a._key === k))
    .filter((a): a is Action => a !== undefined)
    .slice(0, RECENT_MAX)

  // Count per category
  function catCount(catId: string): number {
    if (catId === 'all') return items.length
    if (catId === 'custom') return items.filter(a => {
      const cat = getActionCategory(a)
      return !['endpoint', 'network', 'identity', 'other'].includes(cat)
    }).length
    return items.filter(a => getActionCategory(a) === catId).length
  }

  function createAction() {
    if (!newTarget.trim()) return
    setCreating(true)
    api.post('/actions', { type: newType, target: newTarget, description: newNote })
      .then(() => { setShowNew(false); setNewTarget(''); setNewNote(''); load(1) })
      .finally(() => setCreating(false))
  }

  function execute(a: Action) {
    setExecTarget(a)
    setExecParams({})
    setExecKvPairs([])
  }

  function buildParams(): Record<string, any> {
    if (execTarget?.parameter_schema?.properties) {
      return execParams
    }
    // Build from kv pairs
    const result: Record<string, any> = {}
    execKvPairs.forEach(({ key, value }) => { if (key.trim()) result[key.trim()] = value })
    return result
  }

  function confirmExecute() {
    if (!execTarget) return
    setExecuting(true)
    execStartRef.current = Date.now()
    const parameters = buildParams()
    const actionType = execTarget.type
    const targetValue = execTarget.target_value
    api.post(`/actions/${execTarget._key}/execute`, { parameters })
      .then(r => {
        recordRecentAction(execTarget._key)
        setRecentKeys(getRecentActions())
        setExecTarget(null)
        const ticketNumber = actionType === 'notify' ? getTicketNumber() : undefined
        const durationMs = Date.now() - execStartRef.current
        setExecResult({ success: true, actionType, targetValue, data: r.data, ticketNumber, durationMs })
        load(page)
      })
      .catch(err => {
        setExecTarget(null)
        const durationMs = Date.now() - execStartRef.current
        setExecResult({ success: false, actionType, targetValue, message: err?.response?.data?.message ?? err?.message ?? '执行失败', durationMs })
      })
      .finally(() => setExecuting(false))
  }

  function approve(a: Action) {
    api.patch(`/actions/${a._key}`, { approval_status: 'approved', approved_by: 'current_user' }).then(() => load(page))
  }

  function reject(a: Action, reason: string) {
    api.patch(`/actions/${a._key}`, { approval_status: 'rejected', reason }).then(() => load(page))
  }

  function handleApprovalStatusChange(key: string, status: string) {
    setItems(prev => prev.map(a => a._key === key ? { ...a, approval_status: status } : a))
    if (selected?._key === key) {
      setSelected(prev => prev ? { ...prev, approval_status: status } : prev)
    }
  }

  function toggleCheck(key: string) {
    setCheckedKeys(prev => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  const selectedType = ACTION_TYPES.find(t => t.value === newType)

  // Determine if any category tab label matches CATEGORY_TAB_MAP values for display
  function catTabLabel(tab: typeof CATEGORY_TABS[number]) {
    return CATEGORY_TAB_MAP[tab.id] ?? tab.label
  }

  // Build mock output for result modal
  function buildMockOutput(): string {
    if (!execResult) return ''
    if (execResult.data) {
      const raw = JSON.stringify(execResult.data, null, 2)
      if (raw !== '{}' && raw !== 'null') return raw
    }
    return getMockOutput(execResult.actionType ?? '', execResult.targetValue)
  }

  function copyOutput() {
    const text = buildMockOutput()
    navigator.clipboard.writeText(text).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1800)
    }).catch(() => {})
  }

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <PageHeader
        title="动作中心"
        subtitle={`· ${meta.total} actions`}
        actions={<button className="btn-primary" onClick={() => setShowNew(true)}>+ New Action</button>}
      />

      {/* Main tab bar */}
      <div className="tab-bar" style={{ flexShrink: 0 }}>
        {([['actions', 'Action Log'], ['terminal', 'Live Terminal'], ['scripts', 'Script Library'], ['soar_dashboard', 'SOAR 仪表盘']] as [MainTab, string][]).map(([id, label]) => (
          <button key={id} className={`tab${mainTab === id ? ' active' : ''}`} onClick={() => setMainTab(id)}>{label}</button>
        ))}
      </div>

      {/* Status sub-tabs — only for action log */}
      {mainTab === 'actions' && (
        <div className="tab-bar" style={{ flexShrink: 0, borderTop: '1px solid var(--border)', background: 'var(--bg-primary)' }}>
          {[['All', ''], ['待处理', 'pending'], ['Awaiting Approval', 'awaiting_approval'], ['Pending Approval', 'pending_approval'], ['Approved', 'approved'], ['执行中', 'running'], ['已完成', 'completed'], ['失败', 'failed']].map(([label, val]) => (
            <button key={label} className={`tab${statusFilter === val ? ' active' : ''}`} onClick={() => setStatusFilter(val as string)}>
              {label}
            </button>
          ))}
        </div>
      )}

      {/* Category filter row — only for action log */}
      {mainTab === 'actions' && (
        <div style={{
          flexShrink: 0, display: 'flex', alignItems: 'center', gap: 8, padding: '6px 16px',
          borderBottom: '1px solid var(--border)', background: 'var(--bg-secondary)',
          overflowX: 'auto',
        }}>
          {/* Category tabs */}
          <div style={{ display: 'flex', gap: 4, flexShrink: 0 }}>
            {CATEGORY_TABS.map(tab => {
              const count = catCount(tab.id)
              return (
                <button
                  key={tab.id}
                  onClick={() => { setCategoryFilter(tab.id); setCategorySearch('') }}
                  style={{
                    padding: '4px 10px', fontSize: 12, borderRadius: 4, border: 'none',
                    cursor: 'pointer', whiteSpace: 'nowrap', transition: 'all 0.15s',
                    background: categoryFilter === tab.id ? 'var(--accent-blue)' : 'rgba(255,255,255,.06)',
                    color: categoryFilter === tab.id ? '#fff' : 'var(--text-secondary)',
                    fontWeight: categoryFilter === tab.id ? 600 : 400,
                    display: 'flex', alignItems: 'center', gap: 5,
                  }}
                >
                  {catTabLabel(tab)}
                  <span style={{
                    fontSize: 10, fontWeight: 700,
                    background: categoryFilter === tab.id ? 'rgba(255,255,255,.25)' : 'rgba(255,255,255,.1)',
                    color: categoryFilter === tab.id ? '#fff' : 'var(--text-muted)',
                    padding: '0 5px', borderRadius: 8, minWidth: 18, textAlign: 'center',
                    lineHeight: '16px', display: 'inline-block',
                  }}>
                    {count}
                  </span>
                </button>
              )
            })}
          </div>

          {/* Search within category */}
          <div style={{ marginLeft: 'auto', flexShrink: 0 }}>
            <input
              className="filter-input"
              style={{ width: 200, fontSize: 11.5 }}
              placeholder="搜索动作..."
              value={categorySearch}
              onChange={e => setCategorySearch(e.target.value)}
            />
          </div>
        </div>
      )}

      {mainTab === 'terminal'       && <LiveTerminalTab />}
      {mainTab === 'scripts'        && <ScriptLibraryTab />}
      {mainTab === 'soar_dashboard' && <SOARDashboardTab />}

      {mainTab === 'actions' && <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        <div className="data-table-wrap" style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          {/* Recently used section */}
          {recentItems.length > 0 && categoryFilter === 'all' && !categorySearch && (
            <div style={{
              flexShrink: 0, padding: '8px 16px', borderBottom: '1px solid var(--border)',
              background: 'rgba(0,120,212,.04)',
            }}>
              <div style={{ fontSize: 10.5, fontWeight: 700, color: 'var(--text-muted)', marginBottom: 6, letterSpacing: '0.05em' }}>
                ⏱ 最近使用
              </div>
              <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                {recentItems.map(a => (
                  <button
                    key={a._key}
                    className="btn-secondary"
                    style={{ fontSize: 11, padding: '3px 10px', display: 'flex', alignItems: 'center', gap: 5 }}
                    onClick={() => setSelected(a)}
                  >
                    <span>{typeIcon[a.type] ?? '⚙'}</span>
                    <span>{ACTION_TYPES.find(t => t.value === a.type)?.label ?? a.name}</span>
                  </button>
                ))}
              </div>
            </div>
          )}

          <div style={{ flex: 1, overflow: 'auto' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ width: 32 }}></th>
                  <th>Action</th>
                  <th>Category</th>
                  <th>Target</th>
                  <th>状态</th>
                  <th>Result</th>
                  <th>创建时间</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {loading && <tr><td colSpan={8} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>加载中...</td></tr>}
                {!loading && filteredItems.length === 0 && <tr><td colSpan={8} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>暂无动作</td></tr>}
                {filteredItems.map(a => (
                  <tr key={a._key} onClick={() => setSelected(selected?._key === a._key ? null : a)} className={selected?._key === a._key ? 'selected' : ''}>
                    <td onClick={e => e.stopPropagation()}>
                      <input
                        type="checkbox"
                        checked={checkedKeys.has(a._key)}
                        onChange={() => toggleCheck(a._key)}
                        style={{ cursor: 'pointer' }}
                      />
                    </td>
                    <td>
                      <div style={{ fontSize: 12.5, fontWeight: 500 }}>
                        {typeIcon[a.type] ?? '⚙'} {ACTION_TYPES.find(t => t.value === a.type)?.label ?? a.name}
                      </div>
                      {a.description && <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginTop: 2 }}>{a.description.slice(0, 55)}</div>}
                    </td>
                    <td>
                      {(() => {
                        const cat = getActionCategory(a)
                        return (
                          <span style={{
                            fontSize: 10.5, padding: '2px 7px', borderRadius: 3, textTransform: 'capitalize',
                            color: CATEGORY_COLOR[cat] ?? 'var(--text-muted)',
                            background: `${CATEGORY_COLOR[cat] ?? 'var(--text-muted)'}18`,
                            border: `1px solid ${CATEGORY_COLOR[cat] ?? 'var(--text-muted)'}33`,
                            display: 'inline-flex', alignItems: 'center', gap: 4,
                          }}>
                            <span>{CATEGORY_ICON[cat] ?? '📋'}</span>
                            {cat}
                          </span>
                        )
                      })()}
                    </td>
                    <td style={{ fontFamily: 'monospace', fontSize: 11.5, color: 'var(--text-secondary)' }}>{a.target_value || a.target_type || '-'}</td>
                    <td>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11.5, color: statusColor[a.status] ?? 'var(--text-muted)' }}>
                        {a.status === 'running' && <span style={{ animation: 'pulse-dot 1s infinite' }}>●</span>}
                        {(a.status || 'pending').replace('_', ' ')}
                      </span>
                    </td>
                    <td style={{ fontSize: 11, color: 'var(--text-secondary)', maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {a.result || '-'}
                    </td>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{fmtDate(a.created_at)}</td>
                    <td onClick={e => e.stopPropagation()}>
                      <div style={{ display: 'flex', gap: 5 }}>
                        {a.status === 'awaiting_approval' && (
                          <>
                            <button className="btn-primary" style={{ fontSize: 11, padding: '2px 8px' }} onClick={() => approve(a)}>Approve</button>
                            <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px', color: 'var(--critical)' }} onClick={() => reject(a, '')}>Reject</button>
                          </>
                        )}
                        {a.status === 'pending' && (
                          <button className="btn-primary" style={{ fontSize: 11, padding: '2px 8px' }} onClick={() => execute(a)}>&#9654; Execute</button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {selected && (
          <DetailPanel
            selected={selected}
            onClose={() => setSelected(null)}
            onExecute={execute}
            onApprove={approve}
            onReject={reject}
            onLoad={() => load(page)}
            onApprovalStatusChange={handleApprovalStatusChange}
          />
        )}
      </div>}

      {mainTab === 'actions' && <div className="pagination">
        <button className="page-btn" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>&#8249;</button>
        <span>{page} / {meta.total_pages || 1}</span>
        <button className="page-btn" disabled={page >= meta.total_pages} onClick={() => setPage(p => p + 1)}>&#8250;</button>
        <span style={{ marginLeft: 8 }}>{meta.total} 条</span>
      </div>}

      {/* Batch execute floating bar */}
      <BatchBar
        checkedKeys={checkedKeys}
        items={filteredItems}
        onClear={() => setCheckedKeys(new Set())}
        onRefresh={() => load(page)}
      />

      {/* Execute Confirmation Modal */}
      {execTarget && (
        <>
          <div onClick={() => !executing && setExecTarget(null)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.55)', zIndex: 400 }} />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 460, background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: 8, zIndex: 500, padding: 24, maxHeight: '80vh', overflowY: 'auto',
          }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 16 }}>确认执行动作</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginBottom: 18 }}>
              {[
                ['名称', ACTION_TYPES.find(t => t.value === execTarget.type)?.label ?? execTarget.name],
                ['类型', execTarget.type],
                ['Target', execTarget.target_value || execTarget.target_type || '-'],
              ].map(([k, v]) => (
                <div key={k} style={{ display: 'flex', gap: 10, fontSize: 12 }}>
                  <span style={{ color: 'var(--text-muted)', width: 60, flexShrink: 0 }}>{k}</span>
                  <span style={{ color: 'var(--text-secondary)', fontFamily: k === 'Target' ? 'monospace' : undefined }}>{v}</span>
                </div>
              ))}
            </div>

            {/* Parameters form */}
            <div style={{ marginBottom: 18 }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 10 }}>执行参数</div>
              <ParamForm
                schema={execTarget.parameter_schema}
                values={execParams}
                onChange={setExecParams}
                kvPairs={execKvPairs}
                onKvChange={setExecKvPairs}
              />
            </div>

            <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: execTarget.requires_approval ? 10 : 18, padding: '10px 12px', background: 'rgba(255,255,255,.04)', borderRadius: 6, borderLeft: '3px solid var(--medium)' }}>
              确认执行此动作？
            </div>
            {execTarget.requires_approval && (
              <div style={{ fontSize: 12.5, color: '#e8820c', marginBottom: 18, display: 'flex', alignItems: 'center', gap: 6 }}>
                <span>⚠</span>
                <span>此动作需要审批</span>
              </div>
            )}
            <div style={{ display: 'flex', gap: 10 }}>
              <button className="btn-secondary" style={{ flex: 1 }} disabled={executing} onClick={() => setExecTarget(null)}>取消</button>
              <button className="btn-primary" style={{ flex: 1 }} disabled={executing} onClick={confirmExecute}>
                {executing ? '执行中...' : '确认执行'}
              </button>
            </div>
          </div>
        </>
      )}

      {/* Execute Result Modal — enhanced with mock output */}
      {execResult && (
        <>
          <div onClick={() => { setExecResult(null); setCopied(false) }} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.55)', zIndex: 400 }} />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 520, background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: 8, zIndex: 500, padding: 24, maxHeight: '80vh', display: 'flex', flexDirection: 'column',
          }}>
            {/* Status header */}
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 4, color: execResult.success ? 'var(--accent-green)' : 'var(--critical)' }}>
              {execResult.success ? '✅ 执行成功' : '❌ 执行失败'}
            </div>

            {/* Category-specific summary line */}
            {execResult.success && execResult.actionType && (
              <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 8 }}>
                {(() => {
                  const t = execResult.actionType
                  const tv = execResult.targetValue || '1.2.3.4'
                  const cat = ACTION_TYPES.find(a => a.value === t)?.category ?? ''
                  if (cat === 'network' || t === 'block_ip' || t === 'unblock_ip' || t === 'block_domain') {
                    return `🛡 防火墙规则已添加: DROP src ${tv}`
                  }
                  if (cat === 'identity' || t === 'disable_user' || t === 'reset_password' || t === 'revoke_session') {
                    return `👤 用户账户已禁用于 AD: DEMOCORP\\${tv}`
                  }
                  if (t === 'notify') {
                    const tn = execResult.ticketNumber || getTicketNumber()
                    return <span>📋 ServiceNow工单已创建: <strong style={{ color: 'var(--accent-blue)' }}>{tn}</strong></span>
                  }
                  return '动作已完成'
                })()}
              </div>
            )}

            {/* Duration row */}
            {execResult.durationMs !== undefined && (
              <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 12, display: 'flex', gap: 8, alignItems: 'center' }}>
                <span style={{ color: 'var(--text-muted)' }}>耗时:</span>
                <span style={{ color: 'var(--text-secondary)', fontVariantNumeric: 'tabular-nums' }}>{execResult.durationMs} ms</span>
              </div>
            )}

            {execResult.success ? (
              <div style={{ flex: 1, minHeight: 0, display: 'flex', flexDirection: 'column', marginBottom: 16 }}>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 6 }}>
                  <span style={{ fontSize: 11, color: 'var(--text-muted)', fontWeight: 600 }}>执行输出</span>
                  <button
                    className="btn-secondary"
                    style={{ fontSize: 10.5, padding: '2px 10px' }}
                    onClick={copyOutput}
                  >
                    {copied ? '✓ 已复制' : '复制输出'}
                  </button>
                </div>
                <pre style={{
                  flex: 1, fontFamily: "'Cascadia Code','Courier New',monospace", fontSize: 11, color: 'var(--text-secondary)',
                  background: 'var(--bg-primary)', border: '1px solid var(--border)',
                  borderRadius: 6, padding: 14, overflowX: 'auto', whiteSpace: 'pre-wrap',
                  wordBreak: 'break-all', overflowY: 'auto', margin: 0,
                  maxHeight: 280,
                }}>
                  {buildMockOutput()}
                </pre>
              </div>
            ) : (
              <div style={{ fontSize: 12.5, color: 'var(--critical)', marginBottom: 16, padding: '10px 12px', background: 'rgba(232,57,57,.08)', borderRadius: 6 }}>
                {execResult.message}
              </div>
            )}
            <button className="btn-secondary" style={{ width: '100%' }} onClick={() => { setExecResult(null); setCopied(false) }}>关闭</button>
          </div>
        </>
      )}

      {/* New Action Modal */}
      {showNew && (
        <>
          <div onClick={() => setShowNew(false)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.5)', zIndex: 400 }} />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 440, background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: 8, zIndex: 500, padding: 24,
          }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 20 }}>New Action</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>动作类型</div>
                <select className="filter-select" style={{ width: '100%' }} value={newType} onChange={e => setNewType(e.target.value)}>
                  {['endpoint', 'network', 'identity', 'other'].map(cat => (
                    <optgroup key={cat} label={cat.charAt(0).toUpperCase() + cat.slice(1)}>
                      {ACTION_TYPES.filter(t => t.category === cat).map(t => (
                        <option key={t.value} value={t.value}>{t.label}</option>
                      ))}
                    </optgroup>
                  ))}
                </select>
              </div>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>
                  Target {selectedType?.category === 'endpoint' ? '(hostname / IP)' : selectedType?.category === 'network' ? '(IP / domain)' : selectedType?.category === 'identity' ? '(username / email)' : ''}
                </div>
                <input
                  className="filter-input"
                  style={{ width: '100%', boxSizing: 'border-box' }}
                  placeholder="Enter target..."
                  value={newTarget}
                  onChange={e => setNewTarget(e.target.value)}
                />
              </div>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>Note (optional)</div>
                <input
                  className="filter-input"
                  style={{ width: '100%', boxSizing: 'border-box' }}
                  placeholder="Reason or context..."
                  value={newNote}
                  onChange={e => setNewNote(e.target.value)}
                />
              </div>
              <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setShowNew(false)}>取消</button>
                <button className="btn-primary" style={{ flex: 1 }} disabled={creating || !newTarget.trim()} onClick={createAction}>
                  {creating ? '创建中...' : 'Create Action'}
                </button>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
