import { useEffect, useState, useRef } from 'react'
import api from '@/lib/api'
import type { PageMeta } from '@/lib/api'
import PageHeader from '@/components/PageHeader'

interface Action {
  _key: string
  name: string
  description: string
  type: string
  category: string
  status: string
  target: string
  target_id: string
  params: Record<string, any>
  result: string
  approved_by: string
  requires_approval: boolean
  created_by: string
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
  awaiting_approval: 'var(--high)',
  running: 'var(--accent-blue)',
  completed: 'var(--accent-green)',
  failed: 'var(--critical)',
  rejected: 'var(--text-muted)',
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

// ─── Main page ────────────────────────────────────────────────────────────────

type MainTab = 'actions' | 'terminal' | 'scripts'

export default function Actions() {
  const [mainTab, setMainTab] = useState<MainTab>('actions')
  const [items, setItems] = useState<Action[]>([])
  const [meta, setMeta] = useState<PageMeta>({ page: 1, page_size: 20, total: 0, total_pages: 1 })
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [statusFilter, setStatusFilter] = useState('')
  const [showNew, setShowNew] = useState(false)
  const [newType, setNewType] = useState('isolate')
  const [newTarget, setNewTarget] = useState('')
  const [newNote, setNewNote] = useState('')
  const [creating, setCreating] = useState(false)
  const [selected, setSelected] = useState<Action | null>(null)

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

  function createAction() {
    if (!newTarget.trim()) return
    setCreating(true)
    api.post('/actions', { type: newType, target: newTarget, description: newNote })
      .then(() => { setShowNew(false); setNewTarget(''); setNewNote(''); load(1) })
      .finally(() => setCreating(false))
  }

  function execute(a: Action) {
    api.post(`/actions/${a._key}/execute`).then(() => load(page))
  }

  function approve(a: Action) {
    api.patch(`/actions/${a._key}`, { status: 'running', approved_by: 'current_user' }).then(() => load(page))
  }

  function reject(a: Action) {
    api.patch(`/actions/${a._key}`, { status: 'rejected' }).then(() => load(page))
  }

  const selectedType = ACTION_TYPES.find(t => t.value === newType)

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <PageHeader
        title="动作中心"
        subtitle={`· ${meta.total} actions`}
        actions={<button className="btn-primary" onClick={() => setShowNew(true)}>+ New Action</button>}
      />

      {/* Main tab bar */}
      <div className="tab-bar" style={{ flexShrink: 0 }}>
        {([['actions', 'Action Log'], ['terminal', 'Live Terminal'], ['scripts', 'Script Library']] as [MainTab, string][]).map(([id, label]) => (
          <button key={id} className={`tab${mainTab === id ? ' active' : ''}`} onClick={() => setMainTab(id)}>{label}</button>
        ))}
      </div>

      {/* Status sub-tabs — only for action log */}
      {mainTab === 'actions' && (
        <div className="tab-bar" style={{ flexShrink: 0, borderTop: '1px solid var(--border)', background: 'var(--bg-primary)' }}>
          {[['All', ''], ['待处理', 'pending'], ['Awaiting Approval', 'awaiting_approval'], ['执行中', 'running'], ['已完成', 'completed'], ['失败', 'failed']].map(([label, val]) => (
            <button key={label} className={`tab${statusFilter === val ? ' active' : ''}`} onClick={() => setStatusFilter(val as string)}>
              {label}
            </button>
          ))}
        </div>
      )}

      {mainTab === 'terminal' && <LiveTerminalTab />}
      {mainTab === 'scripts'  && <ScriptLibraryTab />}

      {mainTab === 'actions' && <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        <div className="data-table-wrap" style={{ flex: 1 }}>
          <table className="data-table">
            <thead>
              <tr>
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
              {loading && <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>加载中...</td></tr>}
              {!loading && items.length === 0 && <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>暂无动作</td></tr>}
              {items.map(a => (
                <tr key={a._key} onClick={() => setSelected(selected?._key === a._key ? null : a)} className={selected?._key === a._key ? 'selected' : ''}>
                  <td>
                    <div style={{ fontSize: 12.5, fontWeight: 500 }}>
                      {typeIcon[a.type] ?? '⚙'} {ACTION_TYPES.find(t => t.value === a.type)?.label ?? a.name}
                    </div>
                    {a.description && <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginTop: 2 }}>{a.description.slice(0, 55)}</div>}
                  </td>
                  <td>
                    <span style={{
                      fontSize: 10.5, padding: '2px 7px', borderRadius: 3, textTransform: 'capitalize',
                      color: CATEGORY_COLOR[a.category ?? ACTION_TYPES.find(t => t.value === a.type)?.category ?? 'other'],
                      background: `${CATEGORY_COLOR[a.category ?? ACTION_TYPES.find(t => t.value === a.type)?.category ?? 'other']}18`,
                      border: `1px solid ${CATEGORY_COLOR[a.category ?? ACTION_TYPES.find(t => t.value === a.type)?.category ?? 'other']}33`,
                    }}>
                      {a.category ?? ACTION_TYPES.find(t => t.value === a.type)?.category ?? 'other'}
                    </span>
                  </td>
                  <td style={{ fontFamily: 'monospace', fontSize: 11.5, color: 'var(--text-secondary)' }}>{a.target || '-'}</td>
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
                          <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px', color: 'var(--critical)' }} onClick={() => reject(a)}>Reject</button>
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

        {selected && (
          <div style={{
            width: 320, borderLeft: '1px solid var(--border)', background: 'var(--bg-card)',
            display: 'flex', flexDirection: 'column', overflow: 'hidden', flexShrink: 0,
          }}>
            <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              <span style={{ fontSize: 13, fontWeight: 600 }}>Action Detail</span>
              <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px' }} onClick={() => setSelected(null)}>&#x2715;</button>
            </div>
            <div style={{ flex: 1, overflowY: 'auto', padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div className="card">
                <div style={{ fontSize: 20, marginBottom: 8 }}>{typeIcon[selected.type] ?? '⚙'}</div>
                <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 4 }}>
                  {ACTION_TYPES.find(t => t.value === selected.type)?.label ?? selected.name}
                </div>
                {selected.description && <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 12 }}>{selected.description}</div>}
                {[
                  ['类型', selected.type],
                  ['Target', selected.target || '-'],
                  ['状态', (selected.status || 'pending').replace('_', ' ')],
                  ['Created By', selected.created_by || '-'],
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
              {selected.status === 'awaiting_approval' && (
                <div style={{ display: 'flex', gap: 8 }}>
                  <button className="btn-primary" style={{ flex: 1, fontSize: 11 }} onClick={() => approve(selected)}>Approve</button>
                  <button className="btn-secondary" style={{ flex: 1, fontSize: 11, color: 'var(--critical)' }} onClick={() => reject(selected)}>Reject</button>
                </div>
              )}
              {selected.status === 'pending' && (
                <button className="btn-primary" style={{ fontSize: 11 }} onClick={() => execute(selected)}>&#9654; Execute Action</button>
              )}
            </div>
          </div>
        )}
      </div>}

      {mainTab === 'actions' && <div className="pagination">
        <button className="page-btn" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>&#8249;</button>
        <span>{page} / {meta.total_pages || 1}</span>
        <button className="page-btn" disabled={page >= meta.total_pages} onClick={() => setPage(p => p + 1)}>&#8250;</button>
        <span style={{ marginLeft: 8 }}>{meta.total} 条</span>
      </div>}

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
