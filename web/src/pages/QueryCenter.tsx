import { useState, useRef } from 'react'
import api from '@/lib/api'

interface QueryTab {
  id: string
  name: string
  query: string
}

const SAMPLE_QUERIES = [
  { name: 'Suspicious Outbound Transfers', tag: 'Exfiltration', query: 'dataset = xdr_data\n| filter event_type = "network_connection"\n| filter action_remote_port not in [80, 443]\n| filter bytes_sent > 10000000\n| fields event_timestamp, agent_hostname, action_remote_ip, action_remote_port, bytes_sent\n| sort bytes_sent desc' },
  { name: 'Failed Auth Events - Last 24h', tag: 'Authentication', query: 'dataset = identity_analytics_profile\n| filter failed_logins > 5\n| filter last_activity > now()-24h\n| fields user_name, failed_logins, risk_score, department\n| sort failed_logins desc\n| limit 50' },
  { name: 'PowerShell Encoded Commands', tag: 'Execution', query: 'dataset = xdr_data\n| filter actor_process_image_name = "powershell.exe"\n| filter actor_process_command_line contains "-enc"\n| fields event_timestamp, agent_hostname, actor_process_command_line\n| sort event_timestamp desc' },
  { name: 'Cloud S3 Access Events', tag: 'Cloud', query: 'dataset = cloud_audit_log\n| filter event_name contains "GetObject"\n| filter cloud_provider = "aws"\n| stats count by user_identity, source_ip\n| sort count desc\n| limit 100' },
  { name: 'New Process - First Time Seen', tag: 'Endpoint', query: 'dataset = xdr_data\n| filter event_type = "process_create"\n| dedup actor_process_image_name\n| fields agent_hostname, actor_process_image_name, actor_process_image_path\n| limit 200' },
  { name: 'Lateral Movement Hunt', tag: 'Lateral Movement', query: '// Hunt: Lateral Movement via SMB/RDP\ndataset = network_story\n| filter dst_port in [445, 139, 3389, 22]\n| dedup src_ip, dst_ip\n| stats count by src_ip\n| filter count > 3\n| sort count desc' },
]

const DATASETS = [
  { name: 'xdr_data', desc: 'XSIAM Agent telemetry', fields: [
    { name: 'actor_process_image_name', type: 'string' },
    { name: 'actor_process_image_path', type: 'string' },
    { name: 'actor_process_command_line', type: 'string' },
    { name: 'action_local_ip', type: 'string' },
    { name: 'action_remote_ip', type: 'string' },
    { name: 'action_remote_port', type: 'integer' },
    { name: 'action_file_sha256', type: 'string' },
    { name: 'action_file_name', type: 'string' },
    { name: 'event_type', type: 'string' },
    { name: 'event_timestamp', type: 'timestamp' },
    { name: 'agent_hostname', type: 'string' },
    { name: 'agent_ip_addresses', type: 'string' },
  ]},
  { name: 'network_story', desc: 'Network flow events', fields: [
    { name: 'src_ip', type: 'string' },
    { name: 'dst_ip', type: 'string' },
    { name: 'dst_port', type: 'integer' },
    { name: 'protocol', type: 'string' },
    { name: 'bytes_sent', type: 'integer' },
    { name: 'bytes_received', type: 'integer' },
    { name: 'action', type: 'string' },
    { name: '_time', type: 'timestamp' },
  ]},
  { name: 'cloud_audit_log', desc: 'Cloud provider audit logs', fields: [
    { name: '_time', type: 'timestamp' },
    { name: 'cloud_provider', type: 'string' },
    { name: 'event_name', type: 'string' },
    { name: 'user_identity', type: 'string' },
    { name: 'source_ip', type: 'string' },
    { name: 'resource_name', type: 'string' },
    { name: 'region', type: 'string' },
  ]},
  { name: 'identity_analytics_profile', desc: 'User & entity behavior', fields: [
    { name: 'user_name', type: 'string' },
    { name: 'risk_score', type: 'number' },
    { name: 'risk_level', type: 'string' },
    { name: 'last_activity', type: 'timestamp' },
    { name: 'authentication_count', type: 'integer' },
    { name: 'failed_logins', type: 'integer' },
    { name: 'department', type: 'string' },
  ]},
  { name: 'email_story', desc: 'Email security events', fields: [
    { name: '_time', type: 'timestamp' },
    { name: 'sender', type: 'string' },
    { name: 'recipient', type: 'string' },
    { name: 'subject', type: 'string' },
    { name: 'verdict', type: 'string' },
    { name: 'attachment_sha256', type: 'string' },
    { name: 'url_count', type: 'integer' },
  ]},
]

const XQL_STAGES = ['dataset', '| filter', '| fields', '| sort', '| limit', '| dedup', '| comp', '| join', '| union', '| alter', '| arrayexpand', '| tstats']
const XQL_FUNCTIONS = ['count()', 'sum()', 'avg()', 'min()', 'max()', 'now()', 'to_epoch()', 'coalesce()', 'if()', 'concat()']
const XQL_OPERATORS = ['=', '!=', '>', '<', '>=', '<=', 'in', 'not in', 'contains', 'startswith', 'endswith', 'and', 'or', 'not']

export default function QueryCenter() {
  const [tabs, setTabs] = useState<QueryTab[]>([
    { id: '1', name: SAMPLE_QUERIES[0].name, query: SAMPLE_QUERIES[0].query },
    { id: '2', name: SAMPLE_QUERIES[5].name, query: SAMPLE_QUERIES[5].query },
  ])
  const [activeTab, setActiveTab] = useState('1')
  const [results, set查询结果] = useState<any[]>([])
  const [columns, setColumns] = useState<string[]>([])
  const [loading, setLoading] = useState(false)
  const [error, set错误] = useState('')
  const [elapsed, setElapsed] = useState<number | null>(null)
  const [expandedDatasets, setExpandedDatasets] = useState<Set<string>>(new Set(['xdr_data']))
  const [savedSearch, setSavedSearch] = useState('')
  const [timeRange, setTimeRange] = useState('24h')
  const textareaRef = useRef<HTMLTextAreaElement>(null)

  const currentTab = tabs.find(t => t.id === activeTab)

  function updateQuery(query: string) {
    setTabs(prev => prev.map(t => t.id === activeTab ? { ...t, query } : t))
  }

  function addTab() {
    const id = Date.now().toString()
    setTabs(prev => [...prev, { id, name: `Query ${prev.length + 1}`, query: 'dataset = xdr_data\n| filter event_timestamp > now()-1h\n| limit 100' }])
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

  async function runQuery() {
    if (!currentTab) return
    setLoading(true)
    set错误('')
    set查询结果([])
    const t0 = Date.now()
    try {
      const rangeSeconds: Record<string, number> = { '24h': 86400, '7d': 604800, '30d': 2592000 }
      const nowSec = Math.floor(Date.now() / 1000)
      const fromSec = nowSec - (rangeSeconds[timeRange] ?? 86400)
      const res = await api.get('/logs/query', { params: { q: currentTab.query, limit: 100, from_ts: fromSec, to_ts: nowSec } })
      const rows = res.data.data ?? []
      set查询结果(rows)
      setColumns(rows.length > 0 ? Object.keys(rows[0]) : [])
      setElapsed(Date.now() - t0)
    } catch (e: any) {
      set错误(e.response?.data?.error?.message ?? e.message ?? 'Query failed')
    } finally {
      setLoading(false)
    }
  }

  const queryLines = (currentTab?.query ?? '').split('\n')

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      {/* Query tabs bar — no page header, just tabs at top */}
      <div style={{
        display: 'flex', alignItems: 'center',
        borderBottom: '1px solid var(--border)',
        background: 'var(--bg-sidebar)', flexShrink: 0,
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
              borderRadius: 3, fontSize: 10, color: 'var(--text-muted)',
              background: 'none',
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
          <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>XQL · ArangoDB</span>
        </div>
      </div>

      {/* 3-column body */}
      <div style={{ flex: 1, display: 'flex', overflow: 'hidden', minHeight: 0 }}>

        {/* LEFT: Saved queries + Datasets (240px) */}
        <div style={{
          width: 240, flexShrink: 0, borderRight: '1px solid var(--border)',
          display: 'flex', flexDirection: 'column', overflow: 'hidden',
          background: 'var(--bg-sidebar)',
        }}>
          {/* Saved queries panel */}
          <div style={{ flexShrink: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '10px 14px 6px' }}>
              <span style={{ fontSize: 10, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5 }}>Saved Queries</span>
              <button style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 14, lineHeight: 1 }} onClick={addTab}>+</button>
            </div>
            <input
              value={savedSearch}
              onChange={e => setSavedSearch(e.target.value)}
              placeholder="Search…"
              style={{
                margin: '0 10px 6px', display: 'block', width: 'calc(100% - 20px)',
                background: 'var(--bg-card)', border: '1px solid var(--border-light)',
                borderRadius: 4, padding: '4px 9px', color: 'var(--text-primary)',
                fontSize: 11.5, outline: 'none',
              }}
            />
            <div style={{ maxHeight: 200, overflowY: 'auto' }}>
              {SAMPLE_QUERIES.filter(sq => !savedSearch || sq.name.toLowerCase().includes(savedSearch.toLowerCase())).map(sq => (
                <div
                  key={sq.name}
                  onClick={() => updateQuery(sq.query)}
                  style={{
                    padding: '7px 14px', fontSize: 11.5, cursor: 'pointer',
                    borderLeft: `2px solid ${currentTab?.query === sq.query ? 'var(--accent-orange)' : 'transparent'}`,
                    background: currentTab?.query === sq.query ? 'rgba(250,88,45,.05)' : 'none',
                    color: 'var(--text-secondary)', transition: 'background .1s',
                  }}
                  onMouseEnter={e => { if (currentTab?.query !== sq.query) e.currentTarget.style.background = 'rgba(255,255,255,.03)' }}
                  onMouseLeave={e => { e.currentTarget.style.background = currentTab?.query === sq.query ? 'rgba(250,88,45,.05)' : 'none' }}
                >
                  <div style={{ fontWeight: 500, marginBottom: 3 }}>{sq.name}</div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                    <span style={{ fontSize: 9.5, padding: '1px 5px', background: 'rgba(250,88,45,.12)', color: 'var(--accent-orange)', borderRadius: 3 }}>{sq.tag}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div style={{ height: 1, background: 'var(--border)', margin: '4px 0' }} />

          {/* Datasets panel */}
          <div style={{ flex: 1, overflowY: 'auto' }}>
            <div style={{ padding: '8px 14px 6px', fontSize: 10, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5 }}>Datasets</div>
            {DATASETS.map(ds => (
              <div key={ds.name}>
                <div
                  onClick={() => setExpandedDatasets(prev => {
                    const next = new Set(prev)
                    if (next.has(ds.name)) next.delete(ds.name); else next.add(ds.name)
                    return next
                  })}
                  style={{
                    display: 'flex', alignItems: 'flex-start', gap: 6, padding: '7px 14px',
                    cursor: 'pointer', fontSize: 11.5, color: 'var(--text-secondary)',
                    background: 'none', transition: 'background .1s',
                  }}
                  onMouseEnter={e => (e.currentTarget.style.background = 'rgba(255,255,255,.03)')}
                  onMouseLeave={e => (e.currentTarget.style.background = 'none')}
                >
                  <span style={{ fontSize: 9, color: 'var(--text-muted)', transform: expandedDatasets.has(ds.name) ? 'rotate(90deg)' : 'none', display: 'inline-block', transition: 'transform .15s', marginTop: 2, flexShrink: 0 }}>▶</span>
                  <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="#4fa3e0" strokeWidth="1.8" style={{ flexShrink: 0, marginTop: 1 }}>
                    <ellipse cx="12" cy="5" rx="9" ry="3"/><path d="M21 12c0 1.66-4 3-9 3s-9-1.34-9-3"/><path d="M3 5v14c0 1.66 4 3 9 3s9-1.34 9-3V5"/>
                  </svg>
                  <div>
                    <div style={{ fontWeight: 500 }}>{ds.name}</div>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 1 }}>{ds.desc}</div>
                  </div>
                </div>
                {expandedDatasets.has(ds.name) && (
                  <div style={{ paddingLeft: 28, background: 'rgba(0,0,0,.15)' }}>
                    {ds.fields.map(f => (
                      <div key={f.name} style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '3px 14px', fontSize: 10.5 }}>
                        <span style={{ color: 'var(--text-muted)', fontSize: 9, width: 48, flexShrink: 0 }}>{f.type}</span>
                        <span
                          style={{ color: '#7ec8e3', fontFamily: 'monospace', cursor: 'pointer' }}
                          onClick={() => updateQuery((currentTab?.query ?? '') + f.name)}
                          title="Click to insert"
                        >{f.name}</span>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* CENTER: Editor + 查询结果 (flex:1) */}
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', minWidth: 0, overflow: 'hidden' }}>
          {/* Editor toolbar */}
          <div style={{
            display: 'flex', alignItems: 'center', gap: 8, padding: '6px 12px',
            borderBottom: '1px solid var(--border)', background: 'var(--bg-secondary)', flexShrink: 0,
          }}>
            <select className="filter-select" style={{ fontSize: 11 }} value={timeRange} onChange={e => setTimeRange(e.target.value)}>
              <option value="24h">Last 24H</option>
              <option value="7d">Last 7 Days</option>
              <option value="30d">Last 30 Days</option>
            </select>
            <div style={{ flex: 1 }} />
            <button className="btn-secondary" style={{ fontSize: 11, padding: '4px 10px' }} onClick={() => {
              const name = prompt('Save query as:', currentTab?.name ?? 'My Query')
              if (!name || !currentTab) return
              setTabs(prev => prev.map(t => t.id === activeTab ? { ...t, name } : t))
            }}>保存</button>
            <button className="btn-secondary" style={{ fontSize: 11, padding: '4px 10px' }} onClick={() => {
              const cron = prompt('Schedule this query (cron expression, e.g. "0 */6 * * *"):')
              if (cron) alert(`Scheduled: "${currentTab?.name}" — ${cron}\n(In production this would register a cron job)`)
            }}>
              <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" style={{ marginRight: 4, verticalAlign: 'middle' }}>
                <circle cx="12" cy="12" r="10"/><polyline points="12 6 12 12 16 14"/>
              </svg>
              Schedule
            </button>
            <button
              className="btn-primary"
              style={{ padding: '4px 18px', fontSize: 12 }}
              onClick={runQuery}
              disabled={loading}
            >
              {loading ? '⟳' : '▶'} {loading ? 'Running…' : 'Run'}
            </button>
            <span style={{ fontSize: 10, color: 'var(--text-muted)', marginLeft: 2 }}>Ctrl+Enter</span>
          </div>

          {/* XQL Editor with line numbers */}
          <div style={{ position: 'relative', flexShrink: 0, background: 'var(--bg-primary)' }}>
            {/* Line numbers overlay */}
            <pre style={{
              position: 'absolute', top: 0, left: 0,
              width: 40, height: '100%',
              background: 'var(--bg-secondary)', borderRight: '1px solid var(--border)',
              color: 'var(--text-muted)', fontSize: 12, lineHeight: '1.7em',
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
              onKeyDown={e => {
                if (e.ctrlKey && e.key === 'Enter') { e.preventDefault(); runQuery() }
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
              }}
              style={{
                width: '100%', minHeight: 140, maxHeight: 260,
                resize: 'vertical', paddingLeft: 52, paddingTop: 12, paddingBottom: 12, paddingRight: 16,
                background: 'var(--bg-primary)', color: '#7ec8e3',
                border: 'none', outline: 'none',
                fontFamily: 'Consolas,"JetBrains Mono",monospace',
                fontSize: 12.5, lineHeight: '1.7em',
              }}
              spellCheck={false}
            />
          </div>

          {/* 查询结果 area */}
          <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', borderTop: '2px solid var(--border)' }}>
            {/* Result stats bar */}
            <div style={{
              display: 'flex', alignItems: 'center', gap: 16, padding: '5px 14px',
              borderBottom: '1px solid var(--border)', background: 'var(--bg-secondary)', flexShrink: 0,
            }}>
              {error ? (
                <span style={{ fontSize: 12, color: 'var(--critical)' }}>错误: {error}</span>
              ) : (
                <>
                  <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                    Rows: <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{loading ? '…' : results.length}</span>
                  </span>
                  {elapsed !== null && !loading && (
                    <>
                      <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                        Elapsed: <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>{elapsed}ms</span>
                      </span>
                      <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
                        Scanned: <span style={{ color: 'var(--text-primary)', fontWeight: 600 }}>—</span>
                      </span>
                    </>
                  )}
                </>
              )}
              {results.length > 0 && (
                <button className="btn-secondary" style={{ marginLeft: 'auto', fontSize: 10, padding: '2px 8px' }} onClick={() => {
                  const rows = [columns.join(',')]
                  results.forEach(r => rows.push(columns.map(c => String(r[c] ?? '')).join(',')))
                  const blob = new Blob([rows.join('\n')], { type: 'text/csv' })
                  const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `query_results_${Date.now()}.csv`; a.click()
                }}>
                  Export CSV
                </button>
              )}
            </div>

            {/* 查询结果 table */}
            <div style={{ flex: 1, overflowY: 'auto' }}>
              {results.length > 0 ? (
                <table className="data-table">
                  <thead>
                    <tr>{columns.map(c => <th key={c}>{c}</th>)}</tr>
                  </thead>
                  <tbody>
                    {results.map((row, i) => (
                      <tr key={i}>
                        {columns.map(c => (
                          <td key={c} style={{ fontFamily: typeof row[c] === 'number' ? 'monospace' : undefined, fontSize: 11.5 }}>
                            {row[c] === null || row[c] === undefined
                              ? <span style={{ color: 'var(--text-muted)' }}>null</span>
                              : typeof row[c] === 'object'
                                ? <span style={{ fontFamily: 'monospace', color: '#7ec8e3' }}>{JSON.stringify(row[c])}</span>
                                : String(row[c])}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              ) : (
                <div style={{ padding: 32, textAlign: 'center', color: 'var(--text-muted)', fontSize: 12 }}>
                  {loading ? 'Executing query…' : error ? '' : 'Run a query to see results'}
                </div>
              )}
            </div>
          </div>
        </div>

        {/* RIGHT: XQL Reference (300px) */}
        <div style={{
          width: 300, flexShrink: 0, borderLeft: '1px solid var(--border)',
          display: 'flex', flexDirection: 'column', overflow: 'hidden',
          background: 'var(--bg-sidebar)',
        }}>
          <div style={{ padding: '10px 14px 6px', fontSize: 10, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.5, flexShrink: 0 }}>
            XQL Reference
          </div>
          <div style={{ flex: 1, overflowY: 'auto', padding: '0 0 12px' }}>
            {/* Stages */}
            <div style={{ padding: '6px 14px 4px', fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.4, marginTop: 4 }}>Stages</div>
            {XQL_STAGES.map(s => (
              <div key={s} style={{
                padding: '4px 14px', fontSize: 12, fontFamily: 'Consolas,"JetBrains Mono",monospace',
                color: '#c792ea', cursor: 'pointer',
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
                color: '#82aaff', cursor: 'pointer',
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

            {/* Pro tip */}
            <div style={{
              margin: '8px 14px', padding: '10px 12px',
              background: 'rgba(79,163,224,.06)', border: '1px solid rgba(79,163,224,.2)',
              borderRadius: 6, fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.6,
            }}>
              <div style={{ fontWeight: 600, color: '#4fa3e0', marginBottom: 4 }}>Pro Tip</div>
              Use <code style={{ background: 'rgba(255,255,255,.08)', padding: '1px 4px', borderRadius: 3, fontFamily: 'monospace', fontSize: 10.5 }}>// comment</code> to annotate your queries. Press <code style={{ background: 'rgba(255,255,255,.08)', padding: '1px 4px', borderRadius: 3, fontFamily: 'monospace', fontSize: 10.5 }}>Ctrl+Enter</code> to run.
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}
