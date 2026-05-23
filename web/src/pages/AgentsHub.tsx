import { useState, useRef, useEffect } from 'react'
import PageHeader from '@/components/PageHeader'

const CATEGORY_COLORS: Record<string, { gradient: string; iconBg: string }> = {
  Agentic:   { gradient: 'linear-gradient(90deg,#1565c0,#0078d4)', iconBg: 'rgba(0,120,212,.15)' },
  detection: { gradient: 'linear-gradient(90deg,#c0392b,#e53935)', iconBg: 'rgba(217,64,64,.12)' },
  cloud:     { gradient: 'linear-gradient(90deg,#0077b6,#023e8a)', iconBg: 'rgba(0,119,182,.13)' },
  automation:{ gradient: 'linear-gradient(90deg,#1976d2,#00838f)', iconBg: 'rgba(25,118,210,.12)' },
  identity:  { gradient: 'linear-gradient(90deg,#4a5faa,#2255c0)', iconBg: 'rgba(74,95,170,.14)' },
}

const AI_AGENTS = [
  {
    id: 'case-investigation',
    name: 'Case Investigation Agent',
    category: 'Agentic',
    icon: '🔎',
    active: true,
    desc: 'Autonomously queries telemetry and threat intelligence to produce comprehensive AI case summaries. Replaces 45-minute manual investigation with seconds.',
    stats: [{ label: 'Today', value: '47 cases' }, { label: 'Avg time', value: '12s' }],
    cta: 'View Activity',
  },
  {
    id: 'cloud-posture',
    name: '云 Posture Agent',
    category: 'cloud',
    icon: '☁',
    active: true,
    desc: 'Instantly recognizes cloud misconfigurations and autonomously applies approved fixes. Closes security gaps before external scanners detect them.',
    stats: [{ label: 'Remediations', value: '8 today' }, { label: 'MTTR', value: '23s' }],
    cta: 'View Activity',
  },
  {
    id: 'automation-engineer',
    name: 'Automation Engineer Agent',
    category: 'automation',
    icon: '⚙',
    active: true,
    desc: 'Converts natural language requests into production-ready playbooks and automation scripts. "Build a workflow that isolates any host showing brute-force signs."',
    stats: [{ label: 'Playbooks built', value: '3 today' }],
    cta: 'Try It',
  },
  {
    id: 'alert-triage',
    name: 'Alert Triage Agent',
    category: 'detection',
    icon: '🎯',
    active: true,
    desc: 'Reviews 100% of alerts autonomously. Ensures low-priority signals — often the first signs of a sophisticated breach —?are never ignored.',
    stats: [{ label: 'Alerts reviewed', value: '19,847' }, { label: 'Auto-closed', value: '99.2%' }],
    cta: 'View Activity',
  },
  {
    id: 'identity-risk',
    name: '身份 Risk Agent',
    category: 'identity',
    icon: '👤',
    active: false,
    desc: 'Continuously monitors user behavior and identity signals. Automatically adjusts risk scores and triggers response actions for compromised accounts.',
    stats: [{ label: 'Users monitored', value: '1,847' }],
    cta: 'Enable',
  },
]

const MCP_INTEGRATIONS = [
  { id: 'servicenow', name: 'ServiceNow ITSM', desc: 'Ticket creation & updates', icon: '🔗', connected: true },
  { id: 'slack',      name: 'Slack',           desc: 'Alert notifications',       icon: '💬', connected: true },
  { id: 'teams',      name: 'Microsoft Teams', desc: 'SOC channel integration',   icon: '📧', connected: true },
  { id: 'jira',       name: 'Jira',            desc: 'Security issue tracking',   icon: '🐛', connected: false },
  { id: 'aws',        name: 'AWS Security Hub',desc: '云 findings',            icon: '☁', connected: false },
]

const CHAT_DEMO = [
  { role: 'Agent', text: "I'm your autonomous SOC AI. Unlike Copilot, I can take actions on your behalf — investigating incidents, running queries, and executing playbooks —?with your approval. What would you like me to do?" },
  { role: 'user',  text: 'Investigate INC-001 and tell me if the data exfiltration was successful' },
  { role: 'Agent', text: "I'm investigating INC-001 now...\n\n**Actions taken:**\n✅ Queried XSIAM telemetry for rclone.exe activity\n✅ Cross-referenced 198.51.100.42 with threat intel (Unit 42: confirmed C2)\n✅ Analyzed network flows: 8.3 GB transferred in 4 minutes\n✅ Checked file system for staging location: C:\\Temp\\financial_data_2024.zip (8.3 GB)\n\n**Conclusion: Exfiltration was SUCCESSFUL.** 8.3 GB of data was transferred to a confirmed C2 server before the endpoint was isolated at 09:44:01 UTC.\n\nShall I draft an incident report and notify the security manager?" },
  { role: 'user',  text: 'Yes, draft the report' },
  { role: 'Agent', text: '⟳ Drafting incident report...', pending: true },
]

const QUICK_PROMPTS = [
  'Summarize today\'s critical incidents',
  'Find all lateral movement in last 24h',
  'Run IOC hunt across all endpoints',
  'Generate executive security brief',
  'Identify unpatched critical CVEs',
]

const ACTIONS_LIBRARY = [
  { name: 'Isolate 终端',    icon: '🔒', category: '终端', desc: 'Quarantine a host from network' },
  { name: 'Kill Process',        icon: '⛔', category: '终端', desc: 'Terminate a running process' },
  { name: 'Run Script',          icon: '📜', category: '终端', desc: 'Execute PowerShell or shell script' },
  { name: 'Collect Forensics',   icon: '🔬', category: '终端', desc: 'Gather memory and disk artifacts' },
  { name: 'Block IP',            icon: '🚫', category: '网络',  desc: 'Add IP to block list via firewall' },
  { name: 'Block Domain',        icon: '🌐', category: '网络',  desc: 'Sink-hole a malicious domain' },
  { name: 'Block URL',           icon: '🔗', category: '网络',  desc: 'Block URL at proxy layer' },
  { name: 'Disable AD Account',  icon: '👤', category: '身份', desc: 'Disable user in Active Directory' },
  { name: 'Reset Password',      icon: '🔑', category: '身份', desc: 'Force password reset for user' },
  { name: 'Revoke Session',      icon: '🎫', category: '身份', desc: 'Invalidate all active tokens' },
  { name: 'Create ITSM Ticket',  icon: '📋', category: 'ITSM',     desc: 'Open ServiceNow/Jira incident' },
  { name: 'Send Notification',   icon: '📣', category: 'ITSM',     desc: 'Slack/Teams/email alert' },
]

// —────────────────────—────────────────────—──────────────────── Tab components —────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────—────────────────────

function AgentsTab({ onSwitchTab }: { onSwitchTab: (tab: TabId) => void }) {
  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>
      {/* Stats banner */}
      <div style={{
        display: 'flex', gap: 12, marginBottom: 20, padding: '14px 18px',
        background: 'rgba(0,120,212,.06)', border: '1px solid rgba(0,120,212,.2)',
        borderRadius: 8, alignItems: 'center',
      }}>
        <div style={{ fontSize: 22 }}>✦</div>
        <div>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--accent-blue)' }}>Agentic AI Workforce Active</div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            Your AI Agents reviewed <strong style={{ color: 'var(--text-primary)' }}>19,847 alerts</strong> today
            · <strong style={{ color: 'var(--accent-blue)' }}>99.2% auto-resolved</strong>
            · <strong style={{ color: 'var(--text-primary)' }}>4 Agents running</strong>
          </div>
        </div>
        <div style={{ marginLeft: 'auto' }}>
          <button className="btn-secondary" style={{ fontSize: 11 }} onClick={() => onSwitchTab('assistant')}>View Activity Log</button>
        </div>
      </div>

      {/* Agent card grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16 }}>
        {AI_AGENTS.map(Agent => {
          const colors = CATEGORY_COLORS[Agent.category] ?? CATEGORY_COLORS.Agentic
          return (
            <div key={Agent.id} style={{
              background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 10,
              padding: 20, cursor: 'pointer', position: 'relative', overflow: 'hidden',
              transition: 'all .2s',
            }}
              onMouseEnter={e => { (e.currentTarget as HTMLDivElement).style.borderColor = 'var(--border-light)' }}
              onMouseLeave={e => { (e.currentTarget as HTMLDivElement).style.borderColor = 'var(--border)' }}
            >
              {/* Top stripe */}
              <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 3, background: colors.gradient }} />

              <div style={{ width: 48, height: 48, borderRadius: 10, background: colors.iconBg, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 22, marginBottom: 12 }}>
                {Agent.icon}
              </div>
              <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 4 }}>{Agent.name}</div>
              <div style={{ marginBottom: 8, display: 'flex', alignItems: 'center', gap: 5 }}>
                <span style={{
                  width: 8, height: 8, borderRadius: '50%', display: 'inline-block',
                  background: Agent.active ? 'var(--accent-green)' : '#546e7a',
                  boxShadow: Agent.active ? '0 0 6px #43a047' : 'none',
                }} />
                <span style={{ fontSize: 11, color: Agent.active ? 'var(--accent-blue)' : 'var(--text-muted)' }}>
                  {Agent.active ? 'Active' : 'Idle'}
                </span>
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.5, marginBottom: 12 }}>{Agent.desc}</div>
              <div style={{ display: 'flex', gap: 12, fontSize: 11, color: 'var(--text-secondary)', marginBottom: 12 }}>
                {Agent.stats.map(s => (
                  <span key={s.label}>{s.label}: <strong style={{ color: 'var(--text-primary)' }}>{s.value}</strong></span>
                ))}
              </div>
              <div style={{ display: 'flex', gap: 6 }}>
                <button className="btn-secondary" style={{ fontSize: 11 }} onClick={() => alert(`配置 ${Agent.name}\n\nSettings: thresholds, playbook triggers, approval requirements, output destinations.`)}>配置</button>
                <button className="btn-primary" style={{ fontSize: 11 }} onClick={() => {
                  if (Agent.cta === 'Enable') { alert(`Enabling ${Agent.name}...\n\nThe Agent will begin monitoring in the next few minutes.`) }
                  else { onSwitchTab('assistant') }
                }}>{Agent.cta}</button>
              </div>
            </div>
          )
        })}

        {/* Build Custom Agent card */}
        <div style={{
          background: 'var(--bg-card)', border: '2px dashed var(--border)', borderRadius: 10,
          padding: 20, cursor: 'pointer', display: 'flex', flexDirection: 'column',
          alignItems: 'center', justifyContent: 'center', textAlign: 'center', minHeight: 200,
        }}>
          <div style={{ fontSize: 32, marginBottom: 10, color: 'var(--text-muted)' }}>+</div>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>Build Custom Agent</div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>Use the Agent Builder to create<br />specialized AI Agents</div>
          <button className="btn-primary" style={{ marginTop: 12, fontSize: 11 }} onClick={() => alert('Agent Builder\n\nDefine Agent purpose, data sources, decision rules, and action capabilities.\n(Agent Builder UI coming soon)')}>+ Build Agent</button>
        </div>
      </div>
    </div>
  )
}

function AssistantTab() {
  const [input, setInput] = useState('')
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [])

  return (
    <div style={{ flex: 1, display: 'flex', gap: 20, overflow: 'hidden', padding: 20 }}>
      {/* Chat panel */}
      <div style={{
        flex: 1, background: 'var(--bg-card)', border: '1px solid var(--border)',
        borderRadius: 10, display: 'flex', flexDirection: 'column', overflow: 'hidden',
      }}>
        {/* Chat header */}
        <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ width: 32, height: 32, borderRadius: '50%', background: 'linear-gradient(135deg,#1565c0,#0078d4)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 16 }}>✦</div>
          <div>
            <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--accent-blue)' }}>XSIAM AI Agent助手</div>
            <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>Powered by XSIAM 3.x · All actions are audited</div>
          </div>
          <div style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--text-muted)' }}>Compare with Cortex Assistant ↗</div>
        </div>

        {/* Messages */}
        <div style={{ flex: 1, overflowY: 'auto', padding: '20px 18px', display: 'flex', flexDirection: 'column', gap: 10 }}>
          {CHAT_DEMO.map((msg, i) => (
            <div key={i} style={{
              padding: '10px 14px', borderRadius: 8, fontSize: 12.5, lineHeight: 1.5, maxWidth: '90%',
              ...(msg.role === 'user'
                ? { background: 'rgba(0,120,212,.10)', border: '1px solid rgba(0,120,212,.20)', marginLeft: 'auto', textAlign: 'right' }
                : { background: 'rgba(0,120,212,.12)', border: '1px solid rgba(0,120,212,.25)', color: (msg as any).pending ? 'var(--accent-blue)' : 'var(--text-primary)' }
              ),
            }}>
              {msg.role === 'Agent' && <div style={{ fontSize: 10, color: 'var(--accent-blue)', marginBottom: 4, fontWeight: 600 }}>✦ AGENTIC ASSISTANT</div>}
              <div style={{ whiteSpace: 'pre-line' }}>{msg.text}</div>
            </div>
          ))}
          <div ref={bottomRef} />
        </div>

        {/* Input */}
        <div style={{ padding: '12px 18px', borderTop: '1px solid var(--border)', display: 'flex', gap: 8 }}>
          <input
            className="filter-input"
            style={{ flex: 1, borderRadius: 8, padding: '10px 14px', fontSize: 12.5 }}
            placeholder="Ask the AI Agent助手 to investigate, query, or take action..."
            value={input}
            onChange={e => setInput(e.target.value)}
            onKeyDown={e => { if (e.key === 'Enter' && input.trim()) { alert(`[Demo] AI Agent助手 received: "${input}"\n\nIn production this would trigger an AI-powered investigation.`); setInput('') } }}
          />
          <button className="btn-primary" style={{ fontSize: 12, padding: '8px 18px' }} onClick={() => { if (!input.trim()) return; alert('[Demo] AI Agent助手 received: "' + input + '"\n\nIn production this would trigger an AI-powered investigation.'); setInput('') }}>发送</button>
        </div>
      </div>

      {/* Sidebar */}
      <div style={{ width: 240, flexShrink: 0, overflowY: 'auto' }}>
        <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', marginBottom: 10 }}>快捷操作</div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, marginBottom: 20 }}>
          {QUICK_PROMPTS.map(p => (
            <div key={p} onClick={() => setInput(p)} style={{
              fontSize: 11.5, padding: '8px 12px', background: 'var(--bg-card)', border: '1px solid var(--border)',
              borderRadius: 6, cursor: 'pointer', color: 'var(--text-secondary)', lineHeight: 1.4,
            }}
              onMouseEnter={e => { (e.currentTarget as HTMLDivElement).style.borderColor = 'var(--accent-orange)' }}
              onMouseLeave={e => { (e.currentTarget as HTMLDivElement).style.borderColor = 'var(--border)' }}
            >
              {p}
            </div>
          ))}
        </div>
        <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', marginBottom: 10 }}>CAPABILITIES</div>
        <div style={{ fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.9 }}>
          {['Run XQL queries', 'Investigate incidents', 'Execute playbooks', 'Isolate endpoints', 'Block indicators', 'Generate reports', 'Correlate threat intel', 'Draft notifications'].map(c => (
            <div key={c}>—?{c}</div>
          ))}
        </div>
      </div>
    </div>
  )
}

function McpTab() {
  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>
      <div style={{ marginBottom: 14, fontSize: 12, color: 'var(--text-secondary)' }}>
        Connect external tools via Model Context Protocol (MCP) to extend Agent capabilities
      </div>
      <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
        <button className="btn-primary" style={{ fontSize: 11 }} onClick={() => {
          const name = prompt('MCP Integration name (e.g. PagerDuty, Zoom):')
          if (name) alert(`MCP Integration "${name}" added.\n\n配置 the endpoint URL and authentication in the integration settings.`)
        }}>+ Add MCP Integration</button>
        <button className="btn-secondary" style={{ fontSize: 11 }} onClick={() => alert('Cortex MCP Server\n\nDownload and install the Cortex MCP server package to enable Agent tool use against your internal systems.')}>Install Cortex MCP Server</button>
      </div>
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 12 }}>
        {MCP_INTEGRATIONS.map(m => (
          <div key={m.id} style={{
            padding: '12px 14px', background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: 6, display: 'flex', alignItems: 'center', gap: 10,
          }}>
            <div style={{ width: 32, height: 32, borderRadius: 6, background: 'rgba(79,163,224,.12)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 16, flexShrink: 0 }}>
              {m.icon}
            </div>
            <div>
              <div style={{ fontSize: 12.5, fontWeight: 500 }}>{m.name}</div>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>{m.desc}</div>
            </div>
            <span style={{ marginLeft: 'auto', fontSize: 10, color: m.connected ? 'var(--accent-blue)' : 'var(--text-muted)', flexShrink: 0 }}>
              {m.connected ? '—?Connected' : '—?Not connected'}
            </span>
          </div>
        ))}
        {/* Add custom */}
        <div style={{
          padding: '12px 14px', background: 'var(--bg-card)', border: '2px dashed var(--border)',
          borderRadius: 6, display: 'flex', alignItems: 'center', justifyContent: 'center',
          cursor: 'pointer', color: 'var(--text-muted)', fontSize: 12,
        }}>
          + Add Custom MCP
        </div>
      </div>
    </div>
  )
}

function ActionsLibraryTab() {
  const categories = Array.from(new Set(ACTIONS_LIBRARY.map(a => a.category)))
  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>
      <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
        <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>Actions Agents can execute autonomously or with approval</div>
        <button className="btn-primary" style={{ fontSize: 11 }} onClick={() => {
          const name = prompt('Action name (e.g. Block User in Okta):')
          if (name) alert(`Action "${name}" registered.\n\nDefine input parameters, execution logic, and approval requirements in the action editor.`)
        }}>+ Register New Action</button>
      </div>
      {categories.map(cat => (
        <div key={cat} style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: 1 }}>{cat}</div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 10 }}>
            {ACTIONS_LIBRARY.filter(a => a.category === cat).map(action => (
              <div key={action.name} style={{
                padding: '12px 14px', background: 'var(--bg-card)', border: '1px solid var(--border)',
                borderRadius: 8, cursor: 'pointer',
              }}
                onMouseEnter={e => { (e.currentTarget as HTMLDivElement).style.borderColor = 'var(--border-light)' }}
                onMouseLeave={e => { (e.currentTarget as HTMLDivElement).style.borderColor = 'var(--border)' }}
              >
                <div style={{ fontSize: 20, marginBottom: 8 }}>{action.icon}</div>
                <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 4 }}>{action.name}</div>
                <div style={{ fontSize: 10.5, color: 'var(--text-muted)', lineHeight: 1.4 }}>{action.desc}</div>
              </div>
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}

// ────────────────────────────────────────────────────────────

type TabId = 'Agents' | 'assistant' | 'mcp' | 'actions'

const TABS: { id: TabId; label: string }[] = [
  { id: 'Agents',    label: 'AI Agents' },
  { id: 'assistant', label: 'AI Agent助手' },
  { id: 'mcp',       label: 'MCP Integrations' },
  { id: 'actions',   label: 'Actions Library' },
]

export default function AgentsHub() {
  const [activeTab, setActiveTab] = useState<TabId>('Agents')

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <PageHeader
        title="Agent 中心"
        subtitle="· Agentic AI workforce · XSIAM 3.x"
        actions={<>
          <button className="btn-secondary" style={{ fontSize: 12 }} onClick={() => setActiveTab('mcp')}>MCP Integrations</button>
          <button className="btn-secondary" style={{ fontSize: 12 }} onClick={() => setActiveTab('actions')}>Manage Actions</button>
          <button className="btn-primary" style={{ fontSize: 12 }} onClick={() => setActiveTab('Agents')}>+ Build Agent</button>
        </>}
      />

      {/* Tab bar */}
      <div className="tab-bar" style={{ flexShrink: 0 }}>
        {TABS.map(t => (
          <button key={t.id} className={`tab${activeTab === t.id ? ' active' : ''}`} onClick={() => setActiveTab(t.id)}>
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
        {activeTab === 'Agents'    && <AgentsTab onSwitchTab={setActiveTab} />}
        {activeTab === 'assistant' && <AssistantTab />}
        {activeTab === 'mcp'       && <McpTab />}
        {activeTab === 'actions'   && <ActionsLibraryTab />}
      </div>
    </div>
  )
}
