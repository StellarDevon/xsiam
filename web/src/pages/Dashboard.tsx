import { useEffect, useState } from 'react'
import api from '@/lib/api'
import { getUser } from '@/lib/auth'
import PageHeader from '@/components/PageHeader'

interface DashStats {
  total_alerts: number
  open_alerts: number
  total_incidents: number
  open_incidents: number
  total_assets: number
  total_vulns: number
  critical_vulns: number
  alerts_by_day: { date: string; count: number }[]
  alerts_by_severity: Record<string, number>
  incidents_by_status: Record<string, number>
  top_tactics: { tactic: string; count: number }[]
  mttr_hours: number
}

const SOURCES = [
  { label: '// NGFW', color: '#e05a2b' },
  { label: 'Google Cloud', color: '#4285f4' },
  { label: '▶ amazon webservices', color: '#ff9900' },
  { label: '◼ Azure', color: '#0078d4' },
  { label: '▶ Office 365', color: '#d83b01' },
  { label: 'okta', color: '#009bde' },
  { label: '▶ Proofpoint', color: '#1a73e8' },
  { label: '✦ PRISMA CLOUD', color: '#fa582d' },
  { label: '/ APACHE', color: '#d22128' },
]

export default function Dashboard() {
  const [stats, setStats] = useState<DashStats | null>(null)
  const [copilotOpen, setCopilotOpen] = useState(false)
  const [copilotInput, setCopilotInput] = useState('')
  const [copilotMessages, setCopilotMessages] = useState<{ role: 'user' | 'assistant'; text: string }[]>([])
  const [timeRange, setTimeRange] = useState<'24h' | '7d' | '30d'>('24h')
  const timeRangeLabels = { '24h': '近24小时', '7d': '近7天', '30d': '近30天' }
  const user = getUser()

  useEffect(() => {
    api.get('/dashboard/stats').then(r => setStats(r.data.data)).catch(() => {})
  }, [timeRange])

  const hour = new Date().getHours()
  const greeting = hour < 12 ? '早上好' : hour < 18 ? '下午好' : '晚上好'

  const openCases = stats?.open_incidents ?? 15
  const automated = Math.round(openCases * 0.85)
  const manual = openCases - automated + 6
  const resolved = automated + 6
  const issues = stats?.total_alerts ?? 2581

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden', position: 'relative' }}>
      {/* Agentic banner moved to global TopBar */}

      <PageHeader
        title="仪表盘"
        subtitle="· 概览"
        actions={<>
          <select
            className="filter-select"
            style={{ fontSize: 11 }}
            value={timeRange}
            onChange={e => setTimeRange(e.target.value as '24h' | '7d' | '30d')}
          >
            {(Object.entries(timeRangeLabels) as [string, string][]).map(([v, l]) => (
              <option key={v} value={v}>{l}</option>
            ))}
          </select>
          <button className="btn-secondary" style={{ fontSize: 11 }} onClick={() => setCopilotOpen(true)}>
            ✦ AI助手
          </button>
        </>}
      />

      {/* Title + Greeting */}
      <div style={{ padding: '10px 20px 0', flexShrink: 0 }}>
        <div style={{ fontSize: 18, fontWeight: 700, letterSpacing: -.3 }}>
          XSIAM 指挥中心 <span style={{ fontSize: 14, color: 'var(--text-muted)' }}>▶</span>
        </div>
        <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginTop: 2, fontStyle: 'italic' }}>
          {greeting}, {user?.display_name ?? 'Analyst'}
        </div>
      </div>

      {/* Sankey + Sources */}
      <div style={{ flex: 1, display: 'flex', overflow: 'hidden', minHeight: 0 }}>

        {/* Left sources column */}
        <div style={{
          width: 180, flexShrink: 0, borderRight: '1px solid var(--border)',
          display: 'flex', flexDirection: 'column', padding: '10px 0', overflow: 'hidden',
        }}>
          {/* Endpoints row */}
          <div style={{
            display: 'flex', alignItems: 'center', gap: 6,
            padding: '6px 14px', marginBottom: 4,
            borderBottom: '1px solid var(--border)',
          }}>
            <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)' }}>41.7K</span>
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="#8a8fa0" strokeWidth="1.8">
              <rect x="2" y="3" width="20" height="14" rx="2"/>
              <line x1="8" y1="21" x2="16" y2="21"/>
              <line x1="12" y1="17" x2="12" y2="21"/>
            </svg>
            <span style={{ fontSize: 9, fontWeight: 600, letterSpacing: 1, color: 'var(--text-muted)', textTransform: 'uppercase' }}>终端</span>
            <span style={{ width: 5, height: 5, borderRadius: '50%', background: '#0078d4', boxShadow: '0 0 4px #0078d4', marginLeft: 'auto', flexShrink: 0 }} />
          </div>

          {/* Vendor list */}
          <div style={{ flex: 1, overflowY: 'auto' }}>
            {SOURCES.map((src, i) => (
              <div key={i} style={{
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                padding: '5px 14px', fontSize: 10.5,
              }}>
                <span style={{ color: src.color, fontWeight: 600, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', maxWidth: 130 }}>{src.label}</span>
                <span style={{ width: 5, height: 5, borderRadius: '50%', background: src.color, opacity: 0.7, flexShrink: 0 }} />
              </div>
            ))}
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, padding: '5px 14px', fontSize: 10.5, color: 'var(--text-muted)' }}>
              <span style={{ width: 4, height: 4, borderRadius: '50%', background: 'var(--text-muted)' }} />
              <span>+68 个数据源</span>
            </div>
          </div>
        </div>

        {/* Sankey SVG */}
        <div style={{ flex: 1, display: 'flex', alignItems: 'center', justifyContent: 'center', overflow: 'hidden', padding: '0 0 0 0' }}>
          <svg viewBox="0 0 780 420" preserveAspectRatio="xMidYMid meet"
            style={{ width: '100%', height: '100%', maxHeight: 380 }}>
            <defs>
              <radialGradient id="circleGrad" cx="50%" cy="50%" r="50%">
                <stop offset="0%" stopColor="#0d1e3c"/>
                <stop offset="100%" stopColor="#060a14"/>
              </radialGradient>
              <filter id="glow" x="-30%" y="-30%" width="160%" height="160%">
                <feGaussianBlur stdDeviation="4" result="blur"/>
                <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
              </filter>
              <filter id="glow2" x="-50%" y="-50%" width="200%" height="200%">
                <feGaussianBlur stdDeviation="6" result="blur"/>
                <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
              </filter>
              <marker id="arr" markerWidth="6" markerHeight="6" refX="3" refY="3" orient="auto">
                <path d="M0,0 L6,3 L0,6 Z" fill="#0078d4" opacity="0.8"/>
              </marker>
            </defs>

            {/* Left funnel streams */}
            <path d="M0,15 C90,15 140,195 205,205" stroke="#6b8fa8" strokeWidth="22" fill="none" opacity="0.25"/>
            <path d="M0,65 C90,65 140,198 205,207" stroke="#e05a2b" strokeWidth="10" fill="none" opacity="0.3"/>
            <path d="M0,100 C90,100 140,200 205,208" stroke="#4285f4" strokeWidth="8" fill="none" opacity="0.3"/>
            <path d="M0,132 C90,132 140,202 205,209" stroke="#ff9900" strokeWidth="8" fill="none" opacity="0.3"/>
            <path d="M0,162 C90,162 140,204 205,210" stroke="#0078d4" strokeWidth="7" fill="none" opacity="0.3"/>
            <path d="M0,190 C90,190 140,206 205,211" stroke="#d83b01" strokeWidth="5" fill="none" opacity="0.3"/>
            <path d="M0,215 C90,215 140,208 205,212" stroke="#009bde" strokeWidth="5" fill="none" opacity="0.25"/>
            <path d="M0,238 C90,238 140,210 205,212" stroke="#1a73e8" strokeWidth="4" fill="none" opacity="0.25"/>
            <path d="M0,260 C90,258 140,212 205,213" stroke="#fa582d" strokeWidth="4" fill="none" opacity="0.25"/>
            <path d="M0,280 C90,275 140,214 205,213" stroke="#d22128" strokeWidth="3" fill="none" opacity="0.2"/>
            <path d="M0,298 C90,290 140,215 205,214" stroke="#6b7280" strokeWidth="2.5" fill="none" opacity="0.15"/>

            {/* 告警数 count */}
            <text x="210" y="196" fontSize="26" fontWeight="700" fill="white" fontFamily="'Segoe UI',sans-serif" opacity="0.95">{issues.toLocaleString()}</text>
            <text x="218" y="214" fontSize="10" fill="#9ea3b0" fontFamily="'Segoe UI',sans-serif" letterSpacing="1">ISSUES</text>
            {/* Spark dots */}
            <circle cx="260" cy="200" r="3" fill="#e53935" opacity="0.8"/>
            <circle cx="268" cy="192" r="2" fill="#ff9900" opacity="0.7"/>
            <circle cx="275" cy="205" r="2.5" fill="#4fa3e0" opacity="0.7"/>
            <circle cx="255" cy="210" r="2" fill="#0078d4" opacity="0.6"/>

            {/* Arrow to CASES */}
            <path d="M306,210 L345,210" stroke="#0078d4" strokeWidth="2" markerEnd="url(#arr)" opacity="0.7"/>

            {/* Center circle */}
            <circle cx="390" cy="210" r="110" fill="none" stroke="#0078d4" strokeWidth="0.5" opacity="0.12"/>
            <circle cx="390" cy="210" r="95" fill="none" stroke="#0078d4" strokeWidth="0.5" opacity="0.18"/>
            <circle cx="390" cy="210" r="82" fill="url(#circleGrad)" stroke="#0d2a4a" strokeWidth="1.5"/>
            <circle cx="390" cy="210" r="76" fill="none" stroke="#1a3d6e" strokeWidth="1" strokeDasharray="3,3" opacity="0.5"/>
            {/* Orbit dots */}
            <circle cx="390" cy="134" r="4" fill="#0078d4" opacity="0.9" filter="url(#glow)"/>
            <circle cx="448" cy="148" r="3.5" fill="#0078d4" opacity="0.7"/>
            <circle cx="466" cy="210" r="3" fill="#0078d4" opacity="0.5"/>
            <circle cx="448" cy="272" r="3.5" fill="#0078d4" opacity="0.7"/>
            <circle cx="390" cy="286" r="4" fill="#0078d4" opacity="0.9" filter="url(#glow)"/>
            <circle cx="332" cy="272" r="3.5" fill="#0078d4" opacity="0.7"/>
            <circle cx="314" cy="210" r="3" fill="#0078d4" opacity="0.5"/>
            <circle cx="332" cy="148" r="3.5" fill="#0078d4" opacity="0.7"/>
            {/* Alert dots */}
            <circle cx="420" cy="136" r="3" fill="#e53935" opacity="0.85" filter="url(#glow)"/>
            <circle cx="460" cy="170" r="2.5" fill="#ff6f00" opacity="0.7"/>
            <circle cx="360" cy="284" r="2.5" fill="#f9a825" opacity="0.7"/>
            {/* Inner arrows */}
            <path d="M350,210 L380,210" stroke="#0078d4" strokeWidth="1.5" opacity="0.4" markerEnd="url(#arr)"/>

            {/* Cases count right of circle */}
            <text x="488" y="202" fontSize="28" fontWeight="700" fill="white" fontFamily="'Segoe UI',sans-serif">{openCases + manual + 95}</text>
            <text x="492" y="219" fontSize="10" fill="#9ea3b0" fontFamily="'Segoe UI',sans-serif" letterSpacing="1">CASES</text>

            {/* Top branch: AUTOMATED */}
            <path d="M475,205 C530,205 545,145 590,135" stroke="#0078d4" strokeWidth="14" fill="none" opacity="0.55" filter="url(#glow2)"/>
            <circle cx="592" cy="133" r="16" fill="#0a1e3c" stroke="#0078d4" strokeWidth="1.5"/>
            <text x="592" y="138" textAnchor="middle" fontSize="13" fill="#0078d4">◯</text>
            <path d="M608,133 L720,133" stroke="#0078d4" strokeWidth="10" fill="none" opacity="0.7"/>
            <text x="635" y="116" fontSize="20" fontWeight="700" fill="white" fontFamily="'Segoe UI',sans-serif">{automated}</text>
            <text x="635" y="128" fontSize="9" fill="#9ea3b0" fontFamily="'Segoe UI',sans-serif" letterSpacing="1">AUTOMATED</text>
            <text x="730" y="122" fontSize="22" fontWeight="700" fill="white" fontFamily="'Segoe UI',sans-serif">{resolved}</text>
            <text x="730" y="136" fontSize="9" fill="#9ea3b0" fontFamily="'Segoe UI',sans-serif">RESOLVED</text>
            <text x="730" y="147" fontSize="9" fill="#9ea3b0" fontFamily="'Segoe UI',sans-serif">CASES</text>

            {/* Bottom branch: MANUAL */}
            <path d="M475,215 C530,215 545,285 590,295" stroke="#5a6a7a" strokeWidth="6" fill="none" opacity="0.4"/>
            <circle cx="592" cy="295" r="16" fill="#0d1520" stroke="#4a5568" strokeWidth="1.5"/>
            <text x="592" y="300" textAnchor="middle" fontSize="13" fill="#8a9ab0">&#9654;</text>
            <text x="635" y="283" fontSize="20" fontWeight="700" fill="white" fontFamily="'Segoe UI',sans-serif">{manual}</text>
            <text x="635" y="295" fontSize="9" fill="#9ea3b0" fontFamily="'Segoe UI',sans-serif" letterSpacing="1">MANUAL</text>

            {/* Open cases severity */}
            <path d="M608,295 C640,295 645,270 670,265" stroke="#5a6a7a" strokeWidth="3" fill="none" opacity="0.4"/>
            <path d="M608,295 C640,295 645,300 670,308" stroke="#5a6a7a" strokeWidth="2" fill="none" opacity="0.3"/>
            <rect x="672" y="255" width="14" height="14" rx="3" fill="#e53935"/>
            <text x="679" y="265" textAnchor="middle" fontSize="8" fontWeight="700" fill="white">C</text>
            <text x="690" y="265" fontSize="10" fill="#e8e9ed" fontFamily="'Segoe UI',sans-serif">3</text>
            <rect x="672" y="273" width="14" height="14" rx="3" fill="#ff6f00"/>
            <text x="679" y="283" textAnchor="middle" fontSize="8" fontWeight="700" fill="white">H</text>
            <text x="690" y="283" fontSize="10" fill="#e8e9ed" fontFamily="'Segoe UI',sans-serif">4</text>
            <rect x="672" y="291" width="14" height="14" rx="3" fill="#f9a825"/>
            <text x="679" y="301" textAnchor="middle" fontSize="8" fontWeight="700" fill="white">M</text>
            <text x="690" y="301" fontSize="10" fill="#e8e9ed" fontFamily="'Segoe UI',sans-serif">8</text>
            <rect x="672" y="309" width="14" height="14" rx="3" fill="#00897b"/>
            <text x="679" y="319" textAnchor="middle" fontSize="8" fontWeight="700" fill="white">L</text>
            <text x="690" y="319" fontSize="10" fill="#e8e9ed" fontFamily="'Segoe UI',sans-serif">0</text>
            <text x="718" y="285" fontSize="22" fontWeight="700" fill="white" fontFamily="'Segoe UI',sans-serif">{openCases}</text>
            <text x="718" y="299" fontSize="9" fill="#9ea3b0" fontFamily="'Segoe UI',sans-serif">OPEN</text>
            <text x="718" y="310" fontSize="9" fill="#9ea3b0" fontFamily="'Segoe UI',sans-serif">CASES</text>
          </svg>
        </div>
      </div>

      {/* Bottom stats bar */}
      <div style={{
        height: 68, flexShrink: 0,
        borderTop: '1px solid var(--border)',
        background: 'var(--bg-secondary)',
        display: 'flex', alignItems: 'stretch',
      }}>
        {[
          {
            label: 'Events Ingestion',
            value: '43', unit: 'B/24H',
            spark: 'M0,18 12,16 22,12 34,14 44,8 56,11 66,7 78,9 90,5',
            sparkColor: '#0078d4',
          },
          {
            label: 'Data Ingestion',
            value: '65', unit: 'TB/24H',
            spark: 'M0,14 12,12 22,10 34,13 44,9 56,12 66,8 78,10 90,7',
            sparkColor: '#4fa3e0',
          },
          {
            label: 'Total 开放案例',
            value: String(openCases), unit: '',
            sevRow: true,
          },
          {
            label: 'Prevented Events',
            value: '286.1K', unit: '',
            green: true,
          },
        ].map((s, i) => (
          <div key={i} style={{ display: 'flex', alignItems: 'stretch' }}>
            {i > 0 && <div style={{ width: 1, background: 'var(--border)', alignSelf: 'stretch', margin: '8px 0' }} />}
            <div style={{
              padding: '8px 24px', display: 'flex', flexDirection: 'column',
              justifyContent: 'center', gap: 2, minWidth: 160,
            }}>
              <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 500, textTransform: 'uppercase', letterSpacing: 0.4 }}>{s.label}</div>
              <div style={{ display: 'flex', alignItems: 'baseline', gap: 4 }}>
                <span style={{ fontSize: 20, fontWeight: 700, color: s.green ? 'var(--accent-green)' : 'var(--text-primary)', lineHeight: 1 }}>{s.value}</span>
                {s.unit && <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>{s.unit}</span>}
              </div>
              {s.spark && (
                <svg viewBox="0 0 90 22" width="90" height="18" preserveAspectRatio="none">
                  <polyline points={s.spark} stroke={s.sparkColor} strokeWidth="1.5" fill="none"/>
                </svg>
              )}
              {s.sevRow && (
                <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
                  {[['C','#d94040',3],['H','#d07030',4],['M','#c09020',8],['L','#2a9060',0]].map(([l,c,n]) => (
                    <span key={l as string} style={{ display: 'inline-flex', alignItems: 'center', gap: 3 }}>
                      <span style={{ padding: '1px 4px', background: (c as string)+'25', color: c as string, fontSize: 8, fontWeight: 700, borderRadius: 2 }}>{l}</span>
                      <span style={{ fontSize: 10, color: 'var(--text-secondary)' }}>{n}</span>
                    </span>
                  ))}
                </div>
              )}
            </div>
          </div>
        ))}
      </div>

      {/* Copilot overlay + panel */}
      {copilotOpen && (
        <div
          style={{ position: 'absolute', inset: 0, background: 'rgba(0,0,0,.4)', zIndex: 300 }}
          onClick={() => setCopilotOpen(false)}
        />
      )}
      <div style={{
        position: 'absolute', right: 0, top: 0, bottom: 0,
        width: 420, background: 'var(--bg-card)',
        borderLeft: '1px solid var(--border)',
        zIndex: 301, display: 'flex', flexDirection: 'column',
        transform: copilotOpen ? 'translateX(0)' : 'translateX(100%)',
        transition: 'transform .25s ease',
      }}>
        {/* Drawer header */}
        <div style={{
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
          padding: '12px 16px', borderBottom: '1px solid var(--border)',
          background: 'var(--bg-sidebar)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="#4fa3e0"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/></svg>
            <span style={{ fontSize: 13, fontWeight: 700, color: '#ffffff' }}>XSIAM Copilot</span>
          </div>
          <button onClick={() => setCopilotOpen(false)} style={{ background: 'none', border: 'none', color: 'rgba(255,255,255,.5)', cursor: 'pointer', fontSize: 16 }}>✕</button>
        </div>
        {/* Drawer body */}
        <div style={{ padding: '16px', display: 'flex', flexDirection: 'column', gap: 12, flex: 1, overflow: 'hidden', background: 'var(--bg-card)' }}>
          {/* Greeting bubble */}
          <div style={{
            display: 'flex', alignItems: 'flex-start', gap: 12, padding: '12px 14px',
            background: 'rgba(0,120,212,.08)', borderRadius: 8, border: '1px solid rgba(0,120,212,.18)',
          }}>
            <div style={{
              width: 32, height: 32, borderRadius: '50%', background: 'rgba(0,120,212,.18)',
              display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0,
            }}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="#0078d4"><path d="M12 2l3.09 6.26L22 9.27l-5 4.87 1.18 6.88L12 17.77l-6.18 3.25L7 14.14 2 9.27l6.91-1.01L12 2z"/></svg>
            </div>
            <p style={{ fontSize: 12.5, color: 'var(--text-primary)', lineHeight: 1.6, margin: 0 }}>
              Hi {user?.display_name ?? 'Analyst'}! I'm your AI SecOps assistant. How can I help you today?
            </p>
          </div>
          {/* Quick prompts */}
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {['Summarize today\'s critical incidents','Why did INC-2024-0047 auto-close?','Top threat actors in last 7 days','Investigate alert spike at 02:00'].map(s => (
              <button key={s} onClick={() => setCopilotInput(s)} style={{
                padding: '5px 10px', background: 'rgba(0,120,212,.08)',
                border: '1px solid rgba(0,120,212,.22)', borderRadius: 12,
                color: 'var(--accent-blue)', fontSize: 11, cursor: 'pointer',
              }}>{s}</button>
            ))}
          </div>
          {/* Message thread */}
          <div style={{ flex: 1, overflowY: 'auto', display: 'flex', flexDirection: 'column', gap: 10 }}>
            {copilotMessages.map((m, i) => (
              <div key={i} style={{
                padding: '8px 12px', borderRadius: 8, fontSize: 12, lineHeight: 1.5, maxWidth: '90%',
                ...(m.role === 'user'
                  ? { background: 'rgba(0,120,212,.12)', border: '1px solid rgba(0,120,212,.22)', marginLeft: 'auto', color: 'var(--text-primary)' }
                  : { background: 'var(--bg-card2)', border: '1px solid var(--border)', color: 'var(--text-primary)' }),
              }}>{m.text}</div>
            ))}
          </div>
          {/* Input bar */}
          <div style={{ display: 'flex', gap: 8 }}>
            <input
              placeholder="询问安全态势..."
          value={copilotInput}
              onChange={e => setCopilotInput(e.target.value)}
              onKeyDown={e => {
                if (e.key === 'Enter' && copilotInput.trim()) {
                  const q = copilotInput.trim()
                  setCopilotInput('')
                  setCopilotMessages(prev => [...prev, { role: 'user', text: q }, { role: 'assistant', text: `Analyzing: "${q}"\n\n[演示模式 — 连接AI引擎以获取实时响应]` }])
                }
              }}
              style={{
                flex: 1, background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                borderRadius: 6, padding: '8px 12px', color: 'var(--text-primary)', fontSize: 12, outline: 'none',
              }}
            />
            <button
              onClick={() => {
                const q = copilotInput.trim()
                if (!q) return
                setCopilotInput('')
                setCopilotMessages(prev => [...prev, { role: 'user', text: q }, { role: 'assistant', text: `Analyzing: "${q}"\n\n[演示模式 — 连接AI引擎以获取实时响应]` }])
              }}
              className="btn-primary" style={{ padding: '8px 14px' }}>→</button>
          </div>
        </div>
      </div>
    </div>
  )
}
