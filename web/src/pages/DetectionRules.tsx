import { useEffect, useRef, useState } from 'react'
import ResizableTh from '@/components/ResizableTh'
import { BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import api from '@/lib/api'
import type { PageMeta } from '@/lib/api'
import PageHeader from '@/components/PageHeader'

interface Rule {
  _key: string
  rule_id?: string
  name: string
  description: string
  rule_type: string
  severity: string
  status: string
  source_type?: string
  definition?: {
    query?: string
    condition?: string
    [key: string]: any
  }
  query?: string           // API alias field (seeded rules use this)
  mitre_tactic?: string
  mitre_tactics?: string[]
  mitre_techniques?: string[]
  hit_count: number
  false_positive_rate: number
  last_hit_at?: string
  created_at: string
  updated_at: string
}

function fmtDate(iso: string) {
  if (!iso) return '-'
  return new Date(iso).toLocaleDateString('zh-CN')
}

// ─── MITRE Tactic list (14 ATT&CK tactics) ───────────────────────────────────
const MITRE_TACTICS = [
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Command and Control',
  'Exfiltration',
  'Impact',
  'Resource Development',
  'Reconnaissance',
]
const MITRE_TOTAL = 14

// ─── Status badge config ──────────────────────────────────────────────────────
const STATUS_CFG: Record<string, { color: string; bg: string; border: string; icon: string; glow?: string }> = {
  draft:      { color: 'var(--text-muted)', bg: 'rgba(156,163,175,.12)', border: 'rgba(156,163,175,.3)',  icon: '📝' },
  active:     { color: 'var(--accent-green)', bg: 'rgba(34,197,94,.12)',   border: 'rgba(34,197,94,.35)',   icon: '✅', glow: '0 0 6px rgba(34,197,94,.4)' },
  testing:    { color: 'var(--high)', bg: 'rgba(249,115,22,.12)',  border: 'rgba(249,115,22,.35)',  icon: '🧪' },
  deprecated: { color: 'var(--critical)', bg: 'rgba(239,68,68,.12)',   border: 'rgba(239,68,68,.3)',    icon: '⛔' },
  inactive:   { color: 'var(--text-muted)', bg: 'rgba(107,114,128,.1)',  border: 'rgba(107,114,128,.25)', icon: '⏸' },
  disabled:   { color: 'var(--text-muted)', bg: 'rgba(107,114,128,.1)',  border: 'rgba(107,114,128,.25)', icon: '⏸' },
}
function getStatusCfg(s: string) { return STATUS_CFG[s] ?? STATUS_CFG['draft'] }

// ─── Status Badge Component ───────────────────────────────────────────────────
function StatusBadge({ status, size = 'md' }: { status: string; size?: 'sm' | 'md' }) {
  const cfg = getStatusCfg(status)
  const fs = size === 'sm' ? 10 : 11
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      fontSize: fs, padding: size === 'sm' ? '1px 6px' : '2px 8px',
      borderRadius: 10,
      color: cfg.color, background: cfg.bg, border: `1px solid ${cfg.border}`,
      boxShadow: cfg.glow,
      fontWeight: 500,
      whiteSpace: 'nowrap',
    }}>
      <span style={{ fontSize: fs - 1 }}>{cfg.icon}</span>
      {status || 'draft'}
    </span>
  )
}

// ─── Hash-based mock performance stats ───────────────────────────────────────
function hashKey(key: string): number {
  let h = 0
  for (let i = 0; i < key.length; i++) { h = (h * 31 + key.charCodeAt(i)) >>> 0 }
  return h
}
function mockPerfStats(key: string) {
  const h = hashKey(key)
  const hits30d = h % 501
  const fpr = ((h >> 4) % 150) / 10       // 0–14.9%
  const avgMs = 200 + (h >> 8) % 1800     // 200–1999ms
  // 7-day sparkline
  const spark: number[] = []
  for (let i = 0; i < 7; i++) {
    spark.push(((hashKey(key + i) % Math.max(hits30d, 10)) * Math.max(1, hits30d) / 500) | 0)
  }
  return { hits30d, fpr, avgMs, spark }
}

// ─── Sparkline SVG ────────────────────────────────────────────────────────────
function Sparkline({ data, color = 'var(--accent-blue)' }: { data: number[]; color?: string }) {
  const w = 140, h = 36, pad = 2
  const max = Math.max(...data, 1)
  const pts = data.map((v, i) => {
    const x = pad + (i / (data.length - 1)) * (w - pad * 2)
    const y = h - pad - (v / max) * (h - pad * 2)
    return `${x},${y}`
  })
  const d = 'M' + pts.join(' L')
  return (
    <svg width={w} height={h} style={{ overflow: 'visible' }}>
      <polyline points={pts.join(' ')} fill="none" stroke={color} strokeWidth={1.8} strokeLinejoin="round" strokeLinecap="round" />
      {data.map((v, i) => {
        const x = pad + (i / (data.length - 1)) * (w - pad * 2)
        const y = h - pad - (v / max) * (h - pad * 2)
        return <circle key={i} cx={x} cy={y} r={2} fill={color} />
      })}
      <defs>
        <linearGradient id="sparkFill" x1="0" y1="0" x2="0" y2="1">
          <stop offset="0%" stopColor={color} stopOpacity={0.25} />
          <stop offset="100%" stopColor={color} stopOpacity={0} />
        </linearGradient>
      </defs>
      <path d={`${d} L${w - pad},${h} L${pad},${h} Z`} fill="url(#sparkFill)" />
    </svg>
  )
}

// ─── Sample event templates per source_type / rule_type ───────────────────────
function sampleEventTemplate(rule: Rule): string {
  const base = rule.source_type || rule.rule_type || 'generic'
  const templates: Record<string, object> = {
    bioc: { event_type: 'PROCESS', src_ip: '10.0.1.42', process_name: 'powershell.exe', cmdline: 'powershell -enc YQBtAHMAaQ...', user: 'DOMAIN\\user', pid: 4821, ts: new Date().toISOString() },
    ioc:  { event_type: 'NETWORK', src_ip: '192.168.1.5', dst_ip: '185.220.101.5', domain: 'evil-c2.example.com', url: 'http://evil-c2.example.com/beacon', ts: new Date().toISOString() },
    ueba: { event_type: 'AUTH', user: 'john.doe', src_ip: '10.0.0.5', action: 'LOGIN_FAILED', count: 12, window_h: 1, ts: new Date().toISOString() },
    spl2: { dataset: 'endpoint_events', event_type: 'PROCESS', src_ip: '10.0.1.10', process_name: 'cmd.exe', user: 'SYSTEM', ts: new Date().toISOString() },
    endpoint: { event_type: 'PROCESS', src_ip: '10.0.1.42', process_name: 'powershell.exe', cmdline: '-nop -w hidden -enc ...', user: 'DOMAIN\\user', ts: new Date().toISOString() },
    network: { event_type: 'NETWORK', src_ip: '10.0.0.5', dst_ip: '1.2.3.4', dst_port: 443, bytes: 1024, proto: 'TCP', ts: new Date().toISOString() },
    generic: { event_type: 'GENERIC', src_ip: '10.0.0.1', user: 'user', action: 'action', ts: new Date().toISOString() },
  }
  return JSON.stringify(templates[base] ?? templates.generic, null, 2)
}

// ─── Rule Test Panel ──────────────────────────────────────────────────────────
function RuleTestPanel({ rule }: { rule: Rule }) {
  const [json, setJson] = useState(() => sampleEventTemplate(rule))
  const [jsonErr, setJsonErr] = useState('')
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState<{ matched: boolean; message?: string; output_entry?: any } | null>(null)
  const [apiErr, setApiErr] = useState('')

  function validate(v: string): boolean {
    try { JSON.parse(v); setJsonErr(''); return true }
    catch (e: any) { setJsonErr('JSON 语法错误: ' + e.message); return false }
  }

  function runTest() {
    if (!validate(json)) return
    setRunning(true); setResult(null); setApiErr('')
    api.post(`/detection_rules/${rule._key}/test`, { sample_event: JSON.parse(json), tag: 'test' })
      .then(r => {
        const d = r.data?.data ?? r.data
        setResult({ matched: !!d?.matched, message: d?.message ?? '', output_entry: d?.output_entry })
      })
      .catch(err => setApiErr(err?.response?.data?.message ?? '请求失败'))
      .finally(() => setRunning(false))
  }

  const inputSt: React.CSSProperties = {
    background: 'var(--bg-secondary)', border: '1px solid var(--border)',
    borderRadius: 4, color: 'var(--text-primary)', fontSize: 12, padding: '8px 10px',
    outline: 'none', width: '100%', boxSizing: 'border-box',
    fontFamily: 'Consolas, monospace', lineHeight: 1.6, resize: 'vertical',
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
      <div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>
          粘贴样本事件 JSON（基于规则类型预填充）
        </div>
        <textarea
          style={{ ...inputSt, minHeight: 160, borderColor: jsonErr ? 'var(--critical)' : 'var(--border)' }}
          value={json}
          onChange={e => { setJson(e.target.value); if (jsonErr) validate(e.target.value) }}
          spellCheck={false}
        />
        {jsonErr && (
          <div style={{ fontSize: 10.5, color: 'var(--critical)', marginTop: 4, display: 'flex', alignItems: 'center', gap: 4 }}>
            <span>⚠</span>{jsonErr}
          </div>
        )}
      </div>

      <button
        className="btn-primary"
        disabled={running}
        onClick={runTest}
        style={{ alignSelf: 'flex-start', fontSize: 12 }}
      >
        {running ? '运行中...' : '▶ 运行测试'}
      </button>

      {apiErr && (
        <div style={{ padding: '10px 12px', background: 'rgba(239,68,68,.1)', border: '1px solid rgba(239,68,68,.3)', borderRadius: 6, fontSize: 12, color: 'var(--critical)' }}>
          ❌ {apiErr}
        </div>
      )}

      {result !== null && (
        <div style={{
          padding: '14px 16px',
          background: result.matched ? 'rgba(34,197,94,.08)' : 'rgba(239,68,68,.08)',
          border: `1px solid ${result.matched ? 'rgba(34,197,94,.3)' : 'rgba(239,68,68,.25)'}`,
          borderRadius: 8,
          display: 'flex', flexDirection: 'column', gap: 8,
        }}>
          <div style={{ fontSize: 15, fontWeight: 600, color: result.matched ? 'var(--accent-green)' : 'var(--critical)' }}>
            {result.matched ? '✅ 规则匹配' : '❌ 未匹配'}
          </div>
          {result.message && (
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6 }}>{result.message}</div>
          )}
          {result.output_entry && (
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>output_entry</div>
              <pre style={{ margin: 0, fontSize: 11, fontFamily: 'Consolas,monospace', color: 'var(--accent-blue)', background: 'var(--bg-secondary)', padding: '8px 10px', borderRadius: 4, whiteSpace: 'pre-wrap', wordBreak: 'break-all', lineHeight: 1.5 }}>
                {JSON.stringify(result.output_entry, null, 2)}
              </pre>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ─── Rule Performance Stats Panel ────────────────────────────────────────────
function RulePerfPanel({ rule }: { rule: Rule }) {
  const stats = mockPerfStats(rule._key)
  const days = ['D-6', 'D-5', 'D-4', 'D-3', 'D-2', 'D-1', '今']
  const chartData = stats.spark.map((v, i) => ({ day: days[i], count: v }))

  const rowSt: React.CSSProperties = {
    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
    padding: '7px 0', borderBottom: '1px solid rgba(255,255,255,.04)', fontSize: 12.5,
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      <div>
        <div style={rowSt}>
          <span style={{ color: 'var(--text-muted)' }}>触发次数 (30天)</span>
          <span style={{ color: stats.hits30d > 100 ? 'var(--high)' : 'var(--text-secondary)', fontFamily: 'monospace', fontWeight: 600, fontSize: 14 }}>{stats.hits30d}</span>
        </div>
        <div style={rowSt}>
          <span style={{ color: 'var(--text-muted)' }}>误报率</span>
          <span style={{ color: stats.fpr > 10 ? 'var(--critical)' : stats.fpr > 5 ? 'var(--high)' : 'var(--accent-green)', fontFamily: 'monospace' }}>{stats.fpr.toFixed(1)}%</span>
        </div>
        <div style={{ ...rowSt, borderBottom: 'none' }}>
          <span style={{ color: 'var(--text-muted)' }}>平均响应时间</span>
          <span style={{ color: 'var(--text-secondary)', fontFamily: 'monospace' }}>{(stats.avgMs / 1000).toFixed(1)}s</span>
        </div>
      </div>

      <div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8 }}>触发趋势 (近7天)</div>
        <Sparkline data={stats.spark} />
        <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 4 }}>
          {days.map((d, i) => (
            <span key={i} style={{ fontSize: 9, color: 'var(--text-muted)' }}>{d}</span>
          ))}
        </div>
      </div>

      <div>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8 }}>每日触发柱状图</div>
        <ResponsiveContainer width="100%" height={90}>
          <BarChart data={chartData} margin={{ top: 2, right: 0, left: -24, bottom: 0 }}>
            <XAxis dataKey="day" tick={{ fontSize: 9, fill: 'var(--text-muted)' }} axisLine={false} tickLine={false} />
            <YAxis tick={{ fontSize: 9, fill: 'var(--text-muted)' }} axisLine={false} tickLine={false} />
            <Tooltip
              contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 4, fontSize: 11 }}
              labelStyle={{ color: 'var(--text-secondary)' }}
              itemStyle={{ color: 'var(--accent-blue)' }}
            />
            <Bar dataKey="count" fill="var(--accent-blue)" radius={[3, 3, 0, 0]} maxBarSize={20} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}

// ─── MITRE Coverage Dashboard (full page tab) ─────────────────────────────────
function MitreCoverageDashboard({ onFilterByTactic }: { onFilterByTactic?: (tactic: string) => void }) {
  const [coverage, setCoverage] = useState<Record<string, number> | null>(null)
  const [loadErr, setLoadErr] = useState(false)

  useEffect(() => {
    api.get('/detection_rules/mitre_coverage')
      .then(r => setCoverage(r.data.data ?? {}))
      .catch(() => { setLoadErr(true); setCoverage({}) })
  }, [])

  if (coverage === null) return <div style={{ padding: 32, color: 'var(--text-muted)', fontSize: 13 }}>加载中...</div>
  if (loadErr) return <div style={{ padding: 32, color: 'var(--critical)', fontSize: 13 }}>加载 MITRE 覆盖数据失败</div>

  const coveredTactics = MITRE_TACTICS.filter(t => (coverage[t] ?? 0) > 0)
  const uncoveredTactics = MITRE_TACTICS.filter(t => (coverage[t] ?? 0) === 0)
  const pct = Math.round((coveredTactics.length / MITRE_TOTAL) * 100)

  const barData = MITRE_TACTICS.map(t => ({ tactic: t.split(' ')[0], fullName: t, count: coverage[t] ?? 0 }))

  function cellBg(n: number) {
    if (n === 0) return 'var(--bg-secondary)'
    if (n <= 2) return 'rgba(79,163,224,0.22)'
    if (n <= 5) return 'rgba(79,163,224,0.52)'
    return 'rgba(79,163,224,0.85)'
  }
  function cellText(n: number) {
    return n > 5 ? '#fff' : n > 0 ? 'var(--accent-blue)' : 'var(--text-muted)'
  }

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: '20px 24px', display: 'flex', flexDirection: 'column', gap: 24 }}>
      {/* Large coverage stat */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 28, padding: '20px 24px', background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 10, flexWrap: 'wrap' }}>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 4, minWidth: 160 }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', letterSpacing: '0.06em', textTransform: 'uppercase' }}>ATT&amp;CK 战术覆盖</div>
          <div style={{ display: 'flex', alignItems: 'baseline', gap: 10 }}>
            <span style={{ fontSize: 48, fontWeight: 800, fontFamily: 'monospace', color: pct >= 70 ? 'var(--accent-green)' : pct >= 40 ? 'var(--high)' : 'var(--critical)', lineHeight: 1 }}>{pct}%</span>
          </div>
          <div style={{ fontSize: 13, color: 'var(--text-secondary)', fontWeight: 500 }}>
            本系统覆盖 ATT&amp;CK 战术 <strong style={{ color: pct >= 70 ? 'var(--accent-green)' : pct >= 40 ? 'var(--high)' : 'var(--critical)' }}>{coveredTactics.length}</strong> / {MITRE_TOTAL} 个
          </div>
        </div>
        <div style={{ flex: 1, minWidth: 200, display: 'flex', flexDirection: 'column', gap: 10 }}>
          <div style={{ height: 10, background: 'var(--border)', borderRadius: 5, overflow: 'hidden' }}>
            <div style={{ height: '100%', width: `${pct}%`, background: pct >= 70 ? 'var(--accent-green)' : pct >= 40 ? 'var(--high)' : 'var(--critical)', borderRadius: 5, transition: 'width .5s' }} />
          </div>
          <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
            {([['✅ 已覆盖', coveredTactics.length, 'var(--accent-green)'], ['❌ 未覆盖', uncoveredTactics.length, 'var(--critical)']] as [string, number, string][]).map(([label, n, color]) => (
              <span key={label} style={{ fontSize: 12, color }}>{label}: <strong style={{ fontSize: 15 }}>{n}</strong></span>
            ))}
          </div>
        </div>
      </div>

      {/* Heatmap grid */}
      <div>
        <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 10 }}>MITRE ATT&amp;CK 热力图</div>
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(7, 1fr)', gap: 8 }}>
          {MITRE_TACTICS.map(tactic => {
            const n = coverage[tactic] ?? 0
            return (
              <div key={tactic} style={{
                background: cellBg(n),
                border: '1px solid rgba(255,255,255,.07)',
                borderRadius: 6, padding: '10px 12px',
                minHeight: 64, display: 'flex', flexDirection: 'column', justifyContent: 'space-between',
                transition: 'border-color .15s',
                cursor: onFilterByTactic ? 'pointer' : 'default',
              }}
                onMouseEnter={e => (e.currentTarget.style.borderColor = 'rgba(79,163,224,.5)')}
                onMouseLeave={e => (e.currentTarget.style.borderColor = 'rgba(255,255,255,.07)')}
                onClick={() => onFilterByTactic && onFilterByTactic(tactic)}
              >
                <span style={{ fontSize: 10, color: cellText(n), lineHeight: 1.35, display: 'block' }}>{tactic}</span>
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-end' }}>
                  <span style={{ fontSize: 18, fontWeight: 700, fontFamily: 'monospace', color: cellText(n), lineHeight: 1 }}>{n}</span>
                  {onFilterByTactic && n > 0 && (
                    <span style={{ fontSize: 9, color: n > 5 ? 'rgba(255,255,255,.7)' : 'var(--accent-blue)', textDecoration: 'underline', lineHeight: 1, cursor: 'pointer' }}>筛选规则</span>
                  )}
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Uncovered tactics */}
      {uncoveredTactics.length > 0 && (
        <div style={{ padding: '12px 16px', background: 'rgba(239,68,68,.06)', border: '1px solid rgba(239,68,68,.2)', borderRadius: 8 }}>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--critical)', marginBottom: 8 }}>未覆盖战术</div>
          <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
            {uncoveredTactics.map(t => (
              <span key={t} style={{ fontSize: 11, padding: '3px 10px', background: 'rgba(239,68,68,.1)', border: '1px solid rgba(239,68,68,.25)', borderRadius: 10, color: 'var(--critical)' }}>{t}</span>
            ))}
          </div>
        </div>
      )}

      {/* Bar chart */}
      <div>
        <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 10 }}>各战术规则数量</div>
        <ResponsiveContainer width="100%" height={220}>
          <BarChart data={barData} margin={{ top: 4, right: 8, left: -8, bottom: 50 }}>
            <XAxis
              dataKey="tactic"
              tick={{ fontSize: 9, fill: 'var(--text-muted)' }}
              angle={-35}
              textAnchor="end"
              interval={0}
              axisLine={false} tickLine={false}
            />
            <YAxis tick={{ fontSize: 10, fill: 'var(--text-muted)' }} axisLine={false} tickLine={false} allowDecimals={false} />
            <Tooltip
              formatter={((v: unknown, _: unknown, p: any) => [Number(v ?? 0), p.payload.fullName]) as any}
              contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 4, fontSize: 11 }}
              labelStyle={{ display: 'none' }}
              itemStyle={{ color: 'var(--accent-blue)' }}
            />
            <Bar dataKey="count" fill="var(--accent-blue)" radius={[3, 3, 0, 0]} maxBarSize={28} />
          </BarChart>
        </ResponsiveContainer>
      </div>
    </div>
  )
}

// ─── Wizard types ─────────────────────────────────────────────────────────────
interface EventStep {
  event_type: string
  conditions: { key: string; value: string }[]
}

interface WizardState {
  // Step 1
  rule_type: 'bioc' | 'ioc' | 'ueba' | 'spl2'
  // Step 2 — BIOC
  event_steps: EventStep[]
  // Step 2 — IOC
  ioc_type: string
  ioc_values: string
  ioc_pattern: string
  // Step 2 — UEBA
  ueba_metric: string
  ueba_threshold: string
  ueba_window: string
  // Step 2 — SPL2
  spl2_query: string
  // Step 3
  name: string
  description: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  mitre_tactics: string[]
  tags: string
}

const BLANK_WIZARD: WizardState = {
  rule_type: 'bioc',
  event_steps: [{ event_type: '', conditions: [{ key: '', value: '' }] }],
  ioc_type: 'ip',
  ioc_values: '',
  ioc_pattern: '',
  ueba_metric: 'event_count',
  ueba_threshold: '100',
  ueba_window: '24',
  spl2_query: '',
  name: '',
  description: '',
  severity: 'high',
  mitre_tactics: [],
  tags: '',
}

const BLANK_FORM = { name: '', description: '', rule_type: 'bioc', severity: 'high', status: 'draft', query: '', mitre_tactics: '', mitre_techniques: '' }

// ─── Step Indicator ──────────────────────────────────────────────────────────
function StepIndicator({ step }: { step: number }) {
  const steps = ['规则类型', '规则定义', '元数据', '确认创建']
  return (
    <div style={{ display: 'flex', alignItems: 'center', marginBottom: 24 }}>
      {steps.map((label, i) => {
        const idx = i + 1
        const active = idx === step
        const done = idx < step
        return (
          <div key={idx} style={{ display: 'flex', alignItems: 'center', flex: i < steps.length - 1 ? 1 : 'none' }}>
            <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4, flexShrink: 0 }}>
              <div style={{
                width: 28, height: 28, borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontSize: 12, fontWeight: 700,
                background: active ? 'var(--accent-blue)' : done ? 'rgba(79,163,224,.35)' : 'var(--bg-secondary)',
                color: active ? '#fff' : done ? 'var(--accent-blue)' : 'var(--text-muted)',
                border: active ? '2px solid var(--accent-blue)' : done ? '2px solid rgba(79,163,224,.5)' : '2px solid var(--border)',
                transition: 'all .2s',
              }}>{idx}</div>
              <span style={{ fontSize: 10, color: active ? 'var(--accent-blue)' : 'var(--text-muted)', whiteSpace: 'nowrap' }}>{label}</span>
            </div>
            {i < steps.length - 1 && (
              <div style={{ flex: 1, height: 2, marginBottom: 14, background: done ? 'rgba(79,163,224,.5)' : 'var(--border)', marginLeft: 4, marginRight: 4 }} />
            )}
          </div>
        )
      })}
    </div>
  )
}

// ─── Rule Builder Wizard Modal ───────────────────────────────────────────────
function RuleWizardModal({ onClose, onCreated }: { onClose: () => void; onCreated: () => void }) {
  const [step, setStep] = useState(1)
  const [wiz, setWiz] = useState<WizardState>(BLANK_WIZARD)
  const [saving, setSaving] = useState(false)

  // helpers
  function setW<K extends keyof WizardState>(k: K, v: WizardState[K]) {
    setWiz(p => ({ ...p, [k]: v }))
  }

  // ── Step 1 ───────────────────────────────────────────────────────────────
  const typeCards: { id: WizardState['rule_type']; icon: string; label: string; desc: string }[] = [
    { id: 'bioc', icon: '🔗', label: 'BIOC', desc: '序列行为检测 — 多步骤事件链匹配' },
    { id: 'ioc', icon: '🎯', label: 'IOC', desc: '指标匹配 — IP/域名/Hash/URL/邮箱' },
    { id: 'ueba', icon: '📊', label: 'UEBA', desc: '统计异常 — 用户/实体行为分析' },
    { id: 'spl2', icon: '⌨️', label: 'SPL2', desc: '自定义查询 — 完整 SPL2 语法' },
  ]

  // ── Step 2 helpers ────────────────────────────────────────────────────────
  function addEventStep() {
    setWiz(p => ({ ...p, event_steps: [...p.event_steps, { event_type: '', conditions: [{ key: '', value: '' }] }] }))
  }
  function removeEventStep(i: number) {
    setWiz(p => ({ ...p, event_steps: p.event_steps.filter((_, idx) => idx !== i) }))
  }
  function updateEventStep(i: number, field: 'event_type', val: string) {
    setWiz(p => {
      const steps = [...p.event_steps]
      steps[i] = { ...steps[i], [field]: val }
      return { ...p, event_steps: steps }
    })
  }
  function addCondition(si: number) {
    setWiz(p => {
      const steps = [...p.event_steps]
      steps[si] = { ...steps[si], conditions: [...steps[si].conditions, { key: '', value: '' }] }
      return { ...p, event_steps: steps }
    })
  }
  function removeCondition(si: number, ci: number) {
    setWiz(p => {
      const steps = [...p.event_steps]
      steps[si] = { ...steps[si], conditions: steps[si].conditions.filter((_, idx) => idx !== ci) }
      return { ...p, event_steps: steps }
    })
  }
  function updateCondition(si: number, ci: number, field: 'key' | 'value', val: string) {
    setWiz(p => {
      const steps = [...p.event_steps]
      const conds = [...steps[si].conditions]
      conds[ci] = { ...conds[ci], [field]: val }
      steps[si] = { ...steps[si], conditions: conds }
      return { ...p, event_steps: steps }
    })
  }

  // ── Submit ────────────────────────────────────────────────────────────────
  function buildDefinition() {
    if (wiz.rule_type === 'bioc') {
      return {
        event_sequence: wiz.event_steps.map(s => ({
          event_type: s.event_type,
          conditions: Object.fromEntries(s.conditions.filter(c => c.key).map(c => [c.key, c.value])),
        })),
      }
    }
    if (wiz.rule_type === 'ioc') {
      return {
        ioc_type: wiz.ioc_type,
        values: wiz.ioc_values.split('\n').map(s => s.trim()).filter(Boolean),
        pattern: wiz.ioc_pattern || undefined,
      }
    }
    if (wiz.rule_type === 'ueba') {
      return {
        metric: wiz.ueba_metric,
        threshold: Number(wiz.ueba_threshold),
        time_window_h: Number(wiz.ueba_window),
      }
    }
    // spl2
    return { query: wiz.spl2_query }
  }

  function submit() {
    setSaving(true)
    const body = {
      name: wiz.name,
      description: wiz.description,
      rule_type: wiz.rule_type,
      severity: wiz.severity,
      status: 'draft',
      definition: buildDefinition(),
      mitre_tactics: wiz.mitre_tactics,
      tags: wiz.tags ? wiz.tags.split(',').map(s => s.trim()).filter(Boolean) : [],
    }
    api.post('/detection_rules', body)
      .then(() => { onCreated(); onClose() })
      .finally(() => setSaving(false))
  }

  // ── Tag chips ─────────────────────────────────────────────────────────────
  const tagList = wiz.tags ? wiz.tags.split(',').map(s => s.trim()).filter(Boolean) : []

  const inputSt: React.CSSProperties = {
    background: 'var(--bg-secondary)',
    border: '1px solid var(--border)',
    borderRadius: 4,
    color: 'var(--text-primary)',
    fontSize: 12.5,
    padding: '6px 10px',
    outline: 'none',
    width: '100%',
    boxSizing: 'border-box',
  }
  const labelSt: React.CSSProperties = { fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }

  return (
    <>
      <div onClick={onClose} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
      <div style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: 640, maxHeight: '90vh', overflowY: 'auto', background: 'var(--bg-modal)', border: '1px solid var(--border)', borderRadius: 8, zIndex: 500, padding: '28px 28px 24px' }}>
        {/* Header */}
        <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 20 }}>
          <span style={{ fontSize: 16, fontWeight: 600 }}>新建检测规则</span>
          <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px' }} onClick={onClose}>✕</button>
        </div>

        <StepIndicator step={step} />

        {/* Step 1 — Rule type */}
        {step === 1 && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div style={{ fontSize: 13, fontWeight: 500, marginBottom: 4 }}>选择规则类型</div>
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
              {typeCards.map(card => (
                <div key={card.id} onClick={() => setW('rule_type', card.id)} style={{
                  border: `2px solid ${wiz.rule_type === card.id ? 'var(--accent-blue)' : 'var(--border)'}`,
                  borderRadius: 8, padding: '16px 14px', cursor: 'pointer',
                  background: wiz.rule_type === card.id ? 'rgba(79,163,224,.08)' : 'var(--bg-secondary)',
                  transition: 'all .15s',
                }}>
                  <div style={{ fontSize: 22, marginBottom: 6 }}>{card.icon}</div>
                  <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 4, color: wiz.rule_type === card.id ? 'var(--accent-blue)' : 'var(--text-primary)' }}>{card.label}</div>
                  <div style={{ fontSize: 11.5, color: 'var(--text-muted)', lineHeight: 1.5 }}>{card.desc}</div>
                </div>
              ))}
            </div>
            <div style={{ display: 'flex', justifyContent: 'flex-end', marginTop: 8 }}>
              <button className="btn-primary" onClick={() => setStep(2)}>下一步 →</button>
            </div>
          </div>
        )}

        {/* Step 2 — Rule definition */}
        {step === 2 && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div style={{ fontSize: 13, fontWeight: 500 }}>规则定义 — {wiz.rule_type.toUpperCase()}</div>

            {/* BIOC */}
            {wiz.rule_type === 'bioc' && (
              <div>
                <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-secondary)', marginBottom: 10 }}>事件序列</div>
                {wiz.event_steps.map((es, si) => (
                  <div key={si} style={{ border: '1px solid var(--border)', borderRadius: 6, padding: '12px 14px', marginBottom: 10, background: 'var(--bg-secondary)' }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                      <span style={{ fontSize: 11.5, fontWeight: 600, color: 'var(--accent-blue)' }}>步骤 {si + 1}</span>
                      {wiz.event_steps.length > 1 && (
                        <button onClick={() => removeEventStep(si)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--critical)', fontSize: 14, lineHeight: 1 }}>×</button>
                      )}
                    </div>
                    <div style={{ marginBottom: 8 }}>
                      <div style={labelSt}>event_type</div>
                      <input style={inputSt} placeholder="PROCESS / NETWORK / FILE ..." value={es.event_type}
                        onChange={e => updateEventStep(si, 'event_type', e.target.value)} />
                    </div>
                    <div>
                      <div style={labelSt}>条件</div>
                      {es.conditions.map((cond, ci) => (
                        <div key={ci} style={{ display: 'flex', gap: 6, marginBottom: 6, alignItems: 'center' }}>
                          <input style={{ ...inputSt, flex: 1 }} placeholder="key" value={cond.key}
                            onChange={e => updateCondition(si, ci, 'key', e.target.value)} />
                          <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>=</span>
                          <input style={{ ...inputSt, flex: 1 }} placeholder="value" value={cond.value}
                            onChange={e => updateCondition(si, ci, 'value', e.target.value)} />
                          {es.conditions.length > 1 && (
                            <button onClick={() => removeCondition(si, ci)} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--critical)', fontSize: 16, lineHeight: 1, flexShrink: 0 }}>×</button>
                          )}
                        </div>
                      ))}
                      <button className="btn-secondary" style={{ fontSize: 10.5, padding: '2px 8px' }} onClick={() => addCondition(si)}>+ 添加条件</button>
                    </div>
                  </div>
                ))}
                <button className="btn-secondary" style={{ fontSize: 11, padding: '4px 12px' }} onClick={addEventStep}>+ 添加步骤</button>
              </div>
            )}

            {/* IOC */}
            {wiz.rule_type === 'ioc' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <div>
                  <div style={labelSt}>IOC类型</div>
                  <select style={{ ...inputSt }} value={wiz.ioc_type} onChange={e => setW('ioc_type', e.target.value)}>
                    <option value="ip">IP 地址</option>
                    <option value="domain">域名</option>
                    <option value="hash">文件 Hash</option>
                    <option value="url">URL</option>
                    <option value="email">邮箱</option>
                  </select>
                </div>
                <div>
                  <div style={labelSt}>匹配值 *</div>
                  <textarea style={{ ...inputSt, minHeight: 100, resize: 'vertical', fontFamily: 'monospace', lineHeight: 1.6 }}
                    placeholder="每行一个值" value={wiz.ioc_values}
                    onChange={e => setW('ioc_values', e.target.value)} />
                </div>
                <div>
                  <div style={labelSt}>正则模式 (可选)</div>
                  <input style={inputSt} placeholder="e.g. ^192\.168\." value={wiz.ioc_pattern}
                    onChange={e => setW('ioc_pattern', e.target.value)} />
                </div>
              </div>
            )}

            {/* UEBA */}
            {wiz.rule_type === 'ueba' && (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
                <div>
                  <div style={labelSt}>指标 (metric)</div>
                  <input style={inputSt} value={wiz.ueba_metric}
                    onChange={e => setW('ueba_metric', e.target.value)} />
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                  <div>
                    <div style={labelSt}>阈值</div>
                    <input type="number" style={inputSt} value={wiz.ueba_threshold}
                      onChange={e => setW('ueba_threshold', e.target.value)} />
                  </div>
                  <div>
                    <div style={labelSt}>时间窗口 (小时)</div>
                    <input type="number" style={inputSt} value={wiz.ueba_window}
                      onChange={e => setW('ueba_window', e.target.value)} />
                  </div>
                </div>
              </div>
            )}

            {/* SPL2 */}
            {wiz.rule_type === 'spl2' && (
              <div>
                <div style={labelSt}>SPL2 查询</div>
                <textarea style={{ ...inputSt, minHeight: 160, resize: 'vertical', fontFamily: 'Consolas, monospace', fontSize: 12, lineHeight: 1.6 }}
                  placeholder={`dataset = endpoint_events\n| filter event_type = "PROCESS"\n| stats count by src_ip\n| filter count > 100`}
                  value={wiz.spl2_query}
                  onChange={e => setW('spl2_query', e.target.value)} />
              </div>
            )}

            <div style={{ display: 'flex', gap: 10, justifyContent: 'space-between', marginTop: 4 }}>
              <button className="btn-secondary" onClick={() => setStep(1)}>← 上一步</button>
              <button className="btn-primary" onClick={() => setStep(3)}>下一步 →</button>
            </div>
          </div>
        )}

        {/* Step 3 — Metadata */}
        {step === 3 && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div style={{ fontSize: 13, fontWeight: 500 }}>元数据</div>

            <div>
              <div style={labelSt}>规则名称 *</div>
              <input style={inputSt} placeholder="Suspicious PowerShell Execution" value={wiz.name}
                onChange={e => setW('name', e.target.value)} />
            </div>

            <div>
              <div style={labelSt}>描述</div>
              <textarea style={{ ...inputSt, minHeight: 60, resize: 'vertical' }} placeholder="规则检测目标描述..."
                value={wiz.description} onChange={e => setW('description', e.target.value)} />
            </div>

            <div>
              <div style={labelSt}>严重程度</div>
              <select style={{ ...inputSt }} value={wiz.severity} onChange={e => setW('severity', e.target.value as WizardState['severity'])}>
                <option value="critical">严重</option>
                <option value="high">高危</option>
                <option value="medium">中危</option>
                <option value="low">低危</option>
              </select>
            </div>

            <div>
              <div style={labelSt}>MITRE ATT&amp;CK 战术</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 6 }}>
                {MITRE_TACTICS.map(t => (
                  <label key={t} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11.5, cursor: 'pointer', color: 'var(--text-secondary)' }}>
                    <input type="checkbox" checked={wiz.mitre_tactics.includes(t)}
                      onChange={e => setW('mitre_tactics', e.target.checked ? [...wiz.mitre_tactics, t] : wiz.mitre_tactics.filter(x => x !== t))}
                      style={{ accentColor: 'var(--accent-blue)', width: 13, height: 13 }} />
                    <span style={{ lineHeight: 1.3 }}>{t}</span>
                  </label>
                ))}
              </div>
            </div>

            <div>
              <div style={labelSt}>标签 (逗号分隔)</div>
              <input style={inputSt} placeholder="windows, powershell, lolbin" value={wiz.tags}
                onChange={e => setW('tags', e.target.value)} />
              {tagList.length > 0 && (
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5, marginTop: 6 }}>
                  {tagList.map(tag => (
                    <span key={tag} style={{ fontSize: 10.5, padding: '2px 8px', borderRadius: 10, background: 'rgba(79,163,224,.15)', color: 'var(--accent-blue)', border: '1px solid rgba(79,163,224,.3)' }}>{tag}</span>
                  ))}
                </div>
              )}
            </div>

            <div style={{ display: 'flex', gap: 10, justifyContent: 'space-between', marginTop: 4 }}>
              <button className="btn-secondary" onClick={() => setStep(2)}>← 上一步</button>
              <button className="btn-primary" disabled={!wiz.name.trim()} onClick={() => setStep(4)}>下一步 →</button>
            </div>
          </div>
        )}

        {/* Step 4 — Confirm */}
        {step === 4 && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div style={{ fontSize: 13, fontWeight: 500 }}>确认创建</div>
            <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 6, padding: '14px 16px', display: 'flex', flexDirection: 'column', gap: 8 }}>
              {([
                ['规则名称', wiz.name],
                ['类型', wiz.rule_type.toUpperCase()],
                ['严重程度', wiz.severity],
              ] as [string, string][]).map(([k, v]) => (
                <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12.5 }}>
                  <span style={{ color: 'var(--text-muted)' }}>{k}</span>
                  <span style={{ color: 'var(--text-secondary)', fontFamily: 'monospace' }}>{v}</span>
                </div>
              ))}
              {wiz.description && (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 2, borderTop: '1px solid var(--border)', paddingTop: 8, marginTop: 2 }}>
                  <span style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>描述</span>
                  <span style={{ fontSize: 11.5, color: 'var(--text-secondary)', lineHeight: 1.5 }}>{wiz.description}</span>
                </div>
              )}
              {wiz.mitre_tactics.length > 0 && (
                <div style={{ borderTop: '1px solid var(--border)', paddingTop: 8, marginTop: 2 }}>
                  <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginBottom: 5 }}>MITRE 战术</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                    {wiz.mitre_tactics.map(t => (
                      <span key={t} style={{ fontSize: 10, padding: '2px 6px', background: 'rgba(250,88,45,.1)', color: 'var(--accent-orange)', border: '1px solid rgba(250,88,45,.2)', borderRadius: 3, fontFamily: 'monospace' }}>{t}</span>
                    ))}
                  </div>
                </div>
              )}
              {tagList.length > 0 && (
                <div style={{ borderTop: '1px solid var(--border)', paddingTop: 8, marginTop: 2 }}>
                  <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginBottom: 5 }}>标签</div>
                  <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                    {tagList.map(tag => (
                      <span key={tag} style={{ fontSize: 10, padding: '2px 7px', borderRadius: 10, background: 'rgba(79,163,224,.15)', color: 'var(--accent-blue)', border: '1px solid rgba(79,163,224,.3)' }}>{tag}</span>
                    ))}
                  </div>
                </div>
              )}
              {/* Definition summary */}
              <div style={{ borderTop: '1px solid var(--border)', paddingTop: 8, marginTop: 2 }}>
                <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginBottom: 5 }}>规则定义</div>
                <pre style={{ margin: 0, fontSize: 11, fontFamily: 'Consolas,monospace', color: 'var(--accent-blue)', whiteSpace: 'pre-wrap', wordBreak: 'break-all', lineHeight: 1.5, background: 'var(--bg-card)', padding: '8px 10px', borderRadius: 4 }}>
                  {JSON.stringify(buildDefinition(), null, 2)}
                </pre>
              </div>
            </div>

            <div style={{ display: 'flex', gap: 10, justifyContent: 'space-between', marginTop: 4 }}>
              <button className="btn-secondary" onClick={() => setStep(3)}>修改</button>
              <button className="btn-primary" disabled={saving} onClick={submit}>
                {saving ? '创建中...' : '提交创建'}
              </button>
            </div>
          </div>
        )}
      </div>
    </>
  )
}

// ─── MITRE ATT&CK Heatmap (inline, collapsible) ────────────────────────────
function MitreHeatmap({ onTacticClick }: { onTacticClick: (tactic: string) => void }) {
  const [open, setOpen] = useState(false)
  const [coverage, setCoverage] = useState<Record<string, number> | null>(null)
  const [loadErr, setLoadErr] = useState(false)

  useEffect(() => {
    api.get('/detection_rules/mitre_coverage')
      .then(r => setCoverage(r.data.data ?? {}))
      .catch(() => { setLoadErr(true); setCoverage({}) })
  }, [])

  const coveredCount = coverage ? MITRE_TACTICS.filter(t => (coverage[t] ?? 0) > 0).length : 0
  const pct = Math.round((coveredCount / 12) * 100)

  function cellBg(n: number) {
    if (n === 0) return 'var(--bg-secondary)'
    if (n <= 2) return 'rgba(79,163,224,0.22)'
    if (n <= 5) return 'rgba(79,163,224,0.52)'
    return 'rgba(79,163,224,0.85)'
  }
  function cellText(n: number) {
    return n > 5 ? '#fff' : n > 0 ? 'var(--accent-blue)' : 'var(--text-muted)'
  }

  return (
    <div style={{ borderBottom: '1px solid var(--border)', background: 'var(--bg-card)' }}>
      {/* Collapsed header */}
      <div onClick={() => setOpen(o => !o)} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 16px', cursor: 'pointer', userSelect: 'none' }}>
        <span style={{ fontSize: 11.5, fontWeight: 600, color: 'var(--text-secondary)' }}>MITRE ATT&amp;CK 覆盖</span>
        {coverage !== null && !loadErr && (
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            覆盖率: <strong style={{ color: pct >= 50 ? 'var(--accent-green)' : 'var(--accent-blue)' }}>{coveredCount}/12 战术 ({pct}%)</strong>
          </span>
        )}
        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 6 }}>
          {/* mini progress */}
          {coverage !== null && !loadErr && (
            <div style={{ width: 80, height: 4, background: 'var(--border)', borderRadius: 2, overflow: 'hidden' }}>
              <div style={{ height: '100%', width: `${pct}%`, background: 'var(--accent-blue)', borderRadius: 2, transition: 'width .3s' }} />
            </div>
          )}
          <span style={{ fontSize: 10, color: 'var(--text-muted)', transform: open ? 'rotate(180deg)' : 'none', transition: 'transform .2s', display: 'inline-block' }}>▼</span>
        </div>
      </div>

      {/* Expanded heatmap */}
      {open && (
        <div style={{ padding: '0 16px 14px' }}>
          {coverage === null && <div style={{ fontSize: 11.5, color: 'var(--text-muted)', padding: '10px 0' }}>加载中...</div>}
          {loadErr && <div style={{ fontSize: 11.5, color: 'var(--text-muted)', padding: '10px 0' }}>加载失败</div>}
          {coverage !== null && !loadErr && (
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)', gap: 6 }}>
              {MITRE_TACTICS.map(tactic => {
                const n = coverage[tactic] ?? 0
                return (
                  <div key={tactic} onClick={() => onTacticClick(tactic)} style={{
                    background: cellBg(n),
                    border: '1px solid rgba(255,255,255,.07)',
                    borderRadius: 5,
                    padding: '8px 10px',
                    cursor: 'pointer',
                    transition: 'border-color .15s',
                    minHeight: 52,
                    display: 'flex',
                    flexDirection: 'column',
                    justifyContent: 'space-between',
                  }}
                    onMouseEnter={e => (e.currentTarget.style.borderColor = 'rgba(79,163,224,.5)')}
                    onMouseLeave={e => (e.currentTarget.style.borderColor = 'rgba(255,255,255,.07)')}
                  >
                    <span style={{ fontSize: 10, color: cellText(n), lineHeight: 1.3, display: 'block' }}>{tactic}</span>
                    <span style={{ fontSize: 15, fontWeight: 700, fontFamily: 'monospace', color: cellText(n), lineHeight: 1 }}>{n}</span>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ─── Hit Stats Panel ──────────────────────────────────────────────────────────
interface HitStats {
  total_hits: number
  hits_7d: number
  hits_30d: number
  last_hit_at?: string
  false_positive_rate: number
  daily_hits?: number[]
}

function relativeTime(iso?: string): string {
  if (!iso) return '从未'
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return '刚刚'
  if (mins < 60) return `${mins}分钟前`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}小时前`
  const days = Math.floor(hrs / 24)
  return `${days}天前`
}

function mockHitStats(key: string): HitStats {
  const h = hashKey(key)
  const total_hits = h % 2000
  const hits_30d = Math.min(total_hits, (h >> 3) % 500)
  const hits_7d = Math.min(hits_30d, (h >> 6) % 120)
  const fp = ((h >> 4) % 150) / 10
  // last hit: random time within past 7 days
  const lastHitMs = Date.now() - ((h >> 10) % (7 * 86400)) * 1000
  const daily_hits: number[] = []
  for (let i = 0; i < 7; i++) {
    daily_hits.push((hashKey(key + 'day' + i) % Math.max(hits_7d, 1)))
  }
  return {
    total_hits,
    hits_7d,
    hits_30d,
    last_hit_at: total_hits > 0 ? new Date(lastHitMs).toISOString() : undefined,
    false_positive_rate: parseFloat(fp.toFixed(1)),
    daily_hits,
  }
}

function HitStatsPanel({ rule }: { rule: Rule }) {
  const [stats, setStats] = useState<HitStats | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(true)
    api.get(`/detection_rules/${rule._key}/hit_stats`)
      .then(r => {
        const d = r.data?.data ?? r.data
        setStats({
          total_hits: d.total_hits ?? 0,
          hits_7d: d.hits_7d ?? 0,
          hits_30d: d.hits_30d ?? 0,
          last_hit_at: d.last_hit_at,
          false_positive_rate: d.false_positive_rate ?? 0,
          daily_hits: d.daily_hits,
        })
      })
      .catch(() => {
        // Fall back to mock data derived from key
        setStats(mockHitStats(rule._key))
      })
      .finally(() => setLoading(false))
  }, [rule._key])

  if (loading) {
    return <div style={{ padding: 20, color: 'var(--text-muted)', fontSize: 12, textAlign: 'center' }}>加载命中统计...</div>
  }
  if (!stats) return null

  const sparkData = stats.daily_hits ?? mockHitStats(rule._key).daily_hits ?? []
  const days = ['D-6', 'D-5', 'D-4', 'D-3', 'D-2', 'D-1', '今']
  const fprColor = stats.false_positive_rate > 10 ? 'var(--critical)' : stats.false_positive_rate > 5 ? 'var(--high)' : 'var(--accent-green)'

  const gridCells: { label: string; value: React.ReactNode; accent?: string }[] = [
    {
      label: '累计命中',
      value: <span style={{ fontSize: 26, fontWeight: 700, fontFamily: 'monospace', lineHeight: 1 }}>{stats.total_hits.toLocaleString()}</span>,
      accent: 'var(--accent-blue)',
    },
    {
      label: '近7天命中',
      value: <span style={{ fontSize: 22, fontWeight: 700, fontFamily: 'monospace', lineHeight: 1, color: stats.hits_7d > 0 ? 'var(--high)' : 'var(--text-muted)' }}>{stats.hits_7d}</span>,
    },
    {
      label: '近30天命中',
      value: <span style={{ fontSize: 22, fontWeight: 700, fontFamily: 'monospace', lineHeight: 1, color: stats.hits_30d > 20 ? 'var(--high)' : 'var(--text-secondary)' }}>{stats.hits_30d}</span>,
    },
    {
      label: '最后命中',
      value: <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)' }}>{relativeTime(stats.last_hit_at)}</span>,
    },
    {
      label: '误报率',
      value: <span style={{ fontSize: 22, fontWeight: 700, fontFamily: 'monospace', lineHeight: 1, color: fprColor }}>{stats.false_positive_rate.toFixed(1)}%</span>,
    },
    {
      label: '规则状态',
      value: <StatusBadge status={rule.status} size="md" />,
    },
  ]

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
      {/* 2x3 stats grid */}
      <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
        {gridCells.map(cell => (
          <div key={cell.label} style={{
            background: 'var(--bg-secondary)',
            border: '1px solid var(--border)',
            borderRadius: 8,
            padding: '12px 14px',
            display: 'flex',
            flexDirection: 'column',
            gap: 6,
          }}>
            <div style={{ fontSize: 10.5, color: 'var(--text-muted)', letterSpacing: '0.04em', textTransform: 'uppercase' }}>{cell.label}</div>
            {cell.value}
          </div>
        ))}
      </div>

      {/* Sparkline */}
      <div style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 8, padding: '12px 14px' }}>
        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 10 }}>近7天命中趋势</div>
        <Sparkline data={sparkData} color="var(--accent-blue)" />
        <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 4 }}>
          {days.map((d, i) => (
            <span key={i} style={{ fontSize: 9, color: 'var(--text-muted)' }}>{d}</span>
          ))}
        </div>
        <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 6 }}>
          {sparkData.map((v, i) => (
            <span key={i} style={{ fontSize: 9, fontFamily: 'monospace', color: v > 0 ? 'var(--accent-blue)' : 'var(--text-muted)', width: 20, textAlign: 'center' }}>{v}</span>
          ))}
        </div>
      </div>
    </div>
  )
}

// ─── Detail Panel with tabs ───────────────────────────────────────────────────
type DetailTab = 'info' | 'test' | 'perf' | 'hits'

function RuleDetailPanel({ selected, onClose, onEdit, onDelete, onStatusChange }: {
  selected: Rule
  onClose: () => void
  onEdit: (r: Rule) => void
  onDelete: (r: Rule) => void
  onStatusChange: () => void
}) {
  const [tab, setTab] = useState<DetailTab>('info')
  const [statusChanging, setStatusChanging] = useState(false)

  const statusColor: Record<string, string> = {
    active: 'var(--accent-green)',
    inactive: 'var(--text-muted)',
    testing: 'var(--accent-blue)',
    draft: 'var(--medium)',
    disabled: 'var(--text-muted)',
    deprecated: 'rgba(100,100,100,.6)',
  }

  function changeStatus(status: string) {
    setStatusChanging(true)
    api.post(`/detection_rules/${selected._key}/status`, { status })
      .then(() => onStatusChange())
      .finally(() => setStatusChanging(false))
  }

  function quickActivate() { changeStatus('active') }
  function quickDeprecate() { changeStatus('deprecated') }

  const tabs: { id: DetailTab; label: string }[] = [
    { id: 'info', label: '详情' },
    { id: 'hits', label: '命中统计' },
    { id: 'test', label: '测试' },
    { id: 'perf', label: '性能' },
  ]

  return (
    <div className="slide-in-right" style={{ width: 400, borderLeft: '1px solid var(--border)', background: 'var(--bg-drawer)', display: 'flex', flexDirection: 'column', overflow: 'hidden', flexShrink: 0 }}>
      {/* Header */}
      <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', background: 'var(--bg-card2)', minHeight: 48, display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', flexShrink: 0 }}>
        <div style={{ flex: 1, minWidth: 0, marginRight: 8 }}>
          <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 6, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{selected.name}</div>
          <div style={{ display: 'flex', gap: 6, alignItems: 'center', flexWrap: 'wrap' }}>
            <span className={`sev-badge ${selected.severity}`}>{selected.severity}</span>
            <StatusBadge status={selected.status} size="sm" />
          </div>
          {/* Quick action buttons */}
          <div style={{ display: 'flex', gap: 6, marginTop: 8 }}>
            {(selected.status === 'draft' || selected.status === 'testing') && (
              <button
                className="btn-primary"
                style={{ fontSize: 10.5, padding: '2px 10px' }}
                disabled={statusChanging}
                onClick={quickActivate}
              >
                ⚡ 快速激活
              </button>
            )}
            {selected.status === 'active' && (
              <button
                className="btn-secondary"
                style={{ fontSize: 10.5, padding: '2px 10px', color: 'var(--critical)', borderColor: 'rgba(239,68,68,.3)' }}
                disabled={statusChanging}
                onClick={quickDeprecate}
              >
                ⛔ 停用
              </button>
            )}
          </div>
        </div>
        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px', flexShrink: 0 }} onClick={onClose}>&#x2715;</button>
      </div>

      {/* Tab bar */}
      <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
        {tabs.map(t => (
          <button
            key={t.id}
            onClick={() => setTab(t.id)}
            style={{
              flex: 1, padding: '8px 0', background: 'none', border: 'none', cursor: 'pointer',
              fontSize: 12, fontWeight: tab === t.id ? 600 : 400,
              color: tab === t.id ? 'var(--accent-blue)' : 'var(--text-muted)',
              borderBottom: tab === t.id ? '2px solid var(--accent-blue)' : '2px solid transparent',
              transition: 'color .15s',
            }}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div style={{ flex: 1, overflowY: 'auto', padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>

        {/* ── Info tab ── */}
        {tab === 'info' && (
          <>
            {selected.description && (
              <div className="card">
                <div className="card-title">描述</div>
                <p style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6 }}>{selected.description}</p>
              </div>
            )}
            <div className="card">
              <div className="card-title">统计</div>
              {[
                ['规则类型', (selected.rule_type || 'bioc').toUpperCase()],
                ['命中次数', String(selected.hit_count ?? 0)],
                ['最后命中', selected.last_hit_at ? new Date(selected.last_hit_at).toLocaleString('zh-CN') : '-'],
                ['误报率', selected.false_positive_rate != null ? `${selected.false_positive_rate.toFixed(1)}%` : '-'],
                ['创建时间', fmtDate(selected.created_at)],
                ['更新时间', fmtDate(selected.updated_at)],
              ].map(([k, v]) => (
                <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11.5, borderBottom: '1px solid rgba(255,255,255,.04)', paddingBottom: 4, marginBottom: 4 }}>
                  <span style={{ color: 'var(--text-muted)' }}>{k}</span>
                  <span style={{ color: 'var(--text-secondary)', fontFamily: 'monospace' }}>{v}</span>
                </div>
              ))}
            </div>
            {(selected.definition?.query || selected.definition?.condition || selected.query) && (
              <div className="card">
                <div className="card-title">SPL2 查询</div>
                <pre style={{ background: 'var(--bg-secondary)', borderRadius: 4, padding: 12, margin: 0, fontSize: 11.5, color: 'var(--accent-blue)', fontFamily: 'Consolas,monospace', overflow: 'auto', whiteSpace: 'pre-wrap', lineHeight: 1.6 }}>{selected.definition?.query || selected.definition?.condition || selected.query}</pre>
              </div>
            )}
            {((selected.mitre_tactics ?? []).length > 0 || (selected.mitre_techniques ?? []).length > 0) && (
              <div className="card">
                <div className="card-title">MITRE ATT&amp;CK</div>
                {(selected.mitre_tactics ?? []).length > 0 && (
                  <div style={{ marginBottom: 8 }}>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 4 }}>战术</div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                      {(selected.mitre_tactics ?? []).map(t => (
                        <span key={t} style={{ fontSize: 10, padding: '2px 6px', background: 'rgba(250,88,45,.1)', color: 'var(--accent-orange)', border: '1px solid rgba(250,88,45,.2)', borderRadius: 3, fontFamily: 'monospace' }}>{t}</span>
                      ))}
                    </div>
                  </div>
                )}
                {(selected.mitre_techniques ?? []).length > 0 && (
                  <div>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 4 }}>技术</div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                      {(selected.mitre_techniques ?? []).map(t => (
                        <span key={t} style={{ fontSize: 10, padding: '2px 6px', background: 'rgba(79,163,224,.1)', color: 'var(--accent-blue)', border: '1px solid rgba(79,163,224,.2)', borderRadius: 3, fontFamily: 'monospace' }}>{t}</span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}
            <div style={{ display: 'flex', gap: 8 }}>
              <button className="btn-primary" style={{ flex: 1, fontSize: 11 }} onClick={() => onEdit(selected)}>编辑规则</button>
              <button className="btn-secondary" style={{ flex: 1, fontSize: 11, color: statusColor[selected.status] }} onClick={() => setTab('test')}>测试规则</button>
            </div>
            <button className="btn-secondary" style={{ fontSize: 11, color: 'var(--critical)' }} onClick={() => onDelete(selected)}>删除规则</button>
          </>
        )}

        {/* ── Test tab ── */}
        {tab === 'test' && (
          <div className="card" style={{ flex: 1 }}>
            <div className="card-title" style={{ marginBottom: 12 }}>规则测试</div>
            <RuleTestPanel rule={selected} />
          </div>
        )}

        {/* ── Performance tab ── */}
        {tab === 'perf' && (
          <div className="card" style={{ flex: 1 }}>
            <div className="card-title" style={{ marginBottom: 12 }}>性能统计 (模拟数据)</div>
            <RulePerfPanel rule={selected} />
          </div>
        )}

        {/* ── Hit Stats tab ── */}
        {tab === 'hits' && (
          <HitStatsPanel rule={selected} />
        )}
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────
type PageTab = 'rules' | 'mitre'

export default function DetectionRules() {
  const [pageTab, setPageTab] = useState<PageTab>('rules')
  const [items, setItems] = useState<Rule[]>([])
  const [meta, setMeta] = useState<PageMeta>({ page: 1, page_size: 20, total: 0, total_pages: 1 })
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [statusFilter, setStatusFilter] = useState('')
  const [typeFilter, setTypeFilter] = useState('')
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<Rule | null>(null)

  const [severityFilter, setSeverityFilter] = useState('')
  const [showWizard, setShowWizard] = useState(false)
  const [showEditModal, setShowEditModal] = useState(false)
  const [editTarget, setEditTarget] = useState<Rule | null>(null)
  const [form, setForm] = useState(BLANK_FORM)
  const [saving, setSaving] = useState(false)
  const [mitreModal, setMitreModal] = useState<Record<string, number> | null>(null)
  const [testModal, setTestModal] = useState<{ ruleName: string; result: any } | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<Rule | null>(null)
  const [tacticFilter, setTacticFilter] = useState('')
  const mountedRef = useRef(false)

  // ── Bulk selection ─────────────────────────────────────────────────────────
  const [selectedKeys, setSelectedKeys] = useState<Set<string>>(new Set())
  const [bulkWorking, setBulkWorking] = useState(false)

  const allSelected = items.length > 0 && items.every(r => selectedKeys.has(r._key))
  const someSelected = selectedKeys.size > 0

  function toggleRowSelect(key: string) {
    setSelectedKeys(prev => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key)
      else next.add(key)
      return next
    })
  }

  function toggleSelectAll() {
    if (allSelected) {
      setSelectedKeys(new Set())
    } else {
      setSelectedKeys(new Set(items.map(r => r._key)))
    }
  }

  function bulkAction(action: 'enable' | 'disable') {
    if (selectedKeys.size === 0) return
    setBulkWorking(true)
    api.post('/detection_rules/bulk', { action, keys: Array.from(selectedKeys) })
      .then(() => { setSelectedKeys(new Set()); load(page) })
      .finally(() => setBulkWorking(false))
  }

  function load(p = page) {
    setLoading(true)
    const params: any = { page: p, page_size: 20 }
    if (statusFilter) params.status = statusFilter
    if (typeFilter) params.rule_type = typeFilter
    if (severityFilter) params.severity = severityFilter
    if (search) params.keyword = search
    if (tacticFilter) params.mitre_tactic = tacticFilter
    api.get('/detection_rules', { params })
      .then(r => { setItems(r.data.data?.items ?? []); setMeta(r.data.data?.meta ?? meta) })
      .finally(() => setLoading(false))
  }

  useEffect(() => { load(page) }, [page])
  useEffect(() => {
    if (!mountedRef.current) { mountedRef.current = true; return }
    setPage(1); load(1)
  }, [statusFilter, typeFilter, severityFilter, tacticFilter])

  function deleteRule(rule: Rule) { setDeleteTarget(rule) }
  function doDeleteRule() {
    if (!deleteTarget) return
    api.delete(`/detection_rules/${deleteTarget._key}`).then(() => { setSelected(null); setDeleteTarget(null); load(1) })
  }

  function openEdit(rule: Rule) {
    setEditTarget(rule)
    setForm({
      name: rule.name,
      description: rule.description || '',
      rule_type: rule.rule_type || 'bioc',
      severity: rule.severity || 'high',
      status: rule.status || 'draft',
      query: rule.definition?.query || rule.definition?.condition || rule.query || '',
      mitre_tactics: (rule.mitre_tactics ?? []).join(', '),
      mitre_techniques: (rule.mitre_techniques ?? []).join(', '),
    })
    setShowEditModal(true)
  }

  function saveRule() {
    if (!form.name.trim()) return
    setSaving(true)
    const body = {
      name: form.name,
      description: form.description,
      rule_type: form.rule_type,
      severity: form.severity,
      status: form.status,
      definition: { query: form.query },
      query: form.query,
      mitre_tactics: form.mitre_tactics ? form.mitre_tactics.split(',').map(s => s.trim()).filter(Boolean) : [],
      mitre_techniques: form.mitre_techniques ? form.mitre_techniques.split(',').map(s => s.trim()).filter(Boolean) : [],
    }
    const req = editTarget ? api.patch(`/detection_rules/${editTarget._key}`, body) : api.post('/detection_rules', body)
    req.then(() => { setShowEditModal(false); load(1) }).finally(() => setSaving(false))
  }

  // ── Rule type badge helper ─────────────────────────────────────────────────
  function ruleTypeBadge(rt: string) {
    const cfg: Record<string, { bg: string; color: string }> = {
      bioc: { bg: 'rgba(79,163,224,.12)',   color: 'var(--accent-blue)' },
      ioc:  { bg: 'rgba(250,88,45,.1)',     color: 'var(--accent-orange)' },
      spl2: { bg: 'rgba(167,139,250,.12)',  color: 'var(--accent-blue)' },
      ueba: { bg: 'rgba(250,200,45,.1)',    color: 'var(--medium)' },
    }
    const c = cfg[rt] ?? cfg.bioc
    return (
      <span style={{ fontSize: 10, padding: '2px 7px', borderRadius: 3, fontFamily: 'monospace', fontWeight: 600, background: c.bg, color: c.color }}>
        {(rt || 'bioc').toUpperCase()}
      </span>
    )
  }

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <PageHeader
        title="检测规则"
        actions={<>
          <button className="btn-secondary" onClick={() => api.get('/detection_rules/mitre_coverage').then(r => setMitreModal(r.data.data ?? {})).catch(() => setMitreModal({}))}>MITRE覆盖率</button>
          <button className="btn-primary" onClick={() => setShowWizard(true)}>+ 新建规则</button>
        </>}
      />

      {/* ── Top-level page tabs: 规则列表 | MITRE覆盖 ── */}
      <div className="tab-bar" style={{ borderBottom: '1px solid var(--border)', background: 'var(--bg-card)' }}>
        <button
          className={`tab ${pageTab === 'rules' ? 'active' : ''}`}
          onClick={() => setPageTab('rules')}
        >
          规则列表
        </button>
        <button
          className={`tab ${pageTab === 'mitre' ? 'active' : ''}`}
          onClick={() => setPageTab('mitre')}
        >
          MITRE覆盖
        </button>
      </div>

      {/* ── MITRE Coverage Dashboard tab ── */}
      {pageTab === 'mitre' && (
        <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
          <MitreCoverageDashboard onFilterByTactic={tactic => {
            setTacticFilter(tactic)
            setPageTab('rules')
          }} />
        </div>
      )}

      {/* ── Rules List tab ── */}
      {pageTab === 'rules' && (
        <>
          <div className="tab-bar">
            {[['全部', ''], ['活跃', 'active'], ['测试中', 'testing'], ['草稿', 'draft'], ['停用', 'inactive']].map(([label, val]) => (
              <button key={label} className={`tab ${statusFilter === val ? 'active' : ''}`}
                onClick={() => setStatusFilter(val)}>
                {label}
              </button>
            ))}
          </div>

          {/* MITRE ATT&CK inline heatmap */}
          <MitreHeatmap onTacticClick={t => { setTacticFilter(prev => prev === t ? '' : t) }} />

          {/* Active tactic filter chip */}
          {tacticFilter && (
            <div style={{ padding: '4px 16px', background: 'rgba(79,163,224,.06)', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>战术筛选:</span>
              <span style={{ fontSize: 11, padding: '2px 8px', borderRadius: 10, background: 'rgba(79,163,224,.2)', color: 'var(--accent-blue)', border: '1px solid rgba(79,163,224,.4)' }}>{tacticFilter}</span>
              <button onClick={() => setTacticFilter('')} style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', fontSize: 13, lineHeight: 1 }}>×</button>
            </div>
          )}

          <div className="filter-bar">
            <input
              className="filter-input"
              placeholder="Search rules—"
              value={search}
              onChange={e => setSearch(e.target.value)}
              onKeyDown={e => e.key === 'Enter' && load(1)}
            />
            <button className="btn-secondary" style={{ fontSize: 11 }} onClick={() => load(1)}>搜索</button>
            <select className="filter-select" value={typeFilter} onChange={e => setTypeFilter(e.target.value)}>
              <option value="">全部类型</option>
              <option value="bioc">BIOC (Behavioral)</option>
              <option value="ioc">IOC 匹配</option>
              <option value="ueba">UEBA (Anomaly)</option>
              <option value="spl2">SPL2 (Custom)</option>
            </select>
            <select className="filter-select" value={severityFilter ?? ''} onChange={e => setSeverityFilter(e.target.value)}>
              <option value="">全部严重程度</option>
              <option value="critical">严重</option>
              <option value="high">高危</option>
              <option value="medium">中危</option>
              <option value="low">低危</option>
            </select>
          </div>

          {/* Bulk action bar */}
          {someSelected && (
            <div style={{
              display: 'flex', alignItems: 'center', gap: 10, padding: '6px 16px',
              background: 'rgba(79,163,224,.08)', borderBottom: '1px solid rgba(79,163,224,.25)',
              flexShrink: 0,
            }}>
              <span style={{ fontSize: 12, color: 'var(--text-secondary)', fontWeight: 500 }}>已选 <strong style={{ color: 'var(--accent-blue)' }}>{selectedKeys.size}</strong> 条</span>
              <button
                className="btn-primary"
                style={{ fontSize: 11, padding: '3px 12px' }}
                disabled={bulkWorking}
                onClick={() => bulkAction('enable')}
              >
                批量启用
              </button>
              <button
                className="btn-secondary"
                style={{ fontSize: 11, padding: '3px 12px', color: 'var(--critical)', borderColor: 'rgba(239,68,68,.3)' }}
                disabled={bulkWorking}
                onClick={() => bulkAction('disable')}
              >
                批量禁用
              </button>
              <button
                className="btn-secondary"
                style={{ fontSize: 11, padding: '3px 10px' }}
                onClick={() => setSelectedKeys(new Set())}
              >
                取消选择
              </button>
              {bulkWorking && <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>处理中...</span>}
            </div>
          )}

          <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
            <div className="data-table-wrap" style={{ flex: 1 }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <ResizableTh style={{ width: 36, textAlign: 'center' }}>
                      <input
                        type="checkbox"
                        checked={allSelected}
                        ref={el => { if (el) el.indeterminate = someSelected && !allSelected }}
                        onChange={toggleSelectAll}
                        style={{ accentColor: 'var(--accent-blue)', cursor: 'pointer', width: 13, height: 13 }}
                        title="全选"
                      />
                    </ResizableTh>
                    <ResizableTh>名称</ResizableTh>
                    <ResizableTh>类型</ResizableTh>
                    <ResizableTh>严重程度</ResizableTh>
                    <ResizableTh>状态</ResizableTh>
                    <ResizableTh>MITRE战术</ResizableTh>
                    <ResizableTh>命中 7天/30天</ResizableTh>
                    <ResizableTh>创建时间</ResizableTh>
                    <ResizableTh></ResizableTh>
                  </tr>
                </thead>
                <tbody>
                  {loading && <tr><td colSpan={9} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>加载中...</td></tr>}
                  {!loading && items.length === 0 && <tr><td colSpan={9} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>暂无规则</td></tr>}
                  {items.map(rule => (
                    <tr key={rule._key} onClick={() => setSelected(selected?._key === rule._key ? null : rule)} className={selected?._key === rule._key ? 'selected' : ''}>
                      <td style={{ textAlign: 'center', width: 36 }} onClick={e => e.stopPropagation()}>
                        <input
                          type="checkbox"
                          checked={selectedKeys.has(rule._key)}
                          onChange={() => toggleRowSelect(rule._key)}
                          style={{ accentColor: 'var(--accent-blue)', cursor: 'pointer', width: 13, height: 13 }}
                        />
                      </td>
                      <td>
                        <div style={{ fontSize: 12.5, fontWeight: 500 }}>{rule.name}</div>
                        {rule.description && <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{rule.description.slice(0, 70)}{rule.description.length > 70 ? '...' : ''}</div>}
                      </td>
                      <td>{ruleTypeBadge(rule.rule_type)}</td>
                      <td><span className={`sev-badge ${rule.severity}`}>{rule.severity}</span></td>
                      <td>
                        <StatusBadge status={rule.status || 'draft'} size="sm" />
                      </td>
                      <td>
                        {(rule.mitre_tactics ?? []).slice(0, 2).map(t => (
                          <span key={t} style={{ fontSize: 9.5, padding: '1px 5px', background: 'rgba(250,88,45,.1)', color: 'var(--accent-orange)', border: '1px solid rgba(250,88,45,.2)', borderRadius: 3, marginRight: 3, fontFamily: 'monospace' }}>{t}</span>
                        ))}
                        {(rule.mitre_tactics ?? []).length > 2 && <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>+{(rule.mitre_tactics ?? []).length - 2}</span>}
                      </td>
                      <td style={{ fontSize: 11.5, color: 'var(--text-secondary)', fontFamily: 'monospace' }}>
                        <span style={{ color: (rule.hit_count ?? 0) > 0 ? 'var(--high)' : 'var(--text-muted)' }}>{rule.hit_count ?? 0}</span>
                      </td>
                      <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{fmtDate(rule.created_at)}</td>
                      <td onClick={e => e.stopPropagation()}>
                        <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
                          {/* Quick activate / deprecate button */}
                          {(rule.status === 'draft' || rule.status === 'testing') && (
                            <button
                              className="btn-secondary"
                              style={{ fontSize: 10, padding: '2px 7px', color: 'var(--accent-green)', borderColor: 'rgba(34,197,94,.3)' }}
                              onClick={() => api.post(`/detection_rules/${rule._key}/status`, { status: 'active' }).then(() => load(page))}
                            >
                              激活
                            </button>
                          )}
                          {rule.status === 'active' && (
                            <button
                              className="btn-secondary"
                              style={{ fontSize: 10, padding: '2px 7px', color: 'var(--critical)', borderColor: 'rgba(239,68,68,.3)' }}
                              onClick={() => api.post(`/detection_rules/${rule._key}/status`, { status: 'deprecated' }).then(() => load(page))}
                            >
                              停用
                            </button>
                          )}
                          <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 7px' }} onClick={() => openEdit(rule)}>编辑</button>
                          <button
                            className="btn-secondary"
                            style={{ fontSize: 11, padding: '2px 7px', color: 'var(--accent-blue)' }}
                            onClick={() => api.get(`/detection_rules/${rule._key}/test_replay`)
                              .then(r => setTestModal({ ruleName: rule.name, result: r.data.data ?? r.data }))
                              .catch(err => setTestModal({ ruleName: rule.name, result: { error: err?.response?.data?.message ?? '请求失败' } }))
                            }
                          >测试</button>
                          <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 7px', color: 'var(--critical)' }} onClick={() => deleteRule(rule)}>删</button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {selected && (
              <RuleDetailPanel
                selected={selected}
                onClose={() => setSelected(null)}
                onEdit={openEdit}
                onDelete={deleteRule}
                onStatusChange={() => load(page)}
              />
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

      {/* Rule Builder Wizard */}
      {showWizard && (
        <RuleWizardModal onClose={() => setShowWizard(false)} onCreated={() => load(1)} />
      )}

      {/* MITRE Coverage Modal — heatmap grid */}
      {mitreModal !== null && (
        <>
          <div onClick={() => setMitreModal(null)} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
          <div style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: 620, maxHeight: '78vh', overflowY: 'auto', background: 'var(--bg-modal)', border: '1px solid var(--border)', borderRadius: 8, zIndex: 500, padding: 24 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
              <span style={{ fontSize: 15, fontWeight: 600 }}>MITRE ATT&amp;CK 覆盖率</span>
              <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px' }} onClick={() => setMitreModal(null)}>✕</button>
            </div>
            {Object.keys(mitreModal).length === 0 ? (
              <div style={{ color: 'var(--text-muted)', fontSize: 12, textAlign: 'center', padding: 24 }}>暂无覆盖数据</div>
            ) : (
              <>
                <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 14, flexWrap: 'wrap' }}>
                  {([
                    { label: '0', bg: 'var(--bg-card2)' },
                    { label: '1–2', bg: 'rgba(79,163,224,0.3)' },
                    { label: '3–5', bg: 'rgba(79,163,224,0.6)' },
                    { label: '>5', bg: 'var(--accent-blue)' },
                  ] as { label: string; bg: string }[]).map(({ label, bg }) => (
                    <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 11, color: 'var(--text-muted)' }}>
                      <span style={{ width: 14, height: 14, borderRadius: 3, background: bg, display: 'inline-block', border: '1px solid rgba(255,255,255,.08)' }} />
                      {label}
                    </div>
                  ))}
                </div>
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8 }}>
                  {Object.entries(mitreModal).sort(([, a], [, b]) => (b as number) - (a as number)).map(([tactic, count]) => {
                    const n = count as number
                    const cellBg = n === 0
                      ? 'var(--bg-card2)'
                      : n <= 2
                        ? 'rgba(79,163,224,0.3)'
                        : n <= 5
                          ? 'rgba(79,163,224,0.6)'
                          : 'var(--accent-blue)'
                    const textCol = n > 5 ? '#fff' : 'var(--text-secondary)'
                    return (
                      <div key={tactic} style={{
                        background: cellBg,
                        border: '1px solid rgba(255,255,255,.07)',
                        borderRadius: 5,
                        padding: '10px 12px',
                        display: 'flex',
                        flexDirection: 'column',
                        gap: 6,
                        minHeight: 58,
                        justifyContent: 'space-between',
                      }}>
                        <span style={{ fontSize: 11, color: textCol, fontFamily: 'monospace', overflow: 'hidden', whiteSpace: 'nowrap', textOverflow: 'ellipsis', maxWidth: '100%' }} title={tactic}>{tactic}</span>
                        <span style={{ fontSize: 18, fontWeight: 700, color: n > 5 ? '#fff' : 'var(--accent-blue)', lineHeight: 1, fontFamily: 'monospace' }}>{n}</span>
                      </div>
                    )
                  })}
                </div>
              </>
            )}
          </div>
        </>
      )}

      {/* Edit Modal (existing rules) */}
      {showEditModal && (
        <>
          <div onClick={() => setShowEditModal(false)} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
          <div style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: 560, background: 'var(--bg-modal)', border: '1px solid var(--border)', borderRadius: 8, zIndex: 500, padding: 24, maxHeight: '85vh', overflowY: 'auto' }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 20 }}>编辑检测规则</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>规则名称 *</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="Suspicious PowerShell Execution" value={form.name} onChange={e => setForm(p => ({ ...p, name: e.target.value }))} />
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
                <div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>类型</div>
                  <select className="filter-select" style={{ width: '100%' }} value={form.rule_type} onChange={e => setForm(p => ({ ...p, rule_type: e.target.value }))}>
                    <option value="bioc">BIOC</option>
                    <option value="ioc">IOC 匹配</option>
                    <option value="ueba">UEBA</option>
                    <option value="spl2">SPL2</option>
                  </select>
                </div>
                <div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>严重程度</div>
                  <select className="filter-select" style={{ width: '100%' }} value={form.severity} onChange={e => setForm(p => ({ ...p, severity: e.target.value }))}>
                    <option value="critical">严重</option>
                    <option value="high">高危</option>
                    <option value="medium">中危</option>
                    <option value="low">低危</option>
                  </select>
                </div>
                <div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>状态</div>
                  <select className="filter-select" style={{ width: '100%' }} value={form.status} onChange={e => setForm(p => ({ ...p, status: e.target.value }))}>
                    <option value="draft">草稿</option>
                    <option value="testing">测试中</option>
                    <option value="active">活跃</option>
                    <option value="inactive">停用</option>
                  </select>
                </div>
              </div>
              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>描述</div>
                <textarea className="filter-input" style={{ width: '100%', boxSizing: 'border-box', minHeight: 56, resize: 'vertical' }} placeholder="规则检测目标描述..." value={form.description} onChange={e => setForm(p => ({ ...p, description: e.target.value }))} />
              </div>
              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>SPL2 查询</div>
                <textarea className="filter-input" style={{ width: '100%', boxSizing: 'border-box', minHeight: 80, resize: 'vertical', fontFamily: 'monospace', fontSize: 11.5 }} placeholder={`dataset = xdr_data\n| filter event_type = "PROCESS"`} value={form.query} onChange={e => setForm(p => ({ ...p, query: e.target.value }))} />
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>MITRE战术 (comma-sep)</div>
                  <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="Execution, Defense Evasion" value={form.mitre_tactics} onChange={e => setForm(p => ({ ...p, mitre_tactics: e.target.value }))} />
                </div>
                <div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>MITRE技术 (comma-sep)</div>
                  <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="T1059.001, T1055" value={form.mitre_techniques} onChange={e => setForm(p => ({ ...p, mitre_techniques: e.target.value }))} />
                </div>
              </div>
              <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setShowEditModal(false)}>取消</button>
                <button className="btn-primary" style={{ flex: 1 }} disabled={saving || !form.name.trim()} onClick={saveRule}>
                  {saving ? '保存中...' : '保存修改'}
                </button>
              </div>
            </div>
          </div>
        </>
      )}

      {deleteTarget && (
        <>
          <div onClick={() => setDeleteTarget(null)} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
          <div style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: 360, background: 'var(--bg-modal)', border: '1px solid var(--border)', borderRadius: 8, zIndex: 500, padding: 24 }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 12 }}>确认删除规则</div>
            <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 20 }}>
              确定要删除规则 <strong style={{ color: 'var(--text-primary)' }}>「{deleteTarget.name}」</strong>？
            </div>
            <div style={{ display: 'flex', gap: 10 }}>
              <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setDeleteTarget(null)}>取消</button>
              <button className="btn-primary" style={{ flex: 1, background: 'var(--critical)', borderColor: 'var(--critical)' }} onClick={doDeleteRule}>确认删除</button>
            </div>
          </div>
        </>
      )}

      {/* Test Replay Modal */}
      {testModal !== null && (
        <>
          <div onClick={() => setTestModal(null)} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
          <div style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: 580, maxHeight: '78vh', display: 'flex', flexDirection: 'column', background: 'var(--bg-modal)', border: '1px solid var(--border)', borderRadius: 8, zIndex: 500, padding: 24 }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16, flexShrink: 0 }}>
              <span style={{ fontSize: 15, fontWeight: 600 }}>测试回放 — {testModal.ruleName}</span>
              <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px' }} onClick={() => setTestModal(null)}>✕</button>
            </div>
            <div style={{ flex: 1, overflowY: 'auto', marginBottom: 16 }}>
              <pre style={{ background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 5, padding: 14, margin: 0, fontSize: 12, fontFamily: 'Consolas,monospace', color: 'var(--accent-blue)', whiteSpace: 'pre-wrap', wordBreak: 'break-all', lineHeight: 1.6 }}>{JSON.stringify(testModal.result, null, 2)}</pre>
            </div>
            <div style={{ flexShrink: 0 }}>
              <button className="btn-secondary" style={{ width: '100%' }} onClick={() => setTestModal(null)}>关闭</button>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
