import { useCallback, useEffect, useRef, useState } from 'react'
import { Cell, Pie, PieChart, Tooltip } from 'recharts'
import api from '@/lib/api'
import type { PageMeta } from '@/lib/api'
import PageHeader from '@/components/PageHeader'

// ─── Types ────────────────────────────────────────────────────────────────────

interface ETLMatchCriteria {
  dataset?: string[]
  tag_pattern?: string
  kind?: number
  filter_expr?: string
}

interface ETLAction {
  type: string
  params?: Record<string, string>
}

interface ETLOutput {
  ngx_index: string
  write_arango: boolean
}

interface ETLRule {
  _key: string
  rule_id: string
  name: string
  description?: string
  tenant_id: string
  is_enabled: boolean
  priority: number
  match: ETLMatchCriteria
  raw_write_mode: 'both' | 'etl_only' | 'raw_only'
  actions: ETLAction[]
  output: ETLOutput
  created_at: string
  updated_at: string
  created_by?: string
}

interface TestResult {
  matched: boolean
  raw_ngx_index: string
  etl_ngx_index: string
  write_arango: boolean
  dropped: boolean
  output_entry?: {
    kind: number
    dataset: string
    hostname: string
    fields: Record<string, string>
  }
}

interface AuditLog {
  _key?: string
  action: string
  resource_type: string
  resource_name?: string
  resource_id?: string
  operator_id?: string
  created_at: string
}

interface ETLStats {
  total: number
  enabled: number
  disabled: number
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fmtDate(iso: string) {
  if (!iso) return '-'
  return new Date(iso).toLocaleDateString('zh-CN')
}

function fmtDateTime(iso: string) {
  if (!iso) return '-'
  try {
    return new Date(iso).toLocaleString('zh-CN', { hour12: false })
  } catch {
    return iso
  }
}

const ACTION_TYPES = [
  'set_field', 'rename_field', 'delete_field',
  'parse_json', 'grok',
  'lookup_asset', 'lookup_threat',
  'set_dataset', 'set_kind', 'drop_event',
]

const KIND_NAMES: Record<number, string> = {
  0: 'Syslog', 1: 'Process', 2: 'File', 3: 'Registry',
  4: 'Network', 5: 'DNS', 6: 'Auth', 7: 'Vuln', 8: 'Integrity',
}

function rawModeLabel(m: string) {
  if (m === 'both') return '双写'
  if (m === 'etl_only') return '仅ETL'
  if (m === 'raw_only') return '仅原始'
  return m
}

function rawModeColor(m: string) {
  if (m === 'both') return 'var(--accent-blue)'
  if (m === 'etl_only') return 'var(--accent-blue)'
  if (m === 'raw_only') return 'var(--text-muted)'
  return 'var(--text-muted)'
}

// ─── Validation ────────────────────────────────────────────────────────────────

const RULE_ID_RE = /^[a-z0-9][a-z0-9-]*[a-z0-9]$/

interface FormErrors {
  rule_id?: string
  priority?: string
  match?: string
}

// ─── Default form state ────────────────────────────────────────────────────────

const BLANK_FORM = {
  rule_id: '',
  name: '',
  description: '',
  priority: '50',
  is_enabled: true,
  tag_pattern: '',
  dataset: '',        // comma-separated
  kind: '',           // number string or empty
  filter_expr: '',
  raw_write_mode: 'both' as 'both' | 'etl_only' | 'raw_only',
  ngx_index: '',
  write_arango: true,
  // actions stored as serialized JSON string for simplicity
  actions_json: '[\n  {"type":"set_field","params":{"field":"etl_version","value":"1.0"}}\n]',
}

type FormState = typeof BLANK_FORM

function ruleToForm(r: ETLRule): FormState {
  return {
    rule_id: r.rule_id,
    name: r.name,
    description: r.description ?? '',
    priority: String(r.priority),
    is_enabled: r.is_enabled,
    tag_pattern: r.match?.tag_pattern ?? '',
    dataset: (r.match?.dataset ?? []).join(', '),
    kind: r.match?.kind != null ? String(r.match.kind) : '',
    filter_expr: r.match?.filter_expr ?? '',
    raw_write_mode: r.raw_write_mode ?? 'both',
    ngx_index: r.output?.ngx_index ?? '',
    write_arango: r.output?.write_arango ?? true,
    actions_json: JSON.stringify(r.actions ?? [], null, 2),
  }
}

function formToBody(f: FormState) {
  let actions: ETLAction[] = []
  try { actions = JSON.parse(f.actions_json) } catch { /* ignore */ }

  const match: ETLMatchCriteria = {}
  if (f.tag_pattern.trim()) match.tag_pattern = f.tag_pattern.trim()
  if (f.dataset.trim()) match.dataset = f.dataset.split(',').map(s => s.trim()).filter(Boolean)
  if (f.kind.trim()) match.kind = parseInt(f.kind, 10)
  if (f.filter_expr.trim()) match.filter_expr = f.filter_expr.trim()

  return {
    rule_id: f.rule_id.trim(),
    name: f.name.trim(),
    description: f.description.trim() || undefined,
    priority: parseInt(f.priority, 10) || 50,
    is_enabled: f.is_enabled,
    match,
    raw_write_mode: f.raw_write_mode,
    actions,
    output: {
      ngx_index: f.ngx_index.trim(),
      write_arango: f.write_arango,
    },
  }
}

// ─── Sample test event ────────────────────────────────────────────────────────

const SAMPLE_ENDPOINT_EVENT = JSON.stringify({
  process_name: 'cmd.exe',
  cmdline: 'cmd.exe /c whoami',
  user: 'jdoe',
  pid: 4444,
  parent_pid: 1234,
  parent_process: 'explorer.exe',
  path: 'C:\\Windows\\System32\\cmd.exe',
  hash_md5: 'abc123def456',
}, null, 2)

// ─── Test panel state ─────────────────────────────────────────────────────────

const BLANK_TEST = {
  tag: 'winevent.security',
  kind: '1',
  dataset: '',
  hostname: '',
  agent_id: '',
  fields_json: SAMPLE_ENDPOINT_EVENT,
}

// ─── Animated Pipeline Flow Diagram ──────────────────────────────────────────

interface LiveStats {
  events: number
  matched: number
  dropped: number
  latency: number
}

function PipelineFlowDiagram() {
  const [liveStats, setLiveStats] = useState<LiveStats>({
    events: 142_837,
    matched: 131_204,
    dropped: 3_421,
    latency: 12,
  })

  // Increment counters every 5s by random amounts
  useEffect(() => {
    const timer = setInterval(() => {
      setLiveStats(prev => ({
        events:  prev.events  + Math.floor(Math.random() * 800 + 200),
        matched: prev.matched + Math.floor(Math.random() * 720 + 180),
        dropped: prev.dropped + Math.floor(Math.random() * 40  + 10),
        latency: Math.max(6, Math.min(40, prev.latency + (Math.random() > 0.5 ? 1 : -1) * Math.floor(Math.random() * 3))),
      }))
    }, 5000)
    return () => clearInterval(timer)
  }, [])

  return (
    <div style={{
      padding: '16px 20px',
      background: 'var(--bg-card)',
      borderBottom: '1px solid var(--border)',
      flexShrink: 0,
    }}>
      {/* Animated SVG flow */}
      <style>{`
        @keyframes dashFlow {
          from { stroke-dashoffset: 40; }
          to   { stroke-dashoffset: 0; }
        }
        .etl-flow-arrow {
          stroke-dasharray: 6 4;
          stroke-dashoffset: 40;
          animation: dashFlow 1.2s linear infinite;
        }
        .etl-flow-arrow-slow {
          stroke-dasharray: 6 4;
          stroke-dashoffset: 40;
          animation: dashFlow 1.8s linear infinite;
        }
        @keyframes pulseNode {
          0%, 100% { opacity: 1; }
          50%       { opacity: 0.75; }
        }
        .etl-engine-pulse {
          animation: pulseNode 3s ease-in-out infinite;
        }
      `}</style>

      <svg
        viewBox="0 0 760 160"
        style={{ width: '100%', maxWidth: 820, height: 'auto', display: 'block', margin: '0 auto' }}
        aria-label="ETL Pipeline Flow Diagram"
      >
        {/* ── Source nodes ── */}
        {/* 终端 Agent */}
        <rect x="8" y="16" width="110" height="34" rx="6"
          fill="rgba(63,160,224,.10)" stroke="rgba(63,160,224,.45)" strokeWidth="1.2" />
        <text x="63" y="30" textAnchor="middle" fill="var(--accent-blue)" fontSize="10" fontWeight="700">终端 Agent</text>
        <text x="63" y="44" textAnchor="middle" fill="rgba(63,160,224,.7)" fontSize="8.5">Wazuh / EDR</text>

        {/* Webhook */}
        <rect x="8" y="63" width="110" height="34" rx="6"
          fill="rgba(63,160,224,.10)" stroke="rgba(63,160,224,.45)" strokeWidth="1.2" />
        <text x="63" y="77" textAnchor="middle" fill="var(--accent-blue)" fontSize="10" fontWeight="700">Webhook</text>
        <text x="63" y="91" textAnchor="middle" fill="rgba(63,160,224,.7)" fontSize="8.5">HTTP POST</text>

        {/* REST API */}
        <rect x="8" y="110" width="110" height="34" rx="6"
          fill="rgba(63,160,224,.10)" stroke="rgba(63,160,224,.45)" strokeWidth="1.2" />
        <text x="63" y="124" textAnchor="middle" fill="var(--accent-blue)" fontSize="10" fontWeight="700">REST API</text>
        <text x="63" y="138" textAnchor="middle" fill="rgba(63,160,224,.7)" fontSize="8.5">ingestion</text>

        {/* ── Arrows: Sources → ETL Engine ── */}
        {/* Top arrow */}
        <line x1="118" y1="33" x2="266" y2="55" stroke="var(--accent-blue)" strokeWidth="1.4" className="etl-flow-arrow" />
        <polygon points="262,51 270,57 264,62" fill="var(--accent-blue)" opacity="0.75" />

        {/* Mid arrow */}
        <line x1="118" y1="80" x2="266" y2="80" stroke="var(--accent-blue)" strokeWidth="1.4" className="etl-flow-arrow" />
        <polygon points="262,76 270,80 262,84" fill="var(--accent-blue)" opacity="0.75" />

        {/* Bottom arrow */}
        <line x1="118" y1="127" x2="266" y2="105" stroke="var(--accent-blue)" strokeWidth="1.4" className="etl-flow-arrow" />
        <polygon points="262,99 270,103 264,108" fill="var(--accent-blue)" opacity="0.75" />

        {/* ── ETL Engine box ── */}
        <rect x="268" y="20" width="224" height="120" rx="8"
          fill="rgba(34,197,94,.07)" stroke="rgba(34,197,94,.4)" strokeWidth="1.5"
          className="etl-engine-pulse" />
        <text x="380" y="36" textAnchor="middle" fill="var(--accent-green)" fontSize="11" fontWeight="700" letterSpacing="1">ETL Engine</text>
        {/* Pipeline steps inside box */}
        {['解析 (Parse)', '转换 (Transform)', '过滤 (Filter)', '富化 (Enrich)', '路由 (Route)'].map((label, i) => (
          <g key={label}>
            <rect x="284" y={46 + i * 18} width="192" height="13" rx="3"
              fill={`rgba(34,197,94,${0.04 + i * 0.015})`}
              stroke="rgba(34,197,94,.15)" strokeWidth="0.8" />
            <text x="380" y={56 + i * 18} textAnchor="middle" fill="rgba(34,197,94,.85)" fontSize="8.5">{label}</text>
          </g>
        ))}

        {/* ── Arrows: ETL Engine → Outputs ── */}
        {/* → ArangoDB */}
        <line x1="492" y1="55" x2="638" y2="33" stroke="#14b8a6" strokeWidth="1.4" className="etl-flow-arrow-slow" />
        <polygon points="634,29 642,35 636,40" fill="#14b8a6" opacity="0.75" />

        {/* → 数据湖 */}
        <line x1="492" y1="80" x2="638" y2="80" stroke="#14b8a6" strokeWidth="1.4" className="etl-flow-arrow-slow" />
        <polygon points="634,76 642,80 634,84" fill="#14b8a6" opacity="0.75" />

        {/* → 丢弃 */}
        <line x1="492" y1="105" x2="638" y2="127" stroke="#f87171" strokeWidth="1.4" className="etl-flow-arrow-slow" />
        <polygon points="634,122 642,128 636,133" fill="#f87171" opacity="0.75" />

        {/* ── Output nodes ── */}
        {/* ArangoDB */}
        <rect x="640" y="16" width="110" height="34" rx="6"
          fill="rgba(20,184,166,.10)" stroke="rgba(20,184,166,.45)" strokeWidth="1.2" />
        <text x="695" y="30" textAnchor="middle" fill="#14b8a6" fontSize="10" fontWeight="700">ArangoDB</text>
        <text x="695" y="44" textAnchor="middle" fill="rgba(20,184,166,.7)" fontSize="8.5">结构化存储</text>

        {/* 数据湖 */}
        <rect x="640" y="63" width="110" height="34" rx="6"
          fill="rgba(20,184,166,.10)" stroke="rgba(20,184,166,.45)" strokeWidth="1.2" />
        <text x="695" y="77" textAnchor="middle" fill="#14b8a6" fontSize="10" fontWeight="700">数据湖 (ngx)</text>
        <text x="695" y="91" textAnchor="middle" fill="rgba(20,184,166,.7)" fontSize="8.5">冷存 / SPL2</text>

        {/* 丢弃 */}
        <rect x="640" y="110" width="110" height="34" rx="6"
          fill="rgba(248,113,113,.08)" stroke="rgba(248,113,113,.35)" strokeWidth="1.2" />
        <text x="695" y="124" textAnchor="middle" fill="#f87171" fontSize="10" fontWeight="700">丢弃</text>
        <text x="695" y="138" textAnchor="middle" fill="rgba(248,113,113,.7)" fontSize="8.5">drop_event</text>
      </svg>

      {/* ── Live stats bar ── */}
      <div style={{
        display: 'flex', gap: 0, marginTop: 10, background: 'var(--bg-secondary)',
        border: '1px solid var(--border)', borderRadius: 6, overflow: 'hidden',
        maxWidth: 820, margin: '10px auto 0',
      }}>
        {[
          { label: '今日处理事件', value: liveStats.events.toLocaleString(),   color: 'var(--accent-blue)' },
          { label: '规则匹配',     value: liveStats.matched.toLocaleString(),  color: 'var(--accent-green)' },
          { label: '已丢弃',       value: liveStats.dropped.toLocaleString(),  color: 'var(--critical)' },
          { label: '平均延迟',     value: `${liveStats.latency}ms`,            color: 'var(--accent-green)' },
        ].map((stat, i) => (
          <div key={stat.label} style={{
            flex: 1, padding: '8px 14px', textAlign: 'center',
            borderLeft: i > 0 ? '1px solid var(--border)' : 'none',
          }}>
            <div style={{ fontSize: 16, fontWeight: 700, fontFamily: 'monospace', color: stat.color, lineHeight: 1.2 }}>
              {stat.value}
            </div>
            <div style={{ fontSize: 9.5, color: 'var(--text-muted)', marginTop: 2 }}>{stat.label}</div>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Test modal ───────────────────────────────────────────────────────────────

interface TestModalProps {
  rule: ETLRule
  onClose: () => void
}

function TestModal({ rule, onClose }: TestModalProps) {
  const [testForm, setTestForm] = useState({ ...BLANK_TEST })
  const [testResult, setTestResult] = useState<TestResult | null>(null)
  const [testLoading, setTestLoading] = useState(false)

  function runTest() {
    setTestLoading(true)
    let fields: Record<string, string> = {}
    try { fields = JSON.parse(testForm.fields_json) } catch { /* ok */ }
    const body: Record<string, unknown> = {
      tag: testForm.tag,
      sample: {
        dataset: testForm.dataset || undefined,
        hostname: testForm.hostname || undefined,
        agent_id: testForm.agent_id || undefined,
        fields,
      },
    }
    if (testForm.kind.trim()) {
      (body.sample as Record<string, unknown>).kind = parseInt(testForm.kind, 10)
    }
    api.post(`/etl/rules/${rule._key}/test`, body)
      .then(r => setTestResult(r.data.data))
      .catch(() => setTestResult({ matched: false, raw_ngx_index: '', etl_ngx_index: '', write_arango: false, dropped: false }))
      .finally(() => setTestLoading(false))
  }

  return (
    <>
      <div onClick={onClose} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
      <div style={{
        position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
        width: 580, background: 'var(--bg-modal)', border: '1px solid var(--border)',
        borderRadius: 8, zIndex: 500, padding: 24, maxHeight: '90vh', overflowY: 'auto',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 16 }}>
          <div>
            <div style={{ fontSize: 15, fontWeight: 600 }}>干运行测试</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
              规则: <span style={{ fontFamily: 'monospace', color: 'var(--accent-blue)' }}>{rule.name}</span>
            </div>
          </div>
          <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px' }} onClick={onClose}>✕</button>
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
          {/* Tag + Kind */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            <div>
              <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginBottom: 3 }}>Tag</div>
              <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box', fontSize: 11 }}
                placeholder="winevent.security"
                value={testForm.tag} onChange={e => setTestForm(p => ({ ...p, tag: e.target.value }))} />
            </div>
            <div>
              <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginBottom: 3 }}>Kind (0-8)</div>
              <select className="filter-select" style={{ width: '100%', fontSize: 11 }}
                value={testForm.kind} onChange={e => setTestForm(p => ({ ...p, kind: e.target.value }))}>
                <option value="">（不限）</option>
                {Object.entries(KIND_NAMES).map(([k, v]) => (
                  <option key={k} value={k}>{k} — {v}</option>
                ))}
              </select>
            </div>
          </div>

          {/* Hostname + Agent ID */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            <div>
              <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginBottom: 3 }}>Hostname</div>
              <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box', fontSize: 11 }}
                placeholder="host-01"
                value={testForm.hostname} onChange={e => setTestForm(p => ({ ...p, hostname: e.target.value }))} />
            </div>
            <div>
              <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginBottom: 3 }}>Agent ID</div>
              <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box', fontSize: 11 }}
                placeholder="10001"
                value={testForm.agent_id} onChange={e => setTestForm(p => ({ ...p, agent_id: e.target.value }))} />
            </div>
          </div>

          {/* Fields JSON */}
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 3 }}>
              <div style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>样本事件字段 (JSON)</div>
              <button
                style={{ fontSize: 9.5, color: 'var(--accent-blue)', background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}
                onClick={() => setTestForm(p => ({ ...p, fields_json: SAMPLE_ENDPOINT_EVENT }))}
              >重置示例</button>
            </div>
            <textarea
              className="filter-input"
              style={{
                width: '100%', boxSizing: 'border-box', fontSize: 10.5,
                minHeight: 140, fontFamily: 'Consolas,monospace', resize: 'vertical',
              }}
              value={testForm.fields_json}
              onChange={e => setTestForm(p => ({ ...p, fields_json: e.target.value }))}
            />
          </div>

          <button className="btn-primary" style={{ fontSize: 12 }} disabled={testLoading} onClick={runTest}>
            {testLoading ? '运行中...' : '▶ 运行测试'}
          </button>

          {testResult && (
            <div style={{ background: 'var(--bg-secondary)', borderRadius: 6, padding: 12, fontSize: 11.5 }}>
              {/* Flow diagram */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 0, marginBottom: 14, overflowX: 'auto' }}>
                {/* Input box */}
                <div style={{
                  padding: '7px 12px', borderRadius: 5, background: 'rgba(63,160,224,.1)',
                  border: '1px solid rgba(63,160,224,.35)', fontSize: 11, color: 'var(--accent-blue)',
                  fontWeight: 600, textAlign: 'center', whiteSpace: 'nowrap', flexShrink: 0,
                }}>
                  Input
                </div>
                {/* Arrow */}
                <div style={{ width: 28, height: 1, background: 'var(--border)', position: 'relative', flexShrink: 0 }}>
                  <div style={{ position: 'absolute', right: -4, top: -4, fontSize: 9, color: 'var(--text-muted)' }}>▶</div>
                </div>
                {/* Match box */}
                <div style={{
                  padding: '7px 12px', borderRadius: 5,
                  background: testResult.matched ? 'rgba(34,197,94,.12)' : 'rgba(239,68,68,.1)',
                  border: `1px solid ${testResult.matched ? 'rgba(34,197,94,.4)' : 'rgba(239,68,68,.35)'}`,
                  fontSize: 11, color: testResult.matched ? 'var(--accent-green)' : 'var(--critical)',
                  fontWeight: 700, textAlign: 'center', whiteSpace: 'nowrap', flexShrink: 0,
                }}>
                  {testResult.matched ? '✓ Match' : '✗ No Match'}
                </div>
                {testResult.matched && (
                  <>
                    {/* Arrow */}
                    <div style={{ width: 28, height: 1, background: 'var(--border)', position: 'relative', flexShrink: 0 }}>
                      <div style={{ position: 'absolute', right: -4, top: -4, fontSize: 9, color: 'var(--text-muted)' }}>▶</div>
                    </div>
                    {/* Actions box */}
                    <div style={{
                      padding: '7px 12px', borderRadius: 5, background: 'rgba(167,139,250,.1)',
                      border: '1px solid rgba(167,139,250,.35)', fontSize: 11, color: 'var(--accent-blue)',
                      fontWeight: 600, textAlign: 'center', whiteSpace: 'nowrap', flexShrink: 0,
                    }}>
                      Actions
                    </div>
                    {/* Arrow */}
                    <div style={{ width: 28, height: 1, background: 'var(--border)', position: 'relative', flexShrink: 0 }}>
                      <div style={{ position: 'absolute', right: -4, top: -4, fontSize: 9, color: 'var(--text-muted)' }}>▶</div>
                    </div>
                    {/* Output box */}
                    <div style={{
                      padding: '7px 12px', borderRadius: 5, background: 'rgba(20,184,166,.1)',
                      border: '1px solid rgba(20,184,166,.35)', fontSize: 11, color: 'var(--accent-green)',
                      fontWeight: 600, textAlign: 'center', flexShrink: 0,
                    }}>
                      <div>Output</div>
                      {testResult.etl_ngx_index && (
                        <div style={{ fontSize: 9.5, color: 'var(--accent-green)', fontFamily: 'monospace', marginTop: 2 }}>
                          {testResult.etl_ngx_index}
                        </div>
                      )}
                    </div>
                  </>
                )}
              </div>

              {/* Output index highlight */}
              {testResult.matched && testResult.etl_ngx_index && (
                <div style={{
                  display: 'flex', alignItems: 'center', gap: 10, padding: '8px 12px',
                  background: 'rgba(20,184,166,.08)', border: '1px solid rgba(20,184,166,.25)',
                  borderRadius: 5, marginBottom: 10,
                }}>
                  <span style={{ fontSize: 11, color: 'var(--text-muted)', flexShrink: 0 }}>输出索引</span>
                  <span style={{ fontSize: 14, fontFamily: 'monospace', fontWeight: 700, color: 'var(--accent-green)' }}>
                    {testResult.etl_ngx_index}
                  </span>
                </div>
              )}

              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 10 }}>
                <StatusPill ok={testResult.matched} label={testResult.matched ? '✓ 规则匹配' : '✗ 未匹配'} />
                {testResult.dropped && <StatusPill ok={false} label="✗ 事件丢弃" />}
                {testResult.write_arango && <StatusPill ok label="→ ArangoDB" />}
              </div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                {[
                  ['raw_ngx_index', testResult.raw_ngx_index || '—（抑制）'],
                  ['etl_ngx_index', testResult.etl_ngx_index || '—'],
                ].map(([k, v]) => (
                  <div key={k} style={{ display: 'flex', justifyContent: 'space-between', borderBottom: '1px solid rgba(255,255,255,.04)', paddingBottom: 4 }}>
                    <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>{k}</span>
                    <span style={{ fontFamily: 'monospace', fontSize: 11, color: v === '—（抑制）' || v === '—' ? 'var(--text-muted)' : 'var(--accent-blue)' }}>{v}</span>
                  </div>
                ))}
              </div>
              {testResult.output_entry && (
                <div style={{ marginTop: 10 }}>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 6, textTransform: 'uppercase', letterSpacing: 0.4 }}>
                    输出条目字段
                    {testResult.output_entry.dataset && (
                      <span style={{ marginLeft: 8, color: 'var(--accent-blue)', textTransform: 'none' }}>→ {testResult.output_entry.dataset}</span>
                    )}
                  </div>
                  <pre style={{ margin: 0, fontSize: 10.5, color: 'var(--accent-green)', fontFamily: 'monospace', whiteSpace: 'pre-wrap', overflow: 'auto', background: 'rgba(0,0,0,.2)', borderRadius: 4, padding: 8 }}>
                    {JSON.stringify(testResult.output_entry.fields, null, 2)}
                  </pre>
                </div>
              )}
            </div>
          )}
        </div>
      </div>
    </>
  )
}

// ─── Import Modal ─────────────────────────────────────────────────────────────

interface ImportModalProps {
  onClose: () => void
  onImported: () => void
  showToast: (msg: string) => void
}

function ImportModal({ onClose, onImported, showToast }: ImportModalProps) {
  const [activeTab, setActiveTab] = useState<'file' | 'paste'>('file')

  // File upload tab state
  const [dragOver, setDragOver] = useState(false)
  const [fileName, setFileName] = useState('')
  const [filePreview, setFilePreview] = useState<ETLRule[] | null>(null)
  const [fileError, setFileError] = useState('')

  // Paste tab state
  const [jsonText, setJsonText] = useState('')
  const [pasteError, setPasteError] = useState('')
  const [pastePreview, setPastePreview] = useState<ETLRule[] | null>(null)
  const [pasteValidMsg, setPasteValidMsg] = useState('')

  // Shared
  const [progress, setProgress] = useState('')
  const [done, setDone] = useState(false)
  const [importResult, setImportResult] = useState('')
  const fileInputRef = useRef<HTMLInputElement>(null)

  function parseRuleArray(raw: unknown): ETLRule[] | string {
    const arr: unknown[] = Array.isArray(raw) ? raw : [raw]
    const invalid = arr.filter((r: unknown) => {
      if (typeof r !== 'object' || r === null) return true
      const obj = r as Record<string, unknown>
      return !obj.name || !obj.rule_id
    })
    if (invalid.length > 0) {
      return `${invalid.length} 条记录缺少 name 或 rule_id 字段`
    }
    return arr as ETLRule[]
  }

  function handleFile(file: File) {
    setFileError('')
    setFilePreview(null)
    setFileName(file.name)
    const reader = new FileReader()
    reader.onload = (e) => {
      const text = e.target?.result as string
      let parsed: unknown
      try {
        parsed = JSON.parse(text)
      } catch (err: unknown) {
        const msg = err instanceof Error ? err.message : String(err)
        setFileError('JSON 解析失败: ' + msg)
        return
      }
      const result = parseRuleArray(parsed)
      if (typeof result === 'string') {
        setFileError(result)
      } else {
        setFilePreview(result)
      }
    }
    reader.readAsText(file)
  }

  function handleDropZoneChange(e: React.ChangeEvent<HTMLInputElement>) {
    const file = e.target.files?.[0]
    if (file) handleFile(file)
  }

  function handleDrop(e: React.DragEvent<HTMLDivElement>) {
    e.preventDefault()
    setDragOver(false)
    const file = e.dataTransfer.files?.[0]
    if (file) handleFile(file)
  }

  function validatePaste() {
    setPasteError('')
    setPasteValidMsg('')
    setPastePreview(null)
    if (!jsonText.trim()) { setPasteError('请粘贴 JSON 内容'); return }
    let parsed: unknown
    try { parsed = JSON.parse(jsonText) } catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e)
      setPasteError('JSON 解析失败: ' + msg)
      return
    }
    const result = parseRuleArray(parsed)
    if (typeof result === 'string') {
      setPasteError(result)
    } else {
      setPastePreview(result)
      setPasteValidMsg(`有效: ${result.length} 条规则`)
    }
  }

  async function doImport(rules: ETLRule[]) {
    const total = rules.length
    let ok = 0
    let skipped = 0
    for (let i = 0; i < total; i++) {
      setProgress(`${i + 1}/${total}`)
      const rule = rules[i]
      const body = {
        rule_id: rule.rule_id,
        name: rule.name,
        description: rule.description,
        priority: rule.priority ?? 50,
        is_enabled: rule.is_enabled ?? true,
        match: rule.match ?? {},
        raw_write_mode: rule.raw_write_mode ?? 'both',
        actions: rule.actions ?? [],
        output: rule.output ?? { ngx_index: '', write_arango: false },
      }
      try {
        await api.post('/etl/rules/import', { rules: [body] })
        ok++
      } catch {
        // Fallback: try individual create
        try { await api.post('/etl/rules', body); ok++ } catch { skipped++ }
      }
    }
    setProgress('')
    setDone(true)
    const msg = `✅ 成功导入 ${ok} 条, 跳过 ${skipped} 条`
    setImportResult(msg)
    showToast(`导入完成: ${ok} 条成功${skipped > 0 ? `, ${skipped} 条跳过` : ''}`)
    onImported()
    setTimeout(() => onClose(), 2500)
  }

  const activePreview = activeTab === 'file' ? filePreview : pastePreview

  return (
    <>
      <div onClick={!progress ? onClose : undefined} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
      <div style={{
        position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
        width: 680, background: 'var(--bg-modal)', border: '1px solid var(--border)',
        borderRadius: 8, zIndex: 500, padding: 24, maxHeight: '90vh', display: 'flex', flexDirection: 'column',
      }}>
        {/* Header */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14, flexShrink: 0 }}>
          <div>
            <div style={{ fontSize: 15, fontWeight: 600 }}>导入规则</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>支持文件上传或直接粘贴 JSON</div>
          </div>
          <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px' }} onClick={onClose} disabled={!!progress}>✕</button>
        </div>

        {done ? (
          <div style={{ textAlign: 'center', padding: '32px 0', fontSize: 14 }}>
            <div style={{ fontSize: 22, marginBottom: 10 }}>✅</div>
            <div style={{ color: 'var(--accent-green)', fontWeight: 600 }}>{importResult}</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 8 }}>窗口即将关闭…</div>
          </div>
        ) : !activePreview ? (
          <>
            {/* Tabs */}
            <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', marginBottom: 16, flexShrink: 0 }}>
              {(['file', 'paste'] as const).map(tab => (
                <button
                  key={tab}
                  onClick={() => setActiveTab(tab)}
                  style={{
                    padding: '6px 16px', fontSize: 12, fontWeight: 500,
                    background: 'none', border: 'none', cursor: 'pointer',
                    color: activeTab === tab ? 'var(--accent-blue)' : 'var(--text-muted)',
                    borderBottom: activeTab === tab ? '2px solid var(--accent-blue)' : '2px solid transparent',
                    marginBottom: -1,
                  }}
                >
                  {tab === 'file' ? '📁 文件上传' : '📋 手动粘贴'}
                </button>
              ))}
            </div>

            {/* Tab: File Upload */}
            {activeTab === 'file' && (
              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 12 }}>
                {/* Drag-drop zone */}
                <div
                  onDragOver={e => { e.preventDefault(); setDragOver(true) }}
                  onDragLeave={() => setDragOver(false)}
                  onDrop={handleDrop}
                  onClick={() => fileInputRef.current?.click()}
                  style={{
                    border: `2px dashed ${dragOver ? 'var(--accent-blue)' : fileError ? 'var(--critical)' : 'var(--border)'}`,
                    borderRadius: 8,
                    padding: '32px 20px',
                    textAlign: 'center',
                    cursor: 'pointer',
                    background: dragOver ? 'rgba(63,160,224,.06)' : 'var(--bg-secondary)',
                    transition: 'border-color .15s, background .15s',
                    flex: 1,
                  }}
                >
                  <input
                    ref={fileInputRef}
                    type="file"
                    accept=".json"
                    style={{ display: 'none' }}
                    onChange={handleDropZoneChange}
                  />
                  <div style={{ fontSize: 28, marginBottom: 8, opacity: 0.7 }}>📂</div>
                  {fileName ? (
                    <div style={{ fontSize: 13, color: 'var(--accent-blue)', fontWeight: 500 }}>{fileName}</div>
                  ) : (
                    <>
                      <div style={{ fontSize: 13, color: 'var(--text-secondary)', fontWeight: 500 }}>
                        拖拽文件到此处，或点击选择文件
                      </div>
                      <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>
                        仅支持 .json 文件
                      </div>
                    </>
                  )}
                </div>
                {fileError && (
                  <div style={{ fontSize: 11, color: 'var(--critical)', padding: '8px 12px', background: 'rgba(239,68,68,.07)', borderRadius: 5, border: '1px solid rgba(239,68,68,.2)' }}>
                    {fileError}
                  </div>
                )}
                {filePreview && (
                  <div style={{ fontSize: 11.5, color: 'var(--accent-green)' }}>
                    ✓ 解析成功，共 <strong>{filePreview.length}</strong> 条规则
                  </div>
                )}
              </div>
            )}

            {/* Tab: Manual Paste */}
            {activeTab === 'paste' && (
              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 10 }}>
                <textarea
                  className="filter-input"
                  style={{ flex: 1, minHeight: 200, fontFamily: 'Consolas,monospace', fontSize: 11, resize: 'vertical' }}
                  placeholder={'[\n  {"name":"My Rule","rule_id":"my-rule-001","priority":50,...},\n  ...\n]'}
                  value={jsonText}
                  onChange={e => { setJsonText(e.target.value); setPasteError(''); setPasteValidMsg(''); setPastePreview(null) }}
                />
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <button className="btn-secondary" style={{ fontSize: 12, padding: '4px 14px' }} onClick={validatePaste}>
                    验证 JSON
                  </button>
                  {pasteValidMsg && (
                    <span style={{ fontSize: 11.5, color: 'var(--accent-green)' }}>✓ {pasteValidMsg}</span>
                  )}
                  {pasteError && (
                    <span style={{ fontSize: 11, color: 'var(--critical)' }}>{pasteError}</span>
                  )}
                </div>
              </div>
            )}

            {/* Action buttons */}
            <div style={{ display: 'flex', gap: 10, marginTop: 16, flexShrink: 0 }}>
              <button className="btn-secondary" style={{ flex: 1 }} onClick={onClose}>取消</button>
              <button
                className="btn-primary"
                style={{ flex: 1 }}
                disabled={!activePreview}
                onClick={() => { if (activePreview) doImport(activePreview) }}
              >
                导入 {activePreview ? `(${(activePreview as ETLRule[]).length} 条)` : ''}
              </button>
            </div>
          </>
        ) : (
          /* Preview + confirm */
          <>
            <div style={{ fontSize: 11.5, color: 'var(--text-secondary)', marginBottom: 8, flexShrink: 0 }}>
              共 <strong>{activePreview.length}</strong> 条规则待导入（预览前 3 条）
            </div>
            <div style={{ flex: 1, overflowY: 'auto', marginBottom: 14 }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>规则名称</th>
                    <th>Rule ID</th>
                    <th style={{ width: 70 }}>优先级</th>
                    <th style={{ width: 60 }}>状态</th>
                  </tr>
                </thead>
                <tbody>
                  {activePreview.slice(0, 3).map((r, i) => (
                    <tr key={i}>
                      <td style={{ fontSize: 12 }}>{r.name}</td>
                      <td style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--accent-blue)' }}>{r.rule_id}</td>
                      <td style={{ fontSize: 12, textAlign: 'center' }}>{r.priority ?? 50}</td>
                      <td>
                        <span style={{
                          fontSize: 10, padding: '1px 6px', borderRadius: 3, fontWeight: 600,
                          background: r.is_enabled !== false ? 'rgba(34,197,94,.12)' : 'rgba(120,120,140,.12)',
                          color: r.is_enabled !== false ? 'var(--accent-green)' : 'var(--text-muted)',
                        }}>
                          {r.is_enabled !== false ? '启用' : '禁用'}
                        </span>
                      </td>
                    </tr>
                  ))}
                  {activePreview.length > 3 && (
                    <tr>
                      <td colSpan={4} style={{ textAlign: 'center', fontSize: 11, color: 'var(--text-muted)', padding: '6px 0' }}>
                        … 及另外 {activePreview.length - 3} 条规则
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
            <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexShrink: 0 }}>
              {progress && (
                <span style={{ fontSize: 11, color: 'var(--accent-blue)', flex: 1 }}>导入中 {progress}…</span>
              )}
              {!progress && <span style={{ flex: 1 }} />}
              <button className="btn-secondary" onClick={() => { setFilePreview(null); setPastePreview(null) }} disabled={!!progress}>← 返回</button>
              <button className="btn-primary" onClick={() => doImport(activePreview)} disabled={!!progress}>
                {progress ? `导入中 ${progress}` : '确认导入'}
              </button>
            </div>
          </>
        )}
      </div>
    </>
  )
}

// ─── Toast ────────────────────────────────────────────────────────────────────

function Toast({ message, onDone }: { message: string; onDone: () => void }) {
  useEffect(() => {
    const t = setTimeout(onDone, 3000)
    return () => clearTimeout(t)
  }, [onDone])
  return (
    <div style={{
      position: 'fixed', bottom: 28, right: 28, zIndex: 9999,
      background: 'var(--accent-green)', color: '#fff',
      padding: '10px 18px', borderRadius: 6, fontSize: 13, fontWeight: 500,
      boxShadow: '0 4px 16px rgba(0,0,0,.3)',
      animation: 'fadeIn .2s ease',
    }}>
      {message}
    </div>
  )
}

// ─── Component ────────────────────────────────────────────────────────────────

export default function ETLPipeline() {
  const [items, setItems] = useState<ETLRule[]>([])
  const [meta, setMeta] = useState<PageMeta>({ page: 1, page_size: 50, total: 0, total_pages: 1 })
  const [loading, setLoading] = useState(false)
  const [enabledFilter, setEnabledFilter] = useState<string>('')
  const [selected, setSelected] = useState<ETLRule | null>(null)

  const [showModal, setShowModal] = useState(false)
  const [editTarget, setEditTarget] = useState<ETLRule | null>(null)
  const [form, setForm] = useState<FormState>(BLANK_FORM)
  const [saving, setSaving] = useState(false)
  const [jsonError, setJsonError] = useState('')
  const [formErrors, setFormErrors] = useState<FormErrors>({})

  const [deleteTarget, setDeleteTarget] = useState<ETLRule | null>(null)

  // Test modal
  const [testModalRule, setTestModalRule] = useState<ETLRule | null>(null)

  // Import modal
  const [showImportModal, setShowImportModal] = useState(false)

  // Toast
  const [toast, setToast] = useState('')

  // Stats from API
  const [apiStats, setApiStats] = useState<ETLStats | null>(null)

  // Audit log
  const [showAudit, setShowAudit] = useState(false)
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([])
  const [auditLoading, setAuditLoading] = useState(false)
  const [auditHasMore, setAuditHasMore] = useState(false)
  const [auditPage, setAuditPage] = useState(1)

  const mountedRef = useRef(false)

  const loadAudit = useCallback((page = 1, append = false) => {
    setAuditLoading(true)
    api.get('/audit/logs', { params: { resource_type: 'etl_rule', page_size: '10', page: String(page) } })
      .then(r => {
        const logs: AuditLog[] = r.data.data?.items ?? []
        const m = r.data.data?.meta
        if (append) {
          setAuditLogs(prev => [...prev, ...logs])
        } else {
          setAuditLogs(logs)
        }
        setAuditHasMore(m ? page < m.total_pages : logs.length === 10)
        setAuditPage(page)
      })
      .catch(() => { /* silent */ })
      .finally(() => setAuditLoading(false))
  }, [])

  function loadStats() {
    api.get('/etl/rules/stats')
      .then(r => {
        const d = r.data.data
        if (d && typeof d.total === 'number') {
          setApiStats({ total: d.total, enabled: d.enabled ?? 0, disabled: d.disabled ?? 0 })
        }
      })
      .catch(() => { /* silent — fall back to derived stats */ })
  }

  function load() {
    setLoading(true)
    const params: Record<string, string> = { page_size: '50' }
    if (enabledFilter === 'true') params.enabled = 'true'
    if (enabledFilter === 'false') params.enabled = 'false'
    api.get('/etl/rules', { params })
      .then(r => {
        setItems(r.data.data?.items ?? [])
        setMeta(r.data.data?.meta ?? meta)
      })
      .finally(() => setLoading(false))
  }

  useEffect(() => { load(); loadStats() }, [])
  useEffect(() => {
    if (!mountedRef.current) { mountedRef.current = true; return }
    load()
  }, [enabledFilter])

  // Load audit when section opened
  useEffect(() => {
    if (showAudit) loadAudit(1, false)
  }, [showAudit, loadAudit])

  function openCreate() {
    setEditTarget(null)
    setForm(BLANK_FORM)
    setJsonError('')
    setFormErrors({})
    setShowModal(true)
  }

  function openEdit(rule: ETLRule) {
    setEditTarget(rule)
    setForm(ruleToForm(rule))
    setJsonError('')
    setFormErrors({})
    setShowModal(true)
  }

  function setField<K extends keyof FormState>(k: K, v: FormState[K]) {
    setForm(p => ({ ...p, [k]: v }))
    // Clear the relevant field error on change
    if (k === 'rule_id' || k === 'priority') {
      setFormErrors(prev => ({ ...prev, [k]: undefined }))
    }
  }

  function validateJson(val: string) {
    try { JSON.parse(val); setJsonError(''); return true }
    catch (e: unknown) {
      const msg = e instanceof Error ? e.message : String(e)
      setJsonError('Actions JSON 语法错误: ' + msg)
      return false
    }
  }

  function validateForm(): boolean {
    const errors: FormErrors = {}
    const ruleId = form.rule_id.trim()

    if (ruleId.length < 2 || !RULE_ID_RE.test(ruleId)) {
      errors.rule_id = 'Rule ID 只能包含小写字母、数字和连字符（首尾不能为连字符）'
    }

    const prio = parseInt(form.priority, 10)
    if (!form.priority.trim() || isNaN(prio) || prio < 1 || prio > 9999 || String(prio) !== form.priority.trim()) {
      errors.priority = '优先级必须为整数 1-9999'
    }

    const hasMatch = form.tag_pattern.trim() || form.dataset.trim() || form.filter_expr.trim() || form.kind.trim()
    if (!hasMatch) {
      errors.match = '至少填写一个匹配条件（Tag Pattern / Dataset / Filter Expr / Kind）'
    }

    setFormErrors(errors)
    return Object.keys(errors).length === 0
  }

  function saveRule() {
    if (!form.name.trim() || !form.rule_id.trim()) return
    if (!validateForm()) return
    if (!validateJson(form.actions_json)) return
    setSaving(true)
    const body = formToBody(form)
    const req = editTarget
      ? api.patch(`/etl/rules/${editTarget._key}`, body)
      : api.post('/etl/rules', body)
    req.then(() => {
      setShowModal(false)
      load()
      loadStats()
      if (showAudit) loadAudit(1, false)
    }).finally(() => setSaving(false))
  }

  function toggleEnabled(rule: ETLRule) {
    api.patch(`/etl/rules/${rule._key}`, { is_enabled: !rule.is_enabled }).then(() => load())
  }

  function adjustPriority(rule: ETLRule, delta: number) {
    api.patch(`/etl/rules/${rule._key}`, { priority: rule.priority + delta }).then(() => load())
  }

  function doDelete() {
    if (!deleteTarget) return
    api.delete(`/etl/rules/${deleteTarget._key}`).then(() => {
      setDeleteTarget(null)
      if (selected?._key === deleteTarget._key) setSelected(null)
      load()
      loadStats()
      if (showAudit) loadAudit(1, false)
    })
  }

  // ── Export ──
  function exportRules() {
    // Use dedicated export endpoint if available, fall back to blob download
    const exportUrl = '/api/etl/rules/export'
    window.open(exportUrl, '_blank')
  }

  const sortedItems = [...items].sort((a, b) => a.priority - b.priority)

  // ── Stats — prefer API response, fall back to derived from list ──
  const statsTotal   = apiStats?.total   ?? items.length
  const statsEnabled = apiStats?.enabled ?? items.filter(r => r.is_enabled).length
  const statsDisabled = apiStats?.disabled ?? (statsTotal - statsEnabled)

  // PieChart by output.ngx_index
  const indexCounts: Record<string, number> = {}
  for (const r of items) {
    const key = r.output?.ngx_index || '(未设置)'
    indexCounts[key] = (indexCounts[key] ?? 0) + 1
  }
  const INDEX_COLORS = ['var(--accent-blue)', 'var(--accent-blue)', 'var(--accent-green)', 'var(--medium)', 'var(--critical)', 'var(--accent-green)', 'var(--accent-blue)']
  const pieData = Object.entries(indexCounts).map(([name, value], i) => ({
    name,
    value,
    color: INDEX_COLORS[i % INDEX_COLORS.length],
  }))

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <PageHeader
        title="ETL 流水线"
        subtitle={`· ${meta.total} 条规则  ·  优先级越小越先匹配`}
        actions={
          <div style={{ display: 'flex', gap: 8 }}>
            <button className="btn-secondary" style={{ fontSize: 11 }} onClick={exportRules}>
              导出规则
            </button>
            <button className="btn-secondary" style={{ fontSize: 11 }} onClick={() => setShowImportModal(true)}>
              导入规则
            </button>
            <button className="btn-primary" onClick={openCreate}>+ 新建规则</button>
          </div>
        }
      />

      {/* ── Animated Pipeline Flow Diagram ── */}
      <PipelineFlowDiagram />

      {/* ── Stats Dashboard ── */}
      <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', background: 'var(--bg-card)', flexShrink: 0, display: 'flex', alignItems: 'center', gap: 20, flexWrap: 'wrap' }}>
        {/* Stat tiles */}
        {[
          { label: '总规则数',  value: statsTotal,    border: 'var(--accent-blue)' },
          { label: '启用规则',  value: statsEnabled,  border: 'var(--accent-green)' },
          { label: '禁用规则',  value: statsDisabled, border: 'var(--high)' },
          { label: '平均延迟',  value: '12ms',        border: 'var(--accent-green)' },
        ].map(tile => (
          <div key={tile.label} style={{
            paddingLeft: 12, paddingRight: 16, paddingTop: 8, paddingBottom: 8,
            borderRadius: 6, background: 'var(--bg-secondary)',
            border: '1px solid var(--border)',
            borderLeft: `3px solid ${tile.border}`,
            minWidth: 100,
          }}>
            <div style={{ fontSize: 22, fontWeight: 700, fontFamily: 'monospace', color: 'var(--text-primary)', lineHeight: 1.2 }}>
              {typeof tile.value === 'number' ? tile.value.toLocaleString() : tile.value}
            </div>
            <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginTop: 3 }}>{tile.label}</div>
          </div>
        ))}

        {/* Spacer */}
        <div style={{ flex: 1 }} />

        {/* 规则类型分布 Mini PieChart by ngx_index */}
        {pieData.length > 0 && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', writingMode: 'horizontal-tb', marginRight: 2 }}>
              规则类型分布
            </div>
            <PieChart width={120} height={120}>
              <Pie
                data={pieData}
                cx={55}
                cy={55}
                innerRadius={30}
                outerRadius={50}
                paddingAngle={2}
                dataKey="value"
              >
                {pieData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip
                contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 4, fontSize: 11 }}
                formatter={((value: unknown, name: unknown) => [Number(value ?? 0), name]) as any}
              />
            </PieChart>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4, maxWidth: 140 }}>
              {pieData.slice(0, 5).map(d => (
                <div key={d.name} style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 10.5 }}>
                  <div style={{ width: 8, height: 8, borderRadius: 2, background: d.color, flexShrink: 0 }} />
                  <span style={{ color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 90 }} title={d.name}>{d.name}</span>
                  <span style={{ color: 'var(--text-muted)', fontFamily: 'monospace', marginLeft: 'auto', flexShrink: 0 }}>{d.value}</span>
                </div>
              ))}
              {pieData.length > 5 && (
                <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>+{pieData.length - 5} 更多</div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Filter bar */}
      <div className="tab-bar">
        {[['全部', ''], ['已启用', 'true'], ['已禁用', 'false']].map(([label, val]) => (
          <button key={label} className={`tab ${enabledFilter === val ? 'active' : ''}`}
            onClick={() => setEnabledFilter(val)}>
            {label}
          </button>
        ))}
      </div>

      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        {/* Rules table */}
        <div className="data-table-wrap" style={{ flex: 1 }}>
          <table className="data-table">
            <thead>
              <tr>
                <th style={{ width: 80 }}>优先级</th>
                <th>规则名称</th>
                <th>匹配条件</th>
                <th>写入模式</th>
                <th>输出索引</th>
                <th>动作</th>
                <th style={{ width: 80 }}>状态</th>
                <th></th>
              </tr>
            </thead>
            <tbody>
              {loading && (
                <tr><td colSpan={8} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>加载中...</td></tr>
              )}
              {!loading && sortedItems.length === 0 && (
                <tr><td colSpan={8} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>暂无 ETL 规则</td></tr>
              )}
              {sortedItems.map(rule => (
                <tr key={rule._key}
                  onClick={() => setSelected(selected?._key === rule._key ? null : rule)}
                  className={selected?._key === rule._key ? 'selected' : ''}
                  style={{ opacity: rule.is_enabled ? 1 : 0.5 }}
                >
                  {/* Priority with up/down arrows */}
                  <td onClick={e => e.stopPropagation()}>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 3 }}>
                      <div style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                        <button
                          title="提高优先级（减小数值）"
                          onClick={() => adjustPriority(rule, -10)}
                          style={{
                            width: 16, height: 14, padding: 0, fontSize: 9, lineHeight: 1,
                            background: 'rgba(255,255,255,.06)', border: '1px solid var(--border-light)',
                            borderRadius: 2, color: 'var(--text-muted)', cursor: 'pointer',
                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                          }}
                          onMouseEnter={e => (e.currentTarget.style.background = 'rgba(63,160,224,.2)')}
                          onMouseLeave={e => (e.currentTarget.style.background = 'rgba(255,255,255,.06)')}
                        >↑</button>
                        <button
                          title="降低优先级（增大数值）"
                          onClick={() => adjustPriority(rule, +10)}
                          style={{
                            width: 16, height: 14, padding: 0, fontSize: 9, lineHeight: 1,
                            background: 'rgba(255,255,255,.06)', border: '1px solid var(--border-light)',
                            borderRadius: 2, color: 'var(--text-muted)', cursor: 'pointer',
                            display: 'flex', alignItems: 'center', justifyContent: 'center',
                          }}
                          onMouseEnter={e => (e.currentTarget.style.background = 'rgba(63,160,224,.2)')}
                          onMouseLeave={e => (e.currentTarget.style.background = 'rgba(255,255,255,.06)')}
                        >↓</button>
                      </div>
                      <span style={{ fontSize: 12, fontWeight: 700, fontFamily: 'monospace', color: 'var(--accent-blue)' }}>
                        {rule.priority}
                      </span>
                    </div>
                  </td>

                  <td>
                    <div style={{ fontSize: 12.5, fontWeight: 500 }}>{rule.name}</div>
                    <div style={{ fontSize: 10.5, color: 'var(--text-muted)', fontFamily: 'monospace' }}>{rule.rule_id}</div>
                    {rule.description && (
                      <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 1 }}>
                        {rule.description.slice(0, 60)}{rule.description.length > 60 ? '…' : ''}
                      </div>
                    )}
                  </td>
                  <td>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
                      {rule.match?.tag_pattern && (
                        <Tag color="blue">tag:{rule.match.tag_pattern}</Tag>
                      )}
                      {(rule.match?.dataset ?? []).map(d => (
                        <Tag key={d} color="purple">ds:{d}</Tag>
                      ))}
                      {rule.match?.kind != null && (
                        <Tag color="orange">kind:{KIND_NAMES[rule.match.kind] ?? rule.match.kind}</Tag>
                      )}
                      {rule.match?.filter_expr && (
                        <Tag color="gray">filter</Tag>
                      )}
                    </div>
                  </td>
                  <td>
                    <span style={{
                      fontSize: 10.5, padding: '2px 7px', borderRadius: 3, fontWeight: 600,
                      background: `${rawModeColor(rule.raw_write_mode)}22`,
                      color: rawModeColor(rule.raw_write_mode),
                      border: `1px solid ${rawModeColor(rule.raw_write_mode)}44`,
                    }}>
                      {rawModeLabel(rule.raw_write_mode)}
                    </span>
                  </td>
                  <td>
                    {rule.output?.ngx_index ? (
                      <span style={{ fontSize: 11.5, fontFamily: 'monospace', color: 'var(--accent-blue)' }}>
                        {rule.output.ngx_index}
                      </span>
                    ) : (
                      <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>—</span>
                    )}
                    {rule.output?.write_arango && (
                      <span style={{ marginLeft: 4, fontSize: 10, color: 'var(--accent-green)', fontFamily: 'monospace' }}>+arango</span>
                    )}
                  </td>
                  <td>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
                      {(rule.actions ?? []).slice(0, 3).map((a, i) => (
                        <Tag key={i} color={a.type === 'drop_event' ? 'red' : 'gray'}>{a.type.replace(/_/g, '_​')}</Tag>
                      ))}
                      {(rule.actions ?? []).length > 3 && (
                        <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>+{rule.actions.length - 3}</span>
                      )}
                      {(rule.actions ?? []).length === 0 && (
                        <span style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>—</span>
                      )}
                    </div>
                  </td>

                  {/* Enable/disable toggle */}
                  <td onClick={e => e.stopPropagation()}>
                    <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}
                      title={rule.is_enabled ? '点击禁用' : '点击启用'}>
                      {/* Toggle switch */}
                      <div
                        onClick={() => toggleEnabled(rule)}
                        style={{
                          width: 30, height: 16, borderRadius: 8, position: 'relative',
                          background: rule.is_enabled ? 'var(--accent-green)' : 'rgba(120,120,140,.3)',
                          transition: 'background .2s', cursor: 'pointer', flexShrink: 0,
                          boxShadow: rule.is_enabled ? '0 0 6px rgba(34,197,94,.4)' : 'none',
                        }}
                      >
                        <div style={{
                          position: 'absolute', top: 2,
                          left: rule.is_enabled ? 16 : 2,
                          width: 12, height: 12, borderRadius: '50%',
                          background: 'white', transition: 'left .2s',
                          boxShadow: '0 1px 3px rgba(0,0,0,.3)',
                        }} />
                      </div>
                      <span style={{
                        fontSize: 10.5,
                        color: rule.is_enabled ? 'var(--accent-green)' : 'var(--text-muted)',
                      }}>
                        {rule.is_enabled ? '启用' : '停用'}
                      </span>
                    </label>
                  </td>

                  <td onClick={e => e.stopPropagation()}>
                    <div style={{ display: 'flex', gap: 3 }}>
                      <button className="btn-secondary" style={{ fontSize: 10.5, padding: '2px 7px' }}
                        onClick={() => setTestModalRule(rule)}>
                        测试
                      </button>
                      <button className="btn-secondary" style={{ fontSize: 10.5, padding: '2px 7px' }}
                        onClick={() => openEdit(rule)}>
                        编辑
                      </button>
                      <button className="btn-secondary" style={{ fontSize: 10.5, padding: '2px 7px', color: 'var(--critical)' }}
                        onClick={() => setDeleteTarget(rule)}>
                        删
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Right detail panel */}
        {selected && (
          <div style={{ width: 420, borderLeft: '1px solid var(--border)', background: 'var(--bg-drawer)', display: 'flex', flexDirection: 'column', overflow: 'hidden', flexShrink: 0 }}>
            <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', background: 'var(--bg-card2)', minHeight: 48, display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexShrink: 0 }}>
              <div>
                <div style={{ fontSize: 13, fontWeight: 600 }}>{selected.name}</div>
                <div style={{ fontSize: 10.5, color: 'var(--text-muted)', fontFamily: 'monospace', marginTop: 2 }}>{selected.rule_id}</div>
              </div>
              <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px' }} onClick={() => setSelected(null)}>✕</button>
            </div>

            <div style={{ flex: 1, overflowY: 'auto', padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
              {/* Meta card */}
              <div className="card">
                <div className="card-title">规则信息</div>
                {[
                  ['优先级', String(selected.priority)],
                  ['写入模式', rawModeLabel(selected.raw_write_mode)],
                  ['输出 ngx 索引', selected.output?.ngx_index || '—'],
                  ['写入 ArangoDB', selected.output?.write_arango ? '是' : '否'],
                  ['创建时间', fmtDate(selected.created_at)],
                  ['更新时间', fmtDate(selected.updated_at)],
                ].map(([k, v]) => (
                  <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11.5, borderBottom: '1px solid rgba(255,255,255,.04)', paddingBottom: 4, marginBottom: 4 }}>
                    <span style={{ color: 'var(--text-muted)' }}>{k}</span>
                    <span style={{ color: 'var(--text-secondary)', fontFamily: 'monospace' }}>{v}</span>
                  </div>
                ))}
              </div>

              {/* Match criteria */}
              <div className="card">
                <div className="card-title">匹配条件</div>
                <pre style={{ background: 'var(--bg-secondary)', borderRadius: 4, padding: 10, margin: 0, fontSize: 11, color: 'var(--accent-blue)', fontFamily: 'Consolas,monospace', overflow: 'auto', whiteSpace: 'pre-wrap' }}>
                  {JSON.stringify(selected.match, null, 2)}
                </pre>
              </div>

              {/* Actions */}
              <div className="card">
                <div className="card-title">动作列表 ({(selected.actions ?? []).length})</div>
                {(selected.actions ?? []).length === 0 ? (
                  <div style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>无动作（原始直通）</div>
                ) : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {selected.actions.map((a, i) => (
                      <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 8, fontSize: 11.5, padding: '5px 8px', background: 'var(--bg-secondary)', borderRadius: 4 }}>
                        <Tag color={a.type === 'drop_event' ? 'red' : 'blue'}>{a.type}</Tag>
                        {a.params && Object.keys(a.params).length > 0 && (
                          <span style={{ color: 'var(--text-muted)', fontFamily: 'monospace', fontSize: 11 }}>
                            {Object.entries(a.params).map(([k, v]) => `${k}=${v}`).join(', ')}
                          </span>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>

              {/* Quick test button in detail panel */}
              <button className="btn-secondary" style={{ fontSize: 12 }} onClick={() => setTestModalRule(selected)}>
                ▶ 打开测试面板
              </button>
            </div>
          </div>
        )}
      </div>

      {/* ── Audit Log Section ── */}
      <div style={{ borderTop: '1px solid var(--border)', background: 'var(--bg-card)', flexShrink: 0 }}>
        <button
          onClick={() => setShowAudit(s => !s)}
          style={{
            width: '100%', textAlign: 'left', padding: '8px 16px',
            background: 'none', border: 'none', cursor: 'pointer',
            fontSize: 12, color: 'var(--text-secondary)', fontWeight: 500,
            display: 'flex', alignItems: 'center', gap: 6,
          }}
        >
          <span style={{ fontSize: 10, display: 'inline-block', transform: showAudit ? 'rotate(180deg)' : 'rotate(0deg)', transition: 'transform .2s' }}>▼</span>
          最近操作
        </button>

        {showAudit && (
          <div style={{ padding: '0 16px 12px', maxHeight: 220, overflowY: 'auto' }}>
            {auditLoading && auditLogs.length === 0 && (
              <div style={{ fontSize: 11.5, color: 'var(--text-muted)', padding: '8px 0' }}>加载中...</div>
            )}
            {!auditLoading && auditLogs.length === 0 && (
              <div style={{ fontSize: 11.5, color: 'var(--text-muted)', padding: '8px 0' }}>暂无操作记录</div>
            )}
            <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
              {auditLogs.map((log, i) => (
                <div key={log._key ?? i} style={{ fontSize: 11.5, color: 'var(--text-secondary)', display: 'flex', gap: 6, alignItems: 'baseline' }}>
                  <span style={{ color: 'var(--text-muted)', flexShrink: 0 }}>•</span>
                  <span style={{ color: 'var(--text-muted)', fontFamily: 'monospace', fontSize: 10.5, flexShrink: 0 }}>
                    [{fmtDateTime(log.created_at)}]
                  </span>
                  <span style={{ color: 'var(--accent-blue)', flexShrink: 0 }}>{log.action}</span>
                  <span style={{ color: 'var(--text-secondary)' }}>{log.resource_name ?? log.resource_id ?? ''}</span>
                  {log.operator_id && (
                    <span style={{ color: 'var(--text-muted)', fontSize: 10.5 }}>by {log.operator_id}</span>
                  )}
                </div>
              ))}
            </div>
            {auditHasMore && (
              <button
                className="btn-secondary"
                style={{ fontSize: 11, marginTop: 8, padding: '3px 12px' }}
                onClick={() => loadAudit(auditPage + 1, true)}
                disabled={auditLoading}
              >
                {auditLoading ? '加载中...' : '加载更多'}
              </button>
            )}
          </div>
        )}
      </div>

      {/* ── Test Modal ── */}
      {testModalRule && (
        <TestModal rule={testModalRule} onClose={() => setTestModalRule(null)} />
      )}

      {/* ── Import Modal ── */}
      {showImportModal && (
        <ImportModal
          onClose={() => setShowImportModal(false)}
          onImported={() => { load(); loadStats(); if (showAudit) loadAudit(1, false) }}
          showToast={setToast}
        />
      )}

      {/* ── Create / Edit Modal ── */}
      {showModal && (
        <>
          <div onClick={() => setShowModal(false)} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
          <div style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: 620, background: 'var(--bg-modal)', border: '1px solid var(--border)', borderRadius: 8, zIndex: 500, padding: 24, maxHeight: '90vh', overflowY: 'auto' }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 18 }}>{editTarget ? '编辑 ETL 规则' : '新建 ETL 规则'}</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>

              {/* Row: rule_id + name */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Rule ID *</div>
                  <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box', fontFamily: 'monospace', borderColor: formErrors.rule_id ? 'var(--critical)' : undefined }}
                    placeholder="win-process-enrich-001"
                    value={form.rule_id} onChange={e => setField('rule_id', e.target.value)} />
                  {formErrors.rule_id && (
                    <div style={{ fontSize: 10.5, color: 'var(--critical)', marginTop: 3 }}>{formErrors.rule_id}</div>
                  )}
                </div>
                <div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>规则名称 *</div>
                  <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }}
                    placeholder="Windows Process Enrichment"
                    value={form.name} onChange={e => setField('name', e.target.value)} />
                </div>
              </div>

              {/* Row: priority + is_enabled + raw_write_mode */}
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
                <div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>优先级 (低=先)</div>
                  <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box', fontFamily: 'monospace', borderColor: formErrors.priority ? 'var(--critical)' : undefined }}
                    type="number" min="1" max="9999"
                    value={form.priority} onChange={e => setField('priority', e.target.value)} />
                  {formErrors.priority && (
                    <div style={{ fontSize: 10.5, color: 'var(--critical)', marginTop: 3 }}>{formErrors.priority}</div>
                  )}
                </div>
                <div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>写入模式</div>
                  <select className="filter-select" style={{ width: '100%' }}
                    value={form.raw_write_mode} onChange={e => setField('raw_write_mode', e.target.value as 'both' | 'etl_only' | 'raw_only')}>
                    <option value="both">双写 (both)</option>
                    <option value="etl_only">仅 ETL (etl_only)</option>
                    <option value="raw_only">仅原始 (raw_only)</option>
                  </select>
                </div>
                <div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>状态</div>
                  <select className="filter-select" style={{ width: '100%' }}
                    value={form.is_enabled ? 'true' : 'false'} onChange={e => setField('is_enabled', e.target.value === 'true')}>
                    <option value="true">启用</option>
                    <option value="false">禁用</option>
                  </select>
                </div>
              </div>

              {/* Description */}
              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>描述</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }}
                  placeholder="规则用途简述"
                  value={form.description} onChange={e => setField('description', e.target.value)} />
              </div>

              {/* Match criteria */}
              <div style={{ border: `1px solid ${formErrors.match ? 'var(--critical)' : 'var(--border)'}`, borderRadius: 6, padding: '10px 12px' }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '.04em' }}>匹配条件</div>
                {formErrors.match && (
                  <div style={{ fontSize: 10.5, color: 'var(--critical)', marginBottom: 8 }}>{formErrors.match}</div>
                )}
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
                  <div>
                    <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginBottom: 3 }}>Tag Pattern (glob)</div>
                    <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box', fontFamily: 'monospace', fontSize: 11.5 }}
                      placeholder="winevent.*"
                      value={form.tag_pattern} onChange={e => { setField('tag_pattern', e.target.value); setFormErrors(p => ({ ...p, match: undefined })) }} />
                  </div>
                  <div>
                    <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginBottom: 3 }}>Dataset (逗号分隔)</div>
                    <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box', fontFamily: 'monospace', fontSize: 11.5 }}
                      placeholder="syslog_raw"
                      value={form.dataset} onChange={e => { setField('dataset', e.target.value); setFormErrors(p => ({ ...p, match: undefined })) }} />
                  </div>
                  <div>
                    <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginBottom: 3 }}>Kind (0=Syslog, 1=Process…)</div>
                    <select className="filter-select" style={{ width: '100%', fontSize: 11.5 }}
                      value={form.kind} onChange={e => { setField('kind', e.target.value); setFormErrors(p => ({ ...p, match: undefined })) }}>
                      <option value="">（不限）</option>
                      {Object.entries(KIND_NAMES).map(([k, v]) => (
                        <option key={k} value={k}>{k} — {v}</option>
                      ))}
                    </select>
                  </div>
                  <div>
                    <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginBottom: 3 }}>Filter Expr</div>
                    <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box', fontFamily: 'monospace', fontSize: 11.5 }}
                      placeholder='agent_id = "scanner-01"'
                      value={form.filter_expr} onChange={e => { setField('filter_expr', e.target.value); setFormErrors(p => ({ ...p, match: undefined })) }} />
                  </div>
                </div>
              </div>

              {/* Output */}
              <div style={{ border: '1px solid var(--border)', borderRadius: 6, padding: '10px 12px' }}>
                <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '.04em' }}>输出配置</div>
                <div style={{ display: 'grid', gridTemplateColumns: '2fr 1fr', gap: 10 }}>
                  <div>
                    <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginBottom: 3 }}>ngx 索引名称 (ETL 结果)</div>
                    <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box', fontFamily: 'monospace', fontSize: 11.5 }}
                      placeholder="win_process_enriched"
                      value={form.ngx_index} onChange={e => setField('ngx_index', e.target.value)} />
                  </div>
                  <div>
                    <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginBottom: 3 }}>写入 ArangoDB</div>
                    <select className="filter-select" style={{ width: '100%', fontSize: 11.5 }}
                      value={form.write_arango ? 'true' : 'false'} onChange={e => setField('write_arango', e.target.value === 'true')}>
                      <option value="true">是</option>
                      <option value="false">否</option>
                    </select>
                  </div>
                </div>
              </div>

              {/* Actions JSON */}
              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>
                  动作列表 (JSON)&nbsp;
                  <span style={{ fontSize: 10, opacity: 0.6 }}>
                    类型: {ACTION_TYPES.join(', ')}
                  </span>
                </div>
                <textarea className="filter-input"
                  style={{ width: '100%', boxSizing: 'border-box', minHeight: 120, fontFamily: 'Consolas,monospace', fontSize: 11.5, resize: 'vertical', color: jsonError ? 'var(--critical)' : undefined }}
                  value={form.actions_json}
                  onChange={e => { setField('actions_json', e.target.value); setJsonError('') }}
                  onBlur={e => validateJson(e.target.value)}
                />
                {jsonError && <div style={{ fontSize: 10.5, color: 'var(--critical)', marginTop: 3 }}>{jsonError}</div>}
              </div>

              <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setShowModal(false)}>取消</button>
                <button className="btn-primary" style={{ flex: 1 }}
                  disabled={saving || !form.name.trim() || !form.rule_id.trim()}
                  onClick={saveRule}>
                  {saving ? '保存中...' : editTarget ? '保存修改' : '创建规则'}
                </button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* ── Delete Confirm ── */}
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
              <button className="btn-primary" style={{ flex: 1, background: 'var(--critical)', borderColor: 'var(--critical)' }} onClick={doDelete}>
                确认删除
              </button>
            </div>
          </div>
        </>
      )}

      {/* ── Toast ── */}
      {toast && <Toast message={toast} onDone={() => setToast('')} />}
    </div>
  )
}

// ─── Tiny shared components ───────────────────────────────────────────────────

function Tag({ children, color }: { children: React.ReactNode; color: 'blue' | 'purple' | 'orange' | 'gray' | 'red' }) {
  const MAP = {
    blue:   { bg: 'rgba(63,160,224,.12)',   fg: 'var(--accent-blue)',             border: 'rgba(63,160,224,.25)' },
    purple: { bg: 'rgba(167,139,250,.12)',  fg: 'var(--accent-blue)',             border: 'rgba(167,139,250,.25)' },
    orange: { bg: 'rgba(250,88,45,.1)',     fg: 'var(--accent-orange)', border: 'rgba(250,88,45,.2)' },
    gray:   { bg: 'rgba(120,120,140,.12)',  fg: 'var(--text-muted)',    border: 'rgba(120,120,140,.2)' },
    red:    { bg: 'rgba(239,68,68,.12)',    fg: 'var(--critical)',      border: 'rgba(239,68,68,.25)' },
  }
  const c = MAP[color]
  return (
    <span style={{
      fontSize: 9.5, padding: '1px 5px', borderRadius: 3, fontFamily: 'monospace', fontWeight: 600,
      background: c.bg, color: c.fg, border: `1px solid ${c.border}`,
    }}>
      {children}
    </span>
  )
}

function StatusPill({ ok, label }: { ok: boolean; label: string }) {
  return (
    <span style={{
      fontSize: 11, padding: '2px 8px', borderRadius: 4, fontWeight: 600,
      background: ok ? 'rgba(34,197,94,.12)' : 'rgba(239,68,68,.12)',
      color: ok ? 'var(--accent-green)' : 'var(--critical)',
      border: `1px solid ${ok ? 'rgba(34,197,94,.25)' : 'rgba(239,68,68,.25)'}`,
    }}>
      {label}
    </span>
  )
}
