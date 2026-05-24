import { useEffect, useRef, useState } from 'react'
import { Cell, Pie, PieChart, Tooltip } from 'recharts'
import api from '@/lib/api'
import type { PageMeta } from '@/lib/api'
import ResizableTh from '@/components/ResizableTh'

// ─── Types ────────────────────────────────────────────────────────────────────

interface ETLMatchCriteria {
  dataset?: string[]
  tag_pattern?: string
  kind?: number
  filter_expr?: string
  filter_mode?: 'and' | 'or'
}

interface ETLAction {
  type: string
  params?: Record<string, string>
}

interface ETLSink {
  ngx_index?: string
  arango_collection?: string
  ttl_days?: number
  condition?: string
}

interface ETLOutput {
  sinks?: ETLSink[]
  ngx_index?: string
  arango_collection?: string
  ttl_days?: number
}

interface ETLRule {
  _key: string
  rule_id: string
  name: string
  description?: string
  tenant_id: string
  is_enabled: boolean
  priority: number
  processing_mode?: 'first_match' | 'sequential'
  match: ETLMatchCriteria
  raw_write_mode: 'both' | 'etl_only' | 'raw_only'
  actions: ETLAction[]
  output: ETLOutput
  created_at: string
  updated_at: string
  created_by?: string
}

interface SinkSummary {
  ngx_index?: string
  arango_collection?: string
  ttl_days?: number
  condition_met?: boolean
}

interface TestResult {
  matched: boolean
  raw_ngx_index: string
  sinks?: SinkSummary[]
  dropped: boolean
  output_entry?: {
    kind: number
    dataset: string
    hostname: string
    fields: Record<string, string>
  }
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


const ACTION_TYPES = [
  'set_field', 'rename_field', 'delete_field', 'copy_key',
  'parse_json', 'grok', 'decode_csv', 'encode_csv', 'encode_json',
  'flatten_subrecord', 'nest_keys', 'lift_submap',
  'multiline_join', 'split_record', 'join_records',
  'allow_keys', 'block_keys', 'allow_records', 'block_records', 'drop_event',
  'lookup_asset', 'lookup_threat', 'lookup_geoip',
  'set_dataset', 'set_kind',
  'parse_number', 'hash_key', 'redact_value', 'search_replace',
  'random_sample', 'dedup', 'custom_lua',
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
  return 'var(--text-muted)'
}

function effectiveSinks(rule: ETLRule): ETLSink[] {
  const sinks = rule.output?.sinks ?? []
  if (sinks.length > 0) return sinks
  const legacy: ETLSink = {}
  if (rule.output?.ngx_index) legacy.ngx_index = rule.output.ngx_index
  if (rule.output?.arango_collection) legacy.arango_collection = rule.output.arango_collection
  if (rule.output?.ttl_days) legacy.ttl_days = rule.output.ttl_days
  if (legacy.ngx_index || legacy.arango_collection) return [legacy]
  return []
}

// ─── Validation ────────────────────────────────────────────────────────────────

const RULE_ID_RE = /^[a-z0-9][a-z0-9-]*[a-z0-9]$/

interface FormErrors { rule_id?: string; priority?: string; match?: string }

interface SinkFormRow {
  ngx_index: string; arango_collection: string; ttl_days: string; condition: string
}

const BLANK_SINK: SinkFormRow = { ngx_index: '', arango_collection: '', ttl_days: '', condition: '' }

const BLANK_FORM = {
  rule_id: '',
  name: '',
  description: '',
  priority: '50',
  is_enabled: true,
  processing_mode: 'first_match' as 'first_match' | 'sequential',
  tag_pattern: '',
  dataset: '',
  kind: '',
  filter_expr: '',
  filter_mode: 'and' as 'and' | 'or',
  raw_write_mode: 'both' as 'both' | 'etl_only' | 'raw_only',
  sinks: [{ ...BLANK_SINK }] as SinkFormRow[],
  actions_json: '[\n  {"type":"set_field","params":{"field":"etl_version","value":"1.0"}}\n]',
}

type FormState = typeof BLANK_FORM

function ruleToForm(r: ETLRule): FormState {
  const rawSinks = effectiveSinks(r)
  const sinks: SinkFormRow[] = rawSinks.length > 0
    ? rawSinks.map(s => ({
        ngx_index: s.ngx_index ?? '',
        arango_collection: s.arango_collection ?? '',
        ttl_days: s.ttl_days != null ? String(s.ttl_days) : '',
        condition: s.condition ?? '',
      }))
    : [{ ...BLANK_SINK }]
  return {
    rule_id: r.rule_id, name: r.name, description: r.description ?? '',
    priority: String(r.priority), is_enabled: r.is_enabled,
    processing_mode: r.processing_mode ?? 'first_match',
    tag_pattern: r.match?.tag_pattern ?? '',
    dataset: (r.match?.dataset ?? []).join(', '),
    kind: r.match?.kind != null ? String(r.match.kind) : '',
    filter_expr: r.match?.filter_expr ?? '',
    filter_mode: r.match?.filter_mode ?? 'and',
    raw_write_mode: r.raw_write_mode ?? 'both',
    sinks,
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
  if (f.filter_mode === 'or') match.filter_mode = 'or'
  const sinks: ETLSink[] = f.sinks
    .filter(s => s.ngx_index.trim() || s.arango_collection.trim())
    .map(s => {
      const sink: ETLSink = {}
      if (s.ngx_index.trim()) sink.ngx_index = s.ngx_index.trim()
      if (s.arango_collection.trim()) sink.arango_collection = s.arango_collection.trim()
      const ttl = parseInt(s.ttl_days, 10)
      if (!isNaN(ttl) && ttl > 0) sink.ttl_days = ttl
      if (s.condition.trim()) sink.condition = s.condition.trim()
      return sink
    })
  return {
    rule_id: f.rule_id.trim(), name: f.name.trim(),
    description: f.description.trim() || undefined,
    priority: parseInt(f.priority, 10) || 50,
    is_enabled: f.is_enabled,
    processing_mode: f.processing_mode,
    match, raw_write_mode: f.raw_write_mode, actions,
    output: { sinks },
  }
}

const SAMPLE_ENDPOINT_EVENT = JSON.stringify({
  process_name: 'cmd.exe', cmdline: 'cmd.exe /c whoami', user: 'jdoe',
  pid: 4444, parent_pid: 1234, parent_process: 'explorer.exe',
  path: 'C:\\Windows\\System32\\cmd.exe', hash_md5: 'abc123def456',
}, null, 2)

const BLANK_TEST = {
  tag: 'winevent.security', kind: '1', dataset: '', hostname: '', agent_id: '',
  fields_json: SAMPLE_ENDPOINT_EVENT,
}

// ─── Tiny shared components ────────────────────────────────────────────────────

function Tag({ children, color }: { children: React.ReactNode; color: 'blue' | 'purple' | 'orange' | 'gray' | 'red' }) {
  const MAP = {
    blue:   { bg: 'rgba(63,160,224,.12)',  fg: 'var(--accent-blue)',   border: 'rgba(63,160,224,.25)' },
    purple: { bg: 'rgba(167,139,250,.12)', fg: 'rgba(167,139,250,.9)', border: 'rgba(167,139,250,.25)' },
    orange: { bg: 'rgba(250,88,45,.1)',    fg: 'var(--accent-orange)', border: 'rgba(250,88,45,.2)' },
    gray:   { bg: 'rgba(120,120,140,.12)', fg: 'var(--text-muted)',    border: 'rgba(120,120,140,.2)' },
    red:    { bg: 'rgba(239,68,68,.12)',   fg: 'var(--critical)',      border: 'rgba(239,68,68,.25)' },
  }
  const c = MAP[color]
  return (
    <span style={{ fontSize: 9.5, padding: '1px 5px', borderRadius: 3, fontFamily: 'monospace', fontWeight: 600, background: c.bg, color: c.fg, border: `1px solid ${c.border}` }}>
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
    }}>{label}</span>
  )
}

function Toast({ message, onDone }: { message: string; onDone: () => void }) {
  useEffect(() => { const t = setTimeout(onDone, 3000); return () => clearTimeout(t) }, [onDone])
  return (
    <div style={{
      position: 'fixed', bottom: 28, right: 28, zIndex: 9999,
      background: 'var(--accent-green)', color: '#fff',
      padding: '10px 18px', borderRadius: 6, fontSize: 13, fontWeight: 500,
      boxShadow: '0 4px 16px rgba(0,0,0,.3)',
    }}>{message}</div>
  )
}

// ─── Tab 1: Pipeline Flow ─────────────────────────────────────────────────────

interface LiveStats { events: number; matched: number; dropped: number; latency: number }

function PipelineTab({ stats }: { stats: ETLStats | null }) {
  const [live, setLive] = useState<LiveStats>({ events: 142_837, matched: 131_204, dropped: 3_421, latency: 12 })

  useEffect(() => {
    const t = setInterval(() => {
      setLive(p => ({
        events:  p.events  + Math.floor(Math.random() * 800 + 200),
        matched: p.matched + Math.floor(Math.random() * 720 + 180),
        dropped: p.dropped + Math.floor(Math.random() * 40  + 10),
        latency: Math.max(6, Math.min(40, p.latency + (Math.random() > .5 ? 1 : -1) * Math.floor(Math.random() * 3))),
      }))
    }, 5000)
    return () => clearInterval(t)
  }, [])

  const healthColor = live.latency < 25 ? '#52b788' : live.latency < 35 ? '#e9c46a' : '#e76f51'

  // ── Design tokens (Datadog / Linear inspired) ──────────────────────────────
  // Palette: cool slate base, one warm accent (amber), muted semantic colors
  // All fills use low opacity; strokes carry identity; text stays near-white
  const C = {
    src:     { fill: 'rgba(148,163,184,.07)', stroke: 'rgba(148,163,184,.28)', text: 'rgba(203,213,225,.85)', sub: 'rgba(148,163,184,.55)' },
    ingest:  { fill: 'rgba(251,191,36,.05)',  stroke: 'rgba(251,191,36,.25)',  text: 'rgba(251,191,36,.8)',   sub: 'rgba(251,191,36,.45)' },
    engine:  { fill: 'rgba(99,102,241,.05)',  stroke: 'rgba(99,102,241,.22)',  text: 'rgba(165,180,252,.85)', row: 'rgba(99,102,241,.06)', rowS: 'rgba(99,102,241,.14)' },
    lua:     { text: 'rgba(196,181,253,.75)', rowS: 'rgba(139,92,246,.18)' },
    sink:    { fill: 'rgba(56,189,248,.06)',  stroke: 'rgba(56,189,248,.22)',  text: 'rgba(125,211,252,.85)', sub: 'rgba(56,189,248,.45)' },
    drop:    { fill: 'rgba(248,113,113,.05)', stroke: 'rgba(248,113,113,.2)',  text: 'rgba(252,165,165,.8)',  sub: 'rgba(248,113,113,.4)' },
    arch:    { fill: 'rgba(148,163,184,.04)', stroke: 'rgba(148,163,184,.14)', text: 'rgba(148,163,184,.4)' },
    arrow:   { src: 'rgba(148,163,184,.4)',  mid: 'rgba(251,191,36,.35)',  out: 'rgba(56,189,248,.38)',  drop: 'rgba(248,113,113,.35)' },
    label:   'rgba(148,163,184,.35)',
  }

  // ── Layout constants ────────────────────────────────────────────────────────
  // viewBox = 980×550. Usable vertical: y=30..530 (500px)
  // 4 source boxes: h=80, gap=26 → span=4*80+3*26=398, top=30+(500-398)/2=81
  const BOX_H = 80, BOX_GAP = 26
  const SRC_TOP   = 81   // first box y
  const srcY = (i: number) => SRC_TOP + i * (BOX_H + BOX_GAP)  // 81,187,293,399
  const srcMid = (i: number) => srcY(i) + BOX_H / 2             // 121,227,333,439
  const MID_Y = Math.round((srcMid(0) + srcMid(3)) / 2)         // ≈ 280

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', background: '#0d1117' }}>
      <style>{`
        @keyframes etlDash  { to { stroke-dashoffset: -22; } }
        @keyframes etlDash2 { to { stroke-dashoffset: -22; } }
        .etl-a  { stroke-dasharray: 5 4; stroke-dashoffset: 0; animation: etlDash  1.4s linear infinite; }
        .etl-a2 { stroke-dasharray: 5 4; stroke-dashoffset: 0; animation: etlDash2 2.2s linear infinite; }
        @keyframes engineGlow { 0%,100%{opacity:1} 50%{opacity:.88} }
        .etl-eng { animation: engineGlow 4s ease-in-out infinite; }
        @keyframes livePulse { 0%,100%{r:4} 50%{r:5.5} }
        .live-dot { animation: livePulse 2s ease-in-out infinite; }
      `}</style>

      <div style={{ flex: 1, minHeight: 0, padding: '10px 16px 8px', overflow: 'hidden', position: 'relative' }}>
        <svg viewBox="0 0 980 550"
          style={{ position: 'absolute', top: 10, left: 16, right: 16, bottom: 8, width: 'calc(100% - 32px)', height: 'calc(100% - 18px)' }}
          aria-label="ETL Pipeline">

          {/* subtle horizontal guides */}
          {[138, 275, 413].map(y => (
            <line key={y} x1="0" y1={y} x2="980" y2={y} stroke="rgba(255,255,255,.02)" strokeWidth="1" />
          ))}

          {/* ══ SECTION LABELS ══ */}
          {[
            { x: 72,  label: '数据源' },
            { x: 234, label: '接收' },
            { x: 490, label: '处理引擎' },
            { x: 790, label: '输出' },
          ].map(({ x, label }) => (
            <text key={label} x={x} y="24" textAnchor="middle"
              fill={C.label} fontSize="12" fontWeight="600" letterSpacing="1.4">{label.toUpperCase()}</text>
          ))}
          {/* live indicator — top right */}
          <circle cx="970" cy="18" r="5" fill={healthColor} className="live-dot" opacity=".9" />
          <text x="956" y="22" textAnchor="end" fill={healthColor} fontSize="11" fontWeight="600" opacity=".85">实时</text>

          {/* ══ SOURCE NODES  (4×80px, gap 26, top=81) ══ */}
          {[
            { label: '终端 Agent', sub: 'Wazuh / EDR' },
            { label: 'Webhook',    sub: 'HTTP POST' },
            { label: 'REST API',   sub: '/ingest' },
            { label: 'Syslog',     sub: 'UDP 514' },
          ].map(({ label, sub }, i) => {
            const y = srcY(i)
            return (
              <g key={label}>
                <rect x="10" y={y} width="124" height={BOX_H} rx="8"
                  fill={C.src.fill} stroke={C.src.stroke} strokeWidth="1.5" />
                <text x="72" y={y + 32} textAnchor="middle"
                  fill={C.src.text} fontSize="14" fontWeight="600">{label}</text>
                <text x="72" y={y + 52} textAnchor="middle"
                  fill={C.src.sub} fontSize="11">{sub}</text>
              </g>
            )
          })}

          {/* source → ingest arrows */}
          {[0, 1, 2, 3].map(i => (
            <line key={i} x1="134" y1={srcMid(i)} x2="196" y2={MID_Y}
              stroke={C.arrow.src} strokeWidth="1.5" className="etl-a" />
          ))}

          {/* ══ INGEST BUFFER ══  centered at MID_Y, h=120 */}
          <rect x="196" y={MID_Y - 60} width="76" height="120" rx="8"
            fill={C.ingest.fill} stroke={C.ingest.stroke} strokeWidth="1.5" className="etl-eng" />
          <text x="234" y={MID_Y - 14} textAnchor="middle" fill={C.ingest.text} fontSize="13" fontWeight="700">采集</text>
          <text x="234" y={MID_Y + 8}  textAnchor="middle" fill={C.ingest.sub}  fontSize="11">缓冲</text>
          <text x="234" y={MID_Y + 28} textAnchor="middle" fill={C.ingest.sub}  fontSize="10" opacity=".7">raw_*</text>

          {/* ingest → engine */}
          <line x1="272" y1={MID_Y} x2="316" y2={MID_Y}
            stroke={C.arrow.mid} strokeWidth="1.8" className="etl-a" />
          <polygon points={`312,${MID_Y-5} 322,${MID_Y} 312,${MID_Y+5}`} fill={C.arrow.mid} />

          {/* ══ ETL ENGINE ══  y=38..532 */}
          <rect x="322" y="38" width="354" height="494" rx="10"
            fill={C.engine.fill} stroke={C.engine.stroke} strokeWidth="1.8" className="etl-eng" />
          <text x="499" y="68" textAnchor="middle"
            fill={C.engine.text} fontSize="16" fontWeight="700" letterSpacing="2">ETL 引擎</text>

          {/* stage rows — 7 rows × 60px starting at y=82 */}
          {[
            { label: '① Match  —  tag / dataset / kind / filter_expr',  lua: false },
            { label: '② Transform  —  set / rename / parse / hash',      lua: false },
            { label: '③ Enrich  —  GeoIP / asset / threat lookup',       lua: false },
            { label: '④ Filter  —  allow_keys / block_records',          lua: false },
            { label: '⑤ Dedup / Sample  —  sliding window',              lua: false },
            { label: '⑥ Lua  —  custom_lua  (Fluent Bit compatible)',    lua: true  },
            { label: '⑦ Route  →  Sinks  (multi-sink, per-condition)',   lua: false },
          ].map(({ label, lua }, i) => (
            <g key={i}>
              <rect x="338" y={84 + i * 62} width="322" height="46" rx="5"
                fill={lua ? C.lua.rowS : C.engine.row}
                stroke={lua ? 'rgba(139,92,246,.25)' : C.engine.rowS}
                strokeWidth="1" />
              <text x="499" y={113 + i * 62} textAnchor="middle"
                fill={lua ? C.lua.text : C.engine.text}
                fontSize="12" opacity={lua ? 1 : 0.85}>{label}</text>
            </g>
          ))}

          {/* engine → sink arrows */}
          {/* sink y values: ngx=121-40=81, arango=280-40=240, drop=439-40=399 */}
          <line x1="676" y1="150" x2="718" y2={srcMid(0)}
            stroke={C.arrow.out} strokeWidth="1.5" className="etl-a2" />
          <polygon points={`714,${srcMid(0)-5} 724,${srcMid(0)} 714,${srcMid(0)+5}`} fill={C.arrow.out} />

          <line x1="676" y1={MID_Y} x2="718" y2={MID_Y - 0}
            stroke={C.arrow.out} strokeWidth="1.5" className="etl-a2" />
          <polygon points={`714,${MID_Y-5} 724,${MID_Y} 714,${MID_Y+5}`} fill={C.arrow.out} />

          <line x1="676" y1="420" x2="718" y2={srcMid(3)}
            stroke={C.arrow.drop} strokeWidth="1.5" className="etl-a2" />
          <polygon points={`714,${srcMid(3)-5} 724,${srcMid(3)} 714,${srcMid(3)+5}`} fill={C.arrow.drop} />

          {/* ══ SINK NODES ══  top=srcY(0), mid=MID_Y-40, bottom=srcY(3) */}
          {[
            { y: srcY(0),      label: 'ngx  (ETL)',  sub: '自定义索引',  drop: false },
            { y: MID_Y - 40,   label: 'ArangoDB',    sub: '热数据集合',  drop: false },
            { y: srcY(3),      label: '丢弃',        sub: 'drop_event',  drop: true  },
          ].map(({ y, label, sub, drop }) => (
            <g key={label}>
              <rect x="724" y={y} width="148" height={BOX_H} rx="8"
                fill={drop ? C.drop.fill : C.sink.fill}
                stroke={drop ? C.drop.stroke : C.sink.stroke}
                strokeWidth="1.5" />
              <text x="798" y={y + 32} textAnchor="middle"
                fill={drop ? C.drop.text : C.sink.text}
                fontSize="14" fontWeight="600">{label}</text>
              <text x="798" y={y + 52} textAnchor="middle"
                fill={drop ? C.drop.sub : C.sink.sub}
                fontSize="11">{sub}</text>
            </g>
          ))}

          {/* sink → archive (dashed) */}
          <line x1="872" y1={srcMid(0)} x2="906" y2={srcMid(0)}
            stroke={C.arrow.out} strokeWidth="1" strokeDasharray="4 3" opacity=".45" />
          <line x1="872" y1={srcMid(2)} x2="906" y2={srcMid(2)}
            stroke={C.arrow.out} strokeWidth="1" strokeDasharray="4 3" opacity=".45" />

          {/* ══ ARCHIVE ══  y=60..532 */}
          <rect x="906" y="60" width="62" height="472" rx="8"
            fill={C.arch.fill} stroke={C.arch.stroke} strokeWidth="1" />
          <text x="937" y="240" textAnchor="middle"
            fill={C.arch.text} fontSize="12" fontWeight="500"
            style={{ writingMode: 'vertical-rl' } as React.CSSProperties}>归档 / TTL</text>
          <text x="937" y="420" textAnchor="middle"
            fill={C.arch.text} fontSize="10"
            style={{ writingMode: 'vertical-rl' } as React.CSSProperties}>冷数据 ngx</text>

          {/* archive label */}
          <text x="937" y="48" textAnchor="middle"
            fill={C.label} fontSize="11" fontWeight="600" letterSpacing="1">归档</text>

        </svg>
      </div>

      {/* ── Stats strip ── */}
      <div style={{
        display: 'grid', gridTemplateColumns: 'repeat(6, 1fr)',
        borderTop: '1px solid rgba(255,255,255,.07)',
        background: '#161b22', flexShrink: 0,
      }}>
        {[
          { label: '今日处理事件', value: live.events.toLocaleString(),  color: 'rgba(148,163,184,.9)' },
          { label: '规则匹配',     value: live.matched.toLocaleString(), color: '#52b788' },
          { label: '已丢弃',       value: live.dropped.toLocaleString(), color: 'rgba(252,165,165,.8)' },
          { label: '平均延迟',     value: `${live.latency}ms`,           color: healthColor },
          { label: '规则总数',     value: String(stats?.total ?? '—'),   color: 'rgba(148,163,184,.7)' },
          { label: '启用规则',     value: String(stats?.enabled ?? '—'), color: '#52b788' },
        ].map((s, i) => (
          <div key={s.label} style={{
            padding: '14px 18px', borderLeft: i > 0 ? '1px solid rgba(255,255,255,.07)' : 'none',
            display: 'flex', flexDirection: 'column', gap: 5,
          }}>
            <span style={{ fontSize: 20, fontWeight: 700, fontFamily: 'monospace', color: s.color, lineHeight: 1 }}>
              {s.value}
            </span>
            <span style={{ fontSize: 10, color: 'rgba(148,163,184,.6)', letterSpacing: '.03em' }}>{s.label}</span>
          </div>
        ))}
      </div>

      {/* ── Legend ── */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 20, padding: '7px 24px',
        background: '#161b22', borderTop: '1px solid rgba(255,255,255,.07)',
        flexShrink: 0, flexWrap: 'wrap',
      }}>
        {[
          { color: 'rgba(148,163,184,.6)', label: '数据源' },
          { color: 'rgba(251,191,36,.55)', label: '接收缓冲' },
          { color: 'rgba(99,102,241,.6)',  label: 'ETL 处理' },
          { color: 'rgba(196,181,253,.7)', label: 'Lua 脚本' },
          { color: 'rgba(56,189,248,.6)',  label: '输出 Sink' },
          { color: 'rgba(248,113,113,.6)', label: '丢弃' },
        ].map(({ color, label }) => (
          <div key={label} style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 10.5, color: 'rgba(148,163,184,.7)' }}>
            <div style={{ width: 8, height: 8, borderRadius: 2, background: color, flexShrink: 0 }} />
            {label}
          </div>
        ))}
        <div style={{ marginLeft: 'auto', fontSize: 10, color: 'rgba(148,163,184,.4)' }}>
          数据每 5 秒更新 · 流量为模拟演示
        </div>
      </div>
    </div>
  )
}

// ─── Sinks Editor ─────────────────────────────────────────────────────────────

function SinksEditor({ sinks, onChange }: { sinks: SinkFormRow[]; onChange: (s: SinkFormRow[]) => void }) {
  function setSink(idx: number, key: keyof SinkFormRow, value: string) {
    onChange(sinks.map((s, i) => i === idx ? { ...s, [key]: value } : s))
  }
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {sinks.map((sink, idx) => (
        <div key={idx} style={{ border: '1px solid var(--border)', borderRadius: 6, padding: '10px 12px', background: 'var(--bg-secondary)', position: 'relative' }}>
          <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
            <span style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: '.06em' }}>Sink #{idx + 1}</span>
            <button onClick={() => { if (sinks.length <= 1) { onChange([{ ...BLANK_SINK }]); return }; onChange(sinks.filter((_, i) => i !== idx)) }}
              style={{ fontSize: 11, color: 'var(--critical)', background: 'none', border: 'none', cursor: 'pointer', padding: '0 2px' }} title="删除">✕</button>
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 80px 1fr', gap: 8 }}>
            {[
              { key: 'ngx_index' as const,         label: 'ngx 索引',     ph: 'win_process_enriched' },
              { key: 'arango_collection' as const,  label: 'Arango 集合',  ph: 'proc_events' },
              { key: 'ttl_days' as const,           label: 'TTL 天',       ph: '90' },
              { key: 'condition' as const,          label: '条件 (可选)',  ph: 'severity~=high' },
            ].map(({ key, label, ph }) => (
              <div key={key}>
                <div style={{ fontSize: 9.5, color: 'var(--text-muted)', marginBottom: 3 }}>{label}</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box', fontFamily: 'monospace', fontSize: 11 }}
                  placeholder={ph} type={key === 'ttl_days' ? 'number' : 'text'} min={key === 'ttl_days' ? '0' : undefined}
                  value={sink[key]} onChange={e => setSink(idx, key, e.target.value)} />
              </div>
            ))}
          </div>
        </div>
      ))}
      <button className="btn-secondary" style={{ fontSize: 11, padding: '4px 12px', alignSelf: 'flex-start' }}
        onClick={() => onChange([...sinks, { ...BLANK_SINK }])}>
        + 添加 Sink
      </button>
    </div>
  )
}

// ─── Test Modal ────────────────────────────────────────────────────────────────

function TestModal({ rule, onClose }: { rule: ETLRule; onClose: () => void }) {
  const [testForm, setTestForm] = useState({ ...BLANK_TEST })
  const [testResult, setTestResult] = useState<TestResult | null>(null)
  const [testLoading, setTestLoading] = useState(false)

  function runTest() {
    setTestLoading(true)
    let fields: Record<string, string> = {}
    try { fields = JSON.parse(testForm.fields_json) } catch { /* ok */ }
    const body: Record<string, unknown> = {
      tag: testForm.tag,
      sample: { dataset: testForm.dataset || undefined, hostname: testForm.hostname || undefined, agent_id: testForm.agent_id || undefined, fields },
    }
    if (testForm.kind.trim()) (body.sample as Record<string, unknown>).kind = parseInt(testForm.kind, 10)
    api.post(`/etl/rules/${rule._key}/test`, body)
      .then(r => setTestResult(r.data.data))
      .catch(() => setTestResult({ matched: false, raw_ngx_index: '', sinks: [], dropped: false }))
      .finally(() => setTestLoading(false))
  }

  return (
    <>
      <div onClick={onClose} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
      <div style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: 620, background: 'var(--bg-modal)', border: '1px solid var(--border)', borderRadius: 10, zIndex: 500, padding: 24, maxHeight: '90vh', overflowY: 'auto' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 18 }}>
          <div>
            <div style={{ fontSize: 15, fontWeight: 600 }}>干运行测试</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
              规则: <span style={{ fontFamily: 'monospace', color: 'var(--accent-blue)' }}>{rule.name}</span>
            </div>
          </div>
          <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px' }} onClick={onClose}>✕</button>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
            <div>
              <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginBottom: 3 }}>标签</div>
              <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }}
                placeholder="winevent.security" value={testForm.tag}
                onChange={e => setTestForm(p => ({ ...p, tag: e.target.value }))} />
            </div>
            <div>
              <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginBottom: 3 }}>类型</div>
              <select className="filter-select" style={{ width: '100%' }}
                value={testForm.kind} onChange={e => setTestForm(p => ({ ...p, kind: e.target.value }))}>
                <option value="">（不限）</option>
                {Object.entries(KIND_NAMES).map(([k, v]) => <option key={k} value={k}>{k} — {v}</option>)}
              </select>
            </div>
          </div>
          <div>
            <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 3 }}>
              <div style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>样本事件字段 (JSON)</div>
              <button style={{ fontSize: 9.5, color: 'var(--accent-blue)', background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}
                onClick={() => setTestForm(p => ({ ...p, fields_json: SAMPLE_ENDPOINT_EVENT }))}>重置示例</button>
            </div>
            <textarea className="filter-input"
              style={{ width: '100%', boxSizing: 'border-box', fontSize: 10.5, minHeight: 150, fontFamily: 'Consolas,monospace', resize: 'vertical' }}
              value={testForm.fields_json} onChange={e => setTestForm(p => ({ ...p, fields_json: e.target.value }))} />
          </div>
          <button className="btn-primary" disabled={testLoading} onClick={runTest}>
            {testLoading ? '运行中…' : '▶ 运行测试'}
          </button>

          {testResult && (
            <div style={{ background: 'var(--bg-secondary)', borderRadius: 8, padding: 14, fontSize: 11.5 }}>
              {/* flow pills */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 0, marginBottom: 14, flexWrap: 'nowrap', overflowX: 'auto' }}>
                {[
                  { label: 'Input', color: 'var(--accent-blue)', always: true },
                  { label: testResult.matched ? '✓ Match' : '✗ No Match', color: testResult.matched ? 'var(--accent-green)' : 'var(--critical)', always: true },
                  ...(testResult.matched ? [
                    { label: 'Actions', color: 'rgba(167,139,250,.9)', always: true },
                    { label: `Sinks (${(testResult.sinks ?? []).filter(s => s.condition_met).length})`, color: '#14b8a6', always: true },
                  ] : []),
                ].map((node, i) => (
                  <div key={i} style={{ display: 'flex', alignItems: 'center', flexShrink: 0 }}>
                    {i > 0 && <div style={{ width: 24, height: 1, background: 'var(--border)', position: 'relative' }}><span style={{ position: 'absolute', right: -4, top: -5, fontSize: 9, color: 'var(--text-muted)' }}>▶</span></div>}
                    <div style={{ padding: '6px 12px', borderRadius: 5, background: `${node.color}18`, border: `1px solid ${node.color}40`, fontSize: 11, color: node.color, fontWeight: 600, whiteSpace: 'nowrap' }}>{node.label}</div>
                  </div>
                ))}
              </div>
              <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 10 }}>
                <StatusPill ok={testResult.matched} label={testResult.matched ? '✓ 规则匹配' : '✗ 未匹配'} />
                {testResult.dropped && <StatusPill ok={false} label="✗ 事件丢弃" />}
              </div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8 }}>
                raw_ngx_index: <span style={{ fontFamily: 'monospace', color: 'var(--accent-blue)' }}>{testResult.raw_ngx_index || '—'}</span>
              </div>
              {testResult.matched && (testResult.sinks ?? []).length > 0 && (
                <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 10.5 }}>
                  <thead>
                    <tr style={{ borderBottom: '1px solid var(--border)' }}>
                      {['ngx_index', 'arango_collection', 'ttl', '命中'].map(h => (
                        <ResizableTh key={h} style={{ textAlign: 'left', padding: '3px 6px', fontSize: 10, color: 'var(--text-muted)', fontWeight: 600 }}>{h}</ResizableTh>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {(testResult.sinks ?? []).map((s, i) => (
                      <tr key={i} style={{ opacity: s.condition_met ? 1 : 0.4 }}>
                        <td style={{ padding: '3px 6px', fontFamily: 'monospace', color: 'var(--accent-blue)' }}>{s.ngx_index || '—'}</td>
                        <td style={{ padding: '3px 6px', fontFamily: 'monospace', color: '#14b8a6' }}>{s.arango_collection || '—'}</td>
                        <td style={{ padding: '3px 6px', fontFamily: 'monospace' }}>{s.ttl_days ?? '—'}</td>
                        <td style={{ padding: '3px 6px', textAlign: 'center', color: s.condition_met ? 'var(--accent-green)' : 'var(--text-muted)' }}>{s.condition_met ? '✓' : '✗'}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
              {testResult.output_entry && (
                <div style={{ marginTop: 10 }}>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 5, textTransform: 'uppercase', letterSpacing: .4 }}>输出字段</div>
                  <pre style={{ margin: 0, fontSize: 10.5, color: 'var(--accent-green)', fontFamily: 'monospace', whiteSpace: 'pre-wrap', background: 'rgba(0,0,0,.2)', borderRadius: 4, padding: 8 }}>
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

function ImportModal({ onClose, onImported, showToast }: { onClose: () => void; onImported: () => void; showToast: (m: string) => void }) {
  const [activeTab, setActiveTab] = useState<'file' | 'paste'>('file')
  const [dragOver, setDragOver] = useState(false)
  const [fileName, setFileName] = useState('')
  const [filePreview, setFilePreview] = useState<ETLRule[] | null>(null)
  const [fileError, setFileError] = useState('')
  const [jsonText, setJsonText] = useState('')
  const [pasteError, setPasteError] = useState('')
  const [pastePreview, setPastePreview] = useState<ETLRule[] | null>(null)
  const [pasteValidMsg, setPasteValidMsg] = useState('')
  const [progress, setProgress] = useState('')
  const [done, setDone] = useState(false)
  const [importResult, setImportResult] = useState('')
  const fileInputRef = useRef<HTMLInputElement>(null)

  function parseRuleArray(raw: unknown): ETLRule[] | string {
    const arr: unknown[] = Array.isArray(raw) ? raw : [raw]
    const invalid = arr.filter(r => { if (typeof r !== 'object' || r === null) return true; const o = r as Record<string, unknown>; return !o.name || !o.rule_id })
    if (invalid.length > 0) return `${invalid.length} 条记录缺少 name 或 rule_id`
    return arr as ETLRule[]
  }

  function handleFile(file: File) {
    setFileError(''); setFilePreview(null); setFileName(file.name)
    const reader = new FileReader()
    reader.onload = e => {
      let parsed: unknown
      try { parsed = JSON.parse(e.target?.result as string) }
      catch (err: unknown) { setFileError('JSON 解析失败: ' + (err instanceof Error ? err.message : String(err))); return }
      const result = parseRuleArray(parsed)
      if (typeof result === 'string') setFileError(result)
      else setFilePreview(result)
    }
    reader.readAsText(file)
  }

  function validatePaste() {
    setPasteError(''); setPasteValidMsg(''); setPastePreview(null)
    if (!jsonText.trim()) { setPasteError('请粘贴 JSON 内容'); return }
    let parsed: unknown
    try { parsed = JSON.parse(jsonText) }
    catch (e: unknown) { setPasteError('JSON 解析失败: ' + (e instanceof Error ? e.message : String(e))); return }
    const result = parseRuleArray(parsed)
    if (typeof result === 'string') setPasteError(result)
    else { setPastePreview(result); setPasteValidMsg(`有效: ${result.length} 条规则`) }
  }

  async function doImport(rules: ETLRule[]) {
    let ok = 0, skipped = 0
    for (let i = 0; i < rules.length; i++) {
      setProgress(`${i + 1}/${rules.length}`)
      const rule = rules[i]
      const body = { rule_id: rule.rule_id, name: rule.name, description: rule.description, priority: rule.priority ?? 50, is_enabled: rule.is_enabled ?? true, processing_mode: rule.processing_mode ?? 'first_match', match: rule.match ?? {}, raw_write_mode: rule.raw_write_mode ?? 'both', actions: rule.actions ?? [], output: rule.output ?? { sinks: [] } }
      try { await api.post('/etl/rules/import', { rules: [body] }); ok++ }
      catch { try { await api.post('/etl/rules', body); ok++ } catch { skipped++ } }
    }
    setProgress(''); setDone(true)
    setImportResult(`✅ 成功导入 ${ok} 条, 跳过 ${skipped} 条`)
    showToast(`导入完成: ${ok} 条成功${skipped > 0 ? `, ${skipped} 条跳过` : ''}`)
    onImported()
    setTimeout(() => onClose(), 2500)
  }

  const activePreview = activeTab === 'file' ? filePreview : pastePreview

  return (
    <>
      <div onClick={!progress ? onClose : undefined} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
      <div style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: 680, background: 'var(--bg-modal)', border: '1px solid var(--border)', borderRadius: 10, zIndex: 500, padding: 24, maxHeight: '90vh', display: 'flex', flexDirection: 'column' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 14, flexShrink: 0 }}>
          <div>
            <div style={{ fontSize: 15, fontWeight: 600 }}>导入规则</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>支持文件上传或直接粘贴 JSON</div>
          </div>
          <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px' }} onClick={onClose} disabled={!!progress}>✕</button>
        </div>
        {done ? (
          <div style={{ textAlign: 'center', padding: '32px 0' }}>
            <div style={{ fontSize: 22, marginBottom: 10 }}>✅</div>
            <div style={{ color: 'var(--accent-green)', fontWeight: 600 }}>{importResult}</div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 8 }}>窗口即将关闭…</div>
          </div>
        ) : !activePreview ? (
          <>
            <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', marginBottom: 16, flexShrink: 0 }}>
              {(['file', 'paste'] as const).map(tab => (
                <button key={tab} onClick={() => setActiveTab(tab)} style={{ padding: '6px 16px', fontSize: 12, fontWeight: 500, background: 'none', border: 'none', cursor: 'pointer', color: activeTab === tab ? 'var(--accent-blue)' : 'var(--text-muted)', borderBottom: activeTab === tab ? '2px solid var(--accent-blue)' : '2px solid transparent', marginBottom: -1 }}>
                  {tab === 'file' ? '📁 文件上传' : '📋 手动粘贴'}
                </button>
              ))}
            </div>
            {activeTab === 'file' && (
              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 12 }}>
                <div onDragOver={e => { e.preventDefault(); setDragOver(true) }} onDragLeave={() => setDragOver(false)}
                  onDrop={e => { e.preventDefault(); setDragOver(false); const f = e.dataTransfer.files?.[0]; if (f) handleFile(f) }}
                  onClick={() => fileInputRef.current?.click()}
                  style={{ border: `2px dashed ${dragOver ? 'var(--accent-blue)' : fileError ? 'var(--critical)' : 'var(--border)'}`, borderRadius: 8, padding: '40px 20px', textAlign: 'center', cursor: 'pointer', background: dragOver ? 'rgba(63,160,224,.06)' : 'var(--bg-secondary)', transition: 'border-color .15s, background .15s', flex: 1 }}>
                  <input ref={fileInputRef} type="file" accept=".json" style={{ display: 'none' }} onChange={e => { const f = e.target.files?.[0]; if (f) handleFile(f) }} />
                  <div style={{ fontSize: 28, marginBottom: 8, opacity: .7 }}>📂</div>
                  {fileName ? <div style={{ fontSize: 13, color: 'var(--accent-blue)', fontWeight: 500 }}>{fileName}</div>
                    : <><div style={{ fontSize: 13, color: 'var(--text-secondary)', fontWeight: 500 }}>拖拽文件到此处，或点击选择文件</div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>仅支持 .json 文件</div></>}
                </div>
                {fileError && <div style={{ fontSize: 11, color: 'var(--critical)', padding: '8px 12px', background: 'rgba(239,68,68,.07)', borderRadius: 5, border: '1px solid rgba(239,68,68,.2)' }}>{fileError}</div>}
                {filePreview && <div style={{ fontSize: 11.5, color: 'var(--accent-green)' }}>✓ 解析成功，共 <strong>{filePreview.length}</strong> 条规则</div>}
              </div>
            )}
            {activeTab === 'paste' && (
              <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 10 }}>
                <textarea className="filter-input" style={{ flex: 1, minHeight: 200, fontFamily: 'Consolas,monospace', fontSize: 11, resize: 'vertical' }}
                  placeholder={'[\n  {"name":"My Rule","rule_id":"my-rule-001",...}\n]'}
                  value={jsonText} onChange={e => { setJsonText(e.target.value); setPasteError(''); setPasteValidMsg(''); setPastePreview(null) }} />
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  <button className="btn-secondary" style={{ fontSize: 12, padding: '4px 14px' }} onClick={validatePaste}>验证 JSON</button>
                  {pasteValidMsg && <span style={{ fontSize: 11.5, color: 'var(--accent-green)' }}>✓ {pasteValidMsg}</span>}
                  {pasteError && <span style={{ fontSize: 11, color: 'var(--critical)' }}>{pasteError}</span>}
                </div>
              </div>
            )}
            <div style={{ display: 'flex', gap: 10, marginTop: 16, flexShrink: 0 }}>
              <button className="btn-secondary" style={{ flex: 1 }} onClick={onClose}>取消</button>
              <button className="btn-primary" style={{ flex: 1 }} disabled={!activePreview} onClick={() => { if (activePreview) doImport(activePreview) }}>
                导入 {activePreview ? `(${(activePreview as ETLRule[]).length} 条)` : ''}
              </button>
            </div>
          </>
        ) : (
          <>
            <div style={{ fontSize: 11.5, color: 'var(--text-secondary)', marginBottom: 8, flexShrink: 0 }}>共 <strong>{activePreview.length}</strong> 条规则待导入</div>
            <div style={{ flex: 1, overflowY: 'auto', marginBottom: 14 }}>
              <table className="data-table">
                <thead><tr><ResizableTh>规则名称</ResizableTh><ResizableTh>规则 ID</ResizableTh><ResizableTh style={{ width: 70 }}>优先级</ResizableTh><ResizableTh style={{ width: 60 }}>状态</ResizableTh></tr></thead>
                <tbody>
                  {activePreview.slice(0, 3).map((r, i) => (
                    <tr key={i}>
                      <td style={{ fontSize: 12 }}>{r.name}</td>
                      <td style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--accent-blue)' }}>{r.rule_id}</td>
                      <td style={{ textAlign: 'center' }}>{r.priority ?? 50}</td>
                      <td><span style={{ fontSize: 10, padding: '1px 6px', borderRadius: 3, fontWeight: 600, background: r.is_enabled !== false ? 'rgba(34,197,94,.12)' : 'rgba(120,120,140,.12)', color: r.is_enabled !== false ? 'var(--accent-green)' : 'var(--text-muted)' }}>{r.is_enabled !== false ? '启用' : '禁用'}</span></td>
                    </tr>
                  ))}
                  {activePreview.length > 3 && <tr><td colSpan={4} style={{ textAlign: 'center', fontSize: 11, color: 'var(--text-muted)', padding: '6px 0' }}>… 及另外 {activePreview.length - 3} 条</td></tr>}
                </tbody>
              </table>
            </div>
            <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexShrink: 0 }}>
              {progress ? <span style={{ fontSize: 11, color: 'var(--accent-blue)', flex: 1 }}>导入中 {progress}…</span> : <span style={{ flex: 1 }} />}
              <button className="btn-secondary" onClick={() => { setFilePreview(null); setPastePreview(null) }} disabled={!!progress}>← 返回</button>
              <button className="btn-primary" onClick={() => doImport(activePreview)} disabled={!!progress}>{progress ? `导入中 ${progress}` : '确认导入'}</button>
            </div>
          </>
        )}
      </div>
    </>
  )
}

// ─── Tab 2: Rules Management ───────────────────────────────────────────────────

function RulesTab({
  items, loading, selected, setSelected,
  enabledFilter, setEnabledFilter,
  openEdit,
  toggleEnabled, adjustPriority, setDeleteTarget, setTestModalRule,
  stats,
}: {
  items: ETLRule[]; loading: boolean; selected: ETLRule | null; setSelected: (r: ETLRule | null) => void
  enabledFilter: string; setEnabledFilter: (v: string) => void
  openEdit: (r: ETLRule) => void
  toggleEnabled: (r: ETLRule) => void; adjustPriority: (r: ETLRule, d: number) => void
  setDeleteTarget: (r: ETLRule) => void; setTestModalRule: (r: ETLRule) => void
  stats: ETLStats | null
}) {
  const sortedItems = [...items].sort((a, b) => a.priority - b.priority)

  // PieChart data
  const indexCounts: Record<string, number> = {}
  for (const r of items) {
    const sinks = effectiveSinks(r)
    const key = sinks[0]?.ngx_index || sinks[0]?.arango_collection || '(未配置)'
    indexCounts[key] = (indexCounts[key] ?? 0) + 1
  }
  const INDEX_COLORS = ['var(--accent-blue)', 'var(--accent-green)', 'var(--medium)', 'var(--critical)', '#14b8a6', 'rgba(167,139,250,.9)']
  const pieData = Object.entries(indexCounts).map(([name, value], i) => ({ name, value, color: INDEX_COLORS[i % INDEX_COLORS.length] }))

  const statsTotal    = stats?.total    ?? items.length
  const statsEnabled  = stats?.enabled  ?? items.filter(r => r.is_enabled).length
  const statsDisabled = stats?.disabled ?? (statsTotal - statsEnabled)

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

      {/* ── Stats + Pie row ── */}
      <div style={{ padding: '12px 20px', borderBottom: '1px solid var(--border)', background: 'var(--bg-card)', flexShrink: 0, display: 'flex', alignItems: 'center', gap: 16, flexWrap: 'wrap' }}>
        {[
          { label: '总规则数', value: statsTotal,    color: 'var(--accent-blue)' },
          { label: '启用',     value: statsEnabled,  color: 'var(--accent-green)' },
          { label: '禁用',     value: statsDisabled, color: 'var(--high)' },
        ].map(tile => (
          <div key={tile.label} style={{ padding: '8px 14px 8px 12px', borderRadius: 6, background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderLeft: `3px solid ${tile.color}`, minWidth: 90 }}>
            <div style={{ fontSize: 22, fontWeight: 700, fontFamily: 'monospace', color: 'var(--text-primary)', lineHeight: 1.2 }}>{typeof tile.value === 'number' ? tile.value : tile.value}</div>
            <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginTop: 3 }}>{tile.label}</div>
          </div>
        ))}
        <div style={{ flex: 1 }} />
        {pieData.length > 0 && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>输出分布</div>
            <PieChart width={100} height={100}>
              <Pie data={pieData} cx={45} cy={45} innerRadius={25} outerRadius={44} paddingAngle={2} dataKey="value">
                {pieData.map((entry, index) => <Cell key={index} fill={entry.color} />)}
              </Pie>
              <Tooltip contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 4, fontSize: 11 }}
                formatter={((v: unknown, n: unknown) => [Number(v ?? 0), n]) as any} />
            </PieChart>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 3, maxWidth: 160 }}>
              {pieData.slice(0, 5).map(d => (
                <div key={d.name} style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 10.5 }}>
                  <div style={{ width: 8, height: 8, borderRadius: 2, background: d.color, flexShrink: 0 }} />
                  <span style={{ color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', maxWidth: 100 }} title={d.name}>{d.name}</span>
                  <span style={{ color: 'var(--text-muted)', fontFamily: 'monospace', marginLeft: 'auto', flexShrink: 0 }}>{d.value}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {/* ── Filter bar ── */}
      <div className="tab-bar" style={{ borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
        {[['全部', ''], ['已启用', 'true'], ['已禁用', 'false']].map(([label, val]) => (
          <button key={label} className={`tab ${enabledFilter === val ? 'active' : ''}`} onClick={() => setEnabledFilter(val)}>{label}</button>
        ))}
      </div>

      {/* ── Table + Detail panel ── */}
      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        <div className="data-table-wrap" style={{ flex: 1 }}>
          <table className="data-table">
            <thead>
              <tr>
                <ResizableTh style={{ width: 80 }}>优先级</ResizableTh>
                <ResizableTh>规则名称</ResizableTh>
                <ResizableTh>匹配条件</ResizableTh>
                <ResizableTh>写入模式</ResizableTh>
                <ResizableTh>输出 Sinks</ResizableTh>
                <ResizableTh>动作</ResizableTh>
                <ResizableTh style={{ width: 80 }}>状态</ResizableTh>
                <ResizableTh></ResizableTh>
              </tr>
            </thead>
            <tbody>
              {loading && <tr><td colSpan={8} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>加载中...</td></tr>}
              {!loading && sortedItems.length === 0 && <tr><td colSpan={8} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>暂无 ETL 规则</td></tr>}
              {sortedItems.map(rule => {
                const sinks = effectiveSinks(rule)
                return (
                  <tr key={rule._key} onClick={() => setSelected(selected?._key === rule._key ? null : rule)}
                    className={selected?._key === rule._key ? 'selected' : ''} style={{ opacity: rule.is_enabled ? 1 : 0.5 }}>
                    <td onClick={e => e.stopPropagation()}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 3 }}>
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 1 }}>
                          {[[-10, '↑', '提高优先级'], [+10, '↓', '降低优先级']].map(([delta, arrow, title]) => (
                            <button key={String(arrow)} title={String(title)} onClick={() => adjustPriority(rule, delta as number)}
                              style={{ width: 16, height: 14, padding: 0, fontSize: 9, lineHeight: 1, background: 'rgba(255,255,255,.06)', border: '1px solid var(--border-light)', borderRadius: 2, color: 'var(--text-muted)', cursor: 'pointer', display: 'flex', alignItems: 'center', justifyContent: 'center' }}
                              onMouseEnter={e => (e.currentTarget.style.background = 'rgba(63,160,224,.2)')}
                              onMouseLeave={e => (e.currentTarget.style.background = 'rgba(255,255,255,.06)')}>
                              {arrow}
                            </button>
                          ))}
                        </div>
                        <span style={{ fontSize: 12, fontWeight: 700, fontFamily: 'monospace', color: 'var(--accent-blue)' }}>{rule.priority}</span>
                        {rule.processing_mode === 'sequential' && (
                          <span style={{ fontSize: 8, padding: '0px 3px', borderRadius: 2, background: 'rgba(167,139,250,.15)', color: 'rgba(167,139,250,.9)', border: '1px solid rgba(167,139,250,.3)' }}>序号</span>
                        )}
                      </div>
                    </td>
                    <td>
                      <div style={{ fontSize: 12.5, fontWeight: 500 }}>{rule.name}</div>
                      <div style={{ fontSize: 10.5, color: 'var(--text-muted)', fontFamily: 'monospace' }}>{rule.rule_id}</div>
                      {rule.description && <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 1 }}>{rule.description.slice(0, 55)}{rule.description.length > 55 ? '…' : ''}</div>}
                    </td>
                    <td>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
                        {rule.match?.tag_pattern && <Tag color="blue">tag:{rule.match.tag_pattern}</Tag>}
                        {(rule.match?.dataset ?? []).map(d => <Tag key={d} color="purple">ds:{d}</Tag>)}
                        {rule.match?.kind != null && <Tag color="orange">kind:{KIND_NAMES[rule.match.kind] ?? rule.match.kind}</Tag>}
                        {rule.match?.filter_expr && <Tag color="gray">filter{rule.match.filter_mode === 'or' ? ':OR' : ''}</Tag>}
                      </div>
                    </td>
                    <td>
                      <span style={{ fontSize: 10.5, padding: '2px 7px', borderRadius: 3, fontWeight: 600, background: `${rawModeColor(rule.raw_write_mode)}22`, color: rawModeColor(rule.raw_write_mode), border: `1px solid ${rawModeColor(rule.raw_write_mode)}44` }}>
                        {rawModeLabel(rule.raw_write_mode)}
                      </span>
                    </td>
                    <td>
                      {sinks.length === 0 ? <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>—</span> : (
                        <div style={{ display: 'flex', flexDirection: 'column', gap: 2 }}>
                          {sinks.slice(0, 2).map((s, i) => (
                            <div key={i} style={{ display: 'flex', gap: 4, flexWrap: 'wrap' }}>
                              {s.ngx_index && <span style={{ fontSize: 10.5, fontFamily: 'monospace', color: 'var(--accent-blue)' }}>ngx:{s.ngx_index}</span>}
                              {s.arango_collection && <span style={{ fontSize: 10.5, fontFamily: 'monospace', color: '#14b8a6' }}>db:{s.arango_collection}</span>}
                              {s.ttl_days && <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>{s.ttl_days}d</span>}
                            </div>
                          ))}
                          {sinks.length > 2 && <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>+{sinks.length - 2} 更多</span>}
                        </div>
                      )}
                    </td>
                    <td>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
                        {(rule.actions ?? []).slice(0, 3).map((a, i) => <Tag key={i} color={a.type === 'drop_event' ? 'red' : a.type === 'custom_lua' ? 'purple' : 'gray'}>{a.type}</Tag>)}
                        {(rule.actions ?? []).length > 3 && <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>+{rule.actions.length - 3}</span>}
                        {(rule.actions ?? []).length === 0 && <span style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>—</span>}
                      </div>
                    </td>
                    <td onClick={e => e.stopPropagation()}>
                      <label style={{ display: 'flex', alignItems: 'center', gap: 6, cursor: 'pointer' }}>
                        <div onClick={() => toggleEnabled(rule)} style={{ width: 30, height: 16, borderRadius: 8, position: 'relative', background: rule.is_enabled ? 'var(--accent-green)' : 'rgba(120,120,140,.3)', transition: 'background .2s', cursor: 'pointer', flexShrink: 0, boxShadow: rule.is_enabled ? '0 0 6px rgba(34,197,94,.4)' : 'none' }}>
                          <div style={{ position: 'absolute', top: 2, left: rule.is_enabled ? 16 : 2, width: 12, height: 12, borderRadius: '50%', background: 'white', transition: 'left .2s', boxShadow: '0 1px 3px rgba(0,0,0,.3)' }} />
                        </div>
                        <span style={{ fontSize: 10.5, color: rule.is_enabled ? 'var(--accent-green)' : 'var(--text-muted)' }}>{rule.is_enabled ? '启用' : '停用'}</span>
                      </label>
                    </td>
                    <td onClick={e => e.stopPropagation()}>
                      <div style={{ display: 'flex', gap: 3 }}>
                        <button className="btn-secondary" style={{ fontSize: 10.5, padding: '2px 7px' }} onClick={() => setTestModalRule(rule)}>测试</button>
                        <button className="btn-secondary" style={{ fontSize: 10.5, padding: '2px 7px' }} onClick={() => openEdit(rule)}>编辑</button>
                        <button className="btn-secondary" style={{ fontSize: 10.5, padding: '2px 7px', color: 'var(--critical)' }} onClick={() => setDeleteTarget(rule)}>删</button>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>

        {/* Right detail panel */}
        {selected && (
          <div className="slide-in-right" style={{ width: 420, borderLeft: '1px solid var(--border)', background: 'var(--bg-drawer)', display: 'flex', flexDirection: 'column', overflow: 'hidden', flexShrink: 0 }}>
            <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', background: 'var(--bg-card2)', display: 'flex', justifyContent: 'space-between', alignItems: 'center', flexShrink: 0 }}>
              <div>
                <div style={{ fontSize: 13, fontWeight: 600 }}>{selected.name}</div>
                <div style={{ fontSize: 10.5, color: 'var(--text-muted)', fontFamily: 'monospace', marginTop: 2 }}>{selected.rule_id}</div>
              </div>
              <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px' }} onClick={() => setSelected(null)}>✕</button>
            </div>
            <div style={{ flex: 1, overflowY: 'auto', padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div className="card">
                <div className="card-title">规则信息</div>
                {[
                  ['优先级', String(selected.priority)],
                  ['执行模式', selected.processing_mode === 'sequential' ? '顺序 (sequential)' : '首匹配 (first_match)'],
                  ['写入模式', rawModeLabel(selected.raw_write_mode)],
                  ['创建时间', fmtDate(selected.created_at)],
                  ['更新时间', fmtDate(selected.updated_at)],
                ].map(([k, v]) => (
                  <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11.5, borderBottom: '1px solid rgba(255,255,255,.04)', paddingBottom: 4, marginBottom: 4 }}>
                    <span style={{ color: 'var(--text-muted)' }}>{k}</span>
                    <span style={{ color: 'var(--text-secondary)', fontFamily: 'monospace' }}>{v}</span>
                  </div>
                ))}
              </div>
              <div className="card">
                <div className="card-title">匹配条件</div>
                <pre style={{ background: 'var(--bg-secondary)', borderRadius: 4, padding: 10, margin: 0, fontSize: 11, color: 'var(--accent-blue)', fontFamily: 'Consolas,monospace', overflow: 'auto', whiteSpace: 'pre-wrap' }}>
                  {JSON.stringify(selected.match, null, 2)}
                </pre>
              </div>
              <div className="card">
                <div className="card-title">输出 Sinks ({effectiveSinks(selected).length})</div>
                {effectiveSinks(selected).length === 0 ? <div style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>无 Sink（仅写 raw_*）</div> : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                    {effectiveSinks(selected).map((s, i) => (
                      <div key={i} style={{ padding: '6px 8px', background: 'var(--bg-secondary)', borderRadius: 4, fontSize: 11 }}>
                        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                          {s.ngx_index && <span><span style={{ color: 'var(--text-muted)' }}>ngx: </span><span style={{ fontFamily: 'monospace', color: 'var(--accent-blue)' }}>{s.ngx_index}</span></span>}
                          {s.arango_collection && <span><span style={{ color: 'var(--text-muted)' }}>db: </span><span style={{ fontFamily: 'monospace', color: '#14b8a6' }}>{s.arango_collection}</span></span>}
                          {s.ttl_days && <span style={{ color: 'var(--text-muted)' }}>TTL: {s.ttl_days}d</span>}
                        </div>
                        {s.condition && <div style={{ marginTop: 3, fontSize: 10.5, color: 'var(--text-muted)', fontFamily: 'monospace' }}>条件: {s.condition}</div>}
                      </div>
                    ))}
                  </div>
                )}
              </div>
              <div className="card">
                <div className="card-title">动作列表 ({(selected.actions ?? []).length})</div>
                {(selected.actions ?? []).length === 0 ? <div style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>无动作（原始直通）</div> : (
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
                    {selected.actions.map((a, i) => (
                      <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 8, fontSize: 11.5, padding: '5px 8px', background: 'var(--bg-secondary)', borderRadius: 4 }}>
                        <Tag color={a.type === 'drop_event' ? 'red' : a.type === 'custom_lua' ? 'purple' : 'blue'}>{a.type}</Tag>
                        {a.params && Object.keys(a.params).length > 0 && a.type !== 'custom_lua' && (
                          <span style={{ color: 'var(--text-muted)', fontFamily: 'monospace', fontSize: 11 }}>{Object.entries(a.params).map(([k, v]) => `${k}=${v}`).join(', ')}</span>
                        )}
                        {a.type === 'custom_lua' && <span style={{ color: 'rgba(167,139,250,.7)', fontSize: 10.5, fontStyle: 'italic' }}>Lua 脚本</span>}
                      </div>
                    ))}
                  </div>
                )}
              </div>
              <button className="btn-secondary" style={{ fontSize: 12 }} onClick={() => setTestModalRule(selected)}>▶ 打开测试面板</button>
            </div>
          </div>
        )}
      </div>

    </div>
  )
}

// ─── Edit/Create Modal ─────────────────────────────────────────────────────────

function RuleModal({ editTarget, form, setField, formErrors, setFormErrors, jsonError, saving, showLuaHint, setShowLuaHint, insertLuaTemplate, validateJson, saveRule, onClose }: {
  editTarget: ETLRule | null; form: FormState; setField: <K extends keyof FormState>(k: K, v: FormState[K]) => void
  formErrors: FormErrors; setFormErrors: React.Dispatch<React.SetStateAction<FormErrors>>
  jsonError: string; saving: boolean; showLuaHint: boolean
  setShowLuaHint: (v: boolean) => void; insertLuaTemplate: () => void
  validateJson: (v: string) => boolean; saveRule: () => void; onClose: () => void
}) {
  return (
    <>
      <div onClick={onClose} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
      <div style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: 700, background: 'var(--bg-modal)', border: '1px solid var(--border)', borderRadius: 10, zIndex: 500, padding: 28, maxHeight: '92vh', overflowY: 'auto' }}>
        <div style={{ fontSize: 16, fontWeight: 700, marginBottom: 20, display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ fontSize: 18 }}>{editTarget ? '✏️' : '✨'}</span>
          {editTarget ? '编辑 ETL 规则' : '新建 ETL 规则'}
        </div>

        <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

          {/* Rule ID + Name */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Rule ID *</div>
              <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box', fontFamily: 'monospace', borderColor: formErrors.rule_id ? 'var(--critical)' : undefined }}
                placeholder="win-process-enrich-001" value={form.rule_id}
                onChange={e => setField('rule_id', e.target.value)} />
              {formErrors.rule_id && <div style={{ fontSize: 10.5, color: 'var(--critical)', marginTop: 3 }}>{formErrors.rule_id}</div>}
            </div>
            <div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>规则名称 *</div>
              <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }}
                placeholder="Windows Process Enrichment" value={form.name}
                onChange={e => setField('name', e.target.value)} />
            </div>
          </div>

          {/* Priority + ProcessingMode + WriteMode + Status */}
          <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr 1fr', gap: 10 }}>
            {[
              {
                label: '优先级 (低=先)', content: (
                  <>
                    <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box', fontFamily: 'monospace', borderColor: formErrors.priority ? 'var(--critical)' : undefined }}
                      type="number" min="1" max="9999" value={form.priority}
                      onChange={e => setField('priority', e.target.value)} />
                    {formErrors.priority && <div style={{ fontSize: 10.5, color: 'var(--critical)', marginTop: 3 }}>{formErrors.priority}</div>}
                  </>
                )
              },
              {
                label: '执行模式', content: (
                  <select className="filter-select" style={{ width: '100%' }} value={form.processing_mode}
                    onChange={e => setField('processing_mode', e.target.value as 'first_match' | 'sequential')}>
                    <option value="first_match">首匹配</option>
                    <option value="sequential">顺序</option>
                  </select>
                )
              },
              {
                label: '写入模式', content: (
                  <select className="filter-select" style={{ width: '100%' }} value={form.raw_write_mode}
                    onChange={e => setField('raw_write_mode', e.target.value as 'both' | 'etl_only' | 'raw_only')}>
                    <option value="both">双写</option>
                    <option value="etl_only">仅 ETL</option>
                    <option value="raw_only">仅原始</option>
                  </select>
                )
              },
              {
                label: '状态', content: (
                  <select className="filter-select" style={{ width: '100%' }} value={form.is_enabled ? 'true' : 'false'}
                    onChange={e => setField('is_enabled', e.target.value === 'true')}>
                    <option value="true">启用</option>
                    <option value="false">禁用</option>
                  </select>
                )
              },
            ].map(({ label, content }) => (
              <div key={label}>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>{label}</div>
                {content}
              </div>
            ))}
          </div>

          {/* Description */}
          <div>
            <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>描述</div>
            <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }}
              placeholder="规则用途简述" value={form.description}
              onChange={e => setField('description', e.target.value)} />
          </div>

          {/* Match */}
          <div style={{ border: `1px solid ${formErrors.match ? 'var(--critical)' : 'var(--border)'}`, borderRadius: 8, padding: '12px 14px' }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-secondary)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '.06em' }}>匹配条件</div>
            {formErrors.match && <div style={{ fontSize: 10.5, color: 'var(--critical)', marginBottom: 8 }}>{formErrors.match}</div>}
            <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 10 }}>
              <div>
                <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginBottom: 3 }}>Tag Pattern (glob)</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box', fontFamily: 'monospace', fontSize: 11.5 }}
                  placeholder="winevent.*" value={form.tag_pattern}
                  onChange={e => { setField('tag_pattern', e.target.value); setFormErrors(p => ({ ...p, match: undefined })) }} />
              </div>
              <div>
                <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginBottom: 3 }}>Dataset (逗号分隔)</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box', fontFamily: 'monospace', fontSize: 11.5 }}
                  placeholder="syslog_raw" value={form.dataset}
                  onChange={e => { setField('dataset', e.target.value); setFormErrors(p => ({ ...p, match: undefined })) }} />
              </div>
              <div>
                <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginBottom: 3 }}>类型</div>
                <select className="filter-select" style={{ width: '100%', fontSize: 11.5 }} value={form.kind}
                  onChange={e => { setField('kind', e.target.value); setFormErrors(p => ({ ...p, match: undefined })) }}>
                  <option value="">（不限）</option>
                  {Object.entries(KIND_NAMES).map(([k, v]) => <option key={k} value={k}>{k} — {v}</option>)}
                </select>
              </div>
              <div>
                <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginBottom: 3 }}>
                  Filter Expr <span style={{ opacity: .5 }}>— = != ~= &gt; &lt; &gt;= &lt;=</span>
                </div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box', fontFamily: 'monospace', fontSize: 11.5 }}
                  placeholder='severity~=high|critical' value={form.filter_expr}
                  onChange={e => { setField('filter_expr', e.target.value); setFormErrors(p => ({ ...p, match: undefined })) }} />
              </div>
            </div>
            <div style={{ marginTop: 10, display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>多条件逻辑：</span>
              {(['and', 'or'] as const).map(mode => (
                <button key={mode} onClick={() => setField('filter_mode', mode)} style={{
                  fontSize: 10.5, padding: '2px 10px', borderRadius: 3, cursor: 'pointer', fontWeight: 700,
                  background: form.filter_mode === mode ? 'rgba(63,160,224,.2)' : 'var(--bg-secondary)',
                  color: form.filter_mode === mode ? 'var(--accent-blue)' : 'var(--text-muted)',
                  border: `1px solid ${form.filter_mode === mode ? 'rgba(63,160,224,.4)' : 'var(--border)'}`,
                }}>{mode.toUpperCase()}</button>
              ))}
              <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
                {form.filter_mode === 'or' ? '任一满足即匹配' : '所有条件都满足才匹配'}
              </span>
            </div>
          </div>

          {/* Sinks */}
          <div style={{ border: '1px solid var(--border)', borderRadius: 8, padding: '12px 14px' }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-secondary)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: '.06em', display: 'flex', alignItems: 'center', gap: 8 }}>
              输出 Sinks
              <span style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'none', letterSpacing: 0, fontWeight: 400 }}>每个 Sink 可独立指定目标和过滤条件</span>
            </div>
            <SinksEditor sinks={form.sinks} onChange={sinks => setField('sinks', sinks)} />
          </div>

          {/* Actions JSON */}
          <div>
            <div style={{ display: 'flex', alignItems: 'baseline', justifyContent: 'space-between', marginBottom: 4 }}>
              <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>动作列表 (JSON)</div>
              <button style={{ fontSize: 9.5, color: 'rgba(167,139,250,.85)', background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}
                onClick={() => setShowLuaHint(!showLuaHint)}>+ Lua 脚本</button>
            </div>
            {showLuaHint && (
              <div style={{ fontSize: 10.5, padding: '8px 10px', background: 'rgba(167,139,250,.07)', border: '1px solid rgba(167,139,250,.25)', borderRadius: 4, marginBottom: 6, display: 'flex', alignItems: 'center', gap: 10 }}>
                <span style={{ color: 'rgba(167,139,250,.9)', flex: 1 }}>
                  插入 <code style={{ fontFamily: 'monospace' }}>custom_lua</code> 模板（签名：<code style={{ fontFamily: 'monospace' }}>process(tag, ts_ms, record) → code, record</code>）
                </span>
                <button className="btn-primary" style={{ fontSize: 10.5, padding: '3px 10px', flexShrink: 0 }} onClick={insertLuaTemplate}>插入</button>
                <button onClick={() => setShowLuaHint(false)} style={{ fontSize: 10, color: 'var(--text-muted)', background: 'none', border: 'none', cursor: 'pointer', padding: 0 }}>✕</button>
              </div>
            )}
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 4, lineHeight: 1.5 }}>
              可用类型: {ACTION_TYPES.join(', ')}
            </div>
            <textarea className="filter-input"
              style={{ width: '100%', boxSizing: 'border-box', minHeight: 140, fontFamily: 'Consolas,monospace', fontSize: 11.5, resize: 'vertical', color: jsonError ? 'var(--critical)' : undefined }}
              value={form.actions_json}
              onChange={e => { setField('actions_json', e.target.value) }}
              onBlur={e => validateJson(e.target.value)} />
            {jsonError && <div style={{ fontSize: 10.5, color: 'var(--critical)', marginTop: 3 }}>{jsonError}</div>}
          </div>

          <div style={{ display: 'flex', gap: 10, marginTop: 4 }}>
            <button className="btn-secondary" style={{ flex: 1 }} onClick={onClose}>取消</button>
            <button className="btn-primary" style={{ flex: 1 }} disabled={saving || !form.name.trim() || !form.rule_id.trim()} onClick={saveRule}>
              {saving ? '保存中...' : editTarget ? '保存修改' : '创建规则'}
            </button>
          </div>
        </div>
      </div>
    </>
  )
}

// ─── Main Component ────────────────────────────────────────────────────────────

export default function ETLPipeline() {
  const [activeTab, setActiveTab] = useState<'pipeline' | 'rules'>('pipeline')

  const [items, setItems] = useState<ETLRule[]>([])
  const [meta, setMeta] = useState<PageMeta>({ page: 1, page_size: 50, total: 0, total_pages: 1 })
  const [loading, setLoading] = useState(false)
  const [enabledFilter, setEnabledFilter] = useState('')
  const [selected, setSelected] = useState<ETLRule | null>(null)

  const [showModal, setShowModal] = useState(false)
  const [editTarget, setEditTarget] = useState<ETLRule | null>(null)
  const [form, setForm] = useState<FormState>(BLANK_FORM)
  const [saving, setSaving] = useState(false)
  const [jsonError, setJsonError] = useState('')
  const [formErrors, setFormErrors] = useState<FormErrors>({})
  const [showLuaHint, setShowLuaHint] = useState(false)

  const [deleteTarget, setDeleteTarget] = useState<ETLRule | null>(null)
  const [testModalRule, setTestModalRule] = useState<ETLRule | null>(null)
  const [showImportModal, setShowImportModal] = useState(false)
  const [toast, setToast] = useState('')
  const [apiStats, setApiStats] = useState<ETLStats | null>(null)

  const mountedRef = useRef(false)

  function loadStats() {
    api.get('/etl/rules/stats').then(r => {
      const d = r.data.data
      if (d && typeof d.total === 'number') setApiStats({ total: d.total, enabled: d.enabled ?? 0, disabled: d.disabled ?? 0 })
    }).catch(() => { /* silent */ })
  }

  function load() {
    setLoading(true)
    const params: Record<string, string> = { page_size: '50' }
    if (enabledFilter === 'true') params.enabled = 'true'
    if (enabledFilter === 'false') params.enabled = 'false'
    api.get('/etl/rules', { params })
      .then(r => { setItems(r.data.data?.items ?? []); setMeta(r.data.data?.meta ?? meta) })
      .finally(() => setLoading(false))
  }

  useEffect(() => { load(); loadStats() }, [])
  useEffect(() => { if (!mountedRef.current) { mountedRef.current = true; return }; load() }, [enabledFilter])

  function openCreate() { setEditTarget(null); setForm(BLANK_FORM); setJsonError(''); setFormErrors({}); setShowLuaHint(false); setShowModal(true) }
  function openEdit(rule: ETLRule) { setEditTarget(rule); setForm(ruleToForm(rule)); setJsonError(''); setFormErrors({}); setShowLuaHint(false); setShowModal(true) }

  function setField<K extends keyof FormState>(k: K, v: FormState[K]) {
    setForm(p => ({ ...p, [k]: v }))
    if (k === 'rule_id' || k === 'priority') setFormErrors(prev => ({ ...prev, [k]: undefined }))
  }

  function validateJson(val: string) {
    try { JSON.parse(val); setJsonError(''); return true }
    catch (e: unknown) { setJsonError('Actions JSON 语法错误: ' + (e instanceof Error ? e.message : String(e))); return false }
  }

  function validateForm(): boolean {
    const errors: FormErrors = {}
    const ruleId = form.rule_id.trim()
    if (ruleId.length < 2 || !RULE_ID_RE.test(ruleId)) errors.rule_id = 'Rule ID 只能包含小写字母、数字和连字符（首尾不能为连字符）'
    const prio = parseInt(form.priority, 10)
    if (!form.priority.trim() || isNaN(prio) || prio < 1 || prio > 9999 || String(prio) !== form.priority.trim()) errors.priority = '优先级必须为整数 1-9999'
    const hasMatch = form.tag_pattern.trim() || form.dataset.trim() || form.filter_expr.trim() || form.kind.trim()
    if (!hasMatch) errors.match = '至少填写一个匹配条件（Tag Pattern / Dataset / Filter Expr / Kind）'
    setFormErrors(errors)
    return Object.keys(errors).length === 0
  }

  function saveRule() {
    if (!form.name.trim() || !form.rule_id.trim()) return
    if (!validateForm()) return
    if (!validateJson(form.actions_json)) return
    setSaving(true)
    const body = formToBody(form)
    const req = editTarget ? api.patch(`/etl/rules/${editTarget._key}`, body) : api.post('/etl/rules', body)
    req.then(() => { setShowModal(false); load(); loadStats() }).finally(() => setSaving(false))
  }

  function toggleEnabled(rule: ETLRule) { api.patch(`/etl/rules/${rule._key}`, { is_enabled: !rule.is_enabled }).then(() => load()) }
  function adjustPriority(rule: ETLRule, delta: number) { api.patch(`/etl/rules/${rule._key}`, { priority: rule.priority + delta }).then(() => load()) }
  function doDelete() {
    if (!deleteTarget) return
    api.delete(`/etl/rules/${deleteTarget._key}`).then(() => {
      setDeleteTarget(null)
      if (selected?._key === deleteTarget._key) setSelected(null)
      load(); loadStats()
    })
  }

  function insertLuaTemplate() {
    const luaAction = { type: 'custom_lua', params: { script: 'function process(tag, timestamp_ms, record)\n  record["processed"] = "true"\n  return 1, record\nend' } }
    let actions: ETLAction[] = []
    try { actions = JSON.parse(form.actions_json) } catch { /* ok */ }
    actions.push(luaAction)
    setField('actions_json', JSON.stringify(actions, null, 2))
    setShowLuaHint(false)
  }

  // ── Tab switcher styles ──
  const tabStyle = (active: boolean): React.CSSProperties => ({
    padding: '0 20px', height: '100%', display: 'flex', alignItems: 'center', gap: 7,
    fontSize: 13, fontWeight: 600, cursor: 'pointer', background: 'none', border: 'none',
    borderBottom: active ? '2px solid var(--accent-blue)' : '2px solid transparent',
    color: active ? 'var(--accent-blue)' : 'var(--text-muted)',
    transition: 'color .15s, border-color .15s',
  })

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      {/* ── Top bar: PageHeader + Tabs + Actions ── */}
      <div style={{ display: 'flex', alignItems: 'center', borderBottom: '1px solid var(--border)', background: 'var(--bg-card)', flexShrink: 0, height: 50, paddingLeft: 16 }}>
        {/* Tab buttons */}
        <button style={tabStyle(activeTab === 'pipeline')} onClick={() => setActiveTab('pipeline')}>
          <span style={{ fontSize: 15 }}>⚡</span> ETL 流水线
        </button>
        <button style={tabStyle(activeTab === 'rules')} onClick={() => setActiveTab('rules')}>
          <span style={{ fontSize: 15 }}>📋</span> 规则管理
          {apiStats && apiStats.total > 0 && (
            <span style={{ fontSize: 10, padding: '1px 5px', borderRadius: 10, background: 'var(--accent-blue)', color: '#fff', fontWeight: 700, marginLeft: 2 }}>
              {apiStats.total}
            </span>
          )}
        </button>

        <div style={{ flex: 1 }} />

        {/* Action buttons — always visible */}
        <div style={{ display: 'flex', gap: 8, paddingRight: 16 }}>
          <button className="btn-secondary" style={{ fontSize: 11 }} onClick={() => window.open('/api/etl/rules/export', '_blank')}>导出规则</button>
          <button className="btn-secondary" style={{ fontSize: 11 }} onClick={() => setShowImportModal(true)}>导入规则</button>
          <button className="btn-primary" style={{ fontSize: 12 }} onClick={openCreate}>+ 新建规则</button>
        </div>
      </div>

      {/* ── Tab content ── */}
      {activeTab === 'pipeline' && <PipelineTab stats={apiStats} />}
      {activeTab === 'rules' && (
        <RulesTab
          items={items} loading={loading} selected={selected} setSelected={setSelected}
          enabledFilter={enabledFilter} setEnabledFilter={setEnabledFilter}
          openEdit={openEdit}
          toggleEnabled={toggleEnabled} adjustPriority={adjustPriority}
          setDeleteTarget={setDeleteTarget} setTestModalRule={setTestModalRule}
          stats={apiStats}
        />
      )}

      {/* ── Modals ── */}
      {testModalRule && <TestModal rule={testModalRule} onClose={() => setTestModalRule(null)} />}
      {showImportModal && <ImportModal onClose={() => setShowImportModal(false)} onImported={() => { load(); loadStats() }} showToast={setToast} />}

      {showModal && (
        <RuleModal
          editTarget={editTarget} form={form} setField={setField}
          formErrors={formErrors} setFormErrors={setFormErrors}
          jsonError={jsonError} saving={saving}
          showLuaHint={showLuaHint} setShowLuaHint={setShowLuaHint}
          insertLuaTemplate={insertLuaTemplate}
          validateJson={validateJson} saveRule={saveRule}
          onClose={() => setShowModal(false)}
        />
      )}

      {deleteTarget && (
        <>
          <div onClick={() => setDeleteTarget(null)} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
          <div style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: 360, background: 'var(--bg-modal)', border: '1px solid var(--border)', borderRadius: 10, zIndex: 500, padding: 24 }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 12 }}>确认删除规则</div>
            <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 20 }}>
              确定要删除规则 <strong style={{ color: 'var(--text-primary)' }}>「{deleteTarget.name}」</strong>？
            </div>
            <div style={{ display: 'flex', gap: 10 }}>
              <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setDeleteTarget(null)}>取消</button>
              <button className="btn-primary" style={{ flex: 1, background: 'var(--critical)', borderColor: 'var(--critical)' }} onClick={doDelete}>确认删除</button>
            </div>
          </div>
        </>
      )}

      {toast && <Toast message={toast} onDone={() => setToast('')} />}
    </div>
  )
}
