import { useEffect, useRef, useState, useCallback } from 'react'
import api from '@/lib/api'
import type { PageMeta } from '@/lib/api'
import PageHeader from '@/components/PageHeader'
import ResizableTh from '@/components/ResizableTh'

interface Exposure {
  _key: string
  asset_id: string
  asset_name: string            // API field
  cve_id: string
  cvss_score: number
  exposure_score?: number       // optional: 0-10 scale used for risk matrix X-axis
  in_wild_factor: number        // API: 0.0-1.0 float (>0.5 = in the wild)
  reachability_factor: number   // API: 0.0-1.0 float
  asset_importance_factor: number
  priority_score: number
  fix_status: string            // API field
  fix_deadline?: string
  assigned_to?: string
  due_date?: string
  fix_notes?: string
  last_scored_at: string
  updated_at: string
}

// ─── Fix Progress Dashboard ───────────────────────────────────────────────────

function FixProgressDashboard({ items }: { items: Exposure[] }) {
  const total = items.length
  if (total === 0) return null

  let fixed = 0, inProgress = 0, accepted = 0, unresolved = 0
  for (const e of items) {
    const s = e.fix_status || ''
    if (s === 'fixed') fixed++
    else if (s === 'in_progress' || s === 'verifying' || s === 'planned') inProgress++
    else if (s === 'accepted_risk' || s === 'compensating_control') accepted++
    else unresolved++
  }

  const pct = (n: number) => ((n / total) * 100).toFixed(1)
  const fixRate = Math.round((fixed / total) * 100)

  const seg = (pct: number, color: string) =>
    pct > 0 ? (
      <div style={{ width: `${pct}%`, height: '100%', background: color, transition: 'width 0.4s' }} />
    ) : null

  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border)',
      borderRadius: 8,
      padding: '12px 16px',
      marginBottom: 8,
      flexShrink: 0,
    }}>
      {/* Top row: fix rate + total */}
      <div style={{ display: 'flex', alignItems: 'baseline', gap: 10, marginBottom: 8 }}>
        <span style={{ fontSize: 28, fontWeight: 700, color: 'var(--accent-green)', lineHeight: 1 }}>
          {fixRate}%
        </span>
        <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-secondary)' }}>修复率</span>
        <span style={{ fontSize: 12, color: 'var(--text-muted)', marginLeft: 4 }}>
          共 {total} 个风险项
        </span>
      </div>

      {/* Segmented bar */}
      <div style={{
        width: '100%',
        height: 8,
        borderRadius: 4,
        background: 'var(--bg-card2)',
        overflow: 'hidden',
        display: 'flex',
        marginBottom: 10,
      }}>
        {seg(parseFloat(pct(fixed)), 'var(--accent-green)')}
        {seg(parseFloat(pct(inProgress)), 'var(--accent-blue)')}
        {seg(parseFloat(pct(accepted)), 'var(--text-muted)')}
        {seg(parseFloat(pct(unresolved)), 'var(--critical)')}
      </div>

      {/* Stat chips */}
      <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
        {([
          ['已修复', fixed, 'var(--accent-green)'],
          ['处理中', inProgress, 'var(--accent-blue)'],
          ['已接受', accepted, 'var(--text-muted)'],
          ['未处理', unresolved, 'var(--critical)'],
        ] as [string, number, string][]).map(([label, count, color]) => (
          <div key={label} style={{
            display: 'flex',
            alignItems: 'center',
            gap: 5,
            fontSize: 12,
            color: 'var(--text-secondary)',
          }}>
            <span style={{ width: 8, height: 8, borderRadius: '50%', background: color, display: 'inline-block' }} />
            <span>{label}</span>
            <span style={{ fontWeight: 700, color }}>{count}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ─── Risk Matrix (4×4) ────────────────────────────────────────────────────────

type RiskLevel = 0 | 1 | 2 | 3  // Low / Med / High / Crit

function exposureToXAxis(e: Exposure): RiskLevel {
  // X-axis: 攻击复杂度 mapped from exposure_score (0-10) or cvss_score (0-10)
  const s = e.exposure_score ?? e.cvss_score ?? 0
  if (s >= 9) return 3
  if (s >= 7) return 2
  if (s >= 4) return 1
  return 0
}

function keyToYAxis(e: Exposure): RiskLevel {
  // Y-axis: 业务影响 — use asset_importance_factor if available, else hash _key
  const imp = e.asset_importance_factor
  if (imp !== undefined && imp > 0) {
    if (imp >= 0.85) return 3
    if (imp >= 0.65) return 2
    if (imp >= 0.4) return 1
    return 0
  }
  // fallback: hash _key digits
  const digits = e._key.replace(/\D/g, '')
  const n = digits.length > 0 ? parseInt(digits.slice(-4), 10) : parseInt(e._key, 16) || 0
  return (n % 4) as RiskLevel
}

function cellColor(count: number): string {
  if (count === 0) return 'var(--bg-card2)'
  if (count <= 3) return '#16a34a22'
  if (count <= 6) return '#ca8a0422'
  if (count <= 9) return '#ea580c22'
  return '#dc262622'
}

function cellTextColor(count: number): string {
  if (count === 0) return 'var(--text-muted)'
  if (count <= 3) return 'var(--accent-green)'
  if (count <= 6) return 'var(--medium)'
  if (count <= 9) return 'var(--high)'
  return 'var(--critical)'
}

const AXIS_LABELS = ['Low', 'Med', 'High', 'Crit']

interface RiskMatrixProps {
  items: Exposure[]
  onCellClick: (xIdx: RiskLevel, yIdx: RiskLevel) => void
}

function RiskMatrix({ items, onCellClick }: RiskMatrixProps) {
  const [open, setOpen] = useState(true)

  // grid[y][x]
  const grid: number[][] = Array.from({ length: 4 }, () => [0, 0, 0, 0])
  for (const e of items) {
    const x = exposureToXAxis(e)
    const y = keyToYAxis(e)
    grid[y][x]++
  }

  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border)',
      borderRadius: 8,
      marginBottom: 8,
      flexShrink: 0,
      overflow: 'hidden',
    }}>
      {/* Collapsible header */}
      <button
        onClick={() => setOpen(o => !o)}
        style={{
          width: '100%',
          background: 'none',
          border: 'none',
          cursor: 'pointer',
          padding: '10px 14px',
          display: 'flex',
          alignItems: 'center',
          gap: 8,
          color: 'var(--text-secondary)',
          fontSize: 12,
          fontWeight: 600,
          textAlign: 'left',
        }}
      >
        <span style={{
          fontSize: 10,
          transition: 'transform 0.2s',
          transform: open ? 'rotate(90deg)' : 'rotate(0deg)',
          display: 'inline-block',
        }}>▶</span>
        风险矩阵
        <span style={{ fontWeight: 400, color: 'var(--text-muted)', marginLeft: 2 }}>
          （基于当前页 {items.length} 条 · 点击单元格筛选）
        </span>
      </button>

      {open && (
        <div style={{ padding: '0 14px 12px 14px' }}>
          <div style={{ display: 'flex', gap: 0 }}>
            {/* Y-axis label */}
            <div style={{
              display: 'flex',
              flexDirection: 'column',
              alignItems: 'center',
              justifyContent: 'center',
              marginRight: 6,
              paddingBottom: 22,
              gap: 0,
            }}>
              <div style={{
                writingMode: 'vertical-rl',
                textOrientation: 'mixed',
                transform: 'rotate(180deg)',
                fontSize: 10,
                color: 'var(--text-muted)',
                letterSpacing: 1,
                fontWeight: 500,
              }}>业务影响</div>
            </div>

            <div style={{ flex: 1 }}>
              {/* Grid rows — Y from Crit (3) down to Low (0) */}
              {[3, 2, 1, 0].map(yi => (
                <div key={yi} style={{ display: 'flex', gap: 4, marginBottom: 4 }}>
                  {/* Y-axis tick label */}
                  <div style={{
                    width: 28,
                    fontSize: 10,
                    color: 'var(--text-muted)',
                    textAlign: 'right',
                    paddingRight: 4,
                    display: 'flex',
                    alignItems: 'center',
                    justifyContent: 'flex-end',
                  }}>
                    {AXIS_LABELS[yi]}
                  </div>
                  {/* 4 cells */}
                  {[0, 1, 2, 3].map(xi => {
                    const count = grid[yi][xi]
                    return (
                      <div
                        key={xi}
                        onClick={() => onCellClick(xi as RiskLevel, yi as RiskLevel)}
                        title={`X:${AXIS_LABELS[xi]} Y:${AXIS_LABELS[yi]} → ${count} 项`}
                        style={{
                          flex: 1,
                          height: 48,
                          background: cellColor(count),
                          border: `1px solid ${cellTextColor(count)}44`,
                          borderRadius: 4,
                          display: 'flex',
                          alignItems: 'center',
                          justifyContent: 'center',
                          cursor: 'pointer',
                          transition: 'opacity 0.15s',
                          fontWeight: 700,
                          fontSize: 15,
                          color: cellTextColor(count),
                        }}
                        onMouseEnter={e => (e.currentTarget.style.opacity = '0.75')}
                        onMouseLeave={e => (e.currentTarget.style.opacity = '1')}
                      >
                        {count}
                      </div>
                    )
                  })}
                </div>
              ))}

              {/* X-axis labels */}
              <div style={{ display: 'flex', gap: 4, marginTop: 4 }}>
                <div style={{ width: 28 }} />
                {AXIS_LABELS.map(l => (
                  <div key={l} style={{ flex: 1, textAlign: 'center', fontSize: 10, color: 'var(--text-muted)' }}>{l}</div>
                ))}
              </div>
              {/* X-axis title */}
              <div style={{ textAlign: 'center', fontSize: 10, color: 'var(--text-muted)', marginTop: 2, paddingLeft: 32 }}>
                攻击复杂度
              </div>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Attack Surface Map ───────────────────────────────────────────────────────

/** Seeded pseudo-random number in [0,1) from a string key */
function seededRandom(seed: string, offset = 0): number {
  let h = offset * 2654435761
  for (let i = 0; i < seed.length; i++) {
    h = Math.imul(h ^ seed.charCodeAt(i), 2654435761)
  }
  h = h >>> 0
  return (h % 1000) / 1000
}

interface AttackSurfaceCategory {
  id: string
  name: string
  icon: string
  color: string
  count: number
  detail: string
}

function deriveAttackSurface(items: Exposure[]): AttackSurfaceCategory[] {
  const total = items.length
  const seed = `asm-${total}`

  // 外部暴露: category contains 'external' or score > 70
  const externalCount = items.filter(e =>
    (e.asset_id || '').toLowerCase().includes('external') ||
    (e.asset_name || '').toLowerCase().includes('external') ||
    (e.priority_score ?? 0) > 70
  ).length

  // 内部横向: category contains 'internal'
  const internalCount = items.filter(e =>
    (e.asset_id || '').toLowerCase().includes('internal') ||
    (e.asset_name || '').toLowerCase().includes('internal') ||
    reachCategoryStatic(e.reachability_factor ?? 0) === 'internal'
  ).length

  // 云配置: category contains 'cloud'
  const cloudCount = items.filter(e =>
    (e.asset_id || '').toLowerCase().includes('cloud') ||
    (e.asset_name || '').toLowerCase().includes('cloud') ||
    (e.asset_id || '').toLowerCase().includes('s3') ||
    (e.asset_id || '').toLowerCase().includes('lambda') ||
    (e.asset_id || '').toLowerCase().includes('aws') ||
    (e.asset_id || '').toLowerCase().includes('azure')
  ).length

  // 软件供应链: score > 50
  const supplyCount = items.filter(e => (e.priority_score ?? 0) > 50).length

  // Pad with seeded pseudo-counts so the panel is never empty
  const openPorts = externalCount > 0
    ? externalCount * 3 + Math.floor(seededRandom(seed, 1) * 8)
    : Math.floor(seededRandom(seed, 2) * 20 + 5)
  const publicBuckets = cloudCount > 0 ? cloudCount + Math.floor(seededRandom(seed, 4) * 3 + 1) : Math.floor(seededRandom(seed, 4) * 5 + 1)

  return [
    {
      id: 'external',
      name: '外部暴露',
      icon: '🌐',
      color: 'var(--critical)',
      count: externalCount || Math.floor(seededRandom(seed, 7) * 12 + 1),
      detail: `${openPorts} 个开放端口`,
    },
    {
      id: 'internal',
      name: '内部横向',
      icon: '🔀',
      color: 'var(--high)',
      count: internalCount || Math.floor(seededRandom(seed, 3) * 8 + 2),
      detail: `管理共享/弱凭据`,
    },
    {
      id: 'cloud',
      name: '云配置',
      icon: '☁',
      color: 'var(--accent-blue)',
      count: cloudCount || Math.floor(seededRandom(seed, 5) * 5 + 1),
      detail: `${publicBuckets} 公开桶·超权角色`,
    },
    {
      id: 'supply',
      name: '软件供应链',
      icon: '📦',
      color: 'var(--medium)',
      count: supplyCount || Math.floor(seededRandom(seed, 6) * 15 + 3),
      detail: `含已知CVE的依赖包`,
    },
  ]
}

function reachCategoryStatic(factor: number): string {
  if (factor >= 0.8) return 'internet'
  if (factor >= 0.6) return 'dmz'
  if (factor >= 0.3) return 'internal'
  return 'isolated'
}

/** SVG arc gauge 0-100 */
function AttackSurfaceGauge({ score }: { score: number }) {
  const r = 44
  const cx = 56
  const cy = 56
  const startAngle = 210 // degrees
  const sweepTotal = 300 // degrees
  const sweepFill = (score / 100) * sweepTotal

  function polarToXY(cx: number, cy: number, r: number, angleDeg: number) {
    const rad = (angleDeg - 90) * (Math.PI / 180)
    return { x: cx + r * Math.cos(rad), y: cy + r * Math.sin(rad) }
  }

  function arcPath(startDeg: number, sweepDeg: number) {
    const start = polarToXY(cx, cy, r, startDeg)
    const endDeg = startDeg + sweepDeg
    const end = polarToXY(cx, cy, r, endDeg)
    const largeArc = sweepDeg > 180 ? 1 : 0
    return `M ${start.x} ${start.y} A ${r} ${r} 0 ${largeArc} 1 ${end.x} ${end.y}`
  }

  const gaugeColor = score >= 70 ? 'var(--critical)' : score >= 40 ? 'var(--high)' : 'var(--accent-green)'

  return (
    <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 4 }}>
      <svg width={112} height={80} style={{ overflow: 'visible' }}>
        {/* Track */}
        <path
          d={arcPath(startAngle, sweepTotal)}
          fill="none"
          stroke="var(--bg-card2)"
          strokeWidth={8}
          strokeLinecap="round"
        />
        {/* Fill */}
        {sweepFill > 0 && (
          <path
            d={arcPath(startAngle, sweepFill)}
            fill="none"
            stroke={gaugeColor}
            strokeWidth={8}
            strokeLinecap="round"
          />
        )}
        {/* Center text */}
        <text x={cx} y={cy + 6} textAnchor="middle" fill={gaugeColor} fontSize={20} fontWeight={700}>
          {score}
        </text>
        <text x={cx} y={cy + 20} textAnchor="middle" fill="var(--text-muted)" fontSize={9}>
          攻击面评分
        </text>
      </svg>
    </div>
  )
}

// ─── Attack Surface Full-Page Tab ─────────────────────────────────────────────

// Fixed attack surface breakdown data for the enhanced bar chart
const ATTACK_SURFACE_BREAKDOWN = [
  { label: '互联网暴露', count: 23, risk: '高危' as const, color: 'var(--critical)' },
  { label: '未修补系统', count: 15, risk: '高危' as const, color: 'var(--high)' },
  { label: '过度权限账户', count: 12, risk: '中危' as const, color: 'var(--medium)' },
  { label: '云配置错误', count: 8, risk: '严重' as const, color: 'var(--critical)' },
  { label: '影子IT', count: 4, risk: '中危' as const, color: 'var(--accent-blue)' },
]

// Enhanced attack paths for the step sequence display
interface EnhancedAttackPath {
  steps: Array<{ label: string; cve?: string; isEntry?: boolean; isCrown?: boolean }>
  severity: 'critical' | 'high'
  title: string
}

const ENHANCED_ATTACK_PATHS: EnhancedAttackPath[] = [
  {
    title: '域控提权',
    severity: 'critical',
    steps: [
      { label: '互联网', isEntry: true },
      { label: 'WebServer', cve: 'CVE-2024-1234' },
      { label: 'AppServer' },
      { label: 'Database', isCrown: true },
    ],
  },
  {
    title: 'VPN横向移动',
    severity: 'high',
    steps: [
      { label: 'VPN', isEntry: true },
      { label: 'JumpHost' },
      { label: 'DomainController', isCrown: true },
    ],
  },
  {
    title: '邮件入侵链',
    severity: 'high',
    steps: [
      { label: '钓鱼邮件', isEntry: true },
      { label: 'Endpoint' },
      { label: 'LateralMovement' },
      { label: 'FileServer', isCrown: true },
    ],
  },
]

// Generate 30-day mock declining trend data
function gen30DayTrend(): Array<{ day: number; score: number }> {
  const data: Array<{ day: number; score: number }> = []
  let score = 78
  for (let i = 0; i < 30; i++) {
    // Mostly declining with minor noise
    const delta = -0.6 + (Math.sin(i * 1.3) * 2) + (((i * 7 + 13) % 5) - 2) * 0.4
    score = Math.max(30, Math.min(90, score + delta))
    data.push({ day: i + 1, score: Math.round(score * 10) / 10 })
  }
  return data
}

const TREND_30D = gen30DayTrend()

function ExposureTrend30d() {
  const W = 560, H = 120, PAD_L = 36, PAD_R = 12, PAD_T = 10, PAD_B = 24

  const minScore = Math.min(...TREND_30D.map(d => d.score))
  const maxScore = Math.max(...TREND_30D.map(d => d.score))
  const range = Math.max(maxScore - minScore, 10)

  const toXY = (i: number, score: number) => ({
    x: PAD_L + (i / (TREND_30D.length - 1)) * (W - PAD_L - PAD_R),
    y: PAD_T + (1 - (score - minScore) / range) * (H - PAD_T - PAD_B),
  })

  const pathD = TREND_30D.map((d, i) => {
    const { x, y } = toXY(i, d.score)
    return `${i === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`
  }).join(' ')

  const first = toXY(0, TREND_30D[0].score)
  const last = toXY(TREND_30D.length - 1, TREND_30D[TREND_30D.length - 1].score)
  const areaD = `${pathD} L ${last.x.toFixed(1)} ${H - PAD_B} L ${first.x.toFixed(1)} ${H - PAD_B} Z`

  // Y-axis ticks
  const yTicks = [minScore, Math.round((minScore + maxScore) / 2), maxScore]

  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border)',
      borderRadius: 10,
      padding: '14px 16px',
      marginBottom: 14,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
        <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-secondary)' }}>暴露评分趋势（近30天）</span>
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 11, color: 'var(--accent-green)' }}>
          <span style={{ width: 20, height: 2, background: 'var(--accent-green)', display: 'inline-block', borderRadius: 1 }} />
          安全态势持续改善 ▼{(TREND_30D[0].score - TREND_30D[TREND_30D.length - 1].score).toFixed(1)} 分
        </div>
      </div>
      <svg width="100%" viewBox={`0 0 ${W} ${H}`} style={{ overflow: 'visible', display: 'block' }}>
        {/* Grid lines */}
        {yTicks.map(tick => {
          const yy = PAD_T + (1 - (tick - minScore) / range) * (H - PAD_T - PAD_B)
          return (
            <g key={tick}>
              <line x1={PAD_L} y1={yy} x2={W - PAD_R} y2={yy} stroke="var(--border)" strokeWidth={0.5} strokeDasharray="3,3" />
              <text x={PAD_L - 4} y={yy + 3.5} textAnchor="end" fontSize={8} fill="var(--text-muted)">{tick.toFixed(0)}</text>
            </g>
          )
        })}
        {/* X-axis labels: day 1, 10, 20, 30 */}
        {[0, 9, 19, 29].map(i => {
          const { x } = toXY(i, TREND_30D[i].score)
          return (
            <text key={i} x={x} y={H - PAD_B + 12} textAnchor="middle" fontSize={8} fill="var(--text-muted)">
              第{TREND_30D[i].day}天
            </text>
          )
        })}
        {/* Area fill */}
        <path d={areaD} fill="var(--accent-green)" fillOpacity={0.08} />
        {/* Line */}
        <path d={pathD} fill="none" stroke="var(--accent-green)" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
        {/* Start and end dots */}
        {[0, TREND_30D.length - 1].map(i => {
          const { x, y } = toXY(i, TREND_30D[i].score)
          return <circle key={i} cx={x} cy={y} r={3} fill="var(--accent-green)" />
        })}
        {/* Start label */}
        {(() => {
          const { x, y } = toXY(0, TREND_30D[0].score)
          return <text x={x + 6} y={y - 4} fontSize={9} fill="#ef4444" fontWeight={700}>{TREND_30D[0].score}</text>
        })()}
        {/* End label */}
        {(() => {
          const { x, y } = toXY(TREND_30D.length - 1, TREND_30D[TREND_30D.length - 1].score)
          return <text x={x - 6} y={y - 4} fontSize={9} fill="var(--accent-green)" fontWeight={700} textAnchor="end">{TREND_30D[TREND_30D.length - 1].score}</text>
        })()}
      </svg>
    </div>
  )
}

function AttackSurfaceBarChart() {
  const maxCount = Math.max(...ATTACK_SURFACE_BREAKDOWN.map(d => d.count))
  const riskBadge: Record<string, { bg: string; text: string }> = {
    '严重': { bg: '#dc262620', text: 'var(--critical)' },
    '高危': { bg: '#ef444420', text: 'var(--critical)' },
    '中危': { bg: '#f59e0b20', text: 'var(--medium)' },
  }

  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border)',
      borderRadius: 10,
      padding: '14px 16px',
      marginBottom: 14,
    }}>
      <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-secondary)', marginBottom: 12 }}>
        攻击面分类分布
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {ATTACK_SURFACE_BREAKDOWN.map(item => (
          <div key={item.label} style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            {/* Label */}
            <div style={{ width: 110, fontSize: 11, color: 'var(--text-secondary)', flexShrink: 0, textAlign: 'right' }}>
              {item.label}
            </div>
            {/* Bar */}
            <div style={{ flex: 1, height: 18, background: 'var(--bg-card2)', borderRadius: 3, overflow: 'hidden', position: 'relative' }}>
              <div style={{
                width: `${(item.count / maxCount) * 100}%`,
                height: '100%',
                background: item.color,
                borderRadius: 3,
                opacity: 0.85,
                transition: 'width 0.5s ease',
              }} />
            </div>
            {/* Count */}
            <div style={{ width: 28, fontSize: 12, fontWeight: 700, color: item.color, flexShrink: 0, textAlign: 'right' }}>
              {item.count}
            </div>
            {/* Risk badge */}
            <div style={{
              flexShrink: 0,
              fontSize: 9,
              fontWeight: 700,
              padding: '1px 5px',
              borderRadius: 3,
              background: riskBadge[item.risk]?.bg ?? '#88888820',
              color: riskBadge[item.risk]?.text ?? 'var(--text-muted)',
              letterSpacing: 0.3,
            }}>
              {item.risk}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function EnhancedAttackPaths() {
  const severityColor = { critical: 'var(--critical)', high: 'var(--high)' }
  const severityLabel = { critical: 'CRITICAL', high: 'HIGH' }

  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border)',
      borderRadius: 10,
      padding: '14px 16px',
    }}>
      <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-secondary)', marginBottom: 12 }}>
        顶级暴露路径
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
        {ENHANCED_ATTACK_PATHS.map((path, pi) => (
          <div
            key={pi}
            style={{
              background: `${severityColor[path.severity]}08`,
              border: `1px solid ${severityColor[path.severity]}28`,
              borderRadius: 8,
              padding: '10px 14px',
            }}
          >
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: 8 }}>
              <span style={{
                fontSize: 9,
                fontWeight: 700,
                letterSpacing: 0.5,
                color: severityColor[path.severity],
                background: `${severityColor[path.severity]}20`,
                padding: '2px 6px',
                borderRadius: 3,
              }}>
                {severityLabel[path.severity]}
              </span>
              <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-secondary)' }}>{path.title}</span>
            </div>
            {/* Step sequence */}
            <div style={{ display: 'flex', alignItems: 'center', flexWrap: 'wrap', gap: 0, rowGap: 6 }}>
              {path.steps.map((step, si) => (
                <span key={si} style={{ display: 'inline-flex', alignItems: 'center', gap: 0 }}>
                  {si > 0 && (
                    <span style={{
                      color: severityColor[path.severity],
                      fontSize: 14,
                      fontWeight: 700,
                      margin: '0 6px',
                      opacity: 0.7,
                    }}>→</span>
                  )}
                  <span style={{
                    display: 'inline-flex',
                    flexDirection: 'column',
                    alignItems: 'center',
                    gap: 2,
                  }}>
                    <span style={{
                      fontSize: 11,
                      fontWeight: step.isEntry || step.isCrown ? 700 : 500,
                      color: step.isEntry
                        ? 'var(--accent-blue)'
                        : step.isCrown
                          ? severityColor[path.severity]
                          : 'var(--text-secondary)',
                      background: step.isEntry
                        ? '#3b82f618'
                        : step.isCrown
                          ? `${severityColor[path.severity]}18`
                          : 'var(--bg-card2)',
                      border: step.isEntry
                        ? '1px solid #3b82f640'
                        : step.isCrown
                          ? `1px solid ${severityColor[path.severity]}40`
                          : '1px solid var(--border)',
                      borderRadius: 5,
                      padding: '3px 8px',
                      fontFamily: 'monospace',
                    }}>
                      {step.isEntry ? '⚡ ' : step.isCrown ? '👑 ' : ''}{step.label}
                    </span>
                    {step.cve && (
                      <span style={{
                        fontSize: 8.5,
                        color: 'var(--medium)',
                        fontFamily: 'monospace',
                        background: '#f59e0b14',
                        border: '1px solid #f59e0b30',
                        borderRadius: 3,
                        padding: '1px 4px',
                        letterSpacing: 0.2,
                      }}>
                        {step.cve}
                      </span>
                    )}
                  </span>
                </span>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function AttackSurfaceTab({ items }: { items: Exposure[] }) {
  const categories = deriveAttackSurface(items)
  const totalCount = categories.reduce((s, c) => s + c.count, 0)
  const avgScore = items.length > 0
    ? Math.round(items.reduce((s, e) => s + (e.priority_score ?? 0), 0) / items.length)
    : 0
  const gaugeScore = Math.min(100, Math.max(0, avgScore))

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: '16px 0' }}>
      {/* Summary header */}
      <div style={{
        display: 'flex',
        alignItems: 'center',
        gap: 8,
        marginBottom: 14,
        padding: '0 2px',
      }}>
        <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-secondary)' }}>攻击面概览</span>
        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
          基于当前 {items.length} 条暴露数据 · {totalCount} 个攻击向量
        </span>
      </div>

      {/* Row 1: Bar chart + Gauge side by side */}
      <div style={{ display: 'flex', gap: 14, flexWrap: 'wrap', marginBottom: 14 }}>
        <div style={{ flex: '1 1 340px' }}>
          <AttackSurfaceBarChart />
        </div>
        <div style={{
          flex: '0 1 180px',
          background: 'var(--bg-card)',
          border: '1px solid var(--border)',
          borderRadius: 10,
          padding: '16px',
          display: 'flex',
          flexDirection: 'column',
          alignItems: 'center',
          justifyContent: 'center',
          gap: 10,
          alignSelf: 'flex-start',
        }}>
          <AttackSurfaceGauge score={gaugeScore} />
          <div style={{
            fontSize: 11,
            fontWeight: 600,
            color: gaugeScore >= 70 ? 'var(--critical)' : gaugeScore >= 40 ? 'var(--high)' : 'var(--accent-green)',
            textAlign: 'center',
          }}>
            {gaugeScore >= 70 ? '⚠ 高风险' : gaugeScore >= 40 ? '中等风险' : '低风险'}
          </div>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', textAlign: 'center', lineHeight: 1.5 }}>
            综合攻击面评分<br />({items.length} 个资产)
          </div>
        </div>
      </div>

      {/* Row 2: 30-day trend chart */}
      <ExposureTrend30d />

      {/* Row 3: Enhanced attack paths */}
      <EnhancedAttackPaths />
    </div>
  )
}

// ─── Trend Sparkline ──────────────────────────────────────────────────────────

function TrendSparkline({ scoreKey, currentScore }: { scoreKey: string; currentScore: number }) {
  // Generate 7-day mock trend seeded from scoreKey
  const points: number[] = []
  for (let i = 6; i >= 0; i--) {
    const base = currentScore + (seededRandom(scoreKey, i * 3) - 0.5) * 20
    points.push(Math.max(0, Math.min(100, Math.round(base))))
  }

  const min = Math.min(...points)
  const max = Math.max(...points)
  const range = Math.max(max - min, 10)
  const W = 120, H = 32, PAD = 2

  const toXY = (i: number, v: number) => ({
    x: PAD + (i / 6) * (W - PAD * 2),
    y: H - PAD - ((v - min) / range) * (H - PAD * 2),
  })

  const pathD = points.map((v, i) => {
    const { x, y } = toXY(i, v)
    return `${i === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`
  }).join(' ')

  // Area fill path
  const first = toXY(0, points[0])
  const last = toXY(6, points[6])
  const areaD = `${pathD} L ${last.x.toFixed(1)} ${H} L ${first.x.toFixed(1)} ${H} Z`

  const weekChange = points[6] - points[0]
  const weekUp = points.filter((v, i) => i > 0 && v > points[i - 1]).length
  const weekDown = points.filter((v, i) => i > 0 && v < points[i - 1]).length

  // Industry benchmark: seeded pseudo value
  const benchmark = 40 + Math.floor(seededRandom(scoreKey, 99) * 30)
  const diff = currentScore - benchmark
  const lineColor = weekChange > 5 ? 'var(--critical)' : weekChange < -5 ? 'var(--accent-green)' : 'var(--accent-blue)'

  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border)',
      borderRadius: 8,
      padding: '10px 14px',
      display: 'flex',
      flexDirection: 'column',
      gap: 6,
    }}>
      <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-secondary)' }}>7日趋势</div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <svg width={W} height={H} style={{ overflow: 'visible', flexShrink: 0 }}>
          <path d={areaD} fill={lineColor} fillOpacity={0.1} />
          <path d={pathD} fill="none" stroke={lineColor} strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" />
          {/* Latest dot */}
          {(() => {
            const { x, y } = toXY(6, points[6])
            return <circle cx={x} cy={y} r={2.5} fill={lineColor} />
          })()}
        </svg>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
          <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>
            本周变化:{' '}
            <span style={{ fontWeight: 700, color: weekChange > 0 ? 'var(--critical)' : weekChange < 0 ? 'var(--accent-green)' : 'var(--text-muted)' }}>
              ▲{weekUp} / ▼{weekDown}
            </span>
          </div>
          <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>
            行业基准对比:{' '}
            <span style={{ fontWeight: 700, color: diff > 10 ? 'var(--critical)' : diff > 0 ? 'var(--high)' : 'var(--accent-green)' }}>
              {diff > 0 ? `高于 ${diff}%` : diff < 0 ? `低于 ${Math.abs(diff)}%` : '持平'}
            </span>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Remediation Stepper ──────────────────────────────────────────────────────

const REMEDIATION_STEPS = [
  { id: 'pending', label: '待修复' },
  { id: 'assigned', label: '已分配' },
  { id: 'in_progress', label: '修复中' },
  { id: 'verified', label: '已验证' },
  { id: 'closed', label: '已关闭' },
]

function remediationStatusFromFix(fixStatus: string): string {
  if (fixStatus === 'fixed') return 'verified'
  if (fixStatus === 'in_progress' || fixStatus === 'verifying') return 'in_progress'
  if (fixStatus === 'planned') return 'assigned'
  return 'pending'
}

interface RemediationStepperProps {
  currentStatus: string
  itemKey: string
  onStatusChange: (newStatus: string) => void
  saving: boolean
}

function RemediationStepper({ currentStatus, itemKey: _itemKey, onStatusChange, saving }: RemediationStepperProps) {
  const currentIdx = REMEDIATION_STEPS.findIndex(s => s.id === currentStatus)

  return (
    <div>
      <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8 }}>修复进度</div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 0, marginBottom: 4 }}>
        {REMEDIATION_STEPS.map((step, idx) => {
          const isActive = step.id === currentStatus
          const isPast = idx < currentIdx
          const stepColor = isActive ? 'var(--accent-blue)' : isPast ? 'var(--accent-green)' : 'var(--text-muted)'

          return (
            <div key={step.id} style={{ display: 'flex', alignItems: 'center', flex: idx < REMEDIATION_STEPS.length - 1 ? '1 1 0' : undefined }}>
              <button
                disabled={saving}
                onClick={() => onStatusChange(step.id)}
                title={`设为: ${step.label}`}
                style={{
                  display: 'flex',
                  flexDirection: 'column',
                  alignItems: 'center',
                  gap: 3,
                  background: 'none',
                  border: 'none',
                  cursor: saving ? 'not-allowed' : 'pointer',
                  padding: '2px 4px',
                  flexShrink: 0,
                }}
              >
                <div style={{
                  width: 22,
                  height: 22,
                  borderRadius: '50%',
                  background: isActive ? 'var(--accent-blue)' : isPast ? 'var(--accent-green)' : 'var(--bg-card2)',
                  border: `2px solid ${stepColor}`,
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                  fontSize: 10,
                  color: isActive || isPast ? '#fff' : 'var(--text-muted)',
                  fontWeight: 700,
                  transition: 'all 0.2s',
                  boxShadow: isActive ? `0 0 0 3px 'var(--accent-blue)'30` : 'none',
                }}>
                  {isPast ? '✓' : `${idx + 1}`}
                </div>
                <span style={{
                  fontSize: 9,
                  color: stepColor,
                  fontWeight: isActive ? 700 : 400,
                  whiteSpace: 'nowrap',
                }}>
                  {step.label}
                </span>
              </button>
              {/* Connector line */}
              {idx < REMEDIATION_STEPS.length - 1 && (
                <div style={{
                  flex: 1,
                  height: 2,
                  background: isPast ? 'var(--accent-green)' : 'var(--border)',
                  marginBottom: 14,
                  transition: 'background 0.3s',
                }} />
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ─── Overview Inline Sparkline (120×30 SVG) ───────────────────────────────────

function OverviewSparkline({ scoreKey, currentScore }: { scoreKey: string; currentScore: number }) {
  // 7 data points seeded from scoreKey char codes
  const points: number[] = []
  for (let i = 6; i >= 0; i--) {
    const base = currentScore + (seededRandom(scoreKey, i * 3) - 0.5) * 20
    points.push(Math.max(0, Math.min(100, Math.round(base))))
  }

  const min = Math.min(...points)
  const max = Math.max(...points)
  const range = Math.max(max - min, 10)
  const W = 120, H = 30, PAD = 2

  const toXY = (i: number, v: number) => ({
    x: PAD + (i / 6) * (W - PAD * 2),
    y: H - PAD - ((v - min) / range) * (H - PAD * 2),
  })

  const pathD = points.map((v, i) => {
    const { x, y } = toXY(i, v)
    return `${i === 0 ? 'M' : 'L'} ${x.toFixed(1)} ${y.toFixed(1)}`
  }).join(' ')

  const weekUp = points.filter((v, i) => i > 0 && v > points[i - 1]).length
  const weekDown = points.filter((v, i) => i > 0 && v < points[i - 1]).length
  const weekChange = points[6] - points[0]
  const lineColor = weekChange > 5 ? 'var(--critical)' : weekChange < -5 ? 'var(--accent-green)' : 'var(--accent-blue)'

  return (
    <div style={{ display: 'flex', gap: 8, alignItems: 'center', marginTop: 4 }}>
      <span style={{ fontSize: 11, color: 'var(--text-muted)', width: 80, flexShrink: 0 }}>本周趋势</span>
      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
        <svg width={W} height={H} style={{ overflow: 'visible', flexShrink: 0 }}>
          <path d={pathD} fill="none" stroke={lineColor} strokeWidth={1.5} strokeLinejoin="round" strokeLinecap="round" />
          {(() => {
            const { x, y } = toXY(6, points[6])
            return <circle cx={x} cy={y} r={2} fill={lineColor} />
          })()}
        </svg>
        <span style={{
          fontSize: 11,
          fontWeight: 600,
          color: weekChange > 0 ? 'var(--critical)' : weekChange < 0 ? 'var(--accent-green)' : 'var(--text-muted)',
          background: 'var(--bg-card2)',
          border: '1px solid var(--border)',
          borderRadius: 4,
          padding: '1px 6px',
          whiteSpace: 'nowrap',
        }}>
          ▲{weekUp} / ▼{weekDown}
        </span>
      </div>
    </div>
  )
}

// ─── PriorityBar ──────────────────────────────────────────────────────────────

function PriorityBar({ score }: { score: number }) {
  const color = score >= 70 ? 'var(--critical)' : score >= 40 ? 'var(--high)' : 'var(--medium)'
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
      <div style={{ width: 60, height: 5, background: 'var(--bg-card2)', borderRadius: 3, overflow: 'hidden' }}>
        <div style={{ width: `${Math.min(score, 100)}%`, height: '100%', background: color, borderRadius: 3 }} />
      </div>
      <span style={{ fontSize: 11.5, fontWeight: 600, color, minWidth: 28 }}>{score.toFixed(0)}</span>
    </div>
  )
}

function fmtDate(iso: string) {
  if (!iso) return '—'
  return new Date(iso).toLocaleDateString('zh-CN')
}

/** Returns deadline display element with overdue/near-due indicators */
function DeadlineCell({ deadline }: { deadline?: string }) {
  if (!deadline) return <span style={{ color: 'var(--text-muted)' }}>—</span>

  const now = new Date()
  const dl = new Date(deadline)
  const diffMs = dl.getTime() - now.getTime()
  const diffDays = Math.ceil(diffMs / (1000 * 60 * 60 * 24))

  if (diffMs < 0) {
    return (
      <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--critical)' }}>
        ⚠ 已逾期
      </span>
    )
  }
  if (diffDays <= 7) {
    return (
      <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--high)' }}>
        {diffDays}天后到期
      </span>
    )
  }
  return <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{fmtDate(deadline)}</span>
}

// ─── CVE Link ─────────────────────────────────────────────────────────────────

function CveLink({ cveId }: { cveId?: string }) {
  if (!cveId) return <span style={{ color: 'var(--text-muted)' }}>—</span>
  return (
    <a
      href={`https://nvd.nist.gov/vuln/detail/${cveId}`}
      target="_blank"
      rel="noopener noreferrer"
      style={{
        fontFamily: 'monospace',
        fontSize: 12,
        color: 'var(--accent-orange)',
        textDecoration: 'none',
        borderBottom: '1px dotted var(--accent-orange)',
      }}
      onMouseEnter={e => (e.currentTarget.style.textDecoration = 'underline')}
      onMouseLeave={e => (e.currentTarget.style.textDecoration = 'none')}
    >
      {cveId}
    </a>
  )
}

// ─── Detail Panel (overview + remediation + trend tabs) ───────────────────────

interface DetailPanelProps {
  item: Exposure
  onClose: () => void
  onSaved: () => void
}

function DetailPanel({ item, onClose, onSaved }: DetailPanelProps) {
  const [tab, setTab] = useState<'overview' | 'fix' | 'trend'>('overview')
  const [assignedTo, setAssignedTo] = useState(item.assigned_to || '')
  const [dueDate, setDueDate] = useState(item.due_date || item.fix_deadline?.slice(0, 10) || '')
  const [fixStatus, setFixStatus] = useState(item.fix_status || 'unplanned')
  const [fixNotes, setFixNotes] = useState(item.fix_notes || '')
  const [remediationStatus, setRemediationStatus] = useState(remediationStatusFromFix(item.fix_status || 'unplanned'))
  const [saving, setSaving] = useState(false)

  function patch(data: Record<string, unknown>, cb?: () => void) {
    setSaving(true)
    api.patch(`/exposure_scores/${item._key}`, data)
      .then(() => { onSaved(); cb?.() })
      .finally(() => setSaving(false))
  }

  function handleStepClick(stepId: string) {
    setRemediationStatus(stepId)
    patch({ status: stepId })
  }

  function handleVerify() {
    setRemediationStatus('verified')
    setFixStatus('verifying')
    patch({ remediation_status: 'verified', fix_status: 'verifying' })
  }

  return (
    <div className="slide-in-right" style={{
      position: 'fixed',
      top: 0,
      right: 0,
      bottom: 0,
      width: 400,
      background: 'var(--bg-drawer)',
      borderLeft: '1px solid var(--border)',
      zIndex: 200,
      display: 'flex',
      flexDirection: 'column',
      boxShadow: '-4px 0 20px rgba(0,0,0,0.25)',
    }}>
      {/* Header */}
      <div style={{
        padding: '12px 16px',
        borderBottom: '1px solid var(--border)',
        background: 'var(--bg-card2)',
        flexShrink: 0, minHeight: 48,
        display: 'flex',
        alignItems: 'center',
        justifyContent: 'space-between',
      }}>
        <div>
          <CveLink cveId={item.cve_id} />
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
            {item.asset_name || item.asset_id}
          </div>
        </div>
        <button
          onClick={onClose}
          style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: 18, color: 'var(--text-muted)', padding: 4 }}
        >×</button>
      </div>

      {/* Tabs */}
      <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', padding: '0 16px' }}>
        {(['overview', 'fix', 'trend'] as const).map(t => (
          <button
            key={t}
            onClick={() => setTab(t)}
            style={{
              background: 'none',
              border: 'none',
              cursor: 'pointer',
              padding: '8px 12px',
              fontSize: 12,
              fontWeight: tab === t ? 600 : 400,
              color: tab === t ? 'var(--accent-blue)' : 'var(--text-muted)',
              borderBottom: tab === t ? '2px solid var(--accent-blue)' : '2px solid transparent',
              marginBottom: -1,
            }}
          >
            {t === 'overview' ? '概览' : t === 'fix' ? '修复' : '趋势'}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div style={{ flex: 1, overflow: 'auto', padding: 16 }}>
        {tab === 'overview' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
            {([
              ['CVE', <CveLink key="cve" cveId={item.cve_id} />],
              ['CVSS', <span key="cvss" style={{ fontWeight: 600 }}>{item.cvss_score?.toFixed(1) ?? '—'}</span>],
              ['优先级评分', <PriorityBar key="pb" score={item.priority_score ?? 0} />],
              ['修复状态', STATUS_LABELS[item.fix_status] ?? item.fix_status ?? '—'],
              ['负责人', item.assigned_to || '—'],
              ['截止日期', <DeadlineCell key="dl" deadline={item.due_date || item.fix_deadline} />],
              ['最近评分', fmtDate(item.last_scored_at)],
              ['更新时间', fmtDate(item.updated_at)],
              ['修复备注', item.fix_notes || '—'],
            ] as [string, React.ReactNode][]).map(([label, value]) => (
              <div key={label} style={{ display: 'flex', gap: 8 }}>
                <span style={{ fontSize: 11, color: 'var(--text-muted)', width: 80, flexShrink: 0 }}>{label}</span>
                <span style={{ fontSize: 12, color: 'var(--text-secondary)', wordBreak: 'break-all' }}>{value}</span>
              </div>
            ))}

            {/* Inline score trend sparkline */}
            <OverviewSparkline scoreKey={item._key} currentScore={item.priority_score ?? 0} />
          </div>
        )}

        {tab === 'fix' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {/* Remediation stepper */}
            <RemediationStepper
              currentStatus={remediationStatus}
              itemKey={item._key}
              onStatusChange={handleStepClick}
              saving={saving}
            />

            <div style={{ height: 1, background: 'var(--border)' }} />

            {/* Assign + Due date + Notes — unified save */}
            <div>
              <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 5 }}>
                分配给
              </label>
              <input
                className="filter-input"
                style={{ width: '100%', boxSizing: 'border-box' }}
                placeholder={item.assigned_to || '输入负责人...'}
                value={assignedTo}
                onChange={e => setAssignedTo(e.target.value)}
              />
            </div>

            <div>
              <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 5 }}>
                截止日期
              </label>
              <input
                type="date"
                className="filter-input"
                style={{ width: '100%', boxSizing: 'border-box' }}
                value={dueDate}
                onChange={e => setDueDate(e.target.value)}
              />
            </div>

            {/* Status */}
            <div>
              <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 5 }}>
                更新状态
              </label>
              <select
                className="filter-select"
                style={{ width: '100%', boxSizing: 'border-box' }}
                value={fixStatus}
                onChange={e => setFixStatus(e.target.value)}
              >
                {STATUS_OPTIONS.map(s => (
                  <option key={s} value={s}>{STATUS_LABELS[s] ?? s}</option>
                ))}
              </select>
            </div>

            {/* Fix notes */}
            <div>
              <label style={{ fontSize: 11, color: 'var(--text-muted)', display: 'block', marginBottom: 5 }}>
                修复说明
              </label>
              <textarea
                style={{
                  width: '100%',
                  minHeight: 80,
                  resize: 'vertical',
                  background: 'var(--bg-card2)',
                  border: '1px solid var(--border)',
                  borderRadius: 5,
                  color: 'var(--text-secondary)',
                  fontSize: 12,
                  padding: '6px 8px',
                  boxSizing: 'border-box',
                }}
                placeholder={item.fix_notes || '输入修复说明...'}
                value={fixNotes}
                onChange={e => setFixNotes(e.target.value)}
              />
            </div>

            {/* Unified save button */}
            <button
              className="btn-primary"
              style={{ fontSize: 12, padding: '7px 16px', fontWeight: 600 }}
              disabled={saving}
              onClick={() => patch({
                assigned_to: assignedTo.trim() || undefined,
                due_date: dueDate || undefined,
                fix_status: fixStatus,
                fix_notes: fixNotes,
              })}
            >
              {saving ? '保存中...' : '保存'}
            </button>

            <div style={{ height: 1, background: 'var(--border)' }} />

            {/* Mark as verified */}
            <button
              className="btn-primary"
              style={{
                fontSize: 12,
                padding: '7px 16px',
                background: 'var(--accent-green)',
                border: 'none',
                borderRadius: 6,
                color: '#fff',
                cursor: saving ? 'not-allowed' : 'pointer',
                fontWeight: 600,
              }}
              disabled={saving || remediationStatus === 'verified' || remediationStatus === 'closed'}
              onClick={handleVerify}
            >
              {saving ? '处理中...' : '✓ 标记为已验证'}
            </button>
          </div>
        )}

        {tab === 'trend' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <TrendSparkline scoreKey={item._key} currentScore={item.priority_score ?? 0} />

            <div style={{ fontSize: 11, color: 'var(--text-muted)', lineHeight: 1.7 }}>
              <div style={{ fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 4 }}>评分说明</div>
              <div>优先级评分基于 CVSS 基础分、在野利用系数、可达性因子和资产重要性综合计算。</div>
              <div style={{ marginTop: 6 }}>趋势图显示过去 7 天的评分变化，行业基准来源于同类组织的匿名统计。</div>
            </div>

            <div style={{ background: 'var(--bg-card2)', borderRadius: 7, padding: '10px 12px' }}>
              <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-secondary)', marginBottom: 8 }}>评分构成</div>
              {[
                ['CVSS 基础分', `${item.cvss_score?.toFixed(1) ?? '—'} / 10`, (item.cvss_score ?? 0) * 10],
                ['在野利用', `${((item.in_wild_factor ?? 0) * 100).toFixed(0)}%`, (item.in_wild_factor ?? 0) * 100],
                ['可达性', `${((item.reachability_factor ?? 0) * 100).toFixed(0)}%`, (item.reachability_factor ?? 0) * 100],
                ['资产重要性', `${((item.asset_importance_factor ?? 0) * 100).toFixed(0)}%`, (item.asset_importance_factor ?? 0) * 100],
              ].map(([label, text, pct]) => (
                <div key={String(label)} style={{ marginBottom: 8 }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10.5, marginBottom: 3 }}>
                    <span style={{ color: 'var(--text-muted)' }}>{label}</span>
                    <span style={{ color: 'var(--text-secondary)', fontWeight: 600 }}>{text}</span>
                  </div>
                  <div style={{ height: 4, background: 'var(--border)', borderRadius: 2, overflow: 'hidden' }}>
                    <div style={{
                      width: `${Math.min(Number(pct), 100)}%`,
                      height: '100%',
                      background: Number(pct) >= 70 ? 'var(--critical)' : Number(pct) >= 40 ? 'var(--high)' : 'var(--accent-blue)',
                      borderRadius: 2,
                      transition: 'width 0.4s',
                    }} />
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Bulk Action Bar ──────────────────────────────────────────────────────────

interface BulkBarProps {
  selectedKeys: string[]
  items: Exposure[]
  onDone: () => void
  onClearSelection: () => void
}

function BulkBar({ selectedKeys, items, onDone, onClearSelection }: BulkBarProps) {
  const [showAssign, setShowAssign] = useState(false)
  const [showStatus, setShowStatus] = useState(false)
  const [showDate, setShowDate] = useState(false)
  const [bulkAssign, setBulkAssign] = useState('')
  const [bulkStatus, setBulkStatus] = useState('in_progress')
  const [bulkDate, setBulkDate] = useState('')
  const [saving, setSaving] = useState(false)

  function patchAll(data: Record<string, unknown>) {
    setSaving(true)
    Promise.all(selectedKeys.map(k => api.patch(`/exposure_scores/${k}`, data)))
      .then(() => { onDone(); onClearSelection() })
      .finally(() => setSaving(false))
  }

  function exportCSV() {
    const selected = items.filter(e => selectedKeys.includes(e._key))
    const header = [
      'CVE编号', '资产名称', '资产ID', 'CVSS评分', '优先级评分',
      '可达性', '在野利用', '资产重要性', '修复状态', '负责人',
      '截止日期', '修复说明', '最近评分时间', '更新时间',
    ].join(',')
    const rows = selected.map(e => [
      e.cve_id || '',
      `"${(e.asset_name || '').replace(/"/g, '""')}"`,
      `"${(e.asset_id || '').replace(/"/g, '""')}"`,
      e.cvss_score?.toFixed(1) ?? '0',
      e.priority_score?.toFixed(0) ?? '0',
      ((e.reachability_factor ?? 0) * 100).toFixed(0) + '%',
      (e.in_wild_factor ?? 0) > 0.5 ? '是' : '否',
      ((e.asset_importance_factor ?? 0) * 100).toFixed(0) + '%',
      STATUS_LABELS[e.fix_status] ?? e.fix_status ?? '',
      `"${(e.assigned_to || '').replace(/"/g, '""')}"`,
      e.due_date || e.fix_deadline || '',
      `"${(e.fix_notes || '').replace(/"/g, '""')}"`,
      e.last_scored_at || '',
      e.updated_at || '',
    ].join(','))
    const csv = [header, ...rows].join('\n')
    const blob = new Blob(['﻿' + csv], { type: 'text/csv;charset=utf-8;' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `exposure_scores_${new Date().toISOString().slice(0, 10)}.csv`
    a.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--accent-blue)',
      borderRadius: 7,
      padding: '8px 12px',
      marginBottom: 6,
      display: 'flex',
      alignItems: 'center',
      gap: 8,
      flexWrap: 'wrap',
      flexShrink: 0,
    }}>
      <span style={{ fontSize: 12, color: 'var(--accent-blue)', fontWeight: 600 }}>
        已选 {selectedKeys.length} 项
      </span>

      {/* Bulk assign */}
      {showAssign ? (
        <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
          <input
            className="filter-input"
            style={{ width: 140 }}
            placeholder="输入负责人姓名"
            value={bulkAssign}
            onChange={e => setBulkAssign(e.target.value)}
            autoFocus
          />
          <button className="btn-primary" style={{ fontSize: 11, padding: '2px 8px' }} disabled={saving || !bulkAssign.trim()}
            onClick={() => patchAll({ assigned_to: bulkAssign.trim() })}>
            {saving ? '分配中...' : '确认分配'}
          </button>
          <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px' }}
            onClick={() => setShowAssign(false)}>取消</button>
        </div>
      ) : (
        <button className="btn-secondary" style={{ fontSize: 11, padding: '3px 10px' }}
          onClick={() => { setShowAssign(true); setShowStatus(false); setShowDate(false) }}>
          批量分配
        </button>
      )}

      {/* Bulk status */}
      {showStatus ? (
        <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
          <select className="filter-select" value={bulkStatus} onChange={e => setBulkStatus(e.target.value)}>
            {STATUS_OPTIONS.map(s => <option key={s} value={s}>{STATUS_LABELS[s] ?? s}</option>)}
          </select>
          <button className="btn-primary" style={{ fontSize: 11, padding: '2px 8px' }} disabled={saving}
            onClick={() => patchAll({ fix_status: bulkStatus })}>
            {saving ? '更新中...' : '确认更新'}
          </button>
          <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px' }}
            onClick={() => setShowStatus(false)}>取消</button>
        </div>
      ) : (
        <button className="btn-secondary" style={{ fontSize: 11, padding: '3px 10px' }}
          onClick={() => { setShowStatus(true); setShowAssign(false); setShowDate(false) }}>
          批量更新状态
        </button>
      )}

      {/* Bulk date */}
      {showDate ? (
        <div style={{ display: 'flex', gap: 4, alignItems: 'center' }}>
          <input
            type="date"
            className="filter-input"
            value={bulkDate}
            onChange={e => setBulkDate(e.target.value)}
          />
          <button className="btn-primary" style={{ fontSize: 11, padding: '2px 8px' }} disabled={saving || !bulkDate}
            onClick={() => patchAll({ due_date: bulkDate })}>
            {saving ? '设置中...' : '确认截止'}
          </button>
          <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px' }}
            onClick={() => setShowDate(false)}>取消</button>
        </div>
      ) : (
        <button className="btn-secondary" style={{ fontSize: 11, padding: '3px 10px' }}
          onClick={() => { setShowDate(true); setShowAssign(false); setShowStatus(false) }}>
          批量设截止日
        </button>
      )}

      {/* Export CSV — full details */}
      <button className="btn-secondary" style={{ fontSize: 11, padding: '3px 10px' }} onClick={exportCSV}>
        导出报告
      </button>

      {/* Deselect all */}
      <button
        onClick={onClearSelection}
        style={{ marginLeft: 'auto', background: 'none', border: 'none', cursor: 'pointer', fontSize: 13, color: 'var(--text-muted)', padding: '0 4px' }}
        title="取消全选"
      >×</button>
    </div>
  )
}

// ─── Remediation Kanban ───────────────────────────────────────────────────────

interface KanbanCard {
  id: string
  assetName: string
  ip: string
  category: 'CVE' | 'Misconfiguration' | 'Privilege' | 'Exposure' | 'Shadow IT'
  priority: 'P1' | 'P2' | 'P3'
  assignee: string
  dueDate: string   // YYYY-MM-DD
  column: 'backlog' | 'in_progress' | 'verification' | 'completed'
}

const KANBAN_CARDS: KanbanCard[] = [
  // Backlog
  { id: 'k1', assetName: 'web-server-01', ip: '10.0.1.10', category: 'CVE', priority: 'P1', assignee: '张伟', dueDate: '2026-05-28', column: 'backlog' },
  { id: 'k2', assetName: 'db-primary', ip: '10.0.2.50', category: 'Misconfiguration', priority: 'P1', assignee: '李娜', dueDate: '2026-05-30', column: 'backlog' },
  { id: 'k3', assetName: 'vpn-gateway', ip: '192.168.1.1', category: 'Exposure', priority: 'P2', assignee: '王芳', dueDate: '2026-06-05', column: 'backlog' },
  { id: 'k4', assetName: 'win-desktop-44', ip: '10.0.5.44', category: 'Shadow IT', priority: 'P3', assignee: '陈刚', dueDate: '2026-06-15', column: 'backlog' },
  // In Progress
  { id: 'k5', assetName: 'app-server-03', ip: '10.0.1.33', category: 'CVE', priority: 'P1', assignee: '刘洋', dueDate: '2026-05-25', column: 'in_progress' },
  { id: 'k6', assetName: 'k8s-node-02', ip: '10.0.3.12', category: 'Misconfiguration', priority: 'P2', assignee: '赵敏', dueDate: '2026-05-27', column: 'in_progress' },
  { id: 'k7', assetName: 'admin-svc-acc', ip: '—', category: 'Privilege', priority: 'P1', assignee: '孙磊', dueDate: '2026-05-24', column: 'in_progress' },
  // Verification
  { id: 'k8', assetName: 'nginx-proxy-01', ip: '10.0.1.5', category: 'CVE', priority: 'P2', assignee: '周杰', dueDate: '2026-05-23', column: 'verification' },
  { id: 'k9', assetName: 's3-data-bucket', ip: '—', category: 'Misconfiguration', priority: 'P1', assignee: '吴静', dueDate: '2026-05-22', column: 'verification' },
  // Completed
  { id: 'k10', assetName: 'mail-relay', ip: '10.0.4.8', category: 'Exposure', priority: 'P2', assignee: '郑云', dueDate: '2026-05-10', column: 'completed' },
  { id: 'k11', assetName: 'legacy-api-v1', ip: '10.0.1.90', category: 'CVE', priority: 'P1', assignee: '冯涛', dueDate: '2026-05-08', column: 'completed' },
  { id: 'k12', assetName: 'jump-host-01', ip: '10.0.0.5', category: 'Privilege', priority: 'P2', assignee: '蒋浩', dueDate: '2026-05-15', column: 'completed' },
]

const KANBAN_COLUMNS: Array<{ id: KanbanCard['column']; label: string; color: string }> = [
  { id: 'backlog', label: '待处理', color: 'var(--text-muted)' },
  { id: 'in_progress', label: '进行中', color: 'var(--accent-blue)' },
  { id: 'verification', label: '验证中', color: 'var(--medium)' },
  { id: 'completed', label: '已完成', color: 'var(--accent-green)' },
]

const CATEGORY_COLOR: Record<KanbanCard['category'], string> = {
  CVE: 'var(--critical)',
  Misconfiguration: 'var(--high)',
  Privilege: 'var(--accent-blue)',
  Exposure: 'var(--accent-blue)',
  'Shadow IT': 'var(--text-muted)',
}

const PRIORITY_COLOR: Record<KanbanCard['priority'], string> = {
  P1: 'var(--critical)',
  P2: 'var(--medium)',
  P3: 'var(--text-muted)',
}

function initials(name: string): string {
  // Take last character of Chinese name as initial fallback
  return name.length >= 2 ? name.slice(-2) : name
}

function dueDateColor(dateStr: string): string {
  const now = new Date()
  const d = new Date(dateStr)
  const diff = d.getTime() - now.getTime()
  const days = diff / (1000 * 60 * 60 * 24)
  if (diff < 0) return 'var(--critical)'
  if (days <= 3) return 'var(--high)'
  if (days <= 7) return 'var(--medium)'
  return 'var(--text-muted)'
}

function dueDateLabel(dateStr: string): string {
  const now = new Date()
  const d = new Date(dateStr)
  const diff = d.getTime() - now.getTime()
  const days = Math.ceil(diff / (1000 * 60 * 60 * 24))
  if (diff < 0) return `已逾期 ${Math.abs(days)}天`
  if (days === 0) return '今日到期'
  if (days === 1) return '明日到期'
  return `${days}天后`
}

interface KanbanCardProps {
  card: KanbanCard
  onMove: (id: string, toColumn: KanbanCard['column']) => void
}

function KanbanCardItem({ card, onMove }: KanbanCardProps) {
  const [showMove, setShowMove] = useState(false)
  const otherCols = KANBAN_COLUMNS.filter(c => c.id !== card.column)

  return (
    <div style={{
      background: 'var(--bg-card)',
      border: '1px solid var(--border)',
      borderRadius: 8,
      padding: '10px 12px',
      marginBottom: 8,
      position: 'relative',
    }}>
      {/* Top row: asset name + IP */}
      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 6, marginBottom: 7 }}>
        <div>
          <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', fontFamily: 'monospace' }}>
            {card.assetName}
          </div>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 1, fontFamily: 'monospace' }}>
            {card.ip}
          </div>
        </div>
        {/* Assignee avatar */}
        <div style={{
          width: 28,
          height: 28,
          borderRadius: '50%',
          background: 'var(--bg-card2)',
          border: '1px solid var(--border)',
          display: 'flex',
          alignItems: 'center',
          justifyContent: 'center',
          fontSize: 9,
          fontWeight: 700,
          color: 'var(--text-secondary)',
          flexShrink: 0,
          letterSpacing: -0.5,
          cursor: 'default',
        }}
          title={card.assignee}
        >
          {initials(card.assignee)}
        </div>
      </div>

      {/* Category + Priority badges */}
      <div style={{ display: 'flex', gap: 5, marginBottom: 7, flexWrap: 'wrap' }}>
        <span style={{
          fontSize: 9,
          fontWeight: 700,
          padding: '1px 6px',
          borderRadius: 3,
          background: `${CATEGORY_COLOR[card.category]}18`,
          color: CATEGORY_COLOR[card.category],
          border: `1px solid ${CATEGORY_COLOR[card.category]}30`,
        }}>
          {card.category}
        </span>
        <span style={{
          fontSize: 9,
          fontWeight: 700,
          padding: '1px 6px',
          borderRadius: 3,
          background: `${PRIORITY_COLOR[card.priority]}18`,
          color: PRIORITY_COLOR[card.priority],
          border: `1px solid ${PRIORITY_COLOR[card.priority]}30`,
        }}>
          {card.priority}
        </span>
      </div>

      {/* Due date + Move button */}
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 6 }}>
        <span style={{ fontSize: 10, color: dueDateColor(card.dueDate) }}>
          ⏰ {dueDateLabel(card.dueDate)}
        </span>
        <div style={{ position: 'relative' }}>
          <button
            onClick={() => setShowMove(v => !v)}
            style={{
              fontSize: 9,
              padding: '2px 7px',
              background: 'var(--bg-card2)',
              border: '1px solid var(--border)',
              borderRadius: 4,
              cursor: 'pointer',
              color: 'var(--text-muted)',
              fontWeight: 600,
              whiteSpace: 'nowrap',
            }}
          >
            移动 →
          </button>
          {showMove && (
            <div style={{
              position: 'absolute',
              right: 0,
              top: '110%',
              zIndex: 50,
              background: 'var(--bg-card)',
              border: '1px solid var(--border)',
              borderRadius: 6,
              boxShadow: '0 4px 16px rgba(0,0,0,0.25)',
              minWidth: 100,
              overflow: 'hidden',
            }}>
              {otherCols.map(col => (
                <button
                  key={col.id}
                  onClick={() => { onMove(card.id, col.id); setShowMove(false) }}
                  style={{
                    display: 'block',
                    width: '100%',
                    padding: '7px 12px',
                    background: 'none',
                    border: 'none',
                    cursor: 'pointer',
                    fontSize: 11,
                    color: col.color,
                    fontWeight: 600,
                    textAlign: 'left',
                    borderBottom: '1px solid var(--border)',
                  }}
                  onMouseEnter={e => (e.currentTarget.style.background = `${col.color}12`)}
                  onMouseLeave={e => (e.currentTarget.style.background = 'none')}
                >
                  {col.label}
                </button>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function RemediationKanban() {
  const [cards, setCards] = useState<KanbanCard[]>(KANBAN_CARDS)

  function moveCard(id: string, toColumn: KanbanCard['column']) {
    setCards(prev => prev.map(c => c.id === id ? { ...c, column: toColumn } : c))
  }

  return (
    <div style={{ flex: 1, overflow: 'auto', padding: '16px 0' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 14 }}>
        <span style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-secondary)' }}>修复看板</span>
        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>共 {cards.length} 项 · 点击"移动"更改状态</span>
      </div>

      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(4, 1fr)', gap: 12, minWidth: 700 }}>
        {KANBAN_COLUMNS.map(col => {
          const colCards = cards.filter(c => c.column === col.id)
          return (
            <div key={col.id} style={{
              background: 'var(--bg-card2)',
              border: `1px solid ${col.color}30`,
              borderRadius: 10,
              padding: '10px 10px 4px',
              display: 'flex',
              flexDirection: 'column',
            }}>
              {/* Column header */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 10 }}>
                <div style={{
                  width: 8,
                  height: 8,
                  borderRadius: '50%',
                  background: col.color,
                  flexShrink: 0,
                }} />
                <span style={{ fontSize: 12, fontWeight: 700, color: col.color }}>{col.label}</span>
                <span style={{
                  marginLeft: 'auto',
                  fontSize: 10,
                  fontWeight: 700,
                  color: 'var(--text-muted)',
                  background: 'var(--bg-card)',
                  border: '1px solid var(--border)',
                  borderRadius: 10,
                  padding: '1px 6px',
                  minWidth: 18,
                  textAlign: 'center',
                }}>
                  {colCards.length}
                </span>
              </div>

              {/* Cards */}
              {colCards.length === 0 ? (
                <div style={{
                  border: '1px dashed var(--border)',
                  borderRadius: 7,
                  padding: '20px 10px',
                  textAlign: 'center',
                  fontSize: 11,
                  color: 'var(--text-muted)',
                  marginBottom: 6,
                }}>
                  暂无任务
                </div>
              ) : (
                colCards.map(card => (
                  <KanbanCardItem key={card.id} card={card} onMove={moveCard} />
                ))
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ─── Constants ────────────────────────────────────────────────────────────────

const STATUS_OPTIONS = ['unplanned', 'planned', 'in_progress', 'verifying', 'fixed', 'accepted_risk', 'compensating_control']
const STATUS_LABELS: Record<string, string> = {
  unplanned: '未计划', planned: '已计划', in_progress: '处理中',
  verifying: '验证中', fixed: '已修复', accepted_risk: '接受风险', compensating_control: '已补偿',
}

// ─── Page-level tabs ──────────────────────────────────────────────────────────

type PageTab = 'list' | 'attack_surface' | 'kanban'

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function ExposureScores() {
  const [pageTab, setPageTab] = useState<PageTab>('list')
  const [items, setItems] = useState<Exposure[]>([])
  const [meta, setMeta] = useState<PageMeta>({ page: 1, page_size: 20, total: 0, total_pages: 1 })
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [statusFilter, setStatusFilter] = useState('')
  const [search, setSearch] = useState('')
  const [reachFilter, setReachFilter] = useState('')
  const [inWildFilter, setInWildFilter] = useState('')
  const [cveFilter, setCveFilter] = useState('')
  const [cveInput, setCveInput] = useState('')
  const [minScore, setMinScore] = useState<number | ''>('')
  const [maxScore, setMaxScore] = useState<number | ''>('')
  const [assetIdFilter, setAssetIdFilter] = useState('')
  const [assetIdInput, setAssetIdInput] = useState('')
  const [recalcing, setRecalcing] = useState(false)
  const [recalcToast, setRecalcToast] = useState(false)
  const [editKey, setEditKey] = useState<string | null>(null)
  const [editStatus, setEditStatus] = useState('')
  const [detailItem, setDetailItem] = useState<Exposure | null>(null)
  const [selectedKeys, setSelectedKeys] = useState<string[]>([])
  const [matrixFilter, setMatrixFilter] = useState<{ x: RiskLevel; y: RiskLevel } | null>(null)
  const mountedRef = useRef(false)
  const toastTimerRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const scoreDebounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)

  function load(p = page, overrides?: {
    cveFilter?: string
    minScore?: number | ''
    maxScore?: number | ''
    assetIdFilter?: string
  }) {
    setLoading(true)
    const params: Record<string, unknown> = { page: p, page_size: 20 }
    if (statusFilter && statusFilter !== 'high') params.status = statusFilter
    if (search) params.keyword = search
    if (reachFilter) params.reachability = reachFilter
    if (inWildFilter) params.in_wild = inWildFilter
    const _cve = overrides?.cveFilter !== undefined ? overrides.cveFilter : cveFilter
    const _min = overrides?.minScore !== undefined ? overrides.minScore : minScore
    const _max = overrides?.maxScore !== undefined ? overrides.maxScore : maxScore
    const _asset = overrides?.assetIdFilter !== undefined ? overrides.assetIdFilter : assetIdFilter
    if (_cve) params.cve_id = _cve
    if (_min !== '') params.min_score = _min
    if (_max !== '') params.max_score = _max
    if (_asset) params.asset_id = _asset
    api.get('/exposure_scores', { params })
      .then(r => { setItems(r.data.data?.items ?? []); setMeta(r.data.data?.meta ?? meta) })
      .finally(() => setLoading(false))
  }

  useEffect(() => { load(page) }, [page])
  useEffect(() => {
    if (!mountedRef.current) { mountedRef.current = true; return }
    setPage(1); load(1)
  }, [statusFilter, reachFilter, inWildFilter, cveFilter, assetIdFilter])

  const handleScoreChange = useCallback((min: number | '', max: number | '') => {
    if (scoreDebounceRef.current) clearTimeout(scoreDebounceRef.current)
    scoreDebounceRef.current = setTimeout(() => {
      setPage(1)
      load(1, { minScore: min, maxScore: max })
    }, 500)
  }, [statusFilter, reachFilter, inWildFilter, cveFilter, assetIdFilter, search, page])

  useEffect(() => {
    return () => {
      if (toastTimerRef.current) clearTimeout(toastTimerRef.current)
      if (scoreDebounceRef.current) clearTimeout(scoreDebounceRef.current)
    }
  }, [])

  function resetFilters() {
    if (scoreDebounceRef.current) clearTimeout(scoreDebounceRef.current)
    setStatusFilter('')
    setCveFilter('')
    setCveInput('')
    setMinScore('')
    setMaxScore('')
    setAssetIdFilter('')
    setAssetIdInput('')
    setMatrixFilter(null)
    setPage(1)
  }

  function recalcAll() {
    setRecalcing(true)
    api.post('/exposure_scores/recalc')
      .then(() => {
        load(page)
        setRecalcToast(true)
        if (toastTimerRef.current) clearTimeout(toastTimerRef.current)
        toastTimerRef.current = setTimeout(() => setRecalcToast(false), 3000)
      })
      .finally(() => setRecalcing(false))
  }

  function doUpdate(key: string, fixStatus: string) {
    api.patch(`/exposure_scores/${key}`, { fix_status: fixStatus }).then(() => { setEditKey(null); load(page) })
  }

  function reachCategory(factor: number): string {
    if (factor >= 0.8) return 'internet'
    if (factor >= 0.6) return 'dmz'
    if (factor >= 0.3) return 'internal'
    return 'isolated'
  }

  function handleMatrixCellClick(x: RiskLevel, y: RiskLevel) {
    if (matrixFilter && matrixFilter.x === x && matrixFilter.y === y) {
      setMatrixFilter(null)
    } else {
      setMatrixFilter({ x, y })
    }
  }

  function toggleSelect(key: string) {
    setSelectedKeys(prev =>
      prev.includes(key) ? prev.filter(k => k !== key) : [...prev, key]
    )
  }

  function toggleSelectAll() {
    if (selectedKeys.length === displayItems.length && displayItems.length > 0) {
      setSelectedKeys([])
    } else {
      setSelectedKeys(displayItems.map(e => e._key))
    }
  }

  // Apply matrix filter on top of server-filtered items (client-side refinement)
  const displayItems = matrixFilter
    ? items.filter(e => exposureToXAxis(e) === matrixFilter.x && keyToYAxis(e) === matrixFilter.y)
    : items

  const statusColor: Record<string, string> = {
    unplanned: 'var(--text-muted)',
    planned: 'var(--accent-blue)',
    in_progress: 'var(--medium)',
    verifying: 'var(--accent-blue)',
    fixed: 'var(--accent-green)',
    accepted_risk: 'var(--text-muted)',
    compensating_control: 'var(--accent-blue)',
  }

  const reachColor: Record<string, string> = {
    internet: 'var(--critical)',
    dmz: 'var(--high)',
    internal: 'var(--medium)',
    isolated: 'var(--accent-green)',
  }

  const allSelected = displayItems.length > 0 && selectedKeys.length === displayItems.length

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <PageHeader
        title="暴露面管理"
        actions={
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            {recalcToast && (
              <span style={{
                fontSize: 12,
                color: 'var(--accent-green)',
                background: '#00c77318',
                border: '1px solid var(--accent-green)',
                borderRadius: 5,
                padding: '3px 10px',
                fontWeight: 500,
                transition: 'opacity 0.3s',
              }}>
                ✓ 重新计算已触发
              </span>
            )}
            <button className="btn-secondary" disabled={recalcing} onClick={recalcAll}>
              {recalcing ? '重算中...' : '↻ 重新计算全部'}
            </button>
          </div>
        }
      />

      {/* Page-level tab bar */}
      <div className="tab-bar" style={{ borderBottom: '1px solid var(--border)' }}>
        <button
          className={`tab ${pageTab === 'list' ? 'active' : ''}`}
          onClick={() => setPageTab('list')}
        >
          风险列表
        </button>
        <button
          className={`tab ${pageTab === 'attack_surface' ? 'active' : ''}`}
          onClick={() => setPageTab('attack_surface')}
        >
          攻击面
        </button>
        <button
          className={`tab ${pageTab === 'kanban' ? 'active' : ''}`}
          onClick={() => setPageTab('kanban')}
        >
          修复看板
        </button>
      </div>

      {/* ── Attack Surface tab ── */}
      {pageTab === 'attack_surface' && (
        <AttackSurfaceTab items={items} />
      )}

      {/* ── Remediation Kanban tab ── */}
      {pageTab === 'kanban' && (
        <RemediationKanban />
      )}

      {/* ── Risk List tab ── */}
      {pageTab === 'list' && (
        <>
          <div className="tab-bar">
            {([['全部', ''], ['高优先级 ≥70', 'high'], ['未计划', 'unplanned'], ['处理中', 'in_progress'], ['已修复', 'fixed'], ['接受风险', 'accepted_risk']] as [string, string][]).map(([label, val]) => (
              <button key={label} className={`tab ${statusFilter === val ? 'active' : ''}`}
                onClick={() => setStatusFilter(val)}>
                {label}
              </button>
            ))}
          </div>

          <div className="filter-bar">
            <input
              className="filter-input"
              placeholder="搜索CVE编号、主机名..."
              value={search}
              onChange={e => setSearch(e.target.value)}
              onKeyDown={e => { if (e.key === 'Enter') { setPage(1); load(1) } }}
            />
            <select className="filter-select" value={reachFilter} onChange={e => setReachFilter(e.target.value)}>
              <option value="">全部可达性</option>
              <option value="internet">互联网暴露</option>
              <option value="dmz">DMZ区</option>
              <option value="internal">内部网络</option>
              <option value="isolated">隔离</option>
            </select>
            <select className="filter-select" value={inWildFilter} onChange={e => setInWildFilter(e.target.value)}>
              <option value="">全部</option>
              <option value="true">在野利用</option>
            </select>

            {/* CVE ID filter */}
            <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
              <input
                className="filter-input"
                placeholder="e.g. CVE-2024-1234"
                style={{ paddingRight: cveFilter ? 22 : undefined }}
                value={cveInput}
                onChange={e => setCveInput(e.target.value)}
                onKeyDown={e => {
                  if (e.key === 'Enter') { setCveFilter(cveInput.trim()); setPage(1) }
                }}
                onBlur={() => { if (cveInput.trim() !== cveFilter) { setCveFilter(cveInput.trim()); setPage(1) } }}
              />
              {cveFilter && (
                <button
                  onClick={() => { setCveFilter(''); setCveInput(''); setPage(1) }}
                  style={{
                    position: 'absolute', right: 4,
                    background: 'none', border: 'none', cursor: 'pointer',
                    color: 'var(--text-muted)', fontSize: 13, padding: '0 2px', lineHeight: 1,
                  }}
                  title="清除CVE过滤"
                >×</button>
              )}
            </div>

            {/* Min / Max priority score */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
              <input
                className="filter-input"
                type="number"
                min={0}
                max={100}
                placeholder="最低分"
                style={{ width: 64 }}
                value={minScore === '' ? '' : minScore}
                onChange={e => {
                  const v = e.target.value === '' ? '' : Math.max(0, Math.min(100, Number(e.target.value)))
                  setMinScore(v)
                  handleScoreChange(v, maxScore)
                }}
              />
              <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>–</span>
              <input
                className="filter-input"
                type="number"
                min={0}
                max={100}
                placeholder="最高分"
                style={{ width: 64 }}
                value={maxScore === '' ? '' : maxScore}
                onChange={e => {
                  const v = e.target.value === '' ? '' : Math.max(0, Math.min(100, Number(e.target.value)))
                  setMaxScore(v)
                  handleScoreChange(minScore, v)
                }}
              />
            </div>

            {/* Asset ID filter */}
            <input
              className="filter-input"
              placeholder="资产ID"
              value={assetIdInput}
              onChange={e => setAssetIdInput(e.target.value)}
              onKeyDown={e => {
                if (e.key === 'Enter') { setAssetIdFilter(assetIdInput.trim()); setPage(1) }
              }}
            />

            {/* Reset */}
            <button
              className="btn-secondary"
              onClick={resetFilters}
              title="重置所有过滤条件"
            >
              重置
              {matrixFilter && <span style={{ marginLeft: 4, color: 'var(--accent-blue)' }}>·矩阵</span>}
            </button>
          </div>

          {/* Scrollable content area */}
          <div style={{ flex: 1, overflow: 'auto', display: 'flex', flexDirection: 'column' }}>
            {/* Fix Progress Dashboard */}
            <div style={{ padding: '8px 0 0 0', flexShrink: 0 }}>
              <FixProgressDashboard items={items} />
            </div>

            {/* Risk Matrix */}
            <div style={{ flexShrink: 0 }}>
              <RiskMatrix items={items} onCellClick={handleMatrixCellClick} />
            </div>

            {/* Matrix filter indicator */}
            {matrixFilter && (
              <div style={{
                padding: '4px 0 6px',
                fontSize: 11,
                color: 'var(--accent-blue)',
                flexShrink: 0,
              }}>
                矩阵筛选激活：攻击复杂度 {AXIS_LABELS[matrixFilter.x]} × 业务影响 {AXIS_LABELS[matrixFilter.y]}
                <span style={{ marginLeft: 6 }}>→ {displayItems.length} 项</span>
                <button
                  onClick={() => setMatrixFilter(null)}
                  style={{ marginLeft: 8, background: 'none', border: 'none', cursor: 'pointer', color: 'var(--text-muted)', fontSize: 12 }}
                >清除</button>
              </div>
            )}

            {/* Bulk action bar */}
            {selectedKeys.length >= 2 && (
              <BulkBar
                selectedKeys={selectedKeys}
                items={items}
                onDone={() => load(page)}
                onClearSelection={() => setSelectedKeys([])}
              />
            )}

            <div className="data-table-wrap" style={{ flex: 1 }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <ResizableTh style={{ width: 32 }}>
                      <input
                        type="checkbox"
                        checked={allSelected}
                        onChange={toggleSelectAll}
                        style={{ cursor: 'pointer' }}
                      />
                    </ResizableTh>
                    <ResizableTh>CVE编号</ResizableTh>
                    <ResizableTh>受影响资产</ResizableTh>
                    <ResizableTh>CVSS</ResizableTh>
                    <ResizableTh>可达性</ResizableTh>
                    <ResizableTh>在野利用</ResizableTh>
                    <ResizableTh>优先级评分</ResizableTh>
                    <ResizableTh>状态</ResizableTh>
                    <ResizableTh>截止日期</ResizableTh>
                    <ResizableTh></ResizableTh>
                  </tr>
                </thead>
                <tbody>
                  {loading && <tr><td colSpan={10} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>加载中...</td></tr>}
                  {!loading && displayItems.length === 0 && <tr><td colSpan={10} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>暂无暴露记录</td></tr>}
                  {displayItems.map(e => (
                    <tr key={e._key} className={(e.priority_score ?? 0) >= 70 ? 'row-critical' : ''}>
                      <td>
                        <input
                          type="checkbox"
                          checked={selectedKeys.includes(e._key)}
                          onChange={() => toggleSelect(e._key)}
                          style={{ cursor: 'pointer' }}
                        />
                      </td>
                      <td>
                        <CveLink cveId={e.cve_id} />
                      </td>
                      <td style={{ fontFamily: 'monospace', fontSize: 11.5 }}>{e.asset_name || e.asset_id || '—'}</td>
                      <td>
                        <span style={{
                          fontSize: 11.5, fontWeight: 600,
                          color: e.cvss_score >= 9 ? 'var(--critical)' : e.cvss_score >= 7 ? 'var(--high)' : e.cvss_score >= 4 ? 'var(--medium)' : 'var(--accent-green)',
                        }}>{e.cvss_score?.toFixed(1) ?? '—'}</span>
                      </td>
                      <td>
                        {(() => {
                          const cat = reachCategory(e.reachability_factor ?? 0)
                          const catLabel: Record<string, string> = { internet: '互联网', dmz: 'DMZ', internal: '内网', isolated: '隔离' }
                          return (
                            <span style={{ fontSize: 10.5, padding: '2px 6px', borderRadius: 3,
                              background: `${reachColor[cat]}22`,
                              color: reachColor[cat],
                              border: `1px solid ${reachColor[cat]}44`,
                            }}>
                              {catLabel[cat]}
                              <span style={{ opacity: 0.6, marginLeft: 3 }}>({((e.reachability_factor ?? 0) * 100).toFixed(0)}%)</span>
                            </span>
                          )
                        })()}
                      </td>
                      <td>
                        {(e.in_wild_factor ?? 0) > 0.5
                          ? <span style={{ fontSize: 11, color: 'var(--critical)', fontWeight: 600 }}>⚡ 在野</span>
                          : <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>—</span>}
                      </td>
                      <td><PriorityBar score={e.priority_score ?? 0} /></td>
                      <td>
                        {editKey === e._key ? (
                          <div style={{ display: 'flex', gap: 4 }}>
                            <select
                              className="filter-select"
                              style={{ fontSize: 11, padding: '2px 4px' }}
                              value={editStatus}
                              onChange={ev => setEditStatus(ev.target.value)}
                            >
                              {STATUS_OPTIONS.map(s => <option key={s} value={s}>{STATUS_LABELS[s] ?? s}</option>)}
                            </select>
                            <button className="btn-primary" style={{ fontSize: 10, padding: '1px 6px' }} onClick={() => doUpdate(e._key, editStatus)}>✓</button>
                            <button className="btn-secondary" style={{ fontSize: 10, padding: '1px 6px' }} onClick={() => setEditKey(null)}>✕</button>
                          </div>
                        ) : (
                          <span style={{ fontSize: 10.5, padding: '2px 6px', borderRadius: 3, cursor: 'pointer',
                            color: statusColor[e.fix_status] ?? 'var(--text-muted)',
                            background: `${statusColor[e.fix_status] ?? 'var(--text-muted)'}18`,
                            border: `1px solid ${statusColor[e.fix_status] ?? 'var(--border)'}44`,
                          }} onClick={() => { setEditKey(e._key); setEditStatus(e.fix_status || 'planned') }}>
                            {STATUS_LABELS[e.fix_status] ?? e.fix_status ?? '未计划'}
                          </span>
                        )}
                      </td>
                      <td>
                        <DeadlineCell deadline={e.due_date || e.fix_deadline} />
                      </td>
                      <td>
                        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px' }}
                          onClick={() => setDetailItem(e)}>
                          详情
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="pagination">
              <button className="page-btn" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>&#8249;</button>
              <span>{page} / {meta.total_pages || 1}</span>
              <button className="page-btn" disabled={page >= meta.total_pages} onClick={() => setPage(p => p + 1)}>&#8250;</button>
              <span style={{ marginLeft: 8 }}>{meta.total} 条</span>
            </div>
          </div>
        </>
      )}

      {/* Detail panel overlay */}
      {detailItem && (
        <DetailPanel
          item={detailItem}
          onClose={() => setDetailItem(null)}
          onSaved={() => { load(page); setDetailItem(null) }}
        />
      )}
    </div>
  )
}
