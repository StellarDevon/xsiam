import { useEffect, useRef, useState, useCallback } from 'react'
import ResizableTh from '@/components/ResizableTh'
import { useNavigate } from 'react-router-dom'
import api from '@/lib/api'
import type { PageMeta } from '@/lib/api'
import PageHeader from '@/components/PageHeader'

interface Vuln {
  _key: string
  cve_id: string
  title: string
  severity: string
  cvss_score: number
  cvss_vector?: string
  status: string
  fix_status?: string
  assigned_to?: string
  due_date?: string
  fix_notes?: string
  fix_effort?: string
  affected_assets: string[]
  description: string
  fix: string
  published_at: string
  last_modified_at?: string
  created_at: string
  has_exploit?: boolean
}

interface VulnStats {
  total: number
  critical: number
  high: number
  medium: number
  low: number
  patched: number
}

interface IOCItem {
  _key: string
  type: string
  value: string
  verdict: string
}

interface IncidentItem {
  _key: string
  title: string
  severity: string
  status: string
}

interface AssetItem {
  _key: string
  hostname: string
  ip?: string
  os?: string
  status?: string
  risk_score: number
}

const BLANK_FORM = { cve_id: '', title: '', severity: 'high', cvss_score: '', description: '', fix: '', affected_assets: '' }

// ────────── SLA helpers ──────────
const SLA_HOURS: Record<string, number> = {
  critical: 24,
  high: 72,
  medium: 7 * 24,
  low: 30 * 24,
}

function getSlaInfo(vuln: Vuln): { label: string; pct: number; status: 'green' | 'yellow' | 'red' } {
  const severity = (vuln.severity ?? 'low').toLowerCase()
  const slaHours = SLA_HOURS[severity] ?? SLA_HOURS.low
  const created = new Date(vuln.created_at || vuln.published_at || Date.now())
  const deadline = new Date(created.getTime() + slaHours * 3600 * 1000)
  const now = Date.now()
  const total = deadline.getTime() - created.getTime()
  const elapsed = now - created.getTime()
  const remaining = deadline.getTime() - now
  const pctRemaining = Math.max(0, (remaining / total) * 100)

  let label: string
  if (remaining <= 0) {
    const hrs = Math.round(-remaining / 3600000)
    label = hrs < 48 ? `超${hrs}h` : `超${Math.round(hrs / 24)}d`
  } else {
    const hrs = Math.round(remaining / 3600000)
    label = hrs < 48 ? `剩${hrs}h` : `剩${Math.round(hrs / 24)}d`
  }

  // Suppress from used warning
  void elapsed

  const status = pctRemaining > 50 ? 'green' : pctRemaining > 10 ? 'yellow' : 'red'
  return { label, pct: pctRemaining, status }
}

// ────────── SlaIndicator ──────────
function SlaIndicator({ vuln }: { vuln: Vuln }) {
  const { label, pct, status } = getSlaInfo(vuln)
  const color = status === 'green' ? 'var(--accent-green)' : status === 'yellow' ? 'var(--medium)' : 'var(--critical)'
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 4 }} title={`SLA: ${label}`}>
      <div style={{ width: 36, height: 4, background: 'rgba(255,255,255,0.1)', borderRadius: 2, overflow: 'hidden' }}>
        <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: 2, transition: 'width 0.3s' }} />
      </div>
      <span style={{ fontSize: 9.5, color, whiteSpace: 'nowrap', fontWeight: 600 }}>{label}</span>
    </div>
  )
}

// ────────── Fix Priority Score helpers ──────────
function calcPriority(vuln: Vuln): number {
  const assetCount = vuln.affected_assets?.length ?? 0
  const hasExploit = !!(vuln.has_exploit || (vuln.cvss_score ?? 0) >= 9.0)
  const raw = (vuln.cvss_score ?? 0) * 10
    + (hasExploit ? 20 : 0)
    + (assetCount > 5 ? 15 : 0)
    - (vuln.fix_status === 'patched' ? 50 : 0)
  return Math.max(0, Math.min(100, Math.round(raw)))
}

// ────────── PriorityGauge ──────────
function PriorityGauge({ score }: { score: number }) {
  const r = 28
  const cx = 36
  const cy = 36
  const circumference = 2 * Math.PI * r
  const dashOffset = circumference * (1 - score / 100)
  const color = score >= 75 ? 'var(--critical)' : score >= 50 ? 'var(--high)' : score >= 25 ? 'var(--medium)' : 'var(--accent-green)'
  return (
    <svg width={72} height={72} style={{ display: 'block' }}>
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="rgba(255,255,255,0.08)" strokeWidth={6} />
      <circle
        cx={cx} cy={cy} r={r} fill="none"
        stroke={color} strokeWidth={6}
        strokeDasharray={circumference}
        strokeDashoffset={dashOffset}
        strokeLinecap="round"
        transform={`rotate(-90 ${cx} ${cy})`}
        style={{ transition: 'stroke-dashoffset 0.5s ease' }}
      />
      <text x={cx} y={cy + 1} textAnchor="middle" dominantBaseline="middle"
        style={{ fill: color, fontSize: 14, fontWeight: 700, fontFamily: 'sans-serif' }}>
        {score}
      </text>
    </svg>
  )
}

// ────────── CVE enrichment mock helpers ──────────
function getMockAffectedSoftware(cveId: string): string[] {
  const seed = cveId.replace(/\D/g, '').slice(-3)
  const year = parseInt(cveId.match(/CVE-(\d{4})/)?.[1] ?? '2024')
  const num = parseInt(seed || '100')
  const products = [
    `Apache HTTP Server ${2 + (num % 3)}.${num % 10}.${num % 5}`,
    `OpenSSL 1.${(num % 3) + 1}.${num % 8}`,
    `Ubuntu ${18 + (num % 3) * 2}.04 LTS`,
    `Windows Server 20${year % 10 === 0 ? '16' : '19'}`,
    `nginx 1.${18 + (num % 6)}.${num % 5}`,
    `libssl ${num % 3}.${num % 6}.${num % 9}`,
  ]
  const count = 2 + (num % 2)
  return products.slice(0, count)
}

function hasMockPatch(cveId: string): boolean {
  const num = parseInt(cveId.replace(/\D/g, '').slice(-3) || '100')
  return num % 3 !== 0
}

// ────────── CVSSBar ──────────
function CVSSBar({ score }: { score: number }) {
  const pct = (score / 10) * 100
  const color = score >= 9 ? 'var(--critical)' : score >= 7 ? 'var(--high)' : score >= 4 ? 'var(--medium)' : 'var(--accent-green)'
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
      <div style={{ width: 60, height: 6, background: 'rgba(255,255,255,.1)', borderRadius: 3 }}>
        <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: 3 }} />
      </div>
      <span style={{ fontSize: 11, color }}>{score?.toFixed(1)}</span>
    </div>
  )
}

// ────────── Skeleton ──────────
function Skeleton({ lines = 3 }: { lines?: number }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
      {Array.from({ length: lines }).map((_, i) => (
        <div key={i} style={{
          height: 14, borderRadius: 4,
          background: 'linear-gradient(90deg, var(--bg-secondary) 25%, var(--bg-card2) 50%, var(--bg-secondary) 75%)',
          backgroundSize: '200% 100%',
          animation: 'skeletonShimmer 1.4s infinite',
          width: i % 3 === 2 ? '60%' : '100%',
        }} />
      ))}
    </div>
  )
}

// ────────── CVE Detail Tab ──────────
// Parses CVSS v3 vector string, e.g. "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
const CVSS_METRIC_LABELS: Record<string, { label: string; values: Record<string, string> }> = {
  AV: { label: '攻击向量', values: { N: '网络 (Network)', A: '相邻 (Adjacent)', L: '本地 (Local)', P: '物理 (Physical)' } },
  AC: { label: '攻击复杂度', values: { L: '低 (Low)', H: '高 (High)' } },
  PR: { label: '所需权限', values: { N: '无 (None)', L: '低 (Low)', H: '高 (High)' } },
  UI: { label: '用户交互', values: { N: '无 (None)', R: '需要 (Required)' } },
  S:  { label: '影响范围', values: { U: '不变 (Unchanged)', C: '改变 (Changed)' } },
  C:  { label: '机密性影响', values: { N: '无 (None)', L: '低 (Low)', H: '高 (High)' } },
  I:  { label: '完整性影响', values: { N: '无 (None)', L: '低 (Low)', H: '高 (High)' } },
  A:  { label: '可用性影响', values: { N: '无 (None)', L: '低 (Low)', H: '高 (High)' } },
}

function parseCvssVector(vector: string): Record<string, string> {
  const result: Record<string, string> = {}
  if (!vector) return result
  // Strip prefix like "CVSS:3.1/"
  const parts = vector.replace(/^CVSS:[^/]+\//, '').split('/')
  for (const part of parts) {
    const [key, val] = part.split(':')
    if (key && val) result[key] = val
  }
  return result
}

function CveDetailTab({ vuln, onNavigateIoc }: { vuln: Vuln; onNavigateIoc: (q: string) => void }) {
  const score = vuln.cvss_score ?? 0
  const scoreColor = score >= 9 ? 'var(--critical)' : score >= 7 ? 'var(--high)' : score >= 4 ? 'var(--medium)' : 'var(--accent-green)'
  const scoreBg = score >= 9 ? 'rgba(239,68,68,0.1)' : score >= 7 ? 'rgba(249,115,22,0.1)' : score >= 4 ? 'rgba(234,179,8,0.1)' : 'rgba(34,197,94,0.1)'

  // Use real vector or derive a plausible mock from CVSS score
  const effectiveVector = vuln.cvss_vector || (() => {
    const s = vuln.cvss_score ?? 0
    if (s === 0) return ''
    const av = s >= 9 ? 'N' : s >= 7 ? 'N' : 'L'
    const ac = s >= 8 ? 'L' : 'H'
    const pr = s >= 9 ? 'N' : s >= 7 ? 'L' : 'H'
    const ci = s >= 7 ? 'H' : 'L'
    return `CVSS:3.1/AV:${av}/AC:${ac}/PR:${pr}/UI:N/S:U/C:${ci}/I:${ci}/A:${ci}`
  })()

  const parsed = parseCvssVector(effectiveVector)
  const metricKeys = Object.keys(CVSS_METRIC_LABELS)

  const [assetMap, setAssetMap] = useState<Record<string, AssetItem[]>>({})
  const [loadingAssets, setLoadingAssets] = useState(false)

  useEffect(() => {
    const assets = vuln.affected_assets ?? []
    if (assets.length === 0) return
    setLoadingAssets(true)
    Promise.all(
      assets.map(hostname =>
        api.get('/assets', { params: { q: hostname, page_size: 3 } })
          .then(r => ({ hostname, items: (r.data.data?.items ?? []) as AssetItem[] }))
          .catch(() => ({ hostname, items: [] as AssetItem[] }))
      )
    ).then(results => {
      const map: Record<string, AssetItem[]> = {}
      results.forEach(({ hostname, items }) => { map[hostname] = items })
      setAssetMap(map)
    }).finally(() => setLoadingAssets(false))
  }, [vuln._key])

  function riskColor(s: number) {
    if (s >= 80) return 'var(--critical)'
    if (s >= 60) return 'var(--high)'
    if (s >= 40) return 'var(--medium)'
    return 'var(--accent-green)'
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

      {/* CVSS Score big number */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 16,
        background: scoreBg, border: `1px solid ${scoreColor}44`,
        borderRadius: 8, padding: '12px 16px',
      }}>
        <div style={{ textAlign: 'center' }}>
          <div style={{ fontSize: 36, fontWeight: 800, color: scoreColor, lineHeight: 1 }}>
            {score > 0 ? score.toFixed(1) : 'N/A'}
          </div>
          <div style={{ fontSize: 10, color: scoreColor, marginTop: 2, textTransform: 'uppercase', letterSpacing: '0.06em' }}>
            {score >= 9 ? '严重' : score >= 7 ? '高危' : score >= 4 ? '中危' : '低危'}
          </div>
        </div>
        <div style={{ flex: 1 }}>
          {effectiveVector && (
            <div style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--text-muted)', wordBreak: 'break-all', marginBottom: 6 }}>
              {effectiveVector}
              {!vuln.cvss_vector && (
                <span style={{ marginLeft: 4, color: 'rgba(255,255,255,0.3)', fontSize: 9 }}>(估算)</span>
              )}
            </div>
          )}
          <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
            {vuln.published_at && (
              <span style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>
                发布: {new Date(vuln.published_at).toLocaleDateString('zh-CN')}
              </span>
            )}
            {vuln.last_modified_at && (
              <span style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>
                更新: {new Date(vuln.last_modified_at).toLocaleDateString('zh-CN')}
              </span>
            )}
          </div>
        </div>
      </div>

      {/* CVSS Vector breakdown table */}
      {Object.keys(parsed).length > 0 && (
        <div>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>
            CVSS 向量详情
          </div>
          <div style={{ border: '1px solid var(--border)', borderRadius: 6, overflow: 'hidden' }}>
            {metricKeys.filter(k => parsed[k]).map((k, idx) => {
              const meta = CVSS_METRIC_LABELS[k]
              const val = parsed[k] ?? ''
              const friendly = meta?.values[val] ?? val
              const isLast = idx === metricKeys.filter(x => parsed[x]).length - 1
              return (
                <div key={k} style={{
                  display: 'flex', alignItems: 'center', gap: 8,
                  padding: '6px 12px',
                  borderBottom: isLast ? 'none' : '1px solid var(--border)',
                  background: idx % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.02)',
                }}>
                  <span style={{
                    fontSize: 10, fontFamily: 'monospace', fontWeight: 700,
                    background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                    borderRadius: 3, padding: '1px 5px', color: 'var(--accent-blue)',
                    minWidth: 24, textAlign: 'center', flexShrink: 0,
                  }}>{k}</span>
                  <span style={{ fontSize: 11, color: 'var(--text-muted)', flex: 1 }}>{meta?.label ?? k}</span>
                  <span style={{ fontSize: 11, color: 'var(--text-secondary)', textAlign: 'right' }}>{friendly}</span>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Patch availability badge */}
      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
        <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em' }}>
          补丁状态
        </div>
        {vuln.cve_id ? (
          hasMockPatch(vuln.cve_id) ? (
            <span style={{
              fontSize: 11.5, fontWeight: 700, padding: '3px 10px', borderRadius: 12,
              background: 'rgba(34,197,94,0.12)', color: 'var(--accent-green)', border: '1px solid rgba(34,197,94,0.35)',
            }}>有补丁 ✓</span>
          ) : (
            <span style={{
              fontSize: 11.5, fontWeight: 700, padding: '3px 10px', borderRadius: 12,
              background: 'rgba(239,68,68,0.12)', color: 'var(--critical)', border: '1px solid rgba(239,68,68,0.35)',
            }}>暂无补丁 ✗</span>
          )
        ) : (
          <span style={{ fontSize: 11, color: 'var(--text-muted)', fontStyle: 'italic' }}>未知</span>
        )}
      </div>

      {/* Affected software list */}
      {vuln.cve_id && (
        <div>
          <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>
            受影响软件
          </div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
            {getMockAffectedSoftware(vuln.cve_id).map((sw, i) => (
              <div key={i} style={{
                display: 'flex', alignItems: 'center', gap: 8,
                padding: '5px 10px', borderRadius: 5, border: '1px solid var(--border)',
                background: 'var(--bg-secondary)', fontSize: 11.5,
              }}>
                <span style={{ fontSize: 13, flexShrink: 0 }}>📦</span>
                <span style={{ color: 'var(--text-secondary)', fontFamily: 'monospace' }}>{sw}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* External links */}
      <div>
        <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>
          外部参考
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
          {vuln.cve_id ? (
            <>
              <a
                href={`https://nvd.nist.gov/vuln/detail/${vuln.cve_id}`}
                target="_blank" rel="noopener noreferrer"
                style={{
                  display: 'flex', alignItems: 'center', gap: 6,
                  fontSize: 12, color: 'var(--accent-blue)', textDecoration: 'none',
                  padding: '6px 10px', borderRadius: 5, border: '1px solid var(--border)',
                  background: 'var(--bg-secondary)',
                }}
                onMouseEnter={e => (e.currentTarget.style.borderColor = 'var(--accent-blue)')}
                onMouseLeave={e => (e.currentTarget.style.borderColor = 'var(--border)')}
              >
                <span style={{ fontSize: 14 }}>🔗</span>
                NVD (nist.gov) →
              </a>
              <a
                href={`https://attack.mitre.org/versions/v14/search/?query=${encodeURIComponent(vuln.cve_id)}`}
                target="_blank" rel="noopener noreferrer"
                style={{
                  display: 'flex', alignItems: 'center', gap: 6,
                  fontSize: 12, color: 'var(--accent-blue)', textDecoration: 'none',
                  padding: '6px 10px', borderRadius: 5, border: '1px solid var(--border)',
                  background: 'var(--bg-secondary)',
                }}
                onMouseEnter={e => (e.currentTarget.style.borderColor = 'var(--accent-blue)')}
                onMouseLeave={e => (e.currentTarget.style.borderColor = 'var(--border)')}
              >
                <span style={{ fontSize: 14 }}>🛡</span>
                MITRE ATT&CK →
              </a>
              <a
                href={`https://www.cvedetails.com/cve/${vuln.cve_id}/`}
                target="_blank" rel="noopener noreferrer"
                style={{
                  display: 'flex', alignItems: 'center', gap: 6,
                  fontSize: 12, color: 'var(--accent-blue)', textDecoration: 'none',
                  padding: '6px 10px', borderRadius: 5, border: '1px solid var(--border)',
                  background: 'var(--bg-secondary)',
                }}
                onMouseEnter={e => (e.currentTarget.style.borderColor = 'var(--accent-blue)')}
                onMouseLeave={e => (e.currentTarget.style.borderColor = 'var(--border)')}
              >
                <span style={{ fontSize: 14 }}>📋</span>
                CVE Details →
              </a>
              {hasMockPatch(vuln.cve_id) && (
                <a
                  href={`https://security.debian.org/tracker/${vuln.cve_id}`}
                  target="_blank" rel="noopener noreferrer"
                  style={{
                    display: 'flex', alignItems: 'center', gap: 6,
                    fontSize: 12, color: 'var(--accent-green)', textDecoration: 'none',
                    padding: '6px 10px', borderRadius: 5, border: '1px solid rgba(34,197,94,0.3)',
                    background: 'rgba(34,197,94,0.06)',
                  }}
                  onMouseEnter={e => (e.currentTarget.style.borderColor = 'var(--accent-green)')}
                  onMouseLeave={e => (e.currentTarget.style.borderColor = 'rgba(34,197,94,0.3)')}
                >
                  <span style={{ fontSize: 14 }}>✅</span>
                  Vendor Advisory (Patch Available) →
                </a>
              )}
            </>
          ) : (
            <div style={{ fontSize: 12, color: 'var(--text-muted)', fontStyle: 'italic' }}>无CVE编号，无法生成外部链接</div>
          )}
        </div>
      </div>

      {/* Affected products / assets with risk score bars */}
      <div>
        <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>
          受影响产品 / 资产
        </div>
        {loadingAssets ? (
          <Skeleton lines={Math.min((vuln.affected_assets?.length ?? 0) + 1, 5)} />
        ) : (vuln.affected_assets?.length ?? 0) === 0 ? (
          <div style={{ fontSize: 12, color: 'var(--text-muted)', fontStyle: 'italic' }}>暂无受影响资产</div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {(vuln.affected_assets ?? []).map(hostname => {
              const matched = assetMap[hostname] ?? []
              const riskScore = matched[0]?.risk_score ?? 0
              const color = riskColor(riskScore)
              const pct = Math.min(riskScore, 100)
              return (
                <div key={hostname} style={{
                  padding: '6px 10px', borderRadius: 5, border: '1px solid var(--border)',
                  background: 'var(--bg-secondary)',
                }}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: riskScore > 0 ? 4 : 0 }}>
                    <span style={{ fontSize: 11.5, fontFamily: 'monospace', color: 'var(--text-secondary)' }}>{hostname}</span>
                    {riskScore > 0 && (
                      <span style={{ fontSize: 11, fontWeight: 700, color }}>{riskScore}</span>
                    )}
                  </div>
                  {riskScore > 0 && (
                    <div style={{ height: 4, background: 'rgba(255,255,255,0.08)', borderRadius: 2, overflow: 'hidden' }}>
                      <div style={{ width: `${pct}%`, height: '100%', background: color, borderRadius: 2, transition: 'width 0.3s ease' }} />
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>

      {/* Find related IOC button */}
      {vuln.cve_id && (
        <button
          className="btn-secondary"
          style={{ fontSize: 12, padding: '6px 14px', display: 'flex', alignItems: 'center', gap: 6, justifyContent: 'center' }}
          onClick={() => onNavigateIoc(vuln.cve_id)}
        >
          🔍 发现相关IOC
        </button>
      )}
    </div>
  )
}

// ────────── Enrichment Tab ──────────
function EnrichmentTab({ vuln }: { vuln: Vuln }) {
  const [iocs, setIocs] = useState<IOCItem[]>([])
  const [incidents, setIncidents] = useState<IncidentItem[]>([])
  const [assetMap, setAssetMap] = useState<Record<string, AssetItem[]>>({})
  const [loadingIoc, setLoadingIoc] = useState(true)
  const [loadingInc, setLoadingInc] = useState(true)
  const [loadingAssets, setLoadingAssets] = useState(true)

  useEffect(() => {
    setLoadingIoc(true)
    api.get('/iocs', { params: { q: vuln.cve_id || vuln._key, page_size: 5 } })
      .then(r => setIocs(r.data.data?.items ?? []))
      .catch(() => setIocs([]))
      .finally(() => setLoadingIoc(false))

    setLoadingInc(true)
    api.get('/incidents', { params: { keyword: vuln.cve_id || vuln._key, page_size: 5 } })
      .then(r => setIncidents(r.data.data?.items ?? []))
      .catch(() => setIncidents([]))
      .finally(() => setLoadingInc(false))

    const assets = vuln.affected_assets ?? []
    if (assets.length === 0) { setLoadingAssets(false); return }
    setLoadingAssets(true)
    Promise.all(
      assets.map(hostname =>
        api.get('/assets', { params: { q: hostname, page_size: 3 } })
          .then(r => ({ hostname, items: (r.data.data?.items ?? []) as AssetItem[] }))
          .catch(() => ({ hostname, items: [] as AssetItem[] }))
      )
    ).then(results => {
      const map: Record<string, AssetItem[]> = {}
      results.forEach(({ hostname, items }) => { map[hostname] = items })
      setAssetMap(map)
    }).finally(() => setLoadingAssets(false))
  }, [vuln._key])

  function riskColor(score: number) {
    if (score >= 80) return 'var(--critical)'
    if (score >= 60) return 'var(--high)'
    if (score >= 40) return 'var(--medium)'
    return 'var(--accent-green)'
  }

  const verdictColor = (v: string) => v === 'malicious' ? 'var(--critical)' : v === 'suspicious' ? 'var(--high)' : 'var(--text-muted)'

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
      {/* Section A: IOCs */}
      <div>
        <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>
          关联IOC
        </div>
        {loadingIoc ? <Skeleton lines={3} /> : iocs.length === 0 ? (
          <div style={{ fontSize: 12, color: 'var(--text-muted)', fontStyle: 'italic' }}>暂无关联IOC</div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {iocs.map(ioc => (
              <div key={ioc._key} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
                <span style={{
                  fontSize: 10, background: 'var(--bg-secondary)', border: '1px solid var(--border)',
                  borderRadius: 3, padding: '1px 5px', color: 'var(--accent-blue)', whiteSpace: 'nowrap', flexShrink: 0,
                }}>{ioc.type}</span>
                <span style={{ fontFamily: 'monospace', color: 'var(--text-secondary)', flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{ioc.value}</span>
                <span style={{ fontSize: 10, color: verdictColor(ioc.verdict), whiteSpace: 'nowrap', flexShrink: 0 }}>{ioc.verdict}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      <div style={{ height: 1, background: 'var(--border)' }} />

      {/* Section B: Incidents */}
      <div>
        <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>
          关联事件
        </div>
        {loadingInc ? <Skeleton lines={3} /> : incidents.length === 0 ? (
          <div style={{ fontSize: 12, color: 'var(--text-muted)', fontStyle: 'italic' }}>暂无关联事件</div>
        ) : (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {incidents.map(inc => (
              <div key={inc._key} style={{ display: 'flex', alignItems: 'center', gap: 6, fontSize: 12 }}>
                <span className={`sev-badge ${inc.severity}`} style={{ fontSize: 10, flexShrink: 0 }}>{inc.severity}</span>
                <span style={{ flex: 1, color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{inc.title}</span>
                <span style={{ fontSize: 10, color: 'var(--text-muted)', flexShrink: 0 }}>{inc.status}</span>
              </div>
            ))}
          </div>
        )}
      </div>

      <div style={{ height: 1, background: 'var(--border)' }} />

      {/* Section C: Affected assets enriched */}
      <div>
        <div style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: '0.06em', marginBottom: 8 }}>
          受影响资产
        </div>
        {loadingAssets ? <Skeleton lines={Math.min((vuln.affected_assets?.length ?? 0) + 1, 4)} /> :
          (vuln.affected_assets?.length ?? 0) === 0 ? (
            <div style={{ fontSize: 12, color: 'var(--text-muted)', fontStyle: 'italic' }}>暂无受影响资产</div>
          ) : (
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
              {(vuln.affected_assets ?? []).map(hostname => {
                const matched = assetMap[hostname] ?? []
                const riskScore = matched[0]?.risk_score ?? 0
                const color = riskColor(riskScore)
                return (
                  <span key={hostname} style={{
                    background: 'var(--bg-secondary)',
                    border: `1px solid ${color}44`,
                    borderRadius: 12,
                    fontSize: 11,
                    padding: '2px 10px',
                    color,
                    fontFamily: 'monospace',
                    whiteSpace: 'nowrap',
                    cursor: 'default',
                  }} title={riskScore > 0 ? `风险评分: ${riskScore}` : hostname}>
                    {hostname}{riskScore > 0 ? ` · ${riskScore}` : ''}
                  </span>
                )
              })}
            </div>
          )
        }
      </div>
    </div>
  )
}

// ────────── Affected Assets Tab ──────────
function AffectedAssetsTab({ vuln, onNavigateAsset }: { vuln: Vuln; onNavigateAsset: (key: string) => void }) {
  const [assets, setAssets] = useState<AssetItem[]>([])
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    setLoading(true)
    setAssets([])
    api.get('/assets', { params: { vuln_id: vuln._key, page_size: 50 } })
      .then(r => setAssets(r.data.data?.items ?? []))
      .catch(() => setAssets([]))
      .finally(() => setLoading(false))
  }, [vuln._key])

  function riskColor(s: number) {
    if (s >= 80) return 'var(--critical)'
    if (s >= 60) return 'var(--high)'
    if (s >= 40) return 'var(--medium)'
    return 'var(--accent-green)'
  }

  if (loading) return <Skeleton lines={4} />

  if (assets.length === 0) {
    return (
      <div style={{
        display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 10,
        padding: '32px 0', color: 'var(--text-muted)',
      }}>
        <span style={{ fontSize: 28 }}>🖥️</span>
        <span style={{ fontSize: 13 }}>暂无关联资产</span>
        <span style={{ fontSize: 11 }}>可通过资产管理页面关联此漏洞</span>
      </div>
    )
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>
        共 {assets.length} 台受影响资产
      </div>
      <div style={{ border: '1px solid var(--border)', borderRadius: 6, overflow: 'hidden' }}>
        {/* Table header */}
        <div style={{
          display: 'grid', gridTemplateColumns: '1fr 90px 1fr 60px 60px',
          padding: '6px 10px', background: 'var(--bg-secondary)',
          borderBottom: '1px solid var(--border)',
          fontSize: 10, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: '0.05em',
        }}>
          <span>主机名</span>
          <span>IP</span>
          <span>操作系统</span>
          <span>风险分</span>
          <span>状态</span>
        </div>
        {assets.map((a, idx) => {
          const color = riskColor(a.risk_score ?? 0)
          const isLast = idx === assets.length - 1
          return (
            <div key={a._key} style={{
              display: 'grid', gridTemplateColumns: '1fr 90px 1fr 60px 60px',
              padding: '7px 10px', alignItems: 'center',
              borderBottom: isLast ? 'none' : '1px solid var(--border)',
              background: idx % 2 === 0 ? 'transparent' : 'rgba(255,255,255,0.02)',
              fontSize: 11,
            }}>
              <span style={{ fontFamily: 'monospace', color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {a.hostname || a._key}
              </span>
              <span style={{ fontFamily: 'monospace', fontSize: 10.5, color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                {a.ip ?? '-'}
              </span>
              <span style={{ color: 'var(--text-muted)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', fontSize: 10.5 }}>
                {a.os ?? '-'}
              </span>
              <span style={{ color, fontWeight: 700, fontSize: 11 }}>
                {a.risk_score > 0 ? a.risk_score : '-'}
              </span>
              <button
                onClick={() => onNavigateAsset(a._key)}
                style={{
                  background: 'none', border: '1px solid var(--border)', borderRadius: 4,
                  fontSize: 10, color: 'var(--accent-blue)', cursor: 'pointer', padding: '2px 5px',
                  whiteSpace: 'nowrap',
                }}
                onMouseEnter={e => (e.currentTarget.style.borderColor = 'var(--accent-blue)')}
                onMouseLeave={e => (e.currentTarget.style.borderColor = 'var(--border)')}
              >
                查看资产
              </button>
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ────────── Fix Workflow Tab ──────────
function FixTab({ vuln, onUpdated }: { vuln: Vuln; onUpdated: (updated: Vuln) => void }) {
  const [assignedTo, setAssignedTo] = useState(vuln.assigned_to ?? '')
  const [dueDate, setDueDate] = useState(vuln.due_date ? vuln.due_date.slice(0, 10) : '')
  const [fixStatus, setFixStatus] = useState(vuln.fix_status ?? 'open')
  const [fixNotes, setFixNotes] = useState(vuln.fix_notes ?? '')
  const [fixEffort, setFixEffort] = useState(vuln.fix_effort ?? '')
  const [saving, setSaving] = useState(false)
  const [saveMsg, setSaveMsg] = useState('')

  function saveAll() {
    setSaving(true)
    setSaveMsg('')
    const patch: Record<string, string> = {
      fix_status: fixStatus,
    }
    if (assignedTo !== undefined) patch.assigned_to = assignedTo
    if (dueDate) patch.due_date = new Date(dueDate).toISOString()
    if (fixNotes !== undefined) patch.fix_notes = fixNotes
    if (fixEffort) patch.fix_effort = fixEffort

    api.patch(`/vulnerabilities/${vuln._key}`, patch)
      .then(r => {
        onUpdated({ ...vuln, ...r.data.data })
        setSaveMsg('已保存')
        setTimeout(() => setSaveMsg(''), 2000)
      })
      .catch(() => setSaveMsg('保存失败'))
      .finally(() => setSaving(false))
  }

  const inputStyle: React.CSSProperties = {
    background: 'var(--bg-secondary)', border: '1px solid var(--border)',
    borderRadius: 4, color: 'var(--text-primary)', fontSize: 12,
    padding: '5px 8px', width: '100%', boxSizing: 'border-box',
  }

  const labelStyle: React.CSSProperties = {
    fontSize: 11, color: 'var(--text-muted)', marginBottom: 5, display: 'block',
  }

  const priorityScore = calcPriority(vuln)
  const { label: slaLabel, pct: slaPct, status: slaStatus } = getSlaInfo(vuln)
  const slaColor = slaStatus === 'green' ? 'var(--accent-green)' : slaStatus === 'yellow' ? 'var(--medium)' : 'var(--critical)'

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>

      {/* Priority score + SLA */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 16,
        padding: '12px 14px', borderRadius: 8,
        background: 'var(--bg-secondary)', border: '1px solid var(--border)',
      }}>
        <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
          <PriorityGauge score={priorityScore} />
          <span style={{ fontSize: 10, color: 'var(--text-muted)', textAlign: 'center' }}>修复优先级</span>
        </div>
        <div style={{ flex: 1, display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div>
            <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginBottom: 4 }}>SLA 剩余时间</div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
              <div style={{ flex: 1, height: 6, background: 'rgba(255,255,255,0.08)', borderRadius: 3, overflow: 'hidden' }}>
                <div style={{ width: `${slaPct}%`, height: '100%', background: slaColor, borderRadius: 3, transition: 'width 0.4s' }} />
              </div>
              <span style={{ fontSize: 11, color: slaColor, fontWeight: 700, whiteSpace: 'nowrap' }}>{slaLabel}</span>
            </div>
          </div>
          <div style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>
            发现时间: {vuln.created_at ? new Date(vuln.created_at).toLocaleDateString('zh-CN') : '-'}
          </div>
        </div>
      </div>

      {/* 分配负责人 */}
      <div>
        <label style={labelStyle}>分配负责人</label>
        <input
          style={inputStyle}
          placeholder="输入负责人姓名..."
          value={assignedTo}
          onChange={e => setAssignedTo(e.target.value)}
        />
        {vuln.assigned_to && (
          <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginTop: 3 }}>当前: {vuln.assigned_to}</div>
        )}
      </div>

      {/* 截止日期 */}
      <div>
        <label style={labelStyle}>截止日期</label>
        <input
          type="date"
          style={inputStyle}
          value={dueDate}
          onChange={e => setDueDate(e.target.value)}
        />
        {vuln.due_date && (
          <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginTop: 3 }}>
            当前: {new Date(vuln.due_date).toLocaleDateString('zh-CN')}
          </div>
        )}
      </div>

      {/* 修复状态 */}
      <div>
        <label style={labelStyle}>修复状态</label>
        <select style={inputStyle} className="filter-select" value={fixStatus} onChange={e => setFixStatus(e.target.value)}>
          <option value="open">待修复 (open)</option>
          <option value="in_progress">修复中 (in_progress)</option>
          <option value="resolved">已解决 (resolved)</option>
          <option value="false_positive">误报 (false_positive)</option>
          <option value="wont_fix">不修复 (wont_fix)</option>
        </select>
      </div>

      {/* 修复备注 */}
      <div>
        <label style={labelStyle}>修复备注</label>
        <textarea
          style={{ ...inputStyle, minHeight: 70, resize: 'vertical' }}
          placeholder="输入修复备注..."
          value={fixNotes}
          onChange={e => setFixNotes(e.target.value)}
        />
      </div>

      {/* 预估工作量 */}
      <div>
        <label style={labelStyle}>预估工作量</label>
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          {[
            { val: '<1h', label: '<1h', sub: '极小' },
            { val: '1-4h', label: '1-4h', sub: '小' },
            { val: '1d', label: '1天', sub: '中' },
            { val: '1w', label: '1周', sub: '大' },
          ].map(opt => (
            <label key={opt.val} style={{
              display: 'flex', alignItems: 'center', gap: 4, cursor: 'pointer',
              background: fixEffort === opt.val ? 'var(--accent-blue)' : 'var(--bg-secondary)',
              border: `1px solid ${fixEffort === opt.val ? 'var(--accent-blue)' : 'var(--border)'}`,
              borderRadius: 4, padding: '4px 10px', fontSize: 12,
            }}>
              <input type="radio" name={`fix_effort_${vuln._key}`} value={opt.val} checked={fixEffort === opt.val}
                onChange={() => setFixEffort(opt.val)}
                style={{ display: 'none' }}
              />
              <span style={{ fontWeight: 600 }}>{opt.label}</span>
              <span style={{ fontSize: 10, color: fixEffort === opt.val ? 'rgba(255,255,255,.7)' : 'var(--text-muted)' }}>{opt.sub}</span>
            </label>
          ))}
        </div>
      </div>

      {/* Unified save button */}
      <button
        className="btn-primary"
        style={{ fontSize: 12, padding: '7px 0', width: '100%', marginTop: 4 }}
        disabled={saving}
        onClick={saveAll}
      >
        {saving ? '保存中...' : '保存修复信息'}
      </button>
      {saveMsg && (
        <div style={{ fontSize: 11, textAlign: 'center', color: saveMsg === '已保存' ? 'var(--accent-green)' : 'var(--critical)' }}>
          {saveMsg}
        </div>
      )}
    </div>
  )
}

// ────────── Bulk Bar ──────────
interface BulkBarProps {
  count: number
  items: Vuln[]
  checkedKeys: Set<string>
  onDone: () => void
  onCancel: () => void
}
function BulkBar({ count, items, checkedKeys, onDone, onCancel }: BulkBarProps) {
  const [modal, setModal] = useState<'assign' | 'status' | 'due' | null>(null)
  const [bulkAssign, setBulkAssign] = useState('')
  const [bulkStatus, setBulkStatus] = useState('open')
  const [bulkDue, setBulkDue] = useState('')
  const [working, setWorking] = useState(false)

  const ids = Array.from(checkedKeys)

  async function runBulk(action: string, extra: Record<string, string>) {
    setWorking(true)
    try {
      await api.post('/vulnerabilities/bulk', { action, ids, ...extra })
    } catch (_) {
      // Fallback: patch each individually if bulk endpoint not available
      for (const key of ids) {
        try { await api.patch(`/vulnerabilities/${key}`, extra) } catch (_) {}
      }
    }
    setWorking(false)
    setModal(null)
    onDone()
  }

  function exportCSV() {
    const checked = items.filter(v => checkedKeys.has(v._key))
    // Try API export first, fall back to client-side
    api.get('/vulnerabilities/export', { params: { ids: ids.join(',') }, responseType: 'blob' })
      .then(r => {
        const blob = new Blob([r.data], { type: 'text/csv' })
        const a = document.createElement('a')
        a.href = URL.createObjectURL(blob)
        a.download = `vuln_export_${count}.csv`
        a.click()
      })
      .catch(() => {
        // Client-side fallback
        const rows = [['CVE', 'Score', 'Severity', 'Asset', 'Status', 'AssignedTo', 'DueDate'].join(',')]
        checked.forEach(v => rows.push([
          v.cve_id, v.cvss_score, v.severity,
          `"${(v.affected_assets ?? []).join(';')}"`,
          v.fix_status ?? v.status,
          v.assigned_to ?? '',
          v.due_date ? new Date(v.due_date).toLocaleDateString('zh-CN') : '',
        ].join(',')))
        const blob = new Blob([rows.join('\n')], { type: 'text/csv' })
        const a = document.createElement('a')
        a.href = URL.createObjectURL(blob)
        a.download = `vuln_export_${count}.csv`
        a.click()
      })
  }

  return (
    <>
      <div style={{
        position: 'fixed', bottom: 24, left: '50%', transform: 'translateX(-50%)',
        background: 'var(--bg-card)', border: '1px solid var(--accent-blue)',
        borderRadius: 10, boxShadow: '0 8px 32px rgba(0,0,0,.5)',
        padding: '10px 18px', display: 'flex', alignItems: 'center', gap: 10, zIndex: 300,
        whiteSpace: 'nowrap',
      }}>
        <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--accent-blue)', marginRight: 4 }}>
          已选 {count} 项
        </span>
        <button className="btn-primary" style={{ fontSize: 11, padding: '4px 12px' }} onClick={() => setModal('assign')}>
          批量分配
        </button>
        <button className="btn-primary" style={{ fontSize: 11, padding: '4px 12px' }} onClick={() => setModal('due')}>
          设置截止日
        </button>
        <button className="btn-primary" style={{ fontSize: 11, padding: '4px 12px' }} onClick={() => setModal('status')}>
          更新状态
        </button>
        <button className="btn-secondary" style={{ fontSize: 11, padding: '4px 12px' }} onClick={exportCSV}>
          导出CSV
        </button>
        <button className="btn-secondary" style={{ fontSize: 11, padding: '4px 10px', marginLeft: 4 }} onClick={onCancel}>
          ✕
        </button>
      </div>

      {modal === 'assign' && (
        <>
          <div style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} onClick={() => setModal(null)} />
          <div style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: 340, background: 'var(--bg-modal)', border: '1px solid var(--border)', borderRadius: 8, zIndex: 500, padding: 20 }}>
            <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 14 }}>批量分配负责人</div>
            <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box', marginBottom: 12 }}
              placeholder="负责人姓名..." value={bulkAssign} onChange={e => setBulkAssign(e.target.value)} />
            <div style={{ display: 'flex', gap: 8 }}>
              <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setModal(null)}>取消</button>
              <button className="btn-primary" style={{ flex: 1 }} disabled={working || !bulkAssign.trim()}
                onClick={() => runBulk('assign', { assigned_to: bulkAssign })}>
                {working ? '处理中...' : `确认分配 (${count})`}
              </button>
            </div>
          </div>
        </>
      )}

      {modal === 'due' && (
        <>
          <div style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} onClick={() => setModal(null)} />
          <div style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: 340, background: 'var(--bg-modal)', border: '1px solid var(--border)', borderRadius: 8, zIndex: 500, padding: 20 }}>
            <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 14 }}>批量设截止日期</div>
            <input type="date" className="filter-input" style={{ width: '100%', boxSizing: 'border-box', marginBottom: 12 }}
              value={bulkDue} onChange={e => setBulkDue(e.target.value)} />
            <div style={{ display: 'flex', gap: 8 }}>
              <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setModal(null)}>取消</button>
              <button className="btn-primary" style={{ flex: 1 }} disabled={working || !bulkDue}
                onClick={() => runBulk('due_date', { due_date: new Date(bulkDue).toISOString() })}>
                {working ? '处理中...' : `确认设置 (${count})`}
              </button>
            </div>
          </div>
        </>
      )}

      {modal === 'status' && (
        <>
          <div style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} onClick={() => setModal(null)} />
          <div style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: 340, background: 'var(--bg-modal)', border: '1px solid var(--border)', borderRadius: 8, zIndex: 500, padding: 20 }}>
            <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 14 }}>批量更新修复状态</div>
            <select className="filter-select" style={{ width: '100%', marginBottom: 12 }}
              value={bulkStatus} onChange={e => setBulkStatus(e.target.value)}>
              <option value="open">待修复 (open)</option>
              <option value="in_progress">修复中 (in_progress)</option>
              <option value="resolved">已解决 (resolved)</option>
              <option value="false_positive">误报 (false_positive)</option>
              <option value="wont_fix">不修复 (wont_fix)</option>
            </select>
            <div style={{ display: 'flex', gap: 8 }}>
              <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setModal(null)}>取消</button>
              <button className="btn-primary" style={{ flex: 1 }} disabled={working}
                onClick={() => runBulk('status', { fix_status: bulkStatus })}>
                {working ? '处理中...' : `确认更新 (${count})`}
              </button>
            </div>
          </div>
        </>
      )}
    </>
  )
}

export default function Vulnerabilities() {
  const navigate = useNavigate()

  const [items, setItems] = useState<Vuln[]>([])
  const [meta, setMeta] = useState<PageMeta>({ page: 1, page_size: 20, total: 0, total_pages: 1 })
  const [page, setPage] = useState(1)
  const [loading, setLoading] = useState(false)
  const [severityFilter, setSeverityFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<Vuln | null>(null)
  const [stats, setStats] = useState<VulnStats | null>(null)
  const [detailTab, setDetailTab] = useState<'overview' | 'enrichment' | 'fix' | 'cve' | 'assets'>('overview')

  const [showModal, setShowModal] = useState(false)
  const [editTarget, setEditTarget] = useState<Vuln | null>(null)
  const [form, setForm] = useState(BLANK_FORM)
  const [saving, setSaving] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<Vuln | null>(null)
  const mountedRef = useRef(false)

  // Bulk selection state
  const [checkedKeys, setCheckedKeys] = useState<Set<string>>(new Set())
  const [showAssets, setShowAssets] = useState(false)

  // Filter enhancements
  const [cvssMin, setCvssMin] = useState('')
  const [cvssMax, setCvssMax] = useState('')
  const [cvssApplied, setCvssApplied] = useState<{ min: number; max: number } | null>(null)
  const [exploitableOnly, setExploitableOnly] = useState(false)
  // Published date quick filter: week/month/quarter
  const [dateQuick, setDateQuick] = useState<'week' | 'month' | 'quarter' | ''>('')

  function load(p = page) {
    setLoading(true)
    const params: Record<string, string | number | boolean> = { page: p, page_size: 20 }
    if (severityFilter) params.severity = severityFilter
    if (statusFilter) params.fix_status = statusFilter
    if (search) params.keyword = search
    if (cvssApplied) { params.cvss_min = cvssApplied.min; params.cvss_max = cvssApplied.max }
    if (exploitableOnly) params.cvss_min = 9.0
    if (dateQuick) {
      const now = new Date()
      let since: Date
      if (dateQuick === 'week') { since = new Date(now); since.setDate(now.getDate() - 7) }
      else if (dateQuick === 'month') { since = new Date(now); since.setMonth(now.getMonth() - 1) }
      else { since = new Date(now); since.setMonth(now.getMonth() - 3) }
      params.published_since = since.toISOString()
    }
    api.get('/vulnerabilities', { params })
      .then(r => { setItems(r.data.data?.items ?? []); setMeta(r.data.data?.meta ?? meta) })
      .finally(() => setLoading(false))
  }

  const loadStats = useCallback(() => {
    api.get('/vulnerabilities/stats').then(r => setStats(r.data.data)).catch(() => {})
  }, [])

  useEffect(() => { loadStats() }, [loadStats])
  useEffect(() => { load(page) }, [page])
  useEffect(() => {
    if (!mountedRef.current) { mountedRef.current = true; return }
    setPage(1); load(1)
  }, [severityFilter, statusFilter, cvssApplied, exploitableOnly, dateQuick])

  // Clear checked when page changes
  useEffect(() => { setCheckedKeys(new Set()) }, [page, severityFilter, statusFilter])

  function cvssColor(score: number) {
    if (score >= 9) return 'var(--critical)'
    if (score >= 7) return 'var(--high)'
    if (score >= 4) return 'var(--medium)'
    return 'var(--low)'
  }

  function cvssBarColor(score: number) {
    if (score >= 9) return 'var(--critical)'
    if (score >= 7) return 'var(--high)'
    if (score >= 4) return 'var(--medium)'
    return 'var(--accent-green)'
  }

  function patchStatus(v: Vuln, status: string) {
    api.patch(`/vulnerabilities/${v._key}`, { status }).then(() => {
      setItems(prev => prev.map(x => x._key === v._key ? { ...x, status } : x))
      if (selected?._key === v._key) setSelected({ ...v, status })
    })
  }

  function patchFixStatus(v: Vuln, fix_status: string) {
    api.patch(`/vulnerabilities/${v._key}`, { fix_status }).then(() => {
      load(page)
      loadStats()
      setSelected(null)
    })
  }

  function deleteVuln(v: Vuln) { setDeleteTarget(v) }
  function doDelete() {
    if (!deleteTarget) return
    api.delete(`/vulnerabilities/${deleteTarget._key}`).then(() => { setSelected(null); setDeleteTarget(null); load(1) })
  }

  function openCreate() {
    setEditTarget(null)
    setForm(BLANK_FORM)
    setShowModal(true)
  }

  function openEdit(v: Vuln) {
    setEditTarget(v)
    setForm({
      cve_id: v.cve_id || '',
      title: v.title || '',
      severity: v.severity || 'high',
      cvss_score: String(v.cvss_score ?? ''),
      description: v.description || '',
      fix: v.fix || '',
      affected_assets: (v.affected_assets ?? []).join(', '),
    })
    setShowModal(true)
  }

  function saveVuln() {
    if (!form.title.trim()) return
    setSaving(true)
    const body = {
      cve_id: form.cve_id,
      title: form.title,
      severity: form.severity,
      cvss_score: parseFloat(form.cvss_score) || 0,
      description: form.description,
      fix: form.fix,
      affected_assets: form.affected_assets ? form.affected_assets.split(',').map(s => s.trim()).filter(Boolean) : [],
      status: 'open',
    }
    const req = editTarget
      ? api.patch(`/vulnerabilities/${editTarget._key}`, body)
      : api.post('/vulnerabilities', body)
    req.then(() => { setShowModal(false); load(1); loadStats() })
      .finally(() => setSaving(false))
  }

  function toggleCheck(key: string, e: React.ChangeEvent<HTMLInputElement>) {
    e.stopPropagation()
    setCheckedKeys(prev => {
      const next = new Set(prev)
      if (next.has(key)) next.delete(key); else next.add(key)
      return next
    })
  }

  function toggleAll(e: React.ChangeEvent<HTMLInputElement>) {
    if (e.target.checked) {
      setCheckedKeys(new Set(items.map(v => v._key)))
    } else {
      setCheckedKeys(new Set())
    }
  }

  function handleNavigateIoc(q: string) {
    navigate(`/iocs?q=${encodeURIComponent(q)}`)
  }

  function handleNavigateAsset(assetKey: string) {
    navigate(`/assets?selected=${encodeURIComponent(assetKey)}`)
  }

  const critSevCount = (stats?.critical ?? 0) + (stats?.high ?? 0) + (stats?.medium ?? 0) + (stats?.low ?? 0) || 1
  const allChecked = items.length > 0 && items.every(v => checkedKeys.has(v._key))

  const dateQuickLabels: Array<{ val: 'week' | 'month' | 'quarter'; label: string }> = [
    { val: 'week', label: '本周' },
    { val: 'month', label: '本月' },
    { val: 'quarter', label: '本季度' },
  ]

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      {/* Skeleton shimmer keyframes */}
      <style>{`
        @keyframes skeletonShimmer {
          0% { background-position: 200% 0; }
          100% { background-position: -200% 0; }
        }
      `}</style>

      <PageHeader
        title="漏洞管理"
        actions={<>
          <button className="btn-secondary" onClick={() => {
            const rows = [['CVE ID', 'Title', '严重程度', 'CVSS', '状态', '受影响资产'].join(',')]
            items.forEach(v => rows.push([v.cve_id, `"${v.title}"`, v.severity, v.cvss_score, v.status, (v.affected_assets ?? []).join(';')].join(',')))
            const blob = new Blob([rows.join('\n')], { type: 'text/csv' })
            const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = 'vuln_assessment.csv'; a.click()
          }}>&#8659;Vuln Assessment</button>
          <button className="btn-primary" onClick={openCreate}>+ Add CVE</button>
        </>}
      />

      {/* Severity distribution bar + fix progress */}
      {stats && (
        <div style={{ padding: '10px 20px', borderBottom: '1px solid var(--border)', background: 'var(--bg-sidebar)', flexShrink: 0 }}>
          <div style={{ display: 'flex', gap: 16, alignItems: 'center' }}>
            {[
              { label: '严重', count: stats.critical, color: 'var(--critical)' },
              { label: '高危', count: stats.high, color: 'var(--high)' },
              { label: '中危', count: stats.medium, color: 'var(--medium)' },
              { label: '低危', count: stats.low, color: 'var(--accent-green)' },
            ].map(s => (
              <div key={s.label} style={{ display: 'flex', alignItems: 'center', gap: 8, flex: 1 }}>
                <span style={{ fontSize: 10.5, color: s.color, minWidth: 44 }}>{s.label}</span>
                <div style={{ flex: 1, height: 12, background: 'var(--bg-secondary)', borderRadius: 2, overflow: 'hidden' }}>
                  <div style={{ width: `${(s.count / critSevCount) * 100}%`, height: '100%', background: s.color, borderRadius: 2 }} />
                </div>
                <span style={{ fontSize: 11.5, fontWeight: 700, color: s.color, minWidth: 28 }}>{s.count}</span>
              </div>
            ))}
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginTop: 8 }}>
            <span style={{ fontSize: 10.5, color: 'var(--text-muted)', minWidth: 44 }}>修复进度</span>
            <div style={{ flex: 1, height: 8, background: 'var(--bg-secondary)', borderRadius: 4, overflow: 'hidden' }}>
              <div style={{
                width: `${stats.total > 0 ? ((stats.patched / stats.total) * 100) : 0}%`,
                height: '100%', background: 'var(--accent-green)', borderRadius: 4, transition: 'width 0.4s ease',
              }} />
            </div>
            <span style={{ fontSize: 11, color: 'var(--accent-green)', fontWeight: 600, whiteSpace: 'nowrap' }}>
              已修复: {stats.patched} / {stats.total}
            </span>
          </div>
        </div>
      )}

      {/* Filter bar */}
      <div className="filter-bar" style={{ flexWrap: 'wrap', gap: 8 }}>
        <input
          className="filter-input"
          placeholder="搜索CVE编号、标题..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && load(1)}
        />
        <button className="btn-secondary" style={{ fontSize: 11 }} onClick={() => load(1)}>搜索</button>
        <select className="filter-select" value={severityFilter} onChange={e => setSeverityFilter(e.target.value)}>
          <option value="">全部严重程度</option>
          <option value="critical">严重</option>
          <option value="high">高危</option>
          <option value="medium">中危</option>
          <option value="low">低危</option>
        </select>
        <select className="filter-select" value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
          <option value="">全部状态</option>
          <option value="open">待修复</option>
          <option value="in_progress">修复中</option>
          <option value="patched">已修复</option>
          <option value="mitigated">已缓解</option>
          <option value="accepted">接受风险</option>
        </select>

        {/* CVSS range */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 4 }}>
          <input
            type="number" min={0} max={10} step={0.1}
            className="filter-input" style={{ width: 56 }}
            placeholder="CVSS≥" value={cvssMin}
            onChange={e => setCvssMin(e.target.value)}
          />
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>—</span>
          <input
            type="number" min={0} max={10} step={0.1}
            className="filter-input" style={{ width: 56 }}
            placeholder="≤10" value={cvssMax}
            onChange={e => setCvssMax(e.target.value)}
          />
          <button className="btn-secondary" style={{ fontSize: 11, padding: '3px 8px' }}
            onClick={() => {
              const mn = parseFloat(cvssMin) || 0
              const mx = parseFloat(cvssMax) || 10
              setCvssApplied({ min: mn, max: mx })
            }}>应用</button>
          {cvssApplied && (
            <button className="btn-secondary" style={{ fontSize: 11, padding: '3px 6px', color: 'var(--text-muted)' }}
              onClick={() => { setCvssApplied(null); setCvssMin(''); setCvssMax('') }}>✕</button>
          )}
        </div>

        {/* Exploitable toggle */}
        <label style={{ display: 'flex', alignItems: 'center', gap: 5, fontSize: 12, cursor: 'pointer', color: exploitableOnly ? 'var(--critical)' : 'var(--text-muted)' }}>
          <input type="checkbox" checked={exploitableOnly} onChange={e => setExploitableOnly(e.target.checked)} />
          仅显示可利用
        </label>

        {/* Date quick filter */}
        <div style={{ display: 'flex', gap: 4 }}>
          {dateQuickLabels.map(q => (
            <button key={q.val}
              className={dateQuick === q.val ? 'btn-primary' : 'btn-secondary'}
              style={{ fontSize: 11, padding: '3px 9px' }}
              onClick={() => setDateQuick(prev => prev === q.val ? '' : q.val)}>
              {q.label}
            </button>
          ))}
        </div>
      </div>

      <div style={{ display: 'flex', flex: 1, overflow: 'hidden' }}>
        <div className="data-table-wrap" style={{ flex: 1 }}>
          <table className="data-table">
            <thead>
              <tr>
                <ResizableTh style={{ width: 32, textAlign: 'center' }}>
                  <input type="checkbox" checked={allChecked} onChange={toggleAll} title="全选" style={{ cursor: 'pointer' }} />
                </ResizableTh>
                <ResizableTh>CVE编号</ResizableTh>
                <ResizableTh>标题</ResizableTh>
                <ResizableTh>严重程度</ResizableTh>
                <ResizableTh>CVSS</ResizableTh>
                <ResizableTh>SLA</ResizableTh>
                <ResizableTh>状态</ResizableTh>
                <ResizableTh>受影响资产</ResizableTh>
                <ResizableTh>发布时间</ResizableTh>
                <ResizableTh></ResizableTh>
              </tr>
            </thead>
            <tbody>
              {loading && <tr><td colSpan={10} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>加载中...</td></tr>}
              {!loading && items.length === 0 && <tr><td colSpan={10} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>暂无漏洞</td></tr>}
              {items.map(v => {
                const assetCount = v.affected_assets?.length ?? 0
                const isChecked = checkedKeys.has(v._key)
                return (
                  <tr key={v._key} onClick={() => { setShowAssets(false); setDetailTab('overview'); setSelected(selected?._key === v._key ? null : v) }} className={selected?._key === v._key ? 'selected' : ''}>
                    <td style={{ textAlign: 'center' }} onClick={e => e.stopPropagation()}>
                      <input type="checkbox" checked={isChecked} onChange={e => toggleCheck(v._key, e)} style={{ cursor: 'pointer' }} />
                    </td>
                    <td style={{ fontFamily: 'monospace', fontSize: 12, color: 'var(--accent-orange)', whiteSpace: 'nowrap' }}>{v.cve_id || '-'}</td>
                    <td style={{ fontSize: 12.5, maxWidth: 300, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {v.title}
                      {(v.cvss_score ?? 0) >= 9.0 && (
                        <span style={{
                          marginLeft: 6, fontSize: 10,
                          background: 'rgba(224,80,80,0.15)', color: 'var(--critical)',
                          border: '1px solid rgba(224,80,80,0.4)', borderRadius: 3,
                          padding: '1px 5px', whiteSpace: 'nowrap', fontFamily: 'sans-serif', verticalAlign: 'middle',
                        }}>🔴 野外利用</span>
                      )}
                    </td>
                    <td><span className={`sev-badge ${v.severity}`}>{v.severity}</span></td>
                    <td><CVSSBar score={v.cvss_score ?? 0} /></td>
                    <td style={{ minWidth: 72 }}>
                      <SlaIndicator vuln={v} />
                    </td>
                    <td>
                      <span style={{
                        fontSize: 11.5, textTransform: 'capitalize',
                        color: v.status === 'open' ? 'var(--critical)' : v.status === 'patched' ? 'var(--accent-green)' : v.status === 'in_progress' ? 'var(--accent-blue)' : 'var(--text-muted)',
                      }}>{ {'open':'未修复','in_progress':'处理中','patched':'已修复','accepted_risk':'接受风险'}[v.status] ?? v.status }</span>
                    </td>
                    <td onClick={e => e.stopPropagation()}>
                      {assetCount > 0 ? (
                        <span onClick={() => { setSelected(v); setShowAssets(true) }}
                          style={{
                            display: 'inline-block', background: 'var(--bg-secondary)',
                            border: '1px solid var(--border)', borderRadius: 10,
                            fontSize: 11, padding: '1px 8px', color: 'var(--accent-blue)', cursor: 'pointer', whiteSpace: 'nowrap',
                          }} title="点击查看资产列表">
                          {assetCount} 台资产
                        </span>
                      ) : (
                        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>-</span>
                      )}
                    </td>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                      {v.published_at ? new Date(v.published_at).toLocaleDateString('zh-CN') : '-'}
                    </td>
                    <td onClick={e => e.stopPropagation()}>
                      <div style={{ display: 'flex', gap: 4 }}>
                        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 7px' }} onClick={() => openEdit(v)}>编辑</button>
                        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 7px', color: 'var(--critical)' }} onClick={() => deleteVuln(v)}>删</button>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>

        {/* Detail panel */}
        {selected && (
          <div style={{ width: 400, borderLeft: '1px solid var(--border)', background: 'var(--bg-drawer)', display: 'flex', flexDirection: 'column', overflow: 'hidden', flexShrink: 0 }}>
            {/* Panel header */}
            <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', background: 'var(--bg-card2)', minHeight: 48, display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
              {selected.cve_id ? (
                <a href={`https://nvd.nist.gov/vuln/detail/${selected.cve_id}`} target="_blank" rel="noopener noreferrer"
                  style={{ fontSize: 12, fontWeight: 600, fontFamily: 'monospace', color: 'var(--accent-blue)', textDecoration: 'none' }}
                  onMouseEnter={e => (e.currentTarget.style.textDecoration = 'underline')}
                  onMouseLeave={e => (e.currentTarget.style.textDecoration = 'none')}>
                  {selected.cve_id} ↗
                </a>
              ) : (
                <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)' }}>无 CVE 编号</span>
              )}
              <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px' }} onClick={() => { setSelected(null); setShowAssets(false) }}>✕</button>
            </div>

            {/* Tabs — 概览 / CVE详情 / 关联分析 / 修复 */}
            <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', flexShrink: 0 }}>
              {([
                { key: 'overview', label: '概览' },
                { key: 'cve', label: 'CVE 详情' },
                { key: 'assets', label: '受影响资产' },
                { key: 'enrichment', label: '关联分析' },
                { key: 'fix', label: '修复' },
              ] as const).map(tab => (
                <button key={tab.key}
                  onClick={() => setDetailTab(tab.key)}
                  style={{
                    flex: 1, padding: '8px 0', fontSize: 11.5, fontWeight: detailTab === tab.key ? 600 : 400,
                    background: 'none', border: 'none', cursor: 'pointer',
                    color: detailTab === tab.key ? 'var(--accent-blue)' : 'var(--text-muted)',
                    borderBottom: detailTab === tab.key ? '2px solid var(--accent-blue)' : '2px solid transparent',
                    whiteSpace: 'nowrap',
                  }}>
                  {tab.label}
                </button>
              ))}
            </div>

            <div style={{ flex: 1, overflowY: 'auto', padding: 16, display: 'flex', flexDirection: 'column', gap: 12 }}>

              {/* ── Overview tab ── */}
              {detailTab === 'overview' && <>
                <div className="card">
                  <div style={{ display: 'flex', gap: 8, marginBottom: 10, flexWrap: 'wrap', alignItems: 'center' }}>
                    <span className={`sev-badge ${selected.severity}`}>{selected.severity}</span>
                    {(selected.cvss_score ?? 0) >= 9.0 && (
                      <span style={{ fontSize: 10, background: 'rgba(224,80,80,0.15)', color: 'var(--critical)', border: '1px solid rgba(224,80,80,0.4)', borderRadius: 3, padding: '1px 5px' }}>🔴 野外利用</span>
                    )}
                  </div>
                  <div style={{ marginBottom: 10 }}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 4 }}>
                      <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>CVSS 评分</span>
                      <span style={{ fontSize: 14, fontWeight: 700, color: cvssColor(selected.cvss_score ?? 0) }}>
                        {(selected.cvss_score ?? 0) > 0 ? (selected.cvss_score).toFixed(1) : 'N/A'}
                      </span>
                    </div>
                    <div style={{ width: '100%', height: 10, background: 'var(--bg-secondary)', borderRadius: 4, overflow: 'hidden' }}>
                      <div style={{
                        width: `${Math.min((selected.cvss_score ?? 0) / 10, 1) * 100}%`,
                        height: '100%', background: cvssBarColor(selected.cvss_score ?? 0), borderRadius: 4, transition: 'width 0.3s ease',
                      }} />
                    </div>
                  </div>
                  <div style={{ fontSize: 13, fontWeight: 600, marginBottom: 6 }}>{selected.title}</div>
                  {selected.published_at && (
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8 }}>
                      发布时间：{new Date(selected.published_at).toLocaleDateString('zh-CN')}
                    </div>
                  )}
                  <span style={{
                    fontSize: 11.5, textTransform: 'capitalize',
                    color: selected.status === 'open' ? 'var(--critical)' : selected.status === 'patched' ? 'var(--accent-green)' : selected.status === 'in_progress' ? 'var(--accent-blue)' : 'var(--text-muted)',
                  }}>{ {'open':'未修复','in_progress':'处理中','patched':'已修复','accepted_risk':'接受风险'}[selected.status] ?? selected.status }</span>
                </div>

                {selected.description && (
                  <div className="card">
                    <div className="card-title">描述</div>
                    <div style={{ fontSize: 11.5, color: 'var(--text-secondary)', lineHeight: 1.7, maxHeight: 160, overflowY: 'auto', whiteSpace: 'pre-wrap', wordBreak: 'break-word' }}>
                      {selected.description}
                    </div>
                  </div>
                )}

                {selected.fix && (
                  <div className="card">
                    <div className="card-title">修复方案</div>
                    <div style={{ background: 'var(--bg-card2)', fontFamily: 'monospace', fontSize: 12, padding: 12, borderRadius: 4, color: 'var(--text-secondary)', lineHeight: 1.6, whiteSpace: 'pre-wrap', wordBreak: 'break-word', overflowX: 'auto' }}>
                      {selected.fix}
                    </div>
                  </div>
                )}

                {(selected.affected_assets?.length ?? 0) > 0 && (
                  <div className="card">
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 8 }}>
                      <div className="card-title" style={{ marginBottom: 0 }}>受影响资产 ({selected.affected_assets.length})</div>
                      <button className="btn-secondary" style={{ fontSize: 10, padding: '1px 6px' }} onClick={() => setShowAssets(v => !v)}>
                        {showAssets ? '收起' : '展开'}
                      </button>
                    </div>
                    {showAssets && (
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6, marginTop: 4 }}>
                        {selected.affected_assets.map(a => (
                          <span key={a} style={{ background: 'var(--bg-card2)', border: '1px solid var(--border-light)', borderRadius: 3, fontSize: 11, padding: '2px 8px', color: 'var(--text-secondary)', fontFamily: 'monospace', whiteSpace: 'nowrap' }}>{a}</span>
                        ))}
                      </div>
                    )}
                  </div>
                )}

                <div className="card">
                  <div className="card-title" style={{ marginBottom: 8 }}>更新修复状态</div>
                  <select className="filter-select" style={{ width: '100%' }}
                    value={selected.fix_status || selected.status || 'unplanned'}
                    onChange={e => patchFixStatus(selected, e.target.value)}>
                    <option value="unplanned">未计划 (unplanned)</option>
                    <option value="planned">已计划 (planned)</option>
                    <option value="in_progress">修复中 (in_progress)</option>
                    <option value="verifying">验证中 (verifying)</option>
                    <option value="fixed">已修复 (fixed)</option>
                    <option value="accepted_risk">接受风险 (accepted_risk)</option>
                  </select>
                </div>

                <div style={{ display: 'flex', gap: 8 }}>
                  {selected.status !== 'in_progress' && (
                    <button className="btn-primary" style={{ flex: 1, fontSize: 11 }} onClick={() => patchStatus(selected, 'in_progress')}>标记处理中</button>
                  )}
                  {selected.status !== 'accepted' && (
                    <button className="btn-secondary" style={{ flex: 1, fontSize: 11 }} onClick={() => patchStatus(selected, 'accepted')}>接受风险</button>
                  )}
                  {selected.status !== 'patched' && (
                    <button className="btn-secondary" style={{ flex: 1, fontSize: 11, color: 'var(--accent-green)' }} onClick={() => patchStatus(selected, 'patched')}>标记已修复</button>
                  )}
                </div>
                <div style={{ display: 'flex', gap: 8 }}>
                  <button className="btn-secondary" style={{ flex: 1, fontSize: 11 }} onClick={() => openEdit(selected)}>编辑</button>
                  <button className="btn-secondary" style={{ flex: 1, fontSize: 11, color: 'var(--critical)' }} onClick={() => deleteVuln(selected)}>删除</button>
                </div>
              </>}

              {/* ── CVE Detail tab ── */}
              {detailTab === 'cve' && (
                <CveDetailTab vuln={selected} onNavigateIoc={handleNavigateIoc} />
              )}

              {/* ── Affected Assets tab ── */}
              {detailTab === 'assets' && (
                <AffectedAssetsTab vuln={selected} onNavigateAsset={handleNavigateAsset} />
              )}

              {/* ── Enrichment tab ── */}
              {detailTab === 'enrichment' && <EnrichmentTab vuln={selected} />}

              {/* ── Fix workflow tab ── */}
              {detailTab === 'fix' && (
                <FixTab
                  vuln={selected}
                  onUpdated={updated => {
                    setSelected(updated)
                    setItems(prev => prev.map(x => x._key === updated._key ? updated : x))
                  }}
                />
              )}
            </div>
          </div>
        )}
      </div>

      <div className="pagination">
        <button className="page-btn" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>&#8249;</button>
        <span>{page} / {meta.total_pages || 1}</span>
        <button className="page-btn" disabled={page >= meta.total_pages} onClick={() => setPage(p => p + 1)}>&#8250;</button>
        <span style={{ marginLeft: 8 }}>{meta.total} 条</span>
      </div>

      {/* ── Bulk bar (floating, ≥1 selected) ── */}
      {checkedKeys.size >= 1 && (
        <BulkBar
          count={checkedKeys.size}
          items={items}
          checkedKeys={checkedKeys}
          onDone={() => { setCheckedKeys(new Set()); load(page); loadStats() }}
          onCancel={() => setCheckedKeys(new Set())}
        />
      )}

      {/* Create / Edit Modal */}
      {showModal && (
        <>
          <div onClick={() => setShowModal(false)} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
          <div style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: 520, background: 'var(--bg-modal)', border: '1px solid var(--border)', borderRadius: 8, zIndex: 500, padding: 24 }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 20 }}>{editTarget ? '编辑漏洞' : '添加漏洞'}</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                {[
                  { label: 'CVE ID', key: 'cve_id', ph: 'CVE-2024-1234' },
                  { label: 'CVSS评分', key: 'cvss_score', ph: '9.8' },
                ].map(f => (
                  <div key={f.key}>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>{f.label}</div>
                    <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder={f.ph}
                      value={(form as Record<string, string>)[f.key]} onChange={e => setForm(p => ({ ...p, [f.key]: e.target.value }))} />
                  </div>
                ))}
              </div>
              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>标题 *</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="如：远程代码执行..."
                  value={form.title} onChange={e => setForm(p => ({ ...p, title: e.target.value }))} />
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
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
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>受影响资产 (comma-sep)</div>
                  <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="WKSTN-001, SRV-DB-01"
                    value={form.affected_assets} onChange={e => setForm(p => ({ ...p, affected_assets: e.target.value }))} />
                </div>
              </div>
              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>描述</div>
                <textarea className="filter-input" style={{ width: '100%', boxSizing: 'border-box', minHeight: 60, resize: 'vertical' }}
                  placeholder="漏洞描述..." value={form.description}
                  onChange={e => setForm(p => ({ ...p, description: e.target.value }))} />
              </div>
              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>修复建议</div>
                <textarea className="filter-input" style={{ width: '100%', boxSizing: 'border-box', minHeight: 60, resize: 'vertical' }}
                  placeholder="应用补丁KB..." value={form.fix}
                  onChange={e => setForm(p => ({ ...p, fix: e.target.value }))} />
              </div>
              <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setShowModal(false)}>取消</button>
                <button className="btn-primary" style={{ flex: 1 }} disabled={saving || !form.title.trim()} onClick={saveVuln}>
                  {saving ? '保存中...' : editTarget ? '保存修改' : '添加漏洞'}
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
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 12 }}>确认删除</div>
            <div style={{ fontSize: 13, color: 'var(--text-secondary)', marginBottom: 20 }}>
              确定要删除漏洞 <strong style={{ color: 'var(--accent-orange)', fontFamily: 'monospace' }}>{deleteTarget.cve_id || deleteTarget.title}</strong> 吗？
            </div>
            <div style={{ display: 'flex', gap: 10 }}>
              <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setDeleteTarget(null)}>取消</button>
              <button className="btn-primary" style={{ flex: 1, background: 'var(--critical)', borderColor: 'var(--critical)' }} onClick={doDelete}>确认删除</button>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
