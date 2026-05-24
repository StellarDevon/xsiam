import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '@/lib/api'
import type { PageMeta } from '@/lib/api'
import PageHeader from '@/components/PageHeader'

// ─── Models ──────────────────────────────────────────────────────────────────

interface Alert {
  _key: string
  alert_id?: string
  name: string
  description?: string
  severity: string
  status: string
  source?: string
  source_type?: string
  host?: string
  asset_name?: string
  user?: string
  user_name?: string
  mitre_tactic?: string
  mitre_tactics?: string[]
  detection_rule?: string
  incident_id?: string
  iocs?: IocEntry[]
  process_tree?: ProcessNode[]
  raw_data?: Record<string, unknown>
  triggered_at?: string
  created_at: string
  updated_at?: string
}

interface ProcessNode {
  pid?: number
  name: string
  path?: string
  command_line?: string
  parent_pid?: number
  is_root?: boolean
  is_alert_node?: boolean
  cmd?: string
  verdict?: 'malicious' | 'suspicious' | 'clean'
  depth?: number
  user?: string
  timestamp?: string
}

interface IocEntry {
  type: string
  value: string
  verdict: string
  confidence?: number
  note?: string
}

interface IocSearchResult {
  _key?: string
  type: string
  value: string
  verdict: string
  confidence?: number
  note?: string
  description?: string
}

interface AlertStats {
  total: number
  by_severity: {
    critical?: number
    high?: number
    medium?: number
    low?: number
    info?: number
  }
  by_status: {
    active?: number
    investigating?: number
    resolved?: number
    false_positive?: number
    auto_closed?: number
  }
  new_last_24h: number
  mttr_hours?: number
}

// ─── Constants ───────────────────────────────────────────────────────────────

const STATUS_LABELS: Record<string, string> = {
  active: '活跃', new: '活跃',
  investigating: '调查中', under_investigation: '调查中',
  resolved: '已解决',
  false_positive: '误报',
  auto_closed: '自动关闭',
}
const STATUS_COLORS: Record<string, string> = {
  active: '#4fa3e0', new: '#4fa3e0',
  investigating: '#f9a825', under_investigation: '#f9a825',
  resolved: '#2fb07a',
  false_positive: '#546e7a',
  auto_closed: '#546e7a',
}
const SEV_LABELS: Record<string, string> = {
  critical: '严重', high: '高危', medium: '中危', low: '低危', info: '信息',
}
const SEV_COLORS: Record<string, string> = {
  critical: '#e53935', high: '#ff6f00', medium: '#f9a825', low: '#2fb07a', info: '#546e7a',
}
const SOURCE_LABELS: Record<string, string> = {
  endpoint: '终端', network: '网络', cloud: '云', identity: '身份',
  email: '邮件', wazuh: 'Wazuh', siem: 'SIEM', manual: '手动',
}

// MITRE 战术 → 处置建议
const MITRE_ADVICE: Record<string, string> = {
  'Initial Access':      '检查对外暴露面，审查近期账号登录记录，隔离受影响端点',
  'Execution':           '终止可疑进程，审计脚本执行记录，检查计划任务/启动项',
  'Persistence':         '审查自启动项、注册表 Run 键、计划任务，清除持久化机制',
  'Privilege Escalation':'审查权限提升日志，检查 sudo/UAC 绕过，重置受影响账号',
  'Defense Evasion':     '检查安全工具状态，审查日志完整性，检测进程注入痕迹',
  'Credential Access':   '强制重置涉及账号密码，开启 MFA，检查凭证存储',
  'Discovery':           '分析扫描行为来源，审查内网访问记录',
  'Lateral Movement':    '隔离横向移动路径上的端点，审查共享凭证使用情况',
  'Collection':          '检查数据访问日志，审查文件压缩和打包行为',
  'Command and Control': '封堵 C2 域名/IP，检查 DNS 解析异常，审查代理设置',
  'Exfiltration':        '封堵外传通道，审查大量数据传输记录，检查 DLP 日志',
  'Impact':              '评估数据/系统损毁范围，启动业务连续性计划，隔离受损系统',
}

const MITRE_TACTICS_LIST = [
  'Initial Access', 'Execution', 'Persistence', 'Privilege Escalation',
  'Defense Evasion', 'Credential Access', 'Discovery', 'Lateral Movement',
  'Collection', 'Command and Control', 'Exfiltration', 'Impact',
]

const SOURCE_TYPES_LIST = ['NGFW', 'EDR', 'Cloud', 'Email', 'Identity']

// Alert status flow
const STATUS_FLOW = [
  { key: 'created',      label: '新建' },
  { key: 'analyzing',   label: '分析中' },
  { key: 'remediating', label: '处置中' },
  { key: 'closed',      label: '已关闭' },
]

// ─── Helpers ─────────────────────────────────────────────────────────────────

function fmtDate(iso: string | undefined) {
  if (!iso) return '—'
  try {
    const d = new Date(iso)
    if (isNaN(d.getTime())) return '—'
    const p = (n: number) => n.toString().padStart(2, '0')
    return `${p(d.getMonth()+1)}/${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
  } catch { return '—' }
}

function fmtRelative(iso: string | undefined) {
  if (!iso) return ''
  const ms = Date.now() - new Date(iso).getTime()
  const m = Math.floor(ms / 60000)
  if (m < 1) return '刚刚'
  if (m < 60) return `${m} 分钟前`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h} 小时前`
  return `${Math.floor(h / 24)} 天前`
}

function alertTime(a: Alert) { return a.triggered_at ?? a.created_at }
function alertHost(a: Alert) { return a.host ?? a.asset_name ?? '' }
function alertUser(a: Alert) { return a.user ?? a.user_name ?? '' }
function alertSource(a: Alert) { return a.source ?? a.source_type ?? 'endpoint' }

/** Map alert status to STATUS_FLOW step index */
function statusFlowStep(status: string): number {
  if (status === 'active' || status === 'new') return 1
  if (status === 'investigating' || status === 'under_investigation') return 2
  if (status === 'resolved' || status === 'false_positive' || status === 'auto_closed') return 3
  return 0
}

/** Detect suspicious cmdline patterns */
/** Detect lsass access */
function isLsassAccess(name: string): boolean {
  return name.toLowerCase() === 'lsass.exe'
}

/** Detect suspicious process name patterns */
function isSuspiciousProcess(name: string): boolean {
  return /^(powershell|cmd|rundll32|regsvr32|mshta|wscript|cscript)(\.exe)?$/i.test(name)
}

/** Detect obfuscated commandline */
function hasObfuscatedCmdline(cmdline: string): boolean {
  const lower = cmdline.toLowerCase()
  return lower.includes('-enc') || lower.includes('-encodedcommand') || lower.includes(' hidden')
}

/** Choose process icon based on name */
function procIcon(name: string, isBad: boolean): string {
  if (isBad) return '🔴'
  const n = name.toLowerCase()
  if (n.endsWith('.exe') && (n.includes('explorer') || n.includes('svchost'))) return '📁'
  if (n === 'cmd.exe' || n === 'powershell.exe' || n === 'bash' || n === 'sh') return '💻'
  return '📄'
}

/** Build parent→children tree from flat list */
function buildProcessTree(procs: ProcessNode[]): Map<number | null, ProcessNode[]> {
  const map = new Map<number | null, ProcessNode[]>()
  for (const p of procs) {
    const parentKey = p.is_root ? null : (p.parent_pid ?? null)
    if (!map.has(parentKey)) map.set(parentKey, [])
    map.get(parentKey)!.push(p)
  }
  return map
}

// ─── Sub-components ──────────────────────────────────────────────────────────

function SevBadge({ sev }: { sev: string }) {
  const color = SEV_COLORS[sev] ?? '#546e7a'
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      padding: '2px 9px', borderRadius: 3,
      background: color + '22', color,
      fontSize: 10.5, fontWeight: 700, letterSpacing: 0.3,
    }}>
      <span style={{ width: 5, height: 5, borderRadius: '50%', background: color, flexShrink: 0 }} />
      {SEV_LABELS[sev] ?? sev}
    </span>
  )
}

function StatusBadge({ status }: { status: string }) {
  const c = STATUS_COLORS[status] ?? '#546e7a'
  const label = STATUS_LABELS[status] ?? status
  const pulsing = status === 'active' || status === 'new'
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 5,
      fontSize: 10.5, padding: '2px 8px', borderRadius: 3,
      background: c + '1a', color: c, fontWeight: pulsing ? 600 : 400,
    }}>
      <span style={{
        width: 5, height: 5, borderRadius: '50%', background: c, flexShrink: 0,
        boxShadow: pulsing ? `0 0 5px ${c}` : undefined,
        animation: pulsing ? 'none' : undefined,
      }} />
      {label}
    </span>
  )
}

function SourceBadge({ src }: { src: string }) {
  const label = SOURCE_LABELS[src] ?? src
  const color = src === 'endpoint' ? '#4fa3e0'
    : src === 'network' ? '#ab47bc'
    : src === 'cloud' ? '#26c6da'
    : src === 'identity' ? '#ef5350'
    : src === 'email' ? '#ff7043'
    : '#78909c'
  return (
    <span style={{
      fontSize: 10, padding: '2px 7px', borderRadius: 3,
      background: color + '18', color, border: `1px solid ${color}30`,
      fontWeight: 600, letterSpacing: 0.2, whiteSpace: 'nowrap',
    }}>
      {label}
    </span>
  )
}

// ─── Process Tree Component ───────────────────────────────────────────────────

interface ProcessTreeProps {
  procs: ProcessNode[]
  sourceType: string
}

function ProcessTreeNode({
  node, childMap, depth, isLast, prefixLines,
}: {
  node: ProcessNode
  childMap: Map<number | null, ProcessNode[]>
  depth: number
  isLast: boolean
  prefixLines: boolean[]  // true = draw vertical line at that indent level
}) {
  const children = node.pid != null ? (childMap.get(node.pid) ?? []) : []
  const cmdRaw = node.cmd ?? node.command_line ?? ''
  const isMalicious = node.verdict === 'malicious' || node.is_alert_node || false
  const isSuspNamed = isSuspiciousProcess(node.name)
  const isObfuscated = cmdRaw ? hasObfuscatedCmdline(cmdRaw) : false
  const isLsass = isLsassAccess(node.name)
  const isBad = isMalicious || isSuspNamed
  const icon = procIcon(node.name, isBad)
  const nameColor = isMalicious ? '#e53935' : isSuspNamed ? '#ff6f00' : 'var(--text-primary)'

  // Build the prefix string for this node (connector lines from ancestors)
  const connectorParts: string[] = []
  for (let i = 0; i < depth; i++) {
    connectorParts.push(prefixLines[i] ? '│  ' : '   ')
  }
  const connectorStr = connectorParts.join('')
  const branchStr = depth === 0 ? '' : (isLast ? '└─ ' : '├─ ')

  const cmdDisplay = cmdRaw.length > 55 ? cmdRaw.slice(0, 55) + '…' : cmdRaw

  return (
    <div>
      {/* Node row */}
      <div style={{
        display: 'flex', flexDirection: 'column',
        padding: '4px 0',
        background: isMalicious ? 'rgba(229,57,53,.04)' : 'transparent',
        borderRadius: 3,
      }}>
        {/* Main process line */}
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 0 }}>
          {/* Connector lines */}
          {depth > 0 && (
            <span style={{
              fontFamily: 'Consolas,"JetBrains Mono",monospace',
              fontSize: 12, color: 'rgba(255,255,255,.2)',
              whiteSpace: 'pre', flexShrink: 0, userSelect: 'none',
            }}>
              {connectorStr}{branchStr}
            </span>
          )}
          {/* Icon */}
          <span style={{ fontSize: 13, flexShrink: 0, marginRight: 4 }}>{icon}</span>
          {/* Process name — bold, code font */}
          <span style={{
            fontFamily: 'Consolas,"JetBrains Mono",monospace',
            fontSize: 12, fontWeight: 700, color: nameColor,
          }}>{node.name}</span>
          {/* PID in gray */}
          {node.pid != null && (
            <span style={{
              fontFamily: 'Consolas,"JetBrains Mono",monospace',
              fontSize: 11, color: '#7a8899', marginLeft: 5,
            }}>(PID:{node.pid})</span>
          )}
          {/* User in blue */}
          {node.user && (
            <span style={{
              fontSize: 10.5, color: '#4fa3e0', marginLeft: 6,
              background: 'rgba(79,163,224,.1)', padding: '0 5px',
              borderRadius: 3,
            }}>[{node.user}]</span>
          )}
          {/* Suspicious process badge */}
          {isSuspNamed && (
            <span style={{
              fontSize: 9.5, marginLeft: 6, padding: '1px 6px', borderRadius: 3,
              background: 'rgba(255,111,0,.15)', color: '#ff6f00',
              border: '1px solid rgba(255,111,0,.35)', fontWeight: 700, flexShrink: 0,
            }}>⚠️ Suspicious</span>
          )}
          {/* Timestamp */}
          {node.timestamp && (
            <span style={{ fontSize: 9, color: 'var(--text-muted)', marginLeft: 'auto', flexShrink: 0 }}>
              {fmtDate(node.timestamp)}
            </span>
          )}
        </div>
        {/* Cmdline + badges below, indented */}
        {cmdDisplay && (
          <div style={{
            marginLeft: depth > 0 ? (connectorStr.length * 7.2 + 20) : 20,
            display: 'flex', flexWrap: 'wrap', alignItems: 'center', gap: 5, marginTop: 2,
          }}>
            <span style={{
              fontFamily: 'Consolas,"JetBrains Mono",monospace',
              fontSize: 10, color: isMalicious ? '#ef9a9a' : 'var(--text-muted)',
              overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
              maxWidth: 300,
            }} title={cmdRaw}>{cmdDisplay}</span>
            {isObfuscated && (
              <span style={{
                fontSize: 9.5, padding: '1px 6px', borderRadius: 3,
                background: 'rgba(229,57,53,.15)', color: '#e53935',
                border: '1px solid rgba(229,57,53,.35)', fontWeight: 700, flexShrink: 0,
              }}>⚠️ 混淆命令</span>
            )}
            {isLsass && (
              <span style={{
                fontSize: 9.5, padding: '1px 6px', borderRadius: 3,
                background: 'rgba(255,111,0,.15)', color: '#ff6f00',
                border: '1px solid rgba(255,111,0,.4)', fontWeight: 700, flexShrink: 0,
              }}>⚠️ 凭证访问</span>
            )}
          </div>
        )}
      </div>

      {/* Children */}
      {children.map((child, ci) => {
        const childIsLast = ci === children.length - 1
        // For deeper levels, pass down whether THIS level continues (has siblings after us)
        const nextPrefixLines = [...prefixLines, !isLast]
        return (
          <ProcessTreeNode
            key={child.pid ?? ci}
            node={child}
            childMap={childMap}
            depth={depth + 1}
            isLast={childIsLast}
            prefixLines={nextPrefixLines}
          />
        )
      })}
    </div>
  )
}

function ProcessTree({ procs, sourceType }: ProcessTreeProps) {
  if (procs.length === 0) {
    return (
      <div>
        <div style={{ fontSize: 10.5, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.4, marginBottom: 10 }}>
          进程执行树
        </div>
        <div style={{ fontSize: 12, color: 'var(--text-muted)', padding: '12px 0', lineHeight: 1.7 }}>
          <div>该告警暂无进程链路数据。</div>
          {sourceType === 'endpoint' && (
            <div style={{ marginTop: 6, fontSize: 11, color: 'var(--text-muted)' }}>
              进程数据由 XSIAM 终端 Agent 采集，请确认 Agent 已部署并正常上报。
            </div>
          )}
        </div>
      </div>
    )
  }

  // Build tree map keyed by parent_pid
  const childMap = buildProcessTree(procs)
  // Root nodes: those with is_root=true, or those whose parent_pid is not in any node's pid list
  const allPids = new Set(procs.map(p => p.pid).filter((x): x is number => x != null))
  const roots = procs.filter(p => {
    if (p.is_root) return true
    if (p.parent_pid == null) return true
    return !allPids.has(p.parent_pid)
  })

  return (
    <div>
      <div style={{
        fontSize: 10.5, color: 'var(--text-muted)', textTransform: 'uppercase',
        letterSpacing: 0.4, marginBottom: 10,
        display: 'flex', alignItems: 'center', gap: 8,
      }}>
        <span>进程执行树</span>
        <span style={{
          fontSize: 9.5, padding: '1px 6px', borderRadius: 3,
          background: 'rgba(255,255,255,.06)', color: 'var(--text-muted)',
          border: '1px solid var(--border-light)',
        }}>{procs.length} 个进程</span>
      </div>
      <div style={{
        background: 'var(--bg-secondary)', border: '1px solid var(--border)',
        borderRadius: 5, padding: '10px 12px', overflowX: 'auto',
      }}>
        {roots.map((root, ri) => (
          <ProcessTreeNode
            key={root.pid ?? ri}
            node={root}
            childMap={childMap}
            depth={0}
            isLast={ri === roots.length - 1}
            prefixLines={[]}
          />
        ))}
      </div>
      {/* Legend */}
      <div style={{ marginTop: 8, display: 'flex', gap: 10, flexWrap: 'wrap' }}>
        {[
          { icon: '🔴', label: '可疑进程', color: '#ff6f00' },
          { icon: '⚠️', label: '混淆命令', color: '#e53935' },
          { icon: '📁', label: '系统进程', color: 'var(--text-muted)' },
          { icon: '💻', label: 'Shell', color: 'var(--text-muted)' },
        ].map(item => (
          <span key={item.label} style={{ display: 'flex', alignItems: 'center', gap: 3, fontSize: 9.5, color: item.color }}>
            <span>{item.icon}</span>{item.label}
          </span>
        ))}
      </div>
    </div>
  )
}

// ─── IOC Search Modal ────────────────────────────────────────────────────────

interface IocSearchModalProps {
  onClose: () => void
}
function IocSearchModal({ onClose }: IocSearchModalProps) {
  const navigate = useNavigate()
  const [q, setQ] = useState('')
  const [results, setResults] = useState<IocSearchResult[]>([])
  const [loading, setLoading] = useState(false)
  const inputRef = useRef<HTMLInputElement>(null)
  useEffect(() => { inputRef.current?.focus() }, [])

  function doSearch() {
    if (!q.trim()) return
    setLoading(true)
    api.get('/iocs/search', { params: { q: q.trim(), limit: 10 } })
      .then(r => setResults(r.data.data?.items ?? r.data.data ?? []))
      .catch(() => setResults([]))
      .finally(() => setLoading(false))
  }

  const verdictColor: Record<string, string> = {
    malicious: '#e53935', suspicious: '#ff6f00', clean: '#2fb07a', unknown: '#546e7a',
  }

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 9999,
      background: 'rgba(0,0,0,.55)', display: 'flex', alignItems: 'center', justifyContent: 'center',
    }} onClick={onClose}>
      <div style={{
        width: 540, maxHeight: '70vh', display: 'flex', flexDirection: 'column',
        background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 8,
        boxShadow: '0 20px 60px rgba(0,0,0,.5)',
      }} onClick={e => e.stopPropagation()}>
        <div style={{ padding: '14px 16px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 10 }}>
          <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>搜索 IOC</span>
          <button onClick={onClose} style={{ marginLeft: 'auto', background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 16 }}>✕</button>
        </div>
        <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', display: 'flex', gap: 8 }}>
          <input
            ref={inputRef}
            className="filter-input"
            style={{ flex: 1 }}
            placeholder="输入 IP、域名、Hash、URL..."
            value={q}
            onChange={e => setQ(e.target.value)}
            onKeyDown={e => e.key === 'Enter' && doSearch()}
          />
          <button className="btn-primary" style={{ fontSize: 11 }} disabled={loading || !q.trim()} onClick={doSearch}>
            {loading ? '搜索中...' : '搜索'}
          </button>
        </div>
        <div style={{ flex: 1, overflowY: 'auto', padding: '10px 16px' }}>
          {results.length === 0 && !loading && (
            <div style={{ fontSize: 12, color: 'var(--text-muted)', padding: '16px 0', textAlign: 'center' }}>输入关键字并搜索</div>
          )}
          <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
            {results.map((ioc, i) => {
              const v = ioc.verdict ?? 'unknown'
              const vColor = verdictColor[v] ?? '#546e7a'
              return (
                <div key={i} style={{
                  padding: '8px 10px', background: 'var(--bg-secondary)',
                  border: `1px solid ${vColor}25`, borderLeft: `3px solid ${vColor}`, borderRadius: 4,
                  display: 'flex', alignItems: 'center', gap: 8,
                }}>
                  <span style={{ fontSize: 9.5, padding: '1px 6px', borderRadius: 3, background: vColor + '22', color: vColor, fontWeight: 700, flexShrink: 0 }}>
                    {ioc.type.toUpperCase()}
                  </span>
                  <span style={{
                    flex: 1, fontSize: 11, fontFamily: 'Consolas,"JetBrains Mono",monospace',
                    color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                  }}>{ioc.value}</span>
                  <span style={{ fontSize: 9.5, padding: '2px 6px', borderRadius: 3, background: vColor + '22', color: vColor, fontWeight: 700, flexShrink: 0 }}>
                    {v === 'malicious' ? '恶意' : v === 'suspicious' ? '可疑' : v === 'clean' ? '安全' : '未知'}
                  </span>
                </div>
              )
            })}
          </div>
        </div>
        <div style={{ padding: '10px 16px', borderTop: '1px solid var(--border)', display: 'flex', justifyContent: 'flex-end' }}>
          <button className="btn-secondary" style={{ fontSize: 11 }} onClick={() => { navigate('/iocs'); onClose() }}>
            前往 IOC 情报库 →
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Alert Detail Pane ───────────────────────────────────────────────────────

interface DetailPaneProps {
  alert: Alert | null
  onClose: () => void
  onUpdate: (key: string, patch: Partial<Alert>) => void
}

function AlertDetailPane({ alert, onClose, onUpdate }: DetailPaneProps) {
  const navigate = useNavigate()
  const [tab, setTab] = useState('overview')
  const [detail, setDetail] = useState<Alert | null>(null)
  const [loading, setLoading] = useState(false)
  const [acting, setActing] = useState(false)
  // Link mode: 'none' | 'existing' | 'new'
  const [linkMode, setLinkMode] = useState<'none' | 'existing' | 'new'>('none')
  const [linkInput, setLinkInput] = useState('')
  const prevKey = useRef<string | null>(null)

  // IOC correlation state
  const [iocSearchResults, setIocSearchResults] = useState<IocSearchResult[]>([])
  const [iocSearchLoading, setIocSearchLoading] = useState(false)
  const [iocModalOpen, setIocModalOpen] = useState(false)

  useEffect(() => {
    if (!alert) { prevKey.current = null; setDetail(null); return }
    if (alert._key === prevKey.current) return
    prevKey.current = alert._key
    setTab('overview'); setLinkMode('none'); setLinkInput('')
    setIocSearchResults([])
    setLoading(true)
    api.get(`/alerts/${alert._key}`)
      .then(r => setDetail(r.data.data ?? alert))
      .catch(() => setDetail(alert))
      .finally(() => setLoading(false))
  }, [alert?._key])

  // Fetch IOC search results when IOC tab becomes active
  useEffect(() => {
    if (tab !== 'ioc') return
    const a = detail ?? alert
    if (!a) return
    const host = alertHost(a)
    const user = alertUser(a)
    if (!host && !user) return
    setIocSearchLoading(true)
    const queries: Promise<IocSearchResult[]>[] = []
    if (host) {
      queries.push(
        api.get('/iocs/search', { params: { q: host, limit: 5 } })
          .then(r => (r.data.data?.items ?? r.data.data ?? []) as IocSearchResult[])
          .catch(() => [] as IocSearchResult[])
      )
    }
    if (user) {
      queries.push(
        api.get('/iocs/search', { params: { q: user, limit: 5 } })
          .then(r => (r.data.data?.items ?? r.data.data ?? []) as IocSearchResult[])
          .catch(() => [] as IocSearchResult[])
      )
    }
    Promise.all(queries).then(results => {
      const combined = results.flat()
      // Deduplicate by value
      const seen = new Set<string>()
      const deduped = combined.filter(ioc => {
        if (seen.has(ioc.value)) return false
        seen.add(ioc.value)
        return true
      })
      setIocSearchResults(deduped)
    }).finally(() => setIocSearchLoading(false))
  }, [tab, alert?._key])

  const a = detail ?? alert
  if (!a) return null

  const verdictColor: Record<string, string> = {
    malicious: '#e53935', suspicious: '#ff6f00', clean: '#2fb07a', unknown: '#546e7a',
  }

  function markStatus(newStatus: string) {
    if (newStatus === 'false_positive' && !confirm('确认将此告警标记为误报？')) return
    setActing(true)
    api.patch(`/alerts/${a!._key}`, { status: newStatus })
      .then(() => onUpdate(a!._key, { status: newStatus }))
      .finally(() => setActing(false))
  }

  function doLinkExisting() {
    const val = linkInput.trim()
    if (!val) return
    // Strip INC- prefix if present
    const key = val.replace(/^inc-/i, '').trim()
    setActing(true)
    api.post(`/alerts/${a!._key}/link_incident`, { incident_id: key })
      .then(() => { onUpdate(a!._key, { incident_id: key }); setLinkMode('none'); setLinkInput('') })
      .catch(() => {
        // Fallback: direct patch if link_incident endpoint not available
        api.patch(`/alerts/${a!._key}`, { incident_id: key })
          .then(() => { onUpdate(a!._key, { incident_id: key }); setLinkMode('none'); setLinkInput('') })
      })
      .finally(() => setActing(false))
  }

  function doCreateAndLink() {
    const val = linkInput.trim()
    if (!val) return
    setActing(true)
    api.post('/incidents', {
      title: val, name: val,
      severity: a!.severity, status: 'new',
      description: `来源告警：${a!.name}`,
    })
      .then(r => {
        const incKey = r.data.data?._key
        if (!incKey) return Promise.resolve()
        return api.patch(`/alerts/${a!._key}`, { incident_id: incKey })
          .then(() => onUpdate(a!._key, { incident_id: incKey }))
      })
      .then(() => { setLinkMode('none'); setLinkInput('') })
      .finally(() => setActing(false))
  }

  function viewCausality() {
    if (a!.incident_id) {
      navigate(`/incidents?highlight=${a!.incident_id}`)
    } else {
      window.open(`/causality?alert=${a!._key}`, '_blank')
    }
  }

  const iocs: IocEntry[] = [...(a.iocs ?? [])]
  if (iocs.length === 0) {
    const host = alertHost(a), user = alertUser(a)
    if (host) iocs.push({ type: '主机', value: host, verdict: 'unknown' })
    if (user) iocs.push({ type: '用户', value: user, verdict: 'unknown' })
    if (a.mitre_tactic) iocs.push({ type: 'MITRE 战术', value: a.mitre_tactic, verdict: 'unknown' })
  }

  const procs: ProcessNode[] = a.process_tree ?? []
  const canFP = a.status !== 'false_positive' && a.status !== 'resolved' && a.status !== 'auto_closed'
  const canInvestigate = a.status === 'active' || a.status === 'new'
  const canResolve = a.status === 'investigating' || a.status === 'active' || a.status === 'new'

  // Severity-based urgency
  const urgency = a.severity === 'critical' ? { label: '立即响应', color: '#e53935', bg: 'rgba(229,57,53,.08)' }
    : a.severity === 'high' ? { label: '优先处置', color: '#ff6f00', bg: 'rgba(255,111,0,.06)' }
    : a.severity === 'medium' ? { label: '尽快跟进', color: '#f9a825', bg: 'rgba(249,168,37,.06)' }
    : { label: '按序排期', color: '#2fb07a', bg: 'rgba(47,176,122,.06)' }

  const advice = a.mitre_tactic ? MITRE_ADVICE[a.mitre_tactic] : undefined

  const iocTotalCount = iocs.length + iocSearchResults.length
  const TABS = [
    { id: 'overview', label: '概览' },
    { id: 'process',  label: `进程树${procs.length ? ` (${procs.length})` : ''}` },
    { id: 'ioc',      label: `IOC关联${iocTotalCount ? ` (${iocTotalCount})` : ''}` },
    { id: 'raw',      label: '原始数据' },
  ]

  // Status timeline step
  const currentStep = statusFlowStep(a.status)

  return (
    <div style={{
      width: 460, flexShrink: 0,
      background: 'var(--bg-card)',
      borderLeft: '1px solid var(--border)',
      display: 'flex', flexDirection: 'column', overflow: 'hidden',
    }}>
      {/* ── Header ──────────────────────────── */}
      <div style={{
        padding: '12px 16px 10px',
        borderBottom: '1px solid var(--border)',
        background: 'var(--bg-secondary)',
        flexShrink: 0,
      }}>
        {/* Top row: badges + close */}
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 8 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <SevBadge sev={a.severity} />
            <StatusBadge status={a.status} />
            <span style={{ fontSize: 9.5, color: 'var(--text-muted)', fontFamily: 'monospace' }}>
              ALT-{a._key.slice(-8).toUpperCase()}
            </span>
          </div>
          <button onClick={onClose} style={{
            width: 26, height: 26, display: 'flex', alignItems: 'center', justifyContent: 'center',
            background: 'none', border: '1px solid var(--border-light)', borderRadius: 4,
            color: 'var(--text-muted)', cursor: 'pointer', fontSize: 13, flexShrink: 0,
          }}>✕</button>
        </div>

        {/* Urgency banner */}
        <div style={{
          padding: '6px 10px', borderRadius: 4, marginBottom: 8,
          background: urgency.bg, border: `1px solid ${urgency.color}30`,
          display: 'flex', alignItems: 'center', gap: 8,
        }}>
          <span style={{ fontSize: 11, fontWeight: 700, color: urgency.color }}>{urgency.label}</span>
          <span style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>·</span>
          <span style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>{fmtRelative(alertTime(a))}</span>
          {alertHost(a) && (
            <>
              <span style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>·</span>
              <span style={{ fontSize: 10.5, color: '#4fa3e0', fontFamily: 'monospace' }}>🖥 {alertHost(a)}</span>
            </>
          )}
        </div>

        {/* Alert name */}
        <div style={{
          fontSize: 13, fontWeight: 600, lineHeight: 1.45, marginBottom: 8,
          color: 'var(--text-primary)',
        }}>
          {a.name}
        </div>

        {/* Meta chips */}
        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap', marginBottom: 10, alignItems: 'center' }}>
          <SourceBadge src={alertSource(a)} />
          {a.mitre_tactic && (
            <span style={{
              fontSize: 10, padding: '2px 7px', borderRadius: 3,
              background: 'rgba(59,158,222,.1)', color: 'var(--accent-blue)',
              border: '1px solid rgba(59,158,222,.2)', fontWeight: 600,
            }}>🎯 {a.mitre_tactic}</span>
          )}
          {alertUser(a) && (
            <span style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>👤 {alertUser(a)}</span>
          )}
        </div>

        {/* ── Linked incident badge (prominent) ── */}
        {a.incident_id && (
          <button
            onClick={() => navigate(`/incidents?highlight=${a.incident_id}`)}
            style={{
              width: '100%', padding: '8px 12px', borderRadius: 5, marginBottom: 10,
              background: 'rgba(79,163,224,.1)',
              border: '2px solid rgba(79,163,224,.45)',
              display: 'flex', alignItems: 'center', gap: 8,
              cursor: 'pointer', textAlign: 'left',
              transition: 'background .15s',
            }}
            onMouseEnter={e => (e.currentTarget.style.background = 'rgba(79,163,224,.18)')}
            onMouseLeave={e => (e.currentTarget.style.background = 'rgba(79,163,224,.1)')}
          >
            <span style={{ fontSize: 14, flexShrink: 0 }}>🔗</span>
            <span style={{ fontSize: 12, fontWeight: 700, color: '#4fa3e0', flex: 1 }}>
              关联事件 #{a.incident_id}
            </span>
            <span style={{ fontSize: 11.5, color: '#4fa3e0', fontWeight: 600, flexShrink: 0 }}>→</span>
          </button>
        )}

        {/* Incident association (change/link row) */}
        <div style={{
          padding: '6px 10px', borderRadius: 4, marginBottom: 10,
          background: a.incident_id ? 'rgba(79,163,224,.06)' : 'rgba(255,111,0,.06)',
          border: `1px solid ${a.incident_id ? 'rgba(79,163,224,.2)' : 'rgba(255,111,0,.2)'}`,
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        }}>
          {a.incident_id ? (
            <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
              <span style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>关联事件</span>
              <span
                style={{ color: '#4fa3e0', fontFamily: 'monospace', fontSize: 10.5, cursor: 'pointer', textDecoration: 'underline' }}
                onClick={() => navigate(`/incidents?highlight=${a.incident_id}`)}
              >
                INC-{a.incident_id}
              </span>
            </div>
          ) : (
            <span style={{ fontSize: 10.5, color: '#ff6f00', fontWeight: 500 }}>⚠ 未关联任何事件</span>
          )}
          <button
            className="btn-secondary"
            style={{ fontSize: 10, padding: '2px 8px' }}
            onClick={() => setLinkMode(linkMode !== 'none' ? 'none' : 'existing')}
          >
            {a.incident_id ? '变更' : '关联'}
          </button>
        </div>

        {/* Inline link form */}
        {linkMode !== 'none' && (
          <div style={{ marginBottom: 10 }}>
            {/* Mode switcher */}
            <div style={{ display: 'flex', gap: 0, marginBottom: 8, borderRadius: 4, overflow: 'hidden', border: '1px solid var(--border-light)' }}>
              {(['existing', 'new'] as const).map(mode => (
                <button
                  key={mode}
                  onClick={() => { setLinkMode(mode); setLinkInput('') }}
                  style={{
                    flex: 1, padding: '5px 0', fontSize: 11, cursor: 'pointer', border: 'none',
                    background: linkMode === mode ? 'var(--accent-blue)' : 'var(--bg-card)',
                    color: linkMode === mode ? 'white' : 'var(--text-secondary)',
                    fontWeight: linkMode === mode ? 600 : 400,
                  }}
                >
                  {mode === 'existing' ? '关联已有事件' : '新建事件'}
                </button>
              ))}
            </div>
            <div style={{ display: 'flex', gap: 8 }}>
              <input
                className="filter-input"
                placeholder={linkMode === 'existing' ? '输入事件编号，如 INC-00001A2B...' : '输入新事件标题...'}
                value={linkInput}
                onChange={e => setLinkInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && (linkMode === 'existing' ? doLinkExisting() : doCreateAndLink())}
                style={{ flex: 1, fontSize: 11 }}
                autoFocus
              />
              <button
                className="btn-primary"
                style={{ fontSize: 11 }}
                disabled={acting || !linkInput.trim()}
                onClick={linkMode === 'existing' ? doLinkExisting : doCreateAndLink}
              >
                {acting ? '...' : '确认'}
              </button>
              <button className="btn-secondary" style={{ fontSize: 11 }} onClick={() => { setLinkMode('none'); setLinkInput('') }}>✕</button>
            </div>
          </div>
        )}

        {/* Action buttons */}
        <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
          <button
            className="btn-primary"
            style={{ fontSize: 10.5, padding: '4px 10px' }}
            onClick={viewCausality}
          >
            溯源图 →
          </button>
          {canInvestigate && (
            <button
              className="btn-secondary"
              style={{ fontSize: 10.5, padding: '4px 10px', color: '#f9a825', borderColor: 'rgba(249,168,37,.3)' }}
              disabled={acting}
              onClick={() => markStatus('investigating')}
            >
              开始调查
            </button>
          )}
          {canResolve && a.status === 'investigating' && (
            <button
              className="btn-secondary"
              style={{ fontSize: 10.5, padding: '4px 10px', color: '#2fb07a', borderColor: 'rgba(47,176,122,.3)' }}
              disabled={acting}
              onClick={() => markStatus('resolved')}
            >
              ✓ 标记解决
            </button>
          )}
          {canFP && (
            <button
              className="btn-secondary"
              style={{ fontSize: 10.5, padding: '4px 10px', color: 'var(--text-muted)' }}
              disabled={acting}
              onClick={() => markStatus('false_positive')}
            >
              标记误报
            </button>
          )}
        </div>
      </div>

      {/* ── Tabs ────────────────────────────── */}
      <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', background: 'var(--bg-secondary)', flexShrink: 0 }}>
        {TABS.map(t => (
          <button
            key={t.id}
            className={`tab${tab === t.id ? ' active' : ''}`}
            style={{ padding: '8px 12px', fontSize: 11.5 }}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* ── Tab content ─────────────────────── */}
      <div style={{ flex: 1, overflowY: 'auto', padding: '14px 16px' }}>
        {loading && (
          <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24, fontSize: 12 }}>加载中...</div>
        )}

        {/* 概览 */}
        {!loading && tab === 'overview' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>

            {/* Advice card — most important for security value */}
            {advice && (
              <div style={{
                padding: '10px 12px', borderRadius: 5,
                background: 'rgba(249,168,37,.06)',
                border: '1px solid rgba(249,168,37,.25)',
                borderLeft: '3px solid #f9a825',
              }}>
                <div style={{ fontSize: 10, color: '#f9a825', fontWeight: 700, textTransform: 'uppercase', letterSpacing: 0.5, marginBottom: 5 }}>
                  🛡 处置建议
                </div>
                <div style={{ fontSize: 11.5, color: 'var(--text-secondary)', lineHeight: 1.65 }}>
                  {advice}
                </div>
              </div>
            )}

            {/* Alert age — prominent display */}
            <div style={{
              padding: '10px 12px', borderRadius: 5,
              background: 'rgba(79,163,224,.05)',
              border: '1px solid rgba(79,163,224,.2)',
              display: 'flex', alignItems: 'baseline', gap: 10,
            }}>
              <span style={{ fontSize: 10.5, color: 'var(--text-muted)', flexShrink: 0 }}>触发时间</span>
              <span style={{ fontSize: 15, fontWeight: 700, color: 'var(--accent-blue)' }}>
                {fmtRelative(alertTime(a))}
              </span>
              <span style={{ fontSize: 10.5, color: 'var(--text-muted)', marginLeft: 'auto' }}>
                {fmtDate(alertTime(a))}
              </span>
            </div>

            {/* Key fields */}
            {[
              { label: '来源', value: SOURCE_LABELS[alertSource(a)] ?? alertSource(a) },
              { label: '检测规则', value: a.detection_rule || '—' },
              ...(a.mitre_tactic ? [{ label: 'MITRE 战术', value: a.mitre_tactic, color: 'var(--accent-blue)' as string | undefined }] : []),
            ].map(row => (
              <div key={row.label} style={{
                display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start',
                padding: '5px 0', borderBottom: '1px solid rgba(255,255,255,.04)', fontSize: 12,
                gap: 12,
              }}>
                <span style={{ color: 'var(--text-muted)', flexShrink: 0 }}>{row.label}</span>
                <span style={{ color: (row as { color?: string }).color ?? 'var(--text-secondary)', textAlign: 'right', wordBreak: 'break-all' }}>{row.value}</span>
              </div>
            ))}

            {/* Description */}
            <div>
              <div style={{ fontSize: 10.5, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.4, marginBottom: 8 }}>
                告警描述
              </div>
              <div style={{
                fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.65,
                padding: '10px 12px', background: 'rgba(255,255,255,.03)',
                borderRadius: 4, border: '1px solid var(--border)',
              }}>
                {a.description
                  ? a.description
                  : alertHost(a)
                    ? `在主机 ${alertHost(a)} 上检测到异常行为，由「${a.detection_rule || '行为分析引擎'}」触发。来源：${SOURCE_LABELS[alertSource(a)] ?? alertSource(a)}。`
                    : `告警由「${a.detection_rule || '行为分析引擎'}」触发。来源：${SOURCE_LABELS[alertSource(a)] ?? alertSource(a)}。`
                }
              </div>
            </div>

            {/* MITRE tactic chain */}
            {a.mitre_tactics && a.mitre_tactics.length > 1 && (
              <div>
                <div style={{ fontSize: 10.5, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.4, marginBottom: 8 }}>
                  MITRE ATT&amp;CK 战术链
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {a.mitre_tactics.map(t => (
                    <span key={t} style={{
                      fontSize: 10.5, padding: '3px 8px', borderRadius: 3,
                      background: 'rgba(59,158,222,.1)', color: 'var(--accent-blue)',
                      border: '1px solid rgba(59,158,222,.2)',
                    }}>{t}</span>
                  ))}
                </div>
              </div>
            )}

            {/* ── Status timeline ── */}
            <div>
              <div style={{ fontSize: 10.5, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.4, marginBottom: 10 }}>
                状态进程
              </div>
              <div style={{ display: 'flex', alignItems: 'flex-start', gap: 0 }}>
                {STATUS_FLOW.map((step, idx) => {
                  const isPast = idx < currentStep
                  const isCurrent = idx === currentStep
                  const isFuture = idx > currentStep
                  const dotColor = isCurrent ? '#4fa3e0' : isPast ? '#2fb07a' : 'rgba(255,255,255,.15)'
                  const lineColor = idx < currentStep ? '#2fb07a' : 'rgba(255,255,255,.1)'
                  // Timestamps: first step = created_at, current step = updated_at
                  const ts = idx === 0 ? a.created_at
                    : isCurrent ? (a.updated_at ?? undefined)
                    : isPast ? (a.updated_at ?? undefined)
                    : undefined
                  return (
                    <div key={step.key} style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', flex: 1 }}>
                      <div style={{ display: 'flex', alignItems: 'center', width: '100%' }}>
                        {/* Left connector line */}
                        {idx > 0 && (
                          <div style={{ flex: 1, height: 2, background: lineColor }} />
                        )}
                        {/* Dot */}
                        <div style={{
                          width: isCurrent ? 12 : 8,
                          height: isCurrent ? 12 : 8,
                          borderRadius: '50%',
                          background: dotColor,
                          flexShrink: 0,
                          boxShadow: isCurrent ? '0 0 8px #4fa3e0' : undefined,
                          border: isCurrent ? '2px solid #4fa3e0' : isFuture ? '2px solid rgba(255,255,255,.15)' : 'none',
                          zIndex: 1,
                        }} />
                        {/* Right connector line */}
                        {idx < STATUS_FLOW.length - 1 && (
                          <div style={{ flex: 1, height: 2, background: isCurrent || isPast ? '#2fb07a' : 'rgba(255,255,255,.1)' }} />
                        )}
                      </div>
                      {/* Label + timestamp */}
                      <div style={{ marginTop: 5, textAlign: 'center' }}>
                        <div style={{
                          fontSize: 10, fontWeight: isCurrent ? 700 : 400,
                          color: isCurrent ? '#4fa3e0' : isPast ? '#2fb07a' : 'var(--text-muted)',
                        }}>
                          {step.label}
                        </div>
                        {ts && (
                          <div style={{ fontSize: 9, color: 'var(--text-muted)', marginTop: 2 }}>
                            {fmtDate(ts)}
                          </div>
                        )}
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          </div>
        )}

        {/* 进程树 */}
        {!loading && tab === 'process' && (
          <ProcessTree procs={procs} sourceType={alertSource(a)} />
        )}

        {/* IOC关联 */}
        {!loading && tab === 'ioc' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>

            {/* Alert's own IOCs */}
            <div>
              <div style={{
                fontSize: 10.5, color: 'var(--text-muted)', textTransform: 'uppercase',
                letterSpacing: 0.4, marginBottom: 8,
                display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              }}>
                <span>告警 IOC 指标</span>
                <button
                  onClick={() => navigate('/iocs')}
                  style={{
                    background: 'none', border: 'none', cursor: 'pointer',
                    color: 'var(--accent-blue)', fontSize: 10.5, padding: 0,
                    textDecoration: 'underline',
                  }}
                >查看详情 →</button>
              </div>
              {iocs.length === 0 ? (
                <div style={{
                  padding: '18px 14px', borderRadius: 5, textAlign: 'center',
                  background: 'rgba(255,255,255,.02)', border: '1px dashed var(--border)',
                }}>
                  <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 10 }}>暂无 IOC 关联</div>
                  <button
                    className="btn-secondary"
                    style={{ fontSize: 11 }}
                    onClick={() => setIocModalOpen(true)}
                  >
                    🔍 搜索 IOC
                  </button>
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {iocs.map((ioc, i) => {
                    const vColor = verdictColor[ioc.verdict] ?? '#546e7a'
                    const vLabel = ioc.verdict === 'malicious' ? '恶意'
                      : ioc.verdict === 'suspicious' ? '可疑'
                      : ioc.verdict === 'clean' ? '安全'
                      : '未知'
                    const typeColor = ioc.type === 'ip' || ioc.type === 'IP' ? '#ef5350'
                      : ioc.type === 'domain' ? '#ab47bc'
                      : ioc.type === 'hash' || ioc.type === 'file_hash' ? '#ff7043'
                      : ioc.type === 'url' ? '#26c6da'
                      : '#78909c'
                    const confidence = ioc.confidence ?? 0
                    const valDisplay = ioc.value.length > 42 ? ioc.value.slice(0, 42) + '…' : ioc.value
                    return (
                      <div key={i} style={{
                        padding: '8px 10px', background: 'var(--bg-secondary)',
                        border: `1px solid ${vColor}25`, borderLeft: `3px solid ${vColor}`,
                        borderRadius: 4,
                      }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: confidence > 0 ? 5 : 0 }}>
                          {/* Type badge */}
                          <span style={{
                            fontSize: 9.5, padding: '1px 6px', borderRadius: 3,
                            background: typeColor + '22', color: typeColor,
                            fontWeight: 700, letterSpacing: 0.2, flexShrink: 0,
                          }}>{ioc.type.toUpperCase()}</span>
                          {/* Value — monospace, truncated */}
                          <span style={{
                            flex: 1, fontSize: 11, fontFamily: 'Consolas,"JetBrains Mono",monospace',
                            color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                          }} title={ioc.value}>{valDisplay}</span>
                          {/* Verdict badge */}
                          <span style={{
                            fontSize: 9.5, padding: '2px 6px', borderRadius: 3,
                            background: vColor + '22', color: vColor,
                            fontWeight: 700, flexShrink: 0,
                          }}>{vLabel}</span>
                        </div>
                        {/* Confidence bar */}
                        {confidence > 0 && (
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                            <div style={{
                              flex: 1, height: 3, background: 'rgba(255,255,255,.08)',
                              borderRadius: 2, overflow: 'hidden',
                            }}>
                              <div style={{
                                height: '100%', width: `${Math.min(confidence, 100)}%`,
                                background: vColor, borderRadius: 2, transition: 'width .3s',
                              }} />
                            </div>
                            <span style={{ fontSize: 9.5, color: 'var(--text-muted)', flexShrink: 0 }}>{confidence}%</span>
                          </div>
                        )}
                        {ioc.note && (
                          <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 3 }}>{ioc.note}</div>
                        )}
                        {/* Link to IOC page with query */}
                        <div style={{ marginTop: 5, textAlign: 'right' }}>
                          <button
                            onClick={() => navigate(`/iocs?q=${encodeURIComponent(ioc.value)}`)}
                            style={{
                              background: 'none', border: 'none', cursor: 'pointer',
                              color: 'var(--accent-blue)', fontSize: 10, padding: 0,
                              textDecoration: 'underline',
                            }}
                          >在 IOC 库中查看 →</button>
                        </div>
                      </div>
                    )
                  })}
                </div>
              )}
            </div>

            {/* Related IOCs from search */}
            <div>
              <div style={{
                fontSize: 10.5, color: 'var(--text-muted)', textTransform: 'uppercase',
                letterSpacing: 0.4, marginBottom: 8,
                display: 'flex', alignItems: 'center', gap: 8,
              }}>
                <span>关联 IOC（主机 / 用户）</span>
                {iocSearchLoading && (
                  <span style={{ fontSize: 10, color: 'var(--accent-blue)' }}>搜索中...</span>
                )}
              </div>
              {!iocSearchLoading && iocSearchResults.length === 0 ? (
                <div style={{
                  padding: '18px 14px', borderRadius: 5, textAlign: 'center',
                  background: 'rgba(255,255,255,.02)', border: '1px dashed var(--border)',
                }}>
                  <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 10 }}>
                    {alertHost(a) || alertUser(a)
                      ? '暂无 IOC 关联'
                      : '该告警无主机或用户信息，无法关联搜索。'
                    }
                  </div>
                  {(alertHost(a) || alertUser(a)) && (
                    <button
                      className="btn-secondary"
                      style={{ fontSize: 11 }}
                      onClick={() => setIocModalOpen(true)}
                    >
                      🔍 搜索 IOC
                    </button>
                  )}
                </div>
              ) : (
                <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                  {iocSearchResults.map((ioc, i) => {
                    const v = ioc.verdict ?? 'unknown'
                    const vColor = verdictColor[v] ?? '#546e7a'
                    const vLabel = v === 'malicious' ? '恶意'
                      : v === 'suspicious' ? '可疑'
                      : v === 'clean' ? '安全'
                      : '未知'
                    const typeColor = ioc.type === 'ip' || ioc.type === 'IP' ? '#ef5350'
                      : ioc.type === 'domain' ? '#ab47bc'
                      : ioc.type === 'hash' || ioc.type === 'file_hash' ? '#ff7043'
                      : ioc.type === 'url' ? '#26c6da'
                      : '#78909c'
                    const confidence = ioc.confidence ?? 0
                    const valDisplay = ioc.value.length > 42 ? ioc.value.slice(0, 42) + '…' : ioc.value
                    return (
                      <div key={i} style={{
                        padding: '8px 10px', background: 'var(--bg-secondary)',
                        border: `1px solid ${vColor}25`, borderLeft: `3px solid ${vColor}`,
                        borderRadius: 4,
                      }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, marginBottom: confidence > 0 ? 5 : 0 }}>
                          <span style={{
                            fontSize: 9.5, padding: '1px 6px', borderRadius: 3,
                            background: typeColor + '22', color: typeColor,
                            fontWeight: 700, letterSpacing: 0.2, flexShrink: 0,
                          }}>{ioc.type.toUpperCase()}</span>
                          <span style={{
                            flex: 1, fontSize: 11, fontFamily: 'Consolas,"JetBrains Mono",monospace',
                            color: 'var(--text-secondary)', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                          }} title={ioc.value}>{valDisplay}</span>
                          <span style={{
                            fontSize: 9.5, padding: '2px 6px', borderRadius: 3,
                            background: vColor + '22', color: vColor,
                            fontWeight: 700, flexShrink: 0,
                          }}>{vLabel}</span>
                        </div>
                        {confidence > 0 && (
                          <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                            <div style={{
                              flex: 1, height: 3, background: 'rgba(255,255,255,.08)',
                              borderRadius: 2, overflow: 'hidden',
                            }}>
                              <div style={{
                                height: '100%', width: `${Math.min(confidence, 100)}%`,
                                background: vColor, borderRadius: 2, transition: 'width .3s',
                              }} />
                            </div>
                            <span style={{ fontSize: 9.5, color: 'var(--text-muted)', flexShrink: 0 }}>{confidence}%</span>
                          </div>
                        )}
                        {(ioc.note ?? ioc.description) && (
                          <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 3 }}>
                            {ioc.note ?? ioc.description}
                          </div>
                        )}
                        <div style={{ marginTop: 5, textAlign: 'right' }}>
                          <button
                            onClick={() => navigate(`/iocs?q=${encodeURIComponent(ioc.value)}`)}
                            style={{
                              background: 'none', border: 'none', cursor: 'pointer',
                              color: 'var(--accent-blue)', fontSize: 10, padding: 0,
                              textDecoration: 'underline',
                            }}
                          >在 IOC 库中查看 →</button>
                        </div>
                      </div>
                    )
                  })}
                </div>
              )}
              {/* Navigate to full IOC page */}
              <div style={{ marginTop: 10, textAlign: 'right' }}>
                <button
                  onClick={() => navigate('/iocs')}
                  style={{
                    background: 'none', border: '1px solid var(--border-light)',
                    borderRadius: 4, cursor: 'pointer',
                    color: 'var(--accent-blue)', fontSize: 11, padding: '4px 10px',
                  }}
                >
                  前往 IOC 情报库 →
                </button>
              </div>
            </div>
          </div>
        )}

        {/* 原始数据 */}
        {!loading && tab === 'raw' && (
          <div>
            <div style={{ fontSize: 10.5, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.4, marginBottom: 10 }}>
              原始告警数据
            </div>
            <pre style={{
              background: 'var(--bg-secondary)', border: '1px solid var(--border)', borderRadius: 4,
              padding: 12, fontSize: 10.5, fontFamily: 'Consolas,"JetBrains Mono",monospace',
              color: '#7ec8e3', overflow: 'auto', lineHeight: 1.7, whiteSpace: 'pre-wrap',
              maxHeight: 500,
            }}>
              {JSON.stringify(a, null, 2)}
            </pre>
          </div>
        )}
      </div>

      {/* IOC Search Modal */}
      {iocModalOpen && <IocSearchModal onClose={() => setIocModalOpen(false)} />}
    </div>
  )
}

// ─── Advanced Filter Panel ────────────────────────────────────────────────────

interface AdvancedFilterProps {
  sourceTypes: string[]
  onSourceTypesChange: (v: string[]) => void
  mitreTactics: string[]
  onMitreTacticsChange: (v: string[]) => void
  hostFilter: string
  onHostFilterChange: (v: string) => void
  assignedFilter: string
  onAssignedFilterChange: (v: string) => void
  dateFrom: string
  onDateFromChange: (v: string) => void
  dateTo: string
  onDateToChange: (v: string) => void
  quickTime: string
  onQuickTimeChange: (v: string) => void
  onReset: () => void
}

function AdvancedFilterPanel({
  sourceTypes, onSourceTypesChange,
  mitreTactics, onMitreTacticsChange,
  hostFilter, onHostFilterChange,
  assignedFilter, onAssignedFilterChange,
  dateFrom, onDateFromChange,
  dateTo, onDateToChange,
  quickTime, onQuickTimeChange,
  onReset,
}: AdvancedFilterProps) {
  function toggleItem(arr: string[], val: string, setter: (v: string[]) => void) {
    if (arr.includes(val)) setter(arr.filter(x => x !== val))
    else setter([...arr, val])
  }

  const QUICK_TIMES = [
    { label: '最近1h', value: '1' },
    { label: '最近6h', value: '6' },
    { label: '最近24h', value: '24' },
    { label: '最近7天', value: '168' },
  ]

  return (
    <div style={{
      padding: '12px 20px 14px',
      background: 'var(--bg-secondary)',
      borderBottom: '1px solid var(--border)',
      flexShrink: 0,
    }}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>

        {/* Time range */}
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 14, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 11, color: 'var(--text-muted)', flexShrink: 0, paddingTop: 4, minWidth: 56 }}>时间范围</span>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap', alignItems: 'center' }}>
            {QUICK_TIMES.map(qt => (
              <button
                key={qt.value}
                onClick={() => { onQuickTimeChange(quickTime === qt.value ? '' : qt.value); onDateFromChange(''); onDateToChange('') }}
                style={{
                  padding: '3px 10px', borderRadius: 3, cursor: 'pointer', fontSize: 11,
                  background: quickTime === qt.value ? 'rgba(79,163,224,.2)' : 'rgba(255,255,255,.05)',
                  border: `1px solid ${quickTime === qt.value ? 'rgba(79,163,224,.5)' : 'var(--border-light)'}`,
                  color: quickTime === qt.value ? '#4fa3e0' : 'var(--text-secondary)',
                  fontWeight: quickTime === qt.value ? 600 : 400, transition: 'all .1s',
                }}
              >{qt.label}</button>
            ))}
            <span style={{ fontSize: 11, color: 'var(--text-muted)', margin: '0 4px' }}>自定义</span>
            <input
              type="datetime-local"
              className="filter-input"
              style={{ fontSize: 10.5, padding: '3px 6px', width: 145 }}
              value={dateFrom}
              onChange={e => { onDateFromChange(e.target.value); onQuickTimeChange('') }}
            />
            <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>至</span>
            <input
              type="datetime-local"
              className="filter-input"
              style={{ fontSize: 10.5, padding: '3px 6px', width: 145 }}
              value={dateTo}
              onChange={e => { onDateToChange(e.target.value); onQuickTimeChange('') }}
            />
          </div>
        </div>

        {/* Source type */}
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 14, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 11, color: 'var(--text-muted)', flexShrink: 0, paddingTop: 2, minWidth: 56 }}>来源类型</span>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {SOURCE_TYPES_LIST.map(src => {
              const active = sourceTypes.includes(src)
              return (
                <button
                  key={src}
                  onClick={() => toggleItem(sourceTypes, src, onSourceTypesChange)}
                  style={{
                    padding: '2px 10px', borderRadius: 12, cursor: 'pointer', fontSize: 11,
                    background: active ? 'rgba(79,163,224,.2)' : 'rgba(255,255,255,.04)',
                    border: `1px solid ${active ? 'rgba(79,163,224,.5)' : 'var(--border-light)'}`,
                    color: active ? '#4fa3e0' : 'var(--text-secondary)',
                    fontWeight: active ? 600 : 400, transition: 'all .1s',
                    display: 'inline-flex', alignItems: 'center', gap: 4,
                  }}
                >
                  {active && <span style={{ fontSize: 9, lineHeight: 1 }}>✓</span>}
                  {src}
                </button>
              )
            })}
          </div>
        </div>

        {/* MITRE tactic */}
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 14, flexWrap: 'wrap' }}>
          <span style={{ fontSize: 11, color: 'var(--text-muted)', flexShrink: 0, paddingTop: 2, minWidth: 56 }}>MITRE</span>
          <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
            {MITRE_TACTICS_LIST.map(tactic => (
              <button
                key={tactic}
                onClick={() => toggleItem(mitreTactics, tactic, onMitreTacticsChange)}
                style={{
                  padding: '2px 8px', borderRadius: 3, cursor: 'pointer', fontSize: 10.5,
                  background: mitreTactics.includes(tactic) ? 'rgba(59,158,222,.2)' : 'rgba(255,255,255,.04)',
                  border: `1px solid ${mitreTactics.includes(tactic) ? 'rgba(59,158,222,.5)' : 'var(--border-light)'}`,
                  color: mitreTactics.includes(tactic) ? 'var(--accent-blue)' : 'var(--text-muted)',
                  fontWeight: mitreTactics.includes(tactic) ? 600 : 400, transition: 'all .1s',
                }}
              >{tactic}</button>
            ))}
          </div>
        </div>

        {/* Host + Assigned to */}
        <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap', alignItems: 'center' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 11, color: 'var(--text-muted)', flexShrink: 0 }}>主机</span>
            <input
              className="filter-input"
              style={{ width: 160, fontSize: 11 }}
              placeholder="主机名或 IP..."
              value={hostFilter}
              onChange={e => onHostFilterChange(e.target.value)}
            />
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ fontSize: 11, color: 'var(--text-muted)', flexShrink: 0 }}>处置人</span>
            <input
              className="filter-input"
              style={{ width: 140, fontSize: 11 }}
              placeholder="用户名..."
              value={assignedFilter}
              onChange={e => onAssignedFilterChange(e.target.value)}
            />
          </div>
          <button
            className="btn-secondary"
            style={{ fontSize: 11, marginLeft: 'auto' }}
            onClick={onReset}
          >
            重置筛选
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Alert Stats Panel ────────────────────────────────────────────────────────

interface AlertStatsPanelProps {
  stats: AlertStats | null
  loading: boolean
}

function AlertStatsPanel({ stats, loading }: AlertStatsPanelProps) {
  const tiles: { label: string; value: string | number; color: string; subtext?: string }[] = [
    {
      label: '总告警数',
      value: loading ? '…' : (stats?.total ?? '—'),
      color: '#4fa3e0',
    },
    {
      label: '严重',
      value: loading ? '…' : (stats?.by_severity?.critical ?? 0),
      color: '#e53935',
    },
    {
      label: '高危',
      value: loading ? '…' : (stats?.by_severity?.high ?? 0),
      color: '#ff6f00',
    },
    {
      label: '今日新增',
      value: loading ? '…' : (stats?.new_last_24h ?? 0),
      color: '#f9a825',
    },
    {
      label: '已处置',
      value: loading ? '…' : (stats?.by_status?.resolved ?? 0),
      color: '#2fb07a',
    },
    {
      label: 'MTTR',
      value: loading ? '…' : (stats?.mttr_hours != null ? `${stats.mttr_hours.toFixed(1)}h` : '—'),
      color: '#26c6da',
    },
  ]

  return (
    <div style={{
      display: 'flex', gap: 12, padding: '12px 20px',
      background: 'var(--bg-secondary)',
      borderBottom: '1px solid var(--border)',
      flexShrink: 0, flexWrap: 'wrap',
    }}>
      {tiles.map(tile => (
        <div key={tile.label} style={{
          flex: '1 1 120px', minWidth: 100,
          padding: '10px 14px',
          background: 'var(--bg-card)',
          border: `1px solid var(--border)`,
          borderLeft: `3px solid ${tile.color}`,
          borderRadius: 5,
          display: 'flex', flexDirection: 'column', gap: 4,
        }}>
          <div style={{
            fontSize: 22, fontWeight: 700, fontVariantNumeric: 'tabular-nums',
            color: tile.color, lineHeight: 1,
          }}>
            {tile.value}
          </div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 4 }}>
            {tile.label}
            {tile.subtext && (
              <span style={{
                fontSize: 9, padding: '1px 5px', borderRadius: 3,
                background: tile.color + '22', color: tile.color,
                fontWeight: 700, letterSpacing: 0.3,
              }}>{tile.subtext}</span>
            )}
          </div>
        </div>
      ))}
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function Alerts() {
  const navigate = useNavigate()
  const [alerts, setAlerts] = useState<Alert[]>([])
  const [meta, setMeta] = useState<PageMeta>({ page: 1, page_size: 20, total: 0, total_pages: 1 })
  const [page, setPage] = useState(1)
  const [severityFilter, setSeverityFilter] = useState('')
  const [sourceFilter, setSourceFilter] = useState('')
  const [statusFilter, setStatusFilter] = useState('')
  const [incidentFilter, setIncidentFilter] = useState('')
  const [timeFilter, setTimeFilter] = useState('')
  const [mitreFilter, setMitreFilter] = useState('')
  const [search, setSearch] = useState('')
  const [selected, setSelected] = useState<Alert | null>(null)
  const [loading, setLoading] = useState(false)
  const [checked, setChecked] = useState<Set<string>>(new Set())
  const [sortBy, setSortBy] = useState('triggered_at')
  const [sortDesc, setSortDesc] = useState(true)
  const [hovered, setHovered] = useState<string | null>(null)
  // Bulk investigate inline form
  const [bulkIncMode, setBulkIncMode] = useState(false)
  const [bulkIncTitle, setBulkIncTitle] = useState('')
  const [bulkActing, setBulkActing] = useState(false)
  // Bulk status update
  const [bulkStatusValue, setBulkStatusValue] = useState('')
  const [bulkAssignee, setBulkAssignee] = useState('')

  // ── Advanced filter state ──
  const [advancedOpen, setAdvancedOpen] = useState(false)
  const [advSourceTypes, setAdvSourceTypes] = useState<string[]>([])
  const [advMitreTactics, setAdvMitreTactics] = useState<string[]>([])
  const [advHostFilter, setAdvHostFilter] = useState('')
  const [advAssignedFilter, setAdvAssignedFilter] = useState('')
  const [advDateFrom, setAdvDateFrom] = useState('')
  const [advDateTo, setAdvDateTo] = useState('')
  const [advQuickTime, setAdvQuickTime] = useState('')

  // ── Alert stats state ──
  const [stats, setStats] = useState<AlertStats | null>(null)
  const [statsLoading, setStatsLoading] = useState(false)

  // ── Auto-refresh state ──
  const [autoRefresh, setAutoRefresh] = useState(false)
  const [lastRefreshed, setLastRefreshed] = useState<Date | null>(null)
  const autoRefreshRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const mountedRef = useRef(false)

  function loadStats() {
    setStatsLoading(true)
    api.get('/alerts/stats')
      .then(r => setStats(r.data.data ?? r.data ?? null))
      .catch(() => {})
      .finally(() => setStatsLoading(false))
  }

  // Initial stats load
  useEffect(() => { loadStats() }, [])

  // Stats auto-refresh every 30 seconds
  useEffect(() => {
    const t = setInterval(() => { loadStats() }, 30000)
    return () => clearInterval(t)
  }, [])

  // ── Auto-refresh list ──
  // Wrap load in useCallback to avoid stale closure in interval
  const loadRef = useRef<(p: number) => void>(() => {})

  // Auto-refresh interval management
  useEffect(() => {
    if (autoRefreshRef.current) {
      clearInterval(autoRefreshRef.current)
      autoRefreshRef.current = null
    }
    if (autoRefresh) {
      autoRefreshRef.current = setInterval(() => {
        loadRef.current(1)
        loadStats()
        setLastRefreshed(new Date())
      }, 30000)
    }
    return () => {
      if (autoRefreshRef.current) clearInterval(autoRefreshRef.current)
    }
  }, [autoRefresh])

  function fmtTime(d: Date): string {
    const p = (n: number) => n.toString().padStart(2, '0')
    return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`
  }

  function load(p: number, opts?: {
    severity?: string; source?: string; status?: string; incident?: string
    time?: string; q?: string; sortBy?: string; sortDesc?: boolean; mitre?: string
    host?: string; assigned?: string; dateFrom?: string; dateTo?: string
    sourceTypes?: string[]; mitreTactics?: string[]
  }) {
    const v  = opts?.severity ?? severityFilter
    const sr = opts?.source   ?? sourceFilter
    const s  = opts?.status   ?? statusFilter
    const ic = opts?.incident ?? incidentFilter
    const t  = opts?.time     ?? timeFilter
    const mf = opts?.mitre    ?? mitreFilter
    const q  = opts?.q        ?? search
    const sb = opts?.sortBy   ?? sortBy
    const sd = opts?.sortDesc ?? sortDesc
    const host = opts?.host ?? advHostFilter
    const assigned = opts?.assigned ?? advAssignedFilter
    const dateFrom = opts?.dateFrom ?? advDateFrom
    const dateTo = opts?.dateTo ?? advDateTo
    const srcTypes = opts?.sourceTypes ?? advSourceTypes
    const mTactics = opts?.mitreTactics ?? advMitreTactics
    const quickT = advQuickTime

    setLoading(true)
    const params: Record<string, unknown> = { page: p, page_size: 20, sort_by: sb, sort_desc: sd }
    if (v)  params.severity = v
    if (sr) params.source = sr
    if (s)  params.status = s
    if (q)  params.q = q
    // Time: advanced quick-time takes priority over main filter
    if (quickT) params.hours = quickT
    else if (t) params.hours = t
    if (mf) params.mitre_tactic = mf
    if (ic === 'unlinked') params.unlinked = true
    if (ic === 'linked')   params.linked = true
    // Advanced filter params
    if (host) params.host = host
    if (assigned) params.assigned_to = assigned
    if (dateFrom) params.date_from = dateFrom
    if (dateTo) params.date_to = dateTo
    if (srcTypes.length > 0) params.source_types = srcTypes.join(',')
    if (mTactics.length > 0) params.mitre_tactics = mTactics.join(',')

    api.get('/alerts', { params })
      .then(r => {
        setAlerts(r.data.data?.items ?? [])
        setMeta(r.data.data?.meta ?? { page: p, page_size: 20, total: 0, total_pages: 1 })
      })
      .catch(() => {})
      .finally(() => setLoading(false))
  }

  // Keep loadRef in sync so the auto-refresh interval always calls the latest load
  useEffect(() => { loadRef.current = load })

  useEffect(() => { load(page) }, [page])

  useEffect(() => {
    if (!mountedRef.current) { mountedRef.current = true; return }
    setPage(1); load(1)
  }, [severityFilter, sourceFilter, statusFilter, incidentFilter, timeFilter, mitreFilter])

  // Reload when advanced filters change
  useEffect(() => {
    if (!mountedRef.current) return
    setPage(1); load(1)
  }, [advSourceTypes, advMitreTactics, advHostFilter, advAssignedFilter, advDateFrom, advDateTo, advQuickTime])

  function doSearch() { setPage(1); load(1) }

  function doSort(col: string) {
    const nd = col === sortBy ? !sortDesc : true
    setSortBy(col); setSortDesc(nd)
    setPage(1); load(1, { sortBy: col, sortDesc: nd })
  }

  function handleUpdate(key: string, patch: Partial<Alert>) {
    setAlerts(prev => prev.map(a => a._key === key ? { ...a, ...patch } : a))
    setSelected(prev => prev?._key === key ? { ...prev, ...patch } : prev)
  }

  function resetAdvancedFilters() {
    setAdvSourceTypes([])
    setAdvMitreTactics([])
    setAdvHostFilter('')
    setAdvAssignedFilter('')
    setAdvDateFrom('')
    setAdvDateTo('')
    setAdvQuickTime('')
  }

  function exportCSV() {
    const header = ['ID', '告警名称', '严重程度', '状态', '来源', '主机', '用户', 'MITRE 战术', '检测规则', '时间']
    const rows = [header.join(',')]
    alerts.forEach(a => rows.push([
      `ALT-${a._key.slice(-8).toUpperCase()}`,
      `"${a.name.replace(/"/g, '""')}"`,
      SEV_LABELS[a.severity] ?? a.severity,
      STATUS_LABELS[a.status] ?? a.status,
      SOURCE_LABELS[alertSource(a)] ?? alertSource(a),
      alertHost(a),
      alertUser(a),
      a.mitre_tactic ?? '',
      a.detection_rule ?? '',
      fmtDate(alertTime(a)),
    ].join(',')))
    const blob = new Blob(['﻿' + rows.join('\n')], { type: 'text/csv;charset=utf-8;' })
    const link = document.createElement('a')
    link.href = URL.createObjectURL(blob)
    link.download = `alerts_${new Date().toISOString().slice(0,10)}.csv`
    link.click()
  }

  function exportSelectedCSV() {
    if (!checked.size) return
    const selectedAlerts = alerts.filter(a => checked.has(a._key))
    const header = ['ID', '告警名称', '严重程度', '状态', '来源', '主机', '用户', 'MITRE 战术', '检测规则', '关联事件', '时间']
    const rows = [header.join(',')]
    selectedAlerts.forEach(a => rows.push([
      `ALT-${a._key.slice(-8).toUpperCase()}`,
      `"${a.name.replace(/"/g, '""')}"`,
      SEV_LABELS[a.severity] ?? a.severity,
      STATUS_LABELS[a.status] ?? a.status,
      SOURCE_LABELS[alertSource(a)] ?? alertSource(a),
      alertHost(a),
      alertUser(a),
      a.mitre_tactic ?? '',
      a.detection_rule ?? '',
      a.incident_id ? `INC-${a.incident_id}` : '',
      fmtDate(alertTime(a)),
    ].join(',')))
    const blob = new Blob(['﻿' + rows.join('\n')], { type: 'text/csv;charset=utf-8;' })
    const link = document.createElement('a')
    link.href = URL.createObjectURL(blob)
    link.download = `alerts_selected_${new Date().toISOString().slice(0,10)}.csv`
    link.click()
  }

  function bulkUpdateStatus(status: string) {
    if (!checked.size || !status) return
    setBulkActing(true)
    api.post('/alerts/bulk', { action: 'status', ids: [...checked], status })
      .then(() => {
        setChecked(new Set())
        setBulkStatusValue('')
        load(page)
      })
      .finally(() => setBulkActing(false))
  }

  function bulkAssignTo() {
    if (!checked.size || !bulkAssignee.trim()) return
    setBulkActing(true)
    api.post('/alerts/bulk', { action: 'assign', ids: [...checked], assigned_to: bulkAssignee.trim() })
      .then(() => {
        setChecked(new Set())
        setBulkAssignee('')
        load(page)
      })
      .finally(() => setBulkActing(false))
  }

  const toggleCheck = (key: string) => setChecked(prev => {
    const n = new Set(prev)
    if (n.has(key)) n.delete(key); else n.add(key)
    return n
  })

  // Use bulk API (single request) instead of N individual PATCHes
  function bulkPatch(patch: Record<string, unknown>) {
    const keys = [...checked]
    return api.post('/alerts/bulk', { action: 'update', keys, patch })
  }

  function bulkFalsePositive() {
    if (!checked.size) return
    if (!confirm(`确认将 ${checked.size} 条告警标记为误报？`)) return
    api.post('/alerts/bulk', { action: 'false_positive', ids: [...checked] })
      .then(() => { setChecked(new Set()); load(page) })
  }

  function bulkClose() {
    if (!checked.size) return
    if (!confirm(`确认关闭 ${checked.size} 条告警？`)) return
    api.post('/alerts/bulk', { action: 'close', ids: [...checked] })
      .then(() => { setChecked(new Set()); load(page) })
  }

  function doCreateIncidentAndLink() {
    if (!bulkIncTitle.trim()) return
    setBulkActing(true)
    api.post('/incidents', {
      title: bulkIncTitle.trim(), name: bulkIncTitle.trim(),
      severity: 'high', status: 'new',
    })
      .then(r => {
        const incKey = r.data.data?._key
        if (!incKey) return
        return bulkPatch({ incident_id: incKey, status: 'investigating' })
      })
      .then(() => {
        setChecked(new Set()); setBulkIncMode(false); setBulkIncTitle('')
        load(page)
      })
      .finally(() => setBulkActing(false))
  }

  const sevCounts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 }
  alerts.forEach(a => { if (a.severity in sevCounts) sevCounts[a.severity]++ })
  const unlinkedCount = alerts.filter(a => !a.incident_id).length
  const allChecked = !!alerts.length && checked.size === alerts.length
  const hasFilters = !!(severityFilter || sourceFilter || statusFilter || incidentFilter || timeFilter || mitreFilter || search)
  const hasAdvFilters = !!(advSourceTypes.length || advMitreTactics.length || advHostFilter || advAssignedFilter || advDateFrom || advDateTo || advQuickTime)

  const sortArrow = (col: string) => sortBy === col
    ? <span style={{ marginLeft: 3, fontSize: 9, opacity: 0.7 }}>{sortDesc ? '▼' : '▲'}</span>
    : null

  const colCount = selected ? 9 : 11

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

      {/* ── Header ──────────────────────────────────────── */}
      <PageHeader
        title="告警管理"
        subtitle={meta.total > 0 ? `共 ${meta.total} 条` : undefined}
        actions={<>
          <button className="btn-secondary" style={{ fontSize: 11 }} onClick={exportCSV}>↓ 导出 CSV</button>
          <button className="btn-primary" style={{ fontSize: 11 }} onClick={() => navigate('/detection-rules?new=1')}>
            + 新建检测规则
          </button>
        </>}
      />

      {/* ── Alert stats panel ───────────────────────────── */}
      <AlertStatsPanel stats={stats} loading={statsLoading} />

      {/* ── Severity + stats strip ───────────────────────── */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 10, padding: '7px 20px',
        borderBottom: '1px solid var(--border)', background: 'var(--bg-secondary)', flexShrink: 0,
        flexWrap: 'wrap',
      }}>
        {([
          ['critical', '严重', '#e53935'],
          ['high',     '高危', '#ff6f00'],
          ['medium',   '中危', '#f9a825'],
          ['low',      '低危', '#2fb07a'],
        ] as [string, string, string][]).map(([key, label, color]) => (
          <button
            key={key}
            onClick={() => setSeverityFilter(severityFilter === key ? '' : key)}
            style={{
              padding: '5px 14px', borderRadius: 4, cursor: 'pointer',
              background: severityFilter === key ? color + '30' : color + '12',
              border: `1px solid ${severityFilter === key ? color : color + '30'}`,
              color, fontSize: 11.5, fontWeight: 600, transition: 'all .12s',
            }}
          >
            {label} <strong style={{ fontVariantNumeric: 'tabular-nums' }}>{sevCounts[key]}</strong>
          </button>
        ))}
        {/* Unlinked alert nudge */}
        {unlinkedCount > 0 && (
          <button
            onClick={() => setIncidentFilter(incidentFilter === 'unlinked' ? '' : 'unlinked')}
            style={{
              padding: '5px 12px', borderRadius: 4, cursor: 'pointer',
              background: incidentFilter === 'unlinked' ? 'rgba(255,111,0,.2)' : 'rgba(255,111,0,.08)',
              border: `1px solid ${incidentFilter === 'unlinked' ? '#ff6f00' : 'rgba(255,111,0,.25)'}`,
              color: '#ff6f00', fontSize: 11, fontWeight: 600, transition: 'all .12s',
            }}
          >
            ⚠ 未关联 <strong>{unlinkedCount}</strong>
          </button>
        )}
        <div style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text-muted)' }}>
          当前页 {alerts.length} 条 / 全局 {meta.total} 条
        </div>
      </div>

      {/* ── Filter bar ──────────────────────────────────── */}
      <div className="filter-bar">
        <input
          className="filter-input"
          style={{ width: 210 }}
          placeholder="搜索告警名称、主机、用户..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          onKeyDown={e => e.key === 'Enter' && doSearch()}
        />
        <button className="btn-secondary" style={{ fontSize: 11 }} onClick={doSearch}>搜索</button>
        <select className="filter-select" value={sourceFilter} onChange={e => setSourceFilter(e.target.value)}>
          <option value="">全部来源</option>
          <option value="endpoint">终端</option>
          <option value="network">网络</option>
          <option value="cloud">云</option>
          <option value="identity">身份</option>
          <option value="email">邮件</option>
        </select>
        <select className="filter-select" value={statusFilter} onChange={e => setStatusFilter(e.target.value)}>
          <option value="">全部状态</option>
          <option value="active">活跃</option>
          <option value="investigating">调查中</option>
          <option value="resolved">已解决</option>
          <option value="false_positive">误报</option>
          <option value="auto_closed">自动关闭</option>
        </select>
        <select className="filter-select" value={timeFilter} onChange={e => setTimeFilter(e.target.value)}>
          <option value="">全部时间</option>
          <option value="24">近 24 小时</option>
          <option value="72">近 3 天</option>
          <option value="168">近 7 天</option>
          <option value="720">近 30 天</option>
        </select>
        <select className="filter-select" value={incidentFilter} onChange={e => setIncidentFilter(e.target.value)}>
          <option value="">全部关联状态</option>
          <option value="unlinked">未关联事件</option>
          <option value="linked">已关联事件</option>
        </select>
        {mitreFilter && (
          <span style={{
            display: 'inline-flex', alignItems: 'center', gap: 5,
            padding: '3px 8px', borderRadius: 3, fontSize: 11,
            background: 'rgba(59,158,222,.12)', color: 'var(--accent-blue)',
            border: '1px solid rgba(59,158,222,.25)', fontWeight: 600,
          }}>
            🎯 {mitreFilter}
            <button
              onClick={() => setMitreFilter('')}
              style={{ background: 'none', border: 'none', cursor: 'pointer', color: 'var(--accent-blue)', fontSize: 12, padding: 0, lineHeight: 1 }}
            >✕</button>
          </span>
        )}
        {hasFilters && (
          <button className="btn-secondary" style={{ fontSize: 11 }} onClick={() => {
            setSeverityFilter(''); setSourceFilter(''); setStatusFilter('')
            setTimeFilter(''); setIncidentFilter(''); setMitreFilter(''); setSearch('')
          }}>✕ 清除</button>
        )}
        {/* Auto-refresh toggle */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginLeft: 'auto' }}>
          <button
            className="btn-secondary"
            style={{
              fontSize: 11,
              color: autoRefresh ? '#2fb07a' : undefined,
              borderColor: autoRefresh ? 'rgba(47,176,122,.4)' : undefined,
              background: autoRefresh ? 'rgba(47,176,122,.08)' : undefined,
            }}
            onClick={() => {
              const next = !autoRefresh
              setAutoRefresh(next)
              if (next) setLastRefreshed(new Date())
            }}
            title={autoRefresh ? '关闭自动刷新' : '开启自动刷新（每30秒）'}
          >
            🔄 自动刷新
          </button>
          {autoRefresh && lastRefreshed && (
            <span style={{ fontSize: 10.5, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
              上次更新: {fmtTime(lastRefreshed)}
            </span>
          )}
        </div>
        {/* Advanced filter toggle */}
        <button
          className="btn-secondary"
          style={{
            fontSize: 11,
            color: hasAdvFilters ? 'var(--accent-blue)' : undefined,
            borderColor: hasAdvFilters ? 'rgba(79,163,224,.4)' : undefined,
          }}
          onClick={() => setAdvancedOpen(v => !v)}
        >
          高级筛选 {advancedOpen ? '▲' : '▼'}
          {hasAdvFilters && (
            <span style={{
              display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
              width: 14, height: 14, borderRadius: '50%',
              background: 'var(--accent-blue)', color: 'white',
              fontSize: 8.5, fontWeight: 700, marginLeft: 5,
            }}>
              {advSourceTypes.length + advMitreTactics.length + (advHostFilter ? 1 : 0) + (advAssignedFilter ? 1 : 0) + (advDateFrom || advDateTo || advQuickTime ? 1 : 0)}
            </span>
          )}
        </button>
      </div>

      {/* ── Advanced filter panel ───────────────────────── */}
      {advancedOpen && (
        <AdvancedFilterPanel
          sourceTypes={advSourceTypes}
          onSourceTypesChange={setAdvSourceTypes}
          mitreTactics={advMitreTactics}
          onMitreTacticsChange={setAdvMitreTactics}
          hostFilter={advHostFilter}
          onHostFilterChange={setAdvHostFilter}
          assignedFilter={advAssignedFilter}
          onAssignedFilterChange={setAdvAssignedFilter}
          dateFrom={advDateFrom}
          onDateFromChange={setAdvDateFrom}
          dateTo={advDateTo}
          onDateToChange={setAdvDateTo}
          quickTime={advQuickTime}
          onQuickTimeChange={setAdvQuickTime}
          onReset={resetAdvancedFilters}
        />
      )}

      {/* ── Bulk action bar ─────────────────────────────── */}
      {checked.size > 0 && (
        <div style={{
          flexShrink: 0, borderBottom: '1px solid rgba(59,158,222,.2)',
          background: 'rgba(59,158,222,.06)',
        }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8, padding: '6px 20px', fontSize: 12, flexWrap: 'wrap' }}>
            <span style={{ color: 'var(--accent-blue)', fontWeight: 600, flexShrink: 0 }}>已选 {checked.size} 条</span>
            {/* 批量更新状态 */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexShrink: 0 }}>
              <select
                className="filter-select"
                style={{ fontSize: 11, height: 26 }}
                value={bulkStatusValue}
                onChange={e => setBulkStatusValue(e.target.value)}
              >
                <option value="">批量更新状态...</option>
                <option value="active">活跃</option>
                <option value="investigating">调查中</option>
                <option value="resolved">已解决</option>
                <option value="false_positive">误报</option>
              </select>
              <button
                className="btn-secondary"
                style={{ fontSize: 11 }}
                disabled={!bulkStatusValue || bulkActing}
                onClick={() => bulkUpdateStatus(bulkStatusValue)}
              >
                应用
              </button>
            </div>
            {/* 批量分配 */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 4, flexShrink: 0 }}>
              <input
                className="filter-input"
                style={{ width: 130, fontSize: 11, height: 26 }}
                placeholder="批量分配给..."
                value={bulkAssignee}
                onChange={e => setBulkAssignee(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && bulkAssignTo()}
              />
              <button
                className="btn-secondary"
                style={{ fontSize: 11 }}
                disabled={!bulkAssignee.trim() || bulkActing}
                onClick={bulkAssignTo}
              >
                分配
              </button>
            </div>
            <button className="btn-secondary" style={{ fontSize: 11 }} onClick={() => { setBulkIncMode(v => !v); setBulkIncTitle('') }}>
              升级为事件
            </button>
            <button className="btn-secondary" style={{ fontSize: 11 }} onClick={bulkFalsePositive}>
              批量误报
            </button>
            <button className="btn-secondary" style={{ fontSize: 11 }} onClick={bulkClose}>
              批量关闭
            </button>
            {/* 导出选中 */}
            <button
              className="btn-secondary"
              style={{ fontSize: 11, color: '#2fb07a', borderColor: 'rgba(47,176,122,.3)' }}
              onClick={exportSelectedCSV}
            >
              ↓ 导出选中
            </button>
            <button
              style={{ marginLeft: 'auto', background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 11 }}
              onClick={() => { setChecked(new Set()); setBulkIncMode(false); setBulkStatusValue(''); setBulkAssignee('') }}
            >取消</button>
          </div>
          {/* Inline create-incident form */}
          {bulkIncMode && (
            <div style={{ padding: '0 20px 10px', display: 'flex', gap: 8, alignItems: 'center' }}>
              <input
                className="filter-input"
                style={{ flex: 1 }}
                placeholder={`为选中的 ${checked.size} 条告警新建事件，输入事件标题...`}
                value={bulkIncTitle}
                onChange={e => setBulkIncTitle(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && doCreateIncidentAndLink()}
                autoFocus
              />
              <button
                className="btn-primary"
                style={{ fontSize: 11 }}
                disabled={bulkActing || !bulkIncTitle.trim()}
                onClick={doCreateIncidentAndLink}
              >
                {bulkActing ? '处理中...' : '确认创建'}
              </button>
              <button className="btn-secondary" style={{ fontSize: 11 }} onClick={() => setBulkIncMode(false)}>取消</button>
            </div>
          )}
        </div>
      )}

      {/* ── Table + detail pane ─────────────────────────── */}
      <div style={{ flex: 1, display: 'flex', overflow: 'hidden' }}>
        <div style={{ flex: 1, minWidth: 0, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
          <div className="data-table-wrap">
            <table className="data-table">
              <thead>
                <tr>
                  <th style={{ width: 36 }}>
                    <input type="checkbox"
                      checked={allChecked}
                      onChange={() => setChecked(allChecked ? new Set() : new Set(alerts.map(a => a._key)))}
                    />
                  </th>
                  <th style={{ width: 68, cursor: 'pointer', userSelect: 'none' }} onClick={() => doSort('severity')}>
                    严重程度{sortArrow('severity')}
                  </th>
                  <th style={{ minWidth: 200 }}>告警名称</th>
                  <th style={{ width: 60 }}>来源</th>
                  <th style={{ width: 128 }}>主机 / 用户</th>
                  <th style={{ width: 88 }}>关联事件</th>
                  {!selected && <th style={{ width: 106 }}>MITRE 战术</th>}
                  {!selected && <th style={{ width: 108 }}>检测规则</th>}
                  <th style={{ width: 72 }}>状态</th>
                  <th style={{ width: 80, cursor: 'pointer', userSelect: 'none' }} onClick={() => doSort('triggered_at')}>
                    时间{sortArrow('triggered_at')}
                  </th>
                  <th style={{ width: 56 }}></th>
                </tr>
              </thead>
              <tbody>
                {loading && (
                  <tr><td colSpan={colCount} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 28 }}>加载中...</td></tr>
                )}
                {!loading && alerts.length === 0 && (
                  <tr>
                    <td colSpan={colCount} style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)', fontSize: 12 }}>
                      {hasFilters || hasAdvFilters ? '没有符合条件的告警' : '暂无告警数据'}
                    </td>
                  </tr>
                )}
                {!loading && alerts.map(alert => {
                  const isHovered = hovered === alert._key
                  return (
                    <tr
                      key={alert._key}
                      className={[
                        selected?._key === alert._key ? 'selected' : '',
                        alert.severity === 'critical' ? 'row-critical' : '',
                      ].filter(Boolean).join(' ')}
                      onClick={() => setSelected(selected?._key === alert._key ? null : alert)}
                      onMouseEnter={() => setHovered(alert._key)}
                      onMouseLeave={() => setHovered(null)}
                      style={{ cursor: 'pointer' }}
                    >
                      <td onClick={e => e.stopPropagation()}>
                        <input type="checkbox" checked={checked.has(alert._key)} onChange={() => toggleCheck(alert._key)} />
                      </td>
                      <td><SevBadge sev={alert.severity} /></td>
                      <td style={{ maxWidth: selected ? 170 : 220 }}>
                        <div style={{ fontSize: 12.5, fontWeight: 500, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis', display: 'flex', alignItems: 'center', gap: 5 }}>
                          <span style={{ overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{alert.name}</span>
                          {alert.incident_id && (
                            <span
                              title={`关联事件 #${alert.incident_id}`}
                              onClick={e => { e.stopPropagation(); navigate(`/incidents?highlight=${alert.incident_id}`) }}
                              style={{
                                flexShrink: 0, fontSize: 11, cursor: 'pointer',
                                color: '#4fa3e0', lineHeight: 1,
                                padding: '1px 4px', borderRadius: 3,
                                background: 'rgba(79,163,224,.12)',
                                border: '1px solid rgba(79,163,224,.3)',
                                textDecoration: 'none',
                              }}
                            >🔗</span>
                          )}
                        </div>
                        {alert.detection_rule && !selected && (
                          <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {alert.detection_rule}
                          </div>
                        )}
                      </td>
                      <td><SourceBadge src={alertSource(alert)} /></td>
                      <td style={{ fontSize: 11 }}>
                        {alertHost(alert) && (
                          <span style={{ color: '#4fa3e0', fontFamily: 'monospace', fontSize: 10.5, display: 'block', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            🖥 {alertHost(alert)}
                          </span>
                        )}
                        {alertUser(alert) && (
                          <span style={{ color: 'var(--text-muted)', fontSize: 10.5 }}>👤 {alertUser(alert)}</span>
                        )}
                        {!alertHost(alert) && !alertUser(alert) && <span style={{ color: 'var(--text-muted)' }}>—</span>}
                      </td>
                      <td style={{ fontSize: 11 }}>
                        {alert.incident_id ? (
                          <span
                            style={{ color: '#4fa3e0', fontFamily: 'monospace', fontSize: 10.5, cursor: 'pointer' }}
                            onClick={e => { e.stopPropagation(); navigate(`/incidents?highlight=${alert.incident_id}`) }}
                          >
                            INC-{alert.incident_id}
                          </span>
                        ) : (
                          <span style={{ color: '#ff6f00', fontSize: 10, fontWeight: 600 }}>未关联</span>
                        )}
                      </td>
                      {!selected && (
                        <td>
                          {alert.mitre_tactic ? (
                            <span
                              title={`按战术筛选: ${alert.mitre_tactic}`}
                              onClick={e => {
                                e.stopPropagation()
                                const next = mitreFilter === alert.mitre_tactic ? '' : (alert.mitre_tactic ?? '')
                                setMitreFilter(next)
                                setPage(1)
                                load(1, { mitre: next })
                              }}
                              style={{
                                fontSize: 10, color: 'var(--accent-blue)',
                                background: mitreFilter === alert.mitre_tactic
                                  ? 'rgba(59,158,222,.25)'
                                  : 'rgba(59,158,222,.1)',
                                padding: '2px 6px', borderRadius: 3,
                                display: 'inline-block', maxWidth: 100,
                                overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap',
                                cursor: 'pointer',
                                border: mitreFilter === alert.mitre_tactic
                                  ? '1px solid rgba(59,158,222,.5)'
                                  : '1px solid transparent',
                              }}
                            >
                              {alert.mitre_tactic}
                            </span>
                          ) : (
                            <span style={{ color: 'var(--text-muted)', fontSize: 11 }}>—</span>
                          )}
                        </td>
                      )}
                      {!selected && (
                        <td style={{ fontSize: 10.5, color: 'var(--text-muted)', maxWidth: 108, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                          {alert.detection_rule || '—'}
                        </td>
                      )}
                      <td><StatusBadge status={alert.status} /></td>
                      <td style={{ fontSize: 10.5, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                        {fmtDate(alertTime(alert))}
                      </td>
                      <td onClick={e => e.stopPropagation()}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 4, justifyContent: 'flex-end' }}>
                          {alert.incident_id && (
                            <a
                              href={`/incidents?highlight=${alert.incident_id}`}
                              title={`已关联事件: ${alert.incident_id}`}
                              onClick={e => { e.preventDefault(); e.stopPropagation(); navigate(`/incidents?highlight=${alert.incident_id}`) }}
                              style={{
                                display: 'inline-flex', alignItems: 'center', justifyContent: 'center',
                                fontSize: 12, lineHeight: 1, flexShrink: 0,
                                padding: '2px 4px', borderRadius: 3,
                                background: 'rgba(79,163,224,.12)',
                                border: '1px solid rgba(79,163,224,.3)',
                                color: '#4fa3e0', textDecoration: 'none', cursor: 'pointer',
                              }}
                            >🔗</a>
                          )}
                          {isHovered && (alert.status === 'active' || alert.status === 'new') ? (
                            <>
                              <button
                                className="btn-secondary"
                                style={{ fontSize: 9.5, padding: '2px 6px', color: '#f9a825', borderColor: 'rgba(249,168,37,.3)' }}
                                title="标记为调查中"
                                onClick={e => {
                                  e.stopPropagation()
                                  api.patch(`/alerts/${alert._key}`, { status: 'investigating' })
                                    .then(() => handleUpdate(alert._key, { status: 'investigating' }))
                                }}
                              >调查</button>
                              <button
                                className="btn-secondary"
                                style={{ fontSize: 9.5, padding: '2px 6px' }}
                                onClick={() => setSelected(alert)}
                              >详情</button>
                            </>
                          ) : (
                            <button
                              className="btn-secondary"
                              style={{ fontSize: 10, padding: '2px 8px' }}
                              onClick={() => setSelected(alert)}
                            >
                              详情
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>

          {/* ── Pagination ────────────────────────────── */}
          <div className="pagination">
            <span style={{ marginRight: 8 }}>
              {meta.total > 0
                ? `第 ${(page-1)*meta.page_size+1}–${Math.min(page*meta.page_size, meta.total)} 条，共 ${meta.total} 条`
                : '暂无结果'
              }
            </span>
            <button className="page-btn" disabled={page <= 1} onClick={() => setPage(p => p-1)}>‹</button>
            {(() => {
              const total = meta.total_pages
              if (total <= 7) return Array.from({ length: total }, (_, i) => i + 1)
              const pages: (number | '...')[] = [1]
              if (page > 3) pages.push('...')
              for (let i = Math.max(2, page - 1); i <= Math.min(total - 1, page + 1); i++) pages.push(i)
              if (page < total - 2) pages.push('...')
              pages.push(total)
              return pages
            })().map((p, i) =>
              p === '...' ? (
                <span key={`dot${i}`} style={{ padding: '0 4px', color: 'var(--text-muted)', fontSize: 12 }}>…</span>
              ) : (
                <button key={p} className={`page-btn${p === page ? ' active' : ''}`} onClick={() => setPage(p as number)}>
                  {p}
                </button>
              )
            )}
            <button className="page-btn" disabled={page >= meta.total_pages} onClick={() => setPage(p => p+1)}>›</button>
          </div>
        </div>

        {/* ── Detail pane ─────────────────────────────── */}
        {selected && (
          <AlertDetailPane
            alert={selected}
            onClose={() => setSelected(null)}
            onUpdate={handleUpdate}
          />
        )}
      </div>
    </div>
  )
}
