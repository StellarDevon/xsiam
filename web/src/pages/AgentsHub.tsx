import React, { useState, useRef, useEffect, useCallback } from 'react'
import { useNavigate, Link } from 'react-router-dom'
import api from '@/lib/api'
import PageHeader from '@/components/PageHeader'

interface DashboardStats {
  open_incidents?: number
  total_alerts?: number
  total_vulnerabilities?: number
  total_iocs?: number
  total_risks?: number
  total_reports?: number
  [key: string]: unknown
}

interface AgentDevice {
  _key: string
  name?: string
  status?: string
  last_seen?: string
  task_count?: number
  policy_id?: string
  log_level?: string
  [key: string]: unknown
}

interface AgentPolicy {
  _key: string
  name?: string
  [key: string]: unknown
}

const CATEGORY_COLORS: Record<string, { gradient: string; iconBg: string }> = {
  Agentic:   { gradient: 'linear-gradient(90deg,#1565c0,#0078d4)', iconBg: 'rgba(0,120,212,.15)' },
  detection: { gradient: 'linear-gradient(90deg,#8a2020,#c04040)', iconBg: 'rgba(192,64,64,.12)' },
  cloud:     { gradient: 'linear-gradient(90deg,#0077b6,#023e8a)', iconBg: 'rgba(0,119,182,.13)' },
  automation:{ gradient: 'linear-gradient(90deg,#1976d2,#00838f)', iconBg: 'rgba(25,118,210,.12)' },
  identity:  { gradient: 'linear-gradient(90deg,#4a5faa,#2255c0)', iconBg: 'rgba(74,95,170,.14)' },
}

const AGENT_ROUTES: Record<string, string> = {
  'case-investigation':  '/incidents',
  'cloud-posture':       '/assets',
  'alert-triage':        '/alerts',
  'identity-risk':       '/identity-risks',
  'automation-engineer': '/playbooks',
  'threat-hunt':         '/threat-intel',
  'itdr':                '/identity-risks',
  'vulnerability':       '/vulnerabilities',
  'reporting':           '/reports',
}

// Map agent id → stat field used to determine "running" vs "standby"
const AGENT_STAT_KEY: Record<string, keyof DashboardStats> = {
  'case-investigation':  'open_incidents',
  'alert-triage':        'total_alerts',
  'threat-hunt':         'total_iocs',
  'identity-risk':       'total_risks',
  'vulnerability':       'total_vulnerabilities',
  'reporting':           'total_reports',
}

const AI_AGENTS = [
  {
    id: 'case-investigation',
    name: '案例调查智能体',
    category: 'Agentic',
    icon: '🔎',
    active: true,
    desc: '自主查询遥测数据和威胁情报，生成全面的 AI 案例摘要。将原本45分钟的人工调查压缩到数秒完成。',
    stats: [{ label: '今日', value: '47 个案例' }, { label: '平均耗时', value: '12秒' }],
    cta: '查看活动',
  },
  {
    id: 'cloud-posture',
    name: '云安全态势智能体',
    category: 'cloud',
    icon: '☁',
    active: true,
    desc: '即时识别云端错误配置并自主应用已批准的修复措施，在外部扫描器发现之前关闭安全漏洞。',
    stats: [{ label: '已修复', value: '今日8条' }, { label: 'MTTR', value: '23秒' }],
    cta: '查看活动',
  },
  {
    id: 'automation-engineer',
    name: '自动化工程师智能体',
    category: 'automation',
    icon: '⚙',
    active: true,
    desc: '将自然语言请求转换为可投产的剧本和自动化脚本。"构建一个工作流，自动隔离任何出现暴力破解迹象的主机。"',
    stats: [{ label: '已构建剧本', value: '今日3个' }],
    cta: '立即体验',
  },
  {
    id: 'alert-triage',
    name: '告警分诊智能体',
    category: 'detection',
    icon: '🎯',
    active: true,
    desc: '自主审查100%的告警，确保低优先级信号（通常是高级威胁的早期迹象）不被忽视。',
    stats: [{ label: '已审查告警', value: '19,847' }, { label: '自动关闭', value: '99.2%' }],
    cta: '查看活动',
  },
  {
    id: 'identity-risk',
    name: '身份风险智能体',
    category: 'identity',
    icon: '👤',
    active: false,
    desc: '持续监控用户行为和身份信号，自动调整风险评分并对受损账户触发响应操作。',
    stats: [{ label: '已监控用户', value: '1,847' }],
    cta: 'Enable',
  },
]

const MCP_INTEGRATIONS = [
  { id: 'servicenow', name: 'ServiceNow ITSM', desc: '工单创建与更新', icon: '🔗', connected: true },
  { id: 'slack',      name: 'Slack',           desc: '告警通知',       icon: '💬', connected: true },
  { id: 'teams',      name: 'Microsoft Teams', desc: 'SOC 频道集成',   icon: '📧', connected: true },
  { id: 'jira',       name: 'Jira',            desc: '安全问题跟踪',   icon: '🐛', connected: false },
  { id: 'aws',        name: 'AWS Security Hub',desc: '云端发现结果',   icon: '☁', connected: false },
]

const CHAT_DEMO = [
  { role: 'Agent', text: "我是您的自主 SOC AI。与 Copilot 不同，我可以代您执行操作——调查事件、运行查询和执行剧本——均需您的批准。您希望我做什么？" },
  { role: 'user',  text: '调查 INC-001 并告诉我数据泄露是否成功' },
  { role: 'Agent', text: "我正在调查 INC-001...\n\n**已执行操作：**\n✅ 查询 XSIAM 遥测中的 rclone.exe 活动\n✅ 交叉比对 198.51.100.42 与威胁情报（Unit 42：已确认 C2）\n✅ 分析网络流量：4分钟内传输 8.3 GB\n✅ 检查文件系统暂存位置：C:\\Temp\\financial_data_2024.zip（8.3 GB）\n\n**结论：泄露成功。** 在端点于 09:44:01 UTC 被隔离之前，8.3 GB 数据已传输至已确认的 C2 服务器。\n\n需要我起草事件报告并通知安全经理吗？" },
  { role: 'user',  text: '是，请起草报告' },
  { role: 'Agent', text: '⟳ 正在起草事件报告...', pending: true },
]

const QUICK_PROMPTS = [
  '汇总今日严重事件',
  '查找过去24小时内的所有横向移动',
  '在所有端点进行 IOC 狩猎',
  '生成管理层安全简报',
  '识别未修复的严重 CVE',
]

const ACTIONS_LIBRARY = [
  { name: '隔离终端',         icon: '🔒', category: '终端', desc: '将主机从网络中隔离' },
  { name: '终止进程',         icon: '⛔', category: '终端', desc: '终止正在运行的进程' },
  { name: '运行脚本',         icon: '📜', category: '终端', desc: '执行 PowerShell 或 Shell 脚本' },
  { name: '采集取证数据',     icon: '🔬', category: '终端', desc: '收集内存和磁盘的取证数据' },
  { name: '封锁 IP',          icon: '🚫', category: '网络', desc: '通过防火墙将 IP 加入封锁列表' },
  { name: '封锁域名',         icon: '🌐', category: '网络', desc: '对恶意域名进行流量黑洞处理' },
  { name: '封锁 URL',         icon: '🔗', category: '网络', desc: '在代理层封锁 URL' },
  { name: '禁用 AD 账户',     icon: '👤', category: '身份', desc: '在 Active Directory 中禁用用户' },
  { name: '重置密码',         icon: '🔑', category: '身份', desc: '强制用户重置密码' },
  { name: '吊销会话',         icon: '🎫', category: '身份', desc: '使所有活跃令牌失效' },
  { name: '创建 ITSM 工单',   icon: '📋', category: 'ITSM', desc: '在 ServiceNow/Jira 中创建事件' },
  { name: '发送通知',         icon: '📣', category: 'ITSM', desc: 'Slack/Teams/邮件告警' },
]

// ─── helpers ─────────────────────────────────────────────────

function relativeTime(isoString?: string): string {
  if (!isoString) return '未知'
  const diff = Date.now() - new Date(isoString).getTime()
  if (isNaN(diff)) return '未知'
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return '刚刚'
  if (mins < 60) return `${mins}分钟前`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}小时前`
  return `${Math.floor(hours / 24)}天前`
}

function mockCpu(key: string): number {
  return (parseInt(key || '0', 16) % 60) + 20
}
function mockMem(key: string): number {
  return ((parseInt(key || '0', 16) * 3) % 55) + 25
}

// ─── Agent capabilities / trigger data ────────────────────────

const AGENT_CAPABILITIES: Record<string, { caps: string[]; triggers: string }> = {
  'case-investigation': {
    caps: [
      '自动查询 XSIAM 遥测数据与威胁情报',
      '生成 AI 事件摘要与根因分析',
      '关联多源日志并重建攻击链',
      '输出结构化调查报告供分析员审核',
    ],
    triggers: '新事件创建 · 严重告警升级 · 分析员手动触发',
  },
  'cloud-posture': {
    caps: [
      '持续扫描云资产配置偏差',
      '对比 CIS/NIST 基线自动评分',
      '对已审批的修复动作执行自动化补救',
      '生成云安全态势报告',
    ],
    triggers: '配置变更事件 · 定期扫描（每15分钟）· 新资产发现',
  },
  'automation-engineer': {
    caps: [
      '将自然语言指令转换为可执行 Playbook',
      '生成 Python / PowerShell 自动化脚本',
      '测试并验证生成的 Playbook 逻辑',
      '将 Playbook 发布至自动化库',
    ],
    triggers: '分析员自然语言请求 · Playbook 构建工作区调用',
  },
  'alert-triage': {
    caps: [
      '100% 告警自动分级与评分',
      '低优先级告警自动关闭（FP 过滤）',
      '高风险告警自动升级为事件',
      '提供告警背景与 MITRE ATT&CK 映射',
    ],
    triggers: '新告警入队 · 告警量激增（阈值：>500/小时）',
  },
  'identity-risk': {
    caps: [
      '持续监控用户行为基线异常',
      '动态调整身份风险评分',
      '自动触发 MFA 强制验证',
      '对高风险账号执行临时禁用',
    ],
    triggers: '异常登录行为 · 风险评分超阈值 · 特权账号活动',
  },
}

// ─── Agent Config Tab (inside detail modal) ───────────────────

interface AgentConfigPanelProps {
  agentId: string
}

function AgentConfigPanel({ agentId }: AgentConfigPanelProps) {
  // Load persisted config from localStorage
  function loadConfig(): Record<string, unknown> {
    try {
      const raw = localStorage.getItem(`xsiam_agent_config_${agentId}`)
      if (raw) return JSON.parse(raw) as Record<string, unknown>
    } catch { /* ignore */ }
    return {}
  }

  const [saved, setSaved] = useState(false)

  // ── Correlation Engine ──
  const [corrSimilarity, setCorrSimilarity] = useState<number>(() => {
    const c = loadConfig(); return typeof c.similarity_threshold === 'number' ? c.similarity_threshold : 75
  })
  const [corrTimeWindow, setCorrTimeWindow] = useState<string>(() => {
    const c = loadConfig(); return typeof c.time_window_hours === 'string' ? c.time_window_hours : '24'
  })
  const [corrMaxAlerts, setCorrMaxAlerts] = useState<number>(() => {
    const c = loadConfig(); return typeof c.max_alerts_per_incident === 'number' ? c.max_alerts_per_incident : 50
  })

  // ── Alert Triage ──
  const [triageConfidence, setTriageConfidence] = useState<number>(() => {
    const c = loadConfig(); return typeof c.confidence_threshold === 'number' ? c.confidence_threshold : 70
  })
  const [triageAutoClose, setTriageAutoClose] = useState<boolean>(() => {
    const c = loadConfig(); return c.auto_close_benign === true
  })
  const [triageEscalation, setTriageEscalation] = useState<string>(() => {
    const c = loadConfig(); return typeof c.escalation_threshold === 'string' ? c.escalation_threshold : 'high'
  })

  // ── Threat Hunter ──
  const [huntFreq, setHuntFreq] = useState<string>(() => {
    const c = loadConfig(); return typeof c.scan_frequency === 'string' ? c.scan_frequency : '4h'
  })
  const [huntIocTypes, setHuntIocTypes] = useState<string[]>(() => {
    const c = loadConfig()
    return Array.isArray(c.ioc_types) ? (c.ioc_types as string[]) : ['ip', 'domain', 'hash', 'url']
  })
  const [huntRetroDays, setHuntRetroDays] = useState<number>(() => {
    const c = loadConfig(); return typeof c.retrohunt_days === 'number' ? c.retrohunt_days : 7
  })

  // ── SmartScore ──
  const [scorePreset, setScorePreset] = useState<string>(() => {
    const c = loadConfig(); return typeof c.weight_preset === 'string' ? c.weight_preset : 'balanced'
  })
  const [scoreUpdateFreq, setScoreUpdateFreq] = useState<string>(() => {
    const c = loadConfig(); return typeof c.update_frequency === 'string' ? c.update_frequency : 'realtime'
  })

  function handleIocToggle(type: string) {
    setHuntIocTypes(prev =>
      prev.includes(type) ? prev.filter(t => t !== type) : [...prev, type]
    )
  }

  function handleSave() {
    let config: Record<string, unknown> = {}
    if (agentId === 'case-investigation') {
      config = { similarity_threshold: corrSimilarity, time_window_hours: corrTimeWindow, max_alerts_per_incident: corrMaxAlerts }
    } else if (agentId === 'alert-triage') {
      config = { confidence_threshold: triageConfidence, auto_close_benign: triageAutoClose, escalation_threshold: triageEscalation }
    } else if (agentId === 'threat-hunt') {
      config = { scan_frequency: huntFreq, ioc_types: huntIocTypes, retrohunt_days: huntRetroDays }
    } else if (agentId === 'smartscore') {
      config = { weight_preset: scorePreset, update_frequency: scoreUpdateFreq }
    }
    localStorage.setItem(`xsiam_agent_config_${agentId}`, JSON.stringify(config))
    setSaved(true)
    setTimeout(() => setSaved(false), 2000)
  }

  const rowStyle: React.CSSProperties = { marginBottom: 16 }
  const labelStyle: React.CSSProperties = { fontSize: 11, color: 'var(--text-muted)', marginBottom: 5, fontWeight: 600, textTransform: 'uppercase', letterSpacing: 0.5 }
  const selectStyle: React.CSSProperties = { width: '100%', fontSize: 12, boxSizing: 'border-box' }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>

      {/* ── Correlation Engine ── */}
      {agentId === 'case-investigation' && (
        <>
          <div style={rowStyle}>
            <div style={labelStyle}>相似度阈值 (similarity_threshold): {corrSimilarity}</div>
            <input type="range" min={0} max={100} value={corrSimilarity}
              onChange={e => setCorrSimilarity(Number(e.target.value))}
              style={{ width: '100%', accentColor: 'var(--accent-blue)' }} />
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
              <span>0</span><span>100</span>
            </div>
          </div>
          <div style={rowStyle}>
            <div style={labelStyle}>时间窗口 (time_window_hours)</div>
            <select className="filter-input" style={selectStyle} value={corrTimeWindow} onChange={e => setCorrTimeWindow(e.target.value)}>
              {['1', '4', '8', '24', '72'].map(v => <option key={v} value={v}>{v}h</option>)}
            </select>
          </div>
          <div style={rowStyle}>
            <div style={labelStyle}>每事件最大告警数 (max_alerts_per_incident)</div>
            <input type="number" className="filter-input" min={10} max={200} value={corrMaxAlerts}
              onChange={e => setCorrMaxAlerts(Math.max(10, Math.min(200, Number(e.target.value))))}
              style={{ width: '100%', fontSize: 12, boxSizing: 'border-box' }} />
          </div>
        </>
      )}

      {/* ── Alert Triage ── */}
      {agentId === 'alert-triage' && (
        <>
          <div style={rowStyle}>
            <div style={labelStyle}>置信度阈值 (confidence_threshold): {triageConfidence}</div>
            <input type="range" min={0} max={100} value={triageConfidence}
              onChange={e => setTriageConfidence(Number(e.target.value))}
              style={{ width: '100%', accentColor: 'var(--accent-blue)' }} />
            <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
              <span>0</span><span>100</span>
            </div>
          </div>
          <div style={rowStyle}>
            <div style={labelStyle}>自动关闭良性告警 (auto_close_benign)</div>
            <label style={{ display: 'flex', alignItems: 'center', gap: 8, cursor: 'pointer' }}>
              <div
                onClick={() => setTriageAutoClose(v => !v)}
                style={{
                  width: 36, height: 20, borderRadius: 10, position: 'relative', cursor: 'pointer',
                  background: triageAutoClose ? 'var(--accent-blue)' : 'rgba(255,255,255,.12)',
                  transition: 'background .2s',
                }}
              >
                <div style={{
                  position: 'absolute', top: 2, left: triageAutoClose ? 18 : 2,
                  width: 16, height: 16, borderRadius: '50%',
                  background: '#fff', transition: 'left .2s',
                }} />
              </div>
              <span style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{triageAutoClose ? '已启用' : '已禁用'}</span>
            </label>
          </div>
          <div style={rowStyle}>
            <div style={labelStyle}>升级阈值 (escalation_threshold)</div>
            <select className="filter-input" style={selectStyle} value={triageEscalation} onChange={e => setTriageEscalation(e.target.value)}>
              <option value="high">高危</option>
              <option value="critical">严重</option>
            </select>
          </div>
        </>
      )}

      {/* ── Threat Hunter ── */}
      {agentId === 'threat-hunt' && (
        <>
          <div style={rowStyle}>
            <div style={labelStyle}>扫描频率 (scan_frequency)</div>
            <select className="filter-input" style={selectStyle} value={huntFreq} onChange={e => setHuntFreq(e.target.value)}>
              {['1h', '4h', '12h', '24h'].map(v => <option key={v} value={v}>{v}</option>)}
            </select>
          </div>
          <div style={rowStyle}>
            <div style={labelStyle}>IOC 类型 (ioc_types)</div>
            <div style={{ display: 'flex', gap: 16, flexWrap: 'wrap' }}>
              {['ip', 'domain', 'hash', 'url'].map(t => (
                <label key={t} style={{ display: 'flex', alignItems: 'center', gap: 5, cursor: 'pointer', fontSize: 12, color: 'var(--text-secondary)' }}>
                  <input type="checkbox" checked={huntIocTypes.includes(t)} onChange={() => handleIocToggle(t)}
                    style={{ accentColor: 'var(--accent-blue)', width: 13, height: 13 }} />
                  {t.toUpperCase()}
                </label>
              ))}
            </div>
          </div>
          <div style={rowStyle}>
            <div style={labelStyle}>回溯天数 (retrohunt_days)</div>
            <input type="number" className="filter-input" min={1} max={30} value={huntRetroDays}
              onChange={e => setHuntRetroDays(Math.max(1, Math.min(30, Number(e.target.value))))}
              style={{ width: '100%', fontSize: 12, boxSizing: 'border-box' }} />
          </div>
        </>
      )}

      {/* ── SmartScore ── */}
      {agentId === 'smartscore' && (
        <>
          <div style={rowStyle}>
            <div style={labelStyle}>权重预设 (weight_preset)</div>
            <select className="filter-input" style={selectStyle} value={scorePreset} onChange={e => setScorePreset(e.target.value)}>
              <option value="balanced">均衡</option>
              <option value="security-focused">安全优先</option>
              <option value="compliance-focused">合规优先</option>
            </select>
          </div>
          <div style={rowStyle}>
            <div style={labelStyle}>更新频率 (update_frequency)</div>
            <select className="filter-input" style={selectStyle} value={scoreUpdateFreq} onChange={e => setScoreUpdateFreq(e.target.value)}>
              <option value="realtime">实时</option>
              <option value="hourly">每小时</option>
              <option value="daily">每日</option>
            </select>
          </div>
        </>
      )}

      {/* Fallback for agents without specific config */}
      {!['case-investigation', 'alert-triage', 'threat-hunt', 'smartscore'].includes(agentId) && (
        <div style={{ fontSize: 12, color: 'var(--text-muted)', padding: '12px 0' }}>
          该 Agent 暂无可配置参数。
        </div>
      )}

      {/* Save button */}
      <div style={{ marginTop: 8 }}>
        <button
          className="btn-primary"
          style={{ fontSize: 12, width: '100%' }}
          onClick={handleSave}
        >
          {saved ? '✓ 已保存' : '保存配置'}
        </button>
      </div>
    </div>
  )
}

// ─── Agent Detail Modal ────────────────────────────────────────

interface AgentDetailModalProps {
  agent: typeof AI_AGENTS[number]
  stats: DashboardStats | null
  onClose: () => void
}

function mockBarData(agentId: string): number[] {
  // deterministic 7-day bar chart based on agent id hash
  const seed = agentId.split('').reduce((acc, c) => acc + c.charCodeAt(0), 0)
  return Array.from({ length: 7 }, (_, i) => {
    const v = ((seed * (i + 1) * 31337) % 89) + 12
    return v
  })
}

function AgentDetailModal({ agent, stats, onClose }: AgentDetailModalProps) {
  const [detailTab, setDetailTab] = useState<'detail' | 'config'>('detail')
  const colors = CATEGORY_COLORS[agent.category] ?? CATEGORY_COLORS.Agentic
  const capData = AGENT_CAPABILITIES[agent.id] ?? { caps: ['通用 AI 能力'], triggers: '手动触发' }
  const barData = mockBarData(agent.id)
  const maxBar = Math.max(...barData)
  const days = ['周一', '周二', '周三', '周四', '周五', '周六', '周日']
  const todayIdx = new Date().getDay() === 0 ? 6 : new Date().getDay() - 1

  // live stats
  function getLiveStatValue(label: string, fallback: string): string {
    if (agent.id === 'case-investigation' && label === 'Today') {
      return `${stats?.open_incidents ?? 47} cases`
    }
    if (agent.id === 'alert-triage' && label === 'Alerts reviewed') {
      return stats?.total_alerts != null ? (stats.total_alerts as number).toLocaleString() : '19,847'
    }
    return fallback
  }

  // ESC to close
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', onKey)
    return () => window.removeEventListener('keydown', onKey)
  }, [onClose])

  const statusInfo = (() => {
    if (!agent.active) return { label: 'Offline', color: 'var(--text-muted)' }
    return { label: '运行中', color: 'var(--accent-green)' }
  })()

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 1100,
      background: 'var(--bg-overlay)', display: 'flex', alignItems: 'center', justifyContent: 'center',
      backdropFilter: 'blur(2px)',
    }} onClick={onClose}>
      <div style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 12,
        width: 600, maxWidth: '92vw', maxHeight: '88vh', overflowY: 'auto',
        boxShadow: '0 16px 48px rgba(0,0,0,.5)',
        position: 'relative',
      }} onClick={e => e.stopPropagation()}>

        {/* Top gradient strip */}
        <div style={{ height: 4, background: colors.gradient, borderRadius: '12px 12px 0 0' }} />

        {/* Header */}
        <div style={{ padding: '20px 24px 16px', display: 'flex', gap: 16, alignItems: 'flex-start' }}>
          <div style={{
            width: 56, height: 56, borderRadius: 12, background: colors.iconBg,
            display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 28, flexShrink: 0,
          }}>
            {agent.icon}
          </div>
          <div style={{ flex: 1, minWidth: 0 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
              <span style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)' }}>{agent.name}</span>
              <span style={{
                fontSize: 10, fontWeight: 600, padding: '2px 8px', borderRadius: 10,
                background: colors.iconBg, color: 'var(--accent-blue)', textTransform: 'uppercase', letterSpacing: 0.5,
              }}>{agent.category}</span>
            </div>
            <div style={{ display: 'flex', alignItems: 'center', gap: 6, marginTop: 6 }}>
              <span style={{
                width: 9, height: 9, borderRadius: '50%', display: 'inline-block',
                background: statusInfo.color,
                boxShadow: `0 0 6px ${statusInfo.color}`,
                animation: agent.active ? 'pulse-dot 1.6s ease-in-out infinite' : 'none',
              }} />
              <span style={{ fontSize: 12, color: statusInfo.color, fontWeight: 600 }}>{statusInfo.label}</span>
            </div>
          </div>
          <button
            onClick={onClose}
            style={{
              background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer',
              fontSize: 18, padding: '0 4px', lineHeight: 1, flexShrink: 0,
            }}
          >×</button>
        </div>

        {/* Detail / Config tab bar */}
        <div style={{ display: 'flex', borderBottom: '1px solid var(--border)', padding: '0 24px', gap: 4 }}>
          {([{ id: 'detail', label: '详情' }, { id: 'config', label: '配置' }] as const).map(t => (
            <button
              key={t.id}
              onClick={() => setDetailTab(t.id)}
              style={{
                fontSize: 12, fontWeight: detailTab === t.id ? 700 : 400,
                color: detailTab === t.id ? 'var(--accent-blue)' : 'var(--text-muted)',
                background: 'none', border: 'none', cursor: 'pointer',
                padding: '8px 12px',
                borderBottom: detailTab === t.id ? '2px solid var(--accent-blue)' : '2px solid transparent',
                marginBottom: -1,
              }}
            >
              {t.label}
            </button>
          ))}
        </div>

        <div style={{ padding: '0 24px 24px', display: 'flex', flexDirection: 'column', gap: 18 }}>

          {/* Config tab */}
          {detailTab === 'config' && (
            <div style={{ paddingTop: 16 }}>
              <AgentConfigPanel agentId={agent.id} />
            </div>
          )}

          {/* Detail tab content */}
          {detailTab === 'detail' && <>

          {/* Description */}
          <div style={{
            fontSize: 12.5, color: 'var(--text-secondary)', lineHeight: 1.65,
            padding: '12px 14px', background: 'rgba(0,120,212,.05)',
            border: '1px solid rgba(0,120,212,.12)', borderRadius: 7,
          }}>
            {agent.desc}
          </div>

          {/* Stats table */}
          <div>
            <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: 0.8 }}>实时数据</div>
            <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
              {agent.stats.map(s => (
                <div key={s.label} style={{
                  flex: '1 1 120px', padding: '10px 14px',
                  background: 'rgba(255,255,255,.04)', border: '1px solid var(--border)', borderRadius: 7,
                }}>
                  <div style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)', lineHeight: 1 }}>
                    {getLiveStatValue(s.label, s.value)}
                  </div>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 4 }}>{s.label}</div>
                </div>
              ))}
            </div>
          </div>

          {/* 7-day mini bar chart */}
          <div>
            <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', marginBottom: 10, textTransform: 'uppercase', letterSpacing: 0.8 }}>今日执行次数（近7天）</div>
            <div style={{ display: 'flex', gap: 4, alignItems: 'flex-end', height: 64 }}>
              {barData.map((val, i) => (
                <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 3 }}>
                  <div style={{
                    width: '100%', borderRadius: '3px 3px 0 0',
                    height: `${Math.round((val / maxBar) * 52)}px`,
                    background: i === todayIdx
                      ? colors.gradient
                      : 'rgba(255,255,255,.12)',
                    transition: 'height .3s',
                    position: 'relative',
                  }}>
                    <span style={{
                      position: 'absolute', bottom: '100%', left: '50%', transform: 'translateX(-50%)',
                      fontSize: 9, color: i === todayIdx ? 'var(--accent-blue)' : 'var(--text-muted)',
                      whiteSpace: 'nowrap', marginBottom: 1,
                    }}>{val}</span>
                  </div>
                  <span style={{ fontSize: 9, color: i === todayIdx ? 'var(--accent-blue)' : 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                    {days[i]}
                  </span>
                </div>
              ))}
            </div>
          </div>

          {/* 能力概述 */}
          <div>
            <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', marginBottom: 8, textTransform: 'uppercase', letterSpacing: 0.8 }}>能力概述</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
              {capData.caps.map((cap, i) => (
                <div key={i} style={{ display: 'flex', alignItems: 'flex-start', gap: 7, fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.5 }}>
                  <span style={{ color: 'var(--accent-blue)', flexShrink: 0, marginTop: 1 }}>▸</span>
                  <span>{cap}</span>
                </div>
              ))}
            </div>
          </div>

          {/* 触发条件 */}
          <div style={{
            padding: '10px 14px', background: 'rgba(224,128,64,.05)',
            border: '1px solid rgba(224,128,64,.2)', borderRadius: 7,
          }}>
            <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--high)', marginBottom: 5, textTransform: 'uppercase', letterSpacing: 0.8 }}>触发条件</div>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', lineHeight: 1.6 }}>{capData.triggers}</div>
          </div>

          {/* Action buttons */}
          <div style={{ display: 'flex', gap: 8 }}>
            <button
              className="btn-primary"
              style={{ fontSize: 12, flex: 1 }}
              onClick={() => {
                const route = AGENT_ROUTES[agent.id]
                if (route) window.location.href = route
                onClose()
              }}
            >
              跳转到工作区 →
            </button>
            <button
              className="btn-secondary"
              style={{ fontSize: 12, flex: 1 }}
              onClick={() => { alert(`[Demo] 执行日志 for ${agent.name}\n\n功能开发中，将显示近期执行记录、耗时、结果状态。`); onClose() }}
            >
              查看执行日志
            </button>
          </div>

          </>}{/* end detail tab */}

        </div>
      </div>
    </div>
  )
}

// ─── Agent Config Modal ────────────────────────────────────────

interface ConfigModalProps {
  device: AgentDevice
  policies: AgentPolicy[]
  onClose: () => void
}

function ConfigModal({ device, policies, onClose }: ConfigModalProps) {
  const [policyId, setPolicyId] = useState(device.policy_id ?? '')
  const [logLevel, setLogLevel] = useState((device.log_level as string) ?? 'info')
  const [saving, setSaving] = useState(false)
  const [saved, setSaved] = useState(false)

  async function handleSave() {
    setSaving(true)
    try {
      await api.patch(`/devices/${device._key}`, { policy_id: policyId, log_level: logLevel })
      setSaved(true)
      setTimeout(onClose, 1200)
    } catch {
      alert('保存失败，请重试')
    } finally {
      setSaving(false)
    }
  }

  return (
    <div style={{
      position: 'fixed', inset: 0, zIndex: 1000,
      background: 'var(--bg-overlay)', display: 'flex', alignItems: 'center', justifyContent: 'center',
    }} onClick={onClose}>
      <div style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 10,
        padding: 24, width: 380, boxShadow: '0 8px 32px rgba(0,0,0,.4)',
      }} onClick={e => e.stopPropagation()}>
        <div style={{ fontSize: 14, fontWeight: 700, marginBottom: 18, color: 'var(--text-primary)' }}>
          配置 Agent ⚙
        </div>

        {/* Agent ID */}
        <div style={{ marginBottom: 14 }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>代理 ID</div>
          <input
            className="filter-input"
            value={device._key}
            readOnly
            style={{ width: '100%', fontFamily: 'monospace', fontSize: 12, opacity: 0.7, boxSizing: 'border-box' }}
          />
        </div>

        {/* Policy */}
        <div style={{ marginBottom: 14 }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>分配策略</div>
          <select
            className="filter-input"
            value={policyId}
            onChange={e => setPolicyId(e.target.value)}
            style={{ width: '100%', fontSize: 12, boxSizing: 'border-box' }}
          >
            <option value="">-- 无策略 --</option>
            {policies.map(p => (
              <option key={p._key} value={p._key}>{p.name ?? p._key}</option>
            ))}
          </select>
        </div>

        {/* Log level */}
        <div style={{ marginBottom: 20 }}>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>日志级别</div>
          <select
            className="filter-input"
            value={logLevel}
            onChange={e => setLogLevel(e.target.value)}
            style={{ width: '100%', fontSize: 12, boxSizing: 'border-box' }}
          >
            {['debug', 'info', 'warn', 'error'].map(l => (
              <option key={l} value={l}>{l}</option>
            ))}
          </select>
        </div>

        <div style={{ display: 'flex', gap: 8, justifyContent: 'flex-end' }}>
          <button className="btn-secondary" style={{ fontSize: 12 }} onClick={onClose}>取消</button>
          <button
            className="btn-primary"
            style={{ fontSize: 12 }}
            disabled={saving || saved}
            onClick={handleSave}
          >
            {saved ? '✓ 已保存' : saving ? '保存中...' : '保存配置'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Device Card ───────────────────────────────────────────────

interface DeviceCardProps {
  device: AgentDevice
  policies: AgentPolicy[]
}

function DeviceCard({ device, policies }: DeviceCardProps) {
  const [showConfig, setShowConfig] = useState(false)

  const status = (device.status as string) ?? 'offline'
  const cpu = mockCpu(device._key)
  const mem = mockMem(device._key)
  const taskCount = typeof device.task_count === 'number' ? device.task_count : (status === 'running' ? 2 : 0)
  const deviceRoute = `/assets`

  const statusDot: Record<string, { color: string; glow: string; label: string; pulse: boolean }> = {
    running: { color: 'var(--accent-green)', glow: '0 0 6px rgba(47,176,122,.7)', label: '运行中', pulse: true },
    standby: { color: 'var(--accent-blue)', glow: '0 0 6px #1976d2', label: '待命', pulse: false },
    offline: { color: 'var(--text-muted)', glow: 'none', label: '离线', pulse: false },
  }
  const dot = statusDot[status] ?? statusDot.offline

  return (
    <>
      <div style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 10,
        padding: 16, position: 'relative', overflow: 'hidden',
        transition: 'border-color .2s',
      }}
        onMouseEnter={e => { (e.currentTarget as HTMLDivElement).style.borderColor = 'var(--border-light)' }}
        onMouseLeave={e => { (e.currentTarget as HTMLDivElement).style.borderColor = 'var(--border)' }}
      >
        {/* Status bar top */}
        <div style={{
          position: 'absolute', top: 0, left: 0, right: 0, height: 2,
          background: dot.color, opacity: 0.7,
        }} />

        {/* Status dot + name */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 7, marginBottom: 6 }}>
          <span style={{
            width: 9, height: 9, borderRadius: '50%', display: 'inline-block',
            background: dot.color, boxShadow: dot.glow, flexShrink: 0,
            animation: dot.pulse ? 'pulse-dot 1.6s ease-in-out infinite' : 'none',
          }} />
          <span style={{ fontSize: 13, fontWeight: 600, flex: 1, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
            {device.name ?? `Agent-${device._key}`}
          </span>
          <span style={{ fontSize: 10, color: dot.color }}>{dot.label}</span>
        </div>

        {/* ID */}
        <div style={{ fontSize: 10, fontFamily: 'monospace', color: 'var(--text-muted)', marginBottom: 8 }}>
          ID: {device._key}
        </div>

        {/* Last activity */}
        <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 6 }}>
          最后活跃: <span style={{ color: 'var(--text-primary)' }}>{relativeTime(device.last_seen as string | undefined)}</span>
        </div>

        {/* Tasks */}
        <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 10 }}>
          任务:{' '}
          {taskCount > 0
            ? <span style={{ color: 'var(--high)', fontWeight: 600 }}>{taskCount} 个运行中</span>
            : <span style={{ color: 'var(--text-muted)' }}>空闲</span>
          }
        </div>

        {/* Health bars */}
        <div style={{ marginBottom: 12 }}>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 3, display: 'flex', justifyContent: 'space-between' }}>
            <span>CPU</span><span style={{ color: cpu > 80 ? 'var(--critical)' : 'var(--text-secondary)' }}>{cpu}%</span>
          </div>
          <div style={{ height: 4, background: 'rgba(255,255,255,.08)', borderRadius: 2, overflow: 'hidden', marginBottom: 6 }}>
            <div style={{
              height: '100%', width: `${cpu}%`,
              background: cpu > 80 ? 'var(--critical)' : cpu > 60 ? 'var(--high)' : 'var(--accent-green)',
              borderRadius: 2, transition: 'width .4s',
            }} />
          </div>
          <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 3, display: 'flex', justifyContent: 'space-between' }}>
            <span>内存</span><span style={{ color: mem > 85 ? 'var(--critical)' : 'var(--text-secondary)' }}>{mem}%</span>
          </div>
          <div style={{ height: 4, background: 'rgba(255,255,255,.08)', borderRadius: 2, overflow: 'hidden' }}>
            <div style={{
              height: '100%', width: `${mem}%`,
              background: mem > 85 ? 'var(--critical)' : mem > 70 ? 'var(--high)' : 'var(--accent-blue)',
              borderRadius: 2, transition: 'width .4s',
            }} />
          </div>
        </div>

        {/* Actions */}
        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
          <button
            className="btn-secondary"
            style={{ fontSize: 11 }}
            onClick={() => setShowConfig(true)}
          >
            配置 ⚙
          </button>
          <Link
            to={deviceRoute}
            style={{ fontSize: 11, color: 'var(--accent-blue)', textDecoration: 'none', marginLeft: 'auto', whiteSpace: 'nowrap' }}
            onMouseEnter={e => { (e.currentTarget as HTMLAnchorElement).style.textDecoration = 'underline' }}
            onMouseLeave={e => { (e.currentTarget as HTMLAnchorElement).style.textDecoration = 'none' }}
          >
            查看详情 →
          </Link>
        </div>
      </div>

      {showConfig && (
        <ConfigModal device={device} policies={policies} onClose={() => setShowConfig(false)} />
      )}
    </>
  )
}

// ─── Detection Funnel ─────────────────────────────────────────

const FUNNEL_STAGES = [
  { label: '原始事件',    count: '1,234,567', unit: '/天', color: 'var(--accent-blue)' },
  { label: 'ETL 处理后',  count: '987,234',   unit: '',    color: 'var(--accent-green)' },
  { label: '规则命中',    count: '4,521',     unit: '',    color: 'var(--medium)' },
  { label: '告警',        count: '234',        unit: '',    color: 'var(--high)' },
  { label: '事件',        count: '18',         unit: '',    color: 'var(--critical)' },
]

const FUNNEL_REDUCTIONS = ['↓ 20%', '↓ 99.5%', '↓ 94.8%', '↓ 92.3%']

function DetectionFunnel({ hasActiveAiAgent }: { hasActiveAiAgent: boolean }) {
  // widths from 100% down to ~18%
  const widths = [100, 80, 58, 34, 18]

  return (
    <div style={{ marginTop: 32, padding: '20px 24px', background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 10 }}>
      <div style={{ fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', marginBottom: 18 }}>
        威胁检测漏斗
      </div>

      {/* SVG Funnel */}
      <div style={{ marginBottom: 20 }}>
        {FUNNEL_STAGES.map((stage, i) => (
          <div key={stage.label} style={{ display: 'flex', flexDirection: 'column', marginBottom: 2 }}>
            <div style={{ display: 'flex', alignItems: 'center', gap: 10, marginBottom: 3 }}>
              {/* Label */}
              <div style={{ width: 100, fontSize: 11.5, color: 'var(--text-secondary)', textAlign: 'right', flexShrink: 0 }}>
                {stage.label}
              </div>
              {/* Trapezoid bar via SVG */}
              <div style={{ flex: 1, position: 'relative', height: 28 }}>
                <svg width="100%" height="28" style={{ display: 'block' }}>
                  <defs>
                    <linearGradient id={`funnel-grad-${i}`} x1="0" y1="0" x2="1" y2="0">
                      <stop offset="0%" stopColor={stage.color} stopOpacity="0.9" />
                      <stop offset="100%" stopColor={stage.color} stopOpacity="0.5" />
                    </linearGradient>
                  </defs>
                  {/* Outer container full width */}
                  <rect x="0" y="6" width="100%" height="16" rx="2" fill="rgba(255,255,255,.04)" />
                  {/* Filled trapezoid portion */}
                  <rect x="0" y="4" width={`${widths[i]}%`} height="20" rx="3"
                    fill={`url(#funnel-grad-${i})`} />
                </svg>
              </div>
              {/* Count */}
              <div style={{ width: 90, fontSize: 12, fontWeight: 700, color: 'var(--text-primary)', flexShrink: 0, whiteSpace: 'nowrap' }}>
                {stage.count}<span style={{ fontSize: 10, fontWeight: 400, color: 'var(--text-muted)' }}>{stage.unit}</span>
              </div>
            </div>
            {/* Reduction ratio between stages */}
            {i < FUNNEL_STAGES.length - 1 && (
              <div style={{ paddingLeft: 110, marginBottom: 2 }}>
                <span style={{ fontSize: 10, color: 'var(--high)', fontWeight: 600 }}>{FUNNEL_REDUCTIONS[i]}</span>
              </div>
            )}
          </div>
        ))}
      </div>

      {/* ML Model Performance (shown when AI agent is active) */}
      {hasActiveAiAgent && (
        <div style={{ borderTop: '1px solid var(--border)', paddingTop: 16 }}>
          <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', marginBottom: 12, textTransform: 'uppercase', letterSpacing: 0.8 }}>
            ML 模型性能
          </div>
          <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
            {[
              { label: 'Precision', value: '87.3%', color: 'var(--accent-green)' },
              { label: 'Recall',    value: '92.1%', color: 'var(--accent-blue)' },
              { label: 'F1-Score',  value: '89.6%', color: 'var(--medium)' },
            ].map(m => (
              <div key={m.label} style={{
                flex: '1 1 120px', padding: '12px 16px',
                background: 'rgba(255,255,255,.04)', border: `1px solid ${m.color}33`,
                borderRadius: 8, textAlign: 'center',
              }}>
                <div style={{ fontSize: 22, fontWeight: 700, color: m.color, lineHeight: 1.1, marginBottom: 4 }}>
                  {m.value}
                </div>
                <div style={{ fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.6 }}>
                  {m.label}
                </div>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  )
}

// ─── Agents Tab ────────────────────────────────────────────────

function AgentsTab({ onSwitchTab, stats, onlineCount, devices, policies }: {
  onSwitchTab: (tab: TabId) => void
  stats: DashboardStats | null
  onlineCount: number | null
  devices: AgentDevice[]
  policies: AgentPolicy[]
}) {
  const navigate = useNavigate()
  const [selectedAgent, setSelectedAgent] = useState<typeof AI_AGENTS[number] | null>(null)
  const [sessionElapsed, setSessionElapsed] = useState(0)
  const sessionStartRef = useRef(Date.now())
  const [sessionRefreshing, setSessionRefreshing] = useState(false)
  const [sessionRefreshMsg, setSessionRefreshMsg] = useState<string | null>(null)

  // Session countdown timer — ticks every second
  useEffect(() => {
    const timer = setInterval(() => {
      setSessionElapsed(Math.floor((Date.now() - sessionStartRef.current) / 1000))
    }, 1000)
    return () => clearInterval(timer)
  }, [])

  function resetSession() {
    sessionStartRef.current = Date.now()
    setSessionElapsed(0)
  }

  async function handleRefreshSession() {
    setSessionRefreshing(true)
    setSessionRefreshMsg(null)
    try {
      const token = localStorage.getItem('token') ?? ''
      const res = await fetch('/api/auth/refresh', {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${token}`,
        },
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json() as { data?: { token?: string; expires_at?: string }; token?: string; expires_at?: string }
      const newToken = data?.data?.token ?? data?.token
      const newExpiry = data?.data?.expires_at ?? data?.expires_at
      if (newToken) localStorage.setItem('token', newToken)
      if (newExpiry) localStorage.setItem('token_expiry', newExpiry)
      resetSession()
      setSessionRefreshMsg('会话已刷新')
    } catch {
      setSessionRefreshMsg('刷新失败')
    } finally {
      setSessionRefreshing(false)
      setTimeout(() => setSessionRefreshMsg(null), 2000)
    }
  }

  const sessionMins = Math.floor(sessionElapsed / 60)
  const sessionSecs = sessionElapsed % 60
  const sessionLabel = `会话 ${String(sessionMins).padStart(2, '0')}:${String(sessionSecs).padStart(2, '0')}`

  // Progress bar: 0-30min green, 30-60min orange, >60min red
  const SESSION_MAX = 90 * 60 // cap bar at 90 min
  const sessionPct = Math.min((sessionElapsed / SESSION_MAX) * 100, 100)
  const sessionBarColor = sessionMins < 30 ? 'var(--accent-green)' : sessionMins < 60 ? 'var(--high)' : 'var(--critical)'

  // Aggregate stats
  const total = devices.length || AI_AGENTS.length
  const onlineCnt = onlineCount ?? devices.filter(d => d.status === 'running').length
  const standbyCnt = devices.filter(d => d.status === 'standby').length
  const offlineCnt = devices.filter(d => d.status === 'offline').length
  const runningTasksCnt = devices.length > 0
    ? devices.reduce((acc, d) => acc + (typeof d.task_count === 'number' ? d.task_count : (d.status === 'running' ? 2 : 0)), 0)
    : AI_AGENTS.filter(a => a.active).length * 2

  function getStatValue(agentId: string, label: string, fallback: string): string {
    if (agentId === 'case-investigation' && label === 'Today') {
      return `${stats?.open_incidents ?? 47} cases`
    }
    if (agentId === 'alert-triage' && label === 'Alerts reviewed') {
      return stats?.total_alerts != null ? (stats.total_alerts as number).toLocaleString() : '19,847'
    }
    return fallback
  }

  function getAgentDataStatus(agentId: string): { label: string; color: string; glow: string } {
    const statKey = AGENT_STAT_KEY[agentId]
    if (statKey && stats != null) {
      const val = stats[statKey]
      const count = typeof val === 'number' ? val : 0
      if (count > 0) {
        return { label: '运行中', color: 'var(--accent-green)', glow: '0 0 6px rgba(47,176,122,.7)' }
      }
      return { label: '待命', color: 'var(--high)', glow: '0 0 6px rgba(224,128,64,.7)' }
    }
    if (agentId === 'cloud-posture' || agentId === 'automation-engineer') {
      if (onlineCount != null && onlineCount > 0) {
        return { label: '运行中', color: 'var(--accent-green)', glow: '0 0 6px rgba(47,176,122,.7)' }
      }
      return { label: '待命', color: 'var(--high)', glow: '0 0 6px rgba(224,128,64,.7)' }
    }
    return { label: '待命', color: 'var(--high)', glow: '0 0 6px rgba(224,128,64,.7)' }
  }

  function handleCta(agent: typeof AI_AGENTS[number]) {
    if (!agent.active) return
    const route = AGENT_ROUTES[agent.id]
    if (route) {
      navigate(route)
    } else {
      onSwitchTab('assistant')
    }
  }

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

      {/* ── Session countdown header bar ── */}
      <div style={{
        display: 'flex', alignItems: 'center', gap: 12, padding: '8px 20px',
        background: 'rgba(0,0,0,.18)', borderBottom: '1px solid var(--border)',
        flexShrink: 0,
      }}>
        <span style={{ fontSize: 11, fontWeight: 600, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>{sessionLabel}</span>
        <div style={{ flex: 1, height: 4, background: 'rgba(255,255,255,.07)', borderRadius: 2, overflow: 'hidden', minWidth: 60, maxWidth: 160 }}>
          <div style={{
            height: '100%', width: `${sessionPct}%`, background: sessionBarColor,
            borderRadius: 2, transition: 'width 1s linear, background .5s',
          }} />
        </div>
        <span style={{ fontSize: 10, color: sessionBarColor, whiteSpace: 'nowrap' }}>
          {sessionMins < 30 ? '正常' : sessionMins < 60 ? '较长' : '超时'}
        </span>
        <button
          style={{
            fontSize: 10, padding: '3px 10px', borderRadius: 5,
            background: 'rgba(255,255,255,.05)', border: '1px solid var(--border)',
            color: 'var(--text-muted)', cursor: 'pointer', whiteSpace: 'nowrap',
          }}
          onClick={resetSession}
        >
          重置计时
        </button>
        <button
          style={{
            fontSize: 10, padding: '3px 10px', borderRadius: 5,
            background: 'rgba(0,120,212,.10)', border: '1px solid rgba(0,120,212,.3)',
            color: 'var(--accent-blue)', cursor: 'pointer', whiteSpace: 'nowrap',
            opacity: sessionRefreshing ? 0.6 : 1,
          }}
          onClick={handleRefreshSession}
          disabled={sessionRefreshing}
        >
          {sessionRefreshing ? '刷新中...' : '刷新会话'}
        </button>
        {sessionRefreshMsg && (
          <span style={{
            fontSize: 10, color: sessionRefreshMsg === '会话已刷新' ? 'var(--accent-green)' : 'var(--critical)',
            whiteSpace: 'nowrap', fontWeight: 600,
          }}>
            {sessionRefreshMsg === '会话已刷新' ? '✓ ' : '✗ '}{sessionRefreshMsg}
          </span>
        )}
      </div>

      <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>

      {/* ── 1. Aggregate stats row ── */}
      <div style={{
        display: 'flex', gap: 10, marginBottom: 20, flexWrap: 'wrap',
      }}>
        {[
          { label: 'Agent总数', value: total, color: 'var(--text-primary)', bg: 'rgba(255,255,255,.04)', border: 'var(--border)' },
          { label: '在线', value: onlineCnt, color: 'var(--accent-green)', bg: 'rgba(47,176,122,.07)', border: 'rgba(47,176,122,.25)' },
          { label: '待命', value: standbyCnt, color: 'var(--accent-blue)', bg: 'rgba(25,118,210,.07)', border: 'rgba(25,118,210,.25)' },
          { label: '离线', value: offlineCnt, color: 'var(--text-muted)', bg: 'rgba(120,144,156,.06)', border: 'rgba(120,144,156,.2)' },
          { label: '运行中任务', value: runningTasksCnt, color: 'var(--high)', bg: 'rgba(224,128,64,.07)', border: 'rgba(224,128,64,.25)' },
        ].map(s => (
          <div key={s.label} style={{
            padding: '10px 18px', borderRadius: 8, background: s.bg,
            border: `1px solid ${s.border}`, display: 'flex', alignItems: 'baseline', gap: 8,
          }}>
            <span style={{ fontSize: 20, fontWeight: 700, color: s.color, lineHeight: 1 }}>{s.value}</span>
            <span style={{ fontSize: 11, color: s.color, opacity: 0.85 }}>{s.label}</span>
          </div>
        ))}
      </div>

      {/* Stats banner */}
      <div style={{
        display: 'flex', gap: 12, marginBottom: 20, padding: '14px 18px',
        background: 'rgba(0,120,212,.06)', border: '1px solid rgba(0,120,212,.2)',
        borderRadius: 8, alignItems: 'center',
      }}>
        <div style={{ fontSize: 22 }}>✦</div>
        <div>
          <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--accent-blue)' }}>智能 AI 工作力已激活</div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            AI 智能体今日已审查 <strong style={{ color: 'var(--text-primary)' }}>
              {stats?.total_alerts != null ? (stats.total_alerts as number).toLocaleString() : '19,847'} 条告警
            </strong>
            · <strong style={{ color: 'var(--accent-blue)' }}>99.2% 自动解决</strong>
            · <strong style={{ color: 'var(--text-primary)' }}>4 个智能体运行中</strong>
          </div>
        </div>
        <div style={{ marginLeft: 'auto' }}>
          <button className="btn-secondary" style={{ fontSize: 11 }} onClick={() => onSwitchTab('assistant')}>查看活动日志</button>
        </div>
      </div>

      {/* AI Agent card grid */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 16 }}>
        {AI_AGENTS.map(Agent => {
          const colors = CATEGORY_COLORS[Agent.category] ?? CATEGORY_COLORS.Agentic
          return (
            <div key={Agent.id} style={{
              background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 10,
              padding: 20, cursor: 'pointer', position: 'relative', overflow: 'hidden',
              transition: 'all .2s',
            }}
              onClick={() => setSelectedAgent(Agent)}
              onMouseEnter={e => { (e.currentTarget as HTMLDivElement).style.borderColor = 'var(--border-light)' }}
              onMouseLeave={e => { (e.currentTarget as HTMLDivElement).style.borderColor = 'var(--border)' }}
            >
              <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 3, background: colors.gradient }} />
              <div style={{ width: 48, height: 48, borderRadius: 10, background: colors.iconBg, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 22, marginBottom: 12 }}>
                {Agent.icon}
              </div>
              <div style={{ fontSize: 14, fontWeight: 600, marginBottom: 4 }}>{Agent.name}</div>
              <div style={{ marginBottom: 8, display: 'flex', alignItems: 'center', gap: 5 }}>
                {(() => {
                  if (!Agent.active) {
                    return (
                      <>
                        <span style={{ width: 8, height: 8, borderRadius: '50%', display: 'inline-block', background: 'var(--text-muted)' }} />
                        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>空闲</span>
                      </>
                    )
                  }
                  const ds = getAgentDataStatus(Agent.id)
                  return (
                    <>
                      <span style={{ width: 8, height: 8, borderRadius: '50%', display: 'inline-block', background: ds.color, boxShadow: ds.glow }} />
                      <span style={{ fontSize: 11, color: ds.color }}>{ds.label}</span>
                    </>
                  )
                })()}
              </div>
              <div style={{ fontSize: 12, color: 'var(--text-muted)', lineHeight: 1.5, marginBottom: 12 }}>{Agent.desc}</div>
              <div style={{ display: 'flex', gap: 12, fontSize: 11, color: 'var(--text-secondary)', marginBottom: 12 }}>
                {Agent.stats.map(s => (
                  <span key={s.label}>{s.label}: <strong style={{ color: 'var(--text-primary)' }}>{getStatValue(Agent.id, s.label, s.value)}</strong></span>
                ))}
              </div>
              <div style={{ display: 'flex', gap: 6, alignItems: 'center' }} onClick={e => e.stopPropagation()}>
                <button className="btn-secondary" style={{ fontSize: 11 }} onClick={() => alert(`配置 ${Agent.name}\n\nSettings: thresholds, playbook triggers, approval requirements, output destinations.`)}>配置 ⚙</button>
                {Agent.active ? (
                  <button className="btn-primary" style={{ fontSize: 11 }} onClick={() => handleCta(Agent)}>
                    {Agent.cta}
                  </button>
                ) : (
                  <span style={{ position: 'relative', display: 'inline-block' }} title="Coming Soon">
                    <button className="btn-primary" style={{ fontSize: 11, opacity: 0.5, cursor: 'not-allowed' }} disabled>
                      {Agent.cta}
                    </button>
                  </span>
                )}
                {Agent.active && AGENT_ROUTES[Agent.id] && (
                  <Link
                    to={AGENT_ROUTES[Agent.id]}
                    style={{ fontSize: 11, color: 'var(--accent-blue)', textDecoration: 'none', marginLeft: 4, whiteSpace: 'nowrap' }}
                    onMouseEnter={e => { (e.currentTarget as HTMLAnchorElement).style.textDecoration = 'underline' }}
                    onMouseLeave={e => { (e.currentTarget as HTMLAnchorElement).style.textDecoration = 'none' }}
                  >
                    查看详情 →
                  </Link>
                )}
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
          <div style={{ fontSize: 13, color: 'var(--text-secondary)' }}>构建自定义 Agent</div>
          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>使用智能体构建器创建<br />专用 AI 智能体</div>
          <button className="btn-primary" style={{ marginTop: 12, fontSize: 11 }} onClick={() => alert('智能体构建器\n\n定义智能体用途、数据源、决策规则和操作能力。\n（智能体构建器界面即将推出）')}>+ 构建智能体</button>
        </div>
      </div>

      {/* ── Deployed Agent devices section ── */}
      {devices.length > 0 && (
        <div style={{ marginTop: 28 }}>
          <div style={{ fontSize: 12, fontWeight: 700, color: 'var(--text-muted)', marginBottom: 14, textTransform: 'uppercase', letterSpacing: 1 }}>
            已部署 Agents ({devices.length})
          </div>
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(240px, 1fr))', gap: 14 }}>
            {devices.map(d => (
              <DeviceCard key={d._key} device={d} policies={policies} />
            ))}
          </div>
        </div>
      )}

      {/* ── Detection Funnel ── */}
      <DetectionFunnel hasActiveAiAgent={AI_AGENTS.some(a => a.active)} />

      </div>{/* end scrollable content */}

      {selectedAgent && (
        <AgentDetailModal
          agent={selectedAgent}
          stats={stats}
          onClose={() => setSelectedAgent(null)}
        />
      )}
    </div>
  )
}

// ─── Assistant Tab ─────────────────────────────────────────────

function AssistantTab() {
  const [input, setInput] = useState('')
  const bottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [])

  function handleExecute() {
    if (!input.trim()) return
    alert(`[Demo] AI Agent助手 received: "${input}"\n\nIn production this would trigger an AI-powered investigation.`)
    setInput('')
  }

  const hasInput = input.trim().length > 0

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden', position: 'relative' }}>
      <div style={{ flex: 1, display: 'flex', gap: 20, overflow: 'hidden', padding: 20 }}>
      <div style={{
        flex: 1, background: 'var(--bg-card)', border: '1px solid var(--border)',
        borderRadius: 10, display: 'flex', flexDirection: 'column', overflow: 'hidden',
      }}>
        <div style={{ padding: '14px 18px', borderBottom: '1px solid var(--border)', display: 'flex', alignItems: 'center', gap: 10 }}>
          <div style={{ width: 32, height: 32, borderRadius: '50%', background: 'linear-gradient(135deg,#1565c0,#0078d4)', display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 16 }}>✦</div>
          <div>
            <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--accent-blue)' }}>XSIAM AI Agent助手</div>
            <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>Powered by XSIAM 3.x · All actions are audited</div>
          </div>
          <div style={{ marginLeft: 'auto', fontSize: 10, color: 'var(--text-muted)' }}>Compare with Agentix ↗</div>
        </div>

        <div style={{ flex: 1, overflowY: 'auto', padding: '20px 18px', display: 'flex', flexDirection: 'column', gap: 10 }}>
          {CHAT_DEMO.map((msg, i) => (
            <div key={i} style={{
              padding: '10px 14px', borderRadius: 8, fontSize: 12.5, lineHeight: 1.5, maxWidth: '90%',
              ...(msg.role === 'user'
                ? { background: 'rgba(0,120,212,.10)', border: '1px solid rgba(0,120,212,.20)', marginLeft: 'auto', textAlign: 'right' }
                : { background: 'rgba(0,120,212,.12)', border: '1px solid rgba(0,120,212,.25)', color: (msg as { pending?: boolean }).pending ? 'var(--accent-blue)' : 'var(--text-primary)' }
              ),
            }}>
              {msg.role === 'Agent' && <div style={{ fontSize: 10, color: 'var(--accent-blue)', marginBottom: 4, fontWeight: 600 }}>✦ AGENTIC ASSISTANT</div>}
              <div style={{ whiteSpace: 'pre-line' }}>{msg.text}</div>
            </div>
          ))}
          <div ref={bottomRef} />
        </div>

        <div style={{ padding: '12px 18px', borderTop: '1px solid var(--border)', display: 'flex', flexDirection: 'column', gap: 8 }}>
          <div style={{ display: 'flex', gap: 8 }}>
            <input
              className="filter-input"
              style={{ flex: 1, borderRadius: 8, padding: '10px 14px', fontSize: 12.5 }}
              placeholder="Ask the AI Agent助手 to investigate, query, or take action..."
              value={input}
              onChange={e => setInput(e.target.value)}
              onKeyDown={e => {
                if ((e.key === 'Enter' && (e.ctrlKey || e.metaKey)) || (e.key === 'Enter' && !e.shiftKey)) {
                  e.preventDefault()
                  handleExecute()
                }
              }}
            />
            <button className="btn-primary" style={{ fontSize: 12, padding: '8px 18px' }} onClick={handleExecute}>发送</button>
          </div>
          {/* Hint row */}
          <div style={{ fontSize: 10, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{ opacity: hasInput ? 1 : 0.4, transition: 'opacity .3s' }}>
              按 <kbd style={{
                display: 'inline-block', padding: '1px 5px', borderRadius: 3,
                background: 'rgba(255,255,255,.08)', border: '1px solid rgba(255,255,255,.15)',
                fontSize: 10, fontFamily: 'monospace', color: 'var(--text-secondary)',
              }}>Ctrl+Enter</kbd> 执行
            </span>
            {hasInput && (
              <span style={{ color: 'var(--accent-blue)', animation: 'pulse-dot 1.2s ease-in-out infinite' }}>
                ● 就绪
              </span>
            )}
          </div>
        </div>
      </div>

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
        <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', marginBottom: 10 }}>能力</div>
        <div style={{ fontSize: 11, color: 'var(--text-secondary)', lineHeight: 1.9 }}>
          {['Run XQL queries', 'Investigate incidents', 'Execute playbooks', 'Isolate endpoints', 'Block indicators', 'Generate reports', 'Correlate threat intel', 'Draft notifications'].map(c => (
            <div key={c}>— {c}</div>
          ))}
        </div>
      </div>
      </div>{/* end flex row */}

      {/* ── Quick action floating bar ── */}
      {hasInput && (
        <div style={{
          position: 'absolute', bottom: 20, left: '50%', transform: 'translateX(-50%)',
          display: 'flex', alignItems: 'center', gap: 10,
          padding: '8px 16px', borderRadius: 24,
          background: 'rgba(10,20,40,.92)', border: '1px solid rgba(0,120,212,.35)',
          boxShadow: '0 4px 20px rgba(0,0,0,.5)',
          backdropFilter: 'blur(4px)',
          zIndex: 50,
          whiteSpace: 'nowrap',
        }}>
          <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>
            {input.length > 40 ? `${input.slice(0, 40)}…` : input}
          </span>
          <button
            className="btn-primary"
            style={{
              fontSize: 11, padding: '5px 16px', borderRadius: 20,
              animation: 'execute-pulse 1.4s ease-in-out infinite',
            }}
            onClick={handleExecute}
          >
            执行
          </button>
          <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>
            <kbd style={{
              display: 'inline-block', padding: '1px 5px', borderRadius: 3,
              background: 'rgba(255,255,255,.07)', border: '1px solid rgba(255,255,255,.15)',
              fontSize: 10, fontFamily: 'monospace',
            }}>Ctrl+↵</kbd>
          </span>
        </div>
      )}
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
        <button className="btn-secondary" style={{ fontSize: 11 }} onClick={() => alert('XSIAM MCP Server\n\nDownload and install the XSIAM MCP server package to enable Agent tool use against your internal systems.')}>安装 XSIAM MCP 服务</button>
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
              {m.connected ? '已连接' : '未连接'}
            </span>
          </div>
        ))}
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
        <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>智能体可自主或经批准后执行的操作</div>
        <button className="btn-primary" style={{ fontSize: 11 }} onClick={() => {
          const name = prompt('操作名称（例：在 Okta 中封锁用户）：')
          if (name) alert(`操作 "${name}" 已注册。\n\n请在操作编辑器中定义输入参数、执行逻辑和审批要求。`)
        }}>+ 注册新操作</button>
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
  { id: 'Agents',    label: 'AI 智能体' },
  { id: 'assistant', label: 'AI 助手' },
  { id: 'mcp',       label: 'MCP 集成' },
  { id: 'actions',   label: '操作库' },
]

const REFRESH_INTERVAL = 30

export default function AgentsHub() {
  const [activeTab, setActiveTab] = useState<TabId>('Agents')
  const [stats, setStats] = useState<DashboardStats | null>(null)
  const [onlineCount, setOnlineCount] = useState<number | null>(null)
  const [devices, setDevices] = useState<AgentDevice[]>([])
  const [policies, setPolicies] = useState<AgentPolicy[]>([])
  const [refreshing, setRefreshing] = useState(false)
  const [justUpdated, setJustUpdated] = useState(false)
  const [countdown, setCountdown] = useState(REFRESH_INTERVAL)
  const countdownRef = useRef(REFRESH_INTERVAL)

  const fetchData = useCallback((showIndicator = false) => {
    if (showIndicator) setRefreshing(true)
    countdownRef.current = REFRESH_INTERVAL
    setCountdown(REFRESH_INTERVAL)

    Promise.all([
      api.get('/dashboard/stats')
        .then(r => setStats(r.data?.data ?? r.data ?? null))
        .catch(() => {}),
      api.get('/devices/online-count')
        .then(r => {
          const count = r.data?.data?.count ?? r.data?.count ?? null
          setOnlineCount(count)
        })
        .catch(() => {}),
      api.get('/devices')
        .then(r => {
          const list: AgentDevice[] = r.data?.data ?? r.data ?? []
          setDevices(Array.isArray(list) ? list : [])
        })
        .catch(() => {}),
      api.get('/agent_policies')
        .then(r => {
          const list: AgentPolicy[] = r.data?.data ?? r.data ?? []
          setPolicies(Array.isArray(list) ? list : [])
        })
        .catch(() => {}),
    ]).finally(() => {
      if (showIndicator) {
        setRefreshing(false)
        setJustUpdated(true)
        setTimeout(() => setJustUpdated(false), 2000)
      }
    })
  }, [])

  // Initial load
  useEffect(() => {
    fetchData(false)
  }, [fetchData])

  // Auto-refresh countdown ticker
  useEffect(() => {
    const ticker = setInterval(() => {
      countdownRef.current -= 1
      setCountdown(countdownRef.current)
      if (countdownRef.current <= 0) {
        fetchData(true)
      }
    }, 1000)
    return () => clearInterval(ticker)
  }, [fetchData])

  function handleManualRefresh() {
    fetchData(true)
  }

  const hasOnlineData = onlineCount != null
  const onlineLabel = hasOnlineData ? `${onlineCount} agents online` : null

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <PageHeader
        title="Agent 中心"
        subtitle={onlineLabel ? `· Agentic AI workforce · XSIAM 3.x · ${onlineLabel}` : '· Agentic AI workforce · XSIAM 3.x'}
        actions={<>
          {/* Refresh indicator */}
          {refreshing ? (
            <span style={{ fontSize: 11, color: 'var(--accent-blue)', display: 'inline-flex', alignItems: 'center', gap: 5 }}>
              <span style={{
                width: 11, height: 11, border: '1.5px solid rgba(0,120,212,.3)', borderTopColor: 'var(--accent-blue)',
                borderRadius: '50%', display: 'inline-block',
                animation: 'spin 0.8s linear infinite',
              }} />
              更新中...
            </span>
          ) : justUpdated ? (
            <span style={{ fontSize: 11, color: 'var(--accent-green)', display: 'inline-flex', alignItems: 'center', gap: 4 }}>
              ✓ 已更新
            </span>
          ) : (
            <span style={{ fontSize: 11, color: 'var(--text-muted)', display: 'inline-flex', alignItems: 'center', gap: 6 }}>
              ⟳ {countdown}秒后自动刷新
            </span>
          )}

          {/* Manual refresh button */}
          <button
            className="btn-secondary"
            style={{ fontSize: 11 }}
            disabled={refreshing}
            onClick={handleManualRefresh}
          >
            立即刷新
          </button>

          {hasOnlineData && (
            <span style={{
              fontSize: 11, padding: '3px 10px', borderRadius: 12,
              background: onlineCount! > 0 ? 'rgba(67,160,71,.12)' : 'rgba(120,120,120,.10)',
              border: onlineCount! > 0 ? '1px solid rgba(67,160,71,.3)' : '1px solid rgba(120,120,120,.25)',
              color: onlineCount! > 0 ? 'var(--accent-green)' : 'var(--text-muted)',
              display: 'inline-flex', alignItems: 'center', gap: 5,
            }}>
              <span style={{
                width: 6, height: 6, borderRadius: '50%', display: 'inline-block',
                background: onlineCount! > 0 ? 'var(--accent-green)' : 'var(--text-muted)',
                boxShadow: onlineCount! > 0 ? '0 0 5px rgba(47,176,122,.7)' : 'none',
              }} />
              {onlineLabel}
            </span>
          )}
          <button className="btn-secondary" style={{ fontSize: 12 }} onClick={() => setActiveTab('mcp')}>MCP 集成</button>
          <button className="btn-secondary" style={{ fontSize: 12 }} onClick={() => setActiveTab('actions')}>管理动作</button>
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
        {activeTab === 'Agents'    && <AgentsTab onSwitchTab={setActiveTab} stats={stats} onlineCount={onlineCount} devices={devices} policies={policies} />}
        {activeTab === 'assistant' && <AssistantTab />}
        {activeTab === 'mcp'       && <McpTab />}
        {activeTab === 'actions'   && <ActionsLibraryTab />}
      </div>

      <style>{`
        @keyframes spin { to { transform: rotate(360deg); } }
        @keyframes pulse-dot {
          0%, 100% { opacity: 1; transform: scale(1); }
          50% { opacity: 0.5; transform: scale(1.35); }
        }
        @keyframes execute-pulse {
          0%, 100% { box-shadow: 0 0 0 0 rgba(0,120,212,.5); }
          50% { box-shadow: 0 0 0 6px rgba(0,120,212,.0); }
        }
      `}</style>
    </div>
  )
}
