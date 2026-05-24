import { useEffect, useRef, useState } from 'react'
import {
  PieChart, Pie, Cell, Tooltip as ReTooltip, Legend, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis,
} from 'recharts'
import PageHeader from '@/components/PageHeader'

// ─── Types ────────────────────────────────────────────────────────────────────

type EndpointStatus = '正常' | '异常' | '隔离' | '离线'
type OSType = 'Windows' | 'Linux' | 'macOS'

interface Endpoint {
  id: string
  hostname: string
  ip: string
  os: OSType
  agentVersion: string
  healthScore: number
  lastActive: string
  status: EndpointStatus
}

interface BehaviorEvent {
  id: number
  time: string
  level: 'critical' | 'warning' | 'info'
  endpoint: string
  message: string
}

interface DetectionAlert {
  id: string
  time: string
  endpoint: string
  ruleName: string
  severity: '严重' | '高危' | '中危' | '低危'
  threatType: string
  status: '待处置' | '处置中' | '已关闭' | '误报'
}

interface DetectionRule {
  id: string
  name: string
  enabled: boolean
  hitCount: number
  category: string
}

interface IsolatedEndpoint {
  id: string
  hostname: string
  ip: string
  reason: string
  isolatedAt: string
  operator: string
  status: '隔离中' | '已解除'
}

// ─── Mock Data ────────────────────────────────────────────────────────────────

const MOCK_ENDPOINTS: Endpoint[] = [
  { id: 'ep-001', hostname: 'DESKTOP-WIN11-001', ip: '192.168.1.101', os: 'Windows', agentVersion: '3.2.1', healthScore: 92, lastActive: '2026-05-24T14:30:00Z', status: '正常' },
  { id: 'ep-002', hostname: 'SRV-LINUX-DB01',   ip: '192.168.1.50',  os: 'Linux',   agentVersion: '3.2.1', healthScore: 85, lastActive: '2026-05-24T14:28:00Z', status: '正常' },
  { id: 'ep-003', hostname: 'MACBOOK-DEV-023',  ip: '192.168.1.203', os: 'macOS',   agentVersion: '3.1.8', healthScore: 41, lastActive: '2026-05-24T14:25:00Z', status: '异常' },
  { id: 'ep-004', hostname: 'DESKTOP-WIN10-007',ip: '192.168.1.107', os: 'Windows', agentVersion: '3.0.5', healthScore: 58, lastActive: '2026-05-24T12:10:00Z', status: '异常' },
  { id: 'ep-005', hostname: 'SRV-LINUX-WEB02',  ip: '192.168.1.52',  os: 'Linux',   agentVersion: '3.2.1', healthScore: 88, lastActive: '2026-05-24T14:31:00Z', status: '正常' },
  { id: 'ep-006', hostname: 'DESKTOP-WIN11-042',ip: '192.168.1.142', os: 'Windows', agentVersion: '3.2.1', healthScore: 0,  lastActive: '2026-05-22T09:00:00Z', status: '隔离' },
  { id: 'ep-007', hostname: 'MACBOOK-PRO-011',  ip: '192.168.1.211', os: 'macOS',   agentVersion: '3.2.0', healthScore: 95, lastActive: '2026-05-24T14:29:00Z', status: '正常' },
  { id: 'ep-008', hostname: 'SRV-WIN-APP01',    ip: '192.168.1.61',  os: 'Windows', agentVersion: '3.1.9', healthScore: 72, lastActive: '2026-05-24T11:45:00Z', status: '正常' },
  { id: 'ep-009', hostname: 'DESKTOP-LINUX-005',ip: '192.168.1.105', os: 'Linux',   agentVersion: '3.2.1', healthScore: 0,  lastActive: '2026-05-20T16:00:00Z', status: '离线' },
  { id: 'ep-010', hostname: 'SRV-LINUX-MAIL01', ip: '192.168.1.55',  os: 'Linux',   agentVersion: '3.2.1', healthScore: 79, lastActive: '2026-05-24T14:27:00Z', status: '正常' },
]

const INITIAL_BEHAVIOR_EVENTS: BehaviorEvent[] = [
  { id: 1,  time: '14:32:15', level: 'critical', endpoint: 'ENDPOINT-001', message: 'powershell.exe 执行了可疑命令: cmd /c whoami' },
  { id: 2,  time: '14:31:42', level: 'warning',  endpoint: 'ENDPOINT-023', message: '注册表修改: HKLM\\SOFTWARE\\Run\\malware' },
  { id: 3,  time: '14:30:18', level: 'info',     endpoint: 'ENDPOINT-007', message: '正常文件访问: C:\\Windows\\System32\\notepad.exe' },
  { id: 4,  time: '14:29:55', level: 'critical', endpoint: 'ENDPOINT-001', message: '网络连接建立: 185.220.101.47:443 (C2通信)' },
  { id: 5,  time: '14:28:30', level: 'warning',  endpoint: 'ENDPOINT-042', message: '检测到进程注入: explorer.exe → svchost.exe' },
  { id: 6,  time: '14:27:11', level: 'info',     endpoint: 'ENDPOINT-005', message: '用户登录: administrator@corp.local' },
  { id: 7,  time: '14:26:50', level: 'critical', endpoint: 'ENDPOINT-023', message: '勒索软件特征: 大量文件加密操作 (.locked 扩展)' },
  { id: 8,  time: '14:25:33', level: 'warning',  endpoint: 'ENDPOINT-011', message: '计划任务创建: schtasks /create /tn backdoor' },
  { id: 9,  time: '14:24:18', level: 'info',     endpoint: 'ENDPOINT-008', message: 'DNS 查询: update.microsoft.com (正常)' },
  { id: 10, time: '14:23:05', level: 'critical', endpoint: 'ENDPOINT-007', message: 'Mimikatz 特征: lsass.exe 内存读取' },
  { id: 11, time: '14:22:47', level: 'warning',  endpoint: 'ENDPOINT-031', message: 'WMI 横向移动尝试: wmic /node:192.168.1.105' },
  { id: 12, time: '14:21:30', level: 'info',     endpoint: 'ENDPOINT-002', message: '软件安装: Chrome 124.0.6367.201' },
  { id: 13, time: '14:20:15', level: 'critical', endpoint: 'ENDPOINT-001', message: '特权提升: UAC 绕过成功 (fodhelper)' },
  { id: 14, time: '14:19:02', level: 'warning',  endpoint: 'ENDPOINT-019', message: 'Netsh 防火墙规则修改: 端口 4444 开放' },
  { id: 15, time: '14:18:44', level: 'info',     endpoint: 'ENDPOINT-010', message: '正常备份操作: robocopy /D backup\\daily' },
  { id: 16, time: '14:17:28', level: 'critical', endpoint: 'ENDPOINT-023', message: '数据外泄: 大量文件上传至 104.21.8.121:443' },
  { id: 17, time: '14:16:10', level: 'warning',  endpoint: 'ENDPOINT-055', message: 'PowerShell 编码命令执行: -EncodedCommand ...' },
  { id: 18, time: '14:15:55', level: 'info',     endpoint: 'ENDPOINT-003', message: 'Agent 心跳正常: v3.2.1' },
  { id: 19, time: '14:14:33', level: 'critical', endpoint: 'ENDPOINT-042', message: '挖矿程序: xmrig.exe CPU 使用率 98%' },
  { id: 20, time: '14:13:20', level: 'warning',  endpoint: 'ENDPOINT-006', message: 'USB 设备接入: 未授权存储设备 (8GB)' },
]

const BEHAVIOR_CATEGORIES = [
  { name: '进程创建', count: 1234, color: '#3b9ede' },
  { name: '网络连接', count: 567,  color: '#2fb07a' },
  { name: '文件操作', count: 8901, color: '#4fa3e0' },
  { name: '注册表操作', count: 234, color: '#f9a825' },
  { name: '脚本执行', count: 45,  color: '#e53935' },
]

const MITRE_TECHNIQUES = [
  { id: 'T1059', name: '命令和脚本解释器', count: 23, risk: 'critical' },
  { id: 'T1547', name: '启动或登录自启动', count: 8,  risk: 'high' },
  { id: 'T1055', name: '进程注入',         count: 3,  risk: 'critical' },
  { id: 'T1071', name: '应用层协议C2',     count: 12, risk: 'critical' },
  { id: 'T1083', name: '文件和目录发现',   count: 45, risk: 'warning' },
]

const MOCK_DETECTION_ALERTS: DetectionAlert[] = [
  { id: 'da-001', time: '2026-05-24 14:32', endpoint: 'ENDPOINT-001', ruleName: '可疑PowerShell执行', severity: '严重', threatType: '远控木马',   status: '待处置' },
  { id: 'da-002', time: '2026-05-24 14:28', endpoint: 'ENDPOINT-023', ruleName: '勒索软件行为检测', severity: '严重', threatType: '勒索软件',   status: '处置中' },
  { id: 'da-003', time: '2026-05-24 14:10', endpoint: 'ENDPOINT-042', ruleName: '挖矿程序检测',     severity: '高危', threatType: '挖矿程序',   status: '待处置' },
  { id: 'da-004', time: '2026-05-24 13:55', endpoint: 'ENDPOINT-007', ruleName: '凭证转储检测',     severity: '严重', threatType: '权限提升',   status: '处置中' },
  { id: 'da-005', time: '2026-05-24 13:30', endpoint: 'ENDPOINT-031', ruleName: 'WMI横向移动',      severity: '高危', threatType: '横向移动',   status: '待处置' },
  { id: 'da-006', time: '2026-05-24 12:48', endpoint: 'ENDPOINT-019', ruleName: '防火墙规则篡改',   severity: '中危', threatType: '持久化',     status: '已关闭' },
  { id: 'da-007', time: '2026-05-24 11:20', endpoint: 'ENDPOINT-055', ruleName: 'Base64编码命令',   severity: '中危', threatType: '远控木马',   status: '误报'   },
  { id: 'da-008', time: '2026-05-24 09:15', endpoint: 'ENDPOINT-006', ruleName: 'USB非授权设备',    severity: '低危', threatType: '持久化',     status: '已关闭' },
]

const MOCK_DETECTION_RULES: DetectionRule[] = [
  { id: 'rule-001', name: '勒索软件行为检测', enabled: true,  hitCount: 12, category: '勒索软件' },
  { id: 'rule-002', name: '凭证转储 (LSASS)', enabled: true,  hitCount: 8,  category: '凭证访问' },
  { id: 'rule-003', name: 'Mimikatz 特征检测', enabled: true, hitCount: 3,  category: '凭证访问' },
  { id: 'rule-004', name: '可疑PowerShell执行', enabled: true, hitCount: 45, category: '执行' },
  { id: 'rule-005', name: '挖矿程序行为',       enabled: false, hitCount: 5, category: '影响' },
  { id: 'rule-006', name: 'USB非授权访问检测',  enabled: true,  hitCount: 2, category: '数据收集' },
]

const MOCK_ISOLATED: IsolatedEndpoint[] = [
  { id: 'iso-001', hostname: 'ENDPOINT-042', ip: '192.168.1.142', reason: '发现勒索软件',   isolatedAt: '2026-05-24 11:20', operator: 'admin@corp',    status: '隔离中' },
  { id: 'iso-002', hostname: 'ENDPOINT-001', ip: '192.168.1.101', reason: 'C2通信检测',    isolatedAt: '2026-05-24 14:35', operator: 'soc-analyst1', status: '隔离中' },
  { id: 'iso-003', hostname: 'ENDPOINT-023', ip: '192.168.1.123', reason: '横向移动尝试',  isolatedAt: '2026-05-23 16:00', operator: 'admin@corp',    status: '隔离中' },
  { id: 'iso-004', hostname: 'ENDPOINT-007', ip: '192.168.1.107', reason: '凭证转储行为',  isolatedAt: '2026-05-22 09:30', operator: 'soc-analyst2', status: '隔离中' },
  { id: 'iso-005', hostname: 'ENDPOINT-055', ip: '192.168.1.155', reason: '测试隔离',      isolatedAt: '2026-05-21 14:00', operator: 'admin@corp',    status: '已解除' },
]

// 7-day isolation timeline data (dots per day)
const ISOLATION_TIMELINE = [
  { day: '05/18', events: 0 },
  { day: '05/19', events: 1 },
  { day: '05/20', events: 0 },
  { day: '05/21', events: 2 },
  { day: '05/22', events: 1 },
  { day: '05/23', events: 1 },
  { day: '05/24', events: 3 },
]

// Health donut data
const HEALTH_DATA = [
  { name: '健康 (80-100)', value: 892, color: '#2fb07a' },
  { name: '一般 (60-80)',  value: 234, color: '#f9a825' },
  { name: '较差 (<60)',    value: 158, color: '#e53935' },
]

// ─── Helper functions ─────────────────────────────────────────────────────────

function fmtDate(iso: string) {
  if (!iso) return '—'
  try {
    const d = new Date(iso)
    if (isNaN(d.getTime())) return iso
    const p = (n: number) => n.toString().padStart(2, '0')
    return `${p(d.getMonth() + 1)}/${p(d.getDate())} ${p(d.getHours())}:${p(d.getMinutes())}`
  } catch { return '—' }
}

function healthColor(score: number): string {
  if (score >= 80) return '#2fb07a'
  if (score >= 60) return '#f9a825'
  return '#e53935'
}

function statusColor(status: EndpointStatus): string {
  switch (status) {
    case '正常': return '#2fb07a'
    case '异常': return '#e53935'
    case '隔离': return '#ff6f00'
    case '离线': return '#546e7a'
  }
}

function severityColor(sev: string): string {
  switch (sev) {
    case '严重': return '#e53935'
    case '高危': return '#ff6f00'
    case '中危': return '#f9a825'
    case '低危': return '#2fb07a'
    default: return '#546e7a'
  }
}

function detStatusColor(status: string): string {
  switch (status) {
    case '待处置': return '#e53935'
    case '处置中': return '#f9a825'
    case '已关闭': return '#2fb07a'
    case '误报':   return '#546e7a'
    default: return '#546e7a'
  }
}

function osIcon(os: OSType): string {
  switch (os) {
    case 'Windows': return '🪟'
    case 'Linux':   return '🐧'
    case 'macOS':   return '🍎'
  }
}

function levelEmoji(level: BehaviorEvent['level']): string {
  switch (level) {
    case 'critical': return '🔴'
    case 'warning':  return '🟡'
    case 'info':     return '🟢'
  }
}

function riskEmoji(risk: string): string {
  switch (risk) {
    case 'critical': return '🔴'
    case 'high':     return '🟠'
    case 'warning':  return '🟡'
    default: return '🟢'
  }
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function KpiCard({
  label, value, color, note,
}: { label: string; value: string | number; color?: string; note?: string }) {
  return (
    <div className="kpi-card" style={{ flex: 1, minWidth: 120 }}>
      <div className="kpi-label">{label}</div>
      <div className="kpi-value" style={{ color: color ?? 'var(--text-primary)', fontSize: 22 }}>
        {value}
      </div>
      {note && <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginTop: 4 }}>{note}</div>}
    </div>
  )
}

function ActionBtn({
  label, color, onClick,
}: { label: string; color?: string; onClick?: () => void }) {
  return (
    <button
      className="btn-secondary"
      style={{ fontSize: 10.5, padding: '2px 8px', color: color ?? 'var(--text-secondary)', whiteSpace: 'nowrap' }}
      onClick={onClick}
    >
      {label}
    </button>
  )
}

// ─── Tab 1: 终端概览 ───────────────────────────────────────────────────────────

function EndpointOverview() {
  const [osFilter, setOsFilter] = useState<string>('全部')
  const [statusFilter, setStatusFilter] = useState<string>('全部')
  const [search, setSearch] = useState('')

  const filtered = MOCK_ENDPOINTS.filter(ep => {
    if (osFilter !== '全部' && ep.os !== osFilter) return false
    if (statusFilter !== '全部' && ep.status !== statusFilter) return false
    if (search && !ep.hostname.toLowerCase().includes(search.toLowerCase()) && !ep.ip.includes(search)) return false
    return true
  })

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16, padding: '16px 20px', overflowY: 'auto', flex: 1 }}>

      {/* KPI row */}
      <div style={{ display: 'flex', gap: 10 }}>
        <KpiCard label="受保护终端" value="1,284" />
        <KpiCard label="在线终端"   value="1,156" color="#2fb07a" />
        <KpiCard label="异常终端"   value="23"    color="#e53935" />
        <KpiCard label="隔离中"     value="5"     color="#ff6f00" />
        <KpiCard label="未安装Agent" value="48"   color="#546e7a" />
      </div>

      {/* Charts row */}
      <div style={{ display: 'flex', gap: 12 }}>
        {/* Health score donut */}
        <div className="card" style={{ width: 340, flexShrink: 0 }}>
          <div className="card-title">健康评分分布</div>
          <ResponsiveContainer width="100%" height={200}>
            <PieChart>
              <Pie
                data={HEALTH_DATA}
                cx="50%"
                cy="50%"
                innerRadius={55}
                outerRadius={85}
                paddingAngle={2}
                dataKey="value"
              >
                {HEALTH_DATA.map((entry, index) => (
                  <Cell key={index} fill={entry.color} />
                ))}
              </Pie>
              <ReTooltip
                contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', fontSize: 11, color: 'var(--text-primary)' }}
                formatter={((value: unknown, name: unknown) => [Number(value ?? 0) + ' 台', name]) as any}
              />
              <Legend
                iconType="circle"
                iconSize={8}
                wrapperStyle={{ fontSize: 11, color: 'var(--text-secondary)' }}
              />
            </PieChart>
          </ResponsiveContainer>
          <div style={{ display: 'flex', justifyContent: 'center', gap: 16, marginTop: 4 }}>
            {HEALTH_DATA.map(d => (
              <div key={d.name} style={{ textAlign: 'center' }}>
                <div style={{ fontSize: 16, fontWeight: 700, color: d.color }}>{d.value}</div>
                <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>台</div>
              </div>
            ))}
          </div>
        </div>

        {/* Stats summary */}
        <div className="card" style={{ flex: 1 }}>
          <div className="card-title">终端状态概览</div>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 10, marginTop: 4 }}>
            {[
              { label: '在线率', value: 90, color: '#2fb07a' },
              { label: '健康率 (≥80分)', value: 69, color: '#3b9ede' },
              { label: 'Agent 最新版本覆盖率', value: 83, color: '#f9a825' },
            ].map(item => (
              <div key={item.label}>
                <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 11.5, marginBottom: 4 }}>
                  <span style={{ color: 'var(--text-secondary)' }}>{item.label}</span>
                  <span style={{ color: item.color, fontWeight: 700 }}>{item.value}%</span>
                </div>
                <div style={{ height: 6, background: 'var(--bg-card2)', borderRadius: 3, overflow: 'hidden' }}>
                  <div style={{ width: `${item.value}%`, height: '100%', background: item.color, borderRadius: 3, transition: 'width .5s' }} />
                </div>
              </div>
            ))}
            <div style={{ marginTop: 8, display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 8 }}>
              {[
                { label: '平均健康评分', value: '82.4', color: '#2fb07a' },
                { label: '今日新增告警',  value: '23',   color: '#e53935' },
                { label: '待处置事件',   value: '7',    color: '#ff6f00' },
                { label: '本周隔离操作', value: '12',   color: '#f9a825' },
              ].map(stat => (
                <div key={stat.label} style={{ padding: '8px 10px', background: 'var(--bg-secondary)', borderRadius: 4 }}>
                  <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 3 }}>{stat.label}</div>
                  <div style={{ fontSize: 18, fontWeight: 700, color: stat.color }}>{stat.value}</div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Filter bar */}
      <div className="filter-bar" style={{ borderRadius: 4, padding: '8px 12px' }}>
        <input
          className="filter-input"
          placeholder="搜索主机名 / IP..."
          value={search}
          onChange={e => setSearch(e.target.value)}
          style={{ minWidth: 200 }}
        />
        <select
          className="filter-select"
          value={osFilter}
          onChange={e => setOsFilter(e.target.value)}
        >
          {['全部', 'Windows', 'Linux', 'macOS'].map(o => (
            <option key={o}>{o}</option>
          ))}
        </select>
        <select
          className="filter-select"
          value={statusFilter}
          onChange={e => setStatusFilter(e.target.value)}
        >
          {['全部', '正常', '异常', '隔离', '离线'].map(s => (
            <option key={s}>{s}</option>
          ))}
        </select>
        <span style={{ fontSize: 11, color: 'var(--text-muted)', marginLeft: 'auto' }}>
          共 {filtered.length} 条
        </span>
      </div>

      {/* Endpoint table */}
      <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 6, overflow: 'hidden' }}>
        <table className="data-table">
          <thead>
            <tr>
              <th>主机名</th>
              <th>IP</th>
              <th>OS</th>
              <th>Agent 版本</th>
              <th>健康评分</th>
              <th>最后活跃</th>
              <th>状态</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(ep => {
              const sc = healthColor(ep.healthScore)
              const stc = statusColor(ep.status)
              return (
                <tr key={ep.id} className={ep.status === '异常' ? 'row-critical' : ''}>
                  <td>
                    <div style={{ fontFamily: 'Consolas,"JetBrains Mono",monospace', fontSize: 12, fontWeight: 600, color: 'var(--text-primary)' }}>
                      {ep.hostname}
                    </div>
                  </td>
                  <td>
                    <span style={{ fontFamily: 'Consolas,"JetBrains Mono",monospace', fontSize: 11.5, color: 'var(--text-secondary)' }}>
                      {ep.ip}
                    </span>
                  </td>
                  <td>
                    <span style={{ fontSize: 12 }}>{osIcon(ep.os)} {ep.os}</span>
                  </td>
                  <td>
                    <span style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--text-muted)' }}>{ep.agentVersion}</span>
                  </td>
                  <td>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <div style={{ width: 48, height: 5, background: 'var(--bg-card2)', borderRadius: 3, overflow: 'hidden', flexShrink: 0 }}>
                        <div style={{ width: `${ep.healthScore}%`, height: '100%', background: sc, borderRadius: 3 }} />
                      </div>
                      <span style={{ fontSize: 12, fontWeight: 700, color: sc }}>{ep.healthScore}</span>
                    </div>
                  </td>
                  <td>
                    <span style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>{fmtDate(ep.lastActive)}</span>
                  </td>
                  <td>
                    <span style={{
                      display: 'inline-flex', alignItems: 'center', gap: 4,
                      fontSize: 11, padding: '2px 8px', borderRadius: 3,
                      background: stc + '1a', color: stc, fontWeight: 600,
                    }}>
                      <span style={{ width: 5, height: 5, borderRadius: '50%', background: stc, flexShrink: 0 }} />
                      {ep.status}
                    </span>
                  </td>
                  <td>
                    <div style={{ display: 'flex', gap: 4 }}>
                      <ActionBtn label="详情" />
                      <ActionBtn label="隔离" color="#ff6f00" />
                      <ActionBtn label="升级" color="#3b9ede" />
                    </div>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ─── Tab 2: 行为监控 ───────────────────────────────────────────────────────────

function BehaviorMonitoring() {
  const [events, setEvents] = useState<BehaviorEvent[]>(INITIAL_BEHAVIOR_EVENTS)
  const [autoScroll, setAutoScroll] = useState(true)
  const feedRef = useRef<HTMLDivElement>(null)
  const counterRef = useRef(INITIAL_BEHAVIOR_EVENTS.length)

  // Simulate real-time events every 5 seconds
  useEffect(() => {
    const NEW_TEMPLATES: Omit<BehaviorEvent, 'id' | 'time'>[] = [
      { level: 'critical', endpoint: 'ENDPOINT-099', message: 'mshta.exe 执行远程脚本: http://evil.site/payload.hta' },
      { level: 'warning',  endpoint: 'ENDPOINT-011', message: 'reg.exe 导出注册表: HKLM\\SAM → C:\\Users\\tmp\\sam.dat' },
      { level: 'info',     endpoint: 'ENDPOINT-004', message: 'Windows Update 服务启动' },
      { level: 'critical', endpoint: 'ENDPOINT-033', message: 'wscript.exe 执行 VBS 脚本: C:\\Users\\AppData\\temp.vbs' },
      { level: 'warning',  endpoint: 'ENDPOINT-017', message: '新服务安装: SvcHelper (可疑服务名)' },
    ]

    const tid = setInterval(() => {
      const now = new Date()
      const timeStr = `${now.getHours().toString().padStart(2, '0')}:${now.getMinutes().toString().padStart(2, '0')}:${now.getSeconds().toString().padStart(2, '0')}`
      const template = NEW_TEMPLATES[counterRef.current % NEW_TEMPLATES.length]
      const newEvent: BehaviorEvent = { ...template, id: ++counterRef.current, time: timeStr }
      setEvents(prev => [newEvent, ...prev.slice(0, 39)])
    }, 5000)

    return () => clearInterval(tid)
  }, [])

  useEffect(() => {
    if (autoScroll && feedRef.current) {
      feedRef.current.scrollTop = 0
    }
  }, [events, autoScroll])

  const levelColor = (level: BehaviorEvent['level']) => {
    switch (level) {
      case 'critical': return '#e53935'
      case 'warning':  return '#f9a825'
      case 'info':     return '#2fb07a'
    }
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16, padding: '16px 20px', overflowY: 'auto', flex: 1 }}>

      {/* Behavior categories chart */}
      <div style={{ display: 'flex', gap: 12 }}>
        <div className="card" style={{ flex: 1 }}>
          <div className="card-title">行为分类统计（今日）</div>
          <ResponsiveContainer width="100%" height={160}>
            <BarChart data={BEHAVIOR_CATEGORIES} layout="vertical" margin={{ left: 10, right: 30, top: 4, bottom: 4 }}>
              <XAxis type="number" tick={{ fontSize: 10, fill: '#546e7a' }} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="name" tick={{ fontSize: 11, fill: '#7a8aaa' }} axisLine={false} tickLine={false} width={68} />
              <ReTooltip
                contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', fontSize: 11, color: 'var(--text-primary)' }}
                formatter={((value: unknown) => [Number(value ?? 0).toLocaleString() + ' 次', '事件数']) as any}
              />
              <Bar dataKey="count" radius={[0, 3, 3, 0]}>
                {BEHAVIOR_CATEGORIES.map((entry, index) => (
                  <Cell key={index} fill={entry.color} />
                ))}
              </Bar>
            </BarChart>
          </ResponsiveContainer>
        </div>

        {/* MITRE map */}
        <div className="card" style={{ flex: 1 }}>
          <div className="card-title">MITRE ATT&amp;CK 今日检测</div>
          <table style={{ width: '100%', borderCollapse: 'collapse', fontSize: 11.5 }}>
            <thead>
              <tr>
                {['技术ID', '技术名称', '检测次数', '风险'].map(h => (
                  <th key={h} style={{ textAlign: 'left', padding: '4px 8px', fontSize: 10, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.4, borderBottom: '1px solid var(--border)' }}>
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {MITRE_TECHNIQUES.map(t => (
                <tr key={t.id}>
                  <td style={{ padding: '6px 8px', borderBottom: '1px solid var(--border)', fontFamily: 'monospace', color: '#3b9ede', fontWeight: 600, fontSize: 11 }}>
                    {t.id}
                  </td>
                  <td style={{ padding: '6px 8px', borderBottom: '1px solid var(--border)', color: 'var(--text-secondary)' }}>
                    {t.name}
                  </td>
                  <td style={{ padding: '6px 8px', borderBottom: '1px solid var(--border)', fontWeight: 700, color: 'var(--text-primary)' }}>
                    {t.count}
                  </td>
                  <td style={{ padding: '6px 8px', borderBottom: '1px solid var(--border)' }}>
                    {riskEmoji(t.risk)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Real-time feed */}
      <div className="card" style={{ flex: 1, display: 'flex', flexDirection: 'column' }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', marginBottom: 10 }}>
          <div className="card-title" style={{ marginBottom: 0 }}>实时行为事件流</div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{
              display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 10.5,
              padding: '2px 8px', borderRadius: 10,
              background: 'rgba(47,176,122,.15)', color: '#2fb07a',
              border: '1px solid rgba(47,176,122,.3)',
            }}>
              <span style={{ width: 5, height: 5, borderRadius: '50%', background: '#2fb07a', animation: 'pulse-dot 1.5s infinite' }} />
              实时
            </span>
            <button
              className={autoScroll ? 'btn-primary' : 'btn-secondary'}
              style={{ fontSize: 10.5, padding: '3px 10px' }}
              onClick={() => setAutoScroll(v => !v)}
            >
              {autoScroll ? '⏸ 暂停滚动' : '▶ 自动滚动'}
            </button>
          </div>
        </div>
        <div
          ref={feedRef}
          style={{
            height: 320, overflowY: 'auto',
            background: 'var(--bg-secondary)', borderRadius: 4,
            border: '1px solid var(--border)', padding: '6px 0',
            fontFamily: 'Consolas,"JetBrains Mono",monospace',
          }}
        >
          {events.map((ev, i) => (
            <div
              key={ev.id}
              style={{
                padding: '4px 12px', fontSize: 11.5, lineHeight: 1.5,
                borderBottom: '1px solid rgba(255,255,255,.03)',
                background: i === 0 ? 'rgba(59,158,222,.04)' : 'transparent',
                transition: 'background .3s',
              }}
            >
              <span style={{ color: 'var(--text-muted)', marginRight: 8 }}>[{ev.time}]</span>
              <span style={{ marginRight: 6 }}>{levelEmoji(ev.level)}</span>
              <span style={{ color: '#3b9ede', marginRight: 6 }}>[{ev.endpoint}]</span>
              <span style={{ color: levelColor(ev.level) }}>{ev.message}</span>
            </div>
          ))}
        </div>
        <div style={{ marginTop: 6, fontSize: 10.5, color: 'var(--text-muted)' }}>
          显示最近 {events.length} 条 · 每 5 秒更新
        </div>
      </div>
    </div>
  )
}

// ─── Tab 3: 终端检测 ───────────────────────────────────────────────────────────

function EndpointDetection() {
  const [expandedRules, setExpandedRules] = useState(false)
  const [rules, setRules] = useState(MOCK_DETECTION_RULES)

  function toggleRule(id: string) {
    setRules(prev => prev.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r))
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16, padding: '16px 20px', overflowY: 'auto', flex: 1 }}>

      {/* Detection alerts table */}
      <div className="card">
        <div className="card-title">检测告警</div>
        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>时间</th>
                <th>终端</th>
                <th>规则名称</th>
                <th>严重程度</th>
                <th>威胁类型</th>
                <th>状态</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {MOCK_DETECTION_ALERTS.map(alert => {
                const sc = severityColor(alert.severity)
                const dc = detStatusColor(alert.status)
                return (
                  <tr key={alert.id} className={alert.severity === '严重' ? 'row-critical' : ''}>
                    <td>
                      <span style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--text-muted)' }}>{alert.time}</span>
                    </td>
                    <td>
                      <span style={{ fontFamily: 'monospace', fontSize: 11.5, color: '#3b9ede', fontWeight: 600 }}>{alert.endpoint}</span>
                    </td>
                    <td>
                      <span style={{ fontSize: 12, color: 'var(--text-primary)' }}>{alert.ruleName}</span>
                    </td>
                    <td>
                      <span style={{
                        display: 'inline-flex', alignItems: 'center', gap: 4,
                        fontSize: 11, padding: '2px 8px', borderRadius: 3,
                        background: sc + '22', color: sc, fontWeight: 700,
                      }}>
                        {alert.severity}
                      </span>
                    </td>
                    <td>
                      <span style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>{alert.threatType}</span>
                    </td>
                    <td>
                      <span style={{
                        display: 'inline-flex', alignItems: 'center', gap: 4,
                        fontSize: 11, padding: '2px 8px', borderRadius: 3,
                        background: dc + '1a', color: dc, fontWeight: 600,
                      }}>
                        <span style={{ width: 4, height: 4, borderRadius: '50%', background: dc }} />
                        {alert.status}
                      </span>
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: 4 }}>
                        <ActionBtn label="查看详情" />
                        <ActionBtn label="隔离终端" color="#ff6f00" />
                        <ActionBtn label="标记误报" color="#546e7a" />
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Detection rule coverage */}
      <div className="card">
        <button
          style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            width: '100%', background: 'none', border: 'none', cursor: 'pointer', padding: 0,
          }}
          onClick={() => setExpandedRules(v => !v)}
        >
          <div className="card-title" style={{ marginBottom: 0, color: 'var(--text-secondary)' }}>
            检测规则覆盖率 ({rules.filter(r => r.enabled).length}/{rules.length} 已启用)
          </div>
          <span style={{ fontSize: 12, color: 'var(--text-muted)', flexShrink: 0, marginLeft: 8 }}>
            {expandedRules ? '▲ 收起' : '▼ 展开'}
          </span>
        </button>

        {expandedRules && (
          <div style={{ marginTop: 12, display: 'flex', flexDirection: 'column', gap: 6 }}>
            {rules.map(rule => (
              <div key={rule.id} style={{
                display: 'flex', alignItems: 'center', gap: 10,
                padding: '8px 12px', borderRadius: 4,
                background: 'var(--bg-secondary)', border: '1px solid var(--border)',
              }}>
                {/* Toggle */}
                <button
                  onClick={() => toggleRule(rule.id)}
                  style={{
                    width: 36, height: 18, borderRadius: 9,
                    background: rule.enabled ? '#2fb07a' : '#283044',
                    border: 'none', cursor: 'pointer', padding: 0, flexShrink: 0,
                    position: 'relative', transition: 'background .2s',
                  }}
                >
                  <span style={{
                    position: 'absolute', top: 2,
                    left: rule.enabled ? 20 : 2,
                    width: 14, height: 14,
                    borderRadius: '50%', background: 'white',
                    transition: 'left .2s',
                  }} />
                </button>

                <span style={{ flex: 1, fontSize: 12, color: rule.enabled ? 'var(--text-primary)' : 'var(--text-muted)' }}>
                  {rule.name}
                </span>
                <span style={{ fontSize: 10.5, padding: '2px 6px', borderRadius: 3, background: 'rgba(59,158,222,.12)', color: '#3b9ede' }}>
                  {rule.category}
                </span>
                <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'monospace', width: 50, textAlign: 'right' }}>
                  {rule.hitCount} 次
                </span>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Tab 4: 隔离管理 ─────────────────────────────────────────────────────────

function IsolationManagement() {
  const [isolated, setIsolated] = useState(MOCK_ISOLATED)

  function releaseEndpoint(id: string) {
    setIsolated(prev => prev.map(ep =>
      ep.id === id ? { ...ep, status: '已解除' as const } : ep
    ))
  }

  const isoStatusColor = (s: IsolatedEndpoint['status']) =>
    s === '隔离中' ? '#ff6f00' : '#2fb07a'

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 16, padding: '16px 20px', overflowY: 'auto', flex: 1 }}>

      {/* KPI cards */}
      <div style={{ display: 'flex', gap: 10 }}>
        <KpiCard label="当前隔离" value="5"    color="#ff6f00" note="台终端" />
        <KpiCard label="本周隔离操作" value="12" color="#f9a825" note="次操作" />
        <KpiCard label="平均隔离时长" value="4.2" color="#3b9ede" note="小时" />
      </div>

      {/* Isolated endpoints table */}
      <div className="card">
        <div className="card-title">隔离终端列表</div>
        <div style={{ overflowX: 'auto' }}>
          <table className="data-table">
            <thead>
              <tr>
                <th>主机名</th>
                <th>IP</th>
                <th>隔离原因</th>
                <th>隔离时间</th>
                <th>操作人</th>
                <th>状态</th>
                <th>操作</th>
              </tr>
            </thead>
            <tbody>
              {isolated.map(ep => {
                const sc = isoStatusColor(ep.status)
                return (
                  <tr key={ep.id}>
                    <td>
                      <span style={{ fontFamily: 'monospace', fontSize: 12, fontWeight: 600, color: 'var(--text-primary)' }}>
                        {ep.hostname}
                      </span>
                    </td>
                    <td>
                      <span style={{ fontFamily: 'monospace', fontSize: 11.5, color: 'var(--text-secondary)' }}>
                        {ep.ip}
                      </span>
                    </td>
                    <td>
                      <span style={{
                        fontSize: 11.5, padding: '2px 8px', borderRadius: 3,
                        background: 'rgba(229,57,53,.12)', color: '#ef5350',
                        border: '1px solid rgba(229,57,53,.2)',
                      }}>
                        {ep.reason}
                      </span>
                    </td>
                    <td>
                      <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                        {ep.isolatedAt}
                      </span>
                    </td>
                    <td>
                      <span style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>{ep.operator}</span>
                    </td>
                    <td>
                      <span style={{
                        display: 'inline-flex', alignItems: 'center', gap: 4,
                        fontSize: 11, padding: '2px 8px', borderRadius: 3,
                        background: sc + '22', color: sc, fontWeight: 600,
                      }}>
                        <span style={{ width: 4, height: 4, borderRadius: '50%', background: sc }} />
                        {ep.status}
                      </span>
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: 4 }}>
                        {ep.status === '隔离中' && (
                          <button
                            className="btn-secondary"
                            style={{ fontSize: 10.5, padding: '2px 8px', color: '#2fb07a', borderColor: 'rgba(47,176,122,.3)' }}
                            onClick={() => releaseEndpoint(ep.id)}
                          >
                            解除隔离
                          </button>
                        )}
                        <ActionBtn label="查看详情" />
                        {ep.status === '隔离中' && <ActionBtn label="延长隔离" color="#f9a825" />}
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* Isolation timeline */}
      <div className="card">
        <div className="card-title">近 7 天隔离操作时间线</div>
        <div style={{ display: 'flex', alignItems: 'flex-end', gap: 0, padding: '8px 0 4px' }}>
          {ISOLATION_TIMELINE.map((day, i) => (
            <div key={i} style={{ flex: 1, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 8 }}>
              {/* Events column */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 4, minHeight: 40, justifyContent: 'flex-end', alignItems: 'center' }}>
                {Array.from({ length: day.events }).map((_, j) => (
                  <div
                    key={j}
                    title={`${day.day}: 隔离操作`}
                    style={{
                      width: 10, height: 10, borderRadius: '50%',
                      background: '#ff6f00',
                      boxShadow: '0 0 6px rgba(255,111,0,.5)',
                      cursor: 'pointer',
                      transition: 'transform .15s',
                    }}
                    onMouseEnter={e => { (e.currentTarget as HTMLElement).style.transform = 'scale(1.4)' }}
                    onMouseLeave={e => { (e.currentTarget as HTMLElement).style.transform = 'scale(1)' }}
                  />
                ))}
                {day.events === 0 && (
                  <div style={{ width: 6, height: 6, borderRadius: '50%', background: 'var(--border-light)' }} />
                )}
              </div>
              {/* Count badge */}
              {day.events > 0 && (
                <span style={{ fontSize: 10, fontWeight: 700, color: '#ff6f00' }}>{day.events}</span>
              )}
              {/* Day label */}
              <div style={{ fontSize: 10, color: 'var(--text-muted)', paddingTop: 2, borderTop: '1px solid var(--border)', width: '100%', textAlign: 'center' }}>
                {day.day}
              </div>
            </div>
          ))}
        </div>
        <div style={{ marginTop: 6, display: 'flex', alignItems: 'center', gap: 6, fontSize: 10.5, color: 'var(--text-muted)' }}>
          <span style={{ width: 8, height: 8, borderRadius: '50%', background: '#ff6f00', display: 'inline-block', flexShrink: 0 }} />
          每个点代表一次隔离操作
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

const TABS = [
  { id: 'overview',   label: '终端概览' },
  { id: 'behavior',   label: '行为监控' },
  { id: 'detection',  label: '终端检测' },
  { id: 'isolation',  label: '隔离管理' },
]

export default function EndpointSecurity() {
  const [tab, setTab] = useState('overview')

  return (
    <div style={{ display: 'flex', flexDirection: 'column', height: '100%', overflow: 'hidden', background: 'var(--bg-primary)' }}>

      <PageHeader
        title="终端安全"
        subtitle="Endpoint Security"
        actions={
          <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
            <span style={{
              display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 10.5,
              padding: '3px 10px', borderRadius: 10,
              background: 'rgba(47,176,122,.15)', color: '#2fb07a',
              border: '1px solid rgba(47,176,122,.3)',
            }}>
              <span style={{ width: 5, height: 5, borderRadius: '50%', background: '#2fb07a' }} />
              1,156 在线
            </span>
            <span style={{
              display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 10.5,
              padding: '3px 10px', borderRadius: 10,
              background: 'rgba(229,57,53,.15)', color: '#ef5350',
              border: '1px solid rgba(229,57,53,.3)',
            }}>
              <span style={{ width: 5, height: 5, borderRadius: '50%', background: '#ef5350' }} />
              23 异常
            </span>
            <button className="btn-primary" style={{ fontSize: 11 }}>
              + 部署 Agent
            </button>
          </div>
        }
      />

      {/* Tab bar */}
      <div className="tab-bar">
        {TABS.map(t => (
          <button
            key={t.id}
            className={`tab${tab === t.id ? ' active' : ''}`}
            onClick={() => setTab(t.id)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
        {tab === 'overview'  && <EndpointOverview />}
        {tab === 'behavior'  && <BehaviorMonitoring />}
        {tab === 'detection' && <EndpointDetection />}
        {tab === 'isolation' && <IsolationManagement />}
      </div>
    </div>
  )
}
