import { useState, useEffect } from 'react'
import {
  AreaChart, Area, XAxis, YAxis, Tooltip, Legend, ResponsiveContainer,
} from 'recharts'
import PageHeader from '@/components/PageHeader'
import api from '@/lib/api'

// ─── Types ────────────────────────────────────────────────────────────────────

type Tab = 'traffic' | 'dns' | 'assets' | 'threats'

interface SuspiciousConn {
  id: string
  srcIp: string
  dstIp: string
  port: number
  protocol: string
  bytes: string
  threatType: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  status: 'blocked' | 'alerting' | 'monitoring'
}

interface DnsRecord {
  id: string
  domain: string
  queryCount: number
  resolvedIp: string
  riskLevel: 'critical' | 'high' | 'medium' | 'low' | 'clean'
  category: string
}

interface NetworkDevice {
  id: string
  ip: string
  mac: string
  hostname: string
  deviceType: 'server' | 'workstation' | 'router' | 'switch' | 'camera' | 'mobile' | 'unknown'
  firstSeen: string
  lastActive: string
  risk: 'critical' | 'high' | 'medium' | 'low' | 'none'
  isNew: boolean
  isUnknown: boolean
}

interface ThreatAlert {
  id: string
  time: string
  threatType: string
  srcIp: string
  target: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  status: 'active' | 'investigating' | 'resolved'
}

interface DetectionRule {
  id: string
  name: string
  active: boolean
  hitsToday: number
}

// ─── Mock Data ────────────────────────────────────────────────────────────────

function generateTrafficData() {
  const data = []
  for (let h = 0; h < 24; h++) {
    const peak = h >= 9 && h <= 18
    const base = peak ? 45 : 12
    data.push({
      hour: `${String(h).padStart(2, '0')}:00`,
      入站: Math.round(base + Math.random() * (peak ? 80 : 20)),
      出站: Math.round(base * 0.7 + Math.random() * (peak ? 55 : 12)),
    })
  }
  return data
}

const MOCK_TRAFFIC_DATA = generateTrafficData()

const MOCK_SUSPICIOUS_CONNS: SuspiciousConn[] = [
  { id: '1', srcIp: '192.168.1.45', dstIp: '185.220.101.47', port: 443, protocol: 'TCP', bytes: '2.4 MB', threatType: 'C2通信', severity: 'critical', status: 'alerting' },
  { id: '2', srcIp: '10.0.1.23', dstIp: '198.51.100.22', port: 80, protocol: 'HTTP', bytes: '145 KB', threatType: '数据外传', severity: 'high', status: 'monitoring' },
  { id: '3', srcIp: '172.16.5.102', dstIp: '93.184.216.34', port: 6667, protocol: 'TCP', bytes: '890 KB', threatType: 'IRC隧道', severity: 'high', status: 'blocked' },
  { id: '4', srcIp: '10.0.2.87', dstIp: '104.21.77.88', port: 4444, protocol: 'TCP', bytes: '320 KB', threatType: '反弹Shell', severity: 'critical', status: 'blocked' },
  { id: '5', srcIp: '192.168.10.34', dstIp: '185.199.108.153', port: 443, protocol: 'HTTPS', bytes: '78 KB', threatType: '可疑外联', severity: 'medium', status: 'monitoring' },
  { id: '6', srcIp: '10.1.0.9', dstIp: '45.142.212.100', port: 8080, protocol: 'HTTP', bytes: '2.1 MB', threatType: '扫描探测', severity: 'medium', status: 'alerting' },
  { id: '7', srcIp: '172.16.0.56', dstIp: '8.8.8.8', port: 53, protocol: 'UDP', bytes: '12 KB', threatType: 'DNS隧道', severity: 'high', status: 'monitoring' },
  { id: '8', srcIp: '192.168.3.78', dstIp: '91.108.4.164', port: 443, protocol: 'TLS', bytes: '456 KB', threatType: '加密隧道', severity: 'medium', status: 'monitoring' },
]

const MOCK_DNS_RECORDS: DnsRecord[] = [
  { id: '1', domain: 'evil-domain.ru', queryCount: 847, resolvedIp: '185.220.101.47', riskLevel: 'critical', category: 'C2服务器' },
  { id: '2', domain: 'update-service.top', queryCount: 312, resolvedIp: '104.21.67.90', riskLevel: 'high', category: '恶意下载' },
  { id: '3', domain: 'telemetry.microsoft.com', queryCount: 23841, resolvedIp: '20.54.37.64', riskLevel: 'clean', category: '系统更新' },
  { id: '4', domain: 'cdn-data-exfil.xyz', queryCount: 134, resolvedIp: '198.51.100.5', riskLevel: 'critical', category: '数据外传' },
  { id: '5', domain: 'api.github.com', queryCount: 8920, resolvedIp: '140.82.112.6', riskLevel: 'clean', category: '开发工具' },
  { id: '6', domain: 'payload-host.io', queryCount: 67, resolvedIp: '45.142.212.55', riskLevel: 'high', category: '恶意载荷' },
  { id: '7', domain: 'analytics.google.com', queryCount: 15230, resolvedIp: '142.250.80.46', riskLevel: 'clean', category: '分析服务' },
  { id: '8', domain: 'c2-panel.onion.ws', queryCount: 23, resolvedIp: '91.108.56.174', riskLevel: 'critical', category: 'C2面板' },
  { id: '9', domain: 'aws.amazon.com', queryCount: 11403, resolvedIp: '52.94.76.1', riskLevel: 'clean', category: '云服务' },
  { id: '10', domain: 'secure-update.net', queryCount: 189, resolvedIp: '185.61.148.22', riskLevel: 'medium', category: '可疑域名' },
]

const DEVICE_TYPE_ICON: Record<NetworkDevice['deviceType'], string> = {
  server: '🖥️', workstation: '💻', router: '📡', switch: '🔀',
  camera: '📷', mobile: '📱', unknown: '❓',
}

const DEVICE_TYPE_LABEL: Record<NetworkDevice['deviceType'], string> = {
  server: '服务器', workstation: '工作站', router: '路由器', switch: '交换机',
  camera: '摄像头', mobile: '移动设备', unknown: '未知设备',
}

const MOCK_NETWORK_DEVICES: NetworkDevice[] = [
  { id: '1', ip: '10.0.0.1', mac: 'AA:BB:CC:00:01:01', hostname: 'core-router-01', deviceType: 'router', firstSeen: '2024-01-15T08:00:00Z', lastActive: '2026-05-24T10:30:00Z', risk: 'low', isNew: false, isUnknown: false },
  { id: '2', ip: '10.0.0.100', mac: 'DE:AD:BE:EF:00:01', hostname: 'prod-server-web', deviceType: 'server', firstSeen: '2024-02-10T09:15:00Z', lastActive: '2026-05-24T10:28:00Z', risk: 'none', isNew: false, isUnknown: false },
  { id: '3', ip: '192.168.1.45', mac: 'FA:CE:B0:0C:00:01', hostname: 'analyst-ws-04', deviceType: 'workstation', firstSeen: '2025-03-22T14:00:00Z', lastActive: '2026-05-24T09:45:00Z', risk: 'high', isNew: false, isUnknown: false },
  { id: '4', ip: '192.168.5.201', mac: '00:00:00:00:AB:CD', hostname: '', deviceType: 'unknown', firstSeen: '2026-05-24T07:12:00Z', lastActive: '2026-05-24T10:15:00Z', risk: 'critical', isNew: true, isUnknown: true },
  { id: '5', ip: '10.0.1.88', mac: 'C0:FF:EE:00:01:02', hostname: 'db-server-01', deviceType: 'server', firstSeen: '2024-04-01T10:00:00Z', lastActive: '2026-05-24T10:29:00Z', risk: 'medium', isNew: false, isUnknown: false },
  { id: '6', ip: '172.16.0.12', mac: 'AA:CC:EE:11:22:33', hostname: 'access-sw-02', deviceType: 'switch', firstSeen: '2024-01-20T08:30:00Z', lastActive: '2026-05-24T10:31:00Z', risk: 'none', isNew: false, isUnknown: false },
  { id: '7', ip: '192.168.2.88', mac: 'BB:DD:FF:00:AA:BB', hostname: '', deviceType: 'unknown', firstSeen: '2026-05-23T22:44:00Z', lastActive: '2026-05-24T06:10:00Z', risk: 'high', isNew: true, isUnknown: true },
  { id: '8', ip: '10.0.3.50', mac: '11:22:33:44:55:66', hostname: 'cam-lobby-01', deviceType: 'camera', firstSeen: '2025-01-10T12:00:00Z', lastActive: '2026-05-24T10:00:00Z', risk: 'low', isNew: false, isUnknown: false },
  { id: '9', ip: '192.168.10.34', mac: '77:88:99:AA:BB:CC', hostname: 'iphone-user5', deviceType: 'mobile', firstSeen: '2026-05-24T08:55:00Z', lastActive: '2026-05-24T10:22:00Z', risk: 'none', isNew: true, isUnknown: false },
  { id: '10', ip: '10.0.2.200', mac: 'FE:DC:BA:98:76:54', hostname: 'backup-server', deviceType: 'server', firstSeen: '2024-06-01T11:00:00Z', lastActive: '2026-05-22T14:00:00Z', risk: 'low', isNew: false, isUnknown: false },
]

const MOCK_THREAT_ALERTS: ThreatAlert[] = [
  { id: '1', time: '10:28:43', threatType: '端口扫描', srcIp: '192.168.5.201', target: '10.0.0.0/24', severity: 'high', status: 'active' },
  { id: '2', time: '09:55:17', threatType: 'DNS隧道', srcIp: '172.16.0.56', target: 'evil-domain.ru', severity: 'critical', status: 'investigating' },
  { id: '3', time: '09:33:02', threatType: 'ARP欺骗', srcIp: '192.168.1.45', target: '192.168.1.0/24', severity: 'high', status: 'active' },
  { id: '4', time: '08:47:59', threatType: '异常出站流量', srcIp: '10.0.1.23', target: '198.51.100.22', severity: 'medium', status: 'active' },
  { id: '5', time: '07:12:31', threatType: '暴力破解', srcIp: '45.142.212.100', target: 'ssh:22', severity: 'medium', status: 'resolved' },
  { id: '6', time: '06:04:18', threatType: '横向移动', srcIp: '10.0.1.88', target: '10.0.0.100', severity: 'critical', status: 'investigating' },
]

const MOCK_DETECTION_RULES: DetectionRule[] = [
  { id: '1', name: '端口扫描检测', active: true, hitsToday: 3 },
  { id: '2', name: 'DNS隧道检测', active: true, hitsToday: 1 },
  { id: '3', name: '异常出站流量', active: true, hitsToday: 8 },
  { id: '4', name: 'ARP欺骗检测', active: true, hitsToday: 0 },
  { id: '5', name: '大量连接异常', active: false, hitsToday: 0 },
]

// ─── Helper Components ────────────────────────────────────────────────────────

const SEV_CONFIG: Record<string, { color: string; bg: string; label: string }> = {
  critical: { color: '#e05555', bg: 'rgba(217,64,64,.18)',  label: '高危' },
  high:     { color: '#dd7a30', bg: 'rgba(208,112,48,.16)', label: '中高' },
  medium:   { color: '#d4aa28', bg: 'rgba(192,144,32,.14)', label: '中危' },
  low:      { color: '#3ab07a', bg: 'rgba(42,144,96,.15)',  label: '低危' },
  none:     { color: 'var(--text-muted)', bg: 'rgba(80,100,130,.10)', label: '安全' },
  clean:    { color: '#3ab07a', bg: 'rgba(42,144,96,.15)',  label: '正常' },
}

function SevBadge({ level, label }: { level: string; label?: string }) {
  const cfg = SEV_CONFIG[level] ?? SEV_CONFIG.medium
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center',
      padding: '2px 8px', borderRadius: 3,
      fontSize: 10.5, fontWeight: 700, letterSpacing: 0.3,
      background: cfg.bg, color: cfg.color,
    }}>
      {label ?? cfg.label}
    </span>
  )
}

function StatusBadge({ status }: { status: string }) {
  const MAP: Record<string, { color: string; bg: string; label: string }> = {
    blocked:      { color: '#e05555', bg: 'rgba(217,64,64,.14)',  label: '已封锁' },
    alerting:     { color: '#dd7a30', bg: 'rgba(208,112,48,.13)', label: '告警中' },
    monitoring:   { color: '#d4aa28', bg: 'rgba(192,144,32,.12)', label: '监控中' },
    active:       { color: '#e05555', bg: 'rgba(217,64,64,.14)',  label: '活跃' },
    investigating:{ color: '#3b9ede', bg: 'rgba(59,158,222,.14)', label: '调查中' },
    resolved:     { color: '#3ab07a', bg: 'rgba(42,144,96,.14)',  label: '已解决' },
  }
  const cfg = MAP[status] ?? MAP.monitoring
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 4,
      padding: '2px 8px', borderRadius: 3,
      fontSize: 10.5, fontWeight: 600,
      background: cfg.bg, color: cfg.color,
    }}>
      <span style={{
        width: 5, height: 5, borderRadius: '50%',
        background: cfg.color,
        boxShadow: status === 'active' || status === 'alerting' ? `0 0 5px ${cfg.color}` : 'none',
      }} />
      {cfg.label}
    </span>
  )
}

function KpiCard({
  label, value, valueColor, note,
}: {
  label: string
  value: string | number
  valueColor?: string
  note?: string
}) {
  return (
    <div style={{
      background: 'var(--bg-card)', border: '1px solid var(--border)',
      borderRadius: 6, padding: '12px 16px', flex: 1, minWidth: 120,
    }}>
      <div style={{
        fontSize: 10.5, color: 'var(--text-muted)',
        textTransform: 'uppercase', letterSpacing: 0.4, marginBottom: 6,
      }}>
        {label}
      </div>
      <div style={{
        fontSize: 22, fontWeight: 700, lineHeight: 1,
        color: valueColor ?? 'var(--text-primary)',
      }}>
        {typeof value === 'number' ? value.toLocaleString() : value}
      </div>
      {note && (
        <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginTop: 4 }}>
          {note}
        </div>
      )}
    </div>
  )
}

function fmtDate(iso: string) {
  if (!iso) return '-'
  const d = new Date(iso)
  return `${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')} ` +
         `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`
}

// ─── Custom Tooltip for Recharts ──────────────────────────────────────────────

function TrafficTooltip({ active, payload, label }: {
  active?: boolean
  payload?: Array<{ color: string; name: string; value: number }>
  label?: string
}) {
  if (!active || !payload?.length) return null
  return (
    <div style={{
      background: 'var(--bg-card2)', border: '1px solid var(--border-light)',
      borderRadius: 6, padding: '8px 12px', fontSize: 12,
    }}>
      <div style={{ color: 'var(--text-secondary)', marginBottom: 4 }}>{label}</div>
      {payload.map((p, i) => (
        <div key={i} style={{ color: p.color, display: 'flex', gap: 8, justifyContent: 'space-between' }}>
          <span>{p.name}</span>
          <span style={{ fontWeight: 600 }}>{p.value} GB</span>
        </div>
      ))}
    </div>
  )
}

// ─── Tab 1: 流量分析 ──────────────────────────────────────────────────────────

function TrafficTab() {
  const [blockedConns, setBlockedConns] = useState<Set<string>>(new Set(['3', '4']))

  function blockConn(id: string) {
    api.post('/network/connections/block', { id }).catch(() => {})
    setBlockedConns(prev => new Set([...prev, id]))
  }

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: 16 }}>

      {/* KPI row */}
      <div style={{ display: 'flex', gap: 12 }}>
        <KpiCard label="今日流量" value="1.24 TB" note="全天累计" />
        <KpiCard label="活跃连接" value={8342} note="当前实时" />
        <KpiCard label="异常连接" value={23} valueColor="var(--critical)" note="需要关注" />
        <KpiCard label="封锁连接" value={7} valueColor="#dd7a30" note="今日拦截" />
      </div>

      {/* Traffic Volume Chart */}
      <div style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)',
        borderRadius: 6, padding: '16px 16px 8px',
      }}>
        <div style={{
          fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)',
          textTransform: 'uppercase', letterSpacing: 0.4, marginBottom: 14,
        }}>
          24小时流量概览 (GB)
        </div>
        <ResponsiveContainer width="100%" height={200}>
          <AreaChart data={MOCK_TRAFFIC_DATA} margin={{ top: 4, right: 12, left: 0, bottom: 0 }}>
            <defs>
              <linearGradient id="gradIn" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#3b9ede" stopOpacity={0.25} />
                <stop offset="95%" stopColor="#3b9ede" stopOpacity={0.02} />
              </linearGradient>
              <linearGradient id="gradOut" x1="0" y1="0" x2="0" y2="1">
                <stop offset="5%" stopColor="#2fb07a" stopOpacity={0.25} />
                <stop offset="95%" stopColor="#2fb07a" stopOpacity={0.02} />
              </linearGradient>
            </defs>
            <XAxis
              dataKey="hour"
              tick={{ fill: 'var(--text-muted)', fontSize: 10 }}
              axisLine={{ stroke: 'var(--border)' }}
              tickLine={false}
              interval={3}
            />
            <YAxis
              tick={{ fill: 'var(--text-muted)', fontSize: 10 }}
              axisLine={false}
              tickLine={false}
              width={32}
            />
            <Tooltip content={<TrafficTooltip />} />
            <Legend
              wrapperStyle={{ fontSize: 11, color: 'var(--text-secondary)', paddingTop: 8 }}
            />
            <Area
              type="monotone" dataKey="入站" stroke="#3b9ede"
              strokeWidth={1.5} fill="url(#gradIn)"
            />
            <Area
              type="monotone" dataKey="出站" stroke="#2fb07a"
              strokeWidth={1.5} fill="url(#gradOut)"
            />
          </AreaChart>
        </ResponsiveContainer>
      </div>

      {/* Suspicious Connections Table */}
      <div style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)',
        borderRadius: 6, overflow: 'hidden',
      }}>
        <div style={{
          padding: '12px 16px', borderBottom: '1px solid var(--border)',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        }}>
          <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: 0.4 }}>
            可疑连接列表
          </span>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            共 {MOCK_SUSPICIOUS_CONNS.length} 条
          </span>
        </div>
        <table className="data-table" style={{ margin: 0 }}>
          <thead>
            <tr>
              <th>源IP</th>
              <th>目标IP</th>
              <th>端口</th>
              <th>协议</th>
              <th>字节数</th>
              <th>威胁类型</th>
              <th>状态</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            {MOCK_SUSPICIOUS_CONNS.map(conn => {
              const isBlocked = blockedConns.has(conn.id) || conn.status === 'blocked'
              return (
                <tr key={conn.id} className={conn.severity === 'critical' ? 'row-critical' : ''}>
                  <td style={{ fontFamily: 'monospace', fontSize: 12 }}>{conn.srcIp}</td>
                  <td style={{ fontFamily: 'monospace', fontSize: 12 }}>{conn.dstIp}</td>
                  <td style={{ fontFamily: 'monospace', fontSize: 12, color: 'var(--text-secondary)' }}>{conn.port}</td>
                  <td>
                    <span style={{
                      fontSize: 10, padding: '2px 6px', borderRadius: 3,
                      background: 'rgba(59,158,222,.12)', color: '#3b9ede',
                      fontWeight: 600, textTransform: 'uppercase',
                    }}>
                      {conn.protocol}
                    </span>
                  </td>
                  <td style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{conn.bytes}</td>
                  <td style={{ fontSize: 12 }}>
                    <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                      <SevBadge level={conn.severity} />
                      <span style={{ color: 'var(--text-primary)' }}>{conn.threatType}</span>
                    </span>
                  </td>
                  <td><StatusBadge status={isBlocked ? 'blocked' : conn.status} /></td>
                  <td onClick={e => e.stopPropagation()}>
                    <div style={{ display: 'flex', gap: 5 }}>
                      <button
                        className="btn-secondary"
                        style={{
                          fontSize: 11, padding: '2px 8px',
                          color: isBlocked ? 'var(--text-muted)' : 'var(--critical)',
                          cursor: isBlocked ? 'not-allowed' : 'pointer',
                        }}
                        disabled={isBlocked}
                        onClick={() => blockConn(conn.id)}
                      >
                        {isBlocked ? '已封锁' : '封锁'}
                      </button>
                      <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px' }}>
                        详情
                      </button>
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

// ─── Tab 2: DNS分析 ───────────────────────────────────────────────────────────

interface DomainDetail {
  domain: string
  registrar: string
  created: string
  expiry: string
  resolutionHistory: string[]
  riskLevel: string
  verdict: string
  whois: string
  category: string
}

const MOCK_DOMAIN_DETAILS: Record<string, DomainDetail> = {
  'evil-domain.ru':      { domain: 'evil-domain.ru', registrar: 'REG.RU LLC', created: '2026-03-14', expiry: '2027-03-14', resolutionHistory: ['185.220.101.47', '185.220.101.48'], riskLevel: 'critical', verdict: '恶意', whois: 'Registrant: Privacy Protected\nOrg: WHOIS Privacy\nCountry: RU\nName Server: ns1.evil-ns.ru', category: 'C2服务器' },
  'update-service.top':  { domain: 'update-service.top', registrar: 'Namecheap Inc.', created: '2026-04-02', expiry: '2027-04-02', resolutionHistory: ['104.21.67.90', '172.67.200.14'], riskLevel: 'high', verdict: '可疑', whois: 'Registrant: Privacy Protected\nOrg: WhoisGuard\nCountry: PA\nName Server: ns1.cloudflare.com', category: '恶意下载' },
  'cdn-data-exfil.xyz':  { domain: 'cdn-data-exfil.xyz', registrar: 'GoDaddy LLC', created: '2026-05-01', expiry: '2027-05-01', resolutionHistory: ['198.51.100.5'], riskLevel: 'critical', verdict: '恶意', whois: 'Registrant: John Doe\nOrg: N/A\nCountry: US\nName Server: ns1.godaddy.com', category: '数据外传' },
  'c2-panel.onion.ws':   { domain: 'c2-panel.onion.ws', registrar: 'PDR Ltd.', created: '2026-04-20', expiry: '2027-04-20', resolutionHistory: ['91.108.56.174', '91.108.4.164'], riskLevel: 'critical', verdict: '恶意', whois: 'Registrant: Privacy Protected\nOrg: Domains By Proxy\nCountry: US\nName Server: ns1.pdr.hosting', category: 'C2面板' },
  'payload-host.io':     { domain: 'payload-host.io', registrar: 'Gandi SAS', created: '2026-02-28', expiry: '2027-02-28', resolutionHistory: ['45.142.212.55', '45.142.212.56'], riskLevel: 'high', verdict: '可疑', whois: 'Registrant: Privacy Protected\nOrg: GANDI Privacy\nCountry: FR\nName Server: ns1.gandi.net', category: '恶意载荷' },
}

function DnsTab() {
  const [selectedDomain, setSelectedDomain] = useState<DomainDetail | null>(null)
  const [blocklisted, setBlocklisted] = useState<Set<string>>(new Set())

  function handleRowClick(rec: DnsRecord) {
    const detail = MOCK_DOMAIN_DETAILS[rec.domain]
    if (detail) setSelectedDomain(detail)
    else setSelectedDomain(null)
  }

  function addToBlocklist(domain: string) {
    api.post('/network/dns/blocklist', { domain }).catch(() => {})
    setBlocklisted(prev => new Set([...prev, domain]))
  }

  const DNS_RISK_CONFIG: Record<string, { color: string; bg: string; label: string }> = {
    critical: { color: '#e05555', bg: 'rgba(217,64,64,.15)',  label: '高危' },
    high:     { color: '#dd7a30', bg: 'rgba(208,112,48,.14)', label: '中高' },
    medium:   { color: '#d4aa28', bg: 'rgba(192,144,32,.12)', label: '中危' },
    low:      { color: '#3ab07a', bg: 'rgba(42,144,96,.13)',  label: '低危' },
    clean:    { color: '#3ab07a', bg: 'rgba(42,144,96,.10)',  label: '正常' },
  }

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

      {/* KPI row */}
      <div style={{ display: 'flex', gap: 12, padding: '16px 20px 0', flexShrink: 0 }}>
        <KpiCard label="今日DNS查询" value={234567} note="全天累计" />
        <KpiCard label="异常域名请求" value={12} valueColor="var(--critical)" note="需要关注" />
        <KpiCard label="已封锁域名" value={5 + blocklisted.size} note="当前封锁" />
      </div>

      {/* Main content: table + detail panel */}
      <div style={{ flex: 1, display: 'flex', gap: 0, overflow: 'hidden', padding: '16px 20px' }}>

        {/* DNS table */}
        <div style={{
          flex: 1, display: 'flex', flexDirection: 'column',
          background: 'var(--bg-card)', border: '1px solid var(--border)',
          borderRadius: selectedDomain ? '6px 0 0 6px' : 6, overflow: 'hidden',
        }}>
          <div style={{
            padding: '12px 16px', borderBottom: '1px solid var(--border)',
            fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)',
            textTransform: 'uppercase', letterSpacing: 0.4, flexShrink: 0,
          }}>
            Top DNS查询域名
          </div>
          <div style={{ overflowY: 'auto', flex: 1 }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>域名</th>
                  <th>查询次数</th>
                  <th>解析IP</th>
                  <th>风险等级</th>
                  <th>分类</th>
                </tr>
              </thead>
              <tbody>
                {MOCK_DNS_RECORDS.map(rec => {
                  const cfg = DNS_RISK_CONFIG[rec.riskLevel] ?? DNS_RISK_CONFIG.clean
                  const isSuspicious = rec.riskLevel !== 'clean'
                  return (
                    <tr
                      key={rec.id}
                      className={rec.riskLevel === 'critical' ? 'row-critical' : ''}
                      onClick={() => handleRowClick(rec)}
                      style={{ cursor: isSuspicious ? 'pointer' : 'default' }}
                    >
                      <td style={{ fontFamily: 'monospace', fontSize: 12 }}>
                        {isSuspicious && (
                          <span style={{ marginRight: 6, fontSize: 10 }}>⚠</span>
                        )}
                        <span style={{ color: isSuspicious ? cfg.color : 'var(--text-primary)' }}>
                          {rec.domain}
                        </span>
                      </td>
                      <td style={{ fontSize: 12, fontFamily: 'monospace', color: 'var(--text-secondary)' }}>
                        {rec.queryCount.toLocaleString()}
                      </td>
                      <td style={{ fontFamily: 'monospace', fontSize: 11.5, color: 'var(--text-secondary)' }}>
                        {rec.resolvedIp}
                      </td>
                      <td>
                        <span style={{ padding: '2px 8px', borderRadius: 3, fontSize: 10.5, fontWeight: 700, background: cfg.bg, color: cfg.color }}>
                          {cfg.label}
                        </span>
                      </td>
                      <td style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>{rec.category}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>

        {/* Domain detail panel */}
        {selectedDomain && (
          <div style={{
            width: 320, flexShrink: 0,
            background: 'var(--bg-card2)', border: '1px solid var(--border)',
            borderLeft: 'none', borderRadius: '0 6px 6px 0',
            display: 'flex', flexDirection: 'column', overflow: 'hidden',
          }}>
            {/* Panel header */}
            <div style={{
              padding: '12px 14px', borderBottom: '1px solid var(--border)',
              display: 'flex', alignItems: 'center', justifyContent: 'space-between', flexShrink: 0,
            }}>
              <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: 0.4 }}>
                域名详情
              </span>
              <button
                style={{ background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', fontSize: 16, lineHeight: 1 }}
                onClick={() => setSelectedDomain(null)}
              >
                ×
              </button>
            </div>

            <div style={{ flex: 1, overflowY: 'auto', padding: 14, display: 'flex', flexDirection: 'column', gap: 14 }}>
              {/* Domain name */}
              <div>
                <div style={{ fontFamily: 'monospace', fontSize: 13, fontWeight: 700, color: 'var(--text-primary)', wordBreak: 'break-all' }}>
                  {selectedDomain.domain}
                </div>
                <div style={{ marginTop: 6, display: 'flex', gap: 6, alignItems: 'center' }}>
                  {(() => {
                    const cfg = DNS_RISK_CONFIG[selectedDomain.riskLevel] ?? DNS_RISK_CONFIG.clean
                    return (
                      <span style={{ padding: '2px 10px', borderRadius: 3, fontSize: 11, fontWeight: 700, background: cfg.bg, color: cfg.color }}>
                        {selectedDomain.verdict}
                      </span>
                    )
                  })()}
                  <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>{selectedDomain.category}</span>
                </div>
              </div>

              {/* Registration info */}
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                {[
                  ['注册商', selectedDomain.registrar],
                  ['注册日期', selectedDomain.created],
                  ['到期日期', selectedDomain.expiry],
                ].map(([k, v]) => (
                  <div key={k} style={{ display: 'flex', justifyContent: 'space-between', fontSize: 12 }}>
                    <span style={{ color: 'var(--text-muted)' }}>{k}</span>
                    <span style={{ color: 'var(--text-secondary)', fontFamily: 'monospace', fontSize: 11 }}>{v}</span>
                  </div>
                ))}
              </div>

              {/* IP resolution history */}
              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.4, marginBottom: 6 }}>
                  解析IP历史
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
                  {selectedDomain.resolutionHistory.map(ip => (
                    <div key={ip} style={{
                      fontFamily: 'monospace', fontSize: 12,
                      padding: '4px 8px', background: 'var(--bg-card)',
                      border: '1px solid var(--border)', borderRadius: 4,
                      color: 'var(--text-secondary)',
                    }}>
                      {ip}
                    </div>
                  ))}
                </div>
              </div>

              {/* WHOIS summary */}
              <div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 0.4, marginBottom: 6 }}>
                  WHOIS 摘要
                </div>
                <pre style={{
                  fontFamily: 'monospace', fontSize: 10.5,
                  color: 'var(--text-secondary)', background: 'var(--bg-card)',
                  border: '1px solid var(--border)', borderRadius: 4,
                  padding: '8px 10px', whiteSpace: 'pre-wrap', margin: 0, lineHeight: 1.6,
                }}>
                  {selectedDomain.whois}
                </pre>
              </div>

              {/* Block button */}
              <button
                className={blocklisted.has(selectedDomain.domain) ? 'btn-secondary' : 'btn-primary'}
                disabled={blocklisted.has(selectedDomain.domain)}
                style={{ width: '100%', marginTop: 'auto' }}
                onClick={() => addToBlocklist(selectedDomain.domain)}
              >
                {blocklisted.has(selectedDomain.domain) ? '✓ 已加入封锁列表' : '加入封锁列表'}
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Tab 3: 网络资产感知 ──────────────────────────────────────────────────────

function AssetsTab() {
  const [typeFilter, setTypeFilter] = useState<NetworkDevice['deviceType'] | ''>('')
  const [riskFilter, setRiskFilter] = useState('')
  const [search, setSearch] = useState('')

  const filtered = MOCK_NETWORK_DEVICES.filter(d => {
    if (typeFilter && d.deviceType !== typeFilter) return false
    if (riskFilter && d.risk !== riskFilter) return false
    if (search) {
      const q = search.toLowerCase()
      return d.ip.includes(q) || d.hostname.toLowerCase().includes(q) || d.mac.toLowerCase().includes(q)
    }
    return true
  })

  const unknownCount = MOCK_NETWORK_DEVICES.filter(d => d.isUnknown).length
  const newCount = MOCK_NETWORK_DEVICES.filter(d => d.isNew).length
  const offlineCount = 1 // mock: backup-server last active >24h

  return (
    <div style={{ flex: 1, display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>

      {/* KPI row */}
      <div style={{ display: 'flex', gap: 12, padding: '16px 20px 0', flexShrink: 0 }}>
        <KpiCard label="已发现设备" value={1247} note="网络全量" />
        <KpiCard label="未知设备" value={unknownCount + 32} valueColor="#dd7a30" note="需人工确认" />
        <KpiCard label="新增设备(今天)" value={newCount} note="今日新增" />
        <KpiCard label="离线设备" value={offlineCount + 11} note="超过24小时未上线" />
      </div>

      {/* Filter bar */}
      <div className="filter-bar" style={{ marginTop: 16 }}>
        <input
          className="filter-input"
          placeholder="搜索 IP / 主机名 / MAC..."
          value={search}
          onChange={e => setSearch(e.target.value)}
        />
        <select
          className="filter-select"
          value={typeFilter}
          onChange={e => setTypeFilter(e.target.value as NetworkDevice['deviceType'] | '')}
        >
          <option value="">全部类型</option>
          <option value="server">🖥️ 服务器</option>
          <option value="workstation">💻 工作站</option>
          <option value="router">📡 路由器</option>
          <option value="switch">🔀 交换机</option>
          <option value="camera">📷 摄像头</option>
          <option value="mobile">📱 移动设备</option>
          <option value="unknown">❓ 未知设备</option>
        </select>
        <select
          className="filter-select"
          value={riskFilter}
          onChange={e => setRiskFilter(e.target.value)}
        >
          <option value="">全部风险</option>
          <option value="critical">高危</option>
          <option value="high">中高</option>
          <option value="medium">中危</option>
          <option value="low">低危</option>
          <option value="none">安全</option>
        </select>
        <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text-muted)' }}>
          显示 {filtered.length} / {MOCK_NETWORK_DEVICES.length} 台设备
        </span>
      </div>

      {/* Table */}
      <div className="data-table-wrap">
        <table className="data-table">
          <thead>
            <tr>
              <th>IP地址</th>
              <th>MAC地址</th>
              <th>主机名</th>
              <th>设备类型</th>
              <th>首次发现</th>
              <th>最后活跃</th>
              <th>风险</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            {filtered.map(dev => (
              <tr key={dev.id} className={dev.risk === 'critical' ? 'row-critical' : ''}>
                <td style={{ fontFamily: 'monospace', fontSize: 12 }}>
                  {dev.ip}
                  {dev.isNew && (
                    <span style={{
                      marginLeft: 6, fontSize: 9, padding: '1px 5px',
                      background: 'rgba(59,158,222,.18)', color: '#3b9ede',
                      borderRadius: 2, fontWeight: 700, textTransform: 'uppercase',
                    }}>
                      新
                    </span>
                  )}
                </td>
                <td style={{ fontFamily: 'monospace', fontSize: 11, color: 'var(--text-secondary)' }}>
                  {dev.mac}
                </td>
                <td style={{ fontSize: 12, color: dev.hostname ? 'var(--text-primary)' : 'var(--text-muted)', fontStyle: dev.hostname ? 'normal' : 'italic' }}>
                  {dev.hostname || '未知主机名'}
                </td>
                <td style={{ fontSize: 12 }}>
                  {DEVICE_TYPE_ICON[dev.deviceType]} {DEVICE_TYPE_LABEL[dev.deviceType]}
                  {dev.isUnknown && (
                    <span style={{
                      marginLeft: 6, fontSize: 9, padding: '1px 5px',
                      background: 'rgba(208,112,48,.18)', color: '#dd7a30',
                      borderRadius: 2, fontWeight: 700, textTransform: 'uppercase',
                    }}>
                      未知
                    </span>
                  )}
                </td>
                <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{fmtDate(dev.firstSeen)}</td>
                <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{fmtDate(dev.lastActive)}</td>
                <td><SevBadge level={dev.risk} /></td>
                <td onClick={e => e.stopPropagation()}>
                  <div style={{ display: 'flex', gap: 5 }}>
                    <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px' }}>
                      详情
                    </button>
                    {dev.isUnknown && (
                      <button
                        className="btn-secondary"
                        style={{ fontSize: 11, padding: '2px 8px', color: '#dd7a30' }}
                      >
                        标记
                      </button>
                    )}
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ─── Tab 4: 威胁检测 ──────────────────────────────────────────────────────────

function ThreatsTab() {
  const [rules, setRules] = useState<DetectionRule[]>(MOCK_DETECTION_RULES)

  function toggleRule(id: string) {
    setRules(prev => prev.map(r => r.id === id ? { ...r, active: !r.active } : r))
    const rule = rules.find(r => r.id === id)
    if (rule) {
      api.patch(`/network/detection_rules/${id}`, { active: !rule.active }).catch(() => {})
    }
  }

  const THREAT_TYPE_CONFIG: Record<string, { icon: string; color: string }> = {
    '端口扫描': { icon: '🔍', color: '#dd7a30' },
    'DDoS攻击': { icon: '💥', color: '#e05555' },
    'ARP欺骗': { icon: '🔀', color: '#dd7a30' },
    'DNS隧道': { icon: '🕳️', color: '#e05555' },
    '横向移动': { icon: '↔', color: '#e05555' },
    '暴力破解': { icon: '🔓', color: '#d4aa28' },
    '异常出站流量': { icon: '📤', color: '#d4aa28' },
  }

  return (
    <div style={{ flex: 1, overflowY: 'auto', padding: '16px 20px', display: 'flex', flexDirection: 'column', gap: 16 }}>

      {/* Active Threat Alerts */}
      <div style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)',
        borderRadius: 6, overflow: 'hidden',
      }}>
        <div style={{
          padding: '12px 16px', borderBottom: '1px solid var(--border)',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        }}>
          <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: 0.4 }}>
            活跃威胁告警
          </span>
          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
            {MOCK_THREAT_ALERTS.filter(a => a.status !== 'resolved').length} 条未解决
          </span>
        </div>
        <table className="data-table" style={{ margin: 0 }}>
          <thead>
            <tr>
              <th>时间</th>
              <th>威胁类型</th>
              <th>源IP</th>
              <th>目标</th>
              <th>严重程度</th>
              <th>状态</th>
            </tr>
          </thead>
          <tbody>
            {MOCK_THREAT_ALERTS.map(alert => {
              const typeCfg = THREAT_TYPE_CONFIG[alert.threatType] ?? { icon: '⚠', color: '#d4aa28' }
              return (
                <tr key={alert.id} className={alert.severity === 'critical' ? 'row-critical' : ''}>
                  <td style={{ fontFamily: 'monospace', fontSize: 12, color: 'var(--text-secondary)', whiteSpace: 'nowrap' }}>
                    {alert.time}
                  </td>
                  <td style={{ fontSize: 12 }}>
                    <span style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                      <span>{typeCfg.icon}</span>
                      <span style={{ color: typeCfg.color, fontWeight: 500 }}>{alert.threatType}</span>
                    </span>
                  </td>
                  <td style={{ fontFamily: 'monospace', fontSize: 12 }}>{alert.srcIp}</td>
                  <td style={{ fontFamily: 'monospace', fontSize: 12, color: 'var(--text-secondary)' }}>{alert.target}</td>
                  <td><SevBadge level={alert.severity} /></td>
                  <td><StatusBadge status={alert.status} /></td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {/* Detection Rules */}
      <div style={{
        background: 'var(--bg-card)', border: '1px solid var(--border)',
        borderRadius: 6, overflow: 'hidden',
      }}>
        <div style={{
          padding: '12px 16px', borderBottom: '1px solid var(--border)',
          display: 'flex', alignItems: 'center', justifyContent: 'space-between',
        }}>
          <span style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-secondary)', textTransform: 'uppercase', letterSpacing: 0.4 }}>
            网络检测规则
          </span>
          <span style={{ fontSize: 11, color: 'var(--accent-green)' }}>
            {rules.filter(r => r.active).length} 条规则激活
          </span>
        </div>
        <div style={{ padding: '8px 0' }}>
          {rules.map((rule, idx) => (
            <div
              key={rule.id}
              style={{
                display: 'flex', alignItems: 'center', padding: '10px 16px',
                borderBottom: idx < rules.length - 1 ? '1px solid var(--border)' : 'none',
                gap: 12,
              }}
            >
              {/* Active indicator */}
              <div style={{
                width: 8, height: 8, borderRadius: '50%', flexShrink: 0,
                background: rule.active ? 'var(--accent-green)' : 'var(--text-muted)',
                boxShadow: rule.active ? '0 0 6px var(--accent-green)' : 'none',
                transition: 'all .2s',
              }} />

              {/* Rule name */}
              <div style={{ flex: 1 }}>
                <span style={{
                  fontSize: 13, fontWeight: 500,
                  color: rule.active ? 'var(--text-primary)' : 'var(--text-muted)',
                }}>
                  {rule.name}
                </span>
              </div>

              {/* Hits today */}
              <div style={{ width: 80, textAlign: 'right' }}>
                {rule.hitsToday > 0 ? (
                  <span style={{
                    fontSize: 11, padding: '2px 8px', borderRadius: 3,
                    background: 'rgba(208,112,48,.14)', color: '#dd7a30', fontWeight: 700,
                  }}>
                    今日 {rule.hitsToday} 次
                  </span>
                ) : (
                  <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                    今日 0 次
                  </span>
                )}
              </div>

              {/* Toggle button */}
              <button
                className="btn-secondary"
                style={{
                  fontSize: 11, padding: '3px 12px', flexShrink: 0,
                  color: rule.active ? 'var(--critical)' : 'var(--accent-green)',
                }}
                onClick={() => toggleRule(rule.id)}
              >
                {rule.active ? '停用' : '启用'}
              </button>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function NetworkSecurity() {
  const [tab, setTab] = useState<Tab>('traffic')

  // Attempt to load real data, fall back to mock gracefully
  useEffect(() => {
    // These API calls are non-blocking — mock data is shown regardless
    api.get('/network/stats').catch(() => {})
  }, [])

  const TAB_CONFIG: Array<{ key: Tab; label: string }> = [
    { key: 'traffic', label: '流量分析' },
    { key: 'dns',     label: 'DNS分析' },
    { key: 'assets',  label: '网络资产感知' },
    { key: 'threats', label: '威胁检测' },
  ]

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <PageHeader
        title="网络安全检测"
        subtitle="· 网络流量 · DNS · 资产感知 · 威胁检测"
      />

      {/* Tab bar */}
      <div className="tab-bar">
        {TAB_CONFIG.map(t => (
          <button
            key={t.key}
            className={`tab ${tab === t.key ? 'active' : ''}`}
            onClick={() => setTab(t.key)}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* Tab content */}
      {tab === 'traffic' && <TrafficTab />}
      {tab === 'dns'     && <DnsTab />}
      {tab === 'assets'  && <AssetsTab />}
      {tab === 'threats' && <ThreatsTab />}
    </div>
  )
}
