import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '@/lib/api'
import type { PageMeta } from '@/lib/api'
import PageHeader from '@/components/PageHeader'

// ─── Additional interfaces for new features ───────────────────────────────────

interface Incident {
  _key: string
  title: string
  status: string
  severity: string
  smart_score?: number
  resolved_at?: string
  created_at: string
  alert_count?: number
  assigned_to?: string
}

interface IdentityRisk {
  _key: string
  user_id: string
  username: string
  domain: string
  risk_score: number
  risk_signals?: Array<{ type: string; score: number; detail: string }>
  updated_at: string
  created_at: string
}

interface IOC {
  _key: string
  type: string
  value: string
  verdict: string
  threat_name: string
  confidence: number
  reliability: string
  severity: string
  source: string
  source_name: string
  tags: string[]
  related_incidents: string[]
  active: boolean
  expiry: string
  last_seen: string
  created_at: string
}

interface Feed {
  _key: string
  name: string
  description: string
  feed_type: string
  url: string
  status: string
  ioc_count: number
  last_synced: string
  sync_interval: number
  created_at: string
}

interface IndicatorRule {
  _key: string
  name: string
  rule_type: string
  status: string
  severity: string
  hit_count: number
  mitre_tactic: string
  mitre_technique: string
  created_at: string
}

// Feed used for /threat_intel/samples — these are IOC hash records
interface SampleFeed {
  _key: string
  value: string
  threat_name: string
  verdict: string
  confidence: number
  severity: string
  source_name: string
  tags: string[]
  created_at: string
}

interface Report {
  _key: string
  name: string
  description: string
  template_type: string
  status: string
  created_at: string
  download_url: string
}

type Tab = 'indicators' | 'feeds' | 'rules' | 'samples' | 'sessions' | 'reports' | 'trc' | 'actors' | 'graph'

// ─── Threat Actor Data ────────────────────────────────────────────────────────
interface ThreatActor {
  id: string
  name: string
  alias: string
  country: string
  flag: string
  motivation: 'espionage' | 'financial' | 'ransomware' | 'social engineering' | 'sabotage'
  status: 'Active' | 'Inactive'
  ttps: string[]
  lastActivity: string // ISO date string
  description: string
  targets: string[]
  malwareFamilies: string[]
  confidence: 'High' | 'Medium' | 'Low'
  iocCount: number
  recentCampaigns: Array<{ name: string; date: string }>
}

const THREAT_ACTORS: ThreatActor[] = [
  {
    id: 'apt29',
    name: 'APT29',
    alias: 'Cozy Bear',
    country: 'Russia',
    flag: '🇷🇺',
    motivation: 'espionage',
    status: 'Active',
    ttps: ['T1566 Phishing', 'T1078 Valid Accounts', 'T1021 Remote Services', 'T1560 Archive Data'],
    lastActivity: '2026-05-22',
    description: '与俄罗斯对外情报局（SVR）关联的国家级APT组织，主要针对政府、外交和智库机构开展情报窃取活动。该组织以持久化驻留和高度隐蔽的横向移动技术著称，长期潜伏于目标网络中进行持续情报窃取。',
    targets: ['政府机构', '外交部门', '智库', 'IT供应链'],
    malwareFamilies: ['MiniDuke', 'CozyDuke', 'WellMess', 'SUNBURST'],
    confidence: 'High',
    iocCount: 312,
    recentCampaigns: [
      { name: 'APT29 Spear Phishing — Government Targets', date: '2026-05-10' },
      { name: 'CloudHopper Redux', date: '2026-04-20' },
      { name: 'Operation NobleBaron', date: '2025-11-03' },
    ],
  },
  {
    id: 'apt41',
    name: 'APT41',
    alias: 'Double Dragon',
    country: 'China',
    flag: '🇨🇳',
    motivation: 'financial',
    status: 'Active',
    ttps: ['T1190 Exploit Public App', 'T1059 Command Scripting', 'T1027 Obfuscation', 'T1003 Credential Dumping'],
    lastActivity: '2026-05-18',
    description: '与中国国家安全部关联的双重任务APT组织，同时从事国家支持的情报收集和出于经济利益的网络犯罪活动。该组织擅长利用零日漏洞进行初始访问，并在目标环境中长期驻留以收集高价值情报。',
    targets: ['医疗卫生', '电信', '科技企业', '视频游戏行业'],
    malwareFamilies: ['PlugX', 'ShadowPad', 'Winnti', 'CROSSWALK'],
    confidence: 'High',
    iocCount: 487,
    recentCampaigns: [
      { name: 'Operation BlackShadow', date: '2026-03-15' },
      { name: 'ShadowPad Supply Chain Attack', date: '2025-12-01' },
      { name: 'Telecom Sector Intrusion', date: '2025-09-14' },
    ],
  },
  {
    id: 'lazarus',
    name: 'Lazarus Group',
    alias: 'Hidden Cobra',
    country: 'DPRK',
    flag: '🇰🇵',
    motivation: 'financial',
    status: 'Active',
    ttps: ['T1189 Drive-by Compromise', 'T1055 Process Injection', 'T1105 Ingress Tool Transfer', 'T1486 Data Encrypted'],
    lastActivity: '2026-05-20',
    description: '朝鲜国家支持的高级威胁组织，以针对金融机构、加密货币交易所的大规模盗窃活动著称，曾造成数十亿美元损失。近年来持续发展定制化工具链，针对DeFi协议和跨链桥实施高精度攻击。',
    targets: ['加密货币交易所', '金融机构', '国防承包商', '媒体'],
    malwareFamilies: ['BLINDINGCAN', 'Manuscrypt', 'HOPLIGHT', 'AppleJeus'],
    confidence: 'High',
    iocCount: 634,
    recentCampaigns: [
      { name: 'Operation AppleJeus v4', date: '2026-05-01' },
      { name: 'DeFi Bridge Heist Campaign', date: '2026-02-18' },
      { name: 'TraderTraitor — Crypto Exchange', date: '2025-10-22' },
    ],
  },
  {
    id: 'fin7',
    name: 'FIN7',
    alias: 'Carbanak Group',
    country: 'Unknown',
    flag: '🌐',
    motivation: 'financial',
    status: 'Active',
    ttps: ['T1566.001 Spearphishing', 'T1204 User Execution', 'T1071 App Layer Protocol', 'T1041 Exfil over C2'],
    lastActivity: '2026-05-15',
    description: '以金融为主要动机的有组织网络犯罪集团，专门针对零售、餐饮和酒店行业的POS系统实施支付卡数据窃取。近期转向勒索软件运营，与多个RaaS团伙存在工具共享和人员重叠。',
    targets: ['零售业', '餐饮连锁', '酒店业', 'POS系统'],
    malwareFamilies: ['Carbanak', 'GRIFFON', 'BOOSTWRITE', 'REvil'],
    confidence: 'Medium',
    iocCount: 218,
    recentCampaigns: [
      { name: 'Retail POS Skimming Wave', date: '2026-04-05' },
      { name: 'BOOSTWRITE Loader Campaign', date: '2025-11-20' },
      { name: 'Hotel Chain Lateral Movement', date: '2025-08-30' },
    ],
  },
  {
    id: 'scattered-spider',
    name: 'Scattered Spider',
    alias: 'UNC3944',
    country: 'Unknown',
    flag: '🌐',
    motivation: 'social engineering',
    status: 'Active',
    ttps: ['T1598 Phishing for Info', 'T1621 MFA Request Gen', 'T1534 Internal Spearphish', 'T1078.004 Cloud Accounts'],
    lastActivity: '2026-05-21',
    description: '以社会工程和SIM卡交换攻击著称的年轻网络犯罪集团，擅长冒充IT支持人员绕过MFA防护，近期针对云基础设施。该组织成员主要活跃于英语国家，在Telegram和Discord上协调攻击行动。',
    targets: ['云服务提供商', '电信运营商', '大型科技企业', '酒店业'],
    malwareFamilies: ['RECORDSTEALER', 'SPECTRUM RAT', 'Okta Phishing Kit'],
    confidence: 'Medium',
    iocCount: 156,
    recentCampaigns: [
      { name: 'MGM/Caesars Style Social Eng', date: '2026-05-21' },
      { name: 'Cloud Identity Harvest Q1', date: '2026-03-10' },
      { name: 'Telecom SIM Swap Wave', date: '2025-12-14' },
    ],
  },
  {
    id: 'blackcat',
    name: 'BlackCat/ALPHV',
    alias: 'Noberus',
    country: 'Unknown',
    flag: '🌐',
    motivation: 'ransomware',
    status: 'Inactive',
    ttps: ['T1486 Data Encrypted', 'T1490 Inhibit Recovery', 'T1657 Financial Theft', 'T1657 Data Leak Extortion'],
    lastActivity: '2026-02-10',
    description: '使用Rust语言开发的勒索软件即服务（RaaS）运营商，以双重勒索策略著称。2024年被FBI瓦解后关闭，但相关人员仍活跃于其他勒索软件团伙，基础设施和TTPs被后继组织复用。',
    targets: ['医疗机构', '关键基础设施', '金融服务', '制造业'],
    malwareFamilies: ['BlackCat (Rust)', 'ALPHV Encryptor', 'ExMatter', 'Fendr'],
    confidence: 'High',
    iocCount: 891,
    recentCampaigns: [
      { name: 'Healthcare Sector Ransomware', date: '2026-01-15' },
      { name: 'Change Healthcare Incident', date: '2025-02-21' },
      { name: 'MGM Resorts Extortion', date: '2024-09-11' },
    ],
  },
]

const MOTIVATION_CONFIG: Record<string, { color: string; bg: string; label: string }> = {
  espionage: { color: 'var(--accent-blue)', bg: 'rgba(167,139,250,.15)', label: '情报窃取' },
  financial: { color: 'var(--medium)', bg: 'rgba(200,160,48,.15)', label: '经济利益' },
  ransomware: { color: 'var(--critical)', bg: 'rgba(224,80,80,.15)', label: '勒索软件' },
  'social engineering': { color: 'var(--accent-blue)', bg: 'rgba(79,163,224,.15)', label: '社会工程' },
  sabotage: { color: 'var(--high)', bg: 'rgba(224,128,64,.15)', label: '破坏活动' },
}

function daysAgo(isoDate: string): string {
  const diff = Math.floor((Date.now() - new Date(isoDate).getTime()) / 86400000)
  if (diff === 0) return '今天'
  if (diff === 1) return '昨天'
  return `${diff} 天前`
}

// ─── Campaign Data ────────────────────────────────────────────────────────────
type KillChainStage = 'Recon' | 'Weaponize' | 'Deliver' | 'Exploit' | 'Install' | 'C2' | 'Actions'

interface Campaign {
  id: string
  name: string
  status: 'ongoing' | 'resolved' | 'investigating'
  startDate: string
  endDate?: string
  incidentCount: number
  description: string
  expectedDays: number
  killChain: KillChainStage[]  // confirmed stages
  affectedAssets: number
  relatedIncidents: number
}

const ALL_KILL_CHAIN: KillChainStage[] = ['Recon', 'Weaponize', 'Deliver', 'Exploit', 'Install', 'C2', 'Actions']

const MOCK_CAMPAIGNS: Campaign[] = [
  {
    id: 'blackshadow',
    name: 'Operation BlackShadow',
    status: 'ongoing',
    startDate: '2026-03-15',
    incidentCount: 12,
    description: '针对金融行业的持续性入侵活动，通过供应链攻击横向移动',
    expectedDays: 90,
    killChain: ['Recon', 'Weaponize', 'Deliver', 'Exploit', 'Install', 'C2'],
    affectedAssets: 34,
    relatedIncidents: 12,
  },
  {
    id: 'solarstrike',
    name: 'SolarStrike Campaign',
    status: 'resolved',
    startDate: '2026-01-10',
    endDate: '2026-02-28',
    incidentCount: 8,
    description: '模仿SolarWinds手法的供应链攻击，已完全遏制',
    expectedDays: 60,
    killChain: ['Recon', 'Weaponize', 'Deliver', 'Exploit', 'Install', 'C2', 'Actions'],
    affectedAssets: 17,
    relatedIncidents: 8,
  },
  {
    id: 'cloudhopper',
    name: 'CloudHopper Redux',
    status: 'investigating',
    startDate: '2026-04-20',
    incidentCount: 5,
    description: '疑似APT10重演的云基础设施渗透行动，调查中',
    expectedDays: 45,
    killChain: ['Recon', 'Weaponize', 'Deliver', 'Exploit'],
    affectedAssets: 9,
    relatedIncidents: 5,
  },
]

const CAMPAIGN_STATUS_CONFIG: Record<string, { color: string; bg: string; label: string; border: string }> = {
  ongoing:      { color: 'var(--critical)', bg: 'rgba(224,80,80,.15)',  label: '进行中', border: 'rgba(224,80,80,.35)' },
  resolved:     { color: 'var(--accent-green)', bg: 'rgba(47,176,122,.15)',  label: '已解决', border: 'rgba(47,176,122,.35)' },
  investigating:{ color: 'var(--high)', bg: 'rgba(224,128,64,.15)', label: '调查中', border: 'rgba(224,128,64,.35)' },
}

const IOC_TYPES = ['ip', 'domain', 'url', 'hash', 'email', 'cve', 'cidr', 'registry', 'user_agent', 'mutex']

const IOC_LABELS: Record<string, string> = {
  ip: 'IP Address', domain: 'Domain', url: 'URL', hash: 'File Hash',
  email: 'Email', cve: 'CVE', cidr: 'CIDR', registry: 'Registry Key',
  user_agent: 'User Agent', mutex: 'Mutex',
}

const typeColor: Record<string, string> = {
  ip: 'var(--accent-blue)', domain: 'var(--accent-blue)', url: 'var(--accent-green)',
  hash: 'var(--medium)', email: 'var(--high)', cve: 'var(--text-muted)',
  cidr: 'var(--accent-blue)', registry: 'var(--high)', user_agent: 'var(--accent-green)', mutex: 'var(--accent-blue)',
}

const verdictConfig: Record<string, { bg: string; color: string; label: string }> = {
  malicious:  { bg: 'rgba(224,80,80,.18)',   color: 'var(--critical)', label: '恶意' },
  suspicious: { bg: 'rgba(224,128,64,.15)',  color: 'var(--high)', label: '可疑' },
  benign:     { bg: 'rgba(47,176,122,.15)',  color: 'var(--accent-green)', label: '无害' },
  unknown:    { bg: 'rgba(84,110,122,.15)',  color: 'var(--text-muted)', label: '未知' },
}

const feedStatusColor: Record<string, string> = {
  active: 'var(--accent-green)', inactive: 'var(--text-muted)',
  error: 'var(--critical)', syncing: 'var(--accent-blue)',
}

const feedTypeIcon: Record<string, string> = {
  stix_taxii: '⚠', misp: '🔗', custom: '⚙️', mitre: '🛡️',
  virustotal: '🔍', unit42: '🦅', wildfire: '🔥',
}

function fmtDate(iso: string) {
  if (!iso) return '-'
  return new Date(iso).toLocaleString('zh-CN', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', hour12: false })
}


function 判定结论Badge({ verdict }: { verdict: string }) {
  const cfg = verdictConfig[verdict?.toLowerCase()] ?? verdictConfig.unknown
  return (
    <span style={{ padding: '2px 8px', borderRadius: 3, fontSize: 10.5, fontWeight: 700, background: cfg.bg, color: cfg.color }}>
      {cfg.label}
    </span>
  )
}

const BLANK_IOC = { type: 'ip', value: '', verdict: 'unknown', confidence: '50', source_name: '', threat_name: '', tags: '' }
const BLANK_FEED = { name: '', description: '', feed_type: 'custom', url: '', sync_interval: '60', status: 'active' }
const BLANK_RULE = { name: '', rule_type: 'match', severity: 'medium', status: 'active' }
const BLANK_REPORT = { name: '', template_type: 'weekly', description: '' }

export default function ThreatIntel() {
  const navigate = useNavigate()
  const [tab, setTab] = useState<Tab>('indicators')
  const [showMoreTabs, setShowMoreTabs] = useState(false)

  // IOC state
  const [iocs, setIocs] = useState<IOC[]>([])
  const [iocMeta, setIocMeta] = useState<PageMeta>({ page: 1, page_size: 20, total: 0, total_pages: 1 })
  const [iocPage, setIocPage] = useState(1)
  const [iocLoading, setIocLoading] = useState(false)
  const [typeFilter, setTypeFilter] = useState('')
  const [verdictFilter, set判定结论Filter] = useState('')
  const [search, setSearch] = useState('')
  const [verdictCounts, set判定结论Counts] = useState<Record<string, number>>({})

  // Feed state
  const [feeds, set订阅源] = useState<Feed[]>([])
  const [feedMeta, setFeedMeta] = useState<PageMeta>({ page: 1, page_size: 20, total: 0, total_pages: 1 })
  const [feedPage, setFeedPage] = useState(1)
  const [feedLoading, setFeedLoading] = useState(false)
  const [syncing, setSyncing] = useState<string | null>(null)
  const [feedSearch, setFeedSearch] = useState('')
  const [feedTypeFilter, setFeedTypeFilter] = useState('')
  const [feedStatusFilter, setFeedStatusFilter] = useState('')

  // Indicator Rules state
  const [rules, setRules] = useState<IndicatorRule[]>([])
  const [rulesLoading, setRulesLoading] = useState(false)
  const [showRuleModal, setShowRuleModal] = useState(false)
  const [editRule, setEditRule] = useState<IndicatorRule | null>(null)
  const [ruleForm, setRuleForm] = useState<typeof BLANK_RULE>(BLANK_RULE)
  const [savingRule, setSavingRule] = useState(false)

  // 样本 state
  const [samples, set样本s] = useState<SampleFeed[]>([])
  const [samplesLoading, set样本sLoading] = useState(false)
  const [show提交Modal, setShow提交Modal] = useState(false)
  const [submitFile, set提交File] = useState('')
  const [submitUrl, set提交Url] = useState('')
  const [submitting, set提交ting] = useState(false)

  // 报告 state
  const [reports, set报告] = useState<Report[]>([])
  const [reportsLoading, set报告Loading] = useState(false)
  const [showReportModal, setShowReportModal] = useState(false)
  const [reportForm, setReportForm] = useState(BLANK_REPORT)
  const [savingReport, setSavingReport] = useState(false)

  // IOC modal
  const [showIocModal, setShowIocModal] = useState(false)
  const [editIoc, setEditIoc] = useState<IOC | null>(null)
  const [iocForm, setIocForm] = useState(BLANK_IOC)
  const [savingIoc, setSavingIoc] = useState(false)

  // Feed modal
  const [showFeedModal, setShowFeedModal] = useState(false)
  const [editFeed, setEditFeed] = useState<Feed | null>(null)
  const [feedForm, setFeedForm] = useState(BLANK_FEED)
  const [savingFeed, setSavingFeed] = useState(false)

  // 威胁响应中心 block state
  const [blockingTrc, setBlockingTrc] = useState<string | null>(null)

  // Threat Actor state
  const [selectedActor, setSelectedActor] = useState<ThreatActor | null>(null)
  const [actorMotivationFilter, setActorMotivationFilter] = useState('')

  // IOC Hunt state
  const [iocHuntQuery, setIocHuntQuery] = useState('')
  const [iocHuntResults, setIocHuntResults] = useState<IOC[]>([])
  const [iocHuntLoading, setIocHuntLoading] = useState(false)
  const [iocHuntSearched, setIocHuntSearched] = useState(false)

  // TRC — live incidents
  const [trcIncidents, setTrcIncidents] = useState<Incident[]>([])
  const [trcLoading, setTrcLoading] = useState(false)
  const [trcStats, setTrcStats] = useState({ resolvedToday: 0, mttrHours: 0 })

  // Sessions — identity risks
  const [identityRisks, setIdentityRisks] = useState<IdentityRisk[]>([])
  const [identityLoading, setIdentityLoading] = useState(false)

  // Samples verdict filter
  const [samplesVerdictFilter, setSamplesVerdictFilter] = useState('')

  // Stats summary bar
  const [statsIocTotal, setStatsIocTotal] = useState<number>(0)
  const [statsRulesTotal, setStatsRulesTotal] = useState<number>(0)
  const [statsActiveFeedsTotal, setStatsActiveFeedsTotal] = useState<number>(0)

  // Rules search (client-side)
  const [rulesSearch, setRulesSearch] = useState('')

  function loadStats() {
    api.get('/iocs', { params: { page: 1, page_size: 1 } })
      .then(r => setStatsIocTotal(r.data.data?.meta?.total ?? 0))
      .catch(() => {})
    api.get('/detection_rules', { params: { page: 1, page_size: 1 } })
      .then(r => setStatsRulesTotal(r.data.data?.meta?.total ?? 0))
      .catch(() => {})
    api.get('/intel_feeds', { params: { status: 'active', page: 1, page_size: 1 } })
      .then(r => setStatsActiveFeedsTotal(r.data.data?.meta?.total ?? 0))
      .catch(() => {})
  }

  function loadIocs(p = iocPage) {
    setIocLoading(true)
    const params: any = { page: p, page_size: 20 }
    if (typeFilter) params.type = typeFilter
    if (verdictFilter) params.verdict = verdictFilter
    if (search) params.keyword = search
    api.get('/iocs', { params })
      .then(r => {
        setIocs(r.data.data?.items ?? [])
        setIocMeta(r.data.data?.meta ?? iocMeta)
        const counts = r.data.data?.verdict_counts ?? {}
        if (Object.keys(counts).length) set判定结论Counts(counts)
      })
      .finally(() => setIocLoading(false))
  }

  function load订阅源(p = feedPage) {
    setFeedLoading(true)
    const params: any = { page: p, page_size: 20 }
    if (feedSearch) params.keyword = feedSearch
    if (feedTypeFilter) params.feed_type = feedTypeFilter
    if (feedStatusFilter) params.status = feedStatusFilter
    api.get('/intel_feeds', { params })
      .then(r => { set订阅源(r.data.data?.items ?? []); setFeedMeta(r.data.data?.meta ?? feedMeta) })
      .finally(() => setFeedLoading(false))
  }

  function loadRules() {
    setRulesLoading(true)
    api.get('/threat_intel/rules', { params: { page: 1, page_size: 50 } })
      .then(r => setRules(r.data.data?.items ?? []))
      .catch(() => setRules([]))
      .finally(() => setRulesLoading(false))
  }

  function load样本s() {
    set样本sLoading(true)
    api.get('/threat_intel/samples', { params: { page: 1, page_size: 20 } })
      .then(r => set样本s(r.data.data?.items ?? []))
      .catch(() => set样本s([]))
      .finally(() => set样本sLoading(false))
  }

  function load报告() {
    set报告Loading(true)
    api.get('/threat_intel/reports', { params: { page: 1, page_size: 20 } })
      .then(r => set报告(r.data.data?.items ?? []))
      .catch(() => set报告([]))
      .finally(() => set报告Loading(false))
  }

  function loadTrcIncidents() {
    setTrcLoading(true)
    api.get('/incidents', { params: { status: 'open', page_size: 20, page: 1 } })
      .then(r => {
        const items: Incident[] = r.data.data?.items ?? []
        setTrcIncidents(items)
        // compute stats from all incidents (resolved today + MTTR approximation)
        return api.get('/incidents', { params: { page_size: 50, page: 1 } })
          .then(all => {
            const allItems: Incident[] = all.data.data?.items ?? []
            const todayStr = new Date().toISOString().slice(0, 10)
            const resolvedToday = allItems.filter(i =>
              (i.status === 'resolved' || i.status === 'closed') &&
              i.resolved_at?.startsWith(todayStr)
            ).length
            // rough MTTR: average hours from created_at to resolved_at for resolved items
            const resolvedWithTime = allItems.filter(i => i.resolved_at && i.created_at)
            const mttrMs = resolvedWithTime.length > 0
              ? resolvedWithTime.reduce((sum, i) => sum + (new Date(i.resolved_at!).getTime() - new Date(i.created_at).getTime()), 0) / resolvedWithTime.length
              : 0
            setTrcStats({ resolvedToday, mttrHours: Math.round(mttrMs / 3600000) })
          })
          .catch(() => {})
      })
      .catch(() => setTrcIncidents([]))
      .finally(() => setTrcLoading(false))
  }

  function loadIdentityRisks() {
    setIdentityLoading(true)
    api.get('/identity_risks', { params: { page_size: 50, page: 1 } })
      .then(r => setIdentityRisks(r.data.data?.items ?? []))
      .catch(() => setIdentityRisks([]))
      .finally(() => setIdentityLoading(false))
  }

  useEffect(() => { loadStats() }, [])
  useEffect(() => { loadIocs(1); setIocPage(1) }, [typeFilter, verdictFilter])
  useEffect(() => { loadIocs(iocPage) }, [iocPage])
  useEffect(() => { loadIocs(1) }, [])
  useEffect(() => { if (tab === 'feeds') load订阅源(feedPage) }, [feedPage, tab])
  useEffect(() => { if (tab === 'feeds') load订阅源(1) }, [feedSearch, feedTypeFilter, feedStatusFilter])
  useEffect(() => { if (tab === 'rules' && rules.length === 0) loadRules() }, [tab])
  useEffect(() => { if (tab === 'samples' && samples.length === 0) load样本s() }, [tab])
  useEffect(() => { if (tab === 'reports' && reports.length === 0) load报告() }, [tab])
  useEffect(() => { if (tab === 'trc') loadTrcIncidents() }, [tab])
  useEffect(() => { if (tab === 'sessions' && identityRisks.length === 0) loadIdentityRisks() }, [tab])

  function syncFeed(key: string) {
    setSyncing(key)
    api.post(`/intel_feeds/${key}/sync`).then(() => load订阅源(feedPage)).finally(() => setSyncing(null))
  }

  // IOC CRUD
  function openCreateIoc() { setEditIoc(null); setIocForm(BLANK_IOC); setShowIocModal(true) }
  function openEditIoc(ioc: IOC) {
    setEditIoc(ioc)
    setIocForm({ type: ioc.type, value: ioc.value, verdict: ioc.verdict, confidence: String(ioc.confidence ?? 50), source_name: ioc.source_name || ioc.source || '', threat_name: ioc.threat_name || '', tags: (ioc.tags ?? []).join(', ') })
    setShowIocModal(true)
  }
  function saveIoc() {
    if (!iocForm.value.trim()) return
    setSavingIoc(true)
    const body = { type: iocForm.type, value: iocForm.value, verdict: iocForm.verdict, confidence: parseInt(iocForm.confidence) || 50, source_name: iocForm.source_name, threat_name: iocForm.threat_name, tags: iocForm.tags ? iocForm.tags.split(',').map(s => s.trim()).filter(Boolean) : [], is_active: true }
    const req = editIoc ? api.patch(`/iocs/${editIoc._key}`, body) : api.post('/iocs', body)
    req.then(() => { setShowIocModal(false); loadIocs(1) }).finally(() => setSavingIoc(false))
  }
  function deleteIoc(ioc: IOC) {
    if (!confirm(`Delete IOC ${ioc.value}?`)) return
    api.delete(`/iocs/${ioc._key}`).then(() => loadIocs(1))
  }

  // Feed CRUD
  function openCreateFeed() { setEditFeed(null); setFeedForm(BLANK_FEED); setShowFeedModal(true) }
  function openEditFeed(f: Feed) {
    setEditFeed(f)
    setFeedForm({ name: f.name, description: f.description || '', feed_type: f.feed_type || 'custom', url: f.url || '', sync_interval: String(f.sync_interval ?? 60), status: f.status || 'active' })
    setShowFeedModal(true)
  }
  function saveFeed() {
    if (!feedForm.name.trim()) return
    setSavingFeed(true)
    const body = { name: feedForm.name, description: feedForm.description, feed_type: feedForm.feed_type, url: feedForm.url, sync_interval: parseInt(feedForm.sync_interval) || 60, status: feedForm.status }
    const req = editFeed ? api.patch(`/intel_feeds/${editFeed._key}`, body) : api.post('/intel_feeds', body)
    req.then(() => { setShowFeedModal(false); load订阅源(1) }).finally(() => setSavingFeed(false))
  }
  function deleteFeed(f: Feed) {
    if (!confirm(`Delete feed "${f.name}"?`)) return
    api.delete(`/intel_feeds/${f._key}`).then(() => load订阅源(1))
  }

  // Indicator Rules CRUD
  function openCreateRule() { setEditRule(null); setRuleForm(BLANK_RULE); setShowRuleModal(true) }
  function openEditRule(r: IndicatorRule) {
    setEditRule(r)
    setRuleForm({ name: r.name, rule_type: r.rule_type || 'match', severity: r.severity || 'medium', status: r.status })
    setShowRuleModal(true)
  }
  function saveRule() {
    if (!ruleForm.name.trim()) return
    setSavingRule(true)
    const body = { name: ruleForm.name, rule_type: ruleForm.rule_type, severity: ruleForm.severity, status: ruleForm.status }
    const req = editRule ? api.patch(`/threat_intel/rules/${editRule._key}`, body) : api.post('/threat_intel/rules', body)
    req.then(() => { setShowRuleModal(false); loadRules() }).finally(() => setSavingRule(false))
  }
  function deleteRule(r: IndicatorRule) {
    if (!confirm(`Delete rule "${r.name}"?`)) return
    api.delete(`/threat_intel/rules/${r._key}`).then(() => loadRules())
  }
  function toggleRule(r: IndicatorRule) {
    const newStatus = r.status === 'active' ? 'inactive' : 'active'
    api.patch(`/threat_intel/rules/${r._key}`, { status: newStatus }).then(() => loadRules())
  }

  // 样本s
  function submit样本() {
    if (!submitFile.trim() && !submitUrl.trim()) return
    set提交ting(true)
    api.post('/threat_intel/samples', { filename: submitFile || undefined, url: submitUrl || undefined })
      .then(() => { setShow提交Modal(false); set提交File(''); set提交Url(''); load样本s() })
      .finally(() => set提交ting(false))
  }
  function delete样本(s: SampleFeed) {
    if (!confirm(`Delete sample ${s.value || s._key}?`)) return
    api.delete(`/threat_intel/samples/${s._key}`).then(() => load样本s())
  }

  // 报告
  function createReport() {
    if (!reportForm.name.trim()) return
    setSavingReport(true)
    api.post('/threat_intel/reports', reportForm)
      .then(() => { setShowReportModal(false); setReportForm(BLANK_REPORT); load报告() })
      .finally(() => setSavingReport(false))
  }
  function deleteReport(r: Report) {
    if (!confirm(`Delete report "${r.name}"?`)) return
    api.delete(`/threat_intel/reports/${r._key}`).then(() => load报告())
  }

  // IOC Hunt
  function runIocHunt() {
    if (!iocHuntQuery.trim()) return
    setIocHuntLoading(true)
    setIocHuntSearched(true)
    api.get('/iocs', { params: { q: iocHuntQuery.trim(), page_size: 10, page: 1 } })
      .then(r => setIocHuntResults(r.data.data?.items ?? []))
      .catch(() => setIocHuntResults([]))
      .finally(() => setIocHuntLoading(false))
  }

  // 威胁响应中心 actions
  function trcBlockIOCs(title: string) {
    setBlockingTrc(title)
    api.post('/threat_intel/trc/block', { campaign: title })
      .finally(() => setBlockingTrc(null))
  }
  function trcInvestigate(title: string) {
    api.post('/incidents', { title: `威胁响应中心 Investigation: ${title}`, severity: 'high', status: 'new' })
  }
  function trcCreateRule(title: string) {
    setRuleForm({ name: `Auto: ${title.slice(0, 40)}`, rule_type: 'match', severity: 'high', status: 'active' })
    setEditRule(null)
    setShowRuleModal(true)
    setTab('rules')
  }

  const 威胁响应中心_EVENTS = [
    { title: 'Zero-Day: MOVEit Transfer RCE (CVE-2024-5806)', sev: 'critical' as const, desc: 'Actively exploited zero-day in MOVEit Transfer. SQL injection leading to unauthorized access and data exfiltration. Nation-state actors confirmed.', iocs: 47, assets: 3, date: '2026-05-14' },
    { title: 'LockBit 3.0 Ransomware Campaign — Financial Sector', sev: 'high' as const, desc: 'LockBit 3.0 actors targeting financial institutions with updated TTPs. Lateral movement via valid credentials observed before encryption.', iocs: 128, assets: 0, date: '2026-05-12' },
    { title: 'APT29 Spear Phishing — Government Targets', sev: 'high' as const, desc: 'Cozy Bear credential harvesting campaign targeting government contractors. 恶意 OAuth consent grant phishing observed.', iocs: 34, assets: 0, date: '2026-05-10' },
  ]

  const verdictSummary = (() => {
    const mc = verdictCounts.malicious || 0
    const sc = verdictCounts.suspicious || 0
    const uc = verdictCounts.unknown || 0
    const bc = verdictCounts.benign || 0
    return { mc, sc, uc, bc }
  })()

  const headerBtn = () => {
    if (tab === 'feeds') return <button className="btn-primary" onClick={openCreateFeed}>+ Add Feed</button>
    if (tab === 'indicators') return <button className="btn-primary" onClick={openCreateIoc}>+ Add Indicator</button>
    if (tab === 'rules') return <button className="btn-primary" onClick={openCreateRule}>+ New Rule</button>
    if (tab === 'samples') return <button className="btn-primary" onClick={() => setShow提交Modal(true)}>+ 提交样本</button>
    if (tab === 'reports') return <button className="btn-primary" onClick={() => setShowReportModal(true)}>+ 创建报告</button>
    return null
  }

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <PageHeader
        title="Threat Intel Management"
        actions={<div style={{ display: 'flex', gap: 8 }}>{headerBtn()}</div>}
      />

      {/* ===== IOC HUNT — cross-tab search bar ===== */}
      <div style={{ padding: '10px 20px', borderBottom: '1px solid var(--border)', flexShrink: 0, background: 'var(--bg-primary)' }}>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          <span style={{ fontSize: 11.5, color: 'var(--text-muted)', whiteSpace: 'nowrap', fontWeight: 600, letterSpacing: .3 }}>
            🔍 跨平台IOC搜索
          </span>
          <div style={{ position: 'relative', flex: 1, maxWidth: 480 }}>
            <input
              className="filter-input"
              placeholder="输入 IP、域名、文件哈希或 URL..."
              style={{ width: '100%', boxSizing: 'border-box', paddingRight: 80 }}
              value={iocHuntQuery}
              onChange={e => { setIocHuntQuery(e.target.value); if (!e.target.value.trim()) { setIocHuntSearched(false); setIocHuntResults([]) } }}
              onKeyDown={e => e.key === 'Enter' && runIocHunt()}
            />
            <button
              onClick={runIocHunt}
              disabled={iocHuntLoading || !iocHuntQuery.trim()}
              style={{ position: 'absolute', right: 4, top: '50%', transform: 'translateY(-50%)', fontSize: 11, padding: '2px 10px', background: 'var(--accent-blue)', color: '#fff', border: 'none', borderRadius: 4, cursor: 'pointer', opacity: !iocHuntQuery.trim() ? .4 : 1 }}
            >
              {iocHuntLoading ? '...' : '搜索'}
            </button>
          </div>
          {iocHuntSearched && iocHuntQuery && (
            <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
              <button
                onClick={() => navigate(`/alerts?keyword=${encodeURIComponent(iocHuntQuery)}`)}
                style={{ fontSize: 11, padding: '3px 10px', background: 'rgba(79,163,224,.1)', border: '1px solid rgba(79,163,224,.3)', borderRadius: 4, color: 'var(--accent-blue)', cursor: 'pointer', whiteSpace: 'nowrap' }}
              >
                在告警中搜索 →
              </button>
              <button
                onClick={() => navigate(`/incidents?keyword=${encodeURIComponent(iocHuntQuery)}`)}
                style={{ fontSize: 11, padding: '3px 10px', background: 'rgba(167,139,250,.1)', border: '1px solid rgba(167,139,250,.3)', borderRadius: 4, color: 'var(--accent-blue)', cursor: 'pointer', whiteSpace: 'nowrap' }}
              >
                在事件中搜索 →
              </button>
            </div>
          )}
        </div>

        {/* IOC Hunt results */}
        {iocHuntSearched && (
          <div style={{ marginTop: 8, display: 'flex', flexDirection: 'column', gap: 4 }}>
            {iocHuntLoading && (
              <div style={{ fontSize: 11, color: 'var(--text-muted)', padding: '4px 0' }}>搜索中...</div>
            )}
            {!iocHuntLoading && iocHuntResults.length === 0 && (
              <div style={{ fontSize: 11, color: 'var(--text-muted)', padding: '4px 0' }}>未找到匹配的 IOC 记录</div>
            )}
            {!iocHuntLoading && iocHuntResults.length > 0 && (
              <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                <span style={{ fontSize: 11, color: 'var(--text-muted)', alignSelf: 'center' }}>
                  找到 {iocHuntResults.length} 条结果:
                </span>
                {iocHuntResults.map(ioc => {
                  const vcfg = verdictConfig[ioc.verdict?.toLowerCase()] ?? verdictConfig.unknown
                  return (
                    <div key={ioc._key} style={{
                      display: 'inline-flex', alignItems: 'center', gap: 6,
                      padding: '3px 10px', background: vcfg.bg, border: `1px solid ${vcfg.color}44`,
                      borderRadius: 4, fontSize: 11,
                    }}>
                      <span style={{ fontSize: 9.5, textTransform: 'uppercase', background: `${typeColor[ioc.type] ?? 'var(--accent-blue)'}22`, color: typeColor[ioc.type] ?? 'var(--accent-blue)', padding: '1px 5px', borderRadius: 3, fontWeight: 700 }}>{ioc.type}</span>
                      <span style={{ fontFamily: 'monospace', color: 'var(--text-primary)', maxWidth: 180, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={ioc.value}>{ioc.value}</span>
                      <span style={{ color: vcfg.color, fontWeight: 700, fontSize: 10 }}>{vcfg.label}</span>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        )}
      </div>

      {/* Stats Summary Bar */}
      <div style={{ display: 'flex', gap: 12, padding: '10px 20px', borderBottom: '1px solid var(--border)', flexShrink: 0, background: 'var(--bg-primary)' }}>
        {[
          { label: 'IOC 总数', value: statsIocTotal, color: 'var(--accent-blue)', bg: 'rgba(79,163,224,.1)', border: 'rgba(79,163,224,.25)', suffix: '个 IOC' },
          { label: '检测规则', value: statsRulesTotal, color: 'var(--accent-blue)', bg: 'rgba(167,139,250,.1)', border: 'rgba(167,139,250,.25)', suffix: '条规则' },
          { label: '活跃情报源', value: statsActiveFeedsTotal, color: 'var(--accent-green)', bg: 'rgba(0,200,150,.1)', border: 'rgba(0,200,150,.25)', suffix: '个活跃情报源' },
        ].map(stat => (
          <div key={stat.label} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '8px 16px', background: stat.bg, border: `1px solid ${stat.border}`, borderRadius: 8, minWidth: 160 }}>
            <div>
              <div style={{ fontSize: 20, fontWeight: 700, color: stat.color, lineHeight: 1.1 }}>{stat.value.toLocaleString()}</div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{stat.suffix}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="tab-bar" style={{ position: 'relative' }}>
        <button className={`tab ${tab === 'indicators' ? 'active' : ''}`} onClick={() => setTab('indicators')}>
          指标 <span className="tab-count">{iocMeta.total}</span>
        </button>
        <button className={`tab ${tab === 'feeds' ? 'active' : ''}`} onClick={() => setTab('feeds')}>
          订阅源 <span className="tab-count">{feedMeta.total}</span>
        </button>
        <button className={`tab ${tab === 'samples' ? 'active' : ''}`} onClick={() => setTab('samples')}>
          样本分析 <span className="tab-count">{samples.length}</span>
        </button>
        <button className={`tab ${tab === 'sessions' ? 'active' : ''}`} onClick={() => setTab('sessions')}>
          身份会话 <span className="tab-count">{identityRisks.length}</span>
        </button>
        <button className={`tab ${tab === 'reports' ? 'active' : ''}`} onClick={() => setTab('reports')}>
          TIM报告 <span className="tab-count">{reports.length}</span>
        </button>
        {/* "更多" dropdown for low-frequency tabs */}
        <div style={{ position: 'relative', display: 'inline-flex' }}>
          <button
            className={`tab ${['rules', 'trc', 'actors', 'graph'].includes(tab) ? 'active' : ''}`}
            onClick={() => setShowMoreTabs(p => !p)}
            onBlur={() => setTimeout(() => setShowMoreTabs(false), 150)}
          >
            更多 ▾
          </button>
          {showMoreTabs && (
            <div style={{
              position: 'absolute', top: '100%', left: 0, zIndex: 300,
              background: 'var(--bg-card)', border: '1px solid var(--border)',
              borderRadius: 6, boxShadow: '0 4px 16px rgba(0,0,0,.4)',
              minWidth: 160, overflow: 'hidden',
            }}>
              {([
                ['rules',  'Indicator Rules', rules.length],
                ['trc',    '威胁响应中心',     trcIncidents.length || 0],
                ['actors', '威胁行为者',       THREAT_ACTORS.length],
                ['graph',  '情报图谱',         0],
              ] as [Tab, string, number][]).map(([t, label, count]) => (
                <div
                  key={t}
                  onClick={() => { setTab(t); setShowMoreTabs(false) }}
                  style={{
                    padding: '9px 14px', fontSize: 12, cursor: 'pointer',
                    color: tab === t ? 'var(--accent-orange)' : 'var(--text-secondary)',
                    background: tab === t ? 'rgba(250,88,45,.08)' : 'none',
                    borderBottom: '1px solid rgba(255,255,255,.04)',
                    display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 8,
                    transition: 'background .1s',
                  }}
                  onMouseEnter={e => { if (tab !== t) e.currentTarget.style.background = 'rgba(255,255,255,.04)' }}
                  onMouseLeave={e => { e.currentTarget.style.background = tab === t ? 'rgba(250,88,45,.08)' : 'none' }}
                >
                  <span>{label}</span>
                  {count > 0 && <span style={{ fontSize: 10, padding: '1px 5px', borderRadius: 8, background: 'rgba(250,88,45,.15)', color: 'var(--accent-orange)' }}>{count}</span>}
                </div>
              ))}
            </div>
          )}
        </div>
      </div>

      {/* 判定结论 summary pills — indicators tab only */}
      {tab === 'indicators' && (
        <div style={{ display: 'flex', gap: 8, padding: '8px 20px', borderBottom: '1px solid var(--border)', flexShrink: 0, background: 'var(--bg-primary)', alignItems: 'center' }}>
          {[
            { emoji: '🔴', label: '恶意', count: verdictSummary.mc, bg: 'rgba(224,80,80,.1)', border: 'rgba(224,80,80,.3)', color: 'var(--critical)' },
            { emoji: '🟠', label: '可疑', count: verdictSummary.sc, bg: 'rgba(224,128,64,.1)', border: 'rgba(224,128,64,.3)', color: 'var(--high)' },
            { emoji: '⚪', label: '未知', count: verdictSummary.uc, bg: 'rgba(84,110,122,.1)', border: 'rgba(84,110,122,.3)', color: 'var(--text-muted)' },
            { emoji: '🟢', label: '无害', count: verdictSummary.bc, bg: 'rgba(47,176,122,.1)', border: 'rgba(47,176,122,.3)', color: 'var(--accent-green)' },
          ].map(v => (
            <div key={v.label}
              style={{ padding: '5px 14px', background: v.bg, border: `1px solid ${verdictFilter === v.label.toLowerCase() ? v.color : v.border}`, borderRadius: 6, fontSize: 12, color: v.color, cursor: 'pointer', fontWeight: verdictFilter === v.label.toLowerCase() ? 700 : 400 }}
              onClick={() => set判定结论Filter(verdictFilter === v.label.toLowerCase() ? '' : v.label.toLowerCase())}>
              {v.emoji} {v.label}: <strong>{v.count.toLocaleString()}</strong>
            </div>
          ))}
          <div style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--text-muted)', display: 'flex', alignItems: 'center' }}>
            Total: <strong style={{ color: 'var(--text-primary)', marginLeft: 4 }}>{(verdictSummary.mc + verdictSummary.sc + verdictSummary.uc + verdictSummary.bc).toLocaleString()}</strong> indicators
          </div>
        </div>
      )}

      {/* ===== INDICATORS ===== */}
      {tab === 'indicators' && (
        <>
          <div className="filter-bar">
            <input className="filter-input" placeholder="搜索指标：IP、域名、哈希、URL..."
          value={search} onChange={e => setSearch(e.target.value)} onKeyDown={e => e.key === 'Enter' && loadIocs(1)} />
            <select className="filter-select" value={verdictFilter} onChange={e => set判定结论Filter(e.target.value)}>
              <option value="">All 判定结论s</option>
              <option value="malicious">恶意</option>
              <option value="suspicious">可疑</option>
              <option value="benign">无害</option>
              <option value="unknown">未知</option>
            </select>
          </div>
          <div style={{ display: 'flex', gap: 6, padding: '6px 20px', flexWrap: 'wrap', borderBottom: '1px solid var(--border)', flexShrink: 0, background: 'var(--bg-primary)' }}>
            {(['', ...IOC_TYPES] as string[]).map(t => (
              <button key={t || 'all'} onClick={() => setTypeFilter(t)} style={{
                padding: '3px 12px', borderRadius: 20, fontSize: 11, cursor: 'pointer',
                border: `1px solid ${typeFilter === t ? 'var(--accent-orange)' : 'var(--border)'}`,
                background: typeFilter === t ? 'rgba(250,88,45,.1)' : 'none',
                color: typeFilter === t ? 'var(--accent-orange)' : 'var(--text-secondary)', transition: 'all .15s',
              }}>{t ? (IOC_LABELS[t] ?? t.toUpperCase()) : 'All Types'}</button>
            ))}
          </div>
          <div className="data-table-wrap">
            <table className="data-table">
              <thead>
                <tr><th>类型</th><th style={{ minWidth: 220 }}>Indicator Value</th><th>判定结论</th><th>置信度</th><th>Source / Feed</th><th>Related Incidents</th><th>最近发现</th><th></th></tr>
              </thead>
              <tbody>
                {iocLoading && <tr><td colSpan={8} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>加载中...</td></tr>}
                {!iocLoading && iocs.length === 0 && <tr><td colSpan={8} style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>No indicators</td></tr>}
                {iocs.map(ioc => (
                  <tr key={ioc._key}>
                    <td><span style={{ fontSize: 10, padding: '2px 7px', borderRadius: 3, fontWeight: 600, textTransform: 'uppercase', background: `${typeColor[ioc.type] ?? 'var(--accent-blue)'}22`, color: typeColor[ioc.type] ?? 'var(--accent-blue)' }}>{ioc.type}</span></td>
                    <td style={{ fontFamily: 'monospace', fontSize: 11.5, maxWidth: 240, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap', color: verdictConfig[ioc.verdict?.toLowerCase()]?.color ?? 'var(--text-secondary)' }}>{ioc.value}</td>
                    <td><判定结论Badge verdict={ioc.verdict} /></td>
                    <td style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>{ioc.confidence ?? 0}%</td>
                    <td style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{ioc.source_name || ioc.source || ioc.tags?.[0] || '-'}</td>
                    <td style={{ fontSize: 11.5 }}>
                      {(ioc.related_incidents ?? []).length > 0
                        ? <span style={{ color: 'var(--accent-blue)', cursor: 'pointer' }}>{ioc.related_incidents.slice(0, 2).join(', ')}</span>
                        : <span style={{ color: 'var(--text-muted)' }}>...</span>}
                    </td>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{fmtDate(ioc.last_seen || ioc.created_at)}</td>
                    <td onClick={e => e.stopPropagation()}>
                      <div style={{ display: 'flex', gap: 4 }}>
                        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 7px' }} onClick={() => openEditIoc(ioc)}>编辑</button>
                        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 7px', color: 'var(--critical)' }} onClick={() => deleteIoc(ioc)}>删</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="pagination">
            <button className="page-btn" disabled={iocPage <= 1} onClick={() => setIocPage(p => p - 1)}>...</button>
            <span>{iocPage} / {iocMeta.total_pages || 1}</span>
            <button className="page-btn" disabled={iocPage >= iocMeta.total_pages} onClick={() => setIocPage(p => p + 1)}>...</button>
            <span style={{ marginLeft: 8 }}>{iocMeta.total.toLocaleString()} 条</span>
          </div>
        </>
      )}

      {/* ===== FEEDS ===== */}
      {tab === 'feeds' && (
        <>
          <div className="filter-bar">
            <input className="filter-input" placeholder="搜索订阅源..." value={feedSearch} onChange={e => setFeedSearch(e.target.value)} onKeyDown={e => e.key === 'Enter' && load订阅源(1)} />
            <select className="filter-select" value={feedTypeFilter} onChange={e => setFeedTypeFilter(e.target.value)}>
              <option value="">全部类型</option>
              <option value="stix_taxii">STIX/TAXII</option>
              <option value="misp">MISP</option>
              <option value="mitre">MITRE ATT&CK</option>
              <option value="virustotal">VirusTotal</option>
              <option value="unit42">Unit 42</option>
              <option value="wildfire">WildFire</option>
              <option value="custom">Custom</option>
            </select>
            <select className="filter-select" value={feedStatusFilter} onChange={e => setFeedStatusFilter(e.target.value)}>
              <option value="">全部状态</option>
              <option value="active">Active</option>
              <option value="inactive">Inactive</option>
              <option value="error">Error</option>
            </select>
          </div>
          <div className="data-table-wrap">
            <table className="data-table">
              <thead><tr><th>Feed Name</th><th>类型</th><th>状态</th><th>指标</th><th>Last Synced</th><th>Interval</th><th></th></tr></thead>
              <tbody>
                {feedLoading && <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>加载中...</td></tr>}
                {!feedLoading && feeds.length === 0 && <tr><td colSpan={7} style={{ textAlign: 'center', padding: 40, color: 'var(--text-muted)' }}>No feeds configured</td></tr>}
                {feeds.map(f => (
                  <tr key={f._key}>
                    <td>
                      <div style={{ fontSize: 12.5, fontWeight: 500 }}>{feedTypeIcon[f.feed_type] ?? '📗'} {f.name}</div>
                      {f.description && <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{f.description.slice(0, 60)}</div>}
                    </td>
                    <td><span style={{ fontSize: 10.5, padding: '2px 8px', background: 'var(--bg-card2)', border: '1px solid var(--border-light)', borderRadius: 3, textTransform: 'uppercase', fontFamily: 'monospace', letterSpacing: .3 }}>{f.feed_type || 'custom'}</span></td>
                    <td>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11.5 }}>
                        <span style={{ width: 6, height: 6, borderRadius: '50%', display: 'inline-block', background: feedStatusColor[f.status] ?? 'var(--text-muted)', boxShadow: f.status === 'active' ? `0 0 4px ${feedStatusColor.active}` : 'none' }} />
                        {f.status || 'inactive'}
                      </span>
                    </td>
                    <td style={{ fontSize: 12, color: 'var(--text-secondary)', fontFamily: 'monospace' }}>{(f.ioc_count ?? 0).toLocaleString()}</td>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{fmtDate(f.last_synced)}</td>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{f.sync_interval ? `${f.sync_interval}m` : 'manual'}</td>
                    <td>
                      <div style={{ display: 'flex', gap: 5 }}>
                        <button className="btn-primary" style={{ fontSize: 11, padding: '2px 10px' }} disabled={syncing === f._key} onClick={() => syncFeed(f._key)}>{syncing === f._key ? '...' : '→ 同步'}</button>
                        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px' }} onClick={() => openEditFeed(f)}>编辑</button>
                        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px', color: 'var(--critical)' }} onClick={() => deleteFeed(f)}>删</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <div className="pagination">
            <button className="page-btn" disabled={feedPage <= 1} onClick={() => setFeedPage(p => p - 1)}>...</button>
            <span>{feedPage} / {feedMeta.total_pages || 1}</span>
            <button className="page-btn" disabled={feedPage >= feedMeta.total_pages} onClick={() => setFeedPage(p => p + 1)}>...</button>
            <span style={{ marginLeft: 8 }}>{feedMeta.total} 条</span>
          </div>
        </>
      )}

      {/* ===== INDICATOR RULES ===== */}
      {tab === 'rules' && (
        <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', flex: 1 }}>
              Automatically act on matched indicators ...封锁、告警或丰富上下文 based on verdict and IOC type.
            </div>
            <input
              className="filter-input"
              placeholder="搜索规则名称或描述..."
              style={{ width: 240 }}
              value={rulesSearch}
              onChange={e => setRulesSearch(e.target.value)}
            />
          </div>
          <div className="data-table-wrap" style={{ flex: 'unset' }}>
            <table className="data-table">
              <thead><tr><th>Rule Name</th><th>Type</th><th>Severity</th><th>MITRE Tactic</th><th>状态</th><th>Hits</th><th>创建时间</th><th></th></tr></thead>
              <tbody>
                {rulesLoading && <tr><td colSpan={8} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 40 }}>加载中...</td></tr>}
                {!rulesLoading && rules.length === 0 && <tr><td colSpan={8} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 40 }}>No indicator rules configured. Click "+ New Rule" to create one.</td></tr>}
                {rules.filter(r => !rulesSearch || r.name.toLowerCase().includes(rulesSearch.toLowerCase()) || (r.mitre_tactic ?? '').toLowerCase().includes(rulesSearch.toLowerCase())).map(r => (
                  <tr key={r._key}>
                    <td style={{ fontSize: 12.5, fontWeight: 500 }}>{r.name}</td>
                    <td><span style={{ fontSize: 10.5, padding: '2px 7px', borderRadius: 3, background: 'rgba(79,163,224,.12)', color: 'var(--accent-blue)', textTransform: 'capitalize' }}>{r.rule_type || '-'}</span></td>
                    <td>
                      <span style={{ fontSize: 10.5, padding: '2px 7px', borderRadius: 3, textTransform: 'capitalize',
                        background: r.severity === 'critical' ? 'rgba(224,80,80,.12)' : r.severity === 'high' ? 'rgba(224,128,64,.12)' : r.severity === 'medium' ? 'rgba(200,160,48,.12)' : 'rgba(79,163,224,.12)',
                        color: r.severity === 'critical' ? 'var(--critical)' : r.severity === 'high' ? 'var(--high)' : r.severity === 'medium' ? 'var(--medium)' : 'var(--accent-blue)',
                      }}>{r.severity || 'medium'}</span>
                    </td>
                    <td style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{r.mitre_tactic || '-'}{r.mitre_technique ? ` / ${r.mitre_technique}` : ''}</td>
                    <td>
                      <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11.5 }}>
                        <span style={{ width: 6, height: 6, borderRadius: '50%', background: r.status === 'active' ? 'var(--accent-green)' : 'var(--text-muted)', boxShadow: r.status === 'active' ? '0 0 4px var(--accent-green)' : 'none' }} />
                        {r.status}
                      </span>
                    </td>
                    <td style={{ fontSize: 12, color: 'var(--text-secondary)', fontFamily: 'monospace' }}>{r.hit_count ?? 0}</td>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{fmtDate(r.created_at)}</td>
                    <td>
                      <div style={{ display: 'flex', gap: 4 }}>
                        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 7px', color: r.status === 'active' ? 'var(--high)' : 'var(--accent-green)' }} onClick={() => toggleRule(r)}>{r.status === 'active' ? 'Disable' : 'Enable'}</button>
                        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 7px' }} onClick={() => openEditRule(r)}>编辑</button>
                        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 7px', color: 'var(--critical)' }} onClick={() => deleteRule(r)}>删</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ===== SAMPLE ANALYSIS ===== */}
      {tab === 'samples' && (() => {
        const typeIcon: Record<string, string> = { hash: '🔐', domain: '🌐', ip: '📍', url: '🔗' }
        const filteredSamples = samplesVerdictFilter
          ? samples.filter(s => (s.verdict || 'unknown').toLowerCase() === samplesVerdictFilter)
          : samples
        return (
          <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>
            {/* Header with count */}
            <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 12 }}>
              <div style={{ flex: 1 }}>
                <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>
                  样本分析
                </span>
                <span style={{ marginLeft: 10, fontSize: 11, color: 'var(--text-muted)', background: 'var(--bg-card2)', border: '1px solid var(--border)', borderRadius: 10, padding: '1px 8px' }}>
                  共 {samples.length} 条
                </span>
                <span style={{ marginLeft: 6, fontSize: 11, color: 'var(--text-secondary)' }}>
                  提交 files and URLs for dynamic and static analysis in an isolated sandbox.
                </span>
              </div>
              <button className="btn-secondary" style={{ fontSize: 12, whiteSpace: 'nowrap' }} onClick={() => navigate('/iocs')}>
                + 添加 IOC
              </button>
            </div>
            {/* Verdict filter pills */}
            <div style={{ display: 'flex', gap: 6, marginBottom: 12, alignItems: 'center' }}>
              <span style={{ fontSize: 11, color: 'var(--text-muted)', marginRight: 4 }}>判定结论:</span>
              {[
                { key: '', label: '全部', color: 'var(--text-secondary)', bg: 'var(--bg-card2)', border: 'var(--border)' },
                { key: 'malicious', label: '🔴 恶意', color: 'var(--critical)', bg: 'rgba(224,80,80,.08)', border: 'rgba(224,80,80,.3)' },
                { key: 'suspicious', label: '🟠 可疑', color: 'var(--high)', bg: 'rgba(224,128,64,.08)', border: 'rgba(224,128,64,.3)' },
                { key: 'benign', label: '🟢 无害', color: 'var(--accent-green)', bg: 'rgba(47,176,122,.08)', border: 'rgba(47,176,122,.3)' },
                { key: 'unknown', label: '⚪ 未知', color: 'var(--text-muted)', bg: 'rgba(84,110,122,.08)', border: 'rgba(84,110,122,.3)' },
              ].map(v => (
                <button key={v.key} onClick={() => setSamplesVerdictFilter(v.key)} style={{
                  padding: '3px 12px', borderRadius: 20, fontSize: 11, cursor: 'pointer', border: `1px solid ${samplesVerdictFilter === v.key ? v.color : v.border}`,
                  background: samplesVerdictFilter === v.key ? v.bg : 'none',
                  color: samplesVerdictFilter === v.key ? v.color : 'var(--text-secondary)',
                  fontWeight: samplesVerdictFilter === v.key ? 600 : 400, transition: 'all .15s',
                }}>{v.label}</button>
              ))}
              {samplesVerdictFilter && (
                <span style={{ marginLeft: 4, fontSize: 11, color: 'var(--text-muted)' }}>
                  {filteredSamples.length} / {samples.length} 条
                </span>
              )}
            </div>
            <div className="data-table-wrap" style={{ flex: 'unset' }}>
              <table className="data-table">
                <thead>
                  <tr>
                    <th style={{ width: 32 }}>类型</th>
                    <th style={{ minWidth: 180 }}>Hash / 值</th>
                    <th>Threat Name</th>
                    <th>判定结论</th>
                    <th style={{ minWidth: 120 }}>置信度</th>
                    <th>Severity</th>
                    <th>Source</th>
                    <th>Tags</th>
                    <th>创建时间</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {samplesLoading && <tr><td colSpan={10} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 40 }}>加载中...</td></tr>}
                  {!samplesLoading && filteredSamples.length === 0 && (
                    <tr><td colSpan={10} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 40 }}>
                      {samplesVerdictFilter ? `无"${samplesVerdictFilter}"样本` : 'No IOC hash samples. Click "+ 提交样本" to submit one.'}
                    </td></tr>
                  )}
                  {filteredSamples.map(s => {
                    const conf = s.confidence ?? 0
                    const confColor = conf >= 80 ? 'var(--critical)' : conf >= 60 ? 'var(--high)' : conf >= 40 ? 'var(--medium)' : 'var(--accent-green)'
                    const iocType = (s as any).type as string | undefined
                    const icon = iocType ? (typeIcon[iocType] ?? '🔐') : '🔐'
                    return (
                      <tr key={s._key}>
                        <td style={{ fontSize: 15, textAlign: 'center' }} title={iocType}>{icon}</td>
                        <td style={{ fontFamily: 'monospace', fontSize: 10.5, color: 'var(--text-secondary)', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }} title={s.value}>
                          {s.value ? (s.value.length > 24 ? s.value.slice(0, 12) + '…' + s.value.slice(-8) : s.value) : '-'}
                        </td>
                        <td style={{ fontSize: 11.5, color: 'var(--text-primary)' }}>{s.threat_name || '-'}</td>
                        <td><判定结论Badge verdict={s.verdict || 'unknown'} /></td>
                        <td>
                          <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                            <div style={{ flex: 1, height: 5, background: 'var(--bg-card2)', borderRadius: 3, overflow: 'hidden', minWidth: 60 }}>
                              <div style={{ width: `${conf}%`, height: '100%', background: confColor, borderRadius: 3, transition: 'width .3s' }} />
                            </div>
                            <span style={{ fontSize: 11, color: confColor, fontWeight: 600, minWidth: 28 }}>{conf}%</span>
                          </div>
                        </td>
                        <td>
                          <span style={{ fontSize: 10.5, padding: '2px 7px', borderRadius: 3, textTransform: 'capitalize',
                            background: s.severity === 'critical' ? 'rgba(224,80,80,.12)' : s.severity === 'high' ? 'rgba(224,128,64,.12)' : s.severity === 'medium' ? 'rgba(200,160,48,.12)' : 'rgba(79,163,224,.12)',
                            color: s.severity === 'critical' ? 'var(--critical)' : s.severity === 'high' ? 'var(--high)' : s.severity === 'medium' ? 'var(--medium)' : 'var(--accent-blue)',
                          }}>{s.severity || '-'}</span>
                        </td>
                        <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{s.source_name || '-'}</td>
                        <td style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>{(s.tags ?? []).slice(0, 3).join(', ') || '-'}</td>
                        <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{fmtDate(s.created_at)}</td>
                        <td><button className="btn-secondary" style={{ fontSize: 11, padding: '2px 7px', color: 'var(--critical)' }} onClick={() => delete样本(s)}>删</button></td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        )
      })()}

      {/* ===== SESSIONS (Identity Risks) ===== */}
      {tab === 'sessions' && (
        <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
            <div style={{ flex: 1 }}>
              <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>身份会话风险</span>
              <span style={{ marginLeft: 10, fontSize: 11, color: 'var(--text-muted)', background: 'var(--bg-card2)', border: '1px solid var(--border)', borderRadius: 10, padding: '1px 8px' }}>
                共 {identityRisks.length} 个用户
              </span>
              <span style={{ marginLeft: 8, fontSize: 11, color: 'var(--text-secondary)' }}>
                · 基于行为基线的身份风险评估 · 异常会话检测
              </span>
            </div>
            <button className="btn-secondary" style={{ fontSize: 12, whiteSpace: 'nowrap' }} onClick={() => navigate('/identity-risks')}>
              查看详情 →
            </button>
          </div>
          <div className="data-table-wrap" style={{ flex: 'unset' }}>
            <table className="data-table">
              <thead>
                <tr>
                  <th>用户</th>
                  <th>域</th>
                  <th style={{ minWidth: 140 }}>风险评分</th>
                  <th>信号数</th>
                  <th>最近活动</th>
                  <th>状态</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {identityLoading && (
                  <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 40 }}>加载中...</td></tr>
                )}
                {!identityLoading && identityRisks.length === 0 && (
                  <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 40 }}>
                    暂无身份风险数据
                  </td></tr>
                )}
                {identityRisks.map(ir => {
                  const score = ir.risk_score ?? 0
                  const scoreColor = score >= 80 ? 'var(--critical)' : score >= 50 ? 'var(--high)' : score >= 30 ? 'var(--medium)' : 'var(--accent-green)'
                  const rowBg = score >= 80 ? 'rgba(224,80,80,.06)' : score >= 50 ? 'rgba(224,128,64,.05)' : 'transparent'
                  const signalCount = (ir.risk_signals ?? []).length
                  // Determine session status from risk score
                  const sessionStatus = score >= 80 ? 'suspended' : score >= 50 ? 'active' : 'normal'
                  const statusConfig: Record<string, { color: string; label: string; bg: string }> = {
                    suspended: { color: 'var(--critical)', label: '已挂起', bg: 'rgba(224,80,80,.12)' },
                    active: { color: 'var(--high)', label: '活跃', bg: 'rgba(224,128,64,.12)' },
                    normal: { color: 'var(--accent-green)', label: '正常', bg: 'rgba(47,176,122,.12)' },
                  }
                  const sc = statusConfig[sessionStatus]
                  return (
                    <tr key={ir._key} style={{ background: rowBg }}>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                          <div style={{
                            width: 28, height: 28, borderRadius: '50%', background: scoreColor + '22',
                            border: `1.5px solid ${scoreColor}55`, display: 'flex', alignItems: 'center',
                            justifyContent: 'center', fontSize: 11, fontWeight: 700, color: scoreColor, flexShrink: 0,
                          }}>
                            {(ir.username || ir.user_id || '?').slice(0, 2).toUpperCase()}
                          </div>
                          <div>
                            <div style={{ fontSize: 12.5, fontWeight: 500, color: 'var(--text-primary)' }}>{ir.username || ir.user_id || '-'}</div>
                            <div style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>{ir.user_id || ''}</div>
                          </div>
                        </div>
                      </td>
                      <td style={{ fontSize: 11, color: 'var(--text-secondary)' }}>{ir.domain || '-'}</td>
                      <td>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 7 }}>
                          <div style={{ width: 70, height: 5, background: 'var(--bg-card2)', borderRadius: 3, overflow: 'hidden' }}>
                            <div style={{ width: `${score}%`, height: '100%', background: scoreColor, borderRadius: 3, transition: 'width .3s' }} />
                          </div>
                          <span style={{ fontSize: 12, fontWeight: 700, color: scoreColor, minWidth: 28 }}>{score}</span>
                        </div>
                      </td>
                      <td>
                        <span style={{ fontSize: 12, color: signalCount > 0 ? 'var(--high)' : 'var(--text-muted)', fontWeight: signalCount > 0 ? 600 : 400 }}>
                          {signalCount > 0 ? `⚡ ${signalCount}` : '—'}
                        </span>
                      </td>
                      <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{fmtDate(ir.updated_at || ir.created_at)}</td>
                      <td>
                        <span style={{ fontSize: 10.5, padding: '2px 8px', borderRadius: 3, fontWeight: 600, background: sc.bg, color: sc.color }}>{sc.label}</span>
                      </td>
                      <td>
                        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px', whiteSpace: 'nowrap' }}
                          onClick={() => navigate('/identity-risks')}>查看详情 →</button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ===== TIM REPORTS ===== */}
      {tab === 'reports' && (
        <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
            <div style={{ fontSize: 12, color: 'var(--text-secondary)', flex: 1 }}>
              Threat intelligence reports, executive summaries, indicator trends, and feed health metrics.
            </div>
            <button className="btn-secondary" style={{ fontSize: 12, whiteSpace: 'nowrap' }} onClick={() => navigate('/reports')}>
              生成报告
            </button>
          </div>
          <div className="data-table-wrap" style={{ flex: 'unset' }}>
            <table className="data-table">
              <thead><tr><th>Report Name</th><th>模板类型</th><th>状态</th><th>Description</th><th>创建时间</th><th></th></tr></thead>
              <tbody>
                {reportsLoading && <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 40 }}>加载中...</td></tr>}
                {!reportsLoading && reports.length === 0 && <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 40 }}>暂无报告. Click "+ 创建报告" to generate one.</td></tr>}
                {reports.map(r => (
                  <tr key={r._key}>
                    <td style={{ fontSize: 12.5, fontWeight: 500 }}>
                      {r.download_url
                        ? <a href={r.download_url} target="_blank" rel="noreferrer" style={{ color: 'var(--accent-blue)', textDecoration: 'none' }}>{r.name}</a>
                        : r.name}
                    </td>
                    <td><span style={{ fontSize: 10.5, padding: '2px 7px', background: 'var(--bg-card2)', border: '1px solid var(--border-light)', borderRadius: 3, textTransform: 'capitalize' }}>{r.template_type || 'custom'}</span></td>
                    <td><span style={{ fontSize: 11, color: r.status === 'ready' ? 'var(--accent-green)' : r.status === 'generating' ? 'var(--accent-blue)' : 'var(--text-muted)', textTransform: 'capitalize' }}>{r.status || 'draft'}</span></td>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>{r.description || '-'}</td>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{fmtDate(r.created_at)}</td>
                    <td><button className="btn-secondary" style={{ fontSize: 11, padding: '2px 7px', color: 'var(--critical)' }} onClick={() => deleteReport(r)}>删</button></td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ===== THREAT RESPONSE CENTER ===== */}
      {tab === 'trc' && (
        <div style={{ flex: 1, overflow: 'hidden', display: 'flex', flexDirection: 'column' }}>
          {/* TRC Stats Bar */}
          <div style={{ display: 'flex', gap: 10, padding: '10px 20px', borderBottom: '1px solid var(--border)', flexShrink: 0, background: 'var(--bg-primary)' }}>
            {[
              {
                label: '活跃威胁',
                value: trcLoading ? '…' : trcIncidents.length,
                color: trcIncidents.length > 0 ? 'var(--critical)' : 'var(--accent-green)',
                bg: trcIncidents.length > 0 ? 'rgba(224,80,80,.08)' : 'rgba(47,176,122,.08)',
                border: trcIncidents.length > 0 ? 'rgba(224,80,80,.25)' : 'rgba(47,176,122,.25)',
                icon: '🔥',
              },
              {
                label: '今日已解决',
                value: trcStats.resolvedToday,
                color: 'var(--accent-green)',
                bg: 'rgba(47,176,122,.08)',
                border: 'rgba(47,176,122,.25)',
                icon: '✅',
              },
              {
                label: 'MTTR (平均响应时间)',
                value: trcStats.mttrHours > 0 ? `${trcStats.mttrHours}h` : '—',
                color: trcStats.mttrHours > 24 ? 'var(--critical)' : trcStats.mttrHours > 8 ? 'var(--high)' : 'var(--accent-green)',
                bg: 'rgba(79,163,224,.08)',
                border: 'rgba(79,163,224,.25)',
                icon: '⏱',
              },
            ].map(stat => (
              <div key={stat.label} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '7px 14px', background: stat.bg, border: `1px solid ${stat.border}`, borderRadius: 8, minWidth: 160 }}>
                <span style={{ fontSize: 18 }}>{stat.icon}</span>
                <div>
                  <div style={{ fontSize: 18, fontWeight: 700, color: stat.color, lineHeight: 1.1 }}>{stat.value}</div>
                  <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginTop: 1 }}>{stat.label}</div>
                </div>
              </div>
            ))}
            <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center' }}>
              <button className="btn-secondary" style={{ fontSize: 11 }} onClick={loadTrcIncidents}>↻ 刷新</button>
            </div>
          </div>

          {/* Campaign Tracker */}
          <div style={{ padding: '12px 20px', borderBottom: '1px solid var(--border)', flexShrink: 0, background: 'var(--bg-primary)' }}>
            <div style={{ fontSize: 11.5, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 10 }}>
              📌 攻击活动追踪
            </div>
            <div style={{ display: 'flex', gap: 10, overflowX: 'auto', paddingBottom: 4 }}>
              {MOCK_CAMPAIGNS.map(c => {
                const cfg = CAMPAIGN_STATUS_CONFIG[c.status]
                const start = new Date(c.startDate)
                const nowMs = Date.now()
                const daysActive = Math.floor((nowMs - start.getTime()) / 86400000)
                const progressPct = Math.min(100, Math.round((daysActive / c.expectedDays) * 100))
                return (
                  <div key={c.id} style={{
                    minWidth: 300, flexShrink: 0,
                    padding: '10px 14px',
                    background: 'var(--bg-card)',
                    border: `1px solid ${cfg.border}`,
                    borderTop: `3px solid ${cfg.color}`,
                    borderRadius: 7,
                    display: 'flex', flexDirection: 'column', gap: 7,
                  }}>
                    {/* Header row */}
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start', gap: 6 }}>
                      <div style={{ fontSize: 12.5, fontWeight: 700, color: 'var(--text-primary)', flex: 1 }}>{c.name}</div>
                      <span style={{ fontSize: 9.5, padding: '2px 7px', borderRadius: 3, fontWeight: 700, background: cfg.bg, color: cfg.color, whiteSpace: 'nowrap' }}>
                        {cfg.label}
                      </span>
                    </div>
                    <div style={{ fontSize: 10.5, color: 'var(--text-secondary)', lineHeight: 1.4 }}>{c.description}</div>

                    {/* Progress bar: days active vs expected */}
                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'var(--text-muted)', marginBottom: 3 }}>
                        <span>活动进度</span>
                        <span style={{ color: progressPct >= 100 ? 'var(--critical)' : cfg.color, fontWeight: 600 }}>{daysActive}d / {c.expectedDays}d ({progressPct}%)</span>
                      </div>
                      <div style={{ height: 5, background: 'var(--bg-card2)', borderRadius: 3, overflow: 'hidden' }}>
                        <div style={{
                          height: '100%', width: `${progressPct}%`,
                          background: progressPct >= 100 ? 'var(--critical)' : cfg.color,
                          borderRadius: 3, transition: 'width .3s',
                        }} />
                      </div>
                    </div>

                    {/* Kill chain stage indicator */}
                    <div>
                      <div style={{ fontSize: 10, color: 'var(--text-muted)', marginBottom: 4, fontWeight: 600, textTransform: 'uppercase', letterSpacing: .4 }}>杀伤链阶段</div>
                      <div style={{ display: 'flex', gap: 2, alignItems: 'center' }}>
                        {ALL_KILL_CHAIN.map((stage, idx) => {
                          const confirmed = c.killChain.includes(stage)
                          return (
                            <div key={stage} style={{ display: 'flex', alignItems: 'center', gap: 2 }}>
                              {idx > 0 && (
                                <div style={{ width: 6, height: 1.5, background: confirmed ? cfg.color : 'var(--border)', opacity: confirmed ? 1 : .4 }} />
                              )}
                              <div title={stage} style={{
                                fontSize: 8, padding: '2px 4px', borderRadius: 3, fontWeight: 700, whiteSpace: 'nowrap',
                                background: confirmed ? `${cfg.color}22` : 'var(--bg-card2)',
                                color: confirmed ? cfg.color : 'var(--text-muted)',
                                border: `1px solid ${confirmed ? cfg.color + '55' : 'var(--border)'}`,
                                opacity: confirmed ? 1 : .45,
                              }}>{stage.slice(0, 3)}</div>
                            </div>
                          )
                        })}
                      </div>
                    </div>

                    {/* Counts row */}
                    <div style={{ display: 'flex', gap: 10, fontSize: 10.5 }}>
                      <span style={{ color: 'var(--text-muted)' }}>
                        关联事件: <strong style={{ color: cfg.color }}>{c.relatedIncidents}</strong>
                      </span>
                      <span style={{ color: 'var(--text-muted)' }}>
                        受影响资产: <strong style={{ color: c.affectedAssets > 20 ? 'var(--critical)' : c.affectedAssets > 10 ? 'var(--high)' : 'var(--accent-green)' }}>{c.affectedAssets}</strong>
                      </span>
                    </div>

                    <div style={{ display: 'flex', justifyContent: 'space-between', fontSize: 10, color: 'var(--text-muted)' }}>
                      <span>{c.startDate}{c.endDate ? ` → ${c.endDate}` : ' → 至今'}</span>
                    </div>
                    <button
                      onClick={() => navigate(`/incidents?keyword=${encodeURIComponent(c.name)}`)}
                      style={{ fontSize: 10.5, padding: '4px 10px', background: cfg.bg, border: `1px solid ${cfg.border}`, borderRadius: 4, color: cfg.color, cursor: 'pointer', textAlign: 'center', fontWeight: 600 }}
                    >
                      查看相关事件 →
                    </button>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Main TRC layout: left = active threats, right = quick response */}
          <div style={{ flex: 1, overflow: 'hidden', display: 'flex', gap: 0 }}>

            {/* Left panel: 活跃威胁 list */}
            <div style={{ flex: 1, overflowY: 'auto', padding: '16px 16px 16px 20px', borderRight: '1px solid var(--border)' }}>
              <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 12 }}>
                活跃威胁 · {trcLoading ? '加载中' : `${trcIncidents.length} 个未解决事件`}
              </div>

              {trcLoading && (
                <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 40 }}>加载中...</div>
              )}

              {!trcLoading && trcIncidents.length === 0 && (
                <div style={{ textAlign: 'center', padding: 40 }}>
                  <div style={{ fontSize: 32, marginBottom: 8 }}>✅</div>
                  <div style={{ fontSize: 13, color: 'var(--accent-green)', fontWeight: 600 }}>暂无活跃威胁</div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 4 }}>所有事件均已解决或关闭</div>
                </div>
              )}

              <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                {trcIncidents.map(inc => {
                  const sev = inc.severity?.toLowerCase() ?? 'medium'
                  const sevColor = sev === 'critical' ? 'var(--critical)' : sev === 'high' ? 'var(--high)' : sev === 'medium' ? 'var(--medium)' : 'var(--accent-green)'
                  const sevBorder = sev === 'critical' ? 'rgba(224,80,80,.3)' : sev === 'high' ? 'rgba(224,128,64,.25)' : 'rgba(200,160,48,.2)'
                  const smart = inc.smart_score
                  return (
                    <div key={inc._key} style={{
                      padding: '12px 14px', background: 'var(--bg-card)', borderRadius: 7,
                      border: `1px solid ${sevBorder}`,
                      borderLeft: `3px solid ${sevColor}`,
                      cursor: 'pointer', transition: 'background .15s',
                    }}
                      onClick={() => navigate('/incidents')}
                    >
                      <div style={{ display: 'flex', alignItems: 'flex-start', justifyContent: 'space-between', gap: 8, marginBottom: 6 }}>
                        <div style={{ flex: 1, fontSize: 12.5, fontWeight: 600, lineHeight: 1.35, color: 'var(--text-primary)' }}>
                          {inc.title}
                        </div>
                        <div style={{ display: 'flex', gap: 5, flexShrink: 0, alignItems: 'center' }}>
                          <span style={{ fontSize: 9.5, padding: '2px 7px', borderRadius: 3, fontWeight: 700, textTransform: 'uppercase', background: `${sevColor}22`, color: sevColor }}>
                            {sev}
                          </span>
                          {smart != null && (
                            <span style={{ fontSize: 10, padding: '2px 7px', borderRadius: 3, fontWeight: 600, background: 'rgba(79,163,224,.12)', color: 'var(--accent-blue)' }}>
                              ⚡ {smart}
                            </span>
                          )}
                        </div>
                      </div>
                      <div style={{ display: 'flex', gap: 10, fontSize: 10.5, color: 'var(--text-muted)' }}>
                        <span style={{ background: 'rgba(79,163,224,.08)', color: 'var(--accent-blue)', padding: '1px 6px', borderRadius: 3 }}>
                          {inc.status}
                        </span>
                        {inc.alert_count != null && (
                          <span>告警: <strong style={{ color: 'var(--text-secondary)' }}>{inc.alert_count}</strong></span>
                        )}
                        <span>{fmtDate(inc.created_at)}</span>
                        {inc.assigned_to && <span>→ {inc.assigned_to}</span>}
                      </div>
                    </div>
                  )
                })}
              </div>

              {/* Static reference events if no live data */}
              {!trcLoading && trcIncidents.length === 0 && (
                <div style={{ marginTop: 16 }}>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8 }}>全球威胁参考（示例）</div>
                  {威胁响应中心_EVENTS.map(t => (
                    <div key={t.title} style={{ padding: '12px 14px', background: 'var(--bg-card)', borderRadius: 7, border: `1px solid ${t.sev === 'critical' ? 'rgba(229,57,53,.25)' : 'rgba(255,111,0,.2)'}`, borderLeft: `3px solid ${t.sev === 'critical' ? 'var(--critical)' : 'var(--high)'}`, marginBottom: 8 }}>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                        <div style={{ fontSize: 12, fontWeight: 600 }}>{t.title}</div>
                        <span className={`sev-badge ${t.sev}`}>{t.sev}</span>
                      </div>
                      <div style={{ fontSize: 11, color: 'var(--text-secondary)', marginBottom: 8 }}>{t.desc}</div>
                      <div style={{ display: 'flex', gap: 10, fontSize: 10.5, color: 'var(--text-muted)', marginBottom: 8 }}>
                        <span>IOCs: <strong style={{ color: 'var(--text-primary)' }}>{t.iocs}</strong></span>
                        <span>影响资产: <strong style={{ color: t.assets > 0 ? 'var(--critical)' : 'var(--text-primary)' }}>{t.assets}</strong></span>
                        <span>{t.date}</span>
                      </div>
                      <div style={{ display: 'flex', gap: 6 }}>
                        <button className="btn-primary" style={{ fontSize: 10.5 }} onClick={() => trcInvestigate(t.title)}>调查分析 →</button>
                        <button className="btn-secondary" style={{ fontSize: 10.5 }} disabled={blockingTrc === t.title} onClick={() => trcBlockIOCs(t.title)}>{blockingTrc === t.title ? '封锁中...' : '封锁IOC'}</button>
                        <button className="btn-secondary" style={{ fontSize: 10.5 }} onClick={() => trcCreateRule(t.title)}>创建规则</button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Right panel: 快速响应 */}
            <div style={{ width: 260, flexShrink: 0, overflowY: 'auto', padding: '16px 20px 16px 16px', display: 'flex', flexDirection: 'column', gap: 16 }}>
              {/* Quick response actions */}
              <div>
                <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 10 }}>
                  快速响应
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 7 }}>
                  {[
                    { label: '隔离主机 →', path: '/actions', color: 'var(--critical)', bg: 'rgba(224,80,80,.08)', border: 'rgba(224,80,80,.25)', icon: '🔒' },
                    { label: '封锁 IOC →', path: '/iocs', color: 'var(--high)', bg: 'rgba(224,128,64,.08)', border: 'rgba(224,128,64,.25)', icon: '🛡️' },
                    { label: '查看事件 →', path: '/incidents', color: 'var(--accent-blue)', bg: 'rgba(79,163,224,.08)', border: 'rgba(79,163,224,.25)', icon: '🔎' },
                  ].map(action => (
                    <button key={action.label}
                      onClick={() => navigate(action.path)}
                      style={{
                        display: 'flex', alignItems: 'center', gap: 10, padding: '10px 14px',
                        background: action.bg, border: `1px solid ${action.border}`, borderRadius: 7,
                        cursor: 'pointer', textAlign: 'left', transition: 'all .15s', width: '100%',
                        color: action.color, fontSize: 12.5, fontWeight: 600,
                      }}
                    >
                      <span style={{ fontSize: 16 }}>{action.icon}</span>
                      {action.label}
                    </button>
                  ))}
                </div>
              </div>

              {/* 威胁响应统计 */}
              <div>
                <div style={{ fontSize: 12, fontWeight: 600, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: 1, marginBottom: 10 }}>
                  威胁响应统计
                </div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  <div style={{ padding: '10px 14px', background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 7 }}>
                    <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginBottom: 4 }}>今日已解决事件</div>
                    <div style={{ fontSize: 22, fontWeight: 700, color: trcStats.resolvedToday > 0 ? 'var(--accent-green)' : 'var(--text-secondary)' }}>
                      {trcStats.resolvedToday}
                    </div>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>件 · {new Date().toLocaleDateString('zh-CN')}</div>
                  </div>
                  <div style={{ padding: '10px 14px', background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 7 }}>
                    <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginBottom: 4 }}>平均响应时间 (MTTR)</div>
                    <div style={{ fontSize: 22, fontWeight: 700, color: trcStats.mttrHours > 24 ? 'var(--critical)' : trcStats.mttrHours > 8 ? 'var(--high)' : 'var(--accent-green)' }}>
                      {trcStats.mttrHours > 0 ? `${trcStats.mttrHours}h` : '—'}
                    </div>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
                      {trcStats.mttrHours <= 8 ? '响应迅速' : trcStats.mttrHours <= 24 ? '需要提速' : '响应偏慢'}
                    </div>
                  </div>
                  <div style={{ padding: '10px 14px', background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 7 }}>
                    <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginBottom: 4 }}>当前活跃威胁</div>
                    <div style={{ fontSize: 22, fontWeight: 700, color: trcIncidents.length > 0 ? 'var(--critical)' : 'var(--accent-green)' }}>
                      {trcLoading ? '…' : trcIncidents.length}
                    </div>
                    <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 2 }}>
                      {trcIncidents.length === 0 ? '无活跃事件' : `${trcIncidents.filter(i => i.severity === 'critical').length} 个严重级别`}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      )}

      {/* ===== THREAT ACTOR PROFILES ===== */}
      {tab === 'actors' && (
        <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>
          {/* Header + filter */}
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
            <div style={{ flex: 1 }}>
              <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>威胁行为者档案</span>
              <span style={{ marginLeft: 10, fontSize: 11, color: 'var(--text-muted)', background: 'var(--bg-card2)', border: '1px solid var(--border)', borderRadius: 10, padding: '1px 8px' }}>
                {THREAT_ACTORS.length} 个已知 APT 组织
              </span>
            </div>
            <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
              {[
                { key: '', label: '全部' },
                { key: 'espionage', label: '情报窃取' },
                { key: 'financial', label: '经济利益' },
                { key: 'ransomware', label: '勒索软件' },
                { key: 'social engineering', label: '社会工程' },
              ].map(f => {
                const mc = MOTIVATION_CONFIG[f.key]
                return (
                  <button key={f.key} onClick={() => setActorMotivationFilter(f.key)} style={{
                    padding: '3px 12px', borderRadius: 20, fontSize: 11, cursor: 'pointer',
                    border: `1px solid ${actorMotivationFilter === f.key ? (mc?.color ?? 'var(--accent-blue)') : 'var(--border)'}`,
                    background: actorMotivationFilter === f.key ? (mc?.bg ?? 'rgba(79,163,224,.1)') : 'none',
                    color: actorMotivationFilter === f.key ? (mc?.color ?? 'var(--accent-blue)') : 'var(--text-secondary)',
                    fontWeight: actorMotivationFilter === f.key ? 600 : 400, transition: 'all .15s',
                  }}>{f.label}</button>
                )
              })}
            </div>
          </div>

          {/* Actor cards grid */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fill, minmax(340px, 1fr))', gap: 14 }}>
            {THREAT_ACTORS
              .filter(a => !actorMotivationFilter || a.motivation === actorMotivationFilter)
              .map(actor => {
                const mc = MOTIVATION_CONFIG[actor.motivation] ?? MOTIVATION_CONFIG.espionage
                const isActive = actor.status === 'Active'
                return (
                  <div
                    key={actor.id}
                    onClick={() => setSelectedActor(actor)}
                    style={{
                      padding: '14px 16px',
                      background: 'var(--bg-card)',
                      border: `1px solid ${isActive ? 'rgba(224,80,80,.2)' : 'var(--border)'}`,
                      borderLeft: `3px solid ${isActive ? 'var(--critical)' : 'var(--text-muted)'}`,
                      borderRadius: 8,
                      cursor: 'pointer',
                      transition: 'background .15s, box-shadow .15s',
                      display: 'flex', flexDirection: 'column', gap: 10,
                    }}
                    onMouseEnter={e => (e.currentTarget.style.boxShadow = '0 2px 12px rgba(0,0,0,.2)')}
                    onMouseLeave={e => (e.currentTarget.style.boxShadow = 'none')}
                  >
                    {/* Top row: name + country + status */}
                    <div style={{ display: 'flex', alignItems: 'flex-start', gap: 10 }}>
                      <div style={{
                        width: 40, height: 40, borderRadius: 8,
                        background: mc.bg, border: `1.5px solid ${mc.color}44`,
                        display: 'flex', alignItems: 'center', justifyContent: 'center',
                        fontSize: 20, flexShrink: 0,
                      }}>
                        {actor.flag}
                      </div>
                      <div style={{ flex: 1, minWidth: 0 }}>
                        <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap' }}>
                          <span style={{ fontSize: 14, fontWeight: 700, color: 'var(--text-primary)' }}>{actor.name}</span>
                          <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>({actor.alias})</span>
                        </div>
                        <div style={{ display: 'flex', gap: 6, marginTop: 4, flexWrap: 'wrap', alignItems: 'center' }}>
                          <span style={{ fontSize: 10.5, padding: '2px 8px', borderRadius: 3, background: mc.bg, color: mc.color, fontWeight: 600 }}>
                            {mc.label}
                          </span>
                          <span style={{ fontSize: 10.5, color: 'var(--text-secondary)' }}>{actor.country}</span>
                          <span style={{ display: 'inline-flex', alignItems: 'center', gap: 4, fontSize: 10.5 }}>
                            <span style={{ width: 6, height: 6, borderRadius: '50%', background: isActive ? 'var(--accent-green)' : 'var(--text-muted)', boxShadow: isActive ? '0 0 4px rgba(47,176,122,.7)' : 'none', display: 'inline-block' }} />
                            <span style={{ color: isActive ? 'var(--accent-green)' : 'var(--text-muted)', fontWeight: 600 }}>{actor.status}</span>
                          </span>
                        </div>
                      </div>
                    </div>

                    {/* TTPs */}
                    <div>
                      <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 600, textTransform: 'uppercase', letterSpacing: .5, marginBottom: 5 }}>
                        已知 TTPs
                      </div>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                        {actor.ttps.slice(0, 4).map(t => (
                          <span key={t} style={{
                            fontSize: 10, padding: '2px 7px', borderRadius: 3,
                            background: 'var(--bg-card2)', border: '1px solid var(--border-light)',
                            color: 'var(--text-secondary)', fontFamily: 'monospace',
                          }}>{t}</span>
                        ))}
                      </div>
                    </div>

                    {/* Footer: last activity + targets */}
                    <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginTop: 2 }}>
                      <span style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>
                        最近活动: <strong style={{ color: isActive ? 'var(--high)' : 'var(--text-secondary)' }}>{daysAgo(actor.lastActivity)}</strong>
                      </span>
                      <span style={{ fontSize: 10, color: 'var(--accent-blue)', cursor: 'pointer' }}>查看详情 →</span>
                    </div>
                  </div>
                )
              })}
          </div>
        </div>
      )}

      {/* ===== THREAT INTEL GRAPH ===== */}
      {tab === 'graph' && (
        <div style={{ flex: 1, overflowY: 'auto', padding: 20 }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 16 }}>
            <div style={{ flex: 1 }}>
              <span style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>情报图谱</span>
              <span style={{ marginLeft: 10, fontSize: 11, color: 'var(--text-muted)', background: 'var(--bg-card2)', border: '1px solid var(--border)', borderRadius: 10, padding: '1px 8px' }}>
                威胁行为者 · 恶意软件 · 攻击活动 关系图
              </span>
            </div>
            {/* Legend */}
            <div style={{ display: 'flex', gap: 14, alignItems: 'center', fontSize: 11, color: 'var(--text-muted)' }}>
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                <svg width="14" height="14" viewBox="0 0 14 14"><polygon points="7,1 13,7 7,13 1,7" fill="rgba(224,80,80,.7)" stroke="#c04040" strokeWidth="1.2" /></svg>
                威胁行为者
              </span>
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                <svg width="14" height="14" viewBox="0 0 14 14"><circle cx="7" cy="7" r="5.5" fill="rgba(224,128,64,.7)" stroke="#c07030" strokeWidth="1.2" /></svg>
                恶意软件
              </span>
              <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5 }}>
                <svg width="14" height="14" viewBox="0 0 14 14"><rect x="1" y="3" width="12" height="8" rx="2" fill="rgba(79,163,224,.7)" stroke="var(--accent-blue)" strokeWidth="1.2" /></svg>
                攻击活动
              </span>
            </div>
          </div>

          <div style={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 10, overflow: 'hidden' }}>
            {/* SVG graph */}
            <svg
              viewBox="0 0 900 520"
              style={{ width: '100%', display: 'block', userSelect: 'none' }}
              xmlns="http://www.w3.org/2000/svg"
            >
              {/* Background grid */}
              <defs>
                <pattern id="grid" width="40" height="40" patternUnits="userSpaceOnUse">
                  <path d="M 40 0 L 0 0 0 40" fill="none" stroke="rgba(255,255,255,0.03)" strokeWidth="1" />
                </pattern>
                <marker id="arrow" markerWidth="7" markerHeight="7" refX="6" refY="3.5" orient="auto">
                  <polygon points="0 0, 7 3.5, 0 7" fill="rgba(144,164,174,0.5)" />
                </marker>
              </defs>
              <rect width="900" height="520" fill="var(--bg-card)" />
              <rect width="900" height="520" fill="url(#grid)" />

              {/* ── edges ── */}
              {/* APT29 → WellMess */}
              <line x1="160" y1="130" x2="340" y2="220" stroke="rgba(239,83,80,0.35)" strokeWidth="1.5" markerEnd="url(#arrow)" />
              {/* APT29 → CozyDuke */}
              <line x1="160" y1="130" x2="330" y2="310" stroke="rgba(239,83,80,0.35)" strokeWidth="1.5" markerEnd="url(#arrow)" />
              {/* APT29 → APT29 Spear Phishing campaign */}
              <line x1="160" y1="130" x2="590" y2="100" stroke="rgba(239,83,80,0.25)" strokeWidth="1.3" strokeDasharray="5,3" markerEnd="url(#arrow)" />
              {/* APT29 → CloudHopper Redux campaign */}
              <line x1="160" y1="130" x2="600" y2="220" stroke="rgba(239,83,80,0.25)" strokeWidth="1.3" strokeDasharray="5,3" markerEnd="url(#arrow)" />

              {/* APT41 → PlugX */}
              <line x1="150" y1="270" x2="330" y2="220" stroke="rgba(249,168,37,0.4)" strokeWidth="1.5" markerEnd="url(#arrow)" />
              {/* APT41 → ShadowPad */}
              <line x1="150" y1="270" x2="320" y2="380" stroke="rgba(249,168,37,0.4)" strokeWidth="1.5" markerEnd="url(#arrow)" />
              {/* APT41 → Operation BlackShadow campaign */}
              <line x1="150" y1="270" x2="598" y2="340" stroke="rgba(249,168,37,0.25)" strokeWidth="1.3" strokeDasharray="5,3" markerEnd="url(#arrow)" />

              {/* Lazarus → BLINDINGCAN */}
              <line x1="155" y1="420" x2="340" y2="310" stroke="rgba(167,139,250,0.4)" strokeWidth="1.5" markerEnd="url(#arrow)" />
              {/* Lazarus → AppleJeus */}
              <line x1="155" y1="420" x2="350" y2="430" stroke="rgba(167,139,250,0.4)" strokeWidth="1.5" markerEnd="url(#arrow)" />
              {/* Lazarus → Operation AppleJeus campaign */}
              <line x1="155" y1="420" x2="594" y2="450" stroke="rgba(167,139,250,0.25)" strokeWidth="1.3" strokeDasharray="5,3" markerEnd="url(#arrow)" />

              {/* WellMess → SolarStrike campaign */}
              <line x1="340" y1="220" x2="590" y2="100" stroke="rgba(255,167,38,0.2)" strokeWidth="1" strokeDasharray="4,3" markerEnd="url(#arrow)" />
              {/* PlugX → Operation BlackShadow campaign */}
              <line x1="330" y1="220" x2="598" y2="340" stroke="rgba(255,167,38,0.2)" strokeWidth="1" strokeDasharray="4,3" markerEnd="url(#arrow)" />

              {/* edge labels */}
              <text x="238" y="164" fontSize="9" fill="rgba(144,164,174,0.7)" textAnchor="middle">uses</text>
              <text x="230" y="245" fontSize="9" fill="rgba(144,164,174,0.7)" textAnchor="middle">uses</text>
              <text x="228" y="290" fontSize="9" fill="rgba(144,164,174,0.7)" textAnchor="middle">uses</text>
              <text x="240" y="350" fontSize="9" fill="rgba(144,164,174,0.7)" textAnchor="middle">uses</text>
              <text x="240" y="435" fontSize="9" fill="rgba(144,164,174,0.7)" textAnchor="middle">uses</text>
              <text x="255" y="400" fontSize="9" fill="rgba(144,164,174,0.7)" textAnchor="middle">uses</text>
              <text x="375" y="105" fontSize="9" fill="rgba(144,164,174,0.55)" textAnchor="middle">part of</text>
              <text x="375" y="190" fontSize="9" fill="rgba(144,164,174,0.55)" textAnchor="middle">part of</text>
              <text x="382" y="318" fontSize="9" fill="rgba(144,164,174,0.55)" textAnchor="middle">part of</text>
              <text x="385" y="440" fontSize="9" fill="rgba(144,164,174,0.55)" textAnchor="middle">part of</text>

              {/* ── THREAT ACTOR nodes (red diamond) ── */}
              {/* APT29 */}
              <g transform="translate(160,130)">
                <polygon points="0,-38 38,0 0,38 -38,0" fill="rgba(224,80,80,0.18)" stroke="#c04040" strokeWidth="2" />
                <text y="-46" textAnchor="middle" fontSize="11.5" fontWeight="700" fill="#c04040">APT29</text>
                <text y="-33" textAnchor="middle" fontSize="9" fill="rgba(144,164,174,0.8)">Cozy Bear</text>
                <text y="54" textAnchor="middle" fontSize="9" fill="rgba(144,164,174,0.65)">🇷🇺 Russia · Espionage</text>
              </g>

              {/* APT41 */}
              <g transform="translate(150,270)">
                <polygon points="0,-36 36,0 0,36 -36,0" fill="rgba(200,160,48,0.18)" stroke="#a88028" strokeWidth="2" />
                <text y="-44" textAnchor="middle" fontSize="11.5" fontWeight="700" fill="#a88028">APT41</text>
                <text y="-31" textAnchor="middle" fontSize="9" fill="rgba(144,164,174,0.8)">Double Dragon</text>
                <text y="52" textAnchor="middle" fontSize="9" fill="rgba(144,164,174,0.65)">🇨🇳 China · Financial</text>
              </g>

              {/* Lazarus */}
              <g transform="translate(155,420)">
                <polygon points="0,-36 36,0 0,36 -36,0" fill="rgba(167,139,250,0.18)" stroke="#a78bfa" strokeWidth="2" />
                <text y="-44" textAnchor="middle" fontSize="11.5" fontWeight="700" fill="#a78bfa">Lazarus</text>
                <text y="-31" textAnchor="middle" fontSize="9" fill="rgba(144,164,174,0.8)">Hidden Cobra</text>
                <text y="52" textAnchor="middle" fontSize="9" fill="rgba(144,164,174,0.65)">🇰🇵 DPRK · Financial</text>
              </g>

              {/* ── MALWARE nodes (orange circle) ── */}
              {/* WellMess */}
              <g transform="translate(340,220)">
                <circle r="28" fill="rgba(224,128,64,0.15)" stroke="#c07030" strokeWidth="1.8" />
                <text textAnchor="middle" dy="4" fontSize="10.5" fontWeight="600" fill="#c07030">WellMess</text>
                <text y="40" textAnchor="middle" fontSize="8.5" fill="rgba(144,164,174,0.7)">Backdoor</text>
              </g>

              {/* CozyDuke */}
              <g transform="translate(330,310)">
                <circle r="26" fill="rgba(224,128,64,0.15)" stroke="#c07030" strokeWidth="1.8" />
                <text textAnchor="middle" dy="4" fontSize="10.5" fontWeight="600" fill="#c07030">CozyDuke</text>
                <text y="38" textAnchor="middle" fontSize="8.5" fill="rgba(144,164,174,0.7)">RAT</text>
              </g>

              {/* PlugX */}
              <g transform="translate(460,200)">
                <circle r="26" fill="rgba(224,128,64,0.15)" stroke="#c07030" strokeWidth="1.8" />
                <text textAnchor="middle" dy="4" fontSize="10.5" fontWeight="600" fill="#c07030">PlugX</text>
                <text y="38" textAnchor="middle" fontSize="8.5" fill="rgba(144,164,174,0.7)">RAT / Loader</text>
              </g>

              {/* ShadowPad */}
              <g transform="translate(320,380)">
                <circle r="28" fill="rgba(224,128,64,0.15)" stroke="#c07030" strokeWidth="1.8" />
                <text textAnchor="middle" dy="4" fontSize="10.5" fontWeight="600" fill="#c07030">ShadowPad</text>
                <text y="40" textAnchor="middle" fontSize="8.5" fill="rgba(144,164,174,0.7)">Modular RAT</text>
              </g>

              {/* BLINDINGCAN */}
              <g transform="translate(340,440)">
                <circle r="30" fill="rgba(224,128,64,0.15)" stroke="#c07030" strokeWidth="1.8" />
                <text textAnchor="middle" dy="4" fontSize="10" fontWeight="600" fill="#c07030">BLINDINGCAN</text>
                <text y="42" textAnchor="middle" fontSize="8.5" fill="rgba(144,164,174,0.7)">Backdoor</text>
              </g>

              {/* AppleJeus */}
              <g transform="translate(350,330)">
                <circle r="26" fill="rgba(224,128,64,0.15)" stroke="#c07030" strokeWidth="1.8" />
                <text textAnchor="middle" dy="4" fontSize="10.5" fontWeight="600" fill="#c07030">AppleJeus</text>
                <text y="38" textAnchor="middle" fontSize="8.5" fill="rgba(144,164,174,0.7)">Trojan</text>
              </g>

              {/* ── CAMPAIGN nodes (blue rectangle) ── */}
              {/* APT29 Spear Phishing */}
              <g transform="translate(620,100)">
                <rect x="-82" y="-22" width="164" height="44" rx="6" fill="rgba(79,163,224,0.12)" stroke="var(--accent-blue)" strokeWidth="1.6" />
                <text textAnchor="middle" dy="-3" fontSize="10" fontWeight="600" fill="var(--accent-blue)">APT29 Spear</text>
                <text textAnchor="middle" dy="11" fontSize="10" fontWeight="600" fill="var(--accent-blue)">Phishing Campaign</text>
                <text y="32" textAnchor="middle" fontSize="8.5" fill="rgba(144,164,174,0.7)">2026-05-10 · High</text>
              </g>

              {/* SolarStrike */}
              <g transform="translate(650,210)">
                <rect x="-80" y="-22" width="160" height="44" rx="6" fill="rgba(79,163,224,0.12)" stroke="var(--accent-blue)" strokeWidth="1.6" />
                <text textAnchor="middle" dy="-3" fontSize="10" fontWeight="600" fill="var(--accent-blue)">SolarStrike</text>
                <text textAnchor="middle" dy="11" fontSize="10" fontWeight="600" fill="var(--accent-blue)">Campaign</text>
                <text y="32" textAnchor="middle" fontSize="8.5" fill="rgba(144,164,174,0.7)">2026-01-10 · Resolved</text>
              </g>

              {/* CloudHopper Redux */}
              <g transform="translate(630,330)">
                <rect x="-82" y="-22" width="164" height="44" rx="6" fill="rgba(79,163,224,0.12)" stroke="var(--accent-blue)" strokeWidth="1.6" />
                <text textAnchor="middle" dy="-3" fontSize="10" fontWeight="600" fill="var(--accent-blue)">CloudHopper</text>
                <text textAnchor="middle" dy="11" fontSize="10" fontWeight="600" fill="var(--accent-blue)">Redux</text>
                <text y="32" textAnchor="middle" fontSize="8.5" fill="rgba(144,164,174,0.7)">2026-04-20 · Investigating</text>
              </g>

              {/* Operation BlackShadow */}
              <g transform="translate(635,435)">
                <rect x="-84" y="-22" width="168" height="44" rx="6" fill="rgba(79,163,224,0.12)" stroke="var(--accent-blue)" strokeWidth="1.6" />
                <text textAnchor="middle" dy="-3" fontSize="10" fontWeight="600" fill="var(--accent-blue)">Operation</text>
                <text textAnchor="middle" dy="11" fontSize="10" fontWeight="600" fill="var(--accent-blue)">BlackShadow</text>
                <text y="32" textAnchor="middle" fontSize="8.5" fill="rgba(144,164,174,0.7)">2026-03-15 · Ongoing</text>
              </g>

              {/* Edge from APT41→PlugX needs a line too */}
              <line x1="186" y1="270" x2="434" y2="206" stroke="rgba(249,168,37,0.35)" strokeWidth="1.5" markerEnd="url(#arrow)" />
              <text x="315" y="228" fontSize="9" fill="rgba(144,164,174,0.7)" textAnchor="middle">uses</text>

              {/* section labels */}
              <text x="30" y="22" fontSize="10" fontWeight="600" fill="rgba(239,83,80,0.6)" letterSpacing="1">ACTORS</text>
              <text x="300" y="22" fontSize="10" fontWeight="600" fill="rgba(255,167,38,0.6)" letterSpacing="1">MALWARE</text>
              <text x="545" y="22" fontSize="10" fontWeight="600" fill="rgba(79,163,224,0.6)" letterSpacing="1">CAMPAIGNS</text>
              <line x1="0" y1="30" x2="900" y2="30" stroke="rgba(255,255,255,0.04)" strokeWidth="1" />
            </svg>
          </div>

          {/* Bottom info row */}
          <div style={{ marginTop: 12, display: 'flex', gap: 10, fontSize: 11, color: 'var(--text-muted)', flexWrap: 'wrap' }}>
            <span style={{ background: 'var(--bg-card2)', border: '1px solid var(--border)', borderRadius: 6, padding: '5px 12px' }}>
              3 个威胁行为者
            </span>
            <span style={{ background: 'var(--bg-card2)', border: '1px solid var(--border)', borderRadius: 6, padding: '5px 12px' }}>
              6 个恶意软件家族
            </span>
            <span style={{ background: 'var(--bg-card2)', border: '1px solid var(--border)', borderRadius: 6, padding: '5px 12px' }}>
              4 个攻击活动
            </span>
            <span style={{ background: 'var(--bg-card2)', border: '1px solid var(--border)', borderRadius: 6, padding: '5px 12px' }}>
              虚线边 = 关联关系 &nbsp;|&nbsp; 实线边 = 使用关系
            </span>
          </div>
        </div>
      )}

      {/* ===== MODALS ===== */}

      {/* Threat Actor Detail Modal */}
      {selectedActor && (
        <>
          <div onClick={() => setSelectedActor(null)} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 580, maxHeight: '80vh', overflowY: 'auto',
            background: 'var(--bg-modal)', border: '1px solid var(--border)', borderRadius: 10,
            zIndex: 500, padding: 28,
          }}>
            {(() => {
              const actor = selectedActor
              const mc = MOTIVATION_CONFIG[actor.motivation] ?? MOTIVATION_CONFIG.espionage
              const isActive = actor.status === 'Active'
              return (
                <>
                  {/* Modal header */}
                  <div style={{ display: 'flex', alignItems: 'flex-start', gap: 14, marginBottom: 20 }}>
                    <div style={{ width: 52, height: 52, borderRadius: 10, background: mc.bg, border: `1.5px solid ${mc.color}55`, display: 'flex', alignItems: 'center', justifyContent: 'center', fontSize: 26, flexShrink: 0 }}>
                      {actor.flag}
                    </div>
                    <div style={{ flex: 1 }}>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                        <span style={{ fontSize: 18, fontWeight: 700, color: 'var(--text-primary)' }}>{actor.name}</span>
                        <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>/ {actor.alias}</span>
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11 }}>
                          <span style={{ width: 7, height: 7, borderRadius: '50%', background: isActive ? 'var(--accent-green)' : 'var(--text-muted)', boxShadow: isActive ? '0 0 5px rgba(47,176,122,.7)' : 'none', display: 'inline-block' }} />
                          <span style={{ color: isActive ? 'var(--accent-green)' : 'var(--text-muted)', fontWeight: 700 }}>{actor.status}</span>
                        </span>
                      </div>
                      <div style={{ display: 'flex', gap: 8, marginTop: 6, flexWrap: 'wrap' }}>
                        <span style={{ fontSize: 11, padding: '2px 10px', borderRadius: 4, background: mc.bg, color: mc.color, fontWeight: 600 }}>{mc.label}</span>
                        <span style={{ fontSize: 11, color: 'var(--text-secondary)' }}>来源国: {actor.country}</span>
                        <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>最近活动: {daysAgo(actor.lastActivity)}</span>
                      </div>
                    </div>
                    <button onClick={() => setSelectedActor(null)} style={{ fontSize: 18, background: 'none', border: 'none', color: 'var(--text-muted)', cursor: 'pointer', padding: '0 4px', lineHeight: 1 }}>×</button>
                  </div>

                  {/* Description */}
                  <div style={{ fontSize: 12.5, color: 'var(--text-secondary)', lineHeight: 1.65, marginBottom: 18, padding: '12px 14px', background: 'var(--bg-card2)', borderRadius: 6, border: '1px solid var(--border-light)' }}>
                    {actor.description}
                  </div>

                  {/* Confidence + IOC count row */}
                  <div style={{ display: 'flex', gap: 10, marginBottom: 18 }}>
                    {(() => {
                      const confColor = actor.confidence === 'High' ? 'var(--accent-green)' : actor.confidence === 'Medium' ? 'var(--high)' : 'var(--text-muted)'
                      const confBg = actor.confidence === 'High' ? 'rgba(47,176,122,.12)' : actor.confidence === 'Medium' ? 'rgba(224,128,64,.12)' : 'rgba(84,110,122,.12)'
                      return (
                        <>
                          <div style={{ flex: 1, padding: '10px 14px', background: confBg, border: `1px solid ${confColor}44`, borderRadius: 6 }}>
                            <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: .5, marginBottom: 4 }}>情报置信度</div>
                            <div style={{ fontSize: 16, fontWeight: 700, color: confColor }}>{actor.confidence}</div>
                          </div>
                          <div style={{ flex: 1, padding: '10px 14px', background: 'rgba(79,163,224,.08)', border: '1px solid rgba(79,163,224,.25)', borderRadius: 6 }}>
                            <div style={{ fontSize: 10, color: 'var(--text-muted)', fontWeight: 700, textTransform: 'uppercase', letterSpacing: .5, marginBottom: 4 }}>关联 IOC 数量</div>
                            <div style={{ fontSize: 16, fontWeight: 700, color: 'var(--accent-blue)' }}>{actor.iocCount.toLocaleString()}</div>
                          </div>
                        </>
                      )
                    })()}
                  </div>

                  {/* TTPs section */}
                  <div style={{ marginBottom: 18 }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: .8, marginBottom: 8 }}>
                      TTPs — MITRE ATT&amp;CK
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                      {actor.ttps.map(t => (
                        <span key={t} style={{
                          fontSize: 10.5, padding: '4px 10px', borderRadius: 4,
                          background: 'var(--bg-card2)', border: `1px solid ${mc.color}33`,
                          color: mc.color, fontFamily: 'monospace', fontWeight: 600,
                        }}>{t}</span>
                      ))}
                    </div>
                  </div>

                  {/* Malware families */}
                  <div style={{ marginBottom: 18 }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: .8, marginBottom: 8 }}>
                      已知恶意软件家族
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                      {actor.malwareFamilies.map(m => (
                        <span key={m} style={{
                          fontSize: 11, padding: '3px 10px', borderRadius: 4,
                          background: 'rgba(224,80,80,.1)', border: '1px solid rgba(224,80,80,.25)',
                          color: 'var(--critical)', fontFamily: 'monospace', fontWeight: 600,
                        }}>{m}</span>
                      ))}
                    </div>
                  </div>

                  {/* Targets */}
                  <div style={{ marginBottom: 18 }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: .8, marginBottom: 8 }}>
                      主要攻击目标行业
                    </div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                      {actor.targets.map(t => (
                        <span key={t} style={{
                          fontSize: 11, padding: '3px 10px', borderRadius: 4,
                          background: 'rgba(79,163,224,.1)', border: '1px solid rgba(79,163,224,.25)',
                          color: 'var(--accent-blue)',
                        }}>{t}</span>
                      ))}
                    </div>
                  </div>

                  {/* Recent campaigns */}
                  <div style={{ marginBottom: 18 }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: .8, marginBottom: 8 }}>
                      近期攻击活动
                    </div>
                    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                      {actor.recentCampaigns.map(rc => (
                        <div key={rc.name} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '7px 12px', background: 'var(--bg-card2)', borderRadius: 5, border: '1px solid var(--border-light)' }}>
                          <span style={{ width: 6, height: 6, borderRadius: '50%', background: mc.color, flexShrink: 0, display: 'inline-block' }} />
                          <span style={{ flex: 1, fontSize: 11.5, color: 'var(--text-primary)' }}>{rc.name}</span>
                          <span style={{ fontSize: 10.5, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>{rc.date}</span>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Activity status */}
                  <div style={{ padding: '10px 14px', background: 'var(--bg-card2)', borderRadius: 6, border: '1px solid var(--border-light)', marginBottom: 20 }}>
                    <div style={{ fontSize: 11, fontWeight: 700, color: 'var(--text-muted)', textTransform: 'uppercase', letterSpacing: .8, marginBottom: 8 }}>最近活动</div>
                    <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                      <span style={{ fontSize: 24 }}>{isActive ? '⚡' : '💤'}</span>
                      <div>
                        <div style={{ fontSize: 13, fontWeight: 600, color: isActive ? 'var(--high)' : 'var(--text-secondary)' }}>
                          {daysAgo(actor.lastActivity)} ({actor.lastActivity})
                        </div>
                        <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                          {isActive ? '该组织当前处于活跃状态，建议持续监控相关IOC' : '该组织近期无明显活动迹象'}
                        </div>
                      </div>
                    </div>
                  </div>

                  {/* Actions */}
                  <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                    <button
                      className="btn-primary"
                      onClick={() => { setSelectedActor(null); setTab('indicators'); setIocHuntQuery(actor.name); runIocHunt() }}
                      style={{ fontSize: 12 }}
                    >
                      Hunt for IOCs →
                    </button>
                    <button
                      className="btn-secondary"
                      onClick={() => { setSelectedActor(null); navigate(`/incidents?keyword=${encodeURIComponent(actor.name)}`) }}
                      style={{ fontSize: 12 }}
                    >
                      查看关联事件 →
                    </button>
                    <button className="btn-secondary" style={{ fontSize: 12, marginLeft: 'auto' }} onClick={() => setSelectedActor(null)}>
                      关闭
                    </button>
                  </div>
                </>
              )
            })()}
          </div>
        </>
      )}

      {/* IOC Modal */}
      {showIocModal && (
        <>
          <div onClick={() => setShowIocModal(false)} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
          <div style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: 480, background: 'var(--bg-modal)', border: '1px solid var(--border)', borderRadius: 8, zIndex: 500, padding: 24 }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 20 }}>{editIoc ? 'Edit Indicator' : 'Add Indicator'}</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>IOC Type</div>
                  <select className="filter-select" style={{ width: '100%' }} value={iocForm.type} onChange={e => setIocForm(p => ({ ...p, type: e.target.value }))}>
                    {IOC_TYPES.map(t => <option key={t} value={t}>{IOC_LABELS[t] ?? t}</option>)}
                  </select></div>
                <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>判定结论</div>
                  <select className="filter-select" style={{ width: '100%' }} value={iocForm.verdict} onChange={e => setIocForm(p => ({ ...p, verdict: e.target.value }))}>
                    <option value="malicious">恶意</option>
                    <option value="suspicious">可疑</option>
                    <option value="benign">无害</option>
                    <option value="unknown">未知</option>
                  </select></div>
              </div>
              <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Indicator Value *</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="e.g. 1.2.3.4 or evil.com" value={iocForm.value} onChange={e => setIocForm(p => ({ ...p, value: e.target.value }))} /></div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>置信度 (0-100)</div>
                  <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} type="number" min="0" max="100" value={iocForm.confidence} onChange={e => setIocForm(p => ({ ...p, confidence: e.target.value }))} /></div>
                <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Source Name</div>
                  <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="Unit 42 / Manual" value={iocForm.source_name} onChange={e => setIocForm(p => ({ ...p, source_name: e.target.value }))} /></div>
              </div>
              <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Threat Name</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="LockBit C2 / Phishing" value={iocForm.threat_name} onChange={e => setIocForm(p => ({ ...p, threat_name: e.target.value }))} /></div>
              <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Tags (comma-separated)</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="c2, ransomware, apt" value={iocForm.tags} onChange={e => setIocForm(p => ({ ...p, tags: e.target.value }))} /></div>
              <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setShowIocModal(false)}>取消</button>
                <button className="btn-primary" style={{ flex: 1 }} disabled={savingIoc || !iocForm.value.trim()} onClick={saveIoc}>{savingIoc ? '保存中...' : editIoc ? '保存修改' : 'Add Indicator'}</button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* Feed Modal */}
      {showFeedModal && (
        <>
          <div onClick={() => setShowFeedModal(false)} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
          <div style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: 480, background: 'var(--bg-modal)', border: '1px solid var(--border)', borderRadius: 8, zIndex: 500, padding: 24 }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 20 }}>{editFeed ? 'Edit Feed' : 'Add Feed'}</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>订阅源名称 *</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="Unit 42 Threat Feed" value={feedForm.name} onChange={e => setFeedForm(p => ({ ...p, name: e.target.value }))} /></div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>类型</div>
                  <select className="filter-select" style={{ width: '100%' }} value={feedForm.feed_type} onChange={e => setFeedForm(p => ({ ...p, feed_type: e.target.value }))}>
                    <option value="unit42">Unit 42</option><option value="wildfire">WildFire</option><option value="misp">MISP</option>
                    <option value="stix_taxii">STIX/TAXII</option><option value="mitre">MITRE ATT&CK</option><option value="virustotal">VirusTotal</option><option value="custom">Custom</option>
                  </select></div>
                <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>状态</div>
                  <select className="filter-select" style={{ width: '100%' }} value={feedForm.status} onChange={e => setFeedForm(p => ({ ...p, status: e.target.value }))}>
                    <option value="active">Active</option><option value="inactive">Inactive</option>
                  </select></div>
              </div>
              <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>订阅URL</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="https://feed.example.com/indicators" value={feedForm.url} onChange={e => setFeedForm(p => ({ ...p, url: e.target.value }))} /></div>
              <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>描述</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="简要描述..." value={feedForm.description} onChange={e => setFeedForm(p => ({ ...p, description: e.target.value }))} /></div>
              <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Sync Interval (minutes)</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} type="number" min="0" value={feedForm.sync_interval} onChange={e => setFeedForm(p => ({ ...p, sync_interval: e.target.value }))} /></div>
              <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setShowFeedModal(false)}>取消</button>
                <button className="btn-primary" style={{ flex: 1 }} disabled={savingFeed || !feedForm.name.trim()} onClick={saveFeed}>{savingFeed ? '保存中...' : editFeed ? '保存修改' : 'Add Feed'}</button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* Indicator Rule Modal */}
      {showRuleModal && (
        <>
          <div onClick={() => setShowRuleModal(false)} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
          <div style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: 460, background: 'var(--bg-modal)', border: '1px solid var(--border)', borderRadius: 8, zIndex: 500, padding: 24 }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 20 }}>{editRule ? 'Edit Rule' : 'New Indicator Rule'}</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>规则名称 *</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="Block 恶意 IPs" value={ruleForm.name} onChange={e => setRuleForm(p => ({ ...p, name: e.target.value }))} /></div>
              <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr 1fr', gap: 12 }}>
                <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Rule Type</div>
                  <select className="filter-select" style={{ width: '100%' }} value={ruleForm.rule_type} onChange={e => setRuleForm(p => ({ ...p, rule_type: e.target.value }))}>
                    <option value="match">Match</option><option value="threshold">Threshold</option><option value="schedule">Schedule</option><option value="correlation">Correlation</option>
                  </select></div>
                <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>Severity</div>
                  <select className="filter-select" style={{ width: '100%' }} value={ruleForm.severity} onChange={e => setRuleForm(p => ({ ...p, severity: e.target.value }))}>
                    <option value="critical">Critical</option><option value="high">High</option><option value="medium">Medium</option><option value="low">Low</option>
                  </select></div>
                <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>状态</div>
                  <select className="filter-select" style={{ width: '100%' }} value={ruleForm.status} onChange={e => setRuleForm(p => ({ ...p, status: e.target.value }))}>
                    <option value="active">Active</option><option value="inactive">Inactive</option>
                  </select></div>
              </div>
              <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setShowRuleModal(false)}>取消</button>
                <button className="btn-primary" style={{ flex: 1 }} disabled={savingRule || !ruleForm.name.trim()} onClick={saveRule}>{savingRule ? '保存中...' : editRule ? '保存修改' : 'Create Rule'}</button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* 提交 样本 Modal */}
      {show提交Modal && (
        <>
          <div onClick={() => setShow提交Modal(false)} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
          <div style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: 440, background: 'var(--bg-modal)', border: '1px solid var(--border)', borderRadius: 8, zIndex: 500, padding: 24 }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 20 }}>提交样本进行分析</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>文件路径/名称</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="如：suspicious.exe" value={submitFile} onChange={e => set提交File(e.target.value)} /></div>
              <div style={{ fontSize: 11, color: 'var(--text-muted)', textAlign: 'center' }}>...或...</div>
              <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>待分析URL</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="https://suspicious-site.com/payload" value={submitUrl} onChange={e => set提交Url(e.target.value)} /></div>
              <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setShow提交Modal(false)}>取消</button>
                <button className="btn-primary" style={{ flex: 1 }} disabled={submitting || (!submitFile.trim() && !submitUrl.trim())} onClick={submit样本}>{submitting ? '提交中...' : '提交'}</button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* 创建报告 Modal */}
      {showReportModal && (
        <>
          <div onClick={() => setShowReportModal(false)} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
          <div style={{ position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)', width: 440, background: 'var(--bg-modal)', border: '1px solid var(--border)', borderRadius: 8, zIndex: 500, padding: 24 }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 20 }}>创建威胁情报报告</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
              <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>报告名称 *</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="每周威胁摘要" value={reportForm.name} onChange={e => setReportForm(p => ({ ...p, name: e.target.value }))} /></div>
              <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>模板类型</div>
                <select className="filter-select" style={{ width: '100%' }} value={reportForm.template_type} onChange={e => setReportForm(p => ({ ...p, template_type: e.target.value }))}>
                  <option value="daily">Daily</option><option value="weekly">Weekly</option><option value="monthly">Monthly</option><option value="executive">Executive Summary</option><option value="custom">Custom</option>
                </select></div>
              <div><div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 4 }}>描述</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="简要描述..." value={reportForm.description} onChange={e => setReportForm(p => ({ ...p, description: e.target.value }))} /></div>
              <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setShowReportModal(false)}>取消</button>
                <button className="btn-primary" style={{ flex: 1 }} disabled={savingReport || !reportForm.name.trim()} onClick={createReport}>{savingReport ? '创建中...' : '创建报告'}</button>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
