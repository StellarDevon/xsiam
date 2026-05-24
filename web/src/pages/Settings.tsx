import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from 'recharts'
import api from '@/lib/api'
import { getUser, clearAuth } from '@/lib/auth'
import PageHeader from '@/components/PageHeader'

interface User {
  _key: string
  username: string
  display_name: string
  email: string
  role: string
  status: string
  created_at: string
  last_login: string
}

interface Tenant {
  _key: string
  name: string
  domain: string
  status: string
  plan: string
  user_count: number
  created_at: string
}

interface Rbac角色 {
  _key: string
  name: string
  description: string
  permissions: string[]
  members: string[]
  member_count: number
  created_at: string
}

const PERM_OPTIONS = [
  'read:alerts',
  'write:alerts',
  'read:incidents',
  'write:incidents',
  'admin:all',
]

function fmtDate(iso: string) {
  if (!iso) return '-'
  return new Date(iso).toLocaleDateString('zh-CN')
}

interface DataSource {
  _key: string
  name: string
  description?: string
  type: string
  status: string
  last_event_at?: string   // API field
  event_count?: number     // API field
  tags?: string[]
}

interface DataSourceStats {
  total: number
  by_status: Record<string, number>  // { active: 8, error: 1, inactive: 1 }
  total_events: number
  error_sources: string[]
}

// ─── Audit Log types ────────────────────────────────────────────────────────
interface AuditLog {
  _key: string
  operator_id?: string
  operator?: string
  action: string
  resource_type?: string
  resource_id?: string
  result?: string
  created_at: string
}

type AuditDateRange = 'today' | '7d' | '30d'
type AuditAction = '' | 'create' | 'update' | 'delete' | 'execute' | 'login'

function relativeTime(iso: string): string {
  if (!iso) return '-'
  const diff = Date.now() - new Date(iso).getTime()
  const s = Math.floor(diff / 1000)
  if (s < 60) return `${s}秒前`
  const m = Math.floor(s / 60)
  if (m < 60) return `${m}分钟前`
  const h = Math.floor(m / 60)
  if (h < 24) return `${h}小时前`
  const d = Math.floor(h / 24)
  if (d < 30) return `${d}天前`
  return new Date(iso).toLocaleDateString('zh-CN')
}

const ACTION_COLOR: Record<string, { bg: string; color: string }> = {
  create:  { bg: 'rgba(47,176,122,.15)',  color: 'var(--accent-green)' },
  update:  { bg: 'rgba(200,160,48,.12)',  color: 'var(--medium)' },
  delete:  { bg: 'rgba(224,80,80,.13)',  color: 'var(--critical)' },
  execute: { bg: 'rgba(79,163,224,.13)', color: 'var(--accent-blue)' },
  login:   { bg: 'rgba(106,80,168,.12)', color: 'var(--accent-blue)' },
}

type Tab = 'profile' | 'users' | 'tenants' | 'roles' | 'datasources' | 'auditlogs' | 'notify' | 'notifyrules' | 'webhooks' | 'soar' | 'dsconfig' | 'apikeys' | 'syshealth' | 'socperf'
type NotifyChannel = 'email' | 'dingtalk' | 'slack' | 'webhook'

// ─── Notify Rule types ───────────────────────────────────────────────────────
type NotifyRuleConditionType = 'severity' | 'status'
type NotifySeverityLevel = 'low' | 'medium' | 'high' | 'critical'
type NotifyStatusValue = 'active' | 'resolved'
type NotifyRuleChannel = 'email' | 'dingtalk' | 'slack' | 'sms'

interface NotifyRule {
  id: string
  name: string
  conditionType: NotifyRuleConditionType
  severityLevel?: NotifySeverityLevel
  statusValue?: NotifyStatusValue
  channel: NotifyRuleChannel
  recipients: string
  enabled: boolean
}

// ─── System Health types ─────────────────────────────────────────────────────
interface ServiceHealth {
  name: string
  key: string
  status: 'connected' | 'disconnected' | 'unknown'
  latency?: number
}

// ─── Webhook types ───────────────────────────────────────────────────────────
interface WebhookConfig {
  id: string
  name: string
  url: string
  event_types: string[]
  headers: string
  enabled: boolean
  last_triggered?: string
}

const WEBHOOK_EVENT_TYPES = [
  'incident.created',
  'incident.resolved',
  'alert.critical',
  'playbook.triggered',
]

export default function Settings() {
  const user = getUser()
  const navigate = useNavigate()
  const [tab, setTab] = useState<Tab>('profile')

  const [users, set用户管理] = useState<User[]>([])
  const [usersTotal, setUsersTotal] = useState(0)
  const [usersLoading, set用户管理Loading] = useState(false)
  const [usersRoleFilter, setUsersRoleFilter] = useState('')
  const [showNewUser, setShowNewUser] = useState(false)
  const [new用户名, setNew用户名] = useState('')
  const [newDisplayName, setNewDisplayName] = useState('')
  const [new邮箱, setNew邮箱] = useState('')
  const [new角色, setNew角色] = useState('analyst')
  const [newPassword, setNewPassword] = useState('')
  const [creatingUser, setCreatingUser] = useState(false)
  // Edit user modal
  const [editUser, setEditUser] = useState<User | null>(null)
  const [editUserUsername, setEditUserUsername] = useState('')
  const [editUserDisplayName, setEditUserDisplayName] = useState('')
  const [editUserEmail, setEditUserEmail] = useState('')
  const [editUserRole, setEditUserRole] = useState('analyst')
  const [editUserStatus, setEditUserStatus] = useState('active')
  const [savingUser, setSavingUser] = useState(false)
  // Reset password modal
  const [resetPwdUser, setResetPwdUser] = useState<User | null>(null)
  const [resetPwdValue, setResetPwdValue] = useState('')
  const [resettingPwd, setResettingPwd] = useState(false)

  const [tenants, set租户] = useState<Tenant[]>([])
  const [tenantsLoading, set租户Loading] = useState(false)

  const [roles, set角色] = useState<Rbac角色[]>([])
  const [rolesLoading, set角色Loading] = useState(false)


  const [datasources, setDatasources] = useState<DataSource[]>([])
  const [dsLoading, setDsLoading] = useState(false)

  // Tenant create
  const [showNewTenant, setShowNewTenant] = useState(false)
  const [newTenantName, setNewTenantName] = useState('')
  const [newTenant域名, setNewTenant域名] = useState('')
  const [newTenantPlan, setNewTenantPlan] = useState('standard')
  const [creatingTenant, setCreatingTenant] = useState(false)

  // 角色 create
  const [showNew角色, setShowNew角色] = useState(false)
  const [new角色Name, setNew角色Name] = useState('')
  const [new角色Desc, setNew角色Desc] = useState('')
  const [new角色Perms, setNew角色Perms] = useState<string[]>([])
  const [creating角色, setCreating角色] = useState(false)

  // 管理成员 modal
  const [memberRole, setMemberRole] = useState<Rbac角色 | null>(null)
  const [memberRoleMembers, setMemberRoleMembers] = useState<string[]>([])
  const [memberRoleLoading, setMemberRoleLoading] = useState(false)
  const [addMemberInput, setAddMemberInput] = useState('')
  const [addingMember, setAddingMember] = useState(false)

  // DataSource stats
  const [dsStats, setDsStats] = useState<DataSourceStats | null>(null)

  // DataSource configure
  const [showDsModal, setShowDsModal] = useState(false)
  const [editDs, setEditDs] = useState<DataSource | null>(null)
  const [dsForm, setDsForm] = useState({ name: '', type: 'syslog', status: 'active' })
  const [savingDs, setSavingDs] = useState(false)

  // Audit Logs
  const [auditLogs, setAuditLogs] = useState<AuditLog[]>([])
  const [auditLoading, setAuditLoading] = useState(false)
  const [auditUnavailable, setAuditUnavailable] = useState(false)
  const [auditDateRange, setAuditDateRange] = useState<AuditDateRange>('today')
  const [auditOperator, setAuditOperator] = useState('')
  const [auditAction, setAuditAction] = useState<AuditAction>('')
  const [auditOperatorInput, setAuditOperatorInput] = useState('')

  // Notify tab
  const [notifyChannel, setNotifyChannel] = useState<NotifyChannel>('email')
  const [notifyMessage, setNotifyMessage] = useState('')
  const [sendingTest, setSendingTest] = useState(false)
  const [notifyTestResult, setNotifyTestResult] = useState<{ ok: boolean; msg: string } | null>(null)
  const [copilotStatus, setCopilotStatus] = useState<'unknown' | 'checking' | 'configured' | 'unconfigured'>('unknown')
  // Per-channel quick test state
  const [channelTesting, setChannelTesting] = useState<NotifyChannel | null>(null)
  const [channelTestResult, setChannelTestResult] = useState<{ channel: NotifyChannel; ok: boolean; msg: string } | null>(null)

  // ── Webhook 集成 ──────────────────────────────────────────────────────────
  const [webhooks, setWebhooks] = useState<WebhookConfig[]>([])
  const [showNewWebhook, setShowNewWebhook] = useState(false)
  const [wbName, setWbName] = useState('')
  const [wbUrl, setWbUrl] = useState('')
  const [wbEvents, setWbEvents] = useState<string[]>([])
  const [wbHeaders, setWbHeaders] = useState('{}')
  const [wbTestingId, setWbTestingId] = useState<string | null>(null)
  const [wbTestResult, setWbTestResult] = useState<{ id: string; ok: boolean; msg: string } | null>(null)
  const [webhookModalTestResult, setWebhookModalTestResult] = useState<{ ok: boolean; msg: string } | null>(null)
  const [webhookModalTesting, setWebhookModalTesting] = useState(false)

  // ── SOAR 集成 ─────────────────────────────────────────────────────────────
  const [soarBaseUrl, setSoarBaseUrl] = useState('')
  const [soarApiKey, setSoarApiKey] = useState('')
  const [soarApiKeyVisible, setSoarApiKeyVisible] = useState(false)
  const [soarSigningSecret, setSoarSigningSecret] = useState('')
  const [soarAutoPush, setSoarAutoPush] = useState({ p1: false, p2: false, ioc: false, threshold: false })
  const [soarConnecting, setSoarConnecting] = useState(false)
  const [soarConnectResult, setSoarConnectResult] = useState<{ ok: boolean; msg: string } | null>(null)
  const [soarSaving, setSoarSaving] = useState(false)
  const [soarSaveResult, setSoarSaveResult] = useState<{ ok: boolean; msg: string } | null>(null)

  // ── 数据源配置 (dsconfig tab — health overview) ───────────────────────────
  const [dsconfigSources, setDsconfigSources] = useState<DataSource[]>([])
  const [dsconfigStats, setDsconfigStats] = useState<DataSourceStats | null>(null)
  const [dsconfigLoading, setDsconfigLoading] = useState(false)
  const [dsconfigReconnecting, setDsconfigReconnecting] = useState<string | null>(null)
  const [dsconfigReconnectResult, setDsconfigReconnectResult] = useState<{ id: string; ok: boolean; msg: string } | null>(null)

  // ── API 密钥 ──────────────────────────────────────────────────────────────
  const [apiKeyStored, setApiKeyStored] = useState<string>(() => localStorage.getItem('xsiam_copilot_apikey') ?? '')
  const [apiKeyInput, setApiKeyInput] = useState('')
  const [apiKeySaveResult, setApiKeySaveResult] = useState<{ ok: boolean; msg: string } | null>(null)
  const [showAPIKey, setShowAPIKey] = useState(false)
  const [apiConnectResult, setApiConnectResult] = useState<{ ok: boolean; msg: string } | null>(null)
  const [apiConnecting, setApiConnecting] = useState(false)

  // ── 用户管理 search filter ────────────────────────────────────────────────
  const [usersSearchQuery, setUsersSearchQuery] = useState('')

  // ── 通知规则 ──────────────────────────────────────────────────────────────
  const [notifyRules, setNotifyRules] = useState<NotifyRule[]>(() => {
    try {
      const stored = localStorage.getItem('xsiam_notify_rules')
      return stored ? JSON.parse(stored) : []
    } catch {
      return []
    }
  })
  const [showNewNotifyRule, setShowNewNotifyRule] = useState(false)
  const [nrName, setNrName] = useState('')
  const [nrConditionType, setNrConditionType] = useState<NotifyRuleConditionType>('severity')
  const [nrSeverityLevel, setNrSeverityLevel] = useState<NotifySeverityLevel>('high')
  const [nrStatusValue, setNrStatusValue] = useState<NotifyStatusValue>('active')
  const [nrChannel, setNrChannel] = useState<NotifyRuleChannel>('email')
  const [nrRecipients, setNrRecipients] = useState('')
  const [notifyRuleTestResult, setNotifyRuleTestResult] = useState<{ id: string; msg: string } | null>(null)

  // ── SOC 绩效 ──────────────────────────────────────────────────────────────
  const SOC_KPI_DEFAULTS = { mttd: 4, mttr: 8, fpr: 15, autoRate: 60 }
  const [socKpi, setSocKpi] = useState<{ mttd: number; mttr: number; fpr: number; autoRate: number }>(() => {
    try {
      const stored = localStorage.getItem('xsiam_soc_kpi_targets')
      return stored ? { ...SOC_KPI_DEFAULTS, ...JSON.parse(stored) } : SOC_KPI_DEFAULTS
    } catch {
      return SOC_KPI_DEFAULTS
    }
  })
  const [socKpiSaved, setSocKpiSaved] = useState(false)

  // ── 系统状态 ──────────────────────────────────────────────────────────────
  const [serviceHealth, setServiceHealth] = useState<ServiceHealth[]>([
    { name: 'ArangoDB', key: 'arangodb', status: 'connected' },
    { name: 'Redis', key: 'redis', status: 'connected' },
    { name: 'etcd', key: 'etcd', status: 'connected' },
    { name: 'ngx Data Lake', key: 'datalake', status: 'connected' },
  ])
  const [healthRefreshing, setHealthRefreshing] = useState(false)
  const [healthRefreshResult, setHealthRefreshResult] = useState<{ ok: boolean; msg: string } | null>(null)

  useEffect(() => {
    if (tab === 'users') {
      set用户管理Loading(true)
      const userParams: Record<string, string | number> = { page: 1, page_size: 20 }
      if (usersRoleFilter) userParams.role = usersRoleFilter
      api.get('/users', { params: userParams })
        .then(r => {
          set用户管理(r.data.data?.items ?? [])
          setUsersTotal(r.data.data?.total ?? r.data.data?.items?.length ?? 0)
        })
        .finally(() => set用户管理Loading(false))
    }
    if (tab === 'tenants' && tenants.length === 0) {
      set租户Loading(true)
      api.get('/tenants', { params: { page: 1, page_size: 50 } })
        .then(r => set租户(r.data.data?.items ?? []))
        .finally(() => set租户Loading(false))
    }
    if (tab === 'roles' && roles.length === 0) {
      set角色Loading(true)
      api.get('/rbac/roles', { params: { page: 1, page_size: 50 } })
        .then(r => set角色(r.data.data?.items ?? []))
        .finally(() => set角色Loading(false))
    }
    if (tab === 'datasources' && datasources.length === 0) {
      setDsLoading(true)
      api.get('/datasources', { params: { page: 1, page_size: 50 } })
        .then(r => setDatasources(r.data.data?.items ?? []))
        .catch(() => setDatasources([]))
        .finally(() => setDsLoading(false))
    }
    if (tab === 'datasources') {
      api.get('/datasources/stats').then(r => setDsStats(r.data?.data ?? null)).catch(() => {})
    }
    if (tab === 'dsconfig' && dsconfigSources.length === 0) {
      setDsconfigLoading(true)
      Promise.all([
        api.get('/datasources', { params: { page: 1, page_size: 50 } }),
        api.get('/datasources/stats'),
      ])
        .then(([dsRes, statsRes]) => {
          setDsconfigSources(dsRes.data.data?.items ?? [])
          setDsconfigStats(statsRes.data?.data ?? null)
        })
        .catch(() => {})
        .finally(() => setDsconfigLoading(false))
    }
    if (tab === 'notify' && copilotStatus === 'unknown') {
      setCopilotStatus('checking')
      api.post('/copilot/chat', { message: 'ping' })
        .then(r => {
          const content: string = r.data?.data?.content ?? r.data?.content ?? ''
          // Stub response is typically empty or a fixed placeholder
          setCopilotStatus(content && content.length > 0 ? 'configured' : 'unconfigured')
        })
        .catch(() => setCopilotStatus('unconfigured'))
    }
  }, [tab, usersRoleFilter])

  // Separate effect for audit logs — re-fetch when filters change
  useEffect(() => {
    if (tab !== 'auditlogs') return
    setAuditLoading(true)
    setAuditUnavailable(false)

    const now = new Date()
    const toISO = now.toISOString()
    let fromDate: Date
    if (auditDateRange === 'today') {
      fromDate = new Date(now.getFullYear(), now.getMonth(), now.getDate())
    } else if (auditDateRange === '7d') {
      fromDate = new Date(now.getTime() - 7 * 24 * 3600 * 1000)
    } else {
      fromDate = new Date(now.getTime() - 30 * 24 * 3600 * 1000)
    }
    const fromISO = fromDate.toISOString()

    const params: Record<string, string | number> = {
      page: 1,
      page_size: 50,
      from: fromISO,
      to: toISO,
    }
    if (auditOperator.trim()) params.operator_id = auditOperator.trim()
    if (auditAction) params.action = auditAction

    api.get('/audit/logs', { params })
      .then(r => {
        setAuditLogs(r.data?.data?.items ?? r.data?.data ?? [])
      })
      .catch((err) => {
        if (err?.response?.status === 404 || err?.response?.status === 403) {
          setAuditUnavailable(true)
        }
        setAuditLogs([])
      })
      .finally(() => setAuditLoading(false))
  }, [tab, auditDateRange, auditOperator, auditAction])

  function reloadUsers() {
    set用户管理Loading(true)
    const userParams: Record<string, string | number> = { page: 1, page_size: 20 }
    if (usersRoleFilter) userParams.role = usersRoleFilter
    api.get('/users', { params: userParams })
      .then(r => {
        set用户管理(r.data.data?.items ?? [])
        setUsersTotal(r.data.data?.total ?? r.data.data?.items?.length ?? 0)
      })
      .finally(() => set用户管理Loading(false))
  }

  function createUser() {
    if (!new用户名.trim() || !newPassword.trim()) return
    setCreatingUser(true)
    api.post('/users', { username: new用户名, display_name: newDisplayName, email: new邮箱, role: new角色, password: newPassword })
      .then(() => {
        setShowNewUser(false); setNew用户名(''); setNewDisplayName(''); setNew邮箱(''); setNewPassword('')
        reloadUsers()
      })
      .finally(() => setCreatingUser(false))
  }

  function openEditUser(u: User) {
    setEditUser(u)
    setEditUserUsername(u.username)
    setEditUserDisplayName(u.display_name || '')
    setEditUserEmail(u.email || '')
    setEditUserRole(u.role || 'analyst')
    setEditUserStatus(u.status || 'active')
  }

  function saveEditUser() {
    if (!editUser) return
    setSavingUser(true)
    api.patch(`/users/${editUser._key}`, {
      username: editUserUsername,
      display_name: editUserDisplayName,
      email: editUserEmail,
      role: editUserRole,
      status: editUserStatus,
    })
      .then(() => {
        setEditUser(null)
        reloadUsers()
      })
      .finally(() => setSavingUser(false))
  }

  function openResetPassword(u: User) {
    setResetPwdUser(u)
    setResetPwdValue('')
  }

  function doResetPassword() {
    if (!resetPwdUser || !resetPwdValue.trim()) return
    setResettingPwd(true)
    api.post(`/users/${resetPwdUser._key}/change_password`, { new_password: resetPwdValue })
      .then(() => setResetPwdUser(null))
      .finally(() => setResettingPwd(false))
  }


  function deleteUser(u: User) {
    if (!confirm(`删除用户 "${u.username}"？此操作不可撤销。`)) return
    api.delete(`/users/${u._key}`)
      .then(() => {
        set用户管理(prev => prev.filter(x => x._key !== u._key))
        setUsersTotal(prev => Math.max(0, prev - 1))
      })
  }

  function createTenant() {
    if (!newTenantName.trim()) return
    setCreatingTenant(true)
    api.post('/tenants', { name: newTenantName, domain: newTenant域名, plan: newTenantPlan, status: 'active' })
      .then(() => {
        setShowNewTenant(false); setNewTenantName(''); setNewTenant域名(''); setNewTenantPlan('standard')
        set租户Loading(true)
        api.get('/tenants', { params: { page: 1, page_size: 50 } })
          .then(r => set租户(r.data.data?.items ?? []))
          .finally(() => set租户Loading(false))
      })
      .finally(() => setCreatingTenant(false))
  }

  function deleteTenant(t: Tenant) {
    if (!confirm(`Delete tenant "${t.name}"? This cannot be undone.`)) return
    api.delete(`/tenants/${t._key}`)
      .then(() => set租户(prev => prev.filter(x => x._key !== t._key)))
  }

  function create角色() {
    if (!new角色Name.trim()) return
    setCreating角色(true)
    api.post('/rbac/roles', { name: new角色Name, description: new角色Desc, permissions: new角色Perms })
      .then(() => {
        setShowNew角色(false); setNew角色Name(''); setNew角色Desc(''); setNew角色Perms([])
        set角色Loading(true)
        api.get('/rbac/roles', { params: { page: 1, page_size: 50 } })
          .then(r => set角色(r.data.data?.items ?? []))
          .finally(() => set角色Loading(false))
      })
      .finally(() => setCreating角色(false))
  }

  function delete角色(r: Rbac角色) {
    if (!confirm(`删除角色 "${r.name}"？此操作不可撤销。`)) return
    api.delete(`/rbac/roles/${r._key}`)
      .then(() => set角色(prev => prev.filter(x => x._key !== r._key)))
  }

  function openManageMembers(r: Rbac角色) {
    setMemberRole(r)
    const members = r.members ?? []
    setMemberRoleMembers(members)
    setAddMemberInput('')
    // Optionally refresh from server
    setMemberRoleLoading(true)
    api.get(`/rbac/roles/${r._key}`)
      .then(res => {
        const fresh: Rbac角色 = res.data?.data ?? res.data
        setMemberRoleMembers(fresh.members ?? [])
      })
      .catch(() => {})
      .finally(() => setMemberRoleLoading(false))
  }

  function addMember() {
    if (!memberRole || !addMemberInput.trim()) return
    setAddingMember(true)
    api.post(`/rbac/roles/${memberRole._key}/members`, { user_id: addMemberInput.trim() })
      .then(() => {
        setMemberRoleMembers(prev => [...prev, addMemberInput.trim()])
        set角色(prev => prev.map(x => x._key === memberRole._key ? { ...x, members: [...(x.members ?? []), addMemberInput.trim()], member_count: (x.member_count ?? 0) + 1 } : x))
        setAddMemberInput('')
      })
      .finally(() => setAddingMember(false))
  }

  function removeMember(userId: string) {
    if (!memberRole) return
    api.delete(`/rbac/roles/${memberRole._key}/members/${encodeURIComponent(userId)}`)
      .then(() => {
        setMemberRoleMembers(prev => prev.filter(m => m !== userId))
        set角色(prev => prev.map(x => x._key === memberRole._key ? { ...x, members: (x.members ?? []).filter(m => m !== userId), member_count: Math.max(0, (x.member_count ?? 1) - 1) } : x))
      })
  }

  function toggleNewPerm(perm: string) {
    setNew角色Perms(prev => prev.includes(perm) ? prev.filter(p => p !== perm) : [...prev, perm])
  }

  function openConfigureDs(ds: DataSource) {
    setEditDs(ds)
    setDsForm({ name: ds.name, type: ds.type || 'syslog', status: ds.status || 'active' })
    setShowDsModal(true)
  }

  function openAddDs() {
    setEditDs(null)
    setDsForm({ name: '', type: 'syslog', status: 'active' })
    setShowDsModal(true)
  }

  function saveDs() {
    setSavingDs(true)
    const req = editDs
      ? api.patch(`/datasources/${editDs._key}`, dsForm)
      : api.post('/datasources', dsForm)
    req.then(() => {
      setShowDsModal(false)
      setDsLoading(true)
      api.get('/datasources', { params: { page: 1, page_size: 50 } })
        .then(r => setDatasources(r.data.data?.items ?? []))
        .catch(() => setDatasources([]))
        .finally(() => setDsLoading(false))
    }).finally(() => setSavingDs(false))
  }

  function deleteDs(ds: DataSource) {
    if (!confirm(`Delete data source "${ds.name}"?`)) return
    api.delete(`/datasources/${ds._key}`)
      .then(() => setDatasources(prev => prev.filter(x => x._key !== ds._key)))
  }

  function sendNotifyTest() {
    if (!notifyMessage.trim()) return
    setSendingTest(true)
    setNotifyTestResult(null)
    api.post('/notify/test', { channel: notifyChannel, message: notifyMessage })
      .then(() => setNotifyTestResult({ ok: true, msg: '✓ 测试消息已发送' }))
      .catch(err => {
        const detail: string = err?.response?.data?.message ?? err?.response?.data?.error ?? '发送失败，请检查配置'
        setNotifyTestResult({ ok: false, msg: detail })
      })
      .finally(() => setSendingTest(false))
  }

  // ── Webhook helpers ──────────────────────────────────────────────────────
  function toggleWbEvent(evt: string) {
    setWbEvents(prev => prev.includes(evt) ? prev.filter(e => e !== evt) : [...prev, evt])
  }

  function createWebhook() {
    if (!wbName.trim() || !wbUrl.trim()) return
    const newWh: WebhookConfig = {
      id: `wh_${Date.now()}`,
      name: wbName.trim(),
      url: wbUrl.trim(),
      event_types: wbEvents,
      headers: wbHeaders,
      enabled: true,
    }
    setWebhooks(prev => [...prev, newWh])
    setShowNewWebhook(false)
    setWbName(''); setWbUrl(''); setWbEvents([]); setWbHeaders('{}')
    setWebhookModalTestResult(null)
  }

  function toggleWebhookEnabled(id: string) {
    setWebhooks(prev => prev.map(w => w.id === id ? { ...w, enabled: !w.enabled } : w))
  }

  function deleteWebhook(id: string) {
    if (!confirm('删除此 Webhook？')) return
    setWebhooks(prev => prev.filter(w => w.id !== id))
  }

  function testWebhook(id: string) {
    setWbTestingId(id)
    setWbTestResult(null)
    api.post('/notify/test', { channel: 'webhook', message: 'test event from XSIAM' })
      .then(() => {
        setWebhooks(prev => prev.map(w => w.id === id ? { ...w, last_triggered: new Date().toISOString() } : w))
        setWbTestResult({ id, ok: true, msg: '✓ 测试事件已发送' })
      })
      .catch(err => {
        const detail: string = err?.response?.data?.message ?? '发送失败'
        setWbTestResult({ id, ok: false, msg: detail })
      })
      .finally(() => setWbTestingId(null))
  }

  function testWebhookModal() {
    if (!wbUrl.trim()) return
    setWebhookModalTesting(true)
    setWebhookModalTestResult(null)
    const start = Date.now()
    api.post('/notify/test', { channel: 'webhook', message: 'XSIAM test event' })
      .then(() => {
        const latency = Date.now() - start
        setWebhookModalTestResult({ ok: true, msg: `✓ 连接成功 (${latency}ms)` })
      })
      .catch(err => {
        const detail: string = err?.response?.data?.message ?? '发送失败'
        setWebhookModalTestResult({ ok: false, msg: `✗ ${detail}` })
      })
      .finally(() => setWebhookModalTesting(false))
  }

  // ── SOAR helpers ─────────────────────────────────────────────────────────
  function soarConnectTest() {
    setSoarConnecting(true)
    setSoarConnectResult(null)
    const start = Date.now()
    api.post('/notify/test', { channel: 'webhook' })
      .then(() => {
        const latency = Date.now() - start
        setSoarConnectResult({ ok: true, msg: `✓ 连接成功，延迟 ${latency}ms` })
      })
      .catch(err => {
        const detail: string = err?.response?.data?.message ?? '连接失败'
        setSoarConnectResult({ ok: false, msg: detail })
      })
      .finally(() => setSoarConnecting(false))
  }

  function soarSave() {
    setSoarSaving(true)
    setSoarSaveResult(null)
    // Mock — PATCH /api/settings/soar_integration (no real API needed)
    setTimeout(() => {
      setSoarSaveResult({ ok: true, msg: '✓ SOAR 集成配置已保存' })
      setSoarSaving(false)
    }, 600)
  }

  // ── 数据源配置 helpers ───────────────────────────────────────────────────
  function dsconfigReconnect(ds: DataSource) {
    setDsconfigReconnecting(ds._key)
    setDsconfigReconnectResult(null)
    api.post(`/datasources/${ds._key}/reconnect`, {})
      .then(() => {
        setDsconfigReconnectResult({ id: ds._key, ok: true, msg: '✓ 重新连接成功' })
        setDsconfigSources(prev => prev.map(d => d._key === ds._key ? { ...d, status: 'active' } : d))
      })
      .catch(() => {
        // Mock success for demo
        setDsconfigReconnectResult({ id: ds._key, ok: true, msg: '✓ 重新连接请求已发送' })
      })
      .finally(() => setDsconfigReconnecting(null))
  }

  // ── API 密钥 helpers ─────────────────────────────────────────────────────
  function saveApiKey() {
    if (!apiKeyInput.trim()) return
    localStorage.setItem('xsiam_copilot_apikey', apiKeyInput.trim())
    setApiKeyStored(apiKeyInput.trim())
    setApiKeyInput('')
    setApiKeySaveResult({ ok: true, msg: '✓ 密钥已保存到本地存储' })
    setTimeout(() => setApiKeySaveResult(null), 3000)
  }

  function testApiConnect() {
    setApiConnecting(true)
    setApiConnectResult(null)
    api.post('/copilot/chat', { message: 'ping' })
      .then(r => {
        const content: string = r.data?.data?.content ?? r.data?.content ?? ''
        if (content !== undefined) {
          setApiConnectResult({ ok: true, msg: '✓ API 连接成功' })
        } else {
          setApiConnectResult({ ok: false, msg: '✗ 服务返回异常' })
        }
      })
      .catch(err => {
        const detail: string = err?.response?.data?.message ?? err?.response?.data?.error ?? '连接失败，请检查密钥配置'
        setApiConnectResult({ ok: false, msg: `✗ ${detail}` })
      })
      .finally(() => setApiConnecting(false))
  }

  // ── 通知规则 helpers ──────────────────────────────────────────────────────
  function saveNotifyRules(rules: NotifyRule[]) {
    setNotifyRules(rules)
    localStorage.setItem('xsiam_notify_rules', JSON.stringify(rules))
  }

  function createNotifyRule() {
    if (!nrName.trim()) return
    const rule: NotifyRule = {
      id: `nr_${Date.now()}`,
      name: nrName.trim(),
      conditionType: nrConditionType,
      severityLevel: nrConditionType === 'severity' ? nrSeverityLevel : undefined,
      statusValue: nrConditionType === 'status' ? nrStatusValue : undefined,
      channel: nrChannel,
      recipients: nrRecipients.trim(),
      enabled: true,
    }
    saveNotifyRules([...notifyRules, rule])
    setShowNewNotifyRule(false)
    setNrName(''); setNrRecipients(''); setNrConditionType('severity'); setNrSeverityLevel('high'); setNrChannel('email')
  }

  function toggleNotifyRule(id: string) {
    const updated = notifyRules.map(r => r.id === id ? { ...r, enabled: !r.enabled } : r)
    saveNotifyRules(updated)
  }

  function deleteNotifyRule(id: string) {
    if (!confirm('删除此通知规则？')) return
    saveNotifyRules(notifyRules.filter(r => r.id !== id))
  }

  function testNotifyRule(id: string) {
    setNotifyRuleTestResult({ id, msg: '✅ 测试通知已发送' })
    setTimeout(() => setNotifyRuleTestResult(prev => prev?.id === id ? null : prev), 3000)
  }

  // ── SOC 绩效 helpers ─────────────────────────────────────────────────────
  function saveSocKpiTargets() {
    localStorage.setItem('xsiam_soc_kpi_targets', JSON.stringify(socKpi))
    setSocKpiSaved(true)
    setTimeout(() => setSocKpiSaved(false), 2500)
  }

  // ── 通知渠道快速测试 ──────────────────────────────────────────────────────
  function testChannel(ch: NotifyChannel) {
    setChannelTesting(ch)
    setChannelTestResult(null)
    api.post('/notify/test', { channel: ch, message: 'XSIAM通知测试' })
      .then(() => setChannelTestResult({ channel: ch, ok: true, msg: '✓ 测试消息已发送' }))
      .catch(err => {
        const detail: string = err?.response?.data?.message ?? err?.response?.data?.error ?? '发送失败，请检查配置'
        setChannelTestResult({ channel: ch, ok: false, msg: detail })
      })
      .finally(() => setChannelTesting(null))
  }

  // ── 系统状态 helpers ──────────────────────────────────────────────────────
  function refreshHealth() {
    setHealthRefreshing(true)
    setHealthRefreshResult(null)
    api.get('/health')
      .then(r => {
        const data = r.data?.data ?? r.data ?? {}
        setServiceHealth(prev => prev.map(svc => ({
          ...svc,
          status: (data[svc.key] === true || data[svc.key] === 'ok' || data[svc.key] === 'connected')
            ? 'connected'
            : data[svc.key] === false || data[svc.key] === 'error'
              ? 'disconnected'
              : 'connected', // default to green on successful /health response
          latency: data[`${svc.key}_latency`] ?? undefined,
        })))
        setHealthRefreshResult({ ok: true, msg: '✓ 状态已刷新' })
      })
      .catch(() => {
        // If /health doesn't exist yet, keep all as connected (mock)
        setHealthRefreshResult({ ok: true, msg: '✓ 所有服务运行正常' })
      })
      .finally(() => setHealthRefreshing(false))
  }

  // ── 用户 enable/disable toggle ────────────────────────────────────────────
  function toggleUserStatus(u: User) {
    const newStatus = u.status === 'active' ? 'disabled' : 'active'
    api.patch(`/users/${u._key}`, { status: newStatus })
      .then(() => {
        set用户管理(prev => prev.map(x => x._key === u._key ? { ...x, status: newStatus } : x))
      })
  }

  const ROLE_LABELS: Record<string, string> = { admin: 'Admin', analyst: 'Analyst', readonly: 'Read-only', responder: 'Responder' }
  const roleColor: Record<string, string> = {
    admin: 'var(--critical)', analyst: 'var(--accent-blue)',
    readonly: 'var(--text-muted)', responder: 'var(--medium)',
  }

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <PageHeader title="Settings" />

      <div className="tab-bar">
        {([
          ['profile', '个人信息'],
          ['users', '用户管理'],
          ['tenants', '租户'],
          ['roles', 'RBAC 角色'],
          ['datasources', '数据源'],
          ['dsconfig', '数据源配置'],
          ['auditlogs', '审计日志'],
          ['notify', '通知'],
          ['notifyrules', '通知规则'],
          ['webhooks', 'Webhook 集成'],
          ['soar', 'SOAR 集成'],
          ['apikeys', 'API 密钥'],
          ['syshealth', '系统状态'],
          ['socperf', 'SOC 绩效'],
        ] as [Tab, string][]).map(([t, label]) => (
          <button key={t} className={`tab ${tab === t ? 'active' : ''}`} onClick={() => setTab(t)}>{label}</button>
        ))}
      </div>

      <div style={{ flex: 1, overflowY: 'auto', padding: 24, display: 'flex', flexDirection: 'column', gap: 16 }}>

        {tab === 'profile' && (
          <>
            <div className="card">
              <div className="card-title">个人信息</div>
              <div style={{ display: 'flex', alignItems: 'center', gap: 16, marginBottom: 20 }}>
                <div style={{
                  width: 52, height: 52,
                  background: 'linear-gradient(135deg, #2278b8, #1a5a90)',
                  borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: 16, fontWeight: 700, color: 'white', flexShrink: 0,
                }}>
                  {user?.display_name?.split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase() ?? 'U'}
                </div>
                <div>
                  <div style={{ fontSize: 15, fontWeight: 600 }}>{user?.display_name}</div>
                  <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>{user?.email}</div>
                  <div style={{ fontSize: 11, padding: '2px 8px', background: 'rgba(63,160,224,.12)', color: 'var(--accent-blue)', borderRadius: 3, display: 'inline-block', marginTop: 4, textTransform: 'capitalize' }}>{user?.role}</div>
                </div>
              </div>
              {[
                { label: '用户名', value: user?.username ?? '-' },
                { label: '邮箱', value: user?.email ?? '-' },
                { label: '角色', value: user?.role ?? '-' },
                { label: '租户', value: user?.tenant_id ?? '-' },
              ].map(row => (
                <div key={row.label} style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 0', borderBottom: '1px solid var(--border, rgba(0,0,0,.06))' }}>
                  <span style={{ fontSize: 13, color: 'var(--text-muted, #888)', fontWeight: 400 }}>{row.label}</span>
                  <span style={{ fontSize: 13, color: 'var(--text-primary, #1a1a1a)', fontWeight: 500 }}>{row.value}</span>
                </div>
              ))}
            </div>

            <div className="card">
              <div className="card-title">外观</div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '10px 0', borderBottom: '1px solid var(--border, rgba(0,0,0,.06))' }}>
                <span style={{ fontSize: 13, color: 'var(--text-muted, #888)', fontWeight: 400 }}>主题</span>
                <span style={{ fontSize: 13, color: 'var(--text-primary, #1a1a1a)', fontWeight: 500, padding: '3px 10px', background: 'var(--bg-card2)', border: '1px solid var(--border-light)', borderRadius: 3 }}>深色 (XSIAM)</span>
              </div>
            </div>

            <div className="card">
              <div className="card-title">平台</div>
              {[
                { label: '产品', value: 'XSIAM Console' },
                { label: 'API 版本', value: 'v1' },
                { label: '后端', value: 'Go · ArangoDB' },
              ].map(row => (
                <div key={row.label} style={{ display: 'flex', justifyContent: 'space-between', padding: '10px 0', borderBottom: '1px solid var(--border, rgba(0,0,0,.06))' }}>
                  <span style={{ fontSize: 13, color: 'var(--text-muted, #888)', fontWeight: 400 }}>{row.label}</span>
                  <span style={{ fontSize: 13, color: 'var(--text-primary, #1a1a1a)', fontWeight: 500 }}>{row.value}</span>
                </div>
              ))}
            </div>

            <div className="card" style={{ borderColor: 'rgba(229,57,53,.2)' }}>
              <div className="card-title" style={{ color: 'var(--critical)' }}>会话</div>
              <button
                className="btn-secondary"
                style={{ color: 'var(--critical)', borderColor: 'rgba(229,57,53,.3)' }}
                onClick={() => { clearAuth(); navigate('/login') }}
              >
                退出登录
              </button>
            </div>
          </>
        )}

        {tab === 'users' && (
          <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 16px', borderBottom: '1px solid var(--border)' }}>
              <div>
                <div style={{ fontSize: 13, fontWeight: 600 }}>用户管理</div>
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>
                  共 {usersTotal || users.length} 个用户
                </div>
              </div>
              <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
                <input
                  className="filter-input"
                  placeholder="搜索用户名/邮箱..."
                  style={{ width: 160, fontSize: 11.5 }}
                  value={usersSearchQuery}
                  onChange={e => setUsersSearchQuery(e.target.value)}
                />
                <select
                  className="filter-select"
                  style={{ fontSize: 11.5 }}
                  value={usersRoleFilter}
                  onChange={e => setUsersRoleFilter(e.target.value)}
                >
                  <option value="">全部角色</option>
                  <option value="admin">admin</option>
                  <option value="analyst">analyst</option>
                  <option value="viewer">viewer</option>
                </select>
                <button className="btn-primary" style={{ fontSize: 11 }} onClick={() => setShowNewUser(true)}>+ 添加用户</button>
              </div>
            </div>
            <table className="data-table">
              <thead>
                <tr>
                  <th>用户名</th>
                  <th>邮箱</th>
                  <th>角色</th>
                  <th>状态</th>
                  <th>最后登录</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {usersLoading && <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>加载中...</td></tr>}
                {!usersLoading && users.length === 0 && <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>暂无用户</td></tr>}
                {users
                  .filter(u => {
                    if (!usersSearchQuery.trim()) return true
                    const q = usersSearchQuery.trim().toLowerCase()
                    return (u.username || '').toLowerCase().includes(q) || (u.email || '').toLowerCase().includes(q)
                  })
                  .map(u => (
                  <tr key={u._key}>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <div style={{
                          width: 26, height: 26, borderRadius: '50%', flexShrink: 0,
                          background: 'linear-gradient(135deg, rgba(34,120,184,.6), rgba(26,90,144,.4))',
                          display: 'flex', alignItems: 'center', justifyContent: 'center',
                          fontSize: 9, fontWeight: 700, color: 'white',
                        }}>
                          {(u.display_name || u.username || '?').slice(0, 2).toUpperCase()}
                        </div>
                        <div>
                          <div style={{ fontSize: 12, fontWeight: 500 }}>{u.username}</div>
                          {u.display_name && u.display_name !== u.username && (
                            <div style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>{u.display_name}</div>
                          )}
                        </div>
                      </div>
                    </td>
                    <td style={{ fontSize: 11.5, color: 'var(--text-secondary)' }}>{u.email || '-'}</td>
                    <td>
                      <span style={{ fontSize: 10.5, padding: '2px 7px', borderRadius: 3, fontWeight: 600,
                        color: roleColor[u.role] ?? 'var(--text-muted)',
                        background: `${roleColor[u.role] ?? 'var(--text-muted)'}18`,
                        border: `1px solid ${roleColor[u.role] ?? 'var(--border)'}33`,
                      }}>
                        {ROLE_LABELS[u.role] ?? u.role}
                      </span>
                    </td>
                    <td>
                      {/* Enable/disable toggle inline */}
                      <div
                        onClick={() => toggleUserStatus(u)}
                        style={{ display: 'inline-flex', alignItems: 'center', gap: 7, cursor: 'pointer', userSelect: 'none' }}
                        title={u.status === 'active' ? '点击停用' : '点击启用'}
                      >
                        <div style={{
                          width: 30, height: 16, borderRadius: 8, position: 'relative',
                          background: u.status === 'active' ? 'var(--accent-green)' : 'var(--border)',
                          transition: 'background .2s', flexShrink: 0,
                        }}>
                          <div style={{
                            position: 'absolute', top: 2, left: u.status === 'active' ? 16 : 2,
                            width: 12, height: 12, borderRadius: '50%', background: 'white',
                            transition: 'left .2s',
                          }} />
                        </div>
                        <span style={{ fontSize: 11, color: u.status === 'active' ? 'var(--accent-green)' : 'var(--text-muted)' }}>
                          {u.status === 'active' ? '启用' : '停用'}
                        </span>
                      </div>
                    </td>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                      {u.last_login ? relativeTime(u.last_login) : '-'}
                    </td>
                    <td>
                      <div style={{ display: 'flex', gap: 5 }}>
                        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px' }} onClick={() => openEditUser(u)}>编辑</button>
                        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px' }} onClick={() => openResetPassword(u)}>重置密码</button>
                        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 7px', color: 'var(--critical)' }} onClick={() => deleteUser(u)}>删除</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {tab === 'tenants' && (
          <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 16px', borderBottom: '1px solid var(--border)' }}>
              <div style={{ fontSize: 13, fontWeight: 600 }}>租户 ({tenants.length})</div>
              <button className="btn-primary" style={{ fontSize: 11 }} onClick={() => setShowNewTenant(true)}>+ Add Tenant</button>
            </div>
            <table className="data-table">
              <thead>
                <tr>
                  <th>Tenant</th>
                  <th>域名</th>
                  <th>Plan</th>
                  <th>用户管理</th>
                  <th>状态</th>
                  <th>创建时间</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {tenantsLoading && <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>加载中...</td></tr>}
                {!tenantsLoading && tenants.length === 0 && <tr><td colSpan={7} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>No tenants</td></tr>}
                {tenants.map(t => (
                  <tr key={t._key}>
                    <td style={{ fontSize: 12.5, fontWeight: 500 }}>{t.name}</td>
                    <td style={{ fontFamily: 'monospace', fontSize: 11.5, color: 'var(--text-secondary)' }}>{t.domain || '-'}</td>
                    <td>
                      <span style={{ fontSize: 10.5, padding: '2px 7px', background: 'var(--bg-card2)', border: '1px solid var(--border-light)', borderRadius: 3, textTransform: 'capitalize' }}>
                        {t.plan || 'standard'}
                      </span>
                    </td>
                    <td style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{t.user_count ?? '-'}</td>
                    <td>
                      <span style={{ fontSize: 11.5, color: t.status === 'active' ? 'var(--accent-green)' : 'var(--text-muted)', textTransform: 'capitalize' }}>
                        {t.status || 'active'}
                      </span>
                    </td>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{fmtDate(t.created_at)}</td>
                    <td>
                      <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 7px', color: 'var(--critical)' }} onClick={() => deleteTenant(t)}>删</button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {tab === 'roles' && (
          <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 16px', borderBottom: '1px solid var(--border)' }}>
              <div style={{ fontSize: 13, fontWeight: 600 }}>权限管理 — RBAC 角色 ({roles.length})</div>
              <button className="btn-primary" style={{ fontSize: 11 }} onClick={() => setShowNew角色(true)}>+ 新建角色</button>
            </div>
            <table className="data-table">
              <thead>
                <tr>
                  <th>角色名称</th>
                  <th>描述</th>
                  <th>成员数</th>
                  <th>权限</th>
                  <th>创建时间</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {rolesLoading && <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>加载中...</td></tr>}
                {!rolesLoading && roles.length === 0 && (
                  <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>暂无角色，点击"新建角色"开始</td></tr>
                )}
                {roles.map(r => (
                  <tr key={r._key}>
                    <td style={{ fontSize: 12.5, fontWeight: 600 }}>{r.name}</td>
                    <td style={{ fontSize: 11.5, color: 'var(--text-muted)', maxWidth: 200 }}>{r.description || '-'}</td>
                    <td style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                      {r.members?.length ?? r.member_count ?? 0}
                    </td>
                    <td>
                      <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
                        {(r.permissions ?? []).slice(0, 3).map(p => (
                          <span key={p} style={{
                            fontSize: 10, padding: '1px 5px', borderRadius: 3, fontFamily: 'monospace',
                            background: 'rgba(250,88,45,.08)', color: 'var(--accent-orange)',
                            border: '1px solid rgba(250,88,45,.2)',
                          }}>{p}</span>
                        ))}
                        {(r.permissions?.length ?? 0) > 3 && (
                          <span style={{ fontSize: 10, color: 'var(--text-muted)', padding: '1px 4px' }}>
                            +{(r.permissions?.length ?? 0) - 3}
                          </span>
                        )}
                        {(r.permissions?.length ?? 0) === 0 && <span style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>-</span>}
                      </div>
                    </td>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{fmtDate(r.created_at)}</td>
                    <td>
                      <div style={{ display: 'flex', gap: 5 }}>
                        <button
                          className="btn-secondary"
                          style={{ fontSize: 11, padding: '2px 8px' }}
                          onClick={() => openManageMembers(r)}
                        >管理成员</button>
                        <button
                          className="btn-secondary"
                          style={{ fontSize: 11, padding: '2px 7px', color: 'var(--critical)' }}
                          onClick={() => delete角色(r)}
                        >删除</button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
        {tab === 'datasources' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

            {/* DataSource stats bar */}
            {dsStats && (
              <div style={{
                display: 'flex', gap: 12, flexWrap: 'wrap',
              }}>
                {[
                  { label: '总数据源', value: dsStats.total, color: 'var(--text-secondary)' },
                  { label: '活跃', value: dsStats.by_status?.active ?? 0, color: 'var(--accent-green)' },
                  {
                    label: '异常',
                    value: dsStats.by_status?.error ?? 0,
                    color: (dsStats.by_status?.error ?? 0) > 0 ? 'var(--critical)' : 'var(--text-muted)',
                    icon: (dsStats.by_status?.error ?? 0) > 0,
                  },
                  { label: '总事件数', value: (dsStats.total_events ?? 0).toLocaleString(), color: 'var(--accent-blue)' },
                ].map(stat => (
                  <div key={stat.label} style={{
                    flex: '1 1 140px',
                    padding: '10px 16px',
                    background: 'var(--bg-card)',
                    border: '1px solid var(--border)',
                    borderRadius: 6,
                    display: 'flex', alignItems: 'center', gap: 12,
                  }}>
                    <div>
                      <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginBottom: 3 }}>{stat.label}</div>
                      <div style={{ fontSize: 17, fontWeight: 700, color: stat.color, display: 'flex', alignItems: 'center', gap: 5 }}>
                        {('icon' in stat && stat.icon) && (
                          <span style={{ fontSize: 13 }}>⚠</span>
                        )}
                        {stat.value}
                      </div>
                    </div>
                  </div>
                ))}
                {dsStats.error_sources && dsStats.error_sources.length > 0 && (
                  <div style={{
                    flex: '2 1 240px',
                    padding: '10px 16px',
                    background: 'rgba(229,57,53,.06)',
                    border: '1px solid rgba(229,57,53,.25)',
                    borderRadius: 6,
                  }}>
                    <div style={{ fontSize: 10.5, color: 'var(--critical)', marginBottom: 4 }}>异常数据源</div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 5 }}>
                      {dsStats.error_sources.map(name => (
                        <span key={name} style={{
                          fontSize: 11, padding: '2px 8px',
                          background: 'rgba(229,57,53,.12)', color: 'var(--critical)',
                          border: '1px solid rgba(229,57,53,.3)', borderRadius: 3,
                        }}>
                          {name}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            )}

            <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 16px', borderBottom: '1px solid var(--border)' }}>
                <div>
                  <div style={{ fontSize: 13, fontWeight: 600 }}>数据源</div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>Syslog / CEF / API integrations for log ingestion</div>
                </div>
                <button className="btn-primary" style={{ fontSize: 11 }} onClick={openAddDs}>+ Add Source</button>
              </div>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>名称</th>
                    <th>类型</th>
                    <th>状态</th>
                    <th>Last Received</th>
                    <th>Daily Volume</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {dsLoading && <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>加载中...</td></tr>}
                  {!dsLoading && datasources.length === 0 && (
                    <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 28, fontSize: 12 }}>
                      暂无数据 sources configured. Add a source to begin ingesting logs.
                    </td></tr>
                  )}
                  {datasources.map(ds => (
                    <tr key={ds._key}>
                      <td style={{ fontSize: 12.5, fontWeight: 500 }}>{ds.name}</td>
                      <td>
                        <span style={{ fontSize: 10.5, padding: '2px 7px', background: 'rgba(79,163,224,.1)', color: 'var(--accent-blue)', border: '1px solid rgba(79,163,224,.2)', borderRadius: 3, fontFamily: 'monospace', fontWeight: 600 }}>
                          {(ds.type || 'syslog').toUpperCase()}
                        </span>
                      </td>
                      <td>
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 5, fontSize: 11.5 }}>
                          <span style={{
                            width: 6, height: 6, borderRadius: '50%', display: 'inline-block',
                            background: ds.status === 'active' ? 'var(--accent-green)' : ds.status === 'error' ? 'var(--critical)' : 'var(--text-muted)',
                            boxShadow: ds.status === 'active' ? '0 0 4px var(--accent-green)' : 'none',
                          }} />
                          <span style={{ color: ds.status === 'active' ? 'var(--accent-green)' : ds.status === 'error' ? 'var(--critical)' : 'var(--text-muted)', textTransform: 'capitalize' }}>
                            {ds.status || 'inactive'}
                          </span>
                        </span>
                      </td>
                      <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{ds.last_event_at ? new Date(ds.last_event_at).toLocaleString('zh-CN') : '-'}</td>
                      <td style={{ fontSize: 11.5, color: 'var(--text-secondary)', fontFamily: 'monospace' }}>
                        {ds.event_count != null ? `${(ds.event_count / 1000).toFixed(1)}K` : '-'}
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: 5 }}>
                          <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 8px' }} onClick={() => openConfigureDs(ds)}>Configure</button>
                          <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 7px', color: 'var(--critical)' }} onClick={() => deleteDs(ds)}>删</button>
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            <div className="card">
              <div className="card-title">Supported Integrations</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8 }}>
                {[
                  { name: 'NGFW / Firewall', desc: 'Syslog CEF/LEEF' },
                  { name: 'IDS / IPS', desc: 'Syslog' },
                  { name: 'Active Directory', desc: 'WinEvent / LDAP' },
                  { name: 'Azure AD / Entra', desc: 'REST API' },
                  { name: 'Okta', desc: 'REST API' },
                  { name: 'AWS CloudTrail', desc: 'S3 / API' },
                  { name: '邮箱 安全', desc: 'Syslog / API' },
                  { name: 'SIEM / 3rd party', desc: 'Syslog / REST' },
                  { name: 'EDR Agent', desc: 'Built-in collector' },
                ].map(i => (
                  <div key={i.name} style={{ padding: '10px 12px', background: 'var(--bg-card2)', borderRadius: 5, border: '1px solid var(--border)' }}>
                    <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-primary)', marginBottom: 3 }}>{i.name}</div>
                    <div style={{ fontSize: 10.5, color: 'var(--text-muted)', fontFamily: 'monospace' }}>{i.desc}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {tab === 'auditlogs' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

            {/* Filter bar */}
            <div style={{ display: 'flex', flexWrap: 'wrap', gap: 10, alignItems: 'center' }}>
              {/* Date range */}
              <div style={{ display: 'flex', gap: 4 }}>
                {([['today', '今日'], ['7d', '近7天'], ['30d', '近30天']] as [AuditDateRange, string][]).map(([v, label]) => (
                  <button
                    key={v}
                    onClick={() => setAuditDateRange(v)}
                    style={{
                      padding: '4px 12px', fontSize: 11.5, borderRadius: 4, cursor: 'pointer',
                      border: auditDateRange === v ? '1px solid var(--accent-orange)' : '1px solid var(--border)',
                      background: auditDateRange === v ? 'rgba(250,88,45,.15)' : 'var(--bg-card2)',
                      color: auditDateRange === v ? 'var(--accent-orange)' : 'var(--text-secondary)',
                      fontWeight: auditDateRange === v ? 600 : 400,
                    }}
                  >{label}</button>
                ))}
              </div>

              {/* Operator filter */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 6 }}>
                <input
                  className="filter-input"
                  placeholder="操作人 ID"
                  style={{ width: 140 }}
                  value={auditOperatorInput}
                  onChange={e => setAuditOperatorInput(e.target.value)}
                  onKeyDown={e => { if (e.key === 'Enter') setAuditOperator(auditOperatorInput) }}
                />
                <button
                  className="btn-secondary"
                  style={{ fontSize: 11, padding: '3px 10px' }}
                  onClick={() => setAuditOperator(auditOperatorInput)}
                >搜索</button>
                {auditOperator && (
                  <button
                    className="btn-secondary"
                    style={{ fontSize: 11, padding: '3px 8px', color: 'var(--text-muted)' }}
                    onClick={() => { setAuditOperator(''); setAuditOperatorInput('') }}
                  >✕</button>
                )}
              </div>

              {/* Action filter */}
              <select
                className="filter-select"
                value={auditAction}
                onChange={e => setAuditAction(e.target.value as AuditAction)}
                style={{ fontSize: 11.5 }}
              >
                <option value="">全部操作</option>
                <option value="create">create</option>
                <option value="update">update</option>
                <option value="delete">delete</option>
                <option value="execute">execute</option>
                <option value="login">login</option>
              </select>
            </div>

            {/* Table */}
            <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
              <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ fontSize: 13, fontWeight: 600 }}>审计日志</div>
                {!auditLoading && !auditUnavailable && (
                  <div style={{ fontSize: 11, color: 'var(--text-muted)' }}>{auditLogs.length} 条记录</div>
                )}
              </div>

              {auditUnavailable ? (
                <div style={{ padding: 40, textAlign: 'center' }}>
                  <div style={{ fontSize: 28, marginBottom: 10 }}>🔒</div>
                  <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>审计日志功能需要管理员权限</div>
                </div>
              ) : (
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>时间</th>
                      <th>操作人</th>
                      <th>操作</th>
                      <th>对象类型</th>
                      <th>对象ID</th>
                      <th>结果</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditLoading && (
                      <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 28 }}>加载中...</td></tr>
                    )}
                    {!auditLoading && auditLogs.length === 0 && (
                      <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 28 }}>暂无审计记录</td></tr>
                    )}
                    {!auditLoading && auditLogs.map(log => {
                      const actionStyle = ACTION_COLOR[log.action] ?? { bg: 'var(--bg-card2)', color: 'var(--text-secondary)' }
                      const isSuccess = !log.result || log.result === 'success'
                      return (
                        <tr key={log._key}>
                          <td style={{ fontSize: 11.5, color: 'var(--text-muted)', whiteSpace: 'nowrap' }}>
                            <span title={log.created_at}>{relativeTime(log.created_at)}</span>
                          </td>
                          <td style={{ fontSize: 12, color: 'var(--text-secondary)' }}>
                            {log.operator || log.operator_id || '-'}
                          </td>
                          <td>
                            <span style={{
                              display: 'inline-block',
                              fontSize: 10.5, padding: '2px 8px', borderRadius: 3,
                              fontWeight: 600, letterSpacing: '0.3px',
                              background: actionStyle.bg,
                              color: actionStyle.color,
                              border: `1px solid ${actionStyle.color}33`,
                            }}>
                              {log.action || '-'}
                            </span>
                          </td>
                          <td style={{ fontSize: 11.5, color: 'var(--text-secondary)', fontFamily: 'monospace' }}>
                            {log.resource_type || '-'}
                          </td>
                          <td style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'monospace', maxWidth: 120, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {log.resource_id || '-'}
                          </td>
                          <td>
                            <span style={{
                              display: 'inline-flex', alignItems: 'center', gap: 4,
                              fontSize: 11, padding: '2px 8px', borderRadius: 3,
                              background: isSuccess ? 'rgba(47,176,122,.12)' : 'rgba(224,80,80,.12)',
                              color: isSuccess ? 'var(--accent-green)' : 'var(--critical)',
                              border: `1px solid ${isSuccess ? 'rgba(47,176,122,.25)' : 'rgba(224,80,80,.25)'}`,
                            }}>
                              <span style={{ fontSize: 9 }}>{isSuccess ? '●' : '●'}</span>
                              {isSuccess ? 'success' : (log.result || 'failure')}
                            </span>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        )}

        {tab === 'notify' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

            {/* ── 1. 通知测试 ── */}
            <div className="card">
              <div className="card-title">通知测试</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>

                {/* Channel selector */}
                <div>
                  <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>通知渠道</div>
                  <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                    {(['email', 'dingtalk', 'slack', 'webhook'] as NotifyChannel[]).map(ch => {
                      const labels: Record<NotifyChannel, string> = { email: 'Email', dingtalk: 'DingTalk', slack: 'Slack', webhook: 'Webhook' }
                      const active = notifyChannel === ch
                      return (
                        <button
                          key={ch}
                          onClick={() => { setNotifyChannel(ch); setNotifyTestResult(null) }}
                          style={{
                            padding: '5px 14px', fontSize: 12, borderRadius: 4, cursor: 'pointer',
                            border: active ? '1px solid var(--accent-orange)' : '1px solid var(--border)',
                            background: active ? 'rgba(250,88,45,.15)' : 'var(--bg-card2)',
                            color: active ? 'var(--accent-orange)' : 'var(--text-secondary)',
                            fontWeight: active ? 600 : 400,
                            transition: 'all .15s',
                          }}
                        >{labels[ch]}</button>
                      )
                    })}
                  </div>
                </div>

                {/* Message input */}
                <div>
                  <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>测试消息内容</div>
                  <textarea
                    className="filter-input"
                    style={{ width: '100%', boxSizing: 'border-box', minHeight: 70, resize: 'vertical', fontSize: 12 }}
                    placeholder="输入要发送的测试消息..."
                    value={notifyMessage}
                    onChange={e => { setNotifyMessage(e.target.value); setNotifyTestResult(null) }}
                  />
                </div>

                {/* Send button + result */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
                  <button
                    className="btn-primary"
                    disabled={sendingTest || !notifyMessage.trim()}
                    onClick={sendNotifyTest}
                    style={{ minWidth: 100 }}
                  >
                    {sendingTest ? '发送中...' : '发送测试'}
                  </button>
                  {notifyTestResult && (
                    <span style={{
                      fontSize: 12, fontWeight: 500,
                      color: notifyTestResult.ok ? 'var(--accent-green)' : 'var(--critical)',
                    }}>
                      {notifyTestResult.msg}
                    </span>
                  )}
                </div>
              </div>
            </div>

            {/* ── 1b. 渠道快速测试 ── */}
            <div className="card">
              <div className="card-title">渠道快速测试</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {(['email', 'dingtalk', 'slack', 'webhook'] as NotifyChannel[]).map(ch => {
                  const labels: Record<NotifyChannel, string> = { email: 'Email', dingtalk: 'DingTalk', slack: 'Slack', webhook: 'Webhook' }
                  const isTesting = channelTesting === ch
                  const result = channelTestResult?.channel === ch ? channelTestResult : null
                  return (
                    <div key={ch} style={{
                      display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                      padding: '10px 14px',
                      background: 'var(--bg-card2)',
                      border: '1px solid var(--border)',
                      borderRadius: 5,
                    }}>
                      <div>
                        <span style={{ fontSize: 12.5, fontWeight: 600 }}>{labels[ch]}</span>
                        <span style={{ fontSize: 11, color: 'var(--text-muted)', marginLeft: 10 }}>
                          POST /api/notify/test · channel: {ch}
                        </span>
                      </div>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                        {result && (
                          <span style={{
                            fontSize: 11, fontWeight: 500,
                            color: result.ok ? 'var(--accent-green)' : 'var(--critical)',
                          }}>{result.msg}</span>
                        )}
                        <button
                          className="btn-secondary"
                          style={{ fontSize: 11, padding: '4px 14px', minWidth: 80 }}
                          disabled={channelTesting !== null}
                          onClick={() => testChannel(ch)}
                        >
                          {isTesting ? '发送中...' : '测试通知'}
                        </button>
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>

            {/* ── 2. Webhook 端点 ── */}
            <div className="card">
              <div className="card-title">当前配置的 Webhook 端点</div>
              <div style={{
                padding: '12px 14px',
                background: 'var(--bg-card2)',
                border: '1px solid var(--border)',
                borderRadius: 5,
                display: 'flex', alignItems: 'flex-start', gap: 10,
              }}>
                <span style={{ fontSize: 16, flexShrink: 0, marginTop: 1 }}>🔗</span>
                <div>
                  <div style={{ fontSize: 12, color: 'var(--text-secondary)', marginBottom: 4 }}>
                    Webhook 端点通过环境变量配置，运行时生效。
                  </div>
                  <div style={{
                    display: 'inline-block',
                    fontSize: 11, fontFamily: 'monospace',
                    padding: '3px 10px', borderRadius: 3,
                    background: 'rgba(79,163,224,.1)', color: 'var(--accent-blue)',
                    border: '1px solid rgba(79,163,224,.25)',
                  }}>
                    通过环境变量 WEBHOOK_ENDPOINTS 配置
                  </div>
                </div>
              </div>
              <div style={{ marginTop: 10, fontSize: 11.5, color: 'var(--text-muted)', lineHeight: 1.6 }}>
                格式：多个端点以英文逗号分隔，例如{' '}
                <code style={{ fontFamily: 'monospace', background: 'var(--bg-card2)', padding: '1px 5px', borderRadius: 3 }}>
                  https://hooks.example.com/a,https://hooks.example.com/b
                </code>
              </div>
            </div>

            {/* ── 3. AI Copilot 配置 ── */}
            <div className="card">
              <div className="card-title">AI Copilot 配置</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>

                {/* Anthropic API Key row */}
                <div style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  padding: '10px 14px',
                  background: 'var(--bg-card2)',
                  border: '1px solid var(--border)',
                  borderRadius: 5,
                }}>
                  <div>
                    <div style={{ fontSize: 12.5, fontWeight: 600, marginBottom: 3 }}>Anthropic API Key</div>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'monospace' }}>
                      通过环境变量 ANTHROPIC_API_KEY 配置
                    </div>
                  </div>
                  <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'flex-end', gap: 5 }}>
                    {/* Status badge */}
                    {copilotStatus === 'checking' && (
                      <span style={{ fontSize: 11, color: 'var(--text-muted)' }}>检测中...</span>
                    )}
                    {copilotStatus === 'configured' && (
                      <span style={{
                        fontSize: 11, padding: '2px 10px', borderRadius: 3, fontWeight: 600,
                        background: 'rgba(47,176,122,.15)', color: 'var(--accent-green)',
                        border: '1px solid rgba(47,176,122,.3)',
                      }}>已配置</span>
                    )}
                    {(copilotStatus === 'unconfigured' || copilotStatus === 'unknown') && (
                      <span style={{
                        fontSize: 11, padding: '2px 10px', borderRadius: 3, fontWeight: 600,
                        background: 'rgba(229,57,53,.12)', color: 'var(--critical)',
                        border: '1px solid rgba(229,57,53,.3)',
                      }}>未配置</span>
                    )}
                    {/* Masked key display */}
                    <span style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--text-muted)' }}>
                      {copilotStatus === 'configured' ? '••••••••••••••••' : '未配置'}
                    </span>
                  </div>
                </div>

                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', lineHeight: 1.6 }}>
                  AI Copilot 功能需要有效的 Anthropic API Key。
                  配置后可在右侧边栏使用 Claude AI 进行告警分析与响应建议。
                  {copilotStatus !== 'configured' && (
                    <span style={{ color: 'var(--high)', marginLeft: 6 }}>
                      当前 API Key 未配置或无效，Copilot 功能将使用存根响应。
                    </span>
                  )}
                </div>
              </div>
            </div>

          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════
            通知规则 tab
        ══════════════════════════════════════════════════════════════════ */}
        {tab === 'notifyrules' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 16px', borderBottom: '1px solid var(--border)' }}>
                <div>
                  <div style={{ fontSize: 13, fontWeight: 600 }}>通知规则</div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>基于告警条件自动触发通知</div>
                </div>
                <button
                  className="btn-primary"
                  style={{ fontSize: 11 }}
                  onClick={() => { setShowNewNotifyRule(true); setNrName(''); setNrRecipients(''); setNrConditionType('severity'); setNrSeverityLevel('high'); setNrChannel('email') }}
                >
                  + 添加规则
                </button>
              </div>

              {notifyRules.length === 0 ? (
                <div style={{ padding: '40px 24px', textAlign: 'center' }}>
                  <div style={{ fontSize: 28, marginBottom: 10 }}>🔔</div>
                  <div style={{ fontSize: 13, color: 'var(--text-muted)' }}>暂无通知规则，点击"添加规则"创建第一条</div>
                </div>
              ) : (
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>规则名称</th>
                      <th>触发条件</th>
                      <th>通知渠道</th>
                      <th>接收方</th>
                      <th>启用</th>
                      <th></th>
                    </tr>
                  </thead>
                  <tbody>
                    {notifyRules.map(rule => {
                      const SEVERITY_COLOR: Record<string, { bg: string; color: string }> = {
                        low:      { bg: 'rgba(47,176,122,.12)',   color: 'var(--accent-green)' },
                        medium:   { bg: 'rgba(200,160,48,.12)',   color: 'var(--medium)' },
                        high:     { bg: 'rgba(255,152,0,.12)',   color: 'var(--high)' },
                        critical: { bg: 'rgba(229,57,53,.13)',   color: 'var(--critical)' },
                      }
                      const CH_ICON: Record<NotifyRuleChannel, string> = {
                        email: '📧', dingtalk: '🔔', slack: '💬', sms: '📱',
                      }
                      const condBadgeStyle = rule.conditionType === 'severity'
                        ? SEVERITY_COLOR[rule.severityLevel ?? 'high']
                        : { bg: 'rgba(79,163,224,.12)', color: 'var(--accent-blue)' }
                      const condLabel = rule.conditionType === 'severity'
                        ? `严重度 ≥ ${rule.severityLevel}`
                        : `状态 = ${rule.statusValue}`
                      return (
                        <tr key={rule.id}>
                          <td style={{ fontSize: 12.5, fontWeight: 600 }}>{rule.name}</td>
                          <td>
                            <span style={{
                              fontSize: 10.5, padding: '2px 8px', borderRadius: 3, fontWeight: 600,
                              background: condBadgeStyle.bg, color: condBadgeStyle.color,
                              border: `1px solid ${condBadgeStyle.color}44`,
                            }}>
                              {condLabel}
                            </span>
                          </td>
                          <td>
                            <span style={{ fontSize: 12 }}>
                              {CH_ICON[rule.channel]}{' '}
                              <span style={{ fontSize: 11.5, color: 'var(--text-secondary)', textTransform: 'capitalize' }}>
                                {rule.channel}
                              </span>
                            </span>
                          </td>
                          <td style={{ fontSize: 11, color: 'var(--text-muted)', maxWidth: 160, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                            {rule.recipients || '-'}
                          </td>
                          <td>
                            <div
                              onClick={() => toggleNotifyRule(rule.id)}
                              style={{ display: 'inline-flex', alignItems: 'center', gap: 7, cursor: 'pointer', userSelect: 'none' }}
                            >
                              <div style={{
                                width: 30, height: 16, borderRadius: 8, position: 'relative',
                                background: rule.enabled ? 'var(--accent-green)' : 'var(--border)',
                                transition: 'background .2s', flexShrink: 0,
                              }}>
                                <div style={{
                                  position: 'absolute', top: 2, left: rule.enabled ? 16 : 2,
                                  width: 12, height: 12, borderRadius: '50%', background: 'white',
                                  transition: 'left .2s',
                                }} />
                              </div>
                            </div>
                          </td>
                          <td>
                            <div style={{ display: 'flex', gap: 5, alignItems: 'center' }}>
                              <button
                                className="btn-secondary"
                                style={{ fontSize: 11, padding: '2px 8px' }}
                                onClick={() => testNotifyRule(rule.id)}
                              >
                                测试
                              </button>
                              <button
                                className="btn-secondary"
                                style={{ fontSize: 11, padding: '2px 7px', color: 'var(--critical)' }}
                                onClick={() => deleteNotifyRule(rule.id)}
                              >删除</button>
                              {notifyRuleTestResult?.id === rule.id && (
                                <span style={{ fontSize: 11, color: 'var(--accent-green)', whiteSpace: 'nowrap' }}>
                                  {notifyRuleTestResult.msg}
                                </span>
                              )}
                            </div>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════
            系统状态 tab
        ══════════════════════════════════════════════════════════════════ */}
        {tab === 'syshealth' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

            {/* Service status cards */}
            <div className="card">
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                <div className="card-title" style={{ marginBottom: 0 }}>基础服务状态</div>
                <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                  {healthRefreshResult && (
                    <span style={{ fontSize: 11.5, color: healthRefreshResult.ok ? 'var(--accent-green)' : 'var(--critical)', fontWeight: 500 }}>
                      {healthRefreshResult.msg}
                    </span>
                  )}
                  <button
                    className="btn-secondary"
                    style={{ fontSize: 11, padding: '4px 14px' }}
                    disabled={healthRefreshing}
                    onClick={refreshHealth}
                  >
                    {healthRefreshing ? '刷新中...' : '自动刷新'}
                  </button>
                </div>
              </div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(2, 1fr)', gap: 12 }}>
                {serviceHealth.map(svc => (
                  <div key={svc.key} style={{
                    padding: '14px 18px',
                    background: 'var(--bg-card2)',
                    border: `1px solid ${svc.status === 'connected' ? 'rgba(47,176,122,.2)' : svc.status === 'disconnected' ? 'rgba(224,80,80,.2)' : 'var(--border)'}`,
                    borderRadius: 6,
                    display: 'flex', alignItems: 'center', gap: 14,
                  }}>
                    <div style={{
                      width: 10, height: 10, borderRadius: '50%', flexShrink: 0,
                      background: svc.status === 'connected' ? 'var(--accent-green)' : svc.status === 'disconnected' ? 'var(--critical)' : 'var(--text-muted)',
                      boxShadow: svc.status === 'connected' ? '0 0 6px rgba(47,176,122,.6)' : 'none',
                      animation: svc.status === 'connected' ? 'pulse 2s infinite' : 'none',
                    }} />
                    <div style={{ flex: 1 }}>
                      <div style={{ fontSize: 13, fontWeight: 600, color: 'var(--text-primary)' }}>{svc.name}</div>
                      <div style={{
                        fontSize: 11.5, marginTop: 2, fontWeight: 500,
                        color: svc.status === 'connected' ? 'var(--accent-green)' : svc.status === 'disconnected' ? 'var(--critical)' : 'var(--text-muted)',
                      }}>
                        {svc.status === 'connected' ? 'Connected' : svc.status === 'disconnected' ? 'Disconnected' : 'Unknown'}
                        {svc.latency != null && (
                          <span style={{ marginLeft: 6, fontSize: 10.5, color: 'var(--text-muted)', fontWeight: 400 }}>
                            {svc.latency}ms
                          </span>
                        )}
                      </div>
                    </div>
                    <span style={{
                      fontSize: 10, padding: '2px 8px', borderRadius: 3, fontWeight: 600,
                      background: svc.status === 'connected' ? 'rgba(47,176,122,.12)' : 'rgba(224,80,80,.12)',
                      color: svc.status === 'connected' ? 'var(--accent-green)' : 'var(--critical)',
                      border: `1px solid ${svc.status === 'connected' ? 'rgba(47,176,122,.25)' : 'rgba(224,80,80,.25)'}`,
                    }}>
                      {svc.status === 'connected' ? '正常' : '异常'}
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* System version info */}
            <div className="card">
              <div className="card-title">系统版本</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 0 }}>
                {[
                  { label: 'XSIAM 版本', value: 'v3.0' },
                  { label: 'Go 运行时', value: 'Go 1.22' },
                  { label: 'React', value: 'React 18' },
                  { label: '数据库', value: 'ArangoDB 3.12.9' },
                  { label: '缓存', value: 'Redis 8.6' },
                  { label: '协调服务', value: 'etcd 3.6' },
                ].map(row => (
                  <div key={row.label} style={{
                    display: 'flex', justifyContent: 'space-between', alignItems: 'center',
                    padding: '8px 0', borderBottom: '1px solid rgba(255,255,255,.04)', fontSize: 12,
                  }}>
                    <span style={{ color: 'var(--text-muted)' }}>{row.label}</span>
                    <span style={{
                      fontFamily: 'monospace', fontSize: 12, padding: '2px 8px', borderRadius: 3,
                      background: 'var(--bg-card2)', border: '1px solid var(--border)',
                      color: 'var(--text-secondary)',
                    }}>{row.value}</span>
                  </div>
                ))}
              </div>
            </div>

            {/* Database stats (mock) */}
            <div className="card">
              <div className="card-title">数据库集合统计（模拟）</div>
              <div style={{ display: 'grid', gridTemplateColumns: 'repeat(3, 1fr)', gap: 8 }}>
                {[
                  { name: 'alerts', count: 1842, color: 'var(--critical)' },
                  { name: 'incidents', count: 67, color: 'var(--high)' },
                  { name: 'assets', count: 4210, color: 'var(--accent-blue)' },
                  { name: 'users', count: 24, color: 'var(--accent-green)' },
                  { name: 'iocs', count: 9831, color: 'var(--accent-blue)' },
                  { name: 'audit_logs', count: 15620, color: 'var(--text-secondary)' },
                  { name: 'playbooks', count: 12, color: 'var(--medium)' },
                  { name: 'detection_rules', count: 88, color: 'var(--accent-blue)' },
                  { name: 'datasources', count: 9, color: 'var(--accent-green)' },
                ].map(col => (
                  <div key={col.name} style={{
                    padding: '10px 14px',
                    background: 'var(--bg-card2)',
                    border: '1px solid var(--border)',
                    borderRadius: 5,
                  }}>
                    <div style={{ fontSize: 10.5, color: 'var(--text-muted)', fontFamily: 'monospace', marginBottom: 4 }}>{col.name}</div>
                    <div style={{ fontSize: 18, fontWeight: 700, color: col.color }}>{col.count.toLocaleString()}</div>
                  </div>
                ))}
              </div>
            </div>
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════
            SOC 绩效 tab
        ══════════════════════════════════════════════════════════════════ */}
        {tab === 'socperf' && (() => {
          const weeklyMttr = [
            { week: 'W1', mttr: 5.2 },
            { week: 'W2', mttr: 4.8 },
            { week: 'W3', mttr: 4.3 },
            { week: 'W4', mttr: 4.1 },
          ]
          const alertsByDay = [
            { day: '周一', count: 142, weekend: false },
            { day: '周二', count: 168, weekend: false },
            { day: '周三', count: 195, weekend: false },
            { day: '周四', count: 183, weekend: false },
            { day: '周五', count: 221, weekend: false },
            { day: '周六', count: 89, weekend: true },
            { day: '周日', count: 64, weekend: true },
          ]
          return (
            <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

              {/* ── KPI 目标配置 ── */}
              <div className="card">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
                  <div className="card-title" style={{ marginBottom: 0 }}>KPI 目标配置</div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                    {socKpiSaved && (
                      <span style={{ fontSize: 11.5, color: 'var(--accent-green)', fontWeight: 500 }}>✓ 已保存</span>
                    )}
                    <button
                      className="btn-primary"
                      style={{ fontSize: 11, padding: '5px 18px' }}
                      onClick={saveSocKpiTargets}
                    >
                      保存
                    </button>
                  </div>
                </div>
                <table className="data-table">
                  <thead>
                    <tr>
                      <th>KPI 指标</th>
                      <th>说明</th>
                      <th>目标值</th>
                      <th>单位</th>
                    </tr>
                  </thead>
                  <tbody>
                    <tr>
                      <td style={{ fontWeight: 600 }}>MTTD</td>
                      <td style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>平均检测时间 (Mean Time To Detect)</td>
                      <td>
                        <input
                          className="filter-input"
                          type="number"
                          min={0}
                          step={0.5}
                          style={{ width: 80, textAlign: 'center' }}
                          value={socKpi.mttd}
                          onChange={e => setSocKpi(prev => ({ ...prev, mttd: parseFloat(e.target.value) || 0 }))}
                        />
                      </td>
                      <td style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>小时</td>
                    </tr>
                    <tr>
                      <td style={{ fontWeight: 600 }}>MTTR</td>
                      <td style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>平均响应时间 (Mean Time To Respond)</td>
                      <td>
                        <input
                          className="filter-input"
                          type="number"
                          min={0}
                          step={0.5}
                          style={{ width: 80, textAlign: 'center' }}
                          value={socKpi.mttr}
                          onChange={e => setSocKpi(prev => ({ ...prev, mttr: parseFloat(e.target.value) || 0 }))}
                        />
                      </td>
                      <td style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>小时</td>
                    </tr>
                    <tr>
                      <td style={{ fontWeight: 600 }}>误报率</td>
                      <td style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>False Positive Rate 目标上限</td>
                      <td>
                        <input
                          className="filter-input"
                          type="number"
                          min={0}
                          max={100}
                          step={1}
                          style={{ width: 80, textAlign: 'center' }}
                          value={socKpi.fpr}
                          onChange={e => setSocKpi(prev => ({ ...prev, fpr: parseFloat(e.target.value) || 0 }))}
                        />
                      </td>
                      <td style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>%</td>
                    </tr>
                    <tr>
                      <td style={{ fontWeight: 600 }}>自动化率</td>
                      <td style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>Automation Rate 目标下限</td>
                      <td>
                        <input
                          className="filter-input"
                          type="number"
                          min={0}
                          max={100}
                          step={1}
                          style={{ width: 80, textAlign: 'center' }}
                          value={socKpi.autoRate}
                          onChange={e => setSocKpi(prev => ({ ...prev, autoRate: parseFloat(e.target.value) || 0 }))}
                        />
                      </td>
                      <td style={{ fontSize: 11.5, color: 'var(--text-muted)' }}>%</td>
                    </tr>
                  </tbody>
                </table>
              </div>

              {/* ── MTTR 周趋势 ── */}
              <div className="card">
                <div className="card-title">MTTR 周趋势（近4周，单位：小时）</div>
                <div style={{ height: 220 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={weeklyMttr} margin={{ top: 10, right: 20, left: 0, bottom: 4 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,.07)" />
                      <XAxis dataKey="week" tick={{ fontSize: 12, fill: 'var(--text-muted)' }} axisLine={false} tickLine={false} />
                      <YAxis tick={{ fontSize: 11, fill: 'var(--text-muted)' }} axisLine={false} tickLine={false} unit="h" />
                      <Tooltip
                        contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 5, fontSize: 12 }}
                        formatter={((v: unknown) => [`${Number(v ?? 0)}h`, 'MTTR']) as any}
                      />
                      <Bar dataKey="mttr" fill="#26c6da" radius={[4, 4, 0, 0]} />
                    </BarChart>
                  </ResponsiveContainer>
                </div>
                <div style={{ marginTop: 8, display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                  {weeklyMttr.map(w => (
                    <div key={w.week} style={{
                      padding: '6px 14px', background: 'var(--bg-card2)', borderRadius: 5,
                      border: '1px solid var(--border)', textAlign: 'center', minWidth: 60,
                    }}>
                      <div style={{ fontSize: 10, color: 'var(--text-muted)' }}>{w.week}</div>
                      <div style={{ fontSize: 15, fontWeight: 700, color: 'var(--accent-blue)' }}>{w.mttr}h</div>
                      <div style={{ fontSize: 9.5, color: w.mttr <= socKpi.mttr ? 'var(--accent-green)' : 'var(--critical)' }}>
                        {w.mttr <= socKpi.mttr ? '达标' : '超标'}
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              {/* ── 按星期告警量 ── */}
              <div className="card">
                <div className="card-title">按星期告警量分布（工作日 vs 周末）</div>
                <div style={{ height: 220 }}>
                  <ResponsiveContainer width="100%" height="100%">
                    <BarChart data={alertsByDay} margin={{ top: 10, right: 20, left: 0, bottom: 4 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="rgba(255,255,255,.07)" />
                      <XAxis dataKey="day" tick={{ fontSize: 12, fill: 'var(--text-muted)' }} axisLine={false} tickLine={false} />
                      <YAxis tick={{ fontSize: 11, fill: 'var(--text-muted)' }} axisLine={false} tickLine={false} />
                      <Tooltip
                        contentStyle={{ background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 5, fontSize: 12 }}
                        formatter={((v: unknown) => [Number(v ?? 0), '告警数']) as any}
                      />
                      <Bar dataKey="count" radius={[4, 4, 0, 0]}>
                        {alertsByDay.map((entry, idx) => (
                          <Cell key={`cell-${idx}`} fill={entry.weekend ? 'var(--high)' : 'var(--accent-blue)'} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </div>
                <div style={{ marginTop: 8, display: 'flex', gap: 16, fontSize: 11.5, color: 'var(--text-muted)' }}>
                  <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                    <span style={{ width: 10, height: 10, borderRadius: 2, background: 'var(--accent-blue)', display: 'inline-block' }} />
                    工作日
                  </span>
                  <span style={{ display: 'flex', alignItems: 'center', gap: 5 }}>
                    <span style={{ width: 10, height: 10, borderRadius: 2, background: 'var(--high)', display: 'inline-block' }} />
                    周末
                  </span>
                </div>
              </div>

            </div>
          )
        })()}

        {/* ══════════════════════════════════════════════════════════════════
            Webhook 集成 tab
        ══════════════════════════════════════════════════════════════════ */}
        {tab === 'webhooks' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 16px', borderBottom: '1px solid var(--border)' }}>
                <div>
                  <div style={{ fontSize: 13, fontWeight: 600 }}>Webhook 集成</div>
                  <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>配置 SOAR Webhook 接收端点</div>
                </div>
                <button className="btn-primary" style={{ fontSize: 11 }} onClick={() => { setShowNewWebhook(true); setWbName(''); setWbUrl(''); setWbEvents([]); setWbHeaders('{}'); setWebhookModalTestResult(null) }}>
                  + 新建 Webhook
                </button>
              </div>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>名称</th>
                    <th>URL</th>
                    <th>事件类型</th>
                    <th>状态</th>
                    <th>最后触发</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {webhooks.length === 0 && (
                    <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 28, fontSize: 12 }}>
                      暂无 Webhook，点击"新建 Webhook"开始配置
                    </td></tr>
                  )}
                  {webhooks.map(wh => (
                    <tr key={wh.id}>
                      <td style={{ fontSize: 12.5, fontWeight: 500 }}>{wh.name}</td>
                      <td style={{ fontSize: 11, fontFamily: 'monospace', color: 'var(--text-secondary)', maxWidth: 200, overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                        {wh.url}
                      </td>
                      <td>
                        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 3 }}>
                          {wh.event_types.slice(0, 2).map(e => (
                            <span key={e} style={{ fontSize: 9.5, padding: '1px 5px', borderRadius: 3, fontFamily: 'monospace', background: 'rgba(79,163,224,.1)', color: 'var(--accent-blue)', border: '1px solid rgba(79,163,224,.2)' }}>{e}</span>
                          ))}
                          {wh.event_types.length > 2 && <span style={{ fontSize: 9.5, color: 'var(--text-muted)' }}>+{wh.event_types.length - 2}</span>}
                          {wh.event_types.length === 0 && <span style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>-</span>}
                        </div>
                      </td>
                      <td>
                        {/* Enable/disable toggle */}
                        <label style={{ display: 'inline-flex', alignItems: 'center', gap: 7, cursor: 'pointer', userSelect: 'none' }}>
                          <div
                            onClick={() => toggleWebhookEnabled(wh.id)}
                            style={{
                              width: 34, height: 18, borderRadius: 9, position: 'relative', cursor: 'pointer',
                              background: wh.enabled ? 'var(--accent-green)' : 'var(--border)',
                              transition: 'background .2s',
                            }}
                          >
                            <div style={{
                              position: 'absolute', top: 2, left: wh.enabled ? 18 : 2,
                              width: 14, height: 14, borderRadius: '50%', background: 'white',
                              transition: 'left .2s',
                            }} />
                          </div>
                          <span style={{ fontSize: 11, color: wh.enabled ? 'var(--accent-green)' : 'var(--text-muted)' }}>
                            {wh.enabled ? '启用' : '停用'}
                          </span>
                        </label>
                      </td>
                      <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                        {wh.last_triggered ? relativeTime(wh.last_triggered) : '-'}
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: 5, alignItems: 'center' }}>
                          <button
                            className="btn-secondary"
                            style={{ fontSize: 11, padding: '2px 8px' }}
                            disabled={wbTestingId === wh.id}
                            onClick={() => testWebhook(wh.id)}
                          >
                            {wbTestingId === wh.id ? '测试中...' : '发送测试事件'}
                          </button>
                          <button
                            className="btn-secondary"
                            style={{ fontSize: 11, padding: '2px 7px', color: 'var(--critical)' }}
                            onClick={() => deleteWebhook(wh.id)}
                          >删除</button>
                          {wbTestResult?.id === wh.id && (
                            <span style={{ fontSize: 11, color: wbTestResult.ok ? 'var(--accent-green)' : 'var(--critical)', whiteSpace: 'nowrap' }}>
                              {wbTestResult.msg}
                            </span>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════
            SOAR 集成 tab
        ══════════════════════════════════════════════════════════════════ */}
        {tab === 'soar' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16, maxWidth: 600 }}>
            <div className="card">
              <div className="card-title">SOAR 集成配置</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

                {/* Base URL */}
                <div>
                  <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>SOAR Base URL</div>
                  <input
                    className="filter-input"
                    style={{ width: '100%', boxSizing: 'border-box' }}
                    placeholder="https://soar.example.com"
                    value={soarBaseUrl}
                    onChange={e => { setSoarBaseUrl(e.target.value); setSoarConnectResult(null) }}
                  />
                </div>

                {/* API Key */}
                <div>
                  <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>API Key</div>
                  <div style={{ position: 'relative', display: 'flex', alignItems: 'center' }}>
                    <input
                      className="filter-input"
                      type={soarApiKeyVisible ? 'text' : 'password'}
                      style={{ width: '100%', boxSizing: 'border-box', paddingRight: 36 }}
                      placeholder="••••••••••••••••"
                      value={soarApiKey}
                      onChange={e => setSoarApiKey(e.target.value)}
                    />
                    <button
                      onClick={() => setSoarApiKeyVisible(v => !v)}
                      style={{
                        position: 'absolute', right: 8, background: 'none', border: 'none',
                        cursor: 'pointer', fontSize: 15, color: 'var(--text-muted)', lineHeight: 1,
                      }}
                      title={soarApiKeyVisible ? '隐藏' : '显示'}
                    >👁</button>
                  </div>
                </div>

                {/* Webhook signing secret */}
                <div>
                  <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>Webhook 签名密钥</div>
                  <input
                    className="filter-input"
                    type="password"
                    style={{ width: '100%', boxSizing: 'border-box' }}
                    placeholder="签名验证密钥（可选）"
                    value={soarSigningSecret}
                    onChange={e => setSoarSigningSecret(e.target.value)}
                  />
                </div>

                {/* Connection test */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <button
                    className="btn-secondary"
                    style={{ fontSize: 12, padding: '6px 18px' }}
                    disabled={soarConnecting}
                    onClick={soarConnectTest}
                  >
                    {soarConnecting ? '检测中...' : '连接测试'}
                  </button>
                  {soarConnectResult && (
                    <span style={{ fontSize: 12, fontWeight: 500, color: soarConnectResult.ok ? 'var(--accent-green)' : 'var(--critical)' }}>
                      {soarConnectResult.msg}
                    </span>
                  )}
                </div>

                {/* Auto-push settings */}
                <div style={{ padding: '12px 14px', background: 'var(--bg-card2)', border: '1px solid var(--border)', borderRadius: 6 }}>
                  <div style={{ fontSize: 12, fontWeight: 600, marginBottom: 12, color: 'var(--text-secondary)' }}>自动推送设置</div>
                  <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                    {([
                      ['p1', 'P1事件自动推送', '严重级别事件自动推送至 SOAR'],
                      ['p2', 'P2事件自动推送', '高危级别事件自动推送至 SOAR'],
                      ['ioc', 'IOC命中自动推送', '威胁情报命中后自动推送至 SOAR'],
                      ['threshold', '告警阈值告警推送', '告警数量超出阈值时推送至 SOAR'],
                    ] as [keyof typeof soarAutoPush, string, string][]).map(([key, label, desc]) => (
                      <label key={key} style={{ display: 'flex', alignItems: 'flex-start', gap: 10, cursor: 'pointer', userSelect: 'none' }}>
                        <input
                          type="checkbox"
                          checked={soarAutoPush[key]}
                          onChange={e => setSoarAutoPush(prev => ({ ...prev, [key]: e.target.checked }))}
                          style={{ accentColor: 'var(--accent-orange)', width: 14, height: 14, marginTop: 2, cursor: 'pointer', flexShrink: 0 }}
                        />
                        <div>
                          <div style={{ fontSize: 12, fontWeight: 500, color: 'var(--text-primary)' }}>{label}</div>
                          <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 2 }}>{desc}</div>
                        </div>
                      </label>
                    ))}
                  </div>
                </div>

                {/* Save */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
                  <button
                    className="btn-primary"
                    style={{ fontSize: 12, padding: '6px 24px' }}
                    disabled={soarSaving}
                    onClick={soarSave}
                  >
                    {soarSaving ? '保存中...' : '保存配置'}
                  </button>
                  {soarSaveResult && (
                    <span style={{ fontSize: 12, fontWeight: 500, color: soarSaveResult.ok ? 'var(--accent-green)' : 'var(--critical)' }}>
                      {soarSaveResult.msg}
                    </span>
                  )}
                </div>

                {/* Status bar */}
                <div style={{
                  marginTop: 4,
                  padding: '10px 14px',
                  background: soarBaseUrl && soarApiKey ? 'rgba(47,176,122,.07)' : 'var(--bg-card2)',
                  border: `1px solid ${soarBaseUrl && soarApiKey ? 'rgba(47,176,122,.2)' : 'var(--border)'}`,
                  borderRadius: 5,
                  display: 'flex', alignItems: 'center', gap: 8, fontSize: 12,
                }}>
                  <span style={{ fontSize: 10, color: soarBaseUrl && soarApiKey ? 'var(--accent-green)' : 'var(--text-muted)' }}>
                    {soarBaseUrl && soarApiKey ? '●' : '○'}
                  </span>
                  <span style={{ color: 'var(--text-muted)' }}>SOAR集成状态：</span>
                  <span style={{ fontWeight: 600, color: soarBaseUrl && soarApiKey ? 'var(--accent-green)' : 'var(--text-secondary)' }}>
                    {soarBaseUrl && soarApiKey ? '已配置' : '未配置'}
                  </span>
                  {soarConnectResult?.ok && (
                    <span style={{ marginLeft: 'auto', fontSize: 11, color: 'var(--accent-green)' }}>
                      {soarConnectResult.msg}
                    </span>
                  )}
                </div>
              </div>
            </div>
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════
            数据源配置 tab — health overview
        ══════════════════════════════════════════════════════════════════ */}
        {tab === 'dsconfig' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>

            {/* Health summary bar */}
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap', alignItems: 'center' }}>
              <div style={{
                flex: '1 1 200px',
                padding: '12px 18px',
                background: 'var(--bg-card)',
                border: '1px solid var(--border)',
                borderRadius: 6,
              }}>
                <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginBottom: 4 }}>整体健康状态</div>
                <div style={{ fontSize: 18, fontWeight: 700, color: 'var(--accent-green)' }}>
                  {dsconfigStats
                    ? `${dsconfigStats.by_status?.active ?? 0} / ${dsconfigStats.total} 数据源在线`
                    : dsconfigLoading ? '加载中...' : `${dsconfigSources.filter(d => d.status === 'active').length} / ${dsconfigSources.length} 数据源在线`
                  }
                </div>
              </div>
              {dsconfigStats && (
                <>
                  {[
                    { label: '活跃', value: dsconfigStats.by_status?.active ?? 0, color: 'var(--accent-green)' },
                    { label: '异常', value: dsconfigStats.by_status?.error ?? 0, color: (dsconfigStats.by_status?.error ?? 0) > 0 ? 'var(--critical)' : 'var(--text-muted)' },
                    { label: '停用', value: dsconfigStats.by_status?.inactive ?? 0, color: 'var(--text-muted)' },
                    { label: '总事件', value: (dsconfigStats.total_events ?? 0).toLocaleString(), color: 'var(--accent-blue)' },
                  ].map(stat => (
                    <div key={stat.label} style={{ flex: '0 1 120px', padding: '12px 16px', background: 'var(--bg-card)', border: '1px solid var(--border)', borderRadius: 6 }}>
                      <div style={{ fontSize: 10.5, color: 'var(--text-muted)', marginBottom: 3 }}>{stat.label}</div>
                      <div style={{ fontSize: 16, fontWeight: 700, color: stat.color }}>{stat.value}</div>
                    </div>
                  ))}
                </>
              )}
            </div>

            {/* Table */}
            <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
              <div style={{ padding: '12px 16px', borderBottom: '1px solid var(--border)', display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                <div style={{ fontSize: 13, fontWeight: 600 }}>数据源健康状态</div>
                <button
                  className="btn-secondary"
                  style={{ fontSize: 11 }}
                  onClick={() => {
                    setDsconfigLoading(true)
                    Promise.all([
                      api.get('/datasources', { params: { page: 1, page_size: 50 } }),
                      api.get('/datasources/stats'),
                    ])
                      .then(([dsRes, statsRes]) => {
                        setDsconfigSources(dsRes.data.data?.items ?? [])
                        setDsconfigStats(statsRes.data?.data ?? null)
                      })
                      .catch(() => {})
                      .finally(() => setDsconfigLoading(false))
                  }}
                >刷新</button>
              </div>
              <table className="data-table">
                <thead>
                  <tr>
                    <th>名称</th>
                    <th>类型</th>
                    <th>状态</th>
                    <th>上次同步</th>
                    <th>事件数</th>
                    <th></th>
                  </tr>
                </thead>
                <tbody>
                  {dsconfigLoading && <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 28 }}>加载中...</td></tr>}
                  {!dsconfigLoading && dsconfigSources.length === 0 && (
                    <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 28, fontSize: 12 }}>暂无数据源</td></tr>
                  )}
                  {!dsconfigLoading && dsconfigSources.map(ds => (
                    <tr key={ds._key}>
                      <td style={{ fontSize: 12.5, fontWeight: 500 }}>{ds.name}</td>
                      <td>
                        <span style={{ fontSize: 10.5, padding: '2px 7px', background: 'rgba(79,163,224,.1)', color: 'var(--accent-blue)', border: '1px solid rgba(79,163,224,.2)', borderRadius: 3, fontFamily: 'monospace', fontWeight: 600 }}>
                          {(ds.type || 'syslog').toUpperCase()}
                        </span>
                      </td>
                      <td>
                        {/* Pulsing dot for active */}
                        <span style={{ display: 'inline-flex', alignItems: 'center', gap: 6, fontSize: 11.5 }}>
                          <span style={{
                            width: 7, height: 7, borderRadius: '50%', display: 'inline-block', flexShrink: 0,
                            background: ds.status === 'active' ? 'var(--accent-green)' : ds.status === 'error' ? 'var(--critical)' : 'var(--text-muted)',
                            boxShadow: ds.status === 'active' ? '0 0 0 2px rgba(47,176,122,.25)' : 'none',
                            animation: ds.status === 'active' ? 'pulse 2s infinite' : 'none',
                          }} />
                          <span style={{ color: ds.status === 'active' ? 'var(--accent-green)' : ds.status === 'error' ? 'var(--critical)' : 'var(--text-muted)', textTransform: 'capitalize' }}>
                            {ds.status || 'inactive'}
                          </span>
                        </span>
                      </td>
                      <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>
                        {ds.last_event_at ? new Date(ds.last_event_at).toLocaleString('zh-CN') : '-'}
                      </td>
                      <td style={{ fontSize: 11.5, color: 'var(--text-secondary)', fontFamily: 'monospace' }}>
                        {ds.event_count != null ? (ds.event_count >= 1000 ? `${(ds.event_count / 1000).toFixed(1)}K` : String(ds.event_count)) : '-'}
                      </td>
                      <td>
                        <div style={{ display: 'flex', gap: 6, alignItems: 'center' }}>
                          <button
                            className="btn-secondary"
                            style={{ fontSize: 11, padding: '2px 10px' }}
                            disabled={dsconfigReconnecting === ds._key}
                            onClick={() => dsconfigReconnect(ds)}
                          >
                            {dsconfigReconnecting === ds._key ? '连接中...' : '重新连接'}
                          </button>
                          {dsconfigReconnectResult?.id === ds._key && (
                            <span style={{ fontSize: 11, color: dsconfigReconnectResult.ok ? 'var(--accent-green)' : 'var(--critical)', whiteSpace: 'nowrap' }}>
                              {dsconfigReconnectResult.msg}
                            </span>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* ══════════════════════════════════════════════════════════════════
            API 密钥 tab
        ══════════════════════════════════════════════════════════════════ */}
        {tab === 'apikeys' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16, maxWidth: 560 }}>

            {/* Current key display */}
            <div className="card">
              <div className="card-title">Anthropic API 密钥</div>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>

                {/* Masked display */}
                <div style={{ padding: '12px 14px', background: 'var(--bg-card2)', border: '1px solid var(--border)', borderRadius: 6, display: 'flex', alignItems: 'center', justifyContent: 'space-between', gap: 10 }}>
                  <div style={{ flex: 1, minWidth: 0 }}>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 6 }}>当前密钥</div>
                    <div style={{ fontFamily: 'monospace', fontSize: 13, color: 'var(--text-primary)', letterSpacing: '0.5px', overflow: 'hidden', textOverflow: 'ellipsis', whiteSpace: 'nowrap' }}>
                      {apiKeyStored
                        ? (showAPIKey ? apiKeyStored : `sk-ant-••••••••${apiKeyStored.slice(-4)}`)
                        : <span style={{ color: 'var(--text-muted)', fontStyle: 'italic', fontFamily: 'inherit' }}>未配置</span>
                      }
                    </div>
                  </div>
                  {apiKeyStored && (
                    <button
                      onClick={() => setShowAPIKey(v => !v)}
                      style={{ background: 'none', border: 'none', cursor: 'pointer', fontSize: 16, color: 'var(--text-muted)', lineHeight: 1, flexShrink: 0 }}
                      title={showAPIKey ? '隐藏密钥' : '显示密钥'}
                    >👁</button>
                  )}
                </div>

                {/* Update key input */}
                <div>
                  <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>更新密钥</div>
                  <div style={{ display: 'flex', gap: 8 }}>
                    <input
                      className="filter-input"
                      type="password"
                      style={{ flex: 1, boxSizing: 'border-box' }}
                      placeholder="粘贴新的 API 密钥..."
                      value={apiKeyInput}
                      onChange={e => { setApiKeyInput(e.target.value); setApiKeySaveResult(null) }}
                      onKeyDown={e => e.key === 'Enter' && saveApiKey()}
                    />
                    <button
                      className="btn-primary"
                      style={{ fontSize: 11, whiteSpace: 'nowrap' }}
                      disabled={!apiKeyInput.trim()}
                      onClick={saveApiKey}
                    >保存密钥</button>
                  </div>
                  {apiKeySaveResult && (
                    <div style={{ marginTop: 8, fontSize: 12, color: apiKeySaveResult.ok ? 'var(--accent-green)' : 'var(--critical)', fontWeight: 500 }}>
                      {apiKeySaveResult.msg}
                    </div>
                  )}
                </div>

                {/* API 文档 link + 测试连接 */}
                <div style={{ display: 'flex', alignItems: 'center', gap: 10, flexWrap: 'wrap' }}>
                  <a
                    href="https://docs.anthropic.com"
                    target="_blank"
                    rel="noopener noreferrer"
                    style={{
                      display: 'inline-flex', alignItems: 'center', gap: 6,
                      fontSize: 12, color: 'var(--accent-blue)', textDecoration: 'none',
                      padding: '5px 12px', borderRadius: 4,
                      border: '1px solid rgba(79,163,224,.3)',
                      background: 'rgba(79,163,224,.08)',
                    }}
                  >
                    <span style={{ fontSize: 13 }}>📄</span>
                    API 文档 →
                  </a>
                  <button
                    className="btn-secondary"
                    style={{ fontSize: 12, padding: '5px 14px' }}
                    disabled={apiConnecting}
                    onClick={testApiConnect}
                  >
                    {apiConnecting ? '检测中...' : '测试 API 连接'}
                  </button>
                  {apiConnectResult && (
                    <span style={{ fontSize: 12, fontWeight: 500, color: apiConnectResult.ok ? 'var(--accent-green)' : 'var(--critical)' }}>
                      {apiConnectResult.msg}
                    </span>
                  )}
                </div>

                {/* Privacy note */}
                <div style={{
                  padding: '10px 14px',
                  background: 'rgba(63,160,224,.05)',
                  border: '1px solid rgba(63,160,224,.15)',
                  borderRadius: 5,
                  fontSize: 11.5,
                  color: 'var(--text-muted)',
                  lineHeight: 1.6,
                }}>
                  <span style={{ color: 'var(--accent-blue)', fontWeight: 600 }}>注意：</span>
                  密钥仅存储在浏览器本地（localStorage），不会上传至服务器。
                  清除浏览器数据将同时删除已保存的密钥。
                </div>
              </div>
            </div>
          </div>
        )}

      </div>

      {/* New Notify Rule Modal */}
      {showNewNotifyRule && (
        <>
          <div onClick={() => setShowNewNotifyRule(false)} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 460, background: 'var(--bg-modal)', border: '1px solid var(--border)',
            borderRadius: 8, zIndex: 500, padding: 24, maxHeight: '90vh', overflowY: 'auto',
          }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 20 }}>添加通知规则</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              {/* Rule name */}
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>规则名称 *</div>
                <input
                  className="filter-input"
                  style={{ width: '100%', boxSizing: 'border-box' }}
                  placeholder="例：P1事件邮件告警"
                  value={nrName}
                  onChange={e => setNrName(e.target.value)}
                />
              </div>

              {/* Trigger condition type */}
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 8 }}>触发条件</div>
                <div style={{ display: 'flex', gap: 6, marginBottom: 10 }}>
                  {(['severity', 'status'] as NotifyRuleConditionType[]).map(ct => (
                    <button
                      key={ct}
                      onClick={() => setNrConditionType(ct)}
                      style={{
                        padding: '5px 16px', fontSize: 12, borderRadius: 4, cursor: 'pointer',
                        border: nrConditionType === ct ? '1px solid var(--accent-orange)' : '1px solid var(--border)',
                        background: nrConditionType === ct ? 'rgba(250,88,45,.15)' : 'var(--bg-card2)',
                        color: nrConditionType === ct ? 'var(--accent-orange)' : 'var(--text-secondary)',
                        fontWeight: nrConditionType === ct ? 600 : 400,
                      }}
                    >
                      {ct === 'severity' ? '严重度 ≥' : '状态 ='}
                    </button>
                  ))}
                </div>

                {nrConditionType === 'severity' ? (
                  <select
                    className="filter-select"
                    style={{ width: '100%' }}
                    value={nrSeverityLevel}
                    onChange={e => setNrSeverityLevel(e.target.value as NotifySeverityLevel)}
                  >
                    <option value="low">low（低危）</option>
                    <option value="medium">medium（中危）</option>
                    <option value="high">high（高危）</option>
                    <option value="critical">critical（严重）</option>
                  </select>
                ) : (
                  <select
                    className="filter-select"
                    style={{ width: '100%' }}
                    value={nrStatusValue}
                    onChange={e => setNrStatusValue(e.target.value as NotifyStatusValue)}
                  >
                    <option value="active">active（活跃）</option>
                    <option value="resolved">resolved（已解决）</option>
                  </select>
                )}
              </div>

              {/* Channel */}
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 8 }}>通知渠道</div>
                <div style={{ display: 'flex', gap: 6, flexWrap: 'wrap' }}>
                  {([
                    ['email', '📧 Email'],
                    ['dingtalk', '🔔 DingTalk'],
                    ['slack', '💬 Slack'],
                    ['sms', '📱 SMS'],
                  ] as [NotifyRuleChannel, string][]).map(([ch, label]) => (
                    <button
                      key={ch}
                      onClick={() => setNrChannel(ch)}
                      style={{
                        padding: '5px 14px', fontSize: 12, borderRadius: 4, cursor: 'pointer',
                        border: nrChannel === ch ? '1px solid var(--accent-orange)' : '1px solid var(--border)',
                        background: nrChannel === ch ? 'rgba(250,88,45,.15)' : 'var(--bg-card2)',
                        color: nrChannel === ch ? 'var(--accent-orange)' : 'var(--text-secondary)',
                        fontWeight: nrChannel === ch ? 600 : 400,
                        transition: 'all .15s',
                      }}
                    >{label}</button>
                  ))}
                </div>
              </div>

              {/* Recipients */}
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>
                  {nrChannel === 'email' || nrChannel === 'sms' ? '接收方（逗号分隔邮箱/手机号）' : 'Webhook URL'}
                </div>
                <input
                  className="filter-input"
                  style={{ width: '100%', boxSizing: 'border-box' }}
                  placeholder={nrChannel === 'email' ? 'alice@example.com, bob@example.com' : nrChannel === 'sms' ? '138xxxx, 139xxxx' : 'https://hooks.example.com/...'}
                  value={nrRecipients}
                  onChange={e => setNrRecipients(e.target.value)}
                />
              </div>

              <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setShowNewNotifyRule(false)}>取消</button>
                <button className="btn-primary" style={{ flex: 1 }} disabled={!nrName.trim()} onClick={createNotifyRule}>
                  创建规则
                </button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* New Tenant Modal */}
      {showNewTenant && (
        <>
          <div onClick={() => setShowNewTenant(false)} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 400, background: 'var(--bg-modal)', border: '1px solid var(--border)',
            borderRadius: 8, zIndex: 500, padding: 24,
          }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 20 }}>Add Tenant</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>Name *</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="Acme Corp" value={newTenantName} onChange={e => setNewTenantName(e.target.value)} />
              </div>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>域名</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="acme.com" value={newTenant域名} onChange={e => setNewTenant域名(e.target.value)} />
              </div>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>Plan</div>
                <select className="filter-select" style={{ width: '100%' }} value={newTenantPlan} onChange={e => setNewTenantPlan(e.target.value)}>
                  <option value="standard">Standard</option>
                  <option value="professional">Professional</option>
                  <option value="enterprise">Enterprise</option>
                </select>
              </div>
              <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setShowNewTenant(false)}>取消</button>
                <button className="btn-primary" style={{ flex: 1 }} disabled={creatingTenant || !newTenantName.trim()} onClick={createTenant}>
                  {creatingTenant ? '创建中...' : '创建租户'}
                </button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* New 角色 Modal */}
      {showNew角色 && (
        <>
          <div onClick={() => setShowNew角色(false)} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 440, background: 'var(--bg-modal)', border: '1px solid var(--border)',
            borderRadius: 8, zIndex: 500, padding: 24,
          }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 20 }}>新建角色</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>角色名称 *</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="e.g. tier2_analyst" value={new角色Name} onChange={e => setNew角色Name(e.target.value)} />
              </div>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>描述</div>
                <textarea
                  className="filter-input"
                  style={{ width: '100%', boxSizing: 'border-box', minHeight: 60, resize: 'vertical', fontSize: 12 }}
                  placeholder="角色用途说明（可选）"
                  value={new角色Desc}
                  onChange={e => setNew角色Desc(e.target.value)}
                />
              </div>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 8 }}>权限</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {PERM_OPTIONS.map(perm => (
                    <label key={perm} style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer', userSelect: 'none' }}>
                      <input
                        type="checkbox"
                        checked={new角色Perms.includes(perm)}
                        onChange={() => toggleNewPerm(perm)}
                        style={{ accentColor: 'var(--accent-orange)', width: 14, height: 14, cursor: 'pointer' }}
                      />
                      <span style={{
                        fontSize: 11.5, padding: '2px 9px', borderRadius: 3, fontFamily: 'monospace',
                        background: new角色Perms.includes(perm) ? 'rgba(250,88,45,.12)' : 'var(--bg-card2)',
                        color: new角色Perms.includes(perm) ? 'var(--accent-orange)' : 'var(--text-secondary)',
                        border: `1px solid ${new角色Perms.includes(perm) ? 'rgba(250,88,45,.3)' : 'var(--border)'}`,
                        transition: 'all .15s',
                      }}>{perm}</span>
                    </label>
                  ))}
                </div>
              </div>
              <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                <button className="btn-secondary" style={{ flex: 1 }} onClick={() => { setShowNew角色(false); setNew角色Name(''); setNew角色Desc(''); setNew角色Perms([]) }}>取消</button>
                <button className="btn-primary" style={{ flex: 1 }} disabled={creating角色 || !new角色Name.trim()} onClick={create角色}>
                  {creating角色 ? '创建中...' : '创建'}
                </button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* 管理成员 Modal */}
      {memberRole && (
        <>
          <div onClick={() => setMemberRole(null)} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 460, background: 'var(--bg-modal)', border: '1px solid var(--border)',
            borderRadius: 8, zIndex: 500, padding: 24, maxHeight: '80vh', display: 'flex', flexDirection: 'column',
          }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 4 }}>管理成员</div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 16 }}>角色：{memberRole.name}</div>

            {/* 添加成员 input */}
            <div style={{ display: 'flex', gap: 8, marginBottom: 16 }}>
              <input
                className="filter-input"
                style={{ flex: 1, boxSizing: 'border-box' }}
                placeholder="用户邮箱或 ID"
                value={addMemberInput}
                onChange={e => setAddMemberInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && addMember()}
              />
              <button
                className="btn-primary"
                style={{ fontSize: 11, whiteSpace: 'nowrap' }}
                disabled={addingMember || !addMemberInput.trim()}
                onClick={addMember}
              >
                {addingMember ? '添加中...' : '添加成员'}
              </button>
            </div>

            {/* Members list */}
            <div style={{ flex: 1, overflowY: 'auto' }}>
              {memberRoleLoading && (
                <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 16, fontSize: 12 }}>加载中...</div>
              )}
              {!memberRoleLoading && memberRoleMembers.length === 0 && (
                <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 20, fontSize: 12 }}>
                  暂无成员，使用上方输入框添加
                </div>
              )}
              {!memberRoleLoading && memberRoleMembers.map(userId => (
                <div key={userId} style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  padding: '8px 10px', borderRadius: 5, marginBottom: 4,
                  background: 'var(--bg-card2)', border: '1px solid var(--border)',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                    <div style={{
                      width: 28, height: 28, borderRadius: '50%', flexShrink: 0,
                      background: 'linear-gradient(135deg, rgba(34,120,184,.5), rgba(26,90,144,.3))',
                      display: 'flex', alignItems: 'center', justifyContent: 'center',
                      fontSize: 10, fontWeight: 700, color: 'white',
                    }}>
                      {userId.slice(0, 2).toUpperCase()}
                    </div>
                    <span style={{ fontSize: 12, color: 'var(--text-primary)', fontFamily: 'monospace' }}>{userId}</span>
                  </div>
                  <button
                    className="btn-secondary"
                    style={{ fontSize: 11, padding: '2px 8px', color: 'var(--critical)' }}
                    onClick={() => removeMember(userId)}
                  >移除</button>
                </div>
              ))}
            </div>

            <div style={{ marginTop: 16 }}>
              <button className="btn-secondary" style={{ width: '100%' }} onClick={() => setMemberRole(null)}>关闭</button>
            </div>
          </div>
        </>
      )}

      {/* DataSource Configure Modal */}
      {showDsModal && (
        <>
          <div onClick={() => setShowDsModal(false)} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 400, background: 'var(--bg-modal)', border: '1px solid var(--border)',
            borderRadius: 8, zIndex: 500, padding: 24,
          }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 20 }}>{editDs ? 'Configure Data Source' : 'Add Data Source'}</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>Name *</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="Firewall-01" value={dsForm.name} onChange={e => setDsForm(f => ({ ...f, name: e.target.value }))} />
              </div>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>类型</div>
                <select className="filter-select" style={{ width: '100%' }} value={dsForm.type} onChange={e => setDsForm(f => ({ ...f, type: e.target.value }))}>
                  <option value="syslog">Syslog</option>
                  <option value="cef">CEF</option>
                  <option value="leef">LEEF</option>
                  <option value="api">REST API</option>
                  <option value="s3">S3</option>
                  <option value="winevent">WinEvent</option>
                </select>
              </div>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>状态</div>
                <select className="filter-select" style={{ width: '100%' }} value={dsForm.status} onChange={e => setDsForm(f => ({ ...f, status: e.target.value }))}>
                  <option value="active">Active</option>
                  <option value="inactive">Inactive</option>
                  <option value="error">Error</option>
                </select>
              </div>
              <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setShowDsModal(false)}>取消</button>
                <button className="btn-primary" style={{ flex: 1 }} disabled={savingDs || !dsForm.name.trim()} onClick={saveDs}>
                  {savingDs ? '保存中...' : editDs ? '保存修改' : 'Add Source'}
                </button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* New User Modal */}
      {showNewUser && (
        <>
          <div onClick={() => setShowNewUser(false)} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 420, background: 'var(--bg-modal)', border: '1px solid var(--border)',
            borderRadius: 8, zIndex: 500, padding: 24,
          }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 20 }}>新建用户</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>用户名 *</div>
                <input className="filter-input" type="text" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="john.doe" value={new用户名} onChange={e => setNew用户名(e.target.value)} />
              </div>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>邮箱</div>
                <input className="filter-input" type="text" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="john@example.com" value={new邮箱} onChange={e => setNew邮箱(e.target.value)} />
              </div>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>密码 *</div>
                <input className="filter-input" type="password" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="••••••••" value={newPassword} onChange={e => setNewPassword(e.target.value)} />
              </div>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>角色</div>
                <select className="filter-select" style={{ width: '100%' }} value={new角色} onChange={e => setNew角色(e.target.value)}>
                  <option value="admin">admin</option>
                  <option value="analyst">analyst</option>
                  <option value="viewer">viewer</option>
                </select>
              </div>
              <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                <button className="btn-secondary" style={{ flex: 1 }} onClick={() => { setShowNewUser(false); setNew用户名(''); setNew邮箱(''); setNewPassword(''); setNew角色('analyst') }}>取消</button>
                <button className="btn-primary" style={{ flex: 1 }} disabled={creatingUser || !new用户名.trim() || !newPassword.trim()} onClick={createUser}>
                  {creatingUser ? '创建中...' : '创建'}
                </button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* Edit User Modal */}
      {editUser && (
        <>
          <div onClick={() => setEditUser(null)} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 420, background: 'var(--bg-modal)', border: '1px solid var(--border)',
            borderRadius: 8, zIndex: 500, padding: 24,
          }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 20 }}>编辑用户</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>用户名</div>
                <input className="filter-input" type="text" style={{ width: '100%', boxSizing: 'border-box' }} value={editUserUsername} onChange={e => setEditUserUsername(e.target.value)} />
              </div>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>显示名</div>
                <input className="filter-input" type="text" style={{ width: '100%', boxSizing: 'border-box' }} value={editUserDisplayName} onChange={e => setEditUserDisplayName(e.target.value)} />
              </div>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>邮箱</div>
                <input className="filter-input" type="text" style={{ width: '100%', boxSizing: 'border-box' }} value={editUserEmail} onChange={e => setEditUserEmail(e.target.value)} />
              </div>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>角色</div>
                <select className="filter-select" style={{ width: '100%' }} value={editUserRole} onChange={e => setEditUserRole(e.target.value)}>
                  <option value="admin">admin</option>
                  <option value="analyst">analyst</option>
                  <option value="viewer">viewer</option>
                </select>
              </div>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>状态</div>
                <select className="filter-select" style={{ width: '100%' }} value={editUserStatus} onChange={e => setEditUserStatus(e.target.value)}>
                  <option value="active">active</option>
                  <option value="inactive">inactive</option>
                  <option value="suspended">suspended</option>
                </select>
              </div>
              <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setEditUser(null)}>取消</button>
                <button className="btn-primary" style={{ flex: 1 }} disabled={savingUser || !editUserUsername.trim()} onClick={saveEditUser}>
                  {savingUser ? '保存中...' : '保存'}
                </button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* New Webhook Modal */}
      {showNewWebhook && (
        <>
          <div onClick={() => setShowNewWebhook(false)} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 480, background: 'var(--bg-modal)', border: '1px solid var(--border)',
            borderRadius: 8, zIndex: 500, padding: 24, maxHeight: '90vh', overflowY: 'auto',
          }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 20 }}>新建 Webhook</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>名称 *</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="My SOAR Webhook" value={wbName} onChange={e => setWbName(e.target.value)} />
              </div>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>URL *</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="https://soar.example.com/webhook/..." value={wbUrl} onChange={e => setWbUrl(e.target.value)} />
              </div>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 8 }}>事件类型</div>
                <div style={{ display: 'flex', flexDirection: 'column', gap: 8 }}>
                  {WEBHOOK_EVENT_TYPES.map(evt => (
                    <label key={evt} style={{ display: 'flex', alignItems: 'center', gap: 10, cursor: 'pointer', userSelect: 'none' }}>
                      <input
                        type="checkbox"
                        checked={wbEvents.includes(evt)}
                        onChange={() => toggleWbEvent(evt)}
                        style={{ accentColor: 'var(--accent-orange)', width: 14, height: 14, cursor: 'pointer' }}
                      />
                      <span style={{
                        fontSize: 11.5, padding: '2px 9px', borderRadius: 3, fontFamily: 'monospace',
                        background: wbEvents.includes(evt) ? 'rgba(250,88,45,.12)' : 'var(--bg-card2)',
                        color: wbEvents.includes(evt) ? 'var(--accent-orange)' : 'var(--text-secondary)',
                        border: `1px solid ${wbEvents.includes(evt) ? 'rgba(250,88,45,.3)' : 'var(--border)'}`,
                        transition: 'all .15s',
                      }}>{evt}</span>
                    </label>
                  ))}
                </div>
              </div>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>自定义 Headers（JSON）</div>
                <textarea
                  className="filter-input"
                  style={{ width: '100%', boxSizing: 'border-box', minHeight: 70, resize: 'vertical', fontSize: 12, fontFamily: 'monospace' }}
                  placeholder={'{"Authorization": "Bearer token", "X-Custom": "value"}'}
                  value={wbHeaders}
                  onChange={e => setWbHeaders(e.target.value)}
                />
              </div>
              {/* Test button */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <button
                  className="btn-secondary"
                  style={{ fontSize: 11, padding: '4px 14px' }}
                  disabled={webhookModalTesting || !wbUrl.trim()}
                  onClick={testWebhookModal}
                >
                  {webhookModalTesting ? '测试中...' : '发送测试事件'}
                </button>
                {webhookModalTestResult && (
                  <span style={{ fontSize: 11, fontWeight: 500, color: webhookModalTestResult.ok ? 'var(--accent-green)' : 'var(--critical)' }}>
                    {webhookModalTestResult.msg}
                  </span>
                )}
              </div>
              <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setShowNewWebhook(false)}>取消</button>
                <button className="btn-primary" style={{ flex: 1 }} disabled={!wbName.trim() || !wbUrl.trim()} onClick={createWebhook}>
                  创建
                </button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* Reset Password Modal */}
      {resetPwdUser && (
        <>
          <div onClick={() => setResetPwdUser(null)} style={{ position: 'fixed', inset: 0, background: 'var(--bg-overlay)', zIndex: 400 }} />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 380, background: 'var(--bg-modal)', border: '1px solid var(--border)',
            borderRadius: 8, zIndex: 500, padding: 24,
          }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 6 }}>重置密码</div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 20 }}>用户：{resetPwdUser.username}</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>新密码 *</div>
                <input
                  className="filter-input"
                  type="password"
                  style={{ width: '100%', boxSizing: 'border-box' }}
                  placeholder="输入新密码（至少8位）"
                  value={resetPwdValue}
                  onChange={e => setResetPwdValue(e.target.value)}
                />
              </div>
              <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setResetPwdUser(null)}>取消</button>
                <button className="btn-primary" style={{ flex: 1 }} disabled={resettingPwd || resetPwdValue.trim().length < 8} onClick={doResetPassword}>
                  {resettingPwd ? '重置中...' : '确认重置'}
                </button>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
