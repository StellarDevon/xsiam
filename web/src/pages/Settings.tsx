import { useEffect, useState } from 'react'
import { useNavigate } from 'react-router-dom'
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
  member_count: number
  created_at: string
}

function fmtDate(iso: string) {
  if (!iso) return '-'
  return new Date(iso).toLocaleDateString('zh-CN')
}

interface DataSource {
  _key: string
  name: string
  type: string
  status: string
  last_received: string
  daily_volume: number
}

type Tab = 'profile' | 'users' | 'tenants' | 'roles' | 'datasources'

export default function Settings() {
  const user = getUser()
  const navigate = useNavigate()
  const [tab, setTab] = useState<Tab>('profile')

  const [users, set用户管理] = useState<User[]>([])
  const [usersLoading, set用户管理Loading] = useState(false)
  const [showNewUser, setShowNewUser] = useState(false)
  const [new用户名, setNew用户名] = useState('')
  const [newDisplayName, setNewDisplayName] = useState('')
  const [new邮箱, setNew邮箱] = useState('')
  const [new角色, setNew角色] = useState('analyst')
  const [newPassword, setNewPassword] = useState('')
  const [creatingUser, setCreatingUser] = useState(false)

  const [tenants, set租户] = useState<Tenant[]>([])
  const [tenantsLoading, set租户Loading] = useState(false)

  const [roles, set角色] = useState<Rbac角色[]>([])
  const [rolesLoading, set角色Loading] = useState(false)
  const [expanded角色, setExpanded角色] = useState<string | null>(null)

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
  const [new角色Perms, setNew角色Perms] = useState('')
  const [creating角色, setCreating角色] = useState(false)

  // DataSource configure
  const [showDsModal, setShowDsModal] = useState(false)
  const [editDs, setEditDs] = useState<DataSource | null>(null)
  const [dsForm, setDsForm] = useState({ name: '', type: 'syslog', status: 'active' })
  const [savingDs, setSavingDs] = useState(false)

  useEffect(() => {
    if (tab === 'users' && users.length === 0) {
      set用户管理Loading(true)
      api.get('/users', { params: { page: 1, page_size: 50 } })
        .then(r => set用户管理(r.data.data?.items ?? []))
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
  }, [tab])

  function createUser() {
    if (!new用户名.trim() || !newPassword.trim()) return
    setCreatingUser(true)
    api.post('/users', { username: new用户名, display_name: newDisplayName, email: new邮箱, role: new角色, password: newPassword })
      .then(() => {
        setShowNewUser(false); setNew用户名(''); setNewDisplayName(''); setNew邮箱(''); setNewPassword('')
        set用户管理Loading(true)
        api.get('/users', { params: { page: 1, page_size: 50 } })
          .then(r => set用户管理(r.data.data?.items ?? []))
          .finally(() => set用户管理Loading(false))
      })
      .finally(() => setCreatingUser(false))
  }

  function resetPassword(u: User) {
    const pwd = prompt(`New password for ${u.username} (min 8 chars):`)
    if (!pwd || pwd.length < 8) return
    api.patch(`/users/${u._key}`, { password: pwd })
  }

  function toggleUserStatus(u: User) {
    const newStatus = u.status === 'active' ? 'suspended' : 'active'
    api.patch(`/users/${u._key}`, { status: newStatus })
      .then(() => set用户管理(prev => prev.map(x => x._key === u._key ? { ...x, status: newStatus } : x)))
  }

  function deleteUser(u: User) {
    if (!confirm(`Delete user "${u.username}"? This cannot be undone.`)) return
    api.delete(`/users/${u._key}`)
      .then(() => set用户管理(prev => prev.filter(x => x._key !== u._key)))
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
    const perms = new角色Perms.split(',').map(p => p.trim()).filter(Boolean)
    api.post('/rbac/roles', { name: new角色Name, description: new角色Desc, permissions: perms })
      .then(() => {
        setShowNew角色(false); setNew角色Name(''); setNew角色Desc(''); setNew角色Perms('')
        set角色Loading(true)
        api.get('/rbac/roles', { params: { page: 1, page_size: 50 } })
          .then(r => set角色(r.data.data?.items ?? []))
          .finally(() => set角色Loading(false))
      })
      .finally(() => setCreating角色(false))
  }

  function delete角色(r: Rbac角色) {
    if (!confirm(`Delete role "${r.name}"?`)) return
    api.delete(`/rbac/roles/${r._key}`)
      .then(() => set角色(prev => prev.filter(x => x._key !== r._key)))
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

  const ROLE_LABELS: Record<string, string> = { admin: 'Admin', analyst: 'Analyst', readonly: 'Read-only', responder: 'Responder' }
  const roleColor: Record<string, string> = {
    admin: 'var(--critical)', analyst: 'var(--accent-blue)',
    readonly: 'var(--text-muted)', responder: 'var(--medium)',
  }

  return (
    <div style={{ height: '100%', display: 'flex', flexDirection: 'column', overflow: 'hidden' }}>
      <PageHeader title="Settings" />

      <div className="tab-bar">
        {([['profile', '个人信息'], ['users', '用户管理'], ['tenants', '租户'], ['roles', 'RBAC 角色'], ['datasources', '数据源']] as [Tab, string][]).map(([t, label]) => (
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
                  background: 'linear-gradient(135deg, #fa582d, #d64420)',
                  borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center',
                  fontSize: 16, fontWeight: 700, color: 'white', flexShrink: 0,
                }}>
                  {user?.display_name?.split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase() ?? 'U'}
                </div>
                <div>
                  <div style={{ fontSize: 15, fontWeight: 600 }}>{user?.display_name}</div>
                  <div style={{ fontSize: 12, color: 'var(--text-muted)', marginTop: 2 }}>{user?.email}</div>
                  <div style={{ fontSize: 11, padding: '2px 8px', background: 'rgba(250,88,45,.12)', color: 'var(--accent-orange)', borderRadius: 3, display: 'inline-block', marginTop: 4, textTransform: 'capitalize' }}>{user?.role}</div>
                </div>
              </div>
              {[
                { label: '用户名', value: user?.username ?? '-' },
                { label: '邮箱', value: user?.email ?? '-' },
                { label: '角色', value: user?.role ?? '-' },
                { label: 'Tenant', value: user?.tenant_id ?? '-' },
              ].map(row => (
                <div key={row.label} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid rgba(255,255,255,.04)', fontSize: 12 }}>
                  <span style={{ color: 'var(--text-muted)' }}>{row.label}</span>
                  <span style={{ color: 'var(--text-secondary)' }}>{row.value}</span>
                </div>
              ))}
            </div>

            <div className="card">
              <div className="card-title">Appearance</div>
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '6px 0', fontSize: 12 }}>
                <span style={{ color: 'var(--text-secondary)' }}>Theme</span>
                <span style={{ fontSize: 11, padding: '3px 10px', background: 'var(--bg-card2)', border: '1px solid var(--border-light)', borderRadius: 3 }}>Dark (XSIAM)</span>
              </div>
            </div>

            <div className="card">
              <div className="card-title">Platform</div>
              {[
                { label: 'Product', value: 'XSIAM Console' },
                { label: 'API 版本', value: 'v1' },
                { label: '后端', value: 'Go · ArangoDB' },
              ].map(row => (
                <div key={row.label} style={{ display: 'flex', justifyContent: 'space-between', padding: '6px 0', borderBottom: '1px solid rgba(255,255,255,.04)', fontSize: 12 }}>
                  <span style={{ color: 'var(--text-muted)' }}>{row.label}</span>
                  <span style={{ color: 'var(--text-secondary)' }}>{row.value}</span>
                </div>
              ))}
            </div>

            <div className="card" style={{ borderColor: 'rgba(229,57,53,.2)' }}>
              <div className="card-title" style={{ color: 'var(--critical)' }}>Session</div>
              <button
                className="btn-secondary"
                style={{ color: 'var(--critical)', borderColor: 'rgba(229,57,53,.3)' }}
                onClick={() => { clearAuth(); navigate('/login') }}
              >
                Sign Out
              </button>
            </div>
          </>
        )}

        {tab === 'users' && (
          <div className="card" style={{ padding: 0, overflow: 'hidden' }}>
            <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', padding: '12px 16px', borderBottom: '1px solid var(--border)' }}>
              <div style={{ fontSize: 13, fontWeight: 600 }}>用户管理 ({users.length})</div>
              <button className="btn-primary" style={{ fontSize: 11 }} onClick={() => setShowNewUser(true)}>+ Add User</button>
            </div>
            <table className="data-table">
              <thead>
                <tr>
                  <th>User</th>
                  <th>角色</th>
                  <th>状态</th>
                  <th>Last Login</th>
                  <th>创建时间</th>
                  <th></th>
                </tr>
              </thead>
              <tbody>
                {usersLoading && <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>加载中...</td></tr>}
                {!usersLoading && users.length === 0 && <tr><td colSpan={6} style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24 }}>No users</td></tr>}
                {users.map(u => (
                  <tr key={u._key}>
                    <td>
                      <div style={{ display: 'flex', alignItems: 'center', gap: 8 }}>
                        <div style={{
                          width: 26, height: 26, borderRadius: '50%', flexShrink: 0,
                          background: 'linear-gradient(135deg, rgba(250,88,45,.6), rgba(214,68,32,.4))',
                          display: 'flex', alignItems: 'center', justifyContent: 'center',
                          fontSize: 9, fontWeight: 700, color: 'white',
                        }}>
                          {(u.display_name || u.username || '?').slice(0, 2).toUpperCase()}
                        </div>
                        <div>
                          <div style={{ fontSize: 12, fontWeight: 500 }}>{u.display_name || u.username}</div>
                          <div style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>{u.email || u.username}</div>
                        </div>
                      </div>
                    </td>
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
                      <span style={{ fontSize: 11.5, color: u.status === 'active' ? 'var(--accent-green)' : 'var(--text-muted)', textTransform: 'capitalize' }}>
                        {u.status || 'active'}
                      </span>
                    </td>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{fmtDate(u.last_login)}</td>
                    <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{fmtDate(u.created_at)}</td>
                    <td>
                      <div style={{ display: 'flex', gap: 5 }}>
                        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 7px' }} onClick={() => resetPassword(u)}>Reset Pwd</button>
                        <button
                          className="btn-secondary"
                          style={{ fontSize: 11, padding: '2px 7px', color: u.status === 'active' ? 'var(--high)' : 'var(--accent-green)' }}
                          onClick={() => toggleUserStatus(u)}
                        >
                          {u.status === 'active' ? 'Suspend' : 'Activate'}
                        </button>
                        <button className="btn-secondary" style={{ fontSize: 11, padding: '2px 7px', color: 'var(--critical)' }} onClick={() => deleteUser(u)}>删</button>
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
          <div style={{ display: 'flex', flexDirection: 'column', gap: 12 }}>
            <div style={{ display: 'flex', justifyContent: 'flex-end' }}>
              <button className="btn-primary" style={{ fontSize: 11 }} onClick={() => setShowNew角色(true)}>+ New 角色</button>
            </div>
            {rolesLoading && <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24, fontSize: 12 }}>加载中...</div>}
            {!rolesLoading && roles.length === 0 && <div style={{ textAlign: 'center', color: 'var(--text-muted)', padding: 24, fontSize: 12 }}>No roles defined</div>}
            {roles.map(r => (
              <div key={r._key} className="card">
                <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', cursor: 'pointer' }} onClick={() => setExpanded角色(expanded角色 === r._key ? null : r._key)}>
                  <div>
                    <div style={{ fontSize: 13, fontWeight: 600 }}>{r.name}</div>
                    {r.description && <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginTop: 2 }}>{r.description}</div>}
                  </div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <div style={{ textAlign: 'right' }}>
                      <div style={{ fontSize: 12, color: 'var(--text-secondary)' }}>{r.member_count ?? 0} members</div>
                      <div style={{ fontSize: 10.5, color: 'var(--text-muted)' }}>{r.permissions?.length ?? 0} permissions</div>
                    </div>
                    <button
                      className="btn-secondary"
                      style={{ fontSize: 11, padding: '2px 7px', color: 'var(--critical)' }}
                      onClick={e => { e.stopPropagation(); delete角色(r) }}
                    >删</button>
                    <span style={{ fontSize: 10, color: 'var(--text-muted)' }}>{expanded角色 === r._key ? '▼' : '▶'}</span>
                  </div>
                </div>
                {expanded角色 === r._key && r.permissions && r.permissions.length > 0 && (
                  <div style={{ marginTop: 12, paddingTop: 12, borderTop: '1px solid var(--border)' }}>
                    <div style={{ fontSize: 11, color: 'var(--text-muted)', marginBottom: 8 }}>权限</div>
                    <div style={{ display: 'flex', flexWrap: 'wrap', gap: 4 }}>
                      {r.permissions.map(p => (
                        <span key={p} style={{
                          fontSize: 10.5, padding: '2px 7px', borderRadius: 3, fontFamily: 'monospace',
                          background: 'rgba(250,88,45,.08)', color: 'var(--accent-orange)',
                          border: '1px solid rgba(250,88,45,.2)',
                        }}>{p}</span>
                      ))}
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        )}
        {tab === 'datasources' && (
          <div style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
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
                        <span style={{ fontSize: 10.5, padding: '2px 7px', background: 'rgba(79,163,224,.1)', color: '#4fa3e0', border: '1px solid rgba(79,163,224,.2)', borderRadius: 3, fontFamily: 'monospace', fontWeight: 600 }}>
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
                      <td style={{ fontSize: 11, color: 'var(--text-muted)' }}>{ds.last_received ? new Date(ds.last_received).toLocaleString('zh-CN') : '-'}</td>
                      <td style={{ fontSize: 11.5, color: 'var(--text-secondary)', fontFamily: 'monospace' }}>
                        {ds.daily_volume != null ? `${(ds.daily_volume / 1000).toFixed(1)}K` : '-'}
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

      </div>

      {/* New Tenant Modal */}
      {showNewTenant && (
        <>
          <div onClick={() => setShowNewTenant(false)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.5)', zIndex: 400 }} />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 400, background: 'var(--bg-card)', border: '1px solid var(--border)',
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
          <div onClick={() => setShowNew角色(false)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.5)', zIndex: 400 }} />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 420, background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: 8, zIndex: 500, padding: 24,
          }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 20 }}>New 角色</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>Name *</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="e.g. tier2_analyst" value={new角色Name} onChange={e => setNew角色Name(e.target.value)} />
              </div>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>描述</div>
                <input className="filter-input" style={{ width: '100%', boxSizing: 'border-box' }} placeholder="Optional description" value={new角色Desc} onChange={e => setNew角色Desc(e.target.value)} />
              </div>
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>权限 (comma-separated)</div>
                <textarea
                  className="filter-input"
                  style={{ width: '100%', boxSizing: 'border-box', minHeight: 80, resize: 'vertical', fontFamily: 'monospace', fontSize: 11 }}
                  placeholder="alerts:read, incidents:write, playbooks:execute"
                  value={new角色Perms}
                  onChange={e => setNew角色Perms(e.target.value)}
                />
              </div>
              <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setShowNew角色(false)}>取消</button>
                <button className="btn-primary" style={{ flex: 1 }} disabled={creating角色 || !new角色Name.trim()} onClick={create角色}>
                  {creating角色 ? '创建中...' : 'Create 角色'}
                </button>
              </div>
            </div>
          </div>
        </>
      )}

      {/* DataSource Configure Modal */}
      {showDsModal && (
        <>
          <div onClick={() => setShowDsModal(false)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.5)', zIndex: 400 }} />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 400, background: 'var(--bg-card)', border: '1px solid var(--border)',
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
          <div onClick={() => setShowNewUser(false)} style={{ position: 'fixed', inset: 0, background: 'rgba(0,0,0,.5)', zIndex: 400 }} />
          <div style={{
            position: 'fixed', top: '50%', left: '50%', transform: 'translate(-50%,-50%)',
            width: 420, background: 'var(--bg-card)', border: '1px solid var(--border)',
            borderRadius: 8, zIndex: 500, padding: 24,
          }}>
            <div style={{ fontSize: 15, fontWeight: 600, marginBottom: 20 }}>Add User</div>
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              {[
                { label: '用户名 *', val: new用户名, set: setNew用户名, ph: 'john.doe' },
                { label: '显示名', val: newDisplayName, set: setNewDisplayName, ph: 'John Doe' },
                { label: '邮箱', val: new邮箱, set: setNew邮箱, ph: 'john@example.com' },
                { label: '密码 *', val: newPassword, set: setNewPassword, ph: '••••••••', type: 'password' },
              ].map(f => (
                <div key={f.label}>
                  <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>{f.label}</div>
                  <input
                    className="filter-input"
                    type={(f as any).type ?? 'text'}
                    style={{ width: '100%', boxSizing: 'border-box' }}
                    placeholder={f.ph}
                    value={f.val}
                    onChange={e => f.set(e.target.value)}
                  />
                </div>
              ))}
              <div>
                <div style={{ fontSize: 11.5, color: 'var(--text-muted)', marginBottom: 6 }}>角色</div>
                <select className="filter-select" style={{ width: '100%' }} value={new角色} onChange={e => setNew角色(e.target.value)}>
                  <option value="analyst">Analyst</option>
                  <option value="responder">Responder</option>
                  <option value="readonly">Read-only</option>
                  <option value="admin">Admin</option>
                </select>
              </div>
              <div style={{ display: 'flex', gap: 10, marginTop: 8 }}>
                <button className="btn-secondary" style={{ flex: 1 }} onClick={() => setShowNewUser(false)}>取消</button>
                <button className="btn-primary" style={{ flex: 1 }} disabled={creatingUser || !new用户名.trim() || !newPassword.trim()} onClick={createUser}>
                  {creatingUser ? '创建中...' : '创建用户'}
                </button>
              </div>
            </div>
          </div>
        </>
      )}
    </div>
  )
}
