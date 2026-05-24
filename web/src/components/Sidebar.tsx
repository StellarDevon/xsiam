import { NavLink, useNavigate } from 'react-router-dom'
import { clearAuth, getUser } from '@/lib/auth'
import { useTheme } from '@/lib/theme'

// On the dark-navy sidebar (light mode), nav items need white-family colours.
// In dark mode the sidebar is also very dark, so we keep the same logic.
// We derive colours from CSS vars that are already set correctly in both themes.
//
// light mode: --sidebar-text / --sidebar-text-active / --nav-active-bg / --nav-hover-bg
// dark mode : --text-muted   / --accent-blue          / --nav-active-bg / --nav-hover-bg
//
// Since dark mode sidebar == dark bg too, we can just always use the sidebar vars.
// But the dark theme doesn't define --sidebar-text, so we fall back:
function sidebarNavColor(isActive: boolean, isDark: boolean) {
  if (isDark) {
    return isActive ? 'var(--accent-blue)' : 'var(--text-muted)'
  }
  // light: sidebar is navy, text must be white-family
  return isActive ? 'var(--sidebar-text-active)' : 'var(--sidebar-text)'
}

function sidebarHoverColor(isDark: boolean) {
  return isDark ? 'var(--text-secondary)' : 'rgba(255,255,255,.90)'
}

interface NavItem {
  to: string
  label: string
  icon: React.ReactNode | null
  badge?: { count: number; color: 'red' | 'orange' }
}

const navItems: NavItem[] = [
  {
    to: '/',
    label: '概览',
    icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><rect x="3" y="3" width="7" height="7" rx="1"/><rect x="14" y="3" width="7" height="7" rx="1"/><rect x="3" y="14" width="7" height="7" rx="1"/><rect x="14" y="14" width="7" height="7" rx="1"/></svg>,
  },
  {
    to: '/incidents',
    label: '事件',
    icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M10.29 3.86L1.82 18a2 2 0 001.71 3h16.94a2 2 0 001.71-3L13.71 3.86a2 2 0 00-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/></svg>,
  },
  {
    to: '/alerts',
    label: '告警',
    icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/><path d="M13.73 21a2 2 0 01-3.46 0"/></svg>,
  },
  {
    to: '/causality',
    label: '溯源图',
    icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="5" cy="12" r="2"/><circle cx="19" cy="5" r="2"/><circle cx="19" cy="19" r="2"/><line x1="7" y1="11" x2="17" y2="6"/><line x1="7" y1="13" x2="17" y2="18"/></svg>,
  },
  {
    to: '/query',
    label: '查询中心',
    icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>,
  },
  { to: '__group_response', label: '响应', icon: null },
  {
    to: '/actions',
    label: '动作中心',
    icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><polygon points="5 3 19 12 5 21 5 3"/></svg>,
  },
  {
    to: '/playbooks',
    label: '剧本',
    icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="16" y1="17" x2="8" y2="17"/></svg>,
  },
  { to: '__group_assets', label: '资产与风险', icon: null },
  {
    to: '/assets',
    label: '资产',
    icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/></svg>,
  },
  {
    to: '/identity-risks',
    label: '身份风险',
    icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M20 21v-2a4 4 0 00-4-4H8a4 4 0 00-4 4v2"/><circle cx="12" cy="7" r="4"/><line x1="18" y1="8" x2="23" y2="13"/><line x1="23" y1="8" x2="18" y2="13"/></svg>,
  },
  {
    to: '/vulnerabilities',
    label: '漏洞',
    icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>,
  },
  {
    to: '/exposure',
    label: '暴露面管理',
    icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/></svg>,
  },
  { to: '__group_threat', label: '威胁情报', icon: null },
  {
    to: '/threat-intel',
    label: '威胁情报',
    icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><line x1="12" y1="8" x2="12" y2="13"/><circle cx="12" cy="16" r=".5" fill="currentColor"/></svg>,
  },
  {
    to: '/iocs',
    label: 'IOC 管理',
    icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/><line x1="11" y1="8" x2="11" y2="14"/><line x1="8" y1="11" x2="14" y2="11"/></svg>,
  },
  { to: '__group_aiops', label: 'AI & 案例', icon: null },
  {
    to: '/agentix',
    label: 'Agentix',
    icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><circle cx="12" cy="8" r="4"/><path d="M6 20v-2a4 4 0 014-4h4a4 4 0 014 4v2"/><path d="M16 3.5A4 4 0 0120 7" strokeDasharray="2 2"/></svg>,
  },
  {
    to: '/xsiam-cases',
    label: '案例',
    icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>,
  },
  { to: '__group_infra', label: '基础设施', icon: null },
  {
    to: '/devices',
    label: '设备',
    icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/></svg>,
  },
  {
    to: '/agents-hub',
    label: 'Agent 中心',
    icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><rect x="3" y="11" width="18" height="11" rx="2"/><path d="M7 11V7a5 5 0 0110 0v4"/><circle cx="12" cy="16" r="1" fill="currentColor"/></svg>,
  },
  {
    to: '/detection-rules',
    label: '检测规则',
    icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M22 11.08V12a10 10 0 11-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>,
  },
  {
    to: '/etl-pipeline',
    label: 'ETL 流水线',
    icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M4 4h16v4H4z"/><path d="M4 10h10v4H4z"/><path d="M4 16h6v4H4z"/><polyline points="18 14 22 18 18 22"/><line x1="14" y1="18" x2="22" y2="18"/></svg>,
  },
  { to: '__group_platform', label: '平台管理', icon: null },
  {
    to: '/network-security',
    label: '网络安全',
    icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><rect x="2" y="2" width="20" height="8" rx="2"/><rect x="2" y="14" width="20" height="8" rx="2"/><line x1="6" y1="6" x2="6.01" y2="6" strokeWidth="2.5" strokeLinecap="round"/><line x1="6" y1="18" x2="6.01" y2="18" strokeWidth="2.5" strokeLinecap="round"/><line x1="10" y1="6" x2="18" y2="6"/><line x1="10" y1="18" x2="18" y2="18"/></svg>,
  },
  {
    to: '/endpoint-security',
    label: '终端安全',
    icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><rect x="2" y="3" width="20" height="14" rx="2"/><line x1="8" y1="21" x2="16" y2="21"/><line x1="12" y1="17" x2="12" y2="21"/><path d="M9 10l2 2 4-4" strokeLinecap="round" strokeLinejoin="round"/></svg>,
  },
  {
    to: '/tenant-admin',
    label: '租户管理',
    icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M17 21v-2a4 4 0 00-4-4H5a4 4 0 00-4 4v2"/><circle cx="9" cy="7" r="4"/><path d="M23 21v-2a4 4 0 00-3-3.87"/><path d="M16 3.13a4 4 0 010 7.75"/></svg>,
  },
  {
    to: '/reports',
    label: '报表',
    icon: <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8"><path d="M14 2H6a2 2 0 00-2 2v16a2 2 0 002 2h12a2 2 0 002-2V8z"/><polyline points="14 2 14 8 20 8"/><line x1="16" y1="13" x2="8" y2="13"/><line x1="12" y1="17" x2="8" y2="17"/></svg>,
  },
]

interface SidebarProps { open: boolean; onToggle: () => void }

export default function Sidebar({ open, onToggle }: SidebarProps) {
  const navigate = useNavigate()
  const user = getUser()
  const { theme } = useTheme()
  const isDark = theme === 'dark'
  const initials = user?.display_name?.split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase() ?? 'U'

  return (
    <nav
      className="icon-sidebar"
      style={{
        width: open ? 200 : 48,
        flexShrink: 0,
        background: 'var(--bg-sidebar)',
        borderRight: '1px solid var(--border)',
        display: 'flex', flexDirection: 'column', alignItems: 'flex-start',
        overflow: 'hidden',
        transition: 'width .2s ease',
        height: '100vh',
      }}
    >
      {/* Logo / toggle */}
      <div style={{
        width: '100%', height: 48, display: 'flex', alignItems: 'center',
        padding: '0 4px',
        borderBottom: `1px solid ${isDark ? 'var(--border)' : 'rgba(255,255,255,.12)'}`,
        flexShrink: 0, gap: 0,
      }}>
        <button
          onClick={onToggle}
          style={{
            width: 40, height: 40, display: 'flex', alignItems: 'center', justifyContent: 'center',
            flexShrink: 0, borderRadius: 8, cursor: 'pointer',
            background: 'none', border: 'none', transition: 'background .15s',
          }}
          onMouseEnter={e => (e.currentTarget.style.background = isDark ? 'rgba(255,255,255,.06)' : 'rgba(255,255,255,.10)')}
          onMouseLeave={e => (e.currentTarget.style.background = 'none')}
        >
          {/* Hexagon + scan beam logo */}
          <svg width="30" height="30" viewBox="0 0 30 30" fill="none">
            <defs>
              <linearGradient id="hexGrad" x1="0" y1="0" x2="1" y2="1">
                <stop offset="0%" stopColor="#0078d4"/>
                <stop offset="100%" stopColor="#00c8ff"/>
              </linearGradient>
              <linearGradient id="scanGrad" x1="0" y1="0" x2="1" y2="0">
                <stop offset="0%" stopColor="#00e5ff" stopOpacity="0"/>
                <stop offset="50%" stopColor="#00e5ff" stopOpacity="0.9"/>
                <stop offset="100%" stopColor="#00e5ff" stopOpacity="0"/>
              </linearGradient>
              <clipPath id="hexClip">
                <polygon points="15,2 26,8.5 26,21.5 15,28 4,21.5 4,8.5"/>
              </clipPath>
            </defs>

            {/* Hex fill */}
            <polygon points="15,2 26,8.5 26,21.5 15,28 4,21.5 4,8.5"
              fill="url(#hexGrad)" opacity="0.15"/>

            {/* Hex border */}
            <polygon points="15,2 26,8.5 26,21.5 15,28 4,21.5 4,8.5"
              fill="none" stroke="url(#hexGrad)" strokeWidth="1.4"/>

            {/* Inner hex ring */}
            <polygon points="15,6.5 22.5,10.75 22.5,19.25 15,23.5 7.5,19.25 7.5,10.75"
              fill="none" stroke="#00c8ff" strokeWidth="0.6" opacity="0.45"/>

            {/* Scan line (horizontal sweep) */}
            <rect x="4" y="13.5" width="22" height="2.5" fill="url(#scanGrad)"
              clipPath="url(#hexClip)" opacity="0.85"/>

            {/* Center dot */}
            <circle cx="15" cy="15" r="2" fill="#00e5ff" opacity="0.9"/>
            <circle cx="15" cy="15" r="1" fill="white"/>

            {/* Corner accent dots */}
            <circle cx="15" cy="3.5" r="1" fill="#00c8ff" opacity="0.7"/>
            <circle cx="24.7" cy="9"  r="1" fill="#00c8ff" opacity="0.5"/>
            <circle cx="24.7" cy="21" r="1" fill="#00c8ff" opacity="0.5"/>
            <circle cx="15" cy="26.5" r="1" fill="#00c8ff" opacity="0.7"/>
            <circle cx="5.3"  cy="21" r="1" fill="#00c8ff" opacity="0.5"/>
            <circle cx="5.3"  cy="9"  r="1" fill="#00c8ff" opacity="0.5"/>
          </svg>
        </button>
        <span className="sidebar-logo-text" style={{
          fontSize: 13, fontWeight: 700, letterSpacing: 1,
          background: 'linear-gradient(90deg, #ffffff 0%, #00c8ff 100%)',
          WebkitBackgroundClip: 'text',
          WebkitTextFillColor: 'transparent',
          whiteSpace: 'nowrap', marginLeft: 6,
          opacity: open ? 1 : 0,
          transition: 'opacity .15s .05s',
          pointerEvents: 'none',
        }}>
          XSIAM
        </span>
      </div>

      {/* Nav items */}
      <div style={{ flex: 1, width: 200, display: 'flex', flexDirection: 'column', gap: 0, padding: '8px 4px', overflowY: 'auto', overflowX: 'hidden' }}>
        {navItems.map((item, i) => {
          if (item.to.startsWith('__group_')) {
            if (open) {
              return (
                <div key={i} style={{
                  fontSize: 9, fontWeight: 700, letterSpacing: 1.2,
                  textTransform: 'uppercase' as const,
                  color: 'rgba(79,163,224,.45)',
                  padding: '12px 12px 4px',
                  marginTop: 4,
                  whiteSpace: 'nowrap',
                }}>
                  {item.label}
                </div>
              )
            } else {
              return (
                <div key={i} style={{
                  height: 1,
                  background: 'rgba(255,255,255,.08)',
                  margin: '8px 4px',
                }} />
              )
            }
          }
          return (
            <NavLink
              key={item.to}
              to={item.to}
              end={item.to === '/'}
              title={!open ? item.label : undefined}
              style={({ isActive }) => ({
                position: 'relative', width: 192, height: 36,
                display: 'flex', alignItems: 'center', justifyContent: 'flex-start',
                padding: '0 10px 0 8px', gap: 10, borderRadius: 8, textDecoration: 'none',
                color: sidebarNavColor(isActive, isDark),
                background: isActive
                  ? (!open ? 'rgba(0,120,212,.30)' : 'var(--nav-active-bg)')
                  : 'none',
                borderLeft: isActive ? '2px solid var(--accent-blue)' : '2px solid transparent',
                transition: 'background .15s, color .15s, border-color .15s',
                whiteSpace: 'nowrap', overflow: 'hidden',
                flexShrink: 0,
              })}
              onMouseEnter={e => {
                const el = e.currentTarget
                if (!el.classList.contains('active')) {
                  el.style.background = 'var(--nav-hover-bg)'
                  el.style.color = sidebarHoverColor(isDark)
                }
              }}
              onMouseLeave={e => {
                const el = e.currentTarget
                if (!el.classList.contains('active')) {
                  el.style.background = 'none'
                  el.style.color = isDark ? 'var(--text-muted)' : 'var(--sidebar-text)'
                }
              }}
            >
              <span style={{ flexShrink: 0 }}>{item.icon}</span>
              <span style={{
                fontSize: 12.5,
                opacity: open ? 1 : 0,
                transition: 'opacity .15s .05s',
                pointerEvents: 'none',
              }}>
                {item.label}
              </span>
              {item.badge && (
                <span style={{
                  position: 'absolute', top: '50%', transform: 'translateY(-50%)', right: 8,
                  fontSize: 8, fontWeight: 700, padding: '1px 4px', borderRadius: 6, minWidth: 16,
                  textAlign: 'center', lineHeight: 1.4,
                  background: item.badge.color === 'red' ? 'var(--critical)' : 'var(--high)',
                  color: 'white',
                  opacity: open ? 1 : 0,
                  transition: 'opacity .15s',
                }}>
                  {item.badge.count}
                </span>
              )}
            </NavLink>
          )
        })}
      </div>

      {/* Bottom: avatar + collapse button (settings removed — accessible via TopBar user menu) */}
      <div style={{
        width: 200, display: 'flex', flexDirection: 'column',
        padding: '8px 4px 12px', gap: 4,
        borderTop: `1px solid ${isDark ? 'var(--border)' : 'rgba(255,255,255,.12)'}`,
        flexShrink: 0,
      }}>
        {/* Avatar row */}
        <div
          title={!open ? `${user?.display_name ?? ''} — 点击退出` : undefined}
          style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '4px 10px' }}
        >
          <div
            onClick={() => { clearAuth(); navigate('/login') }}
            style={{
              width: 30, height: 30,
              background: 'linear-gradient(135deg, #0078d4, #005ba1)',
              borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center',
              fontSize: 10, fontWeight: 700, cursor: 'pointer', color: 'white', flexShrink: 0,
            }}
            title={`${user?.display_name ?? ''} — Click to logout`}
          >
            {initials}
          </div>
          <span style={{
            fontSize: 12,
            color: isDark ? 'var(--text-secondary)' : 'rgba(255,255,255,.65)',
            whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
            opacity: open ? 1 : 0, transition: 'opacity .15s .05s',
          }}>
            {user?.display_name}
          </span>
        </div>

        {/* Collapse / expand button */}
        <button
          onClick={onToggle}
          title={open ? '收起侧栏' : '展开侧栏'}
          style={{
            display: 'flex', alignItems: 'center', gap: 8,
            width: 192, height: 32,
            padding: '0 10px 0 8px', borderRadius: 8,
            background: 'none', border: 'none', cursor: 'pointer',
            color: isDark ? 'var(--text-muted)' : 'rgba(255,255,255,.45)',
            transition: 'background .15s, color .15s',
            flexShrink: 0,
          }}
          onMouseEnter={e => {
            e.currentTarget.style.background = isDark ? 'rgba(255,255,255,.06)' : 'rgba(255,255,255,.10)'
            e.currentTarget.style.color = isDark ? 'var(--text-secondary)' : 'rgba(255,255,255,.80)'
          }}
          onMouseLeave={e => {
            e.currentTarget.style.background = 'none'
            e.currentTarget.style.color = isDark ? 'var(--text-muted)' : 'rgba(255,255,255,.45)'
          }}
        >
          {/* Chevron icon — points left when expanded, right when collapsed */}
          <svg
            width="16" height="16" viewBox="0 0 24 24" fill="none"
            stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"
            style={{ flexShrink: 0, transition: 'transform .2s', transform: open ? 'rotate(0deg)' : 'rotate(180deg)' }}
          >
            <polyline points="15 18 9 12 15 6"/>
          </svg>
          <span style={{
            fontSize: 12, opacity: open ? 1 : 0,
            transition: 'opacity .15s .05s',
            whiteSpace: 'nowrap',
          }}>
            收起侧栏
          </span>
        </button>
      </div>
    </nav>
  )
}
