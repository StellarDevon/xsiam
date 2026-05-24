import { useCallback, useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useTheme } from '@/lib/theme'
import { useLang, useT } from '@/lib/i18n'
import { clearAuth, getSecondsToExpiry, getUser } from '@/lib/auth'
import api from '@/lib/api'

/* ── blink keyframe injected once ── */
const blinkStyle = `
@keyframes xsiam-blink {
  0%, 100% { opacity: 1; }
  50%       { opacity: 0.3; }
}
.xsiam-expiry-blink {
  animation: xsiam-blink 1s step-start infinite;
}
`
let blinkInjected = false
function injectBlink() {
  if (blinkInjected) return
  const el = document.createElement('style')
  el.textContent = blinkStyle
  document.head.appendChild(el)
  blinkInjected = true
}

/* ── severity colour helper ── */
function severityColor(sev: string) {
  switch ((sev ?? '').toLowerCase()) {
    case 'critical': return 'var(--critical)'
    case 'high':     return 'var(--high)'
    case 'medium':   return 'var(--medium)'
    case 'low':      return 'var(--accent-green)'
    default:         return 'var(--text-muted)'
  }
}

/* ── relative time ── */
function relativeTime(iso: string): string {
  const diff = Math.floor((Date.now() - new Date(iso).getTime()) / 1000)
  if (diff < 60)    return `${diff}秒前`
  if (diff < 3600)  return `${Math.floor(diff / 60)}分钟前`
  if (diff < 86400) return `${Math.floor(diff / 3600)}小时前`
  return `${Math.floor(diff / 86400)}天前`
}

interface AlertRow {
  _key: string
  name: string
  severity: string
  created_at: string
  triggered_at?: string
}

/* ── localStorage helpers ── */
const LS_RECENT    = 'xsiam_recent_searches'
const LS_LAST_CHK  = 'xsiam_notif_last_checked'

function loadRecentSearches(): string[] {
  try { return JSON.parse(localStorage.getItem(LS_RECENT) ?? '[]') } catch { return [] }
}
function saveRecentSearches(arr: string[]) {
  localStorage.setItem(LS_RECENT, JSON.stringify(arr.slice(0, 5)))
}
function loadLastChecked(): Date {
  const s = localStorage.getItem(LS_LAST_CHK)
  return s ? new Date(s) : new Date(0)
}
function saveLastChecked(d: Date) {
  localStorage.setItem(LS_LAST_CHK, d.toISOString())
}

/* ── Quick-nav entries ── */
const QUICK_NAV = [
  { icon: '🔔', label: '告警管理',  path: '/alerts' },
  { icon: '🔗', label: '事件管理',  path: '/incidents' },
  { icon: '🛡️', label: '威胁情报',  path: '/threat-intel' },
  { icon: '⚙️', label: '设置',      path: '/settings' },
]

/* ── Mock system notifications ── */
const SYSTEM_NOTIFS = [
  { id: 'sys-1', icon: '✅', text: 'ArangoDB连接正常', time: '刚刚' },
  { id: 'sys-2', icon: '💾', text: '上次备份: 2小时前', time: '2小时前' },
  { id: 'sys-3', icon: 'ℹ️', text: '系统版本 v2.4.1 已就绪', time: '5小时前' },
]

/* ── useClickOutside ── */
function useClickOutside(ref: React.RefObject<HTMLElement | null>, onClose: () => void) {
  useEffect(() => {
    function handler(e: MouseEvent) {
      if (ref.current && !ref.current.contains(e.target as Node)) onClose()
    }
    document.addEventListener('mousedown', handler)
    return () => document.removeEventListener('mousedown', handler)
  }, [ref, onClose])
}

/* ──────────────────────────────────────────────────────────────────────────── */

export default function TopBar() {
  injectBlink()

  const navigate = useNavigate()
  const { theme, toggle: toggleTheme } = useTheme()
  const { lang, setLang } = useLang()
  const t = useT()
  const user = getUser()

  const [secsLeft, setSecsLeft]     = useState<number>(() => getSecondsToExpiry())
  const [showRenew, setShowRenew]   = useState(false)
  const [renewToast, setRenewToast] = useState('')
  const renewTimerRef               = useRef<ReturnType<typeof setTimeout> | null>(null)

  /* ── Search modal state ── */
  const [showSearch, setShowSearch]       = useState(false)
  const [searchQuery, setSearchQuery]     = useState('')
  const [searchResults, setSearchResults] = useState<AlertRow[]>([])
  const [recentSearches, setRecentSearches] = useState<string[]>(() => loadRecentSearches())
  const [searchHighlight, setSearchHighlight] = useState(-1)
  const searchInputRef = useRef<HTMLInputElement>(null)
  const debounceRef    = useRef<ReturnType<typeof setTimeout> | null>(null)

  /* ── Notifications state ── */
  const [notifOpen, setNotifOpen]         = useState(false)
  const [notifications, setNotifications] = useState<AlertRow[]>([])
  const [newCount, setNewCount]           = useState(0)
  const [lastChecked, setLastChecked]     = useState<Date>(() => loadLastChecked())
  const [notifTab, setNotifTab]           = useState<'alerts' | 'system'>('alerts')
  const notifRef = useRef<HTMLDivElement>(null)
  useClickOutside(notifRef, () => setNotifOpen(false))

  /* ── User menu state ── */
  const [userMenuOpen, setUserMenuOpen] = useState(false)
  const userMenuRef = useRef<HTMLDivElement>(null)
  useClickOutside(userMenuRef, () => setUserMenuOpen(false))

  /* ── Fetch notifications (with newCount tracking) ── */
  const fetchNotifications = useCallback(async () => {
    try {
      const res = await api.get('/alerts', {
        params: { sort_by: 'triggered_at', sort_desc: true, page_size: 5, hours: 1 },
      })
      const items: AlertRow[] = res.data?.data?.items ?? res.data?.items ?? []
      setNotifications(items)
      // Count items newer than lastChecked
      const chk = loadLastChecked()
      const fresh = items.filter(n => {
        const t = n.triggered_at ?? n.created_at
        return t && new Date(t) > chk
      })
      setNewCount(fresh.length)
    } catch {
      // network / mock — ignore
    }
  }, [])

  useEffect(() => {
    fetchNotifications()
    const id = setInterval(fetchNotifications, 60_000)
    return () => clearInterval(id)
  }, [fetchNotifications])

  /* ── Session expiry ticker ── */
  useEffect(() => {
    const id = setInterval(() => setSecsLeft(getSecondsToExpiry()), 60_000)
    return () => clearInterval(id)
  }, [])

  /* ── Ctrl+K / Escape global listener ── */
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault()
        setShowSearch(true)
      }
      if (e.key === 'Escape') {
        setShowSearch(false)
      }
    }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [])

  /* ── Auto-focus search input when modal opens ── */
  useEffect(() => {
    if (showSearch) {
      setTimeout(() => searchInputRef.current?.focus(), 50)
      setSearchQuery('')
      setSearchResults([])
      setSearchHighlight(-1)
    }
  }, [showSearch])

  /* ── Debounced search fetch ── */
  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current)
    if (searchQuery.length < 2) {
      setSearchResults([])
      return
    }
    debounceRef.current = setTimeout(async () => {
      try {
        const res = await api.get('/alerts', { params: { q: searchQuery, page_size: 5 } })
        const items: AlertRow[] = res.data?.data?.items ?? res.data?.items ?? []
        setSearchResults(items)
      } catch {
        setSearchResults([])
      }
    }, 300)
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current)
    }
  }, [searchQuery])

  /* ── Search keyboard navigation ── */
  function handleSearchKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    const totalNav  = QUICK_NAV.length
    const totalRes  = searchResults.length
    const totalItems = searchQuery.length >= 2 ? totalRes : totalNav

    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setSearchHighlight(prev => (prev + 1) % totalItems)
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setSearchHighlight(prev => (prev <= 0 ? totalItems - 1 : prev - 1))
    } else if (e.key === 'Enter') {
      e.preventDefault()
      if (searchQuery.trim()) {
        addRecentSearch(searchQuery.trim())
      }
      if (searchQuery.length >= 2 && searchResults.length > 0) {
        const idx = searchHighlight >= 0 ? searchHighlight : 0
        const hit = searchResults[idx]
        if (hit) {
          navigate('/alerts')
          setShowSearch(false)
          return
        }
      }
      // Navigate to highlighted quick-nav entry
      const navIdx = searchHighlight >= 0 ? searchHighlight : 0
      const navItem = QUICK_NAV[navIdx]
      if (navItem && searchQuery.length < 2) {
        navigate(navItem.path)
        setShowSearch(false)
      }
    }
  }

  function addRecentSearch(term: string) {
    setRecentSearches(prev => {
      const updated = [term, ...prev.filter(s => s !== term)].slice(0, 5)
      saveRecentSearches(updated)
      return updated
    })
  }

  function handleQuickNav(path: string) {
    if (searchQuery.trim()) addRecentSearch(searchQuery.trim())
    navigate(path)
    setShowSearch(false)
  }

  function handleAlertResult(item: AlertRow) {
    addRecentSearch(item.name ?? searchQuery)
    navigate('/alerts')
    setShowSearch(false)
  }

  function handleRecentClick(term: string) {
    setSearchQuery(term)
    searchInputRef.current?.focus()
  }

  /* ── Mark all read ── */
  function handleMarkAllRead() {
    const now = new Date()
    setLastChecked(now)
    saveLastChecked(now)
    setNewCount(0)
  }

  async function handleRenew() {
    try { await api.post('/auth/refresh') } catch { /* ignore */ }
    setRenewToast('续期成功，会话已延长')
    setShowRenew(false)
    if (renewTimerRef.current) clearTimeout(renewTimerRef.current)
    renewTimerRef.current = setTimeout(() => setRenewToast(''), 3000)
  }

  function handleLogout() {
    clearAuth()
    navigate('/login')
  }

  function roleLabel(role: string) {
    const map: Record<string, string> = {
      admin: '管理员', analyst: '分析师', operator: '操作员', viewer: '只读',
    }
    return map[role] ?? role
  }

  const showIndicator = secsLeft < 1800
  const isCritical    = secsLeft < 300
  const minsLeft      = Math.floor(secsLeft / 60)
  const isDark        = theme === 'dark'

  const initials = user?.display_name?.split(' ').map(w => w[0]).join('').slice(0, 2).toUpperCase() ?? 'U'

  return (
    <>
      {/* ── Global Search Modal ── */}
      {showSearch && (
        <div
          onClick={() => setShowSearch(false)}
          style={{
            position: 'fixed', inset: 0,
            background: 'var(--bg-overlay)',
            backdropFilter: 'blur(4px)',
            zIndex: 1000,
            display: 'flex', alignItems: 'flex-start', justifyContent: 'center',
            paddingTop: 80,
          }}
        >
          <div
            onClick={e => e.stopPropagation()}
            style={{
              width: 560, maxWidth: 'calc(100vw - 32px)',
              background: 'var(--bg-primary)',
              border: '1px solid rgba(79,163,224,.30)',
              borderRadius: 10,
              boxShadow: '0 24px 64px rgba(0,0,0,.8)',
              overflow: 'hidden',
              animation: 'notif-slide-in .12s ease',
            }}
          >
            {/* Search input row */}
            <div style={{
              display: 'flex', alignItems: 'center', gap: 10,
              padding: '12px 16px',
              borderBottom: '1px solid rgba(79,163,224,.15)',
            }}>
              <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="rgba(79,163,224,.70)" strokeWidth="2">
                <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
              </svg>
              <input
                ref={searchInputRef}
                value={searchQuery}
                onChange={e => { setSearchQuery(e.target.value); setSearchHighlight(-1) }}
                onKeyDown={handleSearchKeyDown}
                placeholder={t('search_placeholder')}
                style={{
                  flex: 1, background: 'none', border: 'none', outline: 'none',
                  fontSize: 15, color: 'rgba(255,255,255,.90)',
                  caretColor: 'var(--accent-blue)',
                }}
              />
              <span
                onClick={() => setShowSearch(false)}
                style={{
                  fontSize: 10, color: 'rgba(79,163,224,.50)',
                  padding: '2px 6px', borderRadius: 4,
                  border: '1px solid rgba(79,163,224,.20)',
                  background: 'rgba(0,0,0,.25)',
                  cursor: 'pointer', userSelect: 'none',
                  fontFamily: 'monospace',
                }}
              >
                {t('esc_close')}
              </span>
            </div>

            {/* Recent searches */}
            {recentSearches.length > 0 && searchQuery.length < 2 && (
              <div style={{ padding: '10px 16px', borderBottom: '1px solid rgba(79,163,224,.10)' }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: 'rgba(79,163,224,.50)', letterSpacing: 1, marginBottom: 7, textTransform: 'uppercase' }}>
                  {t('recent_search')}
                </div>
                <div style={{ display: 'flex', flexWrap: 'wrap', gap: 6 }}>
                  {recentSearches.map((s, i) => (
                    <span
                      key={i}
                      onClick={() => handleRecentClick(s)}
                      style={{
                        fontSize: 11, padding: '3px 9px', borderRadius: 12,
                        background: 'rgba(0,120,212,.15)',
                        border: '1px solid rgba(79,163,224,.20)',
                        color: 'var(--accent-blue)', cursor: 'pointer',
                        transition: 'background .12s',
                      }}
                      onMouseEnter={e => (e.currentTarget.style.background = 'rgba(0,120,212,.30)')}
                      onMouseLeave={e => (e.currentTarget.style.background = 'rgba(0,120,212,.15)')}
                    >
                      · {s}
                    </span>
                  ))}
                </div>
              </div>
            )}

            {/* Quick navigation (shown when no typed query or query < 2 chars) */}
            {searchQuery.length < 2 && (
              <div style={{ padding: '10px 0', borderBottom: '1px solid rgba(79,163,224,.10)' }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: 'rgba(79,163,224,.50)', letterSpacing: 1, marginBottom: 4, textTransform: 'uppercase', padding: '0 16px' }}>
                  {t('quick_nav')}
                </div>
                {QUICK_NAV.map((item, i) => (
                  <div
                    key={item.path}
                    onClick={() => handleQuickNav(item.path)}
                    style={{
                      display: 'flex', alignItems: 'center', gap: 10,
                      padding: '8px 16px', cursor: 'pointer',
                      background: searchHighlight === i ? 'rgba(0,120,212,.18)' : 'none',
                      transition: 'background .1s',
                    }}
                    onMouseEnter={e => { if (searchHighlight !== i) e.currentTarget.style.background = 'rgba(0,120,212,.10)' }}
                    onMouseLeave={e => { if (searchHighlight !== i) e.currentTarget.style.background = 'none' }}
                  >
                    <span style={{ fontSize: 14 }}>{item.icon}</span>
                    <span style={{ flex: 1, fontSize: 12.5, color: 'rgba(255,255,255,.80)' }}>{item.label}</span>
                    <span style={{ fontSize: 11, color: 'rgba(79,163,224,.45)', fontFamily: 'monospace' }}>{item.path}</span>
                    <span style={{ fontSize: 11, color: 'rgba(79,163,224,.35)' }}>→</span>
                  </div>
                ))}
              </div>
            )}

            {/* Search results (shown when query >= 2 chars) */}
            {searchQuery.length >= 2 && (
              <div style={{ padding: '10px 0' }}>
                <div style={{ fontSize: 10, fontWeight: 700, color: 'rgba(79,163,224,.50)', letterSpacing: 1, marginBottom: 4, textTransform: 'uppercase', padding: '0 16px' }}>
                  {t('search_results')} {searchResults.length > 0 ? `(${searchResults.length})` : ''}
                </div>
                {searchResults.length === 0 ? (
                  <div style={{ padding: '16px', textAlign: 'center', fontSize: 12, color: 'rgba(79,163,224,.40)' }}>
                    {t('no_results')}
                  </div>
                ) : (
                  searchResults.map((r, i) => (
                    <div
                      key={r._key ?? i}
                      onClick={() => handleAlertResult(r)}
                      style={{
                        display: 'flex', alignItems: 'center', gap: 10,
                        padding: '8px 16px', cursor: 'pointer',
                        background: searchHighlight === i ? 'rgba(0,120,212,.18)' : 'none',
                        transition: 'background .1s',
                      }}
                      onMouseEnter={e => { if (searchHighlight !== i) e.currentTarget.style.background = 'rgba(0,120,212,.10)' }}
                      onMouseLeave={e => { if (searchHighlight !== i) e.currentTarget.style.background = 'none' }}
                    >
                      <span style={{ fontSize: 13 }}>📋</span>
                      <div style={{ flex: 1, overflow: 'hidden' }}>
                        <span style={{
                          fontSize: 12, color: 'rgba(255,255,255,.82)',
                          whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
                          display: 'block',
                        }}>
                          告警: {(r.name ?? '').length > 40 ? r.name.slice(0, 40) + '…' : (r.name ?? '')}
                        </span>
                      </div>
                      <span style={{
                        fontSize: 10, padding: '1px 6px', borderRadius: 3,
                        background: `${severityColor(r.severity)}22`,
                        border: `1px solid ${severityColor(r.severity)}55`,
                        color: severityColor(r.severity),
                        flexShrink: 0,
                      }}>
                        {r.severity}
                      </span>
                      <span style={{ fontSize: 10, color: 'rgba(79,163,224,.45)', flexShrink: 0 }}>
                        {r.created_at ? relativeTime(r.created_at) : ''}
                      </span>
                    </div>
                  ))
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* ── TopBar ── */}
      <div style={{
        height: 48,
        display: 'flex', alignItems: 'center', gap: 8,
        padding: '0 20px',
        background: 'var(--bg-sidebar)',
        borderBottom: '1px solid var(--border)',
        flexShrink: 0, zIndex: 100,
        position: 'relative',
      }}>

        {/* ── Right-side controls ── */}
        <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 8 }}>

          {/* Session expiry indicator */}
          {showIndicator && (
            <div style={{ position: 'relative' }}>
              <button
                onClick={() => setShowRenew(prev => !prev)}
                className={isCritical ? 'xsiam-expiry-blink' : undefined}
                style={{
                  display: 'flex', alignItems: 'center', gap: 4,
                  padding: '0 8px', height: 18, borderRadius: 4,
                  border: `1px solid ${isCritical ? 'rgba(224,80,80,.45)' : 'rgba(224,128,64,.40)'}`,
                  background: isCritical ? 'rgba(224,80,80,.12)' : 'rgba(224,128,64,.10)',
                  color: isCritical ? 'var(--critical)' : 'var(--high)',
                  fontSize: 10, fontWeight: 600,
                  cursor: 'pointer',
                }}
              >
                {isCritical ? '⚠️ 即将过期' : `⏰ 会话剩余 ${minsLeft}m`}
              </button>

              {showRenew && (
                <div style={{
                  position: 'absolute', top: 24, right: 0,
                  background: 'var(--bg-card)',
                  border: '1px solid #0a2a4a',
                  borderRadius: 6, padding: '10px 14px',
                  boxShadow: '0 4px 16px rgba(0,0,0,.5)',
                  zIndex: 200, whiteSpace: 'nowrap',
                  display: 'flex', flexDirection: 'column', gap: 8,
                  minWidth: 140,
                }}>
                  <span style={{ fontSize: 11, color: 'var(--accent-blue)' }}>
                    {isCritical ? '会话即将过期！' : `剩余 ${minsLeft} 分钟`}
                  </span>
                  <button
                    onClick={handleRenew}
                    style={{
                      background: 'var(--accent-blue)', border: 'none', borderRadius: 4,
                      color: '#fff', fontSize: 12, fontWeight: 600,
                      padding: '5px 12px', cursor: 'pointer',
                    }}
                  >
                    续期会话
                  </button>
                </div>
              )}
            </div>
          )}

          {/* Renew success toast */}
          {renewToast && (
            <span style={{
              fontSize: 11, color: 'var(--accent-green)',
              padding: '1px 8px', borderRadius: 4,
              background: 'rgba(47,176,122,.12)',
              border: '1px solid rgba(47,176,122,.3)',
            }}>
              {renewToast}
            </span>
          )}

          {/* Language toggle */}
          <div style={{ display: 'flex', borderRadius: 4, overflow: 'hidden', border: '1px solid rgba(79,163,224,.30)' }}>
            {(['en', 'zh'] as const).map(l => (
              <button
                key={l}
                onClick={() => setLang(l)}
                style={{
                  padding: '0 8px', height: 18, fontSize: 10, fontWeight: 600,
                  cursor: 'pointer', border: 'none', letterSpacing: .4,
                  background: lang === l ? 'rgba(0,120,212,.55)' : 'transparent',
                  color: lang === l ? 'var(--text-primary)' : 'rgba(79,163,224,.70)',
                  transition: 'background .15s, color .15s',
                }}
              >
                {l === 'en' ? 'EN' : '中文'}
              </button>
            ))}
          </div>

          {/* Theme toggle */}
          <button
            onClick={toggleTheme}
            title={theme === 'light' ? 'Switch to dark mode' : 'Switch to light mode'}
            style={{
              width: 24, height: 24, display: 'flex', alignItems: 'center', justifyContent: 'center',
              background: 'none', border: 'none', cursor: 'pointer',
              color: 'rgba(79,163,224,.80)', borderRadius: 4,
              transition: 'background .15s, color .15s',
            }}
            onMouseEnter={e => { e.currentTarget.style.background = 'rgba(255,255,255,.10)'; e.currentTarget.style.color = 'var(--text-primary)' }}
            onMouseLeave={e => { e.currentTarget.style.background = 'none'; e.currentTarget.style.color = 'rgba(79,163,224,.80)' }}
          >
            {theme === 'light' ? (
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/>
              </svg>
            ) : (
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <circle cx="12" cy="12" r="5"/>
                <line x1="12" y1="1" x2="12" y2="3"/>
                <line x1="12" y1="21" x2="12" y2="23"/>
                <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/>
                <line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>
                <line x1="1" y1="12" x2="3" y2="12"/>
                <line x1="21" y1="12" x2="23" y2="12"/>
                <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/>
                <line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
              </svg>
            )}
          </button>

          {/* ── Bell / Notifications ── */}
          <div ref={notifRef} style={{ position: 'relative' }}>
            <button
              onClick={() => setNotifOpen(prev => !prev)}
              title="通知"
              style={{
                width: 24, height: 24, display: 'flex', alignItems: 'center', justifyContent: 'center',
                background: notifOpen ? 'rgba(255,255,255,.10)' : 'none',
                border: 'none', cursor: 'pointer',
                color: 'rgba(79,163,224,.80)', borderRadius: 4,
                transition: 'background .15s, color .15s',
                position: 'relative',
              }}
              onMouseEnter={e => { e.currentTarget.style.background = 'rgba(255,255,255,.10)'; e.currentTarget.style.color = 'var(--text-primary)' }}
              onMouseLeave={e => {
                if (!notifOpen) { e.currentTarget.style.background = 'none'; e.currentTarget.style.color = 'rgba(79,163,224,.80)' }
              }}
            >
              {/* Bell icon */}
              <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
                <path d="M18 8A6 6 0 006 8c0 7-3 9-3 9h18s-3-2-3-9"/>
                <path d="M13.73 21a2 2 0 01-3.46 0"/>
              </svg>
              {/* New-count badge */}
              {newCount > 0 && (
                <span style={{
                  position: 'absolute', top: 1, right: 1,
                  minWidth: 13, height: 13,
                  background: 'var(--critical)',
                  borderRadius: 7, fontSize: 8, fontWeight: 700,
                  color: '#fff', display: 'flex', alignItems: 'center', justifyContent: 'center',
                  padding: '0 3px', lineHeight: 1,
                  border: '1px solid #001e3c',
                }}>
                  {newCount > 99 ? '99+' : newCount}
                </span>
              )}
            </button>

            {/* Notifications dropdown */}
            {notifOpen && (
              <div style={{
                position: 'absolute', top: 28, right: 0,
                width: 320,
                background: isDark ? 'var(--bg-card)' : 'var(--bg-card)',
                border: '1px solid #0a2a4a',
                borderRadius: 8,
                boxShadow: '0 8px 32px rgba(0,0,0,.6)',
                zIndex: 300,
                overflow: 'hidden',
                animation: 'notif-slide-in .15s ease',
              }}>
                {/* Inject animation once */}
                <style>{`
                  @keyframes notif-slide-in {
                    from { opacity: 0; transform: translateY(-6px); }
                    to   { opacity: 1; transform: translateY(0); }
                  }
                `}</style>

                {/* Header */}
                <div style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  padding: '8px 12px',
                  borderBottom: '1px solid #0a2a4a',
                }}>
                  <span style={{ fontSize: 12, fontWeight: 700, color: 'var(--accent-blue)' }}>
                    {newCount > 0 ? `${newCount} ${t('new_notifications')}` : t('notifications')}
                  </span>
                  <button
                    onClick={handleMarkAllRead}
                    style={{
                      fontSize: 10, color: 'rgba(79,163,224,.70)',
                      background: 'none', border: 'none', cursor: 'pointer',
                      padding: '2px 6px', borderRadius: 3,
                      transition: 'color .15s, background .15s',
                    }}
                    onMouseEnter={e => { e.currentTarget.style.color = 'var(--accent-blue)'; e.currentTarget.style.background = 'rgba(79,163,224,.10)' }}
                    onMouseLeave={e => { e.currentTarget.style.color = 'rgba(79,163,224,.70)'; e.currentTarget.style.background = 'none' }}
                  >
                    {t('mark_all_read')}
                  </button>
                </div>

                {/* Tabs */}
                <div style={{
                  display: 'flex',
                  borderBottom: '1px solid #0a2a4a',
                }}>
                  {(['alerts', 'system'] as const).map(tab => (
                    <button
                      key={tab}
                      onClick={() => setNotifTab(tab)}
                      style={{
                        flex: 1, padding: '6px 0', fontSize: 11, fontWeight: 600,
                        background: 'none', border: 'none', cursor: 'pointer',
                        color: notifTab === tab ? 'var(--accent-blue)' : 'rgba(79,163,224,.45)',
                        borderBottom: notifTab === tab ? '2px solid #0078d4' : '2px solid transparent',
                        transition: 'color .15s, border-color .15s',
                      }}
                    >
                      {tab === 'alerts' ? t('alerts_tab') : t('system_tab')}
                    </button>
                  ))}
                </div>

                {/* Tab content */}
                <div style={{ maxHeight: 220, overflowY: 'auto' }}>
                  {notifTab === 'alerts' ? (
                    notifications.length === 0 ? (
                      <div style={{ padding: '24px 12px', textAlign: 'center', color: 'rgba(79,163,224,.45)', fontSize: 12 }}>
                        {t('no_alerts')}
                      </div>
                    ) : (
                      notifications.map((n, i) => {
                        const ts = n.triggered_at ?? n.created_at
                        const isNew = ts ? new Date(ts) > lastChecked : false
                        return (
                          <div
                            key={n._key ?? i}
                            style={{
                              display: 'flex', alignItems: 'center', gap: 8,
                              padding: '7px 12px',
                              borderBottom: i < notifications.length - 1 ? '1px solid rgba(10,42,74,.6)' : 'none',
                              cursor: 'pointer',
                              background: isNew ? 'rgba(0,120,212,.06)' : 'none',
                              transition: 'background .12s',
                            }}
                            onMouseEnter={e => (e.currentTarget.style.background = 'rgba(0,120,212,.12)')}
                            onMouseLeave={e => (e.currentTarget.style.background = isNew ? 'rgba(0,120,212,.06)' : 'none')}
                            onClick={() => { navigate('/alerts'); setNotifOpen(false) }}
                          >
                            {/* Severity dot */}
                            <span style={{
                              width: 6, height: 6, borderRadius: '50%', flexShrink: 0,
                              background: severityColor(n.severity),
                              boxShadow: `0 0 4px ${severityColor(n.severity)}`,
                            }} />
                            {/* Name */}
                            <span style={{
                              flex: 1, fontSize: 11.5, color: 'rgba(255,255,255,.82)',
                              whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis',
                              maxWidth: 185,
                            }}>
                              {(n.name ?? '').length > 35 ? (n.name ?? '').slice(0, 35) + '…' : (n.name ?? '')}
                            </span>
                            {/* New dot */}
                            {isNew && (
                              <span style={{
                                width: 5, height: 5, borderRadius: '50%',
                                background: 'var(--accent-blue)', flexShrink: 0,
                              }} />
                            )}
                            {/* Relative time */}
                            <span style={{ fontSize: 10, color: 'rgba(79,163,224,.50)', flexShrink: 0 }}>
                              {ts ? relativeTime(ts) : ''}
                            </span>
                          </div>
                        )
                      })
                    )
                  ) : (
                    /* System tab */
                    SYSTEM_NOTIFS.map((s, i) => (
                      <div
                        key={s.id}
                        style={{
                          display: 'flex', alignItems: 'center', gap: 9,
                          padding: '8px 12px',
                          borderBottom: i < SYSTEM_NOTIFS.length - 1 ? '1px solid rgba(10,42,74,.6)' : 'none',
                          cursor: 'default',
                        }}
                      >
                        <span style={{ fontSize: 14, flexShrink: 0 }}>{s.icon}</span>
                        <span style={{ flex: 1, fontSize: 11.5, color: 'rgba(255,255,255,.75)' }}>{s.text}</span>
                        <span style={{ fontSize: 10, color: 'rgba(79,163,224,.45)', flexShrink: 0 }}>{s.time}</span>
                      </div>
                    ))
                  )}
                </div>

                {/* Footer */}
                <div style={{
                  borderTop: '1px solid #0a2a4a',
                  padding: '6px 12px',
                  textAlign: 'center',
                }}>
                  <button
                    onClick={() => { navigate('/alerts'); setNotifOpen(false) }}
                    style={{
                      fontSize: 11, color: 'var(--accent-blue)',
                      background: 'none', border: 'none', cursor: 'pointer',
                      padding: '3px 8px', borderRadius: 3,
                      transition: 'color .15s, background .15s',
                    }}
                    onMouseEnter={e => { e.currentTarget.style.color = 'var(--accent-blue)'; e.currentTarget.style.background = 'rgba(79,163,224,.10)' }}
                    onMouseLeave={e => { e.currentTarget.style.color = 'var(--accent-blue)'; e.currentTarget.style.background = 'none' }}
                  >
                    {t('view_all_alerts')}
                  </button>
                </div>
              </div>
            )}
          </div>

          {/* ── User avatar / menu ── */}
          <div ref={userMenuRef} style={{ position: 'relative' }}>
            <button
              onClick={() => setUserMenuOpen(prev => !prev)}
              title={user?.display_name ?? '用户'}
              style={{
                display: 'flex', alignItems: 'center', gap: 5,
                padding: '0 4px', height: 24,
                background: userMenuOpen ? 'rgba(255,255,255,.10)' : 'none',
                border: 'none', cursor: 'pointer', borderRadius: 4,
                transition: 'background .15s',
              }}
              onMouseEnter={e => (e.currentTarget.style.background = 'rgba(255,255,255,.10)')}
              onMouseLeave={e => { if (!userMenuOpen) e.currentTarget.style.background = 'none' }}
            >
              {/* Avatar circle */}
              <div style={{
                width: 20, height: 20,
                background: 'linear-gradient(135deg,#0078d4,#005ba1)',
                borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center',
                fontSize: 8, fontWeight: 700, color: '#fff', flexShrink: 0,
              }}>
                {initials}
              </div>
              <span style={{ fontSize: 10.5, color: 'rgba(255,255,255,.75)', whiteSpace: 'nowrap' }}>
                {user?.display_name ?? '用户'}
              </span>
              {/* Caret */}
              <svg width="8" height="8" viewBox="0 0 10 6" fill="none" stroke="rgba(79,163,224,.65)" strokeWidth="1.5">
                <path d="M1 1l4 4 4-4"/>
              </svg>
            </button>

            {/* User dropdown */}
            {userMenuOpen && (
              <div style={{
                position: 'absolute', top: 28, right: 0,
                width: 200,
                background: isDark ? 'var(--bg-card)' : 'var(--bg-card)',
                border: '1px solid #0a2a4a',
                borderRadius: 8,
                boxShadow: '0 8px 32px rgba(0,0,0,.6)',
                zIndex: 300,
                overflow: 'hidden',
                animation: 'notif-slide-in .15s ease',
              }}>
                {/* User info block */}
                <div style={{
                  padding: '10px 14px',
                  borderBottom: '1px solid #0a2a4a',
                }}>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                    <div style={{
                      width: 32, height: 32,
                      background: 'linear-gradient(135deg,#0078d4,#005ba1)',
                      borderRadius: '50%', display: 'flex', alignItems: 'center', justifyContent: 'center',
                      fontSize: 11, fontWeight: 700, color: '#fff', flexShrink: 0,
                    }}>
                      {initials}
                    </div>
                    <div style={{ overflow: 'hidden' }}>
                      <div style={{ fontSize: 12, fontWeight: 600, color: 'rgba(255,255,255,.90)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {user?.display_name ?? '—'}
                      </div>
                      <div style={{ fontSize: 10, color: 'rgba(79,163,224,.65)', whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>
                        {user?.email ?? '—'}
                      </div>
                    </div>
                  </div>
                  {/* Role badge */}
                  {user?.role && (
                    <div style={{ marginTop: 7 }}>
                      <span style={{
                        fontSize: 9, fontWeight: 700, padding: '2px 7px', borderRadius: 10,
                        background: 'rgba(0,120,212,.25)', color: 'var(--accent-blue)',
                        border: '1px solid rgba(79,163,224,.25)',
                      }}>
                        {roleLabel(user.role)}
                      </span>
                    </div>
                  )}
                </div>

                {/* Menu items */}
                <div style={{ padding: '4px 0' }}>
                  {/* 个人设置 */}
                  <button
                    onClick={() => { navigate('/settings'); setUserMenuOpen(false) }}
                    style={menuItemStyle}
                    onMouseEnter={e => (e.currentTarget.style.background = 'rgba(0,120,212,.10)')}
                    onMouseLeave={e => (e.currentTarget.style.background = 'none')}
                  >
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
                      <circle cx="12" cy="12" r="3"/>
                      <path d="M19.4 15a1.65 1.65 0 00.33 1.82l.06.06a2 2 0 010 2.83 2 2 0 01-2.83 0l-.06-.06a1.65 1.65 0 00-1.82-.33 1.65 1.65 0 00-1 1.51V21a2 2 0 01-2 2 2 2 0 01-2-2v-.09A1.65 1.65 0 009 19.4a1.65 1.65 0 00-1.82.33l-.06.06a2 2 0 01-2.83 0 2 2 0 010-2.83l.06-.06A1.65 1.65 0 004.68 15a1.65 1.65 0 00-1.51-1H3a2 2 0 01-2-2 2 2 0 012-2h.09A1.65 1.65 0 004.6 9a1.65 1.65 0 00-.33-1.82l-.06-.06a2 2 0 010-2.83 2 2 0 012.83 0l.06.06A1.65 1.65 0 009 4.68a1.65 1.65 0 001-1.51V3a2 2 0 012-2 2 2 0 012 2v.09a1.65 1.65 0 001 1.51 1.65 1.65 0 001.82-.33l.06-.06a2 2 0 012.83 0 2 2 0 010 2.83l-.06.06A1.65 1.65 0 0019.4 9a1.65 1.65 0 001.51 1H21a2 2 0 012 2 2 2 0 01-2 2h-.09a1.65 1.65 0 00-1.51 1z"/>
                    </svg>
                    <span>{t('settings')}</span>
                  </button>

                  {/* 切换主题 */}
                  <button
                    onClick={() => { toggleTheme(); setUserMenuOpen(false) }}
                    style={menuItemStyle}
                    onMouseEnter={e => (e.currentTarget.style.background = 'rgba(0,120,212,.10)')}
                    onMouseLeave={e => (e.currentTarget.style.background = 'none')}
                  >
                    {theme === 'light' ? (
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
                        <path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/>
                      </svg>
                    ) : (
                      <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
                        <circle cx="12" cy="12" r="5"/>
                        <line x1="12" y1="1" x2="12" y2="3"/><line x1="12" y1="21" x2="12" y2="23"/>
                        <line x1="4.22" y1="4.22" x2="5.64" y2="5.64"/><line x1="18.36" y1="18.36" x2="19.78" y2="19.78"/>
                        <line x1="1" y1="12" x2="3" y2="12"/><line x1="21" y1="12" x2="23" y2="12"/>
                        <line x1="4.22" y1="19.78" x2="5.64" y2="18.36"/><line x1="18.36" y1="5.64" x2="19.78" y2="4.22"/>
                      </svg>
                    )}
                    <span>{t('switch_theme')} ({theme === 'light' ? t('dark') : t('light')})</span>
                  </button>

                  {/* Divider */}
                  <div style={{ height: 1, background: 'var(--border)', margin: '4px 0' }} />

                  {/* 退出登录 */}
                  <button
                    onClick={handleLogout}
                    style={{ ...menuItemStyle, color: 'rgba(224,80,80,.80)' }}
                    onMouseEnter={e => { e.currentTarget.style.background = 'rgba(224,80,80,.10)'; e.currentTarget.style.color = 'var(--critical)' }}
                    onMouseLeave={e => { e.currentTarget.style.background = 'none'; e.currentTarget.style.color = 'rgba(224,80,80,.80)' }}
                  >
                    <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8">
                      <path d="M9 21H5a2 2 0 01-2-2V5a2 2 0 012-2h4"/>
                      <polyline points="16 17 21 12 16 7"/>
                      <line x1="21" y1="12" x2="9" y2="12"/>
                    </svg>
                    <span>{t('logout')}</span>
                  </button>
                </div>
              </div>
            )}
          </div>

        </div>
      </div>
    </>
  )
}

/* ── Shared menu item style ── */
const menuItemStyle: React.CSSProperties = {
  display: 'flex', alignItems: 'center', gap: 9,
  width: '100%', padding: '7px 14px',
  background: 'none', border: 'none', cursor: 'pointer',
  fontSize: 12, color: 'rgba(255,255,255,.75)',
  textAlign: 'left', transition: 'background .12s, color .12s',
}
