import { Outlet, useNavigate } from 'react-router-dom'
import Sidebar from './Sidebar'
import TopBar from './TopBar'
import { useState, useEffect, useCallback } from 'react'

// Navigable nav items in order (matching Sidebar navItems, dividers excluded)
const NAV_ROUTES = [
  '/',
  '/incidents',
  '/alerts',
  '/causality',
  '/query',
  '/actions',
  '/playbooks',
  '/assets',
  '/identity-risks',
  '/vulnerabilities',
  '/exposure',
  '/threat-intel',
  '/iocs',
  '/agentix',
  '/xsiam-cases',
  '/devices',
  '/agents-hub',
  '/detection-rules',
  '/etl-pipeline',
  '/reports',
]

export default function Layout() {
  const navigate = useNavigate()

  // ── Sidebar collapsed state — persisted in localStorage ──────────────────
  const [sidebarOpen, setSidebarOpen] = useState<boolean>(() => {
    const stored = localStorage.getItem('xsiam_sidebar_collapsed')
    // stored = 'true' means collapsed → open = false
    if (stored !== null) return stored !== 'true'
    return true // default open
  })

  const toggleSidebar = useCallback(() => {
    setSidebarOpen(prev => {
      const next = !prev
      localStorage.setItem('xsiam_sidebar_collapsed', next ? 'false' : 'true')
      return next
    })
  }, [])

  // ── Command palette visibility ────────────────────────────────────────────
  const [cmdPaletteOpen, setCmdPaletteOpen] = useState(false)

  // ── Global keyboard shortcuts ─────────────────────────────────────────────
  useEffect(() => {
    function handler(e: KeyboardEvent) {
      const target = e.target as HTMLElement
      const isInput = target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable

      // Ctrl+K — command palette (works from anywhere)
      if (e.ctrlKey && e.key === 'k') {
        e.preventDefault()
        setCmdPaletteOpen(p => !p)
        return
      }

      // `/` — focus search input on current page, or open command palette
      if (e.key === '/' && !isInput && !e.ctrlKey && !e.altKey && !e.metaKey) {
        e.preventDefault()
        // Try to focus a visible search/filter input on the current page
        const searchInput = document.querySelector<HTMLInputElement>(
          'input[placeholder*="搜索"], input[placeholder*="过滤"], input[placeholder*="Search"], input[placeholder*="Filter"], input[type="search"]'
        )
        if (searchInput) {
          searchInput.focus()
          searchInput.select()
        } else {
          setCmdPaletteOpen(p => !p)
        }
        return
      }

      // Escape — close command palette
      if (e.key === 'Escape' && cmdPaletteOpen) {
        e.preventDefault()
        setCmdPaletteOpen(false)
        return
      }

      // Alt+1..9 — navigate to Nth nav item
      if (e.altKey && !e.ctrlKey && !e.metaKey && e.key >= '1' && e.key <= '9') {
        const idx = parseInt(e.key, 10) - 1
        if (idx < NAV_ROUTES.length) {
          e.preventDefault()
          navigate(NAV_ROUTES[idx])
        }
        return
      }
    }

    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [navigate, cmdPaletteOpen])

  return (
    <div style={{ display: 'flex', height: '100vh', overflow: 'hidden' }}>
      {/* Sidebar — in-flow, not fixed */}
      <Sidebar open={sidebarOpen} onToggle={toggleSidebar} />

      {/* Right column: TopBar + page content */}
      <div style={{
        flex: 1,
        display: 'flex',
        flexDirection: 'column',
        overflow: 'hidden',
        background: 'var(--bg-primary)',
        minWidth: 0,
      }}>
        <TopBar />
        <div style={{ flex: 1, overflow: 'hidden' }}>
          <Outlet />
        </div>
      </div>

      {/* Command palette overlay */}
      {cmdPaletteOpen && (
        <CommandPalette
          onClose={() => setCmdPaletteOpen(false)}
          onNavigate={(route) => { navigate(route); setCmdPaletteOpen(false) }}
        />
      )}
    </div>
  )
}

// ── Command Palette ───────────────────────────────────────────────────────────

interface CmdItem { label: string; route: string; hint: string }

const CMD_ITEMS: CmdItem[] = [
  { label: '概览', route: '/', hint: 'Alt+1' },
  { label: '事件', route: '/incidents', hint: 'Alt+2' },
  { label: '告警', route: '/alerts', hint: 'Alt+3' },
  { label: '溯源图', route: '/causality', hint: 'Alt+4' },
  { label: '查询中心', route: '/query', hint: 'Alt+5' },
  { label: '动作中心', route: '/actions', hint: 'Alt+6' },
  { label: '剧本', route: '/playbooks', hint: 'Alt+7' },
  { label: '资产', route: '/assets', hint: 'Alt+8' },
  { label: '身份风险', route: '/identity-risks', hint: 'Alt+9' },
  { label: '漏洞', route: '/vulnerabilities', hint: '' },
  { label: '暴露面管理', route: '/exposure', hint: '' },
  { label: '威胁情报', route: '/threat-intel', hint: '' },
  { label: 'IOC 管理', route: '/iocs', hint: '' },
  { label: 'Agentix', route: '/agentix', hint: '' },
  { label: 'XSIAM 案例', route: '/xsiam-cases', hint: '' },
  { label: '设备', route: '/devices', hint: '' },
  { label: 'Agent 中心', route: '/agents-hub', hint: '' },
  { label: '检测规则', route: '/detection-rules', hint: '' },
  { label: 'ETL 流水线', route: '/etl-pipeline', hint: '' },
  { label: '报表', route: '/reports', hint: '' },
  { label: '系统设置', route: '/settings', hint: '' },
]

function CommandPalette({ onClose, onNavigate }: { onClose: () => void; onNavigate: (route: string) => void }) {
  const [query, setQuery] = useState('')
  const [activeIdx, setActiveIdx] = useState(0)

  const filtered = query.trim()
    ? CMD_ITEMS.filter(it =>
        it.label.toLowerCase().includes(query.toLowerCase()) ||
        it.route.toLowerCase().includes(query.toLowerCase())
      )
    : CMD_ITEMS

  // Reset active index when filter changes
  useEffect(() => { setActiveIdx(0) }, [query])

  useEffect(() => {
    function handler(e: KeyboardEvent) {
      if (e.key === 'ArrowDown') {
        e.preventDefault()
        setActiveIdx(i => Math.min(i + 1, filtered.length - 1))
      } else if (e.key === 'ArrowUp') {
        e.preventDefault()
        setActiveIdx(i => Math.max(i - 1, 0))
      } else if (e.key === 'Enter') {
        if (filtered[activeIdx]) onNavigate(filtered[activeIdx].route)
      }
    }
    document.addEventListener('keydown', handler)
    return () => document.removeEventListener('keydown', handler)
  }, [filtered, activeIdx, onNavigate])

  return (
    <>
      {/* Backdrop */}
      <div
        onClick={onClose}
        style={{
          position: 'fixed', inset: 0, zIndex: 999,
          background: 'rgba(0,0,0,.55)', backdropFilter: 'blur(2px)',
        }}
      />

      {/* Palette panel */}
      <div style={{
        position: 'fixed', top: '20%', left: '50%', transform: 'translateX(-50%)',
        zIndex: 1000, width: 480, maxWidth: 'calc(100vw - 32px)',
        background: 'var(--bg-card)', border: '1px solid var(--border-light)',
        borderRadius: 12, boxShadow: '0 24px 64px rgba(0,0,0,.55)',
        overflow: 'hidden',
      }}>
        {/* Search row */}
        <div style={{ display: 'flex', alignItems: 'center', padding: '12px 16px', borderBottom: '1px solid var(--border)', gap: 10 }}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="var(--text-muted)" strokeWidth="2">
            <circle cx="11" cy="11" r="8"/><line x1="21" y1="21" x2="16.65" y2="16.65"/>
          </svg>
          <input
            autoFocus
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="跳转到页面..."
            style={{
              flex: 1, background: 'none', border: 'none', outline: 'none',
              fontSize: 14, color: 'var(--text-primary)',
            }}
          />
          <span style={{ fontSize: 11, color: 'var(--text-muted)', background: 'var(--bg-secondary)', padding: '2px 6px', borderRadius: 4, fontFamily: 'monospace' }}>
            Esc
          </span>
        </div>

        {/* Results */}
        <div style={{ maxHeight: 320, overflowY: 'auto', padding: '4px 0' }}>
          {filtered.length === 0 ? (
            <div style={{ padding: '20px 16px', textAlign: 'center', color: 'var(--text-muted)', fontSize: 13 }}>
              无匹配项
            </div>
          ) : (
            filtered.map((item, i) => (
              <div
                key={item.route}
                onMouseEnter={() => setActiveIdx(i)}
                onClick={() => onNavigate(item.route)}
                style={{
                  display: 'flex', alignItems: 'center', justifyContent: 'space-between',
                  padding: '8px 16px', cursor: 'pointer',
                  background: i === activeIdx ? 'var(--nav-active-bg)' : 'none',
                  borderLeft: i === activeIdx ? '2px solid var(--accent-blue)' : '2px solid transparent',
                  transition: 'background .1s',
                }}
              >
                <span style={{ fontSize: 13, color: 'var(--text-primary)' }}>{item.label}</span>
                {item.hint && (
                  <span style={{ fontSize: 11, color: 'var(--text-muted)', fontFamily: 'monospace', background: 'var(--bg-secondary)', padding: '2px 5px', borderRadius: 3 }}>
                    {item.hint}
                  </span>
                )}
              </div>
            ))
          )}
        </div>

        {/* Footer hint */}
        <div style={{ padding: '8px 16px', borderTop: '1px solid var(--border)', display: 'flex', gap: 16 }}>
          {[['↑↓', '选择'], ['↵', '跳转'], ['Ctrl+K', '关闭']].map(([key, label]) => (
            <span key={key} style={{ fontSize: 11, color: 'var(--text-muted)', display: 'flex', alignItems: 'center', gap: 4 }}>
              <span style={{ fontFamily: 'monospace', background: 'var(--bg-secondary)', padding: '1px 5px', borderRadius: 3 }}>{key}</span>
              {label}
            </span>
          ))}
        </div>
      </div>
    </>
  )
}
