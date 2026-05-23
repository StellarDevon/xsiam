import { useTheme } from '@/lib/theme'
import { useLang } from '@/lib/i18n'

export default function TopBar() {
  const { theme, toggle: toggleTheme } = useTheme()
  const { lang, setLang } = useLang()

  return (
    <div style={{
      height: 28,
      display: 'flex', alignItems: 'center', gap: 8,
      padding: '0 16px',
      background: 'linear-gradient(90deg,#001e3c 0%,#00132a 100%)',
      borderBottom: '1px solid #0a2a4a',
      flexShrink: 0, zIndex: 100,
    }}>
      {/* Pulse dot */}
      <span style={{
        width: 6, height: 6, borderRadius: '50%',
        background: '#0078d4', boxShadow: '0 0 5px #0078d4',
        display: 'inline-block', animation: 'pulse-dot 2s ease-in-out infinite',
        flexShrink: 0,
      }} />

      {/* Label */}
      <span style={{
        fontSize: 10.5, fontWeight: 700, letterSpacing: 1.6,
        color: '#4fa3e0', textTransform: 'uppercase', userSelect: 'none',
      }}>
        XSIAM Agentic Assistant
      </span>

      <span style={{ marginLeft: 8, fontSize: 10, color: '#2b88d8', letterSpacing: 0 }}>
        Active · 3 automated responses running
      </span>

      {/* Right-side controls */}
      <div style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 4 }}>

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
                color: lang === l ? '#ffffff' : 'rgba(79,163,224,.70)',
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
          onMouseEnter={e => { e.currentTarget.style.background = 'rgba(255,255,255,.10)'; e.currentTarget.style.color = '#ffffff' }}
          onMouseLeave={e => { e.currentTarget.style.background = 'none'; e.currentTarget.style.color = 'rgba(79,163,224,.80)' }}
        >
          {theme === 'light' ? (
            /* Moon — click to go dark */
            <svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round">
              <path d="M21 12.79A9 9 0 1111.21 3 7 7 0 0021 12.79z"/>
            </svg>
          ) : (
            /* Sun — click to go light */
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

      </div>
    </div>
  )
}
