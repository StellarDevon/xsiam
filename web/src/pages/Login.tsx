import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '@/lib/api'
import { setAuth } from '@/lib/auth'

export default function Login() {
  const navigate = useNavigate()
  const [username, setUsername] = useState('')
  const [password, setPassword] = useState('')
  const [error, setError] = useState('')
  const [loading, setLoading] = useState(false)

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError('')
    setLoading(true)
    try {
      const res = await api.post('/auth/login', { email: username, password })
      const { token, user } = res.data.data
      setAuth(token, user)
      navigate('/')
    } catch (err: any) {
      setError(err.response?.data?.error?.message ?? '登录失败')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div style={{
      height:'100vh', display:'flex', alignItems:'center', justifyContent:'center',
      background:'var(--bg-primary)',
    }}>
      <div style={{
        width:360, background:'var(--bg-card)',
        border:'1px solid var(--border)', borderRadius:8, padding:32,
      }}>
        {/* Logo */}
        <div style={{ display:'flex', alignItems:'center', gap:10, marginBottom:28 }}>
          <svg width="32" height="32" viewBox="0 0 32 32" fill="none">
            <circle cx="16" cy="16" r="15" fill="#0078d4"/>
            <path d="M9 16l5 5 9-9" stroke="white" strokeWidth="2.5" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
          <div>
            <div style={{ fontSize:15, fontWeight:700, color:'var(--text-primary)' }}>XSIAM</div>
            <div style={{ fontSize:11, color:'var(--text-muted)' }}>Security Operations Platform</div>
          </div>
        </div>

        <form onSubmit={handleSubmit} style={{ display:'flex', flexDirection:'column', gap:14 }}>
          <div>
            <label style={{ fontSize:11, color:'var(--text-muted)', display:'block', marginBottom:6, textTransform:'uppercase', letterSpacing:.4 }}>
              Username or Email
            </label>
            <input
              type="text"
              value={username}
              onChange={e => setUsername(e.target.value)}
              placeholder="admin"
              autoComplete="username"
              required
              style={{
                width:'100%', background:'var(--bg-secondary)',
                border:'1px solid var(--border-light)', borderRadius:4,
                padding:'8px 12px', color:'var(--text-primary)', fontSize:13, outline:'none',
              }}
              onFocus={e => e.target.style.borderColor='var(--accent-blue)'}
              onBlur={e => e.target.style.borderColor='var(--border-light)'}
            />
          </div>

          <div>
            <label style={{ fontSize:11, color:'var(--text-muted)', display:'block', marginBottom:6, textTransform:'uppercase', letterSpacing:.4 }}>
              Password
            </label>
            <input
              type="password"
              value={password}
              onChange={e => setPassword(e.target.value)}
              placeholder="admin"
              autoComplete="current-password"
              required
              style={{
                width:'100%', background:'var(--bg-secondary)',
                border:'1px solid var(--border-light)', borderRadius:4,
                padding:'8px 12px', color:'var(--text-primary)', fontSize:13, outline:'none',
              }}
              onFocus={e => e.target.style.borderColor='var(--accent-blue)'}
              onBlur={e => e.target.style.borderColor='var(--border-light)'}
            />
          </div>

          {error && (
            <div style={{ fontSize:12, color:'var(--critical)', padding:'6px 10px', background:'rgba(229,57,53,.08)', border:'1px solid rgba(229,57,53,.2)', borderRadius:4 }}>
              {error}
            </div>
          )}

          <button
            type="submit"
            disabled={loading}
            className="btn-primary"
            style={{ width:'100%', padding:'9px', fontSize:13, marginTop:4, opacity: loading ? .6 : 1 }}
          >
            {loading ? 'Signing in…' : 'Sign In'}
          </button>
        </form>
      </div>
    </div>
  )
}
