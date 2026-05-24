import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '@/lib/api'
import { setAuth } from '@/lib/auth'

/* ── spinner + blink keyframes injected once ── */
const extraStyles = `
@keyframes xsiam-spin {
  to { transform: rotate(360deg); }
}
.xsiam-spinner {
  display: inline-block;
  width: 13px;
  height: 13px;
  border: 2px solid rgba(255,255,255,.35);
  border-top-color: #fff;
  border-radius: 50%;
  animation: xsiam-spin .7s linear infinite;
  vertical-align: middle;
  margin-right: 7px;
}
`

let styleInjected = false
function injectStyles() {
  if (styleInjected) return
  const el = document.createElement('style')
  el.textContent = extraStyles
  document.head.appendChild(el)
  styleInjected = true
}

const MAX_FAILS = 3
const LOCKOUT_SECS = 30

/** Format an ISO timestamp into a locale-friendly string */
function formatLastLogin(iso: string): string {
  try {
    return new Date(iso).toLocaleString('zh-CN', {
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit',
    })
  } catch {
    return iso
  }
}

export default function Login() {
  injectStyles()

  const navigate = useNavigate()

  // ── Session expired banner ──
  const sessionExpired = new URLSearchParams(window.location.search).get('reason') === 'expired'
  const [expiredDismissed, setExpiredDismissed] = useState(false)

  // ── Remembered user / last login ──
  const rememberedUser  = localStorage.getItem('xsiam_remembered_user') ?? ''
  const lastLoginIso    = localStorage.getItem('xsiam_last_login') ?? ''

  const [username, setUsername]       = useState(rememberedUser)
  const [password, setPassword]       = useState('')
  const [rememberMe, setRememberMe]   = useState(!!rememberedUser)
  const [error, setError]             = useState('')
  const [loading, setLoading]         = useState(false)
  const [successMsg, setSuccessMsg]   = useState('')

  // Field-level validation errors
  const [usernameErr, setUsernameErr] = useState('')
  const [passwordErr, setPasswordErr] = useState('')

  // Rate limiting
  const [failCount, setFailCount]     = useState(0)
  const [lockout, setLockout]         = useState(0)   // seconds remaining
  const lockoutRef                    = useRef<ReturnType<typeof setInterval> | null>(null)

  // MFA step
  const [mfaStep, setMfaStep]         = useState(false)
  const [otp, setOtp]                 = useState('')
  const [otpErr, setOtpErr]           = useState('')

  // Start / clear lockout countdown
  useEffect(() => {
    if (failCount >= MAX_FAILS && lockout === 0) {
      setLockout(LOCKOUT_SECS)
    }
  }, [failCount]) // eslint-disable-line react-hooks/exhaustive-deps

  useEffect(() => {
    if (lockout > 0) {
      lockoutRef.current = setInterval(() => {
        setLockout(prev => {
          if (prev <= 1) {
            clearInterval(lockoutRef.current!)
            lockoutRef.current = null
            setFailCount(0)   // reset after lockout ends
            return 0
          }
          return prev - 1
        })
      }, 1000)
    }
    return () => {
      if (lockoutRef.current) clearInterval(lockoutRef.current)
    }
  }, [lockout > 0 && lockoutRef.current === null]) // eslint-disable-line react-hooks/exhaustive-deps

  const isLocked = lockout > 0

  function validateFields(): boolean {
    let valid = true
    if (!username.trim()) {
      setUsernameErr('请输入用户名')
      valid = false
    } else {
      setUsernameErr('')
    }
    if (password.length < 6) {
      setPasswordErr('密码至少6位')
      valid = false
    } else {
      setPasswordErr('')
    }
    return valid
  }

  async function handleSubmit(e?: React.FormEvent) {
    e?.preventDefault()
    if (isLocked || mfaStep) return
    setError('')
    if (!validateFields()) return

    setLoading(true)
    try {
      const res = await api.post('/auth/login', { email: username, password })
      const { token, user, mfa_required } = res.data.data as {
        token: string
        user: { username?: string }
        mfa_required?: boolean
      }

      // Save last login timestamp immediately (before possible MFA detour)
      localStorage.setItem('xsiam_last_login', new Date().toISOString())

      // Persist / clear remembered user
      if (rememberMe) {
        localStorage.setItem('xsiam_remembered_user', username)
      } else {
        localStorage.removeItem('xsiam_remembered_user')
      }

      // Check MFA requirement: real flag OR mock trigger (username contains "mfa")
      const needsMfa = mfa_required === true || username.toLowerCase().includes('mfa')
      if (needsMfa) {
        setLoading(false)
        setMfaStep(true)
        // Stash token + user in a ref so we can complete auth after OTP
        pendingAuthRef.current = { token, user: user as Parameters<typeof setAuth>[1] }
        return
      }

      setAuth(token, user as Parameters<typeof setAuth>[1], rememberMe)
      setSuccessMsg(`✓ 欢迎回来，${user.username ?? username}！`)
      setTimeout(() => navigate('/'), 1200)
    } catch (err: unknown) {
      const anyErr = err as { response?: { data?: { error?: { message?: string } } } }
      setError(anyErr.response?.data?.error?.message ?? '登录失败')
      setFailCount(prev => prev + 1)
    } finally {
      setLoading(false)
    }
  }

  // Stash pending auth while waiting for OTP
  const pendingAuthRef = useRef<{ token: string; user: Parameters<typeof setAuth>[1] } | null>(null)

  function handleOtpSubmit(e?: React.FormEvent) {
    e?.preventDefault()
    setOtpErr('')
    if (otp.length !== 6 || !/^\d+$/.test(otp)) {
      setOtpErr('请输入6位数字验证码')
      return
    }
    // Any valid 6-digit code is accepted (mock)
    const pending = pendingAuthRef.current
    if (!pending) return
    setAuth(pending.token, pending.user, rememberMe)
    setSuccessMsg(`✓ 欢迎回来，${pending.user.username ?? username}！`)
    setTimeout(() => navigate('/'), 1200)
  }

  function handleUsernameKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Enter') {
      e.preventDefault()
      handleSubmit()
    }
  }

  function handlePasswordKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Enter') {
      e.preventDefault()
      handleSubmit()
    }
  }

  function handleForgotPassword() {
    alert('请联系管理员重置密码')
  }

  const inputBase: React.CSSProperties = {
    width: '100%',
    background: 'var(--bg-secondary)',
    border: '1px solid var(--border-light)',
    borderRadius: 4,
    padding: '8px 12px',
    color: 'var(--text-primary)',
    fontSize: 13,
    outline: 'none',
    boxSizing: 'border-box',
  }

  const inputStyle: React.CSSProperties = {
    ...inputBase,
    opacity: loading || isLocked ? 0.5 : 1,
    cursor: loading || isLocked ? 'not-allowed' : 'text',
  }

  return (
    <div style={{
      height: '100vh',
      display: 'flex',
      flexDirection: 'column',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'var(--bg-primary)',
    }}>
      <div style={{
        width: 360,
        background: 'var(--bg-card)',
        border: '1px solid var(--border)',
        borderRadius: 8,
        padding: 32,
      }}>
        {/* Session expired banner */}
        {sessionExpired && !expiredDismissed && (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            fontSize: 12,
            color: '#b45309',
            padding: '8px 12px',
            background: 'rgba(251,191,36,0.12)',
            border: '1px solid rgba(251,191,36,0.4)',
            borderRadius: 4,
            marginBottom: 18,
          }}>
            <span>⚠️ 会话已过期，请重新登录</span>
            <button
              onClick={() => setExpiredDismissed(true)}
              style={{
                background: 'none',
                border: 'none',
                cursor: 'pointer',
                color: '#b45309',
                fontSize: 14,
                lineHeight: 1,
                padding: '0 0 0 8px',
              }}
              aria-label="关闭"
            >
              ×
            </button>
          </div>
        )}

        {/* Brand */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 28 }}>
          <svg width="36" height="36" viewBox="0 0 36 36" fill="none" aria-hidden="true">
            <circle cx="18" cy="18" r="17" fill="#0078d4"/>
            <path d="M18 7 L27 11 L27 19 C27 24 18 29 18 29 C18 29 9 24 9 19 L9 11 Z"
              fill="rgba(255,255,255,0.15)" stroke="rgba(255,255,255,0.6)" strokeWidth="1"/>
            <path d="M13 18.5 L16.5 22 L23 15"
              stroke="white" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
          <div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 6 }}>
              <span style={{ fontSize: 16, fontWeight: 700, color: 'var(--text-primary)', letterSpacing: .5 }}>
                XSIAM
              </span>
              <span style={{ fontSize: 11, color: 'var(--accent-blue)', fontWeight: 600 }}>v3.0</span>
            </div>
            <div style={{ fontSize: 10, color: 'var(--text-muted)', marginTop: 1, letterSpacing: .2 }}>
              Extended Detection &amp; Response Platform
            </div>
          </div>
        </div>

        {/* ── MFA Step ── */}
        {mfaStep ? (
          <form onSubmit={handleOtpSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            <div style={{ fontSize: 13, color: 'var(--text-primary)', marginBottom: 4 }}>
              🔐 双因素验证
            </div>
            <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 6, lineHeight: 1.5 }}>
              请输入您的身份验证器应用中的6位验证码
            </div>

            <div>
              <label style={{
                fontSize: 11, color: 'var(--text-muted)', display: 'block',
                marginBottom: 6, textTransform: 'uppercase', letterSpacing: .4,
              }}>
                验证码
              </label>
              <input
                type="text"
                value={otp}
                onChange={e => { setOtp(e.target.value.replace(/\D/g, '').slice(0, 6)); setOtpErr('') }}
                placeholder="000000"
                maxLength={6}
                pattern="[0-9]{6}"
                autoComplete="one-time-code"
                autoFocus
                style={{
                  ...inputBase,
                  letterSpacing: '0.3em',
                  textAlign: 'center',
                  fontSize: 18,
                }}
                onFocus={e => { e.target.style.borderColor = 'var(--accent-blue)' }}
                onBlur={e => { e.target.style.borderColor = 'var(--border-light)' }}
                onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); handleOtpSubmit() } }}
              />
              {otpErr && (
                <span style={{ fontSize: 11, color: '#ef5350', marginTop: 4, display: 'block' }}>
                  {otpErr}
                </span>
              )}
            </div>

            {successMsg && (
              <div style={{
                fontSize: 12,
                color: '#4caf50',
                padding: '8px 12px',
                background: 'rgba(76,175,80,0.1)',
                border: '1px solid rgba(76,175,80,0.3)',
                borderRadius: 4,
                fontWeight: 600,
              }}>
                {successMsg}
              </div>
            )}

            <div style={{ display: 'flex', gap: 8 }}>
              <button
                type="button"
                onClick={() => { setMfaStep(false); setOtp(''); setOtpErr(''); pendingAuthRef.current = null }}
                style={{
                  flex: 1,
                  padding: '9px',
                  fontSize: 13,
                  background: 'var(--bg-secondary)',
                  border: '1px solid var(--border-light)',
                  borderRadius: 4,
                  color: 'var(--text-muted)',
                  cursor: 'pointer',
                }}
              >
                返回
              </button>
              <button
                type="submit"
                className="btn-primary"
                style={{
                  flex: 2,
                  padding: '9px',
                  fontSize: 13,
                  cursor: 'pointer',
                  display: 'flex',
                  alignItems: 'center',
                  justifyContent: 'center',
                }}
              >
                验证
              </button>
            </div>
          </form>
        ) : (
          /* ── Login Step ── */
          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
            {/* Username */}
            <div>
              <label style={{
                fontSize: 11, color: 'var(--text-muted)', display: 'block',
                marginBottom: 6, textTransform: 'uppercase', letterSpacing: .4,
              }}>
                Username or Email
              </label>
              <input
                type="text"
                value={username}
                onChange={e => { setUsername(e.target.value); if (usernameErr) setUsernameErr('') }}
                onKeyDown={handleUsernameKeyDown}
                placeholder="admin"
                autoComplete="username"
                disabled={loading || isLocked}
                style={inputStyle}
                onFocus={e => { if (!loading && !isLocked) e.target.style.borderColor = 'var(--accent-blue)' }}
                onBlur={e => { e.target.style.borderColor = 'var(--border-light)' }}
              />
              {usernameErr && (
                <span style={{ fontSize: 11, color: '#ef5350', marginTop: 4, display: 'block' }}>
                  {usernameErr}
                </span>
              )}
            </div>

            {/* Password */}
            <div>
              <label style={{
                fontSize: 11, color: 'var(--text-muted)', display: 'block',
                marginBottom: 6, textTransform: 'uppercase', letterSpacing: .4,
              }}>
                Password
              </label>
              <input
                type="password"
                value={password}
                onChange={e => { setPassword(e.target.value); if (passwordErr) setPasswordErr('') }}
                onKeyDown={handlePasswordKeyDown}
                placeholder="••••••"
                autoComplete="current-password"
                disabled={loading || isLocked}
                style={inputStyle}
                onFocus={e => { if (!loading && !isLocked) e.target.style.borderColor = 'var(--accent-blue)' }}
                onBlur={e => { e.target.style.borderColor = 'var(--border-light)' }}
              />
              {passwordErr && (
                <span style={{ fontSize: 11, color: '#ef5350', marginTop: 4, display: 'block' }}>
                  {passwordErr}
                </span>
              )}
            </div>

            {/* Remember me + last login */}
            <div style={{ marginTop: -2 }}>
              <label style={{
                display: 'flex',
                alignItems: 'center',
                gap: 8,
                cursor: loading || isLocked ? 'not-allowed' : 'pointer',
                userSelect: 'none',
              }}>
                <input
                  type="checkbox"
                  checked={rememberMe}
                  onChange={e => setRememberMe(e.target.checked)}
                  disabled={loading || isLocked}
                  style={{ accentColor: 'var(--accent-blue)', cursor: 'inherit', width: 13, height: 13 }}
                />
                <span style={{ fontSize: 12, color: 'var(--text-muted)' }}>记住我</span>
              </label>
              {lastLoginIso && (
                <div style={{ fontSize: 11, color: 'var(--text-muted)', marginTop: 5, paddingLeft: 21 }}>
                  上次登录: {formatLastLogin(lastLoginIso)}
                </div>
              )}
            </div>

            {/* Success message */}
            {successMsg && (
              <div style={{
                fontSize: 12,
                color: '#4caf50',
                padding: '8px 12px',
                background: 'rgba(76,175,80,0.1)',
                border: '1px solid rgba(76,175,80,0.3)',
                borderRadius: 4,
                fontWeight: 600,
              }}>
                {successMsg}
              </div>
            )}

            {/* General error */}
            {error && !successMsg && (
              <div style={{
                fontSize: 12,
                color: '#ef5350',
                padding: '8px 12px',
                background: 'rgba(229,57,53,0.1)',
                border: '1px solid rgba(229,57,53,0.3)',
                borderRadius: 4,
              }}>
                {error}
              </div>
            )}

            {/* Lockout countdown */}
            {isLocked && (
              <div style={{
                fontSize: 12,
                color: '#ff9800',
                padding: '8px 12px',
                background: 'rgba(255,152,0,0.1)',
                border: '1px solid rgba(255,152,0,0.3)',
                borderRadius: 4,
                textAlign: 'center',
              }}>
                请等待 {lockout}s 后重试
              </div>
            )}

            {/* Submit */}
            <button
              type="submit"
              disabled={loading || isLocked}
              className="btn-primary"
              style={{
                width: '100%',
                padding: '9px',
                fontSize: 13,
                marginTop: 4,
                opacity: loading || isLocked ? 0.7 : 1,
                cursor: loading || isLocked ? 'not-allowed' : 'pointer',
                display: 'flex',
                alignItems: 'center',
                justifyContent: 'center',
              }}
            >
              {loading && <span className="xsiam-spinner" aria-hidden="true" />}
              {isLocked
                ? `请等待 ${lockout}s`
                : loading
                  ? 'Signing in…'
                  : 'Sign In'}
            </button>
          </form>
        )}

        {/* Forgot password */}
        {!mfaStep && (
          <div style={{ textAlign: 'right', marginTop: 10 }}>
            <button
              onClick={handleForgotPassword}
              style={{
                background: 'none',
                border: 'none',
                cursor: 'pointer',
                color: 'var(--accent-blue)',
                fontSize: 12,
                padding: 0,
                textDecoration: 'underline',
                textUnderlineOffset: 2,
              }}
            >
              忘记密码?
            </button>
          </div>
        )}
      </div>

      {/* Feature chips */}
      <div style={{
        display: 'flex',
        gap: 8,
        marginTop: 20,
        flexWrap: 'wrap',
        justifyContent: 'center',
      }}>
        {[
          '🛡️ 实时威胁检测',
          '🔍 AI辅助调查',
          '⚡ 自动化响应',
        ].map(chip => (
          <span
            key={chip}
            style={{
              fontSize: 11,
              color: 'var(--text-muted)',
              padding: '3px 10px',
              borderRadius: 12,
              border: '1px solid var(--border-light)',
              background: 'var(--bg-card)',
              userSelect: 'none',
            }}
          >
            {chip}
          </span>
        ))}
      </div>

      {/* Footer */}
      <div style={{
        marginTop: 16,
        fontSize: 11,
        color: 'var(--text-muted)',
        userSelect: 'none',
      }}>
        XSIAM v3.0 · © 2026 SecureOps Corp
      </div>
    </div>
  )
}
