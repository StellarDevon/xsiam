import { useState, useEffect, useRef } from 'react'
import { useNavigate } from 'react-router-dom'
import api from '@/lib/api'
import { setAuth } from '@/lib/auth'

/* ── keyframes injected once ── */
const extraStyles = `
@keyframes xsiam-spin {
  to { transform: rotate(360deg); }
}
.xsiam-spinner {
  display: inline-block;
  width: 14px;
  height: 14px;
  border: 2px solid rgba(255,255,255,.30);
  border-top-color: #fff;
  border-radius: 50%;
  animation: xsiam-spin .7s linear infinite;
  vertical-align: middle;
  margin-right: 8px;
}
@keyframes xsiam-fadein {
  from { opacity: 0; transform: translateY(18px); }
  to   { opacity: 1; transform: translateY(0); }
}
.xsiam-card {
  animation: xsiam-fadein .45s cubic-bezier(.22,1,.36,1) both;
}
.xsiam-input {
  width: 100%;
  background: rgba(255,255,255,.06);
  border: 1px solid rgba(79,163,224,.20);
  border-radius: 8px;
  padding: 0 14px;
  color: #fff;
  font-size: 14px;
  height: 44px;
  outline: none;
  box-sizing: border-box;
  transition: border-color .18s, background .18s;
}
.xsiam-input::placeholder { color: rgba(255,255,255,.30); }
.xsiam-input:focus { border-color: rgba(79,163,224,.60); background: rgba(255,255,255,.09); }
.xsiam-input:disabled { opacity: .45; cursor: not-allowed; }
.xsiam-btn-primary {
  width: 100%;
  height: 44px;
  background: linear-gradient(90deg, #0078d4, #005ba1);
  border: none;
  border-radius: 8px;
  color: #fff;
  font-size: 15px;
  font-weight: 600;
  letter-spacing: .04em;
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  transition: filter .18s, opacity .18s;
}
.xsiam-btn-primary:hover:not(:disabled) { filter: brightness(1.15); }
.xsiam-btn-primary:disabled { opacity: .60; cursor: not-allowed; }
.xsiam-btn-back {
  flex: 1;
  height: 44px;
  background: rgba(255,255,255,.06);
  border: 1px solid rgba(79,163,224,.20);
  border-radius: 8px;
  color: rgba(255,255,255,.55);
  font-size: 13px;
  cursor: pointer;
  transition: background .18s;
}
.xsiam-btn-back:hover { background: rgba(255,255,255,.10); }
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

/* ── shared label style ── */
const labelStyle: React.CSSProperties = {
  fontSize: 11,
  color: 'rgba(255,255,255,.45)',
  display: 'block',
  marginBottom: 7,
  textTransform: 'uppercase',
  letterSpacing: .5,
  fontWeight: 500,
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

  return (
    /* ── 外层容器：真正垂直 + 水平居中，深色渐变背景 ── */
    <div style={{
      minHeight: '100vh',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      background: 'linear-gradient(135deg, #020d1a 0%, #001e3c 50%, #012a4a 100%)',
      flexDirection: 'column',
    }}>
      {/* ── 背景网格光晕装饰层 ── */}
      <div style={{
        position: 'fixed',
        inset: 0,
        pointerEvents: 'none',
        backgroundImage:
          'radial-gradient(circle at 20% 50%, rgba(0,120,212,.12) 0%, transparent 50%), ' +
          'radial-gradient(circle at 80% 20%, rgba(0,200,255,.08) 0%, transparent 40%)',
        backgroundSize: '100% 100%',
      }} />

      {/* ── 登录卡片 ── */}
      <div
        className="xsiam-card"
        style={{
          position: 'relative',
          zIndex: 1,
          background: 'rgba(8,20,40,.85)',
          backdropFilter: 'blur(20px)',
          WebkitBackdropFilter: 'blur(20px)',
          border: '1px solid rgba(79,163,224,.20)',
          borderRadius: 16,
          boxShadow: '0 24px 64px rgba(0,0,0,.6), inset 0 1px 0 rgba(79,163,224,.15)',
          padding: '40px 44px',
          width: 400,
          boxSizing: 'border-box',
        }}
      >
        {/* Session expired banner */}
        {sessionExpired && !expiredDismissed && (
          <div style={{
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            fontSize: 12,
            color: '#f0b429',
            padding: '8px 12px',
            background: 'rgba(251,191,36,0.10)',
            border: '1px solid rgba(251,191,36,0.35)',
            borderRadius: 8,
            marginBottom: 20,
          }}>
            <span>⚠️ 会话已过期，请重新登录</span>
            <button
              onClick={() => setExpiredDismissed(true)}
              style={{
                background: 'none',
                border: 'none',
                cursor: 'pointer',
                color: '#f0b429',
                fontSize: 16,
                lineHeight: 1,
                padding: '0 0 0 8px',
              }}
              aria-label="关闭"
            >
              ×
            </button>
          </div>
        )}

        {/* ── Brand ── */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, marginBottom: 32 }}>
          <svg width="38" height="38" viewBox="0 0 36 36" fill="none" aria-hidden="true">
            <circle cx="18" cy="18" r="17" fill="url(#logoGrad)"/>
            <defs>
              <linearGradient id="logoGrad" x1="0" y1="0" x2="36" y2="36" gradientUnits="userSpaceOnUse">
                <stop stopColor="#0078d4"/>
                <stop offset="1" stopColor="#00b4d8"/>
              </linearGradient>
            </defs>
            <path d="M18 7 L27 11 L27 19 C27 24 18 29 18 29 C18 29 9 24 9 19 L9 11 Z"
              fill="rgba(255,255,255,0.12)" stroke="rgba(255,255,255,0.55)" strokeWidth="1"/>
            <path d="M13 18.5 L16.5 22 L23 15"
              stroke="white" strokeWidth="2.2" strokeLinecap="round" strokeLinejoin="round"/>
          </svg>
          <div>
            <div style={{ display: 'flex', alignItems: 'baseline', gap: 7 }}>
              <span style={{
                fontSize: 18,
                fontWeight: 800,
                letterSpacing: 1,
                background: 'linear-gradient(90deg, #4fa3e0, #00e5ff)',
                WebkitBackgroundClip: 'text',
                WebkitTextFillColor: 'transparent',
              }}>
                XSIAM
              </span>
              <span style={{ fontSize: 11, color: 'rgba(79,163,224,.70)', fontWeight: 600 }}>v3.0</span>
            </div>
            <div style={{ fontSize: 10, color: 'rgba(255,255,255,.35)', marginTop: 2, letterSpacing: .3 }}>
              Extended Detection &amp; Response Platform
            </div>
          </div>
        </div>

        {/* ── MFA Step ── */}
        {mfaStep ? (
          <form onSubmit={handleOtpSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            <div style={{ fontSize: 14, color: '#fff', fontWeight: 600, marginBottom: 2 }}>
              🔐 双因素验证
            </div>
            <div style={{ fontSize: 12, color: 'rgba(255,255,255,.45)', marginBottom: 4, lineHeight: 1.6 }}>
              请输入您的身份验证器应用中的6位验证码
            </div>

            <div>
              <label style={labelStyle}>验证码</label>
              <input
                type="text"
                value={otp}
                onChange={e => { setOtp(e.target.value.replace(/\D/g, '').slice(0, 6)); setOtpErr('') }}
                placeholder="000000"
                maxLength={6}
                pattern="[0-9]{6}"
                autoComplete="one-time-code"
                autoFocus
                className="xsiam-input"
                style={{ letterSpacing: '0.35em', textAlign: 'center', fontSize: 20 }}
                onKeyDown={e => { if (e.key === 'Enter') { e.preventDefault(); handleOtpSubmit() } }}
              />
              {otpErr && (
                <span style={{ fontSize: 11, color: '#ef5350', marginTop: 5, display: 'block' }}>
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
                borderRadius: 8,
                fontWeight: 600,
              }}>
                {successMsg}
              </div>
            )}

            <div style={{ display: 'flex', gap: 10 }}>
              <button
                type="button"
                className="xsiam-btn-back"
                onClick={() => { setMfaStep(false); setOtp(''); setOtpErr(''); pendingAuthRef.current = null }}
              >
                返回
              </button>
              <button
                type="submit"
                className="xsiam-btn-primary"
                style={{ flex: 2 }}
              >
                验证
              </button>
            </div>
          </form>
        ) : (
          /* ── Login Step ── */
          <form onSubmit={handleSubmit} style={{ display: 'flex', flexDirection: 'column', gap: 16 }}>
            {/* Username */}
            <div>
              <label style={labelStyle}>用户名或邮箱</label>
              <input
                type="text"
                value={username}
                onChange={e => { setUsername(e.target.value); if (usernameErr) setUsernameErr('') }}
                onKeyDown={handleUsernameKeyDown}
                placeholder="请输入用户名"
                autoComplete="username"
                disabled={loading || isLocked}
                className="xsiam-input"
              />
              {usernameErr && (
                <span style={{ fontSize: 11, color: '#ef5350', marginTop: 5, display: 'block' }}>
                  {usernameErr}
                </span>
              )}
            </div>

            {/* Password */}
            <div>
              <label style={labelStyle}>密码</label>
              <input
                type="password"
                value={password}
                onChange={e => { setPassword(e.target.value); if (passwordErr) setPasswordErr('') }}
                onKeyDown={handlePasswordKeyDown}
                placeholder="请输入密码"
                autoComplete="current-password"
                disabled={loading || isLocked}
                className="xsiam-input"
              />
              {passwordErr && (
                <span style={{ fontSize: 11, color: '#ef5350', marginTop: 5, display: 'block' }}>
                  {passwordErr}
                </span>
              )}
            </div>

            {/* Remember me + last login */}
            <div style={{ marginTop: -4 }}>
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
                  style={{ accentColor: '#4fa3e0', cursor: 'inherit', width: 13, height: 13 }}
                />
                <span style={{ fontSize: 12, color: 'rgba(255,255,255,.45)' }}>记住我</span>
              </label>
              {lastLoginIso && (
                <div style={{ fontSize: 11, color: 'rgba(255,255,255,.30)', marginTop: 5, paddingLeft: 21 }}>
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
                borderRadius: 8,
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
                background: 'rgba(229,57,53,0.10)',
                border: '1px solid rgba(229,57,53,0.30)',
                borderRadius: 8,
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
                background: 'rgba(255,152,0,0.10)',
                border: '1px solid rgba(255,152,0,0.30)',
                borderRadius: 8,
                textAlign: 'center',
              }}>
                请等待 {lockout}s 后重试
              </div>
            )}

            {/* Submit */}
            <button
              type="submit"
              disabled={loading || isLocked}
              className="xsiam-btn-primary"
              style={{ marginTop: 4 }}
            >
              {loading && <span className="xsiam-spinner" aria-hidden="true" />}
              {isLocked
                ? `请等待 ${lockout}s`
                : loading
                  ? '登录中…'
                  : '登 录'}
            </button>
          </form>
        )}

        {/* Forgot password */}
        {!mfaStep && (
          <div style={{ textAlign: 'right', marginTop: 12 }}>
            <button
              onClick={handleForgotPassword}
              style={{
                background: 'none',
                border: 'none',
                cursor: 'pointer',
                color: 'rgba(79,163,224,.70)',
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

      {/* ── Feature chips ── */}
      <div style={{
        position: 'relative',
        zIndex: 1,
        display: 'flex',
        gap: 8,
        marginTop: 22,
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
              color: 'rgba(79,163,224,.80)',
              padding: '4px 12px',
              borderRadius: 12,
              border: '1px solid rgba(79,163,224,.25)',
              background: 'rgba(79,163,224,.10)',
              userSelect: 'none',
            }}
          >
            {chip}
          </span>
        ))}
      </div>

      {/* ── Footer ── */}
      <div style={{
        position: 'relative',
        zIndex: 1,
        marginTop: 16,
        fontSize: 11,
        color: 'rgba(255,255,255,.30)',
        userSelect: 'none',
      }}>
        XSIAM v3.0 · © 2026 SecureOps Corp
      </div>
    </div>
  )
}
