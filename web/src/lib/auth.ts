export interface AuthUser {
  _key: string
  username: string
  email: string
  role: string
  display_name: string
  tenant_id: string
}

/** Token lives in localStorage (remember-me) or sessionStorage (session-only). */
export function getToken() {
  return localStorage.getItem('token') ?? sessionStorage.getItem('token')
}
export function getUser(): AuthUser | null {
  const u = localStorage.getItem('user') ?? sessionStorage.getItem('user')
  return u ? JSON.parse(u) : null
}

/** Decode a JWT and return its payload, or null on failure. */
function decodeJwtPayload(token: string): Record<string, unknown> | null {
  try {
    const parts = token.split('.')
    if (parts.length !== 3) return null
    // base64url → base64 padding
    const base64 = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    const json = atob(base64)
    return JSON.parse(json) as Record<string, unknown>
  } catch {
    return null
  }
}

/**
 * Persist auth credentials.
 * @param persist    true → localStorage (remember me), false → sessionStorage
 * @param expiresIn  optional TTL in seconds; overridden by JWT `exp` if present
 */
export function setAuth(token: string, user: AuthUser, persist = true, expiresIn?: number) {
  const store = persist ? localStorage : sessionStorage
  store.setItem('token', token)
  store.setItem('user', JSON.stringify(user))

  // Determine expires_at: prefer JWT exp claim, fall back to expiresIn arg
  let expiresAt: number | null = null

  const payload = decodeJwtPayload(token)
  if (payload && typeof payload.exp === 'number') {
    expiresAt = payload.exp * 1000
  } else if (typeof expiresIn === 'number') {
    expiresAt = Date.now() + expiresIn * 1000
  }

  if (expiresAt !== null) {
    store.setItem('auth_expires_at', String(expiresAt))
  }
}

export function clearAuth() {
  localStorage.removeItem('token')
  localStorage.removeItem('user')
  localStorage.removeItem('auth_expires_at')
  sessionStorage.removeItem('token')
  sessionStorage.removeItem('user')
  sessionStorage.removeItem('auth_expires_at')
}

/** Returns true if the stored auth token has passed its expiry timestamp. */
export function isAuthExpired(): boolean {
  const stored =
    localStorage.getItem('auth_expires_at') ?? sessionStorage.getItem('auth_expires_at')
  // If no expiry stored, treat as not expired (legacy tokens)
  if (!stored) return false
  return Date.now() > parseInt(stored, 10)
}

export function isAuthenticated(): boolean {
  return !!getToken() && !isAuthExpired()
}

/** Returns seconds remaining until the session expires (0 if already expired or unknown). */
export function getSecondsToExpiry(): number {
  const stored =
    localStorage.getItem('auth_expires_at') ?? sessionStorage.getItem('auth_expires_at')
  if (!stored) return 9999999 // no expiry info — treat as very far out
  return Math.max(0, (parseInt(stored, 10) - Date.now()) / 1000)
}
