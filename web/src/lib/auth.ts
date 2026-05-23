export interface AuthUser {
  _key: string
  username: string
  email: string
  role: string
  display_name: string
  tenant_id: string
}

export function getToken() { return localStorage.getItem('token') }
export function getUser(): AuthUser | null {
  const u = localStorage.getItem('user')
  return u ? JSON.parse(u) : null
}
export function setAuth(token: string, user: AuthUser) {
  localStorage.setItem('token', token)
  localStorage.setItem('user', JSON.stringify(user))
}
export function clearAuth() {
  localStorage.removeItem('token')
  localStorage.removeItem('user')
}
export function isAuthenticated() { return !!getToken() }
