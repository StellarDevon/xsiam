/**
 * userProfile — thin wrapper around GET/PATCH /api/users/me/profile.
 * Handles loading user preferences (lang, theme, display_name, email)
 * on login, and saving when user changes settings.
 */
import api from './api'

export interface UserProfile {
  user_id?: string
  tenant_id?: string
  display_name: string
  email: string
  lang: string   // 'zh' | 'en'
  theme: string  // 'dark' | 'light'
}

/** Fetch profile from API. Returns null on failure (not logged in / network error). */
export async function fetchProfile(): Promise<UserProfile | null> {
  try {
    const r = await api.get('/users/me/profile')
    return r.data?.data ?? null
  } catch {
    return null
  }
}

/** Patch one or more profile fields. */
export async function saveProfile(patch: Partial<UserProfile>): Promise<void> {
  try {
    await api.patch('/users/me/profile', patch)
  } catch {
    // Silent — preferences are also stored in localStorage as fallback
  }
}
