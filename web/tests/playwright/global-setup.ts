import { chromium } from '@playwright/test'
import { fileURLToPath } from 'url'
import { dirname, join } from 'path'

const __filename = fileURLToPath(import.meta.url)
const __dirname = dirname(__filename)

export const STORAGE_STATE = join(__dirname, 'auth-state.json')

const BASE = 'http://localhost:18080'

export default async function globalSetup() {
  const browser = await chromium.launch()
  const context = await browser.newContext()
  const page = await context.newPage()

  // Navigate to login
  await page.goto(`${BASE}/login`)
  await page.waitForLoadState('networkidle')

  // Fill credentials
  await page.locator('input').first().fill('admin')
  await page.locator('input[type="password"]').fill('admin123')

  // Check "remember me" so token goes to localStorage (not sessionStorage)
  const rememberMe = page.locator('input[type="checkbox"]').first()
  const checked = await rememberMe.isChecked().catch(() => false)
  if (!checked) {
    await rememberMe.check().catch(() => {/* checkbox might not exist */})
  }

  // Submit and wait for redirect away from /login
  await Promise.all([
    page.waitForURL(url => !url.toString().includes('/login'), { timeout: 15000 }),
    page.locator('button[type="submit"], button:has-text("登录"), button:has-text("Sign")').click(),
  ])

  // Wait for app to settle and API calls to complete
  await page.waitForTimeout(3000)

  // Verify token is in localStorage
  const token = await page.evaluate(() => localStorage.getItem('token'))
  if (!token) {
    // Fallback: inject token manually from sessionStorage
    await page.evaluate(() => {
      const t = sessionStorage.getItem('token')
      const u = sessionStorage.getItem('user')
      const exp = sessionStorage.getItem('auth_expires_at')
      if (t) {
        localStorage.setItem('token', t)
        if (u) localStorage.setItem('user', u)
        if (exp) localStorage.setItem('auth_expires_at', exp)
      }
    })
    const tokenAfter = await page.evaluate(() => localStorage.getItem('token'))
    console.log(`Token in localStorage after copy: ${tokenAfter ? 'YES (len='+tokenAfter.length+')' : 'NO'}`)
  } else {
    console.log(`Token in localStorage: YES (len=${token.length})`)
  }

  // Save auth state (cookies + localStorage with JWT token)
  await context.storageState({ path: STORAGE_STATE })

  await browser.close()
  console.log('✓ Global setup: saved auth state to', STORAGE_STATE)
}
