import { Page } from '@playwright/test'

export const BASE = 'http://localhost:18080'
export const EMAIL = 'admin'
export const PASSWORD = 'admin123'

/** Login and store auth state. Returns JWT token. */
export async function login(page: Page): Promise<void> {
  await page.goto(`${BASE}/login`)
  await page.waitForSelector('input[type="text"], input[name="username"], input[placeholder*="用户名"], input[placeholder*="邮箱"]', { timeout: 10000 })
  // Fill username/email field
  const emailInput = page.locator('input').first()
  await emailInput.fill(EMAIL)
  // Fill password
  const pwInput = page.locator('input[type="password"]')
  await pwInput.fill(PASSWORD)
  // Submit
  await Promise.all([
    page.waitForURL(url => !url.toString().includes('/login'), { timeout: 15000 }),
    page.locator('button[type="submit"], button:has-text("登录")').click(),
  ])
}

/** Navigate to a path and wait for page to settle. */
export async function nav(page: Page, path: string): Promise<void> {
  await page.goto(`${BASE}${path}`)
  await page.waitForLoadState('networkidle', { timeout: 15000 })
}
