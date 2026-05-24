import { test, expect, chromium } from '@playwright/test'
import { BASE } from './helpers'

// Login tests run WITHOUT the saved auth state so we can test login flows
test.use({ storageState: { cookies: [], origins: [] } })

test.describe('Login / Auth', () => {
  test('login page renders with correct title', async ({ page }) => {
    await page.goto(`${BASE}/login`)
    await page.waitForLoadState('networkidle')
    await expect(page).toHaveTitle(/XSIAM|Cortex|web/i)
    await expect(page.locator('input').first()).toBeVisible()
    await expect(page.locator('input[type="password"]')).toBeVisible()
  })

  test('short password (<6) shows client-side validation error', async ({ page }) => {
    await page.goto(`${BASE}/login`)
    await page.locator('input').first().fill('admin')
    await page.locator('input[type="password"]').fill('abc')
    await page.locator('button[type="submit"], button:has-text("登录")').click()
    await page.waitForTimeout(500)
    // Should still be on login page - validation blocked submit
    await expect(page).toHaveURL(/login/)
    // Error message should appear
    const body = await page.locator('body').textContent()
    expect(body).toMatch(/至少|密码|6位|minimum/i)
  })

  test('wrong password stays on login', async ({ page }) => {
    await page.goto(`${BASE}/login`)
    await page.locator('input').first().fill('admin')
    await page.locator('input[type="password"]').fill('wrongpassword')
    await page.locator('button[type="submit"], button:has-text("登录")').click()
    await page.waitForTimeout(2500)
    await expect(page).toHaveURL(/login/)
  })

  test('correct credentials redirect to dashboard', async ({ page }) => {
    await page.goto(`${BASE}/login`)
    await page.waitForLoadState('networkidle')
    await page.locator('input').first().fill('admin')
    await page.locator('input[type="password"]').fill('admin123')
    await Promise.all([
      page.waitForURL(url => !url.toString().includes('/login'), { timeout: 15000 }),
      page.locator('button[type="submit"], button:has-text("登录")').click(),
    ])
    await expect(page).not.toHaveURL(/login/)
  })

  test('unauthenticated access redirects to login', async ({ page }) => {
    await page.goto(`${BASE}/incidents`)
    await page.waitForLoadState('networkidle')
    await expect(page).toHaveURL(/login/)
  })
})
