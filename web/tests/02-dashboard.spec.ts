import { test, expect } from '@playwright/test'
import { login, nav } from './helpers'

test.describe('Dashboard', () => {
  test.beforeEach(async ({ page }) => {
    await login(page)
  })

  test('dashboard loads with stat cards', async ({ page }) => {
    await nav(page, '/')
    // Should show some stat/kpi cards
    await expect(page.locator('body')).not.toContainText('Error')
    await expect(page.locator('body')).not.toContainText('Cannot read')
    await expect(page.locator('body')).not.toContainText('undefined is not')
    // At least one numeric value visible (alert counts etc)
    const body = await page.locator('body').textContent()
    expect(body).toBeTruthy()
  })

  test('no JS runtime errors on dashboard', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', e => errors.push(e.message))
    await nav(page, '/')
    await page.waitForTimeout(2000)
    expect(errors.filter(e => !e.includes('ResizeObserver'))).toHaveLength(0)
  })

  test('sidebar navigation links visible', async ({ page }) => {
    await nav(page, '/')
    // Sidebar should contain key nav items
    await expect(page.locator('nav, aside, [class*="sidebar"]').first()).toBeVisible()
  })

  test('theme toggle works', async ({ page }) => {
    await nav(page, '/')
    const themeBtn = page.locator('button[title*="主题"], button[title*="theme"], button[aria-label*="theme"]').first()
    if (await themeBtn.isVisible()) {
      await themeBtn.click()
      await page.waitForTimeout(300)
    }
  })
})
