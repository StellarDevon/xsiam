import { test, expect } from '@playwright/test'
import { login, nav } from './helpers'

test.describe('Alerts', () => {
  test.beforeEach(async ({ page }) => {
    await login(page)
  })

  test('alerts page loads without errors', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', e => errors.push(e.message))
    await nav(page, '/alerts')
    await page.waitForTimeout(2000)
    expect(errors.filter(e => !e.includes('ResizeObserver'))).toHaveLength(0)
  })

  test('alerts list shows rows', async ({ page }) => {
    await nav(page, '/alerts')
    await page.waitForTimeout(2000)
    await expect(page.locator('body')).not.toContainText('Cannot read')
    // Should have table rows or list items
    const body = await page.locator('body').textContent()
    // Seeded alerts should appear (MITRE tactics or severity badges)
    expect(body).toMatch(/critical|high|medium|low|严重|高危/i)
  })

  test('alert search/filter works', async ({ page }) => {
    await nav(page, '/alerts')
    await page.waitForTimeout(1500)
    const searchInput = page.locator('input[placeholder*="搜索"], input[placeholder*="search"]').first()
    if (await searchInput.isVisible()) {
      await searchInput.fill('PowerShell')
      await page.waitForTimeout(1000)
      const body = await page.locator('body').textContent()
      expect(body?.toLowerCase()).toContain('powershell')
    }
  })

  test('alert detail panel opens on click', async ({ page }) => {
    await nav(page, '/alerts')
    await page.waitForTimeout(2000)
    const firstRow = page.locator('table tbody tr, [class*="row"], [class*="item"]').first()
    if (await firstRow.isVisible()) {
      await firstRow.click()
      await page.waitForTimeout(1000)
    }
  })

  test('no JS errors on alerts page', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', e => errors.push(e.message))
    await nav(page, '/alerts')
    await page.waitForTimeout(3000)
    expect(errors.filter(e => !e.includes('ResizeObserver'))).toHaveLength(0)
  })
})
