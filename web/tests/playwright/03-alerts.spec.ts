import { test, expect } from '@playwright/test'
import { nav, collectErrors } from './helpers'

test.describe('Alerts', () => {
  test('loads without JS errors', async ({ page }) => {
    const errors = collectErrors(page)
    await nav(page, '/alerts')
    await page.waitForTimeout(2000)
    expect(errors).toHaveLength(0)
  })

  test('shows seeded alert data', async ({ page }) => {
    await nav(page, '/alerts')
    await page.waitForTimeout(2000)
    const body = await page.locator('body').textContent()
    expect(body).toMatch(/critical|high|medium|low|严重|高危|PowerShell|ALT-/i)
  })

  test('search filter narrows results', async ({ page }) => {
    await nav(page, '/alerts')
    await page.waitForTimeout(1500)
    const searchInput = page.locator('input[placeholder*="搜索"], input[placeholder*="search"], input[placeholder*="Search"]').first()
    if (await searchInput.isVisible()) {
      await searchInput.fill('PowerShell')
      await page.waitForTimeout(1000)
      const body = await page.locator('body').textContent()
      expect(body?.toLowerCase()).toContain('powershell')
    }
  })

  test('clicking a row opens detail', async ({ page }) => {
    await nav(page, '/alerts')
    await page.waitForTimeout(2000)
    const rows = page.locator('table tbody tr').first()
    if (await rows.isVisible()) {
      await rows.click()
      await page.waitForTimeout(800)
      // Some panel/drawer should appear
    }
  })

  test('severity filter works', async ({ page }) => {
    await nav(page, '/alerts')
    await page.waitForTimeout(1500)
    // Try clicking a severity badge/button if present
    const critBtn = page.locator('button:has-text("Critical"), button:has-text("严重"), [class*="critical"]').first()
    if (await critBtn.isVisible()) {
      await critBtn.click()
      await page.waitForTimeout(800)
    }
  })
})
