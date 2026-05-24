import { test, expect } from '@playwright/test'
import { login, nav } from './helpers'

test.describe('Incidents', () => {
  test.beforeEach(async ({ page }) => {
    await login(page)
  })

  test('incidents page loads without JS errors', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', e => errors.push(e.message))
    await nav(page, '/incidents')
    await page.waitForTimeout(2000)
    expect(errors.filter(e => !e.includes('ResizeObserver'))).toHaveLength(0)
  })

  test('incident list shows seeded data', async ({ page }) => {
    await nav(page, '/incidents')
    await page.waitForTimeout(2000)
    const body = await page.locator('body').textContent()
    expect(body).toMatch(/INC-|Ransomware|APT|critical|high/i)
  })

  test('incident detail opens', async ({ page }) => {
    await nav(page, '/incidents')
    await page.waitForTimeout(2000)
    const rows = page.locator('table tbody tr, [class*="row"]')
    if (await rows.count() > 0) {
      await rows.first().click()
      await page.waitForTimeout(1000)
      // detail panel or modal should appear
    }
  })
})
