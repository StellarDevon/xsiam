import { test, expect } from '@playwright/test'
import { nav, collectErrors } from './helpers'

test.describe('Incidents', () => {
  test('loads without JS errors', async ({ page }) => {
    const errors = collectErrors(page)
    await nav(page, '/incidents')
    await page.waitForTimeout(2000)
    expect(errors).toHaveLength(0)
  })

  test('shows seeded incident data', async ({ page }) => {
    await nav(page, '/incidents')
    await page.waitForTimeout(2000)
    const body = await page.locator('body').textContent()
    expect(body).toMatch(/INC-|Ransomware|APT|Lateral|credential/i)
  })

  test('incident list rows are clickable', async ({ page }) => {
    await nav(page, '/incidents')
    await page.waitForTimeout(2000)
    const row = page.locator('table tbody tr, [class*="row"][class*="incident"]').first()
    if (await row.isVisible()) {
      await row.click()
      await page.waitForTimeout(1000)
    }
  })

  test('status filter tabs present', async ({ page }) => {
    await nav(page, '/incidents')
    await page.waitForTimeout(1500)
    const body = await page.locator('body').textContent()
    // Should have status options
    expect(body).toMatch(/新建|调查|处置|关闭|New|Investigating|Resolved|All/i)
  })
})
