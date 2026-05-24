import { test, expect } from '@playwright/test'
import { login, nav } from './helpers'

test.describe('Threat Intel / IOCs / Feeds', () => {
  test.beforeEach(async ({ page }) => { await login(page) })

  test('threat intel page loads', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', e => errors.push(e.message))
    await nav(page, '/threat-intel')
    await page.waitForTimeout(2000)
    expect(errors.filter(e => !e.includes('ResizeObserver'))).toHaveLength(0)
  })

  test('IOCs page loads with data', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', e => errors.push(e.message))
    await nav(page, '/iocs')
    await page.waitForTimeout(2000)
    expect(errors.filter(e => !e.includes('ResizeObserver'))).toHaveLength(0)
    const body = await page.locator('body').textContent()
    expect(body).toMatch(/malicious|suspicious|IOC|ip|domain/i)
  })

  test('intel feeds page loads', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', e => errors.push(e.message))
    await nav(page, '/intel-feeds')
    await page.waitForTimeout(2000)
    expect(errors.filter(e => !e.includes('ResizeObserver'))).toHaveLength(0)
  })
})
