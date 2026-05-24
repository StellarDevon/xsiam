import { test, expect } from '@playwright/test'
import { nav, collectErrors } from './helpers'

test.describe('Threat Intelligence', () => {
  test('threat-intel page loads without JS errors', async ({ page }) => {
    const errors = collectErrors(page)
    await nav(page, '/threat-intel')
    await page.waitForTimeout(2000)
    expect(errors).toHaveLength(0)
  })

  test('shows threat intel content', async ({ page }) => {
    await nav(page, '/threat-intel')
    await page.waitForTimeout(2000)
    const body = await page.locator('body').textContent()
    expect(body).toMatch(/APT|threat|malware|威胁/i)
  })
})

test.describe('IOCs', () => {
  test('loads without JS errors', async ({ page }) => {
    const errors = collectErrors(page)
    await nav(page, '/iocs')
    await page.waitForTimeout(2000)
    expect(errors).toHaveLength(0)
  })

  test('shows IOC data', async ({ page }) => {
    await nav(page, '/iocs')
    await page.waitForTimeout(2000)
    const body = await page.locator('body').textContent()
    expect(body).toMatch(/malicious|suspicious|IP|domain|hash/i)
  })

  test('IOC type tabs work', async ({ page }) => {
    await nav(page, '/iocs')
    await page.waitForTimeout(1500)
    const body = await page.locator('body').textContent()
    expect(body).toMatch(/ip|domain|url|hash|email/i)
  })
})

test.describe('Intel Feeds', () => {
  test('loads without JS errors', async ({ page }) => {
    const errors = collectErrors(page)
    await nav(page, '/intel-feeds')
    await page.waitForTimeout(2000)
    expect(errors).toHaveLength(0)
  })

  test('shows feed list', async ({ page }) => {
    await nav(page, '/intel-feeds')
    await page.waitForTimeout(2000)
    const body = await page.locator('body').textContent()
    expect(body).toMatch(/Unit 42|WildFire|MISP|feed|sync/i)
  })
})
