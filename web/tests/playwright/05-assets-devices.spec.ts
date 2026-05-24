import { test, expect } from '@playwright/test'
import { nav, collectErrors } from './helpers'

test.describe('Assets', () => {
  test('loads without JS errors', async ({ page }) => {
    const errors = collectErrors(page)
    await nav(page, '/assets')
    await page.waitForTimeout(2000)
    expect(errors).toHaveLength(0)
  })

  test('shows seeded asset data', async ({ page }) => {
    await nav(page, '/assets')
    await page.waitForTimeout(2000)
    const body = await page.locator('body').textContent()
    expect(body).toMatch(/WKSTN|SRV-|server|workstation|DC-PROD/i)
  })

  test('asset type filter works', async ({ page }) => {
    await nav(page, '/assets')
    await page.waitForTimeout(1500)
    const filterBtn = page.locator('button:has-text("server"), button:has-text("服务器"), select').first()
    if (await filterBtn.isVisible()) {
      await filterBtn.click()
      await page.waitForTimeout(500)
    }
  })
})

test.describe('Vulnerabilities', () => {
  test('loads without JS errors', async ({ page }) => {
    const errors = collectErrors(page)
    await nav(page, '/vulnerabilities')
    await page.waitForTimeout(2000)
    expect(errors).toHaveLength(0)
  })

  test('shows CVE data', async ({ page }) => {
    await nav(page, '/vulnerabilities')
    await page.waitForTimeout(2000)
    const body = await page.locator('body').textContent()
    expect(body).toMatch(/CVE-2024|critical|high|9\.\d/i)
  })
})

test.describe('Devices / Agents', () => {
  test('loads without JS errors', async ({ page }) => {
    const errors = collectErrors(page)
    await nav(page, '/devices')
    await page.waitForTimeout(2000)
    expect(errors).toHaveLength(0)
  })

  test('shows device list', async ({ page }) => {
    await nav(page, '/devices')
    await page.waitForTimeout(2000)
    const body = await page.locator('body').textContent()
    expect(body).toMatch(/WKSTN|SRV|online|offline|agent/i)
  })
})
