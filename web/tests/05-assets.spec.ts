import { test, expect } from '@playwright/test'
import { login, nav } from './helpers'

test.describe('Assets', () => {
  test.beforeEach(async ({ page }) => { await login(page) })

  test('assets page loads', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', e => errors.push(e.message))
    await nav(page, '/assets')
    await page.waitForTimeout(2000)
    expect(errors.filter(e => !e.includes('ResizeObserver'))).toHaveLength(0)
  })

  test('asset list shows seeded items', async ({ page }) => {
    await nav(page, '/assets')
    await page.waitForTimeout(2000)
    const body = await page.locator('body').textContent()
    expect(body).toMatch(/WKSTN|SRV-|server|workstation/i)
  })
})

test.describe('Vulnerabilities', () => {
  test.beforeEach(async ({ page }) => { await login(page) })

  test('vulns page loads', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', e => errors.push(e.message))
    await nav(page, '/vulnerabilities')
    await page.waitForTimeout(2000)
    expect(errors.filter(e => !e.includes('ResizeObserver'))).toHaveLength(0)
  })

  test('CVE data visible', async ({ page }) => {
    await nav(page, '/vulnerabilities')
    await page.waitForTimeout(2000)
    const body = await page.locator('body').textContent()
    expect(body).toMatch(/CVE-|critical|high/i)
  })
})

test.describe('Devices', () => {
  test.beforeEach(async ({ page }) => { await login(page) })

  test('devices page loads', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', e => errors.push(e.message))
    await nav(page, '/devices')
    await page.waitForTimeout(2000)
    expect(errors.filter(e => !e.includes('ResizeObserver'))).toHaveLength(0)
  })
})
