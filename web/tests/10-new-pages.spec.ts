import { test, expect } from '@playwright/test'
import { login, nav } from './helpers'

test.describe('Agents Hub / Agentix', () => {
  test.beforeEach(async ({ page }) => { await login(page) })

  test('agents hub loads', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', e => errors.push(e.message))
    await nav(page, '/agents-hub')
    await page.waitForTimeout(2000)
    expect(errors.filter(e => !e.includes('ResizeObserver'))).toHaveLength(0)
  })

  test('agentix (AI copilot) loads', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', e => errors.push(e.message))
    await nav(page, '/agentix')
    await page.waitForTimeout(2000)
    expect(errors.filter(e => !e.includes('ResizeObserver'))).toHaveLength(0)
  })
})

test.describe('XSIAM Cases', () => {
  test.beforeEach(async ({ page }) => { await login(page) })

  test('XSIAM cases page loads', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', e => errors.push(e.message))
    await nav(page, '/xsiam-cases')
    await page.waitForTimeout(2000)
    expect(errors.filter(e => !e.includes('ResizeObserver'))).toHaveLength(0)
  })
})

test.describe('ETL Pipeline', () => {
  test.beforeEach(async ({ page }) => { await login(page) })

  test('ETL pipeline page loads', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', e => errors.push(e.message))
    await nav(page, '/etl-pipeline')
    await page.waitForTimeout(2000)
    expect(errors.filter(e => !e.includes('ResizeObserver'))).toHaveLength(0)
  })
})

test.describe('Network Security', () => {
  test.beforeEach(async ({ page }) => { await login(page) })

  test('network security page loads', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', e => errors.push(e.message))
    await nav(page, '/network-security')
    await page.waitForTimeout(2000)
    expect(errors.filter(e => !e.includes('ResizeObserver'))).toHaveLength(0)
  })

  test('network security tabs work', async ({ page }) => {
    await nav(page, '/network-security')
    await page.waitForTimeout(2000)
    const body = await page.locator('body').textContent()
    expect(body).toMatch(/流量|DNS|检测|威胁|网络/i)
  })
})

test.describe('Endpoint Security', () => {
  test.beforeEach(async ({ page }) => { await login(page) })

  test('endpoint security page loads', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', e => errors.push(e.message))
    await nav(page, '/endpoint-security')
    await page.waitForTimeout(2000)
    expect(errors.filter(e => !e.includes('ResizeObserver'))).toHaveLength(0)
  })
})

test.describe('Tenant Admin', () => {
  test.beforeEach(async ({ page }) => { await login(page) })

  test('tenant admin page loads', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', e => errors.push(e.message))
    await nav(page, '/tenant-admin')
    await page.waitForTimeout(2000)
    expect(errors.filter(e => !e.includes('ResizeObserver'))).toHaveLength(0)
  })
})
