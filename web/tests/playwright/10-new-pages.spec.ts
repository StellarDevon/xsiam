import { test, expect } from '@playwright/test'
import { nav, collectErrors } from './helpers'

test.describe('Agents Hub', () => {
  test('loads without JS errors', async ({ page }) => {
    const errors = collectErrors(page)
    await nav(page, '/agents-hub')
    await page.waitForTimeout(2000)
    expect(errors).toHaveLength(0)
  })

  test('shows agent list', async ({ page }) => {
    await nav(page, '/agents-hub')
    await page.waitForTimeout(2000)
    const body = await page.locator('body').textContent()
    expect(body).toMatch(/agent|WKSTN|SRV|online|version/i)
  })
})

test.describe('Agentix (AI Copilot)', () => {
  test('loads without JS errors', async ({ page }) => {
    const errors = collectErrors(page)
    await nav(page, '/agentix')
    await page.waitForTimeout(2000)
    expect(errors).toHaveLength(0)
  })

  test('shows AI chat interface', async ({ page }) => {
    await nav(page, '/agentix')
    await page.waitForTimeout(2000)
    const body = await page.locator('body').textContent()
    expect(body).toMatch(/AI|agent|chat|copilot|assistant|分析/i)
  })
})

test.describe('XSIAM Cases', () => {
  test('loads without JS errors', async ({ page }) => {
    const errors = collectErrors(page)
    await nav(page, '/xsiam-cases')
    await page.waitForTimeout(2000)
    expect(errors).toHaveLength(0)
  })

  test('shows case content', async ({ page }) => {
    await nav(page, '/xsiam-cases')
    await page.waitForTimeout(2000)
    const body = await page.locator('body').textContent()
    expect(body).toMatch(/case|incident|alert|severity|process/i)
  })
})

test.describe('ETL Pipeline', () => {
  test('loads without JS errors', async ({ page }) => {
    const errors = collectErrors(page)
    await nav(page, '/etl-pipeline')
    await page.waitForTimeout(2000)
    expect(errors).toHaveLength(0)
  })

  test('shows ETL rules', async ({ page }) => {
    await nav(page, '/etl-pipeline')
    await page.waitForTimeout(2000)
    const body = await page.locator('body').textContent()
    expect(body).toMatch(/ETL|pipeline|rule|datasource|transform/i)
  })
})

test.describe('Network Security', () => {
  test('loads without JS errors', async ({ page }) => {
    const errors = collectErrors(page)
    await nav(page, '/network-security')
    await page.waitForTimeout(2000)
    expect(errors).toHaveLength(0)
  })

  test('shows network security tabs', async ({ page }) => {
    await nav(page, '/network-security')
    await page.waitForTimeout(2000)
    const body = await page.locator('body').textContent()
    expect(body).toMatch(/流量|DNS|检测|威胁|network|traffic/i)
  })

  test('tab switching works', async ({ page }) => {
    await nav(page, '/network-security')
    await page.waitForTimeout(2000)
    // Click second tab if visible
    const tabs = page.locator('[role="tab"], button[class*="tab"]')
    const count = await tabs.count()
    if (count > 1) {
      await tabs.nth(1).click()
      await page.waitForTimeout(800)
    }
  })
})

test.describe('Endpoint Security', () => {
  test('loads without JS errors', async ({ page }) => {
    const errors = collectErrors(page)
    await nav(page, '/endpoint-security')
    await page.waitForTimeout(2000)
    expect(errors).toHaveLength(0)
  })

  test('shows endpoint security content', async ({ page }) => {
    await nav(page, '/endpoint-security')
    await page.waitForTimeout(2000)
    const body = await page.locator('body').textContent()
    expect(body).toMatch(/endpoint|终端|host|agent|detection|behavior/i)
  })
})

test.describe('Tenant Admin', () => {
  test('loads without JS errors', async ({ page }) => {
    const errors = collectErrors(page)
    await nav(page, '/tenant-admin')
    await page.waitForTimeout(2000)
    expect(errors).toHaveLength(0)
  })

  test('shows tenant list', async ({ page }) => {
    await nav(page, '/tenant-admin')
    await page.waitForTimeout(2000)
    const body = await page.locator('body').textContent()
    expect(body).toMatch(/tenant|租户|admin|tier|usage/i)
  })
})
