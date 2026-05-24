import { test, expect } from '@playwright/test'
import { nav, collectErrors } from './helpers'

test.describe('Detection Rules', () => {
  test('loads without JS errors', async ({ page }) => {
    const errors = collectErrors(page)
    await nav(page, '/detection-rules')
    await page.waitForTimeout(2000)
    expect(errors).toHaveLength(0)
  })

  test('shows seeded rules', async ({ page }) => {
    await nav(page, '/detection-rules')
    await page.waitForTimeout(2000)
    const body = await page.locator('body').textContent()
    expect(body).toMatch(/PowerShell|LSASS|ransomware|RULE-|bioc|ioc|ueba/i)
  })

  test('rule type filter tabs visible', async ({ page }) => {
    await nav(page, '/detection-rules')
    await page.waitForTimeout(1500)
    const body = await page.locator('body').textContent()
    expect(body).toMatch(/BIOC|IOC|UEBA|全部|All/i)
  })
})

test.describe('Playbooks', () => {
  test('loads without JS errors', async ({ page }) => {
    const errors = collectErrors(page)
    await nav(page, '/playbooks')
    await page.waitForTimeout(2000)
    expect(errors).toHaveLength(0)
  })

  test('shows seeded playbooks', async ({ page }) => {
    await nav(page, '/playbooks')
    await page.waitForTimeout(2000)
    const body = await page.locator('body').textContent()
    expect(body).toMatch(/Ransomware|Isolate|Response|IOC|playbook/i)
  })
})

test.describe('Actions', () => {
  test('loads without JS errors', async ({ page }) => {
    const errors = collectErrors(page)
    await nav(page, '/actions')
    await page.waitForTimeout(2000)
    expect(errors).toHaveLength(0)
  })

  test('shows action list', async ({ page }) => {
    await nav(page, '/actions')
    await page.waitForTimeout(2000)
    const body = await page.locator('body').textContent()
    expect(body).toMatch(/isolate|block|kill|reset|pending|completed/i)
  })
})
