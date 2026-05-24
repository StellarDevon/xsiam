import { test, expect } from '@playwright/test'
import { login, nav } from './helpers'

test.describe('Detection Rules', () => {
  test.beforeEach(async ({ page }) => { await login(page) })

  test('detection rules page loads', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', e => errors.push(e.message))
    await nav(page, '/detection-rules')
    await page.waitForTimeout(2000)
    expect(errors.filter(e => !e.includes('ResizeObserver'))).toHaveLength(0)
  })

  test('rules list shows seeded rules', async ({ page }) => {
    await nav(page, '/detection-rules')
    await page.waitForTimeout(2000)
    const body = await page.locator('body').textContent()
    expect(body).toMatch(/PowerShell|LSASS|ransomware|RULE-/i)
  })
})

test.describe('Playbooks', () => {
  test.beforeEach(async ({ page }) => { await login(page) })

  test('playbooks page loads', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', e => errors.push(e.message))
    await nav(page, '/playbooks')
    await page.waitForTimeout(2000)
    expect(errors.filter(e => !e.includes('ResizeObserver'))).toHaveLength(0)
  })

  test('playbooks list shows data', async ({ page }) => {
    await nav(page, '/playbooks')
    await page.waitForTimeout(2000)
    const body = await page.locator('body').textContent()
    expect(body).toMatch(/Ransomware|Isolate|Response|playbook/i)
  })
})

test.describe('Actions', () => {
  test.beforeEach(async ({ page }) => { await login(page) })

  test('actions page loads', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', e => errors.push(e.message))
    await nav(page, '/actions')
    await page.waitForTimeout(2000)
    expect(errors.filter(e => !e.includes('ResizeObserver'))).toHaveLength(0)
  })
})
