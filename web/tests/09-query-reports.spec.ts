import { test, expect } from '@playwright/test'
import { login, nav } from './helpers'

test.describe('Query Center', () => {
  test.beforeEach(async ({ page }) => { await login(page) })

  test('query center loads', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', e => errors.push(e.message))
    await nav(page, '/query')
    await page.waitForTimeout(2000)
    expect(errors.filter(e => !e.includes('ResizeObserver'))).toHaveLength(0)
  })

  test('query editor visible', async ({ page }) => {
    await nav(page, '/query')
    await page.waitForTimeout(2000)
    const body = await page.locator('body').textContent()
    expect(body).toMatch(/XQL|query|查询|dataset/i)
  })
})

test.describe('Reports', () => {
  test.beforeEach(async ({ page }) => { await login(page) })

  test('reports page loads', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', e => errors.push(e.message))
    await nav(page, '/reports')
    await page.waitForTimeout(2000)
    expect(errors.filter(e => !e.includes('ResizeObserver'))).toHaveLength(0)
  })
})

test.describe('Settings', () => {
  test.beforeEach(async ({ page }) => { await login(page) })

  test('settings page loads', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', e => errors.push(e.message))
    await nav(page, '/settings')
    await page.waitForTimeout(2000)
    expect(errors.filter(e => !e.includes('ResizeObserver'))).toHaveLength(0)
  })
})
