import { test, expect } from '@playwright/test'
import { nav, collectErrors } from './helpers'

test.describe('Query Center', () => {
  test('loads without JS errors', async ({ page }) => {
    const errors = collectErrors(page)
    await nav(page, '/query')
    await page.waitForTimeout(2000)
    expect(errors).toHaveLength(0)
  })

  test('shows query editor', async ({ page }) => {
    await nav(page, '/query')
    await page.waitForTimeout(2000)
    const body = await page.locator('body').textContent()
    expect(body).toMatch(/XQL|query|查询|dataset|SELECT/i)
  })

  test('query editor accepts input', async ({ page }) => {
    await nav(page, '/query')
    await page.waitForTimeout(2000)
    const editor = page.locator('textarea, [class*="editor"], [role="textbox"]').first()
    if (await editor.isVisible()) {
      await editor.click()
      await editor.fill('dataset=endpoint_events | limit 10')
      await page.waitForTimeout(500)
    }
  })
})

test.describe('Reports', () => {
  test('loads without JS errors', async ({ page }) => {
    const errors = collectErrors(page)
    await nav(page, '/reports')
    await page.waitForTimeout(2000)
    expect(errors).toHaveLength(0)
  })

  test('shows report list', async ({ page }) => {
    await nav(page, '/reports')
    await page.waitForTimeout(2000)
    const body = await page.locator('body').textContent()
    expect(body).toMatch(/report|weekly|monthly|generate|报告/i)
  })
})

test.describe('Settings', () => {
  test('loads without JS errors', async ({ page }) => {
    const errors = collectErrors(page)
    await nav(page, '/settings')
    await page.waitForTimeout(2000)
    expect(errors).toHaveLength(0)
  })

  test('shows settings sections', async ({ page }) => {
    await nav(page, '/settings')
    await page.waitForTimeout(2000)
    const body = await page.locator('body').textContent()
    expect(body).toMatch(/setting|profile|password|notification|设置|用户/i)
  })
})
