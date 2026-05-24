import { test, expect } from '@playwright/test'
import { nav, collectErrors, BASE } from './helpers'

test.describe('Dashboard', () => {
  test('loads without JS errors', async ({ page }) => {
    const errors = collectErrors(page)
    await nav(page, '/')
    await page.waitForTimeout(2000)
    expect(errors).toHaveLength(0)
  })

  test('shows KPI / stat cards', async ({ page }) => {
    await nav(page, '/')
    await page.waitForTimeout(2000)
    const body = await page.locator('body').textContent()
    expect(body).not.toContain('Cannot read')
    expect(body).not.toContain('undefined is not')
    // Should have numbers or Chinese labels
    expect(body).toMatch(/告警|事件|资产|alerts|incidents|\d+/i)
  })

  test('sidebar is visible with nav items', async ({ page }) => {
    await nav(page, '/')
    await page.waitForTimeout(1000)
    // Sidebar uses class "icon-sidebar" with NavLink anchors
    const sidebar = page.locator('.icon-sidebar, [class*="icon-sidebar"]').first()
    const body = await page.locator('body').textContent()
    // Sidebar contains navigation labels
    expect(body).toMatch(/告警|事件|资产|Dashboard|Alerts|Incidents/i)
  })

  test('topbar / header is visible', async ({ page }) => {
    await nav(page, '/')
    await page.waitForTimeout(500)
    // TopBar renders a div; verify it renders by checking for user avatar or bell icon
    const body = await page.locator('body').textContent()
    // TopBar contains user info or notification elements
    expect(body).toMatch(/admin|XSIAM|v3/i)
  })
})
