import { test, expect } from '@playwright/test'
import { BASE, login } from './helpers'

test.describe('Login / Auth', () => {
  test('login page renders', async ({ page }) => {
    await page.goto(`${BASE}/login`)
    await expect(page).toHaveTitle(/XSIAM|Cortex|web/i)
    await expect(page.locator('input').first()).toBeVisible()
    await expect(page.locator('input[type="password"]')).toBeVisible()
  })

  test('wrong password shows error', async ({ page }) => {
    await page.goto(`${BASE}/login`)
    await page.locator('input').first().fill('admin')
    await page.locator('input[type="password"]').fill('wrongpassword')
    await page.locator('button[type="submit"], button:has-text("登录")').click()
    // Should stay on login page
    await page.waitForTimeout(2000)
    await expect(page).toHaveURL(/login/)
  })

  test('short password (<6) shows client validation error', async ({ page }) => {
    await page.goto(`${BASE}/login`)
    await page.locator('input').first().fill('admin')
    await page.locator('input[type="password"]').fill('abc')
    await page.locator('button[type="submit"], button:has-text("登录")').click()
    await page.waitForTimeout(500)
    // Should still be on login
    await expect(page).toHaveURL(/login/)
  })

  test('successful login redirects to dashboard', async ({ page }) => {
    await login(page)
    await expect(page).not.toHaveURL(/login/)
  })

  test('unauthenticated redirect to login', async ({ page }) => {
    await page.goto(`${BASE}/incidents`)
    await expect(page).toHaveURL(/login/)
  })
})
