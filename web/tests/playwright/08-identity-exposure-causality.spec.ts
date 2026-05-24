import { test, expect } from '@playwright/test'
import { nav, collectErrors } from './helpers'

test.describe('Identity Risks', () => {
  test('loads without JS errors', async ({ page }) => {
    const errors = collectErrors(page)
    await nav(page, '/identity-risks')
    await page.waitForTimeout(2000)
    expect(errors).toHaveLength(0)
  })

  test('shows identity risk content', async ({ page }) => {
    await nav(page, '/identity-risks')
    await page.waitForTimeout(2000)
    const body = await page.locator('body').textContent()
    expect(body).toMatch(/identity|user|risk|privilege|admin/i)
  })
})

test.describe('Exposure Scores', () => {
  test('loads without JS errors', async ({ page }) => {
    const errors = collectErrors(page)
    await nav(page, '/exposure')
    await page.waitForTimeout(2000)
    expect(errors).toHaveLength(0)
  })

  test('shows exposure score data', async ({ page }) => {
    await nav(page, '/exposure')
    await page.waitForTimeout(2000)
    const body = await page.locator('body').textContent()
    expect(body).toMatch(/exposure|score|risk|asset|暴露/i)
  })
})

test.describe('Causality Graph', () => {
  test('loads without JS errors', async ({ page }) => {
    const errors = collectErrors(page)
    await nav(page, '/causality')
    await page.waitForTimeout(3000)
    expect(errors).toHaveLength(0)
  })

  test('shows graph canvas or node list', async ({ page }) => {
    await nav(page, '/causality')
    await page.waitForTimeout(3000)
    const body = await page.locator('body').textContent()
    expect(body).toMatch(/graph|node|edge|incident|causality|因果/i)
  })
})
