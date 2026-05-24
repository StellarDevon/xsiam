import { test, expect } from '@playwright/test'
import { login, nav } from './helpers'

test.describe('Identity Risks', () => {
  test.beforeEach(async ({ page }) => { await login(page) })

  test('identity risks page loads', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', e => errors.push(e.message))
    await nav(page, '/identity-risks')
    await page.waitForTimeout(2000)
    expect(errors.filter(e => !e.includes('ResizeObserver'))).toHaveLength(0)
  })
})

test.describe('Exposure Scores', () => {
  test.beforeEach(async ({ page }) => { await login(page) })

  test('exposure scores page loads', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', e => errors.push(e.message))
    await nav(page, '/exposure')
    await page.waitForTimeout(2000)
    expect(errors.filter(e => !e.includes('ResizeObserver'))).toHaveLength(0)
  })
})

test.describe('Causality Graph', () => {
  test.beforeEach(async ({ page }) => { await login(page) })

  test('causality graph page loads', async ({ page }) => {
    const errors: string[] = []
    page.on('pageerror', e => errors.push(e.message))
    await nav(page, '/causality')
    await page.waitForTimeout(3000)
    expect(errors.filter(e => !e.includes('ResizeObserver'))).toHaveLength(0)
  })
})
