import { Page } from '@playwright/test'

export const BASE = 'http://localhost:18080'

/** Navigate to a path and wait for page to settle. */
export async function nav(page: Page, path: string): Promise<void> {
  await page.goto(`${BASE}${path}`)
  await page.waitForLoadState('networkidle', { timeout: 15000 })
  await page.waitForTimeout(1000)
}

/** Collect JS runtime errors, excluding noise. */
export function collectErrors(page: Page): string[] {
  const errors: string[] = []
  page.on('pageerror', e => {
    const msg = e.message
    // Ignore known benign errors
    if (msg.includes('ResizeObserver') || msg.includes('Non-Error promise rejection')) return
    errors.push(msg)
  })
  return errors
}
