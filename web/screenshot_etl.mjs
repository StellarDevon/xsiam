import { chromium } from '@playwright/test';
const BASE = 'http://localhost:18080';
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage();
await page.setViewportSize({ width: 1440, height: 900 });

const resp = await page.request.post(BASE + '/api/auth/login', {
  data: { email: 'admin', password: 'admin123' },
  headers: { 'Content-Type': 'application/json' }
});
const body = await resp.json().catch(() => ({}));
const token = body.data?.token || body.token;
if (token) {
  await page.goto(BASE);
  await page.evaluate((t) => { localStorage.setItem('token', t); }, token);
}

await page.goto(BASE + '/etl-pipeline');
await page.waitForTimeout(3000);

// Full page screenshot
await page.screenshot({ path: 'etl_full.png' });

// Measure
const dims = await page.evaluate(() => {
  const svg = document.querySelector('[aria-label="ETL Pipeline"]');
  return svg ? svg.getBoundingClientRect() : null;
});
console.log('SVG rect:', JSON.stringify(dims));
await browser.close();
