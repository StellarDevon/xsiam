import { chromium } from '@playwright/test';
const BASE = 'http://localhost:18080';
const browser = await chromium.launch({ headless: true });
const page = await browser.newPage();
await page.setViewportSize({ width: 1440, height: 900 });

// Login
const resp = await page.request.post(BASE + '/api/auth/login', {
  data: { email: 'admin', password: 'admin123' },
  headers: { 'Content-Type': 'application/json' }
});
const body = await resp.json().catch(() => ({}));
const token = body.data?.token || body.token;
await page.goto(BASE);
await page.evaluate((t) => { localStorage.setItem('token', t); }, token);

const pages = [
  { path: '/dashboard',          name: '01_dashboard' },
  { path: '/alerts',             name: '02_alerts' },
  { path: '/incidents',          name: '03_incidents' },
  { path: '/causality-graph',    name: '04_causality' },
  { path: '/query',              name: '05_query' },
  { path: '/actions',            name: '06_actions' },
  { path: '/playbooks',          name: '07_playbooks' },
  { path: '/assets',             name: '08_assets' },
  { path: '/identity-risks',     name: '09_identity' },
  { path: '/vulnerabilities',    name: '10_vulns' },
  { path: '/exposure-scores',    name: '11_exposure' },
  { path: '/threat-intel',       name: '12_threat' },
  { path: '/ioc',                name: '13_ioc' },
  { path: '/detection-rules',    name: '14_detection' },
  { path: '/etl-pipeline',       name: '15_etl' },
  { path: '/devices',            name: '16_devices' },
  { path: '/datasources',        name: '17_datasources' },
  { path: '/agentix',            name: '18_agentix' },
  { path: '/cases',              name: '19_cases' },
  { path: '/reports',            name: '20_reports' },
];

for (const p of pages) {
  await page.goto(BASE + p.path);
  await page.waitForTimeout(1800);
  await page.screenshot({ path: `screenshots/${p.name}.png` });
  console.log(`✓ ${p.name}`);
}

await browser.close();
console.log('All done');
