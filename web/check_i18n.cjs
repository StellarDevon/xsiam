const { chromium } = require('playwright');

async function getToken(browser) {
  const ctx = await browser.newContext();
  const p = await ctx.newPage();
  const res = await p.request.post('http://localhost:18080/api/auth/login', {
    data: { email: 'admin', password: 'admin123' }
  });
  const body = await res.json();
  await ctx.close();
  return body?.data?.token || '';
}

async function shot(browser, token, url, name) {
  const page = await browser.newPage();
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('http://localhost:18080/login', { waitUntil: 'domcontentloaded' });
  await page.evaluate((tok) => {
    localStorage.setItem('token', tok);
    localStorage.setItem('user', JSON.stringify({ username:'admin', email:'admin', role:'admin', tenant_id:'default' }));
    localStorage.setItem('auth_expires_at', String(Date.now() + 7200000));
    localStorage.setItem('xsiam-theme', 'dark');
  }, token);
  await page.goto('http://localhost:18080' + url, { waitUntil: 'networkidle' });
  await page.waitForTimeout(1200);
  await page.screenshot({ path: `screenshots/i18n_${name}.png` });
  await page.close();
  console.log(`  ${name} done`);
}

(async () => {
  const browser = await chromium.launch({ headless: true });
  const token = await getToken(browser);
  if (!token) { console.log('no token'); await browser.close(); return; }

  await shot(browser, token, '/actions', 'actions');
  await shot(browser, token, '/playbooks', 'playbooks');
  await shot(browser, token, '/threat-intel', 'threat_intel');
  await shot(browser, token, '/vulnerabilities', 'vulns');
  await shot(browser, token, '/reports', 'reports');

  await browser.close();
  console.log('Done');
})();
