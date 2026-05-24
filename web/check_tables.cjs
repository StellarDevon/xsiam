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

async function shot(browser, token, theme, url, name) {
  const page = await browser.newPage();
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('http://localhost:18080/login', { waitUntil: 'domcontentloaded' });
  await page.evaluate(([tok, th]) => {
    localStorage.setItem('token', tok);
    localStorage.setItem('user', JSON.stringify({ username:'admin', email:'admin', role:'admin', tenant_id:'default' }));
    localStorage.setItem('auth_expires_at', String(Date.now() + 7200000));
    localStorage.setItem('xsiam-theme', th);
  }, [token, theme]);
  await page.goto('http://localhost:18080' + url, { waitUntil: 'networkidle' });
  await page.waitForTimeout(1200);
  // Zoom into just the table header area
  await page.screenshot({ path: `screenshots/table_${name}_${theme}.png`, clip: { x: 170, y: 0, width: 1270, height: 420 } });
  await page.close();
  console.log(`  ${name} (${theme}) done`);
}

(async () => {
  const browser = await chromium.launch({ headless: true });
  const token = await getToken(browser);
  if (!token) { console.log('no token'); await browser.close(); return; }

  const pages = [
    ['/alerts',    'alerts'],
    ['/incidents', 'incidents'],
    ['/ioc',       'ioc'],
    ['/threat-intel', 'threat_intel'],
    ['/actions',   'actions'],
    ['/devices',   'devices'],
    ['/vulnerabilities', 'vulns'],
  ];

  for (const [url, name] of pages) {
    await shot(browser, token, 'dark',  url, name);
    await shot(browser, token, 'light', url, name);
  }

  await browser.close();
  console.log('Done');
})();
