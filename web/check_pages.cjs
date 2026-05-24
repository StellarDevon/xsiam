const { chromium } = require('playwright');

async function getToken(browser) {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  const res = await page.request.post('http://localhost:18080/api/auth/login', {
    data: { email: 'admin', password: 'admin123' }
  });
  const body = await res.json();
  await ctx.close();
  return body?.data?.token || body?.token || '';
}

async function screenshot(browser, token, theme, url, name) {
  const page = await browser.newPage();
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('http://localhost:18080/login', { waitUntil: 'domcontentloaded' });
  await page.evaluate(([tok, th]) => {
    localStorage.setItem('token', tok);
    localStorage.setItem('user', JSON.stringify({ username: 'admin', email: 'admin', role: 'admin', tenant_id: 'default' }));
    localStorage.setItem('auth_expires_at', String(Date.now() + 7200000));
    localStorage.setItem('xsiam-theme', th);
  }, [token, theme]);
  await page.goto('http://localhost:18080' + url, { waitUntil: 'networkidle' });
  await page.waitForTimeout(1500);
  await page.screenshot({ path: `screenshots/${name}_${theme}.png` });
  await page.close();
  console.log(`  ${name} (${theme}) done`);
}

(async () => {
  const browser = await chromium.launch({ headless: true });
  const token = await getToken(browser);
  if (!token) { console.log('No token'); await browser.close(); return; }

  const pages = [
    ['/', 'dashboard'],
    ['/alerts', 'alerts'],
    ['/incidents', 'incidents'],
  ];

  for (const [url, name] of pages) {
    console.log(`Capturing ${name}...`);
    await screenshot(browser, token, 'dark', url, name);
    await screenshot(browser, token, 'light', url, name);
  }

  await browser.close();
  console.log('All done');
})();
