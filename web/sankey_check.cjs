const { chromium } = require('playwright');

async function getToken(browser) {
  const ctx = await browser.newContext();
  const page = await ctx.newPage();
  const res = await page.request.post('http://localhost:18080/api/auth/login', {
    data: { email: 'admin', password: 'admin123' }
  });
  const body = await res.json();
  const token = body?.data?.token || body?.token || '';
  await ctx.close();
  console.log('token:', token ? 'OK (' + token.slice(0, 20) + '...)' : 'NONE');
  return token;
}

async function takeDashboard(browser, token, theme, prefix) {
  const page = await browser.newPage();
  await page.setViewportSize({ width: 1440, height: 900 });

  // Step 1: go to login page so we're on origin
  await page.goto('http://localhost:18080/login', { waitUntil: 'domcontentloaded' });

  // Step 2: inject auth into localStorage
  await page.evaluate(([tok, th]) => {
    const user = { username: 'admin', email: 'admin', role: 'admin', tenant_id: 'default' };
    localStorage.setItem('token', tok);
    localStorage.setItem('user', JSON.stringify(user));
    localStorage.setItem('auth_expires_at', String(Date.now() + 7200000));
    localStorage.setItem('xsiam-theme', th);
  }, [token, theme]);

  // Step 3: navigate to dashboard
  await page.goto('http://localhost:18080/', { waitUntil: 'networkidle' });
  await page.waitForTimeout(2000);

  const url = page.url();
  const htmlClass = await page.evaluate(() => document.documentElement.className);
  console.log(`[${theme}] url=${url}, html.class="${htmlClass}"`);

  await page.screenshot({ path: `screenshots/${prefix}_full.png` });
  await page.screenshot({ path: `screenshots/${prefix}_sankey.png`, clip: { x: 170, y: 0, width: 1270, height: 440 } });

  await page.close();
}

(async () => {
  const browser = await chromium.launch({ headless: true });
  const token = await getToken(browser);
  if (!token) { await browser.close(); return; }

  await takeDashboard(browser, token, 'dark', 'dark');
  await takeDashboard(browser, token, 'light', 'light');

  await browser.close();
  console.log('Done');
})();
