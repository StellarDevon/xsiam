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

async function shotHeader(browser, token, url, name) {
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

  // Find the first data-table thead and screenshot just that row + a couple data rows
  const tableBox = await page.evaluate(() => {
    const th = document.querySelector('.data-table th');
    if (!th) return null;
    const thead = th.closest('thead');
    if (!thead) return null;
    const rect = thead.getBoundingClientRect();
    return { x: rect.x, y: rect.y, width: rect.width, height: rect.height + 80 };
  });

  if (tableBox) {
    await page.screenshot({
      path: `screenshots/header_${name}.png`,
      clip: {
        x: Math.max(0, tableBox.x - 10),
        y: Math.max(0, tableBox.y - 4),
        width: Math.min(1440, tableBox.width + 20),
        height: tableBox.height + 10,
      }
    });
    console.log(`  ${name}: thead at y=${tableBox.y.toFixed(0)}`);
  } else {
    console.log(`  ${name}: no data-table found`);
  }
  await page.close();
}

(async () => {
  const browser = await chromium.launch({ headless: true });
  const token = await getToken(browser);
  if (!token) { console.log('no token'); await browser.close(); return; }

  await shotHeader(browser, token, '/alerts',    'alerts');
  await shotHeader(browser, token, '/incidents', 'incidents');
  await shotHeader(browser, token, '/vulnerabilities', 'vulns');
  await shotHeader(browser, token, '/devices',   'devices');
  await shotHeader(browser, token, '/actions',   'actions');

  await browser.close();
  console.log('Done');
})();
