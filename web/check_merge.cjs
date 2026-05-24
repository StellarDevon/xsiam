const { chromium } = require('playwright');
async function getToken(b) {
  const ctx = await b.newContext();
  const p = await ctx.newPage();
  const res = await p.request.post('http://localhost:18080/api/auth/login', { data: { email:'admin', password:'admin123' } });
  const body = await res.json();
  await ctx.close();
  return body?.data?.token || '';
}
async function shot(b, tok, url, name) {
  const page = await b.newPage();
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('http://localhost:18080/login', { waitUntil: 'domcontentloaded' });
  await page.evaluate(t => {
    localStorage.setItem('token', t);
    localStorage.setItem('user', JSON.stringify({ username:'admin', email:'admin', role:'admin', tenant_id:'default' }));
    localStorage.setItem('auth_expires_at', String(Date.now() + 7200000));
    localStorage.setItem('xsiam-theme', 'dark');
  }, tok);
  await page.goto('http://localhost:18080' + url, { waitUntil: 'networkidle' });
  await page.waitForTimeout(1500);
  await page.screenshot({ path: `screenshots/merge_${name}.png` });
  await page.close();
  console.log(`  ${name} done`);
}
(async () => {
  const b = await chromium.launch({ headless: true });
  const tok = await getToken(b);
  await shot(b, tok, '/threat-intel', 'threat_intel_tabs');
  // Click the IOC管理 tab
  const page2 = await b.newPage();
  await page2.setViewportSize({ width: 1440, height: 900 });
  await page2.goto('http://localhost:18080/login', { waitUntil: 'domcontentloaded' });
  await page2.evaluate(t => {
    localStorage.setItem('token', t);
    localStorage.setItem('user', JSON.stringify({ username:'admin', email:'admin', role:'admin', tenant_id:'default' }));
    localStorage.setItem('auth_expires_at', String(Date.now() + 7200000));
    localStorage.setItem('xsiam-theme', 'dark');
  }, tok);
  await page2.goto('http://localhost:18080/threat-intel', { waitUntil: 'networkidle' });
  await page2.waitForTimeout(1000);
  // Click IOC管理 tab
  await page2.getByText('IOC 管理').first().click();
  await page2.waitForTimeout(1500);
  await page2.screenshot({ path: 'screenshots/merge_ioc_tab.png' });
  await page2.close();
  console.log('  ioc_tab done');
  await b.close();
  console.log('Done');
})();
