const { chromium } = require("playwright");
(async () => {
  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  await page.goto("http://localhost:18080/login");
  await page.waitForLoadState("networkidle");
  await page.locator("input").first().fill("admin");
  await page.locator("input[type=password]").fill("admin123");
  await Promise.all([
    page.waitForURL(u => !u.toString().includes("/login"), { timeout: 15000 }),
    page.locator("button[type=submit]").click()
  ]);
  await page.waitForTimeout(2000);
  // Click the logo/toggle button to expand sidebar
  await page.locator("nav button").first().click();
  await page.waitForTimeout(500);
  await page.screenshot({ path: "D:/src/xsiam/_shot_sidebar_open.png" });
  console.log("shot: sidebar_open");
  await browser.close();
})().catch(e => { console.error(e.message); process.exit(1); });
