const { chromium } = require("@playwright/test");
(async () => {
  const browser = await chromium.launch({ headless: true });
  const ctx = await browser.newContext({ viewport: { width: 1440, height: 900 } });
  const page = await ctx.newPage();
  await page.goto("http://localhost:18080/login");
  await page.waitForLoadState("networkidle");
  await page.locator("input").first().fill("admin");
  await page.locator("input[type=password]").fill("admin123");
  try { await page.locator("input[type=checkbox]").first().check(); } catch(e) {}
  await Promise.all([
    page.waitForURL(u => !u.toString().includes("/login"), { timeout: 15000 }),
    page.locator("button[type=submit]").click()
  ]);
  await page.waitForTimeout(2500);
  const pages = [
    ["/","dashboard"],["/alerts","alerts"],["/incidents","incidents"],
    ["/assets","assets"],["/threat-intel","threat-intel"],["/query","query"],
    ["/settings","settings"],["/detection-rules","detection-rules"],
    ["/playbooks","playbooks"],["/login","login"]
  ];
  for (const [route, name] of pages) {
    await page.goto("http://localhost:18080" + route);
    await page.waitForTimeout(2000);
    await page.screenshot({ path: "D:/src/xsiam/_shot_" + name + ".png" });
    console.log("shot: " + name);
  }
  await browser.close();
})().catch(e => { console.error(e.message); process.exit(1); });
