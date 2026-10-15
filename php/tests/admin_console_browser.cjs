// admin_console_test.php (j): the admin page in a real browser. Signs in
// through the form, runs Flush stale sessions and signs out, then prints one
// JSON line: what each POST carried as its Origin and what it got back. The
// password comes in on stdin.
// Usage: node admin_console_browser.cjs <playwright dir> <base url> <username>
'use strict';
const fs = require('fs');
const path = require('path');

const [, , playwrightDir, base, username] = process.argv;
const { chromium } = require(path.join(playwrightDir, 'node_modules', 'playwright'));
const password = fs.readFileSync(0, 'utf8').trim();

/** Clicks, and returns the status and the Origin header of the POST to `suffix` the click sent. */
async function post(page, suffix, click) {
  const [response] = await Promise.all([
    page.waitForResponse((r) => r.request().method() === 'POST' && new URL(r.url()).pathname.endsWith(suffix)),
    click(),
  ]);
  const headers = await response.request().allHeaders();
  return { status: response.status(), origin: headers.origin ?? null };
}

(async () => {
  const seen = { signIn: null, console: false, action: null, signOut: null, signedOut: false, cookieLeft: null, error: null };
  const browser = await chromium.launch();
  try {
    const page = await browser.newPage();
    page.setDefaultTimeout(10000);
    await page.goto(base + '/admin');
    await page.fill('input[name=username]', username);
    await page.fill('input[name=password]', password);
    seen.signIn = await post(page, '/admin/login', () => page.click('form button[type=submit]'));
    if (seen.signIn.status === 303) {
      await page.waitForSelector('#flush');
      seen.console = true;
      seen.action = await post(page, '/admin/maintenance', () => page.click('#flush'));
      await page.waitForFunction(() => /HTTP \d+/.test(document.getElementById('result-title').textContent));
      seen.signOut = await post(page, '/admin/logout', () => page.click('form[action$="/logout"] button'));
      await page.waitForSelector('input[name=password]');
      seen.signedOut = true;
      seen.cookieLeft = (await page.context().cookies()).length > 0;
    }
  } catch (error) {
    seen.error = String((error && error.message) || error).split('\n')[0];
  } finally {
    await browser.close();
  }
  console.log(JSON.stringify(seen));
})();
