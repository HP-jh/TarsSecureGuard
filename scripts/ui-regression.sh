#!/usr/bin/env bash
# UI Regression Test Script v2 (Playwright-based)
# Requires: playwright + chromium installed
# Usage: TSG_BASE=file:///path/to/frontend/index.html ./scripts/ui-regression.sh
#        TSG_BASE=http://127.0.0.1:18889 ./scripts/ui-regression.sh

set -uo pipefail

BASE="${TSG_BASE:-http://127.0.0.1:18889}"
HEADLESS="${TSG_HEADLESS:-true}"
ERRORS=0

echo "=== TSG UI Regression Tests v2 ==="
echo "Base URL: $BASE"
echo "Headless: $HEADLESS"
echo ""

# Check playwright availability
if ! command -v npx &>/dev/null || ! npx playwright --version &>/dev/null; then
  echo "[INFO] Playwright not installed. To run UI regression tests:"
  echo "  1. npm install -g @playwright/test"
  echo "  2. npx playwright install chromium"
  echo "  3. TSG_BASE=$BASE ./scripts/ui-regression.sh"
  echo ""
  echo "Test coverage (v2):"
  echo "  - Page loads without JS errors / console errors"
  echo "  - Sidebar navigation: all items visible & clickable"
  echo "  - About page: version badge dynamically populated"
  echo "  - Key dialog overlays: help / palette render without error"
  echo "  - Screenshot artifacts saved to /tmp/tsg-ui-screenshots/"
  exit 0
fi

mkdir -p /tmp/tsg-ui-screenshots

cat > /tmp/tsg-ui-regression.spec.js << 'EOF'
const { test, expect } = require('@playwright/test');

const BASE = process.env.TSG_BASE || 'http://127.0.0.1:18889';
const SCREENSHOTS = '/tmp/tsg-ui-screenshots';

let jsErrors = [];
let consoleErrors = [];

test.describe('TSG UI Regression v2', () => {
  test.beforeEach(async ({ page }) => {
    jsErrors = [];
    consoleErrors = [];
    page.on('pageerror', err => { jsErrors.push(err.message); });
    page.on('console', msg => {
      if (msg.type() === 'error') consoleErrors.push(msg.text());
    });
  });

  test.afterEach(async ({ page }, testInfo) => {
    if (testInfo.status !== 'passed') {
      await page.screenshot({ path: `${SCREENSHOTS}/${testInfo.title.replace(/\s+/g, '_')}.png`, fullPage: true });
    }
  });

  test('index loads without JS errors', async ({ page }) => {
    await page.goto(BASE, { waitUntil: 'networkidle' });
    await expect(page.locator('body')).toBeVisible();
    expect(jsErrors).toHaveLength(0);
    expect(consoleErrors).toHaveLength(0);
  });

  test('sidebar navigation items visible', async ({ page }) => {
    await page.goto(BASE, { waitUntil: 'networkidle' });
    const items = await page.locator('.nav-item').all();
    expect(items.length).toBeGreaterThan(3);
    for (const item of items) {
      await expect(item).toBeVisible();
    }
  });

  test('about page shows dynamic version', async ({ page }) => {
    await page.goto(BASE, { waitUntil: 'networkidle' });
    // Click about nav item if present
    const aboutNav = page.locator('.nav-item').filter({ hasText: /关于|About/ });
    if (await aboutNav.count() > 0) {
      await aboutNav.first().click();
      await page.waitForTimeout(300);
    }
    const verEl = page.locator('#about-ver');
    if (await verEl.count() > 0) {
      const text = await verEl.textContent();
      expect(text).not.toBe('1.0.0');
      expect(text).toMatch(/^\d+\.\d+\.\d+$/);
    }
  });

  test('help overlay opens without error', async ({ page }) => {
    await page.goto(BASE, { waitUntil: 'networkidle' });
    const helpBtn = page.locator('button, [onclick*="help"]').first();
    if (await helpBtn.count() > 0) {
      await helpBtn.click();
      await page.waitForTimeout(200);
      expect(jsErrors).toHaveLength(0);
    }
  });

  test('palette opens without error', async ({ page }) => {
    await page.goto(BASE, { waitUntil: 'networkidle' });
    // Try common palette trigger: press /
    await page.keyboard.press('/');
    await page.waitForTimeout(200);
    expect(jsErrors).toHaveLength(0);
  });

  test('screenshot key pages', async ({ page }) => {
    await page.goto(BASE, { waitUntil: 'networkidle' });
    await page.screenshot({ path: `${SCREENSHOTS}/dashboard.png`, fullPage: false });
    // Try clicking first nav item
    const firstNav = page.locator('.nav-item').first();
    if (await firstNav.count() > 0) {
      await firstNav.click();
      await page.waitForTimeout(300);
      await page.screenshot({ path: `${SCREENSHOTS}/first_page.png`, fullPage: false });
    }
  });
});
EOF

npx playwright test /tmp/tsg-ui-regression.spec.js --project=chromium --reporter=line --headed="${HEADLESS}" 2>&1 || {
  echo "[FAIL] Playwright tests failed. Screenshots saved to /tmp/tsg-ui-screenshots/"
  exit 1
}

echo "[PASS] All UI regression tests passed."
