import { test, expect, type Page } from '@playwright/test';

// =============================================================================
// API schema alignment regression tests
//
// These tests guard against type drift between the TypeScript client types in
// shared/src/api/types.ts and the actual JSON returned by the Go REST API.
//
// Each test loads a view that fetches from a real live backend and asserts
// that key fields actually populate in the DOM. An empty or missing field
// indicates that the TS field name does not match the JSON key the Go handler
// returns, which is exactly the class of bug these tests catch.
//
// The webServer started by playwright.config.ts (start-server.sh) boots
// trusted-acme-client with a preseeded config containing the test-ca account
// and web-demo certificate, so all endpoints return real non-empty data.
// =============================================================================

async function loadSPA(page: Page): Promise<void> {
  await page.goto('/ui/client/', { waitUntil: 'domcontentloaded', timeout: 15000 });
  await page.locator('aside').first().waitFor({ state: 'visible', timeout: 10000 });
}

async function navigateTo(page: Page, navLabel: string): Promise<void> {
  await page.getByRole('navigation').getByText(navLabel, { exact: true }).click();
  await page.waitForTimeout(300);
}

// ---------------------------------------------------------------------------
// Dashboard — GET /api/v1/config → directoryURL field populates "Server" row
// ---------------------------------------------------------------------------

test('Dashboard renders non-empty Server URL in the Account card', async ({ page }) => {
  await loadSPA(page);
  // Dashboard is the default view — we are already there.
  // Wait for the loading spinner to disappear.
  await page.locator('[data-testid="loading-spinner"], .animate-spin').waitFor({ state: 'hidden', timeout: 10000 }).catch(() => {
    // Spinner may never appear if data loads fast; continue.
  });
  // Allow async fetch to complete.
  await page.waitForTimeout(1500);

  // Find the "Server" label and read the sibling value paragraph.
  const serverLabel = page.getByText('Server', { exact: true }).first();
  await serverLabel.waitFor({ state: 'visible', timeout: 8000 });

  // The value paragraph immediately follows the label in the same div.
  const serverValue = serverLabel.locator('~ p').first();
  const text = (await serverValue.textContent())?.trim() ?? '';

  // The preseeded config has directoryURL = "https://localhost:8443/acme/directory".
  // Any non-empty URL indicates the field name matched.
  expect(text.length).toBeGreaterThan(0);
  expect(text).not.toBe('undefined');
  expect(text).not.toBe('null');
});

// ---------------------------------------------------------------------------
// Configuration — GET /api/v1/config → directoryURL populates the URL input
// ---------------------------------------------------------------------------

test('Configuration view ACME Server URL input has a non-empty value after load', async ({ page }) => {
  await loadSPA(page);
  await navigateTo(page, 'Configuration');
  await page.waitForTimeout(1500);

  const serverInput = page.locator('#server-url');
  await serverInput.waitFor({ state: 'visible', timeout: 8000 });

  const value = await serverInput.inputValue();
  expect(value.length).toBeGreaterThan(0);
  expect(value).not.toBe('undefined');
});

// ---------------------------------------------------------------------------
// Auto-Renewal — GET /api/v1/renewal/config → checkInterval populates input
// ---------------------------------------------------------------------------

test('Auto-Renewal view Check Interval input has a non-empty value after load', async ({ page }) => {
  await loadSPA(page);
  await navigateTo(page, 'Auto-Renewal');
  await page.waitForTimeout(1500);

  const checkIntervalInput = page.locator('#check-interval');
  await checkIntervalInput.waitFor({ state: 'visible', timeout: 8000 });

  const value = await checkIntervalInput.inputValue();
  expect(value.length).toBeGreaterThan(0);
  expect(value).not.toBe('0');
  expect(value).not.toBe('undefined');
});

// ---------------------------------------------------------------------------
// No parse-failure toasts — field name drift produces "Failed to parse response
// body" toasts via the shared ApiClient's error handling path.
// ---------------------------------------------------------------------------

test('No "Failed to parse response body" toasts appear when loading Dashboard', async ({ page }) => {
  await loadSPA(page);
  await page.waitForTimeout(2000);

  const failToast = page
    .locator('[role="alert"]')
    .filter({ hasText: /failed to parse response body/i });

  // Either none exist or they are not visible.
  const count = await failToast.count();
  expect(count).toBe(0);
});

test('No "Failed to parse response body" toasts appear when loading Configuration', async ({ page }) => {
  await loadSPA(page);
  await navigateTo(page, 'Configuration');
  await page.waitForTimeout(2000);

  const failToast = page
    .locator('[role="alert"]')
    .filter({ hasText: /failed to parse response body/i });

  const count = await failToast.count();
  expect(count).toBe(0);
});

test('No "Failed to parse response body" toasts appear when loading Auto-Renewal', async ({ page }) => {
  await loadSPA(page);
  await navigateTo(page, 'Auto-Renewal');
  await page.waitForTimeout(2000);

  const failToast = page
    .locator('[role="alert"]')
    .filter({ hasText: /failed to parse response body/i });

  const count = await failToast.count();
  expect(count).toBe(0);
});
