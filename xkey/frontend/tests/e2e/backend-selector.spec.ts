import { test, expect } from '@playwright/test';
import {
  navigateTo,
  navigateToFIDO2,
  waitForAppReady,
  ensureSidebarExpanded,
  isWailsMode,
} from './helpers';

/**
 * Regression tests for BackendSelector component prop forwarding.
 *
 * Bug: BackendSelector did not declare a `data-testid` export prop, so
 * `<BackendSelector data-testid="..."/>` produced a Svelte warning and
 * silently dropped the attribute. Locators returned 0 elements without
 * any visible test failure.
 */
test.describe('BackendSelector data-testid forwarding', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
  });

  test('FIDO2 page exposes [data-testid="fido2-backend-selector"]', async ({
    page,
  }) => {
    await navigateToFIDO2(page);
    const selector = page.locator('[data-testid="fido2-backend-selector"]');
    expect(await selector.count()).toBe(1);
    await expect(selector).toBeVisible();
  });

  test('OATH page exposes [data-testid="oath-backend-selector"]', async ({
    page,
  }) => {
    await navigateTo(page, 'oath');
    const selector = page.locator('[data-testid="oath-backend-selector"]');
    expect(await selector.count()).toBe(1);
    await expect(selector).toBeVisible();
  });
});

/**
 * Regression tests for the Admin "Add Backend" dialog empty state.
 *
 * Bug: When Wails was unavailable, the dialog showed "All Backends
 * Configured" which is misleading. It should distinguish between
 * "backend types not loaded" and "all configured".
 */
test.describe('Admin Add Backend dialog empty state', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
  });

  test('In Vite mode, Add Backend dialog shows "Backend Types Unavailable"', async ({
    page,
  }) => {
    // In Wails mode the real backend returns available backend types, so the
    // "Backend Types Unavailable" empty state is never shown. This assertion
    // is Vite-only (no backend, window.go undefined, types list is empty).
    const wails = await isWailsMode(page).catch(() => false);
    test.skip(wails, 'Real Wails backend provides backend types — unavailable state is Vite-only');

    await navigateTo(page, 'admin');
    // Open the Add Backend dialog.
    const addBtn = page.getByRole('button', { name: /add backend/i }).first();
    await addBtn.click();

    const unavailable = page.locator(
      '[data-testid="add-backend-unavailable"]',
    );
    const allConfigured = page.locator(
      '[data-testid="add-backend-all-configured"]',
    );

    await expect(unavailable).toBeVisible();
    expect(await allConfigured.count()).toBe(0);
    await expect(unavailable).toContainText(/backend types unavailable/i);
  });
});
