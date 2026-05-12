import { test, expect } from '@playwright/test';
import {
  navigateTo,
  waitForAppReady,
  ensureSidebarExpanded,
} from './helpers';

test.describe('Pairing View', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
    await navigateTo(page, 'pairing');
  });

  test('page loads with correct heading and subtitle', async ({ page }) => {
    await expect(page.locator('h1', { hasText: 'Pairing' })).toBeVisible();
    await expect(
      page.locator('.header-subtitle', {
        hasText: 'Manage paired devices, extensions, and remote agents',
      }),
    ).toBeVisible();
  });

  test('shows "0 paired" count badge in empty state', async ({ page }) => {
    const badge = page.locator('.device-count');
    await expect(badge).toBeVisible();
    await expect(badge).toContainText('0 paired');
  });

  test('shows "No Paired Devices" empty state with help text', async ({ page }) => {
    await expect(page.getByText('No Paired Devices')).toBeVisible();
    await expect(
      page.getByText(
        'Pair a BLE phone, browser extension, or remote xKey agent to get started.',
      ),
    ).toBeVisible();
  });

  test('search input is present with correct placeholder', async ({ page }) => {
    const searchInput = page.locator('input[placeholder="Search paired devices..."]');
    await expect(searchInput).toBeVisible();
  });

  test('clicking "+ Pair" button opens "Pair New Device" dialog', async ({ page }) => {
    await page.getByRole('button', { name: 'Pair', exact: true }).click();
    await page.waitForTimeout(300);

    await expect(page.getByText('Pair New Device')).toBeVisible();
  });

  test('"Pair New Device" dialog shows BLE Device option', async ({ page }) => {
    await page.getByRole('button', { name: 'Pair', exact: true }).click();
    await page.waitForTimeout(300);

    await expect(page.getByText('BLE Device', { exact: true })).toBeVisible();
  });

  test('"Pair New Device" dialog shows Remote xKey Agent option', async ({ page }) => {
    await page.getByRole('button', { name: 'Pair', exact: true }).click();
    await page.waitForTimeout(300);

    await expect(page.getByText('Remote xKey Agent', { exact: true })).toBeVisible();
  });

  test('Cancel button in Pair dialog closes the dialog', async ({ page }) => {
    await page.getByRole('button', { name: 'Pair', exact: true }).click();
    await page.waitForTimeout(300);

    await expect(page.getByText('Pair New Device')).toBeVisible();

    await page.getByRole('button', { name: 'Cancel' }).click();
    await page.waitForTimeout(300);

    await expect(page.getByText('Pair New Device')).not.toBeVisible();
  });

  test('context menu closes on Escape in empty state (no paired devices)', async ({ page }) => {
    // In standalone mode there are no paired device rows, so .context-menu
    // elements cannot be opened. We verify that pressing Escape with no open
    // menu produces no errors and the empty state remains stable.
    //
    // If a backend were available and rows existed, the test would open a
    // context menu via the .kebab-btn, assert .context-menu visibility, press
    // Escape, and assert .context-menu is gone. That path is exercised in live
    // integration tests (xkey/frontend/tests/e2e/live/).
    await expect(page.getByText('No Paired Devices')).toBeVisible();

    // Fire Escape — closeMenu() is called; nothing should throw.
    await page.keyboard.press('Escape');
    await page.waitForTimeout(100);

    // Empty state is still present; no context-menu leaked into the DOM.
    await expect(page.getByText('No Paired Devices')).toBeVisible();
    await expect(page.locator('.context-menu')).toHaveCount(0);
  });
});
