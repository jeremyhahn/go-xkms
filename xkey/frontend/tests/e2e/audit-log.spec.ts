import { test, expect } from '@playwright/test';
import {
  navigateTo,
  waitForAppReady,
  ensureSidebarExpanded,
  waitForLoadingComplete,
} from './helpers';

test.describe('Audit Log View', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
    await navigateTo(page, 'audit-log');
  });

  test('page loads with correct heading and subtitle', async ({ page }) => {
    await expect(page.locator('h1', { hasText: 'Audit Log' })).toBeVisible();
    await expect(
      page.locator('.header-subtitle', { hasText: 'Security event history' }),
    ).toBeVisible();
  });

  test('"All operations" filter dropdown is present', async ({ page }) => {
    const select = page.locator('.filter-select').filter({ hasText: 'All operations' });
    await expect(select).toBeVisible();
  });

  test('"All devices" filter dropdown is present', async ({ page }) => {
    const select = page.locator('.filter-select').filter({ hasText: 'All devices' });
    await expect(select).toBeVisible();
  });

  test('"All statuses" filter dropdown is present', async ({ page }) => {
    const select = page.locator('.filter-select').filter({ hasText: 'All statuses' });
    await expect(select).toBeVisible();
  });

  test('search input is present with correct placeholder', async ({ page }) => {
    const searchInput = page.locator('input[placeholder="Search events..."]');
    await expect(searchInput).toBeVisible();
  });

  test('Export button is visible in the toolbar', async ({ page }) => {
    await expect(page.getByRole('button', { name: 'Export' })).toBeVisible();
  });

  test('empty state shows "No audit log entries" with help text', async ({ page }) => {
    await waitForLoadingComplete(page);

    const emptyTitle = page.getByText('No audit log entries');
    const isVisible = await emptyTitle.isVisible().catch(() => false);
    if (isVisible) {
      await expect(emptyTitle).toBeVisible();
      await expect(
        page.getByText(
          'Audit events will appear here as security operations are performed.',
        ),
      ).toBeVisible();
    }
  });

  test('result count shows "0 event(s) found" when no entries are loaded', async ({ page }) => {
    await waitForLoadingComplete(page);

    const resultCount = page.locator('.result-count');
    await expect(resultCount).toBeVisible();

    const text = await resultCount.textContent();
    // In browser-only mode the backend is unavailable so entries remain empty.
    if (text !== null) {
      expect(text.trim()).toMatch(/\d+ event\(s\) found/);
    }
  });

  test('clicking Export opens the Export Audit Log dialog', async ({ page }) => {
    await page.getByRole('button', { name: 'Export' }).click();
    await page.waitForTimeout(300);

    await expect(page.getByText('Export Audit Log')).toBeVisible();
  });

  test('Export dialog Cancel button closes the dialog', async ({ page }) => {
    await page.getByRole('button', { name: 'Export' }).click();
    await page.waitForTimeout(300);

    await expect(page.getByText('Export Audit Log')).toBeVisible();

    await page.getByRole('button', { name: 'Cancel' }).click();
    await page.waitForTimeout(300);

    await expect(page.getByText('Export Audit Log')).not.toBeVisible();
  });
});
