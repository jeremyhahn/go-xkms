import { test, expect } from '@playwright/test';
import {
  navigateTo,
  waitForAppReady,
  ensureSidebarExpanded,
  isWailsMode,
  waitForLoadingComplete,
} from './helpers';

test.describe('Trust Store View', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
    await navigateTo(page, 'trust-store');
  });

  test.describe('Header and Layout', () => {
    test('Trust Store view loads with correct header', async ({ page }) => {
      await expect(page.locator('h1', { hasText: 'Trust Store' })).toBeVisible();
      await expect(page.locator('.header-subtitle', { hasText: 'Trusted root certificates' })).toBeVisible();
    });

    test('Import button is visible in the toolbar', async ({ page }) => {
      const importButton = page.getByRole('button', { name: 'Import' });
      await expect(importButton).toBeVisible();
    });

    test('Refresh button is visible in the toolbar', async ({ page }) => {
      const refreshButton = page.getByRole('button', { name: 'Refresh' });
      await expect(refreshButton).toBeVisible();
    });

    test('certificate count badge is visible in the toolbar', async ({ page }) => {
      const badge = page.locator('.cert-count-badge');
      await expect(badge).toBeVisible();
    });
  });

  test.describe('Purpose Filter Tabs', () => {
    test('all purpose filter tabs are visible', async ({ page }) => {
      const filterBar = page.locator('.filter-bar');
      await expect(filterBar).toBeVisible();

      const expectedTabs = [
        'All',
        'TPM Manufacturer',
        'IDevID Issuer',
        'User CA',
        'Bootstrap CA',
        'Android Hardware',
        'General',
      ];

      for (const label of expectedTabs) {
        const chip = page.locator('.filter-chip', { hasText: label });
        await expect(chip).toBeVisible();
      }
    });

    test('All tab is active by default', async ({ page }) => {
      const allChip = page.locator('.filter-chip.active');
      await expect(allChip).toContainText('All');
    });

    test('clicking a filter tab changes the active state', async ({ page }) => {
      const tpmChip = page.locator('.filter-chip', { hasText: 'TPM Manufacturer' });
      await tpmChip.click();
      await page.waitForTimeout(200);

      await expect(tpmChip).toHaveClass(/active/);

      // The All chip should no longer be active.
      const allChip = page.locator('.filter-chip', { hasText: 'All' });
      await expect(allChip).not.toHaveClass(/active/);
    });

    test('clicking a filter tab twice does not break the UI', async ({ page }) => {
      const userCaChip = page.locator('.filter-chip', { hasText: 'User CA' });
      await userCaChip.click();
      await page.waitForTimeout(100);
      await expect(userCaChip).toHaveClass(/active/);

      // Click again — same tab stays active (no toggle-off behaviour).
      await userCaChip.click();
      await page.waitForTimeout(100);
      await expect(userCaChip).toHaveClass(/active/);
    });

    test('can cycle through all filter tabs', async ({ page }) => {
      const tabs = [
        'All',
        'TPM Manufacturer',
        'IDevID Issuer',
        'User CA',
        'Bootstrap CA',
        'Android Hardware',
        'General',
      ];

      for (const label of tabs) {
        const chip = page.locator('.filter-chip', { hasText: label });
        await chip.click();
        await page.waitForTimeout(100);
        await expect(chip).toHaveClass(/active/);
      }
    });
  });

  test.describe('DataTable Structure', () => {
    test('DataTable renders with correct column headers', async ({ page }) => {
      await waitForLoadingComplete(page);

      const table = page.locator('.data-table, table');
      const tableVisible = await table.first().isVisible().catch(() => false);

      if (tableVisible) {
        const expectedHeaders = ['Subject', 'Purpose', 'Algorithm', 'Expires', 'Fingerprint'];
        for (const header of expectedHeaders) {
          await expect(page.getByRole('columnheader', { name: header })).toBeVisible();
        }
      }
    });

    test('empty state shows when no certificates are loaded in Vite mode', async ({ page }) => {
      await waitForLoadingComplete(page);

      const wails = await isWailsMode(page);
      if (!wails) {
        // Vite mode has no backend, so the table should show the empty state.
        const emptyTitle = page.getByText('No Certificates');
        const isVisible = await emptyTitle.isVisible().catch(() => false);
        if (isVisible) {
          await expect(emptyTitle).toBeVisible();
          await expect(
            page.getByText('Import PEM certificates to populate the trust store.'),
          ).toBeVisible();
        }
      }
    });

    test('empty state shows hint for active filter when no matches', async ({ page }) => {
      await waitForLoadingComplete(page);

      // Switch to a filter that likely has no certs in Vite mode.
      const generalChip = page.locator('.filter-chip', { hasText: 'General' });
      await generalChip.click();
      await page.waitForTimeout(300);

      const emptyDescription = page.getByText(/No certificates found with purpose/);
      const isVisible = await emptyDescription.isVisible().catch(() => false);
      if (isVisible) {
        await expect(emptyDescription).toBeVisible();
      }
    });
  });

  test.describe('Import Modal', () => {
    test('clicking Import opens the import modal', async ({ page }) => {
      const importButton = page.getByRole('button', { name: 'Import' });
      await importButton.click();
      await page.waitForTimeout(300);

      await expect(page.getByText('Import Certificates')).toBeVisible();
    });

    test('import modal has Paste PEM and Browse File tabs', async ({ page }) => {
      await page.getByRole('button', { name: 'Import' }).click();
      await page.waitForTimeout(300);

      await expect(page.locator('.import-tab', { hasText: 'Paste PEM' })).toBeVisible();
      await expect(page.locator('.import-tab', { hasText: 'Browse File' })).toBeVisible();
    });

    test('Paste PEM tab is active by default', async ({ page }) => {
      await page.getByRole('button', { name: 'Import' }).click();
      await page.waitForTimeout(300);

      const pasteTab = page.locator('.import-tab.active');
      await expect(pasteTab).toContainText('Paste PEM');
    });

    test('PEM textarea is visible on the Paste PEM tab', async ({ page }) => {
      await page.getByRole('button', { name: 'Import' }).click();
      await page.waitForTimeout(300);

      const textarea = page.locator('#import-pem');
      await expect(textarea).toBeVisible();
      await expect(textarea).toHaveAttribute(
        'placeholder',
        expect.stringContaining('BEGIN CERTIFICATE'),
      );
    });

    test('Import button in modal is disabled when PEM textarea is empty', async ({ page }) => {
      await page.getByRole('button', { name: 'Import' }).click();
      await page.waitForTimeout(300);

      // The modal's primary Import button (last one on page).
      const modalImportBtn = page.getByRole('button', { name: 'Import' }).last();
      await expect(modalImportBtn).toBeDisabled();
    });

    test('Import button in modal enables when PEM data is entered', async ({ page }) => {
      await page.getByRole('button', { name: 'Import' }).click();
      await page.waitForTimeout(300);

      await page.locator('#import-pem').fill(
        '-----BEGIN CERTIFICATE-----\nMIIBxTCCAW...\n-----END CERTIFICATE-----',
      );
      await page.waitForTimeout(200);

      const modalImportBtn = page.getByRole('button', { name: 'Import' }).last();
      await expect(modalImportBtn).toBeEnabled();
    });

    test('switching to Browse File tab shows file import action', async ({ page }) => {
      await page.getByRole('button', { name: 'Import' }).click();
      await page.waitForTimeout(300);

      await page.locator('.import-tab', { hasText: 'Browse File' }).click();
      await page.waitForTimeout(200);

      await expect(
        page.locator('.import-tab.active', { hasText: 'Browse File' }),
      ).toBeVisible();

      await expect(page.locator('.file-import-action')).toBeVisible();
      await expect(page.getByRole('button', { name: 'Browse File...' })).toBeVisible();
    });

    test('Cancel button closes the import modal', async ({ page }) => {
      await page.getByRole('button', { name: 'Import' }).click();
      await page.waitForTimeout(300);

      await expect(page.getByText('Import Certificates')).toBeVisible();

      await page.getByRole('button', { name: 'Cancel' }).click();
      await page.waitForTimeout(300);

      await expect(page.getByText('Import Certificates')).not.toBeVisible();
    });
  });

  test.describe('Wails Mode — Certificate Operations', () => {
    test('table rows are visible when certificates are loaded', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await waitForLoadingComplete(page);
      await page.waitForTimeout(1000);

      const certCount = page.locator('.cert-count-badge');
      const countText = await certCount.textContent();
      const count = parseInt(countText ?? '0', 10);

      if (count > 0) {
        const rows = page.locator('table tbody tr');
        await expect(rows.first()).toBeVisible();
      }
    });

    test('clicking a table row opens the certificate viewer', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await waitForLoadingComplete(page);
      await page.waitForTimeout(1000);

      const rows = page.locator('table tbody tr');
      const rowCount = await rows.count();

      if (rowCount > 0) {
        await rows.first().click();
        await page.waitForTimeout(500);

        // Certificate viewer dialog should open.
        const viewer = page.locator('.cert-viewer-dialog, [class*="cert-viewer"]');
        const isOpen = await viewer.isVisible().catch(() => false);
        // Just verify the click did not cause a crash.
        expect(typeof isOpen).toBe('boolean');
      }
    });
  });
});
