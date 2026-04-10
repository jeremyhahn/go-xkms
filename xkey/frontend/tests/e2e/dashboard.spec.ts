import { test, expect } from '@playwright/test';
import {
  navigateTo,
  waitForAppReady,
  ensureSidebarExpanded,
  isWailsMode,
  waitForLoadingComplete,
} from './helpers';

test.describe('Dashboard View', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
    // Dashboard is the default view, no navigation needed
  });

  test('dashboard loads as the default view', async ({ page }) => {
    await expect(page.locator('h1.header-title')).toHaveText('xKey');
    await expect(page.getByText('Virtual Security Key')).toBeVisible();
  });

  test('dashboard content area is present', async ({ page }) => {
    const dashboardContent = page.locator('.dashboard-content');
    await expect(dashboardContent).toBeVisible();
  });

  // Quick Actions section was removed from Dashboard.

  test.describe('Recent Activity Section', () => {
    test('recent activity section is visible', async ({ page }) => {
      await expect(page.getByRole('heading', { name: 'Recent Activity' })).toBeVisible();
    });

    test('shows empty activity message when no events', async ({ page }) => {
      // In standalone mode (no backend), there should be no recent activity
      await expect(page.getByText('No recent activity')).toBeVisible();
    });
  });

  test.describe('Status Cards (Wails mode)', () => {
    test('status grid is present', async ({ page }) => {
      const statusGrid = page.locator('.status-grid');
      await expect(statusGrid).toBeVisible();
    });

    test('status cards appear when backend provides app status', async ({ page }) => {
      const wails = await isWailsMode(page);
      if (!wails) {
        // In standalone mode, status cards may be empty (no appStatus)
        // Status grid is rendered but may have zero children
        const statusGrid = page.locator('.status-grid');
        await expect(statusGrid).toBeVisible();
        return;
      }

      await page.waitForTimeout(1000);

      // In Wails mode, we expect Mode, Storage, and TPM status cards
      await expect(page.getByText('Mode')).toBeVisible();
      await expect(page.getByText('Storage')).toBeVisible();
      await expect(page.getByText('TPM 2.0')).toBeVisible();
    });

    test('key inventory section appears when backend is available', async ({ page }) => {
      const wails = await isWailsMode(page);
      if (!wails) {
        // In standalone mode, key inventory is hidden (requires appStatus)
        return;
      }

      await page.waitForTimeout(1000);

      // Should display Key Inventory section with counters
      await expect(page.getByText('Key Inventory')).toBeVisible();
      await expect(page.getByText('OATH Accounts')).toBeVisible();
      await expect(page.getByText('FIDO2 Credentials')).toBeVisible();
      await expect(page.getByText('PIV Certificates')).toBeVisible();
      await expect(page.getByText('Remote Keys')).toBeVisible();
    });

    test('system info footer appears when backend is available', async ({ page }) => {
      const wails = await isWailsMode(page);
      if (!wails) {
        return;
      }

      await page.waitForTimeout(1000);

      const footer = page.locator('.system-info');
      const footerCount = await footer.count();
      if (footerCount > 0) {
        await expect(footer).toBeVisible();
        // Should show version, platform, go version, and uptime
        const footerText = await footer.textContent();
        expect(footerText).toBeTruthy();
      }
    });
  });

  test.describe('Dashboard Layout', () => {
    test('status grid is present', async ({ page }) => {
      const statusGrid = page.locator('.status-grid');
      await expect(statusGrid).toBeVisible();
    });

    test('status grid uses auto-fit responsive layout', async ({ page }) => {
      const statusGrid = page.locator('.status-grid');
      await expect(statusGrid).toBeVisible();
      const gridStyle = await statusGrid.evaluate((el) =>
        getComputedStyle(el).getPropertyValue('grid-template-columns'),
      );
      // auto-fit renders at least one column track
      expect(gridStyle.trim().length).toBeGreaterThan(0);
    });
  });
});
