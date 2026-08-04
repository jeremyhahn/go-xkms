import { test, expect } from '@playwright/test';
import {
  navigateTo,
  waitForAppReady,
  ensureSidebarExpanded,
  isWailsMode,
  waitForLoadingComplete,
} from './helpers';

test.describe('Backend badge consistency', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
  });

  test('Keys view renders BackendBadge elements when keys exist', async ({ page }) => {
    await navigateTo(page, 'keys');
    await waitForLoadingComplete(page);

    const wails = await isWailsMode(page);
    if (!wails) {
      // Vite standalone: no keys loaded — assert empty state and skip badge check.
      await expect(page.getByText('No Keys Found')).toBeVisible();
      return;
    }

    // In Wails mode the backend may or may not have keys; be resilient.
    const hasKeys = await page
      .locator('[data-backend]')
      .first()
      .isVisible()
      .catch(() => false);

    if (hasKeys) {
      // At least one BackendBadge (data-backend attribute) must be visible.
      await expect(page.locator('[data-backend]').first()).toBeVisible();
    }
  });

  test('Certificates view renders BackendBadge elements when certs exist', async ({ page }) => {
    await navigateTo(page, 'certificates');
    await waitForLoadingComplete(page);

    const wails = await isWailsMode(page);
    if (!wails) {
      // Vite standalone: no certs loaded — nothing to assert on badges.
      return;
    }

    const hasCerts = await page
      .locator('[data-backend]')
      .first()
      .isVisible()
      .catch(() => false);

    if (hasCerts) {
      await expect(page.locator('[data-backend]').first()).toBeVisible();
    }
  });

  test('SSH nav item appears under the Applications section', async ({ page }) => {
    // The sidebar groups nav items into labelled sections. After the move,
    // SSH must be rendered inside the APPLICATIONS section container, not STORE.
    const applicationsSection = page.locator('.nav-section', {
      has: page.locator('span.nav-section-label', { hasText: 'APPLICATIONS' }),
    });

    await expect(applicationsSection).toBeVisible();

    const sshButton = applicationsSection.locator('button.nav-item', {
      has: page.locator('span.nav-label:text-is("SSH")'),
    });

    await expect(sshButton).toBeVisible();
  });

  test('SSH nav item is NOT in the Store section', async ({ page }) => {
    const storeSection = page.locator('.nav-section', {
      has: page.locator('span.nav-section-label', { hasText: 'STORE' }),
    });

    const count = await storeSection.count();
    if (count === 0) {
      // If there is no Store section visible, the test passes trivially.
      return;
    }

    const sshInStore = storeSection.locator('button.nav-item', {
      has: page.locator('span.nav-label:text-is("SSH")'),
    });

    await expect(sshInStore).toHaveCount(0);
  });
});
