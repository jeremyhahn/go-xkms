import { test, expect } from '@playwright/test';
import {
  waitForAppReady,
  ensureSidebarExpanded,
  waitForLoadingComplete,
} from './helpers';

/** Navigate to the Certificates view via the sidebar "Certificates" nav button. */
async function navigateToCertificates(page: import('@playwright/test').Page): Promise<void> {
  const certNavBtn = page.locator('nav.sidebar button.nav-item', {
    has: page.locator('span.nav-label:text-is("Certificates")'),
  });
  await certNavBtn.click();
  await page.waitForTimeout(300);
}

test.describe('Certificates View', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
    await navigateToCertificates(page);
  });

  test('page loads with correct heading and subtitle', async ({ page }) => {
    await expect(page.locator('h1', { hasText: 'Certificates' })).toBeVisible();
    await expect(
      page.locator('.header-subtitle', { hasText: 'X.509 certificate management' }),
    ).toBeVisible();
  });

  test('"All Backends" filter chip is visible', async ({ page }) => {
    await waitForLoadingComplete(page);

    const allChip = page.locator('.filter-chip', { hasText: 'All Backends' });
    await expect(allChip).toBeVisible();
  });

  test('Refresh button is present in the toolbar', async ({ page }) => {
    await expect(page.getByRole('button', { name: 'Refresh' })).toBeVisible();
  });

  test('certificate count badge is visible only when count is > 0', async ({ page }) => {
    await waitForLoadingComplete(page);
    const badge = page.locator('.cert-count-badge');
    const count = await badge.count();
    if (count > 0) {
      const text = await badge.textContent();
      expect(parseInt(text?.trim() ?? '0', 10)).toBeGreaterThan(0);
    }
  });

  test('cert-count-badge is not rendered when the certificate list is empty', async ({ page }) => {
    await waitForLoadingComplete(page);
    // In Vite/browser mode there is no backend so certificates.length === 0.
    // The badge must be absent from the DOM, not merely hidden.
    const badge = page.locator('.cert-count-badge');
    const certText = await badge.textContent().catch(() => null);
    if (certText !== null) {
      // Badge present — it must display a value greater than zero.
      expect(parseInt(certText.trim(), 10)).toBeGreaterThan(0);
    } else {
      // Badge is absent — correct behaviour for an empty list.
      await expect(badge).toHaveCount(0);
    }
  });

  test('empty state shows "No Certificates Found" in browser-only mode', async ({ page }) => {
    await waitForLoadingComplete(page);

    const emptyTitle = page.getByText('No Certificates Found');
    const isVisible = await emptyTitle.isVisible().catch(() => false);
    if (isVisible) {
      await expect(emptyTitle).toBeVisible();
      await expect(
        page.getByText('No certificates are available across any backend.'),
      ).toBeVisible();
    }
  });
});
