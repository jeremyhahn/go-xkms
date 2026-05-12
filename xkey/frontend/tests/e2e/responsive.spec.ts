import { test, expect } from '@playwright/test';
import { waitForAppReady } from './helpers';

test.describe('Responsive layout', () => {
  test('sidebar collapses to icon-only width at 800px viewport', async ({ page }) => {
    await page.setViewportSize({ width: 800, height: 600 });
    await page.goto('/');
    await waitForAppReady(page);

    const sidebar = page.locator('nav.sidebar');
    const box = await sidebar.boundingBox();
    expect(box).not.toBeNull();
    // Sidebar must be in icon-only mode (≤ 64px) — not the full 240px
    expect(box!.width).toBeLessThanOrEqual(64);
  });

  test('main content panel stays within viewport at 800px', async ({ page }) => {
    await page.setViewportSize({ width: 800, height: 600 });
    await page.goto('/');
    await waitForAppReady(page);

    const viewport = page.viewportSize()!;
    const content = page.locator('.main-content');
    const box = await content.boundingBox();
    expect(box).not.toBeNull();
    // Right edge of content must not overflow the viewport
    expect(box!.x + box!.width).toBeLessThanOrEqual(viewport.width);
  });

  test('settings view content stays within viewport at 800px', async ({ page }) => {
    await page.setViewportSize({ width: 800, height: 600 });
    await page.goto('/');
    await waitForAppReady(page);

    // Navigate to settings via the sidebar footer button
    const settingsBtn = page.locator('nav.sidebar button.nav-item', {
      has: page.locator('span.nav-label:text-is("Settings")'),
    });
    // In collapsed/icon mode the label is hidden but the button is still present
    await settingsBtn.click();
    await page.waitForTimeout(300);

    const viewport = page.viewportSize()!;
    const viewContainer = page.locator('.view-container');
    await expect(viewContainer).toBeVisible();

    const box = await viewContainer.boundingBox();
    expect(box).not.toBeNull();
    // Content panel must not overflow the viewport
    expect(box!.x + box!.width).toBeLessThanOrEqual(viewport.width);
  });
});
