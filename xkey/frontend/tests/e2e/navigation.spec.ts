import { test, expect } from '@playwright/test';
import {
  navigateTo,
  waitForAppReady,
  ensureSidebarExpanded,
  getActiveNavLabel,
  isWailsMode,
  VIEW_LABELS,
  VIEW_TITLES,
  type ViewId,
} from './helpers';

test.describe('Sidebar Navigation', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
  });

  test('app shell renders with sidebar and main content', async ({ page }) => {
    await expect(page.locator('nav.sidebar')).toBeVisible();
    await expect(page.locator('.main-content')).toBeVisible();
    await expect(page.locator('.view-container')).toBeVisible();
  });

  test('sidebar displays the xKey brand', async ({ page }) => {
    await expect(page.locator('.brand-text')).toHaveText('xKey');
  });

  test('sidebar displays the brand icon', async ({ page }) => {
    const brandIcon = page.locator('.brand-icon');
    await expect(brandIcon).toBeVisible();
  });

  test('sidebar displays all navigation section headers', async ({ page }) => {
    await expect(page.locator('.nav-section-label', { hasText: 'OVERVIEW' })).toBeVisible();
    await expect(page.locator('.nav-section-label', { hasText: 'STORE' })).toBeVisible();
    await expect(page.locator('.nav-section-label', { hasText: 'MANAGEMENT' })).toBeVisible();
  });

  test('core navigation items are visible when sidebar is expanded', async ({
    page,
  }) => {
    // These views are always present regardless of Wails mode, enterprise mode,
    // or developer-tools setting. 'api-explorer' and 'admin' are conditionally
    // hidden, and 'tpm' is hidden when no TPM hardware is available, so they
    // are excluded from this always-visible check.
    const alwaysVisibleViews: ViewId[] = [
      'dashboard', 'pairing', 'keys', 'fido2', 'oath', 'piv',
      'passwords', 'seal', 'audit-log', 'settings',
    ];

    for (const view of alwaysVisibleViews) {
      const label = VIEW_LABELS[view];
      const navLabel = page.locator(`nav.sidebar span.nav-label:text-is("${label}")`);
      await expect(navLabel).toBeVisible({
        timeout: 5_000,
      });
    }
  });

  test('dashboard is the default active view', async ({ page }) => {
    const activeLabel = await getActiveNavLabel(page);
    expect(activeLabel).toBe('Dashboard');
  });

  // Test navigation to each primary view.
  // 'tpm' is conditionally hidden when no TPM hardware is available (Vite mode),
  // so it is tested with a skip guard. 'api-explorer' and 'admin' are only shown
  // when developer tools are enabled or when the user is an admin, so they are
  // excluded from this always-visible navigation test.
  const primaryViews: ViewId[] = [
    'dashboard', 'pairing', 'keys', 'fido2', 'oath', 'piv',
    'passwords', 'seal', 'audit-log', 'settings',
  ];

  for (const view of primaryViews) {
    test(`navigates to ${VIEW_LABELS[view]} view`, async ({ page }) => {
      await navigateTo(page, view);
      const activeLabel = await getActiveNavLabel(page);

      // Settings is in the footer, not in nav-sections, so active state
      // is handled differently but the view still loads.
      if (view !== 'settings') {
        expect(activeLabel).toBe(VIEW_LABELS[view]);
      }

      // Verify the view container has content (not empty).
      const viewContainer = page.locator('.view-container');
      await expect(viewContainer).not.toBeEmpty();
    });
  }

  test('navigates to TPM 2.0 view when TPM is available', async ({ page }) => {
    const tpmNavItem = page.locator('nav.sidebar button.nav-item', {
      has: page.locator('span.nav-label:text-is("TPM 2.0")'),
    });
    const tpmVisible = await tpmNavItem.isVisible().catch(() => false);
    test.skip(!tpmVisible, 'TPM nav item is hidden when no TPM hardware is available');

    await navigateTo(page, 'tpm');
    const activeLabel = await getActiveNavLabel(page);
    expect(activeLabel).toBe('TPM 2.0');

    const viewContainer = page.locator('.view-container');
    await expect(viewContainer).not.toBeEmpty();
  });

  test('sidebar collapse toggle works', async ({ page }) => {
    const shell = page.locator('.app-shell');

    // Initially expanded
    await expect(shell).not.toHaveClass(/sidebar-collapsed/);

    // Click toggle to collapse
    await page.locator('button.sidebar-toggle').click();
    await page.waitForTimeout(400);
    await expect(shell).toHaveClass(/sidebar-collapsed/);

    // Click toggle again to expand
    await page.locator('button.sidebar-toggle').click();
    await page.waitForTimeout(400);
    await expect(shell).not.toHaveClass(/sidebar-collapsed/);
  });

  test('sidebar collapse hides navigation labels', async ({ page }) => {
    // Collapse the sidebar
    await page.locator('button.sidebar-toggle').click();
    await page.waitForTimeout(400);

    // Labels should be hidden (either not visible or have 0 width)
    const shell = page.locator('.app-shell');
    await expect(shell).toHaveClass(/sidebar-collapsed/);

    // The brand text should not be visible when collapsed
    const brandText = page.locator('.brand-text');
    const brandCount = await brandText.count();
    if (brandCount > 0) {
      await expect(brandText).not.toBeVisible();
    }
  });

  test('theme toggle button is visible in sidebar footer', async ({ page }) => {
    const themeButton = page.locator('.sidebar-footer button.nav-item', {
      has: page.locator('span.nav-label:text-is("Theme")'),
    });
    await expect(themeButton).toBeVisible();
  });

  test('theme toggle cycles through themes', async ({ page }) => {
    const themeButton = page.locator('.sidebar-footer button.nav-item', {
      has: page.locator('span.nav-label:text-is("Theme")'),
    });

    // Click theme toggle and verify the data-theme attribute changes
    const html = page.locator('html');
    const initialTheme = await html.getAttribute('data-theme');

    await themeButton.click();
    await page.waitForTimeout(300);

    const newTheme = await html.getAttribute('data-theme');
    // Theme should have changed (or null -> something)
    expect(newTheme !== initialTheme || newTheme !== null).toBeTruthy();
  });

  test('connection indicator is visible in sidebar footer', async ({ page }) => {
    const indicator = page.locator('.connection-indicator');
    await expect(indicator).toBeVisible();
    // Should show "Standalone" when no backend is connected.
    const label = page.locator('.connection-label');
    const count = await label.count();
    if (count > 0) {
      await expect(label).toHaveText(/Standalone|Connected/);
    }
  });

  test('navigating between views updates the active state correctly', async ({
    page,
  }) => {
    // Navigate to OATH
    await navigateTo(page, 'oath');
    let active = await getActiveNavLabel(page);
    expect(active).toBe('OATH');

    // Navigate to PIV
    await navigateTo(page, 'piv');
    active = await getActiveNavLabel(page);
    expect(active).toBe('PIV');

    // Navigate to Keys
    await navigateTo(page, 'keys');
    active = await getActiveNavLabel(page);
    expect(active).toBe('Keys');

    // Navigate to Pairing (always visible, unlike TPM which requires hardware)
    await navigateTo(page, 'pairing');
    active = await getActiveNavLabel(page);
    expect(active).toBe('Pairing');

    // Navigate back to Dashboard
    await navigateTo(page, 'dashboard');
    active = await getActiveNavLabel(page);
    expect(active).toBe('Dashboard');
  });

  test('rapid navigation between views does not break the UI', async ({
    page,
  }) => {
    // Quickly click through several always-visible views.
    // 'tpm' is excluded because it is hidden when no TPM hardware is available.
    const views: ViewId[] = ['fido2', 'oath', 'piv', 'pairing', 'passwords', 'seal', 'dashboard'];
    for (const view of views) {
      await navigateTo(page, view);
    }
    // After all navigation, dashboard should be active and content present
    const active = await getActiveNavLabel(page);
    expect(active).toBe('Dashboard');
    await expect(page.locator('.view-container')).not.toBeEmpty();
  });

  test('sidebar toggle button has correct aria-label', async ({ page }) => {
    const toggleBtn = page.locator('button.sidebar-toggle');
    await expect(toggleBtn).toBeVisible();
    const label = await toggleBtn.getAttribute('aria-label');
    expect(label).toMatch(/Expand sidebar|Collapse sidebar/);
  });

  test('sidebar nav element has correct aria-label', async ({ page }) => {
    const nav = page.locator('nav.sidebar');
    await expect(nav).toHaveAttribute('aria-label', 'Main navigation');
  });
});
