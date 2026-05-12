import { test, expect } from '@playwright/test';
import {
  navigateTo,
  waitForAppReady,
  ensureSidebarExpanded,
  navigateToSettingsCategory,
} from './helpers';

/**
 * Settings → Browser retains only global / app-wide browser preferences.
 * Per-browser configuration, launch, and extension manifest management
 * have moved to Applications → Browser (see secure-browser.spec.ts).
 */

test.describe('Settings → Browser (global prefs)', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
    await navigateTo(page, 'settings');
  });

  test('Browser category is visible in settings nav', async ({ page }) => {
    const browserNav = page
      .locator('.settings-nav')
      .getByRole('button', { name: 'Browser' });
    await expect(browserNav).toBeVisible();
  });

  test('Browser settings panel loads when selected', async ({ page }) => {
    await navigateToSettingsCategory(page, 'Browser');
    await expect(
      page.locator('[data-testid="browser-settings-panel"]'),
    ).toBeVisible();
  });

  test('default browser dropdown is visible', async ({ page }) => {
    await navigateToSettingsCategory(page, 'Browser');
    await expect(page.locator('[data-testid="browser-select"]')).toBeVisible();
  });

  test('custom command input is visible', async ({ page }) => {
    await navigateToSettingsCategory(page, 'Browser');
    await expect(
      page.locator('[data-testid="custom-command-input"]'),
    ).toBeVisible();
  });

  test('system browser is always in the dropdown', async ({ page }) => {
    await navigateToSettingsCategory(page, 'Browser');
    const select = page.locator('[data-testid="browser-select"]');
    const options = await select.locator('option').allTextContents();
    expect(options).toContain('System Default');
  });

  test('custom command shows placeholder with url syntax', async ({ page }) => {
    await navigateToSettingsCategory(page, 'Browser');
    const input = page.locator('[data-testid="custom-command-input"]');
    const placeholder = await input.getAttribute('placeholder');
    expect(placeholder).toContain('{url}');
  });

  test('default browser defaults to system', async ({ page }) => {
    await navigateToSettingsCategory(page, 'Browser');
    const select = page.locator('[data-testid="browser-select"]');
    await expect(select).toHaveValue('system');
  });

  test('test browser button is visible', async ({ page }) => {
    await navigateToSettingsCategory(page, 'Browser');
    const testBtn = page.getByRole('button', { name: 'Test Browser' });
    await expect(testBtn).toBeVisible();
  });

  test('browser section heading is visible', async ({ page }) => {
    await navigateToSettingsCategory(page, 'Browser');
    await expect(
      page
        .locator('[data-testid="browser-settings-panel"]')
        .getByText('Default browser'),
    ).toBeVisible();
  });

  test('CA trust bundle toggle is visible', async ({ page }) => {
    await navigateToSettingsCategory(page, 'Browser');
    await expect(
      page.locator('[data-testid="trust-bundle-toggle"]'),
    ).toBeVisible();
  });

  /**
   * Regression guards: these UI elements moved to the Browser view
   * (Applications → Browser). They must no longer appear in Settings.
   */

  test('Secure Browser Launch card does not appear in Settings', async ({
    page,
  }) => {
    await navigateToSettingsCategory(page, 'Browser');
    await expect(
      page.locator('[data-testid="secure-browser-card"]'),
    ).toHaveCount(0);
    await expect(
      page.locator('[data-testid="secure-browser-launch-btn"]'),
    ).toHaveCount(0);
  });

  test('per-family profile mode selectors do not appear in Settings', async ({
    page,
  }) => {
    await navigateToSettingsCategory(page, 'Browser');
    await expect(
      page.locator('[data-testid="chrome-profile-mode"]'),
    ).toHaveCount(0);
    await expect(
      page.locator('[data-testid="firefox-profile-mode"]'),
    ).toHaveCount(0);
  });

  test('native messaging manifest install UI does not appear in Settings', async ({
    page,
  }) => {
    await navigateToSettingsCategory(page, 'Browser');
    await expect(page.getByRole('button', { name: 'Install All' })).toHaveCount(0);
    await expect(
      page.getByText('Native messaging', { exact: false }),
    ).toHaveCount(0);
  });
});
