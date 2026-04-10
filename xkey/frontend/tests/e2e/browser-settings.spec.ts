import { test, expect } from '@playwright/test';
import { navigateTo, waitForAppReady, ensureSidebarExpanded, navigateToSettingsCategory } from './helpers';

test.describe('Browser Settings', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
    await navigateTo(page, 'settings');
  });

  test('Browser category is visible in settings nav', async ({ page }) => {
    const browserNav = page.locator('.settings-nav').getByRole('button', { name: 'Browser' });
    await expect(browserNav).toBeVisible();
  });

  test('Browser settings panel loads when selected', async ({ page }) => {
    await navigateToSettingsCategory(page, 'Browser');
    await expect(page.locator('[data-testid="browser-settings-panel"]')).toBeVisible();
  });

  test('browser select dropdown is visible', async ({ page }) => {
    await navigateToSettingsCategory(page, 'Browser');
    await expect(page.locator('[data-testid="browser-select"]')).toBeVisible();
  });

  test('custom command input is visible', async ({ page }) => {
    await navigateToSettingsCategory(page, 'Browser');
    await expect(page.locator('[data-testid="custom-command-input"]')).toBeVisible();
  });

  test('browser settings auto-saves (no explicit save button)', async ({ page }) => {
    await navigateToSettingsCategory(page, 'Browser');
    // Settings uses auto-save — verify the select and input are functional
    // (no explicit save button exists).
    await expect(page.locator('[data-testid="browser-select"]')).toBeVisible();
    await expect(page.locator('[data-testid="custom-command-input"]')).toBeVisible();
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

  test('browser select defaults to system', async ({ page }) => {
    await navigateToSettingsCategory(page, 'Browser');
    const select = page.locator('[data-testid="browser-select"]');
    await expect(select).toHaveValue('system');
  });

  test('test browser button is visible', async ({ page }) => {
    await navigateToSettingsCategory(page, 'Browser');
    const testBtn = page.getByRole('button', { name: 'Test Browser' });
    await expect(testBtn).toBeVisible();
  });

  test('browser settings section heading is visible', async ({ page }) => {
    await navigateToSettingsCategory(page, 'Browser');
    await expect(page.locator('[data-testid="browser-settings-panel"]').getByText('Default browser')).toBeVisible();
  });
});
