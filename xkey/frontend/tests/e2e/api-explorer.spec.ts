import { test, expect } from '@playwright/test';
import { navigateTo, waitForAppReady, ensureSidebarExpanded } from './helpers';

test.describe('API Explorer', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
    await navigateTo(page, 'api-explorer');
  });

  test('API Explorer view loads', async ({ page }) => {
    await expect(page.locator('[data-testid="api-explorer-view"]')).toBeVisible();
  });

  test('method selector shows default GET', async ({ page }) => {
    const methodSelect = page.locator('[data-testid="method-select"]');
    await expect(methodSelect).toBeVisible();
    await expect(methodSelect).toHaveValue('GET');
  });

  test('URL input is visible and empty', async ({ page }) => {
    const urlInput = page.locator('[data-testid="url-input"]');
    await expect(urlInput).toBeVisible();
    await expect(urlInput).toHaveValue('');
  });

  test('send button is visible', async ({ page }) => {
    await expect(page.locator('[data-testid="send-button"]')).toBeVisible();
  });

  test('body input hidden for GET requests', async ({ page }) => {
    await expect(page.locator('[data-testid="request-body-input"]')).not.toBeVisible();
  });

  test('body input shown for POST requests', async ({ page }) => {
    await page.locator('[data-testid="method-select"]').selectOption('POST');
    await expect(page.locator('[data-testid="request-body-input"]')).toBeVisible();
  });

  test('body input shown for PUT requests', async ({ page }) => {
    await page.locator('[data-testid="method-select"]').selectOption('PUT');
    await expect(page.locator('[data-testid="request-body-input"]')).toBeVisible();
  });

  test('body input shown for PATCH requests', async ({ page }) => {
    await page.locator('[data-testid="method-select"]').selectOption('PATCH');
    await expect(page.locator('[data-testid="request-body-input"]')).toBeVisible();
  });

  test('body input hidden for DELETE requests', async ({ page }) => {
    await page.locator('[data-testid="method-select"]').selectOption('DELETE');
    await expect(page.locator('[data-testid="request-body-input"]')).not.toBeVisible();
  });

  test('body input hidden for HEAD requests', async ({ page }) => {
    await page.locator('[data-testid="method-select"]').selectOption('HEAD');
    await expect(page.locator('[data-testid="request-body-input"]')).not.toBeVisible();
  });

  test('history list is visible', async ({ page }) => {
    await expect(page.locator('[data-testid="history-list"]')).toBeVisible();
  });

  test('clear history button exists', async ({ page }) => {
    await expect(page.locator('[data-testid="clear-history-button"]')).toBeVisible();
  });

  test('can add custom headers', async ({ page }) => {
    await page.locator('[data-testid="add-header-button"]').click();
    const headerRow = page.locator('[data-testid^="header-row-"]').first();
    await expect(headerRow).toBeVisible();
  });

  test('can add multiple headers', async ({ page }) => {
    await page.locator('[data-testid="add-header-button"]').click();
    await page.locator('[data-testid="add-header-button"]').click();
    const headerRows = page.locator('[data-testid^="header-row-"]');
    await expect(headerRows).toHaveCount(2);
  });

  test('all HTTP methods available in dropdown', async ({ page }) => {
    const select = page.locator('[data-testid="method-select"]');
    const options = await select.locator('option').allTextContents();
    expect(options).toContain('GET');
    expect(options).toContain('POST');
    expect(options).toContain('PUT');
    expect(options).toContain('DELETE');
    expect(options).toContain('PATCH');
    expect(options).toContain('HEAD');
    expect(options).toContain('OPTIONS');
  });

  test('response panel shows placeholder before request', async ({ page }) => {
    const responseBody = page.locator('[data-testid="response-body"]');
    await expect(responseBody).toBeVisible();
    // Should show placeholder text when no request has been sent
    await expect(responseBody).toContainText('Send a request');
  });

  test('URL input accepts text input', async ({ page }) => {
    const urlInput = page.locator('[data-testid="url-input"]');
    await urlInput.fill('https://httpbin.org/get');
    await expect(urlInput).toHaveValue('https://httpbin.org/get');
  });

  test('header row has key and value inputs', async ({ page }) => {
    await page.locator('[data-testid="add-header-button"]').click();
    const headerRow = page.locator('[data-testid="header-row-0"]');
    const keyInput = headerRow.locator('input').first();
    const valueInput = headerRow.locator('input').nth(1);
    await expect(keyInput).toBeVisible();
    await expect(valueInput).toBeVisible();
    await keyInput.fill('Content-Type');
    await valueInput.fill('application/json');
    await expect(keyInput).toHaveValue('Content-Type');
    await expect(valueInput).toHaveValue('application/json');
  });

  test('history shows empty state initially', async ({ page }) => {
    const historyList = page.locator('[data-testid="history-list"]');
    await expect(historyList).toContainText('No requests yet');
  });
});
