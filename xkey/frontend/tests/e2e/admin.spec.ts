import { test, expect } from '@playwright/test';
import {
  navigateTo,
  waitForAppReady,
  ensureSidebarExpanded,
  isWailsMode,
  waitForLoadingComplete,
} from './helpers';
import * as fs from 'fs';

test.describe('Admin View (Backend Administration)', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
    await navigateTo(page, 'admin');
  });

  test('page loads with correct heading and subtitle', async ({ page }) => {
    await expect(page.locator('h1', { hasText: 'Backend Administration' })).toBeVisible();
    await expect(
      page.locator('.header-subtitle', { hasText: 'Configure cryptographic backends' }),
    ).toBeVisible();
  });

  test('"Configured Backends" section heading is present', async ({ page }) => {
    await expect(
      page.getByRole('heading', { name: 'Configured Backends' }),
    ).toBeVisible();
  });

  test('Refresh button is visible in the section toolbar', async ({ page }) => {
    await expect(page.getByRole('button', { name: 'Refresh' })).toBeVisible();
  });

  test('"Add Backend" button is visible in the section toolbar', async ({ page }) => {
    await expect(page.getByRole('button', { name: 'Add Backend' })).toBeVisible();
  });

  test('empty state shows "No Backends Configured" with help text', async ({ page }) => {
    await waitForLoadingComplete(page);

    const emptyTitle = page.getByText('No Backends Configured');
    const isVisible = await emptyTitle.isVisible().catch(() => false);
    if (isVisible) {
      await expect(emptyTitle).toBeVisible();
      await expect(
        page.getByText('Click "Add Backend" to configure a cryptographic backend.'),
      ).toBeVisible();
    }
  });

  test('clicking "Add Backend" opens the Add Backend dialog', async ({ page }) => {
    await page.getByRole('button', { name: 'Add Backend' }).click();
    await page.waitForTimeout(300);

    await expect(page.getByRole('dialog').getByRole('heading', { name: 'Add Backend' })).toBeVisible();
  });

  test('Add Backend dialog shows "Backend Types Unavailable" in browser-only mode', async ({ page }) => {
    const wails = await isWailsMode(page);
    if (wails) {
      // In Wails mode the backend type list loads from the service — skip this assertion.
      return;
    }

    await page.getByRole('button', { name: 'Add Backend' }).click();
    await page.waitForTimeout(300);

    // Without Wails, backendTypesLoaded stays false so the unavailable state renders.
    await expect(page.getByText('Backend Types Unavailable')).toBeVisible();
    await expect(
      page.getByText('The backend service is not available. Please ensure xKey is running.'),
    ).toBeVisible();
  });

  test('Cancel button in the Add Backend dialog closes the dialog', async ({ page }) => {
    await page.getByRole('button', { name: 'Add Backend' }).click();
    await page.waitForTimeout(300);

    // The modal backdrop should now be present.
    await expect(page.locator('.modal-backdrop')).toBeVisible();

    await page.getByRole('button', { name: 'Cancel' }).click();
    await page.waitForTimeout(300);

    // The modal backdrop should be gone after Cancel.
    await expect(page.locator('.modal-backdrop')).not.toBeVisible();
  });
});

// --- PKCS#11 YubiKey SO PIN gating (source) ----------------------------------
// These static-source assertions verify the Admin view enforces the YubiKey
// management-key requirement on the generic PKCS#11 connect flow. They run
// without a live backend because the logic under test is purely in the
// Svelte template + validation code.

const ADMIN_PATH_YKC = '/home/jhahn/sources/go-xkms/xkey/frontend/src/views/Admin.svelte';

test.describe('PKCS#11 YubiKey SO PIN gating (source)', () => {
  test('reactive pkcs11IsYubiKey flag matches libykcs11 in library_path', () => {
    const content = fs.readFileSync(ADMIN_PATH_YKC, 'utf8');
    expect(content).toMatch(/\$: pkcs11IsYubiKey[\s\S]{0,400}libykcs11/);
  });

  test('SO PIN field is rendered with required marker when YubiKey is detected', () => {
    const content = fs.readFileSync(ADMIN_PATH_YKC, 'utf8');
    // The management-key input block must be gated by {#if pkcs11IsYubiKey}
    // and carry required/aria-required attributes so the browser surfaces
    // native validation.
    expect(content).toMatch(
      /\{#if pkcs11IsYubiKey\}[\s\S]{0,600}data-testid="pkcs11-yubi-mgmt-key"[\s\S]{0,200}required[\s\S]{0,200}aria-required="true"/,
    );
  });

  test('validation rejects empty SO PIN on YubiKey PKCS#11 connect flow', () => {
    const content = fs.readFileSync(ADMIN_PATH_YKC, 'utf8');
    // The case 'pkcs11': branch must return early with an error when
    // pkcs11IsYubiKey is true and pkcs11SoPin is empty.
    expect(content).toMatch(
      /if \(pkcs11IsYubiKey && !pkcs11SoPin\)[\s\S]{0,300}addNotification\('error'/,
    );
  });

  test('SO PIN is auto-prefilled with the YubiKey factory management key', () => {
    const content = fs.readFileSync(ADMIN_PATH_YKC, 'utf8');
    // When pkcs11IsYubiKey is true and pkcs11SoPin is empty, the reactive
    // block must seed the field with the factory default so the user only
    // has to override it when they have changed the management key.
    expect(content).toMatch(
      /\$: if \(pkcs11IsYubiKey && !pkcs11SoPin\)[\s\S]{0,200}YUBIKEY_DEFAULT_MGMT_KEY/,
    );
    expect(content).toMatch(
      /YUBIKEY_DEFAULT_MGMT_KEY\s*=\s*'010203040506070801020304050607080102030405060708'/,
    );
  });
});
