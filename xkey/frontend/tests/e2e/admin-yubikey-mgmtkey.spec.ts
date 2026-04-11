import { test, expect } from '@playwright/test';
import { navigateTo, waitForAppReady, ensureSidebarExpanded, isWailsMode } from './helpers';
import * as fs from 'fs';

const ADMIN_PATH = '/home/jhahn/sources/go-xkms/xkey/frontend/src/views/Admin.svelte';
const DEFAULT_MGMT_KEY = '010203040506070801020304050607080102030405060708';

// ── Static source analysis tests ──────────────────────────────────────────────
// These verify the fix at the source level and run without a browser.

test.describe('YubiKey management key default (source)', () => {
  test('yukMgmtKey is initialised to the YubiKey factory default', () => {
    const content = fs.readFileSync(ADMIN_PATH, 'utf8');
    // Variable declaration must carry the factory default value.
    expect(content).toMatch(
      new RegExp(`let yukMgmtKey\\s*=\\s*'${DEFAULT_MGMT_KEY}'`),
    );
  });

  test('yukMgmtKey is reset to the factory default on backend type selection', () => {
    const content = fs.readFileSync(ADMIN_PATH, 'utf8');
    // selectBackendType() resets the field — must restore default, not empty string.
    const occurrences = [...content.matchAll(
      new RegExp(`yukMgmtKey\\s*=\\s*'${DEFAULT_MGMT_KEY}'`, 'g'),
    )];
    // Expect at least two: initial declaration + at least one reset call.
    expect(occurrences.length).toBeGreaterThanOrEqual(2);
  });

  test('management key input uses id="yuk-mgmt-key" bound to yukMgmtKey', () => {
    const content = fs.readFileSync(ADMIN_PATH, 'utf8');
    // The <input> element must have the id and bind the correct variable.
    expect(content).toMatch(/id="yuk-mgmt-key"/);
    expect(content).toMatch(/bind:value\{yukMgmtKey\}|bind:value={yukMgmtKey}/);
  });

  test('management key hint text mentions Pre-filled and factory default', () => {
    const content = fs.readFileSync(ADMIN_PATH, 'utf8');
    // The hint span that follows the management key input must guide the user.
    expect(content).toMatch(/Pre-filled[\s\S]{0,80}factory default/);
  });
});

// ── Static source analysis: PKCS#11 SO PIN forwarding ─────────────────────────

test.describe('PKCS#11 SO PIN forwarding (source)', () => {
  test('Connect call passes pkcs11SoPin, not an empty string', () => {
    const content = fs.readFileSync(ADMIN_PATH, 'utf8');
    // Find the Connect call for the generic PKCS#11 path.
    // It must forward pkcs11SoPin as the soPin argument.
    expect(content).toMatch(
      /PKCS11Service['"]\s*,\s*'Connect'[\s\S]{0,200}pkcs11SoPin/,
    );
  });

  test('pkcs11-so-pin input is bound to pkcs11SoPin', () => {
    const content = fs.readFileSync(ADMIN_PATH, 'utf8');
    expect(content).toMatch(/id="pkcs11-so-pin"/);
    expect(content).toMatch(/bind:value={pkcs11SoPin}/);
  });

  test('SO PIN confirmation field is present and bound', () => {
    const content = fs.readFileSync(ADMIN_PATH, 'utf8');
    expect(content).toMatch(/id="pkcs11-so-pin-confirm"/);
    expect(content).toMatch(/bind:value={pkcs11SoPinConfirm}/);
  });

  test('SO PIN fields are inside the initialize-token conditional block', () => {
    const content = fs.readFileSync(ADMIN_PATH, 'utf8');
    // The SO PIN inputs must be guarded by pkcs11Initialize being truthy so
    // they only appear when the user opts into token initialisation.
    const initBlock = content.match(
      /pkcs11Initialize[\s\S]{0,2000}pkcs11-so-pin/,
    );
    expect(initBlock).not.toBeNull();
  });
});

// ── Browser tests (Wails mode only) ───────────────────────────────────────────
// The YubiKey backend-type card is only rendered when the Wails backend reports
// the 'yubikey' or 'pkcs11' compiled type. In Vite-only dev server mode the
// backend types list is empty and the dialog shows "Backend Types Unavailable".
// These tests are therefore skipped when running against the Vite dev server.

test.describe('Admin: YubiKey management key default (browser)', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
    await navigateTo(page, 'admin');
  });

  test('YubiKey management key input is pre-filled with factory default', async ({ page }) => {
    const wails = await isWailsMode(page).catch(() => false);
    test.skip(!wails, 'Requires Wails backend to populate backend-type cards');

    // Open the Add Backend dialog.
    await page.getByRole('button', { name: 'Add Backend' }).click();

    // The modal must appear.
    const modal = page.locator('[role="dialog"]');
    await expect(modal).toBeVisible();

    // Click the YubiKey backend type card.
    const yukCard = modal.locator('.backend-type-card', { hasText: 'YubiKey' });
    await expect(yukCard).toBeVisible({ timeout: 5_000 });
    await yukCard.click();

    // The management key input should now be visible and carry the default value.
    const mgmtKeyInput = page.locator('#yuk-mgmt-key');
    await expect(mgmtKeyInput).toBeVisible({ timeout: 5_000 });

    const value = await mgmtKeyInput.inputValue();
    // Must not be empty.
    expect(value.length).toBeGreaterThan(0);
    // Must be exactly 48 hex characters (24 bytes).
    expect(value).toMatch(/^[0-9a-fA-F]{48}$/);
    // Must equal the known YubiKey factory default.
    expect(value).toBe(DEFAULT_MGMT_KEY);
  });

  test('YubiKey management key hint describes the pre-filled factory default', async ({ page }) => {
    const wails = await isWailsMode(page).catch(() => false);
    test.skip(!wails, 'Requires Wails backend to populate backend-type cards');

    await page.getByRole('button', { name: 'Add Backend' }).click();

    const modal = page.locator('[role="dialog"]');
    await expect(modal).toBeVisible();

    const yukCard = modal.locator('.backend-type-card', { hasText: 'YubiKey' });
    await expect(yukCard).toBeVisible({ timeout: 5_000 });
    await yukCard.click();

    // The hint span adjacent to the management key input must explain the default.
    const hintText = await page
      .locator('.form-field', { has: page.locator('#yuk-mgmt-key') })
      .locator('.field-hint')
      .textContent({ timeout: 5_000 });

    expect(hintText).toMatch(/[Pp]re-filled|factory default/);
  });
});

test.describe('Admin: PKCS#11 SO PIN field accessibility (browser)', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
    await navigateTo(page, 'admin');
  });

  test('PKCS#11 SO PIN field appears and accepts input when initialize is checked', async ({ page }) => {
    const wails = await isWailsMode(page).catch(() => false);
    test.skip(!wails, 'Requires Wails backend to populate backend-type cards');

    // Open Add Backend dialog.
    await page.getByRole('button', { name: 'Add Backend' }).click();

    const modal = page.locator('[role="dialog"]');
    await expect(modal).toBeVisible();

    // Select PKCS#11 backend type.
    const pkcs11Card = modal.locator('.backend-type-card', { hasText: /PKCS.?11/i });
    await expect(pkcs11Card).toBeVisible({ timeout: 5_000 });
    await pkcs11Card.click();

    // Tick the "Initialize token" checkbox to reveal SO PIN fields.
    const initLabel = page.locator('.checkbox-label', { hasText: 'Initialize token' });
    await expect(initLabel).toBeVisible({ timeout: 5_000 });
    await initLabel.locator('input[type="checkbox"]').check();

    // SO PIN input must now be visible and accept a value.
    const soPinInput = page.locator('#pkcs11-so-pin');
    await expect(soPinInput).toBeVisible({ timeout: 5_000 });
    await soPinInput.fill('secureSOpin123');
    await expect(soPinInput).toHaveValue('secureSOpin123');

    // SO PIN confirm field must also be present.
    const soPinConfirm = page.locator('#pkcs11-so-pin-confirm');
    await expect(soPinConfirm).toBeVisible();
    await soPinConfirm.fill('secureSOpin123');
    await expect(soPinConfirm).toHaveValue('secureSOpin123');
  });
});
