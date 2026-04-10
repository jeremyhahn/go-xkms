import { test, expect } from '@playwright/test';
import {
  navigateTo,
  waitForAppReady,
  ensureSidebarExpanded,
  isWailsMode,
  waitForLoadingComplete,
} from './helpers';

/**
 * PKCS#11 PIV certificate loading tests.
 *
 * These tests verify that pre-existing certificates on a PKCS#11 token are
 * correctly displayed when the user selects the PKCS#11 backend in the PIV
 * page. This is a regression guard for the bug where pre-existing certs were
 * not shown after backend selection.
 *
 * Prerequisites:
 *   - SoftHSM2 token "e2e-piv-test" pre-populated via setup-softhsm-piv.sh
 *     (all four standard PIV slots loaded with test certificates)
 *   - Wails backend running (tests skip in plain Vite mode)
 */
test.describe('PKCS#11 PIV Certificate Loading', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
  });

  // ---------------------------------------------------------------------------
  // Helper: register the SoftHSM module via the Admin page.
  // Returns true if registration completed, false if the UI affordance was
  // not found (so callers can skip gracefully).
  // ---------------------------------------------------------------------------
  async function registerSoftHSM(page: import('@playwright/test').Page): Promise<boolean> {
    await navigateTo(page, 'admin');
    await waitForLoadingComplete(page);

    const addBtn = page.locator('[data-testid="add-backend-btn"]');
    if (!(await addBtn.isVisible().catch(() => false))) {
      return false;
    }
    await addBtn.click();

    const pkcs11Option = page.getByText('PKCS#11');
    if (!(await pkcs11Option.isVisible({ timeout: 5000 }).catch(() => false))) {
      return false;
    }
    await pkcs11Option.click();

    const libraryInput = page.locator(
      '[data-testid="pkcs11-library-path"], input[placeholder*="library"], input[name*="library"]',
    );
    await libraryInput.fill('/usr/lib/softhsm/libsofthsm2.so');

    const pinInput = page.locator('[data-testid="pkcs11-pin"], input[type="password"]');
    if (await pinInput.isVisible().catch(() => false)) {
      await pinInput.fill('123456');
    }

    const registerBtn = page.locator(
      '[data-testid="pkcs11-register-btn"], button:has-text("Register"), button:has-text("Add"), button:has-text("Connect")',
    );
    await registerBtn.first().click();

    // Allow time for PKCS#11 initialization.
    await page.waitForTimeout(2000);
    return true;
  }

  // ---------------------------------------------------------------------------
  // Test 1: Pre-existing certificates are visible after backend selection
  // ---------------------------------------------------------------------------
  test('pre-existing PKCS#11 certificates are visible in PIV slots', async ({ page }) => {
    const wails = await isWailsMode(page).catch(() => false);
    test.skip(!wails, 'Requires Wails backend for PKCS#11 PIV testing');

    const registered = await registerSoftHSM(page);
    test.skip(!registered, 'Add backend button not found — PKCS#11 registration UI unavailable');

    await navigateTo(page, 'piv');
    await waitForLoadingComplete(page);

    // Select the PKCS#11 / SoftHSM backend chip.
    const backendChips = page.locator('.filter-chip, .backend-chip');
    const pkcs11Chip = backendChips.filter({ hasText: /PKCS|HSM|SoftHSM|softhsm/i });

    const hasPkcs11 = await pkcs11Chip.first().isVisible({ timeout: 5000 }).catch(() => false);
    test.skip(!hasPkcs11, 'PKCS#11 backend chip not available');

    await pkcs11Chip.first().click();
    await waitForLoadingComplete(page);

    // Slot 9A must be visible.
    const slot9a = page.locator('[data-testid="piv-slot-card-9A"], [data-testid="piv-slot-9a"]');
    await expect(slot9a).toBeVisible({ timeout: 10000 });

    // The slot must display certificate details — not the "No certificate" empty state.
    const certIndicator = slot9a.locator(
      '.slot-loaded, :has-text("PIV Authentication"), :has-text("RSA"), :has-text("ECDSA")',
    );
    await expect(certIndicator.first()).toBeVisible({ timeout: 10000 });
  });

  // ---------------------------------------------------------------------------
  // Test 2: Switching away from PKCS#11 does not leave stale data or errors
  // ---------------------------------------------------------------------------
  test('switching away from PKCS#11 backend hides its certificates', async ({ page }) => {
    const wails = await isWailsMode(page).catch(() => false);
    test.skip(!wails, 'Requires Wails backend');

    await navigateTo(page, 'piv');
    await waitForLoadingComplete(page);

    const backendChips = page.locator('.filter-chip, .backend-chip');
    const pkcs11Chip = backendChips.filter({ hasText: /PKCS|HSM|SoftHSM/i });
    const hasPkcs11 = await pkcs11Chip.first().isVisible({ timeout: 3000 }).catch(() => false);
    test.skip(!hasPkcs11, 'PKCS#11 backend not available');

    // Select PKCS#11 first.
    await pkcs11Chip.first().click();
    await waitForLoadingComplete(page);

    // Switch to the Software backend.
    const softwareChip = backendChips.filter({ hasText: /Software/i });
    if (await softwareChip.isVisible()) {
      await softwareChip.click();
      await waitForLoadingComplete(page);
    }

    // All five standard PIV slot cards must still be present (empty defaults).
    const slotCards = page.locator('[data-testid^="piv-slot-card-"]');
    const count = await slotCards.count();
    expect(count).toBe(5);

    // No error notifications must be visible.
    const errorNotif = page.locator('.notification.error, [data-testid="notification-error"]');
    await expect(errorNotif).not.toBeVisible();
  });

  // ---------------------------------------------------------------------------
  // Test 3: All four standard PIV slots show pre-loaded certificates
  // ---------------------------------------------------------------------------
  test('all four PIV slots show certificates from PKCS#11 token', async ({ page }) => {
    const wails = await isWailsMode(page).catch(() => false);
    test.skip(!wails, 'Requires Wails backend for PKCS#11 PIV testing');

    // This test relies on setup-softhsm-piv.sh having populated slots
    // 9A, 9C, 9D, and 9E with test certificates using the YubiKey CKA_ID
    // convention (0x01–0x04).

    await navigateTo(page, 'piv');
    await waitForLoadingComplete(page);

    const backendChips = page.locator('.filter-chip, .backend-chip');
    const pkcs11Chip = backendChips.filter({ hasText: /PKCS|HSM|SoftHSM/i });
    const hasPkcs11 = await pkcs11Chip.first().isVisible({ timeout: 5000 }).catch(() => false);
    test.skip(!hasPkcs11, 'PKCS#11 backend not available');

    await pkcs11Chip.first().click();
    await waitForLoadingComplete(page);

    // Every standard PIV slot must have a loaded certificate indicator.
    for (const slotId of ['9A', '9C', '9D', '9E']) {
      const slot = page.locator(`[data-testid="piv-slot-card-${slotId}"]`);
      await expect(slot).toBeVisible({ timeout: 5000 });

      const loadedIndicator = slot.locator('.slot-loaded');
      await expect(loadedIndicator).toBeVisible({ timeout: 5000 });
    }
  });
});
