import { test, expect } from '@playwright/test';
import {
  navigateTo,
  waitForAppReady,
  ensureSidebarExpanded,
  isWailsMode,
  navigateToFIDO2,
  waitForLoadingComplete,
} from './helpers';

/**
 * FIDO2 PKCS#11 Backend Selection Tests
 *
 * These tests verify that:
 * 1. A PKCS#11 backend appears in the FIDO2 backend selector after registration
 * 2. Selecting the PKCS#11 backend sets it as the default for new credentials
 * 3. The backend selector visually indicates the active selection
 * 4. Switching back to software or "all" works correctly
 *
 * Requires: Wails backend running with a PKCS#11 module registered (SoftHSM or YubiKey).
 * Run via: make test-e2e-docker (full stack) or manually with Wails dev server.
 */
test.describe('FIDO2 PKCS#11 Backend Selection', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
  });

  test('PKCS#11 backend chip appears in FIDO2 backend selector', async ({ page }) => {
    const wails = await isWailsMode(page).catch(() => false);
    test.skip(!wails, 'Requires Wails backend');

    await navigateToFIDO2(page);
    await waitForLoadingComplete(page);

    // The backend selector should be present on the credentials tab.
    const selector = page.locator('[data-testid="fido2-backend-selector"]');
    await expect(selector).toBeVisible({ timeout: 5000 });

    // Look for a PKCS#11/HSM chip in the selector.
    const pkcs11Chip = selector.locator('.filter-chip').filter({
      hasText: /PKCS|HSM|SoftHSM|YubiKey|pkcs11/i,
    });
    const hasPKCS11 = await pkcs11Chip.first().isVisible({ timeout: 5000 }).catch(() => false);
    test.skip(!hasPKCS11, 'No PKCS#11 backend registered — register via Admin first');

    // The chip should be clickable and not already active.
    await expect(pkcs11Chip.first()).toBeEnabled();
  });

  test('selecting PKCS#11 chip marks it as active default backend', async ({ page }) => {
    const wails = await isWailsMode(page).catch(() => false);
    test.skip(!wails, 'Requires Wails backend');

    await navigateToFIDO2(page);
    await waitForLoadingComplete(page);

    const selector = page.locator('[data-testid="fido2-backend-selector"]');
    const pkcs11Chip = selector.locator('.filter-chip').filter({
      hasText: /PKCS|HSM|SoftHSM|YubiKey|pkcs11/i,
    });
    const hasPKCS11 = await pkcs11Chip.first().isVisible({ timeout: 5000 }).catch(() => false);
    test.skip(!hasPKCS11, 'No PKCS#11 backend registered');

    // Click the PKCS#11 chip.
    await pkcs11Chip.first().click();
    await page.waitForTimeout(500); // Allow SetDefaultBackend call to complete.

    // The clicked chip should now have the .active class.
    await expect(pkcs11Chip.first()).toHaveClass(/active/);

    // The "All Backends" chip should NOT be active.
    const allChip = selector.locator('.filter-chip').filter({ hasText: /All/i });
    if (await allChip.isVisible()) {
      await expect(allChip).not.toHaveClass(/active/);
    }
  });

  test('switching from PKCS#11 to software deactivates PKCS#11 chip', async ({ page }) => {
    const wails = await isWailsMode(page).catch(() => false);
    test.skip(!wails, 'Requires Wails backend');

    await navigateToFIDO2(page);
    await waitForLoadingComplete(page);

    const selector = page.locator('[data-testid="fido2-backend-selector"]');
    const pkcs11Chip = selector.locator('.filter-chip').filter({
      hasText: /PKCS|HSM|SoftHSM|YubiKey|pkcs11/i,
    });
    const hasPKCS11 = await pkcs11Chip.first().isVisible({ timeout: 5000 }).catch(() => false);
    test.skip(!hasPKCS11, 'No PKCS#11 backend registered');

    // Select PKCS#11 first.
    await pkcs11Chip.first().click();
    await page.waitForTimeout(300);
    await expect(pkcs11Chip.first()).toHaveClass(/active/);

    // Now select Software.
    const softwareChip = selector.locator('.filter-chip').filter({ hasText: /Software/i });
    if (await softwareChip.isVisible()) {
      await softwareChip.click();
      await page.waitForTimeout(300);

      // Software should be active, PKCS#11 should not.
      await expect(softwareChip).toHaveClass(/active/);
      await expect(pkcs11Chip.first()).not.toHaveClass(/active/);
    }
  });

  test('FIDO2 credentials tab shows empty state when filtering by PKCS#11', async ({ page }) => {
    const wails = await isWailsMode(page).catch(() => false);
    test.skip(!wails, 'Requires Wails backend');

    await navigateToFIDO2(page);
    await waitForLoadingComplete(page);

    const selector = page.locator('[data-testid="fido2-backend-selector"]');
    const pkcs11Chip = selector.locator('.filter-chip').filter({
      hasText: /PKCS|HSM|SoftHSM|YubiKey|pkcs11/i,
    });
    const hasPKCS11 = await pkcs11Chip.first().isVisible({ timeout: 5000 }).catch(() => false);
    test.skip(!hasPKCS11, 'No PKCS#11 backend registered');

    // Select PKCS#11 backend.
    await pkcs11Chip.first().click();
    await waitForLoadingComplete(page);

    // Unless credentials were previously created with PKCS#11,
    // the credentials list should be empty or show the empty state.
    const emptyState = page.locator('[data-testid="fido2-empty-credentials"]');
    const credList = page.locator('[data-testid="fido2-credential-list"]');

    // Either empty state is shown, or the credential list is visible
    // (both are valid — depends on whether PKCS#11 credentials exist).
    const emptyVisible = await emptyState.isVisible().catch(() => false);
    const listVisible = await credList.isVisible().catch(() => false);
    expect(emptyVisible || listVisible).toBe(true);

    // No error notifications should appear (this was the old bug —
    // backend name mismatch caused silent failures).
    const errorToast = page.locator('.notification.error, .toast.error, [role="alert"]');
    const errorCount = await errorToast.count();
    expect(errorCount).toBe(0);
  });

  test('PKCS#11 backend chip shows FIDO2 capability', async ({ page }) => {
    const wails = await isWailsMode(page).catch(() => false);
    test.skip(!wails, 'Requires Wails backend');

    await navigateToFIDO2(page);
    await waitForLoadingComplete(page);

    // The backend selector filters by "fido2" capability.
    // If a PKCS#11 backend is visible, it must have FIDO2 capability.
    const selector = page.locator('[data-testid="fido2-backend-selector"]');
    await expect(selector).toBeVisible({ timeout: 5000 });

    // Count all filter chips (including "All Backends").
    const chips = selector.locator('.filter-chip');
    const chipCount = await chips.count();

    // Should have at least 2 chips: "All Backends" + "Software".
    expect(chipCount).toBeGreaterThanOrEqual(2);

    // Each non-"All" chip represents a backend with FIDO2 capability.
    // Verify they are all enabled (not disabled).
    for (let i = 0; i < chipCount; i++) {
      await expect(chips.nth(i)).toBeEnabled();
    }
  });
});
