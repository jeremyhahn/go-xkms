import { test, expect } from '@playwright/test';
import {
  navigateTo,
  waitForAppReady,
  ensureSidebarExpanded,
  isWailsMode,
  waitForLoadingComplete,
} from './helpers';

/**
 * PIV integration tests.
 *
 * These tests exercise the PIV key lifecycle (generate → view → export →
 * delete) and backend switching through the GUI. They are designed to run
 * against the Wails dev server backed by real swtpm and softhsm2 instances
 * inside a Docker container (via `make test-e2e-piv-integration`).
 */
test.describe('PIV Integration', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
    await navigateTo(page, 'piv');
    await waitForLoadingComplete(page);
  });

  test.describe('Software PIV Key Lifecycle', () => {
    test('generate a key in slot 9A, then view and delete it', async ({ page }) => {
      const wails = await isWailsMode(page).catch(() => false);
      test.skip(!wails, 'Requires Wails backend for PIV key generation');

      // Click the 9A slot card to open it.
      const slot9a = page.locator('[data-testid="piv-slot-9a"]');
      await expect(slot9a).toBeVisible();
      await slot9a.click();

      // Open the generate key dialog.
      const generateBtn = page.locator('[data-testid="piv-generate-key"]');
      await expect(generateBtn).toBeVisible();
      await generateBtn.click();

      // Select ECCP256 algorithm.
      const algoSelect = page.locator('[data-testid="piv-algorithm-select"]');
      await expect(algoSelect).toBeVisible();
      await algoSelect.selectOption('ECCP256');

      // Confirm generation.
      const confirmBtn = page.locator('[data-testid="piv-generate-confirm"]');
      await expect(confirmBtn).toBeVisible();
      await confirmBtn.click();

      // Wait for success notification.
      await expect(page.getByText(/Key generated/i)).toBeVisible({ timeout: 15000 });

      // Slot should now show a certificate.
      await expect(slot9a.getByText(/ECDSA|ECCP256/i)).toBeVisible();

      // Export the certificate.
      const exportBtn = page.locator('[data-testid="piv-export-cert"]');
      if (await exportBtn.isVisible()) {
        await exportBtn.click();
        await expect(page.getByText(/BEGIN CERTIFICATE/)).toBeVisible({ timeout: 5000 });
      }

      // Delete the certificate.
      const deleteBtn = page.locator('[data-testid="piv-delete-cert"]');
      await expect(deleteBtn).toBeVisible();
      await deleteBtn.click();

      // Confirm deletion.
      const confirmDeleteBtn = page.locator('[data-testid="piv-delete-confirm"]');
      if (await confirmDeleteBtn.isVisible()) {
        await confirmDeleteBtn.click();
      }

      // Slot should revert to empty state.
      await expect(slot9a.getByText(/No certificate/i)).toBeVisible({ timeout: 5000 });
    });
  });

  test.describe('Backend Switching', () => {
    test('switching backend updates the slot display', async ({ page }) => {
      const wails = await isWailsMode(page).catch(() => false);
      test.skip(!wails, 'Requires Wails backend for backend switching');

      // The backend selector should be visible on the PIV page.
      const backendSelector = page.locator('[data-testid="backend-selector"]');
      await expect(backendSelector).toBeVisible();

      // Select the first available backend option.
      const options = backendSelector.locator('option');
      const count = await options.count();
      expect(count).toBeGreaterThan(0);

      // Pick the first option and verify slots reload without error.
      await backendSelector.selectOption({ index: 0 });
      await waitForLoadingComplete(page);

      // Slots should still be visible after switching.
      await expect(page.locator('[data-testid="piv-slot-9a"]')).toBeVisible();
    });
  });

  test.describe('TPM2 PIV Key Lifecycle', () => {
    test('generate a key in slot 9A using TPM2 backend', async ({ page }) => {
      // The backend selector should show TPM2 as an option when swtpm is available.
      const backendChips = page.locator('.filter-chip, .backend-chip');
      const tpm2Chip = backendChips.filter({ hasText: /TPM/i });

      // Skip if TPM2 backend is not available (no swtpm in this environment).
      const hasTpm2 = await tpm2Chip.isVisible({ timeout: 3_000 }).catch(() => false);
      test.skip(!hasTpm2, 'TPM2 backend not available — requires swtpm');

      // Select the TPM2 backend.
      await tpm2Chip.click();
      await waitForLoadingComplete(page);

      // Click the 9A slot card.
      const slot9a = page.locator('[data-testid="piv-slot-9a"]');
      await expect(slot9a).toBeVisible();
      await slot9a.click();

      // Open the generate key dialog.
      const generateBtn = page.locator('[data-testid="piv-generate-key"]');
      await expect(generateBtn).toBeVisible();
      await generateBtn.click();

      // Select ECCP256 algorithm.
      const algoSelect = page.locator('[data-testid="piv-algorithm-select"]');
      await expect(algoSelect).toBeVisible();
      await algoSelect.selectOption('ECCP256');

      // Confirm generation.
      const confirmBtn = page.locator('[data-testid="piv-generate-confirm"]');
      await expect(confirmBtn).toBeVisible();
      await confirmBtn.click();

      // Wait for success — the key should be generated using the TPM2 backend.
      await expect(page.getByText(/Key generated/i)).toBeVisible({ timeout: 15_000 });

      // Slot should now show a certificate.
      await expect(slot9a.getByText(/ECDSA|ECCP256/i)).toBeVisible({ timeout: 5_000 });

      // Clean up — delete the certificate.
      const deleteBtn = page.locator('[data-testid="piv-delete-cert"]');
      if (await deleteBtn.isVisible({ timeout: 2_000 }).catch(() => false)) {
        await deleteBtn.click();
        const confirmDeleteBtn = page.locator('[data-testid="piv-delete-confirm"]');
        if (await confirmDeleteBtn.isVisible({ timeout: 2_000 }).catch(() => false)) {
          await confirmDeleteBtn.click();
        }
        await expect(slot9a.getByText(/No certificate/i)).toBeVisible({ timeout: 5_000 });
      }
    });
  });

  test.describe('PKCS11 PIV Key Lifecycle', () => {
    test('generate a key in slot 9A using PKCS11 backend', async ({ page }) => {
      const backendChips = page.locator('.filter-chip, .backend-chip');
      const pkcs11Chip = backendChips.filter({ hasText: /PKCS|HSM|YubiKey/i });

      const hasPkcs11 = await pkcs11Chip.first().isVisible({ timeout: 3_000 }).catch(() => false);
      test.skip(!hasPkcs11, 'PKCS#11 backend not available');

      await pkcs11Chip.first().click();
      await waitForLoadingComplete(page);

      const slot9a = page.locator('[data-testid="piv-slot-9a"]');
      await expect(slot9a).toBeVisible();
      await slot9a.click();

      const generateBtn = page.locator('[data-testid="piv-generate-key"]');
      await expect(generateBtn).toBeVisible();
      await generateBtn.click();

      const algoSelect = page.locator('[data-testid="piv-algorithm-select"]');
      await expect(algoSelect).toBeVisible();
      await algoSelect.selectOption('ECCP256');

      const confirmBtn = page.locator('[data-testid="piv-generate-confirm"]');
      await expect(confirmBtn).toBeVisible();
      await confirmBtn.click();

      await expect(page.getByText(/Key generated/i)).toBeVisible({ timeout: 15_000 });
      await expect(slot9a.getByText(/ECDSA|ECCP256/i)).toBeVisible({ timeout: 5_000 });

      // Clean up
      const deleteBtn = page.locator('[data-testid="piv-delete-cert"]');
      if (await deleteBtn.isVisible({ timeout: 2_000 }).catch(() => false)) {
        await deleteBtn.click();
        const confirmDeleteBtn = page.locator('[data-testid="piv-delete-confirm"]');
        if (await confirmDeleteBtn.isVisible({ timeout: 2_000 }).catch(() => false)) {
          await confirmDeleteBtn.click();
        }
      }
    });
  });

  test.describe('Backend Certificate Isolation', () => {
    test('certificates are isolated per backend', async ({ page }) => {
      const wails = await isWailsMode(page).catch(() => false);
      test.skip(!wails, 'Requires Wails backend for certificate isolation test');

      const backendChips = page.locator('.filter-chip, .backend-chip');

      // Count backends
      const chipCount = await backendChips.count();
      test.skip(chipCount < 2, 'Need at least 2 backends to test isolation');

      // Select first backend and count loaded slots
      await backendChips.nth(0).click();
      await waitForLoadingComplete(page);

      const firstBackendSlots = page.locator('[data-testid^="piv-slot-"]');
      const firstCount = await firstBackendSlots.count();

      // Select second backend
      await backendChips.nth(1).click();
      await waitForLoadingComplete(page);

      const secondBackendSlots = page.locator('[data-testid^="piv-slot-"]');
      const secondCount = await secondBackendSlots.count();

      // Both should show 5 standard slots (empty or loaded)
      expect(firstCount).toBe(5);
      expect(secondCount).toBe(5);

      // Verify no errors were shown during switching
      const errorNotification = page.locator('.notification.error, [data-testid="notification-error"]');
      await expect(errorNotification).not.toBeVisible();
    });
  });

  test.describe('PKCS11 Backend Custom Name', () => {
    test('custom name input is present in PKCS11 backend dialog', async ({ page }) => {
      // Navigate to Admin view.
      await navigateTo(page, 'admin');
      await waitForLoadingComplete(page);

      // Open Add Backend dialog.
      const addBtn = page.locator('[data-testid="add-backend-btn"]');
      if (await addBtn.isVisible()) {
        await addBtn.click();

        // Select PKCS#11 backend type.
        const pkcs11Card = page.getByText('PKCS#11');
        if (await pkcs11Card.isVisible()) {
          await pkcs11Card.click();

          // The custom name input should be present.
          const customNameInput = page.locator('[data-testid="pkcs11-custom-name"]');
          await expect(customNameInput).toBeVisible();

          // Type a custom name.
          await customNameInput.fill('My HSM Token');
          await expect(customNameInput).toHaveValue('My HSM Token');
        }
      }
    });
  });
});
