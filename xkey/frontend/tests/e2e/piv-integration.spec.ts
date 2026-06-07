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
 *
 * Slot test-id scheme (from PIV.svelte):
 *   - Outer card:   data-testid="piv-slot-card-{slotId}"     (always present)
 *   - Empty state:  data-testid="piv-slot-empty-{slotId}"    (no cert, no key)
 *   - Key-only:     data-testid="piv-slot-key-only-{slotId}" (key, no cert)
 *   - Loaded:       data-testid="piv-slot-details-{slotId}"  (cert present)
 *
 * Generate dialog buttons have no data-testid; use role/text matchers.
 * Delete is via the ActionMenu overflow: data-testid="action-menu-kebab"
 * then data-testid="piv-action-delete".
 * BackendSelector in PIV uses showAll=false; chips are .backend-selector .filter-chip.
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

      // The slot card is always present (piv-slot-card-9A).
      const slotCard = page.locator('[data-testid="piv-slot-card-9A"]');
      await expect(slotCard).toBeVisible();

      // The "Generate Key" action button is inside the empty slot state.
      const generateActionBtn = page.locator('[data-testid="piv-slot-action-9A"]');
      await expect(generateActionBtn).toBeVisible();
      await generateActionBtn.click();

      // The generate dialog should open.
      const dialog = page.locator('[data-testid="piv-generate-dialog"]');
      await expect(dialog).toBeVisible({ timeout: 5_000 });

      // Ensure the Common Name field is filled (loadDefaults is async; if it hasn't
      // resolved yet, set a value explicitly to avoid a backend validation failure).
      const cnInput = dialog.getByLabel('Common Name');
      await expect(cnInput).toBeVisible();
      const existingCN = await cnInput.inputValue();
      if (!existingCN.trim()) {
        await cnInput.fill('Test User');
      }

      // Select ECCP256 algorithm.
      const algoSelect = page.locator('[data-testid="piv-algorithm-select"]');
      await expect(algoSelect).toBeVisible();
      await algoSelect.selectOption('ECCP256');

      // Click the "Generate Key" button. The empty slot cards each expose an inline
      // "Generate Key" button, and the dialog's submit button lives in the role=dialog
      // footer (outside the piv-generate-dialog content node), so scope to the dialog
      // by its accessible name to target the submit button unambiguously.
      const generateBtn = page
        .getByRole('dialog', { name: 'Generate PIV Key' })
        .getByRole('button', { name: 'Generate Key', exact: true });
      await expect(generateBtn).toBeVisible();
      await generateBtn.click();

      // Wait for the dialog to close (self-signed format closes on success).
      await expect(dialog).toBeHidden({ timeout: 20_000 });
      await waitForLoadingComplete(page);

      // Slot should now show a key/cert state (details or key-only).
      const slotLoaded = page.locator(
        '[data-testid="piv-slot-details-9A"], [data-testid="piv-slot-key-only-9A"]',
      );
      await expect(slotLoaded).toBeVisible({ timeout: 10_000 });

      // Delete: open the ActionMenu overflow on the slot card.
      const kebab = slotCard.locator('[data-testid="action-menu-kebab"]');
      await expect(kebab).toBeVisible();
      await kebab.click();

      // Click the delete action in the overflow menu.
      const deleteAction = page.locator('[data-testid="piv-action-delete"]');
      await expect(deleteAction).toBeVisible({ timeout: 3_000 });
      await deleteAction.click();

      // Confirm deletion in the modal.
      const confirmDeleteBtn = page.getByRole('button', { name: 'Delete' });
      await expect(confirmDeleteBtn).toBeVisible({ timeout: 3_000 });
      await confirmDeleteBtn.click();

      // Slot should revert to empty state.
      await expect(
        page.locator('[data-testid="piv-slot-empty-9A"]'),
      ).toBeVisible({ timeout: 10_000 });
    });
  });

  test.describe('Backend Switching', () => {
    test('switching backend updates the slot display', async ({ page }) => {
      const wails = await isWailsMode(page).catch(() => false);
      test.skip(!wails, 'Requires Wails backend for backend switching');

      // The PIV BackendSelector renders as .backend-selector with showAll=false
      // (no "All Backends" chip — only per-backend filter chips).
      const backendSelector = page.locator('.backend-selector');
      await expect(backendSelector).toBeVisible();

      // Enumerate available backend chips.
      const chips = backendSelector.locator('.filter-chip');
      const count = await chips.count();
      expect(count).toBeGreaterThan(0);

      // Click the first chip and verify slots reload without error.
      await chips.nth(0).click();
      await waitForLoadingComplete(page);

      // At least one slot card should be visible after switching.
      await expect(
        page.locator('[data-testid="piv-slot-card-9A"]'),
      ).toBeVisible({ timeout: 10_000 });
    });
  });

  test.describe('TPM2 PIV Key Lifecycle', () => {
    test('generate a key in slot 9A using TPM2 backend', async ({ page }) => {
      // Check for a TPM2 chip in the BackendSelector (not .backend-chip, which is
      // a per-slot label, but .filter-chip inside .backend-selector).
      const tpm2Chip = page.locator('.backend-selector .filter-chip').filter({ hasText: /TPM/i });

      // Skip if TPM2 backend is not available (no swtpm in this environment).
      const hasTpm2 = await tpm2Chip.isVisible({ timeout: 3_000 }).catch(() => false);
      test.skip(!hasTpm2, 'TPM2 backend not available — requires swtpm');

      // Select the TPM2 backend.
      await tpm2Chip.click();
      await waitForLoadingComplete(page);

      // Verify 9A slot card is present.
      const slotCard = page.locator('[data-testid="piv-slot-card-9A"]');
      await expect(slotCard).toBeVisible();

      // Open generate dialog via the slot action button.
      const generateActionBtn = page.locator('[data-testid="piv-slot-action-9A"]');
      await expect(generateActionBtn).toBeVisible();
      await generateActionBtn.click();

      // The generate dialog should open.
      const dialog = page.locator('[data-testid="piv-generate-dialog"]');
      await expect(dialog).toBeVisible({ timeout: 5_000 });

      // Ensure Common Name is filled before generating (loadDefaults is async).
      const cnInput = dialog.getByLabel('Common Name');
      await expect(cnInput).toBeVisible();
      const existingCN = await cnInput.inputValue();
      if (!existingCN.trim()) {
        await cnInput.fill('Test User');
      }

      // Select ECCP256 algorithm.
      const algoSelect = page.locator('[data-testid="piv-algorithm-select"]');
      await expect(algoSelect).toBeVisible();
      await algoSelect.selectOption('ECCP256');

      // Click "Generate Key" — scope to the role=dialog footer (slot cards also expose
      // inline "Generate Key" buttons; the submit button is outside the testid node).
      const generateBtn = page
        .getByRole('dialog', { name: 'Generate PIV Key' })
        .getByRole('button', { name: 'Generate Key', exact: true });
      await expect(generateBtn).toBeVisible();
      await generateBtn.click();

      // Wait for dialog to close — TPM key generation may take a few seconds.
      await expect(dialog).toBeHidden({ timeout: 25_000 });
      await waitForLoadingComplete(page);

      // Slot should now show a key/cert state.
      const slotLoaded = page.locator(
        '[data-testid="piv-slot-details-9A"], [data-testid="piv-slot-key-only-9A"]',
      );
      await expect(slotLoaded).toBeVisible({ timeout: 10_000 });

      // Clean up — delete via ActionMenu.
      const kebab = slotCard.locator('[data-testid="action-menu-kebab"]');
      if (await kebab.isVisible({ timeout: 2_000 }).catch(() => false)) {
        await kebab.click();
        const deleteAction = page.locator('[data-testid="piv-action-delete"]');
        if (await deleteAction.isVisible({ timeout: 2_000 }).catch(() => false)) {
          await deleteAction.click();
          const confirmDeleteBtn = page.getByRole('button', { name: 'Delete' });
          if (await confirmDeleteBtn.isVisible({ timeout: 2_000 }).catch(() => false)) {
            await confirmDeleteBtn.click();
          }
          await expect(
            page.locator('[data-testid="piv-slot-empty-9A"]'),
          ).toBeVisible({ timeout: 10_000 });
        }
      }
    });
  });

  test.describe('PKCS11 PIV Key Lifecycle', () => {
    test('generate a key in slot 9A using PKCS11 backend', async ({ page }) => {
      // PKCS#11 chips are filter chips inside .backend-selector, not .backend-chip
      // (which is a per-slot informational badge, not interactive).
      const pkcs11Chip = page.locator('.backend-selector .filter-chip').filter({ hasText: /PKCS|HSM|YubiKey/i });

      const hasPkcs11 = await pkcs11Chip.first().isVisible({ timeout: 3_000 }).catch(() => false);
      test.skip(!hasPkcs11, 'PKCS#11 backend not available');

      await pkcs11Chip.first().click();
      await waitForLoadingComplete(page);

      const slotCard = page.locator('[data-testid="piv-slot-card-9A"]');
      await expect(slotCard).toBeVisible();

      const generateActionBtn = page.locator('[data-testid="piv-slot-action-9A"]');
      await expect(generateActionBtn).toBeVisible();
      await generateActionBtn.click();

      const dialog = page.locator('[data-testid="piv-generate-dialog"]');
      await expect(dialog).toBeVisible({ timeout: 5_000 });

      // Ensure Common Name is filled before generating (loadDefaults is async).
      const cnInput = dialog.getByLabel('Common Name');
      await expect(cnInput).toBeVisible();
      const existingCN = await cnInput.inputValue();
      if (!existingCN.trim()) {
        await cnInput.fill('Test User');
      }

      const algoSelect = page.locator('[data-testid="piv-algorithm-select"]');
      await expect(algoSelect).toBeVisible();
      await algoSelect.selectOption('ECCP256');

      const generateBtn = page.getByRole('button', { name: 'Generate Key' });
      await expect(generateBtn).toBeVisible();
      await generateBtn.click();

      await expect(dialog).toBeHidden({ timeout: 20_000 });
      await waitForLoadingComplete(page);

      const slotLoaded = page.locator(
        '[data-testid="piv-slot-details-9A"], [data-testid="piv-slot-key-only-9A"]',
      );
      await expect(slotLoaded).toBeVisible({ timeout: 10_000 });

      // Clean up
      const kebab = slotCard.locator('[data-testid="action-menu-kebab"]');
      if (await kebab.isVisible({ timeout: 2_000 }).catch(() => false)) {
        await kebab.click();
        const deleteAction = page.locator('[data-testid="piv-action-delete"]');
        if (await deleteAction.isVisible({ timeout: 2_000 }).catch(() => false)) {
          await deleteAction.click();
          const confirmDeleteBtn = page.getByRole('button', { name: 'Delete' });
          if (await confirmDeleteBtn.isVisible({ timeout: 2_000 }).catch(() => false)) {
            await confirmDeleteBtn.click();
          }
        }
      }
    });
  });

  test.describe('Backend Certificate Isolation', () => {
    test('certificates are isolated per backend', async ({ page }) => {
      const wails = await isWailsMode(page).catch(() => false);
      test.skip(!wails, 'Requires Wails backend for certificate isolation test');

      // Use .filter-chip inside .backend-selector (not .backend-chip, which is
      // a per-slot informational badge and not interactive).
      const backendChips = page.locator('.backend-selector .filter-chip');

      // Count backends; the PIV BackendSelector uses showAll=false so each chip
      // is a backend (no "All Backends" chip).
      const chipCount = await backendChips.count();
      test.skip(chipCount < 2, 'Need at least 2 backends to test isolation');

      // Select first backend and count slot cards.
      // Use piv-slot-card-* (exactly one per slot) to avoid counting inner state
      // divs (piv-slot-empty-*, piv-slot-details-*, piv-slot-key-only-*).
      await backendChips.nth(0).click();
      await waitForLoadingComplete(page);

      const firstBackendSlots = page.locator('[data-testid^="piv-slot-card-"]');
      const firstCount = await firstBackendSlots.count();

      // Select second backend
      await backendChips.nth(1).click();
      await waitForLoadingComplete(page);

      const secondBackendSlots = page.locator('[data-testid^="piv-slot-card-"]');
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
