import { test, expect, type Page } from '@playwright/test';
import {
  navigateTo,
  waitForAppReady,
  waitForBackendReady,
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

// resetPIVSlots clears every PIV slot via the backend binding so each test
// starts from a clean, all-empty state. Real-backend (Wails) only. This
// prevents state left by a prior test (or by piv.spec.ts running in parallel)
// from causing assertion failures in lifecycle tests that expect an empty slot.
//
// PKCS#11 backends are deliberately EXCLUDED from the generic "original
// backend" sweep below. Unlike the ephemeral software/tpm2 test backends,
// the PKCS#11 backend in the e2e sandbox points at a SoftHSM2 token that is
// pre-provisioned with long-lived fixture certificates (test/e2e/
// setup-softhsm-piv.sh, consumed by tests/e2e/piv-pkcs11-loading.spec.ts).
// Sweeping it here would permanently delete that shared fixture the moment
// any test in this file switches the active backend to PKCS#11 — exactly the
// bug this comment now documents. The one test that needs an empty PKCS#11
// slot 9A (see "PKCS11 PIV Key Lifecycle" below) clears that single slot
// itself instead of relying on this blanket sweep.
async function resetPIVSlots(page: Page): Promise<void> {
  if (!(await isWailsMode(page))) return;
  await page.evaluate(async () => {
    type PIVBinding = {
      DeleteCertificate?: (slot: string) => Promise<void>;
      SetBackend?: (backend: string) => Promise<void>;
      GetBackend?: () => Promise<string>;
    };
    const piv = (window as { go?: { services?: { PIVService?: PIVBinding } } }).go
      ?.services?.PIVService;
    if (!piv?.DeleteCertificate) return;
    // DeleteCertificate operates on the service's currently selected backend,
    // so a reset must sweep every local backend — a prior run may have left a
    // key on tpm2 while the service is parked on software (and vice versa).
    // PKCS#11 module IDs (e.g. "pkcs11-libsofthsm2") are excluded — see the
    // function doc comment above.
    const original = await piv.GetBackend?.().catch(() => '') ?? '';
    const backends = ['software', 'tpm2'];
    if (original && !backends.includes(original) && !original.startsWith('pkcs11')) backends.push(original);
    for (const backend of backends) {
      try {
        await piv.SetBackend?.(backend);
      } catch {
        continue;
      }
      for (const slot of ['9A', '9C', '9D', '9E', 'F9']) {
        try {
          await piv.DeleteCertificate(slot);
        } catch {
          // Slot already empty / nothing to delete — ignore.
        }
      }
    }
    if (original) {
      try {
        await piv.SetBackend?.(original);
      } catch {
        // Best effort — the next chip click resets it anyway.
      }
    }
  });
}

test.describe('PIV Integration', () => {
  // Serial mode ensures all tests run sequentially on one worker so each
  // lifecycle test starts with a predictably clean backend PIV state.
  // fullyParallel=true would dispatch concurrent workers that all share the
  // same Wails singleton PIVService, causing slot-state races.
  test.describe.configure({ mode: 'serial' });

  // One-time initial reset so any slots left dirty by a previous run are
  // cleared before the first test's beforeEach fires.
  test.beforeAll(async ({ browser }) => {
    const page = await browser.newPage();
    try {
      await page.goto('/');
      await waitForAppReady(page);
      // Ensure the Wails WebSocket is fully connected before calling any
      // backend method (resetPIVSlots uses window.go directly; if the WS
      // is not yet live, the delete calls silently no-op).
      await waitForBackendReady(page);
      await resetPIVSlots(page);
    } finally {
      await page.close();
    }
  });

  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await waitForAppReady(page);
    // waitForBackendReady MUST run before resetPIVSlots and navigateTo.
    //
    // resetPIVSlots calls PIVService.DeleteCertificate directly via window.go;
    // if the Wails WebSocket is not yet connected the calls silently no-op and
    // the slot state is not actually cleared.
    //
    // navigateTo loads the PIV view whose onMount fires BackendSelector.refresh()
    // → AdminService.ListBackends immediately. Without a live WS, callBackend()
    // returns null silently and only the auto-selected backend from the store is
    // shown — chips for TPM2/PKCS11 never appear, causing isVisible() checks in
    // the test bodies to time out and trigger spurious test.skip() calls.
    await waitForBackendReady(page);
    // Reset PIV slot state BEFORE navigating to PIV so the view loads fresh
    // slot data after the reset completes. If we reset after navigation the
    // Svelte store has already received the stale state and may not re-render.
    await resetPIVSlots(page);
    await ensureSidebarExpanded(page);
    await navigateTo(page, 'piv');
    await waitForLoadingComplete(page);
  });

  test.afterEach(async ({ page }) => {
    // Best-effort reset after each test so the next test's beforeEach starts
    // with a clean slate even when the test itself didn't clean up (e.g. on
    // failure mid-sequence). Errors here are swallowed because a failed reset
    // should not mask the original test failure.
    await resetPIVSlots(page).catch(() => {});
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

      // Wait for at least one chip to appear before counting. The BackendSelector
      // calls AdminService.ListBackends asynchronously; chips.count() called
      // immediately after navigation returns 0 before the fetch resolves.
      // waitForBackendReady in beforeEach ensures the WS is connected so the
      // ListBackends call returns promptly; 5 s is a generous safety margin.
      const firstChip = backendSelector.locator('.filter-chip').first();
      const anyChipVisible = await firstChip
        .isVisible({ timeout: 5_000 })
        .catch(() => false);

      if (!anyChipVisible) {
        // No backends with PIV capability in this environment — skip gracefully.
        test.skip(true, 'No PIV-capable backends available in this environment');
        return;
      }

      // Now count is safe — at least one chip is already in the DOM.
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

      // waitForBackendReady in beforeEach ensures the Wails WS is connected and
      // AdminService.ListBackends has already been called before the PIV view
      // mounted. The BackendSelector chips should be in the DOM within milliseconds
      // of the view rendering; 10 s is a generous safety margin for CI load.
      const hasTpm2 = await tpm2Chip.isVisible({ timeout: 10_000 }).catch(() => false);
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
      // After GenerateKeyAdvanced succeeds, handleKeyGenerated() calls loadSlots()
      // which queries PIVService.GetSlots scoped to the current TPM2 backend.
      // The Go service's localBackend is still "tpm2" (set by the chip click above);
      // getLocalSlots() remaps all returned slot Backend fields to that same ID so
      // the filteredSlots reactive (which filters on selectedBackend="tpm2") includes
      // slot 9A with loaded=true (self-signed cert) or hasKey=true (key-only).
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

      // waitForBackendReady in beforeEach ensures the chips are populated quickly;
      // 10 s matches the TPM2 timeout for consistency across hardware-backend tests.
      const hasPkcs11 = await pkcs11Chip.first().isVisible({ timeout: 10_000 }).catch(() => false);
      test.skip(!hasPkcs11, 'PKCS#11 backend not available');

      await pkcs11Chip.first().click();
      await waitForLoadingComplete(page);

      // The e2e SoftHSM2 fixture (test/e2e/setup-softhsm-piv.sh, provisioned by
      // `make dev-browser-e2e`) pre-loads slot 9A with a test certificate so
      // tests/e2e/piv-pkcs11-loading.spec.ts can verify pre-existing PKCS#11
      // certs render correctly. This test needs an EMPTY 9A to exercise key
      // generation, so it clears exactly that one slot itself — see the
      // resetPIVSlots() doc comment for why the generic sweep above
      // deliberately does not touch PKCS#11 backends.
      await page.evaluate(async () => {
        const piv = (window as { go?: { services?: { PIVService?: { DeleteCertificate?: (s: string) => Promise<void> } } } })
          .go?.services?.PIVService;
        try {
          await piv?.DeleteCertificate?.('9A');
        } catch {
          // Slot already empty — nothing to delete.
        }
      });

      // The delete above calls PIVService.DeleteCertificate directly via the
      // Wails binding, bypassing the UI's own delete-button flow that would
      // normally trigger a slot list refresh. Reload and re-select the
      // PKCS#11 chip so PIV.svelte re-fetches GetSlots() and reflects the
      // now-empty slot 9A, instead of continuing to show its stale
      // pre-deletion (loaded) render.
      await page.reload({ waitUntil: 'domcontentloaded' });
      await waitForAppReady(page);
      await waitForBackendReady(page);
      await ensureSidebarExpanded(page);
      await navigateTo(page, 'piv');
      await waitForLoadingComplete(page);
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

      // Every other empty PIV slot on the page also renders its own inline
      // "Generate Key" button, and the dialog's submit button lives in the
      // role=dialog footer (outside piv-generate-dialog's content node), so
      // scope to the dialog by its accessible name to target the submit
      // button unambiguously (matches the Software/TPM2 lifecycle tests above).
      const generateBtn = page
        .getByRole('dialog', { name: 'Generate PIV Key' })
        .getByRole('button', { name: 'Generate Key', exact: true });
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
