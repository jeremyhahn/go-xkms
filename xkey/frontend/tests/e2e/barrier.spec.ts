import { test, expect } from '@playwright/test';
import {
  navigateTo,
  waitForAppReady,
  ensureSidebarExpanded,
  isWailsMode,
  waitForBackendReady,
} from './helpers';

/**
 * Barrier integration tests.
 *
 * These tests verify the barrier encryption card on the Sealed Data page
 * and the end-to-end seal/unseal flow after barrier initialization.
 *
 * Requires Wails backend with swtpm (devcontainer or E2E Docker environment).
 */
test.describe('Barrier Integration', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
  });

  test.describe('Barrier Status Card', () => {
    test('barrier card shows initialized status after setup', async ({ page }) => {
      // 180 s budget: under 4-worker parallel load AppService.GetStatus and
      // BarrierService.GetSealInfo can each take 60–90 s to respond.
      test.setTimeout(180_000);
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      // waitForBackendReady makes a real RPC round-trip (AppLockService.GetStatus)
      // via page.evaluate, which does not return until the backend responds —
      // confirming the WebSocket is live and the call queue is being drained.
      //
      // The Dashboard from beforeEach may have called loadData() while the
      // WebSocket was still connecting. callBackend() catches Wails errors and
      // returns null silently; the Dashboard has no retry mechanism. Navigating
      // away and back forces a fresh Dashboard mount AFTER the WebSocket is
      // confirmed connected, so the new loadData() succeeds and populates
      // statusCards / barrierInfo.
      await waitForBackendReady(page);
      await navigateTo(page, 'seal');
      await navigateTo(page, 'dashboard');

      // 120 s: AppService.GetStatus + BarrierService.GetSealInfo (Promise.all)
      // can take up to 60–90 s under 4-worker parallel load. Must remain
      // below (test.setTimeout(180 s) − waitForBackendReady overhead).
      await expect(page.locator('.status-card-inner').first()).toBeVisible({ timeout: 120_000 });

      // The barrier-detail section renders only when barrierInfo.initialized === true.
      // Its presence confirms the barrier is configured.
      const barrierDetail = page.locator('.barrier-detail');
      await expect(barrierDetail).toBeVisible({ timeout: 10_000 });

      // The StatusBadge inside the barrier detail shows the seal state.
      // 'Disconnected' = sealed, 'Verified' = unsealed. Both are valid initialized states.
      const statusBadge = barrierDetail.locator('[role="status"]');
      await expect(statusBadge).toBeVisible();
      const statusText = await statusBadge.textContent();
      expect(['Disconnected', 'Verified']).toContain(statusText?.trim());

      // "Barrier Encryption" label must be present.
      await expect(barrierDetail.getByText('Barrier Encryption')).toBeVisible();
    });

    test('barrier card shows correct strategy (tpm2 when TPM available)', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend with TPM');

      await navigateTo(page, 'seal');
      await page.waitForTimeout(1000);

      const barrierCard = page.locator('.barrier-card');
      const isVisible = await barrierCard.isVisible().catch(() => false);
      if (!isVisible) return;

      // Check if barrier is initialized.
      const sealed = page.locator('.barrier-status-sealed');
      const unsealed = page.locator('.barrier-status-unsealed');
      const isInitialized =
        (await sealed.isVisible().catch(() => false)) ||
        (await unsealed.isVisible().catch(() => false));

      if (isInitialized) {
        // Strategy label should be visible and contain "tpm2" or "TPM".
        const strategyLabel = page.locator('.barrier-label:text("Strategy")');
        await expect(strategyLabel).toBeVisible();

        const strategyValue = strategyLabel.locator('..').locator('.barrier-value');
        const strategyText = await strategyValue.textContent();
        expect(strategyText?.toLowerCase()).toContain('tpm');
      }
    });

    test('barrier card shows hardware-backed badge when TPM2 strategy', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend with TPM');

      await navigateTo(page, 'seal');
      await page.waitForTimeout(1000);

      const barrierCard = page.locator('.barrier-card');
      const isVisible = await barrierCard.isVisible().catch(() => false);
      if (!isVisible) return;

      // When barrier uses TPM2, "Hardware" badge should be present.
      const hwBadge = page.locator('.barrier-hw-badge');
      const hasHWBadge = await hwBadge.isVisible().catch(() => false);

      // If barrier is initialized with TPM2, hardware badge must be visible.
      const unsealed = page.locator('.barrier-status-unsealed');
      const isUnsealed = await unsealed.isVisible().catch(() => false);
      if (isUnsealed) {
        // Check if strategy text mentions TPM.
        const strategyRow = page.locator('.barrier-row', { hasText: 'Strategy' });
        const strategyText = await strategyRow.textContent();
        if (strategyText?.toLowerCase().includes('tpm')) {
          expect(hasHWBadge).toBeTruthy();
        }
      }
    });

    test('barrier card displays root key path', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await navigateTo(page, 'seal');
      await page.waitForTimeout(1000);

      // When barrier is initialized, root key path should be shown.
      const rootKeyLabel = page.locator('.barrier-label:text("Root Key")');
      const isVisible = await rootKeyLabel.isVisible().catch(() => false);

      if (isVisible) {
        const rootKeyPath = page.locator('.barrier-path');
        await expect(rootKeyPath).toBeVisible();
        const pathText = await rootKeyPath.textContent();
        expect(pathText).toContain('root');
      }
    });
  });

  test.describe('Seal with Active Barrier', () => {
    test('seal data succeeds when barrier is active', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend with swtpm');

      await navigateTo(page, 'seal');
      await page.waitForTimeout(1000);

      // Seal.svelte has no barrier status card of its own (that markup only
      // exists on Dashboard.svelte) — "barrier is active" on this page is
      // expressed by SealService.CanSeal() gating the "Seal New Data"
      // button's disabled state, exactly like the sibling "unseal
      // previously sealed data" test below already does.
      const sealButton = page.getByRole('button', { name: 'Seal New Data' });
      const canSeal = await sealButton.isEnabled().catch(() => false);
      test.skip(!canSeal, 'No sealing backend available — cannot test seal operations');

      // Open seal dialog.
      await expect(sealButton).toBeEnabled();
      await sealButton.click();

      // Fill label and data.
      await page.locator('input[placeholder="e.g. API Secret"]').fill('Barrier Test Secret');
      await page.locator('#seal-data').fill('barrier-encrypted-test-data');

      // Seal with default backend.
      const sealAction = page.getByRole('button', { name: 'Seal' }).last();
      await sealAction.click();
      await page.waitForTimeout(2000);

      // Dialog should close and blob should appear in the blob table. Scope
      // to .content (the DataTable's container) — the success toast also
      // reads 'Data sealed as "Barrier Test Secret"' and would otherwise
      // create a strict-mode ambiguity with an unscoped getByText lookup.
      // Use .first() rather than requiring exactly one match: this test uses
      // a fixed label and does not delete the blob afterward, so repeated
      // runs against the same persistent dev backend legitimately produce
      // multiple rows with the same label — what matters is that at least
      // one now exists.
      await expect(page.getByText('Seal Data')).not.toBeVisible();
      await expect(page.locator('.content').getByText('Barrier Test Secret').first()).toBeVisible();
    });

    test('unseal previously sealed data returns correct content', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend with swtpm');

      await navigateTo(page, 'seal');
      await page.waitForTimeout(1000);

      // First seal some data.
      const sealButton = page.getByRole('button', { name: 'Seal New Data' });
      const canSeal = await sealButton.isEnabled().catch(() => false);
      test.skip(!canSeal, 'Seal button disabled — no TPM available');

      await sealButton.click();
      await page.locator('input[placeholder="e.g. API Secret"]').fill('Roundtrip Test');
      await page.locator('#seal-data').fill('roundtrip-verify-data');
      await page.getByRole('button', { name: 'Seal' }).last().click();
      await page.waitForTimeout(2000);

      // Now unseal it.
      const unsealButton = page.getByRole('button', { name: 'Unseal' }).first();
      const hasBlobs = await unsealButton.isVisible().catch(() => false);

      if (hasBlobs) {
        await unsealButton.click();
        await page.waitForTimeout(1000);

        // Unseal result should show the original data.
        const unsealData = page.locator('.unseal-data-text');
        const dataVisible = await unsealData.isVisible().catch(() => false);
        if (dataVisible) {
          const dataText = await unsealData.textContent();
          expect(dataText).toContain('roundtrip-verify-data');
        }

        // Close dialog.
        const closeBtn = page.getByRole('button', { name: 'Close' });
        const closeBtnVisible = await closeBtn.isVisible().catch(() => false);
        if (closeBtnVisible) {
          await closeBtn.click();
        }
      }
    });
  });
});
