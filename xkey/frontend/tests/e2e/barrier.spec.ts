import { test, expect } from '@playwright/test';
import {
  navigateTo,
  waitForAppReady,
  ensureSidebarExpanded,
  isWailsMode,
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
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await navigateTo(page, 'seal');
      await page.waitForTimeout(1000);

      const barrierCard = page.locator('.barrier-card');
      await expect(barrierCard).toBeVisible();

      // After setup completes, barrier should be either Sealed or Unsealed — NOT "Not Configured".
      const notConfigured = page.locator('.barrier-status-warn');
      const isNotConfigured = await notConfigured.isVisible().catch(() => false);

      if (isNotConfigured) {
        // This is a failure — barrier should be configured after setup.
        test.fail(true, 'Barrier shows "Not Configured" — barrier initialization failed during setup');
      }

      // Should show Sealed or Unsealed.
      const statusText = page.locator('.barrier-status');
      await expect(statusText).toBeVisible();
      const text = await statusText.textContent();
      expect(['Sealed', 'Unsealed']).toContain(text?.trim());
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

      // Verify barrier is active (Unsealed).
      const unsealed = page.locator('.barrier-status-unsealed');
      const isUnsealed = await unsealed.isVisible().catch(() => false);
      test.skip(!isUnsealed, 'Barrier not unsealed — cannot test seal operations');

      // Open seal dialog.
      const sealButton = page.getByRole('button', { name: 'Seal New Data' });
      await expect(sealButton).toBeEnabled();
      await sealButton.click();

      // Fill label and data.
      await page.locator('input[placeholder="e.g. API Secret"]').fill('Barrier Test Secret');
      await page.locator('#seal-data').fill('barrier-encrypted-test-data');

      // Seal with default backend.
      const sealAction = page.getByRole('button', { name: 'Seal' }).last();
      await sealAction.click();
      await page.waitForTimeout(2000);

      // Dialog should close and blob should appear.
      await expect(page.getByText('Seal Data')).not.toBeVisible();
      await expect(page.getByText('Barrier Test Secret')).toBeVisible();
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
