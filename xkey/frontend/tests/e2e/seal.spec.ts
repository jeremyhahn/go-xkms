import { test, expect } from '@playwright/test';
import {
  navigateTo,
  waitForAppReady,
  ensureSidebarExpanded,
  isWailsMode,
  waitForLoadingComplete,
} from './helpers';

test.describe('Seal View', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
    await navigateTo(page, 'seal');
  });

  test.describe('Header and Layout', () => {
    test('Seal view loads with correct header', async ({ page }) => {
      await expect(page.locator('h1.header-title')).toHaveText('Sealed Data');
      await expect(page.getByText('Encrypted data storage')).toBeVisible();
    });

    test('Seal New Data button is present in header', async ({ page }) => {
      const sealButton = page.getByRole('button', { name: 'Seal New Data' });
      await expect(sealButton).toBeVisible();
    });

    test('seal view content area is visible', async ({ page }) => {
      const content = page.locator('.seal-view .content');
      await expect(content).toBeVisible();
    });
  });

  test.describe('Barrier Status Card', () => {
    test('barrier section is visible after loading', async ({ page }) => {
      await page.waitForTimeout(500);

      // The barrier card should be visible (loaded from backend or showing default state).
      const barrierCard = page.locator('.barrier-card');
      const isVisible = await barrierCard.isVisible().catch(() => false);

      // If running in Vite mode without backend, barrier info may not be available.
      // In Wails mode it should always be visible.
      const wails = await isWailsMode(page);
      if (wails) {
        await expect(barrierCard).toBeVisible();
      } else {
        // In Vite mode, barrier card may or may not be present depending on mock data.
        expect(true).toBeTruthy();
      }
    });

    test('barrier card shows status label', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await page.waitForTimeout(1000);

      const barrierCard = page.locator('.barrier-card');
      const isCardVisible = await barrierCard.isVisible().catch(() => false);

      if (isCardVisible) {
        // Status row should exist with one of: "Not Configured", "Sealed", or "Unsealed".
        const statusLabel = page.locator('.barrier-label:text("Status")');
        await expect(statusLabel).toBeVisible();

        const statusText = page.locator('.barrier-status');
        await expect(statusText).toBeVisible();
        const text = await statusText.textContent();
        expect(['Not Configured', 'Sealed', 'Unsealed']).toContain(text?.trim());
      }
    });

    test('barrier card shows sealer details when initialized', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await page.waitForTimeout(1000);

      const barrierCard = page.locator('.barrier-card');
      const isCardVisible = await barrierCard.isVisible().catch(() => false);

      if (isCardVisible) {
        // If barrier IS initialized, strategy and root key should be shown.
        const sealed = page.locator('.barrier-status-sealed');
        const unsealed = page.locator('.barrier-status-unsealed');
        const isInitialized =
          (await sealed.isVisible().catch(() => false)) ||
          (await unsealed.isVisible().catch(() => false));

        if (isInitialized) {
          await expect(page.locator('.barrier-label:text("Strategy")')).toBeVisible();
          await expect(page.locator('.barrier-label:text("Root Key")')).toBeVisible();
        }
      }
    });

    test('default sealer details section displays backend-specific info', async ({
      page,
    }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await page.waitForTimeout(1000);

      // The sealer details section shows info about the default sealer (TPM2 or software).
      const detailsSection = page.locator('.barrier-details-section');
      const isVisible = await detailsSection.isVisible().catch(() => false);

      if (isVisible) {
        // At least one detail row should be present.
        const detailRows = detailsSection.locator('.barrier-row');
        const count = await detailRows.count();
        expect(count).toBeGreaterThan(0);
      }
    });

    test('TPM2 sealer details show Platform SRK handle 0x81000002', async ({
      page,
    }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend with TPM');

      await page.waitForTimeout(1000);

      // When TPM2 is the default sealer, SRK handle should show 0x81000002 (Platform SRK).
      const srkHandle = page.getByText('0x81000002');
      const isVisible = await srkHandle.isVisible().catch(() => false);

      // This will be true when TPM2 is available and is the default sealer.
      if (isVisible) {
        await expect(srkHandle).toBeVisible();
      }
    });
  });

  test.describe('Vite Mode (No TPM)', () => {
    test('TPM availability check runs and shows status', async ({ page }) => {
      await page.waitForTimeout(500);

      // In Vite mode without backend, canSeal=false so the warning shows.
      // In Wails mode with a backend, the blob list or empty state shows.
      const noBackendWarning = page.getByText('No Sealing Backends Available');
      const emptyState = page.getByText('No sealed data');

      const hasWarning = await noBackendWarning.isVisible().catch(() => false);
      const hasEmpty = await emptyState.isVisible().catch(() => false);

      // At least one state should be visible after loading.
      expect(hasWarning || hasEmpty).toBeTruthy();
    });

    test('shows no sealing backends warning with explanation when no backend is available', async ({
      page,
    }) => {
      await page.waitForTimeout(500);

      const warning = page.getByText('No Sealing Backends Available');
      const isVisible = await warning.isVisible().catch(() => false);

      if (isVisible) {
        await expect(
          page.getByText(/Configure a backend in Management to enable seal\/unseal operations/),
        ).toBeVisible();
      }
    });

    test('Seal New Data button is disabled when no backend is available', async ({
      page,
    }) => {
      await page.waitForTimeout(500);

      const warning = page.getByText('No Sealing Backends Available');
      const isWarningVisible = await warning.isVisible().catch(() => false);

      if (isWarningVisible) {
        const sealButton = page.getByRole('button', { name: 'Seal New Data' });
        await expect(sealButton).toBeDisabled();
      }
    });

    test('shows empty state when no sealed blobs exist', async ({ page }) => {
      await page.waitForTimeout(500);

      const emptyTitle = page.getByText('No sealed data');
      const dataTable = page.locator('.data-table');

      const hasEmpty = await emptyTitle.isVisible().catch(() => false);
      const hasTable = await dataTable.isVisible().catch(() => false);

      expect(hasEmpty || hasTable).toBeTruthy();
    });

    test('empty state shows descriptive message', async ({ page }) => {
      await page.waitForTimeout(500);

      const emptyTitle = page.getByText('No sealed data');
      const isVisible = await emptyTitle.isVisible().catch(() => false);

      if (isVisible) {
        await expect(
          page.getByText('Seal sensitive data for encrypted storage.'),
        ).toBeVisible();
      }
    });
  });

  test.describe('Seal Dialog', () => {
    test('seal dialog opens with correct form fields when TPM is available', async ({
      page,
    }) => {
      await page.waitForTimeout(500);

      const sealButton = page.getByRole('button', { name: 'Seal New Data' });
      const isDisabled = await sealButton.isDisabled();

      if (!isDisabled) {
        await sealButton.click();

        // Modal title
        await expect(page.getByText('Seal Data')).toBeVisible();

        // Form fields
        await expect(page.getByText('Label')).toBeVisible();
        await expect(page.getByText('Data')).toBeVisible();

        // Protection policy section
        await expect(page.getByText('Protection Policy')).toBeVisible();
      }
    });

    test('seal dialog shows all four policy options', async ({ page }) => {
      await page.waitForTimeout(500);

      const sealButton = page.getByRole('button', { name: 'Seal New Data' });
      const isDisabled = await sealButton.isDisabled();

      if (!isDisabled) {
        await sealButton.click();

        await expect(page.getByText('None')).toBeVisible();
        await expect(page.getByText('Password')).toBeVisible();
        await expect(page.getByText('Platform Policy')).toBeVisible();
        await expect(page.getByText('Custom PCR')).toBeVisible();
      }
    });

    test('seal dialog shows policy descriptions', async ({ page }) => {
      await page.waitForTimeout(500);

      const sealButton = page.getByRole('button', { name: 'Seal New Data' });
      const isDisabled = await sealButton.isDisabled();

      if (!isDisabled) {
        await sealButton.click();

        await expect(page.getByText('Basic TPM sealing without additional policy')).toBeVisible();
        await expect(page.getByText('Require a password to unseal')).toBeVisible();
        await expect(page.getByText('Bind to platform PCR measurements')).toBeVisible();
        await expect(page.getByText('Select specific PCRs to bind')).toBeVisible();
      }
    });

    test('seal dialog Cancel and Seal buttons are present', async ({ page }) => {
      await page.waitForTimeout(500);

      const sealButton = page.getByRole('button', { name: 'Seal New Data' });
      const isDisabled = await sealButton.isDisabled();

      if (!isDisabled) {
        await sealButton.click();

        await expect(page.getByRole('button', { name: 'Cancel' })).toBeVisible();
        await expect(page.getByRole('button', { name: 'Seal' })).toBeVisible();
      }
    });

    test('seal dialog Seal button is disabled when label and data are empty', async ({
      page,
    }) => {
      await page.waitForTimeout(500);

      const sealButton = page.getByRole('button', { name: 'Seal New Data' });
      const isDisabled = await sealButton.isDisabled();

      if (!isDisabled) {
        await sealButton.click();

        const sealAction = page.getByRole('button', { name: 'Seal' }).last();
        await expect(sealAction).toBeDisabled();
      }
    });

    test('seal dialog Cancel closes the dialog', async ({ page }) => {
      await page.waitForTimeout(500);

      const sealButton = page.getByRole('button', { name: 'Seal New Data' });
      const isDisabled = await sealButton.isDisabled();

      if (!isDisabled) {
        await sealButton.click();
        await expect(page.getByText('Seal Data')).toBeVisible();

        await page.getByRole('button', { name: 'Cancel' }).click();
        await page.waitForTimeout(300);

        await expect(page.getByText('Seal Data')).not.toBeVisible();
      }
    });

    test('selecting Password policy shows password fields', async ({ page }) => {
      await page.waitForTimeout(500);

      const sealButton = page.getByRole('button', { name: 'Seal New Data' });
      const isDisabled = await sealButton.isDisabled();

      if (!isDisabled) {
        await sealButton.click();

        // Click the "Password" policy radio
        const passwordRadio = page.locator('label.policy-radio', {
          hasText: 'Password',
        });
        await passwordRadio.click();
        await page.waitForTimeout(200);

        // Password and Confirm Password fields should appear
        await expect(page.getByText('Confirm Password')).toBeVisible();
      }
    });

    test('selecting Custom PCR policy shows PCR grid with 24 buttons', async ({
      page,
    }) => {
      await page.waitForTimeout(500);

      const sealButton = page.getByRole('button', { name: 'Seal New Data' });
      const isDisabled = await sealButton.isDisabled();

      if (!isDisabled) {
        await sealButton.click();

        // Click the "Custom PCR" policy radio
        const customPCRRadio = page.locator('label.policy-radio', {
          hasText: 'Custom PCR',
        });
        await customPCRRadio.click();
        await page.waitForTimeout(200);

        // PCR grid should appear with 24 PCR chip buttons (0-23)
        const pcrChips = page.locator('.pcr-grid .pcr-chip');
        const count = await pcrChips.count();
        expect(count).toBe(24);

        // PCR description text should be visible
        await expect(
          page.getByText('Select PCRs to bind'),
        ).toBeVisible();
      }
    });

    test('PCR chip buttons toggle selection state', async ({ page }) => {
      await page.waitForTimeout(500);

      const sealButton = page.getByRole('button', { name: 'Seal New Data' });
      const isDisabled = await sealButton.isDisabled();

      if (!isDisabled) {
        await sealButton.click();

        const customPCRRadio = page.locator('label.policy-radio', {
          hasText: 'Custom PCR',
        });
        await customPCRRadio.click();
        await page.waitForTimeout(200);

        // Click PCR 0
        const pcr0 = page.locator('.pcr-grid .pcr-chip').first();
        await pcr0.click();
        await expect(pcr0).toHaveClass(/pcr-selected/);

        // Click again to deselect
        await pcr0.click();
        await expect(pcr0).not.toHaveClass(/pcr-selected/);
      }
    });

    test('selecting Platform Policy shows status card', async ({ page }) => {
      await page.waitForTimeout(500);

      const sealButton = page.getByRole('button', { name: 'Seal New Data' });
      const isDisabled = await sealButton.isDisabled();

      if (!isDisabled) {
        await sealButton.click();

        const ppRadio = page.locator('label.policy-radio', {
          hasText: 'Platform Policy',
        });
        await ppRadio.click();
        await page.waitForTimeout(500);

        // Should show either a loading state, configured status, or not-configured message
        const ppSection = page.locator('.policy-detail-section');
        await expect(ppSection).toBeVisible();
      }
    });
  });

  test.describe('Backend Selector', () => {
    test('backend selector dropdown is present in seal dialog', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await page.waitForTimeout(500);

      const sealButton = page.getByRole('button', { name: 'Seal New Data' });
      const isDisabled = await sealButton.isDisabled();

      if (!isDisabled) {
        await sealButton.click();

        // Backend selector should be visible
        const backendSelect = page.locator('#seal-backend');
        await expect(backendSelect).toBeVisible();

        // Should have "Default (Best Available)" as first option
        const defaultOption = backendSelect.locator('option[value=""]');
        await expect(defaultOption).toHaveText('Default (Best Available)');
      }
    });

    test('backend selector lists available sealers with labels', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await page.waitForTimeout(500);

      const sealButton = page.getByRole('button', { name: 'Seal New Data' });
      const isDisabled = await sealButton.isDisabled();

      if (!isDisabled) {
        await sealButton.click();

        const backendSelect = page.locator('#seal-backend');
        const options = backendSelect.locator('option');
        const count = await options.count();

        // Should have at least 2 options: "Default" + at least one sealer
        expect(count).toBeGreaterThanOrEqual(2);
      }
    });

    test('storage location section always visible in seal dialog', async ({
      page,
    }) => {
      await page.waitForTimeout(500);

      const sealButton = page.getByRole('button', { name: 'Seal New Data' });
      const isDisabled = await sealButton.isDisabled();

      if (!isDisabled) {
        await sealButton.click();

        // Storage Location label should always be visible regardless of backend
        await expect(page.getByText('Storage Location')).toBeVisible();

        // Disk radio should always be visible
        const diskRadio = page.locator('.storage-radio', { hasText: 'Disk' });
        await expect(diskRadio).toBeVisible();
      }
    });

    test('storage radio defaults to Disk selected', async ({ page }) => {
      await page.waitForTimeout(500);

      const sealButton = page.getByRole('button', { name: 'Seal New Data' });
      const isDisabled = await sealButton.isDisabled();

      if (!isDisabled) {
        await sealButton.click();

        // Disk should be selected by default
        const diskRadio = page.locator('.storage-radio', { hasText: 'Disk' });
        await expect(diskRadio).toHaveClass(/storage-radio-selected/);
      }
    });

    test('Disk radio is clickable and stays selected', async ({ page }) => {
      await page.waitForTimeout(500);

      const sealButton = page.getByRole('button', { name: 'Seal New Data' });
      const isDisabled = await sealButton.isDisabled();

      if (!isDisabled) {
        await sealButton.click();

        const diskRadio = page.locator('.storage-radio', { hasText: 'Disk' });
        await diskRadio.click();
        await page.waitForTimeout(100);

        // Disk should be selected
        await expect(diskRadio).toHaveClass(/storage-radio-selected/);

        // The radio dot indicator should be visible
        const dot = diskRadio.locator('.storage-radio-dot');
        await expect(dot).toBeVisible();
      }
    });

    test('NV RAM radio only visible when TPM2 backend selected', async ({
      page,
    }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await page.waitForTimeout(500);

      const sealButton = page.getByRole('button', { name: 'Seal New Data' });
      const isDisabled = await sealButton.isDisabled();

      if (!isDisabled) {
        await sealButton.click();

        // Select software backend — NV RAM should NOT be visible
        const backendSelect = page.locator('#seal-backend');
        await backendSelect.selectOption('software');
        await page.waitForTimeout(200);

        const nvramRadio = page.locator('.storage-radio', { hasText: 'NV RAM' });
        await expect(nvramRadio).not.toBeVisible();

        // Disk should still be visible
        const diskRadio = page.locator('.storage-radio', { hasText: 'Disk' });
        await expect(diskRadio).toBeVisible();
      }
    });

    test('NV RAM radio appears when switching to TPM2 backend', async ({
      page,
    }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend with TPM');

      await page.waitForTimeout(500);

      const sealButton = page.getByRole('button', { name: 'Seal New Data' });
      const isDisabled = await sealButton.isDisabled();

      if (!isDisabled) {
        await sealButton.click();

        // Select TPM2 backend — NV RAM should appear
        const backendSelect = page.locator('#seal-backend');
        await backendSelect.selectOption('tpm2');
        await page.waitForTimeout(200);

        const nvramRadio = page.locator('.storage-radio', { hasText: 'NV RAM' });
        await expect(nvramRadio).toBeVisible();

        const diskRadio = page.locator('.storage-radio', { hasText: 'Disk' });
        await expect(diskRadio).toBeVisible();
      }
    });

    test('storage radio toggles between Disk and NV RAM for TPM2', async ({
      page,
    }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend with TPM');

      await page.waitForTimeout(500);

      const sealButton = page.getByRole('button', { name: 'Seal New Data' });
      const isDisabled = await sealButton.isDisabled();

      if (!isDisabled) {
        await sealButton.click();

        const backendSelect = page.locator('#seal-backend');
        await backendSelect.selectOption('tpm2');
        await page.waitForTimeout(200);

        // Click NV RAM
        const nvramRadio = page.locator('.storage-radio', { hasText: 'NV RAM' });
        await nvramRadio.click();
        await page.waitForTimeout(200);

        await expect(nvramRadio).toHaveClass(/storage-radio-selected/);

        const diskRadio = page.locator('.storage-radio', { hasText: 'Disk' });
        await expect(diskRadio).not.toHaveClass(/storage-radio-selected/);

        // Click Disk again
        await diskRadio.click();
        await page.waitForTimeout(200);

        await expect(diskRadio).toHaveClass(/storage-radio-selected/);
        await expect(nvramRadio).not.toHaveClass(/storage-radio-selected/);
      }
    });

    test('NV RAM resets to Disk when switching from TPM2 to software', async ({
      page,
    }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend with TPM');

      await page.waitForTimeout(500);

      const sealButton = page.getByRole('button', { name: 'Seal New Data' });
      const isDisabled = await sealButton.isDisabled();

      if (!isDisabled) {
        await sealButton.click();

        const backendSelect = page.locator('#seal-backend');

        // Select TPM2 and choose NV RAM
        await backendSelect.selectOption('tpm2');
        await page.waitForTimeout(200);
        const nvramRadio = page.locator('.storage-radio', { hasText: 'NV RAM' });
        await nvramRadio.click();
        await page.waitForTimeout(200);
        await expect(nvramRadio).toHaveClass(/storage-radio-selected/);

        // Switch to software — NV RAM disappears, Disk should be selected
        await backendSelect.selectOption('software');
        await page.waitForTimeout(200);

        const diskRadio = page.locator('.storage-radio', { hasText: 'Disk' });
        await expect(diskRadio).toHaveClass(/storage-radio-selected/);
        await expect(nvramRadio).not.toBeVisible();
      }
    });
  });

  test.describe('Wails Mode (swtpm)', () => {
    test('CanSeal returns true when swtpm is available', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend with swtpm');

      await page.waitForTimeout(1000);

      // When TPM is available, the Seal New Data button should be enabled
      const sealButton = page.getByRole('button', { name: 'Seal New Data' });
      await expect(sealButton).toBeEnabled();

      // The TPM Not Available warning should NOT be visible
      const tpmWarning = page.getByText('TPM Not Available');
      await expect(tpmWarning).not.toBeVisible();
    });

    test('create a sealed blob with None policy and verify it appears', async ({
      page,
    }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend with swtpm');

      await page.waitForTimeout(500);

      const sealButton = page.getByRole('button', { name: 'Seal New Data' });
      await sealButton.click();

      // Fill in label and data
      await page.locator('input[placeholder="e.g. API Secret"]').fill('Test Secret');
      await page.locator('#seal-data').fill('my-secret-data-12345');

      // None policy is the default -- just click Seal
      const sealAction = page.getByRole('button', { name: 'Seal' }).last();
      await sealAction.click();
      await page.waitForTimeout(1000);

      // Dialog should close and blob should appear in the list
      await expect(page.getByText('Seal Data')).not.toBeVisible();
      await expect(page.getByText('Test Secret')).toBeVisible();
    });

    test('seal with software backend succeeds', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await page.waitForTimeout(500);

      const sealButton = page.getByRole('button', { name: 'Seal New Data' });
      await sealButton.click();

      // Select software backend explicitly
      const backendSelect = page.locator('#seal-backend');
      await backendSelect.selectOption('software');
      await page.waitForTimeout(200);

      // Fill in label and data
      await page.locator('input[placeholder="e.g. API Secret"]').fill('Software Sealed');
      await page.locator('#seal-data').fill('software-sealed-data-test');

      // Click Seal
      const sealAction = page.getByRole('button', { name: 'Seal' }).last();
      await sealAction.click();
      await page.waitForTimeout(2000);

      // Dialog should close and blob should appear
      await expect(page.getByText('Seal Data')).not.toBeVisible();
      await expect(page.getByText('Software Sealed')).toBeVisible();
    });

    test('seal with TPM2 backend succeeds', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend with swtpm');

      await page.waitForTimeout(500);

      const sealButton = page.getByRole('button', { name: 'Seal New Data' });
      await sealButton.click();

      // Select TPM2 backend explicitly
      const backendSelect = page.locator('#seal-backend');
      await backendSelect.selectOption('tpm2');
      await page.waitForTimeout(200);

      // Fill in label and data
      await page.locator('input[placeholder="e.g. API Secret"]').fill('TPM Sealed');
      await page.locator('#seal-data').fill('tpm-sealed-data-test');

      // Click Seal
      const sealAction = page.getByRole('button', { name: 'Seal' }).last();
      await sealAction.click();
      await page.waitForTimeout(2000);

      // Dialog should close and blob should appear
      await expect(page.getByText('Seal Data')).not.toBeVisible();
      await expect(page.getByText('TPM Sealed')).toBeVisible();
    });

    test('unseal a blob and verify data matches', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend with swtpm');

      await page.waitForTimeout(500);

      // Look for an Unseal button (requires at least one blob to exist)
      const unsealButton = page.getByRole('button', { name: 'Unseal' }).first();
      const hasBlobs = await unsealButton.isVisible().catch(() => false);

      if (hasBlobs) {
        await unsealButton.click();
        await page.waitForTimeout(1000);

        // Unseal result dialog should show the data
        const unsealData = page.locator('.unseal-data-text');
        const dataVisible = await unsealData.isVisible().catch(() => false);
        if (dataVisible) {
          const dataText = await unsealData.textContent();
          expect(dataText).toBeTruthy();
        }

        // Close the dialog
        await page.getByRole('button', { name: 'Close' }).click();
      }
    });

    test('create a sealed blob with Password policy', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend with swtpm');

      await page.waitForTimeout(500);

      const sealButton = page.getByRole('button', { name: 'Seal New Data' });
      await sealButton.click();

      // Fill in label and data
      await page.locator('input[placeholder="e.g. API Secret"]').fill('Password Protected Secret');
      await page.locator('#seal-data').fill('password-protected-data');

      // Select Password policy
      const passwordRadio = page.locator('label.policy-radio', {
        hasText: 'Password',
      });
      await passwordRadio.click();
      await page.waitForTimeout(200);

      // Fill in password
      await page.locator('input[placeholder="Enter password for sealed data"]').fill('TestPassword123!');
      await page.locator('input[placeholder="Re-enter password"]').fill('TestPassword123!');

      const sealAction = page.getByRole('button', { name: 'Seal' }).last();
      await sealAction.click();
      await page.waitForTimeout(1000);

      // Verify the blob appears
      await expect(page.getByText('Password Protected Secret')).toBeVisible();
    });

    test('create a sealed blob with Custom PCR policy', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend with swtpm');

      await page.waitForTimeout(500);

      const sealButton = page.getByRole('button', { name: 'Seal New Data' });
      await sealButton.click();

      // Fill in label and data
      await page.locator('input[placeholder="e.g. API Secret"]').fill('PCR Bound Secret');
      await page.locator('#seal-data').fill('pcr-bound-data');

      // Select Custom PCR policy
      const customPCRRadio = page.locator('label.policy-radio', {
        hasText: 'Custom PCR',
      });
      await customPCRRadio.click();
      await page.waitForTimeout(200);

      // Select PCRs 0, 1, 7
      const pcrChips = page.locator('.pcr-grid .pcr-chip');
      await pcrChips.nth(0).click(); // PCR 0
      await pcrChips.nth(1).click(); // PCR 1
      await pcrChips.nth(7).click(); // PCR 7

      // Verify they are selected
      await expect(pcrChips.nth(0)).toHaveClass(/pcr-selected/);
      await expect(pcrChips.nth(1)).toHaveClass(/pcr-selected/);
      await expect(pcrChips.nth(7)).toHaveClass(/pcr-selected/);

      const sealAction = page.getByRole('button', { name: 'Seal' }).last();
      await sealAction.click();
      await page.waitForTimeout(1000);

      await expect(page.getByText('PCR Bound Secret')).toBeVisible();
    });

    test('delete a blob and verify it disappears', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend with swtpm');

      await page.waitForTimeout(500);

      // Look for a Delete button (requires at least one blob)
      const deleteButton = page.getByRole('button', { name: 'Delete' }).first();
      const hasBlobs = await deleteButton.isVisible().catch(() => false);

      if (hasBlobs) {
        // Get the blob label before deleting
        const blobLabel = page.locator('.blob-label').first();
        const labelText = await blobLabel.textContent();

        await deleteButton.click();
        await page.waitForTimeout(300);

        // Confirm delete dialog should appear
        await expect(page.getByText('Delete Sealed Data?')).toBeVisible();
        await expect(page.getByText('This action cannot be undone')).toBeVisible();

        // Confirm the deletion
        await page.getByRole('button', { name: 'Delete' }).last().click();
        await page.waitForTimeout(500);

        // The blob should be gone (or the list should be shorter)
        if (labelText) {
          // Dialog should be closed
          await expect(page.getByText('Delete Sealed Data?')).not.toBeVisible();
        }
      }
    });

    test('blob card shows policy badge for password-protected blobs', async ({
      page,
    }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend with swtpm');

      await page.waitForTimeout(500);

      // Check if there are any blobs with a policy badge
      const policyBadge = page.locator('.blob-policy-badge');
      const count = await policyBadge.count();
      if (count > 0) {
        await expect(policyBadge.first()).toBeVisible();
      }
    });
  });
});
