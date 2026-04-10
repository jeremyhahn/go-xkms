import { test, expect } from '@playwright/test';
import {
  navigateTo,
  waitForAppReady,
  ensureSidebarExpanded,
  isWailsMode,
  waitForLoadingComplete,
} from './helpers';

test.describe('PIV View', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
    await navigateTo(page, 'piv');
  });

  test.describe('Header and Layout', () => {
    test('PIV view loads with correct header', async ({ page }) => {
      await expect(page.getByText('PIV Smart Card')).toBeVisible();
      await expect(
        page.getByText('NIST SP 800-73 certificate slots'),
      ).toBeVisible();
    });

    test('PIV view has data-testid attribute', async ({ page }) => {
      await expect(page.locator('[data-testid="piv-view"]')).toBeVisible();
    });

    test('PIV content area is visible', async ({ page }) => {
      const content = page.locator('.piv-content');
      await expect(content).toBeVisible();
    });

    test('slots render in a 2-column grid', async ({ page }) => {
      const pivGrid = page.locator('.piv-grid');
      await expect(pivGrid).toBeVisible();
      const gridStyle = await pivGrid.evaluate((el) =>
        getComputedStyle(el).getPropertyValue('grid-template-columns'),
      );
      const columns = gridStyle.trim().split(/\s+/);
      expect(columns.length).toBe(2);
    });
  });

  test.describe('Slot Display', () => {
    test('displays all four default PIV slots by ID', async ({ page }) => {
      await expect(page.getByText('9A')).toBeVisible();
      await expect(page.getByText('9C')).toBeVisible();
      await expect(page.getByText('9D')).toBeVisible();
      await expect(page.getByText('9E')).toBeVisible();
    });

    test('displays slot labels for all four slots', async ({ page }) => {
      const pivGrid = page.locator('.piv-grid');
      await expect(pivGrid.getByText('PIV Authentication')).toBeVisible();
      await expect(pivGrid.getByText('Digital Signature')).toBeVisible();
      await expect(pivGrid.getByText('Key Management')).toBeVisible();
      await expect(pivGrid.getByText('Card Authentication').first()).toBeVisible();
    });

    test('displays slot purposes for all four slots', async ({ page }) => {
      await expect(
        page.getByText('General authentication, SSH, VPN'),
      ).toBeVisible();
      await expect(
        page.getByText('Code signing, document signing'),
      ).toBeVisible();
      await expect(page.getByText('Encryption, key exchange')).toBeVisible();
      await expect(
        page.getByText('Physical access, card authentication'),
      ).toBeVisible();
    });

    test('slot cards are present in the grid', async ({ page }) => {
      const slotCards = page.locator('.piv-grid .slot-card');
      const count = await slotCards.count();
      // defaultSlots includes 9A, 9C, 9D, 9E, and F9 (Attestation)
      expect(count).toBe(5);
    });

    test('each slot card has a data-testid attribute', async ({ page }) => {
      await expect(page.locator('[data-testid="piv-slot-card-9A"]')).toBeVisible();
      await expect(page.locator('[data-testid="piv-slot-card-9C"]')).toBeVisible();
      await expect(page.locator('[data-testid="piv-slot-card-9D"]')).toBeVisible();
      await expect(page.locator('[data-testid="piv-slot-card-9E"]')).toBeVisible();
    });
  });

  test.describe('Empty Slots', () => {
    test('empty slots show "Empty slot" text', async ({ page }) => {
      const emptySlots = page.locator('.slot-empty-text');
      const count = await emptySlots.count();
      // All 5 default slots (9A, 9C, 9D, 9E, F9) are empty in standalone mode.
      expect(count).toBe(5);
    });

    test('Generate Key button is visible for each empty slot', async ({
      page,
    }) => {
      // 9A, 9C, 9D, 9E have "Generate Key"; F9 (Attestation) has "Import Certificate"
      // Use data-testid to target the actual button elements, not the Card role="button"
      await expect(page.locator('[data-testid="piv-slot-action-9A"]')).toBeVisible();
      await expect(page.locator('[data-testid="piv-slot-action-9C"]')).toBeVisible();
      await expect(page.locator('[data-testid="piv-slot-action-9D"]')).toBeVisible();
      await expect(page.locator('[data-testid="piv-slot-action-9E"]')).toBeVisible();
    });

    test('empty slots have data-testid attributes', async ({ page }) => {
      await expect(page.locator('[data-testid="piv-slot-empty-9A"]')).toBeVisible();
      await expect(page.locator('[data-testid="piv-slot-empty-9C"]')).toBeVisible();
      await expect(page.locator('[data-testid="piv-slot-empty-9D"]')).toBeVisible();
      await expect(page.locator('[data-testid="piv-slot-empty-9E"]')).toBeVisible();
      await expect(page.locator('[data-testid="piv-slot-empty-F9"]')).toBeVisible();
    });
  });

  test.describe('Generate Key Dialog', () => {
    test('clicking Generate Key opens the generate dialog', async ({ page }) => {
      const generateButton = page.locator('[data-testid="piv-slot-action-9A"]');
      await generateButton.click();

      await expect(page.getByText('Generate PIV Key')).toBeVisible();
    });

    test('generate dialog has data-testid attribute', async ({ page }) => {
      const generateButton = page.locator('[data-testid="piv-slot-action-9A"]');
      await generateButton.click();

      await expect(page.locator('[data-testid="piv-generate-dialog"]')).toBeVisible();
    });

    test('generate dialog shows slot information', async ({ page }) => {
      const generateButton = page.locator('[data-testid="piv-slot-action-9A"]');
      await generateButton.click();

      await expect(page.locator('[data-testid="piv-generate-slot-info"]')).toContainText('9A');
    });

    test('generate dialog shows slot label alongside slot ID', async ({
      page,
    }) => {
      const generateButton = page.locator('[data-testid="piv-slot-action-9A"]');
      await generateButton.click();

      // The dialog shows "9A -- PIV Authentication"
      await expect(page.locator('[data-testid="piv-generate-slot-info"]')).toContainText('PIV Authentication');
    });

    test('generate dialog has algorithm selector with all options', async ({
      page,
    }) => {
      const generateButton = page.locator('[data-testid="piv-slot-action-9A"]');
      await generateButton.click();

      const algorithmSelect = page.locator('[data-testid="piv-algorithm-select"]');
      await expect(algorithmSelect).toBeVisible();

      const options = algorithmSelect.locator('option');
      const optionTexts = await options.allTextContents();
      expect(optionTexts).toContain('ECDSA P-256');
      expect(optionTexts).toContain('ECDSA P-384');
      expect(optionTexts).toContain('Ed25519');
      expect(optionTexts).toContain('RSA 2048');
      expect(optionTexts).toContain('RSA 4096');
    });

    test('ECDSA P-256 is selected by default', async ({ page }) => {
      const generateButton = page.locator('[data-testid="piv-slot-action-9A"]');
      await generateButton.click();

      const algorithmSelect = page.locator('[data-testid="piv-algorithm-select"]');
      await expect(algorithmSelect).toHaveValue('ECCP256');
    });

    test('generate dialog shows RSA warning when RSA algorithm is selected', async ({
      page,
    }) => {
      const generateButton = page.locator('[data-testid="piv-slot-action-9A"]');
      await generateButton.click();

      const algorithmSelect = page.locator('[data-testid="piv-algorithm-select"]');

      // Select RSA 2048
      await algorithmSelect.selectOption('RSA2048');
      await page.waitForTimeout(200);

      // Should show RSA generation time warning
      await expect(
        page.getByText(/RSA key generation may take several seconds/),
      ).toBeVisible();

      // Select ECDSA P-256 (non-RSA) and warning should disappear
      await algorithmSelect.selectOption('ECCP256');
      await page.waitForTimeout(200);
      await expect(
        page.getByText(/RSA key generation may take several seconds/),
      ).not.toBeVisible();
    });

    test('RSA 4096 also triggers the RSA warning', async ({ page }) => {
      const generateButton = page.locator('[data-testid="piv-slot-action-9A"]');
      await generateButton.click();

      const algorithmSelect = page.locator('[data-testid="piv-algorithm-select"]');
      await algorithmSelect.selectOption('RSA4096');
      await page.waitForTimeout(200);

      await expect(
        page.getByText(/RSA key generation may take several seconds/),
      ).toBeVisible();
    });

    test('Ed25519 does not trigger the RSA warning', async ({ page }) => {
      const generateButton = page.locator('[data-testid="piv-slot-action-9A"]');
      await generateButton.click();

      const algorithmSelect = page.locator('[data-testid="piv-algorithm-select"]');
      await algorithmSelect.selectOption('Ed25519');
      await page.waitForTimeout(200);

      await expect(
        page.getByText(/RSA key generation may take several seconds/),
      ).not.toBeVisible();
    });

    test('generate dialog has Cancel and Generate Key action buttons', async ({
      page,
    }) => {
      const generateButton = page.locator('[data-testid="piv-slot-action-9A"]');
      await generateButton.click();

      await expect(page.getByRole('button', { name: 'Cancel' })).toBeVisible();
      const dialogGenerate = page.getByRole('button', {
        name: /Generate Key|Generating/,
      });
      await expect(dialogGenerate.last()).toBeVisible();
    });

    test('generate dialog Cancel closes the dialog', async ({ page }) => {
      const generateButton = page.locator('[data-testid="piv-slot-action-9A"]');
      await generateButton.click();
      await expect(page.getByText('Generate PIV Key')).toBeVisible();

      await page.getByRole('button', { name: 'Cancel' }).click();
      await page.waitForTimeout(300);
      await expect(page.getByText('Generate PIV Key')).not.toBeVisible();
    });

    test('reopening dialog resets algorithm to ECDSA P-256', async ({ page }) => {
      const generateButton = page.locator('[data-testid="piv-slot-action-9A"]');
      await generateButton.click();

      // Change algorithm
      const algorithmSelect = page.locator('[data-testid="piv-algorithm-select"]');
      await algorithmSelect.selectOption('RSA4096');

      // Cancel
      await page.getByRole('button', { name: 'Cancel' }).click();
      await page.waitForTimeout(300);

      // Reopen
      await generateButton.click();
      await expect(algorithmSelect).toHaveValue('ECCP256');
    });

    test('each slot opens the dialog with correct slot information', async ({
      page,
    }) => {
      // Click the Generate Key button for slot 9C
      await page.locator('[data-testid="piv-slot-action-9C"]').click();
      await page.waitForTimeout(200);

      await expect(page.getByText('Generate PIV Key')).toBeVisible();
      await expect(page.locator('[data-testid="piv-generate-slot-info"]')).toContainText('9C');
      await expect(page.locator('[data-testid="piv-generate-slot-info"]')).toContainText('Digital Signature');

      // Close and test 9D
      await page.getByRole('button', { name: 'Cancel' }).click();
      await page.waitForTimeout(300);

      await page.locator('[data-testid="piv-slot-action-9D"]').click();
      await page.waitForTimeout(200);

      await expect(page.locator('[data-testid="piv-generate-slot-info"]')).toContainText('9D');
      await expect(page.locator('[data-testid="piv-generate-slot-info"]')).toContainText('Key Management');

      // Close and test 9E
      await page.getByRole('button', { name: 'Cancel' }).click();
      await page.waitForTimeout(300);

      await page.locator('[data-testid="piv-slot-action-9E"]').click();
      await page.waitForTimeout(200);

      await expect(page.locator('[data-testid="piv-generate-slot-info"]')).toContainText('9E');
      await expect(page.locator('[data-testid="piv-generate-slot-info"]')).toContainText('Card Authentication');

      await page.getByRole('button', { name: 'Cancel' }).click();
    });
  });

  test.describe('Slot Click Navigation', () => {
    test('clicking a slot card navigates to slot detail view', async ({
      page,
    }) => {
      // Click on the first slot card (not the Generate Key button, but the card itself)
      const slotCard = page.locator('[data-testid="piv-slot-card-9A"]');
      await slotCard.click();
      await page.waitForTimeout(300);

      // Should navigate to PIVSlot detail view
      await expect(page.locator('[data-testid="piv-slot-view"]')).toBeVisible();
    });

    test('slot detail view shows correct slot header', async ({ page }) => {
      const slotCard = page.locator('[data-testid="piv-slot-card-9A"]');
      await slotCard.click();
      await page.waitForTimeout(300);

      await expect(page.getByText('Slot 9A -- PIV Authentication')).toBeVisible();
    });

    test('slot detail view shows back button to PIV list', async ({ page }) => {
      const slotCard = page.locator('[data-testid="piv-slot-card-9A"]');
      await slotCard.click();
      await page.waitForTimeout(300);

      const backBtn = page.locator('.back-btn');
      await expect(backBtn).toBeVisible();
      await expect(backBtn).toContainText('PIV Smart Card');
    });

    test('back button returns to PIV grid view', async ({ page }) => {
      const slotCard = page.locator('[data-testid="piv-slot-card-9A"]');
      await slotCard.click();
      await page.waitForTimeout(300);

      await page.locator('.back-btn').click();
      await page.waitForTimeout(300);

      // Should be back at the PIV grid view
      await expect(page.locator('[data-testid="piv-view"]')).toBeVisible();
      await expect(page.getByText('PIV Smart Card')).toBeVisible();
    });

    test('empty slot detail view shows empty state with generate button', async ({
      page,
    }) => {
      const slotCard = page.locator('[data-testid="piv-slot-card-9A"]');
      await slotCard.click();
      await waitForLoadingComplete(page);

      await expect(page.locator('[data-testid="piv-slot-empty"]')).toBeVisible();
      await expect(page.getByText('Slot 9A is empty')).toBeVisible();
      await expect(page.getByRole('button', { name: 'Generate Key' })).toBeVisible();
    });

    test('navigating to each slot shows the correct empty state', async ({
      page,
    }) => {
      const slotTests = [
        { testid: 'piv-slot-card-9C', text: 'Slot 9C is empty', purpose: 'Code signing, document signing' },
        { testid: 'piv-slot-card-9D', text: 'Slot 9D is empty', purpose: 'Encryption, key exchange' },
        { testid: 'piv-slot-card-9E', text: 'Slot 9E is empty', purpose: 'Physical access, card authentication' },
      ];

      for (const st of slotTests) {
        await navigateTo(page, 'piv');
        const slotCard = page.locator(`[data-testid="${st.testid}"]`);
        await slotCard.click();
        await waitForLoadingComplete(page);

        await expect(page.getByText(st.text)).toBeVisible();
        await expect(page.getByText(st.purpose)).toBeVisible();
      }
    });
  });

  test.describe('Slot Detail Generate Key Dialog', () => {
    test('generate key dialog in slot detail view opens correctly', async ({
      page,
    }) => {
      // Navigate to slot 9A detail view
      const slotCard = page.locator('[data-testid="piv-slot-card-9A"]');
      await slotCard.click();
      await waitForLoadingComplete(page);

      // Click Generate Key button in the empty slot view
      await page.getByRole('button', { name: 'Generate Key' }).click();
      await page.waitForTimeout(200);

      // Dialog should appear
      await expect(page.locator('[data-testid="piv-generate-dialog"]')).toBeVisible();
      await expect(page.locator('[data-testid="piv-generate-slot-info"]')).toContainText('9A');
    });
  });

  test.describe('Wails Mode - Key Generation', () => {
    test('generate ECCP256 key in slot 9A and verify slot shows as loaded', async ({
      page,
    }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      // Click Generate Key for slot 9A
      const generateButton = page
        .locator('[data-testid="piv-slot-card-9A"]')
        .getByRole('button', { name: 'Generate Key' });
      await generateButton.click();

      // Verify dialog opened with correct slot
      await expect(page.locator('[data-testid="piv-generate-dialog"]')).toBeVisible();
      await expect(page.locator('[data-testid="piv-generate-slot-info"]')).toContainText('9A');

      // Default algorithm should be ECCP256
      await expect(page.locator('[data-testid="piv-algorithm-select"]')).toHaveValue('ECCP256');

      // Click Generate Key in dialog
      const dialogGenerate = page
        .getByRole('button', { name: /Generate Key|Generating/ })
        .last();
      await dialogGenerate.click();

      // Wait for generation to complete (dialog should close)
      await expect(page.locator('[data-testid="piv-generate-dialog"]')).not.toBeVisible({ timeout: 15_000 });

      // Slot 9A should now show as loaded (no more "Empty slot" for 9A)
      await expect(page.locator('[data-testid="piv-slot-empty-9A"]')).not.toBeVisible();

      // Slot should show certificate details
      await expect(page.locator('[data-testid="piv-slot-details-9A"]')).toBeVisible();
    });

    test('generate Ed25519 key in slot 9C', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      // Open dialog for slot 9C
      const generateButton = page
        .locator('[data-testid="piv-slot-card-9C"]')
        .getByRole('button', { name: 'Generate Key' });
      await generateButton.click();

      await expect(page.locator('[data-testid="piv-generate-slot-info"]')).toContainText('9C');

      // Select Ed25519
      await page.locator('[data-testid="piv-algorithm-select"]').selectOption('Ed25519');

      // Generate
      const dialogGenerate = page
        .getByRole('button', { name: /Generate Key|Generating/ })
        .last();
      await dialogGenerate.click();

      // Wait for completion
      await expect(page.locator('[data-testid="piv-generate-dialog"]')).not.toBeVisible({ timeout: 15_000 });

      // Slot 9C should now be loaded
      await expect(page.locator('[data-testid="piv-slot-details-9C"]')).toBeVisible();
    });

    test('generate ECCP384 key in slot 9D', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      const generateButton = page
        .locator('[data-testid="piv-slot-card-9D"]')
        .getByRole('button', { name: 'Generate Key' });
      await generateButton.click();

      await page.locator('[data-testid="piv-algorithm-select"]').selectOption('ECCP384');

      const dialogGenerate = page
        .getByRole('button', { name: /Generate Key|Generating/ })
        .last();
      await dialogGenerate.click();

      await expect(page.locator('[data-testid="piv-generate-dialog"]')).not.toBeVisible({ timeout: 15_000 });
      await expect(page.locator('[data-testid="piv-slot-details-9D"]')).toBeVisible();
    });

    test('generate RSA2048 key in slot 9E', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      const generateButton = page
        .locator('[data-testid="piv-slot-card-9E"]')
        .getByRole('button', { name: 'Generate Key' });
      await generateButton.click();

      await page.locator('[data-testid="piv-algorithm-select"]').selectOption('RSA2048');

      // Verify RSA warning appears
      await expect(
        page.getByText(/RSA key generation may take several seconds/),
      ).toBeVisible();

      const dialogGenerate = page
        .getByRole('button', { name: /Generate Key|Generating/ })
        .last();
      await dialogGenerate.click();

      // RSA takes longer
      await expect(page.locator('[data-testid="piv-generate-dialog"]')).not.toBeVisible({ timeout: 30_000 });
      await expect(page.locator('[data-testid="piv-slot-details-9E"]')).toBeVisible();
    });
  });

  test.describe('Wails Mode - Slot Detail Operations', () => {
    test.beforeEach(async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      // Generate a key in slot 9A first
      const generateButton = page
        .locator('[data-testid="piv-slot-card-9A"]')
        .getByRole('button', { name: 'Generate Key' });
      await generateButton.click();

      await expect(page.locator('[data-testid="piv-algorithm-select"]')).toHaveValue('ECCP256');

      const dialogGenerate = page
        .getByRole('button', { name: /Generate Key|Generating/ })
        .last();
      await dialogGenerate.click();

      await expect(page.locator('[data-testid="piv-generate-dialog"]')).not.toBeVisible({ timeout: 15_000 });
      await expect(page.locator('[data-testid="piv-slot-details-9A"]')).toBeVisible();
    });

    test('slot detail view shows certificate data after generation', async ({
      page,
    }) => {
      // Navigate to slot detail
      const slotCard = page.locator('[data-testid="piv-slot-card-9A"]');
      await slotCard.click();
      await waitForLoadingComplete(page);

      // Certificate details section should be visible
      await expect(page.locator('[data-testid="piv-cert-details"]')).toBeVisible();

      // Should show certificate fields
      await expect(page.getByText('Subject')).toBeVisible();
      await expect(page.getByText('Issuer')).toBeVisible();
      await expect(page.getByText('Algorithm')).toBeVisible();
      await expect(page.getByText('Valid From')).toBeVisible();
      await expect(page.getByText('Valid Until')).toBeVisible();

      // Should show ECDSA since we generated with ECCP256
      await expect(page.getByText('ECDSA')).toBeVisible();

      // Should show PIV Authentication as the subject (from self-signed cert)
      await expect(page.getByText(/PIV Authentication/)).toBeVisible();
    });

    test('slot detail view shows action buttons for loaded slot', async ({
      page,
    }) => {
      const slotCard = page.locator('[data-testid="piv-slot-card-9A"]');
      await slotCard.click();
      await waitForLoadingComplete(page);

      await expect(page.getByRole('button', { name: 'Export Certificate (PEM)' })).toBeVisible();
      await expect(page.getByRole('button', { name: 'Generate CSR' })).toBeVisible();
      await expect(page.getByRole('button', { name: 'Delete Key and Certificate' })).toBeVisible();
    });

    test('slot detail view shows fingerprint section', async ({ page }) => {
      const slotCard = page.locator('[data-testid="piv-slot-card-9A"]');
      await slotCard.click();
      await waitForLoadingComplete(page);

      await expect(page.getByText('Fingerprint (SHA-256)')).toBeVisible();
    });

    test('export certificate copies PEM to clipboard', async ({ page, context }) => {
      // Grant clipboard permissions
      await context.grantPermissions(['clipboard-read', 'clipboard-write']);

      const slotCard = page.locator('[data-testid="piv-slot-card-9A"]');
      await slotCard.click();
      await waitForLoadingComplete(page);

      await page.getByRole('button', { name: 'Export Certificate (PEM)' }).click();
      await page.waitForTimeout(1000);

      // Should show success notification
      await expect(page.getByText(/copied to clipboard|Certificate PEM/i)).toBeVisible({ timeout: 5_000 });
    });

    test('delete key and certificate shows confirmation dialog', async ({
      page,
    }) => {
      const slotCard = page.locator('[data-testid="piv-slot-card-9A"]');
      await slotCard.click();
      await waitForLoadingComplete(page);

      await page.getByRole('button', { name: 'Delete Key and Certificate' }).click();
      await page.waitForTimeout(200);

      // Confirmation dialog should appear
      await expect(page.getByText('Delete Key and Certificate?')).toBeVisible();
      await expect(page.getByText(/permanently delete/)).toBeVisible();
      await expect(page.getByRole('button', { name: 'Cancel' })).toBeVisible();
      await expect(page.getByRole('button', { name: 'Delete' })).toBeVisible();
    });

    test('cancel delete returns to slot detail without deleting', async ({
      page,
    }) => {
      const slotCard = page.locator('[data-testid="piv-slot-card-9A"]');
      await slotCard.click();
      await waitForLoadingComplete(page);

      await page.getByRole('button', { name: 'Delete Key and Certificate' }).click();
      await page.waitForTimeout(200);

      await page.getByRole('button', { name: 'Cancel' }).click();
      await page.waitForTimeout(300);

      // Should still be in loaded slot view with cert details
      await expect(page.locator('[data-testid="piv-cert-details"]')).toBeVisible();
    });

    test('confirm delete removes the key and returns to PIV grid', async ({
      page,
    }) => {
      const slotCard = page.locator('[data-testid="piv-slot-card-9A"]');
      await slotCard.click();
      await waitForLoadingComplete(page);

      await page.getByRole('button', { name: 'Delete Key and Certificate' }).click();
      await page.waitForTimeout(200);

      await page.getByRole('button', { name: 'Delete' }).click();
      await page.waitForTimeout(1000);

      // Should navigate back to PIV grid view
      await expect(page.locator('[data-testid="piv-view"]')).toBeVisible({ timeout: 5_000 });

      // Slot 9A should be empty again
      await expect(page.locator('[data-testid="piv-slot-empty-9A"]')).toBeVisible();
    });

    test('generate CSR opens CSR dialog', async ({ page }) => {
      const slotCard = page.locator('[data-testid="piv-slot-card-9A"]');
      await slotCard.click();
      await waitForLoadingComplete(page);

      await page.getByRole('button', { name: 'Generate CSR' }).click();
      await page.waitForTimeout(200);

      // CSR dialog should appear with common name field
      await expect(page.getByText(/Common Name/i)).toBeVisible();
    });
  });

  test.describe('Wails Mode - Full Lifecycle', () => {
    test('generate, view, and delete a key in slot 9A', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      // Step 1: Generate key
      const generateButton = page
        .locator('[data-testid="piv-slot-card-9A"]')
        .getByRole('button', { name: 'Generate Key' });
      await generateButton.click();
      await page.locator('[data-testid="piv-algorithm-select"]').selectOption('ECCP256');

      const dialogGenerate = page
        .getByRole('button', { name: /Generate Key|Generating/ })
        .last();
      await dialogGenerate.click();
      await expect(page.locator('[data-testid="piv-generate-dialog"]')).not.toBeVisible({ timeout: 15_000 });

      // Step 2: Verify slot shows as loaded
      await expect(page.locator('[data-testid="piv-slot-details-9A"]')).toBeVisible();

      // Step 3: View certificate details
      const slotCard = page.locator('[data-testid="piv-slot-card-9A"]');
      await slotCard.click();
      await waitForLoadingComplete(page);

      await expect(page.locator('[data-testid="piv-cert-details"]')).toBeVisible();
      await expect(page.getByText('ECDSA')).toBeVisible();

      // Step 4: Delete the key
      await page.getByRole('button', { name: 'Delete Key and Certificate' }).click();
      await page.waitForTimeout(200);
      await page.getByRole('button', { name: 'Delete' }).click();

      // Step 5: Verify slot is empty again
      await expect(page.locator('[data-testid="piv-view"]')).toBeVisible({ timeout: 5_000 });
      await expect(page.locator('[data-testid="piv-slot-empty-9A"]')).toBeVisible();
    });
  });
});
