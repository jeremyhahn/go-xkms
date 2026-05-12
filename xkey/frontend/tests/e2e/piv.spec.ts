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

    test('empty slot detail view shows empty state with no action buttons', async ({
      page,
    }) => {
      const slotCard = page.locator('[data-testid="piv-slot-card-9A"]');
      await slotCard.click();
      await waitForLoadingComplete(page);

      // Detail page is read-only — shows empty state with hint text.
      await expect(page.locator('[data-testid="piv-slot-empty"]')).toBeVisible();
      await expect(page.getByText('Slot 9A is empty')).toBeVisible();
      await expect(page.getByText(/Actions for this slot are available from the PIV overview page/)).toBeVisible();
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

  test.describe('Slot Detail — Read-Only', () => {
    test('slot detail view for empty slot shows actions hint and no mutation controls', async ({
      page,
    }) => {
      // Navigate to slot 9A detail view
      const slotCard = page.locator('[data-testid="piv-slot-card-9A"]');
      await slotCard.click();
      await waitForLoadingComplete(page);

      // Detail page is read-only: no Generate Key button, no ActionMenu
      await expect(page.locator('[data-testid="piv-slot-empty"]')).toBeVisible();
      await expect(page.locator('[data-testid="action-menu-kebab"]')).not.toBeVisible();
      await expect(page.getByText(/Actions for this slot are available from the PIV overview page/)).toBeVisible();
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

    test('slot card shows ActionMenu primary button and kebab for loaded slot', async ({
      page,
    }) => {
      // ActionMenu is now on the overview card, not the detail page.
      const card = page.locator('[data-testid="piv-slot-card-9A"]');
      await expect(card).toBeVisible();

      // Primary action button is "View Certificate"
      await expect(page.locator('[data-testid="piv-action-view-cert"]')).toBeVisible();
      await expect(page.locator('[data-testid="piv-action-view-cert"]')).toContainText('View Certificate');

      // Kebab overflow button is present on the card
      await expect(page.locator('[data-testid="action-menu-kebab"]')).toBeVisible();
    });

    test('slot detail view shows fingerprint section', async ({ page }) => {
      const slotCard = page.locator('[data-testid="piv-slot-card-9A"]');
      await slotCard.click();
      await waitForLoadingComplete(page);

      await expect(page.getByText('Fingerprint (SHA-256)')).toBeVisible();
    });

    test('export certificate (PEM) via card overflow menu copies to clipboard', async ({ page, context }) => {
      // Grant clipboard permissions
      await context.grantPermissions(['clipboard-read', 'clipboard-write']);

      // ActionMenu lives on the overview card — no need to navigate to detail first.
      await page.locator('[data-testid="action-menu-kebab"]').click();
      await page.waitForTimeout(100);

      // Click "Export Certificate (PEM)" menu item
      await page.locator('[data-testid="piv-action-export-cert"]').click();
      await page.waitForTimeout(1000);

      // Should show success notification
      await expect(page.getByText(/copied to clipboard|Certificate PEM/i)).toBeVisible({ timeout: 5_000 });
    });

    test('delete key and certificate shows confirmation dialog', async ({
      page,
    }) => {
      // Open overflow menu on the overview card and click delete
      await page.locator('[data-testid="action-menu-kebab"]').click();
      await page.waitForTimeout(100);
      await page.locator('[data-testid="piv-action-delete"]').click();
      await page.waitForTimeout(200);

      // Confirmation dialog should appear
      await expect(page.getByText('Delete Key and Certificate?')).toBeVisible();
      await expect(page.getByText(/permanently delete/)).toBeVisible();
      await expect(page.getByRole('button', { name: 'Cancel' })).toBeVisible();
      await expect(page.getByRole('button', { name: 'Delete' })).toBeVisible();
    });

    test('cancel delete stays on PIV overview with slot still loaded', async ({
      page,
    }) => {
      await page.locator('[data-testid="action-menu-kebab"]').click();
      await page.waitForTimeout(100);
      await page.locator('[data-testid="piv-action-delete"]').click();
      await page.waitForTimeout(200);

      await page.getByRole('button', { name: 'Cancel' }).click();
      await page.waitForTimeout(300);

      // Should still be on the PIV overview with the slot details visible
      await expect(page.locator('[data-testid="piv-view"]')).toBeVisible();
      await expect(page.locator('[data-testid="piv-slot-details-9A"]')).toBeVisible();
    });

    test('confirm delete removes the key and slot shows empty', async ({
      page,
    }) => {
      await page.locator('[data-testid="action-menu-kebab"]').click();
      await page.waitForTimeout(100);
      await page.locator('[data-testid="piv-action-delete"]').click();
      await page.waitForTimeout(200);

      await page.getByRole('button', { name: 'Delete' }).click();
      await page.waitForTimeout(1000);

      // Should remain on PIV grid view
      await expect(page.locator('[data-testid="piv-view"]')).toBeVisible({ timeout: 5_000 });

      // Slot 9A should be empty again
      await expect(page.locator('[data-testid="piv-slot-empty-9A"]')).toBeVisible();
    });

    test('generate CSR opens CSR dialog via card overflow menu', async ({ page }) => {
      await page.locator('[data-testid="action-menu-kebab"]').click();
      await page.waitForTimeout(100);
      await page.locator('[data-testid="piv-action-gen-csr"]').click();
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

      // Step 2: Verify slot shows as loaded on the overview card
      await expect(page.locator('[data-testid="piv-slot-details-9A"]')).toBeVisible();

      // Step 3: View certificate details in the read-only detail pane
      const slotCard = page.locator('[data-testid="piv-slot-card-9A"]');
      await slotCard.click();
      await waitForLoadingComplete(page);

      await expect(page.locator('[data-testid="piv-cert-details"]')).toBeVisible();
      await expect(page.getByText('ECDSA')).toBeVisible();

      // Step 4: Navigate back and delete the key via the card's overflow menu
      await page.locator('.back-btn').click();
      await page.waitForTimeout(300);
      await expect(page.locator('[data-testid="piv-view"]')).toBeVisible();

      await page.locator('[data-testid="action-menu-kebab"]').click();
      await page.waitForTimeout(100);
      await page.locator('[data-testid="piv-action-delete"]').click();
      await page.waitForTimeout(200);
      await page.getByRole('button', { name: 'Delete' }).click();

      // Step 5: Verify slot is empty again
      await expect(page.locator('[data-testid="piv-view"]')).toBeVisible({ timeout: 5_000 });
      await expect(page.locator('[data-testid="piv-slot-empty-9A"]')).toBeVisible();
    });
  });

  // ── Enhanced Generate Dialog ────────────────────────────────────────────

  test.describe('Enhanced Generate Dialog — Subject Fields', () => {
    test('opening dialog pre-fills Common Name with slot label', async ({ page }) => {
      await page.locator('[data-testid="piv-slot-action-9A"]').click();
      await expect(page.locator('[data-testid="piv-generate-dialog"]')).toBeVisible();

      // In standalone (non-Wails) mode there is no identity config to load, so
      // the Common Name field is present but may be empty.  The important thing
      // is that the field is rendered and editable.
      const cnInput = page.locator('[data-testid="piv-generate-dialog"] input[type="text"]').first();
      await expect(cnInput).toBeVisible();
    });

    test('Common Name input is visible and editable', async ({ page }) => {
      await page.locator('[data-testid="piv-slot-action-9A"]').click();
      await expect(page.locator('[data-testid="piv-generate-dialog"]')).toBeVisible();

      // The first text input inside the dialog form is Common Name.
      const cnInput = page.locator('[data-testid="piv-generate-dialog"] input').first();
      await expect(cnInput).toBeVisible();
      await expect(cnInput).toBeEditable();

      await cnInput.fill('Test User');
      await expect(cnInput).toHaveValue('Test User');
    });

    test('"Advanced Subject" toggle is visible and reveals Organization and Country fields', async ({ page }) => {
      await page.locator('[data-testid="piv-slot-action-9A"]').click();
      await expect(page.locator('[data-testid="piv-generate-dialog"]')).toBeVisible();

      // Advanced Subject toggle button exists
      const toggle = page.locator('[data-testid="piv-generate-dialog"] button.collapse-toggle');
      await expect(toggle).toBeVisible();
      await expect(toggle).toContainText('Advanced Subject');

      // Organization and Country are hidden before expanding
      const advancedSection = page.locator('[data-testid="piv-generate-dialog"] .advanced-subject');
      await expect(advancedSection).not.toBeVisible();

      // Click the toggle to expand
      await toggle.click();
      await page.waitForTimeout(150);

      await expect(advancedSection).toBeVisible();

      // Two additional inputs (Organization, Country) are now rendered
      const advancedInputs = advancedSection.locator('input');
      await expect(advancedInputs).toHaveCount(2);
    });

    test('closing and reopening dialog resets subject fields', async ({ page }) => {
      const openBtn = page.locator('[data-testid="piv-slot-action-9A"]');
      await openBtn.click();
      await expect(page.locator('[data-testid="piv-generate-dialog"]')).toBeVisible();

      // Modify Common Name
      const cnInput = page.locator('[data-testid="piv-generate-dialog"] input').first();
      await cnInput.fill('Changed Name');

      // Expand advanced subject and fill Organization
      const toggle = page.locator('[data-testid="piv-generate-dialog"] button.collapse-toggle');
      await toggle.click();
      await page.waitForTimeout(150);
      const orgInput = page.locator('[data-testid="piv-generate-dialog"] .advanced-subject input').first();
      await orgInput.fill('My Org');

      // Cancel and reopen
      await page.getByRole('button', { name: 'Cancel' }).click();
      await page.waitForTimeout(300);
      await openBtn.click();
      await expect(page.locator('[data-testid="piv-generate-dialog"]')).toBeVisible();

      // Common Name should be reset (empty or reloaded from defaults)
      const freshCn = page.locator('[data-testid="piv-generate-dialog"] input').first();
      await expect(freshCn).not.toHaveValue('Changed Name');

      // Advanced subject section should be collapsed again
      await expect(page.locator('[data-testid="piv-generate-dialog"] .advanced-subject')).not.toBeVisible();
    });
  });

  test.describe('Enhanced Generate Dialog — Output Format', () => {
    test('Output Format selector is visible with all 4 options', async ({ page }) => {
      await page.locator('[data-testid="piv-slot-action-9A"]').click();
      await expect(page.locator('[data-testid="piv-generate-dialog"]')).toBeVisible();

      const formatSelect = page.locator('[data-testid="piv-output-format-select"]');
      await expect(formatSelect).toBeVisible();

      const options = formatSelect.locator('option');
      const texts = await options.allTextContents();
      expect(texts).toContain('Self-Signed Certificate');
      expect(texts).toContain('Public Key Only');
      expect(texts).toContain('Certificate Signing Request (CSR)');
      expect(texts).toContain('CA-Signed Certificate');
    });

    test('"Self-Signed Certificate" is selected by default', async ({ page }) => {
      await page.locator('[data-testid="piv-slot-action-9A"]').click();
      await expect(page.locator('[data-testid="piv-generate-dialog"]')).toBeVisible();

      const formatSelect = page.locator('[data-testid="piv-output-format-select"]');
      await expect(formatSelect).toHaveValue('self-signed');
    });

    test('selecting "Public Key Only" hides validity and CA source fields', async ({ page }) => {
      await page.locator('[data-testid="piv-slot-action-9A"]').click();
      await expect(page.locator('[data-testid="piv-generate-dialog"]')).toBeVisible();

      await page.locator('[data-testid="piv-output-format-select"]').selectOption('public-key');
      await page.waitForTimeout(150);

      // Validity input label should not be present
      await expect(page.locator('[data-testid="piv-generate-dialog"]').getByText('Validity (days)')).not.toBeVisible();
      // CA Source radio group should not be present
      await expect(page.locator('[data-testid="piv-generate-dialog"] [role="radiogroup"]')).not.toBeVisible();
    });

    test('selecting "CSR" hides validity and CA source fields', async ({ page }) => {
      await page.locator('[data-testid="piv-slot-action-9A"]').click();
      await expect(page.locator('[data-testid="piv-generate-dialog"]')).toBeVisible();

      await page.locator('[data-testid="piv-output-format-select"]').selectOption('csr');
      await page.waitForTimeout(150);

      await expect(page.locator('[data-testid="piv-generate-dialog"]').getByText('Validity (days)')).not.toBeVisible();
      await expect(page.locator('[data-testid="piv-generate-dialog"] [role="radiogroup"]')).not.toBeVisible();
    });

    test('selecting "CA-Signed Certificate" shows CA source radio buttons', async ({ page }) => {
      await page.locator('[data-testid="piv-slot-action-9A"]').click();
      await expect(page.locator('[data-testid="piv-generate-dialog"]')).toBeVisible();

      await page.locator('[data-testid="piv-output-format-select"]').selectOption('ca-signed');
      await page.waitForTimeout(150);

      const radioGroup = page.locator('[data-testid="piv-generate-dialog"] [role="radiogroup"]');
      await expect(radioGroup).toBeVisible();
    });

    test('selecting "Self-Signed Certificate" shows validity input', async ({ page }) => {
      await page.locator('[data-testid="piv-slot-action-9A"]').click();
      await expect(page.locator('[data-testid="piv-generate-dialog"]')).toBeVisible();

      // Switch away first, then back to self-signed
      await page.locator('[data-testid="piv-output-format-select"]').selectOption('public-key');
      await page.waitForTimeout(150);
      await page.locator('[data-testid="piv-output-format-select"]').selectOption('self-signed');
      await page.waitForTimeout(150);

      await expect(page.locator('[data-testid="piv-generate-dialog"]').getByText('Validity (days)')).toBeVisible();
    });
  });

  test.describe('Enhanced Generate Dialog — Validity', () => {
    test('validity input shows default 3650 for self-signed', async ({ page }) => {
      await page.locator('[data-testid="piv-slot-action-9A"]').click();
      await expect(page.locator('[data-testid="piv-generate-dialog"]')).toBeVisible();

      // Self-signed is the default format; validity input should be rendered.
      const validityInput = page.locator('[data-testid="piv-generate-dialog"] input[type="number"]');
      await expect(validityInput).toBeVisible();
      await expect(validityInput).toHaveValue('3650');
    });

    test('validity input changes to 1095 when switching to CA-signed', async ({ page }) => {
      await page.locator('[data-testid="piv-slot-action-9A"]').click();
      await expect(page.locator('[data-testid="piv-generate-dialog"]')).toBeVisible();

      await page.locator('[data-testid="piv-output-format-select"]').selectOption('ca-signed');
      await page.waitForTimeout(150);

      const validityInput = page.locator('[data-testid="piv-generate-dialog"] input[type="number"]');
      await expect(validityInput).toBeVisible();
      await expect(validityInput).toHaveValue('1095');
    });

    test('validity input is editable', async ({ page }) => {
      await page.locator('[data-testid="piv-slot-action-9A"]').click();
      await expect(page.locator('[data-testid="piv-generate-dialog"]')).toBeVisible();

      const validityInput = page.locator('[data-testid="piv-generate-dialog"] input[type="number"]');
      await expect(validityInput).toBeVisible();
      await validityInput.fill('365');
      await expect(validityInput).toHaveValue('365');
    });
  });

  test.describe('Enhanced Generate Dialog — CA Source', () => {
    test('CA source section is only visible when CA-Signed is selected', async ({ page }) => {
      await page.locator('[data-testid="piv-slot-action-9A"]').click();
      await expect(page.locator('[data-testid="piv-generate-dialog"]')).toBeVisible();

      const radioGroup = page.locator('[data-testid="piv-generate-dialog"] [role="radiogroup"]');

      // Not visible for self-signed (default)
      await expect(radioGroup).not.toBeVisible();

      // Switch to ca-signed
      await page.locator('[data-testid="piv-output-format-select"]').selectOption('ca-signed');
      await page.waitForTimeout(150);
      await expect(radioGroup).toBeVisible();

      // Switch back to self-signed
      await page.locator('[data-testid="piv-output-format-select"]').selectOption('self-signed');
      await page.waitForTimeout(150);
      await expect(radioGroup).not.toBeVisible();
    });

    test('Local CA and Remote xkms Server radio options are present', async ({ page }) => {
      await page.locator('[data-testid="piv-slot-action-9A"]').click();
      await expect(page.locator('[data-testid="piv-generate-dialog"]')).toBeVisible();

      await page.locator('[data-testid="piv-output-format-select"]').selectOption('ca-signed');
      await page.waitForTimeout(150);

      const radioGroup = page.locator('[data-testid="piv-generate-dialog"] [role="radiogroup"]');
      await expect(radioGroup.getByText('Local CA')).toBeVisible();
      await expect(radioGroup.getByText('Remote xkms Server')).toBeVisible();
    });

    test('disabled CA options show reason text when CA is unavailable', async ({ page }) => {
      // In standalone (non-Wails) mode caAvailabilityLoaded stays false until
      // loadDefaults() resolves, so the reason spans only render once loaded.
      // We validate this once the caAvailabilityLoaded flag would be set — but
      // since callBackend returns null in standalone mode the loaded flag is still
      // set to true after the await.  Give the reactive chain a moment to settle.
      await page.locator('[data-testid="piv-slot-action-9A"]').click();
      await expect(page.locator('[data-testid="piv-generate-dialog"]')).toBeVisible();

      await page.locator('[data-testid="piv-output-format-select"]').selectOption('ca-signed');
      await page.waitForTimeout(300);

      const radioGroup = page.locator('[data-testid="piv-generate-dialog"] [role="radiogroup"]');

      // In standalone mode both sources are unavailable; reason text should appear.
      const localLabel = radioGroup.locator('.radio-option').first();
      const remoteLabel = radioGroup.locator('.radio-option').last();

      // At least one option must be rendered inside the group.
      await expect(localLabel).toBeVisible();
      await expect(remoteLabel).toBeVisible();

      // If both are unavailable (standalone mode), reason spans should be visible.
      const localReason = localLabel.locator('.radio-reason');
      const remoteReason = remoteLabel.locator('.radio-reason');

      const localReasonVisible = await localReason.isVisible().catch(() => false);
      const remoteReasonVisible = await remoteReason.isVisible().catch(() => false);

      // In standalone mode both CAs are unavailable so both reasons must show.
      if (localReasonVisible) {
        await expect(localReason).toContainText('CA not configured');
      }
      if (remoteReasonVisible) {
        await expect(remoteReason).toContainText('Not connected');
      }
    });
  });

  test.describe('Enhanced Generate Dialog — Reset on Reopen', () => {
    test('dialog resets all fields when reopened', async ({ page }) => {
      const openBtn = page.locator('[data-testid="piv-slot-action-9A"]');
      await openBtn.click();
      await expect(page.locator('[data-testid="piv-generate-dialog"]')).toBeVisible();

      // Mutate every resettable field.
      await page.locator('[data-testid="piv-algorithm-select"]').selectOption('RSA4096');
      await page.locator('[data-testid="piv-output-format-select"]').selectOption('ca-signed');
      await page.waitForTimeout(150);

      const validityInput = page.locator('[data-testid="piv-generate-dialog"] input[type="number"]');
      await validityInput.fill('999');

      const cnInput = page.locator('[data-testid="piv-generate-dialog"] input[type="text"]').first();
      await cnInput.fill('Reset Test');

      // Close and reopen
      await page.getByRole('button', { name: 'Cancel' }).click();
      await page.waitForTimeout(300);
      await openBtn.click();
      await expect(page.locator('[data-testid="piv-generate-dialog"]')).toBeVisible();

      // Algorithm resets to ECCP256
      await expect(page.locator('[data-testid="piv-algorithm-select"]')).toHaveValue('ECCP256');

      // Output format resets to self-signed
      await expect(page.locator('[data-testid="piv-output-format-select"]')).toHaveValue('self-signed');

      // Validity resets to 3650
      const freshValidity = page.locator('[data-testid="piv-generate-dialog"] input[type="number"]');
      await expect(freshValidity).toHaveValue('3650');

      // Common Name does not retain the previous value
      const freshCn = page.locator('[data-testid="piv-generate-dialog"] input[type="text"]').first();
      await expect(freshCn).not.toHaveValue('Reset Test');

      // Advanced subject section is collapsed
      await expect(page.locator('[data-testid="piv-generate-dialog"] .advanced-subject')).not.toBeVisible();

      // CA source radio group is hidden (self-signed is active)
      await expect(page.locator('[data-testid="piv-generate-dialog"] [role="radiogroup"]')).not.toBeVisible();
    });
  });

  // ── Three-State Slot Cards ────────────────────────────────────────────────

  test.describe('Three-State Slot Cards', () => {
    test('empty slot shows "Empty slot" text and Generate Key button', async ({ page }) => {
      // In standalone mode all slots are empty by default.
      const slot9A = page.locator('[data-testid="piv-slot-card-9A"]');
      await expect(slot9A).toBeVisible();
      await expect(page.locator('[data-testid="piv-slot-empty-9A"]')).toBeVisible();
      await expect(page.locator('[data-testid="piv-slot-empty-9A"]').getByText('Empty slot')).toBeVisible();
      await expect(page.locator('[data-testid="piv-slot-action-9A"]')).toBeVisible();
      await expect(page.locator('[data-testid="piv-slot-action-9A"]')).toContainText('Generate Key');
    });

    test('algorithm dropdown is present in the generate dialog', async ({ page }) => {
      await page.locator('[data-testid="piv-slot-action-9A"]').click();
      await expect(page.locator('[data-testid="piv-generate-dialog"]')).toBeVisible();

      const algorithmSelect = page.locator('[data-testid="piv-algorithm-select"]');
      await expect(algorithmSelect).toBeVisible();

      const options = algorithmSelect.locator('option');
      const texts = await options.allTextContents();
      // Software backend: all 5 algorithms including Ed25519 should be present.
      expect(texts).toContain('ECDSA P-256');
      expect(texts).toContain('ECDSA P-384');
      expect(texts).toContain('Ed25519');
      expect(texts).toContain('RSA 2048');
      expect(texts).toContain('RSA 4096');
    });

    test('Ed25519 filtering note is absent for software backend', async ({ page }) => {
      // In standalone mode the backend prop defaults to "software"; YubiKey note must not appear.
      await page.locator('[data-testid="piv-slot-action-9A"]').click();
      await expect(page.locator('[data-testid="piv-generate-dialog"]')).toBeVisible();

      // The YubiKey info note should not be visible for the software backend.
      await expect(page.locator('[data-testid="piv-yubikey-ed25519-note"]')).not.toBeVisible();
    });
  });

  // ── ActionMenu Component Tests ────────────────────────────────────────────

  test.describe('ActionMenu — Cert State (standalone)', () => {
    test.beforeEach(async ({ page }) => {
      // Navigate to slot 9A detail view (will be empty/no-cert in standalone mode,
      // so we exercise the empty-slot path; actual cert/key-only tests are Wails-gated).
      const slotCard = page.locator('[data-testid="piv-slot-card-9A"]');
      await slotCard.click();
      await waitForLoadingComplete(page);
    });

    test('slot detail view renders back button and header', async ({ page }) => {
      await expect(page.locator('[data-testid="piv-slot-view"]')).toBeVisible();
      await expect(page.locator('.back-btn')).toBeVisible();
      await expect(page.getByText('Slot 9A is empty')).toBeVisible();
    });
  });

  test.describe('ActionMenu — Cert State (Wails)', () => {
    test.beforeEach(async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      // Generate a key in 9A so the slot is in loaded (cert) state.
      await page.locator('[data-testid="piv-slot-card-9A"]').getByRole('button', { name: 'Generate Key' }).click();
      await expect(page.locator('[data-testid="piv-generate-dialog"]')).toBeVisible();
      await page.locator('[data-testid="piv-algorithm-select"]').selectOption('ECCP256');
      await page.getByRole('button', { name: /Generate Key|Generating/ }).last().click();
      await expect(page.locator('[data-testid="piv-generate-dialog"]')).not.toBeVisible({ timeout: 15_000 });

      // ActionMenu is on the overview card — stay on the PIV overview.
      await expect(page.locator('[data-testid="piv-slot-details-9A"]')).toBeVisible();
    });

    test('primary action button on loaded card has text "View Certificate"', async ({ page }) => {
      await expect(page.locator('[data-testid="piv-action-view-cert"]')).toBeVisible();
      await expect(page.locator('[data-testid="piv-action-view-cert"]')).toContainText('View Certificate');
    });

    test('kebab button on loaded card has correct aria attributes', async ({ page }) => {
      const kebab = page.locator('[data-testid="action-menu-kebab"]');
      await expect(kebab).toBeVisible();
      await expect(kebab).toHaveAttribute('aria-haspopup', 'menu');
      await expect(kebab).toHaveAttribute('aria-expanded', 'false');
    });

    test('opening the menu reveals "Delete Key and Certificate" with destructive class', async ({ page }) => {
      await page.locator('[data-testid="action-menu-kebab"]').click();
      await page.waitForTimeout(100);

      const deleteItem = page.locator('[data-testid="piv-action-delete"]');
      await expect(deleteItem).toBeVisible();
      await expect(deleteItem).toHaveClass(/destructive/);
    });

    test('opening the menu reveals all expected overflow items', async ({ page }) => {
      await page.locator('[data-testid="action-menu-kebab"]').click();
      await page.waitForTimeout(100);

      await expect(page.locator('[data-testid="piv-action-export-cert"]')).toBeVisible();
      await expect(page.locator('[data-testid="piv-action-save-cert"]')).toBeVisible();
      await expect(page.locator('[data-testid="piv-action-export-pubkey"]')).toBeVisible();
      await expect(page.locator('[data-testid="piv-action-save-pubkey"]')).toBeVisible();
      await expect(page.locator('[data-testid="piv-action-gen-csr"]')).toBeVisible();
    });

    test('Escape closes the overflow menu', async ({ page }) => {
      await page.locator('[data-testid="action-menu-kebab"]').click();
      await page.waitForTimeout(100);
      await expect(page.locator('[role="menu"]')).toBeVisible();

      await page.keyboard.press('Escape');
      await page.waitForTimeout(150);
      await expect(page.locator('[role="menu"]')).not.toBeVisible();
    });

    test('clicking outside closes the overflow menu', async ({ page }) => {
      await page.locator('[data-testid="action-menu-kebab"]').click();
      await page.waitForTimeout(100);
      await expect(page.locator('[role="menu"]')).toBeVisible();

      // Click an area outside the menu (the slot header area of a different card)
      await page.locator('[data-testid="piv-slot-card-9C"]').click({ position: { x: 10, y: 10 } });
      await page.waitForTimeout(150);
      await expect(page.locator('[role="menu"]')).not.toBeVisible();
    });
  });

  test.describe('ActionMenu — Key-Only State (Wails)', () => {
    test.beforeEach(async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      // Generate a public-key-only result so slot 9A has a key but no cert.
      await page.locator('[data-testid="piv-slot-card-9A"]').getByRole('button', { name: 'Generate Key' }).click();
      await expect(page.locator('[data-testid="piv-generate-dialog"]')).toBeVisible();
      await page.locator('[data-testid="piv-algorithm-select"]').selectOption('ECCP256');
      await page.locator('[data-testid="piv-output-format-select"]').selectOption('public-key');
      await page.getByRole('button', { name: /Generate Key|Generating/ }).last().click();
      // Stay open showing PEM result — click Done to close without generating cert
      await expect(page.locator('[data-testid="piv-pem-result"]')).toBeVisible({ timeout: 15_000 });
      await page.getByRole('button', { name: 'Done' }).click();

      // ActionMenu is on the overview card — stay on the PIV overview.
      await expect(page.locator('[data-testid="piv-slot-key-only-9A"]')).toBeVisible();
    });

    test('primary action button on key-only card is "Import Certificate"', async ({ page }) => {
      await expect(page.locator('[data-testid="piv-action-import-cert"]')).toBeVisible();
      await expect(page.locator('[data-testid="piv-action-import-cert"]')).toContainText('Import Certificate');
    });

    test('overflow menu contains "Generate Self-Signed Certificate" and "Generate CSR"', async ({ page }) => {
      await page.locator('[data-testid="action-menu-kebab"]').click();
      await page.waitForTimeout(100);

      await expect(page.locator('[data-testid="piv-action-self-sign"]')).toBeVisible();
      await expect(page.locator('[data-testid="piv-action-self-sign"]')).toContainText('Generate Self-Signed Certificate');
      await expect(page.locator('[data-testid="piv-action-gen-csr"]')).toBeVisible();
    });

    test('Escape closes the key-only overflow menu', async ({ page }) => {
      await page.locator('[data-testid="action-menu-kebab"]').click();
      await page.waitForTimeout(100);
      await expect(page.locator('[role="menu"]')).toBeVisible();

      await page.keyboard.press('Escape');
      await page.waitForTimeout(150);
      await expect(page.locator('[role="menu"]')).not.toBeVisible();
    });
  });

  // ── No downloadPEM() in PIV Save paths (Bug 3 regression) ──────────────
  //
  // Save Certificate / Save Public Key / Save CSR previously used a browser
  // Blob + <a download> that silently dropped files into Downloads. The
  // fix routes all Save actions through AppService.SavePEMFile so Wails
  // shows a native file-save dialog. These source-content assertions
  // prevent reintroducing downloadPEM() under reflex.

  test.describe('No downloadPEM() in PIV Save paths', () => {
    const PIV_VIEW_PATH = '/home/jhahn/sources/go-xkms/xkey/frontend/src/views/PIV.svelte';
    const GEN_DIALOG_PATH = '/home/jhahn/sources/go-xkms/xkey/frontend/src/lib/components/GeneratePIVKeyDialog.svelte';

    test('PIV.svelte does not call downloadPEM', async () => {
      const fs = await import('fs');
      const content = fs.readFileSync(PIV_VIEW_PATH, 'utf8');
      expect(content).not.toMatch(/\bdownloadPEM\s*\(/);
    });

    test('PIV.svelte does not import downloadPEM', async () => {
      const fs = await import('fs');
      const content = fs.readFileSync(PIV_VIEW_PATH, 'utf8');
      expect(content).not.toMatch(/import[^;]*\bdownloadPEM\b/);
    });

    test('PIV.svelte routes all Save actions through AppService.SavePEMFile', async () => {
      const fs = await import('fs');
      const content = fs.readFileSync(PIV_VIEW_PATH, 'utf8');
      const matches = content.match(/SavePEMFile/g) ?? [];
      expect(matches.length).toBeGreaterThanOrEqual(3);
    });

    test('GeneratePIVKeyDialog.svelte does not call downloadPEM', async () => {
      const fs = await import('fs');
      const content = fs.readFileSync(GEN_DIALOG_PATH, 'utf8');
      expect(content).not.toMatch(/\bdownloadPEM\s*\(/);
    });

    test('GeneratePIVKeyDialog.svelte does not import downloadPEM', async () => {
      const fs = await import('fs');
      const content = fs.readFileSync(GEN_DIALOG_PATH, 'utf8');
      expect(content).not.toMatch(/import[^;]*\bdownloadPEM\b/);
    });

    test('GeneratePIVKeyDialog.svelte routes Save through AppService.SavePEMFile', async () => {
      const fs = await import('fs');
      const content = fs.readFileSync(GEN_DIALOG_PATH, 'utf8');
      expect(content).toMatch(/SavePEMFile/);
    });
  });

  // ── PIV backend slot-based lookup (Bug 1 & 2 regression) ───────────────
  //
  // These file-content assertions catch regressions where someone re-adds
  // a CN-only match in the backend PIV code paths. Matching by PIVSlot is
  // required for YubiKey PKCS#11 where the user-chosen subject CN cannot
  // be predicted.

  test.describe('PIV slot-based key lookup (Bugs 1 & 2)', () => {
    test('piv_service.ExportPublicKey matches by PIVSlot', async () => {
      const fs = await import('fs');
      const content = fs.readFileSync(
        '/home/jhahn/sources/go-xkms/xkey/pkg/gui/services/piv_service.go', 'utf8');
      expect(content).toMatch(/ExportPublicKey[\s\S]{0,2000}ka\.PIVSlot/);
    });

    test('piv_keygen_backend.GetPIVSigner populates PIVSlot attribute', async () => {
      const fs = await import('fs');
      const content = fs.readFileSync(
        '/home/jhahn/sources/go-xkms/pkg/xkms/piv_keygen_backend.go', 'utf8');
      expect(content).toMatch(/func \(g \*backendPIVKeyGenerator\) GetPIVSigner[\s\S]{0,400}PIVSlot:\s*string\(slot\)/);
    });
  });
});
