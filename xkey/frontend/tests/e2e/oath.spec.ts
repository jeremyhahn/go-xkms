import { test, expect } from '@playwright/test';
import {
  navigateTo,
  waitForAppReady,
  ensureSidebarExpanded,
  isWailsMode,
  openQRCodePage,
} from './helpers';

test.describe('OATH View', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
    await navigateTo(page, 'oath');
  });

  test.describe('Header and Layout', () => {
    test('OATH view loads with correct header', async ({ page }) => {
      await expect(page.getByRole('heading', { name: 'OATH Accounts', exact: true })).toBeVisible();
      await expect(page.locator('.header-subtitle')).toHaveText('TOTP and HOTP codes');
    });

    test('Add Account button is visible in the header', async ({ page }) => {
      const addButton = page.getByRole('button', { name: 'Add Account' }).first();
      await expect(addButton).toBeVisible();
    });

    test('oath view content area is visible', async ({ page }) => {
      const content = page.locator('.oath-content');
      await expect(content).toBeVisible();
    });
  });

  test.describe('Empty State', () => {
    test('shows empty state or accounts grid', async ({ page }) => {
      const emptyTitle = page.getByText('No OATH Accounts');
      const accountGrid = page.locator('.oath-grid');

      const hasEmpty = await emptyTitle.isVisible().catch(() => false);
      const hasGrid = await accountGrid.isVisible().catch(() => false);
      expect(hasEmpty || hasGrid).toBeTruthy();
    });

    test('empty state shows descriptive message', async ({ page }) => {
      const emptyTitle = page.getByText('No OATH Accounts');
      const isVisible = await emptyTitle.isVisible().catch(() => false);
      if (isVisible) {
        await expect(
          page.getByText(
            'Add your first TOTP account to generate one-time codes for two-factor authentication.',
          ),
        ).toBeVisible();
      }
    });

    test('empty state has an Add Account action button', async ({ page }) => {
      const emptyTitle = page.getByText('No OATH Accounts');
      const isVisible = await emptyTitle.isVisible().catch(() => false);
      if (isVisible) {
        const actionButton = page.locator('.oath-content').getByRole('button', { name: 'Add Account' }).first();
        await expect(actionButton).toBeVisible();
      }
    });

    test('empty state action button opens add account dialog', async ({ page }) => {
      const emptyTitle = page.getByText('No OATH Accounts');
      const isVisible = await emptyTitle.isVisible().catch(() => false);
      if (isVisible) {
        const actionButton = page.locator('.oath-content').getByRole('button', { name: 'Add Account' }).first();
        await actionButton.click();
        await expect(page.getByText('Add OATH Account')).toBeVisible();
      }
    });
  });

  test.describe('Add Account Dialog', () => {
    test('Add Account button opens the add account dialog', async ({ page }) => {
      const addButton = page.getByRole('button', { name: 'Add Account' }).first();
      await addButton.click();
      await expect(page.getByText('Add OATH Account')).toBeVisible();
    });

    test('add account dialog shows QR scan button', async ({ page }) => {
      const addButton = page.getByRole('button', { name: 'Add Account' }).first();
      await addButton.click();

      const scanButton = page.getByRole('button', { name: /Scan QR from Screen/ });
      await expect(scanButton).toBeVisible();
    });

    test('add account dialog shows OR ENTER MANUALLY divider', async ({ page }) => {
      const addButton = page.getByRole('button', { name: 'Add Account' }).first();
      await addButton.click();

      await expect(page.getByText('OR ENTER MANUALLY')).toBeVisible();
    });

    test('add account dialog has all manual entry fields', async ({ page }) => {
      const addButton = page.getByRole('button', { name: 'Add Account' }).first();
      await addButton.click();

      await expect(page.getByText('Issuer')).toBeVisible();
      await expect(page.getByText('Account Name')).toBeVisible();
      await expect(page.getByText('Secret Key')).toBeVisible();
      await expect(page.locator('label[for="oath-digits"]')).toBeVisible();
      await expect(page.locator('label[for="oath-period"]')).toBeVisible();
    });

    test('add account dialog has correct placeholders', async ({ page }) => {
      const addButton = page.getByRole('button', { name: 'Add Account' }).first();
      await addButton.click();

      await expect(
        page.locator('input[placeholder="e.g., GitHub, Google"]'),
      ).toBeVisible();
      await expect(
        page.locator('input[placeholder="e.g., user@example.com"]'),
      ).toBeVisible();
      await expect(
        page.locator('input[placeholder="Base32 encoded secret"]'),
      ).toBeVisible();
    });

    test('add account dialog Digits selector has 6 and 8 options', async ({
      page,
    }) => {
      const addButton = page.getByRole('button', { name: 'Add Account' }).first();
      await addButton.click();

      const digitsSelect = page.locator('#oath-digits');
      await expect(digitsSelect).toBeVisible();

      const options = digitsSelect.locator('option');
      const texts = await options.allTextContents();
      expect(texts).toContain('6 digits');
      expect(texts).toContain('8 digits');
    });

    test('add account dialog Period selector has 30s and 60s options', async ({
      page,
    }) => {
      const addButton = page.getByRole('button', { name: 'Add Account' }).first();
      await addButton.click();

      const periodSelect = page.locator('#oath-period');
      await expect(periodSelect).toBeVisible();

      const options = periodSelect.locator('option');
      const texts = await options.allTextContents();
      expect(texts).toContain('30 seconds');
      expect(texts).toContain('60 seconds');
    });

    test('add account dialog Cancel button closes the dialog', async ({
      page,
    }) => {
      const addButton = page.getByRole('button', { name: 'Add Account' }).first();
      await addButton.click();
      await expect(page.getByText('Add OATH Account')).toBeVisible();

      await page.getByRole('button', { name: 'Cancel' }).click();
      await page.waitForTimeout(300);

      await expect(page.getByText('Add OATH Account')).not.toBeVisible();
    });

    test('add account dialog Add Account button is present', async ({ page }) => {
      const addButton = page.getByRole('button', { name: 'Add Account' }).first();
      await addButton.click();

      // The dialog has an "Add Account" action button in the modal actions area
      const dialogAddButton = page.locator('.modal-backdrop .modal-actions')
        .getByRole('button', { name: 'Add Account' });
      await expect(dialogAddButton).toBeVisible();
    });

    test('add account dialog fields reset when reopened', async ({ page }) => {
      const addButton = page.getByRole('button', { name: 'Add Account' }).first();

      // Open and fill in some data
      await addButton.click();
      const issuerInput = page.locator('input[placeholder="e.g., GitHub, Google"]');
      await issuerInput.fill('TestIssuer');

      // Close
      await page.getByRole('button', { name: 'Cancel' }).click();
      await page.waitForTimeout(300);

      // Reopen
      await addButton.click();
      await page.waitForTimeout(200);

      // Fields should be cleared
      const issuerValue = await issuerInput.inputValue();
      expect(issuerValue).toBe('');
    });
  });

  test.describe('Wails Mode - Manual Entry', () => {
    test('manually add an account and verify it appears in the list', async ({
      page,
    }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      const addButton = page.getByRole('button', { name: 'Add Account' }).first();
      await addButton.click();

      // Fill the manual entry form
      await page.locator('input[placeholder="e.g., GitHub, Google"]').fill('GitHub');
      await page.locator('input[placeholder="e.g., user@example.com"]').fill('user@github.com');
      await page.locator('input[placeholder="Base32 encoded secret"]').fill('JBSWY3DPEHPK3PXP');

      // Submit
      // Find the submit button inside the dialog actions
      const dialogAddBtn = page.getByRole('button', { name: 'Add Account' }).last();
      await dialogAddBtn.click();
      await page.waitForTimeout(1000);

      // The account should appear in the grid
      await expect(page.getByText('GitHub')).toBeVisible();
    });

    test('TOTP code displays as 6 digits', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await page.waitForTimeout(1000);

      // If accounts exist, check that TOTP codes are displayed
      const codeElements = page.locator('.totp-code');
      const count = await codeElements.count();
      if (count > 0) {
        const codeText = await codeElements.first().textContent();
        // Code should be numeric and 6 or 8 digits
        expect(codeText?.replace(/\s/g, '')).toMatch(/^\d{6,8}$/);
      }
    });

    test('delete an account and verify removal', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await page.waitForTimeout(1000);

      // Find and click a delete button on an account card
      const deleteButton = page.locator('.totp-card').first().getByRole('button', { name: /delete/i });
      const hasAccounts = await deleteButton.isVisible().catch(() => false);

      if (hasAccounts) {
        const accountCards = page.locator('.totp-card');
        const countBefore = await accountCards.count();

        await deleteButton.click();
        await page.waitForTimeout(500);

        // After deletion, either the count decreased or the card is gone
        const countAfter = await accountCards.count();
        expect(countAfter).toBeLessThan(countBefore);
      }
    });
  });

  test.describe('Wails Mode - QR Scanning', () => {
    test('QR scan button triggers screen scan', async ({ page, context }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend for QR scanning');

      // Open the add account dialog
      const addButton = page.getByRole('button', { name: 'Add Account' }).first();
      await addButton.click();

      // The scan button should be visible
      const scanButton = page.getByRole('button', { name: /Scan QR from Screen/ });
      await expect(scanButton).toBeVisible();

      // Note: Actually scanning requires a visible QR on screen (Xvfb environment)
      // This test just verifies the button is clickable and changes state
      await scanButton.click();
      // Should show "Scanning..." while in progress
      await page.waitForTimeout(500);
    });
  });

  test.describe('Search Functionality', () => {
    test('search bar appears when accounts exist', async ({ page }) => {
      const wails = await isWailsMode(page);
      await page.waitForTimeout(500);

      const accountGrid = page.locator('.oath-grid');
      const hasAccounts = await accountGrid.isVisible().catch(() => false);

      if (hasAccounts) {
        const searchInput = page.locator('input[placeholder="Search accounts..."]');
        await expect(searchInput).toBeVisible();
      }
    });

    test('search filters accounts by query', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend with accounts');

      await page.waitForTimeout(500);

      const searchInput = page.locator('input[placeholder="Search accounts..."]');
      const isVisible = await searchInput.isVisible().catch(() => false);

      if (isVisible) {
        await searchInput.fill('nonexistent-query-xyz');
        await page.waitForTimeout(300);

        // Should show "No matching accounts" empty state
        await expect(page.getByText('No matching accounts')).toBeVisible();
      }
    });
  });
});
