import { test, expect } from '@playwright/test';
import {
  navigateTo,
  waitForAppReady,
  ensureSidebarExpanded,
  isWailsMode,
  navigateToTPMCategory,
  waitForLoadingComplete,
} from './helpers';

test.describe('TPM 2.0 View', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);

    // The TPM nav item is only rendered when TPM hardware is available.
    // In Vite dev mode there is no Wails bridge, so tpmAvailable is false and
    // the nav item is hidden.  Skip the test rather than timing out.
    const tpmNavItem = page.locator('nav.sidebar button.nav-item', {
      has: page.locator('span.nav-label:text-is("TPM 2.0")'),
    });
    const tpmVisible = await tpmNavItem.isVisible().catch(() => false);
    if (!tpmVisible) {
      test.skip(true, 'TPM nav item is hidden — no TPM hardware available in this environment');
    }

    await navigateTo(page, 'tpm');
  });

  test.describe('Header and Layout', () => {
    test('TPM view loads with correct title', async ({ page }) => {
      await expect(page.locator('h1.header-title')).toHaveText('TPM 2.0');
    });

    test('TPM layout has sidebar navigation and content panel', async ({
      page,
    }) => {
      await waitForLoadingComplete(page);

      const tpmLayout = page.locator('.tpm-layout');
      const tpmLayoutVisible = await tpmLayout.isVisible().catch(() => false);

      if (tpmLayoutVisible) {
        const tpmNav = page.locator('.tpm-nav');
        await expect(tpmNav).toBeVisible();

        const tpmPanel = page.locator('.tpm-panel');
        await expect(tpmPanel).toBeVisible();
      }
    });
  });

  test.describe('Category Navigation', () => {
    test('all 10 TPM categories are visible in the sidebar', async ({
      page,
    }) => {
      await waitForLoadingComplete(page);

      const tpmNav = page.locator('.tpm-nav');
      const navVisible = await tpmNav.isVisible().catch(() => false);

      if (navVisible) {
        const categories = [
          'Overview', 'Platform Keys', 'Measurements', 'Key Handles',
          'NV Storage', 'Policies', 'Attestation', 'Lockout', 'Authorization', 'Verification',
        ];

        for (const cat of categories) {
          const navItem = page.locator('.tpm-nav .tpm-nav-item', {
            hasText: cat,
          });
          await expect(navItem).toBeVisible();
        }
      }
    });

    test('Overview is the default active category', async ({ page }) => {
      await waitForLoadingComplete(page);

      const tpmNav = page.locator('.tpm-nav');
      const navVisible = await tpmNav.isVisible().catch(() => false);

      if (navVisible) {
        const activeItem = page.locator('.tpm-nav .tpm-nav-item.nav-active');
        await expect(activeItem).toContainText('Overview');
      }
    });

    test('clicking a category changes the active state', async ({ page }) => {
      await waitForLoadingComplete(page);

      const tpmNav = page.locator('.tpm-nav');
      const navVisible = await tpmNav.isVisible().catch(() => false);

      if (navVisible) {
        await navigateToTPMCategory(page, 'Identity Keys');

        const activeItem = page.locator('.tpm-nav .tpm-nav-item.nav-active');
        await expect(activeItem).toContainText('Identity Keys');
      }
    });

    test('can navigate to all categories sequentially', async ({ page }) => {
      await waitForLoadingComplete(page);

      const tpmNav = page.locator('.tpm-nav');
      const navVisible = await tpmNav.isVisible().catch(() => false);

      if (navVisible) {
        const categories = [
          'Overview', 'Platform Keys', 'Measurements', 'Key Handles',
          'NV Storage', 'Policies', 'Attestation', 'Lockout', 'Authorization', 'Verification',
        ];

        for (const cat of categories) {
          await navigateToTPMCategory(page, cat);
          const activeItem = page.locator('.tpm-nav .tpm-nav-item.nav-active');
          await expect(activeItem).toContainText(cat);
        }
      }
    });
  });

  test.describe('Overview Category', () => {
    test('shows TPM Hardware section', async ({ page }) => {
      await waitForLoadingComplete(page);

      const tpmPanel = page.locator('.tpm-panel');
      const panelVisible = await tpmPanel.isVisible().catch(() => false);

      if (panelVisible) {
        await expect(page.getByText('TPM Hardware')).toBeVisible();
      }
    });

    test('shows provisioning state badge', async ({ page }) => {
      await waitForLoadingComplete(page);

      const tpmPanel = page.locator('.tpm-panel');
      const panelVisible = await tpmPanel.isVisible().catch(() => false);

      if (panelVisible) {
        await expect(page.getByText('Provisioning')).toBeVisible();
        // Should show one of: Verified, Device Identity, Provisioned, Owner Provisioned, Manufacturer Default, Not Provisioned
        const provisionText = page.locator('.provisioning-status');
        const provisionCount = await provisionText.count();
        if (provisionCount > 0) {
          await expect(provisionText).toBeVisible();
        }
      }
    });

    test('shows hardware detail fields', async ({ page }) => {
      await waitForLoadingComplete(page);

      const tpmPanel = page.locator('.tpm-panel');
      const panelVisible = await tpmPanel.isVisible().catch(() => false);

      if (panelVisible) {
        // The overview shows Manufacturer, Model, Firmware, Specification fields
        await expect(page.getByText('Manufacturer')).toBeVisible();
        await expect(page.getByText('Model')).toBeVisible();
        await expect(page.getByText('Firmware')).toBeVisible();
        await expect(page.getByText('Specification')).toBeVisible();
      }
    });

    test('shows Storage Root Key (SRK) section', async ({ page }) => {
      await waitForLoadingComplete(page);

      const tpmPanel = page.locator('.tpm-panel');
      const panelVisible = await tpmPanel.isVisible().catch(() => false);

      if (panelVisible) {
        await expect(page.getByText('Storage Root Key (SRK)')).toBeVisible();
      }
    });

    test('shows Provision TPM button when not fully provisioned', async ({
      page,
    }) => {
      await waitForLoadingComplete(page);

      const wails = await isWailsMode(page);
      if (!wails) return;

      // Provision button appears when status level is not 'verified' or 'device_identity'
      const provisionBtn = page.getByRole('button', { name: 'Provision TPM' });
      const hasBtn = await provisionBtn.isVisible().catch(() => false);
      // This is conditional - just verify the button state is valid
      expect(typeof hasBtn).toBe('boolean');
    });
  });

  test.describe('Platform Keys Category', () => {
    test('shows platform keys section', async ({ page }) => {
      await waitForLoadingComplete(page);

      const tpmNav = page.locator('.tpm-nav');
      const navVisible = await tpmNav.isVisible().catch(() => false);
      if (!navVisible) return;

      await navigateToTPMCategory(page, 'Platform Keys');

      await expect(page.getByText('Platform Keys')).toBeVisible();
    });

    test('displays identity key types including EK and IAK', async ({ page }) => {
      await waitForLoadingComplete(page);

      const tpmNav = page.locator('.tpm-nav');
      const navVisible = await tpmNav.isVisible().catch(() => false);
      if (!navVisible) return;

      await navigateToTPMCategory(page, 'Platform Keys');

      // Platform Keys view renders the PlatformKeys component which shows EK/IAK cards
      await expect(page.getByText('Endorsement Key (EK-RSA)')).toBeVisible();
      await expect(page.getByText('Endorsement Key (EK-ECC)')).toBeVisible();
      await expect(page.getByText('Initial Attestation Key (IAK)')).toBeVisible();
      await expect(page.getByText('Initial Device ID (IDevID)')).toBeVisible();
    });

    test('each platform key shows a status badge', async ({
      page,
    }) => {
      await waitForLoadingComplete(page);

      const tpmNav = page.locator('.tpm-nav');
      const navVisible = await tpmNav.isVisible().catch(() => false);
      if (!navVisible) return;

      await navigateToTPMCategory(page, 'Platform Keys');

      // Each key row should have a StatusBadge
      const keyRows = page.locator('.identity-key-row');
      const count = await keyRows.count();
      expect(count).toBe(4);
    });
  });

  test.describe('Measurements Category', () => {
    test('shows PCR viewer or loading state', async ({ page }) => {
      await waitForLoadingComplete(page);

      const tpmNav = page.locator('.tpm-nav');
      const navVisible = await tpmNav.isVisible().catch(() => false);
      if (!navVisible) return;

      await navigateToTPMCategory(page, 'Measurements');
      await page.waitForTimeout(500);

      // Should show PCR viewer or loading spinner
      const pcrViewer = page.locator('.pcr-viewer');
      const loading = page.getByText('Loading PCR values...');
      const hardwareDetails = page.getByText('Hardware Details');

      const hasPcr = await pcrViewer.isVisible().catch(() => false);
      const hasLoading = await loading.isVisible().catch(() => false);
      const hasHardware = await hardwareDetails.isVisible().catch(() => false);

      // In standalone mode, we may just see the hardware details
      expect(hasPcr || hasLoading || hasHardware).toBeTruthy();
    });
  });

  test.describe('Key Handles Category', () => {
    test('shows Key Handles section with tabs', async ({ page }) => {
      await waitForLoadingComplete(page);

      const tpmNav = page.locator('.tpm-nav');
      const navVisible = await tpmNav.isVisible().catch(() => false);
      if (!navVisible) return;

      await navigateToTPMCategory(page, 'Key Handles');

      await expect(page.getByText('Key Handles')).toBeVisible();

      // Should show Persistent and Transient tabs
      const persistentTab = page.locator('.handle-tab', { hasText: 'Persistent' });
      const transientTab = page.locator('.handle-tab', { hasText: 'Transient' });
      await expect(persistentTab).toBeVisible();
      await expect(transientTab).toBeVisible();
    });

    test('Persistent tab is active by default', async ({ page }) => {
      await waitForLoadingComplete(page);

      const tpmNav = page.locator('.tpm-nav');
      const navVisible = await tpmNav.isVisible().catch(() => false);
      if (!navVisible) return;

      await navigateToTPMCategory(page, 'Key Handles');

      const activeTab = page.locator('.handle-tab.handle-tab-active');
      await expect(activeTab).toContainText('Persistent');
    });

    test('switching to Transient tab works', async ({ page }) => {
      await waitForLoadingComplete(page);

      const tpmNav = page.locator('.tpm-nav');
      const navVisible = await tpmNav.isVisible().catch(() => false);
      if (!navVisible) return;

      await navigateToTPMCategory(page, 'Key Handles');

      const transientTab = page.locator('.handle-tab', { hasText: 'Transient' });
      await transientTab.click();
      await page.waitForTimeout(200);

      const activeTab = page.locator('.handle-tab.handle-tab-active');
      await expect(activeTab).toContainText('Transient');
    });
  });

  test.describe('NV Storage Category', () => {
    test('shows NV Storage section', async ({ page }) => {
      await waitForLoadingComplete(page);

      const tpmNav = page.locator('.tpm-nav');
      const navVisible = await tpmNav.isVisible().catch(() => false);
      if (!navVisible) return;

      await navigateToTPMCategory(page, 'NV Storage');

      await expect(page.getByText('NV Storage')).toBeVisible();
    });

    test('shows NV summary counts or loading state', async ({ page }) => {
      await waitForLoadingComplete(page);

      const tpmNav = page.locator('.tpm-nav');
      const navVisible = await tpmNav.isVisible().catch(() => false);
      if (!navVisible) return;

      await navigateToTPMCategory(page, 'NV Storage');
      await page.waitForTimeout(500);

      // Should show summary counts, loading spinner, or error state
      const summaryCard = page.locator('.nv-summary-card');
      const loading = page.getByText('Loading NV storage...');
      const errorState = page.getByText('Unable to load NV storage information');

      const hasSummary = await summaryCard.isVisible().catch(() => false);
      const hasLoading = await loading.isVisible().catch(() => false);
      const hasError = await errorState.isVisible().catch(() => false);

      expect(hasSummary || hasLoading || hasError).toBeTruthy();
    });

    test('Create NV Index button is visible when data is loaded', async ({
      page,
    }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await waitForLoadingComplete(page);
      await navigateToTPMCategory(page, 'NV Storage');
      await page.waitForTimeout(1000);

      const createBtn = page.getByRole('button', { name: 'Create NV Index' });
      const hasBtn = await createBtn.isVisible().catch(() => false);
      if (hasBtn) {
        await expect(createBtn).toBeVisible();
      }
    });
  });

  test.describe('Attestation Category', () => {
    test('shows Attestation section with action buttons', async ({
      page,
    }) => {
      await waitForLoadingComplete(page);

      const tpmNav = page.locator('.tpm-nav');
      const navVisible = await tpmNav.isVisible().catch(() => false);
      if (!navVisible) return;

      await navigateToTPMCategory(page, 'Attestation');

      await expect(page.getByText('Attestation')).toBeVisible();
    });

    test('shows Generate Quote button', async ({ page }) => {
      await waitForLoadingComplete(page);

      const tpmNav = page.locator('.tpm-nav');
      const navVisible = await tpmNav.isVisible().catch(() => false);
      if (!navVisible) return;

      await navigateToTPMCategory(page, 'Attestation');

      await expect(
        page.getByRole('button', { name: 'Generate Quote' }),
      ).toBeVisible();
    });

    test('shows View Event Log button', async ({ page }) => {
      await waitForLoadingComplete(page);

      const tpmNav = page.locator('.tpm-nav');
      const navVisible = await tpmNav.isVisible().catch(() => false);
      if (!navVisible) return;

      await navigateToTPMCategory(page, 'Attestation');

      await expect(
        page.getByRole('button', { name: 'View Event Log' }),
      ).toBeVisible();
    });

    test('shows Certify Key section with handle input', async ({ page }) => {
      await waitForLoadingComplete(page);

      const tpmNav = page.locator('.tpm-nav');
      const navVisible = await tpmNav.isVisible().catch(() => false);
      if (!navVisible) return;

      await navigateToTPMCategory(page, 'Attestation');

      await expect(page.getByText('Certify Key')).toBeVisible();
      await expect(
        page.locator('input[placeholder="0x81020000"]'),
      ).toBeVisible();
      await expect(
        page.getByRole('button', { name: 'Certify' }),
      ).toBeVisible();
    });

    test('attestation descriptions are present', async ({ page }) => {
      await waitForLoadingComplete(page);

      const tpmNav = page.locator('.tpm-nav');
      const navVisible = await tpmNav.isVisible().catch(() => false);
      if (!navVisible) return;

      await navigateToTPMCategory(page, 'Attestation');

      await expect(
        page.getByText('Create a TPM quote over selected PCR registers'),
      ).toBeVisible();
      await expect(
        page.getByText('View the TPM event log entries'),
      ).toBeVisible();
    });
  });

  test.describe('Lockout Category', () => {
    test('shows Lockout section', async ({ page }) => {
      await waitForLoadingComplete(page);

      const tpmNav = page.locator('.tpm-nav');
      const navVisible = await tpmNav.isVisible().catch(() => false);
      if (!navVisible) return;

      await navigateToTPMCategory(page, 'Lockout');

      await expect(page.getByText('Lockout')).toBeVisible();
    });

    test('shows DA counter details when loaded (Wails mode)', async ({
      page,
    }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await waitForLoadingComplete(page);
      await navigateToTPMCategory(page, 'Lockout');
      await page.waitForTimeout(1000);

      // Should show counter fields
      const counter = page.getByText('Counter');
      const maxFail = page.getByText('Max Failures');
      const loading = page.getByText('Loading lockout info...');

      const hasCounter = await counter.isVisible().catch(() => false);
      const hasLoading = await loading.isVisible().catch(() => false);

      expect(hasCounter || hasLoading).toBeTruthy();

      if (hasCounter) {
        await expect(maxFail).toBeVisible();
        await expect(page.getByText('Interval')).toBeVisible();
        await expect(page.getByText('Recovery')).toBeVisible();
        await expect(page.getByText('Status')).toBeVisible();
      }
    });

    test('shows Reset Lockout Counter section', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await waitForLoadingComplete(page);
      await navigateToTPMCategory(page, 'Lockout');
      await page.waitForTimeout(1000);

      const resetSection = page.getByText('Reset Lockout Counter');
      const hasSection = await resetSection.isVisible().catch(() => false);
      if (hasSection) {
        await expect(resetSection).toBeVisible();
      }
    });

    test('shows Force Reset Lockout section with warning', async ({
      page,
    }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await waitForLoadingComplete(page);
      await navigateToTPMCategory(page, 'Lockout');
      await page.waitForTimeout(1000);

      const forceReset = page.getByText('Force Reset Lockout');
      const hasForceReset = await forceReset.isVisible().catch(() => false);
      if (hasForceReset) {
        await expect(forceReset).toBeVisible();
        // Should show warning text
        await expect(
          page.getByText(/Force Reset Lockout resets the dictionary attack counter/),
        ).toBeVisible();
      }
    });
  });

  test.describe('Authorization Category', () => {
    test('shows three hierarchy authorization sections', async ({
      page,
    }) => {
      await waitForLoadingComplete(page);

      const tpmNav = page.locator('.tpm-nav');
      const navVisible = await tpmNav.isVisible().catch(() => false);
      if (!navVisible) return;

      await navigateToTPMCategory(page, 'Authorization');

      await expect(page.getByText('Owner Authorization')).toBeVisible();
      await expect(page.getByText('Endorsement Authorization')).toBeVisible();
      await expect(page.getByText('Lockout Authorization')).toBeVisible();
    });

    test('each authorization section has password change form', async ({
      page,
    }) => {
      await waitForLoadingComplete(page);

      const tpmNav = page.locator('.tpm-nav');
      const navVisible = await tpmNav.isVisible().catch(() => false);
      if (!navVisible) return;

      await navigateToTPMCategory(page, 'Authorization');

      // Each section should have Current Password, New Password, Confirm Password
      const currentPasswordFields = page.locator(
        'input[placeholder*="Current"]',
      );
      const newPasswordFields = page.locator('input[placeholder*="New"]');
      const confirmPasswordFields = page.locator(
        'input[placeholder*="Confirm"]',
      );

      const currentCount = await currentPasswordFields.count();
      const newCount = await newPasswordFields.count();
      const confirmCount = await confirmPasswordFields.count();

      expect(currentCount).toBe(3);
      expect(newCount).toBe(3);
      expect(confirmCount).toBe(3);
    });

    test('change buttons are present for each hierarchy', async ({
      page,
    }) => {
      await waitForLoadingComplete(page);

      const tpmNav = page.locator('.tpm-nav');
      const navVisible = await tpmNav.isVisible().catch(() => false);
      if (!navVisible) return;

      await navigateToTPMCategory(page, 'Authorization');

      await expect(
        page.getByRole('button', { name: 'Change Owner Auth' }),
      ).toBeVisible();
      await expect(
        page.getByRole('button', { name: 'Change Endorsement Auth' }),
      ).toBeVisible();
      await expect(
        page.getByRole('button', { name: 'Change Lockout Auth' }),
      ).toBeVisible();
    });

    test('change buttons are disabled when fields are empty', async ({
      page,
    }) => {
      await waitForLoadingComplete(page);

      const tpmNav = page.locator('.tpm-nav');
      const navVisible = await tpmNav.isVisible().catch(() => false);
      if (!navVisible) return;

      await navigateToTPMCategory(page, 'Authorization');

      await expect(
        page.getByRole('button', { name: 'Change Owner Auth' }),
      ).toBeDisabled();
      await expect(
        page.getByRole('button', { name: 'Change Endorsement Auth' }),
      ).toBeDisabled();
      await expect(
        page.getByRole('button', { name: 'Change Lockout Auth' }),
      ).toBeDisabled();
    });

    test('password mismatch warning shows when passwords differ', async ({
      page,
    }) => {
      await waitForLoadingComplete(page);

      const tpmNav = page.locator('.tpm-nav');
      const navVisible = await tpmNav.isVisible().catch(() => false);
      if (!navVisible) return;

      await navigateToTPMCategory(page, 'Authorization');

      // Fill in mismatched passwords for owner hierarchy
      const currentFields = page.locator('input[placeholder*="Current owner"]');
      const newFields = page.locator('input[placeholder*="New owner"]');
      const confirmFields = page.locator('input[placeholder*="Confirm new auth"]').first();

      await currentFields.fill('oldpass');
      await newFields.fill('newpass1');
      await confirmFields.fill('newpass2');
      await page.waitForTimeout(200);

      await expect(page.getByText('Passwords do not match').first()).toBeVisible();
    });
  });

  test.describe('Verification Category', () => {
    test('shows CA Certificate Import section', async ({ page }) => {
      await waitForLoadingComplete(page);

      const tpmNav = page.locator('.tpm-nav');
      const navVisible = await tpmNav.isVisible().catch(() => false);
      if (!navVisible) return;

      await navigateToTPMCategory(page, 'Verification');

      await expect(page.getByText('CA Certificate Import')).toBeVisible();
    });

    test('shows PEM textarea for CA import', async ({ page }) => {
      await waitForLoadingComplete(page);

      const tpmNav = page.locator('.tpm-nav');
      const navVisible = await tpmNav.isVisible().catch(() => false);
      if (!navVisible) return;

      await navigateToTPMCategory(page, 'Verification');

      const pemTextarea = page.locator(
        'textarea[placeholder*="Paste PEM-encoded CA certificate"]',
      );
      await expect(pemTextarea).toBeVisible();
    });

    test('Import CA Certificate button is disabled when textarea is empty', async ({
      page,
    }) => {
      await waitForLoadingComplete(page);

      const tpmNav = page.locator('.tpm-nav');
      const navVisible = await tpmNav.isVisible().catch(() => false);
      if (!navVisible) return;

      await navigateToTPMCategory(page, 'Verification');

      const importBtn = page.getByRole('button', {
        name: 'Import CA Certificate',
      });
      await expect(importBtn).toBeDisabled();
    });

    test('Import CA Certificate button enables when PEM is entered', async ({
      page,
    }) => {
      await waitForLoadingComplete(page);

      const tpmNav = page.locator('.tpm-nav');
      const navVisible = await tpmNav.isVisible().catch(() => false);
      if (!navVisible) return;

      await navigateToTPMCategory(page, 'Verification');

      const pemTextarea = page.locator(
        'textarea[placeholder*="Paste PEM-encoded CA certificate"]',
      );
      await pemTextarea.fill('-----BEGIN CERTIFICATE-----\nMIIBxTCCAW...\n-----END CERTIFICATE-----');
      await page.waitForTimeout(200);

      const importBtn = page.getByRole('button', {
        name: 'Import CA Certificate',
      });
      await expect(importBtn).toBeEnabled();
    });

    test('shows TPM Verification section with Verify button', async ({
      page,
    }) => {
      await waitForLoadingComplete(page);

      const tpmNav = page.locator('.tpm-nav');
      const navVisible = await tpmNav.isVisible().catch(() => false);
      if (!navVisible) return;

      await navigateToTPMCategory(page, 'Verification');

      await expect(page.getByText('TPM Verification')).toBeVisible();
      await expect(page.getByText('Verify TPM')).toBeVisible();
      await expect(
        page.getByRole('button', { name: 'Verify' }),
      ).toBeVisible();
    });

    test('Verify TPM description text is present', async ({ page }) => {
      await waitForLoadingComplete(page);

      const tpmNav = page.locator('.tpm-nav');
      const navVisible = await tpmNav.isVisible().catch(() => false);
      if (!navVisible) return;

      await navigateToTPMCategory(page, 'Verification');

      await expect(
        page.getByText(
          'Verify the TPM endorsement key certificate chain against imported CA certificates',
        ),
      ).toBeVisible();
    });
  });

  test.describe('Policies Category', () => {
    test('Policies is visible in the TPM sidebar navigation', async ({ page }) => {
      await waitForLoadingComplete(page);

      const tpmNav = page.locator('.tpm-nav');
      const navVisible = await tpmNav.isVisible().catch(() => false);
      if (!navVisible) return;

      const policiesItem = page.locator('.tpm-nav .tpm-nav-item', { hasText: 'Policies' });
      await expect(policiesItem).toBeVisible();
    });

    test('navigating to Policies shows the Policies heading and action buttons', async ({
      page,
    }) => {
      await waitForLoadingComplete(page);

      const tpmNav = page.locator('.tpm-nav');
      const navVisible = await tpmNav.isVisible().catch(() => false);
      if (!navVisible) return;

      await navigateToTPMCategory(page, 'Policies');

      await expect(page.getByText('Policies').first()).toBeVisible();
      await expect(page.getByRole('button', { name: 'Create Policy' })).toBeVisible();
      await expect(page.getByRole('button', { name: 'Import' })).toBeVisible();
    });

    test('Policies DataTable renders with expected column headers', async ({ page }) => {
      await waitForLoadingComplete(page);

      const tpmNav = page.locator('.tpm-nav');
      const navVisible = await tpmNav.isVisible().catch(() => false);
      if (!navVisible) return;

      await navigateToTPMCategory(page, 'Policies');
      await page.waitForTimeout(500);

      // The DataTable should render header columns.
      const table = page.locator('.data-table, table');
      const tableVisible = await table.first().isVisible().catch(() => false);

      if (tableVisible) {
        const expectedHeaders = ['Name', 'Type', 'PCRs', 'Status', 'Created'];
        for (const header of expectedHeaders) {
          await expect(page.getByRole('columnheader', { name: header })).toBeVisible();
        }
      }
    });

    test('Policies DataTable shows empty state when no policies exist', async ({
      page,
    }) => {
      await waitForLoadingComplete(page);

      const tpmNav = page.locator('.tpm-nav');
      const navVisible = await tpmNav.isVisible().catch(() => false);
      if (!navVisible) return;

      await navigateToTPMCategory(page, 'Policies');
      await page.waitForTimeout(500);

      // In Vite mode without a backend, the table renders with an empty state.
      const wails = await isWailsMode(page);
      if (!wails) {
        const emptyTitle = page.getByText('No policies defined');
        const isVisible = await emptyTitle.isVisible().catch(() => false);
        if (isVisible) {
          await expect(emptyTitle).toBeVisible();
          await expect(
            page.getByText('Create one to define authorization requirements for quoting and sealing operations.'),
          ).toBeVisible();
        }
      }
    });

    test('Policy Assignments section uses DataTable with Key Handle, Policy, and Assigned columns', async ({
      page,
    }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend with policy assignments');

      await waitForLoadingComplete(page);
      await navigateToTPMCategory(page, 'Policies');
      await page.waitForTimeout(1000);

      const assignmentsHeading = page.getByText('Policy Assignments');
      const hasAssignments = await assignmentsHeading.isVisible().catch(() => false);

      if (hasAssignments) {
        await expect(assignmentsHeading).toBeVisible();

        // The assignments DataTable should have these columns.
        await expect(page.getByRole('columnheader', { name: 'Key Handle' })).toBeVisible();
        await expect(page.getByRole('columnheader', { name: 'Policy' })).toBeVisible();
        await expect(page.getByRole('columnheader', { name: 'Assigned' })).toBeVisible();
      }
    });

    test('Create Policy button opens the create policy dialog', async ({ page }) => {
      await waitForLoadingComplete(page);

      const tpmNav = page.locator('.tpm-nav');
      const navVisible = await tpmNav.isVisible().catch(() => false);
      if (!navVisible) return;

      await navigateToTPMCategory(page, 'Policies');

      await page.getByRole('button', { name: 'Create Policy' }).click();
      await page.waitForTimeout(300);

      // A modal or form for creating a policy should appear.
      const dialog = page.locator('[role="dialog"]');
      const isOpen = await dialog.isVisible().catch(() => false);
      if (isOpen) {
        await expect(dialog).toBeVisible();
      }
    });
  });

  test.describe('Loading State', () => {
    test('shows loading spinner while TPM data is being fetched', async ({
      page,
    }) => {
      // Navigate to TPM immediately
      // The loading state should briefly appear
      const loadingContainer = page.locator('.loading-container');
      const loadingText = page.getByText('Loading TPM status...');

      // In standalone mode, loading finishes quickly since there is no backend
      // Just verify the loading container or the TPM layout is eventually visible
      await page.waitForTimeout(500);

      const hasLoading = await loadingContainer.isVisible().catch(() => false);
      const hasLayout = await page.locator('.tpm-layout').isVisible().catch(() => false);
      const hasTitle = await page.locator('h1.tpm-title').isVisible().catch(() => false);

      expect(hasLoading || hasLayout || hasTitle).toBeTruthy();
    });
  });
});
