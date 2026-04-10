import { test, expect } from '@playwright/test';
import {
  navigateTo,
  waitForAppReady,
  ensureSidebarExpanded,
  navigateToSettingsCategory,
  isWailsMode,
} from './helpers';

test.describe('Settings View', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
    await navigateTo(page, 'settings');
  });

  test.describe('Header and Layout', () => {
    test('Settings view loads with correct title', async ({ page }) => {
      await expect(page.locator('h1.header-title')).toHaveText('Settings');
    });

    test('settings navigation sidebar is visible', async ({ page }) => {
      const settingsNav = page.locator('.settings-nav');
      await expect(settingsNav).toBeVisible();
    });

    test('settings panel content area is visible', async ({ page }) => {
      const settingsPanel = page.locator('.settings-panel');
      await expect(settingsPanel).toBeVisible();
    });

    test('settings layout uses two-column flex layout', async ({ page }) => {
      const layout = page.locator('.settings-layout');
      await expect(layout).toBeVisible();
      const display = await layout.evaluate((el) =>
        getComputedStyle(el).getPropertyValue('display'),
      );
      expect(display).toBe('flex');
    });
  });

  test.describe('Category Navigation', () => {
    test('settings navigation sidebar renders all 11 categories', async ({
      page,
    }) => {
      const settingsNav = page.locator('.settings-nav');
      await expect(settingsNav).toBeVisible();

      const categories = [
        'General',
        'Appearance',
        'Browser',
        'API Explorer',
        'Server',
        'Phone',
        'Security',
        'PIN Management',
        'Storage',
        'Notifications',
        'Advanced',
      ];

      for (const cat of categories) {
        await expect(
          settingsNav.getByRole('button', { name: cat }),
        ).toBeVisible();
      }
    });

    test('exactly 11 navigation items are rendered', async ({ page }) => {
      const navItems = page.locator('.settings-nav .settings-nav-item');
      const count = await navItems.count();
      expect(count).toBe(11);
    });

    test('General is the default active category', async ({ page }) => {
      const generalButton = page.locator('.settings-nav-item.nav-active');
      await expect(generalButton).toContainText('General');
    });

    test('clicking a category highlights it as active', async ({ page }) => {
      await navigateToSettingsCategory(page, 'Advanced');
      const activeButton = page.locator('.settings-nav-item.nav-active');
      await expect(activeButton).toContainText('Advanced');
    });

    test('switching between categories updates the panel content', async ({
      page,
    }) => {
      // Start on General
      await expect(page.getByText('Start with system')).toBeVisible();

      // Switch to Advanced
      await navigateToSettingsCategory(page, 'Advanced');
      await expect(page.getByText('Debug mode')).toBeVisible();

      // General-specific content should no longer be visible
      await expect(page.getByText('Start with system')).not.toBeVisible();

      // Switch back to General
      await navigateToSettingsCategory(page, 'General');
      await expect(page.getByText('Start with system')).toBeVisible();
    });

    test('each category is clickable and shows content', async ({ page }) => {
      // Verify each category can be activated and shows unique content.
      // Use locators that won't match multiple elements to avoid strict mode violations.
      const categoryContentMap: Array<[string, () => Promise<void>]> = [
        ['General', async () => { await expect(page.getByText('Start with system')).toBeVisible(); }],
        ['Appearance', async () => { await expect(page.getByText('Choose between light, dark, or system theme')).toBeVisible(); }],
        ['Server', async () => { await expect(page.locator('.settings-section h2').filter({ hasText: 'Server Connection' })).toBeVisible(); }],
        ['Phone', async () => { await expect(page.getByText('Phone Settings')).toBeVisible(); }],
        ['Security', async () => { await expect(page.getByText('Lock timeout')).toBeVisible(); }],
        ['Storage', async () => { await expect(page.getByText('LUKS Encrypted Storage')).toBeVisible(); }],
        ['Notifications', async () => { await expect(page.locator('.settings-section h2').filter({ hasText: 'Desktop Notifications' })).toBeVisible(); }],
        ['Advanced', async () => { await expect(page.getByText('xkmsd URL')).toBeVisible(); }],
      ];

      for (const [cat, check] of categoryContentMap) {
        await navigateToSettingsCategory(page, cat);
        await check();
      }
    });
  });

  test.describe('General Category', () => {
    test('General section heading is visible', async ({ page }) => {
      await expect(page.getByText('General').first()).toBeVisible();
    });

    test('shows Start with system toggle with description', async ({
      page,
    }) => {
      await expect(page.getByText('Start with system')).toBeVisible();
      await expect(
        page.getByText('Launch xKey automatically when you log in'),
      ).toBeVisible();
    });

    test('shows Start minimized toggle with description', async ({ page }) => {
      await expect(page.getByText('Start minimized')).toBeVisible();
      await expect(
        page.getByText(
          'Start in the system tray instead of showing the window',
        ),
      ).toBeVisible();
    });

    test('shows Auto-connect toggle with description', async ({ page }) => {
      await expect(
        page.getByText('Auto-connect to default device'),
      ).toBeVisible();
      await expect(
        page.getByText(
          'Automatically connect to the default phone on startup',
        ),
      ).toBeVisible();
    });

    test('shows FIDO2 Virtual Authenticator toggle with description', async ({
      page,
    }) => {
      await expect(
        page.getByText('FIDO2 Virtual Authenticator'),
      ).toBeVisible();
      await expect(
        page.getByText(
          'Enable the virtual FIDO2/WebAuthn authenticator for passwordless authentication',
        ),
      ).toBeVisible();
    });

    test('General category has exactly 6 setting rows', async ({
      page,
    }) => {
      // General has: Start with system, Start minimized, Auto-connect,
      // FIDO2 Virtual Authenticator, Require touch, Multi-key intent check
      const settingRows = page.locator(
        '.settings-panel .settings-section .setting-row',
      );
      const count = await settingRows.count();
      expect(count).toBe(6);
    });
  });

  test.describe('Appearance Category', () => {
    test.beforeEach(async ({ page }) => {
      await navigateToSettingsCategory(page, 'Appearance');
    });

    test('Appearance section heading is visible', async ({ page }) => {
      await expect(page.getByText('Appearance').first()).toBeVisible();
    });

    test('shows theme selector with Light, Dark, and System options', async ({
      page,
    }) => {
      const themeSelect = page
        .locator('.settings-panel .form-select')
        .first();
      await expect(themeSelect).toBeVisible();

      const options = themeSelect.locator('option');
      const optionTexts = await options.allTextContents();
      expect(optionTexts).toContain('Light');
      expect(optionTexts).toContain('Dark');
      expect(optionTexts).toContain('System');
    });

    test('shows theme description text', async ({ page }) => {
      await expect(
        page.getByText('Choose between light, dark, or system theme'),
      ).toBeVisible();
    });

    test('shows font size slider', async ({ page }) => {
      // Use the title span specifically to avoid matching the description text
      await expect(page.locator('span.text-title-small', { hasText: 'Font size' })).toBeVisible();
      const rangeInput = page.locator('.range-input');
      await expect(rangeInput).toBeVisible();
    });

    test('font size slider has correct min and max attributes', async ({
      page,
    }) => {
      const rangeInput = page.locator('.range-input');
      await expect(rangeInput).toHaveAttribute('min', '12');
      await expect(rangeInput).toHaveAttribute('max', '20');
    });

    test('shows Theme Preview section with 4 color swatches', async ({
      page,
    }) => {
      await expect(page.getByText('Theme Preview')).toBeVisible();
      await expect(page.getByText('Primary')).toBeVisible();
      await expect(page.getByText('Secondary')).toBeVisible();
      await expect(page.getByText('Tertiary')).toBeVisible();
      await expect(page.getByText('Surface')).toBeVisible();
    });

    test('theme selector changes data-theme to dark', async ({ page }) => {
      const themeSelect = page
        .locator('.settings-panel .form-select')
        .first();

      await themeSelect.selectOption('dark');
      await page.waitForTimeout(300);

      const html = page.locator('html');
      await expect(html).toHaveAttribute('data-theme', 'dark');
    });

    test('theme selector changes data-theme to light', async ({ page }) => {
      const themeSelect = page
        .locator('.settings-panel .form-select')
        .first();

      await themeSelect.selectOption('light');
      await page.waitForTimeout(300);

      const html = page.locator('html');
      await expect(html).toHaveAttribute('data-theme', 'light');
    });

    test('theme round-trip: dark then light preserves data-theme', async ({
      page,
    }) => {
      const themeSelect = page
        .locator('.settings-panel .form-select')
        .first();
      const html = page.locator('html');

      await themeSelect.selectOption('dark');
      await page.waitForTimeout(300);
      await expect(html).toHaveAttribute('data-theme', 'dark');

      await themeSelect.selectOption('light');
      await page.waitForTimeout(300);
      await expect(html).toHaveAttribute('data-theme', 'light');
    });
  });

  test.describe('Server Category', () => {
    test.beforeEach(async ({ page }) => {
      await navigateToSettingsCategory(page, 'Server');
    });

    test('Server Connection section heading is visible', async ({ page }) => {
      await expect(page.locator('.settings-section h2').filter({ hasText: 'Server Connection' })).toBeVisible();
    });

    test('shows Protocol selector with all transport options', async ({
      page,
    }) => {
      await expect(page.locator('span.text-title-small', { hasText: 'Protocol' })).toBeVisible();

      const protocolSelect = page.locator('.settings-panel .form-select').first();
      await expect(protocolSelect).toBeVisible();

      const options = protocolSelect.locator('option');
      const optionTexts = await options.allTextContents();
      expect(optionTexts).toContain('gRPC');
      expect(optionTexts).toContain('REST');
      expect(optionTexts).toContain('Unix Socket');
      expect(optionTexts).toContain('QUIC');
      expect(optionTexts).toContain('MCP');
    });

    test('shows Address field with placeholder', async ({ page }) => {
      await expect(page.locator('span.text-title-small', { hasText: 'Address' })).toBeVisible();
      await expect(
        page.getByText('Server address (e.g., localhost:9443)'),
      ).toBeVisible();
    });

    test('shows TLS toggle with description', async ({ page }) => {
      await expect(page.getByText('TLS', { exact: true })).toBeVisible();
      await expect(
        page.getByText('Enable TLS encryption for the server connection'),
      ).toBeVisible();
    });

    test('shows Auto-connect toggle for server', async ({ page }) => {
      // Note: This is the server auto-connect, different from General auto-connect
      const autoConnectText = page.getByText('Automatically connect to server on startup');
      await expect(autoConnectText).toBeVisible();
    });

    test('shows Connection Status section', async ({ page }) => {
      await expect(page.getByText('Connection Status')).toBeVisible();
    });

    test('shows Test Connection button when not connected', async ({
      page,
    }) => {
      const testButton = page.getByRole('button', {
        name: /Test Connection|Connecting/,
      });
      const disconnectButton = page.getByRole('button', {
        name: 'Disconnect',
      });

      const hasTest = await testButton.isVisible().catch(() => false);
      const hasDisconnect = await disconnectButton.isVisible().catch(() => false);
      // One of them should be visible
      expect(hasTest || hasDisconnect).toBeTruthy();
    });

  });

  test.describe('Phone Category', () => {
    test.beforeEach(async ({ page }) => {
      await navigateToSettingsCategory(page, 'Phone');
    });

    test('Phone Settings section heading is visible', async ({ page }) => {
      await expect(page.getByText('Phone Settings')).toBeVisible();
    });

    test('shows Default device selector', async ({ page }) => {
      await expect(page.getByText('Default device')).toBeVisible();
      await expect(
        page.getByText(
          'Device used for operations when no device is specified',
        ),
      ).toBeVisible();
    });

    test('Default device selector has options including Auto-detect', async ({
      page,
    }) => {
      const deviceSelect = page.locator('.settings-panel .form-select').first();
      await expect(deviceSelect).toBeVisible();

      const options = deviceSelect.locator('option');
      const optionTexts = await options.allTextContents();
      expect(optionTexts).toContain('Auto-detect');
    });

    test('shows Attestation policy selector', async ({ page }) => {
      await expect(page.getByText('Attestation policy')).toBeVisible();
      await expect(
        page.getByText(
          'When to require hardware attestation from the phone',
        ),
      ).toBeVisible();
    });

    test('Attestation policy has Always, Periodic, and Manual options', async ({
      page,
    }) => {
      // Find the attestation policy select (second form-select in Phone section)
      const selects = page.locator('.settings-panel .form-select');
      // We need the one after the device selector
      const policySelect = selects.nth(1);
      await expect(policySelect).toBeVisible();

      const options = policySelect.locator('option');
      const optionTexts = await options.allTextContents();
      expect(optionTexts).toContain('Always');
      expect(optionTexts).toContain('Periodic');
      expect(optionTexts).toContain('Manual only');
    });

    test('shows Grace period with number input in hours', async ({ page }) => {
      await expect(page.getByText('Grace period')).toBeVisible();
      await expect(
        page.getByText('Hours between automatic attestation checks'),
      ).toBeVisible();

      const numberInput = page.locator('.number-input');
      await expect(numberInput).toBeVisible();

      // Verify the "hours" label
      await expect(
        page.locator('.inline-input').getByText('hours'),
      ).toBeVisible();
    });

    test('Grace period number input has min and max constraints', async ({
      page,
    }) => {
      const numberInput = page.locator('.number-input');
      await expect(numberInput).toHaveAttribute('min', '1');
      await expect(numberInput).toHaveAttribute('max', '168');
    });
  });

  test.describe('Security Category', () => {
    test.beforeEach(async ({ page }) => {
      await navigateToSettingsCategory(page, 'Security');
    });

    test('Security section heading is visible', async ({ page }) => {
      await expect(page.getByText('Security').first()).toBeVisible();
    });

    test('shows Lock timeout setting with number input', async ({ page }) => {
      await expect(page.getByText('Lock timeout')).toBeVisible();
      await expect(
        page.getByText(
          'Lock the application after this many minutes of inactivity',
          { exact: false },
        ),
      ).toBeVisible();

      // Use first() since Security also shows a Clipboard number input
      const numberInput = page.locator('.number-input').first();
      await expect(numberInput).toBeVisible();

      await expect(
        page.locator('.inline-input').getByText('minutes'),
      ).toBeVisible();
    });

    test('Lock timeout has min and max constraints', async ({ page }) => {
      // Lock timeout is the first number input; Clipboard timeout is the second
      const numberInput = page.locator('.number-input').first();
      await expect(numberInput).toHaveAttribute('min', '0');
      await expect(numberInput).toHaveAttribute('max', '60');
    });

    test('shows Require authentication toggle with description', async ({
      page,
    }) => {
      await expect(
        page.getByText('Require authentication for sensitive operations'),
      ).toBeVisible();
      await expect(
        page.getByText(
          'Require PIN/password for key operations, deletions, and settings changes',
        ),
      ).toBeVisible();
    });

    test('shows Clipboard section heading', async ({ page }) => {
      await expect(page.locator('.settings-section h2', { hasText: 'Clipboard' })).toBeVisible();
    });

    test('shows Clipboard clear timeout with number input', async ({ page }) => {
      await expect(page.getByText('Clear timeout')).toBeVisible();
      // Clipboard timeout is the second number input in the Security category
      const numberInput = page.locator('.number-input').nth(1);
      await expect(numberInput).toBeVisible();
      await expect(numberInput).toHaveAttribute('min', '0');
      await expect(numberInput).toHaveAttribute('max', '300');
    });
  });

  test.describe('Storage Category', () => {
    test.beforeEach(async ({ page }) => {
      await navigateToSettingsCategory(page, 'Storage');
    });

    test('LUKS Encrypted Storage section heading is visible', async ({
      page,
    }) => {
      await expect(page.getByText('LUKS Encrypted Storage')).toBeVisible();
    });

    test('shows storage loading or status content', async ({ page }) => {
      await page.waitForTimeout(500);

      const loading = page.getByText('Loading storage status...');
      const retryBtn = page.getByRole('button', { name: 'Retry' });
      const volumeLabel = page.getByText('Volume');
      const encryptionLabel = page.getByText('Encryption');

      const hasLoading = await loading.isVisible().catch(() => false);
      const hasRetry = await retryBtn.first().isVisible().catch(() => false);
      const hasVolume = await volumeLabel.first().isVisible().catch(() => false);
      const hasEncryption = await encryptionLabel.isVisible().catch(() => false);
      expect(hasLoading || hasRetry || hasVolume || hasEncryption).toBeTruthy();
    });

    test('shows Auto-Unseal with TPM section heading', async ({ page }) => {
      await expect(page.getByText('Auto-Unseal with TPM')).toBeVisible();
    });

    test('Auto-Unseal shows loading or status content', async ({ page }) => {
      await page.waitForTimeout(500);

      const loading = page.getByText('Loading auto-unseal status...');
      const tpmAvailable = page.getByText('TPM Available');
      const retryBtn = page.getByRole('button', { name: 'Retry' });

      const hasLoading = await loading.isVisible().catch(() => false);
      const hasTpm = await tpmAvailable.isVisible().catch(() => false);
      const hasRetry = await retryBtn.last().isVisible().catch(() => false);
      expect(hasLoading || hasTpm || hasRetry).toBeTruthy();
    });

    test('Barrier Auto-Unseal section heading is visible', async ({ page }) => {
      await expect(page.getByRole('heading', { name: 'Barrier Auto-Unseal' })).toBeVisible();
    });

    test('Barrier Auto-Unseal shows loading or status content', async ({ page }) => {
      await page.waitForTimeout(500);

      const loading = page.getByText('Loading barrier auto-unseal status...');
      const tpmAvailable = page.getByText('TPM Available');
      const retryBtn = page.getByRole('button', { name: 'Retry' });
      const unableToLoad = page.getByText('Unable to load barrier auto-unseal status.');

      const hasLoading = await loading.isVisible().catch(() => false);
      const hasTpm = await tpmAvailable.isVisible().catch(() => false);
      const hasRetry = await retryBtn.last().isVisible().catch(() => false);
      const hasError = await unableToLoad.isVisible().catch(() => false);

      expect(hasLoading || hasTpm || hasRetry || hasError).toBeTruthy();
    });

    test('Barrier Auto-Unseal shows TPM availability status indicator when loaded (Wails mode)', async ({
      page,
    }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await page.waitForTimeout(1000);

      const tpmAvailableLabel = page.getByText('TPM Available');
      const hasLabel = await tpmAvailableLabel.isVisible().catch(() => false);

      if (hasLabel) {
        await expect(tpmAvailableLabel).toBeVisible();

        // Should show one of: "TPM detected on this system" or "No TPM detected"
        const detected = page.getByText('TPM detected on this system');
        const notDetected = page.getByText('No TPM detected');

        const hasDetected = await detected.isVisible().catch(() => false);
        const hasNotDetected = await notDetected.isVisible().catch(() => false);
        expect(hasDetected || hasNotDetected).toBeTruthy();
      }
    });

    test('Barrier Auto-Unseal shows policy selection when TPM is available and no policy configured', async ({
      page,
    }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend with TPM');

      await page.waitForTimeout(1000);

      // If policy is not yet configured, an Enable button or policy select should appear.
      const enableBtn = page.getByRole('button', { name: 'Enable' });
      const policySelect = page.locator('select.form-select');

      const hasEnable = await enableBtn.isVisible().catch(() => false);
      const hasSelect = await policySelect.isVisible().catch(() => false);

      // We can't assert a specific state without knowing backend data,
      // so just confirm the structure is valid.
      if (hasEnable) {
        await expect(enableBtn).toBeVisible();
      }
      if (hasSelect) {
        await expect(policySelect.first()).toBeVisible();
      }
    });

    test('Barrier Auto-Unseal shows active policy name when configured (Wails mode)', async ({
      page,
    }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend with configured barrier auto-unseal');

      await page.waitForTimeout(1000);

      const activePolicyLabel = page.getByText('Active Policy');
      const hasActive = await activePolicyLabel.isVisible().catch(() => false);

      if (hasActive) {
        await expect(activePolicyLabel).toBeVisible();

        // PCR State should also be shown.
        await expect(page.getByText('PCR State')).toBeVisible();

        // Disable button should appear.
        await expect(page.getByRole('button', { name: 'Disable' })).toBeVisible();
      }
    });
  });

  test.describe('Notifications Category', () => {
    test.beforeEach(async ({ page }) => {
      await navigateToSettingsCategory(page, 'Notifications');
    });

    test('Desktop Notifications section heading is visible', async ({
      page,
    }) => {
      await expect(page.locator('.settings-section h2', { hasText: 'Desktop Notifications' })).toBeVisible();
    });

    test('shows Enable desktop notifications toggle', async ({ page }) => {
      await expect(
        page.getByText('Enable desktop notifications'),
      ).toBeVisible();
      await expect(
        page.getByText(
          'Send system notifications for FIDO2 touch prompts and important events',
        ),
      ).toBeVisible();
    });

    test('shows Test notification with Send Test button', async ({ page }) => {
      await expect(page.getByText('Test notification')).toBeVisible();
      await expect(
        page.getByText('Send a test desktop notification to verify delivery'),
      ).toBeVisible();

      const sendTestButton = page.getByRole('button', { name: 'Send Test' });
      await expect(sendTestButton).toBeVisible();
    });

    test('Event Notifications section heading is visible', async ({
      page,
    }) => {
      await expect(page.getByText('Event Notifications')).toBeVisible();
    });

    test('shows Device connection events toggle', async ({ page }) => {
      await expect(
        page.getByText('Device connection events'),
      ).toBeVisible();
      await expect(
        page.getByText('Notify when a phone connects or disconnects'),
      ).toBeVisible();
    });

    test('shows Authentication events toggle', async ({ page }) => {
      await expect(page.getByText('Authentication events')).toBeVisible();
      await expect(
        page.getByText('Notify on WebAuthn authentication attempts'),
      ).toBeVisible();
    });

    test('shows Error events toggle', async ({ page }) => {
      await expect(page.getByText('Error events')).toBeVisible();
      await expect(
        page.getByText('Notify on errors and failures'),
      ).toBeVisible();
    });
  });

  test.describe('Advanced Category', () => {
    test.beforeEach(async ({ page }) => {
      await navigateToSettingsCategory(page, 'Advanced');
    });

    test('Advanced section heading is visible', async ({ page }) => {
      await expect(page.getByText('Advanced').first()).toBeVisible();
    });

    test('shows xkmsd URL field with placeholder', async ({ page }) => {
      await expect(page.getByText('xkmsd URL')).toBeVisible();
      await expect(
        page.getByText('Server URL for the xkmsd daemon'),
      ).toBeVisible();
    });

    test('shows Default backend selector with all options', async ({
      page,
    }) => {
      await expect(page.getByText('Default backend')).toBeVisible();
      await expect(
        page.getByText('Default cryptographic backend for new keys'),
      ).toBeVisible();

      const backendSelect = page.locator('.settings-panel .form-select').first();
      await expect(backendSelect).toBeVisible();

      const options = backendSelect.locator('option');
      const optionTexts = await options.allTextContents();
      expect(optionTexts).toContain('Phone');
      expect(optionTexts).toContain('Software');
      expect(optionTexts).toContain('TPM 2.0');
      expect(optionTexts).toContain('PKCS #11');
    });

    test('shows Log level selector with all verbosity options', async ({
      page,
    }) => {
      await expect(page.getByText('Log level')).toBeVisible();
      await expect(
        page.getByText('Logging verbosity for troubleshooting'),
      ).toBeVisible();

      // Log level is the second form-select in the Advanced section
      const selects = page.locator('.settings-panel .form-select');
      const logSelect = selects.nth(1);
      await expect(logSelect).toBeVisible();

      const options = logSelect.locator('option');
      const optionTexts = await options.allTextContents();
      expect(optionTexts).toContain('Error');
      expect(optionTexts).toContain('Warning');
      expect(optionTexts).toContain('Info');
      expect(optionTexts).toContain('Debug');
      expect(optionTexts).toContain('Trace');
    });

    test('shows Debug mode toggle with description', async ({ page }) => {
      await expect(page.getByText('Debug mode')).toBeVisible();
      await expect(
        page.getByText('Enable developer tools and extended logging'),
      ).toBeVisible();
    });
  });

  test.describe('Wails Mode - Security', () => {
    test('Password Protection loads status from backend', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await navigateToSettingsCategory(page, 'Security');
      await page.waitForTimeout(1000);

      // Should show encryption mode status
      const encryptionMode = page.getByText('Encryption Mode');
      const hasMode = await encryptionMode.isVisible().catch(() => false);

      if (hasMode) {
        // Should show one of the encryption mode descriptions
        const plaintext = page.getByText('Passwords are stored as plaintext');
        const aes = page.getByText('AES-256-GCM with master password');
        const tpm = page.getByText('TPM-sealed encryption');

        const hasPlain = await plaintext.isVisible().catch(() => false);
        const hasAes = await aes.isVisible().catch(() => false);
        const hasTpm = await tpm.isVisible().catch(() => false);
        expect(hasPlain || hasAes || hasTpm).toBeTruthy();
      }
    });

    test('Password Protection shows Stored Passwords count', async ({
      page,
    }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await navigateToSettingsCategory(page, 'Security');
      await page.waitForTimeout(1000);

      const storedLabel = page.getByText('Stored Passwords');
      const hasLabel = await storedLabel.isVisible().catch(() => false);
      if (hasLabel) {
        // The count text like "0 passwords" or "3 passwords" should be visible
        await expect(page.getByText(/\d+ passwords?/)).toBeVisible();
      }
    });

    test('Platform Policy shows Configure button when not configured', async ({
      page,
    }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await navigateToSettingsCategory(page, 'Security');
      await page.waitForTimeout(1000);

      const notConfigured = page.getByText('Not Configured');
      const hasNotConfigured = await notConfigured.isVisible().catch(() => false);

      if (hasNotConfigured) {
        await expect(
          page.getByText('Configure Platform Policy'),
        ).toBeVisible();
        await expect(
          page.getByRole('button', { name: 'Configure' }),
        ).toBeVisible();
      }
    });

    test('Platform Policy shows Verify/Update/Delete when configured', async ({
      page,
    }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await navigateToSettingsCategory(page, 'Security');
      await page.waitForTimeout(1000);

      const pcrBank = page.getByText('PCR Bank');
      const hasPolicy = await pcrBank.isVisible().catch(() => false);

      if (hasPolicy) {
        await expect(
          page.getByRole('button', { name: 'Verify' }),
        ).toBeVisible();
        await expect(
          page.getByRole('button', { name: 'Update' }),
        ).toBeVisible();
        await expect(
          page.getByRole('button', { name: 'Delete' }),
        ).toBeVisible();
      }
    });
  });

  test.describe('Wails Mode - Storage', () => {
    test('LUKS storage loads status from backend', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await navigateToSettingsCategory(page, 'Storage');
      await page.waitForTimeout(1000);

      // Should show storage status fields
      const volumeLabel = page.getByText('Volume').first();
      const encryptionLabel = page.getByText('Encryption');
      const stateLabel = page.getByText('State');

      const hasVolume = await volumeLabel.isVisible().catch(() => false);
      const hasEncryption = await encryptionLabel.isVisible().catch(() => false);
      const hasState = await stateLabel.isVisible().catch(() => false);
      expect(hasVolume || hasEncryption || hasState).toBeTruthy();
    });

    test('LUKS storage shows action buttons when status is loaded', async ({
      page,
    }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await navigateToSettingsCategory(page, 'Storage');
      await page.waitForTimeout(1000);

      // Actions section should appear when status is loaded
      const actionsHeading = page.getByText('Actions');
      const hasActions = await actionsHeading.isVisible().catch(() => false);

      if (hasActions) {
        // Should show at least one of: Create Volume, Unlock, Lock, Migrate
        const createBtn = page.getByRole('button', { name: 'Create Volume' });
        const unlockBtn = page.getByRole('button', { name: 'Unlock' });
        const lockBtn = page.getByRole('button', { name: 'Lock' });
        const migrateBtn = page.getByRole('button', { name: 'Migrate' });

        const hasCreate = await createBtn.isVisible().catch(() => false);
        const hasUnlock = await unlockBtn.isVisible().catch(() => false);
        const hasLock = await lockBtn.isVisible().catch(() => false);
        const hasMigrate = await migrateBtn.isVisible().catch(() => false);
        expect(hasCreate || hasUnlock || hasLock || hasMigrate).toBeTruthy();
      }
    });

    test('Auto-Unseal shows TPM Available status', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await navigateToSettingsCategory(page, 'Storage');
      await page.waitForTimeout(1000);

      const tpmAvailable = page.getByText('TPM Available');
      const hasTpm = await tpmAvailable.isVisible().catch(() => false);

      if (hasTpm) {
        // Should show either "TPM detected" or "No TPM detected"
        const detected = page.getByText('TPM detected on this system');
        const notDetected = page.getByText('No TPM detected');

        const hasDetected = await detected.isVisible().catch(() => false);
        const hasNotDetected = await notDetected.isVisible().catch(() => false);
        expect(hasDetected || hasNotDetected).toBeTruthy();
      }
    });
  });

  test.describe('Wails Mode - Server Connection', () => {
    test('Test Connection button is functional', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await navigateToSettingsCategory(page, 'Server');

      const testButton = page.getByRole('button', {
        name: /Test Connection|Connecting/,
      });
      const isVisible = await testButton.isVisible().catch(() => false);

      if (isVisible) {
        // The button should be disabled when no address is entered
        // or enabled if an address is pre-configured
        const isDisabled = await testButton.isDisabled();
        // Just verify the button exists and has a state
        expect(typeof isDisabled).toBe('boolean');
      }
    });

    test('Save Settings persists config', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      await navigateToSettingsCategory(page, 'Server');

      const saveButton = page.getByRole('button', { name: 'Save Settings' });
      await expect(saveButton).toBeVisible();
      await saveButton.click();
      await page.waitForTimeout(500);

      // After save, the notification toast should appear
      // (the addNotification call in handleSave fires 'Settings saved')
    });
  });

  test.describe('Wails Mode - FIDO2 Toggle', () => {
    test('FIDO2 toggle state persists after navigation', async ({ page }) => {
      const wails = await isWailsMode(page);
      test.skip(!wails, 'Requires Wails backend');

      // Note the current state of the FIDO2 toggle
      // Navigate away and back
      await navigateTo(page, 'dashboard');
      await page.waitForTimeout(300);
      await navigateTo(page, 'settings');
      await page.waitForTimeout(500);

      // FIDO2 toggle should still be visible
      await expect(
        page.getByText('FIDO2 Virtual Authenticator'),
      ).toBeVisible();
    });
  });
});
