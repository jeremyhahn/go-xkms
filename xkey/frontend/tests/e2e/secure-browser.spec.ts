import { test, expect, type Page } from '@playwright/test';
import {
  navigateTo,
  waitForAppReady,
  ensureSidebarExpanded,
  navigateToSettingsCategory,
} from './helpers';

/**
 * Playwright coverage for the Secure Browser Launch card in Settings →
 * Browser. The tests install a mocked Wails backend via addInitScript
 * before navigating so that SecureBrowserService returns a deterministic
 * set of browsers and LaunchBrowser call arguments can be captured.
 */

interface SecureBrowserTestBackend {
  browsers: Array<{ name: string; path: string }>;
  certCount: number;
  config: {
    default_browser: string;
    custom_command: string;
    include_trust_bundle: boolean;
    chrome_profile_mode: string;
    firefox_profile_mode: string;
  };
  launchResult?: {
    browser: string;
    family: string;
    mode: string;
    cert_count: number;
    pid: number;
  };
  launchError?: string;
}

async function installSecureBrowserMock(
  page: Page,
  backend: SecureBrowserTestBackend,
): Promise<void> {
  const payload = JSON.stringify(backend);

  await page.addInitScript((serialized: string) => {
    const data = JSON.parse(serialized);
    const launchCalls: Array<{ browserPath: string; url: string }> = [];
    (window as any).__secureBrowserLaunchCalls = launchCalls;
    (window as any).__secureBrowserConfig = { ...data.config };

    (window as any).go = {
      main: {},
      services: {
        // Setup wizard gate — keep the app out of the wizard flow.
        SetupWizardService: {
          GetStartupState: async () => ({
            setup_complete: true,
            enterprise_mode: false,
          }),
          GetPolicy: async () => ({}),
        },
        AuthService: {
          SetModeUser: async () => {},
        },
        TPMService: {
          GetStatus: async () => ({ available: false, device_exists: false }),
        },
        // Extension/autofill — required so the Browser category reactive
        // block terminates. Without these the reactive statement that
        // triggers loadExtensionPairingStatus() loops indefinitely because
        // extensionFullStatus stays null while extensionLoading flips.
        PairingService: {
          GetExtensionFullStatus: async () => ({
            ipc_running: true,
            ipc_socket_path: '/tmp/xkey.sock',
            paired_extensions: [],
            manifests: [],
          }),
          InstallManifest: async () => {},
          UninstallManifest: async () => {},
        },
        AutoFillService: {
          IsEnabled: async () => false,
          GetRequireAuthentication: async () => false,
        },
        AppService: {
          GetConfig: async () => ({
            start_minimized: false,
            auto_tray: false,
            server_protocol: 'grpc',
            server_address: '',
            server_tls_enabled: false,
            server_tls_skip_verify: false,
            server_tls_ca_file: '',
            server_auto_connect: false,
            fido2_authenticator_enabled: false,
            fido2_require_user_presence: true,
            fido2_user_intent_check: true,
            clipboard_timeout: 30,
            require_auth: false,
            app_auto_lock_minutes: 15,
            app_lock_on_screen_lock: true,
            barrier_auto_unseal_enabled: false,
            sealer_backend: 'software',
            api_explorer_sandbox_policy: 'allow-same-origin allow-scripts allow-forms',
            developer_tools: true,
            browser_extension_enabled: false,
          }),
        },
        BrowserService: {
          GetConfig: async () => ({ ...((window as any).__secureBrowserConfig) }),
          SetConfig: async (cfg: any) => {
            (window as any).__secureBrowserConfig = { ...cfg };
          },
          DetectBrowsers: async () => [
            { name: 'System Default', path: 'system' },
            ...data.browsers,
          ],
          GetTrustBundlePath: async () => '/tmp/bundle.pem',
          OpenURL: async (_url: string) => {},
        },
        TrustService: {
          GetBrowserBundleStatus: async () => ({
            exists: false,
            stale: false,
            cert_count: 0,
            last_generated: '',
            bundle_path: '/tmp/bundle.pem',
          }),
          CertificateCount: async () => data.certCount,
        },
        SecureBrowserService: {
          DetectBrowsers: async () => data.browsers,
          LaunchBrowser: async (browserPath: string, url: string) => {
            launchCalls.push({ browserPath, url });
            if (data.launchError) {
              throw new Error(data.launchError);
            }
            return data.launchResult ?? {
              browser: browserPath,
              family: 'chrome',
              mode: 'isolated',
              cert_count: data.certCount,
              pid: 12345,
            };
          },
        },
      },
    };
  }, payload);
}

const defaultBackend: SecureBrowserTestBackend = {
  browsers: [
    { name: 'Firefox', path: '/usr/bin/firefox' },
    { name: 'Google Chrome', path: '/usr/bin/google-chrome' },
  ],
  certCount: 3,
  config: {
    default_browser: 'system',
    custom_command: '',
    include_trust_bundle: false,
    chrome_profile_mode: 'isolated',
    firefox_profile_mode: 'isolated',
  },
};

async function gotoBrowserSettings(
  page: Page,
  backend: SecureBrowserTestBackend = defaultBackend,
): Promise<void> {
  await installSecureBrowserMock(page, backend);
  await page.goto('/');
  await waitForAppReady(page);
  await ensureSidebarExpanded(page);
  await navigateTo(page, 'settings');
  await navigateToSettingsCategory(page, 'Browser');
  // Wait for async loadBrowserConfig / loadSecureBrowserData to resolve.
  await page.waitForSelector('[data-testid="secure-browser-card"]', { timeout: 5_000 });
}

test.describe('Secure Browser Launch card', () => {
  test('renders the card with its heading', async ({ page }) => {
    await gotoBrowserSettings(page);

    const card = page.locator('[data-testid="secure-browser-card"]');
    await expect(card).toBeVisible();
    await expect(card.getByText('Secure Browser Launch')).toBeVisible();
  });

  test('populates the browser dropdown from SecureBrowserService.DetectBrowsers', async ({
    page,
  }) => {
    await gotoBrowserSettings(page);

    const select = page.locator('[data-testid="secure-browser-select"]');
    await expect(select).toBeVisible();

    const options = await select.locator('option').allTextContents();
    expect(options).toEqual(['Firefox', 'Google Chrome']);
  });

  test('renders the warning banner when no Chrome/Firefox family browsers are detected', async ({
    page,
  }) => {
    await gotoBrowserSettings(page, {
      ...defaultBackend,
      browsers: [],
    });

    await expect(
      page.locator('[data-testid="secure-browser-no-browsers"]'),
    ).toBeVisible();
    await expect(
      page.locator('[data-testid="secure-browser-select"]'),
    ).toHaveCount(0);
    await expect(
      page.locator('[data-testid="secure-browser-launch-btn"]'),
    ).toHaveCount(0);
  });

  test('profile mode selects render with isolated default', async ({ page }) => {
    await gotoBrowserSettings(page);

    const chromeMode = page.locator('[data-testid="chrome-profile-mode"]');
    const firefoxMode = page.locator('[data-testid="firefox-profile-mode"]');

    await expect(chromeMode).toBeVisible();
    await expect(firefoxMode).toBeVisible();
    await expect(chromeMode).toHaveValue('isolated');
    await expect(firefoxMode).toHaveValue('isolated');
  });

  test('cert count is displayed from TrustService.CertificateCount', async ({
    page,
  }) => {
    await gotoBrowserSettings(page, { ...defaultBackend, certCount: 7 });

    const card = page.locator('[data-testid="secure-browser-card"]');
    await expect(card.getByText('Certificates to inject')).toBeVisible();
    await expect(card.getByText('7', { exact: true })).toBeVisible();
  });

  test('launch button is disabled when cert count is zero', async ({ page }) => {
    await gotoBrowserSettings(page, { ...defaultBackend, certCount: 0 });

    const btn = page.locator('[data-testid="secure-browser-launch-btn"]');
    await expect(btn).toBeVisible();
    await expect(btn).toBeDisabled();
  });

  test('launch button enabled when cert count > 0 and browser selected', async ({
    page,
  }) => {
    await gotoBrowserSettings(page);

    const btn = page.locator('[data-testid="secure-browser-launch-btn"]');
    await expect(btn).toBeEnabled();
  });

  test('clicking Launch calls SecureBrowserService.LaunchBrowser with the selected browser and URL', async ({
    page,
  }) => {
    await gotoBrowserSettings(page);

    // Select Google Chrome from the dropdown.
    await page
      .locator('[data-testid="secure-browser-select"]')
      .selectOption('/usr/bin/google-chrome');

    // Set the URL input.
    const urlInput = page.locator('[data-testid="secure-browser-url"]');
    await urlInput.fill('https://example.org');

    await page.locator('[data-testid="secure-browser-launch-btn"]').click();

    await page.waitForFunction(
      () => ((window as any).__secureBrowserLaunchCalls ?? []).length > 0,
      { timeout: 5_000 },
    );

    const calls = await page.evaluate(
      () => (window as any).__secureBrowserLaunchCalls as Array<{ browserPath: string; url: string }>,
    );
    expect(calls).toHaveLength(1);
    expect(calls[0]).toEqual({
      browserPath: '/usr/bin/google-chrome',
      url: 'https://example.org',
    });
  });

  test('detected family label updates when the browser selection changes', async ({
    page,
  }) => {
    await gotoBrowserSettings(page);

    const card = page.locator('[data-testid="secure-browser-card"]');

    // First browser is Firefox by default.
    await page
      .locator('[data-testid="secure-browser-select"]')
      .selectOption('/usr/bin/firefox');
    await expect(card.getByText('firefox', { exact: true })).toBeVisible();

    await page
      .locator('[data-testid="secure-browser-select"]')
      .selectOption('/usr/bin/google-chrome');
    await expect(card.getByText('chrome', { exact: true })).toBeVisible();
  });

  test('chrome_profile_mode change is persisted via BrowserService.SetConfig', async ({
    page,
  }) => {
    await gotoBrowserSettings(page);

    await page
      .locator('[data-testid="chrome-profile-mode"]')
      .selectOption('shared');

    // The autosave debounces at 300ms.
    await page.waitForTimeout(500);

    const saved = await page.evaluate(
      () => (window as any).__secureBrowserConfig?.chrome_profile_mode,
    );
    expect(saved).toBe('shared');
  });

  test('firefox_profile_mode change is persisted via BrowserService.SetConfig', async ({
    page,
  }) => {
    await gotoBrowserSettings(page);

    await page
      .locator('[data-testid="firefox-profile-mode"]')
      .selectOption('shared');

    await page.waitForTimeout(500);

    const saved = await page.evaluate(
      () => (window as any).__secureBrowserConfig?.firefox_profile_mode,
    );
    expect(saved).toBe('shared');
  });
});
