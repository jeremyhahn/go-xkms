import { test, expect, type Page } from '@playwright/test';
import {
  navigateTo,
  waitForAppReady,
  ensureSidebarExpanded,
} from './helpers';

/**
 * Playwright coverage for the Browser application view (Applications →
 * Browser). The view renders a summary card plus one card per detected
 * Chrome/Firefox family browser. Each card exposes a secure launch pane
 * (URL + profile mode + Launch) and an extension pane (manifest
 * install/uninstall).
 *
 * Mock strategy — two-phase injection:
 *
 * Phase 1 (addInitScript): Runs before the page scripts load. Sets
 * window-global state arrays (__browserViewLaunchCalls, etc.) and installs
 * a provisional window.go shim for Vite-only runs (no real Wails bridge).
 *
 * Phase 2 (page.evaluate after waitForAppReady): Patches
 * window.go.services with the test service implementations. This runs
 * AFTER the real Wails runtime has injected window.go, so it correctly
 * overrides the live bindings regardless of whether the real Wails bridge
 * is present. The Browser component's onMount(load) fires on navigation
 * (after this patch), so every backend call goes to the mock.
 */

interface BrowserViewTestBackend {
  browsers: Array<{ name: string; path: string }>;
  certCount: number;
  manifests: Array<{ browser: string; installed: boolean }>;
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

/**
 * Phase 1: Install window-global state and a provisional window.go shim
 * via addInitScript (runs before page JS). In Wails mode the real runtime
 * will overwrite window.go; patchBrowserViewServices() re-installs the
 * service mocks after app ready.
 */
async function installBrowserViewInitScript(
  page: Page,
  backend: BrowserViewTestBackend,
): Promise<void> {
  const payload = JSON.stringify(backend);

  await page.addInitScript((serialized: string) => {
    const data = JSON.parse(serialized);
    const launchCalls: Array<{ browserPath: string; url: string }> = [];
    const manifestCalls: Array<{ action: 'install' | 'uninstall'; browser: string }> = [];
    (window as any).__browserViewLaunchCalls = launchCalls;
    (window as any).__browserViewManifestCalls = manifestCalls;
    (window as any).__browserViewConfig = { ...data.config };
    (window as any).__browserViewManifests = data.manifests.map(
      (m: { browser: string; installed: boolean }) => ({ ...m }),
    );
    (window as any).__browserViewData = data;

    // Provisional shim: active in Vite-only mode where no real Wails bridge
    // exists. In real-Wails mode patchBrowserViewServices() overwrites this.
    (window as any).go = {
      main: {},
      services: {
        SetupWizardService: {
          GetStartupState: async () => ({
            setup_complete: true,
            enterprise_mode: false,
          }),
          GetPolicy: async () => ({}),
        },
        AuthService: { SetModeUser: async () => {} },
        TPMService: {
          GetStatus: async () => ({ available: false, device_exists: false }),
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
            local_app_access_enabled: false,
          }),
          GetDeveloperTools: async () => true,
        },
        AppLockService: { RecordActivity: async () => {}, GetStatus: async () => ({ is_locked: false }) },
        PairingService: {
          GetExtensionFullStatus: async () => ({
            ipc_running: true,
            ipc_socket_path: '/tmp/xkey.sock',
            paired_extensions: [],
            manifests: (window as any).__browserViewManifests.map(
              (m: { browser: string; installed: boolean }) => ({
                browser: m.browser,
                name: m.browser,
                installed: m.installed,
                path: `/tmp/${m.browser}.json`,
              }),
            ),
          }),
          InstallManifest: async (browser: string) => {
            (window as any).__browserViewManifestCalls.push({ action: 'install', browser });
            const entry = (window as any).__browserViewManifests.find(
              (m: { browser: string }) => m.browser === browser,
            );
            if (entry) entry.installed = true;
          },
          UninstallManifest: async (browser: string) => {
            (window as any).__browserViewManifestCalls.push({ action: 'uninstall', browser });
            const entry = (window as any).__browserViewManifests.find(
              (m: { browser: string }) => m.browser === browser,
            );
            if (entry) entry.installed = false;
          },
        },
        BrowserService: {
          GetConfig: async () => ({ ...((window as any).__browserViewConfig) }),
          SetConfig: async (cfg: any) => {
            (window as any).__browserViewConfig = { ...cfg };
          },
        },
        TrustService: {
          CertificateCount: async () => (window as any).__browserViewData.certCount,
        },
        SecureBrowserService: {
          DetectBrowsers: async () => (window as any).__browserViewData.browsers,
          LaunchBrowser: async (browserPath: string, url: string) => {
            (window as any).__browserViewLaunchCalls.push({ browserPath, url });
            const d = (window as any).__browserViewData;
            if (d.launchError) {
              throw new Error(d.launchError);
            }
            return (
              d.launchResult ?? {
                browser: browserPath,
                family: browserPath.includes('chrome') ? 'chrome' : 'firefox',
                mode: 'isolated',
                cert_count: d.certCount,
                pid: 12345,
              }
            );
          },
        },
      },
    };
  }, payload);
}

/**
 * Phase 2: Patch window.go.services with mock implementations. Called after
 * waitForAppReady so this runs after the real Wails runtime has injected
 * window.go. Overwrites only the services the Browser view uses, leaving
 * any other real services intact (auth, TPM, app-lock, etc. already ran
 * during app init and do not need re-mocking here).
 */
async function patchBrowserViewServices(page: Page): Promise<void> {
  await page.evaluate(() => {
    const svc = (window as any).go?.services;
    if (!svc) return;

    svc.TrustService = {
      ...svc.TrustService,
      CertificateCount: async () => (window as any).__browserViewData.certCount,
    };

    svc.SecureBrowserService = {
      ...svc.SecureBrowserService,
      DetectBrowsers: async () => (window as any).__browserViewData.browsers,
      LaunchBrowser: async (browserPath: string, url: string) => {
        (window as any).__browserViewLaunchCalls.push({ browserPath, url });
        const d = (window as any).__browserViewData;
        if (d.launchError) {
          throw new Error(d.launchError);
        }
        return (
          d.launchResult ?? {
            browser: browserPath,
            family: browserPath.includes('chrome') ? 'chrome' : 'firefox',
            mode: 'isolated',
            cert_count: d.certCount,
            pid: 12345,
          }
        );
      },
    };

    svc.BrowserService = {
      ...svc.BrowserService,
      GetConfig: async () => ({ ...((window as any).__browserViewConfig) }),
      SetConfig: async (cfg: any) => {
        (window as any).__browserViewConfig = { ...cfg };
      },
    };

    svc.PairingService = {
      ...svc.PairingService,
      GetExtensionFullStatus: async () => ({
        ipc_running: true,
        ipc_socket_path: '/tmp/xkey.sock',
        paired_extensions: [],
        manifests: (window as any).__browserViewManifests.map(
          (m: { browser: string; installed: boolean }) => ({
            browser: m.browser,
            name: m.browser,
            installed: m.installed,
            path: `/tmp/${m.browser}.json`,
          }),
        ),
      }),
      InstallManifest: async (browser: string) => {
        (window as any).__browserViewManifestCalls.push({ action: 'install', browser });
        const entry = (window as any).__browserViewManifests.find(
          (m: { browser: string }) => m.browser === browser,
        );
        if (entry) entry.installed = true;
      },
      UninstallManifest: async (browser: string) => {
        (window as any).__browserViewManifestCalls.push({ action: 'uninstall', browser });
        const entry = (window as any).__browserViewManifests.find(
          (m: { browser: string }) => m.browser === browser,
        );
        if (entry) entry.installed = false;
      },
    };
  });
}

const defaultBackend: BrowserViewTestBackend = {
  browsers: [
    { name: 'Firefox', path: '/usr/bin/firefox' },
    { name: 'Google Chrome', path: '/usr/bin/google-chrome' },
  ],
  certCount: 3,
  manifests: [
    { browser: 'chrome', installed: false },
    { browser: 'firefox', installed: true },
  ],
  config: {
    default_browser: 'system',
    custom_command: '',
    include_trust_bundle: false,
    chrome_profile_mode: 'isolated',
    firefox_profile_mode: 'isolated',
  },
};

async function gotoBrowserView(
  page: Page,
  backend: BrowserViewTestBackend = defaultBackend,
): Promise<void> {
  await installBrowserViewInitScript(page, backend);
  await page.goto('/');
  await waitForAppReady(page);
  await ensureSidebarExpanded(page);
  // Patch services after Wails runtime has loaded (overrides real bindings).
  await patchBrowserViewServices(page);
  await navigateTo(page, 'browser');
  // Wait for the Browser view heading to confirm it has mounted and loaded.
  await expect(page.getByRole('heading', { name: 'Browser', level: 1 })).toBeVisible();
}

test.describe('Browser view — navigation', () => {
  test('Browser nav item appears under Applications', async ({ page }) => {
    await installBrowserViewInitScript(page, defaultBackend);
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);

    const nav = page.locator('nav.sidebar button.nav-item', {
      has: page.locator('span.nav-label:text-is("Browser")'),
    });
    await expect(nav).toBeVisible();
  });

  test('clicking Browser nav renders the view', async ({ page }) => {
    await gotoBrowserView(page);
    await expect(page.getByRole('heading', { name: 'Browser', level: 1 })).toBeVisible();
  });
});

test.describe('Browser view — summary card', () => {
  test('displays trust store cert count and detected browser count', async ({
    page,
  }) => {
    await gotoBrowserView(page, { ...defaultBackend, certCount: 7 });
    await expect(page.getByText('7 certificates', { exact: true })).toBeVisible();
    // Browser count: the mock returns 2 browsers; verify the "Detected browsers"
    // summary item shows 2. Scope to the summary info div that follows the label.
    const detectedItem = page.locator('.summary-item', {
      has: page.locator('.field-label', { hasText: 'Detected browsers' }),
    });
    await expect(detectedItem.getByText('2', { exact: true })).toBeVisible();
  });

  test('singular certificate label when count is 1', async ({ page }) => {
    await gotoBrowserView(page, { ...defaultBackend, certCount: 1 });
    await expect(page.getByText('1 certificate', { exact: true })).toBeVisible();
  });

  test('Refresh button re-queries detection and manifest status', async ({
    page,
  }) => {
    await gotoBrowserView(page);

    // Flip Chrome manifest state in the in-memory mock, then click Refresh —
    // the view re-calls PairingService.GetExtensionFullStatus and should
    // render the updated install state.
    await page.evaluate(() => {
      const list = (window as any).__browserViewManifests;
      const entry = list.find(
        (m: { browser: string; installed: boolean }) => m.browser === 'chrome',
      );
      if (entry) entry.installed = true;
    });

    await page.getByRole('button', { name: 'Refresh' }).click();

    const chromeCard = page.locator('[data-testid="browser-card-chrome"]');
    await expect(chromeCard.getByRole('button', { name: 'Uninstall manifest' })).toBeVisible();
  });
});

test.describe('Browser view — empty state', () => {
  test('shows "No supported browsers" when detection returns none', async ({
    page,
  }) => {
    await gotoBrowserView(page, { ...defaultBackend, browsers: [] });

    await expect(page.locator('[data-testid="browser-empty"]')).toBeVisible();
    await expect(page.locator('[data-testid="browser-card-chrome"]')).toHaveCount(0);
    await expect(page.locator('[data-testid="browser-card-firefox"]')).toHaveCount(0);
  });
});

test.describe('Browser view — per-browser cards', () => {
  test('renders one card per detected Chrome/Firefox browser', async ({
    page,
  }) => {
    await gotoBrowserView(page);

    await expect(page.locator('[data-testid="browser-card-firefox"]')).toBeVisible();
    await expect(page.locator('[data-testid="browser-card-chrome"]')).toBeVisible();
  });

  test('card shows the browser name, binary path, and family badge', async ({
    page,
  }) => {
    await gotoBrowserView(page);

    const firefox = page.locator('[data-testid="browser-card-firefox"]');
    await expect(firefox.getByText('Firefox', { exact: true })).toBeVisible();
    await expect(firefox.getByText('/usr/bin/firefox')).toBeVisible();
    await expect(firefox.getByText('firefox', { exact: true })).toBeVisible();

    const chrome = page.locator('[data-testid="browser-card-chrome"]');
    await expect(chrome.getByText('Google Chrome')).toBeVisible();
    await expect(chrome.getByText('/usr/bin/google-chrome')).toBeVisible();
    await expect(chrome.getByText('chrome', { exact: true })).toBeVisible();
  });
});

test.describe('Browser view — launch', () => {
  test('Launch button calls SecureBrowserService.LaunchBrowser with card URL', async ({
    page,
  }) => {
    await gotoBrowserView(page);

    const chromeCard = page.locator('[data-testid="browser-card-chrome"]');
    const urlInput = chromeCard.locator('input[type="text"]');
    await urlInput.fill('https://example.org');

    await chromeCard.getByRole('button', { name: 'Launch secure browser' }).click();

    await page.waitForFunction(
      () => ((window as any).__browserViewLaunchCalls ?? []).length > 0,
      { timeout: 5_000 },
    );

    const calls = await page.evaluate(
      () =>
        (window as any).__browserViewLaunchCalls as Array<{
          browserPath: string;
          url: string;
        }>,
    );
    expect(calls).toHaveLength(1);
    expect(calls[0]).toEqual({
      browserPath: '/usr/bin/google-chrome',
      url: 'https://example.org',
    });
  });

  test('empty URL falls back to about:blank', async ({ page }) => {
    await gotoBrowserView(page);

    const firefoxCard = page.locator('[data-testid="browser-card-firefox"]');
    // Input default is 'about:blank'; clear it then launch.
    await firefoxCard.locator('input[type="text"]').fill('');

    await firefoxCard
      .getByRole('button', { name: 'Launch secure browser' })
      .click();

    await page.waitForFunction(
      () => ((window as any).__browserViewLaunchCalls ?? []).length > 0,
      { timeout: 5_000 },
    );

    const calls = await page.evaluate(
      () =>
        (window as any).__browserViewLaunchCalls as Array<{
          browserPath: string;
          url: string;
        }>,
    );
    expect(calls[0]).toEqual({
      browserPath: '/usr/bin/firefox',
      url: 'about:blank',
    });
  });

  test('Launch button is disabled when trust store is empty', async ({
    page,
  }) => {
    await gotoBrowserView(page, { ...defaultBackend, certCount: 0 });

    const card = page.locator('[data-testid="browser-card-chrome"]');
    const btn = card.getByRole('button', { name: 'Launch secure browser' });
    await expect(btn).toBeDisabled();
  });

  test('each card launches only its own browser', async ({ page }) => {
    await gotoBrowserView(page);

    const firefox = page.locator('[data-testid="browser-card-firefox"]');
    await firefox.locator('input[type="text"]').fill('https://mozilla.org');
    await firefox.getByRole('button', { name: 'Launch secure browser' }).click();

    await page.waitForFunction(
      () => ((window as any).__browserViewLaunchCalls ?? []).length === 1,
    );

    const chrome = page.locator('[data-testid="browser-card-chrome"]');
    await chrome.locator('input[type="text"]').fill('https://google.com');
    await chrome.getByRole('button', { name: 'Launch secure browser' }).click();

    await page.waitForFunction(
      () => ((window as any).__browserViewLaunchCalls ?? []).length === 2,
    );

    const calls = await page.evaluate(
      () =>
        (window as any).__browserViewLaunchCalls as Array<{
          browserPath: string;
          url: string;
        }>,
    );
    expect(calls).toEqual([
      { browserPath: '/usr/bin/firefox', url: 'https://mozilla.org' },
      { browserPath: '/usr/bin/google-chrome', url: 'https://google.com' },
    ]);
  });
});

test.describe('Browser view — profile mode', () => {
  test('profile mode defaults to isolated from BrowserService.GetConfig', async ({
    page,
  }) => {
    await gotoBrowserView(page);

    const chromeCard = page.locator('[data-testid="browser-card-chrome"]');
    const select = chromeCard.locator('select');
    await expect(select).toHaveValue('isolated');
  });

  test('changing chrome profile mode is persisted via BrowserService.SetConfig', async ({
    page,
  }) => {
    await gotoBrowserView(page);

    await page
      .locator('[data-testid="browser-card-chrome"] select')
      .selectOption('shared');

    await page.waitForFunction(
      () => (window as any).__browserViewConfig?.chrome_profile_mode === 'shared',
      { timeout: 5_000 },
    );
  });

  test('changing firefox profile mode is persisted via BrowserService.SetConfig', async ({
    page,
  }) => {
    await gotoBrowserView(page);

    await page
      .locator('[data-testid="browser-card-firefox"] select')
      .selectOption('shared');

    await page.waitForFunction(
      () => (window as any).__browserViewConfig?.firefox_profile_mode === 'shared',
      { timeout: 5_000 },
    );
  });

  test('firefox mode change does not clobber chrome mode', async ({ page }) => {
    await gotoBrowserView(page);

    await page
      .locator('[data-testid="browser-card-firefox"] select')
      .selectOption('shared');

    await page.waitForFunction(
      () => (window as any).__browserViewConfig?.firefox_profile_mode === 'shared',
      { timeout: 5_000 },
    );

    const chromeMode = await page.evaluate(
      () => (window as any).__browserViewConfig?.chrome_profile_mode,
    );
    expect(chromeMode).toBe('isolated');
  });
});

test.describe('Browser view — extension manifest management', () => {
  test('card reflects current manifest install state per family', async ({
    page,
  }) => {
    await gotoBrowserView(page);

    const firefox = page.locator('[data-testid="browser-card-firefox"]');
    await expect(
      firefox.getByRole('button', { name: 'Uninstall manifest' }),
    ).toBeVisible();

    const chrome = page.locator('[data-testid="browser-card-chrome"]');
    await expect(
      chrome.getByRole('button', { name: 'Install manifest' }),
    ).toBeVisible();
  });

  test('Install manifest calls PairingService.InstallManifest with family name', async ({
    page,
  }) => {
    await gotoBrowserView(page);

    const chrome = page.locator('[data-testid="browser-card-chrome"]');
    await chrome.getByRole('button', { name: 'Install manifest' }).click();

    await page.waitForFunction(
      () => ((window as any).__browserViewManifestCalls ?? []).length > 0,
      { timeout: 5_000 },
    );

    const calls = await page.evaluate(
      () =>
        (window as any).__browserViewManifestCalls as Array<{
          action: string;
          browser: string;
        }>,
    );
    expect(calls[0]).toEqual({ action: 'install', browser: 'chrome' });

    // After successful install the card should show Uninstall.
    await expect(
      chrome.getByRole('button', { name: 'Uninstall manifest' }),
    ).toBeVisible();
  });

  test('Uninstall manifest calls PairingService.UninstallManifest with family name', async ({
    page,
  }) => {
    await gotoBrowserView(page);

    const firefox = page.locator('[data-testid="browser-card-firefox"]');
    await firefox.getByRole('button', { name: 'Uninstall manifest' }).click();

    await page.waitForFunction(
      () => ((window as any).__browserViewManifestCalls ?? []).length > 0,
      { timeout: 5_000 },
    );

    const calls = await page.evaluate(
      () =>
        (window as any).__browserViewManifestCalls as Array<{
          action: string;
          browser: string;
        }>,
    );
    expect(calls[0]).toEqual({ action: 'uninstall', browser: 'firefox' });

    await expect(
      firefox.getByRole('button', { name: 'Install manifest' }),
    ).toBeVisible();
  });

  test('chrome install does not touch firefox manifest state', async ({
    page,
  }) => {
    await gotoBrowserView(page);

    const chrome = page.locator('[data-testid="browser-card-chrome"]');
    await chrome.getByRole('button', { name: 'Install manifest' }).click();

    await page.waitForFunction(
      () => ((window as any).__browserViewManifestCalls ?? []).length > 0,
    );

    const firefox = page.locator('[data-testid="browser-card-firefox"]');
    await expect(
      firefox.getByRole('button', { name: 'Uninstall manifest' }),
    ).toBeVisible();
  });
});
