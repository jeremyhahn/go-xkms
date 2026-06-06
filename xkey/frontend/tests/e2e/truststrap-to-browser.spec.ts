import { test, expect, type Page } from '@playwright/test';
import {
  navigateTo,
  waitForAppReady,
  ensureSidebarExpanded,
} from './helpers';

/**
 * End-to-end flow: bootstrap the xkey trust store from a (mocked) xkms
 * server via go-truststrap (SPKI and Noise), then confirm the Browser
 * view reflects the new cert count and can launch a secure browser
 * pointed at the xkms web service URL.
 *
 * Mock strategy — two-phase injection (same pattern as secure-browser.spec.ts):
 *
 * Phase 1 (addInitScript): Runs before page scripts load. Sets window-global
 * recording state (__trustStrapCalls, __launchCalls, __certs) and installs a
 * provisional window.go shim. The real Wails runtime overwrites window.go
 * after load; the globals survive because they are on window directly.
 *
 * Phase 2 (patchTrustToBrowserServices, called after waitForAppReady):
 * Patches window.go.services on the live object. Because the Svelte views
 * navigate AFTER this patch, all service calls go to the recording closures.
 */

interface TestCAEntry {
  id: string;
  subject: { common_name: string };
  fingerprint: string;
  tags?: string[];
}

interface TrustStrapCall {
  method: string;
  server: string;
  bundle_path: string;
  dns_server: string;
  dns_over_tls: boolean;
  server_static_key: string;
  spki_pin_sha256: string;
}

/**
 * Phase 1: Install window-global recording state and a provisional window.go
 * shim via addInitScript. In real-Wails mode patchTrustToBrowserServices()
 * re-installs the service mocks after app ready.
 */
async function installBackendInitScript(page: Page): Promise<void> {
  await page.addInitScript(() => {
    const trustStrapCalls: TrustStrapCall[] = [];
    const launchCalls: Array<{ browserPath: string; url: string }> = [];
    const certs: TestCAEntry[] = [];
    const installedManifests: Record<string, boolean> = {
      chrome: false,
      firefox: false,
    };

    (window as any).__trustStrapCalls = trustStrapCalls;
    (window as any).__launchCalls = launchCalls;
    (window as any).__certs = certs;
    (window as any).__installedManifests = installedManifests;

    // Provisional shim: active in Vite-only mode where no real Wails bridge
    // exists. In real-Wails mode patchTrustToBrowserServices() overwrites this.
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
            setup_complete: true,
            storage_type: 'file',
            barrier_initialized: false,
            browser_extension_enabled: false,
            server_protocol: 'rest',
            server_address: '',
            server_tls_enabled: false,
            server_auto_connect: false,
            sealer_backend: 'software',
            developer_tools: true,
            fido2_authenticator_enabled: false,
            fido2_require_user_presence: true,
            fido2_user_intent_check: true,
            clipboard_timeout: 30,
            require_auth: false,
            app_auto_lock_minutes: 0,
            app_lock_on_screen_lock: false,
            barrier_auto_unseal_enabled: false,
            start_minimized: false,
            auto_tray: false,
            api_explorer_sandbox_policy: 'allow-scripts',
          }),
        },
        AppLockService: { RecordActivity: async () => {} },
        TrustService: {
          AllCertificates: async () => [...(window as any).__certs],
          CertificateCount: async () => (window as any).__certs.length,
          ListCertificates: async () => [...(window as any).__certs],
          GetBrowserBundleStatus: async () => ({
            exists: false,
            stale: false,
            cert_count: 0,
            last_generated: '',
            bundle_path: '',
          }),
          ImportFromTrustStrap: async (req: TrustStrapCall) => {
            (window as any).__trustStrapCalls.push({ ...req });
            const count = 1;
            const list: TestCAEntry[] = (window as any).__certs;
            const fp =
              req.method === 'spki'
                ? 'spki-bootstrap-fingerprint'
                : 'noise-bootstrap-fingerprint';
            if (!list.some((c) => c.fingerprint === fp)) {
              list.push({
                id: fp,
                subject: {
                  common_name:
                    req.method === 'spki'
                      ? 'xkms Local Dev Root CA (via SPKI)'
                      : 'xkms Local Dev Root CA (via Noise)',
                },
                fingerprint: fp,
                tags: ['bootstrap-ca'],
              });
            }
            return count;
          },
        },
        BrowserService: {
          GetConfig: async () => ({
            default_browser: 'system',
            custom_command: '',
            include_trust_bundle: false,
            chrome_profile_mode: 'isolated',
            firefox_profile_mode: 'isolated',
          }),
          SetConfig: async () => {},
          GetTrustBundlePath: async () => '',
        },
        PairingService: {
          GetExtensionFullStatus: async () => ({
            ipc_running: true,
            ipc_socket_path: '/tmp/xkey.sock',
            paired_extensions: [],
            manifests: Object.keys((window as any).__installedManifests).map((b) => ({
              browser: b,
              name: b,
              installed: (window as any).__installedManifests[b],
              path: '',
            })),
          }),
          InstallManifest: async (b: string) => {
            (window as any).__installedManifests[b] = true;
          },
          UninstallManifest: async (b: string) => {
            (window as any).__installedManifests[b] = false;
          },
        },
        AutoFillService: {
          IsEnabled: async () => false,
          GetRequireAuthentication: async () => false,
        },
        SecureBrowserService: {
          DetectBrowsers: async () => [
            { name: 'Google Chrome', path: '/usr/bin/google-chrome' },
            { name: 'Firefox', path: '/usr/bin/firefox' },
          ],
          LaunchBrowser: async (browserPath: string, url: string) => {
            (window as any).__launchCalls.push({ browserPath, url });
            return {
              browser: browserPath,
              family: browserPath.includes('chrome') ? 'chrome' : 'firefox',
              mode: 'isolated',
              cert_count: (window as any).__certs.length,
              pid: 7777,
            };
          },
          Rebuild: async () => {},
        },
      },
    };
  });
}

/**
 * Phase 2: Patch window.go.services after the real Wails runtime has injected
 * window.go. Overwrites TrustService, SecureBrowserService, BrowserService,
 * and PairingService with closures that record into the window-global arrays
 * set in Phase 1.
 */
async function patchTrustToBrowserServices(page: Page): Promise<void> {
  await page.evaluate(() => {
    const svc = (window as any).go?.services;
    if (!svc) return;

    svc.TrustService = {
      ...svc.TrustService,
      AllCertificates: async () => [...(window as any).__certs],
      CertificateCount: async () => (window as any).__certs.length,
      ListCertificates: async () => [...(window as any).__certs],
      GetBrowserBundleStatus: async () => ({
        exists: false,
        stale: false,
        cert_count: 0,
        last_generated: '',
        bundle_path: '',
      }),
      ImportFromTrustStrap: async (req: TrustStrapCall) => {
        (window as any).__trustStrapCalls.push({ ...req });
        const count = 1;
        const list: TestCAEntry[] = (window as any).__certs;
        const fp =
          req.method === 'spki'
            ? 'spki-bootstrap-fingerprint'
            : 'noise-bootstrap-fingerprint';
        if (!list.some((c: TestCAEntry) => c.fingerprint === fp)) {
          list.push({
            id: fp,
            subject: {
              common_name:
                req.method === 'spki'
                  ? 'xkms Local Dev Root CA (via SPKI)'
                  : 'xkms Local Dev Root CA (via Noise)',
            },
            fingerprint: fp,
            tags: ['bootstrap-ca'],
          });
        }
        return count;
      },
    };

    svc.SecureBrowserService = {
      ...svc.SecureBrowserService,
      DetectBrowsers: async () => [
        { name: 'Google Chrome', path: '/usr/bin/google-chrome' },
        { name: 'Firefox', path: '/usr/bin/firefox' },
      ],
      LaunchBrowser: async (browserPath: string, url: string) => {
        (window as any).__launchCalls.push({ browserPath, url });
        return {
          browser: browserPath,
          family: browserPath.includes('chrome') ? 'chrome' : 'firefox',
          mode: 'isolated',
          cert_count: (window as any).__certs.length,
          pid: 7777,
        };
      },
      Rebuild: async () => {},
    };

    svc.BrowserService = {
      ...svc.BrowserService,
      GetConfig: async () => ({
        default_browser: 'system',
        custom_command: '',
        include_trust_bundle: false,
        chrome_profile_mode: 'isolated',
        firefox_profile_mode: 'isolated',
      }),
      SetConfig: async () => {},
      GetTrustBundlePath: async () => '',
    };

    svc.PairingService = {
      ...svc.PairingService,
      GetExtensionFullStatus: async () => ({
        ipc_running: true,
        ipc_socket_path: '/tmp/xkey.sock',
        paired_extensions: [],
        manifests: Object.keys((window as any).__installedManifests).map((b: string) => ({
          browser: b,
          name: b,
          installed: (window as any).__installedManifests[b],
          path: '',
        })),
      }),
      InstallManifest: async (b: string) => {
        (window as any).__installedManifests[b] = true;
      },
      UninstallManifest: async (b: string) => {
        (window as any).__installedManifests[b] = false;
      },
    };
  });
}

async function gotoTrustStore(page: Page): Promise<void> {
  await installBackendInitScript(page);
  await page.goto('/');
  await waitForAppReady(page);
  // Patch services after Wails runtime has loaded (overrides real bindings).
  await patchTrustToBrowserServices(page);
  await ensureSidebarExpanded(page);
  await navigateTo(page, 'trust-store');
}

async function importViaSPKI(
  page: Page,
  server: string,
  pin: string,
): Promise<void> {
  await page.getByRole('button', { name: 'Import' }).first().click();
  await page.getByRole('button', { name: 'SPKI' }).click();
  await page.getByLabel('Server URL').fill(server);
  await page.getByLabel('SPKI Pin (SHA-256)').fill(pin);
  await page.getByRole('button', { name: 'Fetch & Import' }).click();
}

async function importViaNoise(
  page: Page,
  addr: string,
  staticPubKeyHex: string,
): Promise<void> {
  await page.getByRole('button', { name: 'Import' }).first().click();
  await page.getByRole('button', { name: 'Noise' }).click();
  await page.getByLabel('Server Address').fill(addr);
  await page.getByLabel(/Server Static (Public )?Key/i).fill(staticPubKeyHex);
  await page.getByRole('button', { name: 'Fetch & Import' }).click();
}

test.describe('Truststrap → Browser integration', () => {
  test('SPKI import forwards server + pin to TrustService.ImportFromTrustStrap', async ({
    page,
  }) => {
    await gotoTrustStore(page);

    const pin = 'b783d401bfd401a1c6e173f5a5d7719670cd07744b3e333022b1a9ff4de518ff';
    await importViaSPKI(page, 'https://localhost:8443', pin);

    await page.waitForFunction(
      () => ((window as any).__trustStrapCalls ?? []).length > 0,
      { timeout: 5_000 },
    );
    const calls = await page.evaluate(
      () => (window as any).__trustStrapCalls as TrustStrapCall[],
    );
    expect(calls).toHaveLength(1);
    expect(calls[0].method).toBe('spki');
    expect(calls[0].server).toBe('https://localhost:8443');
    expect(calls[0].spki_pin_sha256).toBe(pin);
  });

  test('Noise import forwards addr + server static key to TrustService', async ({
    page,
  }) => {
    await gotoTrustStore(page);

    const noisePub =
      '831c77ccf6897993b912e7890d9e4ff39e17b3f7c44811d148e11d600417a54d';
    await importViaNoise(page, 'localhost:8447', noisePub);

    await page.waitForFunction(
      () => ((window as any).__trustStrapCalls ?? []).length > 0,
      { timeout: 5_000 },
    );
    const calls = await page.evaluate(
      () => (window as any).__trustStrapCalls as TrustStrapCall[],
    );
    expect(calls[0].method).toBe('noise');
    expect(calls[0].server).toBe('localhost:8447');
    expect(calls[0].server_static_key).toBe(noisePub);
  });

  test('imported CA appears in the Browser view summary and enables launch', async ({
    page,
  }) => {
    await gotoTrustStore(page);

    // Bootstrap via SPKI — adds 1 cert.
    const pin = 'b783d401bfd401a1c6e173f5a5d7719670cd07744b3e333022b1a9ff4de518ff';
    await importViaSPKI(page, 'https://localhost:8443', pin);
    await page.waitForFunction(
      () => ((window as any).__certs ?? []).length === 1,
      { timeout: 5_000 },
    );

    // Navigate to Browser view and verify summary reflects 1 cert.
    await navigateTo(page, 'browser');

    await expect(page.getByText('1 certificate', { exact: true })).toBeVisible();

    // The chrome card's Launch button must be enabled now that certCount > 0.
    const chromeCard = page.locator('[data-testid="browser-card-chrome"]');
    const launchBtn = chromeCard.getByRole('button', {
      name: 'Launch secure browser',
    });
    await expect(launchBtn).toBeEnabled();

    // Launch with the xkms health URL — verify SecureBrowserService sees it.
    await chromeCard.locator('input[type="text"]').fill('https://localhost:8443/health');
    await launchBtn.click();

    await page.waitForFunction(
      () => ((window as any).__launchCalls ?? []).length > 0,
      { timeout: 5_000 },
    );
    const calls = await page.evaluate(
      () =>
        (window as any).__launchCalls as Array<{
          browserPath: string;
          url: string;
        }>,
    );
    expect(calls[0]).toEqual({
      browserPath: '/usr/bin/google-chrome',
      url: 'https://localhost:8443/health',
    });
  });

  test('both SPKI and Noise imports populate the trust store for the Browser view', async ({
    page,
  }) => {
    await gotoTrustStore(page);

    await importViaSPKI(
      page,
      'https://localhost:8443',
      'b783d401bfd401a1c6e173f5a5d7719670cd07744b3e333022b1a9ff4de518ff',
    );
    await page.waitForFunction(
      () => ((window as any).__certs ?? []).length === 1,
      { timeout: 5_000 },
    );

    await importViaNoise(
      page,
      'localhost:8447',
      '831c77ccf6897993b912e7890d9e4ff39e17b3f7c44811d148e11d600417a54d',
    );
    await page.waitForFunction(
      () => ((window as any).__certs ?? []).length === 2,
      { timeout: 5_000 },
    );

    await navigateTo(page, 'browser');
    await expect(page.getByText('2 certificates', { exact: true })).toBeVisible();
  });

  test('Noise validation rejects https:// scheme', async ({ page }) => {
    await gotoTrustStore(page);

    await page.getByRole('button', { name: 'Import' }).first().click();
    await page.getByRole('button', { name: 'Noise' }).click();

    await page.getByLabel('Server Address').fill('https://localhost:8447');
    await page
      .getByLabel(/Server Static (Public )?Key/i)
      .fill('831c77ccf6897993b912e7890d9e4ff39e17b3f7c44811d148e11d600417a54d');
    await page.getByRole('button', { name: 'Fetch & Import' }).click();

    const calls = await page.evaluate(
      () => (window as any).__trustStrapCalls as TrustStrapCall[],
    );
    expect(calls).toHaveLength(0);
  });

  test('SPKI validation requires https:// scheme', async ({ page }) => {
    await gotoTrustStore(page);

    await page.getByRole('button', { name: 'Import' }).first().click();
    await page.getByRole('button', { name: 'SPKI' }).click();

    await page.getByLabel('Server URL').fill('localhost:8443');
    await page
      .getByLabel('SPKI Pin (SHA-256)')
      .fill('b783d401bfd401a1c6e173f5a5d7719670cd07744b3e333022b1a9ff4de518ff');
    await page.getByRole('button', { name: 'Fetch & Import' }).click();

    const calls = await page.evaluate(
      () => (window as any).__trustStrapCalls as TrustStrapCall[],
    );
    expect(calls).toHaveLength(0);
  });
});
