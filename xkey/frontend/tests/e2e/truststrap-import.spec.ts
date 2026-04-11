import { test, expect, type Page } from '@playwright/test';
import {
  navigateTo,
  waitForAppReady,
  ensureSidebarExpanded,
} from './helpers';

/**
 * Playwright coverage for the go-truststrap import dialog in Trust Store.
 *
 * The tests mock TrustService.ImportFromTrustStrap via addInitScript so
 * the frontend flow can be exercised without a real bootstrap server. Each
 * call to the mocked method is captured in window.__truststrapImportCalls
 * so tests can assert on the exact payload the frontend sent.
 */

interface TrustStrapTestBackend {
  certs: Array<{
    fingerprint: string;
    subject: string;
    issuer: string;
    algorithm: string;
    not_before: string;
    not_after: string;
    is_ca: boolean;
    is_expired: boolean;
    purpose: string;
    source: string;
    tags: string[];
    system_installed: boolean;
  }>;
  importResult?: number;
  importError?: string;
}

async function installTrustStrapMock(
  page: Page,
  backend: TrustStrapTestBackend,
): Promise<void> {
  const payload = JSON.stringify(backend);

  await page.addInitScript((serialized: string) => {
    const data = JSON.parse(serialized);
    const calls: Array<Record<string, unknown>> = [];
    (window as any).__truststrapImportCalls = calls;

    let certStore = [...data.certs];

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
        TPMService: { GetStatus: async () => ({ available: false, device_exists: false }) },
        AppService: {
          GetConfig: async () => ({
            developer_tools: true,
            browser_extension_enabled: false,
          }),
        },
        TrustService: {
          ListCertificates: async () => certStore,
          CertificateCount: async () => certStore.length,
          AddCertificatesPEM: async () => 0,
          RemoveCertificate: async () => {},
          GetCertificatePEM: async () => '',
          ImportCertificateFile: async () => 0,
          SetBrowserExport: async () => {},
          ImportFromTrustStrap: async (req: Record<string, unknown>) => {
            calls.push(req);
            if (data.importError) {
              throw new Error(data.importError);
            }
            const added = data.importResult ?? 1;
            // Simulate cert store mutation so the refresh shows new rows.
            for (let i = 0; i < added; i++) {
              certStore.push({
                fingerprint: 'imported-' + calls.length + '-' + i,
                subject: 'CN=TrustStrap Imported ' + calls.length + ' ' + i,
                issuer: 'CN=TrustStrap Imported ' + calls.length + ' ' + i,
                algorithm: 'ECDSA',
                not_before: '2026-01-01T00:00:00Z',
                not_after: '2027-01-01T00:00:00Z',
                is_ca: true,
                is_expired: false,
                purpose: 'user-ca',
                source: 'truststrap',
                tags: [],
                system_installed: false,
              });
            }
            return added;
          },
        },
      },
    };
  }, payload);
}

const emptyBackend: TrustStrapTestBackend = {
  certs: [],
  importResult: 1,
};

async function gotoTrustStore(
  page: Page,
  backend: TrustStrapTestBackend = emptyBackend,
): Promise<void> {
  await installTrustStrapMock(page, backend);
  await page.goto('/');
  await waitForAppReady(page);
  await ensureSidebarExpanded(page);
  await navigateTo(page, 'trust-store');
  // Wait for the primary toolbar Import button to mount.
  await page.waitForSelector('[data-testid="truststore-import-btn"]', {
    timeout: 5_000,
  });
}

async function openImportDialog(page: Page): Promise<void> {
  await page.locator('[data-testid="truststore-import-btn"]').click();
  await page.waitForSelector('[data-testid="import-tabs"]', { timeout: 5_000 });
}

test.describe('Trust Store — truststrap import dialog', () => {
  test('Import button opens the dialog with all 6 tabs', async ({ page }) => {
    await gotoTrustStore(page);
    await openImportDialog(page);

    for (const tab of ['paste', 'file', 'dane', 'noise', 'spki', 'direct']) {
      await expect(
        page.locator(`[data-testid="import-tab-${tab}"]`),
      ).toBeVisible();
    }
  });

  test('Paste PEM tab is active by default', async ({ page }) => {
    await gotoTrustStore(page);
    await openImportDialog(page);

    const pasteTab = page.locator('[data-testid="import-tab-paste"]');
    await expect(pasteTab).toHaveClass(/active/);
    await expect(page.locator('#import-pem')).toBeVisible();
  });

  test('clicking DANE tab reveals the shared Server URL input', async ({
    page,
  }) => {
    await gotoTrustStore(page);
    await openImportDialog(page);
    await page.locator('[data-testid="import-tab-dane"]').click();

    const server = page.locator('[data-testid="truststrap-server-input"]');
    await expect(server).toBeVisible();
    await expect(server).toHaveAttribute(
      'placeholder',
      'https://kms.example.com:8443',
    );
    await expect(page.locator('#truststrap-bundle-path')).toBeVisible();
  });

  test('Noise tab shows Server Address label and hides Bundle Path', async ({
    page,
  }) => {
    await gotoTrustStore(page);
    await openImportDialog(page);
    await page.locator('[data-testid="import-tab-noise"]').click();

    const server = page.locator('[data-testid="truststrap-server-input"]');
    await expect(server).toBeVisible();
    await expect(server).toHaveAttribute(
      'placeholder',
      'kms.example.com:8445',
    );
    await expect(
      page.locator('label[for="truststrap-server"]'),
    ).toHaveText('Server Address');
    // Bundle path is not used by Noise — hidden.
    await expect(page.locator('#truststrap-bundle-path')).toHaveCount(0);
    // Noise-specific key field appears.
    await expect(
      page.locator('[data-testid="truststrap-noise-key-input"]'),
    ).toBeVisible();
  });

  test('SPKI tab shows the pin input', async ({ page }) => {
    await gotoTrustStore(page);
    await openImportDialog(page);
    await page.locator('[data-testid="import-tab-spki"]').click();

    await expect(
      page.locator('[data-testid="truststrap-spki-pin-input"]'),
    ).toBeVisible();
  });

  test('Direct tab shows only the shared Server URL + Bundle Path', async ({
    page,
  }) => {
    await gotoTrustStore(page);
    await openImportDialog(page);
    await page.locator('[data-testid="import-tab-direct"]').click();

    await expect(
      page.locator('[data-testid="truststrap-server-input"]'),
    ).toBeVisible();
    await expect(page.locator('#truststrap-bundle-path')).toBeVisible();
    // No method-specific inputs on the Direct tab.
    await expect(
      page.locator('[data-testid="truststrap-noise-key-input"]'),
    ).toHaveCount(0);
    await expect(
      page.locator('[data-testid="truststrap-spki-pin-input"]'),
    ).toHaveCount(0);
  });

  test('Fetch & Import button is disabled until Server is populated', async ({
    page,
  }) => {
    await gotoTrustStore(page);
    await openImportDialog(page);
    await page.locator('[data-testid="import-tab-direct"]').click();

    const btn = page.locator('[data-testid="truststrap-fetch-btn"]');
    await expect(btn).toBeDisabled();

    await page
      .locator('[data-testid="truststrap-server-input"]')
      .fill('https://kms.example.com:8443');
    await expect(btn).toBeEnabled();
  });

  test('Noise Fetch & Import button requires Server AND Server Static Key', async ({
    page,
  }) => {
    await gotoTrustStore(page);
    await openImportDialog(page);
    await page.locator('[data-testid="import-tab-noise"]').click();

    const btn = page.locator('[data-testid="truststrap-fetch-btn"]');

    await page
      .locator('[data-testid="truststrap-server-input"]')
      .fill('kms.example.com:8445');
    await expect(btn).toBeDisabled();

    await page
      .locator('[data-testid="truststrap-noise-key-input"]')
      .fill('a'.repeat(64));
    await expect(btn).toBeEnabled();
  });

  test('SPKI Fetch & Import button requires Server AND SPKI pin', async ({
    page,
  }) => {
    await gotoTrustStore(page);
    await openImportDialog(page);
    await page.locator('[data-testid="import-tab-spki"]').click();

    const btn = page.locator('[data-testid="truststrap-fetch-btn"]');

    await page
      .locator('[data-testid="truststrap-server-input"]')
      .fill('https://kms.example.com:8443');
    await expect(btn).toBeDisabled();

    await page
      .locator('[data-testid="truststrap-spki-pin-input"]')
      .fill('b'.repeat(64));
    await expect(btn).toBeEnabled();
  });

  test('successful Direct import invokes ImportFromTrustStrap with the right payload', async ({
    page,
  }) => {
    await gotoTrustStore(page, { ...emptyBackend, importResult: 2 });
    await openImportDialog(page);
    await page.locator('[data-testid="import-tab-direct"]').click();

    await page
      .locator('[data-testid="truststrap-server-input"]')
      .fill('https://kms.example.com:8443');
    await page
      .locator('#truststrap-bundle-path')
      .fill('/custom/bundle');

    await page.locator('[data-testid="truststrap-fetch-btn"]').click();

    await page.waitForFunction(
      () => ((window as any).__truststrapImportCalls ?? []).length > 0,
      { timeout: 5_000 },
    );

    const calls = await page.evaluate(
      () => (window as any).__truststrapImportCalls as Array<Record<string, unknown>>,
    );
    expect(calls).toHaveLength(1);
    expect(calls[0]).toMatchObject({
      method: 'direct',
      server: 'https://kms.example.com:8443',
      bundle_path: '/custom/bundle',
      server_static_key: '',
      spki_pin_sha256: '',
      dns_over_tls: false,
    });

    // Modal should close after a successful import.
    await expect(page.locator('[data-testid="import-tabs"]')).toHaveCount(0);
  });

  test('SPKI import sends the pin in the request', async ({ page }) => {
    await gotoTrustStore(page);
    await openImportDialog(page);
    await page.locator('[data-testid="import-tab-spki"]').click();

    await page
      .locator('[data-testid="truststrap-server-input"]')
      .fill('https://kms.example.com:8443');
    const pin = 'c'.repeat(64);
    await page
      .locator('[data-testid="truststrap-spki-pin-input"]')
      .fill(pin);

    await page.locator('[data-testid="truststrap-fetch-btn"]').click();

    await page.waitForFunction(
      () => ((window as any).__truststrapImportCalls ?? []).length > 0,
      { timeout: 5_000 },
    );

    const calls = await page.evaluate(
      () => (window as any).__truststrapImportCalls as Array<Record<string, unknown>>,
    );
    expect(calls[0]).toMatchObject({
      method: 'spki',
      server: 'https://kms.example.com:8443',
      spki_pin_sha256: pin,
    });
  });

  test('Noise import sends the server static key in the request', async ({
    page,
  }) => {
    await gotoTrustStore(page);
    await openImportDialog(page);
    await page.locator('[data-testid="import-tab-noise"]').click();

    const key = 'd'.repeat(64);
    await page
      .locator('[data-testid="truststrap-server-input"]')
      .fill('kms.example.com:8445');
    await page
      .locator('[data-testid="truststrap-noise-key-input"]')
      .fill(key);

    await page.locator('[data-testid="truststrap-fetch-btn"]').click();

    await page.waitForFunction(
      () => ((window as any).__truststrapImportCalls ?? []).length > 0,
      { timeout: 5_000 },
    );

    const calls = await page.evaluate(
      () => (window as any).__truststrapImportCalls as Array<Record<string, unknown>>,
    );
    expect(calls[0]).toMatchObject({
      method: 'noise',
      server: 'kms.example.com:8445',
      server_static_key: key,
    });
  });

  test('DANE DNS-over-TLS checkbox is sent in the import request', async ({
    page,
  }) => {
    await gotoTrustStore(page);
    await openImportDialog(page);
    await page.locator('[data-testid="import-tab-dane"]').click();

    await page
      .locator('[data-testid="truststrap-server-input"]')
      .fill('https://kms.example.com:8443');
    await page.locator('#truststrap-dns').fill('8.8.8.8:53');
    await page
      .getByRole('checkbox', { name: 'Use DNS-over-TLS (DoT)' })
      .check();

    await page.locator('[data-testid="truststrap-fetch-btn"]').click();

    await page.waitForFunction(
      () => ((window as any).__truststrapImportCalls ?? []).length > 0,
      { timeout: 5_000 },
    );

    const calls = await page.evaluate(
      () => (window as any).__truststrapImportCalls as Array<Record<string, unknown>>,
    );
    expect(calls[0]).toMatchObject({
      method: 'dane',
      server: 'https://kms.example.com:8443',
      dns_server: '8.8.8.8:53',
      dns_over_tls: true,
    });
  });

  test('failed import keeps the modal open', async ({ page }) => {
    await gotoTrustStore(page, {
      ...emptyBackend,
      importError: 'fetch failed: connection refused',
    });
    await openImportDialog(page);
    await page.locator('[data-testid="import-tab-direct"]').click();

    await page
      .locator('[data-testid="truststrap-server-input"]')
      .fill('https://kms.example.com:8443');

    await page.locator('[data-testid="truststrap-fetch-btn"]').click();

    // Modal must still be visible after the error.
    await expect(
      page.locator('[data-testid="import-tabs"]'),
    ).toBeVisible();
  });

  test('switching between truststrap tabs preserves the Server input value', async ({
    page,
  }) => {
    await gotoTrustStore(page);
    await openImportDialog(page);
    await page.locator('[data-testid="import-tab-direct"]').click();

    await page
      .locator('[data-testid="truststrap-server-input"]')
      .fill('https://kms.example.com:8443');

    await page.locator('[data-testid="import-tab-spki"]').click();
    await expect(
      page.locator('[data-testid="truststrap-server-input"]'),
    ).toHaveValue('https://kms.example.com:8443');

    await page.locator('[data-testid="import-tab-dane"]').click();
    await expect(
      page.locator('[data-testid="truststrap-server-input"]'),
    ).toHaveValue('https://kms.example.com:8443');
  });
});
