/**
 * FIDO2 Multi-Backend Credential Binding Tests
 *
 * Covers two scenarios:
 *
 *   A) Live (Wails) — TPM-backed backend selection and default verification.
 *      Guard: isWailsMode + tpm2 in ListKeyBackends; skip otherwise.
 *      Proves that SetDefaultBackend('tpm2') persists to DefaultBackend() and
 *      that the TPM chip is selectable + active in the BackendSelector.
 *
 *   B) Vite mock — UI selection → SetDefaultBackend → credential backendType
 *      badge for all backend types: tpm2, pkcs11, awskms, gcpkms, azurekv.
 *      Guard: isRealWailsRuntime → skip when real Wails overrides the mock.
 *      Installs window.go mock with all 6 backends + one credential per type;
 *      verifies that chip selection calls SetDefaultBackend with the correct ID,
 *      the chip gains the "active" class, and the credential list filters to show
 *      only credentials with the matching backendType badge.
 *
 * DOCUMENTED PRODUCT GAP:
 *   FIDO2Service has no CreateCredential method. New credentials are bound to the
 *   current default backend exclusively via the CTAP2 MakeCredential ceremony
 *   inside a real browser WebAuthn call. A full "create credential on
 *   tpm2/pkcs11/cloud" flow cannot be driven from the Wails service layer —
 *   it requires a Chrome CDP virtual authenticator + a WebAuthn-capable RP.
 *   Test A-3 documents this gap as a verified assertion.
 *
 *   Similarly, FIDO2Service has no ExportPrivateKey method and the credential
 *   detail view has no export UI, so hardware-backed export refusal cannot be
 *   exercised from the service or GUI layers.
 */

import { test, expect, type Page } from '@playwright/test';
import {
  waitForAppReady,
  ensureSidebarExpanded,
  navigateToFIDO2,
  waitForBackendReady,
  isWailsMode,
} from './helpers';
import { isRealWailsRuntime } from './setup-helpers';

// ---------------------------------------------------------------------------
// Shared mock data
// ---------------------------------------------------------------------------

const ALL_BACKENDS = ['software', 'tpm2', 'pkcs11', 'awskms', 'gcpkms', 'azurekv'] as const;
type BackendId = (typeof ALL_BACKENDS)[number];
const NON_SOFTWARE_BACKENDS = ALL_BACKENDS.slice(1);

/**
 * Display names returned by the mock AdminService.ListBackends.
 * Must match what BackendSelector renders as chip text ({b.display_name || b.id}).
 */
const DISPLAY_NAMES: Record<BackendId, string> = {
  software: 'Software',
  tpm2: 'TPM 2.0',
  pkcs11: 'PKCS#11',
  awskms: 'AWS KMS',
  gcpkms: 'GCP KMS',
  azurekv: 'Azure Key Vault',
};

const MOCK_BACKENDS = [
  {
    id: 'software', type: 'software', display_name: 'Software',
    enabled: true, connected: true, key_count: 3, algorithms: ['ECDSA'],
    description: 'Software key backend',
    capabilities: {
      signing: true, encryption: true, decryption: true, key_encapsulation: false,
      sealing: true, attestation: false, hardware_backed: false, quantum_signing: false,
      fido2: true, piv: true, oath: true, passwords: true,
    },
  },
  {
    id: 'tpm2', type: 'tpm2', display_name: 'TPM 2.0',
    enabled: true, connected: true, key_count: 1, algorithms: ['ECDSA'],
    description: 'TPM 2.0 hardware backend',
    capabilities: {
      signing: true, encryption: true, decryption: true, key_encapsulation: false,
      sealing: true, attestation: true, hardware_backed: true, quantum_signing: false,
      fido2: true, piv: true, oath: true, passwords: true,
    },
  },
  {
    id: 'pkcs11', type: 'pkcs11', display_name: 'PKCS#11',
    enabled: true, connected: true, key_count: 0, algorithms: ['ECDSA', 'RSA'],
    description: 'PKCS#11 HSM backend',
    capabilities: {
      signing: true, encryption: true, decryption: true, key_encapsulation: false,
      sealing: true, attestation: false, hardware_backed: true, quantum_signing: false,
      fido2: true, piv: true, oath: true, passwords: true,
    },
  },
  {
    id: 'awskms', type: 'awskms', display_name: 'AWS KMS',
    enabled: true, connected: true, key_count: 0, algorithms: ['ECDSA'],
    description: 'AWS KMS cloud backend',
    capabilities: {
      signing: true, encryption: true, decryption: true, key_encapsulation: false,
      sealing: false, attestation: false, hardware_backed: true, quantum_signing: false,
      fido2: true, piv: false, oath: false, passwords: false,
    },
  },
  {
    id: 'gcpkms', type: 'gcpkms', display_name: 'GCP KMS',
    enabled: true, connected: true, key_count: 0, algorithms: ['ECDSA'],
    description: 'GCP Cloud KMS backend',
    capabilities: {
      signing: true, encryption: true, decryption: true, key_encapsulation: false,
      sealing: false, attestation: false, hardware_backed: true, quantum_signing: false,
      fido2: true, piv: false, oath: false, passwords: false,
    },
  },
  {
    id: 'azurekv', type: 'azurekv', display_name: 'Azure Key Vault',
    enabled: true, connected: true, key_count: 0, algorithms: ['ECDSA'],
    description: 'Azure Key Vault backend',
    capabilities: {
      signing: true, encryption: true, decryption: true, key_encapsulation: false,
      sealing: false, attestation: false, hardware_backed: true, quantum_signing: false,
      fido2: true, piv: false, oath: false, passwords: false,
    },
  },
];

// One representative credential per backend type. Each has a unique hex ID and a
// backend_type that matches its backend. Credentials are loaded on FIDO2 view mount
// via ListCredentials; the view then filters client-side by selectedBackend.
const MOCK_CREDENTIALS = MOCK_BACKENDS.map((b, i) => ({
  id: `a1b2c3d4e5f6${String(i).padStart(28, '0')}`,
  relying_party_id: `${b.id}.example.com`,
  relying_party: `${DISPLAY_NAMES[b.id as BackendId]} Example RP`,
  user_name: `user@${b.id}.example.com`,
  user_display_name: `${DISPLAY_NAMES[b.id as BackendId]} User`,
  algorithm: 'ES256',
  key_type: 'ECDSA P-256',
  cred_protect: 0,
  backend_type: b.id,
  use_count: i,
  discoverable: true,
  created_at: new Date(Date.now() - i * 86_400_000).toISOString(),
  last_used: '',
}));

/**
 * Install a complete window.go mock providing all services the FIDO2 view
 * needs. The mock exposes two global counters so tests can assert
 * SetDefaultBackend call semantics without relying on Svelte internals:
 *   window.__lastSetDefaultBackend  — ID passed to the last SetDefaultBackend call
 *   window.__setDefaultBackendCalls — total number of SetDefaultBackend calls
 */
async function installMock(page: Page): Promise<void> {
  const backendsJSON = JSON.stringify(MOCK_BACKENDS);
  const credsJSON = JSON.stringify(MOCK_CREDENTIALS);
  await page.addInitScript((data: { b: string; c: string }) => {
    const backends = JSON.parse(data.b);
    const creds = JSON.parse(data.c);
    let defaultBackend = 'software';
    (window as any).__lastSetDefaultBackend = '';
    (window as any).__setDefaultBackendCalls = 0;
    (window as any).go = {
      services: {
        SetupWizardService: {
          GetStartupState: async () => ({ setup_complete: true, enterprise_mode: false }),
        },
        AdminService: {
          ListBackends: async () => backends,
          GetDefaultBackend: async () => defaultBackend,
          SetDefaultBackend: async () => {},
          GetBackendTypes: async () => [],
          RemoveBackend: async () => {},
          ConnectBackend: async () => {},
          DisconnectBackend: async () => {},
          GetBackendInfo: async () => ({ key_count: 0 }),
          UpdateBackendDisplayName: async () => {},
        },
        FIDO2Service: {
          ListCredentials: async () => creds,
          DeleteCredential: async () => {},
          SetDefaultBackend: async (id: string) => {
            defaultBackend = id;
            (window as any).__lastSetDefaultBackend = id;
            (window as any).__setDefaultBackendCalls++;
          },
          DefaultBackend: async () => defaultBackend,
          ListKeyBackends: async () => backends.map((b: { id: string }) => b.id),
          ListRPPolicies: async () => [],
          GetBridgeStatus: async () => ({ running: false, requests: 0 }),
          StartPhoneBridge: async () => {},
          StopPhoneBridge: async () => {},
        },
        FIDO2DeviceService: {
          GetStatus: async () => ({
            running: true,
            device_name: 'xKey Virtual (mock)',
            vendor_id: 'TEST',
            product_id: 'TEST',
            has_pending_touch: false,
            authenticator_available: true,
          }),
          ApproveTouchRequest: async () => true,
        },
        AuthService: {
          SetModeUser: async () => {},
        },
      },
    };
  }, { b: backendsJSON, c: credsJSON });
}

/**
 * Wait for BackendSelector to populate per-backend chips (async ListBackends call).
 * Chips.nth(1) is the first non-"All Backends" chip; its appearance confirms the
 * async call completed and the selector re-rendered.
 */
async function waitForBackendChips(page: Page): Promise<void> {
  const chips = page
    .locator('[data-testid="fido2-backend-selector"]')
    .locator('.filter-chip');
  await expect(chips.nth(1)).toBeVisible({ timeout: 5_000 });
}

// ---------------------------------------------------------------------------
// A. Live (Wails) — TPM-backed FIDO2 backend binding
// ---------------------------------------------------------------------------

test.describe('A. Live Wails — TPM-backed FIDO2 backend binding', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
  });

  test('A-1: SetDefaultBackend("tpm2") persists — DefaultBackend() returns "tpm2"', async ({ page }) => {
    const wails = await isWailsMode(page);
    test.skip(!wails, 'Requires live Wails runtime');

    await waitForBackendReady(page);

    const backends = await page.evaluate<string[]>(async () =>
      (window as any).go.services.FIDO2Service.ListKeyBackends(),
    );
    test.skip(!backends?.includes('tpm2'), 'TPM 2.0 FIDO2 key backend not registered in this environment');

    // Set tpm2 as the default via the service layer directly.
    const setErr = await page.evaluate<string | null>(async () => {
      try {
        await (window as any).go.services.FIDO2Service.SetDefaultBackend('tpm2');
        return null;
      } catch (e: unknown) {
        return String(e);
      }
    });
    expect(setErr, 'SetDefaultBackend("tpm2") must not error').toBeNull();

    // DefaultBackend() must now reflect the change.
    const defaultBackend = await page.evaluate<string>(async () =>
      (window as any).go.services.FIDO2Service.DefaultBackend(),
    );
    expect(defaultBackend).toBe('tpm2');
  });

  test('A-2: BackendSelector TPM chip becomes active after UI click and DefaultBackend() confirms "tpm2"', async ({ page }) => {
    const wails = await isWailsMode(page);
    test.skip(!wails, 'Requires live Wails runtime');

    await waitForBackendReady(page);

    const backends = await page.evaluate<string[]>(async () =>
      (window as any).go.services.FIDO2Service.ListKeyBackends(),
    );
    test.skip(!backends?.includes('tpm2'), 'TPM 2.0 FIDO2 key backend not registered in this environment');

    await navigateToFIDO2(page);

    // BackendSelector calls AdminService.ListBackends async on mount;
    // wait for per-backend chips before interacting.
    const selector = page.locator('[data-testid="fido2-backend-selector"]');
    await expect(selector).toBeVisible();
    const chips = selector.locator('.filter-chip');
    await expect(chips.nth(1)).toBeVisible({ timeout: 10_000 });

    const tpmChip = chips.filter({ hasText: /TPM/i }).first();
    await expect(tpmChip).toBeVisible({ timeout: 10_000 });
    await tpmChip.click();

    // Give the reactive SetDefaultBackend call time to reach the backend.
    await page.waitForTimeout(500);

    // The chip must become active; "All Backends" must no longer be active.
    await expect(tpmChip).toHaveClass(/active/);
    await expect(chips.first()).not.toHaveClass(/active/);

    // Confirm DefaultBackend() reflects the selection.
    const defaultBackend = await page.evaluate<string>(async () =>
      (window as any).go.services.FIDO2Service.DefaultBackend(),
    );
    expect(defaultBackend).toBe('tpm2');
  });

  test('A-3: No FIDO2Service.CreateCredential method — documents service-layer gap', async ({ page }) => {
    // This assertion documents that credential creation cannot be driven from
    // the FIDO2Service. The only creation path is the CTAP2 MakeCredential
    // ceremony inside a real browser WebAuthn call.  A full "create credential
    // on tpm2/pkcs11/cloud" E2E test would require Chrome CDP virtual authenticator
    // + a live WebAuthn-capable relying party. That path is out of scope for
    // service-layer automation.
    const wails = await isWailsMode(page);
    test.skip(!wails, 'Requires live Wails runtime');

    await waitForBackendReady(page);

    const hasCreateMethod = await page.evaluate<boolean>(
      () => typeof (window as any).go?.services?.FIDO2Service?.CreateCredential === 'function',
    );
    // Expected to be false — this assertion documents the gap.
    expect(hasCreateMethod).toBe(false);
  });

  test('A-4: TPM backend chip is enabled, connected, and selectable in BackendSelector', async ({ page }) => {
    const wails = await isWailsMode(page);
    test.skip(!wails, 'Requires live Wails runtime');

    await waitForBackendReady(page);

    const backends = await page.evaluate<string[]>(async () =>
      (window as any).go.services.FIDO2Service.ListKeyBackends(),
    );
    test.skip(!backends?.includes('tpm2'), 'TPM 2.0 FIDO2 key backend not registered in this environment');

    await navigateToFIDO2(page);

    const selector = page.locator('[data-testid="fido2-backend-selector"]');
    await expect(selector).toBeVisible();
    const chips = selector.locator('.filter-chip');
    await expect(chips.nth(1)).toBeVisible({ timeout: 10_000 });

    const tpmChip = chips.filter({ hasText: /TPM/i }).first();
    await expect(tpmChip).toBeVisible({ timeout: 10_000 });
    await expect(tpmChip).toBeEnabled();

    // A connected TPM backend must NOT show an offline dot.
    await expect(tpmChip.locator('.offline-dot')).toHaveCount(0);
  });

  test('A-5: swtpm-backed tpm2 backend is registered in this e2e container (assert, not skip)', async ({ page }) => {
    // This test asserts without skipping. It exists to prove that the e2e
    // docker entrypoint correctly wires the swtpm daemon into the xkey
    // unified config so AutoInitialize creates a real TCP-connected tpm2
    // backend. If ListKeyBackends() does not include "tpm2", this test fails
    // loudly rather than silently skipping — confirming the swtpm plumbing.
    //
    // This test runs ONLY in the real Wails runtime (the e2e docker container).
    // In Vite mock mode the window.go bindings are absent, so skip there.
    const wails = await isWailsMode(page);
    test.skip(!wails, 'A-5 requires live Wails runtime (e2e docker container)');

    await waitForBackendReady(page);

    const backends = await page.evaluate<string[]>(async () =>
      (window as any).go.services.FIDO2Service.ListKeyBackends(),
    );

    // Hard assertion: the e2e container MUST expose a tpm2 backend.
    expect(backends, 'ListKeyBackends() must include "tpm2" in e2e container').toContain('tpm2');
  });
});

// ---------------------------------------------------------------------------
// B. Vite mock — all non-software backends: selection, SetDefaultBackend, badge
// ---------------------------------------------------------------------------

test.describe('B. Vite mock — FIDO2 multi-backend selection and credential binding', () => {
  test.beforeEach(async ({ page }) => {
    // Skip in the real Wails runtime: the live backend overwrites window.go,
    // so the mock's controlled state cannot hold. Pattern from dashboard.spec.ts.
    const realWails = await isRealWailsRuntime(page);
    test.skip(realWails, 'Vite mock-mode only; real Wails backend overrides window.go');

    await installMock(page);
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
  });

  // ── B-1: All 6 backend types appear as chips ──────────────────────────────

  test('B-1: BackendSelector shows all 6 backend types including cloud and hardware', async ({ page }) => {
    await navigateToFIDO2(page);
    await waitForBackendChips(page);

    const selector = page.locator('[data-testid="fido2-backend-selector"]');
    const chips = selector.locator('.filter-chip');

    // "All Backends" + 6 backend chips.
    const chipCount = await chips.count();
    expect(chipCount).toBe(7);

    // Every backend must have a visible chip with the expected display name.
    for (const displayName of Object.values(DISPLAY_NAMES)) {
      await expect(chips.filter({ hasText: displayName })).toBeVisible();
    }
  });

  // ── B-2..B-6: Individual chip → SetDefaultBackend for each non-software backend

  test('B-2: Selecting tpm2 chip calls SetDefaultBackend("tpm2") and chip becomes active', async ({ page }) => {
    await navigateToFIDO2(page);
    await waitForBackendChips(page);

    const chips = page
      .locator('[data-testid="fido2-backend-selector"]')
      .locator('.filter-chip');

    const tpmChip = chips.filter({ hasText: DISPLAY_NAMES.tpm2 });
    await tpmChip.click();
    await page.waitForFunction(
      () => (window as any).__lastSetDefaultBackend === 'tpm2',
      { timeout: 3_000 },
    );

    await expect(tpmChip).toHaveClass(/active/);
    // "All Backends" must no longer be active.
    await expect(chips.first()).not.toHaveClass(/active/);
  });

  test('B-3: Selecting pkcs11 chip calls SetDefaultBackend("pkcs11") and chip becomes active', async ({ page }) => {
    await navigateToFIDO2(page);
    await waitForBackendChips(page);

    const chips = page
      .locator('[data-testid="fido2-backend-selector"]')
      .locator('.filter-chip');

    const pkcsChip = chips.filter({ hasText: DISPLAY_NAMES.pkcs11 });
    await pkcsChip.click();
    await page.waitForFunction(
      () => (window as any).__lastSetDefaultBackend === 'pkcs11',
      { timeout: 3_000 },
    );

    await expect(pkcsChip).toHaveClass(/active/);
    await expect(chips.first()).not.toHaveClass(/active/);
  });

  test('B-4: Selecting awskms chip calls SetDefaultBackend("awskms") and chip becomes active', async ({ page }) => {
    await navigateToFIDO2(page);
    await waitForBackendChips(page);

    const chips = page
      .locator('[data-testid="fido2-backend-selector"]')
      .locator('.filter-chip');

    const awsChip = chips.filter({ hasText: DISPLAY_NAMES.awskms });
    await awsChip.click();
    await page.waitForFunction(
      () => (window as any).__lastSetDefaultBackend === 'awskms',
      { timeout: 3_000 },
    );

    await expect(awsChip).toHaveClass(/active/);
    await expect(chips.first()).not.toHaveClass(/active/);
  });

  test('B-5: Selecting gcpkms chip calls SetDefaultBackend("gcpkms") and chip becomes active', async ({ page }) => {
    await navigateToFIDO2(page);
    await waitForBackendChips(page);

    const chips = page
      .locator('[data-testid="fido2-backend-selector"]')
      .locator('.filter-chip');

    const gcpChip = chips.filter({ hasText: DISPLAY_NAMES.gcpkms });
    await gcpChip.click();
    await page.waitForFunction(
      () => (window as any).__lastSetDefaultBackend === 'gcpkms',
      { timeout: 3_000 },
    );

    await expect(gcpChip).toHaveClass(/active/);
    await expect(chips.first()).not.toHaveClass(/active/);
  });

  test('B-6: Selecting azurekv chip calls SetDefaultBackend("azurekv") and chip becomes active', async ({ page }) => {
    await navigateToFIDO2(page);
    await waitForBackendChips(page);

    const chips = page
      .locator('[data-testid="fido2-backend-selector"]')
      .locator('.filter-chip');

    const azureChip = chips.filter({ hasText: DISPLAY_NAMES.azurekv });
    await azureChip.click();
    await page.waitForFunction(
      () => (window as any).__lastSetDefaultBackend === 'azurekv',
      { timeout: 3_000 },
    );

    await expect(azureChip).toHaveClass(/active/);
    await expect(chips.first()).not.toHaveClass(/active/);
  });

  // ── B-7..B-9: Credential badge shows correct backendType after filtering ──

  test('B-7: tpm2 credential card renders "tpm2" backendType badge', async ({ page }) => {
    await navigateToFIDO2(page);
    await waitForBackendChips(page);

    // Wait for onMount credentials to load (list appears after async ListCredentials).
    await expect(page.locator('[data-testid="fido2-credential-list"]')).toBeVisible({ timeout: 5_000 });

    const chips = page
      .locator('[data-testid="fido2-backend-selector"]')
      .locator('.filter-chip');
    await chips.filter({ hasText: DISPLAY_NAMES.tpm2 }).click();
    await page.waitForFunction(
      () => (window as any).__lastSetDefaultBackend === 'tpm2',
      { timeout: 3_000 },
    );

    // Filtering to tpm2 leaves exactly one credential card.
    const cards = page
      .locator('[data-testid="fido2-credential-list"]')
      .locator('[data-testid^="fido2-credential-card-"]');
    await expect(cards).toHaveCount(1);
    await expect(cards.first().locator('.cred-badge')).toHaveText('tpm2');
  });

  test('B-8: pkcs11 credential card renders "pkcs11" backendType badge', async ({ page }) => {
    await navigateToFIDO2(page);
    await waitForBackendChips(page);
    await expect(page.locator('[data-testid="fido2-credential-list"]')).toBeVisible({ timeout: 5_000 });

    const chips = page
      .locator('[data-testid="fido2-backend-selector"]')
      .locator('.filter-chip');
    await chips.filter({ hasText: DISPLAY_NAMES.pkcs11 }).click();
    await page.waitForFunction(
      () => (window as any).__lastSetDefaultBackend === 'pkcs11',
      { timeout: 3_000 },
    );

    const cards = page
      .locator('[data-testid="fido2-credential-list"]')
      .locator('[data-testid^="fido2-credential-card-"]');
    await expect(cards).toHaveCount(1);
    await expect(cards.first().locator('.cred-badge')).toHaveText('pkcs11');
  });

  test('B-9: awskms credential card renders "awskms" backendType badge', async ({ page }) => {
    await navigateToFIDO2(page);
    await waitForBackendChips(page);
    await expect(page.locator('[data-testid="fido2-credential-list"]')).toBeVisible({ timeout: 5_000 });

    const chips = page
      .locator('[data-testid="fido2-backend-selector"]')
      .locator('.filter-chip');
    await chips.filter({ hasText: DISPLAY_NAMES.awskms }).click();
    await page.waitForFunction(
      () => (window as any).__lastSetDefaultBackend === 'awskms',
      { timeout: 3_000 },
    );

    const cards = page
      .locator('[data-testid="fido2-credential-list"]')
      .locator('[data-testid^="fido2-credential-card-"]');
    await expect(cards).toHaveCount(1);
    await expect(cards.first().locator('.cred-badge')).toHaveText('awskms');
  });

  // ── B-10..B-11: Filtering hides credentials for other backends ──────────────

  test('B-10: Selecting tpm2 hides all non-tpm2 credentials; "All Backends" restores all 6', async ({ page }) => {
    await navigateToFIDO2(page);
    await waitForBackendChips(page);

    const credList = page.locator('[data-testid="fido2-credential-list"]');
    await expect(credList).toBeVisible({ timeout: 5_000 });
    const cards = credList.locator('[data-testid^="fido2-credential-card-"]');

    // Initial state: all 6 credentials visible with "All Backends" active.
    const allChip = page
      .locator('[data-testid="fido2-backend-selector"]')
      .locator('.filter-chip')
      .first();
    await expect(allChip).toHaveClass(/active/);
    await expect(cards).toHaveCount(6);

    // Select tpm2: only the tpm2 credential remains.
    const tpmChip = page
      .locator('[data-testid="fido2-backend-selector"]')
      .locator('.filter-chip')
      .filter({ hasText: DISPLAY_NAMES.tpm2 });
    await tpmChip.click();
    await page.waitForFunction(
      () => (window as any).__lastSetDefaultBackend === 'tpm2',
      { timeout: 3_000 },
    );
    await expect(cards).toHaveCount(1);
    await expect(cards.first().locator('.cred-badge')).toHaveText('tpm2');

    // Return to "All Backends": all 6 cards reappear.
    await allChip.click();
    await page.waitForTimeout(300);
    await expect(allChip).toHaveClass(/active/);
    await expect(tpmChip).not.toHaveClass(/active/);
    await expect(cards).toHaveCount(6);
  });

  test('B-11: Selecting pkcs11 shows only pkcs11 credential; other backend types are hidden', async ({ page }) => {
    await navigateToFIDO2(page);
    await waitForBackendChips(page);
    await expect(page.locator('[data-testid="fido2-credential-list"]')).toBeVisible({ timeout: 5_000 });

    const pkcsChip = page
      .locator('[data-testid="fido2-backend-selector"]')
      .locator('.filter-chip')
      .filter({ hasText: DISPLAY_NAMES.pkcs11 });
    await pkcsChip.click();
    await page.waitForFunction(
      () => (window as any).__lastSetDefaultBackend === 'pkcs11',
      { timeout: 3_000 },
    );

    const cards = page
      .locator('[data-testid="fido2-credential-list"]')
      .locator('[data-testid^="fido2-credential-card-"]');
    await expect(cards).toHaveCount(1);
    await expect(cards.first().locator('.cred-badge')).toHaveText('pkcs11');

    // Spot-check: the tpm2 domain label must NOT be visible.
    await expect(page.getByText('tpm2.example.com')).not.toBeVisible();
  });

  // ── B-12: DefaultBackend() tracks every chip selection ────────────────────

  test('B-12: DefaultBackend() reflects each SetDefaultBackend call across all backends', async ({ page }) => {
    await navigateToFIDO2(page);
    await waitForBackendChips(page);

    const chips = page
      .locator('[data-testid="fido2-backend-selector"]')
      .locator('.filter-chip');

    for (const bt of NON_SOFTWARE_BACKENDS) {
      const displayName = DISPLAY_NAMES[bt];
      await chips.filter({ hasText: displayName }).click();
      await page.waitForFunction(
        (id) => (window as any).__lastSetDefaultBackend === id,
        bt,
        { timeout: 3_000 },
      );

      const defaultBackend = await page.evaluate<string>(async () =>
        (window as any).go.services.FIDO2Service.DefaultBackend(),
      );
      expect(
        defaultBackend,
        `DefaultBackend() must return '${bt}' after selecting its chip`,
      ).toBe(bt);
    }
  });

  // ── B-13: Cloud backends — gcpkms and azurekv badges ────────────────────

  test('B-13: gcpkms and azurekv cloud credential cards render correct backendType badges', async ({ page }) => {
    await navigateToFIDO2(page);
    await waitForBackendChips(page);
    await expect(page.locator('[data-testid="fido2-credential-list"]')).toBeVisible({ timeout: 5_000 });

    const chips = page
      .locator('[data-testid="fido2-backend-selector"]')
      .locator('.filter-chip');
    const allChip = chips.first();

    for (const bt of ['gcpkms', 'azurekv'] as const) {
      await chips.filter({ hasText: DISPLAY_NAMES[bt] }).click();
      await page.waitForFunction(
        (id) => (window as any).__lastSetDefaultBackend === id,
        bt,
        { timeout: 3_000 },
      );

      const cards = page
        .locator('[data-testid="fido2-credential-list"]')
        .locator('[data-testid^="fido2-credential-card-"]');
      await expect(cards).toHaveCount(1);
      await expect(cards.first().locator('.cred-badge')).toHaveText(bt);

      // Reset to "All Backends" before the next iteration.
      await allChip.click();
      await page.waitForTimeout(200);
    }
  });

  // ── B-14: SetDefaultBackend call count is correct ────────────────────────

  test('B-14: SetDefaultBackend is called exactly once per chip selection', async ({ page }) => {
    await navigateToFIDO2(page);
    await waitForBackendChips(page);

    const chips = page
      .locator('[data-testid="fido2-backend-selector"]')
      .locator('.filter-chip');

    // Initial state: no SetDefaultBackend calls (selectedBackend starts at 'all').
    const initialCount = await page.evaluate<number>(
      () => (window as any).__setDefaultBackendCalls,
    );
    expect(initialCount).toBe(0);

    // Each non-software chip click must increment the counter by exactly 1.
    let expectedCalls = 0;
    for (const bt of NON_SOFTWARE_BACKENDS) {
      expectedCalls++;
      await chips.filter({ hasText: DISPLAY_NAMES[bt] }).click();
      await page.waitForFunction(
        (n) => (window as any).__setDefaultBackendCalls === n,
        expectedCalls,
        { timeout: 3_000 },
      );
    }

    const finalCount = await page.evaluate<number>(
      () => (window as any).__setDefaultBackendCalls,
    );
    expect(finalCount).toBe(NON_SOFTWARE_BACKENDS.length);
  });

  // ── B-15: Clicking "All Backends" does NOT call SetDefaultBackend ─────────

  test('B-15: Clicking "All Backends" chip does not call SetDefaultBackend', async ({ page }) => {
    await navigateToFIDO2(page);
    await waitForBackendChips(page);

    const chips = page
      .locator('[data-testid="fido2-backend-selector"]')
      .locator('.filter-chip');
    const allChip = chips.first();

    // Select a non-software backend first to prove the counter works.
    await chips.filter({ hasText: DISPLAY_NAMES.tpm2 }).click();
    await page.waitForFunction(
      () => (window as any).__setDefaultBackendCalls === 1,
      { timeout: 3_000 },
    );

    // Click "All Backends": the FIDO2 view does NOT call SetDefaultBackend for
    // 'all' (the reactive guard is selectedBackend !== 'all').
    await allChip.click();
    await page.waitForTimeout(300);

    const callCount = await page.evaluate<number>(
      () => (window as any).__setDefaultBackendCalls,
    );
    expect(callCount).toBe(1); // Still 1 — no additional call for "All Backends".
  });
});
