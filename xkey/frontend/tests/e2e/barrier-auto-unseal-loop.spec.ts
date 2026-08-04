import { test, expect, type Page } from '@playwright/test';
import {
  waitForAppReady,
  ensureSidebarExpanded,
  navigateTo,
  navigateToSettingsCategory,
} from './helpers';
import { isRealWailsRuntime } from './setup-helpers';

/**
 * Regression coverage for the Settings > Storage "Barrier Auto-Unseal"
 * runaway retry loop (see BarrierAutoUnsealService.GetAutoUnsealStatus and
 * Settings.svelte's barrierAutoUnsealAttempted latch).
 *
 * Root cause: the `$: if (... && !barrierAutoUnsealStatus && !barrierAutoUnsealLoading)`
 * reactive statement refired forever whenever GetAutoUnsealStatus rejected,
 * because a rejected call leaves barrierAutoUnsealStatus null and loading
 * flips back to false, satisfying the guard again on the very next tick.
 *
 * These tests install a Vite-mode window.go mock (guarded by
 * isRealWailsRuntime so they never run against a live backend, whose
 * genuine service overwrites window.go) and assert:
 *   1. GetAutoUnsealStatus is called a bounded number of times even when it
 *      always rejects (proves the frontend latch, independent of the Go
 *      fix that makes GetAutoUnsealStatus never error in production).
 *   2. An { available: false, reason } status renders a terminal
 *      "unavailable" panel instead of the infinite loading spinner.
 */

const BASE_MOCK_SCRIPT = () => {
  (window as any).__getAutoUnsealStatusCalls = 0;

  (window as any).go = {
    services: {
      SetupWizardService: {
        GetStartupState: async () => ({
          setup_complete: true,
          enterprise_mode: false,
          enterprise_wizard_mode: '',
        }),
      },
      AppLockService: {
        GetStatus: async () => ({ is_locked: false }),
        RecordActivity: async () => {},
      },
      AuthService: {
        SetModeUser: async () => {},
      },
      AppService: {
        GetStatus: async () => ({
          version: '0.1.0-test',
          uptime: '1h',
          phone_connected: false,
          key_count: 0,
          bridge_running: false,
          platform: 'linux',
          go_version: 'go1.26.1',
          server_connected: false,
          server_address: '',
          remote_key_count: 0,
          oath_account_count: 0,
          fido2_cred_count: 0,
          piv_cert_count: 0,
          tpm_available: false,
          tpm_device_exists: false,
          tpm_provisioned: false,
          storage_encrypted: false,
          storage_mounted: false,
          mode: 'standalone',
          sealed: false,
          pin_configured: false,
          pin_locked: false,
          pin_strategy: 'barrier',
          seal_strategy: 'software',
          hardware_backed: false,
        }),
        GetConfig: async () => ({
          auto_tray: false,
          theme: 'dark',
          start_minimized: false,
          notifications: true,
          window_width: 1200,
          window_height: 800,
          remember_position: true,
          window_x: 0,
          window_y: 0,
          server_address: '',
          server_protocol: 'grpc',
          server_tls_enabled: false,
          server_tls_skip_verify: false,
          server_tls_ca_file: '',
          server_auto_connect: false,
          auto_unseal_enabled: false,
          auto_unseal_blob_id: '',
          auto_unseal_pcrs: [],
          auto_unseal_pcr_bank: 'sha256',
          fido2_authenticator_enabled: false,
          clipboard_timeout: 30,
          require_auth: false,
          app_auto_lock_minutes: 5,
          app_lock_on_screen_lock: false,
          setup_complete: true,
          api_explorer_sandbox_policy: 'strict',
          browser_extension_enabled: false,
          fido2_require_user_presence: true,
          fido2_user_intent_check: true,
          developer_tools: false,
          barrier_auto_unseal_enabled: false,
        }),
        GetDeveloperTools: async () => false,
      },
      StorageService: {
        GetStatus: async () => ({
          engine: 'file',
          encrypted: false,
          mounted: true,
        }),
      },
      AutoUnsealService: {
        GetStatus: async () => ({ available: false, configured: false, blob_id: '' }),
      },
      TPMService: {
        ListPolicies: async () => [],
      },
    },
  };
};

/** Installs the mock with GetAutoUnsealStatus rejecting on every call. */
async function installRejectingMock(page: Page): Promise<void> {
  await page.addInitScript(BASE_MOCK_SCRIPT);
  await page.addInitScript(() => {
    (window as any).go.services.BarrierAutoUnsealService = {
      GetAutoUnsealStatus: async () => {
        (window as any).__getAutoUnsealStatusCalls++;
        throw new Error('policy store not configured');
      },
    };
  });
}

/** Installs the mock with GetAutoUnsealStatus resolving to an unavailable status. */
async function installUnavailableMock(page: Page): Promise<void> {
  await page.addInitScript(BASE_MOCK_SCRIPT);
  await page.addInitScript(() => {
    (window as any).go.services.BarrierAutoUnsealService = {
      GetAutoUnsealStatus: async () => {
        (window as any).__getAutoUnsealStatusCalls++;
        return {
          available: false,
          reason: 'PCR policy store is not configured',
          tpm_available: false,
          barrier_sealed: false,
          policy_configured: false,
          policy_name: '',
          pcrs_match: false,
        };
      },
    };
  });
}

test.describe('Vite Mock: Barrier Auto-Unseal runaway retry loop regression', () => {
  test.beforeEach(async ({ page }) => {
    // Vite mock-mode only: the real Wails runtime overwrites window.go with
    // the live backend, so the controlled reject/unavailable mock cannot hold.
    const realWails = await isRealWailsRuntime(page);
    test.skip(realWails, 'Vite mock-mode only; real Wails backend overrides window.go');
  });

  test('rejecting GetAutoUnsealStatus reaches a terminal state and is called a bounded number of times', async ({
    page,
  }) => {
    await installRejectingMock(page);
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
    await navigateTo(page, 'settings');
    await navigateToSettingsCategory(page, 'Storage');

    // Give the (formerly infinite) reactive loop ample time to misbehave.
    await page.waitForTimeout(3000);

    // Terminal state: no perpetual loading spinner for the barrier
    // auto-unseal panel specifically.
    await expect(
      page.getByText('Loading barrier auto-unseal status...'),
    ).not.toBeVisible();
    await expect(
      page.getByText('Unable to load barrier auto-unseal status.'),
    ).toBeVisible();

    const calls = await page.evaluate<number>(() => (window as any).__getAutoUnsealStatusCalls);
    expect(calls).toBeLessThanOrEqual(2);
  });

  test('available:false status renders the unavailable panel with reason, no spam', async ({
    page,
  }) => {
    await installUnavailableMock(page);
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
    await navigateTo(page, 'settings');
    await navigateToSettingsCategory(page, 'Storage');

    await page.waitForTimeout(3000);

    await expect(
      page.getByText('Loading barrier auto-unseal status...'),
    ).not.toBeVisible();
    await expect(
      page.getByText(/Barrier auto-unseal is unavailable: PCR policy store is not configured/),
    ).toBeVisible();

    const calls = await page.evaluate<number>(() => (window as any).__getAutoUnsealStatusCalls);
    expect(calls).toBeLessThanOrEqual(2);
  });
});
