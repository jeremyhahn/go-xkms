import { test, expect, type Page } from '@playwright/test';
import {
  waitForAppReady,
  ensureSidebarExpanded,
  navigateTo,
  navigateToSettingsCategory,
} from './helpers';
import { isRealWailsRuntime } from './setup-helpers';

/**
 * Regression coverage for Settings > PIN Management ignoring the active PIN
 * backend's SO PIN capability (see PINService.SOPINSupported in
 * pkg/gui/services/pin_service.go and the "so_pin_supported" field on
 * PINStatusInfo). Before this fix, the tpm2 PIN strategy — which has no
 * separate Security Officer PIN concept — still rendered a "Set SO PIN"
 * button that always failed with the raw backend error "pin: PIN not set".
 *
 * These tests install a Vite-mode window.go mock (guarded by
 * isRealWailsRuntime so they never run against a live backend, whose
 * genuine service overwrites window.go) and assert:
 *   1. so_pin_supported: false renders an explanatory panel and no
 *      "Set SO PIN" / "Change SO PIN" button.
 *   2. so_pin_supported: true renders the normal SO PIN section unchanged.
 */

const BASE_MOCK_SCRIPT = () => {
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
          sealer_backend: 'software',
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
    },
  };
};

/** Installs the mock with GetPINStatus reporting a software backend (SO PIN supported). */
async function installSoftwareStrategyMock(page: Page): Promise<void> {
  await page.addInitScript(BASE_MOCK_SCRIPT);
  await page.addInitScript(() => {
    (window as any).go.services.PINService = {
      GetPINStatus: async () => ({
        so_pin_set: true,
        user_pin_set: true,
        initialized: true,
        strategy: 'software',
        so_pin_supported: true,
      }),
      GetLockoutStatus: async () => ({
        failed_attempts: 0,
        max_attempts: 5,
        is_locked: false,
        lockout_until: '',
        recovery_seconds: 0,
      }),
    };
  });
}

/** Installs the mock with GetPINStatus reporting a tpm2 backend (SO PIN not supported). */
async function installTPM2StrategyMock(page: Page): Promise<void> {
  await page.addInitScript(BASE_MOCK_SCRIPT);
  await page.addInitScript(() => {
    (window as any).go.services.PINService = {
      GetPINStatus: async () => ({
        so_pin_set: false,
        user_pin_set: true,
        initialized: true,
        strategy: 'tpm2',
        so_pin_supported: false,
      }),
      GetLockoutStatus: async () => ({
        failed_attempts: 0,
        max_attempts: 5,
        is_locked: false,
        lockout_until: '',
        recovery_seconds: 0,
      }),
    };
  });
}

test.describe('Vite Mock: PIN Management SO PIN capability regression', () => {
  test.beforeEach(async ({ page }) => {
    // Vite mock-mode only: the real Wails runtime overwrites window.go with
    // the live backend, so the controlled strategy mock cannot hold.
    const realWails = await isRealWailsRuntime(page);
    test.skip(realWails, 'Vite mock-mode only; real Wails backend overrides window.go');
  });

  test('tpm2 strategy (so_pin_supported: false) shows the explanation panel and no Set/Change SO PIN button', async ({
    page,
  }) => {
    await installTPM2StrategyMock(page);
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
    await navigateTo(page, 'settings');
    await navigateToSettingsCategory(page, 'PIN Management');

    await expect(page.getByText('Loading PIN status...')).not.toBeVisible();

    // The "Security Officer PIN" card renders the capability explanation
    // panel in place of the normal status/action rows.
    const soPINCard = page.locator('.settings-section', {
      has: page.locator('h2', { hasText: 'Security Officer PIN' }),
    });
    await expect(soPINCard).toBeVisible();
    await expect(soPINCard.locator('.auto-unseal-info')).toContainText(
      'binds authorization to the platform hardware directly',
    );

    // No dead buttons: neither the "Set SO PIN" nor "Change SO PIN" action exists.
    await expect(soPINCard.getByRole('button')).toHaveCount(0);

    // User PIN and Lockout Status cards must still render (unaffected by SO
    // PIN capability) — they are not dead-ended by the missing SO PIN.
    await expect(page.locator('.settings-section h2').filter({ hasText: 'User PIN' })).toBeVisible();
    await expect(page.locator('.settings-section h2').filter({ hasText: 'Lockout Status' })).toBeVisible();

    // Reset Lockout copy reflects the tpm2-appropriate credential.
    await expect(page.getByText(/TPM Lockout hierarchy password/)).toBeVisible();
  });

  test('software strategy (so_pin_supported: true) shows the normal SO PIN section', async ({
    page,
  }) => {
    await installSoftwareStrategyMock(page);
    await page.goto('/');
    await waitForAppReady(page);
    await ensureSidebarExpanded(page);
    await navigateTo(page, 'settings');
    await navigateToSettingsCategory(page, 'PIN Management');

    await expect(page.getByText('Loading PIN status...')).not.toBeVisible();

    // Normal SO PIN section is present (so_pin_set: true -> "Change SO PIN").
    const soPINCard = page.locator('.settings-section', {
      has: page.locator('h2', { hasText: 'Security Officer PIN' }),
    });
    await expect(soPINCard).toBeVisible();
    await expect(soPINCard.getByText('SO PIN is configured')).toBeVisible();
    await expect(soPINCard.getByRole('button', { name: 'Change' })).toBeVisible();

    // The tpm2-only explanation panel must not appear.
    await expect(soPINCard.locator('.auto-unseal-info')).toHaveCount(0);
  });
});
