import { type Page } from '@playwright/test';

export { isWailsMode } from './helpers';

/**
 * Default mock password entries for testing.
 */
const mockPasswords = [
  {
    id: 'pw-1',
    name: 'GitHub',
    title: 'GitHub',
    username: 'testuser',
    password: 'gh-secret-123',
    url: 'https://github.com',
    notes: 'Dev account',
    folder_path: '',
    backend_id: 'barrier',
    expires_at: '',
    created_at: '2025-01-01T00:00:00Z',
    updated_at: '2025-01-01T00:00:00Z',
    is_expired: false,
    days_until_expiry: -1,
    read_only: false,
  },
  {
    id: 'pw-2',
    name: 'AWS Console',
    title: 'AWS Console',
    username: 'admin@company.com',
    password: 'aws-secret-456',
    url: 'https://console.aws.amazon.com',
    notes: 'Production',
    folder_path: 'Work',
    backend_id: 'barrier',
    expires_at: '',
    created_at: '2025-01-02T00:00:00Z',
    updated_at: '2025-01-02T00:00:00Z',
    is_expired: false,
    days_until_expiry: -1,
    read_only: false,
  },
];

/**
 * Options for configuring the password store mock behavior.
 */
export interface PasswordMockOptions {
  /** Whether password_store_require_pin is enabled. Default: true. */
  pinRequired?: boolean;
  /** Whether the PIN verification should succeed. Default: true. */
  pinVerifySucceeds?: boolean;
  /** Whether the store starts locked. Default: false. */
  startLocked?: boolean;
  /** Initial password entries. Default: mockPasswords. */
  passwords?: typeof mockPasswords;
  /** Auto-lock minutes. Default: 5. */
  autoLockMinutes?: number;
}

/**
 * Install a mock of window.go that provides password store services.
 * The mock includes AppService, PINService, PasswordProtectionService,
 * StaticPasswordService, and SetupWizardService (to show main app).
 *
 * Must be called BEFORE page.goto('/').
 */
export async function installPasswordMock(
  page: Page,
  options: PasswordMockOptions = {},
): Promise<void> {
  const opts = {
    pinRequired: options.pinRequired ?? true,
    pinVerifySucceeds: options.pinVerifySucceeds ?? true,
    startLocked: options.startLocked ?? false,
    passwords: options.passwords ?? mockPasswords,
    autoLockMinutes: options.autoLockMinutes ?? 5,
  };

  await page.addInitScript(
    (serializedOpts) => {
      let isLocked = serializedOpts.startLocked;

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
          TPMService: {
            GetStatus: async () => ({ available: false, device_exists: false }),
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
              storage_encrypted: true,
              storage_mounted: true,
              mode: 'standalone',
              sealed: false,
              pin_configured: true,
              pin_locked: false,
              pin_strategy: 'barrier',
              seal_strategy: 'barrier',
              hardware_backed: false,
            }),
            GetDeveloperTools: async () => false,
            GetConfig: async () => ({
              auto_tray: false,
              theme: 'system',
              start_minimized: false,
              notifications: true,
              window_width: 1200,
              window_height: 800,
              remember_position: false,
              window_x: 0,
              window_y: 0,
              server_address: '',
              server_protocol: 'rest',
              server_tls_enabled: false,
              server_tls_skip_verify: false,
              server_tls_ca_file: '',
              server_auto_connect: false,
              auto_unseal_enabled: false,
              auto_unseal_blob_id: '',
              auto_unseal_pcrs: [],
              auto_unseal_pcr_bank: '',
              fido2_authenticator_enabled: false,
              clipboard_timeout: 30,
              require_auth: false,
              seal_require_pin: false,
              password_store_require_pin: serializedOpts.pinRequired,
              password_store_auto_lock_minutes: serializedOpts.autoLockMinutes,
              seal_auto_lock_minutes: 5,
              app_auto_lock_minutes: 0,
              app_lock_on_screen_lock: false,
              setup_complete: true,
              api_explorer_sandbox_policy: '',
              browser_extension_enabled: false,
              fido2_require_user_presence: true,
              fido2_user_intent_check: false,
              developer_tools: false,
            }),
            UpdateConfig: async () => true,
            SetTheme: async () => {},
            GetTheme: async () => 'system',
          },
          PINService: {
            VerifyUserPIN: async (pin: string) => {
              if (!serializedOpts.pinVerifySucceeds) {
                throw new Error('Incorrect PIN');
              }
              // PIN verification succeeds
            },
            GetPINStatus: async () => ({
              so_pin_set: true,
              user_pin_set: true,
              initialized: true,
              strategy: 'barrier',
            }),
          },
          PasswordProtectionService: {
            GetStatus: async () => ({
              mode: 'barrier',
              tpm_available: false,
              key_source: 'barrier',
              is_locked: isLocked,
              password_count: serializedOpts.passwords.length,
            }),
            Unlock: async () => {
              isLocked = false;
            },
            Lock: async () => {
              isLocked = true;
            },
          },
          StaticPasswordService: {
            ListPasswords: async () => serializedOpts.passwords,
            ListFolders: async () => {
              const folders = new Set<string>();
              for (const pw of serializedOpts.passwords) {
                if (pw.folder_path) folders.add(pw.folder_path);
              }
              return Array.from(folders);
            },
            AddPasswordV2: async (params: any) => ({
              id: 'pw-new-' + Date.now(),
              ...params,
              created_at: new Date().toISOString(),
              updated_at: new Date().toISOString(),
              is_expired: false,
              days_until_expiry: -1,
              read_only: false,
            }),
            DeletePassword: async () => {},
            GeneratePassword: async (length: number) =>
              'x'.repeat(length || 20),
          },
          SealService: {
            CanSeal: async () => false,
          },
          FIDO2DeviceService: {
            GetStatus: async () => ({
              running: false,
              device_name: '',
              vendor_id: '',
              product_id: '',
              has_pending_touch: false,
            }),
            ApproveTouchRequest: async () => true,
          },
        },
      };
    },
    opts,
  );
}

/**
 * Install a mock where PIN is required and store starts locked.
 * After PINGate verification, Passwords.svelte should auto-unlock.
 */
export async function installLockedPasswordMock(
  page: Page,
): Promise<void> {
  await installPasswordMock(page, {
    pinRequired: true,
    pinVerifySucceeds: true,
    startLocked: true,
  });
}

/**
 * Install a mock where PIN is required but verification fails.
 */
export async function installPinFailureMock(
  page: Page,
): Promise<void> {
  await installPasswordMock(page, {
    pinRequired: true,
    pinVerifySucceeds: false,
    startLocked: false,
  });
}

/**
 * Install a mock where PIN is NOT required and store is unlocked.
 * PINGate should be bypassed, passwords shown immediately.
 */
export async function installUnlockedPasswordMock(
  page: Page,
): Promise<void> {
  await installPasswordMock(page, {
    pinRequired: false,
    startLocked: false,
  });
}
