<script lang="ts">
  import { onMount } from 'svelte';
  import { Quit } from '../wailsjs/runtime/runtime';
  import Card from '$lib/components/Card.svelte';
  import GradientHeader from '$lib/components/GradientHeader.svelte';
  import Toggle from '$lib/components/Toggle.svelte';
  import Input from '$lib/components/Input.svelte';
  import Button from '$lib/components/Button.svelte';
  import StatusBadge from '$lib/components/StatusBadge.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
  import StoragePassphraseDialog from '$lib/components/StoragePassphraseDialog.svelte';
  import PINDialog from '$lib/components/PINDialog.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import {
    mdiCog, mdiWeatherSunny, mdiCellphone, mdiLockOutline,
    mdiAlert, mdiWrenchOutline, mdiServerNetwork, mdiLanConnect,
    mdiHarddisk, mdiLockOpen, mdiDatabaseLock, mdiShieldAlert,
    mdiDeleteSweep, mdiPlus,
    mdiBellOutline, mdiTestTube, mdiChip, mdiShieldLockOutline,
    mdiFormTextboxPassword, mdiLockAlert, mdiCheck, mdiClose, mdiLockReset,
    mdiWeb, mdiRefresh, mdiShieldCheck, mdiCertificate, mdiConsoleLine
  } from '$lib/utils/icons';
  import { formatBytes } from '$lib/utils/format';
  import { theme, setTheme } from '$lib/stores/theme';
  import { addNotification } from '$lib/stores/notifications';
  import type { ThemeMode } from '$lib/stores/theme';
  import { isWailsAvailable, callBackend, callBackendVoid, callBackendVoidWithError, callBackendWithError } from '$lib/api/backend';
  import type { GUIConfig, AutoUnsealStatus, AutoUnsealResult, PINStatus, LockoutStatus, BarrierAutoUnsealStatus, PCRPolicy } from '$lib/api/backend';
  import { isServerConnected, connect, disconnect } from '$lib/stores/connection';
  import { isEnterpriseMode, enterprisePolicy } from '$lib/stores/auth';
  import { extensionPairingChanged } from '$lib/stores/events';
  import { setDevToolsEnabled, devToolsEnabled as devToolsStore } from '$lib/stores/app';

  type SettingsCategory = 'general' | 'appearance' | 'server' | 'phone' | 'security' | 'pin' | 'storage' | 'notifications' | 'browser' | 'api-explorer' | 'advanced';

  /** Response shape from StorageService.GetStatus */
  interface StorageStatus {
    volume_exists: boolean;
    is_luks: boolean;
    is_mounted: boolean;
    is_open: boolean;
    volume_path: string;
    mount_point: string;
    volume_size_bytes: number;
    elevation_available: boolean;
  }

  const categories = [
    { id: 'general' as SettingsCategory, label: 'General', icon: mdiCog },
    { id: 'appearance' as SettingsCategory, label: 'Appearance', icon: mdiWeatherSunny },
    { id: 'browser' as SettingsCategory, label: 'Browser', icon: mdiWeb },
    { id: 'api-explorer' as SettingsCategory, label: 'API Explorer', icon: mdiConsoleLine },
    { id: 'server' as SettingsCategory, label: 'Server', icon: mdiServerNetwork },
    { id: 'phone' as SettingsCategory, label: 'Phone', icon: mdiCellphone },
    { id: 'security' as SettingsCategory, label: 'Security', icon: mdiLockOutline },
    { id: 'pin' as SettingsCategory, label: 'PIN Management', icon: mdiFormTextboxPassword },
    { id: 'storage' as SettingsCategory, label: 'Storage', icon: mdiHarddisk },
    { id: 'notifications' as SettingsCategory, label: 'Notifications', icon: mdiAlert },
    { id: 'advanced' as SettingsCategory, label: 'Advanced', icon: mdiWrenchOutline },
  ];

  let activeCategory: SettingsCategory = 'general';

  // Settings state
  let startWithSystem = false;
  let startMinimized = false;
  let autoConnect = true;
  let currentTheme: ThemeMode = 'system';
  let fontSize = 16;
  let defaultDevice = '';
  let attestationPolicy = 'always';
  let gracePeriod = 24;
  let lockTimeout = 15;
  let lockOnScreenLock = true;
  let barrierAutoUnsealEnabled = false;
  let requireAuth = true;
  let clipboardTimeout = 30;
  // API Explorer sandbox settings
  let sandboxAllowSameOrigin = true;
  let sandboxAllowScripts = true;
  let sandboxAllowForms = true;
  let sandboxAllowPopups = true;
  let sandboxPolicyLocked = false; // enterprise policy override

  // PIN verification dialog state for disabling security toggles.
  let showAuthPINDialog = false;
  let authPINValue = '';
  let authPINLoading = false;
  let authPINError = '';
  // Which toggle is being disabled: 'requireAuth'
  let authPINTarget: string = '';

  /**
   * Called by Toggle onChange when a security toggle is flipped OFF.
   * Since bind:checked already updated the variable, we revert it
   * and show the PIN dialog. On successful verification, we apply
   * the change via applySecurityToggle.
   */
  function guardSecurityToggle(target: string): void {
    // Revert the toggle immediately (bind:checked already flipped it).
    if (target === 'requireAuth') requireAuth = true;

    authPINTarget = target;
    authPINValue = '';
    authPINError = '';
    authPINLoading = false;
    showAuthPINDialog = true;
  }

  function applySecurityToggle(target: string): void {
    if (target === 'requireAuth') requireAuth = false;
    autoSave();
  }

  async function handleAuthPINSubmit(): Promise<void> {
    if (!authPINValue.trim()) {
      authPINError = 'PIN is required';
      return;
    }
    authPINLoading = true;
    authPINError = '';

    // Check if user PIN is actually configured before trying to verify.
    const pinStatus = await callBackend<PINStatus>('PINService', 'GetPINStatus');
    if (!pinStatus?.user_pin_set) {
      // No user PIN configured — allow the toggle change without verification.
      showAuthPINDialog = false;
      applySecurityToggle(authPINTarget);
      addNotification('info', 'Security setting disabled');
      authPINLoading = false;
      return;
    }

    const result = await callBackendVoidWithError('PINService', 'VerifyUserPIN', authPINValue.trim());
    authPINLoading = false;

    if (result.ok) {
      showAuthPINDialog = false;
      applySecurityToggle(authPINTarget);
      addNotification('info', 'Security setting disabled');
    } else {
      authPINError = result.error || 'Invalid PIN';
    }
  }

  function handleAuthPINCancel(): void {
    showAuthPINDialog = false;
    authPINValue = '';
    authPINError = '';
  }

  let notifyOnConnect = true;
  let notifyOnAuth = true;
  let notifyOnError = true;
  let desktopNotifications = true;
  let testingNotification = false;
  let serverProtocol = 'grpc';
  let serverAddress = '';
  let serverTLSEnabled = false;
  let serverTLSSkipVerify = false;
  let serverTLSCAFile = '';
  let serverAutoConnect = false;
  let connecting = false;
  let xkmsdUrl = 'localhost:8443';
  let defaultBackend = 'software';
  let logLevel = 'info';
  let debugMode = false;
  let fido2AuthenticatorEnabled = false;
  let fido2RequireUserPresence = true;
  let fido2UserIntentCheck = true;

  // Browser settings state
  interface BrowserConfig {
    default_browser: string;
    custom_command: string;
    include_trust_bundle: boolean;
    chrome_profile_mode: string;
    firefox_profile_mode: string;
  }
  interface BrowserInfo {
    name: string;
    path: string;
  }
  interface BrowserBundleStatus {
    exists: boolean;
    stale: boolean;
    cert_count: number;
    last_generated: string;
    bundle_path: string;
  }
  interface SecureBrowserLaunchResult {
    browser: string;
    family: string;
    mode: string;
    cert_count: number;
    pid: number;
  }
  let browserConfig: BrowserConfig = {
    default_browser: 'system',
    custom_command: '',
    include_trust_bundle: false,
    chrome_profile_mode: 'isolated',
    firefox_profile_mode: 'isolated',
  };
  let detectedBrowsers: BrowserInfo[] = [{ name: 'System Default', path: 'system' }];
  let browserLoading = false;
  let browserConfigLoaded = false;
  let bundleStatus: BrowserBundleStatus | null = null;
  let bundleStatusLoading = false;
  let bundleRegenerating = false;

  // Secure browser launch state (go-truststrap cert injection).
  let secureBrowsers: BrowserInfo[] = [];
  let secureBrowserPath = '';
  let secureBrowserURL = 'about:blank';
  let secureBrowserLaunching = false;
  let secureBrowserCertCount = 0;

  // Extension pairing state
  interface ExtensionPairingStatus {
    paired: boolean;
    origin: string;
    paired_at: string;
  }
  interface ManifestInfo {
    browser: string;
    name: string;
    installed: boolean;
    path: string;
  }
  interface ExtensionFullStatus {
    ipc_running: boolean;
    ipc_socket_path: string;
    paired_extensions: ExtensionPairingStatus[];
    manifests: ManifestInfo[];
  }
  let extensionPairedList: ExtensionPairingStatus[] = [];
  let extensionFullStatus: ExtensionFullStatus | null = null;
  let extensionLoading = false;
  let extensionUnpairing = false;
  let extensionEnabled = true;
  let requireAutofillAuth = true;
  let manifestInstalling: string | null = null;

  // Storage state
  let storageStatus: StorageStatus | null = null;
  let storageLoading = false;
  let storageLocking = false;
  let storageUnlockPassphrase = '';
  let showCreateDialog = false;
  let showMigrateDialog = false;
  let showUnlockDialog = false;
  let showWipeConfirm = false;
  let wipeStandard = 'nist';
  let wiping = false;
  let wipePINRequired = false;
  let wipePINValue = '';
  let wipePINError = '';

  // Auto-unseal state
  let autoUnsealStatus: AutoUnsealStatus | null = null;
  let autoUnsealLoading = false;
  let showAutoUnsealEnableDialog = false;
  let autoUnsealPassphrase = '';
  let autoUnsealConfirmPassphrase = '';
  let autoUnsealEnabling = false;
  let autoUnsealDisabling = false;
  let showAutoUnsealDisableConfirm = false;

  // Barrier auto-unseal state
  let barrierAutoUnsealStatus: BarrierAutoUnsealStatus | null = null;
  let barrierAutoUnsealLoading = false;
  let barrierAutoUnsealPolicies: PCRPolicy[] = [];
  let barrierAutoUnsealSelectedPolicy = '';
  let barrierAutoUnsealSetting = false;
  let barrierAutoUnsealClearing = false;

  // PIN management state
  let pinStatus: PINStatus | null = null;
  let pinLoading = false;
  let lockoutStatusData: LockoutStatus | null = null;
  let lockoutLoading = false;
  let showPINDialog = false;
  let pinDialogMode: 'set-so' | 'change-so' | 'set-user' | 'change-user' = 'set-so';
  let showResetLockoutConfirm = false;
  let resetLockoutSOPIN = '';
  let resettingLockout = false;

  $: currentTheme = $theme;

  // Load PIN status when the PIN category is selected
  $: if (activeCategory === 'pin' && isWailsAvailable() && !pinStatus && !pinLoading) {
    loadPINStatus();
  }

  // Load lockout status when the PIN category is selected
  $: if (activeCategory === 'pin' && isWailsAvailable() && !lockoutStatusData && !lockoutLoading) {
    loadLockoutStatus();
  }

  // Load storage status when the storage category is selected
  $: if (activeCategory === 'storage' && isWailsAvailable() && !storageStatus && !storageLoading) {
    loadStorageStatus();
  }

  // Load auto-unseal status when the storage category is selected
  $: if (activeCategory === 'storage' && isWailsAvailable() && !autoUnsealStatus && !autoUnsealLoading) {
    loadAutoUnsealStatus();
  }

  // Load barrier auto-unseal status when the storage category is selected
  $: if (activeCategory === 'storage' && isWailsAvailable() && !barrierAutoUnsealStatus && !barrierAutoUnsealLoading) {
    loadBarrierAutoUnsealStatus();
  }

  // Load browser config when the browser category is selected
  $: if (activeCategory === 'browser' && isWailsAvailable() && !browserConfigLoaded && !browserLoading) {
    loadBrowserConfig();
  }

  // Load extension pairing status when browser category is activated
  $: if (activeCategory === 'browser' && isWailsAvailable() && !extensionLoading && extensionFullStatus === null) {
    loadExtensionPairingStatus();
  }

  // Re-fetch extension pairing status when pairing events fire (paired/unpaired).
  // Reset counter first to prevent infinite re-triggering (extensionLoading
  // transitions false → reactive re-evaluates → counter still > 0 → loop).
  $: if ($extensionPairingChanged > 0 && isWailsAvailable() && !extensionLoading) {
    extensionPairingChanged.set(0);
    loadExtensionPairingStatus();
  }

  onMount(async () => {
    if (isWailsAvailable()) {
      const cfg = await callBackend<GUIConfig>('AppService', 'GetConfig');
      if (cfg) {
        startMinimized = cfg.start_minimized;
        startWithSystem = cfg.auto_tray;
        serverProtocol = cfg.server_protocol || 'grpc';
        serverAddress = cfg.server_address || '';
        serverTLSEnabled = cfg.server_tls_enabled || false;
        serverTLSSkipVerify = cfg.server_tls_skip_verify || false;
        serverTLSCAFile = cfg.server_tls_ca_file || '';
        serverAutoConnect = cfg.server_auto_connect || false;
        fido2AuthenticatorEnabled = cfg.fido2_authenticator_enabled || false;
        fido2RequireUserPresence = cfg.fido2_require_user_presence ?? true;
        fido2UserIntentCheck = cfg.fido2_user_intent_check ?? true;
        clipboardTimeout = cfg.clipboard_timeout ?? 30;
        requireAuth = cfg.require_auth || false;
        lockTimeout = cfg.app_auto_lock_minutes ?? 15;
        lockOnScreenLock = cfg.app_lock_on_screen_lock ?? true;
        barrierAutoUnsealEnabled = cfg.barrier_auto_unseal_enabled ?? false;
        defaultBackend = cfg.sealer_backend || 'software';

        // Initialize sandbox checkboxes from config.
        const sp = cfg.api_explorer_sandbox_policy || 'allow-same-origin allow-scripts allow-forms allow-popups';
        sandboxAllowSameOrigin = sp.includes('allow-same-origin');
        sandboxAllowScripts = sp.includes('allow-scripts');
        sandboxAllowForms = sp.includes('allow-forms');
        sandboxAllowPopups = sp.includes('allow-popups');
        setDevToolsEnabled(cfg.developer_tools ?? true);
      }
      // Check enterprise policy override for sandbox.
      if ($isEnterpriseMode && $enterprisePolicy?.api_explorer_sandbox_policy) {
        const ep = $enterprisePolicy.api_explorer_sandbox_policy as string;
        sandboxAllowSameOrigin = ep.includes('allow-same-origin');
        sandboxAllowScripts = ep.includes('allow-scripts');
        sandboxAllowForms = ep.includes('allow-forms');
        sandboxAllowPopups = ep.includes('allow-popups');
        sandboxPolicyLocked = true;
      }
    }
  });

  async function loadStorageStatus(): Promise<void> {
    storageLoading = true;
    const status = await callBackend<StorageStatus>('StorageService', 'GetStatus');
    if (status) {
      storageStatus = status;
    }
    storageLoading = false;
  }


  async function handleUnlockVolume(): Promise<void> {
    if (!storageUnlockPassphrase) {
      addNotification('error', 'Passphrase is required');
      return;
    }
    storageLocking = true;
    const result = await callBackendVoidWithError('StorageService', 'UnlockVolume', storageUnlockPassphrase);
    storageLocking = false;
    showUnlockDialog = false;
    storageUnlockPassphrase = '';

    if (result.ok) {
      addNotification('success', 'Volume unlocked and mounted');
      loadStorageStatus();
    } else {
      addNotification('error', result.error || 'Failed to unlock volume -- check passphrase');
    }
  }

  async function handleLockVolume(): Promise<void> {
    storageLocking = true;
    const result = await callBackendVoidWithError('StorageService', 'LockVolume');
    storageLocking = false;

    if (result.ok) {
      addNotification('success', 'Volume locked');
      loadStorageStatus();
    } else {
      addNotification('error', result.error || 'Failed to lock volume');
    }
  }

  async function handleWipeVolume(): Promise<void> {
    // Require PIN if "Require authentication for sensitive operations" is enabled
    const cfg = await callBackend<GUIConfig>('AppService', 'GetConfig');
    if (cfg?.require_auth) {
      wipePINRequired = true;
      wipePINValue = '';
      wipePINError = '';
      return;
    }
    await executeWipe();
  }

  async function handleWipePINSubmit(): Promise<void> {
    if (!wipePINValue.trim()) {
      wipePINError = 'PIN is required';
      return;
    }
    wipePINError = '';
    const verify = await callBackendVoidWithError('PINService', 'VerifyUserPIN', wipePINValue.trim());
    if (!verify.ok) {
      wipePINError = verify.error || 'Invalid PIN';
      return;
    }
    wipePINRequired = false;
    wipePINValue = '';
    await executeWipe();
  }

  async function executeWipe(): Promise<void> {
    wiping = true;
    const result = await callBackendVoidWithError('StorageService', 'WipeVolume', wipeStandard);
    wiping = false;
    showWipeConfirm = false;

    if (result.ok) {
      addNotification('success', `Volume wiped using ${wipeStandard.toUpperCase()} standard. Closing application...`);
      setTimeout(() => Quit(), 1500);
    } else {
      addNotification('error', result.error || 'Failed to wipe volume');
    }
  }

  function handleStorageDialogComplete(): void {
    loadStorageStatus();
  }

  async function loadAutoUnsealStatus(): Promise<void> {
    autoUnsealLoading = true;
    const status = await callBackend<AutoUnsealStatus>('AutoUnsealService', 'GetStatus');
    if (status) {
      autoUnsealStatus = status;
    }
    autoUnsealLoading = false;
  }

  $: autoUnsealPassphraseIsValid = autoUnsealPassphrase.length >= 8
    && autoUnsealPassphrase === autoUnsealConfirmPassphrase;

  async function handleEnableAutoUnseal(): Promise<void> {
    if (!autoUnsealPassphraseIsValid) {
      addNotification('error', 'Passphrases must match and be at least 8 characters');
      return;
    }
    autoUnsealEnabling = true;
    const defaultPCRs = [0, 1, 2, 3, 4, 5, 6, 7];
    const defaultBank = 'sha256';
    const result = await callBackend<AutoUnsealResult>(
      'AutoUnsealService', 'Enable',
      autoUnsealPassphrase, defaultPCRs, defaultBank, 'custom_pcr', '', 'tpm2'
    );
    autoUnsealEnabling = false;
    if (result && result.success) {
      addNotification('success', result.message || 'Auto-unseal enabled');
      showAutoUnsealEnableDialog = false;
      autoUnsealPassphrase = '';
      autoUnsealConfirmPassphrase = '';
      autoUnsealStatus = null;
      loadAutoUnsealStatus();
    } else {
      addNotification('error', result?.message || 'Failed to enable auto-unseal');
    }
  }

  async function handleDisableAutoUnseal(): Promise<void> {
    autoUnsealDisabling = true;
    const ok = await callBackendVoid('AutoUnsealService', 'Disable');
    autoUnsealDisabling = false;
    showAutoUnsealDisableConfirm = false;
    if (ok) {
      addNotification('success', 'Auto-unseal disabled');
      autoUnsealStatus = null;
      loadAutoUnsealStatus();
    } else {
      addNotification('error', 'Failed to disable auto-unseal');
    }
  }

  async function loadBarrierAutoUnsealStatus(): Promise<void> {
    barrierAutoUnsealLoading = true;
    const [status, policies] = await Promise.all([
      callBackend<BarrierAutoUnsealStatus>('BarrierAutoUnsealService', 'GetAutoUnsealStatus'),
      callBackend<PCRPolicy[]>('TPMService', 'ListPolicies'),
    ]);
    if (status) {
      barrierAutoUnsealStatus = status;
      barrierAutoUnsealSelectedPolicy = status.policy_name || '';
    }
    if (policies) {
      barrierAutoUnsealPolicies = policies;
    }
    barrierAutoUnsealLoading = false;
  }

  async function handleSetBarrierAutoUnsealPolicy(): Promise<void> {
    if (!barrierAutoUnsealSelectedPolicy) {
      addNotification('error', 'Select a PCR policy first');
      return;
    }
    barrierAutoUnsealSetting = true;
    const result = await callBackendVoidWithError(
      'BarrierAutoUnsealService', 'SetAutoUnsealPolicy',
      barrierAutoUnsealSelectedPolicy,
    );
    barrierAutoUnsealSetting = false;
    if (result.ok) {
      addNotification('success', `Barrier auto-unseal policy set to "${barrierAutoUnsealSelectedPolicy}"`);
      barrierAutoUnsealStatus = null;
      loadBarrierAutoUnsealStatus();
    } else {
      addNotification('error', result.error || 'Failed to set barrier auto-unseal policy');
    }
  }

  async function handleClearBarrierAutoUnsealPolicy(): Promise<void> {
    barrierAutoUnsealClearing = true;
    const result = await callBackendVoidWithError('BarrierAutoUnsealService', 'ClearAutoUnsealPolicy');
    barrierAutoUnsealClearing = false;
    if (result.ok) {
      addNotification('success', 'Barrier auto-unseal policy cleared');
      barrierAutoUnsealSelectedPolicy = '';
      barrierAutoUnsealStatus = null;
      loadBarrierAutoUnsealStatus();
    } else {
      addNotification('error', result.error || 'Failed to clear barrier auto-unseal policy');
    }
  }

  async function loadPINStatus(): Promise<void> {
    pinLoading = true;
    const status = await callBackend<PINStatus>('PINService', 'GetPINStatus');
    if (status) {
      pinStatus = status;
    }
    pinLoading = false;
  }

  async function loadLockoutStatus(): Promise<void> {
    lockoutLoading = true;
    const status = await callBackend<LockoutStatus>('PINService', 'GetLockoutStatus');
    if (status) {
      lockoutStatusData = status;
    }
    lockoutLoading = false;
  }

  function openPINDialog(dialogMode: 'set-so' | 'change-so' | 'set-user' | 'change-user'): void {
    pinDialogMode = dialogMode;
    showPINDialog = true;
  }

  function handlePINSuccess(): void {
    showPINDialog = false;
    pinStatus = null;
    lockoutStatusData = null;
    loadPINStatus();
    loadLockoutStatus();
  }

  async function handleResetLockout(): Promise<void> {
    if (!resetLockoutSOPIN) {
      addNotification('error', 'SO PIN is required to reset lockout');
      return;
    }
    resettingLockout = true;
    const result = await callBackendVoidWithError('PINService', 'ResetLockout', resetLockoutSOPIN);
    resettingLockout = false;
    if (result.ok) {
      addNotification('success', 'Lockout reset successfully');
      showResetLockoutConfirm = false;
      resetLockoutSOPIN = '';
      lockoutStatusData = null;
      loadLockoutStatus();
    } else {
      addNotification('error', result.error || 'Failed to reset lockout');
    }
  }

  function formatPINStrategy(strategy: string): string {
    if (!strategy) return 'Unknown';
    const map: Record<string, string> = {
      'software': 'Software',
      'tpm2': 'TPM 2.0',
      'tpm': 'TPM 2.0',
      'pkcs11': 'PKCS#11',
    };
    return map[strategy.toLowerCase()] || strategy;
  }


  async function handleBarrierAutoUnsealToggle(enabled: boolean): Promise<void> {
    const ok = await callBackendVoid('AppService', 'ToggleBarrierAutoUnseal', enabled);
    if (ok) {
      barrierAutoUnsealEnabled = enabled;
      addNotification('success', enabled
        ? 'Auto-unseal enabled — app will unlock automatically on startup'
        : 'Auto-unseal disabled — PIN required on startup');
    } else {
      barrierAutoUnsealEnabled = !enabled;
      addNotification('error', 'Failed to update auto-unseal setting');
    }
  }

  function handleThemeChange(e: Event): void {
    const target = e.target as HTMLSelectElement;
    setTheme(target.value as ThemeMode);
    addNotification('info', `Theme changed to ${target.value}`);
  }

  function buildSandboxPolicy(): string {
    const parts: string[] = [];
    if (sandboxAllowSameOrigin) parts.push('allow-same-origin');
    if (sandboxAllowScripts) parts.push('allow-scripts');
    if (sandboxAllowForms) parts.push('allow-forms');
    if (sandboxAllowPopups) parts.push('allow-popups');
    return parts.join(' ');
  }

  let autoSaveTimer: ReturnType<typeof setTimeout> | null = null;

  /** Persist all current settings to config. Debounced to avoid rapid writes. */
  function autoSave(): void {
    if (autoSaveTimer) clearTimeout(autoSaveTimer);
    autoSaveTimer = setTimeout(doAutoSave, 300);
  }

  async function doAutoSave(): Promise<void> {
    if (!isWailsAvailable()) return;
    const current = await callBackend<GUIConfig>('AppService', 'GetConfig');
    const merged = {
      ...current,
      auto_tray: startWithSystem,
      theme: currentTheme,
      start_minimized: startMinimized,
      notifications: desktopNotifications,
      server_address: serverAddress,
      server_protocol: serverProtocol,
      server_tls_enabled: serverTLSEnabled,
      server_tls_skip_verify: serverTLSSkipVerify,
      server_tls_ca_file: serverTLSCAFile,
      server_auto_connect: serverAutoConnect,
      fido2_authenticator_enabled: fido2AuthenticatorEnabled,
      fido2_require_user_presence: fido2RequireUserPresence,
      fido2_user_intent_check: fido2UserIntentCheck,
      clipboard_timeout: clipboardTimeout,
      require_auth: requireAuth,
      app_auto_lock_minutes: lockTimeout,
      app_lock_on_screen_lock: lockOnScreenLock,
      barrier_auto_unseal_enabled: barrierAutoUnsealEnabled,
      sealer_backend: defaultBackend,
      api_explorer_sandbox_policy: buildSandboxPolicy(),
      developer_tools: $devToolsStore,
    };
    await callBackendVoid('AppService', 'UpdateConfig', merged);
    // Push live side-effects so changes take effect immediately.
    await callBackendVoid('ClipboardService', 'SetTimeout', clipboardTimeout);
    await callBackendVoid('AppLockService', 'SetAutoLockMinutes', lockTimeout);
    await callBackendVoid('AppLockService', 'SetLockOnScreenLock', lockOnScreenLock);
  }

  async function loadExtensionPairingStatus(): Promise<void> {
    extensionLoading = true;
    const fullStatus = await callBackend<ExtensionFullStatus>('PairingService', 'GetExtensionFullStatus');
    if (fullStatus) {
      extensionFullStatus = fullStatus;
      extensionPairedList = fullStatus.paired_extensions || [];
    }
    const enabled = await callBackend<boolean>('AutoFillService', 'IsEnabled');
    if (enabled !== null && enabled !== undefined) {
      extensionEnabled = enabled;
    }
    const authRequired = await callBackend<boolean>('AutoFillService', 'GetRequireAuthentication');
    if (authRequired !== null && authRequired !== undefined) {
      requireAutofillAuth = authRequired;
    }
    extensionLoading = false;
  }

  async function handleToggleFIDO2UserPresence(newValue: boolean): Promise<void> {
    const current = await callBackend<GUIConfig>('AppService', 'GetConfig');
    if (current) {
      await callBackendVoid('AppService', 'UpdateConfig', { ...current, fido2_require_user_presence: newValue });
      addNotification('success', newValue
        ? 'User presence (touch) enabled'
        : 'User presence (touch) disabled');
    }
  }

  async function handleToggleFIDO2IntentCheck(newValue: boolean): Promise<void> {
    const current = await callBackend<GUIConfig>('AppService', 'GetConfig');
    if (current) {
      await callBackendVoid('AppService', 'UpdateConfig', { ...current, fido2_user_intent_check: newValue });
      addNotification('success', newValue
        ? 'Multi-key intent check enabled'
        : 'Multi-key intent check disabled');
    }
  }

  async function handleToggleExtensionEnabled(newValue: boolean): Promise<void> {
    const { error } = await callBackendWithError<void>('AutoFillService', 'SetEnabled', newValue);
    if (error) {
      extensionEnabled = !newValue;
      addNotification('error', `Failed to update extension setting: ${error}`);
    } else {
      // Persist in config so it survives restart.
      const current = await callBackend<GUIConfig>('AppService', 'GetConfig');
      if (current) {
        await callBackendVoid('AppService', 'UpdateConfig', { ...current, browser_extension_enabled: newValue });
      }
      addNotification('success', newValue
        ? 'Browser extension autofill enabled'
        : 'Browser extension autofill disabled');
    }
  }

  async function handleDevToolsToggle(e: CustomEvent<boolean>): void {
    const newValue = e.detail;
    const { error } = await callBackendWithError<void>('AppService', 'SetDeveloperTools', newValue);
    if (error) {
      setDevToolsEnabled(!newValue);
      addNotification('error', `Failed to update developer tools setting: ${error}`);
    } else {
      setDevToolsEnabled(newValue);
      addNotification('success', newValue
        ? 'Developer Tools section enabled'
        : 'Developer Tools section hidden');
    }
  }

  async function handleToggleAutofillAuth(newValue: boolean): Promise<void> {
    const { error } = await callBackendWithError<void>('AutoFillService', 'SetRequireAuthentication', newValue);
    if (error) {
      requireAutofillAuth = !newValue;
      addNotification('error', `Failed to update authentication setting: ${error}`);
    } else {
      addNotification('success', newValue
        ? 'FIDO2 authentication enabled for autofill'
        : 'FIDO2 authentication disabled for autofill');
    }
  }

  async function handleUnpairExtension(origin: string = ''): Promise<void> {
    extensionUnpairing = true;
    const { error } = await callBackendWithError<void>('PairingService', 'Unpair', origin);
    extensionUnpairing = false;
    if (error) {
      addNotification('error', `Failed to unpair extension: ${error}`);
    } else {
      if (origin) {
        extensionPairedList = extensionPairedList.filter(e => e.origin !== origin);
      } else {
        extensionPairedList = [];
      }
      addNotification('success', 'Extension unpaired successfully');
    }
  }

  async function handleInstallManifest(browser: string): Promise<void> {
    manifestInstalling = browser;
    const { error } = await callBackendWithError<void>('PairingService', 'InstallManifest', browser);
    manifestInstalling = null;
    if (error) {
      addNotification('error', `Failed to install ${browser} manifest: ${error}`);
    } else {
      addNotification('success', `Native messaging manifest installed for ${browser}`);
      await loadExtensionPairingStatus();
    }
  }

  async function handleUninstallManifest(browser: string): Promise<void> {
    manifestInstalling = browser;
    const { error } = await callBackendWithError<void>('PairingService', 'UninstallManifest', browser);
    manifestInstalling = null;
    if (error) {
      addNotification('error', `Failed to uninstall ${browser} manifest: ${error}`);
    } else {
      addNotification('success', `Native messaging manifest uninstalled for ${browser}`);
      await loadExtensionPairingStatus();
    }
  }

  async function loadSecureBrowserData(): Promise<void> {
    const browsers = await callBackend<BrowserInfo[]>('SecureBrowserService', 'DetectBrowsers');
    if (browsers) {
      secureBrowsers = browsers;
      if (!secureBrowserPath && browsers.length > 0) {
        secureBrowserPath = browsers[0].path;
      }
    }
    const count = await callBackend<number>('TrustService', 'CertificateCount');
    if (count !== null) {
      secureBrowserCertCount = count;
    }
  }

  function secureBrowserFamily(browserPath: string): 'chrome' | 'firefox' | '' {
    const base = (browserPath.split('/').pop() ?? browserPath).toLowerCase();
    if (/chrome|chromium|brave|edge|opera|vivaldi/.test(base)) return 'chrome';
    if (/firefox|librewolf|waterfox/.test(base)) return 'firefox';
    return '';
  }

  async function handleLaunchSecureBrowser(): Promise<void> {
    if (!secureBrowserPath) {
      addNotification('error', 'Select a browser to launch');
      return;
    }
    if (!secureBrowserURL.trim()) {
      addNotification('error', 'URL is required');
      return;
    }
    secureBrowserLaunching = true;
    const { result, error } = await callBackendWithError<SecureBrowserLaunchResult>(
      'SecureBrowserService',
      'LaunchBrowser',
      secureBrowserPath,
      secureBrowserURL.trim(),
    );
    secureBrowserLaunching = false;
    if (error) {
      addNotification('error', `Secure browser launch failed: ${error}`);
      return;
    }
    if (result) {
      addNotification('success',
        `Launched ${result.family} (${result.mode}) with ${result.cert_count} certificate${result.cert_count !== 1 ? 's' : ''}`);
    }
  }

  async function loadBrowserConfig(): Promise<void> {
    browserLoading = true;
    const config = await callBackend<BrowserConfig>('BrowserService', 'GetConfig');
    if (config) {
      // Normalize profile mode defaults for legacy configs missing these fields.
      browserConfig = {
        ...config,
        chrome_profile_mode: config.chrome_profile_mode || 'isolated',
        firefox_profile_mode: config.firefox_profile_mode || 'isolated',
      };
    }
    const browsers = await callBackend<BrowserInfo[]>('BrowserService', 'DetectBrowsers');
    if (browsers && browsers.length > 0) {
      detectedBrowsers = browsers;
    }
    browserLoading = false;
    browserConfigLoaded = true;
    loadBundleStatus();
    loadSecureBrowserData();
  }

  async function loadBundleStatus(): Promise<void> {
    bundleStatusLoading = true;
    const bundlePath = await callBackend<string>('BrowserService', 'GetTrustBundlePath');
    if (bundlePath) {
      const status = await callBackend<BrowserBundleStatus>('TrustService', 'GetBrowserBundleStatus', bundlePath);
      if (status) {
        bundleStatus = status;
      }
    }
    bundleStatusLoading = false;
  }

  let browserAutoSaveTimer: ReturnType<typeof setTimeout> | null = null;

  function browserAutoSave(): void {
    if (browserAutoSaveTimer) clearTimeout(browserAutoSaveTimer);
    browserAutoSaveTimer = setTimeout(doBrowserAutoSave, 300);
  }

  async function doBrowserAutoSave(): Promise<void> {
    if (!isWailsAvailable()) return;
    await callBackendVoid('BrowserService', 'SetConfig', browserConfig);
  }

  async function handleRegenerateTrustBundle(): Promise<void> {
    bundleRegenerating = true;
    const bundlePath = await callBackend<string>('BrowserService', 'GetTrustBundlePath');
    if (bundlePath) {
      const count = await callBackend<number>('TrustService', 'ExportBrowserTrustBundle', bundlePath);
      if (count !== null && count >= 0) {
        addNotification('success', `Trust bundle regenerated with ${count} certificate${count !== 1 ? 's' : ''}`);
        loadBundleStatus();
      } else {
        addNotification('error', 'Failed to regenerate trust bundle');
      }
    } else {
      addNotification('error', 'Trust bundle path not configured');
    }
    bundleRegenerating = false;
  }

  async function handleTestBrowser(): Promise<void> {
    const ok = await callBackendVoid('BrowserService', 'OpenURL', 'https://example.com');
    if (ok) {
      addNotification('info', 'Opening test URL in browser');
    } else {
      addNotification('error', 'Failed to launch browser');
    }
  }

  async function handleConnect(): Promise<void> {
    if (!serverAddress) {
      addNotification('error', 'Server address is required');
      return;
    }
    connecting = true;
    await connect(serverProtocol, serverAddress, serverTLSEnabled, serverTLSSkipVerify, serverTLSCAFile);
    connecting = false;
  }

  async function handleDisconnect(): Promise<void> {
    await disconnect();
    addNotification('info', 'Disconnected from server');
  }

  async function handleTestConnection(): Promise<void> {
    if (!serverAddress) {
      addNotification('error', 'Server address is required');
      return;
    }
    connecting = true;
    await connect(serverProtocol, serverAddress, serverTLSEnabled, serverTLSSkipVerify, serverTLSCAFile);
    connecting = false;
    if ($isServerConnected) {
      addNotification('success', 'Connection successful');
    }
  }
</script>

<div class="settings-view">
  <GradientHeader title="Settings" subtitle="Application configuration" />

  <div class="settings-layout">
    <!-- Category Sidebar -->
    <nav class="settings-nav">
      {#each categories as cat}
        <button
          class="settings-nav-item"
          class:nav-active={activeCategory === cat.id}
          on:click={() => (activeCategory = cat.id)}
        >
          <Icon path={cat.icon} size={20} />
          <span class="text-label-large">{cat.label}</span>
        </button>
      {/each}
    </nav>

    <!-- Settings Panel -->
    <div class="settings-panel">
      {#if activeCategory === 'general'}
        <Card variant="elevated">
          <div class="settings-section">
            <h2 class="text-title-medium section-heading">General</h2>
            <div class="setting-row">
              <div class="setting-info">
                <span class="text-title-small">Start with system</span>
                <span class="text-body-small setting-desc">Launch xKey automatically when you log in</span>
              </div>
              <Toggle bind:checked={startWithSystem} on:change={autoSave} />
            </div>
            <div class="setting-row">
              <div class="setting-info">
                <span class="text-title-small">Start minimized</span>
                <span class="text-body-small setting-desc">Start in the system tray instead of showing the window</span>
              </div>
              <Toggle bind:checked={startMinimized} on:change={autoSave} />
            </div>
            <div class="setting-row">
              <div class="setting-info">
                <span class="text-title-small">Auto-connect to default device</span>
                <span class="text-body-small setting-desc">Automatically connect to the default phone on startup</span>
              </div>
              <Toggle bind:checked={autoConnect} on:change={autoSave} />
            </div>
            <div class="setting-row">
              <div class="setting-info">
                <span class="text-title-small">FIDO2 Virtual Authenticator</span>
                <span class="text-body-small setting-desc">Enable the virtual FIDO2/WebAuthn authenticator for passwordless authentication</span>
              </div>
              <Toggle bind:checked={fido2AuthenticatorEnabled} on:change={() => {
                if (isWailsAvailable()) {
                  callBackendVoid('AppService', 'ToggleFIDO2Authenticator', fido2AuthenticatorEnabled);
                }
                autoSave();
              }} data-testid="settings-fido2-toggle" />
            </div>
            <div class="setting-row">
              <div class="setting-info">
                <span class="text-title-small">Require touch (user presence)</span>
                <span class="text-body-small setting-desc">Require physical touch for FIDO2 operations. Matches the YubiKey experience where the device lights up and waits for touch.</span>
                {#if $isEnterpriseMode && $enterprisePolicy?.fido2_require_user_presence !== undefined}
                  <span class="text-label-small extension-enforced-badge">Enforced by organization policy</span>
                {/if}
              </div>
              <Toggle
                bind:checked={fido2RequireUserPresence}
                onChange={handleToggleFIDO2UserPresence}
                disabled={$isEnterpriseMode && $enterprisePolicy?.fido2_require_user_presence !== undefined}
              />
            </div>
            <div class="setting-row">
              <div class="setting-info">
                <span class="text-title-small">Multi-key intent check</span>
                <span class="text-body-small setting-desc">When multiple security keys are connected, show a confirmation before entering xKey's PIN flow. This lets you decline and use a different key (e.g. YubiKey).</span>
                {#if $isEnterpriseMode && $enterprisePolicy?.fido2_user_intent_check !== undefined}
                  <span class="text-label-small extension-enforced-badge">Enforced by organization policy</span>
                {/if}
              </div>
              <Toggle
                bind:checked={fido2UserIntentCheck}
                onChange={handleToggleFIDO2IntentCheck}
                disabled={$isEnterpriseMode && $enterprisePolicy?.fido2_user_intent_check !== undefined}
              />
            </div>
          </div>
        </Card>

      {:else if activeCategory === 'appearance'}
        <Card variant="elevated">
          <div class="settings-section">
            <h2 class="text-title-medium section-heading">Appearance</h2>
            <div class="setting-row">
              <div class="setting-info">
                <span class="text-title-small">Theme</span>
                <span class="text-body-small setting-desc">Choose between light, dark, or system theme</span>
              </div>
              <select class="form-select" value={currentTheme} on:change={handleThemeChange}>
                <option value="light">Light</option>
                <option value="dark">Dark</option>
                <option value="system">System</option>
              </select>
            </div>
            <div class="setting-row">
              <div class="setting-info">
                <span class="text-title-small">Font size</span>
                <span class="text-body-small setting-desc">Adjust the base font size ({fontSize}px)</span>
              </div>
              <input
                type="range"
                min="12"
                max="20"
                bind:value={fontSize}
                class="range-input"
              />
            </div>
          </div>
        </Card>

        <!-- Theme Preview -->
        <Card variant="outlined">
          <div class="theme-preview">
            <h3 class="text-title-small">Theme Preview</h3>
            <div class="preview-colors">
              <div class="preview-swatch" style="background: var(--gradient-primary);">
                <span>Primary</span>
              </div>
              <div class="preview-swatch" style="background: var(--color-secondary);">
                <span>Secondary</span>
              </div>
              <div class="preview-swatch" style="background: var(--color-tertiary);">
                <span>Tertiary</span>
              </div>
              <div class="preview-swatch" style="background: var(--color-surface-container); color: var(--color-on-surface);">
                <span>Surface</span>
              </div>
            </div>
          </div>
        </Card>

      {:else if activeCategory === 'api-explorer'}
        <Card variant="elevated">
          <div class="settings-section">
            <h2 class="text-title-medium section-heading">Security Settings</h2>
            <p class="text-body-small setting-desc" style="margin-bottom: 12px;">
              Configure the iframe sandbox policy for the API Explorer response preview.
              {#if sandboxPolicyLocked}
                <br /><em>(Set by organization policy)</em>
              {/if}
            </p>
            <div class="setting-row">
              <div class="setting-info">
                <span class="text-title-small">allow-same-origin</span>
                <span class="text-body-small setting-desc">Allow the preview to access same-origin resources</span>
              </div>
              <Toggle bind:checked={sandboxAllowSameOrigin} disabled={sandboxPolicyLocked} on:change={autoSave} />
            </div>
            <div class="setting-row">
              <div class="setting-info">
                <span class="text-title-small">allow-scripts</span>
                <span class="text-body-small setting-desc">Allow JavaScript execution in the preview</span>
              </div>
              <Toggle bind:checked={sandboxAllowScripts} disabled={sandboxPolicyLocked} on:change={autoSave} />
            </div>
            <div class="setting-row">
              <div class="setting-info">
                <span class="text-title-small">allow-forms</span>
                <span class="text-body-small setting-desc">Allow form submissions in the preview</span>
              </div>
              <Toggle bind:checked={sandboxAllowForms} disabled={sandboxPolicyLocked} on:change={autoSave} />
            </div>
            <div class="setting-row">
              <div class="setting-info">
                <span class="text-title-small">allow-popups</span>
                <span class="text-body-small setting-desc">Allow opening popup windows from the preview</span>
              </div>
              <Toggle bind:checked={sandboxAllowPopups} disabled={sandboxPolicyLocked} on:change={autoSave} />
            </div>
          </div>
        </Card>

        {#if $isEnterpriseMode}
          <Card variant="outlined" style="margin-top: 16px;">
            <div class="settings-section">
              <h2 class="text-title-medium section-heading">Enterprise Status</h2>
              <div class="setting-row">
                <div class="setting-info">
                  <span class="text-title-small">API Explorer Enabled</span>
                  <span class="text-body-small setting-desc">
                    {#if $enterprisePolicy?.api_explorer_enabled === false}
                      API Explorer is disabled by organization policy
                    {:else}
                      API Explorer is enabled
                    {/if}
                  </span>
                </div>
                <StatusBadge
                  status={$enterprisePolicy?.api_explorer_enabled === false ? 'error' : 'success'}
                  text={$enterprisePolicy?.api_explorer_enabled === false ? 'Disabled' : 'Enabled'}
                />
              </div>
            </div>
          </Card>
        {/if}

      {:else if activeCategory === 'server'}
        <Card variant="elevated">
          <div class="settings-section">
            <h2 class="text-title-medium section-heading">Server Connection</h2>
            <div class="setting-row">
              <div class="setting-info">
                <span class="text-title-small">Protocol</span>
                <span class="text-body-small setting-desc">Transport protocol for the xkmsd server</span>
              </div>
              <select class="form-select" bind:value={serverProtocol} on:change={autoSave}>
                <option value="grpc">gRPC</option>
                <option value="rest">REST</option>
                <option value="unix">Unix Socket</option>
                <option value="quic">QUIC</option>
                <option value="mcp">MCP</option>
              </select>
            </div>
            <div class="setting-row">
              <div class="setting-info">
                <span class="text-title-small">Address</span>
                <span class="text-body-small setting-desc">Server address (e.g., localhost:9443)</span>
              </div>
              <div class="compact-input">
                <Input placeholder="localhost:9443" bind:value={serverAddress} monospace on:blur={autoSave} />
              </div>
            </div>
            <div class="setting-row">
              <div class="setting-info">
                <span class="text-title-small">TLS</span>
                <span class="text-body-small setting-desc">Enable TLS encryption for the server connection</span>
              </div>
              <Toggle bind:checked={serverTLSEnabled} on:change={autoSave} />
            </div>
            {#if serverTLSEnabled}
              <div class="setting-row">
                <div class="setting-info">
                  <span class="text-title-small">Skip TLS verification</span>
                  <span class="text-body-small setting-desc setting-warn">Insecure: skip server certificate verification</span>
                </div>
                <Toggle bind:checked={serverTLSSkipVerify} on:change={autoSave} />
              </div>
              <div class="setting-row">
                <div class="setting-info">
                  <span class="text-title-small">CA certificate file</span>
                  <span class="text-body-small setting-desc">Path to custom CA certificate for TLS verification</span>
                </div>
                <div class="compact-input">
                  <Input placeholder="/path/to/ca.crt" bind:value={serverTLSCAFile} monospace on:blur={autoSave} />
                </div>
              </div>
            {/if}
            <div class="setting-row">
              <div class="setting-info">
                <span class="text-title-small">Auto-connect</span>
                <span class="text-body-small setting-desc">Automatically connect to server on startup</span>
              </div>
              <Toggle bind:checked={serverAutoConnect} on:change={autoSave} />
            </div>
          </div>
        </Card>

        <Card variant="outlined">
          <div class="settings-section">
            <h2 class="text-title-medium section-heading">Connection Status</h2>
            <div class="server-status-row">
              <StatusBadge status={$isServerConnected ? 'connected' : 'disconnected'} />
              <span class="text-body-medium">{$isServerConnected ? `Connected to ${serverAddress}` : 'Not connected'}</span>
            </div>
            <div class="server-actions-row">
              {#if $isServerConnected}
                <Button variant="outline" icon={mdiLanConnect} on:click={handleDisconnect}>
                  Disconnect
                </Button>
              {:else}
                <Button variant="primary" icon={mdiLanConnect} on:click={handleTestConnection} disabled={connecting || !serverAddress}>
                  {connecting ? 'Connecting...' : 'Test Connection'}
                </Button>
              {/if}
            </div>
          </div>
        </Card>

      {:else if activeCategory === 'phone'}
        <Card variant="elevated">
          <div class="settings-section">
            <h2 class="text-title-medium section-heading">Phone Settings</h2>
            <div class="setting-row">
              <div class="setting-info">
                <span class="text-title-small">Default device</span>
                <span class="text-body-small setting-desc">Device used for operations when no device is specified</span>
              </div>
              <select class="form-select" bind:value={defaultDevice}>
                <option value="">Auto-detect</option>
                <option value="pixel8">John's Pixel 8</option>
                <option value="galaxy">Work Galaxy S24</option>
              </select>
            </div>
            <div class="setting-row">
              <div class="setting-info">
                <span class="text-title-small">Attestation policy</span>
                <span class="text-body-small setting-desc">When to require hardware attestation from the phone</span>
              </div>
              <select class="form-select" bind:value={attestationPolicy}>
                <option value="always">Always</option>
                <option value="periodic">Periodic</option>
                <option value="manual">Manual only</option>
              </select>
            </div>
            <div class="setting-row">
              <div class="setting-info">
                <span class="text-title-small">Grace period</span>
                <span class="text-body-small setting-desc">Hours between automatic attestation checks</span>
              </div>
              <div class="inline-input">
                <input type="number" class="number-input" bind:value={gracePeriod} min="1" max="168" />
                <span class="text-body-small">hours</span>
              </div>
            </div>
          </div>
        </Card>

      {:else if activeCategory === 'security'}
        <Card variant="elevated">
          <div class="settings-section">
            <h2 class="text-title-medium section-heading">Security</h2>
            <div class="setting-row">
              <div class="setting-info">
                <span class="text-title-small">Lock timeout</span>
                <span class="text-body-small setting-desc">Lock the application after this many minutes of inactivity. 0 to disable.</span>
              </div>
              <div class="inline-input">
                <input type="number" class="number-input" bind:value={lockTimeout} min="0" max="60" on:blur={autoSave} />
                <span class="text-body-small">minutes</span>
              </div>
            </div>
            <div class="setting-row">
              <div class="setting-info">
                <span class="text-title-small">Lock on screen lock</span>
                <span class="text-body-small setting-desc">Automatically lock the app when the OS screen lock activates</span>
              </div>
              <Toggle bind:checked={lockOnScreenLock} on:change={autoSave} />
            </div>
            <div class="setting-row">
              <div class="setting-info">
                <span class="text-title-small">Auto-Unseal on Startup</span>
                <span class="text-body-small setting-desc">When enabled, the app automatically unseals using the TPM on startup without requiring a PIN. When disabled, you must enter your User PIN each time.</span>
              </div>
              <Toggle bind:checked={barrierAutoUnsealEnabled} on:change={() => handleBarrierAutoUnsealToggle(barrierAutoUnsealEnabled)} />
            </div>
            <div class="setting-row">
              <div class="setting-info">
                <span class="text-title-small">Require authentication for sensitive operations</span>
                <span class="text-body-small setting-desc">Require PIN/password for key operations, deletions, and settings changes</span>
              </div>
              <Toggle bind:checked={requireAuth} onChange={(val) => {
                if (!val) guardSecurityToggle('requireAuth');
                else autoSave();
              }} />
            </div>
          </div>
        </Card>

        <!-- Clipboard -->
        <Card variant="outlined">
          <div class="settings-section">
            <h2 class="text-title-medium section-heading">Clipboard</h2>
            <div class="setting-row">
              <div class="setting-info">
                <span class="text-title-small">Clear timeout</span>
                <span class="text-body-small setting-desc">Automatically clear copied secrets from the clipboard after this many seconds. 0 to disable.</span>
              </div>
              <div class="inline-input">
                <input type="number" class="number-input" bind:value={clipboardTimeout} min="0" max="300" on:blur={autoSave} />
                <span class="text-body-small">seconds</span>
              </div>
            </div>
          </div>
        </Card>



      {:else if activeCategory === 'pin'}
        <!-- PIN Strategy -->
        <Card variant="elevated">
          <div class="settings-section">
            <h2 class="text-title-medium section-heading">PIN Management</h2>

            {#if pinLoading}
              <div class="storage-loading">
                <LoadingSpinner size={32} />
                <span class="text-body-medium">Loading PIN status...</span>
              </div>
            {:else if pinStatus}
              <div class="setting-row">
                <div class="setting-info">
                  <span class="text-title-small">Strategy</span>
                  <span class="text-body-small setting-desc">PIN management is handled by the {formatPINStrategy(pinStatus.strategy)} backend</span>
                </div>
                <span class="pin-strategy-badge">{formatPINStrategy(pinStatus.strategy)}</span>
              </div>
            {:else}
              <p class="text-body-medium storage-empty-msg">Unable to load PIN status.</p>
              <Button variant="outline" on:click={loadPINStatus}>Retry</Button>
            {/if}
          </div>
        </Card>

        <!-- SO PIN Card -->
        {#if pinStatus}
          <Card variant="outlined">
            <div class="settings-section">
              <h2 class="text-title-medium section-heading">Security Officer PIN</h2>
              <div class="setting-row">
                <div class="setting-info">
                  <span class="text-title-small">Status</span>
                  <span class="text-body-small setting-desc">
                    {pinStatus.so_pin_set ? 'SO PIN is configured' : 'SO PIN has not been set'}
                  </span>
                </div>
                <div class="pin-check-indicator">
                  {#if pinStatus.so_pin_set}
                    <Icon path={mdiCheck} size={18} color="var(--color-security-verified)" />
                    <span class="text-label-small" style="color: var(--color-security-verified);">Set</span>
                  {:else}
                    <Icon path={mdiClose} size={18} color="var(--color-on-surface-variant)" />
                    <span class="text-label-small" style="color: var(--color-on-surface-variant);">Not Set</span>
                  {/if}
                </div>
              </div>
              <div class="storage-actions">
                {#if pinStatus.so_pin_set}
                  <div class="storage-action-row">
                    <div class="setting-info">
                      <span class="text-title-small">Change SO PIN</span>
                      <span class="text-body-small setting-desc">Update the Security Officer PIN</span>
                    </div>
                    <Button variant="outline" icon={mdiFormTextboxPassword} on:click={() => openPINDialog('change-so')}>
                      Change
                    </Button>
                  </div>
                {:else}
                  <div class="storage-action-row">
                    <div class="setting-info">
                      <span class="text-title-small">Set SO PIN</span>
                      <span class="text-body-small setting-desc">Configure the Security Officer PIN for administrative operations</span>
                    </div>
                    <Button variant="primary" icon={mdiFormTextboxPassword} on:click={() => openPINDialog('set-so')}>
                      Set SO PIN
                    </Button>
                  </div>
                {/if}
              </div>
            </div>
          </Card>

          <!-- User PIN Card -->
          <Card variant="outlined">
            <div class="settings-section">
              <h2 class="text-title-medium section-heading">User PIN</h2>
              <div class="setting-row">
                <div class="setting-info">
                  <span class="text-title-small">Status</span>
                  <span class="text-body-small setting-desc">
                    {pinStatus.user_pin_set ? 'User PIN is configured' : 'User PIN has not been set'}
                  </span>
                </div>
                <div class="pin-check-indicator">
                  {#if pinStatus.user_pin_set}
                    <Icon path={mdiCheck} size={18} color="var(--color-security-verified)" />
                    <span class="text-label-small" style="color: var(--color-security-verified);">Set</span>
                  {:else}
                    <Icon path={mdiClose} size={18} color="var(--color-on-surface-variant)" />
                    <span class="text-label-small" style="color: var(--color-on-surface-variant);">Not Set</span>
                  {/if}
                </div>
              </div>
              <div class="storage-actions">
                {#if pinStatus.user_pin_set}
                  {#if !$isEnterpriseMode || $enterprisePolicy?.user_can_change_own_pin !== false}
                    <div class="storage-action-row">
                      <div class="setting-info">
                        <span class="text-title-small">Change User PIN</span>
                        <span class="text-body-small setting-desc">Update the User PIN for everyday operations</span>
                      </div>
                      <Button variant="outline" icon={mdiFormTextboxPassword} on:click={() => openPINDialog('change-user')}>
                        Change
                      </Button>
                    </div>
                  {:else}
                    <div class="storage-action-row">
                      <div class="setting-info">
                        <span class="text-title-small">Change User PIN</span>
                        <span class="text-body-small setting-desc">User PIN changes are disabled by organization policy. Contact your administrator.</span>
                      </div>
                    </div>
                  {/if}
                {:else}
                  <div class="storage-action-row">
                    <div class="setting-info">
                      <span class="text-title-small">Set User PIN</span>
                      <span class="text-body-small setting-desc">
                        Configure the User PIN for cryptographic operations
                        {#if !pinStatus.so_pin_set}
                          (requires SO PIN to be set first)
                        {/if}
                      </span>
                    </div>
                    <Button variant="primary" icon={mdiFormTextboxPassword} on:click={() => openPINDialog('set-user')} disabled={!pinStatus.so_pin_set}>
                      Set User PIN
                    </Button>
                  </div>
                {/if}
              </div>
            </div>
          </Card>

          <!-- Lockout Status Card -->
          <Card variant="outlined">
            <div class="settings-section">
              <h2 class="text-title-medium section-heading">Lockout Status</h2>

              {#if lockoutLoading}
                <div class="storage-loading">
                  <LoadingSpinner size={32} />
                  <span class="text-body-medium">Loading lockout status...</span>
                </div>
              {:else if lockoutStatusData}
                <div class="lockout-status-grid">
                  <div class="storage-status-item">
                    <span class="text-label-small field-label">Failed Attempts</span>
                    <span class="text-body-medium">
                      {lockoutStatusData.failed_attempts} / {lockoutStatusData.max_attempts}
                    </span>
                  </div>
                  <div class="storage-status-item">
                    <span class="text-label-small field-label">Lockout Status</span>
                    {#if lockoutStatusData.is_locked}
                      <StatusBadge status="error" />
                    {:else}
                      <StatusBadge status="verified" />
                    {/if}
                  </div>
                  {#if lockoutStatusData.is_locked && lockoutStatusData.recovery_seconds > 0}
                    <div class="storage-status-item">
                      <span class="text-label-small field-label">Recovery Time</span>
                      <span class="text-body-medium lockout-recovery-time">
                        {Math.ceil(lockoutStatusData.recovery_seconds / 60)} minutes remaining
                      </span>
                    </div>
                  {/if}
                </div>

                {#if lockoutStatusData.is_locked}
                  <div class="lockout-alert" role="alert">
                    <Icon path={mdiLockAlert} size={20} color="var(--color-security-danger)" />
                    <span class="text-body-small">
                      PIN entry is locked due to too many failed attempts.
                      {#if lockoutStatusData.recovery_seconds > 0}
                        Recovery in {Math.ceil(lockoutStatusData.recovery_seconds / 60)} minutes,
                        or use the SO PIN to reset immediately.
                      {/if}
                    </span>
                  </div>
                {/if}

                <div class="setting-row">
                  <div class="setting-info">
                    <span class="text-title-small">Maximum Failed Attempts</span>
                    <span class="text-body-small setting-desc">
                      {#if $isEnterpriseMode && $enterprisePolicy?.pin_max_attempts > 0}
                        Locked by organization policy
                      {:else}
                        Number of failed PIN attempts before lockout
                      {/if}
                    </span>
                  </div>
                  <input
                    type="number"
                    class="number-input"
                    min="1"
                    max="20"
                    value={lockoutStatusData.max_attempts}
                    disabled={$isEnterpriseMode && $enterprisePolicy?.pin_max_attempts > 0}
                    on:change={async (e) => {
                      const val = parseInt(e.currentTarget.value) || 5;
                      const clamped = Math.max(1, Math.min(20, val));
                      e.currentTarget.value = String(clamped);
                      const result = await callBackendVoidWithError('PINService', 'SetPINMaxAttempts', clamped);
                      if (result.error) {
                        console.error('Failed to set max attempts:', result.error);
                      } else {
                        loadLockoutStatus();
                      }
                    }}
                  />
                </div>

                <div class="storage-actions">
                  <div class="storage-action-row">
                    <div class="setting-info">
                      <span class="text-title-small">Reset Lockout</span>
                      <span class="text-body-small setting-desc">
                        Reset the failed attempts counter using the SO PIN
                      </span>
                    </div>
                    <Button
                      variant="outline"
                      icon={mdiLockReset}
                      on:click={() => { resetLockoutSOPIN = ''; showResetLockoutConfirm = true; }}
                      disabled={!lockoutStatusData.is_locked && lockoutStatusData.failed_attempts === 0}
                    >
                      Reset
                    </Button>
                  </div>
                </div>
              {:else}
                <p class="text-body-medium storage-empty-msg">Unable to load lockout status.</p>
                <Button variant="outline" on:click={loadLockoutStatus}>Retry</Button>
              {/if}
            </div>
          </Card>
        {/if}

      {:else if activeCategory === 'storage'}
        <!-- Volume Status Card -->
        <Card variant="elevated">
          <div class="settings-section">
            <h2 class="text-title-medium section-heading">LUKS Encrypted Storage</h2>

            {#if storageLoading}
              <div class="storage-loading">
                <LoadingSpinner size={32} />
                <span class="text-body-medium">Loading storage status...</span>
              </div>
            {:else if storageStatus}
              <div class="storage-status-grid">
                <div class="storage-status-item">
                  <span class="text-label-small field-label">Volume</span>
                  <span class="text-body-medium">
                    {storageStatus.volume_exists ? 'Exists' : 'Not created'}
                  </span>
                </div>
                <div class="storage-status-item">
                  <span class="text-label-small field-label">Encryption</span>
                  <span class="text-body-medium">
                    {storageStatus.is_luks ? 'LUKS encrypted' : 'Not encrypted'}
                  </span>
                </div>
                <div class="storage-status-item">
                  <span class="text-label-small field-label">State</span>
                  <StatusBadge status={storageStatus.is_mounted ? 'connected' : storageStatus.is_open ? 'warning' : 'disconnected'} />
                </div>
                {#if storageStatus.volume_path}
                  <div class="storage-status-item">
                    <span class="text-label-small field-label">Volume Path</span>
                    <span class="text-body-small font-mono">{storageStatus.volume_path}</span>
                  </div>
                {/if}
                {#if storageStatus.mount_point}
                  <div class="storage-status-item">
                    <span class="text-label-small field-label">Mount Point</span>
                    <span class="text-body-small font-mono">{storageStatus.mount_point}</span>
                  </div>
                {/if}
                {#if storageStatus.volume_size_bytes > 0}
                  <div class="storage-status-item">
                    <span class="text-label-small field-label">Size</span>
                    <span class="text-body-medium">{formatBytes(storageStatus.volume_size_bytes)}</span>
                  </div>
                {/if}
              </div>

              <!-- Elevation Info Notice -->
              {#if !storageStatus.elevation_available}
                <div class="root-warning" role="alert">
                  <Icon path={mdiShieldAlert} size={20} color="var(--color-security-warning)" />
                  <span class="text-body-small">
                    Privilege elevation is not available. Install PolicyKit (pkexec) or sudo to enable LUKS storage operations.
                  </span>
                </div>
              {/if}
            {:else}
              <p class="text-body-medium storage-empty-msg">
                Unable to retrieve storage status. Make sure the backend is running.
              </p>
              <Button variant="outline" on:click={loadStorageStatus}>
                Retry
              </Button>
            {/if}
          </div>
        </Card>

        <!-- Storage Actions -->
        {#if storageStatus}
          <Card variant="outlined">
            <div class="settings-section">
              <h2 class="text-title-medium section-heading">Actions</h2>
              <div class="storage-actions">
                {#if !storageStatus.volume_exists}
                  <div class="storage-action-row">
                    <div class="setting-info">
                      <span class="text-title-small">Create Encrypted Volume</span>
                      <span class="text-body-small setting-desc">Create a LUKS-encrypted volume and migrate existing data from ~/.xkey/data/ into it</span>
                    </div>
                    <Button variant="primary" icon={mdiPlus} on:click={() => (showMigrateDialog = true)} disabled={!storageStatus.elevation_available}>
                      Create & Migrate
                    </Button>
                  </div>
                {:else}
                  <!-- Unlock / Lock toggle -->
                  <div class="storage-action-row">
                    <div class="setting-info">
                      <span class="text-title-small">
                        {storageStatus.is_mounted || storageStatus.is_open ? 'Lock Volume' : 'Unlock Volume'}
                      </span>
                      <span class="text-body-small setting-desc">
                        {storageStatus.is_mounted || storageStatus.is_open
                          ? 'Unmount and close the encrypted volume'
                          : 'Open and mount the encrypted volume'}
                      </span>
                    </div>
                    {#if storageStatus.is_mounted || storageStatus.is_open}
                      <Button variant="outline" icon={mdiDatabaseLock} loading={storageLocking} on:click={handleLockVolume} disabled={!storageStatus.elevation_available}>
                        Lock
                      </Button>
                    {:else}
                      <Button variant="primary" icon={mdiLockOpen} on:click={() => { storageUnlockPassphrase = ''; showUnlockDialog = true; }} disabled={!storageStatus.elevation_available}>
                        Unlock
                      </Button>
                    {/if}
                  </div>
                {/if}

                <!-- Wipe Volume -->
                {#if storageStatus.volume_exists && !storageStatus.is_mounted && !storageStatus.is_open}
                  <div class="storage-action-row">
                    <div class="setting-info">
                      <span class="text-title-small">Wipe Volume</span>
                      <span class="text-body-small setting-desc setting-warn">Securely erase the encrypted volume and all data within it</span>
                    </div>
                    <Button variant="danger" icon={mdiDeleteSweep} on:click={() => (showWipeConfirm = true)} disabled={!storageStatus.elevation_available}>
                      Wipe
                    </Button>
                  </div>
                {/if}
              </div>
            </div>
          </Card>
        {/if}

        <!-- Auto-Unseal with TPM -->
        <Card variant="outlined">
          <div class="settings-section">
            <h2 class="text-title-medium section-heading">Auto-Unseal with TPM</h2>

            {#if autoUnsealLoading}
              <div class="storage-loading">
                <LoadingSpinner size={32} />
                <span class="text-body-medium">Loading auto-unseal status...</span>
              </div>
            {:else if autoUnsealStatus}
              <div class="setting-row">
                <div class="setting-info">
                  <span class="text-title-small">TPM Available</span>
                  <span class="text-body-small setting-desc">
                    {autoUnsealStatus.available ? 'TPM detected on this system' : 'No TPM detected'}
                  </span>
                </div>
                <StatusBadge status={autoUnsealStatus.available ? 'connected' : 'disconnected'} />
              </div>

              {#if !autoUnsealStatus.available}
                <div class="auto-unseal-info" role="status">
                  <Icon path={mdiChip} size={20} color="var(--color-on-surface-variant)" />
                  <span class="text-body-small">
                    A Trusted Platform Module (TPM) is required for auto-unseal. Ensure your system has a TPM 2.0 device available.
                  </span>
                </div>
              {:else if !autoUnsealStatus.configured}
                <div class="storage-actions">
                  <div class="storage-action-row">
                    <div class="setting-info">
                      <span class="text-title-small">Enable Auto-Unseal</span>
                      <span class="text-body-small setting-desc">
                        {#if !storageStatus?.volume_exists}
                          Create an encrypted LUKS volume first before enabling auto-unseal
                        {:else}
                          Seal your LUKS passphrase to the TPM so the volume unlocks automatically on startup
                        {/if}
                      </span>
                    </div>
                    <Button
                      variant="primary"
                      icon={mdiShieldLockOutline}
                      disabled={!storageStatus?.volume_exists}
                      on:click={() => {
                        autoUnsealPassphrase = '';
                        autoUnsealConfirmPassphrase = '';
                        showAutoUnsealEnableDialog = true;
                      }}
                    >
                      Enable
                    </Button>
                  </div>
                </div>
              {:else}
                <div class="setting-row">
                  <div class="setting-info">
                    <span class="text-title-small">Status</span>
                    <span class="text-body-small setting-desc">Auto-unseal is active for this volume</span>
                  </div>
                  <StatusBadge status="verified" />
                </div>

                {#if autoUnsealStatus.blob_id}
                  <div class="setting-row">
                    <div class="setting-info">
                      <span class="text-title-small">Sealed Blob ID</span>
                      <span class="text-body-small font-mono setting-desc">{autoUnsealStatus.blob_id}</span>
                    </div>
                  </div>
                {/if}

                <div class="storage-actions">
                  <div class="storage-action-row">
                    <div class="setting-info">
                      <span class="text-title-small">Disable Auto-Unseal</span>
                      <span class="text-body-small setting-desc setting-warn">
                        Remove the TPM-sealed passphrase and require manual unlock
                      </span>
                    </div>
                    <Button
                      variant="danger"
                      loading={autoUnsealDisabling}
                      on:click={() => (showAutoUnsealDisableConfirm = true)}
                    >
                      Disable
                    </Button>
                  </div>
                </div>
              {/if}
            {:else}
              <p class="text-body-medium storage-empty-msg">Unable to load auto-unseal status.</p>
              <Button variant="outline" on:click={loadAutoUnsealStatus}>Retry</Button>
            {/if}
          </div>
        </Card>

        <!-- Barrier Auto-Unseal -->
        <Card variant="outlined">
          <div class="settings-section">
            <h2 class="text-title-medium section-heading">Barrier Auto-Unseal</h2>

            {#if barrierAutoUnsealLoading}
              <div class="storage-loading">
                <LoadingSpinner size={32} />
                <span class="text-body-medium">Loading barrier auto-unseal status...</span>
              </div>
            {:else if barrierAutoUnsealStatus}
              <div class="setting-row">
                <div class="setting-info">
                  <span class="text-title-small">TPM Available</span>
                  <span class="text-body-small setting-desc">
                    {barrierAutoUnsealStatus.tpm_available ? 'TPM detected on this system' : 'No TPM detected'}
                  </span>
                </div>
                <StatusBadge status={barrierAutoUnsealStatus.tpm_available ? 'connected' : 'disconnected'} />
              </div>

              {#if !barrierAutoUnsealStatus.tpm_available}
                <div class="auto-unseal-info" role="status">
                  <Icon path={mdiChip} size={20} color="var(--color-on-surface-variant)" />
                  <span class="text-body-small">
                    A Trusted Platform Module (TPM) is required for barrier auto-unseal. Ensure your system has a TPM 2.0 device available.
                  </span>
                </div>
              {:else if !barrierAutoUnsealStatus.policy_configured}
                <div class="setting-row">
                  <div class="setting-info">
                    <span class="text-title-small">Policy</span>
                    <span class="text-body-small setting-desc">No auto-unseal PCR policy configured</span>
                  </div>
                  <StatusBadge status="warning" />
                </div>

                {#if barrierAutoUnsealPolicies.length === 0}
                  <div class="auto-unseal-info" role="status">
                    <Icon path={mdiShieldLockOutline} size={20} color="var(--color-on-surface-variant)" />
                    <span class="text-body-small">
                      No PCR policies found. Create a PCR policy in the TPM section before configuring barrier auto-unseal.
                    </span>
                  </div>
                {:else}
                  <div class="storage-actions">
                    <div class="storage-action-row">
                      <div class="setting-info">
                        <span class="text-title-small">Enable Barrier Auto-Unseal</span>
                        <span class="text-body-small setting-desc">
                          Select a PCR policy to automatically unseal the barrier when platform state matches
                        </span>
                      </div>
                    </div>
                    <div class="storage-action-row">
                      <select
                        class="form-select"
                        bind:value={barrierAutoUnsealSelectedPolicy}
                      >
                        <option value="">-- Select a PCR policy --</option>
                        {#each barrierAutoUnsealPolicies as policy}
                          <option value={policy.name}>{policy.name}</option>
                        {/each}
                      </select>
                      <Button
                        variant="primary"
                        icon={mdiShieldLockOutline}
                        loading={barrierAutoUnsealSetting}
                        disabled={!barrierAutoUnsealSelectedPolicy}
                        on:click={handleSetBarrierAutoUnsealPolicy}
                      >
                        Enable
                      </Button>
                    </div>
                  </div>
                {/if}
              {:else}
                <div class="setting-row">
                  <div class="setting-info">
                    <span class="text-title-small">Active Policy</span>
                    <span class="text-body-small font-mono setting-desc">{barrierAutoUnsealStatus.policy_name}</span>
                  </div>
                  <StatusBadge status="verified" />
                </div>

                <div class="setting-row">
                  <div class="setting-info">
                    <span class="text-title-small">PCR State</span>
                    <span class="text-body-small setting-desc">
                      {barrierAutoUnsealStatus.pcrs_match
                        ? 'Current platform PCR values match the policy'
                        : 'PCR values do not match — auto-unseal will not activate'}
                    </span>
                  </div>
                  <StatusBadge status={barrierAutoUnsealStatus.pcrs_match ? 'verified' : 'warning'} />
                </div>

                {#if barrierAutoUnsealPolicies.length > 0}
                  <div class="storage-actions">
                    <div class="storage-action-row">
                      <div class="setting-info">
                        <span class="text-title-small">Change Policy</span>
                        <span class="text-body-small setting-desc">Switch to a different PCR policy for auto-unseal</span>
                      </div>
                    </div>
                    <div class="storage-action-row">
                      <select
                        class="form-select"
                        bind:value={barrierAutoUnsealSelectedPolicy}
                      >
                        {#each barrierAutoUnsealPolicies as policy}
                          <option value={policy.name}>{policy.name}</option>
                        {/each}
                      </select>
                      <Button
                        variant="outline"
                        icon={mdiRefresh}
                        loading={barrierAutoUnsealSetting}
                        disabled={!barrierAutoUnsealSelectedPolicy || barrierAutoUnsealSelectedPolicy === barrierAutoUnsealStatus.policy_name}
                        on:click={handleSetBarrierAutoUnsealPolicy}
                      >
                        Apply
                      </Button>
                    </div>
                  </div>
                {/if}

                <div class="storage-actions">
                  <div class="storage-action-row">
                    <div class="setting-info">
                      <span class="text-title-small">Disable Barrier Auto-Unseal</span>
                      <span class="text-body-small setting-desc setting-warn">
                        Remove the PCR policy binding — the barrier will require a PIN on next startup
                      </span>
                    </div>
                    <Button
                      variant="danger"
                      loading={barrierAutoUnsealClearing}
                      on:click={handleClearBarrierAutoUnsealPolicy}
                    >
                      Disable
                    </Button>
                  </div>
                </div>
              {/if}
            {:else}
              <p class="text-body-medium storage-empty-msg">Unable to load barrier auto-unseal status.</p>
              <Button variant="outline" on:click={loadBarrierAutoUnsealStatus}>Retry</Button>
            {/if}
          </div>
        </Card>

      {:else if activeCategory === 'notifications'}
        <Card variant="elevated">
          <div class="settings-section">
            <h2 class="text-title-medium section-heading">Desktop Notifications</h2>
            <div class="setting-row">
              <div class="setting-info">
                <span class="text-title-small">Enable desktop notifications</span>
                <span class="text-body-small setting-desc">Send system notifications for FIDO2 touch prompts and important events</span>
              </div>
              <Toggle bind:checked={desktopNotifications} on:change={() => {
                if (isWailsAvailable()) {
                  callBackend('NotificationService', 'SetEnabled', desktopNotifications);
                }
                autoSave();
              }} />
            </div>
            <div class="setting-row">
              <div class="setting-info">
                <span class="text-title-small">Test notification</span>
                <span class="text-body-small setting-desc">Send a test desktop notification to verify delivery</span>
              </div>
              <Button variant="outline" icon={mdiTestTube} loading={testingNotification} on:click={async () => {
                testingNotification = true;
                const result = await callBackend('NotificationService', 'SendNotification', { title: 'xKey Test', message: 'Desktop notifications are working!' });
                testingNotification = false;
                if (result !== null) {
                  addNotification('success', 'Test notification sent');
                } else {
                  addNotification('error', 'Failed to send test notification');
                }
              }}>
                Send Test
              </Button>
            </div>
          </div>
        </Card>

        <Card variant="elevated">
          <div class="settings-section">
            <h2 class="text-title-medium section-heading">Event Notifications</h2>
            <div class="setting-row">
              <div class="setting-info">
                <span class="text-title-small">Device connection events</span>
                <span class="text-body-small setting-desc">Notify when a phone connects or disconnects</span>
              </div>
              <Toggle bind:checked={notifyOnConnect} on:change={autoSave} />
            </div>
            <div class="setting-row">
              <div class="setting-info">
                <span class="text-title-small">Authentication events</span>
                <span class="text-body-small setting-desc">Notify on WebAuthn authentication attempts</span>
              </div>
              <Toggle bind:checked={notifyOnAuth} on:change={autoSave} />
            </div>
            <div class="setting-row">
              <div class="setting-info">
                <span class="text-title-small">Error events</span>
                <span class="text-body-small setting-desc">Notify on errors and failures</span>
              </div>
              <Toggle bind:checked={notifyOnError} on:change={autoSave} />
            </div>
          </div>
        </Card>

      {:else if activeCategory === 'browser'}
        <div data-testid="browser-settings-panel">
          <Card variant="elevated">
            <div class="settings-section">
              <h2 class="text-title-medium section-heading">Browser</h2>

              {#if browserLoading}
                <div class="storage-loading">
                  <LoadingSpinner size={32} />
                  <span class="text-body-medium">Loading browser settings...</span>
                </div>
              {:else}
                <div class="setting-row">
                  <div class="setting-info">
                    <span class="text-title-small">Default browser</span>
                    <span class="text-body-small setting-desc">Select the browser to use for opening external links</span>
                  </div>
                  <select
                    class="form-select"
                    bind:value={browserConfig.default_browser}
                    data-testid="browser-select"
                    on:change={browserAutoSave}
                  >
                    {#each detectedBrowsers as browser}
                      <option value={browser.path}>{browser.name}</option>
                    {/each}
                  </select>
                </div>
                <div class="setting-row">
                  <div class="setting-info">
                    <span class="text-title-small">Custom command</span>
                    <span class="text-body-small setting-desc">Custom command to open URLs. Use {'{url}'} as placeholder for the URL.</span>
                  </div>
                  <div class="compact-input">
                    <input
                      type="text"
                      class="custom-command-input"
                      placeholder="firefox --new-tab {'{url}'}"
                      bind:value={browserConfig.custom_command}
                      data-testid="custom-command-input"
                      on:blur={browserAutoSave}
                    />
                  </div>
                </div>
              {/if}
            </div>
          </Card>

          <!-- CA Trust Bundle -->
          <Card variant="outlined">
            <div class="settings-section">
              <h2 class="text-title-medium section-heading">
                <span class="section-heading-with-icon">
                  <Icon path={mdiCertificate} size={20} />
                  CA Trust Bundle
                </span>
              </h2>

              <div class="setting-row">
                <div class="setting-info">
                  <span class="text-title-small">Include CA trust bundle</span>
                  <span class="text-body-small setting-desc">
                    Inject your private CA certificates into the browser via SSL_CERT_FILE
                    so it trusts websites signed by your private CAs
                  </span>
                </div>
                <Toggle
                  bind:checked={browserConfig.include_trust_bundle}
                  data-testid="trust-bundle-toggle"
                  on:change={browserAutoSave}
                />
              </div>

              {#if browserConfig.include_trust_bundle}
                {#if bundleStatusLoading}
                  <div class="storage-loading">
                    <LoadingSpinner size={24} />
                    <span class="text-body-small">Checking bundle status...</span>
                  </div>
                {:else if bundleStatus}
                  <div class="bundle-status-grid">
                    <div class="storage-status-item">
                      <span class="text-label-small field-label">Status</span>
                      <div class="bundle-status-indicator">
                        {#if !bundleStatus.exists}
                          <StatusBadge status="warning" />
                          <span class="text-body-small">Not generated</span>
                        {:else if bundleStatus.stale}
                          <StatusBadge status="warning" />
                          <span class="text-body-small">Stale - certificates have changed</span>
                        {:else}
                          <StatusBadge status="verified" />
                          <span class="text-body-small">Up to date</span>
                        {/if}
                      </div>
                    </div>
                    {#if bundleStatus.exists}
                      <div class="storage-status-item">
                        <span class="text-label-small field-label">Certificates</span>
                        <span class="text-body-medium">{bundleStatus.cert_count}</span>
                      </div>
                      <div class="storage-status-item">
                        <span class="text-label-small field-label">Last Generated</span>
                        <span class="text-body-small">
                          {new Date(bundleStatus.last_generated).toLocaleString()}
                        </span>
                      </div>
                    {/if}
                  </div>

                  {#if !bundleStatus.exists || bundleStatus.stale}
                    <div class="bundle-stale-hint">
                      <Icon path={mdiShieldAlert} size={18} color="var(--color-security-warning)" />
                      <span class="text-body-small">
                        {#if !bundleStatus.exists}
                          No trust bundle has been generated yet. Click Regenerate to create one from your
                          trust store certificates that have browser export enabled.
                        {:else}
                          Certificates have been added or removed from the trust store since the bundle
                          was last generated. Regenerate to update the browser trust bundle.
                        {/if}
                      </span>
                    </div>
                  {/if}
                {/if}

                <div class="storage-actions">
                  <div class="storage-action-row">
                    <div class="setting-info">
                      <span class="text-title-small">Regenerate trust bundle</span>
                      <span class="text-body-small setting-desc">
                        Rebuild the browser trust bundle from certificates in your trust store
                        that have browser export enabled
                      </span>
                    </div>
                    <Button
                      variant="outline"
                      icon={mdiRefresh}
                      loading={bundleRegenerating}
                      on:click={handleRegenerateTrustBundle}
                    >
                      Regenerate
                    </Button>
                  </div>
                </div>
              {/if}
            </div>
          </Card>

          <!-- Secure Browser Launch (CA injection via truststrap) -->
          <Card variant="outlined">
            <div class="settings-section" data-testid="secure-browser-card">
              <h2 class="text-title-medium section-heading">
                <span class="section-heading-with-icon">
                  <Icon path={mdiShieldCheck} size={20} />
                  Secure Browser Launch
                </span>
              </h2>

              <p class="text-body-small secure-browser-desc">
                Launch a browser with CA certificates from your trust store pre-injected via
                enterprise policy (Firefox) or NSS database (Chrome family). No manual import
                needed &mdash; certificates are synchronized automatically whenever the trust
                store changes.
              </p>

              {#if secureBrowsers.length === 0}
                <div class="bundle-stale-hint" data-testid="secure-browser-no-browsers">
                  <Icon path={mdiAlert} size={18} color="var(--color-security-warning)" />
                  <span class="text-body-small">
                    No Chrome or Firefox family browsers detected on this system.
                  </span>
                </div>
              {:else}
                <div class="setting-row">
                  <div class="setting-info">
                    <span class="text-title-small">Browser</span>
                    <span class="text-body-small setting-desc">
                      Only Chrome and Firefox family browsers are supported
                    </span>
                  </div>
                  <select
                    class="form-select"
                    bind:value={secureBrowserPath}
                    data-testid="secure-browser-select"
                  >
                    {#each secureBrowsers as browser}
                      <option value={browser.path}>{browser.name}</option>
                    {/each}
                  </select>
                </div>

                <div class="setting-row">
                  <div class="setting-info">
                    <span class="text-title-small">Chrome profile mode</span>
                    <span class="text-body-small setting-desc">
                      <strong>Isolated</strong> uses a clean separate profile.
                      <strong>Shared</strong> syncs certificates to <code>~/.pki/nssdb</code>
                      so they apply to your normal Chrome profile.
                    </span>
                  </div>
                  <select
                    class="form-select"
                    bind:value={browserConfig.chrome_profile_mode}
                    data-testid="chrome-profile-mode"
                    on:change={browserAutoSave}
                  >
                    <option value="isolated">Isolated</option>
                    <option value="shared">Shared</option>
                  </select>
                </div>

                <div class="setting-row">
                  <div class="setting-info">
                    <span class="text-title-small">Firefox profile mode</span>
                    <span class="text-body-small setting-desc">
                      <strong>Isolated</strong> uses a clean separate profile.
                      <strong>Shared</strong> overlays an enterprise policy on your normal
                      Firefox profile.
                    </span>
                  </div>
                  <select
                    class="form-select"
                    bind:value={browserConfig.firefox_profile_mode}
                    data-testid="firefox-profile-mode"
                    on:change={browserAutoSave}
                  >
                    <option value="isolated">Isolated</option>
                    <option value="shared">Shared</option>
                  </select>
                </div>

                <div class="setting-row">
                  <div class="setting-info">
                    <span class="text-title-small">URL</span>
                    <span class="text-body-small setting-desc">Initial page to open</span>
                  </div>
                  <div class="compact-input">
                    <input
                      type="text"
                      class="custom-command-input"
                      placeholder="https://example.com"
                      bind:value={secureBrowserURL}
                      data-testid="secure-browser-url"
                    />
                  </div>
                </div>

                <div class="bundle-status-grid">
                  <div class="storage-status-item">
                    <span class="text-label-small field-label">Certificates to inject</span>
                    <span class="text-body-medium">{secureBrowserCertCount}</span>
                  </div>
                  {#if secureBrowserPath}
                    <div class="storage-status-item">
                      <span class="text-label-small field-label">Detected family</span>
                      <span class="text-body-medium">
                        {secureBrowserFamily(secureBrowserPath) || 'unknown'}
                      </span>
                    </div>
                  {/if}
                </div>

                <div class="storage-actions">
                  <div class="storage-action-row">
                    <div class="setting-info">
                      <span class="text-title-small">Launch secure browser</span>
                      <span class="text-body-small setting-desc">
                        Synchronizes certificates then launches the selected browser
                      </span>
                    </div>
                    <Button
                      variant="primary"
                      icon={mdiShieldCheck}
                      loading={secureBrowserLaunching}
                      on:click={handleLaunchSecureBrowser}
                      disabled={secureBrowserCertCount === 0 || !secureBrowserPath}
                      data-testid="secure-browser-launch-btn"
                    >
                      Launch Secure Browser
                    </Button>
                  </div>
                </div>
              {/if}
            </div>
          </Card>

          <Card variant="outlined">
            <div class="settings-section">
              <h2 class="text-title-medium section-heading">Actions</h2>
              <div class="server-actions-row">
                <Button variant="outline" icon={mdiWeb} on:click={handleTestBrowser}>
                  Test Browser
                </Button>
              </div>
            </div>
          </Card>

          <!-- Extension Status & Pairing -->
          <Card variant="outlined">
            <div class="settings-section">
              <h2 class="text-title-medium section-heading">
                <span class="section-heading-with-icon">
                  <Icon path={mdiShieldCheck} size={20} />
                  Browser Extension
                </span>
              </h2>

              {#if $isEnterpriseMode && $enterprisePolicy?.extension_enabled === false}
                <div class="extension-enterprise-banner">
                  <Icon path={mdiAlert} size={18} />
                  <span class="text-body-small">Browser extension disabled by organization policy</span>
                </div>
              {/if}

              {#if extensionLoading}
                <div class="storage-loading">
                  <LoadingSpinner size={24} />
                  <span class="text-body-small">Checking extension status...</span>
                </div>
              {:else}
                <!-- IPC Server Status -->
                <div class="setting-row">
                  <div class="setting-info">
                    <span class="text-title-small">IPC Service</span>
                    <span class="text-body-small setting-desc">
                      {#if extensionFullStatus?.ipc_socket_path}
                        Socket: <code>{extensionFullStatus.ipc_socket_path}</code>
                      {:else}
                        Local communication service for browser extension
                      {/if}
                    </span>
                  </div>
                  {#if extensionFullStatus?.ipc_running}
                    <StatusBadge status="verified" label="Running" />
                  {:else}
                    <StatusBadge status="error" label="Stopped" />
                  {/if}
                </div>

                <!-- Native Messaging Manifests -->
                {#if extensionFullStatus?.manifests}
                  <div class="setting-row manifest-section">
                    <div class="setting-info" style="width: 100%;">
                      <span class="text-title-small">Native messaging</span>
                      <div class="manifest-list">
                        {#each extensionFullStatus.manifests as manifest}
                          <div class="manifest-browser-row">
                            <span class="manifest-browser-label">
                              <span class="extension-manifest-row">{manifest.name || manifest.browser}</span>
                              {#if manifest.installed}
                                <StatusBadge status="verified" label="Installed" />
                              {:else}
                                <StatusBadge status="warning" label="Not installed" />
                              {/if}
                            </span>
                            <span class="manifest-browser-action">
                              {#if manifest.installed}
                                <Button
                                  variant="outlined"
                                  size="small"
                                  icon={mdiClose}
                                  on:click={() => handleUninstallManifest(manifest.browser)}
                                  disabled={manifestInstalling !== null}
                                >
                                  {manifestInstalling === manifest.browser ? 'Removing...' : 'Uninstall'}
                                </Button>
                              {:else}
                                <Button
                                  variant="primary"
                                  size="small"
                                  icon={mdiPlus}
                                  on:click={() => handleInstallManifest(manifest.browser)}
                                  disabled={manifestInstalling !== null}
                                >
                                  {manifestInstalling === manifest.browser ? 'Installing...' : 'Install'}
                                </Button>
                              {/if}
                            </span>
                          </div>
                        {/each}
                      </div>
                      {#if extensionFullStatus.manifests.some(m => !m.installed)}
                        <div class="manifest-install-all">
                          <Button
                            variant="primary"
                            size="small"
                            icon={mdiPlus}
                            on:click={() => handleInstallManifest('all')}
                            disabled={manifestInstalling !== null}
                          >
                            {manifestInstalling === 'all' ? 'Installing...' : 'Install All'}
                          </Button>
                        </div>
                      {/if}
                    </div>
                  </div>
                {/if}

                <!-- Extension Enabled Toggle -->
                <div class="setting-row">
                  <div class="setting-info">
                    <span class="text-title-small">Enable browser extension autofill</span>
                    <span class="text-body-small setting-desc">
                      Allow the browser extension to search and fill credentials from xKey.
                    </span>
                  </div>
                  <Toggle
                    bind:checked={extensionEnabled}
                    onChange={handleToggleExtensionEnabled}
                    disabled={$isEnterpriseMode && ($enterprisePolicy?.extension_enabled === false || $enterprisePolicy?.user_can_configure_extension === false)}
                  />
                </div>

                <!-- Extension Pairing -->
                {#if extensionPairedList.length > 0}
                  {#each extensionPairedList as ext}
                    <div class="setting-row">
                      <div class="setting-info" style="min-width: 0;">
                        <span class="text-title-small">Paired extension</span>
                        <span class="text-body-small setting-desc" style="overflow-wrap: anywhere;">
                          Origin: <code style="word-break: break-all;">{ext.origin}</code>
                        </span>
                        {#if ext.paired_at}
                          <span class="text-body-small setting-desc">
                            Paired: {new Date(ext.paired_at).toLocaleString()}
                          </span>
                        {/if}
                      </div>
                      <div style="display: flex; align-items: center; gap: 8px; flex-shrink: 0;">
                        <StatusBadge status="verified" label="Paired" />
                        <Button
                          variant="outline"
                          icon={mdiClose}
                          loading={extensionUnpairing}
                          disabled={$isEnterpriseMode && $enterprisePolicy?.user_can_configure_extension === false}
                          on:click={() => handleUnpairExtension(ext.origin)}
                        >
                          Unpair
                        </Button>
                      </div>
                    </div>
                  {/each}
                  {#if extensionPairedList.length > 1}
                    <div class="storage-actions">
                      <div class="storage-action-row">
                        <div class="setting-info">
                          <span class="text-title-small">Unpair all extensions</span>
                          <span class="text-body-small setting-desc">
                            Remove all paired extension identities. All extensions will need to re-pair before they can autofill credentials.
                          </span>
                        </div>
                        <Button
                          variant="outline"
                          icon={mdiClose}
                          loading={extensionUnpairing}
                          disabled={$isEnterpriseMode && $enterprisePolicy?.user_can_configure_extension === false}
                          on:click={() => handleUnpairExtension()}
                        >
                          Unpair All
                        </Button>
                      </div>
                    </div>
                  {/if}
                {:else}
                  <div class="setting-row">
                    <div class="setting-info">
                      <span class="text-title-small">Extension pairing</span>
                      <span class="text-body-small setting-desc">
                        No extension paired. Install the xKey browser extension and click its icon to start pairing.
                      </span>
                    </div>
                    <StatusBadge status="inactive" label="Not paired" />
                  </div>
                {/if}

                {#if $isEnterpriseMode && $enterprisePolicy?.user_can_configure_extension === false}
                  <p class="text-body-small setting-desc" style="margin-bottom: 4px;">
                    <em>(Extension settings locked by organization policy)</em>
                  </p>
                {/if}

                <!-- FIDO2 Auth Toggle -->
                <div class="setting-row">
                  <div class="setting-info">
                    <span class="text-title-small">Require FIDO2 authentication for autofill</span>
                    <span class="text-body-small setting-desc">
                      When enabled, xKey requires PIN verification and touch before filling credentials.
                    </span>
                    {#if $isEnterpriseMode && $enterprisePolicy?.extension_require_authentication === true}
                      <span class="text-label-small extension-enforced-badge">Enforced by organization policy</span>
                    {/if}
                  </div>
                  <Toggle
                    bind:checked={requireAutofillAuth}
                    onChange={handleToggleAutofillAuth}
                    disabled={($isEnterpriseMode && $enterprisePolicy?.extension_require_authentication === true) || ($isEnterpriseMode && $enterprisePolicy?.user_can_configure_extension === false)}
                  />
                </div>
              {/if}
            </div>
          </Card>
        </div>

      {:else if activeCategory === 'advanced'}
        <Card variant="elevated">
          <div class="settings-section">
            <h2 class="text-title-medium section-heading">Advanced</h2>
            <div class="setting-row">
              <div class="setting-info">
                <span class="text-title-small">xkmsd URL</span>
                <span class="text-body-small setting-desc">Server URL for the xkmsd daemon</span>
              </div>
              <div class="compact-input">
                <Input placeholder="localhost:8443" bind:value={xkmsdUrl} monospace on:blur={autoSave} />
              </div>
            </div>
            <div class="setting-row">
              <div class="setting-info">
                <span class="text-title-small">Default backend</span>
                <span class="text-body-small setting-desc">Default cryptographic backend for new keys</span>
              </div>
              <select class="form-select" bind:value={defaultBackend} on:change={autoSave}>
                <option value="phone">Phone</option>
                <option value="software">Software</option>
                <option value="tpm2">TPM 2.0</option>
                <option value="pkcs11">PKCS #11</option>
              </select>
            </div>
            <div class="setting-row">
              <div class="setting-info">
                <span class="text-title-small">Log level</span>
                <span class="text-body-small setting-desc">Logging verbosity for troubleshooting</span>
              </div>
              <select class="form-select" bind:value={logLevel} on:change={autoSave}>
                <option value="error">Error</option>
                <option value="warn">Warning</option>
                <option value="info">Info</option>
                <option value="debug">Debug</option>
                <option value="trace">Trace</option>
              </select>
            </div>
            <div class="setting-row">
              <div class="setting-info">
                <span class="text-title-small">Debug mode</span>
                <span class="text-body-small setting-desc">Enable developer tools and extended logging</span>
              </div>
              <Toggle bind:checked={debugMode} on:change={autoSave} />
            </div>
            <div class="setting-row">
              <div class="setting-info">
                <span class="text-title-small">Developer Tools</span>
                <span class="text-body-small setting-desc">
                  Show API Explorer and OIDC in the sidebar
                  {#if $isEnterpriseMode && $enterprisePolicy?.developer_tools_enabled === false}
                    <span class="text-body-small" style="color: var(--color-on-surface-variant); font-style: italic;"> (Disabled by policy)</span>
                  {/if}
                </span>
              </div>
              <Toggle
                checked={$devToolsStore}
                disabled={$isEnterpriseMode && $enterprisePolicy?.developer_tools_enabled === false}
                on:change={handleDevToolsToggle}
              />
            </div>
          </div>
        </Card>
      {/if}
    </div>
  </div>

  <!-- Storage Dialogs -->
  <StoragePassphraseDialog
    bind:open={showMigrateDialog}
    mode="migrate"
    onClose={() => (showMigrateDialog = false)}
    onComplete={handleStorageDialogComplete}
  />

  <Modal bind:open={showUnlockDialog} title="Unlock Volume" maxWidth="400px">
    <div class="unlock-form">
      <p class="text-body-medium">Enter your passphrase to unlock the encrypted volume.</p>
      <Input
        label="Passphrase"
        type="password"
        placeholder="Enter volume passphrase"
        bind:value={storageUnlockPassphrase}
        disabled={storageLocking}
      />
    </div>
    <svelte:fragment slot="actions">
      <Button variant="text" on:click={() => { showUnlockDialog = false; storageUnlockPassphrase = ''; }} disabled={storageLocking}>
        Cancel
      </Button>
      <Button variant="primary" loading={storageLocking} on:click={handleUnlockVolume}>
        Unlock
      </Button>
    </svelte:fragment>
  </Modal>


  <Modal bind:open={showWipeConfirm} title="Wipe Encrypted Volume?" maxWidth="480px">
    <div class="wipe-form">
      {#if wipePINRequired}
        <p class="text-body-medium">
          Enter your User PIN to authorize this operation.
        </p>
        <Input
          label="User PIN"
          type="password"
          placeholder="Enter your User PIN"
          bind:value={wipePINValue}
        />
        {#if wipePINError}
          <p class="text-body-small" style="color: var(--color-security-danger); margin-top: 4px;">{wipePINError}</p>
        {/if}
      {:else}
        <div class="wipe-warning-box" role="alert">
          <Icon path={mdiShieldAlert} size={24} color="var(--color-security-danger)" />
          <div>
            <p class="text-body-medium wipe-warning-text">
              This will permanently destroy the following encrypted volume and <strong>all data</strong> within it.
              This action cannot be undone.
            </p>
          </div>
        </div>
        {#if storageStatus}
          <div class="wipe-volume-details">
            {#if storageStatus.volume_path}
              <div class="wipe-detail-row">
                <span class="text-label-small field-label">Volume</span>
                <span class="text-body-small font-mono">{storageStatus.volume_path}</span>
              </div>
            {/if}
            {#if storageStatus.volume_size_bytes > 0}
              <div class="wipe-detail-row">
                <span class="text-label-small field-label">Size</span>
                <span class="text-body-small">{formatBytes(storageStatus.volume_size_bytes)}</span>
              </div>
            {/if}
          </div>
        {/if}
        <div class="form-field-inline">
          <label class="text-label-medium" for="wipe-standard">Wipe Standard</label>
          <select id="wipe-standard" class="form-select" bind:value={wipeStandard} disabled={wiping}>
            <option value="nist">NIST SP 800-88 (1 pass)</option>
            <option value="dod3">DoD 5220.22-M (3 passes)</option>
            <option value="dod7">DoD 5220.22-M ECE (7 passes)</option>
          </select>
        </div>
      {/if}
    </div>
    <svelte:fragment slot="actions">
      <Button variant="text" on:click={() => { showWipeConfirm = false; wipePINRequired = false; wipePINValue = ''; wipePINError = ''; }} disabled={wiping}>Cancel</Button>
      {#if wipePINRequired}
        <Button variant="danger" on:click={handleWipePINSubmit}>Verify & Wipe</Button>
      {:else}
        <Button variant="danger" loading={wiping} on:click={handleWipeVolume}>Wipe Volume</Button>
      {/if}
    </svelte:fragment>
  </Modal>

  <Modal bind:open={showAutoUnsealEnableDialog} title="Enable Auto-Unseal" maxWidth="440px">
    <div class="unlock-form">
      <p class="text-body-medium">
        Enter the LUKS volume passphrase to seal it to the TPM. The passphrase will be encrypted
        and bound to PCRs 0-7 (SHA-256) so the volume can be unlocked automatically on boot.
      </p>
      <Input
        label="LUKS Passphrase"
        type="password"
        placeholder="Enter volume passphrase"
        bind:value={autoUnsealPassphrase}
        disabled={autoUnsealEnabling}
      />
      <Input
        label="Confirm Passphrase"
        type="password"
        placeholder="Confirm volume passphrase"
        bind:value={autoUnsealConfirmPassphrase}
        disabled={autoUnsealEnabling}
      />
      {#if autoUnsealPassphrase.length > 0 && autoUnsealPassphrase.length < 8}
        <p class="text-body-small auto-unseal-validation-msg">Passphrase must be at least 8 characters</p>
      {/if}
      {#if autoUnsealConfirmPassphrase.length > 0 && autoUnsealPassphrase !== autoUnsealConfirmPassphrase}
        <p class="text-body-small auto-unseal-validation-msg">Passphrases do not match</p>
      {/if}
    </div>
    <svelte:fragment slot="actions">
      <Button
        variant="text"
        on:click={() => { showAutoUnsealEnableDialog = false; autoUnsealPassphrase = ''; autoUnsealConfirmPassphrase = ''; }}
        disabled={autoUnsealEnabling}
      >
        Cancel
      </Button>
      <Button
        variant="primary"
        loading={autoUnsealEnabling}
        on:click={handleEnableAutoUnseal}
        disabled={!autoUnsealPassphraseIsValid}
      >
        Enable Auto-Unseal
      </Button>
    </svelte:fragment>
  </Modal>


  <PINDialog
    bind:open={showPINDialog}
    mode={pinDialogMode}
    on:close={() => (showPINDialog = false)}
    on:success={handlePINSuccess}
  />

  <Modal bind:open={showResetLockoutConfirm} title="Reset Lockout" maxWidth="400px">
    <div class="unlock-form">
      <p class="text-body-medium">Enter the Security Officer PIN to reset the lockout counter.</p>
      <Input
        label="SO PIN"
        type="password"
        placeholder="Enter SO PIN"
        bind:value={resetLockoutSOPIN}
        disabled={resettingLockout}
      />
    </div>
    <svelte:fragment slot="actions">
      <Button variant="text" on:click={() => { showResetLockoutConfirm = false; resetLockoutSOPIN = ''; }} disabled={resettingLockout}>
        Cancel
      </Button>
      <Button variant="primary" loading={resettingLockout} on:click={handleResetLockout} disabled={!resetLockoutSOPIN}>
        Reset Lockout
      </Button>
    </svelte:fragment>
  </Modal>

  <Modal bind:open={showAutoUnsealDisableConfirm} title="Disable Auto-Unseal?" maxWidth="440px">
    <div class="wipe-form">
      <p class="text-body-medium">
        This will remove the TPM-sealed passphrase. You will need to manually enter the LUKS
        passphrase each time the volume is unlocked.
      </p>
    </div>
    <svelte:fragment slot="actions">
      <Button variant="text" on:click={() => (showAutoUnsealDisableConfirm = false)} disabled={autoUnsealDisabling}>
        Cancel
      </Button>
      <Button variant="danger" loading={autoUnsealDisabling} on:click={handleDisableAutoUnseal}>
        Disable Auto-Unseal
      </Button>
    </svelte:fragment>
  </Modal>

  <!-- PIN verification dialog for disabling security toggles -->
  <Modal bind:open={showAuthPINDialog} title="Verify PIN" maxWidth="400px">
    <div class="auth-pin-form">
      <p class="text-body-medium">Enter your User PIN to disable this security setting.</p>
      <Input
        label="User PIN"
        type="password"
        placeholder="Enter your User PIN"
        bind:value={authPINValue}
        error={authPINError}
        disabled={authPINLoading}
      />
    </div>
    <svelte:fragment slot="actions">
      <Button variant="text" on:click={handleAuthPINCancel} disabled={authPINLoading}>
        Cancel
      </Button>
      <Button variant="primary" loading={authPINLoading} on:click={handleAuthPINSubmit} disabled={!authPINValue.trim()}>
        Verify
      </Button>
    </svelte:fragment>
  </Modal>
</div>

<style>
  .settings-view {
    height: 100%;
    display: flex;
    flex-direction: column;
  }

  .settings-layout {
    flex: 1;
    display: flex;
    overflow: hidden;
  }

  .settings-nav {
    width: 220px;
    min-width: 220px;
    padding: 16px 12px;
    border-right: 1px solid var(--color-outline-variant);
    display: flex;
    flex-direction: column;
    gap: 4px;
    overflow-y: auto;
  }

  .settings-nav-item {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 16px;
    border: none;
    border-radius: var(--radius-full);
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    font-family: var(--font-sans);
    text-align: left;
    transition: background-color var(--transition-fast), color var(--transition-fast);
    width: 100%;
  }

  .settings-nav-item:hover {
    background-color: var(--color-surface-container);
    color: var(--color-on-surface);
  }

  .settings-nav-item.nav-active {
    background-color: var(--color-primary-95);
    color: var(--color-primary);
    font-weight: 600;
  }

  :global([data-theme="dark"]) .settings-nav-item.nav-active {
    background-color: var(--color-primary-container);
    color: var(--color-on-primary-container);
  }

  .settings-panel {
    flex: 1;
    overflow-y: auto;
    padding: 24px;
    display: flex;
    flex-direction: column;
    gap: 20px;
    max-width: 700px;
  }

  .settings-section {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .section-heading {
    margin: 0;
    color: var(--color-on-surface);
    padding-bottom: 8px;
    border-bottom: 1px solid var(--color-outline-variant);
  }

  .setting-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 24px;
    padding: 12px 0;
  }

  .setting-row + .setting-row {
    border-top: 1px solid var(--color-surface-variant);
  }

  .setting-info {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .setting-info span:first-child {
    color: var(--color-on-surface);
  }

  .setting-desc {
    color: var(--color-on-surface-variant);
  }

  .form-select {
    height: 40px;
    padding: 0 12px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    background-color: var(--color-surface-container-lowest);
    color: var(--color-on-surface);
    font-family: var(--font-sans);
    font-size: 14px;
    outline: none;
    cursor: pointer;
    min-width: 140px;
  }

  .form-select:focus {
    border-color: var(--color-primary);
  }

  .range-input {
    width: 140px;
    accent-color: var(--color-primary);
  }

  .inline-input {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .number-input {
    width: 80px;
    height: 40px;
    padding: 0 12px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    background-color: var(--color-surface-container-lowest);
    color: var(--color-on-surface);
    font-family: var(--font-mono);
    font-size: 14px;
    outline: none;
    text-align: center;
  }

  .number-input:focus {
    border-color: var(--color-primary);
  }

  .compact-input {
    width: 240px;
  }

  .setting-warn {
    color: var(--color-security-danger);
  }

  .server-status-row {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 8px 0;
  }

  .server-actions-row {
    display: flex;
    gap: 12px;
    padding-top: 8px;
  }

  /* Theme Preview */
  .theme-preview {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .theme-preview h3 {
    margin: 0;
    color: var(--color-on-surface);
  }

  .preview-colors {
    display: flex;
    gap: 8px;
  }

  .preview-swatch {
    flex: 1;
    height: 48px;
    border-radius: var(--radius-md);
    display: flex;
    align-items: center;
    justify-content: center;
    color: #FFFFFF;
    font-size: 12px;
    font-weight: 500;
  }

  /* Storage Panel */
  .storage-loading {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 16px 0;
    color: var(--color-on-surface-variant);
  }

  .storage-status-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 12px;
  }

  .storage-status-item {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .field-label {
    color: var(--color-on-surface-variant);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .root-warning {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 12px 16px;
    background-color: var(--color-security-warning-container);
    border-radius: var(--radius-sm);
    color: var(--color-on-security-warning-container);
  }

  .storage-empty-msg {
    color: var(--color-on-surface-variant);
    margin: 0;
  }

  .storage-actions {
    display: flex;
    flex-direction: column;
    gap: 0;
  }

  .storage-action-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 24px;
    padding: 12px 0;
  }

  .storage-action-row + .storage-action-row {
    border-top: 1px solid var(--color-surface-variant);
  }

  .auto-unseal-info {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 12px 16px;
    background-color: var(--color-surface-container);
    border-radius: var(--radius-sm);
    color: var(--color-on-surface-variant);
  }

  .auto-unseal-validation-msg {
    margin: 0;
    color: var(--color-error);
  }

  /* PIN Management */
  .pin-strategy-badge {
    display: inline-flex;
    align-items: center;
    padding: 4px 12px;
    border-radius: var(--radius-full);
    background-color: var(--color-primary-95);
    color: var(--color-primary);
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 0.3px;
  }

  :global([data-theme="dark"]) .pin-strategy-badge {
    background-color: var(--color-primary-container);
    color: var(--color-on-primary-container);
  }

  .pin-check-indicator {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .lockout-status-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 12px;
  }

  .lockout-recovery-time {
    color: var(--color-security-danger);
    font-weight: 500;
  }

  .lockout-alert {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 12px 16px;
    background-color: var(--color-security-danger-container);
    border-radius: var(--radius-sm);
    color: var(--color-on-security-danger-container);
  }

  .unlock-form {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .unlock-form p {
    margin: 0;
    color: var(--color-on-surface-variant);
  }

  .wipe-form {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .wipe-warning-text {
    margin: 0;
    color: var(--color-error);
  }

  .wipe-warning-box {
    display: flex;
    gap: 12px;
    align-items: flex-start;
    padding: 12px;
    border-radius: 8px;
    background: color-mix(in srgb, var(--color-error) 8%, transparent);
    border: 1px solid color-mix(in srgb, var(--color-error) 25%, transparent);
  }

  .wipe-volume-details {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 12px;
    border-radius: 8px;
    background: var(--color-surface-variant);
  }

  .wipe-detail-row {
    display: flex;
    justify-content: space-between;
    align-items: center;
  }

  .form-field-inline {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .form-field-inline label {
    color: var(--color-on-surface-variant);
  }

  /* Browser Settings */
  .custom-command-input {
    width: 100%;
    height: 48px;
    padding: 0 16px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-md);
    background-color: var(--color-surface-container-lowest);
    color: var(--color-on-surface);
    font-family: var(--font-mono);
    font-size: 14px;
    line-height: 20px;
    outline: none;
    box-sizing: border-box;
    transition: border-color var(--transition-fast);
  }

  .custom-command-input:focus {
    border-color: var(--color-primary);
    box-shadow: 0 0 0 1px var(--color-primary);
  }

  .custom-command-input::placeholder {
    color: var(--color-on-surface-variant);
    opacity: 0.6;
  }

  /* CA Trust Bundle */
  .section-heading-with-icon {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .bundle-status-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 12px;
  }

  .bundle-status-indicator {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .bundle-stale-hint {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 12px 16px;
    background-color: var(--color-security-warning-container);
    border-radius: var(--radius-sm);
    color: var(--color-on-security-warning-container);
  }

  .secure-browser-desc {
    margin: 0 0 8px 0;
    color: var(--color-on-surface-variant);
    line-height: 1.5;
  }

  .auth-pin-form {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .auth-pin-form p {
    margin: 0;
    color: var(--color-on-surface-variant);
  }

  /* Extension Enterprise Policy */
  .extension-enterprise-banner {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 12px 16px;
    background-color: var(--color-security-warning-container);
    border-radius: var(--radius-sm);
    color: var(--color-on-security-warning-container);
  }

  .extension-enforced-badge {
    display: inline-block;
    margin-top: 4px;
    color: var(--color-primary);
    font-style: italic;
  }

  .extension-manifest-row {
    display: inline;
    text-transform: capitalize;
  }

  .manifest-list {
    display: flex;
    flex-direction: column;
    gap: 8px;
    margin-top: 8px;
  }

  .manifest-browser-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 6px 0;
  }

  .manifest-browser-label {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .manifest-browser-action {
    flex-shrink: 0;
  }

  .manifest-install-all {
    margin-top: 8px;
    display: flex;
    justify-content: flex-end;
  }

  .manifest-section {
    flex-direction: column;
    align-items: stretch;
  }
</style>
