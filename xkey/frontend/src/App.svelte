<script lang="ts">
  import { onMount } from 'svelte';
  import { appState, currentView, navigateTo, toggleSidebar, sidebarCollapsed, setupComplete, setSetupComplete, devToolsEnabled, setDevToolsEnabled, tpmAvailable, setTPMAvailable } from '$lib/stores/app';
  import { initTheme, theme, toggleTheme } from '$lib/stores/theme';
  import { setupEventListeners, appLocked } from '$lib/stores/events';
  import Toast from '$lib/components/Toast.svelte';
  import ShutdownOverlay from '$lib/components/ShutdownOverlay.svelte';
  import ExtensionPairingDialog from '$lib/components/ExtensionPairingDialog.svelte';
  import AppLockOverlay from '$lib/components/AppLockOverlay.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import XKeyBrandIcon from '$lib/components/XKeyBrandIcon.svelte';
  import TouchButton from '$lib/components/TouchButton.svelte';
  import LockButton from '$lib/components/LockButton.svelte';
  import { touchPending } from '$lib/stores/touch';
  import { callBackend, callBackendVoid, isWailsAvailable } from '$lib/api/backend';
  import { addNotification } from '$lib/stores/notifications';
  import SetupWizard from './views/SetupWizard.svelte';
  import AuthLoginGate from '$lib/components/AuthLoginGate.svelte';
  import AdminApp from './views/AdminApp.svelte';
  import { authMode, isEnterpriseMode, setAuthMode, setEnterpriseMode, setPolicyVerified, enterprisePolicy, setEnterprisePolicy } from '$lib/stores/auth';
  import type { StartupState, AuthMode } from '$lib/types/setup';
  import {
    mdiViewDashboard, mdiShieldCheckOutline, mdiNumeric,
    mdiCreditCardOutline, mdiChip, mdiCog, mdiClipboardTextOutline,
    mdiWrenchOutline, mdiMenu, mdiWeatherSunny, mdiWeatherNight,
    mdiThemeLightDark, mdiKey, mdiChevronLeft, mdiLanConnect, mdiLockOutline,
    mdiShieldLockOutline, mdiOpenInApp, mdiCertificate, mdiConsoleLine
  } from '$lib/utils/icons';
  import { isServerConnected } from '$lib/stores/connection';

  function handleAuthenticated(e: CustomEvent<{ mode: string }>): void {
    setAuthMode(e.detail.mode as AuthMode);
  }

  import { addDevice } from '$lib/stores/pairing';
  import type { PairedDevice } from '$lib/stores/pairing';
  import Dashboard from './views/Dashboard.svelte';
  import Pairing from './views/Pairing.svelte';
  import PairingDetail from './views/PairingDetail.svelte';
  import FIDO2 from './views/FIDO2.svelte';
  import FIDO2Credential from './views/FIDO2Credential.svelte';
  import OATH from './views/OATH.svelte';
  import PIV from './views/PIV.svelte';
  import PIVSlot from './views/PIVSlot.svelte';
  import TPM from './views/TPM.svelte';
  import Settings from './views/Settings.svelte';
  import AuditLog from './views/AuditLog.svelte';
  import Admin from './views/Admin.svelte';
  import AdminBackends from './views/AdminBackends.svelte';
  import Keys from './views/Keys.svelte';
  import Passwords from './views/Passwords.svelte';
  import Seal from './views/Seal.svelte';
  import TrustStore from './views/TrustStore.svelte';
  import OIDC from './views/OIDC.svelte';
  import Certificates from './views/Certificates.svelte';
  import APIExplorer from './views/APIExplorer.svelte';

  interface NavItem {
    id: string;
    label: string;
    icon: string;
    section?: string;
  }

  const navItems: NavItem[] = [
    { id: 'dashboard', label: 'Dashboard', icon: mdiViewDashboard, section: 'main' },
    { id: 'pairing', label: 'Pairing', icon: mdiLanConnect, section: 'main' },
    { id: 'tpm', label: 'TPM 2.0', icon: mdiChip, section: 'main' },
    { id: 'keys', label: 'Keys', icon: mdiKey, section: 'store' },
    { id: 'trust-store', label: 'Trust Store', icon: mdiShieldLockOutline, section: 'store' },
    { id: 'certificates', label: 'Certificates', icon: mdiCertificate, section: 'store' },
    { id: 'fido2', label: 'FIDO2', icon: mdiShieldCheckOutline, section: 'applications' },
    { id: 'oath', label: 'OATH', icon: mdiNumeric, section: 'applications' },
    { id: 'piv', label: 'PIV', icon: mdiCreditCardOutline, section: 'applications' },
    { id: 'passwords', label: 'Passwords', icon: mdiLockOutline, section: 'applications' },
    { id: 'seal', label: 'Sealed Data', icon: mdiShieldCheckOutline, section: 'applications' },
    { id: 'audit-log', label: 'Audit Log', icon: mdiClipboardTextOutline, section: 'admin' },
    { id: 'admin', label: 'Admin', icon: mdiWrenchOutline, section: 'admin' },
    { id: 'oidc', label: 'OIDC', icon: mdiOpenInApp, section: 'developer' },
    { id: 'api-explorer', label: 'API Explorer', icon: mdiConsoleLine, section: 'developer' },
    { id: 'settings', label: 'Settings', icon: mdiCog, section: 'settings' },
  ];

  let startupState: StartupState | null = null;

  // Extension pairing dialog state (driven by Wails events).
  let extensionPairingOpen = false;
  let extensionPairingCode = '';
  let extensionPairingOrigin = '';
  let extensionPairingSuccess = false;

  // Activity tracking for app auto-lock (throttled to 30s).
  let lastActivity = 0;
  function reportActivity(): void {
    const now = Date.now();
    if (now - lastActivity < 30000) return;
    lastActivity = now;
    if (isWailsAvailable()) {
      callBackendVoid('AppLockService', 'RecordActivity');
    }
  }

  const themeIcons: Record<string, string> = {
    light: mdiWeatherSunny,
    dark: mdiWeatherNight,
    system: mdiThemeLightDark,
  };

  $: collapsed = $sidebarCollapsed;
  $: view = $currentView;
  $: themeIcon = themeIcons[$theme] || mdiThemeLightDark;

  $: filteredNavItems = navItems.filter(item => {
    // Hide TPM nav when no TPM hardware is available.
    if (item.id === 'tpm' && !$tpmAvailable) return false;
    // Developer tools section: hidden when user toggles off or enterprise policy disables.
    if (item.section === 'developer') {
      const p = $enterprisePolicy;
      if (p && p.developer_tools_enabled === false) return false;
      if (!$devToolsEnabled) return false;
    }
    if (!$isEnterpriseMode) return true;
    if (item.id === 'admin') return false;
    const p = $enterprisePolicy;
    if (!p) return true;
    if (item.id === 'audit-log' && !p.user_can_view_audit_log) return false;
    if (item.id === 'seal' && !p.user_can_manage_sealed_data) return false;
    if (item.id === 'trust-store' && !p.user_can_manage_trust_store) return false;
    return true;
  });

  function isNavActive(navId: string, currentView: string): boolean {
    if (navId === currentView) return true;
    if (navId === 'pairing' && currentView === 'pairing-detail') return true;
    if (navId === 'fido2' && currentView === 'fido2-credential') return true;
    if (navId === 'piv' && currentView === 'piv-slot') return true;
    if (navId === 'admin' && currentView === 'admin-backends') return true;
    return false;
  }

  async function handleTouch(): Promise<void> {
    const approved = await callBackend<boolean>('FIDO2DeviceService', 'ApproveTouchRequest');
    if (!approved) {
      addNotification('error', 'Touch approval failed — is the authenticator running?');
    }
    // Do NOT call clearTouchPending() here — the backend emits
    // fido2:touch_resolved on success, which clears the pending state
    // via the event listener in events.ts.
  }

  onMount(async () => {
    initTheme();
    setupEventListeners();

    // Listen for extension pairing request events from the backend.
    // Wails emits events.Event struct: { type, payload: { code, origin }, time }.
    if (typeof window !== 'undefined' && (window as any).runtime?.EventsOn) {
      (window as any).runtime.EventsOn('extension:pairing_request', (data: any) => {
        const payload = data?.payload || data;
        extensionPairingCode = payload?.code || '';
        extensionPairingOrigin = payload?.origin || '';
        extensionPairingSuccess = false;
        extensionPairingOpen = true;
      });
      (window as any).runtime.EventsOn('extension:paired', (data: any) => {
        extensionPairingSuccess = true;
        // Add the extension to the unified pairing store.
        const payload = data?.payload || data;
        const extDevice: PairedDevice = {
          name: payload?.name || `Extension (${extensionPairingOrigin || 'unknown'})`,
          address: extensionPairingOrigin || payload?.origin || 'extension',
          paired: new Date().toISOString(),
          securityLevel: 'browser',
          attestationStatus: 'connected',
          lastAttestation: null,
          isDefault: false,
          isBackend: false,
          attestation: null,
          policy: null,
          type: 'extension',
        };
        addDevice(extDevice);
      });
    }

    // Check initial app lock state.
    if (isWailsAvailable()) {
      const lockStatus = await callBackend<{ is_locked: boolean }>('AppLockService', 'GetStatus');
      if (lockStatus?.is_locked) {
        appLocked.set(true);
      }
    }

    // Load dev tools toggle state from config.
    if (isWailsAvailable()) {
      const dt = await callBackend<boolean>('AppService', 'GetDeveloperTools');
      if (dt !== null) setDevToolsEnabled(dt);
    }

    // Check TPM availability to conditionally show/hide TPM navigation.
    // Show the TPM nav item when the device node exists, even if TPM
    // initialization failed — the user should still see the TPM page
    // with a "Not Ready" status rather than having it silently vanish.
    if (isWailsAvailable()) {
      const tpmStatus = await callBackend<{ available: boolean; device_exists: boolean }>('TPMService', 'GetStatus');
      setTPMAvailable((tpmStatus?.available || tpmStatus?.device_exists) ?? false);
    }

    // Fetch startup state from backend
    const state = await callBackend<StartupState>('SetupWizardService', 'GetStartupState');
    startupState = state;

    if (state) {
      if (!state.setup_complete) {
        setSetupComplete(false);
      }
      if (state.enterprise_mode) {
        setEnterpriseMode(true);
        // Load enterprise policy for navigation filtering.
        const policy = await callBackend<Record<string, any>>('SetupWizardService', 'GetPolicy');
        if (policy) {
          setEnterprisePolicy(policy);
        }
      }
      // In personal mode, auto-authenticate as user (barrier unseal is sufficient)
      if (state.setup_complete && !state.enterprise_mode) {
        // Call backend to set user mode
        await callBackend<void>('AuthService', 'SetModeUser');
        setAuthMode('user');
      }
    }
  });
</script>

{#if !$setupComplete}
  <SetupWizard mode={startupState?.enterprise_wizard_mode ?? ''} on:complete={() => setSetupComplete(true)} />
{:else if $isEnterpriseMode && $authMode === 'locked'}
  <AuthLoginGate on:authenticated={handleAuthenticated} />
{:else if $authMode === 'so_admin'}
  <AdminApp on:switchToUser={() => setAuthMode('user')} on:logout={() => setAuthMode('locked')} />
{:else}
<div class="app-shell" class:sidebar-collapsed={collapsed}>
  <nav class="sidebar" aria-label="Main navigation">
    <div class="sidebar-header">
      {#if !collapsed}
        <div class="brand">
          <div class="brand-icon">
            <XKeyBrandIcon size={28} />
          </div>
          <span class="brand-text text-title-large">xKey</span>
        </div>
      {/if}
      <button class="sidebar-toggle" on:click={toggleSidebar} aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}>
        <Icon path={collapsed ? mdiMenu : mdiChevronLeft} size={20} />
      </button>
    </div>

    <div class="nav-sections">
      <div class="nav-section">
        {#if !collapsed}
          <span class="nav-section-label text-label-small">OVERVIEW</span>
        {/if}
        {#each filteredNavItems.filter(n => n.section === 'main') as item}
          <button
            class="nav-item"
            class:nav-active={isNavActive(item.id, view)}
            on:click={() => navigateTo(item.id)}
            title={collapsed ? item.label : ''}
          >
            <Icon path={item.icon} size={20} />
            {#if !collapsed}
              <span class="nav-label text-label-large">{item.label}</span>
            {/if}
          </button>
        {/each}
      </div>

      <div class="nav-section">
        {#if !collapsed}
          <span class="nav-section-label text-label-small">STORE</span>
        {/if}
        {#each filteredNavItems.filter(n => n.section === 'store') as item}
          <button
            class="nav-item"
            class:nav-active={isNavActive(item.id, view)}
            on:click={() => navigateTo(item.id)}
            title={collapsed ? item.label : ''}
          >
            <Icon path={item.icon} size={20} />
            {#if !collapsed}
              <span class="nav-label text-label-large">{item.label}</span>
            {/if}
          </button>
        {/each}
      </div>

      <div class="nav-section">
        {#if !collapsed}
          <span class="nav-section-label text-label-small">APPLICATIONS</span>
        {/if}
        {#each filteredNavItems.filter(n => n.section === 'applications') as item}
          <button
            class="nav-item"
            class:nav-active={isNavActive(item.id, view)}
            on:click={() => navigateTo(item.id)}
            title={collapsed ? item.label : ''}
          >
            <Icon path={item.icon} size={20} />
            {#if !collapsed}
              <span class="nav-label text-label-large">{item.label}</span>
            {/if}
          </button>
        {/each}
      </div>

      <div class="nav-section">
        {#if !collapsed}
          <span class="nav-section-label text-label-small">MANAGEMENT</span>
        {/if}
        {#each filteredNavItems.filter(n => n.section === 'admin') as item}
          <button
            class="nav-item"
            class:nav-active={isNavActive(item.id, view)}
            on:click={() => navigateTo(item.id)}
            title={collapsed ? item.label : ''}
          >
            <Icon path={item.icon} size={20} />
            {#if !collapsed}
              <span class="nav-label text-label-large">{item.label}</span>
            {/if}
          </button>
        {/each}
      </div>

      {#if filteredNavItems.some(n => n.section === 'developer')}
        <div class="nav-section">
          {#if !collapsed}
            <span class="nav-section-label text-label-small">DEVELOPER TOOLS</span>
          {/if}
          {#each filteredNavItems.filter(n => n.section === 'developer') as item}
            <button
              class="nav-item"
              class:nav-active={isNavActive(item.id, view)}
              on:click={() => navigateTo(item.id)}
              title={collapsed ? item.label : ''}
            >
              <Icon path={item.icon} size={20} />
              {#if !collapsed}
                <span class="nav-label text-label-large">{item.label}</span>
              {/if}
            </button>
          {/each}
        </div>
      {/if}
    </div>

    <div class="sidebar-footer">
      <div class="connection-indicator" title={$isServerConnected ? 'Connected to server' : 'Standalone mode'}>
        <div class="connection-dot" class:connected={$isServerConnected}></div>
        {#if !collapsed}
          <span class="text-label-small connection-label">{$isServerConnected ? 'Connected' : 'Standalone'}</span>
        {/if}
      </div>
      <button class="nav-item" on:click={toggleTheme} title="Toggle theme">
        <Icon path={themeIcon} size={20} />
        {#if !collapsed}
          <span class="nav-label text-label-large">Theme</span>
        {/if}
      </button>
      {#each filteredNavItems.filter(n => n.section === 'settings') as item}
        <button
          class="nav-item"
          class:nav-active={isNavActive(item.id, view)}
          on:click={() => navigateTo(item.id)}
          title={collapsed ? item.label : ''}
        >
          <Icon path={item.icon} size={20} />
          {#if !collapsed}
            <span class="nav-label text-label-large">{item.label}</span>
          {/if}
        </button>
      {/each}
    </div>
  </nav>

  <main class="main-content">
    <div class="app-header">
      <div class="header-spacer"></div>
      <div class="header-actions">
        <LockButton />
        <TouchButton pending={$touchPending} onTouch={handleTouch} />
      </div>
    </div>
    <div class="view-container">
      {#if view === 'dashboard'}
        <Dashboard />
      {:else if view === 'pairing'}
        <Pairing />
      {:else if view === 'pairing-detail'}
        <PairingDetail />
      {:else if view === 'fido2'}
        <FIDO2 />
      {:else if view === 'fido2-credential'}
        <FIDO2Credential />
      {:else if view === 'oath'}
        <OATH />
      {:else if view === 'oidc'}
        <OIDC />
      {:else if view === 'piv'}
        <PIV />
      {:else if view === 'piv-slot'}
        <PIVSlot />
      {:else if view === 'tpm'}
        <TPM />
      {:else if view === 'settings'}
        <Settings />
      {:else if view === 'audit-log'}
        <AuditLog />
      {:else if view === 'admin'}
        <Admin />
      {:else if view === 'admin-backends'}
        <AdminBackends />
      {:else if view === 'keys'}
        <Keys />
      {:else if view === 'passwords'}
        <Passwords />
      {:else if view === 'seal'}
        <Seal />
      {:else if view === 'trust-store'}
        <TrustStore />
      {:else if view === 'certificates'}
        <Certificates />
      {:else if view === 'api-explorer'}
        <APIExplorer />
      {/if}
    </div>
  </main>
</div>
{/if}

<svelte:window on:mousemove={reportActivity} on:keydown={reportActivity} />

<Toast />
<AppLockOverlay />
<ShutdownOverlay />
<ExtensionPairingDialog
  bind:open={extensionPairingOpen}
  code={extensionPairingCode}
  origin={extensionPairingOrigin}
  success={extensionPairingSuccess}
  onClose={() => { extensionPairingOpen = false; extensionPairingSuccess = false; }}
/>

<style>
  .app-shell {
    display: flex;
    width: 100vw;
    height: 100vh;
    overflow: hidden;
  }

  /* Sidebar */
  .sidebar {
    width: 240px;
    min-width: 240px;
    height: 100vh;
    display: flex;
    flex-direction: column;
    background-color: var(--color-surface-container-lowest);
    border-right: 1px solid var(--color-outline-variant);
    transition: width var(--transition-normal), min-width var(--transition-normal);
    overflow: hidden;
  }

  .sidebar-collapsed .sidebar {
    width: 64px;
    min-width: 64px;
  }

  .sidebar-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 16px;
    height: 64px;
    flex-shrink: 0;
  }

  .sidebar-collapsed .sidebar-header {
    justify-content: center;
    padding: 16px 12px;
  }

  .brand {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .brand-icon {
    width: 36px;
    height: 36px;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  .brand-text {
    color: var(--color-on-surface);
    font-weight: 700;
    white-space: nowrap;
  }

  .sidebar-toggle {
    width: 36px;
    height: 36px;
    border: none;
    border-radius: 50%;
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    transition: background-color var(--transition-fast);
  }

  .sidebar-toggle:hover {
    background-color: var(--color-surface-variant);
  }

  /* Navigation */
  .nav-sections {
    flex: 1;
    overflow-y: auto;
    padding: 8px;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .nav-section {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding-bottom: 8px;
  }

  .nav-section + .nav-section {
    padding-top: 8px;
    border-top: 1px solid var(--color-outline-variant);
  }

  .nav-section-label {
    color: var(--color-on-surface-variant);
    opacity: 0.6;
    padding: 8px 12px 4px;
    text-transform: uppercase;
    letter-spacing: 1px;
    white-space: nowrap;
  }

  .nav-item {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 12px;
    border: none;
    border-radius: var(--radius-full);
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    transition: background-color var(--transition-fast),
                color var(--transition-fast);
    font-family: var(--font-sans);
    white-space: nowrap;
    text-align: left;
    width: 100%;
  }

  .sidebar-collapsed .nav-item {
    justify-content: center;
    padding: 10px;
  }

  .nav-item:hover {
    background-color: var(--color-surface-container);
    color: var(--color-on-surface);
  }

  .nav-active {
    background-color: var(--color-primary-95);
    color: var(--color-primary);
    font-weight: 600;
  }

  :global([data-theme="dark"]) .nav-active {
    background-color: var(--color-primary-container);
    color: var(--color-on-primary-container);
  }

  .nav-label {
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .sidebar-footer {
    padding: 8px;
    border-top: 1px solid var(--color-outline-variant);
    display: flex;
    flex-direction: column;
    gap: 2px;
    flex-shrink: 0;
  }

  .connection-indicator {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 12px;
  }

  .sidebar-collapsed .connection-indicator {
    justify-content: center;
    padding: 8px;
  }

  .connection-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background-color: var(--color-on-surface-variant);
    opacity: 0.4;
    flex-shrink: 0;
  }

  .connection-dot.connected {
    background-color: var(--color-security-verified);
    opacity: 1;
  }

  .connection-label {
    color: var(--color-on-surface-variant);
    white-space: nowrap;
  }

  /* Main Content */
  .main-content {
    flex: 1;
    overflow: hidden;
    background-color: var(--color-background);
    display: flex;
    flex-direction: column;
  }

  .app-header {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    padding: 8px 16px;
    height: 48px;
    flex-shrink: 0;
    border-bottom: 1px solid var(--color-outline-variant);
  }

  .header-spacer {
    flex: 1;
  }

  .header-actions {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .view-container {
    width: 100%;
    flex: 1;
    overflow-y: auto;
    animation: fade-in 200ms ease;
  }

  @keyframes fade-in {
    from { opacity: 0; }
    to { opacity: 1; }
  }
</style>
