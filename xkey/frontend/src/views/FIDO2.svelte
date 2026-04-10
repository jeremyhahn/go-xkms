<script lang="ts">
  import { onMount } from 'svelte';
  import GradientHeader from '$lib/components/GradientHeader.svelte';
  import Tabs from '$lib/components/Tabs.svelte';
  import Card from '$lib/components/Card.svelte';
  import Button from '$lib/components/Button.svelte';
  import StatusBadge from '$lib/components/StatusBadge.svelte';
  import SearchBar from '$lib/components/SearchBar.svelte';
  import BridgeStatus from '$lib/components/BridgeStatus.svelte';
  import EmptyState from '$lib/components/EmptyState.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import BackendSelector from '$lib/components/BackendSelector.svelte';
  import {
    mdiShieldCheckOutline, mdiDelete, mdiEye, mdiKey, mdiConnection, mdiOpenInNew
  } from '$lib/utils/icons';
  import { navigateTo, appState } from '$lib/stores/app';
  import {
    fido2State, fido2Credentials, fido2CredentialCount,
    bridgeStatus, setCredentials, setFIDO2Search
  } from '$lib/stores/fido2';
  import { formatRelativeTime } from '$lib/utils/format';
  import { addNotification } from '$lib/stores/notifications';
  import type { FIDO2Credential as CredType } from '$lib/stores/fido2';
  import { isWailsAvailable, callBackend, callBackendVoid } from '$lib/api/backend';
  import type { BackendFIDO2Credential, FIDO2DeviceStatus } from '$lib/api/backend';

  const tabs = [
    { id: 'credentials', label: 'Credentials' },
    { id: 'bridge', label: 'Bridge' },
    { id: 'relying-parties', label: 'Relying Parties' },
  ];

  let activeTab = 'credentials';
  let searchQuery = '';
  let selectedBackend = 'all';
  let deleteTarget: CredType | null = null;
  let showDeleteConfirm = false;
  let deviceStatus: FIDO2DeviceStatus | null = null;

  function mapCredential(c: BackendFIDO2Credential): CredType {
    return {
      id: c.id,
      relyingPartyId: c.relying_party_id,
      relyingPartyName: c.relying_party,
      userName: c.user_name,
      userDisplayName: c.user_display_name,
      algorithm: c.algorithm,
      keyType: c.key_type,
      credProtect: c.cred_protect,
      backendType: c.backend_type,
      useCount: c.use_count,
      discoverable: c.discoverable,
      created: c.created_at,
      lastUsed: c.last_used || null,
    };
  }

  onMount(async () => {
    if (isWailsAvailable()) {
      const [creds, status] = await Promise.all([
        callBackend<BackendFIDO2Credential[]>('FIDO2Service', 'ListCredentials'),
        callBackend<FIDO2DeviceStatus>('FIDO2DeviceService', 'GetStatus'),
      ]);
      if (creds) {
        setCredentials(creds.map(mapCredential));
      }
      if (status) {
        deviceStatus = status;
      }
    }
  });

  function handleSearch(value: string): void {
    searchQuery = value;
    setFIDO2Search(value);
  }

  async function openRP(rpId: string): Promise<void> {
    if (!rpId) return;
    const url = `https://${rpId}`;
    const ok = await callBackendVoid('BrowserService', 'OpenURL', url);
    if (!ok) {
      addNotification('error', 'Failed to open browser');
    }
  }

  function viewCredential(cred: CredType): void {
    appState.update((s) => ({
      ...s,
      currentView: 'fido2-credential',
      modalProps: { credentialId: cred.id },
    }));
  }

  function confirmDelete(cred: CredType): void {
    deleteTarget = cred;
    showDeleteConfirm = true;
  }

  async function handleDelete(): Promise<void> {
    if (deleteTarget) {
      if (isWailsAvailable()) {
        await callBackendVoid('FIDO2Service', 'DeleteCredential', deleteTarget.id);
      }
      addNotification('info', `Credential for ${deleteTarget.relyingPartyName} deleted`);
      if (isWailsAvailable()) {
        const creds = await callBackend<BackendFIDO2Credential[]>('FIDO2Service', 'ListCredentials');
        if (creds) {
          setCredentials(creds.map(mapCredential));
        }
      }
      showDeleteConfirm = false;
      deleteTarget = null;
    }
  }

  async function handleEnableAuthenticator(): Promise<void> {
    if (isWailsAvailable()) {
      await callBackendVoid('AppService', 'ToggleFIDO2Authenticator', true);
      const status = await callBackend<FIDO2DeviceStatus>('FIDO2DeviceService', 'GetStatus');
      if (status) deviceStatus = status;
      if (status?.running) {
        addNotification('success', 'FIDO2 authenticator enabled');
      } else {
        addNotification('error', `Failed to enable: ${status?.reason || 'unknown error'}`);
      }
    }
  }

  async function handleFixUHID(): Promise<void> {
    if (isWailsAvailable()) {
      const ok = await callBackendVoid('FIDO2DeviceService', 'FixUHIDPermissions');
      if (ok) {
        // Try to start the authenticator now that permissions are fixed.
        await handleEnableAuthenticator();
        // Re-check status — if still not running, the user likely needs to
        // log out and back in for the new group membership to take effect.
        const status = await callBackend<FIDO2DeviceStatus>('FIDO2DeviceService', 'GetStatus');
        if (status && !status.running) {
          addNotification('warning', 'udev rule created and user added to input group. Please log out and log back in for the group change to take effect, then restart xKey.');
        }
      } else {
        addNotification('error', 'Failed to fix UHID permissions — privilege escalation may have been denied');
      }
    }
  }

  async function handleBridgeToggle(enabled: boolean): Promise<void> {
    if (!isWailsAvailable()) return;
    try {
      if (enabled) {
        await callBackendVoid('FIDO2Service', 'StartPhoneBridge');
        addNotification('success', 'Phone bridge started');
      } else {
        await callBackendVoid('FIDO2Service', 'StopPhoneBridge');
        addNotification('info', 'Phone bridge stopped');
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes('no server connection')) {
        addNotification('warning', 'Connect to an xkmsd server first');
      } else {
        addNotification('error', `Bridge error: ${msg}`);
      }
    }
  }

  // When the user selects a specific backend, set it as the default for new
  // credential creation so that WebAuthn MakeCredential uses the chosen backend.
  $: if (selectedBackend && selectedBackend !== 'all' && isWailsAvailable()) {
    callBackendVoid('FIDO2Service', 'SetDefaultBackend', selectedBackend).catch((err: unknown) => {
      console.debug('[FIDO2] SetDefaultBackend failed:', err);
    });
  }

  // Filter credentials by selected backend, then by search query (from store).
  $: visibleCredentials = selectedBackend === 'all'
    ? $fido2Credentials
    : $fido2Credentials.filter((c) => c.backendType === selectedBackend);

  // Group credentials by RP, respecting the active backend filter.
  $: rpGroups = (() => {
    const map = new Map<string, CredType[]>();
    for (const cred of visibleCredentials) {
      if (!map.has(cred.relyingPartyId)) {
        map.set(cred.relyingPartyId, []);
      }
      map.get(cred.relyingPartyId)!.push(cred);
    }
    return Array.from(map.entries()).map(([rpId, creds]) => ({
      rpId,
      rpName: creds[0].relyingPartyName,
      credentials: creds,
    }));
  })();
</script>

<div class="fido2-view" data-testid="fido2-view">
  <GradientHeader title="FIDO2" subtitle="WebAuthn credentials and phone bridge" />

  {#if deviceStatus}
    <div class="fido2-status-banner"
         class:banner-running={deviceStatus.running}
         class:banner-disabled={!deviceStatus.running && !deviceStatus.authenticator_available}
         class:banner-partial={!deviceStatus.running && deviceStatus.authenticator_available}
         data-testid="fido2-status-banner">
      <span class="banner-dot"></span>
      <span class="text-label-medium">
        {#if deviceStatus.running}
          Authenticator Running{deviceStatus.device_name ? ` — ${deviceStatus.device_name}` : ''}
        {:else if deviceStatus.authenticator_available}
          USB Device Unavailable — Authenticator available via browser extension
        {:else}
          Authenticator Disabled{#if deviceStatus.reason} — {deviceStatus.reason}{/if}
        {/if}
      </span>
      {#if !deviceStatus.running}
        <Button variant="text" size="sm" on:click={handleFixUHID} data-testid="fido2-fix-btn">
          Fix Permissions
        </Button>
        <Button variant="text" size="sm" on:click={handleEnableAuthenticator} data-testid="fido2-enable-btn">
          Retry
        </Button>
      {/if}
    </div>
    {#if !deviceStatus.running && deviceStatus.raw_reason?.includes('permission denied')}
      <div class="fido2-uhid-tip">
        <span class="text-body-small">/dev/uhid requires elevated permissions. Click <strong>Fix Permissions</strong> to create a udev rule automatically, or manually run: <code>sudo modprobe uhid && echo 'KERNEL=="uhid", SUBSYSTEM=="misc", MODE="0660", GROUP="input"' | sudo tee /etc/udev/rules.d/99-xkey-uhid.rules && sudo udevadm control --reload-rules && sudo udevadm trigger</code></span>
      </div>
    {/if}
  {/if}

  <div class="fido2-content">
    <Tabs {tabs} {activeTab} onChange={(id) => (activeTab = id)} />

    <div class="tab-content">
      {#if activeTab === 'credentials'}
        <div class="credentials-tab">
          <SearchBar
            placeholder="Search credentials..."
            value={searchQuery}
            onChange={handleSearch}
            data-testid="fido2-search"
          />
          <BackendSelector
            capability="fido2"
            bind:selected={selectedBackend}
            data-testid="fido2-backend-selector"
          />

          {#if visibleCredentials.length > 0}
            <div class="credential-list" data-testid="fido2-credential-list">
              {#each visibleCredentials as cred (cred.id)}
                <Card variant="outlined" hoverable on:click={() => viewCredential(cred)} data-testid="fido2-credential-card-{cred.id}">
                  <div class="credential-card">
                    <div class="cred-icon">
                      <Icon path={mdiShieldCheckOutline} size={24} />
                    </div>
                    <div class="cred-info">
                      <div class="cred-header-row">
                        <span class="text-title-small">{cred.relyingPartyName}</span>
                        <span class="text-body-small cred-domain">{cred.relyingPartyId}</span>
                      </div>
                      <span class="text-body-medium cred-user">{cred.userName}</span>
                      <div class="cred-meta">
                        <span class="text-label-small cred-badge">{cred.backendType}</span>
                        <span class="text-body-small cred-date">
                          Created {formatRelativeTime(cred.created)}
                        </span>
                        {#if cred.lastUsed}
                          <span class="text-body-small cred-date">
                            Used {formatRelativeTime(cred.lastUsed)}
                          </span>
                        {/if}
                      </div>
                    </div>
                    <div class="cred-actions" on:click|stopPropagation on:keydown|stopPropagation role="presentation">
                      <Button variant="text" size="sm" icon={mdiOpenInNew} on:click={() => openRP(cred.relyingPartyId)} data-testid="fido2-cred-login-{cred.id}">
                        Login
                      </Button>
                      <Button variant="text" size="sm" icon={mdiEye} on:click={() => viewCredential(cred)} data-testid="fido2-cred-details-{cred.id}">
                        Details
                      </Button>
                      <Button variant="text" size="sm" icon={mdiDelete} on:click={() => confirmDelete(cred)} data-testid="fido2-cred-delete-{cred.id}">
                        Delete
                      </Button>
                    </div>
                  </div>
                </Card>
              {/each}
            </div>
          {:else}
            <EmptyState
              icon={mdiShieldCheckOutline}
              title="No FIDO2 Credentials"
              description="Credentials will appear here when you register with websites using WebAuthn."
              data-testid="fido2-empty-credentials"
            />
          {/if}
        </div>

      {:else if activeTab === 'bridge'}
        <div class="bridge-tab">
          <BridgeStatus status={$bridgeStatus} onToggle={handleBridgeToggle} />
        </div>

      {:else if activeTab === 'relying-parties'}
        <div class="rp-tab">
          {#if rpGroups.length > 0}
            {#each rpGroups as rp}
              <Card variant="outlined" data-testid="fido2-rp-group-{rp.rpId}">
                <div class="rp-group">
                  <div class="rp-header">
                    <div class="rp-icon">
                      <Icon path={mdiConnection} size={20} />
                    </div>
                    <div class="rp-info">
                      <span class="text-title-small">{rp.rpName}</span>
                      <span class="text-body-small rp-domain">{rp.rpId}</span>
                    </div>
                    <span class="text-label-medium rp-count">{rp.credentials.length} credential(s)</span>
                  </div>
                  <div class="rp-creds">
                    {#each rp.credentials as cred}
                      <button class="rp-cred-row" on:click={() => viewCredential(cred)}>
                        <Icon path={mdiKey} size={16} />
                        <span class="text-body-medium">{cred.userName}</span>
                        <span class="text-body-small rp-cred-backend">{cred.backendType}</span>
                        <span class="text-body-small rp-cred-date">
                          {cred.lastUsed ? formatRelativeTime(cred.lastUsed) : 'Never used'}
                        </span>
                      </button>
                    {/each}
                  </div>
                </div>
              </Card>
            {/each}
          {:else}
            <EmptyState
              icon={mdiConnection}
              title="No Relying Parties"
              description="Relying parties will appear here when you register credentials with websites."
              data-testid="fido2-empty-rp"
            />
          {/if}
        </div>
      {/if}
    </div>
  </div>

  <Modal bind:open={showDeleteConfirm} title="Delete Credential?" maxWidth="400px" data-testid="fido2-delete-modal">
    <p class="text-body-medium">
      Are you sure you want to delete the credential for
      <strong>{deleteTarget?.relyingPartyName}</strong> ({deleteTarget?.userName})?
      This action cannot be undone.
    </p>
    <svelte:fragment slot="actions">
      <Button variant="text" on:click={() => (showDeleteConfirm = false)} data-testid="fido2-delete-cancel">Cancel</Button>
      <Button variant="danger" on:click={handleDelete} data-testid="fido2-delete-confirm">Delete</Button>
    </svelte:fragment>
  </Modal>
</div>

<style>
  .fido2-view {
    height: 100%;
    display: flex;
    flex-direction: column;
  }

  .fido2-status-banner {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 24px;
    font-weight: 500;
    flex-shrink: 0;
  }

  .fido2-status-banner.banner-running {
    background-color: var(--color-security-verified-container);
    color: var(--color-on-security-verified-container);
  }

  .fido2-status-banner.banner-disabled {
    background-color: var(--color-security-warning-container);
    color: var(--color-on-security-warning-container);
  }

  .fido2-status-banner.banner-partial {
    background: var(--md-sys-color-tertiary-container, #e8def8);
    color: var(--md-sys-color-on-tertiary-container, #1d192b);
  }
  .fido2-status-banner.banner-partial .banner-dot {
    background: var(--md-sys-color-tertiary, #7d5260);
  }

  .banner-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
  }

  .banner-running .banner-dot {
    background-color: var(--color-security-verified);
    animation: pulse-banner 2s ease-in-out infinite;
  }

  .banner-disabled .banner-dot {
    background-color: var(--color-security-warning);
  }

  .fido2-uhid-tip {
    padding: 4px 24px 4px 40px;
    background-color: var(--color-security-warning-container);
    color: var(--color-on-security-warning-container);
    font-style: italic;
  }

  @keyframes pulse-banner {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.4; }
  }

  .fido2-content {
    flex: 1;
    overflow: hidden;
    display: flex;
    flex-direction: column;
  }

  .tab-content {
    flex: 1;
    overflow-y: auto;
    padding: 24px;
  }

  .credentials-tab {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .credential-list {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .credential-card {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .cred-icon {
    width: 44px;
    height: 44px;
    border-radius: var(--radius-md);
    background: var(--gradient-tertiary);
    color: #FFFFFF;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  .cred-info {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }

  .cred-header-row {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .cred-header-row span:first-child {
    color: var(--color-on-surface);
  }

  .cred-domain {
    color: var(--color-on-surface-variant);
    font-family: var(--font-mono);
    font-size: 11px;
  }

  .cred-user {
    color: var(--color-on-surface);
  }

  .cred-meta {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }

  .cred-badge {
    padding: 2px 8px;
    border-radius: var(--radius-full);
    background-color: var(--color-surface-container-high);
    color: var(--color-on-surface-variant);
    text-transform: capitalize;
  }

  .cred-date {
    color: var(--color-on-surface-variant);
  }

  .cred-actions {
    display: flex;
    gap: 4px;
    flex-shrink: 0;
  }

  /* Bridge tab */
  .bridge-tab {
    max-width: 640px;
  }

  /* RP tab */
  .rp-tab {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .rp-group {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .rp-header {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .rp-icon {
    width: 36px;
    height: 36px;
    border-radius: 50%;
    background: var(--gradient-primary);
    color: #FFFFFF;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  .rp-info {
    flex: 1;
    display: flex;
    flex-direction: column;
  }

  .rp-info span:first-child {
    color: var(--color-on-surface);
  }

  .rp-domain {
    color: var(--color-on-surface-variant);
    font-family: var(--font-mono);
  }

  .rp-count {
    color: var(--color-on-surface-variant);
    flex-shrink: 0;
  }

  .rp-creds {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding-left: 48px;
  }

  .rp-cred-row {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 12px;
    border: none;
    background: transparent;
    border-radius: var(--radius-sm);
    cursor: pointer;
    transition: background-color var(--transition-fast);
    font-family: var(--font-sans);
    color: var(--color-on-surface);
    text-align: left;
    width: 100%;
  }

  .rp-cred-row:hover {
    background-color: var(--color-surface-container-low);
  }

  .rp-cred-backend {
    padding: 1px 6px;
    border-radius: var(--radius-full);
    background-color: var(--color-surface-container);
    color: var(--color-on-surface-variant);
    font-size: 11px;
  }

  .rp-cred-date {
    color: var(--color-on-surface-variant);
    margin-left: auto;
  }
</style>
