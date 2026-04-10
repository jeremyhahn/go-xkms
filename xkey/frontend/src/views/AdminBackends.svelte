<script lang="ts">
  import { onMount } from 'svelte';
  import Card from '$lib/components/Card.svelte';
  import Button from '$lib/components/Button.svelte';
  import StatusBadge from '$lib/components/StatusBadge.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
  import {
    mdiArrowLeft, mdiKey, mdiChip, mdiShieldCheckOutline, mdiCellphone, mdiCloudOutline, mdiCog,
    mdiCheck, mdiClose, mdiShieldKey, mdiLock, mdiFileSign, mdiAtom, mdiAccountGroup, mdiPencil
  } from '$lib/utils/icons';
  import { navigateTo } from '$lib/stores/app';
  import { isWailsAvailable, callBackend } from '$lib/api/backend';
  import type { BackendBackendInfo, BackendCapabilityInfo } from '$lib/api/backend';

  interface BackendDetail {
    id: string;
    name: string;
    type: string;
    status: 'connected' | 'disconnected' | 'error';
    keyCount: number;
    icon: string;
    description: string;
    config: Array<{ key: string; value: string }>;
    algorithms: string[];
    capabilities: BackendCapabilityInfo;
  }

  let backends: BackendDetail[] = [];
  let loading = true;
  let defaultBackend = '';
  let settingDefault = '';
  let editingId = '';
  let editName = '';

  const iconMap: Record<string, string> = {
    software: mdiKey,
    tpm2: mdiChip,
    pkcs11: mdiShieldCheckOutline,
    phone: mdiCellphone,
    awskms: mdiCloudOutline,
    gcpkms: mdiCloudOutline,
    azurekv: mdiCloudOutline,
    vault: mdiCloudOutline,
    threshold: mdiAccountGroup,
    frost: mdiAccountGroup,
    quantum: mdiAtom,
  };

  onMount(async () => {
    if (isWailsAvailable()) {
      // Get default backend
      const defaultId = await callBackend<string>('AdminService', 'GetDefaultBackend');
      if (defaultId) {
        defaultBackend = defaultId;
      }

      const backendList = await callBackend<BackendBackendInfo[]>('AdminService', 'ListBackends');
      if (backendList) {
        backends = backendList
          .filter(b => b.enabled)
          .map(b => {
            const config: Array<{ key: string; value: string }> = [];
            if (b.metadata) {
              for (const [key, value] of Object.entries(b.metadata)) {
                config.push({ key: formatConfigKey(key), value: value || 'N/A' });
              }
            }
            return {
              id: b.id,
              name: b.display_name || b.id,
              type: b.type,
              status: b.connected ? 'connected' : 'disconnected',
              keyCount: b.key_count,
              icon: iconMap[b.type] || mdiKey,
              description: b.description,
              config,
              algorithms: b.algorithms || [],
              capabilities: b.capabilities || {},
            };
          });
      }
    }
    loading = false;
  });

  function formatConfigKey(key: string): string {
    return key
      .split('_')
      .map(word => word.charAt(0).toUpperCase() + word.slice(1))
      .join(' ');
  }

  async function setAsDefault(backendId: string): Promise<void> {
    settingDefault = backendId;
    try {
      await callBackend('AdminService', 'SetDefaultBackend', backendId);
      defaultBackend = backendId;
    } catch (err) {
      console.error('Failed to set default backend:', err);
    } finally {
      settingDefault = '';
    }
  }

  function startRename(backend: BackendDetail): void {
    editingId = backend.id;
    editName = backend.name;
  }

  function cancelRename(): void {
    editingId = '';
    editName = '';
  }

  async function saveRename(backendId: string): Promise<void> {
    const trimmed = editName.trim();
    if (!trimmed) {
      cancelRename();
      return;
    }
    await callBackend('AdminService', 'RenameBackend', backendId, trimmed);
    const idx = backends.findIndex(b => b.id === backendId);
    if (idx >= 0) {
      backends[idx].name = trimmed;
      backends = backends;
    }
    cancelRename();
  }

  // Helper to get capability display items
  function getCapabilityItems(caps: BackendCapabilityInfo): Array<{ name: string; enabled: boolean; icon: string }> {
    return [
      { name: 'Signing', enabled: caps.signing || false, icon: mdiFileSign },
      { name: 'Encryption', enabled: caps.encryption || false, icon: mdiLock },
      { name: 'Decryption', enabled: caps.decryption || false, icon: mdiLock },
      { name: 'Key Encapsulation', enabled: caps.key_encapsulation || false, icon: mdiKey },
      { name: 'Sealing', enabled: caps.sealing || false, icon: mdiShieldKey },
      { name: 'Attestation', enabled: caps.attestation || false, icon: mdiShieldCheckOutline },
      { name: 'Hardware Backed', enabled: caps.hardware_backed || false, icon: mdiChip },
      { name: 'Quantum Signing', enabled: caps.quantum_signing || false, icon: mdiAtom },
    ].filter(c => c.enabled); // Only show enabled capabilities
  }
</script>

<div class="backends-view">
  <div class="detail-header">
    <button class="back-btn" on:click={() => navigateTo('admin')}>
      <Icon path={mdiArrowLeft} size={20} />
      <span class="text-label-large">Administration</span>
    </button>
    <h1 class="text-headline-small detail-title">Cryptographic Backends</h1>
  </div>

  <div class="detail-content">
    {#if loading}
      <div class="loading-state">
        <LoadingSpinner size={48} />
        <span class="text-body-medium">Loading backends...</span>
      </div>
    {:else if backends.length === 0}
      <Card variant="outlined">
        <div class="empty-state">
          <span class="text-body-medium">No backends configured</span>
        </div>
      </Card>
    {:else}
      {#each backends as backend}
        <Card variant={backend.status === 'connected' ? 'elevated' : 'outlined'}>
          <div class="backend-detail">
          <div class="backend-header">
            <div class="backend-icon" class:active={backend.status === 'connected'}>
              <Icon path={backend.icon} size={28} />
            </div>
            <div class="backend-header-info">
              <div class="backend-name-row">
                {#if editingId === backend.id}
                  <input
                    class="rename-input text-title-large"
                    bind:value={editName}
                    on:keydown={(e) => {
                      if (e.key === 'Enter') saveRename(backend.id);
                      if (e.key === 'Escape') cancelRename();
                    }}
                  />
                  <Button variant="text" size="sm" icon={mdiCheck} on:click={() => saveRename(backend.id)} />
                  <Button variant="text" size="sm" icon={mdiClose} on:click={cancelRename} />
                {:else}
                  <h2 class="text-title-large">{backend.name}</h2>
                  {#if backend.type === 'pkcs11' || backend.type === 'awskms' || backend.type === 'gcpkms' || backend.type === 'azurekv' || backend.type === 'vault'}
                    <button class="rename-btn" title="Rename backend" on:click|stopPropagation={() => startRename(backend)}>
                      <Icon path={mdiPencil} size={16} />
                    </button>
                  {/if}
                {/if}
                <StatusBadge status={backend.status} />
                {#if backend.id === defaultBackend || backend.type === defaultBackend}
                  <span class="default-badge">
                    <Icon path={mdiCheck} size={12} />
                    Active Default
                  </span>
                {:else if backend.status === 'connected'}
                  <button
                    class="set-default-btn"
                    disabled={settingDefault !== ''}
                    on:click|stopPropagation={() => setAsDefault(backend.id)}
                  >
                    {#if settingDefault === backend.id}
                      Setting...
                    {:else}
                      Set as Default
                    {/if}
                  </button>
                {/if}
              </div>
              <span class="text-body-small backend-type font-mono">{backend.type}</span>
            </div>
            <div class="backend-key-count">
              <span class="text-display-small count-number">{backend.keyCount}</span>
              <span class="text-label-small count-label">keys</span>
            </div>
          </div>

          <p class="text-body-medium backend-desc">{backend.description}</p>

          <!-- Capabilities -->
          {#if getCapabilityItems(backend.capabilities).length > 0}
            <div class="backend-section">
              <h3 class="text-title-small section-subheading">
                <Icon path={mdiShieldKey} size={18} />
                Capabilities
              </h3>
              <div class="capability-chips">
                {#each getCapabilityItems(backend.capabilities) as cap}
                  <span class="capability-chip">
                    <Icon path={cap.icon} size={14} />
                    {cap.name}
                  </span>
                {/each}
              </div>
            </div>
          {/if}

          <!-- Configuration -->
          {#if backend.config.length > 0}
            <div class="backend-section">
              <h3 class="text-title-small section-subheading">
                <Icon path={mdiCog} size={18} />
                Configuration
              </h3>
              <div class="config-table">
                {#each backend.config as cfg}
                  <div class="config-row">
                    <span class="text-label-medium config-key">{cfg.key}</span>
                    <span class="text-body-medium config-value">{cfg.value}</span>
                  </div>
                {/each}
              </div>
            </div>
          {/if}

          <!-- Supported Algorithms -->
          {#if backend.algorithms.length > 0}
            <div class="backend-section">
              <h3 class="text-title-small section-subheading">Supported Algorithms</h3>
              <div class="algo-chips">
                {#each backend.algorithms as algo}
                  <span class="algo-chip text-label-small">{algo}</span>
                {/each}
              </div>
            </div>
          {/if}
        </div>
      </Card>
      {/each}
    {/if}
  </div>
</div>

<style>
  .backends-view {
    height: 100%;
    display: flex;
    flex-direction: column;
  }

  .detail-header {
    padding: 16px 24px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    border-bottom: 1px solid var(--color-outline-variant);
    flex-shrink: 0;
  }

  .back-btn {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    border: none;
    background: transparent;
    color: var(--color-primary);
    cursor: pointer;
    font-family: var(--font-sans);
    padding: 4px 0;
    align-self: flex-start;
    transition: opacity var(--transition-fast);
  }

  .back-btn:hover { opacity: 0.8; }

  .detail-title { margin: 0; color: var(--color-on-surface); }

  .detail-content {
    flex: 1;
    overflow-y: auto;
    padding: 24px;
    display: flex;
    flex-direction: column;
    gap: 20px;
    max-width: 900px;
  }

  .backend-detail {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .backend-header {
    display: flex;
    align-items: center;
    gap: 16px;
  }

  .backend-icon {
    width: 56px;
    height: 56px;
    border-radius: var(--radius-lg);
    background-color: var(--color-surface-container-high);
    color: var(--color-on-surface-variant);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  .backend-icon.active {
    background: var(--gradient-primary);
    color: #FFFFFF;
  }

  .backend-header-info {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .backend-name-row {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .backend-name-row h2 {
    margin: 0;
    color: var(--color-on-surface);
  }

  .backend-type {
    color: var(--color-on-surface-variant);
  }

  .backend-key-count {
    display: flex;
    flex-direction: column;
    align-items: center;
    flex-shrink: 0;
  }

  .count-number {
    color: var(--color-primary);
    font-weight: 600;
    line-height: 1;
  }

  .count-label {
    color: var(--color-on-surface-variant);
    text-transform: uppercase;
  }

  .backend-desc {
    color: var(--color-on-surface-variant);
    margin: 0;
    line-height: 1.5;
  }

  .backend-section {
    display: flex;
    flex-direction: column;
    gap: 12px;
    padding-top: 8px;
    border-top: 1px solid var(--color-outline-variant);
  }

  .section-subheading {
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 0;
    color: var(--color-on-surface);
  }

  .config-table {
    display: flex;
    flex-direction: column;
  }

  .config-row {
    display: flex;
    align-items: center;
    padding: 8px 0;
  }

  .config-row + .config-row {
    border-top: 1px solid var(--color-surface-variant);
  }

  .config-key {
    width: 180px;
    flex-shrink: 0;
    color: var(--color-on-surface-variant);
  }

  .config-value {
    color: var(--color-on-surface);
  }

  .algo-chips {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }

  .algo-chip {
    padding: 4px 12px;
    border-radius: var(--radius-full);
    background-color: var(--color-surface-container);
    color: var(--color-on-surface);
    font-family: var(--font-mono);
  }

  .capability-chips {
    display: flex;
    flex-wrap: wrap;
    gap: 8px;
  }

  .capability-chip {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 6px 12px;
    border-radius: var(--radius-full);
    background-color: var(--color-primary-container);
    color: var(--color-on-primary-container);
    font-size: 13px;
    font-weight: 500;
  }

  .default-badge {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 2px 10px;
    border-radius: var(--radius-full);
    background: var(--gradient-primary);
    color: #FFFFFF;
    font-size: 11px;
    font-weight: 600;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .set-default-btn {
    padding: 4px 12px;
    border-radius: var(--radius-full);
    border: 1px solid var(--color-outline);
    background: transparent;
    color: var(--color-primary);
    font-size: 12px;
    font-weight: 500;
    cursor: pointer;
    font-family: var(--font-sans);
    transition: all var(--transition-fast);
  }

  .set-default-btn:hover:not(:disabled) {
    background-color: var(--color-primary-container);
    border-color: var(--color-primary);
  }

  .set-default-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .loading-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 16px;
    padding: 48px;
    color: var(--color-on-surface-variant);
  }

  .empty-state {
    padding: 32px;
    text-align: center;
    color: var(--color-on-surface-variant);
  }

  .rename-input {
    border: none;
    border-bottom: 2px solid var(--color-primary);
    background: transparent;
    color: var(--color-on-surface);
    font-family: var(--font-sans);
    outline: none;
    padding: 2px 4px;
    min-width: 200px;
  }

  .rename-btn {
    display: inline-flex;
    align-items: center;
    border: none;
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    padding: 4px;
    border-radius: var(--radius-sm);
    opacity: 0;
    transition: opacity var(--transition-fast);
  }

  .backend-name-row:hover .rename-btn {
    opacity: 0.7;
  }

  .rename-btn:hover {
    opacity: 1 !important;
    color: var(--color-primary);
    background-color: var(--color-surface-container);
  }
</style>
