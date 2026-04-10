<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import Button from './Button.svelte';
  import Icon from './Icon.svelte';
  import {
    mdiClose, mdiFingerprint, mdiShieldCheckOutline, mdiExport,
    mdiDelete, mdiRefresh, mdiLockOutline, mdiKey
  } from '$lib/utils/icons';
  import { callBackend, callBackendVoid } from '$lib/api/backend';
  import { addNotification } from '$lib/stores/notifications';
  import type { RemoteKeyInfo } from '$lib/api/backend';

  export let open = false;
  export let key: RemoteKeyInfo | null = null;

  const dispatch = createEventDispatcher();

  function handleClose(): void {
    open = false;
    dispatch('close');
  }

  async function handleSign(): Promise<void> {
    if (!key) return;
    addNotification('info', `Sign operation for ${key.key_id} - use API directly`);
  }

  async function handleExport(): Promise<void> {
    if (!key) return;
    const result = await callBackend<string>('KeyService', 'ExportKey', key.backend, key.key_id, 'pem');
    if (result) {
      addNotification('success', `Key exported: ${key.key_id}`);
    }
  }

  async function handleRotate(): Promise<void> {
    if (!key) return;
    const result = await callBackend<RemoteKeyInfo>('KeyService', 'RotateKey', key.backend, key.key_id);
    if (result) {
      addNotification('success', `Key rotated: ${key.key_id}`);
      dispatch('refresh');
    }
  }

  async function handleAttest(): Promise<void> {
    if (!key) return;
    const result = await callBackend<unknown>('KeyService', 'AttestKey', key.backend, key.key_id, '');
    if (result) {
      addNotification('success', `Attestation complete for ${key.key_id}`);
    }
  }

  async function handleDelete(): Promise<void> {
    if (!key) return;
    await callBackendVoid('KeyService', 'DeleteKey', key.backend, key.key_id);
    addNotification('info', `Key deleted: ${key.key_id}`);
    dispatch('refresh');
    handleClose();
  }
</script>

{#if open && key}
  <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
  <div class="dialog-overlay" role="presentation" tabindex="-1" on:click={handleClose} on:keydown={(e) => e.key === 'Escape' && handleClose()}>
    <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
    <div class="dialog" on:click|stopPropagation on:keydown|stopPropagation role="dialog" aria-label="Key Details" aria-modal="true">
      <div class="dialog-header">
        <h2 class="text-title-large">Key Details</h2>
        <button class="dialog-close" on:click={handleClose}>
          <Icon path={mdiClose} size={20} />
        </button>
      </div>

      <div class="dialog-body">
        <div class="detail-row">
          <span class="text-label-small detail-label">KEY ID</span>
          <span class="text-body-medium font-mono">{key.key_id}</span>
        </div>
        <div class="detail-row">
          <span class="text-label-small detail-label">TYPE</span>
          <span class="text-body-medium">{key.key_type}</span>
        </div>
        <div class="detail-row">
          <span class="text-label-small detail-label">ALGORITHM</span>
          <span class="text-body-medium font-mono">{key.algorithm}</span>
        </div>
        <div class="detail-row">
          <span class="text-label-small detail-label">BACKEND</span>
          <span class="text-body-medium">{key.backend}</span>
        </div>
        {#if key.public_key_pem}
          <div class="detail-row">
            <span class="text-label-small detail-label">PUBLIC KEY</span>
            <pre class="public-key-pem">{key.public_key_pem}</pre>
          </div>
        {/if}
      </div>

      <div class="dialog-footer">
        <div class="action-grid">
          <Button variant="primary" icon={mdiFingerprint} on:click={handleSign}>Sign</Button>
          <Button variant="secondary" icon={mdiShieldCheckOutline} on:click={handleAttest}>Attest</Button>
          <Button variant="outline" icon={mdiExport} on:click={handleExport}>Export</Button>
          <Button variant="outline" icon={mdiRefresh} on:click={handleRotate}>Rotate</Button>
          <Button variant="outline" icon={mdiDelete} on:click={handleDelete}>Delete</Button>
        </div>
      </div>
    </div>
  </div>
{/if}

<style>
  .dialog-overlay {
    position: fixed;
    inset: 0;
    background-color: rgba(0, 0, 0, 0.5);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
  }

  .dialog {
    background-color: var(--color-surface-container-lowest);
    border-radius: var(--radius-xl);
    width: 520px;
    max-width: 90vw;
    max-height: 85vh;
    overflow-y: auto;
    box-shadow: var(--elevation-3);
  }

  .dialog-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 24px 24px 16px;
  }

  .dialog-header h2 {
    margin: 0;
    color: var(--color-on-surface);
  }

  .dialog-close {
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
  }

  .dialog-close:hover {
    background-color: var(--color-surface-variant);
  }

  .dialog-body {
    padding: 0 24px;
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .detail-row {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .detail-label {
    color: var(--color-on-surface-variant);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .public-key-pem {
    margin: 0;
    padding: 12px;
    background-color: var(--color-surface-container);
    border-radius: var(--radius-sm);
    font-family: var(--font-mono);
    font-size: 11px;
    color: var(--color-on-surface);
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-all;
  }

  .dialog-footer {
    padding: 24px;
  }

  .action-grid {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
  }
</style>
