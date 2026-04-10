<script lang="ts">
  import Modal from './Modal.svelte';
  import Button from './Button.svelte';
  import { callBackendWithError } from '$lib/api/backend';
  import type { PIVGenerateKeyResult } from '$lib/api/backend';
  import { addNotification } from '$lib/stores/notifications';

  export let open: boolean = false;
  export let slotId: string = '';
  export let slotLabel: string = '';
  export let backend: string = 'software';
  export let onClose: () => void = () => {};
  export let onGenerated: () => void = () => {};

  const algorithms = [
    { value: 'ECCP256', label: 'ECDSA P-256' },
    { value: 'ECCP384', label: 'ECDSA P-384' },
    { value: 'Ed25519', label: 'Ed25519' },
    { value: 'RSA2048', label: 'RSA 2048' },
    { value: 'RSA4096', label: 'RSA 4096' },
  ];

  let selectedAlgorithm = 'ECCP256';
  let generating = false;

  $: if (open) {
    selectedAlgorithm = 'ECCP256';
    generating = false;
  }

  async function handleGenerate(): Promise<void> {
    generating = true;
    const { result, error } = await callBackendWithError<PIVGenerateKeyResult>('PIVService', 'GenerateKey', slotId, selectedAlgorithm);
    generating = false;

    if (result !== null) {
      addNotification('success', result.message);
      open = false;
      onGenerated();
    } else {
      addNotification('error', error || `Failed to generate key in slot ${slotId}`);
    }
  }

  function handleCancel(): void {
    open = false;
    onClose();
  }
</script>

<Modal bind:open title="Generate PIV Key" maxWidth="440px">
  <div class="generate-form" data-testid="piv-generate-dialog">
    <div class="form-info">
      <div class="info-row">
        <span class="text-label-medium info-label">Slot</span>
        <span class="text-body-medium" data-testid="piv-generate-slot-info">{slotId} -- {slotLabel}</span>
      </div>
      <div class="info-row">
        <span class="text-label-medium info-label">Backend</span>
        <span class="text-body-medium" data-testid="piv-generate-backend-info">{backend}</span>
      </div>
    </div>

    <div class="form-field">
      <label class="text-label-medium form-label" for="piv-algorithm">Algorithm</label>
      <select id="piv-algorithm" class="form-select" data-testid="piv-algorithm-select" bind:value={selectedAlgorithm} disabled={generating}>
        {#each algorithms as algo}
          <option value={algo.value}>{algo.label}</option>
        {/each}
      </select>
    </div>

    {#if selectedAlgorithm.startsWith('RSA')}
      <div class="form-notice" role="alert">
        <span class="text-body-small notice-text">
          RSA key generation may take several seconds depending on key size.
        </span>
      </div>
    {/if}

    {#if generating}
      <div class="generating-status" role="status" aria-live="polite">
        <svg class="status-spinner" viewBox="0 0 24 24" width="20" height="20" aria-hidden="true">
          <circle cx="12" cy="12" r="10" fill="none" stroke="var(--color-primary)" stroke-width="2" stroke-dasharray="31.4 31.4" />
        </svg>
        <span class="text-body-small">Generating {selectedAlgorithm} key pair and self-signed certificate...</span>
      </div>
    {/if}
  </div>

  <svelte:fragment slot="actions">
    <Button variant="text" on:click={handleCancel} disabled={generating}>Cancel</Button>
    <Button variant="primary" on:click={handleGenerate} loading={generating}>
      {generating ? 'Generating...' : 'Generate Key'}
    </Button>
  </svelte:fragment>
</Modal>

<style>
  .generate-form {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .form-info {
    padding: 12px 16px;
    background-color: var(--color-surface-container);
    border-radius: var(--radius-sm);
  }

  .info-row {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .info-label {
    color: var(--color-on-surface-variant);
    min-width: 48px;
  }

  .form-field {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .form-label {
    color: var(--color-on-surface-variant);
    padding-left: 4px;
  }

  .form-select {
    height: 48px;
    padding: 0 16px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-md);
    background-color: var(--color-surface-container-lowest);
    color: var(--color-on-surface);
    font-family: var(--font-sans);
    font-size: 14px;
    outline: none;
    cursor: pointer;
    transition: border-color var(--transition-fast);
  }

  .form-select:focus {
    border-color: var(--color-primary);
    box-shadow: 0 0 0 1px var(--color-primary);
  }

  .form-select:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .form-notice {
    padding: 10px 14px;
    background-color: var(--color-security-warning-container);
    border-radius: var(--radius-sm);
  }

  .notice-text {
    color: var(--color-on-security-warning-container);
  }

  .generating-status {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 14px;
    background-color: var(--color-surface-container);
    border-radius: var(--radius-sm);
    color: var(--color-on-surface-variant);
  }

  .status-spinner {
    animation: spin 0.8s linear infinite;
    flex-shrink: 0;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }
</style>
