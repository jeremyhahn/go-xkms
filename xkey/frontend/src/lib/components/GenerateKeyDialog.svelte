<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import Card from './Card.svelte';
  import Button from './Button.svelte';
  import Input from './Input.svelte';
  import Icon from './Icon.svelte';
  import { mdiClose, mdiKeyPlus } from '$lib/utils/icons';
  import { callBackend, isWailsAvailable } from '$lib/api/backend';
  import { addNotification } from '$lib/stores/notifications';
  import type { RemoteBackendInfo, GenerateKeyParams, GenerateKeyResult, SupportedKeyTypes } from '$lib/api/backend';

  export let open = false;
  export let backends: RemoteBackendInfo[] = [];

  const dispatch = createEventDispatcher();

  let keyId = '';
  let backend = '';
  let keyType = 'ecdsa';
  let keySize = 256;
  let curve = 'P-256';
  let exportable = false;
  let generating = false;
  let supportedTypes: SupportedKeyTypes | null = null;

  const defaultKeyTypes = ['rsa', 'ecdsa', 'ed25519', 'aes'];
  const defaultCurves = ['P-256', 'P-384', 'P-521'];
  const rsaSizes = [2048, 3072, 4096];
  const aesSizes = [128, 192, 256];

  $: keyTypes = supportedTypes?.algorithms.map(a => a.toLowerCase()) || defaultKeyTypes;
  $: curves = supportedTypes?.curves || defaultCurves;
  $: showCurve = keyType === 'ecdsa';
  $: showKeySize = keyType === 'rsa' || keyType === 'aes';
  $: showMlKemSizes = keyType === 'ml-kem';

  // Fetch supported key types when backend changes.
  $: if (backend && isWailsAvailable()) {
    fetchSupportedTypes(backend);
  }

  async function fetchSupportedTypes(backendId: string): Promise<void> {
    supportedTypes = await callBackend<SupportedKeyTypes>('KeyService', 'GetSupportedKeyTypes', 'local', backendId);
    // Reset key type if current selection is not supported.
    if (supportedTypes && !supportedTypes.algorithms.map(a => a.toLowerCase()).includes(keyType)) {
      keyType = supportedTypes.algorithms[0]?.toLowerCase() || 'ecdsa';
    }
  }

  async function handleGenerate(): Promise<void> {
    if (!keyId || !backend) return;
    generating = true;
    const params: GenerateKeyParams = {
      key_id: keyId,
      backend,
      key_type: keyType,
      exportable,
    };
    if (showCurve) params.curve = curve;
    if (showKeySize) params.key_size = keySize;

    const result = await callBackend<GenerateKeyResult>('KeyService', 'GenerateKey', params);
    generating = false;
    if (result) {
      addNotification('success', `Key generated: ${result.key_id}`);
      dispatch('generated', result);
      handleClose();
    } else {
      addNotification('error', 'Key generation failed');
    }
  }

  function handleClose(): void {
    keyId = '';
    backend = '';
    keyType = 'ecdsa';
    exportable = false;
    open = false;
    dispatch('close');
  }
</script>

{#if open}
  <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
  <div class="dialog-overlay" role="presentation" tabindex="-1" on:click={handleClose} on:keydown={(e) => e.key === 'Escape' && handleClose()}>
    <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
    <div class="dialog" on:click|stopPropagation on:keydown|stopPropagation role="dialog" aria-label="Generate Key" aria-modal="true">
      <div class="dialog-header">
        <h2 class="text-title-large">Generate Key</h2>
        <button class="dialog-close" on:click={handleClose}>
          <Icon path={mdiClose} size={20} />
        </button>
      </div>

      <div class="dialog-body">
        <div class="form-field">
          <label class="text-label-large" for="gen-key-id">Key ID</label>
          <Input id="gen-key-id" placeholder="my-signing-key" bind:value={keyId} monospace />
        </div>

        <div class="form-field">
          <label class="text-label-large" for="gen-backend">Backend</label>
          <select class="form-select" id="gen-backend" bind:value={backend}>
            <option value="">Select backend...</option>
            {#each backends as b}
              <option value={b.id}>{b.id} ({b.type})</option>
            {/each}
          </select>
        </div>

        <div class="form-field">
          <label class="text-label-large" for="gen-key-type">Key Type</label>
          <select class="form-select" id="gen-key-type" bind:value={keyType}>
            {#each keyTypes as kt}
              <option value={kt}>{kt.toUpperCase()}</option>
            {/each}
          </select>
        </div>

        {#if showCurve}
          <div class="form-field">
            <label class="text-label-large" for="gen-curve">Curve</label>
            <select class="form-select" id="gen-curve" bind:value={curve}>
              {#each curves as c}
                <option value={c}>{c}</option>
              {/each}
            </select>
          </div>
        {/if}

        {#if showKeySize}
          <div class="form-field">
            <label class="text-label-large" for="gen-size">Key Size</label>
            <select class="form-select" id="gen-size" bind:value={keySize}>
              {#each (keyType === 'rsa' ? rsaSizes : aesSizes) as size}
                <option value={size}>{size} bits</option>
              {/each}
            </select>
          </div>
        {/if}

        {#if showMlKemSizes}
          <div class="form-field">
            <label class="text-label-large" for="gen-mlkem-size">Security Level</label>
            <select class="form-select" id="gen-mlkem-size" bind:value={keySize}>
              <option value={512}>ML-KEM-512 (128-bit security)</option>
              <option value={768}>ML-KEM-768 (192-bit security)</option>
              <option value={1024}>ML-KEM-1024 (256-bit security)</option>
            </select>
          </div>
        {/if}

        <div class="form-field-inline">
          <label class="text-label-large" for="gen-export">Exportable</label>
          <input type="checkbox" id="gen-export" bind:checked={exportable} />
        </div>
      </div>

      <div class="dialog-footer">
        <Button variant="outline" on:click={handleClose}>Cancel</Button>
        <Button variant="primary" icon={mdiKeyPlus} on:click={handleGenerate} disabled={!keyId || !backend || generating}>
          {generating ? 'Generating...' : 'Generate'}
        </Button>
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
    width: 480px;
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

  .form-field {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .form-field label {
    color: var(--color-on-surface);
  }

  .form-field-inline {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .form-field-inline label {
    color: var(--color-on-surface);
  }

  .form-select {
    height: 44px;
    padding: 0 12px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    background-color: var(--color-surface-container-lowest);
    color: var(--color-on-surface);
    font-family: var(--font-sans);
    font-size: 14px;
    outline: none;
    cursor: pointer;
  }

  .form-select:focus {
    border-color: var(--color-primary);
  }

  .dialog-footer {
    display: flex;
    justify-content: flex-end;
    gap: 12px;
    padding: 24px;
  }
</style>
