<script lang="ts">
  import Modal from '$lib/components/Modal.svelte';
  import Button from '$lib/components/Button.svelte';
  import BackendSelector from '$lib/components/BackendSelector.svelte';
  import { addNotification } from '$lib/stores/notifications';
  import {
    isWailsAvailable,
    callBackend,
    callBackendWithError,
    type SSHKeyInfo,
  } from '$lib/api/backend';

  /**
   * Shared SSH-key generation dialog. This is the SINGLE generation path for
   * SSH keys — used by both the unified Keys view and the SSH application's
   * Keys tab. It mints a backend-bound key via SSHService.GenerateKey (the
   * private half stays in the chosen backend for hardware backends).
   */
  export let open = false;
  export let onClose: () => void = () => {};
  export let onGenerated: (key: SSHKeyInfo) => void = () => {};

  const allAlgorithms = [
    { value: 'ed25519', label: 'Ed25519' },
    { value: 'rsa', label: 'RSA' },
    { value: 'ecdsa-p256', label: 'ECDSA P-256' },
    { value: 'ecdsa-p384', label: 'ECDSA P-384' },
    { value: 'ecdsa-p521', label: 'ECDSA P-521' },
  ];
  const rsaBitOptions = [2048, 3072, 4096];

  let genName = '';
  let genAlgorithm = 'ed25519';
  let genRSABits = 2048;
  let genComment = '';
  /** Backend chosen via BackendSelector (signing-capable backends). */
  let genBackend = '';
  let generating = false;
  /** Bound BackendSelector instance, used to resolve genBackend's display name. */
  let backendSelector: BackendSelector;

  /**
   * Algorithms the currently selected backend can generate, per the Go
   * SSHService.SupportedAlgorithms (canonical algorithm/backend mapping —
   * see pkg/ssh/backend.SupportedAlgorithms). Defaults to the full set so
   * the dropdown is never empty before the backend answers.
   */
  let supportedValues: string[] = allAlgorithms.map((a) => a.value);
  $: algorithms = allAlgorithms.filter((a) => supportedValues.includes(a.value));

  /** Set when the selected algorithm was auto-switched because the newly
   * selected backend doesn't support it; cleared on the next backend change
   * that doesn't require a switch. */
  let switchedFromAlgorithm = '';
  let switchHintBackendLabel = '';

  // Reset fields and seed the default backend each time the dialog opens.
  let lastOpen = false;
  $: if (open !== lastOpen) {
    lastOpen = open;
    if (open) resetAndInit();
  }

  // Re-derive supported algorithms whenever the backend selection changes,
  // and auto-switch away from an algorithm the new backend can't generate.
  let lastBackendChecked = '';
  $: if (genBackend !== lastBackendChecked) {
    lastBackendChecked = genBackend;
    refreshSupportedAlgorithms(genBackend);
  }

  async function refreshSupportedAlgorithms(backendID: string): Promise<void> {
    switchedFromAlgorithm = '';
    if (!isWailsAvailable() || !backendID) {
      supportedValues = allAlgorithms.map((a) => a.value);
      return;
    }
    const supported = await callBackend<string[]>('SSHService', 'SupportedAlgorithms', backendID);
    supportedValues = supported && supported.length > 0 ? supported : allAlgorithms.map((a) => a.value);

    if (!supportedValues.includes(genAlgorithm)) {
      const previous = genAlgorithm;
      const fallback = allAlgorithms.find((a) => supportedValues.includes(a.value));
      if (fallback) {
        genAlgorithm = fallback.value;
        switchedFromAlgorithm = previous;
        const match = backendSelector?.getBackends().find((b) => b.id === backendID);
        switchHintBackendLabel = match?.display_name || backendID;
      }
    }
  }

  function algorithmLabel(value: string): string {
    return allAlgorithms.find((a) => a.value === value)?.label ?? value;
  }

  async function resetAndInit(): Promise<void> {
    genName = '';
    genAlgorithm = 'ed25519';
    genRSABits = 2048;
    genComment = '';
    supportedValues = allAlgorithms.map((a) => a.value);
    switchedFromAlgorithm = '';
    lastBackendChecked = '';
    if (isWailsAvailable()) {
      const def = await callBackend<string>('SSHService', 'GetDefaultBackend');
      if (def) genBackend = def;
    }
  }

  function close(): void {
    open = false;
    onClose();
  }

  async function handleGenerate(): Promise<void> {
    if (!genName.trim()) {
      addNotification('error', 'Key name is required');
      return;
    }
    generating = true;
    const params = {
      name: genName.trim(),
      algorithm: genAlgorithm,
      rsa_bits: genAlgorithm === 'rsa' ? genRSABits : 0,
      comment: genComment.trim(),
      backend: genBackend,
    };
    const { result, error } = await callBackendWithError<SSHKeyInfo>('SSHService', 'GenerateKey', params);
    generating = false;
    if (result) {
      addNotification('success', `SSH key "${result.name}" generated`);
      open = false;
      onGenerated(result);
    } else {
      addNotification('error', error ? `Failed to generate SSH key: ${error}` : 'Failed to generate SSH key');
    }
  }
</script>

<Modal bind:open title="Generate SSH Key" maxWidth="480px">
  <div class="form-fields">
    <div class="form-field">
      <label class="field-label text-label-medium" for="ssh-gen-name">Key Name</label>
      <input
        id="ssh-gen-name"
        class="text-input"
        type="text"
        placeholder="e.g., my-ssh-key"
        bind:value={genName}
      />
    </div>
    <div class="form-field">
      <label class="field-label text-label-medium" for="ssh-gen-algorithm">Algorithm</label>
      <select id="ssh-gen-algorithm" class="text-input select-input" bind:value={genAlgorithm}>
        {#each algorithms as algo (algo.value)}
          <option value={algo.value}>{algo.label}</option>
        {/each}
      </select>
      {#if switchedFromAlgorithm}
        <span class="field-hint field-hint-notice text-body-small" role="status">
          {algorithmLabel(switchedFromAlgorithm)} is not supported by {switchHintBackendLabel} — switched to {algorithmLabel(genAlgorithm)}.
        </span>
      {/if}
    </div>
    {#if genAlgorithm === 'rsa'}
      <div class="form-field">
        <label class="field-label text-label-medium" for="ssh-gen-rsa-bits">RSA Bits</label>
        <select id="ssh-gen-rsa-bits" class="text-input select-input" bind:value={genRSABits}>
          {#each rsaBitOptions as bits (bits)}
            <option value={bits}>{bits}</option>
          {/each}
        </select>
      </div>
    {/if}
    <div class="form-field">
      <label class="field-label text-label-medium" for="ssh-gen-comment">Comment (optional)</label>
      <input
        id="ssh-gen-comment"
        class="text-input"
        type="text"
        placeholder="e.g., user@hostname"
        bind:value={genComment}
      />
    </div>
    <div class="form-field">
      <span class="field-label text-label-medium">Backend</span>
      <BackendSelector
        bind:this={backendSelector}
        capability="signing"
        bind:selected={genBackend}
        showAll={false}
        on:change={(e) => { genBackend = e.detail; }}
      />
      <span class="field-hint text-body-small">
        The key's private half is created on and never leaves this backend
        (hardware backends keep it in the device).
      </span>
    </div>
  </div>
  <svelte:fragment slot="actions">
    <Button variant="outline" on:click={close}>Cancel</Button>
    <Button variant="primary" loading={generating} on:click={handleGenerate}>Generate</Button>
  </svelte:fragment>
</Modal>

<style>
  .form-fields {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .form-field {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .field-label {
    color: var(--color-on-surface-variant);
  }

  .text-input {
    height: 40px;
    padding: 0 12px;
    border: 1px solid var(--color-outline);
    border-radius: var(--radius-sm);
    background-color: var(--color-surface-container-high);
    color: var(--color-on-surface);
    font-family: var(--font-sans);
    font-size: 14px;
  }

  .text-input:focus {
    outline: none;
    border-color: var(--color-primary);
  }

  .select-input {
    cursor: pointer;
  }

  .field-hint {
    color: var(--color-on-surface-variant);
  }

  .field-hint-notice {
    color: var(--color-security-warning);
  }
</style>
