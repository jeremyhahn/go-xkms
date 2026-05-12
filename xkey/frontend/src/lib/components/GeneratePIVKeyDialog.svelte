<script lang="ts">
  import Modal from './Modal.svelte';
  import Input from './Input.svelte';
  import Button from './Button.svelte';
  import { callBackend, callBackendWithError } from '$lib/api/backend';
  import type { IdentityConfig, PIVGenerateOptions, PIVGenerateAdvancedResult, PIVCAAvailability } from '$lib/api/backend';
  import { addNotification } from '$lib/stores/notifications';

  export let open: boolean = false;
  export let slotId: string = '';
  export let slotLabel: string = '';
  export let backend: string = 'software';
  export let onClose: () => void = () => {};
  export let onGenerated: () => void = () => {};

  const allAlgorithms = [
    { value: 'ECCP256', label: 'ECDSA P-256' },
    { value: 'ECCP384', label: 'ECDSA P-384' },
    { value: 'Ed25519', label: 'Ed25519' },
    { value: 'RSA2048', label: 'RSA 2048' },
    { value: 'RSA4096', label: 'RSA 4096' },
  ];

  // Ed25519 is not supported by YubiKey PIV; filter it out for PKCS#11 backends.
  $: isYubiKeyBackend = backend === 'pkcs11' || backend.toLowerCase().includes('yubikey');
  $: algorithms = isYubiKeyBackend
    ? allAlgorithms.filter(a => a.value !== 'Ed25519')
    : allAlgorithms;

  const outputFormats = [
    { value: 'self-signed', label: 'Self-Signed Certificate' },
    { value: 'public-key', label: 'Public Key Only' },
    { value: 'csr', label: 'Certificate Signing Request (CSR)' },
    { value: 'ca-signed', label: 'CA-Signed Certificate' },
  ];

  let selectedAlgorithm = 'ECCP256';
  let selectedOutputFormat = 'self-signed';
  let commonName = '';
  let organization = '';
  let country = '';
  let validityDays: number = 3650;
  let caSource = 'local';
  let showAdvancedSubject = false;
  let generating = false;
  let copied = false;

  let caAvailability: PIVCAAvailability = { local: false, remote: false };
  let caAvailabilityLoaded = false;

  // Result state for PEM output formats
  let generationResult: PIVGenerateAdvancedResult | null = null;

  $: showValidity = selectedOutputFormat === 'self-signed' || selectedOutputFormat === 'ca-signed';
  $: showCASource = selectedOutputFormat === 'ca-signed';
  $: showPEMResult = generationResult !== null && (selectedOutputFormat === 'public-key' || selectedOutputFormat === 'csr');
  $: pemOutput = generationResult?.public_key_pem || generationResult?.csr_pem || '';

  $: if (selectedOutputFormat === 'self-signed') {
    validityDays = 3650;
  } else if (selectedOutputFormat === 'ca-signed') {
    validityDays = 1095;
  }

  let prevOpen = false;
  $: if (open !== prevOpen) {
    prevOpen = open;
    if (open) {
      // Defer to a microtask so dependent reactives (showCASource, etc.)
      // re-run after resetForm mutates state. Without this, Svelte batches
      // the write and dependent reactives see stale values.
      Promise.resolve().then(() => {
        resetForm();
        loadDefaults();
      });
    }
  }

  // When switching to a backend that doesn't support the selected algorithm, reset to ECCP256.
  $: if (isYubiKeyBackend && selectedAlgorithm === 'Ed25519') {
    selectedAlgorithm = 'ECCP256';
  }

  function resetForm(): void {
    selectedAlgorithm = 'ECCP256';
    selectedOutputFormat = 'self-signed';
    commonName = '';
    organization = '';
    country = '';
    validityDays = 3650;
    caSource = 'local';
    showAdvancedSubject = false;
    generating = false;
    copied = false;
    generationResult = null;
    caAvailabilityLoaded = false;
    caAvailability = { local: false, remote: false };
  }

  async function loadDefaults(): Promise<void> {
    const identity = await callBackend<IdentityConfig>('AppService', 'GetIdentity');
    if (identity) {
      commonName = identity.common_name || '';
      organization = identity.organization || '';
      country = identity.country || '';
    }

    const availability = await callBackend<PIVCAAvailability>('PIVService', 'GetCAAvailability');
    if (availability) {
      caAvailability = availability;
    }
    caAvailabilityLoaded = true;

    // Default to the first available CA source if ca-signed is selected
    if (!caAvailability.local && caAvailability.remote) {
      caSource = 'remote';
    }
  }

  async function handleGenerate(): Promise<void> {
    generating = true;
    generationResult = null;

    const options: PIVGenerateOptions = {
      slot: slotId,
      algorithm: selectedAlgorithm,
      subject: commonName,
      organization,
      country,
      output_format: selectedOutputFormat,
      validity_days: validityDays,
      ca_source: caSource,
    };

    const { result, error } = await callBackendWithError<PIVGenerateAdvancedResult>(
      'PIVService',
      'GenerateKeyAdvanced',
      options,
    );
    generating = false;

    if (result !== null) {
      addNotification('success', result.message);
      if (selectedOutputFormat === 'public-key' || selectedOutputFormat === 'csr') {
        generationResult = result;
        // Stay open to show the PEM output
      } else {
        open = false;
        onGenerated();
      }
    } else {
      addNotification('error', error || `Failed to generate key in slot ${slotId}`);
    }
  }

  async function handleCopy(): Promise<void> {
    try {
      await navigator.clipboard.writeText(pemOutput);
      copied = true;
      setTimeout(() => { copied = false; }, 1500);
    } catch {
      addNotification('error', 'Failed to copy to clipboard');
    }
  }

  async function handleSave(): Promise<void> {
    const ext = selectedOutputFormat === 'csr' ? 'csr' : 'public';
    const suggested = `slot-${slotId.toLowerCase()}-${ext}.pem`;
    const { result, error } = await callBackendWithError<string>('AppService', 'SavePEMFile', suggested, pemOutput);
    if (result) {
      addNotification('success', `Saved to ${result}`);
    } else if (error) {
      addNotification('error', error);
    }
  }

  function handleDone(): void {
    open = false;
    if (generationResult) {
      onGenerated();
    } else {
      onClose();
    }
  }

  function handleCancel(): void {
    open = false;
    onClose();
  }
</script>

<Modal bind:open title="Generate PIV Key" maxWidth="520px">
  <div class="generate-form" data-testid="piv-generate-dialog">
    <!-- Slot / Backend info -->
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

    <!-- Subject -->
    <div class="form-section" data-testid="piv-subject-section">
      <Input
        label="Common Name"
        placeholder="e.g. John Smith"
        bind:value={commonName}
        disabled={generating}
      />

      <button
        type="button"
        class="collapse-toggle text-label-medium"
        on:click={() => (showAdvancedSubject = !showAdvancedSubject)}
        aria-expanded={showAdvancedSubject}
        disabled={generating}
      >
        <span class="collapse-arrow" class:expanded={showAdvancedSubject}>&#9654;</span>
        Advanced Subject
      </button>

      {#if showAdvancedSubject}
        <div class="advanced-subject">
          <Input
            label="Organization"
            placeholder="e.g. Acme Corp"
            bind:value={organization}
            disabled={generating}
          />
          <Input
            label="Country (ISO 3166-1 alpha-2)"
            placeholder="e.g. US"
            bind:value={country}
            disabled={generating}
          />
        </div>
      {/if}
    </div>

    <!-- Algorithm -->
    <div class="form-field">
      <label class="text-label-medium form-label" for="piv-algorithm">Algorithm</label>
      <select
        id="piv-algorithm"
        class="form-select"
        data-testid="piv-algorithm-select"
        bind:value={selectedAlgorithm}
        disabled={generating}
      >
        {#each algorithms as algo}
          <option value={algo.value}>{algo.label}</option>
        {/each}
      </select>
    </div>

    <!-- Output Format -->
    <div class="form-field">
      <label class="text-label-medium form-label" for="piv-output-format">Output Format</label>
      <select
        id="piv-output-format"
        class="form-select"
        data-testid="piv-output-format-select"
        bind:value={selectedOutputFormat}
        disabled={generating}
      >
        {#each outputFormats as fmt}
          <option value={fmt.value}>{fmt.label}</option>
        {/each}
      </select>
    </div>

    <!-- Validity (conditional) -->
    {#if showValidity}
      <div class="form-field" data-testid="piv-validity-section">
        <Input
          label="Validity (days)"
          type="number"
          placeholder="3650"
          bind:value={validityDays}
          disabled={generating}
        />
      </div>
    {/if}

    <!-- CA Source (conditional) -->
    {#if showCASource}
      <div class="form-field" data-testid="piv-ca-source-section">
        <span class="text-label-medium form-label">CA Source</span>
        <div class="radio-group" role="radiogroup" aria-label="CA Source">
          <label
            class="radio-option"
            class:radio-disabled={!caAvailability.local}
            aria-disabled={!caAvailability.local}
          >
            <input
              type="radio"
              name="ca-source"
              value="local"
              bind:group={caSource}
              disabled={generating || !caAvailability.local}
            />
            <span class="text-body-medium">Local CA</span>
            {#if caAvailabilityLoaded && !caAvailability.local}
              <span class="radio-reason text-body-small">CA not configured</span>
            {/if}
          </label>
          <label
            class="radio-option"
            class:radio-disabled={!caAvailability.remote}
            aria-disabled={!caAvailability.remote}
          >
            <input
              type="radio"
              name="ca-source"
              value="remote"
              bind:group={caSource}
              disabled={generating || !caAvailability.remote}
            />
            <span class="text-body-medium">Remote xkms Server</span>
            {#if caAvailabilityLoaded && !caAvailability.remote}
              <span class="radio-reason text-body-small">Not connected</span>
            {/if}
          </label>
        </div>
      </div>
    {/if}

    <!-- RSA warning -->
    {#if selectedAlgorithm.startsWith('RSA')}
      <div class="form-notice" role="alert">
        <span class="text-body-small notice-text">
          RSA key generation may take several seconds on hardware tokens.
        </span>
      </div>
    {/if}

    <!-- YubiKey Ed25519 note -->
    {#if isYubiKeyBackend}
      <div class="form-notice form-notice-info" role="note" data-testid="piv-yubikey-ed25519-note">
        <span class="text-body-small notice-text-info">
          YubiKey PIV supports ECDSA P-256/P-384 and RSA. Ed25519 is only available via FIDO2.
        </span>
      </div>
    {/if}

    <!-- Generation progress -->
    {#if generating}
      <div class="generating-status" role="status" aria-live="polite">
        <svg class="status-spinner" viewBox="0 0 24 24" width="20" height="20" aria-hidden="true">
          <circle cx="12" cy="12" r="10" fill="none" stroke="var(--color-primary)" stroke-width="2" stroke-dasharray="31.4 31.4" />
        </svg>
        <span class="text-body-small">Generating {selectedAlgorithm} key pair...</span>
      </div>
    {/if}

    <!-- PEM result area -->
    {#if showPEMResult}
      <div class="pem-result" data-testid="piv-pem-result">
        <div class="pem-result-header">
          <span class="text-label-medium form-label">
            {selectedOutputFormat === 'csr' ? 'Certificate Signing Request' : 'Public Key'}
          </span>
          <div class="pem-result-actions">
            <button type="button" class="copy-btn text-label-medium" on:click={handleCopy}>
              {copied ? 'Copied!' : 'Copy'}
            </button>
            <button type="button" class="copy-btn text-label-medium" on:click={handleSave}>
              Save...
            </button>
          </div>
        </div>
        <textarea
          class="pem-textarea text-body-small font-mono"
          readonly
          rows={8}
          value={pemOutput}
          aria-label="PEM output"
        ></textarea>
      </div>
    {/if}
  </div>

  <svelte:fragment slot="actions">
    {#if showPEMResult}
      <Button variant="primary" on:click={handleDone}>Done</Button>
    {:else}
      <Button variant="text" on:click={handleCancel} disabled={generating}>Cancel</Button>
      <Button variant="primary" on:click={handleGenerate} loading={generating}>
        {generating ? 'Generating...' : 'Generate Key'}
      </Button>
    {/if}
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
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .info-row {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .info-label {
    color: var(--color-on-surface-variant);
    min-width: 56px;
  }

  .form-section {
    display: flex;
    flex-direction: column;
    gap: 10px;
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

  /* Collapsible advanced subject */
  .collapse-toggle {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    background: none;
    border: none;
    padding: 0 4px;
    cursor: pointer;
    color: var(--color-primary);
    font-family: var(--font-sans);
    font-size: 13px;
    align-self: flex-start;
  }

  .collapse-toggle:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .collapse-arrow {
    display: inline-block;
    font-size: 10px;
    transition: transform var(--transition-fast);
    color: var(--color-primary);
  }

  .collapse-arrow.expanded {
    transform: rotate(90deg);
  }

  .advanced-subject {
    display: flex;
    flex-direction: column;
    gap: 10px;
    padding-left: 16px;
    border-left: 2px solid var(--color-outline-variant);
  }

  /* Radio group for CA source */
  .radio-group {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding: 8px 0;
  }

  .radio-option {
    display: flex;
    align-items: center;
    gap: 10px;
    cursor: pointer;
    padding: 4px 0;
  }

  .radio-option.radio-disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .radio-option input[type="radio"] {
    width: 16px;
    height: 16px;
    accent-color: var(--color-primary);
    flex-shrink: 0;
  }

  .radio-reason {
    color: var(--color-on-surface-variant);
    font-style: italic;
    margin-left: 4px;
  }

  /* Notices */
  .form-notice {
    padding: 10px 14px;
    background-color: var(--color-security-warning-container);
    border-radius: var(--radius-sm);
  }

  .notice-text {
    color: var(--color-on-security-warning-container);
  }

  .form-notice-info {
    background-color: var(--color-surface-container-high);
  }

  .notice-text-info {
    color: var(--color-on-surface-variant);
  }

  /* Generation spinner */
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

  /* PEM result */
  .pem-result {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .pem-result-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 0 4px;
  }

  .pem-result-actions {
    display: flex;
    align-items: center;
    gap: 4px;
  }

  .copy-btn {
    background: none;
    border: none;
    padding: 2px 8px;
    cursor: pointer;
    color: var(--color-primary);
    font-family: var(--font-sans);
    font-size: 13px;
    border-radius: var(--radius-sm);
    transition: background-color var(--transition-fast);
  }

  .copy-btn:hover {
    background-color: var(--color-primary-container);
  }

  .pem-textarea {
    width: 100%;
    padding: 12px 14px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-md);
    background-color: var(--color-surface-container);
    color: var(--color-on-surface);
    font-size: 12px;
    line-height: 1.5;
    resize: vertical;
    outline: none;
    box-sizing: border-box;
    white-space: pre;
    overflow-x: auto;
  }
</style>
