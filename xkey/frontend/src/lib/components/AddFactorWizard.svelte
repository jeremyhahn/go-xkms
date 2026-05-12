<script lang="ts">
  /**
   * AddFactorWizard — 4-step modal for enrolling or rotating an auth factor.
   * Pixel-equivalent to the web UI AddFactorWizard per §5e.
   *
   * Step 1: pick type (mTLS / FIDO2 / PIV)
   * Step 2: type-specific credential
   * Step 3: label
   * Step 4: success
   */

  import { createEventDispatcher } from 'svelte';
  import Modal from '$lib/components/Modal.svelte';
  import Button from '$lib/components/Button.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import Input from '$lib/components/Input.svelte';
  import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
  import StatusBadge from '$lib/components/StatusBadge.svelte';
  import {
    mdiKey, mdiFingerprint, mdiCreditCardOutline,
    mdiCheckCircle, mdiAlert, mdiUpload, mdiChevronLeft,
  } from '$lib/utils/icons';
  import { SecurityFactorService, type AuthFactor, type AuthFactorType } from '$lib/stores/auth-factors';
  import { resolveVendorBadge } from '$lib/utils/vendor-badge';
  import { addNotification } from '$lib/stores/notifications';
  import { isWailsAvailable } from '$lib/api/backend';

  // ----- props -----

  export let open: boolean = false;
  export let userId: string = '';
  /** Pre-selected factor ID when rotating an existing factor. */
  export let rotateFactorId: string | undefined = undefined;
  /** Pre-selected type when rotating — skips step 1. */
  export let rotateFactorType: AuthFactorType | undefined = undefined;

  // ----- events -----

  const dispatch = createEventDispatcher<{
    close: void;
    added: AuthFactor;
  }>();

  // ----- wizard state -----

  type Step = 1 | 2 | 3 | 4;
  type MTLSMode = 'generate' | 'upload';

  let step: Step = rotateFactorType ? 2 : 1;
  let selectedType: AuthFactorType | null = rotateFactorType ?? null;

  // mTLS
  let mtlsMode: MTLSMode = 'generate';
  let mtlsCertPEM = '';

  // FIDO2
  let fido2Response = '';
  let fido2Vendor = '';
  let fido2Tapped = false;

  // PIV
  let pivCertPEM = '';
  let pivSlot = '9a';
  let pivVendor = '';
  let pivCards: { reader_name: string; card_vendor: string }[] = [];
  let pivLoading = false;

  // shared
  let label = '';
  let busy = false;
  let error = '';
  let addedFactor: AuthFactor | null = null;

  // ----- reactive -----

  $: canAdvance = computeCanAdvance(step, selectedType, mtlsCertPEM, fido2Response, pivCertPEM, label);

  function computeCanAdvance(
    s: Step,
    type: AuthFactorType | null,
    cert: string,
    fido2: string,
    piv: string,
    lbl: string
  ): boolean {
    switch (s) {
      case 1: return type !== null;
      case 2:
        if (type === 'mtls') return !!cert;
        if (type === 'fido2') return !!fido2;
        if (type === 'piv') return !!piv;
        return false;
      case 3: return lbl.trim().length > 0;
      default: return false;
    }
  }

  // ----- lifecycle -----

  $: if (open) {
    resetState();
    if (selectedType === 'piv') loadPIVCards();
  }

  function resetState(): void {
    step = rotateFactorType ? 2 : 1;
    selectedType = rotateFactorType ?? null;
    mtlsMode = 'generate';
    mtlsCertPEM = '';
    fido2Response = '';
    fido2Vendor = '';
    fido2Tapped = false;
    pivCertPEM = '';
    pivSlot = '9a';
    pivVendor = '';
    label = '';
    busy = false;
    error = '';
    addedFactor = null;
  }

  // ----- actions -----

  function goBack(): void {
    error = '';
    step = (step - 1) as Step;
  }

  async function handleNext(): Promise<void> {
    if (step === 3) {
      await submit();
      return;
    }
    error = '';
    // When selecting PIV in step 1, load available cards
    if (step === 1 && selectedType === 'piv') {
      await loadPIVCards();
    }
    step = (step + 1) as Step;
  }

  async function submit(): Promise<void> {
    busy = true;
    error = '';
    try {
      let resp;
      if (rotateFactorId) {
        resp = await SecurityFactorService.rotate(userId, {
          factor_id: rotateFactorId,
          cert_pem: selectedType === 'mtls' ? mtlsCertPEM : undefined,
          webauthn_response: selectedType === 'fido2' ? fido2Response : undefined,
          piv_cert_pem: selectedType === 'piv' ? pivCertPEM : undefined,
          piv_slot: selectedType === 'piv' ? pivSlot : undefined,
        });
      } else {
        resp = await SecurityFactorService.add(userId, {
          type: selectedType!,
          label: label.trim(),
          cert_pem: selectedType === 'mtls' ? mtlsCertPEM : undefined,
          webauthn_response: selectedType === 'fido2' ? fido2Response : undefined,
          piv_cert_pem: selectedType === 'piv' ? pivCertPEM : undefined,
          piv_slot: selectedType === 'piv' ? pivSlot : undefined,
        });
      }

      if (!resp) {
        error = 'Failed to add factor — no response from backend';
        return;
      }

      addedFactor = resp.factor;
      step = 4;
      dispatch('added', resp.factor);
    } catch (err) {
      error = err instanceof Error ? err.message : String(err);
    } finally {
      busy = false;
    }
  }

  // ----- mTLS helpers -----

  async function handleGenerateCert(): Promise<void> {
    busy = true;
    error = '';
    try {
      // Generate key via platform CSR endpoint through the backend service.
      // The service connects via mTLS to the platform server.
      const pem = await SecurityFactorService.readPIVCertPEM('generate-mtls-csr');
      if (pem) {
        mtlsCertPEM = pem;
      } else {
        error = 'Certificate generation requires a connected platform server.';
      }
    } catch (err) {
      error = err instanceof Error ? err.message : 'Failed to generate certificate';
    } finally {
      busy = false;
    }
  }

  function handleFileUpload(): void {
    const input = document.createElement('input');
    input.type = 'file';
    input.accept = '.pem,.crt,.cer';
    input.onchange = () => {
      const file = input.files?.[0];
      if (!file) return;
      const reader = new FileReader();
      reader.onload = (e) => {
        mtlsCertPEM = (e.target?.result as string) ?? '';
      };
      reader.readAsText(file);
    };
    input.click();
  }

  // ----- PIV helpers -----

  async function loadPIVCards(): Promise<void> {
    if (!isWailsAvailable()) return;
    pivLoading = true;
    const cards = await SecurityFactorService.enumeratePIVCards();
    pivCards = cards;
    pivLoading = false;
  }

  async function readPIVCert(): Promise<void> {
    busy = true;
    error = '';
    try {
      const pem = await SecurityFactorService.readPIVCertPEM(pivSlot);
      if (pem) {
        pivCertPEM = pem;
        // Infer vendor from cert subject — done server side; treat as "PIV Card" for now.
        pivVendor = pivCards[0]?.card_vendor ?? 'PIV Card';
      } else {
        error = 'Could not read certificate from card. Check PIN and slot.';
      }
    } catch (err) {
      error = err instanceof Error ? err.message : 'Failed to read PIV certificate';
    } finally {
      busy = false;
    }
  }

  // ----- label input -----

  function handleLabelInput(e: Event): void {
    const t = e.target as HTMLInputElement | null;
    if (t) label = t.value;
  }

  // ----- close -----

  function handleClose(): void {
    dispatch('close');
  }

  const SLOT_OPTIONS = [
    { value: '9a', label: '9a — PIV Authentication' },
    { value: '9c', label: '9c — Digital Signature' },
    { value: '9d', label: '9d — Key Management' },
    { value: '9e', label: '9e — Card Authentication' },
  ];

  const STEP_LABELS = ['Type', 'Credential', 'Label', 'Done'];
</script>

<Modal
  {open}
  title={step === 4 ? 'Factor added' : rotateFactorId ? 'Rotate factor' : 'Add factor'}
  maxWidth="520px"
  on:close={handleClose}
>
  <!-- Step indicator -->
  <div class="step-indicator" role="progressbar" aria-valuenow={step} aria-valuemin={1} aria-valuemax={4} aria-label="Step {step} of 4">
    {#each STEP_LABELS as lbl, i}
      {@const n = i + 1}
      <div class="step-dot-wrap">
        <div class="step-dot" class:active={n === step} class:done={n < step}>
          {#if n < step}
            <Icon path={mdiCheckCircle} size={16} color="white" />
          {:else}
            {n}
          {/if}
        </div>
        <span class="step-lbl" class:step-lbl-active={n === step}>{lbl}</span>
      </div>
      {#if i < STEP_LABELS.length - 1}
        <div class="step-line" class:done={n < step}></div>
      {/if}
    {/each}
  </div>

  <!-- Step content -->
  <div class="wizard-body">
    {#if step === 1}
      <!-- Step 1: pick type -->
      <p class="text-body-medium hint">Choose the type of authentication factor to add.</p>
      <div class="type-options" role="group" aria-labelledby="pick-type">
        {#each [
          { type: 'mtls', icon: mdiKey, color: '#3b82f6', title: 'mTLS Certificate', desc: 'Generate a new client cert or upload an existing PEM.' },
          { type: 'fido2', icon: mdiFingerprint, color: '#8b5cf6', title: 'FIDO2 / Passkey', desc: 'Tap your security key or use a built-in authenticator.' },
          { type: 'piv', icon: mdiCreditCardOutline, color: '#22c55e', title: 'PIV Smartcard', desc: 'Insert your PIV card and enter your User PIN.' },
        ] as opt}
          <label class="type-option" class:selected={selectedType === opt.type}>
            <input
              type="radio"
              name="factor-type"
              value={opt.type}
              bind:group={selectedType}
              class="type-radio"
              aria-label={opt.title}
            />
            <Icon path={opt.icon} size={20} color={opt.color} />
            <div>
              <div class="text-label-large">{opt.title}</div>
              <div class="text-body-small hint">{opt.desc}</div>
            </div>
          </label>
        {/each}
      </div>

    {:else if step === 2 && selectedType === 'mtls'}
      <!-- Step 2a: mTLS -->
      <div class="mtls-mode-row" role="group" aria-label="mTLS source">
        <label class="mode-radio">
          <input type="radio" name="mtls-mode" value="generate" bind:group={mtlsMode} />
          Generate new cert
        </label>
        <label class="mode-radio">
          <input type="radio" name="mtls-mode" value="upload" bind:group={mtlsMode} />
          Upload existing cert
        </label>
      </div>

      {#if mtlsMode === 'generate'}
        <p class="text-body-small hint">
          A new ECDSA P-256 keypair will be generated. The platform CA will sign the CSR.
        </p>
        {#if mtlsCertPEM}
          <div class="cert-preview">{mtlsCertPEM.slice(0, 120)}…</div>
        {:else}
          <Button variant="outline" on:click={handleGenerateCert} disabled={busy}>
            {#if busy}<LoadingSpinner size={16} />{:else}<Icon path={mdiKey} size={16} />{/if}
            Generate certificate
          </Button>
        {/if}
      {:else}
        <Button variant="outline" on:click={handleFileUpload}>
          <Icon path={mdiUpload} size={16} />
          Select PEM file
        </Button>
        {#if mtlsCertPEM}
          <div class="cert-preview">{mtlsCertPEM.slice(0, 120)}…</div>
        {/if}
      {/if}

    {:else if step === 2 && selectedType === 'fido2'}
      <!-- Step 2b: FIDO2 -->
      <div class="fido2-center">
        <div class="fido2-icon" class:pulsing={fido2Tapped}>
          <Icon path={mdiFingerprint} size={64} color={fido2Tapped ? '#8b5cf6' : 'var(--on-surface-variant)'} />
        </div>
        <p class="text-body-medium">
          {fido2Tapped
            ? 'Waiting for authenticator — tap your security key or follow the prompt.'
            : 'Click below to start FIDO2 registration.'}
        </p>
        {#if fido2Vendor}
          <StatusBadge text={fido2Vendor} variant="success" />
        {:else}
          <Button
            variant="primary"
            on:click={async () => {
              // FIDO2 registration in Wails: call through the SecurityFactorService.
              // The desktop app uses the local CTAP2 bridge.
              fido2Tapped = true;
              busy = true;
              error = '';
              const resp = await SecurityFactorService.add(userId, {
                type: 'fido2',
                label: '__probe__',
              });
              fido2Tapped = false;
              busy = false;
              if (resp) {
                fido2Response = resp.factor.id;
                fido2Vendor = resolveVendorBadge(resp.factor).name;
              } else {
                error = 'Registration failed — please try again.';
              }
            }}
            disabled={busy || !!fido2Vendor}
          >
            {#if busy}<LoadingSpinner size={16} />{:else}<Icon path={mdiFingerprint} size={16} />{/if}
            {fido2Tapped ? 'Waiting…' : 'Register security key'}
          </Button>
        {/if}
      </div>

    {:else if step === 2 && selectedType === 'piv'}
      <!-- Step 2c: PIV -->
      <div class="piv-section">
        {#if pivLoading}
          <LoadingSpinner size={24} />
        {:else if pivCards.length === 0}
          <div class="empty-state-sm">
            <Icon path={mdiCreditCardOutline} size={32} color="var(--on-surface-variant)" />
            <p class="text-body-medium">No PIV cards detected.</p>
            <p class="text-body-small hint">Insert your card and click Refresh.</p>
            <Button variant="text" on:click={loadPIVCards}>Refresh</Button>
          </div>
        {:else}
          <div class="field-group">
            <label class="text-label-medium" for="piv-slot">Slot</label>
            <select id="piv-slot" bind:value={pivSlot} class="piv-select">
              {#each SLOT_OPTIONS as opt}
                <option value={opt.value}>{opt.label}</option>
              {/each}
            </select>
          </div>

          {#if pivCertPEM}
            <StatusBadge text={pivVendor || 'PIV Card'} variant="success" />
            <div class="cert-preview">{pivCertPEM.slice(0, 120)}…</div>
          {:else}
            <Button variant="outline" on:click={readPIVCert} disabled={busy}>
              {#if busy}<LoadingSpinner size={16} />{/if}
              Read certificate from card
            </Button>
          {/if}
        {/if}
      </div>

    {:else if step === 3}
      <!-- Step 3: label -->
      <p class="text-body-medium hint">Give this factor a friendly name.</p>
      <div class="field-group">
        <label class="text-label-medium" for="factor-label">Label</label>
        <Input
          id="factor-label"
          value={label}
          on:input={handleLabelInput}
          placeholder={selectedType === 'mtls' ? 'Work laptop cert' : selectedType === 'fido2' ? 'YubiKey 5C — work' : 'PIV card'}
        />
        <span id="label-hint" class="text-body-small hint">Max 80 characters.</span>
      </div>

    {:else if step === 4 && addedFactor}
      <!-- Step 4: success -->
      <div class="success-state">
        <Icon path={mdiCheckCircle} size={64} color="#22c55e" />
        <p class="text-title-medium">Factor added successfully</p>
        <div class="success-meta">
          <span class="text-body-medium">{addedFactor.label}</span>
          <StatusBadge text={resolveVendorBadge(addedFactor).name} variant="success" />
        </div>
      </div>
    {/if}

    {#if error}
      <div class="error-banner">
        <Icon path={mdiAlert} size={16} color="var(--error)" />
        <span class="text-body-small">{error}</span>
      </div>
    {/if}
  </div>

  <!-- Footer actions -->
  <div slot="actions" class="wizard-footer">
    {#if step > 1 && step < 4 && !rotateFactorType}
      <Button variant="text" on:click={goBack} disabled={busy}>
        <Icon path={mdiChevronLeft} size={16} />
        Back
      </Button>
    {:else}
      <span></span>
    {/if}

    {#if step < 4}
      <Button
        variant="primary"
        on:click={handleNext}
        disabled={!canAdvance || busy}
      >
        {#if busy}<LoadingSpinner size={16} />{/if}
        {step === 3 ? 'Add factor' : 'Next'}
      </Button>
    {:else}
      <Button variant="primary" on:click={handleClose}>Done</Button>
    {/if}
  </div>
</Modal>

<style>
  .step-indicator {
    display: flex;
    align-items: center;
    margin-bottom: 24px;
  }

  .step-dot-wrap {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 4px;
  }

  .step-dot {
    width: 28px;
    height: 28px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 12px;
    font-weight: 600;
    background: var(--surface-variant);
    color: var(--on-surface-variant);
    transition: background 0.2s, color 0.2s;
  }

  .step-dot.active {
    background: color-mix(in srgb, var(--primary) 20%, transparent);
    color: var(--primary);
    border: 2px solid var(--primary);
  }

  .step-dot.done {
    background: var(--primary);
    color: white;
  }

  .step-lbl {
    font-size: 11px;
    color: var(--on-surface-variant);
    white-space: nowrap;
  }

  .step-lbl-active {
    color: var(--primary);
    font-weight: 600;
  }

  .step-line {
    flex: 1;
    height: 2px;
    background: var(--outline-variant);
    margin-top: -16px;
    transition: background 0.2s;
  }

  .step-line.done {
    background: var(--primary);
  }

  .wizard-body {
    min-height: 180px;
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .hint {
    color: var(--on-surface-variant);
  }

  .type-options {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .type-option {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 12px;
    border-radius: 8px;
    border: 1px solid var(--outline-variant);
    cursor: pointer;
    transition: border-color 0.15s, background 0.15s;
  }

  .type-option:hover {
    background: var(--surface-variant);
  }

  .type-option.selected {
    border-color: var(--primary);
    background: color-mix(in srgb, var(--primary) 5%, transparent);
  }

  .type-radio {
    margin-top: 3px;
    accent-color: var(--primary);
    flex-shrink: 0;
  }

  .mtls-mode-row {
    display: flex;
    gap: 20px;
  }

  .mode-radio {
    display: flex;
    align-items: center;
    gap: 6px;
    cursor: pointer;
    font-size: 14px;
  }

  .mode-radio input {
    accent-color: var(--primary);
  }

  .cert-preview {
    background: var(--surface-variant);
    border-radius: 6px;
    padding: 8px 12px;
    font-family: monospace;
    font-size: 11px;
    word-break: break-all;
  }

  .fido2-center {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 16px;
    padding: 16px;
    text-align: center;
  }

  .fido2-icon {
    transition: transform 0.2s;
  }

  .fido2-icon.pulsing :global(svg) {
    animation: pulse 1.2s ease-in-out infinite;
  }

  @keyframes pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.4; }
  }

  .piv-section {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .field-group {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .piv-select {
    padding: 8px 12px;
    border-radius: 6px;
    border: 1px solid var(--outline);
    background: var(--surface);
    color: var(--on-surface);
    font-size: 14px;
  }

  .empty-state-sm {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 8px;
    padding: 24px;
    text-align: center;
    color: var(--on-surface-variant);
  }

  .success-state {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 12px;
    padding: 24px;
    text-align: center;
  }

  .success-meta {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .error-banner {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 8px 12px;
    border-radius: 6px;
    background: color-mix(in srgb, var(--error) 10%, transparent);
    color: var(--error);
  }

  .wizard-footer {
    display: flex;
    justify-content: space-between;
    align-items: center;
    width: 100%;
  }
</style>
