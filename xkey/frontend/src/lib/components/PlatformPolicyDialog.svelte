<script lang="ts">
  import Modal from './Modal.svelte';
  import Button from './Button.svelte';
  import Icon from './Icon.svelte';
  import LoadingSpinner from './LoadingSpinner.svelte';
  import { mdiChevronLeft, mdiChevronRight, mdiCheck, mdiChip } from '$lib/utils/icons';
  import { addNotification } from '$lib/stores/notifications';
  import { callBackend } from '$lib/api/backend';
  import type { BackendPCRValue, PlatformPolicyStatus } from '$lib/api/backend';

  export let open: boolean = false;
  export let mode: 'create' | 'update' = 'create';
  export let currentPCRs: number[] = [];
  export let currentBank: string = 'sha256';
  export let onClose: () => void = () => {};
  export let onComplete: () => void = () => {};

  type Step = 'bank' | 'pcrs' | 'confirm';

  const banks: Array<{ value: string; label: string }> = [
    { value: 'sha1', label: 'SHA-1' },
    { value: 'sha256', label: 'SHA-256' },
    { value: 'sha384', label: 'SHA-384' },
    { value: 'sha512', label: 'SHA-512' },
  ];

  let step: Step = 'bank';
  let selectedBank = 'sha256';
  let selectedPCRs: number[] = [];
  let pcrDigests: Map<number, string> = new Map();
  let loadingPCRs = false;
  let processing = false;

  $: dialogTitle = mode === 'create' ? 'Configure Platform Policy' : 'Update Platform Policy';

  $: stepIndex = step === 'bank' ? 0 : step === 'pcrs' ? 1 : 2;

  $: displayBank = banks.find((b) => b.value === selectedBank)?.label ?? selectedBank.toUpperCase();

  $: if (open) {
    step = 'bank';
    selectedBank = mode === 'update' && currentBank ? currentBank : 'sha256';
    selectedPCRs = mode === 'update' && currentPCRs.length > 0 ? [...currentPCRs] : [];
    pcrDigests = new Map();
    processing = false;
    loadingPCRs = false;
  }

  async function fetchPCRDigests(): Promise<void> {
    loadingPCRs = true;
    const result = await callBackend<BackendPCRValue[]>('TPMService', 'ReadPCRs', selectedBank);
    if (result && Array.isArray(result)) {
      const digestMap = new Map<number, string>();
      for (const pcr of result) {
        digestMap.set(pcr.index, pcr.digest);
      }
      pcrDigests = digestMap;
    }
    loadingPCRs = false;
  }

  function togglePCR(index: number): void {
    if (selectedPCRs.includes(index)) {
      selectedPCRs = selectedPCRs.filter(p => p !== index);
    } else {
      selectedPCRs = [...selectedPCRs, index].sort((a, b) => a - b);
    }
  }

  function goToStep(target: Step): void {
    if (target === 'pcrs') {
      fetchPCRDigests();
    }
    step = target;
  }

  async function handleConfirm(): Promise<void> {
    if (selectedPCRs.length === 0) {
      addNotification('error', 'Select at least one PCR');
      return;
    }

    processing = true;

    const serviceMethod = mode === 'create' ? 'CreatePolicy' : 'UpdatePolicy';
    const result = await callBackend<PlatformPolicyStatus>(
      'PlatformPolicyService',
      serviceMethod,
      selectedPCRs,
      selectedBank,
    );

    processing = false;

    if (result) {
      addNotification('success', mode === 'create' ? 'Platform policy created' : 'Platform policy updated');
      open = false;
      onComplete();
    } else {
      addNotification('error', `Failed to ${mode === 'create' ? 'create' : 'update'} platform policy`);
    }
  }

  function handleCancel(): void {
    open = false;
    onClose();
  }

  function truncateDigest(digest: string): string {
    if (!digest || digest.length <= 16) return digest || '--';
    return digest.substring(0, 8) + '...' + digest.substring(digest.length - 8);
  }
</script>

<Modal bind:open title={dialogTitle} maxWidth="560px">
  <div class="ppd-content">
    <!-- Step indicator -->
    <div class="step-indicator">
      {#each ['PCR Bank', 'Select PCRs', 'Confirm'] as label, i}
        <div class="step-dot" class:step-active={stepIndex >= i} class:step-current={stepIndex === i}>
          <span class="step-number">{i + 1}</span>
        </div>
        {#if i < 2}
          <div class="step-line" class:step-line-active={stepIndex > i}></div>
        {/if}
      {/each}
    </div>
    <div class="step-labels">
      <span class="text-label-small" class:label-active={stepIndex >= 0}>PCR Bank</span>
      <span class="text-label-small" class:label-active={stepIndex >= 1}>Select PCRs</span>
      <span class="text-label-small" class:label-active={stepIndex >= 2}>Confirm</span>
    </div>

    <!-- Step 1: Select PCR Bank -->
    {#if step === 'bank'}
      <div class="step-content">
        <p class="text-body-medium step-desc">
          Select the hash algorithm (PCR bank) for the platform policy. SHA-256 is recommended for most systems.
        </p>
        <div class="bank-options">
          {#each banks as bankOption}
            <button
              class="bank-option"
              class:bank-selected={selectedBank === bankOption.value}
              on:click={() => (selectedBank = bankOption.value)}
            >
              <div class="bank-radio">
                {#if selectedBank === bankOption.value}
                  <div class="bank-radio-dot"></div>
                {/if}
              </div>
              <div class="bank-label">
                <span class="text-title-small">{bankOption.label}</span>
                <span class="text-body-small bank-desc">
                  {#if bankOption.value === 'sha1'}
                    Legacy 160-bit hash (not recommended)
                  {:else if bankOption.value === 'sha256'}
                    Standard 256-bit hash (recommended)
                  {:else if bankOption.value === 'sha384'}
                    Extended 384-bit hash
                  {:else}
                    Full 512-bit hash
                  {/if}
                </span>
              </div>
            </button>
          {/each}
        </div>
      </div>

    <!-- Step 2: Select PCRs -->
    {:else if step === 'pcrs'}
      <div class="step-content">
        <p class="text-body-medium step-desc">
          Select which PCRs to include in the platform policy. Selected PCRs will be measured and bound to sealed data.
        </p>

        {#if loadingPCRs}
          <div class="pcr-loading">
            <LoadingSpinner size={24} />
            <span class="text-body-small">Reading PCR values...</span>
          </div>
        {/if}

        <div class="pcr-selection-grid">
          {#each Array.from({length: 24}, (_, i) => i) as idx}
            <button
              class="pcr-select-chip"
              class:pcr-chip-selected={selectedPCRs.includes(idx)}
              on:click={() => togglePCR(idx)}
              title={pcrDigests.has(idx) ? `PCR ${idx}: ${pcrDigests.get(idx)}` : `PCR ${idx}`}
            >
              <div class="pcr-chip-header">
                <span class="pcr-chip-index">{idx}</span>
                {#if selectedPCRs.includes(idx)}
                  <Icon path={mdiCheck} size={14} />
                {/if}
              </div>
              {#if pcrDigests.has(idx)}
                <span class="pcr-chip-digest text-label-small">{truncateDigest(pcrDigests.get(idx) ?? '')}</span>
              {/if}
            </button>
          {/each}
        </div>

        {#if selectedPCRs.length > 0}
          <p class="text-body-small pcr-summary">
            Selected: PCR {selectedPCRs.join(', ')} ({selectedPCRs.length} PCR{selectedPCRs.length !== 1 ? 's' : ''})
          </p>
        {:else}
          <p class="text-body-small pcr-summary pcr-summary-empty">No PCRs selected</p>
        {/if}
      </div>

    <!-- Step 3: Confirmation -->
    {:else if step === 'confirm'}
      <div class="step-content">
        <p class="text-body-medium step-desc">
          Review the platform policy configuration before {mode === 'create' ? 'creating' : 'updating'}.
        </p>

        <div class="confirm-card">
          <div class="confirm-row">
            <span class="text-label-small confirm-label">PCR Bank</span>
            <span class="text-body-medium">{displayBank}</span>
          </div>
          <div class="confirm-row">
            <span class="text-label-small confirm-label">PCRs</span>
            <div class="confirm-pcr-list">
              {#each selectedPCRs as pcr}
                <span class="confirm-pcr-tag text-label-small">{pcr}</span>
              {/each}
            </div>
          </div>
          <div class="confirm-row">
            <span class="text-label-small confirm-label">PCR Count</span>
            <span class="text-body-medium">{selectedPCRs.length}</span>
          </div>
          <div class="confirm-row">
            <span class="text-label-small confirm-label">Mode</span>
            <span class="text-body-medium">{mode === 'create' ? 'Create new policy' : 'Update existing policy'}</span>
          </div>
        </div>

        {#if processing}
          <div class="processing-status" role="status" aria-live="polite">
            <LoadingSpinner size={20} />
            <span class="text-body-small">
              {mode === 'create' ? 'Creating' : 'Updating'} platform policy...
            </span>
          </div>
        {/if}
      </div>
    {/if}
  </div>

  <svelte:fragment slot="actions">
    {#if step === 'bank'}
      <Button variant="text" on:click={handleCancel}>Cancel</Button>
      <Button variant="primary" icon={mdiChevronRight} on:click={() => goToStep('pcrs')}>
        Next
      </Button>
    {:else if step === 'pcrs'}
      <Button variant="text" icon={mdiChevronLeft} on:click={() => goToStep('bank')}>Back</Button>
      <Button variant="primary" icon={mdiChevronRight} on:click={() => goToStep('confirm')} disabled={selectedPCRs.length === 0}>
        Next
      </Button>
    {:else}
      <Button variant="text" icon={mdiChevronLeft} on:click={() => goToStep('pcrs')} disabled={processing}>Back</Button>
      <Button variant="primary" icon={mdiCheck} loading={processing} on:click={handleConfirm}>
        {mode === 'create' ? 'Create Policy' : 'Update Policy'}
      </Button>
    {/if}
  </svelte:fragment>
</Modal>

<style>
  .ppd-content {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  /* Step Indicator */
  .step-indicator {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0;
    padding: 4px 0;
  }

  .step-dot {
    width: 28px;
    height: 28px;
    border-radius: 50%;
    background-color: var(--color-surface-container);
    border: 2px solid var(--color-outline-variant);
    display: flex;
    align-items: center;
    justify-content: center;
    transition: all var(--transition-fast);
    flex-shrink: 0;
  }

  .step-dot.step-active {
    background-color: var(--color-primary);
    border-color: var(--color-primary);
  }

  .step-dot.step-current {
    box-shadow: 0 0 0 3px var(--color-primary-95);
  }

  :global([data-theme="dark"]) .step-dot.step-current {
    box-shadow: 0 0 0 3px var(--color-primary-container);
  }

  .step-number {
    font-size: 12px;
    font-weight: 600;
    color: var(--color-on-surface-variant);
  }

  .step-active .step-number {
    color: var(--color-on-primary);
  }

  .step-line {
    flex: 1;
    height: 2px;
    background-color: var(--color-outline-variant);
    max-width: 80px;
    transition: background-color var(--transition-fast);
  }

  .step-line-active {
    background-color: var(--color-primary);
  }

  .step-labels {
    display: flex;
    justify-content: space-between;
    padding: 0 8px;
    color: var(--color-on-surface-variant);
  }

  .step-labels span {
    text-align: center;
    min-width: 70px;
  }

  .label-active {
    color: var(--color-primary);
    font-weight: 600;
  }

  /* Step Content */
  .step-content {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .step-desc {
    margin: 0;
    color: var(--color-on-surface-variant);
    line-height: 1.5;
  }

  /* Bank Selection */
  .bank-options {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .bank-option {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 16px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-md);
    background: var(--color-surface);
    cursor: pointer;
    text-align: left;
    font-family: var(--font-sans);
    transition: border-color var(--transition-fast), background-color var(--transition-fast);
  }

  .bank-option:hover {
    background-color: var(--color-surface-container-low);
  }

  .bank-selected {
    border-color: var(--color-primary);
    background-color: var(--color-primary-95);
  }

  :global([data-theme="dark"]) .bank-selected {
    background-color: var(--color-primary-container);
  }

  .bank-radio {
    width: 20px;
    height: 20px;
    border-radius: 50%;
    border: 2px solid var(--color-outline);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    transition: border-color var(--transition-fast);
  }

  .bank-selected .bank-radio {
    border-color: var(--color-primary);
  }

  .bank-radio-dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background-color: var(--color-primary);
  }

  .bank-label {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .bank-label span:first-child {
    color: var(--color-on-surface);
  }

  .bank-desc {
    color: var(--color-on-surface-variant);
  }

  /* PCR Selection */
  .pcr-loading {
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--color-on-surface-variant);
    padding: 8px 0;
  }

  .pcr-selection-grid {
    display: grid;
    grid-template-columns: repeat(6, 1fr);
    gap: 6px;
  }

  .pcr-select-chip {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 2px;
    padding: 6px 4px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    background: var(--color-surface);
    cursor: pointer;
    font-family: var(--font-sans);
    transition: all var(--transition-fast);
    min-height: 40px;
  }

  .pcr-select-chip:hover {
    background-color: var(--color-surface-container);
  }

  .pcr-chip-selected {
    background-color: var(--color-primary);
    color: var(--color-on-primary);
    border-color: var(--color-primary);
  }

  .pcr-chip-selected:hover {
    filter: brightness(1.1);
  }

  .pcr-chip-header {
    display: flex;
    align-items: center;
    gap: 2px;
  }

  .pcr-chip-index {
    font-size: 13px;
    font-weight: 600;
  }

  .pcr-chip-digest {
    font-family: var(--font-mono, monospace);
    font-size: 8px;
    opacity: 0.7;
    max-width: 100%;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .pcr-summary {
    margin: 0;
    color: var(--color-primary);
    font-weight: 500;
  }

  .pcr-summary-empty {
    color: var(--color-on-surface-variant);
    font-weight: 400;
  }

  /* Confirmation */
  .confirm-card {
    display: flex;
    flex-direction: column;
    gap: 0;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-md);
    overflow: hidden;
  }

  .confirm-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 16px;
    gap: 16px;
  }

  .confirm-row + .confirm-row {
    border-top: 1px solid var(--color-outline-variant);
  }

  .confirm-label {
    color: var(--color-on-surface-variant);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    flex-shrink: 0;
  }

  .confirm-pcr-list {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
    justify-content: flex-end;
  }

  .confirm-pcr-tag {
    padding: 2px 8px;
    background-color: var(--color-primary-95);
    color: var(--color-primary);
    border-radius: var(--radius-full);
    font-weight: 500;
  }

  :global([data-theme="dark"]) .confirm-pcr-tag {
    background-color: var(--color-primary-container);
    color: var(--color-on-primary-container);
  }

  .processing-status {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 10px 14px;
    background-color: var(--color-surface-container);
    border-radius: var(--radius-sm);
    color: var(--color-on-surface-variant);
  }
</style>
