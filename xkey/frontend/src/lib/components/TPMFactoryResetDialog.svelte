<script lang="ts">
  import Modal from './Modal.svelte';
  import Button from './Button.svelte';
  import Input from './Input.svelte';
  import Icon from './Icon.svelte';
  import LoadingSpinner from './LoadingSpinner.svelte';
  import { mdiCheck, mdiAlert, mdiDeleteSweep } from '$lib/utils/icons';
  import { addNotification } from '$lib/stores/notifications';
  import { callBackendVoidWithError, isTPMAuthError } from '$lib/api/backend';

  export let open: boolean = false;
  export let onClose: () => void = () => {};
  export let onComplete: () => void = () => {};

  type Step = 'input' | 'confirm' | 'progress' | 'result';

  let step: Step = 'input';
  let ownerAuth = '';
  let errors: Record<string, string> = {};
  let resetError = '';
  let resetSuccess = false;
  let confirmChecked = false;

  $: if (open) {
    step = 'input';
    ownerAuth = '';
    errors = {};
    resetError = '';
    resetSuccess = false;
    confirmChecked = false;
  }

  function handleNext(): void {
    step = 'confirm';
  }

  function handleBack(): void {
    step = 'input';
    confirmChecked = false;
  }

  async function handleReset(): Promise<void> {
    step = 'progress';
    resetError = '';
    resetSuccess = false;

    const result = await callBackendVoidWithError('TPMService', 'FactoryReset', ownerAuth);

    if (result.ok) {
      resetSuccess = true;
      step = 'result';
      addNotification('success', 'TPM factory reset completed');
    } else if (isTPMAuthError(result.error)) {
      errors['auth'] = 'Authorization required. Please enter the owner authorization password.';
      confirmChecked = false;
      step = 'input';
    } else {
      resetSuccess = false;
      resetError = 'Factory reset failed. Check the TPM state and authorization password.';
      step = 'result';
      addNotification('error', 'TPM factory reset failed');
    }
  }

  function handleFinish(): void {
    open = false;
    onClose();
    if (resetSuccess) {
      onComplete();
    }
  }
</script>

<Modal bind:open title="Factory Reset TPM" maxWidth="480px">
  {#if step === 'input'}
    <div class="reset-form">
      <div class="step-indicator">
        <span class="step-badge active danger-active">1</span>
        <span class="step-line"></span>
        <span class="step-badge">2</span>
        <span class="step-line"></span>
        <span class="step-badge">3</span>
      </div>
      <div class="danger-banner" role="alert">
        <Icon path={mdiAlert} size={20} />
        <span class="text-body-medium">
          This is a destructive operation that cannot be undone.
        </span>
      </div>
      <p class="text-body-medium reset-description">
        Enter the TPM owner authorization password to proceed with factory reset.
        Leave blank if no owner authorization has been configured.
      </p>
      <Input
        label="Owner Authorization"
        placeholder="Leave blank if not set"
        type="password"
        bind:value={ownerAuth}
        error={errors['auth'] || ''}
      />
    </div>

  {:else if step === 'confirm'}
    <div class="reset-form">
      <div class="step-indicator">
        <span class="step-badge completed danger-completed">
          <Icon path={mdiCheck} size={14} color="#FFFFFF" />
        </span>
        <span class="step-line danger-completed-line"></span>
        <span class="step-badge active danger-active">2</span>
        <span class="step-line"></span>
        <span class="step-badge">3</span>
      </div>
      <div class="confirm-content">
        <div class="confirm-icon danger">
          <Icon path={mdiDeleteSweep} size={40} />
        </div>
        <h3 class="text-title-medium confirm-title danger-text">Confirm Factory Reset</h3>
        <p class="text-body-medium confirm-text">
          This will reset the TPM to the manufacturer OEM state.
          Only the manufacturer Endorsement Key (EK) will remain.
        </p>
        <div class="danger-box" role="alert">
          <Icon path={mdiAlert} size={18} />
          <div class="danger-details">
            <span class="text-body-small danger-text-bold">The following will be permanently deleted:</span>
            <ul class="delete-list">
              <li class="text-body-small">Shared Storage Root Key (SRK)</li>
              <li class="text-body-small">Initial Attestation Key (IAK)</li>
              <li class="text-body-small">Initial Device ID (IDevID)</li>
              <li class="text-body-small">IAK and IDevID NV certificates</li>
            </ul>
            <span class="text-body-small" style="margin-top: 4px; opacity: 0.8;">Note: Endorsement Key (EK) certificates are preserved.</span>
          </div>
        </div>
        <label class="confirm-checkbox">
          <input type="checkbox" bind:checked={confirmChecked} />
          <span class="text-body-small">I understand this action cannot be undone</span>
        </label>
      </div>
    </div>

  {:else if step === 'progress'}
    <div class="reset-form">
      <div class="step-indicator">
        <span class="step-badge completed danger-completed">
          <Icon path={mdiCheck} size={14} color="#FFFFFF" />
        </span>
        <span class="step-line danger-completed-line"></span>
        <span class="step-badge completed danger-completed">
          <Icon path={mdiCheck} size={14} color="#FFFFFF" />
        </span>
        <span class="step-line danger-completed-line"></span>
        <span class="step-badge active danger-active">3</span>
      </div>
      <div class="progress-content">
        <LoadingSpinner size={48} />
        <p class="text-body-medium progress-text">Resetting TPM to factory state...</p>
        <p class="text-body-small progress-subtext">This may take a moment. Do not close this dialog.</p>
      </div>
    </div>

  {:else if step === 'result'}
    <div class="reset-form">
      <div class="step-indicator">
        <span class="step-badge completed danger-completed">
          <Icon path={mdiCheck} size={14} color="#FFFFFF" />
        </span>
        <span class="step-line danger-completed-line"></span>
        <span class="step-badge completed danger-completed">
          <Icon path={mdiCheck} size={14} color="#FFFFFF" />
        </span>
        <span class="step-line danger-completed-line"></span>
        <span class="step-badge" class:completed={resetSuccess} class:danger-completed={resetSuccess} class:error-badge={!resetSuccess}>
          {#if resetSuccess}
            <Icon path={mdiCheck} size={14} color="#FFFFFF" />
          {:else}
            !
          {/if}
        </span>
      </div>
      {#if resetSuccess}
        <div class="result-content success">
          <div class="result-icon success-icon">
            <Icon path={mdiCheck} size={32} color="var(--color-security-verified)" />
          </div>
          <h3 class="text-title-medium result-title">Factory Reset Complete</h3>
          <p class="text-body-medium result-text">
            The TPM has been reset to manufacturer state. Only the EK remains.
            You may now re-provision the TPM using the Install button.
          </p>
        </div>
      {:else}
        <div class="result-content error">
          <div class="result-icon error-icon">
            <Icon path={mdiAlert} size={32} color="var(--color-error)" />
          </div>
          <h3 class="text-title-medium result-title">Factory Reset Failed</h3>
          <p class="text-body-medium result-text">{resetError}</p>
        </div>
      {/if}
    </div>
  {/if}

  <svelte:fragment slot="actions">
    {#if step === 'input'}
      <Button variant="text" on:click={() => { open = false; onClose(); }}>Cancel</Button>
      <Button variant="primary" on:click={handleNext}>Next</Button>
    {:else if step === 'confirm'}
      <Button variant="text" on:click={handleBack}>Back</Button>
      <Button variant="primary" disabled={!confirmChecked} on:click={handleReset}>
        Reset TPM
      </Button>
    {:else if step === 'progress'}
      <!-- No actions during reset -->
    {:else if step === 'result'}
      <Button variant="primary" on:click={handleFinish}>
        {resetSuccess ? 'Done' : 'Close'}
      </Button>
    {/if}
  </svelte:fragment>
</Modal>

<style>
  .reset-form {
    display: flex;
    flex-direction: column;
    gap: 20px;
  }

  .reset-description {
    color: var(--color-on-surface-variant);
    margin: 0;
    line-height: 1.5;
  }

  .step-indicator {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0;
    padding: 8px 0;
  }

  .step-badge {
    width: 28px;
    height: 28px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 12px;
    font-weight: 600;
    background-color: var(--color-surface-container);
    color: var(--color-on-surface-variant);
    border: 2px solid var(--color-outline-variant);
    flex-shrink: 0;
  }

  .step-badge.active {
    background-color: var(--color-primary);
    color: var(--color-on-primary);
    border-color: var(--color-primary);
  }

  .step-badge.danger-active {
    background-color: var(--color-error);
    border-color: var(--color-error);
  }

  .step-badge.completed {
    background-color: var(--color-security-verified);
    border-color: var(--color-security-verified);
  }

  .step-badge.danger-completed {
    background-color: var(--color-error);
    border-color: var(--color-error);
  }

  .step-badge.error-badge {
    background-color: var(--color-error);
    color: var(--color-on-error);
    border-color: var(--color-error);
  }

  .step-line {
    width: 40px;
    height: 2px;
    background-color: var(--color-outline-variant);
    margin: 0 4px;
  }

  .step-line.danger-completed-line {
    background-color: var(--color-error);
  }

  .danger-banner {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 12px;
    border-radius: var(--radius-md);
    background-color: var(--color-security-danger-container);
    color: var(--color-error);
  }

  .confirm-content {
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
    gap: 12px;
  }

  .confirm-icon.danger {
    color: var(--color-error);
  }

  .confirm-title {
    margin: 0;
    color: var(--color-on-surface);
  }

  .danger-text {
    color: var(--color-error);
  }

  .confirm-text {
    color: var(--color-on-surface-variant);
    margin: 0;
    line-height: 1.5;
  }

  .danger-box {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    padding: 12px;
    border-radius: var(--radius-md);
    background-color: var(--color-security-danger-container);
    color: var(--color-error);
    width: 100%;
    text-align: left;
  }

  .danger-details {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .danger-text-bold {
    font-weight: 600;
  }

  .delete-list {
    list-style: disc;
    padding-left: 16px;
    margin: 4px 0 0 0;
  }

  .delete-list li {
    padding: 2px 0;
  }

  .confirm-checkbox {
    display: flex;
    align-items: center;
    gap: 8px;
    cursor: pointer;
    padding: 8px 0;
  }

  .confirm-checkbox input {
    width: 18px;
    height: 18px;
    accent-color: var(--color-error);
  }

  .progress-content {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 16px;
    padding: 24px 0;
  }

  .progress-text {
    color: var(--color-on-surface);
    margin: 0;
    font-weight: 500;
  }

  .progress-subtext {
    color: var(--color-on-surface-variant);
    margin: 0;
  }

  .result-content {
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
    gap: 12px;
    padding: 16px 0;
  }

  .result-icon {
    width: 64px;
    height: 64px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .success-icon {
    background-color: var(--color-security-verified-container);
  }

  .error-icon {
    background-color: var(--color-security-danger-container);
  }

  .result-title {
    margin: 0;
    color: var(--color-on-surface);
  }

  .result-text {
    color: var(--color-on-surface-variant);
    margin: 0;
    line-height: 1.5;
    max-width: 360px;
  }
</style>
