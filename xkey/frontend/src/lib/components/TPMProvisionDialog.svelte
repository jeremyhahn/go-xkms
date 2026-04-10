<script lang="ts">
  import Modal from './Modal.svelte';
  import Button from './Button.svelte';
  import Input from './Input.svelte';
  import Icon from './Icon.svelte';
  import LoadingSpinner from './LoadingSpinner.svelte';
  import { mdiCheck, mdiAlert, mdiShieldKey } from '$lib/utils/icons';
  import { addNotification } from '$lib/stores/notifications';
  import { callBackendVoid } from '$lib/api/backend';

  export let open: boolean = false;
  export let onClose: () => void = () => {};
  export let onComplete: () => void = () => {};

  type Step = 'input' | 'confirm' | 'progress' | 'result';

  let step: Step = 'input';
  let ownerAuth = '';
  let ownerAuthConfirm = '';
  let errors: Record<string, string> = {};
  let provisionError = '';
  let provisionSuccess = false;

  $: if (open) {
    step = 'input';
    ownerAuth = '';
    ownerAuthConfirm = '';
    errors = {};
    provisionError = '';
    provisionSuccess = false;
  }

  function validateInput(): boolean {
    errors = {};
    if (!ownerAuth) {
      errors['auth'] = 'Owner authorization password is required';
    } else if (ownerAuth.length < 8) {
      errors['auth'] = 'Password must be at least 8 characters';
    }
    if (ownerAuth !== ownerAuthConfirm) {
      errors['confirm'] = 'Passwords do not match';
    }
    return Object.keys(errors).length === 0;
  }

  function handleNext(): void {
    if (!validateInput()) return;
    step = 'confirm';
  }

  function handleBack(): void {
    step = 'input';
  }

  async function handleProvision(): Promise<void> {
    step = 'progress';
    provisionError = '';
    provisionSuccess = false;

    const ok = await callBackendVoid('TPMService', 'Provision', { owner_auth: ownerAuth });

    if (ok) {
      provisionSuccess = true;
      step = 'result';
      addNotification('success', 'TPM provisioned successfully');
    } else {
      provisionSuccess = false;
      provisionError = 'TPM provisioning failed. Check the TPM state and try again.';
      step = 'result';
      addNotification('error', 'TPM provisioning failed');
    }
  }

  function handleFinish(): void {
    open = false;
    onClose();
    if (provisionSuccess) {
      onComplete();
    }
  }
</script>

<Modal bind:open title="Provision TPM" maxWidth="480px">
  {#if step === 'input'}
    <div class="provision-form">
      <div class="step-indicator">
        <span class="step-badge active">1</span>
        <span class="step-line"></span>
        <span class="step-badge">2</span>
        <span class="step-line"></span>
        <span class="step-badge">3</span>
      </div>
      <p class="text-body-medium provision-description">
        Set the owner authorization password for the TPM. This password protects
        the TPM hierarchy and is required for administrative operations.
      </p>
      <Input
        label="Owner Authorization"
        placeholder="Enter owner auth password"
        type="password"
        bind:value={ownerAuth}
        error={errors['auth'] || ''}
        helperText="Minimum 8 characters. Store this securely."
      />
      <Input
        label="Confirm Authorization"
        placeholder="Re-enter owner auth password"
        type="password"
        bind:value={ownerAuthConfirm}
        error={errors['confirm'] || ''}
      />
    </div>

  {:else if step === 'confirm'}
    <div class="provision-form">
      <div class="step-indicator">
        <span class="step-badge completed">
          <Icon path={mdiCheck} size={14} color="#FFFFFF" />
        </span>
        <span class="step-line completed-line"></span>
        <span class="step-badge active">2</span>
        <span class="step-line"></span>
        <span class="step-badge">3</span>
      </div>
      <div class="confirm-content">
        <div class="confirm-icon">
          <Icon path={mdiShieldKey} size={40} />
        </div>
        <h3 class="text-title-medium confirm-title">Confirm Provisioning</h3>
        <p class="text-body-medium confirm-text">
          This will provision the TPM with the specified owner authorization.
          This operation will create the following hierarchy keys:
        </p>
        <ul class="provision-list">
          <li class="text-body-medium">Endorsement Key (EK)</li>
          <li class="text-body-medium">Storage Root Key (SRK)</li>
          <li class="text-body-medium">Initial Attestation Key (IAK)</li>
          <li class="text-body-medium">Initial Device ID (IDevID)</li>
        </ul>
        <div class="warning-box" role="alert">
          <Icon path={mdiAlert} size={18} />
          <span class="text-body-small">
            This operation may overwrite existing TPM keys and cannot be undone.
          </span>
        </div>
      </div>
    </div>

  {:else if step === 'progress'}
    <div class="provision-form">
      <div class="step-indicator">
        <span class="step-badge completed">
          <Icon path={mdiCheck} size={14} color="#FFFFFF" />
        </span>
        <span class="step-line completed-line"></span>
        <span class="step-badge completed">
          <Icon path={mdiCheck} size={14} color="#FFFFFF" />
        </span>
        <span class="step-line completed-line"></span>
        <span class="step-badge active">3</span>
      </div>
      <div class="progress-content">
        <LoadingSpinner size={48} />
        <p class="text-body-medium progress-text">Provisioning TPM...</p>
        <p class="text-body-small progress-subtext">This may take a moment. Do not close this dialog.</p>
      </div>
    </div>

  {:else if step === 'result'}
    <div class="provision-form">
      <div class="step-indicator">
        <span class="step-badge completed">
          <Icon path={mdiCheck} size={14} color="#FFFFFF" />
        </span>
        <span class="step-line completed-line"></span>
        <span class="step-badge completed">
          <Icon path={mdiCheck} size={14} color="#FFFFFF" />
        </span>
        <span class="step-line completed-line"></span>
        <span class="step-badge" class:completed={provisionSuccess} class:error-badge={!provisionSuccess}>
          {#if provisionSuccess}
            <Icon path={mdiCheck} size={14} color="#FFFFFF" />
          {:else}
            !
          {/if}
        </span>
      </div>
      {#if provisionSuccess}
        <div class="result-content success">
          <div class="result-icon success-icon">
            <Icon path={mdiCheck} size={32} color="var(--color-security-verified)" />
          </div>
          <h3 class="text-title-medium result-title">Provisioning Complete</h3>
          <p class="text-body-medium result-text">
            The TPM has been successfully provisioned with the owner authorization.
            All hierarchy keys have been created.
          </p>
        </div>
      {:else}
        <div class="result-content error">
          <div class="result-icon error-icon">
            <Icon path={mdiAlert} size={32} color="var(--color-error)" />
          </div>
          <h3 class="text-title-medium result-title">Provisioning Failed</h3>
          <p class="text-body-medium result-text">{provisionError}</p>
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
      <Button variant="primary" on:click={handleProvision}>Provision</Button>
    {:else if step === 'progress'}
      <!-- No actions during provisioning -->
    {:else if step === 'result'}
      <Button variant="primary" on:click={handleFinish}>
        {provisionSuccess ? 'Done' : 'Close'}
      </Button>
    {/if}
  </svelte:fragment>
</Modal>

<style>
  .provision-form {
    display: flex;
    flex-direction: column;
    gap: 20px;
  }

  .provision-description {
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

  .step-badge.completed {
    background-color: var(--color-security-verified);
    border-color: var(--color-security-verified);
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

  .step-line.completed-line {
    background-color: var(--color-security-verified);
  }

  .confirm-content {
    display: flex;
    flex-direction: column;
    align-items: center;
    text-align: center;
    gap: 12px;
  }

  .confirm-icon {
    color: var(--color-primary);
  }

  .confirm-title {
    margin: 0;
    color: var(--color-on-surface);
  }

  .confirm-text {
    color: var(--color-on-surface-variant);
    margin: 0;
    line-height: 1.5;
  }

  .provision-list {
    list-style: none;
    padding: 0;
    margin: 0;
    text-align: left;
    width: 100%;
  }

  .provision-list li {
    padding: 6px 0;
    padding-left: 20px;
    position: relative;
    color: var(--color-on-surface);
  }

  .provision-list li::before {
    content: '\2022';
    position: absolute;
    left: 4px;
    color: var(--color-primary);
    font-weight: bold;
  }

  .warning-box {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    padding: 12px;
    border-radius: var(--radius-md);
    background-color: var(--color-security-warning-container);
    color: var(--color-on-security-warning-container);
    width: 100%;
    text-align: left;
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
