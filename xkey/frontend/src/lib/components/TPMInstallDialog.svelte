<script lang="ts">
  import Modal from './Modal.svelte';
  import Button from './Button.svelte';
  import Input from './Input.svelte';
  import Icon from './Icon.svelte';
  import LoadingSpinner from './LoadingSpinner.svelte';
  import { mdiCheck, mdiAlert, mdiShieldKey } from '$lib/utils/icons';
  import { addNotification } from '$lib/stores/notifications';
  import { callBackendVoidWithError, isTPMAuthError } from '$lib/api/backend';

  export let open: boolean = false;
  export let onClose: () => void = () => {};
  export let onComplete: () => void = () => {};

  type Step = 'input' | 'confirm' | 'progress' | 'result';

  let step: Step = 'input';
  let ownerAuth = '';
  let errors: Record<string, string> = {};
  let installError = '';
  let installSuccess = false;

  $: if (open) {
    step = 'input';
    ownerAuth = '';
    errors = {};
    installError = '';
    installSuccess = false;
  }

  function handleNext(): void {
    step = 'confirm';
  }

  function handleBack(): void {
    step = 'input';
  }

  async function handleInstall(): Promise<void> {
    step = 'progress';
    installError = '';
    installSuccess = false;

    const result = await callBackendVoidWithError('TPMService', 'Install', ownerAuth);

    if (result.ok) {
      installSuccess = true;
      step = 'result';
      addNotification('success', 'TPM installed successfully');
    } else if (isTPMAuthError(result.error)) {
      if (ownerAuth === '') {
        // Empty password failed - this TPM requires auth, show on result page
        installSuccess = false;
        installError = 'This TPM requires an owner authorization password. Please try again with the correct password.';
        step = 'result';
      } else {
        // Non-empty password was wrong - go back to input for retry
        errors['auth'] = 'Authorization failed. Please check the owner authorization password.';
        step = 'input';
      }
    } else {
      installSuccess = false;
      installError = 'TPM installation failed. Check the TPM state and authorization password.';
      step = 'result';
      addNotification('error', 'TPM installation failed');
    }
  }

  function handleFinish(): void {
    open = false;
    onClose();
    if (installSuccess) {
      onComplete();
    }
  }
</script>

<Modal bind:open title="Install TPM" maxWidth="480px">
  {#if step === 'input'}
    <div class="install-form">
      <div class="step-indicator">
        <span class="step-badge active">1</span>
        <span class="step-line"></span>
        <span class="step-badge">2</span>
        <span class="step-line"></span>
        <span class="step-badge">3</span>
      </div>
      <p class="text-body-medium install-description">
        Provisions the TCG Shared SRK, IAK, and IDevID. This is a safe operation
        that will not overwrite existing keys.
      </p>
      <Input
        label="Owner Authorization"
        placeholder="Leave blank if not set"
        type="password"
        bind:value={ownerAuth}
        error={errors['auth'] || ''}
        helperText="Leave blank if no owner authorization has been configured."
      />
    </div>

  {:else if step === 'confirm'}
    <div class="install-form">
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
        <h3 class="text-title-medium confirm-title">Confirm Installation</h3>
        <p class="text-body-medium confirm-text">
          This will provision the following TPM identity keys using the provided authorization:
        </p>
        <ul class="install-list">
          <li class="text-body-medium">Shared Storage Root Key (SRK)</li>
          <li class="text-body-medium">Initial Attestation Key (IAK)</li>
          <li class="text-body-medium">Initial Device ID (IDevID)</li>
        </ul>
        <div class="info-box" role="note">
          <Icon path={mdiShieldKey} size={18} />
          <span class="text-body-small">
            Existing keys will not be overwritten. Only missing keys will be created.
          </span>
        </div>
      </div>
    </div>

  {:else if step === 'progress'}
    <div class="install-form">
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
        <p class="text-body-medium progress-text">Installing TPM keys...</p>
        <p class="text-body-small progress-subtext">This may take a moment. Do not close this dialog.</p>
      </div>
    </div>

  {:else if step === 'result'}
    <div class="install-form">
      <div class="step-indicator">
        <span class="step-badge completed">
          <Icon path={mdiCheck} size={14} color="#FFFFFF" />
        </span>
        <span class="step-line completed-line"></span>
        <span class="step-badge completed">
          <Icon path={mdiCheck} size={14} color="#FFFFFF" />
        </span>
        <span class="step-line completed-line"></span>
        <span class="step-badge" class:completed={installSuccess} class:error-badge={!installSuccess}>
          {#if installSuccess}
            <Icon path={mdiCheck} size={14} color="#FFFFFF" />
          {:else}
            !
          {/if}
        </span>
      </div>
      {#if installSuccess}
        <div class="result-content success">
          <div class="result-icon success-icon">
            <Icon path={mdiCheck} size={32} color="var(--color-security-verified)" />
          </div>
          <h3 class="text-title-medium result-title">Installation Complete</h3>
          <p class="text-body-medium result-text">
            The TPM has been successfully installed with SRK, IAK, and IDevID keys.
          </p>
        </div>
      {:else}
        <div class="result-content error">
          <div class="result-icon error-icon">
            <Icon path={mdiAlert} size={32} color="var(--color-error)" />
          </div>
          <h3 class="text-title-medium result-title">Installation Failed</h3>
          <p class="text-body-medium result-text">{installError}</p>
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
      <Button variant="primary" on:click={handleInstall}>Install</Button>
    {:else if step === 'progress'}
      <!-- No actions during installation -->
    {:else if step === 'result'}
      <Button variant="primary" on:click={handleFinish}>
        {installSuccess ? 'Done' : 'Close'}
      </Button>
    {/if}
  </svelte:fragment>
</Modal>

<style>
  .install-form {
    display: flex;
    flex-direction: column;
    gap: 20px;
  }

  .install-description {
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

  .install-list {
    list-style: none;
    padding: 0;
    margin: 0;
    text-align: left;
    width: 100%;
  }

  .install-list li {
    padding: 6px 0;
    padding-left: 20px;
    position: relative;
    color: var(--color-on-surface);
  }

  .install-list li::before {
    content: '\2022';
    position: absolute;
    left: 4px;
    color: var(--color-primary);
    font-weight: bold;
  }

  .info-box {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    padding: 12px;
    border-radius: var(--radius-md);
    background-color: var(--color-surface-container-high);
    color: var(--color-on-surface-variant);
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
