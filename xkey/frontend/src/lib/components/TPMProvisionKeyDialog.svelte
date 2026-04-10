<script lang="ts">
  import Modal from './Modal.svelte';
  import Button from './Button.svelte';
  import Input from './Input.svelte';
  import Icon from './Icon.svelte';
  import LoadingSpinner from './LoadingSpinner.svelte';
  import { mdiCheck, mdiAlert, mdiKey } from '$lib/utils/icons';
  import { addNotification } from '$lib/stores/notifications';
  import { callBackendVoidWithError, isTPMAuthError } from '$lib/api/backend';

  export let open: boolean = false;
  export let keyType: 'IAK' | 'IDevID' = 'IAK';
  export let onClose: () => void = () => {};
  export let onComplete: () => void = () => {};

  type Step = 'input' | 'progress' | 'result';

  let step: Step = 'input';
  let ownerAuth = '';
  let errors: Record<string, string> = {};
  let provisionError = '';
  let provisionSuccess = false;

  $: keyLabel = keyType === 'IAK' ? 'Initial Attestation Key (IAK)' : 'Initial Device ID (IDevID)';
  $: backendMethod = keyType === 'IAK' ? 'ProvisionIAK' : 'ProvisionIDevID';

  $: if (open) {
    step = 'input';
    ownerAuth = '';
    errors = {};
    provisionError = '';
    provisionSuccess = false;
  }

  async function handleProvision(): Promise<void> {
    step = 'progress';
    provisionError = '';
    provisionSuccess = false;

    const result = await callBackendVoidWithError('TPMService', backendMethod, ownerAuth);

    if (result.ok) {
      provisionSuccess = true;
      step = 'result';
      addNotification('success', `${keyType} provisioned successfully`);
    } else if (isTPMAuthError(result.error)) {
      errors['auth'] = 'Authorization required. Please enter the owner authorization password.';
      step = 'input';
    } else {
      provisionSuccess = false;
      provisionError = `${keyType} provisioning failed. Check the TPM state and authorization password.`;
      step = 'result';
      addNotification('error', `${keyType} provisioning failed`);
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

<Modal bind:open title="Provision {keyType}" maxWidth="440px">
  {#if step === 'input'}
    <div class="provision-form">
      <p class="text-body-medium provision-description">
        Provision the {keyLabel} on the TPM. Leave the owner authorization
        blank if no password has been configured.
      </p>
      <Input
        label="Owner Authorization"
        placeholder="Leave blank if not set"
        type="password"
        bind:value={ownerAuth}
        error={errors['auth'] || ''}
      />
    </div>

  {:else if step === 'progress'}
    <div class="provision-form">
      <div class="progress-content">
        <LoadingSpinner size={48} />
        <p class="text-body-medium progress-text">Provisioning {keyType}...</p>
        <p class="text-body-small progress-subtext">This may take a moment. Do not close this dialog.</p>
      </div>
    </div>

  {:else if step === 'result'}
    <div class="provision-form">
      {#if provisionSuccess}
        <div class="result-content success">
          <div class="result-icon success-icon">
            <Icon path={mdiCheck} size={32} color="var(--color-security-verified)" />
          </div>
          <h3 class="text-title-medium result-title">{keyType} Provisioned</h3>
          <p class="text-body-medium result-text">
            The {keyLabel} has been successfully created on the TPM.
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
      <Button variant="primary" on:click={handleProvision}>
        <Icon path={mdiKey} size={16} />
        Provision {keyType}
      </Button>
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
