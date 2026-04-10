<script lang="ts">
  import Modal from './Modal.svelte';
  import Button from './Button.svelte';
  import Input from './Input.svelte';
  import Toggle from './Toggle.svelte';
  import Icon from './Icon.svelte';
  import { createEventDispatcher } from 'svelte';
  import { mdiChip, mdiShieldLockOutline } from '$lib/utils/icons';
  import { callBackendVoidWithError } from '$lib/api/backend';
  import { addNotification } from '$lib/stores/notifications';

  export let open: boolean = false;
  export let strategy: string = 'software';

  const dispatch = createEventDispatcher<{ close: void; success: void }>();

  let password = '';
  let autoUnseal = false;
  let loading = false;
  let backendError = '';

  $: credentialLabel = getCredentialLabel(strategy);
  $: isTPMAvailable = strategy === 'tpm2' || strategy === 'tpm';

  function getCredentialLabel(strat: string): string {
    if (strat === 'pkcs11' || strat === 'PKCS#11') return 'Enter PKCS#11 PIN';
    if (strat === 'tpm2' || strat === 'tpm' || strat === 'TPM 2.0') return 'Enter PIN';
    return 'Enter password';
  }

  function resetFields(): void {
    password = '';
    autoUnseal = false;
    backendError = '';
    loading = false;
  }

  function handleClose(): void {
    resetFields();
    dispatch('close');
  }

  async function handleSubmit(): Promise<void> {
    if (!password && !autoUnseal) return;
    loading = true;
    backendError = '';

    let result: { ok: boolean; error?: string };

    if (autoUnseal) {
      result = await callBackendVoidWithError('BarrierService', 'AutoUnseal');
    } else {
      result = await callBackendVoidWithError('BarrierService', 'Unseal', password);
    }

    loading = false;

    if (result.ok) {
      addNotification('success', 'Barrier unsealed successfully');
      resetFields();
      dispatch('success');
    } else {
      backendError = result.error || 'Failed to unseal. Check your credentials.';
    }
  }

  $: if (open) {
    resetFields();
  }
</script>

<Modal bind:open title="Unseal Barrier" maxWidth="420px">
  <div class="unseal-form">
    <div class="strategy-indicator">
      <Icon path={mdiShieldLockOutline} size={20} />
      <div class="strategy-info">
        <span class="text-label-medium">Strategy</span>
        <span class="text-body-medium strategy-value">{strategy}</span>
      </div>
    </div>

    {#if isTPMAvailable}
      <div class="auto-unseal-option">
        <div class="setting-info">
          <span class="text-title-small">Auto-unseal with TPM</span>
          <span class="text-body-small setting-desc">Use TPM-sealed credentials to unseal without a password</span>
        </div>
        <Toggle bind:checked={autoUnseal} />
      </div>
    {/if}

    {#if !autoUnseal}
      <Input
        label={credentialLabel}
        type="password"
        placeholder={credentialLabel}
        bind:value={password}
        disabled={loading}
      />
    {:else}
      <div class="auto-unseal-notice" role="status">
        <Icon path={mdiChip} size={20} />
        <span class="text-body-small">
          The TPM will provide the sealed credentials automatically. No password input is needed.
        </span>
      </div>
    {/if}

    {#if backendError}
      <div class="error-banner" role="alert">
        <p class="text-body-small">{backendError}</p>
      </div>
    {/if}
  </div>

  <svelte:fragment slot="actions">
    <Button variant="text" on:click={handleClose} disabled={loading}>
      Cancel
    </Button>
    <Button
      variant="primary"
      loading={loading}
      on:click={handleSubmit}
      disabled={!autoUnseal && !password}
    >
      Unseal
    </Button>
  </svelte:fragment>
</Modal>

<style>
  .unseal-form {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .strategy-indicator {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 16px;
    background-color: var(--color-surface-container);
    border-radius: var(--radius-sm);
    color: var(--color-on-surface-variant);
  }

  .strategy-info {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .strategy-info .text-label-medium {
    color: var(--color-on-surface-variant);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    font-size: 10px;
  }

  .strategy-value {
    color: var(--color-on-surface);
    text-transform: capitalize;
  }

  .auto-unseal-option {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
    padding: 8px 0;
  }

  .setting-info {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .setting-info span:first-child {
    color: var(--color-on-surface);
  }

  .setting-desc {
    color: var(--color-on-surface-variant);
  }

  .auto-unseal-notice {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 12px 16px;
    background-color: var(--color-surface-container);
    border-radius: var(--radius-sm);
    color: var(--color-on-surface-variant);
  }

  .error-banner {
    padding: 10px 14px;
    background-color: var(--color-security-danger-container);
    border-radius: var(--radius-sm);
  }

  .error-banner p {
    margin: 0;
    color: var(--color-on-security-danger-container);
  }
</style>
