<script lang="ts">
  import Modal from './Modal.svelte';
  import Button from './Button.svelte';
  import Input from './Input.svelte';
  import { createEventDispatcher } from 'svelte';
  import { callBackendVoidWithError } from '$lib/api/backend';
  import { addNotification } from '$lib/stores/notifications';

  export let open: boolean = false;
  export let mode: 'set-so' | 'change-so' | 'set-user' | 'change-user' = 'set-so';

  const dispatch = createEventDispatcher<{ close: void; success: void }>();

  let authPIN = '';
  let newPIN = '';
  let confirmPIN = '';
  let loading = false;
  let backendError = '';

  const MIN_PIN_LENGTH = 6;

  const titleMap: Record<string, string> = {
    'set-so': 'Set Security Officer PIN',
    'change-so': 'Change Security Officer PIN',
    'set-user': 'Set User PIN',
    'change-user': 'Change User PIN',
  };

  $: title = titleMap[mode] || 'PIN Operation';
  $: strength = getPINStrength(newPIN);

  /** Whether the auth field is required for this mode. */
  $: needsAuth = mode === 'change-so' || mode === 'change-user' || mode === 'set-user';

  function getPINStrength(pin: string): { label: string; color: string; width: string } {
    if (!pin) return { label: '', color: 'transparent', width: '0%' };
    let score = 0;
    if (pin.length >= 6) score++;
    if (pin.length >= 8) score++;
    if (pin.length >= 12) score++;
    if (/[A-Za-z]/.test(pin) && /[0-9]/.test(pin)) score++;
    if (/[^a-zA-Z0-9]/.test(pin)) score++;

    if (score <= 1) return { label: 'Weak', color: 'var(--color-security-danger)', width: '20%' };
    if (score <= 2) return { label: 'Fair', color: 'var(--color-security-warning)', width: '40%' };
    if (score <= 3) return { label: 'Good', color: 'var(--color-security-neutral)', width: '60%' };
    if (score <= 4) return { label: 'Strong', color: 'var(--color-security-verified)', width: '80%' };
    return { label: 'Very Strong', color: 'var(--color-security-verified)', width: '100%' };
  }

  function resetFields(): void {
    authPIN = '';
    newPIN = '';
    confirmPIN = '';
    backendError = '';
    loading = false;
  }

  function handleClose(): void {
    resetFields();
    dispatch('close');
  }

  function formIsValid(): boolean {
    if (newPIN.length < MIN_PIN_LENGTH) return false;
    if (newPIN !== confirmPIN) return false;
    if (needsAuth && authPIN.length === 0) return false;
    return true;
  }

  async function handleSubmit(): Promise<void> {
    if (!formIsValid()) return;
    loading = true;
    backendError = '';

    let result: { ok: boolean; error?: string };

    if (mode === 'set-so') {
      result = await callBackendVoidWithError('PINService', 'SetSOPIN', '', newPIN);
    } else if (mode === 'change-so') {
      result = await callBackendVoidWithError('PINService', 'ChangeSOPIN', authPIN, newPIN);
    } else if (mode === 'set-user') {
      result = await callBackendVoidWithError('PINService', 'SetUserPIN', authPIN, newPIN);
    } else {
      result = await callBackendVoidWithError('PINService', 'ChangeUserPIN', authPIN, newPIN);
    }

    loading = false;

    if (result.ok) {
      addNotification('success', `${titleMap[mode]} successful`);
      resetFields();
      dispatch('success');
    } else {
      backendError = result.error || 'Operation failed';
    }
  }

  $: if (open) {
    resetFields();
  }
</script>

<Modal bind:open title={title} maxWidth="420px">
  <div class="pin-form">
    {#if mode === 'change-so' || mode === 'change-user'}
      <Input
        label={mode === 'change-so' ? 'Current SO PIN' : 'Current User PIN'}
        type="password"
        placeholder="Enter current PIN"
        bind:value={authPIN}
        disabled={loading}
      />
    {/if}

    {#if mode === 'set-user'}
      <Input
        label="SO PIN (Authorization)"
        type="password"
        placeholder="Enter SO PIN to authorize"
        bind:value={authPIN}
        disabled={loading}
      />
    {/if}

    <Input
      label="New PIN"
      type="password"
      placeholder="Enter new PIN"
      bind:value={newPIN}
      disabled={loading}
    />

    {#if newPIN}
      <div class="strength-indicator">
        <div class="strength-bar">
          <div class="strength-fill" style="width: {strength.width}; background-color: {strength.color};"></div>
        </div>
        <span class="text-label-small" style="color: {strength.color};">{strength.label}</span>
      </div>
    {/if}

    <Input
      label="Confirm PIN"
      type="password"
      placeholder="Confirm new PIN"
      bind:value={confirmPIN}
      disabled={loading}
    />

    {#if newPIN.length > 0 && newPIN.length < MIN_PIN_LENGTH}
      <p class="text-body-small validation-msg">PIN must be at least {MIN_PIN_LENGTH} characters</p>
    {/if}

    {#if confirmPIN.length > 0 && newPIN !== confirmPIN}
      <p class="text-body-small validation-msg">PINs do not match</p>
    {/if}

    {#if needsAuth && authPIN.length === 0 && newPIN.length >= MIN_PIN_LENGTH && newPIN === confirmPIN}
      <p class="text-body-small validation-msg" style="color: var(--color-on-surface-variant);">Enter current PIN above to continue</p>
    {/if}

    {#if backendError}
      <div class="error-banner" role="alert">
        <p class="text-body-small">{backendError}</p>
      </div>
    {/if}

    {#if mode === 'set-so'}
      <p class="text-body-small hint-text">
        The Security Officer PIN is used to authorize administrative operations such as setting the User PIN and resetting lockouts.
      </p>
    {:else if mode === 'set-user'}
      <p class="text-body-small hint-text">
        The User PIN is required for everyday cryptographic operations. The SO PIN is needed to authorize this operation.
      </p>
    {/if}
  </div>

  <svelte:fragment slot="actions">
    <Button variant="text" on:click={handleClose} disabled={loading}>
      Cancel
    </Button>
    <Button variant="primary" loading={loading} on:click={handleSubmit} disabled={newPIN.length < MIN_PIN_LENGTH || newPIN !== confirmPIN || (needsAuth && authPIN.length === 0)}>
      {#if mode === 'set-so' || mode === 'set-user'}
        Set PIN
      {:else}
        Change PIN
      {/if}
    </Button>
  </svelte:fragment>
</Modal>

<style>
  .pin-form {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .strength-indicator {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .strength-bar {
    flex: 1;
    height: 4px;
    border-radius: 2px;
    background-color: var(--color-surface-variant);
    overflow: hidden;
  }

  .strength-fill {
    height: 100%;
    border-radius: 2px;
    transition: width 200ms ease, background-color 200ms ease;
  }

  .validation-msg {
    margin: 0;
    color: var(--color-error);
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

  .hint-text {
    color: var(--color-on-surface-variant);
    margin: 0;
  }
</style>
