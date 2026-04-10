<script lang="ts">
  import Modal from './Modal.svelte';
  import Button from './Button.svelte';
  import Icon from './Icon.svelte';
  import { mdiShieldLockOutline } from '$lib/utils/icons';

  export let open: boolean = false;
  export let title: string = 'Authentication Required';
  export let message: string = 'This operation requires administrator privileges.';
  export let onAuthenticate: (password: string) => void = () => {};
  export let onCancel: () => void = () => {};

  let password = '';
  let submitting = false;

  function handleSubmit(): void {
    if (!password.trim()) return;
    submitting = true;
    onAuthenticate(password);
    // Clear password from memory immediately after passing it
    password = '';
    submitting = false;
  }

  function handleCancel(): void {
    password = '';
    open = false;
    onCancel();
  }

  function handleKeydown(e: KeyboardEvent): void {
    if (e.key === 'Enter') {
      handleSubmit();
    }
  }

  // Clear password when dialog closes
  $: if (!open) {
    password = '';
  }
</script>

<Modal bind:open {title} maxWidth="420px">
  <div class="sudo-prompt">
    <div class="sudo-header">
      <div class="sudo-icon">
        <Icon path={mdiShieldLockOutline} size={32} />
      </div>
      <p class="text-body-medium sudo-message">{message}</p>
    </div>

    <div class="form-field">
      <label class="text-label-large" for="sudo-password">Password</label>
      <input
        id="sudo-password"
        class="form-input"
        type="password"
        autocomplete="off"
        placeholder="Enter your password"
        bind:value={password}
        on:keydown={handleKeydown}
      />
    </div>
  </div>

  <svelte:fragment slot="actions">
    <Button variant="text" on:click={handleCancel} disabled={submitting}>Cancel</Button>
    <Button
      variant="primary"
      loading={submitting}
      on:click={handleSubmit}
      disabled={!password.trim()}
    >
      Authenticate
    </Button>
  </svelte:fragment>
</Modal>

<style>
  .sudo-prompt {
    display: flex;
    flex-direction: column;
    gap: 20px;
  }

  .sudo-header {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 12px;
    text-align: center;
  }

  .sudo-icon {
    width: 56px;
    height: 56px;
    border-radius: var(--radius-full);
    background: var(--color-primary-95);
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--color-primary);
  }

  :global([data-theme="dark"]) .sudo-icon {
    background: var(--color-primary-container);
    color: var(--color-on-primary-container);
  }

  .sudo-message {
    margin: 0;
    color: var(--color-on-surface-variant);
    line-height: 1.5;
  }

  .form-field {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .form-field label {
    color: var(--color-on-surface-variant);
  }

  .form-input {
    padding: 10px 12px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    background: var(--color-surface);
    color: var(--color-on-surface);
    font-family: var(--font-sans);
    font-size: 14px;
    outline: none;
    transition: border-color var(--transition-fast);
  }

  .form-input:focus {
    border-color: var(--color-primary);
  }

  .form-input::placeholder {
    color: var(--color-on-surface-variant);
    opacity: 0.5;
  }
</style>
