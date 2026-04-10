<script lang="ts">
  import Modal from './Modal.svelte';
  import Button from './Button.svelte';
  import Input from './Input.svelte';
  import { addNotification } from '$lib/stores/notifications';

  export let open: boolean = false;
  export let mode: 'set' | 'unlock' | 'change' = 'set';
  export let onClose: () => void = () => {};
  export let onSubmit: (password: string, oldPassword?: string) => void = () => {};

  let password = '';
  let confirmPassword = '';
  let oldPassword = '';
  let loading = false;

  $: title = mode === 'set' ? 'Set Master Password'
    : mode === 'unlock' ? 'Unlock Passwords'
    : 'Change Master Password';

  $: strength = getPasswordStrength(password);

  function getPasswordStrength(pw: string): { label: string; color: string; width: string } {
    if (!pw) return { label: '', color: 'transparent', width: '0%' };
    let score = 0;
    if (pw.length >= 8) score++;
    if (pw.length >= 12) score++;
    if (/[A-Z]/.test(pw)) score++;
    if (/[0-9]/.test(pw)) score++;
    if (/[^a-zA-Z0-9]/.test(pw)) score++;

    if (score <= 1) return { label: 'Weak', color: 'var(--color-security-danger)', width: '20%' };
    if (score <= 2) return { label: 'Fair', color: 'var(--color-security-warning)', width: '40%' };
    if (score <= 3) return { label: 'Good', color: 'var(--color-security-neutral)', width: '60%' };
    if (score <= 4) return { label: 'Strong', color: 'var(--color-security-verified)', width: '80%' };
    return { label: 'Very Strong', color: 'var(--color-security-verified)', width: '100%' };
  }

  function handleSubmit(): void {
    if (mode === 'unlock') {
      if (!password) {
        addNotification('error', 'Password is required');
        return;
      }
      onSubmit(password);
    } else if (mode === 'set') {
      if (!password) {
        addNotification('error', 'Password is required');
        return;
      }
      if (password !== confirmPassword) {
        addNotification('error', 'Passwords do not match');
        return;
      }
      if (password.length < 8) {
        addNotification('error', 'Password must be at least 8 characters');
        return;
      }
      onSubmit(password);
    } else if (mode === 'change') {
      if (!oldPassword) {
        addNotification('error', 'Current password is required');
        return;
      }
      if (!password) {
        addNotification('error', 'New password is required');
        return;
      }
      if (password !== confirmPassword) {
        addNotification('error', 'New passwords do not match');
        return;
      }
      if (password.length < 8) {
        addNotification('error', 'New password must be at least 8 characters');
        return;
      }
      onSubmit(password, oldPassword);
    }
  }

  function resetFields(): void {
    password = '';
    confirmPassword = '';
    oldPassword = '';
  }

  $: if (open) {
    resetFields();
  }
</script>

<Modal bind:open {title} maxWidth="420px">
  <div class="master-pw-form">
    {#if mode === 'change'}
      <Input
        label="Current Password"
        type="password"
        placeholder="Enter current password"
        bind:value={oldPassword}
      />
    {/if}

    <Input
      label={mode === 'change' ? 'New Password' : 'Master Password'}
      type="password"
      placeholder={mode === 'unlock' ? 'Enter master password' : 'Enter new password'}
      bind:value={password}
    />

    {#if mode !== 'unlock' && password}
      <div class="strength-indicator">
        <div class="strength-bar">
          <div class="strength-fill" style="width: {strength.width}; background-color: {strength.color};"></div>
        </div>
        <span class="text-label-small" style="color: {strength.color};">{strength.label}</span>
      </div>
    {/if}

    {#if mode !== 'unlock'}
      <Input
        label="Confirm Password"
        type="password"
        placeholder="Confirm password"
        bind:value={confirmPassword}
      />
    {/if}

    {#if mode === 'set'}
      <p class="text-body-small hint-text">
        This password will be used to encrypt your stored passwords. Choose a strong, memorable password.
      </p>
    {/if}
  </div>

  <svelte:fragment slot="actions">
    <Button variant="text" on:click={() => { onClose(); }} disabled={loading}>
      Cancel
    </Button>
    <Button variant="primary" loading={loading} on:click={handleSubmit}>
      {mode === 'unlock' ? 'Unlock' : mode === 'change' ? 'Change Password' : 'Set Password'}
    </Button>
  </svelte:fragment>
</Modal>

<style>
  .master-pw-form {
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

  .hint-text {
    color: var(--color-on-surface-variant);
    margin: 0;
  }
</style>
