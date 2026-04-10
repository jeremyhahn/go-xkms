<script lang="ts">
  import Modal from './Modal.svelte';
  import Button from './Button.svelte';
  import Input from './Input.svelte';
  import Icon from './Icon.svelte';
  import { mdiQrcodeScan } from '$lib/utils/icons';
  import { isWailsAvailable, callBackend, callBackendWithError } from '$lib/api/backend';
  import type { QRScanResult } from '$lib/api/backend';
  import { addNotification } from '$lib/stores/notifications';

  export let open: boolean = false;
  export let onClose: () => void = () => {};
  export let onAdd: ((data: { issuer: string; account: string; secret: string; digits: number; period: number }) => void) | null = null;
  export let onAccountAdded: (() => void) | null = null;

  let issuer = '';
  let account = '';
  let secret = '';
  let digits = 6;
  let period = 30;
  let errors: Record<string, string> = {};
  let scanning = false;
  let scanError = '';

  $: if (open) {
    issuer = '';
    account = '';
    secret = '';
    digits = 6;
    period = 30;
    errors = {};
    scanError = '';
  }

  function validate(): boolean {
    errors = {};
    if (!issuer.trim()) errors['issuer'] = 'Issuer is required';
    if (!account.trim()) errors['account'] = 'Account name is required';
    if (!secret.trim()) errors['secret'] = 'Secret key is required';
    return Object.keys(errors).length === 0;
  }

  function handleAdd(): void {
    if (!validate()) return;
    onAdd?.({ issuer, account, secret, digits, period });
    open = false;
    onClose();
  }

  function handleClose(): void {
    open = false;
    onClose();
  }

  async function handleScanQR(): Promise<void> {
    if (!isWailsAvailable()) return;
    scanning = true;
    scanError = '';

    const { result, error: scanErr } = await callBackendWithError<QRScanResult>('OATHService', 'ScanQR', -1);
    if (scanErr) {
      // Surface the actual backend error so users can diagnose the issue.
      if (scanErr.includes('no QR code found')) {
        scanError = 'No QR code found on screen. Make sure the QR code is visible, or enter the secret key manually below.';
      } else if (scanErr.includes('not contain a valid otpauth')) {
        scanError = 'QR code found but it is not a TOTP code (e.g., Okta FastPass uses a different protocol). If your service offers a "Can\'t scan?" option, enter the secret key manually below.';
      } else {
        scanError = `Scan failed: ${scanErr}`;
      }
      scanning = false;
      return;
    }

    if (result && result.uri) {
      const { error: addErr } = await callBackendWithError<unknown>('OATHService', 'AddAccountFromURI', result.uri);
      if (addErr) {
        scanError = `Failed to add account: ${addErr}`;
      } else {
        addNotification('success', 'Account added from QR code');
        onAccountAdded?.();
        open = false;
        onClose();
      }
    } else {
      scanError = 'No QR code found on screen. Make sure the otpauth:// QR code is visible.';
    }

    scanning = false;
  }
</script>

<Modal bind:open title="Add OATH Account" maxWidth="440px">
  <div class="add-account-form">
    <!-- QR Scan Section -->
    <div class="qr-scan-section">
      <Button variant="secondary" icon={mdiQrcodeScan} on:click={handleScanQR} loading={scanning} fullWidth>
        {scanning ? 'Scanning...' : 'Scan QR from Screen'}
      </Button>
      {#if scanError}
        <p class="text-body-small scan-error">{scanError}</p>
      {/if}
    </div>

    <!-- Divider -->
    <div class="form-divider">
      <span class="divider-line"></span>
      <span class="text-label-small divider-text">OR ENTER MANUALLY</span>
      <span class="divider-line"></span>
    </div>

    <!-- Manual Form -->
    <Input
      label="Issuer"
      placeholder="e.g., GitHub, Google"
      bind:value={issuer}
      error={errors['issuer'] || ''}
    />
    <Input
      label="Account Name"
      placeholder="e.g., user@example.com"
      bind:value={account}
      error={errors['account'] || ''}
    />
    <Input
      label="Secret Key"
      placeholder="Base32 encoded secret"
      bind:value={secret}
      error={errors['secret'] || ''}
      monospace
    />
    <div class="form-row">
      <div class="form-field">
        <label class="text-label-medium form-label" for="oath-digits">Digits</label>
        <select id="oath-digits" class="form-select" bind:value={digits}>
          <option value={6}>6 digits</option>
          <option value={8}>8 digits</option>
        </select>
      </div>
      <div class="form-field">
        <label class="text-label-medium form-label" for="oath-period">Period</label>
        <select id="oath-period" class="form-select" bind:value={period}>
          <option value={30}>30 seconds</option>
          <option value={60}>60 seconds</option>
        </select>
      </div>
    </div>
  </div>

  <svelte:fragment slot="actions">
    <Button variant="text" on:click={handleClose}>Cancel</Button>
    <Button variant="primary" on:click={handleAdd}>Add Account</Button>
  </svelte:fragment>
</Modal>

<style>
  .add-account-form {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .qr-scan-section {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .scan-error {
    color: var(--color-error);
    margin: 0;
    text-align: center;
  }

  .form-divider {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 4px 0;
  }

  .divider-line {
    flex: 1;
    height: 1px;
    background-color: var(--color-outline-variant);
  }

  .divider-text {
    color: var(--color-on-surface-variant);
    white-space: nowrap;
    letter-spacing: 0.5px;
  }

  .form-row {
    display: flex;
    gap: 16px;
  }

  .form-field {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .form-label {
    color: var(--color-on-surface-variant);
    padding-left: 4px;
  }

  .form-select {
    height: 48px;
    padding: 0 16px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-md);
    background-color: var(--color-surface-container-lowest);
    color: var(--color-on-surface);
    font-family: var(--font-sans);
    font-size: 14px;
    outline: none;
    cursor: pointer;
    appearance: auto;
    transition: border-color var(--transition-fast);
  }

  .form-select:focus {
    border-color: var(--color-primary);
    box-shadow: 0 0 0 1px var(--color-primary);
  }
</style>
