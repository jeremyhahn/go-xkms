<script lang="ts">
  import Modal from './Modal.svelte';
  import Button from './Button.svelte';
  import Input from './Input.svelte';
  import { callBackendWithError } from '$lib/api/backend';
  import { addNotification } from '$lib/stores/notifications';

  export let open: boolean = false;
  export let mode: 'create' | 'migrate' = 'create';
  export let onClose: () => void = () => {};
  export let onComplete: () => void = () => {};

  let passphrase = '';
  let confirmPassphrase = '';
  let sizeGB = 10;
  let backupOriginal = true;
  let errors: Record<string, string> = {};
  let processing = false;

  const MIN_PASSPHRASE_LENGTH = 8;
  const MIN_SIZE_GB = 1;
  const MAX_SIZE_GB = 100;

  $: if (open) {
    passphrase = '';
    confirmPassphrase = '';
    sizeGB = 10;
    backupOriginal = true;
    errors = {};
    processing = false;
  }

  $: dialogTitle = mode === 'create' ? 'Create Encrypted Volume' : 'Migrate to Encrypted Storage';

  function validate(): boolean {
    errors = {};

    if (!passphrase) {
      errors['passphrase'] = 'Passphrase is required';
    } else if (passphrase.length < MIN_PASSPHRASE_LENGTH) {
      errors['passphrase'] = `Passphrase must be at least ${MIN_PASSPHRASE_LENGTH} characters`;
    }

    if (!confirmPassphrase) {
      errors['confirm'] = 'Please confirm your passphrase';
    } else if (passphrase !== confirmPassphrase) {
      errors['confirm'] = 'Passphrases do not match';
    }

    if (sizeGB < MIN_SIZE_GB || sizeGB > MAX_SIZE_GB) {
      errors['size'] = `Volume size must be between ${MIN_SIZE_GB} and ${MAX_SIZE_GB} GB`;
    }

    return Object.keys(errors).length === 0;
  }

  async function handleSubmit(): Promise<void> {
    if (!validate()) return;

    processing = true;

    if (mode === 'create') {
      const { error } = await callBackendWithError<unknown>('StorageService', 'CreateVolume', {
        size_gb: sizeGB,
        passphrase: passphrase,
      });
      processing = false;

      if (!error) {
        addNotification('success', `Encrypted volume created and unlocked (${sizeGB} GB)`);
        open = false;
        onComplete();
      } else {
        addNotification('error', `Failed to create volume: ${error}`);
      }
    } else {
      const { error } = await callBackendWithError<unknown>(
        'StorageService', 'MigrateToEncrypted',
        sizeGB, passphrase, backupOriginal
      );
      processing = false;

      if (!error) {
        const backupMsg = backupOriginal ? ' Original data backed up to ~/.xkey-backup.' : '';
        addNotification('success', `Data migrated to encrypted storage and volume unlocked.${backupMsg}`);
        open = false;
        onComplete();
      } else {
        addNotification('error', `Failed to migrate: ${error}`);
      }
    }
  }

  function handleCancel(): void {
    open = false;
    onClose();
  }
</script>

<Modal bind:open title={dialogTitle} maxWidth="480px">
  <div class="storage-form">
    <p class="text-body-medium form-desc">
      {#if mode === 'create'}
        Create a LUKS-encrypted volume for secure key storage. Choose a strong passphrase that you will remember -- it cannot be recovered.
      {:else}
        Migrate existing data from <code>~/.xkey/</code> into a new LUKS-encrypted volume. Existing data will be copied into the encrypted container and the original plaintext data will be removed.
      {/if}
    </p>

    <Input
      label="Passphrase"
      type="password"
      placeholder="Enter a strong passphrase"
      bind:value={passphrase}
      error={errors['passphrase'] || ''}
      disabled={processing}
    />

    <Input
      label="Confirm Passphrase"
      type="password"
      placeholder="Re-enter passphrase"
      bind:value={confirmPassphrase}
      error={errors['confirm'] || ''}
      disabled={processing}
    />

    <div class="form-field">
      <label class="text-label-medium form-label" for="volume-size">Volume Size (GB)</label>
      <div class="size-input-row">
        <input
          id="volume-size"
          type="range"
          min={MIN_SIZE_GB}
          max={MAX_SIZE_GB}
          bind:value={sizeGB}
          class="range-input"
          disabled={processing}
          aria-describedby="volume-size-value"
        />
        <span id="volume-size-value" class="text-body-medium size-value">{sizeGB} GB</span>
      </div>
      {#if errors['size']}
        <span class="text-body-small error-text">{errors['size']}</span>
      {/if}
    </div>

    {#if mode === 'migrate'}
      <label class="checkbox-row" class:checkbox-disabled={processing}>
        <input
          type="checkbox"
          bind:checked={backupOriginal}
          disabled={processing}
          class="checkbox-input"
        />
        <div class="checkbox-text">
          <span class="text-body-medium">Backup original data</span>
          <span class="text-body-small checkbox-desc">
            Save a copy of your existing data to <code>~/.xkey-backup/</code> before removing the originals
          </span>
        </div>
      </label>
    {/if}

    {#if processing}
      <div class="processing-status" role="status" aria-live="polite">
        <svg class="status-spinner" viewBox="0 0 24 24" width="20" height="20" aria-hidden="true">
          <circle cx="12" cy="12" r="10" fill="none" stroke="var(--color-primary)" stroke-width="2" stroke-dasharray="31.4 31.4" />
        </svg>
        <span class="text-body-small">
          {mode === 'create' ? 'Creating encrypted volume...' : 'Migrating data to encrypted storage...'}
          This may take a few minutes.
        </span>
      </div>
    {/if}
  </div>

  <svelte:fragment slot="actions">
    <Button variant="text" on:click={handleCancel} disabled={processing}>Cancel</Button>
    <Button variant="primary" on:click={handleSubmit} loading={processing}>
      {#if processing}
        {mode === 'create' ? 'Creating...' : 'Migrating...'}
      {:else}
        {mode === 'create' ? 'Create Volume' : 'Migrate Data'}
      {/if}
    </Button>
  </svelte:fragment>
</Modal>

<style>
  .storage-form {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .form-desc {
    margin: 0;
    color: var(--color-on-surface-variant);
    line-height: 1.5;
  }

  .form-desc code {
    padding: 2px 6px;
    background-color: var(--color-surface-container);
    border-radius: var(--radius-sm);
    font-family: var(--font-mono);
    font-size: 13px;
  }

  .form-field {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .form-label {
    color: var(--color-on-surface-variant);
    padding-left: 4px;
  }

  .size-input-row {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .range-input {
    flex: 1;
    accent-color: var(--color-primary);
    height: 6px;
  }

  .range-input:disabled {
    opacity: 0.5;
  }

  .size-value {
    min-width: 56px;
    text-align: right;
    color: var(--color-on-surface);
    font-weight: 500;
  }

  .error-text {
    color: var(--color-error);
    padding-left: 4px;
  }

  .checkbox-row {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 10px 12px;
    border-radius: var(--radius-sm);
    background-color: var(--color-surface-container);
    cursor: pointer;
    transition: background-color var(--transition-fast);
  }

  .checkbox-row:hover {
    background-color: var(--color-surface-container-high);
  }

  .checkbox-disabled {
    opacity: 0.5;
    pointer-events: none;
  }

  .checkbox-input {
    margin-top: 2px;
    accent-color: var(--color-primary);
    flex-shrink: 0;
    width: 16px;
    height: 16px;
  }

  .checkbox-text {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .checkbox-text code {
    padding: 1px 4px;
    background-color: var(--color-surface-container-highest);
    border-radius: var(--radius-sm);
    font-family: var(--font-mono);
    font-size: 12px;
  }

  .checkbox-desc {
    color: var(--color-on-surface-variant);
    line-height: 1.4;
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

  .status-spinner {
    animation: spin 0.8s linear infinite;
    flex-shrink: 0;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }
</style>
