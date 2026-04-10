<script lang="ts">
  import Modal from './Modal.svelte';
  import Button from './Button.svelte';
  import Icon from './Icon.svelte';
  import { mdiShieldCheck, mdiClose, mdiCheck, mdiContentCopy } from '$lib/utils/icons';
  import { addNotification } from '$lib/stores/notifications';

  export let open: boolean = false;
  export let code: string = '';
  export let origin: string = '';
  export let success: boolean = false;
  export let onClose: () => void = () => {};

  type PairingStep = 'display_code' | 'success' | 'error';
  let step: PairingStep = 'display_code';
  let errorMessage = '';
  let copied = false;

  $: if (open && !success) {
    step = 'display_code';
    errorMessage = '';
  }

  // When success prop is set externally (from extension:paired event),
  // transition to the success state and auto-close after 2 seconds.
  $: if (success && open && step !== 'success') {
    handleSuccess();
  }

  $: codeDigits = code.split('');

  function handleClose(): void {
    open = false;
    onClose();
  }

  function handleSuccess(): void {
    step = 'success';
    setTimeout(() => {
      handleClose();
    }, 2000);
  }

  async function copyCode(): Promise<void> {
    try {
      await navigator.clipboard.writeText(code);
      copied = true;
      addNotification('success', 'Pairing code copied');
      setTimeout(() => { copied = false; }, 2000);
    } catch {
      addNotification('error', 'Failed to copy code');
    }
  }
</script>

<Modal bind:open title="Extension Pairing" maxWidth="400px">
  <div class="pairing-content">
    {#if step === 'display_code'}
      <div class="pairing-center">
        <div class="pairing-icon">
          <Icon path={mdiShieldCheck} size={48} color="var(--color-primary)" />
        </div>
        <p class="text-body-large pairing-message">
          Enter this code in the browser extension
        </p>
        <div class="code-display">
          {#each codeDigits as digit}
            <span class="code-digit text-headline-medium">{digit}</span>
          {/each}
        </div>
        <button class="copy-btn" on:click={copyCode} title="Copy code to clipboard">
          <Icon path={copied ? mdiCheck : mdiContentCopy} size={16} />
          <span class="text-label-small">{copied ? 'Copied' : 'Copy code'}</span>
        </button>
        <p class="text-body-small pairing-hint">
          The extension from <strong>{origin}</strong> is requesting to pair with xKey.
          Enter the code above in the extension popup to complete pairing.
        </p>
      </div>
    {:else if step === 'success'}
      <div class="pairing-center">
        <div class="success-icon">
          <Icon path={mdiCheck} size={48} color="var(--color-security-verified)" />
        </div>
        <p class="text-body-large pairing-message">Extension paired successfully!</p>
      </div>
    {:else if step === 'error'}
      <div class="pairing-center">
        <p class="text-body-large pairing-error">{errorMessage}</p>
      </div>
    {/if}
  </div>

  <svelte:fragment slot="actions">
    {#if step === 'success'}
      <Button variant="primary" on:click={handleClose}>Done</Button>
    {:else}
      <Button variant="text" on:click={handleClose}>Cancel</Button>
    {/if}
  </svelte:fragment>
</Modal>

<style>
  .pairing-content {
    min-height: 200px;
    display: flex;
    flex-direction: column;
  }

  .pairing-center {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 16px;
    text-align: center;
    padding: 24px 0;
    flex: 1;
  }

  .pairing-icon {
    animation: pulse-indicator 2s ease-in-out infinite;
  }

  .pairing-message {
    color: var(--color-on-surface);
    margin: 0;
  }

  .pairing-hint {
    color: var(--color-on-surface-variant);
    margin: 0;
    max-width: 300px;
  }

  .code-display {
    display: flex;
    gap: 8px;
    justify-content: center;
    margin: 8px 0;
  }

  .code-digit {
    width: 48px;
    height: 56px;
    display: flex;
    align-items: center;
    justify-content: center;
    border: 2px solid var(--color-primary);
    border-radius: var(--radius-md);
    background: var(--color-surface-container-lowest);
    color: var(--color-primary);
    font-family: var(--font-mono);
    font-weight: 700;
  }

  .copy-btn {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 6px 12px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--color-primary);
    cursor: pointer;
    font-family: var(--font-sans);
    transition: background-color var(--transition-fast);
  }

  .copy-btn:hover {
    background-color: var(--color-surface-container);
  }

  .success-icon {
    width: 72px;
    height: 72px;
    border-radius: 50%;
    background-color: var(--color-security-verified-container);
    display: flex;
    align-items: center;
    justify-content: center;
    animation: scale-in 300ms cubic-bezier(0.34, 1.56, 0.64, 1);
  }

  .pairing-error {
    color: var(--color-error);
    margin: 0;
  }

  @keyframes pulse-indicator {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
  }

  @keyframes scale-in {
    from { opacity: 0; transform: scale(0.5); }
    to { opacity: 1; transform: scale(1); }
  }
</style>
