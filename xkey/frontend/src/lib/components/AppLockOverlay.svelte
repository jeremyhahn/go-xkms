<script lang="ts">
  import { appLocked } from '$lib/stores/events';
  import { setupComplete } from '$lib/stores/app';
  import Icon from './Icon.svelte';
  import { mdiLockOutline } from '$lib/utils/icons';
  import { callBackendVoidWithError } from '$lib/api/backend';

  let pin = '';
  let unlocking = false;
  let error = '';

  function focus(node: HTMLElement) {
    node.focus();
  }

  async function handleUnlock(): Promise<void> {
    if (!pin.trim()) {
      error = 'PIN is required';
      return;
    }
    unlocking = true;
    error = '';
    const result = await callBackendVoidWithError('AppLockService', 'Unlock', pin.trim());
    unlocking = false;
    if (result.ok) {
      appLocked.set(false);
      pin = '';
      error = '';
    } else {
      error = result.error || 'Incorrect PIN';
    }
  }

  function handleKeydown(e: KeyboardEvent): void {
    if (e.key === 'Enter') {
      handleUnlock();
    }
  }
</script>

{#if $appLocked && $setupComplete}
  <div class="lock-overlay" role="dialog" aria-label="App locked">
    <div class="lock-content">
      <div class="lock-icon">
        <Icon path={mdiLockOutline} size={48} color="white" />
      </div>
      <h2>App Locked</h2>
      <p>Enter your PIN to unlock</p>
      <div class="pin-form">
        <input
          type="password"
          class="pin-input"
          bind:value={pin}
          on:keydown={handleKeydown}
          placeholder="Enter PIN"
          disabled={unlocking}
          use:focus
        />
        {#if error}
          <div class="pin-error">{error}</div>
        {/if}
        <button
          class="unlock-button"
          on:click={handleUnlock}
          disabled={unlocking || !pin.trim()}
        >
          {#if unlocking}
            <div class="button-spinner"></div>
            Unlocking...
          {:else}
            Unlock
          {/if}
        </button>
      </div>
    </div>
  </div>
{/if}

<style>
  .lock-overlay {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: rgba(0, 0, 0, 0.9);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 99998;
  }

  .lock-content {
    text-align: center;
    color: white;
    max-width: 320px;
    width: 100%;
    padding: 0 24px;
  }

  .lock-icon {
    width: 80px;
    height: 80px;
    border-radius: 50%;
    background: rgba(255, 255, 255, 0.1);
    display: flex;
    align-items: center;
    justify-content: center;
    margin: 0 auto 24px;
  }

  .lock-content h2 {
    margin: 0 0 8px;
    font-size: 1.5rem;
    font-weight: 600;
  }

  .lock-content p {
    margin: 0 0 24px;
    opacity: 0.7;
    font-size: 0.9rem;
  }

  .pin-form {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .pin-input {
    width: 100%;
    padding: 12px 16px;
    border: 2px solid rgba(255, 255, 255, 0.2);
    border-radius: 8px;
    background: rgba(255, 255, 255, 0.1);
    color: white;
    font-size: 1rem;
    text-align: center;
    letter-spacing: 4px;
    outline: none;
    transition: border-color 0.2s;
    box-sizing: border-box;
  }

  .pin-input:focus {
    border-color: rgba(255, 255, 255, 0.5);
  }

  .pin-input::placeholder {
    color: rgba(255, 255, 255, 0.4);
    letter-spacing: normal;
  }

  .pin-input:disabled {
    opacity: 0.5;
  }

  .pin-error {
    color: #ef5350;
    font-size: 0.85rem;
  }

  .unlock-button {
    padding: 12px 24px;
    border: none;
    border-radius: 8px;
    background: var(--color-primary, #6750a4);
    color: white;
    font-size: 1rem;
    font-weight: 500;
    cursor: pointer;
    transition: opacity 0.2s;
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
  }

  .unlock-button:hover:not(:disabled) {
    opacity: 0.9;
  }

  .unlock-button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .button-spinner {
    width: 16px;
    height: 16px;
    border: 2px solid rgba(255, 255, 255, 0.3);
    border-top-color: white;
    border-radius: 50%;
    animation: spin 0.6s linear infinite;
  }

  @keyframes spin {
    to { transform: rotate(360deg); }
  }
</style>
