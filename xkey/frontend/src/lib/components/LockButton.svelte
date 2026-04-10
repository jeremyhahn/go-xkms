<script lang="ts">
  import Icon from './Icon.svelte';
  import { mdiLock } from '$lib/utils/icons';
  import { callBackendVoidWithError } from '$lib/api/backend';
  import { appLocked } from '$lib/stores/events';
  import { addNotification } from '$lib/stores/notifications';

  let locking = false;

  async function handleLock(): Promise<void> {
    locking = true;
    const result = await callBackendVoidWithError('AppLockService', 'Lock');
    locking = false;
    if (result.ok) {
      appLocked.set(true);
    } else {
      addNotification('error', result.error || 'Failed to lock app');
    }
  }
</script>

<button
  class="lock-button"
  on:click={handleLock}
  disabled={locking}
  aria-label="Lock app"
  title="Lock app"
  data-testid="lock-button"
>
  <Icon path={mdiLock} size={20} />
  <span class="lock-label">Lock</span>
</button>

<style>
  .lock-button {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 8px 14px;
    border: none;
    border-radius: var(--radius-full, 20px);
    background-color: var(--color-surface-container-high, #e7e0ec);
    color: var(--color-on-surface-variant, #49454f);
    cursor: pointer;
    font-family: var(--font-sans);
    font-size: 13px;
    font-weight: 500;
    transition: all var(--transition-fast, 150ms) ease;
    flex-shrink: 0;
  }

  .lock-button:hover {
    background-color: var(--color-surface-container-highest, #d6d0db);
  }

  .lock-button:active {
    transform: scale(0.97);
  }

  .lock-button:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  :global([data-theme="dark"]) .lock-button {
    background-color: var(--color-surface-container-high, #2b2930);
    color: var(--color-on-surface-variant, #cac4d0);
  }

  :global([data-theme="dark"]) .lock-button:hover {
    background-color: var(--color-surface-container-highest, #36343b);
  }

  .lock-label {
    line-height: 1;
  }
</style>
