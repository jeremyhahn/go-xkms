<script lang="ts">
  import Icon from './Icon.svelte';
  import { mdiContentCopy } from '$lib/utils/icons';
  import { addNotification } from '$lib/stores/notifications';

  /** The text to copy to the clipboard. */
  export let text: string;
  /** Optional tooltip / aria-label override. */
  export let tooltip: string = 'Copy to clipboard';

  async function handleClick(): Promise<void> {
    try {
      await navigator.clipboard.writeText(text);
      addNotification('success', 'Copied to clipboard');
    } catch {
      addNotification('error', 'Failed to copy to clipboard');
    }
  }
</script>

<button
  class="copy-btn"
  type="button"
  on:click={handleClick}
  title={tooltip}
  aria-label={tooltip}
>
  <Icon path={mdiContentCopy} size={16} />
</button>

<style>
  .copy-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    border: none;
    border-radius: 6px;
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    transition: background-color 120ms, color 120ms;
    flex-shrink: 0;
  }

  .copy-btn:hover {
    background: var(--color-surface-variant);
    color: var(--color-on-surface);
  }

  .copy-btn:focus-visible {
    outline: 2px solid var(--color-primary);
    outline-offset: 2px;
  }
</style>
