<script lang="ts">
  import Icon from './Icon.svelte';
  import { mdiClose } from '$lib/utils/icons';

  export let open: boolean = false;
  export let title: string = '';
  export let maxWidth: string = '480px';
  export let persistent: boolean = true;

  function handleBackdrop(): void {
    if (!persistent) {
      open = false;
    }
  }

  function handleKeydown(e: KeyboardEvent): void {
    if (e.key === 'Escape' && !persistent) {
      open = false;
    }
  }
</script>

<svelte:window on:keydown={handleKeydown} />

{#if open}
  <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
  <div class="modal-backdrop" on:click={handleBackdrop} on:keydown role="presentation">
    <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
    <div
      class="modal-surface"
      style="max-width: {maxWidth}"
      on:click|stopPropagation
      on:keydown|stopPropagation
      role="dialog"
      aria-modal="true"
      aria-labelledby="modal-title"
      {...$$restProps}
    >
      <div class="modal-header">
        <h2 id="modal-title" class="text-title-large modal-title">{title}</h2>
        <button class="modal-close" on:click={() => (open = false)} aria-label="Close dialog">
          <Icon path={mdiClose} size={20} />
        </button>
      </div>
      <div class="modal-body">
        <slot />
      </div>
      <div class="modal-actions">
        <slot name="actions" />
      </div>
    </div>
  </div>
{/if}

<style>
  .modal-backdrop {
    position: fixed;
    inset: 0;
    background-color: var(--color-scrim-medium);
    display: flex;
    align-items: center;
    justify-content: center;
    z-index: 1000;
    animation: fade-in 200ms ease;
    padding: 24px;
  }

  .modal-surface {
    width: 100%;
    background-color: var(--color-surface-container-high);
    border-radius: var(--radius-xl);
    box-shadow: var(--shadow-xl);
    animation: scale-in 200ms cubic-bezier(0.34, 1.56, 0.64, 1);
    overflow: hidden;
    max-height: calc(100vh - 48px);
    display: flex;
    flex-direction: column;
  }

  .modal-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 24px 24px 0 24px;
  }

  .modal-title {
    color: var(--color-on-surface);
    margin: 0;
  }

  .modal-close {
    width: 36px;
    height: 36px;
    border: none;
    border-radius: 50%;
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: background-color var(--transition-fast);
    flex-shrink: 0;
  }

  .modal-close:hover {
    background-color: var(--color-surface-variant);
  }

  .modal-body {
    padding: 16px 24px;
    overflow-y: auto;
    flex: 1;
  }

  .modal-actions {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    gap: 8px;
    padding: 8px 24px 24px 24px;
  }

  .modal-actions:empty {
    display: none;
  }

  @keyframes fade-in {
    from { opacity: 0; }
    to { opacity: 1; }
  }

  @keyframes scale-in {
    from { opacity: 0; transform: scale(0.92); }
    to { opacity: 1; transform: scale(1); }
  }
</style>
