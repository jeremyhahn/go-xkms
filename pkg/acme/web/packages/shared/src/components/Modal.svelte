<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import { fade, fly } from 'svelte/transition';

  export let open: boolean = false;
  export let title: string = '';
  export let size: 'sm' | 'md' | 'lg' | 'xl' = 'md';
  export let closeable: boolean = true;

  const dispatch = createEventDispatcher<{ close: void }>();

  const sizeClasses: Record<string, string> = {
    sm: 'max-w-sm',
    md: 'max-w-lg',
    lg: 'max-w-2xl',
    xl: 'max-w-4xl',
  };

  function handleClose() {
    if (closeable) {
      open = false;
      dispatch('close');
    }
  }

  function handleKeydown(e: KeyboardEvent) {
    if (e.key === 'Escape' && closeable) {
      handleClose();
    }
  }

  function handleBackdropClick() {
    handleClose();
  }
</script>

<svelte:window on:keydown={handleKeydown} />

{#if open}
  <!-- Backdrop -->
  <div
    class="fixed inset-0 z-50 flex items-center justify-center"
    role="dialog"
    aria-modal="true"
    aria-labelledby="modal-title"
  >
    <!-- svelte-ignore a11y-click-events-have-key-events -->
    <!-- svelte-ignore a11y-no-static-element-interactions -->
    <div
      class="absolute inset-0 bg-black/50 dark:bg-black/70"
      on:click={handleBackdropClick}
      transition:fade={{ duration: 150 }}
    ></div>

    <div
      class="relative z-10 w-full {sizeClasses[size]} rounded-xl bg-white shadow-2xl dark:bg-slate-800"
      transition:fly={{ y: 16, duration: 200 }}
    >
      <!-- Header -->
      {#if title || closeable}
        <div class="flex items-center justify-between border-b border-slate-200 px-6 py-4 dark:border-slate-700">
          {#if title}
            <h2
              id="modal-title"
              class="text-lg font-semibold text-slate-900 dark:text-slate-100"
            >
              {title}
            </h2>
          {/if}

          {#if closeable}
            <button
              class="rounded-lg p-1 text-slate-400 hover:bg-slate-100 hover:text-slate-600 dark:hover:bg-slate-700 dark:hover:text-slate-300"
              on:click={handleClose}
              aria-label="Close"
            >
              <svg class="h-5 w-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                <path stroke-linecap="round" stroke-linejoin="round" d="M6 18L18 6M6 6l12 12" />
              </svg>
            </button>
          {/if}
        </div>
      {/if}

      <!-- Body -->
      <div class="px-6 py-4">
        <slot />
      </div>

      <!-- Footer -->
      {#if $$slots.footer}
        <div class="border-t border-slate-200 px-6 py-3 dark:border-slate-700">
          <slot name="footer" />
        </div>
      {/if}
    </div>
  </div>
{/if}
