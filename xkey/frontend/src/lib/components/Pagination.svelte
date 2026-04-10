<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import Button from '$lib/components/Button.svelte';

  /** The currently active page (1-indexed). */
  export let currentPage: number = 1;

  /** Total number of pages. */
  export let totalPages: number = 1;

  /** Total number of items across all pages. */
  export let totalItems: number = 0;

  /** Number of items shown per page. */
  export let pageSize: number = 25;

  const dispatch = createEventDispatcher<{ pagechange: number }>();

  $: startItem = totalItems === 0 ? 0 : (currentPage - 1) * pageSize + 1;
  $: endItem = Math.min(currentPage * pageSize, totalItems);

  function prev(): void {
    if (currentPage > 1) dispatch('pagechange', currentPage - 1);
  }

  function next(): void {
    if (currentPage < totalPages) dispatch('pagechange', currentPage + 1);
  }
</script>

<div class="pagination">
  <span class="pagination-summary text-body-small">
    {#if totalItems === 0}
      No items
    {:else}
      Showing {startItem}–{endItem} of {totalItems}
    {/if}
  </span>

  <div class="pagination-controls">
    <Button
      variant="text"
      size="sm"
      disabled={currentPage <= 1}
      on:click={prev}
    >
      Previous
    </Button>

    <span class="pagination-page text-body-medium">
      {currentPage} / {totalPages}
    </span>

    <Button
      variant="text"
      size="sm"
      disabled={currentPage >= totalPages}
      on:click={next}
    >
      Next
    </Button>
  </div>
</div>

<style>
  .pagination {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 12px 16px;
    border-top: 1px solid var(--md-sys-color-outline-variant, var(--color-outline-variant));
    gap: 16px;
    flex-wrap: wrap;
  }

  .pagination-summary {
    color: var(--md-sys-color-on-surface-variant, var(--color-on-surface-variant));
    white-space: nowrap;
  }

  .pagination-controls {
    display: flex;
    align-items: center;
    gap: 4px;
  }

  .pagination-page {
    color: var(--md-sys-color-on-surface-variant, var(--color-on-surface-variant));
    min-width: 60px;
    text-align: center;
    white-space: nowrap;
  }
</style>
