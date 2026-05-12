<script lang="ts">
  import { createEventDispatcher } from 'svelte';

  export let currentPage: number = 1;
  export let totalPages: number = 1;

  const dispatch = createEventDispatcher<{ pageChange: number }>();

  function goToPage(page: number) {
    if (page < 1 || page > totalPages || page === currentPage) return;
    dispatch('pageChange', page);
  }

  /** Build a list of page numbers to display, with ellipsis gaps. */
  function getPageNumbers(current: number, total: number): (number | '...')[] {
    if (total <= 7) {
      return Array.from({ length: total }, (_, i) => i + 1);
    }

    const pages: (number | '...')[] = [1];

    if (current > 3) {
      pages.push('...');
    }

    const start = Math.max(2, current - 1);
    const end = Math.min(total - 1, current + 1);

    for (let i = start; i <= end; i++) {
      pages.push(i);
    }

    if (current < total - 2) {
      pages.push('...');
    }

    pages.push(total);
    return pages;
  }

  $: pageNumbers = getPageNumbers(currentPage, totalPages);
</script>

<nav class="flex items-center justify-between" aria-label="Pagination">
  <button
    class="rounded-lg px-3 py-1.5 text-sm font-medium text-slate-600 hover:bg-slate-100 disabled:cursor-not-allowed disabled:opacity-40 dark:text-slate-400 dark:hover:bg-slate-800"
    disabled={currentPage <= 1}
    on:click={() => goToPage(currentPage - 1)}
  >
    Previous
  </button>

  <div class="flex items-center gap-1">
    {#each pageNumbers as page}
      {#if page === '...'}
        <span class="px-2 text-sm text-slate-400">...</span>
      {:else}
        <button
          class="rounded-lg px-3 py-1.5 text-sm font-medium transition-colors
                 {currentPage === page
                   ? 'bg-blue-600 text-white'
                   : 'text-slate-600 hover:bg-slate-100 dark:text-slate-400 dark:hover:bg-slate-800'}"
          on:click={() => goToPage(page)}
          aria-current={currentPage === page ? 'page' : undefined}
        >
          {page}
        </button>
      {/if}
    {/each}
  </div>

  <button
    class="rounded-lg px-3 py-1.5 text-sm font-medium text-slate-600 hover:bg-slate-100 disabled:cursor-not-allowed disabled:opacity-40 dark:text-slate-400 dark:hover:bg-slate-800"
    disabled={currentPage >= totalPages}
    on:click={() => goToPage(currentPage + 1)}
  >
    Next
  </button>
</nav>
