<script lang="ts">
  import LoadingSpinner from './LoadingSpinner.svelte';
  import Pagination from './Pagination.svelte';

  interface Column {
    key: string;
    label: string;
    sortable?: boolean;
    width?: string;
    align?: 'left' | 'center' | 'right';
    render?: (value: any, row: any) => string;
  }

  export let columns: Column[] = [];
  export let data: any[] = [];
  export let loading: boolean = false;
  export let emptyMessage: string = 'No data available';
  export let sortKey: string = '';
  export let sortDirection: 'asc' | 'desc' = 'asc';
  export let currentPage: number = 1;
  export let totalPages: number = 1;
  export let showPagination: boolean = false;
  export let onPageChange: ((event: CustomEvent<number>) => void) | undefined =
    undefined;
  export let onRowClick: ((row: unknown) => void) | undefined = undefined;

  function handleSort(key: string) {
    if (sortKey === key) {
      sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
    } else {
      sortKey = key;
      sortDirection = 'asc';
    }
  }

  function getCellValue(row: any, col: Column): string {
    const value = row[col.key];
    if (col.render) return col.render(value, row);
    if (value === undefined || value === null) return '-';
    return String(value);
  }

  function handlePageChange(event: CustomEvent<number>) {
    currentPage = event.detail;
    onPageChange?.(event);
  }
</script>

<div class="overflow-hidden rounded-lg border border-slate-200 dark:border-slate-700">
  <div class="overflow-x-auto">
    <table class="w-full text-left text-sm">
      <thead class="bg-slate-50 dark:bg-slate-800/50">
        <tr>
          {#each columns as col}
            <th
              class="px-4 py-3 font-medium text-slate-600 dark:text-slate-300
                     {col.align === 'center' ? 'text-center' : ''}
                     {col.align === 'right' ? 'text-right' : ''}"
              style={col.width ? `width: ${col.width}` : ''}
            >
              {#if col.sortable}
                <button
                  class="inline-flex items-center gap-1 hover:text-slate-900 dark:hover:text-slate-100"
                  on:click={() => handleSort(col.key)}
                >
                  {col.label}
                  {#if sortKey === col.key}
                    <span class="text-xs">
                      {sortDirection === 'asc' ? '\u25B2' : '\u25BC'}
                    </span>
                  {/if}
                </button>
              {:else}
                {col.label}
              {/if}
            </th>
          {/each}
        </tr>
      </thead>

      <tbody class="divide-y divide-slate-200 dark:divide-slate-700">
        {#if loading}
          <tr>
            <td colspan={columns.length} class="px-4 py-12 text-center">
              <LoadingSpinner size="md" />
            </td>
          </tr>
        {:else if data.length === 0}
          <tr>
            <td
              colspan={columns.length}
              class="px-4 py-12 text-center text-slate-500 dark:text-slate-400"
            >
              {emptyMessage}
            </td>
          </tr>
        {:else}
          {#each data as row}
            <tr
              class="bg-white hover:bg-slate-50 dark:bg-slate-800 dark:hover:bg-slate-700/50
                     {onRowClick ? 'cursor-pointer' : ''}"
              on:click={onRowClick ? () => onRowClick(row) : undefined}
            >
              {#each columns as col}
                <td
                  class="px-4 py-3 text-slate-700 dark:text-slate-300
                         {col.align === 'center' ? 'text-center' : ''}
                         {col.align === 'right' ? 'text-right' : ''}"
                >
                  {getCellValue(row, col)}
                </td>
              {/each}
            </tr>
          {/each}
        {/if}
      </tbody>
    </table>
  </div>

  {#if showPagination && totalPages > 1}
    <div class="border-t border-slate-200 px-4 py-3 dark:border-slate-700">
      <Pagination
        {currentPage}
        {totalPages}
        on:pageChange={handlePageChange}
      />
    </div>
  {/if}
</div>
