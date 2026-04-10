<script lang="ts" context="module">
  /**
   * Column definition for the DataTable.
   */
  export interface Column {
    /** Data field name used to look up the value from each row. */
    key: string;
    /** Header display text. */
    label: string;
    /** CSS width (e.g., '120px', 'auto'). */
    width?: string;
    /** Whether this column is sortable. */
    sortable?: boolean;
    /** Text alignment within the column. */
    align?: 'left' | 'center' | 'right';
  }
</script>

<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import EmptyState from '$lib/components/EmptyState.svelte';
  import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
  import Pagination from '$lib/components/Pagination.svelte';

  // ---------------------------------------------------------------------------
  // Props
  // ---------------------------------------------------------------------------

  /** Column definitions describing each visible column. */
  export let columns: Column[] = [];

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  /** Data rows to render. Each row is a plain object keyed by column `key`. */
  export let rows: any[] = [];

  /** The property name used as the unique identifier for each row. */
  export let rowKey: string = 'id';

  /** Enable checkbox-based row selection. */
  export let selectable: boolean = false;

  /** The set of currently-selected row IDs (bindable). */
  export let selectedIds: Set<string> = new Set();

  /** The key of the column currently being sorted. */
  export let sortColumn: string = '';

  /** The current sort direction. */
  export let sortDirection: 'asc' | 'desc' = 'asc';

  /** MDI icon path for the empty state. */
  export let emptyIcon: string = '';

  /** Title text shown when there are no rows. */
  export let emptyTitle: string = 'No data';

  /** Description text shown when there are no rows. */
  export let emptyDescription: string = '';

  /** Whether the table is in a loading state. */
  export let loading: boolean = false;

  /**
   * Number of rows per page. Set to 0 (default) to disable pagination and
   * render all rows.
   */
  export let pageSize: number = 0;

  /**
   * Current page number (1-indexed). Bindable so the parent can read or
   * control the active page.
   */
  export let currentPage: number = 1;

  /**
   * Total number of items when the parent handles server-side pagination.
   * Ignored when serverSidePagination is false.
   */
  export let totalItems: number = 0;

  /**
   * When true the component shows pagination controls but does NOT slice
   * rows — the parent is responsible for providing the correct page slice.
   */
  export let serverSidePagination: boolean = false;

  // ---------------------------------------------------------------------------
  // Events
  // ---------------------------------------------------------------------------

  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const dispatch = createEventDispatcher<{
    select: { selectedIds: Set<string> };
    sort: { column: string; direction: string };
    rowclick: { row: any };
    rowdblclick: { row: any };
    pagechange: number;
  }>();

  // ---------------------------------------------------------------------------
  // Derived state
  // ---------------------------------------------------------------------------

  $: paginationEnabled = pageSize > 0;

  /** Total pages for client-side pagination. */
  $: clientTotalPages = paginationEnabled
    ? Math.max(1, Math.ceil(rows.length / pageSize))
    : 1;

  /** Total pages resolved: server-side uses totalItems, client-side uses rows. */
  $: resolvedTotalPages = serverSidePagination
    ? Math.max(1, Math.ceil(totalItems / pageSize))
    : clientTotalPages;

  /** Total item count shown in the pagination summary. */
  $: resolvedTotalItems = serverSidePagination ? totalItems : rows.length;

  /** Rows to actually render in the table body. */
  $: displayRows = (paginationEnabled && !serverSidePagination)
    ? rows.slice((currentPage - 1) * pageSize, currentPage * pageSize)
    : rows;

  /** Whether every visible row is currently selected. */
  $: allSelected = displayRows.length > 0 && displayRows.every((row) => selectedIds.has(String(row[rowKey])));

  /** Whether at least one -- but not all -- rows are selected. */
  $: someSelected = displayRows.some((row) => selectedIds.has(String(row[rowKey]))) && !allSelected;

  /** Reset to page 1 whenever the underlying row set changes. */
  $: if (rows) { currentPage = 1; }

  // ---------------------------------------------------------------------------
  // Handlers
  // ---------------------------------------------------------------------------

  /**
   * Toggle the selection of all rows at once.
   * Only operates on the currently visible (display) rows.
   */
  function toggleSelectAll(): void {
    if (allSelected) {
      selectedIds = new Set();
    } else {
      selectedIds = new Set(displayRows.map((row) => String(row[rowKey])));
    }
    dispatch('select', { selectedIds });
  }

  /** Handle a page change event from the Pagination component. */
  function handlePageChange(event: CustomEvent<number>): void {
    currentPage = event.detail;
    dispatch('pagechange', currentPage);
  }

  /**
   * Toggle the selection of a single row identified by its key value.
   */
  function toggleRowSelection(id: string): void {
    const next = new Set(selectedIds);
    if (next.has(id)) {
      next.delete(id);
    } else {
      next.add(id);
    }
    selectedIds = next;
    dispatch('select', { selectedIds });
  }

  /**
   * Handle a click on a column header.  If the column is sortable, toggle the
   * sort direction (or switch to the new column in ascending order).
   */
  function handleHeaderClick(column: Column): void {
    if (!column.sortable) return;

    if (sortColumn === column.key) {
      sortDirection = sortDirection === 'asc' ? 'desc' : 'asc';
    } else {
      sortColumn = column.key;
      sortDirection = 'asc';
    }
    dispatch('sort', { column: sortColumn, direction: sortDirection });
  }

  /**
   * Handle a click on a table row.  Toggles selection when selectable, and
   * always dispatches the rowclick event.
   */
  function handleRowClick(row: any): void {
    if (selectable) {
      toggleRowSelection(String(row[rowKey]));
    }
    dispatch('rowclick', { row });
  }

  /**
   * Handle a double-click on a table row.
   */
  function handleRowDblClick(row: any): void {
    dispatch('rowdblclick', { row });
  }

  /**
   * Return the sort indicator character for a given column, or an empty
   * string when the column is not the active sort target.
   */
  function sortIndicator(col: Column): string {
    if (sortColumn !== col.key) return '';
    return sortDirection === 'asc' ? ' \u2191' : ' \u2193';
  }
</script>

<div class="data-table-wrapper">
  {#if loading}
    <div class="loading-container">
      <LoadingSpinner size={40} />
    </div>
  {:else if rows.length === 0}
    <EmptyState
      icon={emptyIcon}
      title={emptyTitle}
      description={emptyDescription}
    />
  {:else}
    <table class="data-table">
      <thead>
        <tr>
          {#if selectable}
            <th class="col-checkbox">
              <input
                type="checkbox"
                checked={allSelected}
                indeterminate={someSelected}
                on:change={toggleSelectAll}
              />
            </th>
          {/if}
          {#each columns as col (col.key)}
            <th
              class="col-header"
              class:sortable={col.sortable}
              style={col.width ? `width: ${col.width}` : ''}
              style:text-align={col.align || 'left'}
              on:click={() => handleHeaderClick(col)}
            >
              {col.label}{sortIndicator(col)}
            </th>
          {/each}
          {#if $$slots.actions}
            <th class="col-header col-actions">Actions</th>
          {/if}
        </tr>
      </thead>
      <tbody>
        {#each displayRows as row (row[rowKey])}
          <tr
            class="data-row"
            class:selected={selectable && selectedIds.has(String(row[rowKey]))}
            on:click={() => handleRowClick(row)}
            on:dblclick={() => handleRowDblClick(row)}
          >
            {#if selectable}
              <td class="col-checkbox">
                <input
                  type="checkbox"
                  checked={selectedIds.has(String(row[rowKey]))}
                  on:change|stopPropagation={() => toggleRowSelection(String(row[rowKey]))}
                />
              </td>
            {/if}
            {#each columns as col (col.key)}
              <td style:text-align={col.align || 'left'}>
                <slot name="cell" {row} column={col} value={row[col.key]}>
                  {row[col.key] ?? ''}
                </slot>
              </td>
            {/each}
            {#if $$slots.actions}
              <td class="col-actions-cell">
                <slot name="actions" {row} />
              </td>
            {/if}
          </tr>
        {/each}
      </tbody>
    </table>

    {#if paginationEnabled && resolvedTotalPages > 1}
      <Pagination
        {currentPage}
        totalPages={resolvedTotalPages}
        totalItems={resolvedTotalItems}
        {pageSize}
        on:pagechange={handlePageChange}
      />
    {/if}
  {/if}
</div>

<style>
  /* -----------------------------------------------------------------------
   * Wrapper
   * --------------------------------------------------------------------- */
  .data-table-wrapper {
    overflow-x: auto;
    border-radius: 12px;
    border: 1px solid var(--md-sys-color-outline-variant);
  }

  /* -----------------------------------------------------------------------
   * Loading state
   * --------------------------------------------------------------------- */
  .loading-container {
    display: flex;
    align-items: center;
    justify-content: center;
    padding: 48px 0;
  }

  /* -----------------------------------------------------------------------
   * Table base
   * --------------------------------------------------------------------- */
  .data-table {
    width: 100%;
    border-collapse: collapse;
    font-size: 0.875rem;
  }

  /* -----------------------------------------------------------------------
   * Header
   * --------------------------------------------------------------------- */
  .data-table thead {
    background: var(--md-sys-color-surface-container);
  }

  .col-header {
    padding: 0.75rem 1rem;
    text-align: left;
    font-weight: 500;
    color: var(--md-sys-color-on-surface-variant);
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    border-bottom: 1px solid var(--md-sys-color-outline-variant);
    white-space: nowrap;
    user-select: none;
  }

  .col-header.sortable {
    cursor: pointer;
  }

  .col-header.sortable:hover {
    color: var(--md-sys-color-on-surface);
  }

  /* -----------------------------------------------------------------------
   * Rows
   * --------------------------------------------------------------------- */
  .data-table td {
    padding: 0.625rem 1rem;
    border-bottom: 1px solid var(--md-sys-color-surface-container-highest);
    vertical-align: middle;
  }

  .data-row {
    cursor: pointer;
    transition: background 0.1s ease;
  }

  .data-row:hover {
    background: var(--md-sys-color-surface-container-low);
  }

  .data-row.selected {
    background: var(--md-sys-color-secondary-container);
  }

  /* -----------------------------------------------------------------------
   * Checkbox column
   * --------------------------------------------------------------------- */
  .col-checkbox {
    width: 40px;
    text-align: center;
  }

  .col-checkbox input[type='checkbox'] {
    cursor: pointer;
    width: 16px;
    height: 16px;
    accent-color: var(--md-sys-color-primary);
  }

  /* -----------------------------------------------------------------------
   * Actions column
   * --------------------------------------------------------------------- */
  .col-actions {
    width: 1%;
    white-space: nowrap;
    text-align: right;
  }

  .col-actions-cell {
    text-align: right;
    white-space: nowrap;
  }
</style>
