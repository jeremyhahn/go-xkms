<!--
  Copyright (c) 2025 Jeremy Hahn
  Copyright (c) 2025 Automate The Things, LLC
  SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
-->
<script lang="ts">
  import { onMount } from 'svelte';
  import Card from '@trustedca/shared/components/Card.svelte';
  import LoadingSpinner from '@trustedca/shared/components/LoadingSpinner.svelte';
  import { formatDateTime } from '@trustedca/shared/utils/formatters';
  import { adminApi } from '../lib/api/admin-api';
  import { notifyError } from '@trustedca/shared/stores/notifications';
  import type { AuditLog as AuditLogEntry, ListAuditLogsParams } from '@trustedca/shared/api/types';

  let logs = $state<AuditLogEntry[]>([]);
  let loading = $state(false);
  let page = $state(1);
  let totalPages = $state(1);
  let totalCount = $state(0);

  // Filter state
  let filterActor = $state('');
  let filterAction = $state('');
  let filterResource = $state('');
  let filterStartTime = $state('');
  let filterEndTime = $state('');

  // Debounce timer handle
  let filterDebounceTimer: ReturnType<typeof setTimeout> | null = null;

  async function loadLogs() {
    loading = true;
    try {
      const params: ListAuditLogsParams = {
        page,
        per_page: 25,
        actor: filterActor.trim() || undefined,
        action: filterAction.trim() || undefined,
        resource: filterResource.trim() || undefined,
        start_time: filterStartTime || undefined,
        end_time: filterEndTime || undefined,
      };
      const res = await adminApi.listAuditLogs(params) as any;
      logs = res.items ?? res.data ?? [];
      totalCount = res.total ?? res.pagination?.total ?? logs.length;
      const perPage = res.per_page ?? res.pagination?.per_page ?? 25;
      totalPages = Math.ceil(totalCount / perPage);
    } catch (e) {
      notifyError(`Failed to load audit logs: ${(e as Error).message}`);
      logs = [];
    } finally {
      loading = false;
    }
  }

  function onFilterChange() {
    page = 1;
    if (filterDebounceTimer !== null) {
      clearTimeout(filterDebounceTimer);
    }
    filterDebounceTimer = setTimeout(() => {
      loadLogs();
    }, 350);
  }

  function clearFilters() {
    filterActor = '';
    filterAction = '';
    filterResource = '';
    filterStartTime = '';
    filterEndTime = '';
    page = 1;
    loadLogs();
  }

  function prevPage() {
    if (page > 1) {
      page -= 1;
      loadLogs();
    }
  }

  function nextPage() {
    if (page < totalPages) {
      page += 1;
      loadLogs();
    }
  }

  const hasActiveFilters = $derived(
    filterActor !== '' ||
    filterAction !== '' ||
    filterResource !== '' ||
    filterStartTime !== '' ||
    filterEndTime !== ''
  );

  onMount(() => {
    loadLogs();
  });
</script>

<div class="p-6">
  <div class="mb-6 flex items-center justify-between">
    <div>
      <h1 class="text-2xl font-bold text-slate-900 dark:text-slate-100">Audit Log</h1>
      {#if totalCount > 0}
        <p class="mt-1 text-sm text-slate-500 dark:text-slate-400">
          {totalCount} event{totalCount === 1 ? '' : 's'} total
        </p>
      {/if}
    </div>

    <button class="btn btn-ghost btn-sm" onclick={loadLogs}>
      <svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M4 4v5h.582m15.356 2A8.001 8.001 0 004.582 9m0 0H9m11 11v-5h-.581m0 0a8.003 8.003 0 01-15.357-2m15.357 2H15" />
      </svg>
      Refresh
    </button>
  </div>

  <!-- Filters -->
  <Card>
    <div class="mb-1 flex items-center justify-between">
      <h2 class="text-sm font-semibold text-slate-700 dark:text-slate-300">Filters</h2>
      {#if hasActiveFilters}
        <button class="btn btn-ghost btn-xs" onclick={clearFilters}>
          Clear filters
        </button>
      {/if}
    </div>

    <div class="mt-3 grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5">
      <div class="form-control">
        <label class="label py-1" for="filter-actor">
          <span class="label-text text-xs">Actor</span>
        </label>
        <input
          id="filter-actor"
          class="input input-bordered input-sm w-full"
          type="text"
          placeholder="e.g. admin"
          bind:value={filterActor}
          oninput={onFilterChange}
        />
      </div>

      <div class="form-control">
        <label class="label py-1" for="filter-action">
          <span class="label-text text-xs">Action</span>
        </label>
        <input
          id="filter-action"
          class="input input-bordered input-sm w-full"
          type="text"
          placeholder="e.g. create"
          bind:value={filterAction}
          oninput={onFilterChange}
        />
      </div>

      <div class="form-control">
        <label class="label py-1" for="filter-resource">
          <span class="label-text text-xs">Resource</span>
        </label>
        <input
          id="filter-resource"
          class="input input-bordered input-sm w-full"
          type="text"
          placeholder="e.g. tenant"
          bind:value={filterResource}
          oninput={onFilterChange}
        />
      </div>

      <div class="form-control">
        <label class="label py-1" for="filter-start">
          <span class="label-text text-xs">Start Time</span>
        </label>
        <input
          id="filter-start"
          class="input input-bordered input-sm w-full"
          type="datetime-local"
          bind:value={filterStartTime}
          onchange={onFilterChange}
        />
      </div>

      <div class="form-control">
        <label class="label py-1" for="filter-end">
          <span class="label-text text-xs">End Time</span>
        </label>
        <input
          id="filter-end"
          class="input input-bordered input-sm w-full"
          type="datetime-local"
          bind:value={filterEndTime}
          onchange={onFilterChange}
        />
      </div>
    </div>
  </Card>

  <!-- Results table -->
  <div class="mt-4">
    <Card>
      {#if loading}
        <div class="flex justify-center py-12">
          <LoadingSpinner size="lg" />
        </div>
      {:else if logs.length === 0}
        <div class="py-12 text-center text-sm text-slate-500 dark:text-slate-400">
          {hasActiveFilters ? 'No audit events match the current filters.' : 'No audit events found.'}
        </div>
      {:else}
        <div class="overflow-x-auto">
          <table class="table w-full text-sm">
            <thead>
              <tr>
                <th>Timestamp</th>
                <th>Actor</th>
                <th>Action</th>
                <th>Resource</th>
                <th>Details</th>
                <th class="text-center">Result</th>
              </tr>
            </thead>
            <tbody>
              {#each logs as log (log.id)}
                <tr class="hover">
                  <td class="whitespace-nowrap text-slate-500 dark:text-slate-400">
                    {formatDateTime(log.timestamp)}
                  </td>
                  <td class="font-medium text-slate-900 dark:text-slate-100">
                    {log.actor}
                  </td>
                  <td>
                    <span class="badge badge-ghost badge-sm font-mono">
                      {log.action}
                    </span>
                  </td>
                  <td class="text-slate-600 dark:text-slate-300">
                    {log.resource}
                  </td>
                  <td class="max-w-xs truncate text-slate-500 dark:text-slate-400" title={log.details ?? ''}>
                    {log.details || '—'}
                  </td>
                  <td class="text-center">
                    {#if log.success}
                      <span class="badge badge-success badge-sm">OK</span>
                    {:else}
                      <span class="badge badge-error badge-sm">Fail</span>
                    {/if}
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>

        <!-- Pagination -->
        {#if totalPages > 1}
          <div class="mt-4 flex items-center justify-between border-t border-base-200 pt-4">
            <span class="text-sm text-slate-500 dark:text-slate-400">
              Page {page} of {totalPages}
            </span>
            <div class="flex gap-2">
              <button class="btn btn-sm btn-ghost" disabled={page <= 1} onclick={prevPage}>
                Previous
              </button>
              <button class="btn btn-sm btn-ghost" disabled={page >= totalPages} onclick={nextPage}>
                Next
              </button>
            </div>
          </div>
        {/if}
      {/if}
    </Card>
  </div>
</div>
