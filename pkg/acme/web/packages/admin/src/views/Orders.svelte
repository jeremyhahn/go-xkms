<script lang="ts">
  import { onMount, createEventDispatcher } from 'svelte';
  import Card from '@trustedca/shared/components/Card.svelte';
  import LoadingSpinner from '@trustedca/shared/components/LoadingSpinner.svelte';
  import StatusBadge from '@trustedca/shared/components/StatusBadge.svelte';
  import Pagination from '@trustedca/shared/components/Pagination.svelte';
  import { formatDateTime, formatDate } from '@trustedca/shared/utils/formatters';
  import { orders, ordersPagination, ordersLoading, fetchOrders } from '../lib/stores/orders';
  import type { OrderInfo } from '@trustedca/shared/api/types';

  const dispatch = createEventDispatcher<{ viewOrder: string }>();

  let page = 1;
  let statusFilter = '';
  let accountIdFilter = '';

  $: totalPages = $ordersPagination
    ? Math.ceil($ordersPagination.total / ($ordersPagination.per_page || 20))
    : 1;

  function handlePageChange(event: CustomEvent<number>) {
    page = event.detail;
    loadOrders();
  }

  function handleRowClick(order: OrderInfo) {
    dispatch('viewOrder', String(order.id));
  }

  function formatIdentifiers(identifiers: string[]): string {
    if (!Array.isArray(identifiers) || identifiers.length === 0) return '-';
    if (identifiers.length <= 2) return identifiers.join(', ');
    return `${identifiers.slice(0, 2).join(', ')} +${identifiers.length - 2} more`;
  }

  function loadOrders() {
    fetchOrders({
      page,
      per_page: 20,
      status: statusFilter || undefined,
      account_id: accountIdFilter ? Number(accountIdFilter) : undefined,
    });
  }

  onMount(() => {
    loadOrders();
  });
</script>

<div class="p-6">
  <div class="mb-6 flex items-center justify-between">
    <h1 class="text-2xl font-bold text-slate-900 dark:text-slate-100">
      Orders
    </h1>

    <div class="flex items-center gap-3">
      <input
        class="input w-40"
        type="text"
        placeholder="Account ID"
        bind:value={accountIdFilter}
        on:change={loadOrders}
      />

      <select
        class="select"
        bind:value={statusFilter}
        on:change={loadOrders}
      >
        <option value="">All Statuses</option>
        <option value="pending">Pending</option>
        <option value="ready">Ready</option>
        <option value="processing">Processing</option>
        <option value="valid">Valid</option>
        <option value="invalid">Invalid</option>
      </select>
    </div>
  </div>

  <Card>
    <div class="overflow-hidden rounded-lg border border-slate-200 dark:border-slate-700">
      <div class="overflow-x-auto">
        <table class="w-full text-left text-sm">
          <thead class="bg-slate-50 dark:bg-slate-800/50">
            <tr>
              <th class="px-4 py-3 font-medium text-slate-600 dark:text-slate-300">ID</th>
              <th class="px-4 py-3 font-medium text-slate-600 dark:text-slate-300">Account ID</th>
              <th class="px-4 py-3 font-medium text-slate-600 dark:text-slate-300">Status</th>
              <th class="px-4 py-3 font-medium text-slate-600 dark:text-slate-300">Identifiers</th>
              <th class="px-4 py-3 font-medium text-slate-600 dark:text-slate-300">Created</th>
              <th class="px-4 py-3 font-medium text-slate-600 dark:text-slate-300">Expires</th>
            </tr>
          </thead>

          <tbody class="divide-y divide-slate-200 dark:divide-slate-700">
            {#if $ordersLoading}
              <tr>
                <td colspan="6" class="px-4 py-12 text-center">
                  <LoadingSpinner size="md" />
                </td>
              </tr>
            {:else if $orders.length === 0}
              <tr>
                <td colspan="6" class="px-4 py-12 text-center text-slate-500 dark:text-slate-400">
                  No orders found
                </td>
              </tr>
            {:else}
              {#each $orders as order}
                <!-- svelte-ignore a11y-click-events-have-key-events -->
                <!-- svelte-ignore a11y-no-noninteractive-element-interactions -->
                <tr
                  class="cursor-pointer bg-white hover:bg-slate-50 dark:bg-slate-800 dark:hover:bg-slate-700/50"
                  on:click={() => handleRowClick(order)}
                >
                  <td class="px-4 py-3 font-mono text-slate-700 dark:text-slate-300">{order.id}</td>
                  <td class="px-4 py-3 text-slate-700 dark:text-slate-300">{order.account_id}</td>
                  <td class="px-4 py-3">
                    <StatusBadge status={order.status} />
                  </td>
                  <td class="px-4 py-3 text-slate-700 dark:text-slate-300">
                    {formatIdentifiers(order.identifiers)}
                  </td>
                  <td class="px-4 py-3 text-slate-700 dark:text-slate-300">
                    {formatDateTime(order.created_at)}
                  </td>
                  <td class="px-4 py-3 text-slate-700 dark:text-slate-300">
                    {formatDate(order.expires)}
                  </td>
                </tr>
              {/each}
            {/if}
          </tbody>
        </table>
      </div>

      {#if totalPages > 1}
        <div class="border-t border-slate-200 px-4 py-3 dark:border-slate-700">
          <Pagination
            currentPage={page}
            {totalPages}
            on:pageChange={handlePageChange}
          />
        </div>
      {/if}
    </div>
  </Card>
</div>
