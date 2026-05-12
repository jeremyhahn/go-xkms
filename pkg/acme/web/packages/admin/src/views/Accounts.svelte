<script lang="ts">
  import { onMount } from 'svelte';
  import Card from '@trustedca/shared/components/Card.svelte';
  import DataTable from '@trustedca/shared/components/DataTable.svelte';
  import { formatDateTime, formatNumber } from '@trustedca/shared/utils/formatters';
  import { accounts, accountsPagination, accountsLoading, fetchAccounts } from '../lib/stores/accounts';

  let page = 1;
  let statusFilter = '';

  const columns = [
    { key: 'id', label: 'ID', sortable: true },
    { key: 'status', label: 'Status', sortable: true },
    {
      key: 'contact',
      label: 'Contact',
      render: (v: string[]) => (v && v.length > 0 ? v.join(', ') : '-'),
    },
    { key: 'order_count', label: 'Orders', sortable: true, align: 'right' as const, render: (v: number) => formatNumber(v) },
    { key: 'created_at', label: 'Created', sortable: true, render: (v: string) => formatDateTime(v) },
  ];

  function handlePageChange(event: CustomEvent<number>) {
    page = event.detail;
    loadAccounts();
  }

  function loadAccounts() {
    fetchAccounts({
      page,
      per_page: 20,
      status: statusFilter || undefined,
    });
  }

  onMount(() => {
    loadAccounts();
  });
</script>

<div class="p-6">
  <div class="mb-6 flex items-center justify-between">
    <h1 class="text-2xl font-bold text-slate-900 dark:text-slate-100">
      Accounts
    </h1>

    <div class="flex items-center gap-3">
      <select
        class="select"
        bind:value={statusFilter}
        on:change={loadAccounts}
      >
        <option value="">All Statuses</option>
        <option value="valid">Valid</option>
        <option value="deactivated">Deactivated</option>
        <option value="revoked">Revoked</option>
      </select>
    </div>
  </div>

  <Card>
    <DataTable
      {columns}
      data={$accounts}
      loading={$accountsLoading}
      emptyMessage="No accounts found"
      showPagination={true}
      currentPage={page}
      totalPages={$accountsPagination ? Math.ceil($accountsPagination.total / ($accountsPagination.per_page || 20)) : 1}
      on:pageChange={handlePageChange}
    />
  </Card>
</div>
