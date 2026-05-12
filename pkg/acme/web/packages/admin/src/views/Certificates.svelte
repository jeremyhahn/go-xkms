<script lang="ts">
  import { onMount } from 'svelte';
  import Card from '@trustedca/shared/components/Card.svelte';
  import DataTable from '@trustedca/shared/components/DataTable.svelte';
  import StatusBadge from '@trustedca/shared/components/StatusBadge.svelte';
  import { formatDate, formatSerial, formatSubject } from '@trustedca/shared/utils/formatters';
  import { certificates, certsPagination, certsLoading, fetchCertificates } from '../lib/stores/certs';

  let page = 1;
  let statusFilter = '';

  const columns = [
    { key: 'serial_number', label: 'Serial', sortable: true, render: (v: string) => formatSerial(v) },
    { key: 'subject', label: 'Subject', sortable: true, render: (v: string) => formatSubject(v) },
    { key: 'issuer', label: 'Issuer', render: (v: string) => formatSubject(v) },
    { key: 'not_before', label: 'Valid From', sortable: true, render: (v: string) => formatDate(v) },
    { key: 'not_after', label: 'Expires', sortable: true, render: (v: string) => formatDate(v) },
    { key: 'status', label: 'Status', sortable: true },
  ];

  function handlePageChange(event: CustomEvent<number>) {
    page = event.detail;
    loadCertificates();
  }

  function loadCertificates() {
    fetchCertificates({
      page,
      per_page: 20,
      status: statusFilter || undefined,
    });
  }

  onMount(() => {
    loadCertificates();
  });
</script>

<div class="p-6">
  <div class="mb-6 flex items-center justify-between">
    <h1 class="text-2xl font-bold text-slate-900 dark:text-slate-100">
      Certificates
    </h1>

    <div class="flex items-center gap-3">
      <select
        class="select"
        bind:value={statusFilter}
        on:change={loadCertificates}
      >
        <option value="">All Statuses</option>
        <option value="valid">Valid</option>
        <option value="revoked">Revoked</option>
        <option value="expired">Expired</option>
      </select>
    </div>
  </div>

  <Card>
    <DataTable
      {columns}
      data={$certificates}
      loading={$certsLoading}
      emptyMessage="No certificates found"
      showPagination={true}
      currentPage={page}
      totalPages={$certsPagination ? Math.ceil($certsPagination.total / ($certsPagination.per_page || 20)) : 1}
      on:pageChange={handlePageChange}
    />
  </Card>
</div>
