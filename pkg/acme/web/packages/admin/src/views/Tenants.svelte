<!--
  Copyright (c) 2025 Jeremy Hahn
  Copyright (c) 2025 Automate The Things, LLC
  SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
-->
<script lang="ts">
  import { onMount } from 'svelte';
  import Card from '@trustedca/shared/components/Card.svelte';
  import DataTable from '@trustedca/shared/components/DataTable.svelte';
  import Button from '@trustedca/shared/components/Button.svelte';
  import { formatDateTime } from '@trustedca/shared/utils/formatters';
  import { tenants, tenantsPagination, tenantsLoading, fetchTenants } from '../lib/stores/tenants';
  import { adminApi } from '../lib/api/admin-api';
  import { notifySuccess, notifyError } from '@trustedca/shared/stores/notifications';

  interface Props {
    onviewTenant?: (tenantId: string) => void;
  }

  let { onviewTenant }: Props = $props();

  let page = $state(1);
  let statusFilter = $state('');

  let showCreateModal = $state(false);
  let newTenantId = $state('');
  let newTenantName = $state('');
  let createSubmitting = $state(false);

  const columns = [
    { key: 'id', label: 'ID', sortable: true },
    { key: 'name', label: 'Name', sortable: true },
    { key: 'status', label: 'Status', sortable: true },
    { key: 'created_at', label: 'Created', sortable: true, render: (v: string) => formatDateTime(v) },
    { key: 'updated_at', label: 'Updated', sortable: true, render: (v: string) => formatDateTime(v) },
  ];

  function handlePageChange(event: CustomEvent<number>) {
    page = event.detail;
    loadTenants();
  }

  function loadTenants() {
    fetchTenants({
      page,
      per_page: 20,
      status: statusFilter || undefined,
    });
  }

  async function handleCreateTenant() {
    if (!newTenantId.trim() || !newTenantName.trim()) {
      notifyError('Tenant ID and Name are required.');
      return;
    }
    createSubmitting = true;
    try {
      await adminApi.createTenant({ id: newTenantId.trim(), name: newTenantName.trim() });
      showCreateModal = false;
      newTenantId = '';
      newTenantName = '';
      notifySuccess('Tenant created successfully.');
      loadTenants();
    } catch (e) {
      notifyError(`Failed to create tenant: ${(e as Error).message}`);
    } finally {
      createSubmitting = false;
    }
  }

  function handleRowClick(row: unknown) {
    const tenant = row as { id: string };
    onviewTenant?.(tenant.id);
  }

  onMount(() => {
    loadTenants();
  });
</script>

<div class="p-6">
  <div class="mb-6 flex items-center justify-between">
    <h1 class="text-2xl font-bold text-slate-900 dark:text-slate-100">
      Tenants
    </h1>

    <div class="flex items-center gap-3">
      <select
        class="select"
        bind:value={statusFilter}
        onchange={loadTenants}
      >
        <option value="">All Statuses</option>
        <option value="active">Active</option>
        <option value="suspended">Suspended</option>
        <option value="deleted">Deleted</option>
      </select>

      <Button variant="primary" size="sm" onclick={() => { showCreateModal = true; }}>
        Create Tenant
      </Button>
    </div>
  </div>

  <Card>
    <DataTable
      {columns}
      data={$tenants}
      loading={$tenantsLoading}
      emptyMessage="No tenants found"
      showPagination={true}
      currentPage={page}
      totalPages={$tenantsPagination ? Math.ceil($tenantsPagination.total / ($tenantsPagination.per_page || 20)) : 1}
      onPageChange={handlePageChange}
      onRowClick={handleRowClick}
    />
  </Card>
</div>

<!-- Create Tenant Modal -->
<dialog class="modal" class:modal-open={showCreateModal}>
  <div class="modal-box">
    <h3 class="text-lg font-bold text-slate-900 dark:text-slate-100">Create Tenant</h3>
    <p class="py-2 text-sm text-slate-500 dark:text-slate-400">
      Provision a new tenant with an isolated CA hierarchy.
    </p>

    <div class="mt-4 space-y-4">
      <div class="form-control w-full">
        <label class="label" for="tenant-id">
          <span class="label-text">Tenant ID <span class="text-error">*</span></span>
        </label>
        <input
          id="tenant-id"
          class="input input-bordered w-full"
          type="text"
          placeholder="e.g. acme-corp"
          bind:value={newTenantId}
        />
        <label class="label">
          <span class="label-text-alt text-slate-500">Unique identifier — lowercase, no spaces.</span>
        </label>
      </div>

      <div class="form-control w-full">
        <label class="label" for="tenant-name">
          <span class="label-text">Display Name <span class="text-error">*</span></span>
        </label>
        <input
          id="tenant-name"
          class="input input-bordered w-full"
          type="text"
          placeholder="e.g. ACME Corporation"
          bind:value={newTenantName}
        />
      </div>
    </div>

    <div class="modal-action">
      <button
        class="btn"
        onclick={() => { showCreateModal = false; newTenantId = ''; newTenantName = ''; }}
      >
        Cancel
      </button>
      <button
        class="btn btn-primary"
        class:loading={createSubmitting}
        disabled={createSubmitting}
        onclick={handleCreateTenant}
      >
        Create
      </button>
    </div>
  </div>
  <form method="dialog" class="modal-backdrop">
    <button onclick={() => { showCreateModal = false; }}>close</button>
  </form>
</dialog>
