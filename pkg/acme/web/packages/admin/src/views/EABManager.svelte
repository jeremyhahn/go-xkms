<!--
  Copyright (c) 2025 Jeremy Hahn
  Copyright (c) 2025 Automate The Things, LLC
  SPDX-License-Identifier: AGPL-3.0-or-later OR Commercial
-->
<script lang="ts">
  import { onMount } from 'svelte';
  import Card from '@trustedca/shared/components/Card.svelte';
  import StatusBadge from '@trustedca/shared/components/StatusBadge.svelte';
  import LoadingSpinner from '@trustedca/shared/components/LoadingSpinner.svelte';
  import { formatDateTime } from '@trustedca/shared/utils/formatters';
  import { adminApi } from '../lib/api/admin-api';
  import { tenants, fetchTenants } from '../lib/stores/tenants';
  import { notifySuccess, notifyError } from '@trustedca/shared/stores/notifications';
  import type { EABInfo, CreateEABResponse } from '@trustedca/shared/api/types';

  let selectedTenantId = $state('');
  let eabList = $state<EABInfo[]>([]);
  let eabLoading = $state(false);
  let page = $state(1);
  let totalPages = $state(1);

  // Create modal
  let showCreateModal = $state(false);
  let createPurpose = $state('');
  let createContact = $state('');
  let createExpiresInDays = $state<number | undefined>(undefined);
  let createSubmitting = $state(false);

  // Newly created EAB — shown once after creation
  let newEAB = $state<CreateEABResponse | null>(null);
  let showNewEABModal = $state(false);
  let macKeyCopied = $state(false);

  // Revoke confirmation
  let showRevokeModal = $state(false);
  let revokeTarget = $state<EABInfo | null>(null);
  let revokeSubmitting = $state(false);

  async function loadEAB() {
    if (!selectedTenantId) return;
    eabLoading = true;
    try {
      const res = await adminApi.listEABCredentials(selectedTenantId, { page, per_page: 20 });
      eabList = res.data ?? [];
      if (res.pagination) {
        totalPages = Math.ceil(res.pagination.total / (res.pagination.per_page || 20));
      }
    } catch (e) {
      notifyError(`Failed to load EAB credentials: ${(e as Error).message}`);
      eabList = [];
    } finally {
      eabLoading = false;
    }
  }

  function onTenantChange() {
    page = 1;
    eabList = [];
    loadEAB();
  }

  function prevPage() {
    if (page > 1) {
      page -= 1;
      loadEAB();
    }
  }

  function nextPage() {
    if (page < totalPages) {
      page += 1;
      loadEAB();
    }
  }

  async function handleCreateEAB() {
    createSubmitting = true;
    try {
      const req = {
        purpose: createPurpose.trim() || undefined,
        contact: createContact.trim() ? [createContact.trim()] : undefined,
        expires_in_days: createExpiresInDays || undefined,
      };
      const resp = await adminApi.createEABCredential(selectedTenantId, req);
      showCreateModal = false;
      createPurpose = '';
      createContact = '';
      createExpiresInDays = undefined;
      newEAB = resp;
      macKeyCopied = false;
      showNewEABModal = true;
      notifySuccess('EAB credential created. Save the MAC key now — it will not be shown again.');
      await loadEAB();
    } catch (e) {
      notifyError(`Failed to create EAB credential: ${(e as Error).message}`);
    } finally {
      createSubmitting = false;
    }
  }

  async function copyMacKey() {
    if (!newEAB) return;
    try {
      await navigator.clipboard.writeText(newEAB.mac_key);
      macKeyCopied = true;
      setTimeout(() => { macKeyCopied = false; }, 3000);
    } catch {
      notifyError('Failed to copy to clipboard.');
    }
  }

  function openRevokeModal(eab: EABInfo) {
    revokeTarget = eab;
    showRevokeModal = true;
  }

  async function handleRevokeEAB() {
    if (!revokeTarget) return;
    revokeSubmitting = true;
    try {
      await adminApi.revokeEABCredential(selectedTenantId, revokeTarget.id);
      showRevokeModal = false;
      revokeTarget = null;
      notifySuccess('EAB credential revoked.');
      await loadEAB();
    } catch (e) {
      notifyError(`Failed to revoke EAB credential: ${(e as Error).message}`);
    } finally {
      revokeSubmitting = false;
    }
  }

  onMount(async () => {
    await fetchTenants({ per_page: 100 });
    if ($tenants.length > 0) {
      selectedTenantId = $tenants[0].id;
      loadEAB();
    }
  });
</script>

<div class="p-6">
  <div class="mb-6 flex items-center justify-between">
    <h1 class="text-2xl font-bold text-slate-900 dark:text-slate-100">EAB Manager</h1>

    <div class="flex items-center gap-3">
      <select
        class="select select-bordered"
        bind:value={selectedTenantId}
        onchange={onTenantChange}
      >
        <option value="">Select Tenant</option>
        {#each $tenants as tenant (tenant.id)}
          <option value={tenant.id}>{tenant.name} ({tenant.id})</option>
        {/each}
      </select>

      <button
        class="btn btn-primary btn-sm"
        disabled={!selectedTenantId}
        onclick={() => { showCreateModal = true; }}
      >
        + Create EAB
      </button>
    </div>
  </div>

  <Card>
    {#if !selectedTenantId}
      <div class="py-12 text-center text-sm text-slate-500 dark:text-slate-400">
        Select a tenant to manage its EAB credentials.
      </div>
    {:else if eabLoading}
      <div class="flex justify-center py-12">
        <LoadingSpinner size="lg" />
      </div>
    {:else if eabList.length === 0}
      <div class="py-12 text-center text-sm text-slate-500 dark:text-slate-400">
        No EAB credentials found for this tenant.
      </div>
    {:else}
      <div class="overflow-x-auto">
        <table class="table w-full">
          <thead>
            <tr>
              <th>ID</th>
              <th>Purpose</th>
              <th>Status</th>
              <th>Contact</th>
              <th>Created</th>
              <th>Expires</th>
              <th class="text-right">Actions</th>
            </tr>
          </thead>
          <tbody>
            {#each eabList as eab (eab.id)}
              <tr class="hover">
                <td class="font-mono text-xs">{eab.id}</td>
                <td>{eab.purpose || '—'}</td>
                <td><StatusBadge status={eab.status} /></td>
                <td class="text-sm text-slate-600 dark:text-slate-300">
                  {eab.contact && eab.contact.length > 0 ? eab.contact.join(', ') : '—'}
                </td>
                <td class="text-sm text-slate-500 dark:text-slate-400">
                  {formatDateTime(eab.created_at)}
                </td>
                <td class="text-sm text-slate-500 dark:text-slate-400">
                  {eab.expires_at ? formatDateTime(eab.expires_at) : '—'}
                </td>
                <td>
                  <div class="flex justify-end">
                    <button
                      class="btn btn-ghost btn-xs text-error"
                      disabled={eab.status === 'revoked'}
                      onclick={() => openRevokeModal(eab)}
                    >
                      Revoke
                    </button>
                  </div>
                </td>
              </tr>
            {/each}
          </tbody>
        </table>
      </div>

      <!-- Pagination -->
      {#if totalPages > 1}
        <div class="mt-4 flex items-center justify-center gap-4">
          <button class="btn btn-sm btn-ghost" disabled={page <= 1} onclick={prevPage}>
            Previous
          </button>
          <span class="text-sm text-slate-500 dark:text-slate-400">
            Page {page} of {totalPages}
          </span>
          <button class="btn btn-sm btn-ghost" disabled={page >= totalPages} onclick={nextPage}>
            Next
          </button>
        </div>
      {/if}
    {/if}
  </Card>
</div>

<!-- Create EAB Modal -->
<dialog class="modal" class:modal-open={showCreateModal}>
  <div class="modal-box">
    <h3 class="text-lg font-bold text-slate-900 dark:text-slate-100">Create EAB Credential</h3>
    <p class="py-2 text-sm text-slate-500 dark:text-slate-400">
      Generate an External Account Binding credential for ACME registration.
    </p>

    <div class="mt-4 space-y-4">
      <div class="form-control w-full">
        <label class="label" for="eab-purpose">
          <span class="label-text">Purpose</span>
          <span class="label-text-alt text-slate-400">Optional</span>
        </label>
        <input
          id="eab-purpose"
          class="input input-bordered w-full"
          type="text"
          placeholder="e.g. tls-automation, device-enroll"
          bind:value={createPurpose}
        />
      </div>

      <div class="form-control w-full">
        <label class="label" for="eab-contact">
          <span class="label-text">Contact</span>
          <span class="label-text-alt text-slate-400">Optional</span>
        </label>
        <input
          id="eab-contact"
          class="input input-bordered w-full"
          type="email"
          placeholder="e.g. admin@example.com"
          bind:value={createContact}
        />
      </div>

      <div class="form-control w-full">
        <label class="label" for="eab-expires">
          <span class="label-text">Expires In (days)</span>
          <span class="label-text-alt text-slate-400">Optional — leave blank for no expiry</span>
        </label>
        <input
          id="eab-expires"
          class="input input-bordered w-full"
          type="number"
          min="1"
          placeholder="e.g. 365"
          bind:value={createExpiresInDays}
        />
      </div>
    </div>

    <div class="modal-action">
      <button
        class="btn"
        onclick={() => { showCreateModal = false; createPurpose = ''; createContact = ''; createExpiresInDays = undefined; }}
      >
        Cancel
      </button>
      <button
        class="btn btn-primary"
        class:loading={createSubmitting}
        disabled={createSubmitting}
        onclick={handleCreateEAB}
      >
        Create
      </button>
    </div>
  </div>
  <form method="dialog" class="modal-backdrop">
    <button onclick={() => { showCreateModal = false; }}>close</button>
  </form>
</dialog>

<!-- New EAB Credential Display Modal (one-time MAC key reveal) -->
<dialog class="modal" class:modal-open={showNewEABModal}>
  <div class="modal-box max-w-lg">
    <div class="flex items-center gap-3 mb-4">
      <div class="rounded-full bg-warning/20 p-2">
        <svg class="h-6 w-6 text-warning" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
        </svg>
      </div>
      <h3 class="text-lg font-bold text-slate-900 dark:text-slate-100">EAB Credential Created</h3>
    </div>

    <div class="alert alert-warning mb-4">
      <svg class="h-5 w-5 shrink-0" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v2m0 4h.01m-6.938 4h13.856c1.54 0 2.502-1.667 1.732-3L13.732 4c-.77-1.333-2.694-1.333-3.464 0L3.34 16c-.77 1.333.192 3 1.732 3z" />
      </svg>
      <span class="text-sm">
        <strong>Save the MAC key now.</strong> It will not be shown again after you close this dialog.
      </span>
    </div>

    {#if newEAB}
      <div class="space-y-3">
        <div>
          <label class="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">Key ID (KID)</label>
          <div class="mt-1 rounded-lg bg-base-200 px-3 py-2 font-mono text-sm break-all">
            {newEAB.id}
          </div>
        </div>

        <div>
          <label class="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">MAC Key</label>
          <div class="mt-1 flex items-start gap-2">
            <div class="flex-1 rounded-lg bg-base-200 px-3 py-2 font-mono text-sm break-all">
              {newEAB.mac_key}
            </div>
            <button
              class="btn btn-sm {macKeyCopied ? 'btn-success' : 'btn-ghost'} flex-shrink-0"
              onclick={copyMacKey}
              title="Copy MAC key"
            >
              {#if macKeyCopied}
                <svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M5 13l4 4L19 7" />
                </svg>
                Copied
              {:else}
                <svg class="h-4 w-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                  <path stroke-linecap="round" stroke-linejoin="round" d="M8 16H6a2 2 0 01-2-2V6a2 2 0 012-2h8a2 2 0 012 2v2m-6 12h8a2 2 0 002-2v-8a2 2 0 00-2-2h-8a2 2 0 00-2 2v8a2 2 0 002 2z" />
                </svg>
                Copy
              {/if}
            </button>
          </div>
        </div>

        <div>
          <label class="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">Algorithm</label>
          <div class="mt-1 rounded-lg bg-base-200 px-3 py-2 font-mono text-sm">
            {newEAB.algorithm}
          </div>
        </div>

        {#if newEAB.expires_at}
          <div>
            <label class="text-xs font-semibold uppercase tracking-wide text-slate-500 dark:text-slate-400">Expires At</label>
            <div class="mt-1 rounded-lg bg-base-200 px-3 py-2 text-sm">
              {formatDateTime(newEAB.expires_at)}
            </div>
          </div>
        {/if}
      </div>
    {/if}

    <div class="modal-action">
      <button
        class="btn btn-primary"
        onclick={() => { showNewEABModal = false; newEAB = null; }}
      >
        I have saved the MAC key
      </button>
    </div>
  </div>
</dialog>

<!-- Revoke Confirmation Modal -->
<dialog class="modal" class:modal-open={showRevokeModal}>
  <div class="modal-box">
    <h3 class="text-lg font-bold text-slate-900 dark:text-slate-100">Revoke EAB Credential</h3>
    <p class="py-4 text-sm text-slate-600 dark:text-slate-300">
      Are you sure you want to revoke EAB credential
      <strong class="font-mono">{revokeTarget?.id}</strong>?
      Any ACME accounts already registered with this EAB will continue to work,
      but the credential cannot be used for new registrations.
    </p>
    <div class="modal-action">
      <button
        class="btn"
        onclick={() => { showRevokeModal = false; revokeTarget = null; }}
      >
        Cancel
      </button>
      <button
        class="btn btn-error"
        class:loading={revokeSubmitting}
        disabled={revokeSubmitting}
        onclick={handleRevokeEAB}
      >
        Revoke
      </button>
    </div>
  </div>
  <form method="dialog" class="modal-backdrop">
    <button onclick={() => { showRevokeModal = false; }}>close</button>
  </form>
</dialog>
