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
  import { formatDate, formatDateTime } from '@trustedca/shared/utils/formatters';
  import { adminApi } from '../lib/api/admin-api';
  import { tenants, fetchTenants } from '../lib/stores/tenants';
  import { notifySuccess, notifyError } from '@trustedca/shared/stores/notifications';
  import type { CAStatus, TenantCAStatusInfo, TenantInfo } from '@trustedca/shared/api/types';

  let rootCAStatus = $state<CAStatus | null>(null);
  let rootCALoading = $state(false);
  let rootCAError = $state(false);

  let tenantCAMap = $state<Record<string, TenantCAStatusInfo | null>>({});
  let tenantCALoading = $state<Record<string, boolean>>({});

  let expandedTenants = $state<Set<string>>(new Set());

  // Create Intermediate CA modal state
  let showIntCAModal = $state(false);
  let intCATargetTenantId = $state('');
  let intCAForm = $state({
    common_name: '',
    parent_type: 'root',
    purpose: '',
    key_algorithm: 'EC',
    validity_years: 5,
    set_as_default: false,
  });
  let intCASubmitting = $state(false);

  const keyAlgorithms = ['EC', 'RSA-2048', 'RSA-4096', 'Ed25519'];

  async function loadRootCA() {
    rootCALoading = true;
    rootCAError = false;
    try {
      rootCAStatus = await adminApi.getStatus();
    } catch (e) {
      rootCAError = true;
      notifyError(`Failed to load CA status: ${(e as Error).message}`);
    } finally {
      rootCALoading = false;
    }
  }

  async function loadTenantCA(tenantId: string) {
    tenantCALoading = { ...tenantCALoading, [tenantId]: true };
    try {
      const status = await adminApi.getTenantCAStatus(tenantId);
      tenantCAMap = { ...tenantCAMap, [tenantId]: status };
    } catch (e) {
      tenantCAMap = { ...tenantCAMap, [tenantId]: null };
      notifyError(`Failed to load CA status for tenant ${tenantId}: ${(e as Error).message}`);
    } finally {
      tenantCALoading = { ...tenantCALoading, [tenantId]: false };
    }
  }

  function toggleTenant(tenantId: string) {
    const next = new Set(expandedTenants);
    if (next.has(tenantId)) {
      next.delete(tenantId);
    } else {
      next.add(tenantId);
      if (!tenantCAMap[tenantId]) {
        loadTenantCA(tenantId);
      }
    }
    expandedTenants = next;
  }

  function openIntCAModal(tenantId: string) {
    intCATargetTenantId = tenantId;
    intCAForm = {
      common_name: '',
      parent_type: 'root',
      purpose: '',
      key_algorithm: 'EC',
      validity_years: 5,
      set_as_default: false,
    };
    showIntCAModal = true;
  }

  async function handleCreateIntermediateCA() {
    if (!intCAForm.common_name.trim()) {
      notifyError('Common Name is required.');
      return;
    }
    intCASubmitting = true;
    try {
      await adminApi.createTenantIntermediateCA(intCATargetTenantId, {
        ...intCAForm,
        purpose: intCAForm.purpose || undefined,
      });
      showIntCAModal = false;
      notifySuccess('Intermediate CA created successfully.');
      // Reload the expanded tenant CA status
      tenantCAMap = { ...tenantCAMap, [intCATargetTenantId]: null };
      await loadTenantCA(intCATargetTenantId);
    } catch (e) {
      notifyError(`Failed to create intermediate CA: ${(e as Error).message}`);
    } finally {
      intCASubmitting = false;
    }
  }

  onMount(async () => {
    await Promise.all([loadRootCA(), fetchTenants({ per_page: 100 })]);
  });
</script>

<div class="p-6">
  <h1 class="mb-6 text-2xl font-bold text-slate-900 dark:text-slate-100">
    CA Manager
  </h1>

  <!-- Root CA Info -->
  <div class="mb-6">
    <Card title="Root Certificate Authority">
      {#if rootCALoading}
        <div class="flex justify-center py-8">
          <LoadingSpinner size="lg" />
        </div>
      {:else if rootCAError || !rootCAStatus}
        <p class="py-4 text-center text-sm text-slate-500 dark:text-slate-400">
          Failed to load root CA information.
        </p>
      {:else}
        <!-- Hierarchy visual -->
        <div class="mb-6 flex items-center gap-2 text-sm">
          <div class="rounded-lg border-2 border-blue-500 bg-blue-50 px-4 py-2 font-medium text-blue-800 dark:bg-blue-900/30 dark:text-blue-300">
            <div class="text-xs text-blue-500 dark:text-blue-400">Root CA</div>
            {rootCAStatus.root_ca}
          </div>
          {#if rootCAStatus.intermediate_ca}
            <svg class="h-5 w-5 flex-shrink-0 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
              <path stroke-linecap="round" stroke-linejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" />
            </svg>
            <div class="rounded-lg border-2 border-green-500 bg-green-50 px-4 py-2 font-medium text-green-800 dark:bg-green-900/30 dark:text-green-300">
              <div class="text-xs text-green-500 dark:text-green-400">Default Intermediate CA</div>
              {rootCAStatus.intermediate_ca}
            </div>
          {/if}
        </div>

        <div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
          <div>
            <p class="text-sm text-slate-500 dark:text-slate-400">Identity</p>
            <p class="mt-1 font-medium text-slate-900 dark:text-slate-100">{rootCAStatus.identity}</p>
          </div>
          <div>
            <p class="text-sm text-slate-500 dark:text-slate-400">Status</p>
            <div class="mt-1">
              <StatusBadge status={rootCAStatus.initialized ? 'active' : 'pending'} />
            </div>
          </div>
          <div>
            <p class="text-sm text-slate-500 dark:text-slate-400">Version</p>
            <p class="mt-1 font-medium text-slate-900 dark:text-slate-100">{rootCAStatus.version}</p>
          </div>
          <div>
            <p class="text-sm text-slate-500 dark:text-slate-400">Started</p>
            <p class="mt-1 font-medium text-slate-900 dark:text-slate-100">{formatDateTime(rootCAStatus.started_at)}</p>
          </div>
        </div>

        {#if rootCAStatus.keys && rootCAStatus.keys.length > 0}
          <div class="mt-4">
            <p class="text-sm font-medium text-slate-500 dark:text-slate-400 mb-2">Supported Keys</p>
            <div class="overflow-hidden rounded-lg border border-slate-200 dark:border-slate-700">
              <table class="w-full text-left text-sm">
                <thead class="bg-slate-50 dark:bg-slate-800/50">
                  <tr>
                    <th class="px-3 py-2 font-medium text-slate-600 dark:text-slate-300">Algorithm</th>
                    <th class="px-3 py-2 font-medium text-slate-600 dark:text-slate-300">Signature</th>
                    <th class="px-3 py-2 font-medium text-slate-600 dark:text-slate-300">Store</th>
                    <th class="px-3 py-2 font-medium text-slate-600 dark:text-slate-300">Parameters</th>
                    <th class="px-3 py-2 font-medium text-slate-600 dark:text-slate-300">Role</th>
                  </tr>
                </thead>
                <tbody class="divide-y divide-slate-200 dark:divide-slate-700">
                  {#each rootCAStatus.keys as key}
                    <tr class="bg-white dark:bg-slate-800">
                      <td class="px-3 py-2 font-medium text-slate-900 dark:text-slate-100">{key.algorithm}</td>
                      <td class="px-3 py-2 text-slate-700 dark:text-slate-300">{key.signature_algorithm}</td>
                      <td class="px-3 py-2 text-slate-700 dark:text-slate-300">{key.store}</td>
                      <td class="px-3 py-2 text-slate-700 dark:text-slate-300">
                        {key.curve || (key.key_size ? `${key.key_size}-bit` : '—')}
                      </td>
                      <td class="px-3 py-2">
                        {#if key.default}
                          <span class="inline-flex items-center rounded-full bg-blue-100 px-2 py-0.5 text-xs font-medium text-blue-700 dark:bg-blue-900/30 dark:text-blue-400">
                            Default
                          </span>
                        {:else}
                          <span class="text-xs text-slate-400">Available</span>
                        {/if}
                      </td>
                    </tr>
                  {/each}
                </tbody>
              </table>
            </div>
          </div>
        {:else}
          <div class="mt-4 grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <p class="text-sm text-slate-500 dark:text-slate-400">Key Algorithm</p>
              <p class="mt-1 font-medium text-slate-900 dark:text-slate-100">{rootCAStatus.key_algorithm}</p>
            </div>
            <div>
              <p class="text-sm text-slate-500 dark:text-slate-400">Signature Algorithm</p>
              <p class="mt-1 font-medium text-slate-900 dark:text-slate-100">{rootCAStatus.signature_algorithm}</p>
            </div>
          </div>
        {/if}
      {/if}
    </Card>
  </div>

  <!-- Tenant CA Hierarchies -->
  <Card title="Tenant Certificate Authorities" noPadding>
    {#if $tenants.length === 0}
      <p class="px-6 py-6 text-center text-sm text-slate-500 dark:text-slate-400">
        No tenants configured. Create a tenant first.
      </p>
    {:else}
      <div class="divide-y divide-slate-200 dark:divide-slate-700">
        {#each $tenants as tenant (tenant.id)}
          <div>
            <!-- Tenant row / accordion header -->
            <button
              class="flex w-full items-center justify-between px-4 py-3 text-left hover:bg-slate-50 dark:hover:bg-slate-800/50 transition-colors"
              onclick={() => toggleTenant(tenant.id)}
            >
              <div class="flex items-center gap-3">
                <svg
                  class="h-4 w-4 flex-shrink-0 text-slate-400 transition-transform {expandedTenants.has(tenant.id) ? 'rotate-90' : ''}"
                  fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2"
                >
                  <path stroke-linecap="round" stroke-linejoin="round" d="M9 5l7 7-7 7" />
                </svg>
                <span class="font-medium text-slate-900 dark:text-slate-100">{tenant.name}</span>
                <span class="font-mono text-xs text-slate-500 dark:text-slate-400">({tenant.id})</span>
              </div>
              <StatusBadge status={tenant.status} />
            </button>

            {#if expandedTenants.has(tenant.id)}
              <div class="border-t border-slate-100 bg-slate-50/50 px-4 py-4 dark:border-slate-700/50 dark:bg-slate-800/20">
                {#if tenantCALoading[tenant.id]}
                  <div class="flex justify-center py-6">
                    <LoadingSpinner size="md" />
                  </div>
                {:else}
                  {@const caStatus = tenantCAMap[tenant.id]}
                  {#if !caStatus}
                    <p class="text-sm text-slate-500 dark:text-slate-400">
                      No CA information available.
                    </p>
                  {:else}
                    <!-- Tenant CA Overview -->
                    <div class="mb-4 flex items-center gap-6 text-sm">
                      <div>
                        <span class="text-slate-500 dark:text-slate-400">Can Issue: </span>
                        <StatusBadge status={caStatus.can_issue_certificates ? 'active' : 'invalid'} />
                      </div>
                      <div>
                        <span class="text-slate-500 dark:text-slate-400">Active CAs: </span>
                        <span class="font-bold text-slate-900 dark:text-slate-100">{caStatus.active_ca_count}</span>
                      </div>
                    </div>

                    <!-- Root CA for tenant -->
                    {#if caStatus.root_ca}
                      <div class="mb-4 rounded-lg border border-blue-200 bg-blue-50/50 p-4 dark:border-blue-800/50 dark:bg-blue-900/10">
                        <div class="mb-2 flex items-center gap-2">
                          <svg class="h-4 w-4 text-blue-600 dark:text-blue-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                            <path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z" />
                          </svg>
                          <span class="text-xs font-semibold uppercase tracking-wide text-blue-600 dark:text-blue-400">Root CA</span>
                          <StatusBadge status={caStatus.root_ca.status} />
                        </div>
                        <div class="grid grid-cols-2 gap-3 text-sm lg:grid-cols-4">
                          <div>
                            <p class="text-slate-500 dark:text-slate-400">Common Name</p>
                            <p class="font-medium text-slate-900 dark:text-slate-100">{caStatus.root_ca.common_name}</p>
                          </div>
                          <div>
                            <p class="text-slate-500 dark:text-slate-400">Key Algorithm</p>
                            <p class="font-medium text-slate-900 dark:text-slate-100">{caStatus.root_ca.key_algorithm}</p>
                          </div>
                          <div>
                            <p class="text-slate-500 dark:text-slate-400">Valid From</p>
                            <p class="font-medium text-slate-900 dark:text-slate-100">{formatDate(caStatus.root_ca.not_before)}</p>
                          </div>
                          <div>
                            <p class="text-slate-500 dark:text-slate-400">Valid Until</p>
                            <p class="font-medium text-slate-900 dark:text-slate-100">{formatDate(caStatus.root_ca.not_after)}</p>
                          </div>
                        </div>
                      </div>
                    {:else}
                      <p class="mb-4 text-sm text-slate-500 dark:text-slate-400">
                        No root CA configured for this tenant.
                      </p>
                    {/if}

                    <!-- Intermediate CAs for tenant -->
                    {#if caStatus.intermediate_cas && caStatus.intermediate_cas.length > 0}
                      <div class="space-y-2">
                        {#each caStatus.intermediate_cas as intCA (intCA.id)}
                          <div class="rounded-lg border border-green-200 bg-green-50/50 p-4 dark:border-green-800/50 dark:bg-green-900/10">
                            <div class="mb-2 flex items-center gap-2">
                              <svg class="h-4 w-4 text-green-600 dark:text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
                                <path stroke-linecap="round" stroke-linejoin="round" d="M13 7l5 5m0 0l-5 5m5-5H6" />
                              </svg>
                              <span class="text-xs font-semibold uppercase tracking-wide text-green-600 dark:text-green-400">Intermediate CA</span>
                              {#if intCA.id === caStatus.default_intermediate_ca_id}
                                <span class="badge badge-info badge-sm">default</span>
                              {/if}
                              <StatusBadge status={intCA.status} />
                            </div>
                            <div class="grid grid-cols-2 gap-3 text-sm lg:grid-cols-4">
                              <div>
                                <p class="text-slate-500 dark:text-slate-400">Common Name</p>
                                <p class="font-medium text-slate-900 dark:text-slate-100">{intCA.common_name}</p>
                              </div>
                              <div>
                                <p class="text-slate-500 dark:text-slate-400">Purpose</p>
                                <p class="font-medium text-slate-900 dark:text-slate-100">{intCA.purpose || '—'}</p>
                              </div>
                              <div>
                                <p class="text-slate-500 dark:text-slate-400">Key Algorithm</p>
                                <p class="font-medium text-slate-900 dark:text-slate-100">{intCA.key_algorithm}</p>
                              </div>
                              <div>
                                <p class="text-slate-500 dark:text-slate-400">Valid Until</p>
                                <p class="font-medium text-slate-900 dark:text-slate-100">{formatDate(intCA.not_after)}</p>
                              </div>
                            </div>
                          </div>
                        {/each}
                      </div>
                    {:else}
                      <p class="mt-2 text-sm text-slate-500 dark:text-slate-400">
                        No intermediate CAs configured.
                      </p>
                    {/if}

                    <!-- Action: add intermediate CA -->
                    <div class="mt-4 flex justify-end">
                      <button
                        class="btn btn-sm btn-primary"
                        disabled={!caStatus.root_ca}
                        onclick={() => openIntCAModal(tenant.id)}
                      >
                        + Add Intermediate CA
                      </button>
                    </div>
                  {/if}
                {/if}
              </div>
            {/if}
          </div>
        {/each}
      </div>
    {/if}
  </Card>
</div>

<!-- Create Intermediate CA Modal -->
<dialog class="modal" class:modal-open={showIntCAModal}>
  <div class="modal-box">
    <h3 class="text-lg font-bold text-slate-900 dark:text-slate-100">Create Intermediate CA</h3>
    <p class="py-2 text-sm text-slate-500 dark:text-slate-400">
      Add an intermediate certificate authority for tenant <strong>{intCATargetTenantId}</strong>.
    </p>

    <div class="mt-4 space-y-4">
      <div class="form-control w-full">
        <label class="label" for="int-cn">
          <span class="label-text">Common Name <span class="text-error">*</span></span>
        </label>
        <input
          id="int-cn"
          class="input input-bordered w-full"
          type="text"
          placeholder="e.g. My Organization Intermediate CA"
          bind:value={intCAForm.common_name}
        />
      </div>

      <div class="form-control w-full">
        <label class="label" for="int-parent">
          <span class="label-text">Parent Type <span class="text-error">*</span></span>
        </label>
        <select id="int-parent" class="select select-bordered w-full" bind:value={intCAForm.parent_type}>
          <option value="root">Root CA</option>
          <option value="intermediate">Intermediate CA</option>
        </select>
      </div>

      <div class="form-control w-full">
        <label class="label" for="int-purpose">
          <span class="label-text">Purpose</span>
          <span class="label-text-alt text-slate-400">Optional</span>
        </label>
        <input
          id="int-purpose"
          class="input input-bordered w-full"
          type="text"
          placeholder="e.g. tls, code-signing, email"
          bind:value={intCAForm.purpose}
        />
      </div>

      <div class="form-control w-full">
        <label class="label" for="int-alg">
          <span class="label-text">Key Algorithm <span class="text-error">*</span></span>
        </label>
        <select id="int-alg" class="select select-bordered w-full" bind:value={intCAForm.key_algorithm}>
          {#each keyAlgorithms as alg}
            <option value={alg}>{alg}</option>
          {/each}
        </select>
      </div>

      <div class="form-control w-full">
        <label class="label" for="int-validity">
          <span class="label-text">Validity (years) <span class="text-error">*</span></span>
        </label>
        <input
          id="int-validity"
          class="input input-bordered w-full"
          type="number"
          min="1"
          max="20"
          bind:value={intCAForm.validity_years}
        />
      </div>

      <div class="form-control">
        <label class="label cursor-pointer justify-start gap-3">
          <input
            id="int-default"
            class="checkbox checkbox-primary"
            type="checkbox"
            bind:checked={intCAForm.set_as_default}
          />
          <span class="label-text">Set as default intermediate CA</span>
        </label>
      </div>
    </div>

    <div class="modal-action">
      <button
        class="btn"
        onclick={() => { showIntCAModal = false; }}
      >
        Cancel
      </button>
      <button
        class="btn btn-primary"
        class:loading={intCASubmitting}
        disabled={intCASubmitting}
        onclick={handleCreateIntermediateCA}
      >
        Create
      </button>
    </div>
  </div>
  <form method="dialog" class="modal-backdrop">
    <button onclick={() => { showIntCAModal = false; }}>close</button>
  </form>
</dialog>
