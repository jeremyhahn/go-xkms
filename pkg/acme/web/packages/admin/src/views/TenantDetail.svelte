<script lang="ts">
  import { onMount } from 'svelte';
  import Card from '@trustedca/shared/components/Card.svelte';
  import Tabs from '@trustedca/shared/components/Tabs.svelte';
  import StatusBadge from '@trustedca/shared/components/StatusBadge.svelte';
  import LoadingSpinner from '@trustedca/shared/components/LoadingSpinner.svelte';
  import Button from '@trustedca/shared/components/Button.svelte';
  import Modal from '@trustedca/shared/components/Modal.svelte';
  import FormField from '@trustedca/shared/components/FormField.svelte';
  import { formatDateTime, formatDate } from '@trustedca/shared/utils/formatters';
  import { selectedTenant, tenantsLoading, fetchTenant } from '../lib/stores/tenants';
  import { adminApi } from '../lib/api/admin-api';
  import { notifyError } from '@trustedca/shared/stores/notifications';
  import type { TenantCAStatusInfo, CreateTenantRootCARequest, CreateTenantIntermediateCARequest } from '@trustedca/shared/api/types';

  export let tenantId: string;

  let activeTab = 'overview';
  let caStatus: TenantCAStatusInfo | null = null;
  let caStatusLoading = false;

  let showRootCAModal = false;
  let rootCAForm: CreateTenantRootCARequest = { common_name: '', key_algorithm: 'EC', validity_years: 10 };
  let rootCASubmitting = false;

  let showIntCAModal = false;
  let intCAForm: CreateTenantIntermediateCARequest = {
    common_name: '',
    parent_type: 'root',
    purpose: '',
    key_algorithm: 'EC',
    validity_years: 5,
    set_as_default: false,
  };
  let intCASubmitting = false;

  const tabs = [
    { label: 'Overview', value: 'overview' },
    { label: 'Certificate Authorities', value: 'cas' },
    { label: 'EAB Credentials', value: 'eab' },
    { label: 'Settings', value: 'settings' },
  ];

  const keyAlgorithms = ['EC', 'RSA-2048', 'RSA-4096', 'Ed25519'];

  function handleTabChange(event: CustomEvent<string>) {
    activeTab = event.detail;
    if (event.detail === 'cas' && caStatus === null) {
      loadCAStatus();
    }
  }

  async function loadCAStatus() {
    caStatusLoading = true;
    try {
      caStatus = await adminApi.getTenantCAStatus(tenantId);
    } catch (e) {
      notifyError(`Failed to load CA status: ${(e as Error).message}`);
    } finally {
      caStatusLoading = false;
    }
  }

  async function handleCreateRootCA() {
    rootCASubmitting = true;
    try {
      await adminApi.createTenantRootCA(tenantId, rootCAForm);
      showRootCAModal = false;
      rootCAForm = { common_name: '', key_algorithm: 'EC', validity_years: 10 };
      await loadCAStatus();
    } catch (e) {
      notifyError(`Failed to create root CA: ${(e as Error).message}`);
    } finally {
      rootCASubmitting = false;
    }
  }

  async function handleCreateIntermediateCA() {
    intCASubmitting = true;
    try {
      await adminApi.createTenantIntermediateCA(tenantId, {
        ...intCAForm,
        purpose: intCAForm.purpose || undefined,
      });
      showIntCAModal = false;
      intCAForm = {
        common_name: '',
        parent_type: 'root',
        purpose: '',
        key_algorithm: 'EC',
        validity_years: 5,
        set_as_default: false,
      };
      await loadCAStatus();
    } catch (e) {
      notifyError(`Failed to create intermediate CA: ${(e as Error).message}`);
    } finally {
      intCASubmitting = false;
    }
  }

  onMount(() => {
    fetchTenant(tenantId);
  });
</script>

<div class="p-6">
  {#if $tenantsLoading}
    <div class="flex items-center justify-center py-20">
      <LoadingSpinner size="lg" />
    </div>
  {:else if $selectedTenant}
    <div class="mb-6 flex items-center gap-4">
      <h1 class="text-2xl font-bold text-slate-900 dark:text-slate-100">
        {$selectedTenant.name}
      </h1>
      <StatusBadge status={$selectedTenant.status} />
    </div>

    <Tabs {tabs} {activeTab} on:change={handleTabChange}>
      {#if activeTab === 'overview'}
        <Card title="Tenant Details">
          <div class="grid grid-cols-1 gap-4 sm:grid-cols-2">
            <div>
              <p class="text-sm text-slate-500 dark:text-slate-400">ID</p>
              <p class="mt-1 font-mono text-sm text-slate-900 dark:text-slate-100">
                {$selectedTenant.id}
              </p>
            </div>
            <div>
              <p class="text-sm text-slate-500 dark:text-slate-400">Created</p>
              <p class="mt-1 text-sm text-slate-900 dark:text-slate-100">
                {formatDateTime($selectedTenant.created_at)}
              </p>
            </div>
            <div>
              <p class="text-sm text-slate-500 dark:text-slate-400">Updated</p>
              <p class="mt-1 text-sm text-slate-900 dark:text-slate-100">
                {formatDateTime($selectedTenant.updated_at)}
              </p>
            </div>
            {#if $selectedTenant.created_by}
              <div>
                <p class="text-sm text-slate-500 dark:text-slate-400">Created By</p>
                <p class="mt-1 text-sm text-slate-900 dark:text-slate-100">
                  {$selectedTenant.created_by}
                </p>
              </div>
            {/if}
          </div>
        </Card>

      {:else if activeTab === 'cas'}
        {#if caStatusLoading}
          <div class="flex items-center justify-center py-12">
            <LoadingSpinner size="lg" />
          </div>
        {:else}
          <!-- CA Status Overview -->
          {#if caStatus}
            <div class="mb-4">
              <Card title="CA Status Overview">
                <div class="grid grid-cols-1 gap-4 sm:grid-cols-3">
                  <div>
                    <p class="text-sm text-slate-500 dark:text-slate-400">Can Issue Certificates</p>
                    <div class="mt-1">
                      <StatusBadge status={caStatus.can_issue_certificates ? 'active' : 'invalid'} />
                    </div>
                  </div>
                  <div>
                    <p class="text-sm text-slate-500 dark:text-slate-400">Active CAs</p>
                    <p class="mt-1 text-2xl font-bold text-slate-900 dark:text-slate-100">
                      {caStatus.active_ca_count}
                    </p>
                  </div>
                  {#if caStatus.default_intermediate_ca_id}
                    <div>
                      <p class="text-sm text-slate-500 dark:text-slate-400">Default Intermediate CA</p>
                      <p class="mt-1 font-mono text-sm text-slate-900 dark:text-slate-100">
                        {caStatus.default_intermediate_ca_id}
                      </p>
                    </div>
                  {/if}
                </div>
              </Card>
            </div>
          {/if}

          <!-- Root CA -->
          <div class="mb-4">
            <Card title="Root Certificate Authority">
              {#if caStatus?.root_ca}
                <div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-3">
                  <div>
                    <p class="text-sm text-slate-500 dark:text-slate-400">Common Name</p>
                    <p class="mt-1 font-medium text-slate-900 dark:text-slate-100">
                      {caStatus.root_ca.common_name}
                    </p>
                  </div>
                  <div>
                    <p class="text-sm text-slate-500 dark:text-slate-400">Status</p>
                    <div class="mt-1">
                      <StatusBadge status={caStatus.root_ca.status} />
                    </div>
                  </div>
                  <div>
                    <p class="text-sm text-slate-500 dark:text-slate-400">Key Algorithm</p>
                    <p class="mt-1 text-sm text-slate-900 dark:text-slate-100">
                      {caStatus.root_ca.key_algorithm}
                    </p>
                  </div>
                  {#if caStatus.root_ca.serial_number}
                    <div>
                      <p class="text-sm text-slate-500 dark:text-slate-400">Serial Number</p>
                      <p class="mt-1 font-mono text-xs text-slate-900 dark:text-slate-100 break-all">
                        {caStatus.root_ca.serial_number}
                      </p>
                    </div>
                  {/if}
                  <div>
                    <p class="text-sm text-slate-500 dark:text-slate-400">Valid From</p>
                    <p class="mt-1 text-sm text-slate-900 dark:text-slate-100">
                      {formatDate(caStatus.root_ca.not_before)}
                    </p>
                  </div>
                  <div>
                    <p class="text-sm text-slate-500 dark:text-slate-400">Valid Until</p>
                    <p class="mt-1 text-sm text-slate-900 dark:text-slate-100">
                      {formatDate(caStatus.root_ca.not_after)}
                    </p>
                  </div>
                  <div>
                    <p class="text-sm text-slate-500 dark:text-slate-400">Created</p>
                    <p class="mt-1 text-sm text-slate-900 dark:text-slate-100">
                      {formatDateTime(caStatus.root_ca.created_at)}
                    </p>
                  </div>
                </div>
              {:else}
                <div class="flex flex-col items-center justify-center py-8 gap-4">
                  <p class="text-sm text-slate-500 dark:text-slate-400">
                    No root CA has been created for this tenant.
                  </p>
                  <Button variant="primary" size="sm" on:click={() => (showRootCAModal = true)}>
                    Create Root CA
                  </Button>
                </div>
              {/if}
            </Card>
          </div>

          <!-- Intermediate CAs -->
          <Card title="Intermediate Certificate Authorities">
            <div class="mb-4 flex justify-end">
              <Button
                variant="primary"
                size="sm"
                disabled={!caStatus?.root_ca}
                on:click={() => (showIntCAModal = true)}
              >
                Create Intermediate CA
              </Button>
            </div>

            {#if caStatus?.intermediate_cas && caStatus.intermediate_cas.length > 0}
              <div class="overflow-hidden rounded-lg border border-slate-200 dark:border-slate-700">
                <table class="w-full text-left text-sm">
                  <thead class="bg-slate-50 dark:bg-slate-800/50">
                    <tr>
                      <th class="px-4 py-3 font-medium text-slate-600 dark:text-slate-300">Common Name</th>
                      <th class="px-4 py-3 font-medium text-slate-600 dark:text-slate-300">Purpose</th>
                      <th class="px-4 py-3 font-medium text-slate-600 dark:text-slate-300">Key Algorithm</th>
                      <th class="px-4 py-3 font-medium text-slate-600 dark:text-slate-300">Valid Until</th>
                      <th class="px-4 py-3 font-medium text-slate-600 dark:text-slate-300">Status</th>
                    </tr>
                  </thead>
                  <tbody class="divide-y divide-slate-200 dark:divide-slate-700">
                    {#each caStatus.intermediate_cas as intCA}
                      <tr class="bg-white dark:bg-slate-800">
                        <td class="px-4 py-3 text-slate-900 dark:text-slate-100">
                          {intCA.common_name}
                          {#if intCA.id === caStatus.default_intermediate_ca_id}
                            <span class="ml-2 rounded-full bg-blue-100 px-2 py-0.5 text-xs font-medium text-blue-700 dark:bg-blue-900/30 dark:text-blue-400">
                              default
                            </span>
                          {/if}
                        </td>
                        <td class="px-4 py-3 text-slate-700 dark:text-slate-300">
                          {intCA.purpose || '-'}
                        </td>
                        <td class="px-4 py-3 text-slate-700 dark:text-slate-300">
                          {intCA.key_algorithm}
                        </td>
                        <td class="px-4 py-3 text-slate-700 dark:text-slate-300">
                          {formatDate(intCA.not_after)}
                        </td>
                        <td class="px-4 py-3">
                          <StatusBadge status={intCA.status} />
                        </td>
                      </tr>
                    {/each}
                  </tbody>
                </table>
              </div>
            {:else}
              <p class="py-6 text-center text-sm text-slate-500 dark:text-slate-400">
                No intermediate CAs created yet.
                {#if !caStatus?.root_ca}
                  Create a root CA first.
                {/if}
              </p>
            {/if}
          </Card>
        {/if}

      {:else if activeTab === 'eab'}
        <Card title="External Account Bindings">
          <p class="text-sm text-slate-500 dark:text-slate-400">
            EAB credential management for this tenant.
          </p>
        </Card>

      {:else if activeTab === 'settings'}
        <Card title="Tenant Settings">
          <p class="text-sm text-slate-500 dark:text-slate-400">
            Configuration and policy settings for this tenant.
          </p>
        </Card>
      {/if}
    </Tabs>
  {:else}
    <p class="text-slate-500 dark:text-slate-400">Tenant not found.</p>
  {/if}
</div>

<!-- Create Root CA Modal -->
<Modal bind:open={showRootCAModal} title="Create Root CA" size="md">
  <div class="space-y-4">
    <FormField label="Common Name" required id="root-cn">
      <input
        id="root-cn"
        class="input w-full"
        type="text"
        placeholder="e.g. My Organization Root CA"
        bind:value={rootCAForm.common_name}
      />
    </FormField>

    <FormField label="Key Algorithm" required id="root-alg">
      <select id="root-alg" class="select w-full" bind:value={rootCAForm.key_algorithm}>
        {#each keyAlgorithms as alg}
          <option value={alg}>{alg}</option>
        {/each}
      </select>
    </FormField>

    <FormField label="Validity (years)" required id="root-validity">
      <input
        id="root-validity"
        class="input w-full"
        type="number"
        min="1"
        max="30"
        bind:value={rootCAForm.validity_years}
      />
    </FormField>
  </div>

  <svelte:fragment slot="footer">
    <div class="flex justify-end gap-3">
      <Button variant="secondary" size="sm" on:click={() => (showRootCAModal = false)}>
        Cancel
      </Button>
      <Button
        variant="primary"
        size="sm"
        loading={rootCASubmitting}
        on:click={handleCreateRootCA}
      >
        Create Root CA
      </Button>
    </div>
  </svelte:fragment>
</Modal>

<!-- Create Intermediate CA Modal -->
<Modal bind:open={showIntCAModal} title="Create Intermediate CA" size="md">
  <div class="space-y-4">
    <FormField label="Common Name" required id="int-cn">
      <input
        id="int-cn"
        class="input w-full"
        type="text"
        placeholder="e.g. My Organization Intermediate CA"
        bind:value={intCAForm.common_name}
      />
    </FormField>

    <FormField label="Parent Type" required id="int-parent">
      <select id="int-parent" class="select w-full" bind:value={intCAForm.parent_type}>
        <option value="root">Root CA</option>
        <option value="intermediate">Intermediate CA</option>
      </select>
    </FormField>

    <FormField label="Purpose" id="int-purpose" hint="Optional: tls, code-signing, email, etc.">
      <input
        id="int-purpose"
        class="input w-full"
        type="text"
        placeholder="e.g. tls"
        bind:value={intCAForm.purpose}
      />
    </FormField>

    <FormField label="Key Algorithm" required id="int-alg">
      <select id="int-alg" class="select w-full" bind:value={intCAForm.key_algorithm}>
        {#each keyAlgorithms as alg}
          <option value={alg}>{alg}</option>
        {/each}
      </select>
    </FormField>

    <FormField label="Validity (years)" required id="int-validity">
      <input
        id="int-validity"
        class="input w-full"
        type="number"
        min="1"
        max="20"
        bind:value={intCAForm.validity_years}
      />
    </FormField>

    <div class="flex items-center gap-2">
      <input
        id="int-default"
        class="h-4 w-4 rounded border-slate-300 text-blue-600 dark:border-slate-600"
        type="checkbox"
        bind:checked={intCAForm.set_as_default}
      />
      <label for="int-default" class="text-sm text-slate-700 dark:text-slate-300">
        Set as default intermediate CA
      </label>
    </div>
  </div>

  <svelte:fragment slot="footer">
    <div class="flex justify-end gap-3">
      <Button variant="secondary" size="sm" on:click={() => (showIntCAModal = false)}>
        Cancel
      </Button>
      <Button
        variant="primary"
        size="sm"
        loading={intCASubmitting}
        on:click={handleCreateIntermediateCA}
      >
        Create Intermediate CA
      </Button>
    </div>
  </svelte:fragment>
</Modal>
