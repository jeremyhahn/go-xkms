<script lang="ts">
  import { onMount } from 'svelte';
  import Card from '@trustedca/shared/components/Card.svelte';
  import LoadingSpinner from '@trustedca/shared/components/LoadingSpinner.svelte';
  import Button from '@trustedca/shared/components/Button.svelte';
  import { clientApi } from '../lib/api/client-api';
  import type { AccountConfig, CertificateSpec } from '@trustedca/shared/api/types';

  let accounts: Record<string, AccountConfig> = {};
  let certificates: Record<string, CertificateSpec> = {};
  let loading = false;
  let fetchError = false;

  async function loadData() {
    loading = true;
    fetchError = false;
    try {
      [accounts, certificates] = await Promise.all([
        clientApi.listAccounts(),
        clientApi.listCertificates(),
      ]);
    } catch {
      fetchError = true;
    } finally {
      loading = false;
    }
  }

  onMount(() => {
    loadData();
  });

  $: accountNames = Object.keys(accounts).sort();
  $: certEntries = Object.entries(certificates);
  $: autoRenewCount = certEntries.filter(([, spec]) => spec.renewal?.auto).length;
</script>

<div class="p-6">
  <h1 class="text-2xl font-bold text-slate-900 dark:text-slate-100 mb-6">
    Dashboard
  </h1>

  {#if loading}
    <div class="flex flex-col items-center justify-center py-20 gap-3">
      <LoadingSpinner size="lg" />
      <p class="text-sm text-slate-500 dark:text-slate-400">Loading dashboard data...</p>
    </div>
  {:else if fetchError}
    <div class="flex flex-col items-center justify-center py-20 gap-4">
      <svg class="h-12 w-12 text-slate-400 dark:text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
        <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
      </svg>
      <p class="text-sm text-slate-600 dark:text-slate-400">Failed to load dashboard data.</p>
      <Button variant="secondary" size="sm" on:click={loadData}>
        Retry
      </Button>
    </div>
  {:else}
    <div class="grid grid-cols-1 gap-6 lg:grid-cols-2">
      <!-- Accounts -->
      <Card title="Accounts">
        {#if accountNames.length === 0}
          <p class="text-sm text-slate-500 dark:text-slate-400">
            No accounts configured. Use <span class="font-medium">Register</span> to add one.
          </p>
        {:else}
          <div class="space-y-3">
            <div>
              <p class="text-sm text-slate-500 dark:text-slate-400">Configured Accounts</p>
              <p class="mt-1 text-sm font-medium text-slate-900 dark:text-slate-100">
                {accountNames.length}
              </p>
            </div>
            <ul class="space-y-1">
              {#each accountNames as name}
                <li class="text-sm text-slate-700 dark:text-slate-300">
                  {name} — {accounts[name].directory}
                </li>
              {/each}
            </ul>
          </div>
        {/if}
      </Card>

      <!-- Certificates -->
      <Card title="Certificates">
        {#if certEntries.length === 0}
          <p class="text-sm text-slate-500 dark:text-slate-400">
            No certificates managed yet.
          </p>
        {:else}
          <div class="space-y-3">
            <div>
              <p class="text-sm text-slate-500 dark:text-slate-400">Managed Certificates</p>
              <p class="mt-1 text-sm font-medium text-slate-900 dark:text-slate-100">
                {certEntries.length}
              </p>
            </div>
            <div>
              <p class="text-sm text-slate-500 dark:text-slate-400">Auto-Renewal Enabled</p>
              <p class="mt-1 text-sm font-medium text-slate-900 dark:text-slate-100">
                {autoRenewCount} of {certEntries.length}
              </p>
            </div>
          </div>
        {/if}
      </Card>
    </div>
  {/if}
</div>
