<script lang="ts">
  import { onMount } from 'svelte';
  import Card from '@trustedca/shared/components/Card.svelte';
  import StatusBadge from '@trustedca/shared/components/StatusBadge.svelte';
  import LoadingSpinner from '@trustedca/shared/components/LoadingSpinner.svelte';
  import Button from '@trustedca/shared/components/Button.svelte';
  import { renewalStatus, acmeLoading, fetchRenewalStatus } from '../lib/stores/acme';
  import { clientConfig, fetchConfig } from '../lib/stores/config';

  let fetchError = false;

  async function loadData() {
    fetchError = false;
    try {
      await Promise.all([fetchRenewalStatus(), fetchConfig()]);
    } catch {
      fetchError = true;
    }
  }

  onMount(() => {
    loadData();
  });
</script>

<div class="p-6">
  <h1 class="text-2xl font-bold text-slate-900 dark:text-slate-100 mb-6">
    Dashboard
  </h1>

  {#if $acmeLoading}
    <div class="flex flex-col items-center justify-center py-20 gap-3">
      <LoadingSpinner size="lg" />
      <p class="text-sm text-slate-500 dark:text-slate-400">Loading dashboard data...</p>
    </div>
  {:else if fetchError || (!$clientConfig && !$renewalStatus)}
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
      <!-- Account Info -->
      <Card title="Account">
        {#if $clientConfig}
          <div class="space-y-3">
            <div>
              <p class="text-sm text-slate-500 dark:text-slate-400">Server</p>
              <p class="mt-1 text-sm font-medium text-slate-900 dark:text-slate-100">
                {$clientConfig.directoryURL}
              </p>
            </div>
            <div>
              <p class="text-sm text-slate-500 dark:text-slate-400">Account Email</p>
              <p class="mt-1 text-sm font-medium text-slate-900 dark:text-slate-100">
                {$clientConfig.accountEmail || 'Not configured'}
              </p>
            </div>
          </div>
        {:else}
          <p class="text-sm text-slate-500 dark:text-slate-400">
            Configuration not loaded.
          </p>
        {/if}
      </Card>

      <!-- Renewal Status -->
      <Card title="Auto-Renewal">
        {#if $renewalStatus}
          <div class="space-y-3">
            <div class="flex items-center gap-2">
              <StatusBadge status={$renewalStatus.enabled ? 'active' : 'pending'} />
              <span class="text-sm text-slate-700 dark:text-slate-300">
                {$renewalStatus.enabled ? 'Enabled' : 'Disabled'}
              </span>
            </div>
            <div>
              <p class="text-sm text-slate-500 dark:text-slate-400">Check Interval</p>
              <p class="mt-1 text-sm font-medium text-slate-900 dark:text-slate-100">
                {$renewalStatus.checkInterval}
              </p>
            </div>
            <div>
              <p class="text-sm text-slate-500 dark:text-slate-400">Renewal Threshold</p>
              <p class="mt-1 text-sm font-medium text-slate-900 dark:text-slate-100">
                {$renewalStatus.renewalThreshold}
              </p>
            </div>
          </div>
        {:else}
          <p class="text-sm text-slate-500 dark:text-slate-400">
            Renewal status not available.
          </p>
        {/if}
      </Card>
    </div>
  {/if}
</div>
