<script lang="ts">
  import { onMount } from 'svelte';
  import Card from '@trustedca/shared/components/Card.svelte';
  import StatusBadge from '@trustedca/shared/components/StatusBadge.svelte';
  import LoadingSpinner from '@trustedca/shared/components/LoadingSpinner.svelte';
  import Button from '@trustedca/shared/components/Button.svelte';
  import { formatDateTime, formatNumber, formatDate, daysRemaining } from '@trustedca/shared/utils/formatters';
  import { caStatus, caStats, statusLoading, fetchStatus } from '../lib/stores/status';
  import { adminApi } from '../lib/api/admin-api';
  import type { CertificateInfo } from '@trustedca/shared/api/types';

  let fetchError = false;
  let expiringCerts: CertificateInfo[] = [];
  let expiringCount = 0;
  let expiringLoading = false;

  async function loadData() {
    fetchError = false;
    try {
      await fetchStatus();
    } catch {
      fetchError = true;
    }
  }

  async function loadExpiringCerts() {
    expiringLoading = true;
    try {
      const res = await adminApi.listCertificates({ expires_days: 30, per_page: 5 });
      expiringCerts = res.data ?? [];
      expiringCount = res.pagination?.total ?? expiringCerts.length;
    } catch {
      // Non-critical widget — silently ignore errors
    } finally {
      expiringLoading = false;
    }
  }

  onMount(() => {
    loadData();
    loadExpiringCerts();
  });
</script>

<div class="p-6">
  <h1 class="text-2xl font-bold text-slate-900 dark:text-slate-100 mb-6">
    Dashboard
  </h1>

  {#if $statusLoading}
    <div class="flex flex-col items-center justify-center py-20 gap-3">
      <LoadingSpinner size="lg" />
      <p class="text-sm text-slate-500 dark:text-slate-400">Loading dashboard data...</p>
    </div>
  {:else if fetchError || (!$caStatus && !$caStats)}
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
    <!-- CA Status -->
    <div class="mb-8">
      <Card title="Certificate Authority Status">
        {#if $caStatus}
          <div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4">
            <div>
              <p class="text-sm text-slate-500 dark:text-slate-400">Identity</p>
              <p class="mt-1 font-medium text-slate-900 dark:text-slate-100">
                {$caStatus.identity}
              </p>
            </div>
            <div>
              <p class="text-sm text-slate-500 dark:text-slate-400">Status</p>
              <div class="mt-1">
                <StatusBadge status={$caStatus.initialized ? 'active' : 'pending'} />
              </div>
            </div>
            <div>
              <p class="text-sm text-slate-500 dark:text-slate-400">Version</p>
              <p class="mt-1 font-medium text-slate-900 dark:text-slate-100">
                {$caStatus.version}
              </p>
            </div>
            <div>
              <p class="text-sm text-slate-500 dark:text-slate-400">Started</p>
              <p class="mt-1 font-medium text-slate-900 dark:text-slate-100">
                {formatDateTime($caStatus.started_at)}
              </p>
            </div>
            <div>
              <p class="text-sm text-slate-500 dark:text-slate-400">Key Algorithms</p>
              <p class="mt-1 font-medium text-slate-900 dark:text-slate-100">
                {#if $caStatus.keys && $caStatus.keys.length > 0}
                  {$caStatus.keys.filter(k => k.default).map(k => k.algorithm).join(', ')}
                  {#if $caStatus.keys.length > 1}
                    <span class="text-xs text-slate-400 ml-1">(+{$caStatus.keys.length - 1} more)</span>
                  {/if}
                {:else}
                  {$caStatus.key_algorithm}
                {/if}
              </p>
            </div>
            <div>
              <p class="text-sm text-slate-500 dark:text-slate-400">Signature Algorithm</p>
              <p class="mt-1 font-medium text-slate-900 dark:text-slate-100">
                {#if $caStatus.keys && $caStatus.keys.length > 0}
                  {$caStatus.keys.filter(k => k.default).map(k => k.signature_algorithm).join(', ')}
                {:else}
                  {$caStatus.signature_algorithm}
                {/if}
              </p>
            </div>
          </div>
        {:else}
          <p class="text-slate-500 dark:text-slate-400">Unable to load CA status.</p>
        {/if}
      </Card>
    </div>

    <!-- Stats cards -->
    {#if $caStats}
      <div class="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-4 mb-8">
        <Card>
          <div class="text-center">
            <p class="text-3xl font-bold text-blue-600 dark:text-blue-400">
              {formatNumber($caStats.total_certificates)}
            </p>
            <p class="mt-1 text-sm text-slate-500 dark:text-slate-400">Total Certificates</p>
            <div class="mt-2 flex justify-center gap-2 text-xs">
              <span class="text-green-600 dark:text-green-400">
                {formatNumber($caStats.valid_certificates)} valid
              </span>
              <span class="text-red-600 dark:text-red-400">
                {formatNumber($caStats.revoked_certificates)} revoked
              </span>
            </div>
          </div>
        </Card>

        <Card>
          <div class="text-center">
            <p class="text-3xl font-bold text-green-600 dark:text-green-400">
              {formatNumber($caStats.active_accounts)}
            </p>
            <p class="mt-1 text-sm text-slate-500 dark:text-slate-400">Active Accounts</p>
            <p class="mt-2 text-xs text-slate-400 dark:text-slate-500">
              of {formatNumber($caStats.total_accounts)} total
            </p>
          </div>
        </Card>

        <Card>
          <div class="text-center">
            <p class="text-3xl font-bold text-amber-600 dark:text-amber-400">
              {formatNumber($caStats.pending_orders)}
            </p>
            <p class="mt-1 text-sm text-slate-500 dark:text-slate-400">Pending Orders</p>
            <p class="mt-2 text-xs text-slate-400 dark:text-slate-500">
              {formatNumber($caStats.completed_orders)} completed
            </p>
          </div>
        </Card>

        <Card>
          <div class="text-center">
            <p class="text-3xl font-bold text-slate-600 dark:text-slate-300">
              {formatNumber($caStats.expired_certificates)}
            </p>
            <p class="mt-1 text-sm text-slate-500 dark:text-slate-400">Expired Certificates</p>
          </div>
        </Card>
      </div>
    {/if}

    <!-- Expiring Certificates Widget -->
    <Card title="Expiring Soon">
      <div class="mb-4 flex items-center justify-between">
        <p class="text-sm text-slate-500 dark:text-slate-400">
          {#if expiringLoading}
            Loading...
          {:else}
            <span class="font-semibold text-amber-600 dark:text-amber-400">
              {formatNumber(expiringCount)}
            </span>
            {expiringCount === 1 ? 'certificate expires' : 'certificates expire'} within 30 days
          {/if}
        </p>
      </div>

      {#if expiringLoading}
        <div class="flex justify-center py-6">
          <LoadingSpinner size="md" />
        </div>
      {:else if expiringCerts.length === 0}
        <div class="flex items-center gap-3 rounded-lg bg-green-50 px-4 py-3 dark:bg-green-900/20">
          <svg class="h-5 w-5 flex-shrink-0 text-green-600 dark:text-green-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
            <path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m6 2a9 9 0 11-18 0 9 9 0 0118 0z" />
          </svg>
          <p class="text-sm text-green-700 dark:text-green-300">
            No certificates expiring within the next 30 days.
          </p>
        </div>
      {:else}
        <div class="overflow-hidden rounded-lg border border-slate-200 dark:border-slate-700">
          <table class="w-full text-left text-sm">
            <thead class="bg-slate-50 dark:bg-slate-800/50">
              <tr>
                <th class="px-4 py-3 font-medium text-slate-600 dark:text-slate-300">Subject</th>
                <th class="px-4 py-3 font-medium text-slate-600 dark:text-slate-300">Serial</th>
                <th class="px-4 py-3 font-medium text-slate-600 dark:text-slate-300">Expires</th>
                <th class="px-4 py-3 font-medium text-slate-600 dark:text-slate-300">Days Left</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-200 dark:divide-slate-700">
              {#each expiringCerts as cert}
                {@const days = daysRemaining(cert.not_after)}
                <tr class="bg-white dark:bg-slate-800">
                  <td class="px-4 py-3 text-slate-900 dark:text-slate-100 max-w-xs truncate">
                    {cert.subject}
                  </td>
                  <td class="px-4 py-3 font-mono text-xs text-slate-600 dark:text-slate-400">
                    {cert.serial_number.length > 16
                      ? cert.serial_number.slice(0, 8) + '…' + cert.serial_number.slice(-8)
                      : cert.serial_number}
                  </td>
                  <td class="px-4 py-3 text-slate-700 dark:text-slate-300">
                    {formatDate(cert.not_after)}
                  </td>
                  <td class="px-4 py-3">
                    <span class="inline-flex items-center rounded-full px-2.5 py-0.5 text-xs font-medium
                      {days !== null && days <= 7
                        ? 'bg-red-100 text-red-800 dark:bg-red-900/30 dark:text-red-400'
                        : 'bg-amber-100 text-amber-800 dark:bg-amber-900/30 dark:text-amber-400'}">
                      {days !== null ? `${days}d` : '-'}
                    </span>
                  </td>
                </tr>
              {/each}
            </tbody>
          </table>
        </div>

        {#if expiringCount > expiringCerts.length}
          <div class="mt-3 text-right">
            <span class="text-sm text-blue-600 hover:underline dark:text-blue-400 cursor-pointer">
              View all {expiringCount} expiring certificates
            </span>
          </div>
        {/if}
      {/if}
    </Card>
  {/if}
</div>
