<script lang="ts">
  import { onMount } from 'svelte';
  import Card from '@trustedca/shared/components/Card.svelte';
  import Button from '@trustedca/shared/components/Button.svelte';
  import StatusBadge from '@trustedca/shared/components/StatusBadge.svelte';
  import LoadingSpinner from '@trustedca/shared/components/LoadingSpinner.svelte';
  import { notifySuccess, notifyError } from '@trustedca/shared/stores/notifications';
  import { clientApi } from '../lib/api/client-api';
  import type { CertificateSpec, ManagedCertInfo } from '@trustedca/shared/api/types';

  interface CertRow {
    name: string;
    spec: CertificateSpec;
    issued: boolean;
    issued_at?: string;
    expires_at?: string;
  }

  let allRows: CertRow[] = [];
  let accountFilter = '';
  let accounts: string[] = [];
  let loading = false;
  let error = '';

  // Per-row action loading states keyed by cert name
  let actionLoading: Record<string, string> = {};

  $: filteredRows = accountFilter
    ? allRows.filter((r) => r.spec.account === accountFilter)
    : allRows;

  async function loadCertificates() {
    loading = true;
    error = '';
    try {
      const data = await clientApi.listCertificates();
      allRows = Object.entries(data).map(([name, spec]) => ({
        name,
        spec,
        issued: false,
      }));
      accounts = [...new Set(allRows.map((r) => r.spec.account))].sort();
    } catch (e) {
      error = (e as Error).message;
    } finally {
      loading = false;
    }
  }

  async function handleRequest(name: string) {
    actionLoading = { ...actionLoading, [name]: 'request' };
    try {
      await clientApi.requestCertificate({ name });
      notifySuccess(`Certificate request submitted for "${name}"`);
      await loadCertificates();
    } catch (e) {
      notifyError(`Failed to request certificate: ${(e as Error).message}`);
    } finally {
      const next = { ...actionLoading };
      delete next[name];
      actionLoading = next;
    }
  }

  async function handleRenew(name: string) {
    actionLoading = { ...actionLoading, [name]: 'renew' };
    try {
      await clientApi.renewCertificate({ name });
      notifySuccess(`Renewal initiated for "${name}"`);
      await loadCertificates();
    } catch (e) {
      notifyError(`Failed to renew certificate: ${(e as Error).message}`);
    } finally {
      const next = { ...actionLoading };
      delete next[name];
      actionLoading = next;
    }
  }

  async function handleRevoke(name: string) {
    actionLoading = { ...actionLoading, [name]: 'revoke' };
    try {
      await clientApi.revokeCertificate({ name, reason: 0 });
      notifySuccess(`Certificate "${name}" revoked`);
      await loadCertificates();
    } catch (e) {
      notifyError(`Failed to revoke certificate: ${(e as Error).message}`);
    } finally {
      const next = { ...actionLoading };
      delete next[name];
      actionLoading = next;
    }
  }

  async function handleDeploy(name: string) {
    actionLoading = { ...actionLoading, [name]: 'deploy' };
    try {
      await clientApi.deployCertificate(name);
      notifySuccess(`Certificate "${name}" deployed`);
      await loadCertificates();
    } catch (e) {
      notifyError(`Failed to deploy certificate: ${(e as Error).message}`);
    } finally {
      const next = { ...actionLoading };
      delete next[name];
      actionLoading = next;
    }
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
        class="rounded-lg border border-slate-300 bg-white px-3 py-1.5 text-sm text-slate-700
               focus:outline-none focus:ring-2 focus:ring-blue-500
               dark:border-slate-600 dark:bg-slate-800 dark:text-slate-300"
        bind:value={accountFilter}
      >
        <option value="">All Accounts</option>
        {#each accounts as account}
          <option value={account}>{account}</option>
        {/each}
      </select>

      <Button variant="secondary" size="sm" on:click={loadCertificates} disabled={loading}>
        Refresh
      </Button>
    </div>
  </div>

  {#if loading}
    <div class="flex flex-col items-center justify-center py-20 gap-3">
      <LoadingSpinner size="lg" />
      <p class="text-sm text-slate-500 dark:text-slate-400">Loading certificates...</p>
    </div>
  {:else if error}
    <div class="flex flex-col items-center justify-center py-20 gap-4">
      <svg class="h-12 w-12 text-slate-400 dark:text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
        <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
      </svg>
      <p class="text-sm text-slate-600 dark:text-slate-400">{error}</p>
      <Button variant="secondary" size="sm" on:click={loadCertificates}>Retry</Button>
    </div>
  {:else}
    <Card>
      <div class="overflow-hidden rounded-lg border border-slate-200 dark:border-slate-700">
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm">
            <thead class="bg-slate-50 dark:bg-slate-800/50">
              <tr>
                <th class="px-4 py-3 font-medium text-slate-600 dark:text-slate-300">Name</th>
                <th class="px-4 py-3 font-medium text-slate-600 dark:text-slate-300">Account</th>
                <th class="px-4 py-3 font-medium text-slate-600 dark:text-slate-300">Subject (CN)</th>
                <th class="px-4 py-3 font-medium text-slate-600 dark:text-slate-300">Challenge</th>
                <th class="px-4 py-3 font-medium text-slate-600 dark:text-slate-300">Status</th>
                <th class="px-4 py-3 font-medium text-slate-600 dark:text-slate-300 text-center">Auto-Renew</th>
                <th class="px-4 py-3 font-medium text-slate-600 dark:text-slate-300 text-right">Actions</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-200 dark:divide-slate-700">
              {#if filteredRows.length === 0}
                <tr>
                  <td colspan="7" class="px-4 py-12 text-center text-slate-500 dark:text-slate-400">
                    No certificates found
                  </td>
                </tr>
              {:else}
                {#each filteredRows as row}
                  {@const busy = actionLoading[row.name]}
                  <tr class="bg-white hover:bg-slate-50 dark:bg-slate-800 dark:hover:bg-slate-700/50">
                    <td class="px-4 py-3 font-medium text-slate-900 dark:text-slate-100">
                      {row.name}
                    </td>
                    <td class="px-4 py-3 text-slate-700 dark:text-slate-300">
                      {row.spec.account}
                    </td>
                    <td class="px-4 py-3 text-slate-700 dark:text-slate-300">
                      {row.spec.subject.cn}
                    </td>
                    <td class="px-4 py-3 text-slate-700 dark:text-slate-300">
                      {row.spec.challenge}
                    </td>
                    <td class="px-4 py-3">
                      <StatusBadge status={row.issued ? 'issued' : 'pending'} />
                    </td>
                    <td class="px-4 py-3 text-center text-slate-700 dark:text-slate-300">
                      {#if row.spec.renewal?.auto}
                        <span class="inline-flex items-center rounded-full bg-green-100 px-2.5 py-0.5 text-xs font-medium text-green-800 dark:bg-green-900/30 dark:text-green-400">
                          Yes
                        </span>
                      {:else}
                        <span class="inline-flex items-center rounded-full bg-slate-100 px-2.5 py-0.5 text-xs font-medium text-slate-600 dark:bg-slate-700 dark:text-slate-400">
                          No
                        </span>
                      {/if}
                    </td>
                    <td class="px-4 py-3">
                      <div class="flex items-center justify-end gap-2">
                        <Button
                          variant="primary"
                          size="sm"
                          disabled={!!busy}
                          loading={busy === 'request'}
                          on:click={() => handleRequest(row.name)}
                        >
                          Request
                        </Button>
                        <Button
                          variant="secondary"
                          size="sm"
                          disabled={!!busy}
                          loading={busy === 'renew'}
                          on:click={() => handleRenew(row.name)}
                        >
                          Renew
                        </Button>
                        <Button
                          variant="secondary"
                          size="sm"
                          disabled={!!busy}
                          loading={busy === 'deploy'}
                          on:click={() => handleDeploy(row.name)}
                        >
                          Deploy
                        </Button>
                        <Button
                          variant="danger"
                          size="sm"
                          disabled={!!busy}
                          loading={busy === 'revoke'}
                          on:click={() => handleRevoke(row.name)}
                        >
                          Revoke
                        </Button>
                      </div>
                    </td>
                  </tr>
                {/each}
              {/if}
            </tbody>
          </table>
        </div>
      </div>
    </Card>
  {/if}
</div>
