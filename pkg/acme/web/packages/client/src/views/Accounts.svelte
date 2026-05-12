<script lang="ts">
  import { onMount } from 'svelte';
  import Card from '@trustedca/shared/components/Card.svelte';
  import Button from '@trustedca/shared/components/Button.svelte';
  import LoadingSpinner from '@trustedca/shared/components/LoadingSpinner.svelte';
  import Modal from '@trustedca/shared/components/Modal.svelte';
  import { notifySuccess, notifyError } from '@trustedca/shared/stores/notifications';
  import { clientApi } from '../lib/api/client-api';
  import type { AccountConfig } from '@trustedca/shared/api/types';

  interface AccountRow {
    name: string;
    config: AccountConfig;
  }

  let rows: AccountRow[] = [];
  let loading = false;
  let error = '';

  let confirmOpen = false;
  let removingName = '';
  let removing = false;

  async function loadAccounts() {
    loading = true;
    error = '';
    try {
      const data = await clientApi.listAccounts();
      rows = Object.entries(data).map(([name, config]) => ({ name, config }));
    } catch (e) {
      error = (e as Error).message;
    } finally {
      loading = false;
    }
  }

  function openConfirm(name: string) {
    removingName = name;
    confirmOpen = true;
  }

  function closeConfirm() {
    confirmOpen = false;
    removingName = '';
  }

  async function handleRemove() {
    removing = true;
    try {
      await clientApi.removeAccount(removingName);
      notifySuccess(`Account "${removingName}" removed`);
      confirmOpen = false;
      removingName = '';
      await loadAccounts();
    } catch (e) {
      notifyError(`Failed to remove account: ${(e as Error).message}`);
    } finally {
      removing = false;
    }
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
    <Button variant="secondary" size="sm" on:click={loadAccounts} disabled={loading}>
      Refresh
    </Button>
  </div>

  {#if loading}
    <div class="flex flex-col items-center justify-center py-20 gap-3">
      <LoadingSpinner size="lg" />
      <p class="text-sm text-slate-500 dark:text-slate-400">Loading accounts...</p>
    </div>
  {:else if error}
    <div class="flex flex-col items-center justify-center py-20 gap-4">
      <svg class="h-12 w-12 text-slate-400 dark:text-slate-500" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="1.5">
        <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m9-.75a9 9 0 11-18 0 9 9 0 0118 0zm-9 3.75h.008v.008H12v-.008z" />
      </svg>
      <p class="text-sm text-slate-600 dark:text-slate-400">{error}</p>
      <Button variant="secondary" size="sm" on:click={loadAccounts}>Retry</Button>
    </div>
  {:else}
    <Card>
      <div class="overflow-hidden rounded-lg border border-slate-200 dark:border-slate-700">
        <div class="overflow-x-auto">
          <table class="w-full text-left text-sm">
            <thead class="bg-slate-50 dark:bg-slate-800/50">
              <tr>
                <th class="px-4 py-3 font-medium text-slate-600 dark:text-slate-300">Name</th>
                <th class="px-4 py-3 font-medium text-slate-600 dark:text-slate-300">Directory</th>
                <th class="px-4 py-3 font-medium text-slate-600 dark:text-slate-300">Email</th>
                <th class="px-4 py-3 font-medium text-slate-600 dark:text-slate-300">Key Algorithm</th>
                <th class="px-4 py-3 font-medium text-slate-600 dark:text-slate-300">Store</th>
                <th class="px-4 py-3 font-medium text-slate-600 dark:text-slate-300 text-right">Actions</th>
              </tr>
            </thead>
            <tbody class="divide-y divide-slate-200 dark:divide-slate-700">
              {#if rows.length === 0}
                <tr>
                  <td colspan="6" class="px-4 py-12 text-center text-slate-500 dark:text-slate-400">
                    No accounts configured
                  </td>
                </tr>
              {:else}
                {#each rows as row}
                  <tr class="bg-white hover:bg-slate-50 dark:bg-slate-800 dark:hover:bg-slate-700/50">
                    <td class="px-4 py-3 font-medium text-slate-900 dark:text-slate-100">
                      {row.name}
                    </td>
                    <td class="px-4 py-3 text-slate-700 dark:text-slate-300 max-w-xs truncate">
                      {row.config.directory}
                    </td>
                    <td class="px-4 py-3 text-slate-700 dark:text-slate-300">
                      {row.config.email}
                    </td>
                    <td class="px-4 py-3 text-slate-700 dark:text-slate-300">
                      {row.config.key.algorithm}
                    </td>
                    <td class="px-4 py-3 text-slate-700 dark:text-slate-300">
                      {row.config.key.store}
                    </td>
                    <td class="px-4 py-3 text-right">
                      <Button
                        variant="danger"
                        size="sm"
                        on:click={() => openConfirm(row.name)}
                      >
                        Remove
                      </Button>
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

<Modal
  open={confirmOpen}
  title="Remove Account"
  size="sm"
  on:close={closeConfirm}
>
  <p class="text-sm text-slate-700 dark:text-slate-300">
    Are you sure you want to remove account <span class="font-semibold">"{removingName}"</span>?
    This action cannot be undone.
  </p>

  <svelte:fragment slot="footer">
    <div class="flex justify-end gap-3">
      <Button variant="secondary" size="sm" on:click={closeConfirm} disabled={removing}>
        Cancel
      </Button>
      <Button variant="danger" size="sm" on:click={handleRemove} loading={removing}>
        Remove
      </Button>
    </div>
  </svelte:fragment>
</Modal>
