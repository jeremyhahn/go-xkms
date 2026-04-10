<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import GradientHeader from '$lib/components/GradientHeader.svelte';
  import ViewToolbar from '$lib/components/ViewToolbar.svelte';
  import Button from '$lib/components/Button.svelte';
  import TOTPCard from '$lib/components/TOTPCard.svelte';
  import SearchBar from '$lib/components/SearchBar.svelte';
  import EmptyState from '$lib/components/EmptyState.svelte';
  import AddAccountDialog from '$lib/components/AddAccountDialog.svelte';
  import BackendSelector from '$lib/components/BackendSelector.svelte';
  import { mdiPlus, mdiNumeric, mdiDelete } from '$lib/utils/icons';
  import {
    oathState, oathAccounts, setAccounts, removeAccount,
    startOATHTimer, stopOATHTimer, currentTimerSeconds
  } from '$lib/stores/oath';
  import { addNotification } from '$lib/stores/notifications';
  import type { OATHAccount } from '$lib/stores/oath';
  import { isWailsAvailable, callBackend, callBackendWithError } from '$lib/api/backend';
  import type { BackendOATHAccount, TOTPCode } from '$lib/api/backend';

  let showAddDialog = false;
  let searchQuery = '';
  let selectedBackend = 'all';

  let codes: Record<string, string> = {};

  async function refreshCodes(): Promise<void> {
    const newCodes: Record<string, string> = {};
    if (isWailsAvailable()) {
      for (const account of $oathState.accounts) {
        if (account.type.toLowerCase() === 'totp') {
          const result = await callBackend<TOTPCode>('OATHService', 'GenerateTOTP', account.id);
          if (result) {
            newCodes[account.id] = result.code;
          }
        }
      }
    }
    codes = newCodes;
  }

  $: filteredAccounts = $oathAccounts;

  // Refresh codes when timer hits period boundary.
  // Reference $currentTimerSeconds to trigger reactivity on each tick.
  let lastPeriod = -1;
  $: {
    const _tick = $currentTimerSeconds;
    const currentPeriod = Math.floor(Date.now() / 30000);
    if (currentPeriod !== lastPeriod) {
      lastPeriod = currentPeriod;
      refreshCodes();
    }
  }

  onMount(async () => {
    startOATHTimer();

    if (isWailsAvailable()) {
      const accounts = await callBackend<BackendOATHAccount[]>('OATHService', 'ListAccounts');
      if (accounts && accounts.length > 0) {
        setAccounts(accounts.map(a => ({
          id: a.id,
          issuer: a.issuer,
          accountName: a.account_name || a.name,
          algorithm: a.algorithm as OATHAccount['algorithm'],
          digits: a.digits as OATHAccount['digits'],
          period: a.period,
          type: a.type as OATHAccount['type'],
          currentCode: null,
          nextRotation: 0,
          created: '',
          lastUsed: null,
        })));
      }
    }

    await refreshCodes();
  });

  onDestroy(() => {
    stopOATHTimer();
  });

  function handleSearch(value: string): void {
    searchQuery = value;
    oathState.update((s) => ({ ...s, searchQuery: value }));
  }

  function handleCopy(code: string): void {
    if (typeof navigator !== 'undefined' && navigator.clipboard) {
      navigator.clipboard.writeText(code);
    }
    addNotification('success', 'Code copied to clipboard');
  }

  async function handleDelete(accountId: string): Promise<void> {
    if (!isWailsAvailable()) return;
    const err = await callBackend<unknown>('OATHService', 'DeleteAccount', accountId);
    // DeleteAccount returns error only; null on callBackend error, undefined on success.
    removeAccount(accountId);
    delete codes[accountId];
    codes = codes;
    addNotification('success', 'Account deleted');
  }

  async function handleAccountAdded(): Promise<void> {
    if (!isWailsAvailable()) return;
    const accounts = await callBackend<BackendOATHAccount[]>('OATHService', 'ListAccounts');
    if (accounts) {
      setAccounts(accounts.map(a => ({
        id: a.id, issuer: a.issuer, accountName: a.account_name || a.name,
        algorithm: a.algorithm as OATHAccount['algorithm'],
        digits: a.digits as OATHAccount['digits'],
        period: a.period,
        type: a.type as OATHAccount['type'],
        currentCode: null, nextRotation: 0, created: '', lastUsed: null,
      })));
    }
    await refreshCodes();
  }

  async function handleAddAccount(data: { issuer: string; account: string; secret: string; digits: number; period: number }): Promise<void> {
    if (isWailsAvailable()) {
      const { error: addErr } = await callBackendWithError<BackendOATHAccount>(
        'OATHService', 'AddAccountManual', data.account, data.issuer, data.secret
      );
      if (addErr) {
        addNotification('error', `Failed to add account: ${addErr}`);
        return;
      }
      await handleAccountAdded();
    }
    addNotification('success', `Account ${data.issuer} added`);
    showAddDialog = false;
  }
</script>

<div class="oath-view">
  <GradientHeader title="OATH Accounts" subtitle="TOTP and HOTP codes" />

  <div class="oath-content">
    <ViewToolbar>
      <SearchBar
        placeholder="Search accounts..."
        value={searchQuery}
        onChange={handleSearch}
      />
      <BackendSelector
        capability="oath"
        bind:selected={selectedBackend}
        data-testid="oath-backend-selector"
      />
      <div class="toolbar-spacer" />
      <Button variant="primary" size="sm" icon={mdiPlus} on:click={() => (showAddDialog = true)}>
        Add Account
      </Button>
    </ViewToolbar>

    {#if filteredAccounts.length > 0}
      <div class="oath-grid">
        {#each filteredAccounts as account (account.id)}
          <TOTPCard
            {account}
            code={codes[account.id] || ''}
            timeRemaining={$currentTimerSeconds}
            period={account.period}
            onCopy={handleCopy}
            onDelete={handleDelete}
          />
        {/each}
      </div>
    {:else if searchQuery}
      <EmptyState
        icon={mdiNumeric}
        title="No matching accounts"
        description="No accounts match your search. Try a different search term."
      />
    {:else}
      <EmptyState
        icon={mdiNumeric}
        title="No OATH Accounts"
        description="Add your first TOTP account to generate one-time codes for two-factor authentication."
        actionLabel="Add Account"
        onAction={() => (showAddDialog = true)}
      />
    {/if}
  </div>

  <AddAccountDialog
    bind:open={showAddDialog}
    onClose={() => (showAddDialog = false)}
    onAdd={handleAddAccount}
    onAccountAdded={handleAccountAdded}
  />
</div>

<style>
  .oath-view {
    height: 100%;
    display: flex;
    flex-direction: column;
  }

  .oath-content {
    flex: 1;
    overflow-y: auto;
    padding: 24px;
  }

  .oath-grid {
    display: grid;
    grid-template-columns: repeat(auto-fill, minmax(320px, 1fr));
    gap: 16px;
  }
</style>
