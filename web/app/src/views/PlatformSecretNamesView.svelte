<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import StatusBadge from "$components/StatusBadge.svelte";
  import Alert from "$components/Alert.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";

  // Names only: this view never fetches a secret value.
  let names = $state<string[]>([]);
  let total = $state(0);
  let error = $state<string | null>(null);
  let loading = $state(true);
  let filter = $state("");

  const shown = $derived.by(() => {
    const q = filter.trim().toLowerCase();
    return names.filter((n) => n.toLowerCase().includes(q));
  });

  async function load(): Promise<void> {
    loading = true;
    error = null;
    try {
      const res = await getSDKClient().platform.listSecrets();
      names = [...res.names].sort((a, b) => a.localeCompare(b));
      total = res.total;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  onMount(() => {
    void load();
  });
</script>

<PageHeader title="Secret Names" subtitle="Names of the secrets in the platform seal store">
  {#snippet actions()}
    <button class="btn btn-ghost btn-sm" onclick={load} disabled={loading}>Refresh</button>
  {/snippet}
</PageHeader>

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if error}
  <Alert kind="error"><span>{error}</span></Alert>
{:else}
  <div class="flex flex-wrap items-center gap-2 mb-4">
    <input
      class="input input-bordered input-sm w-64"
      aria-label="Filter secret names"
      placeholder="Filter"
      bind:value={filter}
    />
    <StatusBadge label={`${total} secrets`} kind="neutral" />
  </div>
  {#if names.length === 0}
    <p class="text-center text-base-content/60 py-6">No secrets stored</p>
  {:else if shown.length === 0}
    <p class="text-center text-base-content/60 py-6">No names match the filter</p>
  {:else}
    <ul class="menu bg-base-100 rounded-box" aria-label="Secret names">
      {#each shown as name (name)}
        <li class="font-mono px-4 py-1">{name}</li>
      {/each}
    </ul>
  {/if}
{/if}
