<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import Alert from "$components/Alert.svelte";
  import type { CustodianGroupInfo } from "@go-xkms/sdk";

  let groups = $state<CustodianGroupInfo[]>([]);
  let error = $state<string | null>(null);
  let loading = $state(true);

  async function load(): Promise<void> {
    loading = true;
    error = null;
    try {
      const resp = await getSDKClient().custodian.listGroups();
      groups = resp.groups;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  async function distribute(id: string): Promise<void> {
    try {
      await getSDKClient().custodian.distributeShares(id);
      showToast("success", "Shares distributed.");
      await load();
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    }
  }

  // Mount-time load: the view has no reactive inputs, so onMount is both
  // correct and immune to an $effect re-running on unrelated state.
  onMount(() => {
    void load();
  });
</script>

<PageHeader title="Custodians" subtitle="Shamir custodian groups" />

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if error}
  <Alert kind="error"><span>{error}</span></Alert>
{:else}
  <div class="grid grid-cols-1 lg:grid-cols-2 gap-4">
    {#each groups as g (g.id)}
      <div class="card bg-base-200">
        <div class="card-body p-4">
          <div class="flex items-center justify-between">
            <h3 class="font-semibold">{g.name}</h3>
            <span class="badge badge-neutral">{g.threshold}-of-{g.total}</span>
          </div>
          <p class="text-xs text-base-content/60">{g.purpose}</p>
          <div class="text-xs mt-1">{g.members.length} members</div>
          <button class="btn btn-sm btn-primary w-fit mt-2" onclick={() => distribute(g.id)}>Distribute shares</button>
        </div>
      </div>
    {/each}
    {#if groups.length === 0}
      <div class="text-base-content/60">No custodian groups. Create one with <code class="font-mono">xkmsctl custodian create</code>.</div>
    {/if}
  </div>
{/if}
