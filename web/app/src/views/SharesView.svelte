<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import Alert from "$components/Alert.svelte";
  import type { ShareStatusResponse } from "@go-xkms/sdk";

  let shares = $state<ShareStatusResponse[]>([]);
  let error = $state<string | null>(null);
  let loading = $state(true);

  async function load(): Promise<void> {
    loading = true;
    error = null;
    try {
      const resp = await getSDKClient().shares.list();
      shares = resp.shares;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  // Mount-time load: the view has no reactive inputs, so onMount is both
  // correct and immune to an $effect re-running on unrelated state.
  onMount(() => {
    void load();
  });
</script>

<PageHeader title="Shares" subtitle="Collected Shamir shares" />

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if error}
  <Alert kind="error"><span>{error}</span></Alert>
{:else}
  <div class="overflow-x-auto">
    <table class="table table-sm">
      <caption class="sr-only">Collected Shamir shares</caption>
      <thead><tr><th scope="col">Group</th><th scope="col">Index</th><th scope="col">Server</th><th scope="col">Purpose</th><th scope="col">Received</th></tr></thead>
      <tbody>
        {#each shares as s (s.server_url + s.group_id + s.share_index)}
          <tr>
            <td>{s.group_name ?? s.group_id}</td>
            <td>{s.share_index}</td>
            <td>{s.server_url}</td>
            <td>{s.purpose ?? "—"}</td>
            <td>{s.received_at}</td>
          </tr>
        {/each}
        {#if shares.length === 0}
          <tr><td colspan="5" class="text-center text-base-content/60 py-6">No shares collected.</td></tr>
        {/if}
      </tbody>
    </table>
  </div>
{/if}
