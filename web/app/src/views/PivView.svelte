<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import Alert from "$components/Alert.svelte";
  import type { PIVSlotStatus } from "@go-xkms/sdk";

  let slots = $state<PIVSlotStatus[]>([]);
  let error = $state<string | null>(null);
  let loading = $state(true);

  async function load(): Promise<void> {
    loading = true;
    error = null;
    try {
      const resp = await getSDKClient().piv.listSlots();
      slots = resp.slots;
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

<PageHeader title="PIV" subtitle="Smart-card PIV slots" />

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if error}
  <Alert kind="error"><span>{error}</span></Alert>
{:else}
  <div class="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
    {#each slots as s (s.slot)}
      <div class="card bg-base-200">
        <div class="card-body p-4">
          <div class="flex items-center justify-between">
            <h3 class="font-semibold">{s.slot} · {s.name}</h3>
            <div class="flex gap-1">
              {#if s.has_key}<span class="badge badge-success badge-sm">key</span>{/if}
              {#if s.has_cert}<span class="badge badge-info badge-sm">cert</span>{/if}
            </div>
          </div>
          <p class="text-xs text-base-content/60">{s.description}</p>
          {#if s.subject}<div class="text-xs mt-1">Subject: {s.subject}</div>{/if}
          {#if s.algorithm}<div class="text-xs">Algorithm: {s.algorithm}</div>{/if}
          {#if s.not_after}<div class="text-xs">Expires: {s.not_after}</div>{/if}
        </div>
      </div>
    {/each}
    {#if slots.length === 0}
      <div class="text-base-content/60">No PIV slots reported.</div>
    {/if}
  </div>
{/if}
