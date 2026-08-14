<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import DataTable from "$components/DataTable.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import Alert from "$components/Alert.svelte";
  import type { BackendInfo } from "@go-xkms/sdk";

  let backends = $state<BackendInfo[]>([]);
  let error = $state<string | null>(null);
  let loading = $state(true);

  const columns = [
    { key: "id", label: "ID" },
    { key: "type", label: "Type" },
    { key: "hardware", label: "Hardware-backed" },
  ];

  const rows = $derived(
    backends.map((b) => ({
      id: b.id,
      type: b.type,
      hardware: b.hardware_backed ? "yes" : "no",
    })),
  );

  async function load(): Promise<void> {
    loading = true;
    error = null;
    try {
      const resp = await getSDKClient().backends.list();
      backends = resp.backends;
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

<PageHeader title="Backends" subtitle="Configured crypto backends" />

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if error}
  <Alert kind="error"><span>{error}</span></Alert>
{:else}
  <DataTable {columns} {rows} emptyMessage="No backends configured." caption="Configured crypto backends" />
{/if}
