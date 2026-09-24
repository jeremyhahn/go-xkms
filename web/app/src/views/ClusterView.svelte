<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import DataTable from "$components/DataTable.svelte";
  import StatusBadge from "$components/StatusBadge.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import Alert from "$components/Alert.svelte";
  import type { ClusterStatusResponse, ClusterMemberInfo } from "@go-xkms/sdk";

  let status = $state<ClusterStatusResponse | null>(null);
  let members = $state<ClusterMemberInfo[]>([]);
  let error = $state<string | null>(null);
  let loading = $state(true);

  const columns = [
    { key: "replica_id", label: "Replica ID" },
    { key: "address", label: "Address" },
    { key: "leader", label: "Leader" },
  ];

  const rows = $derived(
    members.map((m) => ({
      replica_id: m.replica_id,
      address: m.address,
      leader: m.is_leader ? "yes" : "no",
    })),
  );

  async function load(): Promise<void> {
    loading = true;
    error = null;
    const c = getSDKClient();
    try {
      status = await c.cluster.status();
      const m = await c.cluster.members();
      members = m.members;
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

<PageHeader title="Cluster" subtitle="Raft cluster membership (read-only)" />

<Alert kind="info" class="mb-4">
  <span>
    Cluster membership changes are performed over the Raft admin plane with
    <code class="font-mono">xkmsctl cluster add / remove</code> and are
    intentionally not exposed here.
  </span>
</Alert>

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if error}
  <Alert kind="error"><span>{error}</span></Alert>
{:else}
  {#if status}
    <div class="flex flex-wrap gap-2 mb-4">
      <StatusBadge label={status.status.clustered ? "clustered" : "standalone"} ok={status.status.clustered} />
      <StatusBadge label={status.status.has_leader ? "leader elected" : "no leader"} ok={status.status.has_leader} />
      <StatusBadge label={`node ${status.status.node_id}`} kind="neutral" />
    </div>
  {/if}
  <DataTable {columns} {rows} emptyMessage="No cluster members (standalone node)." caption="Cluster members" />
{/if}
