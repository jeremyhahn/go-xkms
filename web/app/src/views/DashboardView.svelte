<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import StatCard from "$components/StatCard.svelte";
  import StatusBadge from "$components/StatusBadge.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { hasCapability } from "$stores/session.svelte.ts";
  import Alert from "$components/Alert.svelte";
  import type {
    HealthResponse,
    BarrierStatusResponse,
    ClusterStatusResponse,
  } from "@go-xkms/sdk";

  let health = $state<HealthResponse | null>(null);
  let barrier = $state<BarrierStatusResponse | null>(null);
  let cluster = $state<ClusterStatusResponse | null>(null);
  let backendCount = $state<number | null>(null);
  let error = $state<string | null>(null);
  let loading = $state(true);

  async function load(): Promise<void> {
    loading = true;
    error = null;
    const c = getSDKClient();
    try {
      health = await c.health.health();
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
    // The remaining panels are best-effort: a deployment may not expose every
    // subsystem, and one failing call must not blank the whole dashboard.
    try {
      barrier = await c.barrier.status();
    } catch {
      barrier = null;
    }
    try {
      const b = await c.backends.list();
      backendCount = b.backends.length;
    } catch {
      backendCount = null;
    }
    if (hasCapability("cluster")) {
      try {
        cluster = await c.cluster.status();
      } catch {
        cluster = null;
      }
    }
    loading = false;
  }

  // Mount-time load: the view has no reactive inputs, so onMount is both
  // correct and immune to an $effect re-running on unrelated state.
  onMount(() => {
    void load();
  });
</script>

<PageHeader title="Dashboard" subtitle="xKMS service health and posture" />

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else}
  {#if error}
    <Alert kind="error" class="mb-4"><span>{error}</span></Alert>
  {/if}

  <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
    <StatCard label="Status" value={health?.status ?? "unknown"} hint={health?.version ?? ""} />
    <StatCard label="Backends" value={backendCount ?? "—"} />
    <StatCard
      label="Barrier"
      value={barrier === null ? "—" : barrier.sealed ? "sealed" : "unsealed"}
      hint={barrier?.strategy ?? ""}
    />
    <StatCard
      label="Cluster"
      value={cluster === null ? "standalone" : cluster.status.clustered ? "clustered" : "standalone"}
      hint={cluster?.status.has_leader ? "leader elected" : ""}
    />
  </div>

  <div class="card bg-base-200 mt-6">
    <div class="card-body">
      <h2 class="card-title text-base">Service</h2>
      <div class="flex flex-wrap gap-2">
        <StatusBadge label={`status: ${health?.status ?? "unknown"}`} ok={health?.status === "ok"} />
        {#if barrier}
          <StatusBadge label={barrier.sealed ? "barrier: sealed" : "barrier: unsealed"} ok={!barrier.sealed} />
          {#if barrier.hardware_backed}<StatusBadge label="hardware-backed" ok={true} />{/if}
        {/if}
      </div>
    </div>
  </div>
{/if}
