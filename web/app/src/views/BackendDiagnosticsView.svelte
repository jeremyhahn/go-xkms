<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import StatusBadge from "$components/StatusBadge.svelte";
  import Alert from "$components/Alert.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import {
    backendAlgorithms,
    backendStatus,
    backendTest,
    type BackendStatusResponse,
    type BackendTestResponse,
  } from "$lib/backendDiagnostics.ts";
  import type { BackendInfo } from "@go-xkms/sdk";

  let backends = $state<BackendInfo[]>([]);
  let listError = $state<string | null>(null);
  let loading = $state(true);

  let selected = $state("");
  let status = $state<BackendStatusResponse | null>(null);
  let statusError = $state<string | null>(null);
  let algorithms = $state<string[] | null>(null);
  let algError = $state<string | null>(null);

  let testing = $state(false);
  let result = $state<BackendTestResponse | null>(null);
  let testError = $state<string | null>(null);

  const healthy = new Set(["healthy", "ok", "available", "ready"]);
  const enabledCaps = $derived(
    status?.capabilities ? Object.keys(status.capabilities).filter((k) => status?.capabilities?.[k]) : [],
  );

  function msg(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
  }

  async function loadBackends(): Promise<void> {
    loading = true;
    listError = null;
    try {
      backends = (await getSDKClient().backends.list()).backends;
    } catch (e) {
      listError = msg(e);
    } finally {
      loading = false;
    }
  }

  // Status and algorithms load independently: an algorithms failure (it
  // needs keys:list) must not hide the status card.
  async function choose(id: string): Promise<void> {
    selected = id;
    status = null;
    statusError = null;
    algorithms = null;
    algError = null;
    result = null;
    testError = null;
    if (id === "") return;
    await Promise.all([
      backendStatus(id).then(
        (s) => { if (selected === id) status = s; },
        (e) => { if (selected === id) statusError = msg(e); },
      ),
      backendAlgorithms(id).then(
        (a) => { if (selected === id) algorithms = a.algorithms; },
        (e) => { if (selected === id) algError = msg(e); },
      ),
    ]);
  }

  async function runTest(): Promise<void> {
    const id = selected;
    testing = true;
    result = null;
    testError = null;
    try {
      const r = await backendTest(id);
      if (selected === id) result = r;
    } catch (e) {
      if (selected === id) testError = msg(e);
    } finally {
      testing = false;
    }
  }

  onMount(() => {
    void loadBackends();
  });
</script>

<PageHeader title="Backend Diagnostics" subtitle="Status, self-test and algorithms of one backend" />

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if listError}
  <Alert kind="error"><span>{listError}</span></Alert>
{:else}
  <div class="flex flex-wrap items-end gap-3 mb-4">
    <label class="form-control">
      <span class="label-text mb-1">Backend</span>
      <select
        class="select select-bordered select-sm"
        aria-label="Backend"
        value={selected}
        onchange={(e) => void choose((e.currentTarget as HTMLSelectElement).value)}
      >
        <option value="">Choose a backend</option>
        {#each backends as b (b.id)}
          <option value={b.id}>{b.id}</option>
        {/each}
      </select>
    </label>
    <button class="btn btn-primary btn-sm" onclick={runTest} disabled={selected === "" || testing}>
      {#if testing}<span class="loading loading-spinner loading-xs"></span>{/if}
      Run self-test
    </button>
  </div>

  {#if testError}
    <Alert kind="error" class="mb-3"><span>{testError}</span></Alert>
  {:else if result}
    <div class="flex flex-wrap items-center gap-2 mb-4">
      {#if result.success}
        <StatusBadge label="passed" ok={true} />
        <span>Self-test passed in {result.duration_ms} ms</span>
      {:else}
        <StatusBadge label="failed" ok={false} />
        {#if result.message}<span>{result.message}</span>{/if}
      {/if}
    </div>
  {/if}

  {#if statusError}
    <Alert kind="error" class="mb-3"><span>{statusError}</span></Alert>
  {:else if status}
    <div class="card bg-base-100 border border-base-300 mb-4">
      <div class="card-body p-4">
        <h2 class="card-title text-base">Status</h2>
        <dl class="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
          <dt>Type</dt><dd>{status.backend_type}</dd>
          <dt>Status</dt>
          <dd><StatusBadge label={status.status} ok={healthy.has(status.status.toLowerCase())} /></dd>
          {#if status.device}<dt>Device</dt><dd>{status.device}</dd>{/if}
          {#if status.region}<dt>Region</dt><dd>{status.region}</dd>{/if}
          {#if status.key_id}<dt>Key ID</dt><dd>{status.key_id}</dd>{/if}
          {#if status.pcr_banks?.length}<dt>PCR banks</dt><dd>{status.pcr_banks.join(", ")}</dd>{/if}
          {#if status.pcr_registers?.length}<dt>PCR registers</dt><dd>{status.pcr_registers.join(", ")}</dd>{/if}
        </dl>
        {#if enabledCaps.length}
          <h3 class="font-semibold text-sm mt-2">Capabilities</h3>
          <ul class="flex flex-wrap gap-2">
            {#each enabledCaps as cap (cap)}<li class="badge badge-outline">{cap}</li>{/each}
          </ul>
        {/if}
      </div>
    </div>
  {/if}

  {#if algError}
    <Alert kind="error" class="mb-3"><span>{algError}</span></Alert>
  {:else if algorithms}
    <h2 class="font-semibold mb-2">Supported algorithms</h2>
    <ul class="flex flex-wrap gap-2">
      {#each algorithms as alg (alg)}<li class="badge">{alg}</li>{/each}
      {#if algorithms.length === 0}<li class="text-base-content/60">No algorithms reported.</li>{/if}
    </ul>
  {/if}
{/if}
