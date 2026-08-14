<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import StatusBadge from "$components/StatusBadge.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import Alert from "$components/Alert.svelte";
  import type { InitStatusResponse, CredentialStrategyResponse } from "@go-xkms/sdk";

  let init = $state<InitStatusResponse | null>(null);
  let strategy = $state<CredentialStrategyResponse | null>(null);
  let error = $state<string | null>(null);
  let loading = $state(true);

  async function load(): Promise<void> {
    loading = true;
    error = null;
    const c = getSDKClient();
    try {
      init = await c.init.status();
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    }
    try {
      strategy = await c.credentials.strategy();
    } catch {
      strategy = null;
    }
    loading = false;
  }

  // Mount-time load: the view has no reactive inputs, so onMount is both
  // correct and immune to an $effect re-running on unrelated state.
  onMount(() => {
    void load();
  });
</script>

<PageHeader title="Init & Ceremony" subtitle="First-boot initialization state" />

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if error}
  <Alert kind="error"><span>{error}</span></Alert>
{:else}
  <div class="card bg-base-200 mb-4">
    <div class="card-body">
      <h2 class="card-title text-base">Ceremony state</h2>
      <div><StatusBadge label={init?.state ?? "unknown"} kind="neutral" /></div>
    </div>
  </div>
  {#if strategy}
    <div class="card bg-base-200">
      <div class="card-body">
        <h2 class="card-title text-base">Credential strategy</h2>
        <dl class="text-sm space-y-1">
          <div class="flex justify-between"><dt class="text-base-content/60">Strategy</dt><dd>{strategy.strategy}</dd></div>
          <div class="flex justify-between"><dt class="text-base-content/60">Auto-unseal</dt><dd>{strategy.auto_unseal ? "yes" : "no"}</dd></div>
        </dl>
      </div>
    </div>
  {/if}
  <Alert kind="info" class="mt-6">
    <span>
      Officer certificate and Shamir-share claims run before trust is
      established and are driven by <code class="font-mono">xkmsctl init</code>.
    </span>
  </Alert>
{/if}
