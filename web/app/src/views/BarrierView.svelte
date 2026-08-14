<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import StatusBadge from "$components/StatusBadge.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { can } from "$stores/session.svelte.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import Alert from "$components/Alert.svelte";
  import type { BarrierStatusResponse } from "@go-xkms/sdk";

  let status = $state<BarrierStatusResponse | null>(null);
  let error = $state<string | null>(null);
  let loading = $state(true);
  let busy = $state(false);
  let passphrase = $state("");

  async function load(): Promise<void> {
    loading = true;
    error = null;
    try {
      status = await getSDKClient().barrier.status();
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  async function unseal(): Promise<void> {
    busy = true;
    try {
      await getSDKClient().barrier.unseal({ secret: passphrase });
      showToast("success", "Barrier unsealed.");
      passphrase = "";
      await load();
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    } finally {
      busy = false;
    }
  }

  async function seal(): Promise<void> {
    busy = true;
    try {
      await getSDKClient().barrier.seal();
      showToast("success", "Barrier sealed.");
      await load();
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    } finally {
      busy = false;
    }
  }

  // Mount-time load: the view has no reactive inputs, so onMount is both
  // correct and immune to an $effect re-running on unrelated state.
  onMount(() => {
    void load();
  });
</script>

<PageHeader title="Barrier & Seal" subtitle="Encryption barrier lifecycle" />

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if error}
  <Alert kind="error"><span>{error}</span></Alert>
{:else if status}
  <div class="card bg-base-200 mb-6">
    <div class="card-body">
      <div class="flex flex-wrap gap-2">
        <StatusBadge label={status.sealed ? "sealed" : "unsealed"} ok={!status.sealed} />
        <StatusBadge label={`strategy: ${status.strategy}`} kind="neutral" />
        {#if status.hardware_backed}<StatusBadge label="hardware-backed" ok={true} />{/if}
      </div>
    </div>
  </div>

  {#if status.sealed && can("seal", "unseal")}
    <div class="card bg-base-200 mb-4">
      <div class="card-body">
        <h2 class="card-title text-base">Unseal</h2>
        <label class="form-control max-w-sm">
          <span class="label-text">Passphrase</span>
          <input type="password" class="input input-bordered" bind:value={passphrase} />
        </label>
        <button class="btn btn-primary btn-sm mt-2 w-fit" onclick={unseal} disabled={busy}>Unseal</button>
      </div>
    </div>
  {/if}

  {#if !status.sealed && can("seal", "seal")}
    <button class="btn btn-warning btn-sm" onclick={seal} disabled={busy}>Seal barrier</button>
  {/if}

  <Alert kind="info" class="mt-6">
    <span>
      Shamir quorum initialization, rekey, recovery-key management, and root-token
      generation are available via <code class="font-mono">xkmsctl barrier</code>.
      Multi-operator ceremonies are best driven from the CLI.
    </span>
  </Alert>
{/if}
