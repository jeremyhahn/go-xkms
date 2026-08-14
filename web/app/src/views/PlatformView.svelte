<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import StatusBadge from "$components/StatusBadge.svelte";
  import Modal from "$components/Modal.svelte";
  import Alert from "$components/Alert.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import type { SealStoreStatusResponse } from "@go-xkms/sdk";

  let status = $state<SealStoreStatusResponse | null>(null);
  let error = $state<string | null>(null);
  let loading = $state(true);
  let busy = $state(false);
  let showPut = $state(false);

  let pName = $state("");
  let pValue = $state("");
  let pErr = $state<string | null>(null);

  function toB64(s: string): string {
    return btoa(unescape(encodeURIComponent(s)));
  }

  async function load(): Promise<void> {
    loading = true;
    error = null;
    try {
      status = await getSDKClient().platform.status();
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  async function put(): Promise<void> {
    busy = true;
    pErr = null;
    try {
      await getSDKClient().platform.putSecret(pName, { name: pName, secret: toB64(pValue) });
      showToast("success", `Secret "${pName}" stored.`);
      showPut = false;
      pName = ""; pValue = "";
      await load();
    } catch (e) {
      pErr = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  async function reseal(name: string): Promise<void> {
    try {
      await getSDKClient().platform.resealSecret(name);
      showToast("success", `Secret "${name}" resealed.`);
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    }
  }

  async function del(name: string): Promise<void> {
    try {
      await getSDKClient().platform.deleteSecret(name);
      showToast("success", `Secret "${name}" deleted.`);
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

<PageHeader title="Platform Secrets" subtitle="Sealed platform credential store">
  {#snippet actions()}
    <button class="btn btn-primary btn-sm" onclick={() => (showPut = true)}>+ Store</button>
  {/snippet}
</PageHeader>

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if error}
  <Alert kind="error"><span>{error}</span></Alert>
{:else if status}
  <div class="flex flex-wrap gap-2 mb-4">
    <StatusBadge label={status.available ? "available" : "unavailable"} ok={status.available} />
    <StatusBadge label={`${status.total} secrets`} kind="neutral" />
  </div>
  <div class="overflow-x-auto">
    <table class="table table-sm">
      <caption class="sr-only">Platform secrets</caption>
      <thead><tr><th scope="col">Name</th><th scope="col"><span class="sr-only">Actions</span></th></tr></thead>
      <tbody>
        {#each status.names as name (name)}
          <tr>
            <td>{name}</td>
            <td class="text-right">
              <button class="btn btn-ghost btn-xs" onclick={() => reseal(name)}>Reseal</button>
              <button class="btn btn-ghost btn-xs text-error" onclick={() => del(name)}>Delete</button>
            </td>
          </tr>
        {/each}
        {#if status.names.length === 0}
          <tr><td colspan="2" class="text-center text-base-content/60 py-6">No secrets stored.</td></tr>
        {/if}
      </tbody>
    </table>
  </div>
{/if}

{#if showPut}
  <Modal open={showPut} onClose={() => (showPut = false)} labelledby="store-secret-title">
      <h3 id="store-secret-title" class="text-lg font-semibold mb-4">Store platform secret</h3>
      {#if pErr}<Alert kind="error" class="mb-3"><span>{pErr}</span></Alert>{/if}
      <div class="space-y-3">
        <input class="input input-bordered w-full" aria-label="Name" placeholder="Name" bind:value={pName} />
        <textarea class="textarea textarea-bordered w-full" aria-label="Secret value" placeholder="Secret value" bind:value={pValue} rows="3"></textarea>
      </div>
      <div class="modal-action">
        <button class="btn btn-ghost" onclick={() => (showPut = false)} disabled={busy}>Cancel</button>
        <button class="btn btn-primary" onclick={put} disabled={busy || pName === "" || pValue === ""}>Store</button>
      </div>
  </Modal>
{/if}
