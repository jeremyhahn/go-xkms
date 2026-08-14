<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import Modal from "$components/Modal.svelte";
  import Alert from "$components/Alert.svelte";
  import type { TenantInfoResponse } from "@go-xkms/sdk";

  let tenants = $state<TenantInfoResponse[]>([]);
  let error = $state<string | null>(null);
  let loading = $state(true);
  let busy = $state(false);
  let showCreate = $state(false);

  let cId = $state("");
  let cName = $state("");
  let cIsolation = $state("shared");
  let cErr = $state<string | null>(null);

  async function load(): Promise<void> {
    loading = true;
    error = null;
    try {
      const resp = await getSDKClient().tenants.list();
      tenants = resp.tenants;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  async function create(): Promise<void> {
    busy = true;
    cErr = null;
    try {
      await getSDKClient().tenants.create({ id: cId, name: cName, isolation_type: cIsolation });
      showToast("success", `Tenant "${cId}" created.`);
      showCreate = false;
      cId = ""; cName = "";
      await load();
    } catch (e) {
      cErr = e instanceof Error ? e.message : String(e);
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

<PageHeader title="Tenants" subtitle="Multi-tenant isolation">
  {#snippet actions()}
    <button class="btn btn-primary btn-sm" onclick={() => (showCreate = true)}>+ Create</button>
  {/snippet}
</PageHeader>

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if error}
  <Alert kind="error"><span>{error}</span></Alert>
{:else}
  <div class="overflow-x-auto">
    <table class="table table-sm">
      <caption class="sr-only">Tenants</caption>
      <thead><tr><th scope="col">ID</th><th scope="col">Name</th><th scope="col">Isolation</th><th scope="col">Barrier</th></tr></thead>
      <tbody>
        {#each tenants as t (t.id)}
          <tr>
            <td>{t.id}</td>
            <td>{t.name ?? "—"}</td>
            <td>{t.isolation_type ?? "—"}</td>
            <td>{t.sealed ? "sealed" : "unsealed"}</td>
          </tr>
        {/each}
        {#if tenants.length === 0}
          <tr><td colspan="4" class="text-center text-base-content/60 py-6">No tenants.</td></tr>
        {/if}
      </tbody>
    </table>
  </div>
{/if}

{#if showCreate}
  <Modal open={showCreate} onClose={() => (showCreate = false)} labelledby="create-tenant-title">
      <h3 id="create-tenant-title" class="text-lg font-semibold mb-4">Create tenant</h3>
      {#if cErr}<Alert kind="error" class="mb-3"><span>{cErr}</span></Alert>{/if}
      <div class="space-y-3">
        <input class="input input-bordered w-full" aria-label="Tenant ID" placeholder="Tenant ID" bind:value={cId} />
        <input class="input input-bordered w-full" aria-label="Name" placeholder="Name" bind:value={cName} />
        <select class="select select-bordered w-full" aria-label="Isolation type" bind:value={cIsolation}>
          <option>shared</option><option>dedicated</option>
        </select>
      </div>
      <div class="modal-action">
        <button class="btn btn-ghost" onclick={() => (showCreate = false)} disabled={busy}>Cancel</button>
        <button class="btn btn-primary" onclick={create} disabled={busy || cId === ""}>Create</button>
      </div>
  </Modal>
{/if}
