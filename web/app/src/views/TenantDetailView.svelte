<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import StatusBadge from "$components/StatusBadge.svelte";
  import Alert from "$components/Alert.svelte";
  import { showToast } from "$stores/toast.svelte.ts";
  import { listTenantIds, loadTenant, deleteTenant, isNotFound } from "$lib/tenantDetail.ts";
  import type { TenantInfoResponse } from "@go-xkms/sdk";

  let ids = $state<string[]>([]);
  let selected = $state("");
  let typed = $state("");
  let tenant = $state<TenantInfoResponse | null>(null);
  let confirm = $state("");
  let error = $state<string | null>(null);
  let busy = $state(false);

  // The free ID input wins over the select when set.
  const target = $derived(typed.trim() !== "" ? typed.trim() : selected);
  const canDelete = $derived(tenant !== null && confirm === tenant.id && !busy);

  function message(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
  }

  async function refresh(): Promise<void> {
    try {
      ids = await listTenantIds();
    } catch (e) {
      error = message(e);
    }
  }

  async function load(): Promise<void> {
    busy = true;
    error = null;
    tenant = null;
    confirm = "";
    try {
      tenant = await loadTenant(target);
    } catch (e) {
      // A tenant-scoped identity gets 404 for any other tenant: never say it exists.
      error = isNotFound(e) ? "Tenant not found" : message(e);
    } finally {
      busy = false;
    }
  }

  async function remove(): Promise<void> {
    if (tenant === null || confirm !== tenant.id) return;
    const id = tenant.id;
    busy = true;
    error = null;
    try {
      await deleteTenant(id);
      showToast("success", `Tenant "${id}" deleted.`);
      tenant = null;
      confirm = "";
      selected = "";
      typed = "";
      await refresh();
    } catch (e) {
      error = message(e);
    } finally {
      busy = false;
    }
  }

  onMount(() => {
    void refresh();
  });
</script>

<PageHeader title="Tenant Detail" subtitle="Inspect one tenant; deleting a tenant cannot be undone" />

{#if error}<Alert kind="error" class="mb-4"><span>{error}</span></Alert>{/if}

<div class="card bg-base-100 shadow-sm mb-4">
  <div class="card-body gap-3">
    <div class="flex flex-wrap items-end gap-2">
      <select class="select select-bordered select-sm" aria-label="Tenant" bind:value={selected}>
        <option value="">Choose a tenant</option>
        {#each ids as id (id)}<option value={id}>{id}</option>{/each}
      </select>
      <input class="input input-bordered input-sm" aria-label="Tenant ID" placeholder="or type a tenant ID" bind:value={typed} />
      <button class="btn btn-primary btn-sm" onclick={load} disabled={busy || target === ""}>
        {#if busy}<span class="loading loading-spinner loading-xs"></span>{/if}Load
      </button>
    </div>
  </div>
</div>

{#if tenant}
  <div class="card bg-base-100 shadow-sm mb-4">
    <div class="card-body">
      <h2 class="card-title text-base">Tenant</h2>
      <dl class="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
        <dt>ID</dt><dd class="font-mono">{tenant.id}</dd>
        <dt>Name</dt><dd>{tenant.name ?? "—"}</dd>
        <dt>Barrier</dt><dd><StatusBadge label={tenant.sealed ? "sealed" : "unsealed"} ok={!tenant.sealed} /></dd>
        <dt>Isolation</dt><dd>{tenant.isolation_type ?? "—"}</dd>
        <dt>Created</dt><dd>{tenant.created_at ?? "—"}</dd>
        <dt>Updated</dt><dd>{tenant.updated_at ?? "—"}</dd>
      </dl>
    </div>
  </div>
{/if}

<div class="card bg-base-100 shadow-sm border border-error">
  <div class="card-body gap-3">
    <h2 class="card-title text-base text-error">Delete tenant</h2>
    <p class="text-sm">Type the loaded tenant's ID to confirm. This cannot be undone.</p>
    <div class="flex flex-wrap items-end gap-2">
      <input class="input input-bordered input-sm" aria-label="Confirm tenant ID" placeholder={tenant?.id ?? "tenant ID"} bind:value={confirm} disabled={tenant === null} />
      <button class="btn btn-error btn-sm" onclick={remove} disabled={!canDelete}>Delete tenant</button>
    </div>
  </div>
</div>
