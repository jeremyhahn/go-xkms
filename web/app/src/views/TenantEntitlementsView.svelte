<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import Alert from "$components/Alert.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import type { TenantEntitlements, TenantInfoResponse } from "@go-xkms/sdk";

  type Flag =
    | "allow_dedicated_raft"
    | "allow_volume_storage"
    | "allow_system_managed_barrier"
    | "allow_dedicated_wal";
  type ListField = "allowed_isolation_modes" | "allowed_barrier_modes";

  const flags: Flag[] = [
    "allow_dedicated_raft",
    "allow_volume_storage",
    "allow_system_managed_barrier",
    "allow_dedicated_wal",
  ];
  const lists: ListField[] = ["allowed_isolation_modes", "allowed_barrier_modes"];

  let tenants = $state<TenantInfoResponse[]>([]);
  let loading = $state(true);
  let error = $state<string | null>(null);
  let busy = $state(false);
  let tenantId = $state("");
  let checked = $state<Record<Flag, boolean>>({
    allow_dedicated_raft: false,
    allow_volume_storage: false,
    allow_system_managed_barrier: false,
    allow_dedicated_wal: false,
  });
  let text = $state<Record<ListField, string>>({ allowed_isolation_modes: "", allowed_barrier_modes: "" });
  // undefined = nothing saved yet; null = the reply carried no entitlements.
  let returned = $state<TenantEntitlements | null | undefined>(undefined);

  function message(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
  }

  function split(s: string): string[] {
    return s.split(",").map((v) => v.trim()).filter((v) => v !== "");
  }

  function tenantLabel(t: TenantInfoResponse): string {
    return t.name ? t.name : t.id;
  }

  async function load(): Promise<void> {
    loading = true;
    error = null;
    try {
      tenants = (await getSDKClient().tenants.list()).tenants;
    } catch (e) {
      error = message(e);
    } finally {
      loading = false;
    }
  }

  async function save(): Promise<void> {
    busy = true;
    error = null;
    returned = undefined;
    const entitlements: TenantEntitlements = {
      allowed_isolation_modes: split(text.allowed_isolation_modes),
      allow_dedicated_raft: checked.allow_dedicated_raft,
      allow_volume_storage: checked.allow_volume_storage,
      allow_system_managed_barrier: checked.allow_system_managed_barrier,
      allowed_barrier_modes: split(text.allowed_barrier_modes),
      allow_dedicated_wal: checked.allow_dedicated_wal,
    };
    try {
      const res = await getSDKClient().tenants.updateEntitlements(tenantId, { tenant_id: tenantId, entitlements });
      returned = res.tenant.entitlements ?? null;
      const t = tenants.find((x) => x.id === tenantId);
      showToast("success", `Entitlements saved for "${t ? tenantLabel(t) : tenantId}".`);
    } catch (e) {
      error = message(e);
    } finally {
      busy = false;
    }
  }

  function showFlag(v: boolean | undefined): string {
    return v === undefined ? "not set" : String(v);
  }

  function showList(v: string[] | undefined): string {
    if (v === undefined) return "not set";
    return v.length === 0 ? "none" : v.join(", ");
  }

  onMount(() => {
    void load();
  });
</script>

<PageHeader title="Tenant Entitlements" subtitle="Isolation and storage features a tenant may use" />

{#if error}
  <Alert kind="error" class="mb-4"><span>{error}</span></Alert>
{/if}

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else}
  <div class="card bg-base-100 shadow-sm mb-4">
    <div class="card-body space-y-3">
      <label class="form-control w-full max-w-md">
        <span class="label-text">Tenant</span>
        <select class="select select-bordered" aria-label="Tenant" bind:value={tenantId}>
          <option value="">Choose a tenant</option>
          {#each tenants as t (t.id)}
            <option value={t.id}>{tenantLabel(t)}</option>
          {/each}
        </select>
      </label>

      <p class="text-sm text-base-content/70">
        Save sends the whole entitlement set: an unchecked box sends false and an empty list sends none.
      </p>

      {#each flags as f (f)}
        <label class="label cursor-pointer justify-start gap-3">
          <input type="checkbox" class="checkbox checkbox-sm" aria-label={f} bind:checked={checked[f]} />
          <span class="label-text font-mono">{f}</span>
        </label>
      {/each}

      {#each lists as l (l)}
        <label class="form-control w-full max-w-md">
          <span class="label-text font-mono">{l}</span>
          <input class="input input-bordered" aria-label={l} placeholder="comma-separated" bind:value={text[l]} />
        </label>
      {/each}

      <div>
        <button class="btn btn-primary" onclick={save} disabled={busy || tenantId === ""}>
          {#if busy}<span class="loading loading-spinner loading-xs"></span>{/if}
          Save
        </button>
      </div>
    </div>
  </div>

  {#if returned !== undefined}
    <section class="card bg-base-100 shadow-sm" aria-label="Returned entitlements">
      <div class="card-body">
        <h2 class="card-title text-base">Returned entitlements</h2>
        {#if returned === null}
          <p class="text-base-content/60">none returned</p>
        {:else}
          <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
            {#each flags as f (f)}
              <dt class="font-mono">{f}</dt>
              <dd data-testid={f}>{showFlag(returned[f])}</dd>
            {/each}
            {#each lists as l (l)}
              <dt class="font-mono">{l}</dt>
              <dd data-testid={l}>{showList(returned[l])}</dd>
            {/each}
          </dl>
        {/if}
      </div>
    </section>
  {/if}
{/if}
