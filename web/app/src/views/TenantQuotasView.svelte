<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import Alert from "$components/Alert.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import type { TenantInfo, TenantInfoResponse, TenantQuotas } from "@go-xkms/sdk";

  // The PUT replaces the whole quota set, so every field is always sent.
  const fields: Array<keyof TenantQuotas> = [
    "max_databases",
    "max_raft_groups",
    "max_replicas_per_group",
    "max_total_replicas",
    "max_collections",
    "max_keys",
    "max_storage_bytes",
    "max_database_size_bytes",
    "max_users",
    "max_roles",
    "max_certificates",
    "max_backups",
    "max_vector_dims",
    "max_ts_metrics",
    "system_barrier_quota",
    "max_dedicated_wal_groups",
  ];

  let tenants = $state<TenantInfoResponse[]>([]);
  let tenantId = $state("");
  let values = $state<Record<string, string>>({});
  let fieldErrors = $state<Record<string, string>>({});
  let error = $state<string | null>(null);
  let loading = $state(true);
  let busy = $state(false);
  let result = $state<TenantInfo | null>(null);

  async function load(): Promise<void> {
    loading = true;
    error = null;
    try {
      tenants = (await getSDKClient().tenants.list()).tenants;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  // Returns the full quota set, or null after recording an inline error for
  // each field that is not a whole number of 0 or more. Empty means 0.
  function collect(): TenantQuotas | null {
    const quotas = {} as TenantQuotas;
    const errs: Record<string, string> = {};
    for (const f of fields) {
      const raw = (values[f] ?? "").trim();
      const n = raw === "" ? 0 : Number(raw);
      if (!Number.isSafeInteger(n) || n < 0) {
        errs[f] = `${f} must be a whole number of 0 or more.`;
      } else {
        quotas[f] = n;
      }
    }
    fieldErrors = errs;
    return Object.keys(errs).length === 0 ? quotas : null;
  }

  async function save(): Promise<void> {
    const quotas = collect();
    if (quotas === null || tenantId === "") return;
    busy = true;
    error = null;
    try {
      const reply = await getSDKClient().tenants.updateQuotas(tenantId, { tenant_id: tenantId, quotas });
      result = reply.tenant;
      showToast("success", `Quotas for "${reply.tenant.name || tenantId}" saved.`);
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  onMount(() => {
    void load();
  });
</script>

<PageHeader title="Tenant Quotas" subtitle="Resource limits for one tenant" />

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else}
  {#if error}<Alert kind="error" class="mb-4"><span>{error}</span></Alert>{/if}
  <div class="space-y-4">
    <label class="form-control w-full max-w-md">
      <span class="label-text mb-1">Tenant</span>
      <select class="select select-bordered" aria-label="Tenant" bind:value={tenantId}>
        <option value="" disabled>Choose a tenant</option>
        {#each tenants as t (t.id)}
          <option value={t.id}>{t.name ? `${t.name} (${t.id})` : t.id}</option>
        {/each}
      </select>
    </label>
    <p class="text-sm text-base-content/70">
      Save sends the whole quota set and replaces the stored one; an empty field is sent as 0.
    </p>
    <div class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
      {#each fields as f (f)}
        <label class="form-control">
          <span class="label-text text-xs font-mono mb-1">{f}</span>
          <input
            class="input input-bordered input-sm"
            type="number"
            min="0"
            step="1"
            aria-label={f}
            placeholder="0"
            value={values[f] ?? ""}
            oninput={(e) => (values[f] = e.currentTarget.value)}
          />
          {#if fieldErrors[f]}<span class="text-error text-xs mt-1">{fieldErrors[f]}</span>{/if}
        </label>
      {/each}
    </div>
    <button class="btn btn-primary btn-sm" onclick={save} disabled={busy || tenantId === ""}>
      {#if busy}<span class="loading loading-spinner loading-xs"></span>{/if}
      Save
    </button>
  </div>

  {#if result}
    <section class="card bg-base-200 mt-6" aria-label="Stored quotas">
      <div class="card-body">
        <h2 class="card-title text-base">Stored quotas for {result.name || result.id}</h2>
        {#if result.quotas}
          <dl class="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-2 text-sm">
            {#each fields as f (f)}
              <div class="flex justify-between gap-2"><dt class="font-mono">{f}</dt><dd>{result.quotas[f]}</dd></div>
            {/each}
          </dl>
        {:else}
          <p class="text-base-content/60">none returned</p>
        {/if}
      </div>
    </section>
  {/if}
{/if}
