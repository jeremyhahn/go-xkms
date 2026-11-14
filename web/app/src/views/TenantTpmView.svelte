<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import StatusBadge from "$components/StatusBadge.svelte";
  import Modal from "$components/Modal.svelte";
  import Alert from "$components/Alert.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import type { SetTenantTPMModeRequest, TenantInfoResponse, TenantVTPMStatusResponse } from "@go-xkms/sdk";

  const modes = ["none", "shared", "vtpm"] as const;

  let tenants = $state<TenantInfoResponse[]>([]);
  let listError = $state<string | null>(null);
  let tenantId = $state("");
  let mode = $state<string | null>(null);
  let modeError = $state<string | null>(null);
  let newMode = $state("none");
  let ownerAuth = $state("");
  let vtpm = $state<TenantVTPMStatusResponse | null>(null);
  let busy = $state(false);
  let confirmMode = $state(false);
  let confirmStop = $state(false);

  function msg(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
  }

  function toB64(s: string): string {
    return btoa(unescape(encodeURIComponent(s)));
  }

  function label(t: TenantInfoResponse): string {
    return t.name ? `${t.name} (${t.id})` : t.id;
  }

  async function loadTenants(): Promise<void> {
    listError = null;
    try {
      tenants = (await getSDKClient().tenants.list()).tenants ?? [];
    } catch (e) {
      listError = msg(e);
    }
  }

  async function loadVtpm(id: string): Promise<void> {
    try {
      vtpm = await getSDKClient().tenants.vtpmStatus(id);
    } catch (e) {
      showToast("error", msg(e));
    }
  }

  async function selectTenant(id: string): Promise<void> {
    tenantId = id;
    mode = null;
    modeError = null;
    vtpm = null;
    ownerAuth = "";
    if (id === "") return;
    try {
      const r = await getSDKClient().tenants.getTPMMode(id);
      mode = r.mode;
      newMode = r.mode;
      if (r.mode === "vtpm") await loadVtpm(id);
    } catch (e) {
      modeError = msg(e);
    }
  }

  async function applyMode(): Promise<void> {
    confirmMode = false;
    busy = true;
    const req: SetTenantTPMModeRequest = { tenant_id: tenantId, mode: newMode };
    if (ownerAuth !== "") req.owner_auth = toB64(ownerAuth);
    try {
      const r = await getSDKClient().tenants.setTPMMode(tenantId, req);
      mode = r.mode;
      ownerAuth = "";
      showToast("success", `TPM mode set to ${r.mode}.`);
      vtpm = null;
      if (r.mode === "vtpm") await loadVtpm(tenantId);
    } catch (e) {
      showToast("error", msg(e));
    } finally {
      busy = false;
    }
  }

  async function start(): Promise<void> {
    busy = true;
    try {
      vtpm = await getSDKClient().tenants.vtpmStart(tenantId);
      showToast("success", "vTPM started.");
    } catch (e) {
      showToast("error", msg(e));
    } finally {
      busy = false;
    }
  }

  async function stop(): Promise<void> {
    confirmStop = false;
    busy = true;
    try {
      vtpm = await getSDKClient().tenants.vtpmStop(tenantId);
      showToast("success", "vTPM stopped.");
    } catch (e) {
      showToast("error", msg(e));
    } finally {
      busy = false;
    }
  }

  onMount(() => {
    void loadTenants();
  });
</script>

<PageHeader title="Tenant TPM" subtitle="Per-tenant TPM mode and virtual TPM" />

{#if listError}
  <Alert kind="error"><span>{listError}</span></Alert>
{:else}
  <div class="mb-4 max-w-md">
    <label class="label" for="tenant-tpm-tenant">Tenant</label>
    <select
      id="tenant-tpm-tenant"
      class="select select-bordered w-full"
      value={tenantId}
      onchange={(e) => selectTenant((e.currentTarget as HTMLSelectElement).value)}
    >
      <option value="">Select a tenant</option>
      {#each tenants as t (t.id)}
        <option value={t.id}>{label(t)}</option>
      {/each}
    </select>
  </div>

  {#if modeError}
    <Alert kind="error"><span>{modeError}</span></Alert>
  {:else if mode !== null}
    <section class="card bg-base-100 shadow-sm mb-4">
      <div class="card-body space-y-3">
        <h2 class="card-title text-base">TPM mode</h2>
        <p>Current mode: <strong data-testid="current-mode">{mode}</strong></p>
        <div class="flex flex-wrap items-end gap-2">
          <div>
            <label class="label" for="tenant-tpm-mode">New mode</label>
            <select id="tenant-tpm-mode" class="select select-bordered select-sm" bind:value={newMode}>
              {#each modes as m (m)}<option value={m}>{m}</option>{/each}
            </select>
          </div>
          <div>
            <label class="label" for="tenant-tpm-owner">Owner auth (optional)</label>
            <input id="tenant-tpm-owner" type="password" class="input input-bordered input-sm" bind:value={ownerAuth} />
          </div>
          <button class="btn btn-primary btn-sm" onclick={() => (confirmMode = true)} disabled={busy || newMode === mode}>Apply</button>
        </div>
      </div>
    </section>

    {#if mode === "vtpm" && vtpm}
      <section class="card bg-base-100 shadow-sm">
        <div class="card-body space-y-3">
          <h2 class="card-title text-base">Virtual TPM</h2>
          <div><StatusBadge label={vtpm.running ? "running" : "stopped"} ok={vtpm.running} /></div>
          <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
            <dt>PID</dt><dd>{vtpm.pid ?? "-"}</dd>
            <dt>Socket</dt><dd>{vtpm.socket ?? "-"}</dd>
            <dt>Restarts</dt><dd>{vtpm.restarts ?? 0}</dd>
          </dl>
          <div>
            {#if vtpm.running}
              <button class="btn btn-sm text-error" onclick={() => (confirmStop = true)} disabled={busy}>Stop</button>
            {:else}
              <button class="btn btn-primary btn-sm" onclick={start} disabled={busy}>Start</button>
            {/if}
          </div>
        </div>
      </section>
    {/if}
  {/if}
{/if}

{#if confirmMode}
  <Modal open={confirmMode} onClose={() => (confirmMode = false)} labelledby="tenant-tpm-mode-title">
    <h3 id="tenant-tpm-mode-title" class="text-lg font-semibold mb-4">Change TPM mode to {newMode}?</h3>
    <p>The change is refused while the tenant holds TPM keys or policies.</p>
    <div class="modal-action">
      <button class="btn btn-ghost" onclick={() => (confirmMode = false)}>Cancel</button>
      <button class="btn btn-primary" onclick={applyMode}>Change mode</button>
    </div>
  </Modal>
{/if}

{#if confirmStop}
  <Modal open={confirmStop} onClose={() => (confirmStop = false)} labelledby="tenant-tpm-stop-title">
    <h3 id="tenant-tpm-stop-title" class="text-lg font-semibold mb-4">Stop the virtual TPM?</h3>
    <p>TPM operations for this tenant fail until it is started again.</p>
    <div class="modal-action">
      <button class="btn btn-ghost" onclick={() => (confirmStop = false)}>Cancel</button>
      <button class="btn btn-primary" onclick={stop}>Stop vTPM</button>
    </div>
  </Modal>
{/if}
