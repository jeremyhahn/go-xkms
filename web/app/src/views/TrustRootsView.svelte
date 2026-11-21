<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import Alert from "$components/Alert.svelte";
  import Modal from "$components/Modal.svelte";
  import { showToast } from "$stores/toast.svelte.ts";
  import {
    TRUST_ROOT_PURPOSES,
    deleteTrustRoot,
    importTrustRoots,
    listTrustRoots,
    quarantineTrustRoot,
    type TrustRoot,
    type TrustRootImportRequest,
  } from "$lib/trustRoots.ts";

  let roots = $state<TrustRoot[]>([]);
  let error = $state<string | null>(null);
  let loading = $state(true);
  let filter = $state("");

  let pem = $state("");
  let importPurpose = $state("");
  let source = $state("");
  let importing = $state(false);
  let importErr = $state<string | null>(null);
  let importResult = $state<string | null>(null);

  function msg(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
  }

  function short(fp: string): string {
    return fp.length > 16 ? `${fp.slice(0, 16)}…` : fp;
  }

  function day(ts: string): string {
    return ts ? ts.slice(0, 10) : "";
  }

  async function load(): Promise<void> {
    loading = true;
    error = null;
    try {
      roots = await listTrustRoots(filter || undefined);
    } catch (e) {
      error = msg(e);
    } finally {
      loading = false;
    }
  }

  async function doImport(): Promise<void> {
    importing = true;
    importErr = null;
    importResult = null;
    try {
      const req: TrustRootImportRequest = { pem };
      if (importPurpose) req.purpose = importPurpose;
      if (source.trim()) req.source = source.trim();
      const res = await importTrustRoots(req);
      importResult = `Imported: added ${res.added}, skipped ${res.skipped}`;
      pem = "";
      source = "";
      await load();
    } catch (e) {
      importErr = msg(e);
    } finally {
      importing = false;
    }
  }

  // Destructive actions ask through components/Modal.svelte, never
  // window.confirm: `pending` holds the action until the dialog confirms it.
  interface PendingConfirm {
    title: string;
    message: string;
    label: string;
    run: () => Promise<void>;
  }
  let pending = $state<PendingConfirm | null>(null);

  async function confirmPending(): Promise<void> {
    const p = pending;
    pending = null;
    if (p) await p.run();
  }

  function quarantine(r: TrustRoot): void {
    pending = {
      title: "Quarantine trust root",
      message: `Quarantine trust root ${r.subject}? It is reclassified as synced.`,
      label: "Quarantine",
      run: () => quarantineConfirmed(r),
    };
  }

  function remove(r: TrustRoot): void {
    pending = {
      title: "Delete trust root",
      message: `Delete trust root ${r.subject}?`,
      label: "Delete",
      run: () => removeConfirmed(r),
    };
  }

  async function quarantineConfirmed(r: TrustRoot): Promise<void> {
    try {
      await quarantineTrustRoot(r.fingerprint);
      showToast("success", `Trust root ${short(r.fingerprint)} quarantined.`);
      await load();
    } catch (e) {
      showToast("error", msg(e));
    }
  }

  async function removeConfirmed(r: TrustRoot): Promise<void> {
    try {
      await deleteTrustRoot(r.fingerprint);
      showToast("success", `Trust root ${short(r.fingerprint)} deleted.`);
      await load();
    } catch (e) {
      showToast("error", msg(e));
    }
  }

  // Mount-time load; the filter reloads through its change handler.
  onMount(() => {
    void load();
  });
</script>

<PageHeader title="Trust Roots" subtitle="CA roots the server trusts, by purpose" />

<div class="flex items-center gap-2 mb-4">
  <select
    class="select select-bordered select-sm"
    aria-label="Filter by purpose"
    bind:value={filter}
    onchange={() => void load()}
  >
    <option value="">All purposes</option>
    {#each TRUST_ROOT_PURPOSES as p (p)}<option value={p}>{p}</option>{/each}
  </select>
</div>

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if error}
  <Alert kind="error"><span>{error}</span></Alert>
{:else}
  <div class="overflow-x-auto">
    <table class="table table-sm">
      <caption class="sr-only">Trust roots</caption>
      <thead>
        <tr>
          <th scope="col">Subject</th>
          <th scope="col">Purpose</th>
          <th scope="col">Issuer</th>
          <th scope="col">Algorithm</th>
          <th scope="col">Validity</th>
          <th scope="col">Fingerprint</th>
          <th scope="col"><span class="sr-only">Actions</span></th>
        </tr>
      </thead>
      <tbody>
        {#each roots as r (r.fingerprint)}
          <tr>
            <td>{r.subject}</td>
            <td>{r.purpose}</td>
            <td>{r.issuer}</td>
            <td>{r.algorithm}</td>
            <td>{day(r.not_before)} – {day(r.not_after)}</td>
            <td><code title={r.fingerprint}>{short(r.fingerprint)}</code></td>
            <td class="text-right">
              <button class="btn btn-ghost btn-xs" onclick={() => quarantine(r)}>Quarantine</button>
              <button class="btn btn-ghost btn-xs text-error" onclick={() => remove(r)}>Delete</button>
            </td>
          </tr>
        {/each}
        {#if roots.length === 0}
          <tr><td colspan="7" class="text-center text-base-content/60 py-6">No trust roots.</td></tr>
        {/if}
      </tbody>
    </table>
  </div>
{/if}

<div class="card bg-base-100 border border-base-300 mt-6">
  <div class="card-body space-y-3">
    <h2 class="card-title text-base">Import trust roots</h2>
    {#if importErr}<Alert kind="error"><span>{importErr}</span></Alert>{/if}
    {#if importResult}<p class="text-sm">{importResult}</p>{/if}
    <textarea
      class="textarea textarea-bordered w-full font-mono text-xs"
      aria-label="PEM"
      placeholder="-----BEGIN CERTIFICATE-----"
      rows="6"
      bind:value={pem}
    ></textarea>
    <div class="flex flex-wrap gap-2">
      <select class="select select-bordered select-sm" aria-label="Import purpose" bind:value={importPurpose}>
        <option value="">Default purpose</option>
        {#each TRUST_ROOT_PURPOSES as p (p)}<option value={p}>{p}</option>{/each}
      </select>
      <input class="input input-bordered input-sm" aria-label="Source" placeholder="Source (optional)" bind:value={source} />
      <button class="btn btn-primary btn-sm" onclick={doImport} disabled={importing || pem.trim() === ""}>Import</button>
    </div>
  </div>

  {#if pending}
    <Modal open onClose={() => (pending = null)} labelledby="trust-root-confirm-title">
      <h3 id="trust-root-confirm-title" class="text-lg font-semibold mb-4">{pending.title}</h3>
      <p>{pending.message}</p>
      <div class="modal-action">
        <button class="btn btn-ghost" onclick={() => (pending = null)}>Cancel</button>
        <button class="btn btn-error" onclick={confirmPending}>{pending.label}</button>
      </div>
    </Modal>
  {/if}
</div>
