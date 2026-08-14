<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import Modal from "$components/Modal.svelte";
  import Alert from "$components/Alert.svelte";
  import type { AuditEvent } from "@go-xkms/sdk";

  let events = $state<AuditEvent[]>([]);
  let error = $state<string | null>(null);
  let loading = $state(true);
  let busy = $state(false);
  let total = $state(0);

  // Paging is by opaque cursor, not offset: an append-only chain shifts under
  // an offset between pages. `next` is the server's continuation token and an
  // empty value means the last page.
  let next = $state<string>("");
  let cursors = $state<string[]>([]);

  let fActor = $state("");
  let fResource = $state("");
  let fAction = $state("");
  let fOutcome = $state("");
  let fFrom = $state("");
  let fTo = $state("");
  let limit = $state(100);

  let selected = $state<AuditEvent | null>(null);

  // toRFC3339 converts a datetime-local value ("2026-01-01T00:00") into the
  // RFC3339 the endpoint requires. An empty box means an unbounded side.
  function toRFC3339(local: string): string | undefined {
    if (local === "") {
      return undefined;
    }
    const d = new Date(local);
    return isNaN(d.getTime()) ? undefined : d.toISOString();
  }

  async function load(cursor = ""): Promise<void> {
    loading = true;
    error = null;
    try {
      const page = await getSDKClient().audit.query({
        actor: fActor === "" ? undefined : fActor,
        resource: fResource === "" ? undefined : fResource,
        action: fAction === "" ? undefined : fAction,
        outcome: fOutcome === "" ? undefined : fOutcome,
        from: toRFC3339(fFrom),
        to: toRFC3339(fTo),
        limit,
        cursor: cursor === "" ? undefined : cursor,
      });
      events = page.events ?? [];
      next = page.next ?? "";
      total = page.total ?? 0;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  async function applyFilters(): Promise<void> {
    busy = true;
    cursors = [];
    await load("");
    busy = false;
  }

  async function nextPage(): Promise<void> {
    if (next === "") {
      return;
    }
    cursors = [...cursors, next];
    await load(next);
  }

  async function prevPage(): Promise<void> {
    if (cursors.length === 0) {
      return;
    }
    const trimmed = cursors.slice(0, -1);
    cursors = trimmed;
    await load(trimmed.length === 0 ? "" : (trimmed[trimmed.length - 1] ?? ""));
  }

  async function clearFilters(): Promise<void> {
    fActor = "";
    fResource = "";
    fAction = "";
    fOutcome = "";
    fFrom = "";
    fTo = "";
    await applyFilters();
  }

  function copyEvent(ev: AuditEvent): void {
    void navigator.clipboard.writeText(JSON.stringify(ev, null, 2));
    showToast("success", "Event copied to clipboard.");
  }

  function outcomeClass(outcome: string): string {
    const normalized = outcome.toLowerCase();
    if (normalized === "allow" || normalized === "success") {
      return "badge-success";
    }
    if (normalized === "deny" || normalized === "failure" || normalized === "error") {
      return "badge-error";
    }
    return "badge-ghost";
  }

  function fmt(ts: string): string {
    return ts === "" ? "—" : new Date(ts).toLocaleString();
  }

  onMount(() => {
    void load("");
  });
</script>

<PageHeader title="Audit" subtitle="Tamper-evident record of every privileged operation">
  {#snippet actions()}
    <button class="btn btn-ghost btn-sm" onclick={clearFilters} disabled={busy}>Clear</button>
  {/snippet}
</PageHeader>

<div class="card bg-base-200 mb-4">
  <div class="card-body py-4">
    <div class="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
      <label class="form-control">
        <span class="label-text">Actor</span>
        <input class="input input-bordered input-sm w-full" bind:value={fActor} />
      </label>
      <label class="form-control">
        <span class="label-text">Resource</span>
        <input class="input input-bordered input-sm w-full" bind:value={fResource} />
      </label>
      <label class="form-control">
        <span class="label-text">Action</span>
        <input class="input input-bordered input-sm w-full" bind:value={fAction} />
      </label>
      <label class="form-control">
        <span class="label-text">Outcome</span>
        <select class="select select-bordered select-sm w-full" bind:value={fOutcome}>
          <option value="">any</option>
          <option value="allow">allow</option>
          <option value="deny">deny</option>
        </select>
      </label>
      <label class="form-control">
        <span class="label-text">From</span>
        <input type="datetime-local" class="input input-bordered input-sm w-full" bind:value={fFrom} />
      </label>
      <label class="form-control">
        <span class="label-text">To</span>
        <input type="datetime-local" class="input input-bordered input-sm w-full" bind:value={fTo} />
      </label>
      <label class="form-control">
        <span class="label-text">Page size</span>
        <input type="number" min="1" max="1000" class="input input-bordered input-sm w-full" bind:value={limit} />
      </label>
      <div class="flex items-end">
        <button class="btn btn-primary btn-sm w-full" onclick={applyFilters} disabled={busy}>Apply</button>
      </div>
    </div>
  </div>
</div>

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if error}
  <Alert kind="error"><span>{error}</span></Alert>
{:else}
  <div class="overflow-x-auto">
    <table class="table table-sm">
      <caption class="sr-only">Audit events</caption>
      <thead>
        <tr>
          <th scope="col">Timestamp</th><th scope="col">Actor</th><th scope="col">Resource</th>
          <th scope="col">Action</th><th scope="col">Outcome</th><th scope="col"><span class="sr-only">Actions</span></th>
        </tr>
      </thead>
      <tbody>
        {#each events as ev (ev.request_id ? ev.request_id + ev.timestamp : ev.timestamp + ev.actor + ev.action)}
          <tr>
            <td class="text-xs whitespace-nowrap">{fmt(ev.timestamp)}</td>
            <td>{ev.actor}</td>
            <td>{ev.resource}</td>
            <td>{ev.action}</td>
            <td><span class="badge badge-sm {outcomeClass(ev.outcome)}">{ev.outcome}</span></td>
            <td class="text-right">
              <button class="btn btn-ghost btn-xs" onclick={() => (selected = ev)}>Details</button>
            </td>
          </tr>
        {/each}
        {#if events.length === 0}
          <tr><td colspan="6" class="text-center text-base-content/60 py-6">No audit events match these filters.</td></tr>
        {/if}
      </tbody>
    </table>
  </div>

  <div class="flex items-center justify-between mt-4">
    <span class="text-sm text-base-content/60">
      {events.length} shown{total > 0 ? ` of ${total}` : ""}
    </span>
    <div class="join">
      <button class="btn btn-sm join-item" onclick={prevPage} disabled={cursors.length === 0}>Previous</button>
      <button class="btn btn-sm join-item" onclick={nextPage} disabled={next === ""}>Next</button>
    </div>
  </div>
{/if}

{#if selected}
  <Modal
    open={selected !== null}
    onClose={() => (selected = null)}
    boxClass="modal-box max-w-2xl"
    labelledby="audit-event-title"
  >
      <h3 id="audit-event-title" class="text-lg font-semibold mb-4">Audit event</h3>
      <dl class="grid grid-cols-3 gap-2 text-sm">
        <dt class="font-medium">Timestamp</dt><dd class="col-span-2">{fmt(selected.timestamp)}</dd>
        <dt class="font-medium">Actor</dt><dd class="col-span-2">{selected.actor}</dd>
        <dt class="font-medium">Role</dt><dd class="col-span-2">{selected.role ?? "—"}</dd>
        <dt class="font-medium">Tenant</dt><dd class="col-span-2">{selected.tenant_id ?? "—"}</dd>
        <dt class="font-medium">Resource</dt><dd class="col-span-2">{selected.resource}</dd>
        <dt class="font-medium">Action</dt><dd class="col-span-2">{selected.action}</dd>
        <dt class="font-medium">Outcome</dt><dd class="col-span-2">{selected.outcome}</dd>
        <dt class="font-medium">Client IP</dt><dd class="col-span-2">{selected.client_ip ?? "—"}</dd>
        <dt class="font-medium">Request ID</dt><dd class="col-span-2 font-mono text-xs">{selected.request_id ?? "—"}</dd>
        <!-- prev_hash is the chain link that makes the log verifiable; it is
             shown so an operator can follow the chain, not decoration. -->
        <dt class="font-medium">Prev hash</dt>
        <dd class="col-span-2 font-mono text-xs break-all">{selected.prev_hash ?? "—"}</dd>
      </dl>

      {#if selected.attributes && Object.keys(selected.attributes).length > 0}
        <h4 class="font-medium mt-4 mb-2">Attributes</h4>
        <pre class="bg-base-200 rounded p-3 text-xs overflow-x-auto">{JSON.stringify(selected.attributes, null, 2)}</pre>
      {/if}

      <div class="modal-action">
        <button class="btn btn-ghost btn-sm" onclick={() => selected && copyEvent(selected)}>Copy JSON</button>
        <button class="btn btn-sm" onclick={() => (selected = null)}>Close</button>
      </div>
  </Modal>
{/if}
