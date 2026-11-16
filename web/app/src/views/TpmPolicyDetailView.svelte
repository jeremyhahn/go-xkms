<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import Alert from "$components/Alert.svelte";
  import StatusBadge from "$components/StatusBadge.svelte";
  import {
    listScopes,
    listPolicyNames,
    loadPolicy,
    policyObjects,
    verifyPolicy,
    pcrRows,
  } from "$lib/tpmPolicyDetail.ts";
  import type { TPMPolicy, TPMPolicyReference, TPMPolicyVerifyResponse } from "@go-xkms/sdk";

  let scopes = $state<string[]>([]);
  let scope = $state("");
  let names = $state<string[]>([]);
  let name = $state("");
  let policy = $state<TPMPolicy | null>(null);
  let objects = $state<string[] | null>(null);
  let verdict = $state<TPMPolicyVerifyResponse | null>(null);
  let error = $state<string | null>(null);
  let loadBusy = $state(false);
  let objectsBusy = $state(false);
  let verifyBusy = $state(false);

  // An empty scope is the caller's own scope: the SDK then omits tenant_id.
  function tenantId(): string | undefined {
    return scope === "" ? undefined : scope;
  }

  function message(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
  }

  // Every scope or policy pick starts a new generation; a reply is applied
  // only while the generation and the scope/policy it was asked for still
  // match, so a slow reply for an earlier pick never shows under a new one.
  let gen = 0;

  function begin(): void {
    gen++;
    policy = null;
    objects = null;
    verdict = null;
    error = null;
    loadBusy = false;
    objectsBusy = false;
    verifyBusy = false;
  }

  async function request<T>(fetch: () => Promise<T>, apply: (v: T) => void, setBusy?: (b: boolean) => void): Promise<void> {
    const mine = gen;
    const at = `${scope}\u0000${name}`;
    const current = () => mine === gen && at === `${scope}\u0000${name}`;
    setBusy?.(true);
    error = null;
    try {
      const v = await fetch();
      if (current()) apply(v);
    } catch (e) {
      if (current()) error = message(e);
    } finally {
      if (mine === gen) setBusy?.(false);
    }
  }

  function refreshNames(): Promise<void> {
    name = "";
    names = [];
    begin();
    return request(() => listPolicyNames(tenantId()), (v) => (names = v));
  }

  function pickScope(value: string): void {
    scope = value;
    void refreshNames();
  }

  function pickPolicy(value: string): void {
    name = value;
    begin();
  }

  function load(): Promise<void> {
    const n = name;
    return request(() => loadPolicy(n, tenantId()), (v) => (policy = v), (b) => (loadBusy = b));
  }

  function listObjects(): Promise<void> {
    const n = name;
    return request(() => policyObjects(n, tenantId()), (v) => (objects = v), (b) => (objectsBusy = b));
  }

  function verify(): Promise<void> {
    const n = name;
    return request(() => verifyPolicy(n, tenantId()), (v) => (verdict = v), (b) => (verifyBusy = b));
  }

  onMount(() => {
    void listScopes().then((ids) => (scopes = ids));
    void refreshNames();
  });
</script>

<!-- The signed reference values (CoRIM) a branch was updated from, or a note
     that its values were captured from the live PCRs. -->
{#snippet referenceOf(ref: TPMPolicyReference | undefined)}
  {#if ref}
    <dl class="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm mb-2">
      <dt>Reference</dt><dd class="font-mono break-all">{ref.id || "-"}</dd>
      <dt>Profile</dt><dd class="font-mono break-all">{ref.profile || "-"}</dd>
      <dt>Signer</dt><dd>{ref.signer || "-"}</dd>
      <dt>Digest</dt><dd><code class="break-all">{ref.digest}</code></dd>
    </dl>
  {:else}
    <div class="text-sm text-base-content/60 mb-2">captured live</div>
  {/if}
{/snippet}

<PageHeader
  title="TPM Policy Detail"
  subtitle="Read-only: a policy's captured PCR values, its bound objects and a live PCR check"
/>

{#if error}
  <Alert kind="error" class="mb-4"><span>{error}</span></Alert>
{/if}

<div class="card bg-base-100 shadow-sm mb-4">
  <div class="card-body gap-3">
    <div class="flex flex-wrap items-end gap-3">
      <label class="form-control">
        <span class="label-text">Scope</span>
        <select
          class="select select-bordered select-sm"
          value={scope}
          onchange={(e) => pickScope(e.currentTarget.value)}
        >
          <option value="">Own scope</option>
          {#each scopes as id (id)}
            <option value={id}>{id}</option>
          {/each}
        </select>
      </label>
      <label class="form-control">
        <span class="label-text">Policy</span>
        <select
          class="select select-bordered select-sm"
          value={name}
          onchange={(e) => pickPolicy(e.currentTarget.value)}
        >
          <option value="" disabled>Choose a policy</option>
          {#each names as n (n)}
            <option value={n}>{n}</option>
          {/each}
        </select>
      </label>
      <button class="btn btn-primary btn-sm" onclick={load} disabled={name === "" || loadBusy}>
        {#if loadBusy}<span class="loading loading-spinner loading-xs" aria-hidden="true"></span>{/if}Load
      </button>
      <button class="btn btn-sm" onclick={listObjects} disabled={name === "" || objectsBusy}>
        {#if objectsBusy}<span class="loading loading-spinner loading-xs" aria-hidden="true"></span>{/if}Objects
      </button>
      <button class="btn btn-sm" onclick={verify} disabled={name === "" || verifyBusy}>
        {#if verifyBusy}<span class="loading loading-spinner loading-xs" aria-hidden="true"></span>{/if}Verify
      </button>
    </div>
  </div>
</div>

{#if policy}
  <div class="card bg-base-100 shadow-sm mb-4">
    <div class="card-body gap-3">
      <h2 class="card-title">{policy.name}</h2>
      <dl class="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
        <dt>Scope</dt><dd>{policy.tenant_id || "own scope"}</dd>
        <dt>Index</dt><dd data-testid="policy-index">{policy.index}</dd>
        <dt>Epoch</dt><dd>{policy.epoch ?? "-"}</dd>
        <dt>Status</dt>
        <dd>
          <StatusBadge label={policy.approved ? "approved" : "not approved"} ok={policy.approved} />
        </dd>
        <dt>Auto-unseal</dt><dd>{policy.auto_unseal ? "on" : "off"}</dd>
        <dt>Created</dt><dd>{policy.created_at}</dd>
        <dt>Updated</dt><dd>{policy.updated_at ?? "-"}</dd>
      </dl>
      {#each policy.branches as branch, i (i)}
        {@const bname = branch.name || `branch-${i + 1}`}
        <section class="border border-base-300 rounded p-3" data-testid={`policy-branch-${bname}`}>
          <div class="flex flex-wrap items-center gap-2 mb-2">
            <h3 class="font-semibold">{bname}</h3>
            <StatusBadge label={branch.approved ? "approved" : "not approved"} ok={branch.approved === true} />
          </div>
          {@render referenceOf(branch.reference)}
          {#each branch.conditions as c, j (j)}
            <div class="mb-2">
              {#if c.type === "pcr"}
                <div class="text-sm">Bank: <span class="font-mono">{c.bank}</span></div>
                <table class="table table-xs w-auto">
                  <caption class="sr-only">Captured PCR values</caption>
                  <thead><tr><th scope="col">PCR</th><th scope="col">Value</th></tr></thead>
                  <tbody>
                    {#each pcrRows(c) as r (r.pcr)}
                      <tr data-testid="pcr-row"><td>{`PCR ${r.pcr} `}</td><td class="font-mono break-all">{r.value}</td></tr>
                    {/each}
                  </tbody>
                </table>
                {#if c.pcr_digest}
                  <div class="text-sm">Digest: <code class="break-all">{c.pcr_digest}</code></div>
                {/if}
              {:else if c.type === "locality"}
                <div class="text-sm">Localities: {(c.localities ?? []).join(", ")}</div>
              {:else}
                <div class="text-sm">auth value</div>
              {/if}
            </div>
          {/each}
        </section>
      {/each}
    </div>
  </div>
{/if}

{#if objects}
  <div class="card bg-base-100 shadow-sm mb-4">
    <div class="card-body gap-2">
      <h2 class="card-title">Bound objects</h2>
      {#if objects.length === 0}
        <p class="text-base-content/60">No objects bound</p>
      {:else}
        <ul class="font-mono text-sm">
          {#each objects as id (id)}
            <li>{id}</li>
          {/each}
        </ul>
      {/if}
    </div>
  </div>
{/if}

{#if verdict}
  <div class="card bg-base-100 shadow-sm mb-4">
    <div class="card-body gap-2">
      <h2 class="card-title">Live PCR check</h2>
      <div class="flex flex-wrap gap-2">
        <StatusBadge label={verdict.match ? "match" : "mismatch"} ok={verdict.match} />
        <StatusBadge label={verdict.approved ? "approved" : "not approved"} ok={verdict.approved} />
      </div>
      {#each verdict.branches as b, i (i)}
        {@const bname = b.name || `branch-${i + 1}`}
        <div class="text-sm" data-testid={`verify-branch-${bname}`}>
          <div class="flex flex-wrap items-center gap-2">
            <span class="font-semibold">{bname}</span>
            <StatusBadge label={b.match ? "match" : "mismatch"} ok={b.match} />
            <StatusBadge label={b.approved ? "approved" : "not approved"} ok={b.approved} />
            {#each b.mismatched ?? [] as p (p)}
              <span class="badge badge-outline">PCR {p}</span>
            {/each}
          </div>
          {@render referenceOf(b.reference)}
        </div>
      {/each}
    </div>
  </div>
{/if}
