<script lang="ts">
  import PageHeader from "$components/PageHeader.svelte";
  import Alert from "$components/Alert.svelte";
  import Modal from "$components/Modal.svelte";
  import { showToast } from "$stores/toast.svelte.ts";
  import {
    KEY_USAGES,
    getKeyPolicy,
    setKeyPolicy,
    deleteKeyPolicy,
    type KeyPolicy,
    type KeyUsage,
  } from "$lib/keyAccessPolicy.ts";

  let keyId = $state("");
  let backend = $state("");
  let busy = $state(false);
  let error = $state<string | null>(null);
  let formError = $state<string | null>(null);
  // null: nothing loaded or saved yet; "default": the key has no own policy.
  let version = $state<number | "default" | null>(null);

  let ops = $state<Record<KeyUsage, boolean>>(emptyOps());
  // An empty allowed_operations list means "every operation RBAC grants"
  // (pkg/keypolicy), so unrestricted is an explicit choice, never an empty
  // selection. loadedRestricted is the stored policy's state, to warn before
  // a save widens it.
  let restrictOps = $state(false);
  let loadedRestricted = $state(false);
  let confirmWiden = $state<KeyPolicy | null>(null);
  let allowed = $state<string[]>([]);
  let denied = $state<string[]>([]);
  let newAllowed = $state("");
  let newDenied = $state("");
  let expiry = $state("");
  // The stored expires_at and the date it shows as: the date editor holds
  // only a day, so an untouched Expiry saves the exact stored time.
  let keptExpiry: { date: string; at: number } | null = null;
  let maxUsage = $state("");
  let rotationRequired = $state(false);

  const ready = $derived(keyId.trim() !== "" && backend.trim() !== "");

  function emptyOps(): Record<KeyUsage, boolean> {
    return Object.fromEntries(KEY_USAGES.map((u) => [u, false])) as Record<KeyUsage, boolean>;
  }

  function message(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
  }

  function fill(p: KeyPolicy | undefined): void {
    ops = emptyOps();
    for (const u of p?.allowed_operations ?? []) ops[u] = true;
    restrictOps = (p?.allowed_operations ?? []).length > 0;
    loadedRestricted = restrictOps;
    allowed = [...(p?.allowed_principals ?? [])];
    denied = [...(p?.denied_principals ?? [])];
    expiry = p?.expires_at ? new Date(p.expires_at * 1000).toISOString().slice(0, 10) : "";
    keptExpiry = p?.expires_at ? { date: expiry, at: p.expires_at } : null;
    maxUsage = p?.max_usage_count ? String(p.max_usage_count) : "";
    rotationRequired = p?.rotation_required ?? false;
  }

  function add(list: "allowed" | "denied"): void {
    const name = (list === "allowed" ? newAllowed : newDenied).trim();
    if (list === "allowed") {
      if (name !== "" && !allowed.includes(name)) allowed = [...allowed, name];
      newAllowed = "";
    } else {
      if (name !== "" && !denied.includes(name)) denied = [...denied, name];
      newDenied = "";
    }
  }

  // Builds the policy to send, omitting empty fields; returns an error
  // string when the form is invalid.
  function build(): KeyPolicy | string {
    const both = allowed.filter((p) => denied.includes(p));
    if (both.length > 0) return `A principal cannot be both allowed and denied: ${both.join(", ")}`;
    const policy: KeyPolicy = {};
    if (restrictOps) {
      const operations = KEY_USAGES.filter((u) => ops[u]);
      if (operations.length === 0) {
        return "Select at least one operation, or turn off Restrict operations to allow every operation RBAC grants.";
      }
      policy.allowed_operations = operations;
    }
    if (allowed.length > 0) policy.allowed_principals = [...allowed];
    if (denied.length > 0) policy.denied_principals = [...denied];
    if (expiry !== "") {
      const at =
        keptExpiry !== null && keptExpiry.date === expiry
          ? keptExpiry.at
          : Math.floor(Date.parse(`${expiry}T00:00:00Z`) / 1000);
      if (!Number.isFinite(at) || at * 1000 <= Date.now()) return "Expiry must be in the future.";
      policy.expires_at = at;
    }
    const cap = maxUsage.trim();
    if (cap !== "") {
      if (!/^\d+$/.test(cap)) return "Max usage count must be a whole number, 0 or more.";
      const n = Number(cap);
      if (n > 0) policy.max_usage_count = n;
    }
    if (rotationRequired) policy.rotation_required = true;
    return policy;
  }

  // seq names the current target: editing the key or backend inputs, or a
  // new Load, bumps it, and a response for an older target is dropped.
  let seq = 0;

  // Editing the key or backend clears a loaded form, so Save never sends
  // one key's policy to another.
  function retarget(): void {
    seq++;
    if (version !== null) {
      fill(undefined);
      version = null;
      error = null;
      formError = null;
    }
  }

  async function load(): Promise<void> {
    const n = ++seq;
    const id = keyId.trim();
    const be = backend.trim();
    busy = true;
    error = null;
    formError = null;
    try {
      const res = await getKeyPolicy(id, be);
      if (n !== seq) return;
      fill(res.policy);
      version = res.policy ? (res.policy.version ?? 0) : "default";
    } catch (e) {
      if (n === seq) error = message(e);
    } finally {
      busy = false;
    }
  }

  async function save(): Promise<void> {
    error = null;
    const policy = build();
    if (typeof policy === "string") {
      formError = policy;
      return;
    }
    formError = null;
    if (loadedRestricted && !restrictOps) {
      confirmWiden = policy;
      return;
    }
    await put(policy);
  }

  async function put(policy: KeyPolicy): Promise<void> {
    confirmWiden = null;
    busy = true;
    const n = seq;
    const id = keyId.trim();
    const be = backend.trim();
    try {
      const res = await setKeyPolicy(id, be, policy);
      if (n === seq) {
        version = res.policy_version;
        loadedRestricted = policy.allowed_operations !== undefined;
        const at = policy.expires_at;
        keptExpiry = at ? { date: new Date(at * 1000).toISOString().slice(0, 10), at } : null;
      }
      showToast("success", `Access policy for "${id}" saved (version ${res.policy_version}).`);
    } catch (e) {
      error = message(e);
    } finally {
      busy = false;
    }
  }

  // Remove asks through components/Modal.svelte, never window.confirm.
  let confirmRemove = $state<string | null>(null);

  function remove(): void {
    confirmRemove = keyId.trim();
  }

  async function removeConfirmed(): Promise<void> {
    const id = confirmRemove;
    confirmRemove = null;
    if (id === null) return;
    const n = seq;
    busy = true;
    error = null;
    formError = null;
    try {
      await deleteKeyPolicy(id, backend.trim());
      if (n === seq) {
        fill(undefined);
        version = "default";
      }
      showToast("success", `Access policy for "${id}" removed.`);
    } catch (e) {
      error = message(e);
    } finally {
      busy = false;
    }
  }
</script>

<PageHeader title="Key Access Policy" subtitle="Who may use a key, and for what" />

<div class="flex flex-wrap items-end gap-2 mb-4">
  <input class="input input-bordered input-sm" aria-label="Key ID" placeholder="Key ID" bind:value={keyId} oninput={retarget} />
  <input class="input input-bordered input-sm" aria-label="Backend" placeholder="Backend" bind:value={backend} oninput={retarget} />
  <button class="btn btn-sm" onclick={load} disabled={!ready || busy}>Load</button>
  {#if version === "default"}
    <span class="text-sm text-base-content/60">No access policy set (default applies)</span>
  {:else if version !== null}
    <span class="badge badge-neutral">Version {version}</span>
  {/if}
</div>

{#if error}<Alert kind="error" class="mb-3"><span>{error}</span></Alert>{/if}

<div class="space-y-4 max-w-3xl">
  <fieldset>
    <legend class="font-semibold mb-1">Allowed operations</legend>
    <label class="label cursor-pointer gap-2 justify-start">
      <input type="checkbox" class="checkbox checkbox-sm" bind:checked={restrictOps} />
      <span>Restrict operations</span>
    </label>
    {#if !restrictOps}
      <p class="text-sm text-base-content/60">Unrestricted: every operation RBAC grants is allowed.</p>
    {/if}
    <div class="flex flex-wrap gap-x-4">
      {#each KEY_USAGES as u (u)}
        <label class="label cursor-pointer gap-2">
          <input type="checkbox" class="checkbox checkbox-sm" bind:checked={ops[u]} onchange={() => { if (ops[u]) restrictOps = true; }} />
          <span>{u}</span>
        </label>
      {/each}
    </div>
  </fieldset>

  <div class="grid gap-4 md:grid-cols-2">
    <div>
      <h3 class="font-semibold mb-1">Allowed principals</h3>
      <div class="flex gap-2">
        <input class="input input-bordered input-sm flex-1" aria-label="Allowed principal" placeholder="Allowed principal" bind:value={newAllowed} />
        <button class="btn btn-sm" onclick={() => add("allowed")}>Add allowed</button>
      </div>
      <ul class="mt-2">
        {#each allowed as p (p)}
          <li class="flex items-center gap-2">
            <span>{p}</span>
            <button class="btn btn-ghost btn-xs" aria-label={`Remove ${p}`} onclick={() => (allowed = allowed.filter((x) => x !== p))}>✕</button>
          </li>
        {/each}
      </ul>
    </div>
    <div>
      <h3 class="font-semibold mb-1">Denied principals</h3>
      <div class="flex gap-2">
        <input class="input input-bordered input-sm flex-1" aria-label="Denied principal" placeholder="Denied principal" bind:value={newDenied} />
        <button class="btn btn-sm" onclick={() => add("denied")}>Add denied</button>
      </div>
      <ul class="mt-2">
        {#each denied as p (p)}
          <li class="flex items-center gap-2">
            <span>{p}</span>
            <button class="btn btn-ghost btn-xs" aria-label={`Remove ${p}`} onclick={() => (denied = denied.filter((x) => x !== p))}>✕</button>
          </li>
        {/each}
      </ul>
    </div>
  </div>

  <div class="flex flex-wrap items-end gap-4">
    <label class="form-control">
      <span class="label-text">Expiry</span>
      <input type="date" class="input input-bordered input-sm" bind:value={expiry} />
    </label>
    <label class="form-control">
      <span class="label-text">Max usage count</span>
      <input type="text" inputmode="numeric" class="input input-bordered input-sm" placeholder="unlimited" bind:value={maxUsage} />
    </label>
    <label class="label cursor-pointer gap-2">
      <input type="checkbox" class="checkbox checkbox-sm" bind:checked={rotationRequired} />
      <span>Rotation required</span>
    </label>
    <label class="label gap-2">
      <input type="checkbox" class="checkbox checkbox-sm" checked={false} disabled aria-describedby="require-mfa-note" />
      <span>Require MFA</span>
    </label>
  </div>
  <p id="require-mfa-note" class="text-sm text-base-content/60">
    Require MFA is unavailable: the service refuses it because it has no per-operation MFA challenge.
  </p>

  {#if formError}<p class="text-error text-sm" role="alert">{formError}</p>{/if}

  <div class="flex gap-2">
    <button class="btn btn-primary btn-sm" onclick={save} disabled={!ready || busy}>Save</button>
    <button class="btn btn-ghost btn-sm text-error" onclick={remove} disabled={!ready || busy}>Remove policy</button>
  </div>
</div>

{#if confirmWiden}
  <Modal open={confirmWiden !== null} onClose={() => (confirmWiden = null)} labelledby="key-policy-widen-title">
    <h3 id="key-policy-widen-title" class="text-lg font-semibold mb-4">Remove the operation restriction</h3>
    <p>This save removes the operation restriction: the key will allow every operation RBAC grants.</p>
    <div class="modal-action">
      <button class="btn btn-ghost" onclick={() => (confirmWiden = null)} disabled={busy}>Cancel</button>
      <button class="btn btn-warning" onclick={() => confirmWiden && put(confirmWiden)} disabled={busy}>Widen and save</button>
    </div>
  </Modal>
{/if}

{#if confirmRemove !== null}
    <Modal open onClose={() => (confirmRemove = null)} labelledby="key-policy-remove-title">
      <h3 id="key-policy-remove-title" class="text-lg font-semibold mb-4">Remove the access policy</h3>
      <p>Remove the access policy of "{confirmRemove}"? The key falls back to the default policy.</p>
      <div class="modal-action">
        <button class="btn btn-ghost" onclick={() => (confirmRemove = null)}>Cancel</button>
        <button class="btn btn-error" onclick={removeConfirmed}>Remove policy</button>
      </div>
    </Modal>
{/if}
