<script lang="ts">
  import PageHeader from "$components/PageHeader.svelte";
  import Alert from "$components/Alert.svelte";
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
  let allowed = $state<string[]>([]);
  let denied = $state<string[]>([]);
  let newAllowed = $state("");
  let newDenied = $state("");
  let expiry = $state("");
  let maxUsage = $state("");
  let rotationRequired = $state(false);
  let requireMfa = $state(false);

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
    allowed = [...(p?.allowed_principals ?? [])];
    denied = [...(p?.denied_principals ?? [])];
    expiry = p?.expires_at ? new Date(p.expires_at * 1000).toISOString().slice(0, 10) : "";
    maxUsage = p?.max_usage_count ? String(p.max_usage_count) : "";
    rotationRequired = p?.rotation_required ?? false;
    requireMfa = p?.require_mfa ?? false;
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
    const operations = KEY_USAGES.filter((u) => ops[u]);
    if (operations.length > 0) policy.allowed_operations = operations;
    if (allowed.length > 0) policy.allowed_principals = [...allowed];
    if (denied.length > 0) policy.denied_principals = [...denied];
    if (expiry !== "") {
      const at = Math.floor(Date.parse(`${expiry}T00:00:00Z`) / 1000);
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
    if (requireMfa) policy.require_mfa = true;
    return policy;
  }

  async function load(): Promise<void> {
    busy = true;
    error = null;
    formError = null;
    try {
      const res = await getKeyPolicy(keyId.trim(), backend.trim());
      fill(res.policy);
      version = res.policy ? (res.policy.version ?? 0) : "default";
    } catch (e) {
      error = message(e);
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
    busy = true;
    try {
      const id = keyId.trim();
      const res = await setKeyPolicy(id, backend.trim(), policy);
      version = res.policy_version;
      showToast("success", `Access policy for "${id}" saved (version ${res.policy_version}).`);
    } catch (e) {
      error = message(e);
    } finally {
      busy = false;
    }
  }

  async function remove(): Promise<void> {
    const id = keyId.trim();
    if (!window.confirm(`Remove the access policy of "${id}"? The key falls back to the default policy.`)) return;
    busy = true;
    error = null;
    formError = null;
    try {
      await deleteKeyPolicy(id, backend.trim());
      fill(undefined);
      version = "default";
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
  <input class="input input-bordered input-sm" aria-label="Key ID" placeholder="Key ID" bind:value={keyId} />
  <input class="input input-bordered input-sm" aria-label="Backend" placeholder="Backend" bind:value={backend} />
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
    <div class="flex flex-wrap gap-x-4">
      {#each KEY_USAGES as u (u)}
        <label class="label cursor-pointer gap-2">
          <input type="checkbox" class="checkbox checkbox-sm" bind:checked={ops[u]} />
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
    <label class="label cursor-pointer gap-2">
      <input type="checkbox" class="checkbox checkbox-sm" bind:checked={requireMfa} />
      <span>Require MFA</span>
    </label>
  </div>

  {#if formError}<p class="text-error text-sm" role="alert">{formError}</p>{/if}

  <div class="flex gap-2">
    <button class="btn btn-primary btn-sm" onclick={save} disabled={!ready || busy}>Save</button>
    <button class="btn btn-ghost btn-sm text-error" onclick={remove} disabled={!ready || busy}>Remove policy</button>
  </div>
</div>
