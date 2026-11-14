<script lang="ts">
  import PageHeader from "$components/PageHeader.svelte";
  import StatusBadge from "$components/StatusBadge.svelte";
  import Alert from "$components/Alert.svelte";
  import { showToast } from "$stores/toast.svelte.ts";
  import {
    diffMetadata,
    getKeyMetadata,
    updateKeyMetadata,
    type EditableMetadata,
    type KeyMetadata,
  } from "$lib/keyMetadata.ts";

  interface TagRow {
    key: string;
    value: string;
  }

  let keyId = $state("");
  let backend = $state("");
  let md = $state<KeyMetadata | null>(null);
  // The key and backend the shown metadata belongs to; Save targets these,
  // not whatever the inputs hold now.
  let loadedId = $state("");
  let loadedBackend = $state("");
  let error = $state<string | null>(null);
  let loading = $state(false);
  let busy = $state(false);

  let name = $state("");
  let description = $state("");
  let rows = $state<TagRow[]>([]);

  function edits(): EditableMetadata {
    const tags: Record<string, string> = {};
    for (const r of rows) {
      if (r.key !== "") tags[r.key] = r.value;
    }
    return { name, description, tags };
  }

  const tagError = $derived.by(() => {
    const seen = new Set<string>();
    for (const r of rows) {
      if (r.key === "" && r.value === "") continue;
      if (r.key === "") return "Tag keys must not be empty.";
      if (seen.has(r.key)) return `Duplicate tag key: ${r.key}`;
      seen.add(r.key);
    }
    return null;
  });

  const changes = $derived.by(() => {
    if (!md) return {};
    const before: EditableMetadata = { name: md.name ?? "", description: md.description ?? "", tags: md.tags ?? {} };
    return diffMetadata(before, edits());
  });
  const changed = $derived(Object.keys(changes).length > 0);

  function show(m: KeyMetadata): void {
    md = m;
    name = m.name ?? "";
    description = m.description ?? "";
    rows = Object.entries(m.tags ?? {}).map(([key, value]) => ({ key, value }));
  }

  function fmt(s?: number): string {
    return s ? new Date(s * 1000).toISOString() : "—";
  }

  function rotation(m: KeyMetadata): string {
    const rp = m.rotation_policy;
    if (!rp) return "None";
    let s = `${rp.enabled ? "enabled" : "disabled"}, every ${rp.interval_seconds} s`;
    if (rp.retain_versions) s += `, keeps ${rp.retain_versions} versions`;
    if (rp.next_rotation) s += `, next ${fmt(rp.next_rotation)}`;
    return s;
  }

  async function load(): Promise<void> {
    loading = true;
    error = null;
    try {
      const m = await getKeyMetadata(keyId, backend);
      loadedId = keyId;
      loadedBackend = backend;
      show(m);
    } catch (e) {
      md = null;
      error = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  async function save(): Promise<void> {
    if (tagError || !changed) return;
    busy = true;
    error = null;
    try {
      show(await updateKeyMetadata(loadedId, loadedBackend, changes));
      showToast("success", `Metadata of key "${loadedId}" saved.`);
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }
</script>

<PageHeader title="Key Metadata" subtitle="Status, flags and labels of a key; edit its name, description and tags" />

<div class="flex flex-wrap gap-2 mb-4">
  <input class="input input-bordered input-sm" aria-label="Key ID" placeholder="Key ID" bind:value={keyId} />
  <input class="input input-bordered input-sm" aria-label="Backend" placeholder="Backend" bind:value={backend} />
  <button class="btn btn-primary btn-sm" onclick={load} disabled={loading || keyId === "" || backend === ""}>Load</button>
</div>

{#if error}
  <Alert kind="error" class="mb-4"><span>{error}</span></Alert>
{/if}

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if md}
  <div class="card bg-base-100 border border-base-300 mb-4">
    <div class="card-body p-4">
      <div class="flex items-center gap-2 mb-2">
        <span class="font-mono">{md.key_id}</span>
        <StatusBadge label={md.status} ok={md.status === "enabled"} />
      </div>
      <dl class="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
        <dt>Algorithm</dt><dd>{md.algorithm || "—"}</dd>
        <dt>Usage</dt><dd>{md.usage?.length ? md.usage.join(", ") : "—"}</dd>
        <dt>Version</dt><dd>{md.version}</dd>
        <dt>Exportable</dt><dd>{md.exportable ? "yes" : "no"}</dd>
        <dt>Deletion protection</dt><dd>{md.deletion_protection ? "yes" : "no"}</dd>
        <dt>Created</dt><dd>{fmt(md.created_at)}</dd>
        <dt>Updated</dt><dd>{fmt(md.updated_at)}</dd>
        <dt>Last used</dt><dd>{fmt(md.last_used_at)}</dd>
        <dt>Owner</dt><dd>{md.owner || "—"}</dd>
        <dt>Rotation policy</dt><dd>{rotation(md)}</dd>
      </dl>
    </div>
  </div>

  <div class="space-y-3">
    <label class="form-control">
      <span class="label-text">Name</span>
      <input class="input input-bordered input-sm" bind:value={name} />
    </label>
    <label class="form-control">
      <span class="label-text">Description</span>
      <textarea class="textarea textarea-bordered" rows="2" bind:value={description}></textarea>
    </label>
    <p class="text-xs text-base-content/60">An empty name or description leaves it unchanged.</p>

    <div class="overflow-x-auto">
      <table class="table table-sm">
        <caption class="sr-only">Tags</caption>
        <thead><tr><th scope="col">Tag</th><th scope="col">Value</th><th scope="col"><span class="sr-only">Actions</span></th></tr></thead>
        <tbody>
          {#each rows as row, i (i)}
            <tr>
              <td><input class="input input-bordered input-xs w-full" aria-label={`Tag key ${i + 1}`} bind:value={row.key} /></td>
              <td><input class="input input-bordered input-xs w-full" aria-label={`Tag value ${i + 1}`} bind:value={row.value} /></td>
              <td class="text-right">
                <button class="btn btn-ghost btn-xs text-error" aria-label={`Delete tag ${row.key || i + 1}`} onclick={() => rows.splice(i, 1)}>Delete</button>
              </td>
            </tr>
          {/each}
          {#if rows.length === 0}
            <tr><td colspan="3" class="text-center text-base-content/60 py-4">No tags</td></tr>
          {/if}
        </tbody>
      </table>
    </div>
    {#if tagError}<p class="text-error text-sm">{tagError}</p>{/if}

    <div class="flex gap-2">
      <button class="btn btn-ghost btn-sm" onclick={() => rows.push({ key: "", value: "" })}>+ Add tag</button>
      <button class="btn btn-primary btn-sm" onclick={save} disabled={busy || !changed || tagError !== null}>
        {#if busy}<span class="loading loading-spinner loading-xs"></span>{/if}Save
      </button>
    </div>
  </div>
{/if}
