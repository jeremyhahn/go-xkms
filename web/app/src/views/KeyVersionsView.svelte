<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import StatusBadge from "$components/StatusBadge.svelte";
  import Modal from "$components/Modal.svelte";
  import Alert from "$components/Alert.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import type { KeyInfo, ListKeyVersionsResponse, RotateScopeKeysResponse } from "@go-xkms/sdk";

  let keys = $state<KeyInfo[]>([]);
  let keysError = $state<string | null>(null);
  let selected = $state("");
  let data = $state<ListKeyVersionsResponse | null>(null);
  let error = $state<string | null>(null);
  let loading = $state(false);
  let busy = $state(false);

  let retireVersion = $state<number | null>(null);
  let showRotate = $state(false);
  let rotation = $state<RotateScopeKeysResponse | null>(null);

  const key = $derived(selected === "" ? null : (keys[Number(selected)] ?? null));

  function msg(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
  }

  async function loadKeys(): Promise<void> {
    try {
      keys = (await getSDKClient().keys.list()).keys;
    } catch (e) {
      keysError = msg(e);
    }
  }

  async function load(): Promise<void> {
    if (!key) {
      data = null;
      return;
    }
    loading = true;
    error = null;
    try {
      data = await getSDKClient().keys.versions.list(key.key_id, key.backend);
    } catch (e) {
      error = msg(e);
      data = null;
    } finally {
      loading = false;
    }
  }

  async function run(action: () => Promise<string>): Promise<void> {
    busy = true;
    try {
      showToast("success", await action());
      await load();
    } catch (e) {
      showToast("error", msg(e));
    } finally {
      busy = false;
    }
  }

  function setState(version: number, enable: boolean): Promise<void> {
    return run(async () => {
      const k = key!;
      const v = getSDKClient().keys.versions;
      await (enable ? v.enable(k.key_id, version, k.backend) : v.disable(k.key_id, version, k.backend));
      return `Version ${version} ${enable ? "enabled" : "disabled"}.`;
    });
  }

  function setAll(enable: boolean): Promise<void> {
    return run(async () => {
      const k = key!;
      const v = getSDKClient().keys.versions;
      const res = await (enable ? v.enableAll(k.key_id, k.backend) : v.disableAll(k.key_id, k.backend));
      return `${res.count} versions ${enable ? "enabled" : "disabled"}.`;
    });
  }

  async function retire(): Promise<void> {
    const version = retireVersion!;
    retireVersion = null;
    await run(async () => {
      const k = key!;
      await getSDKClient().keys.versions.retire(k.key_id, version, k.backend);
      return `Version ${version} retired.`;
    });
  }

  async function rotate(): Promise<void> {
    busy = true;
    try {
      rotation = await getSDKClient().keys.versions.rotateAll();
      await load();
    } catch (e) {
      showRotate = false;
      showToast("error", msg(e));
    } finally {
      busy = false;
    }
  }

  function closeRotate(): void {
    showRotate = false;
    rotation = null;
  }

  onMount(() => {
    void loadKeys();
  });
</script>

<PageHeader title="Key Versions" subtitle="List, enable, disable and retire a key's versions">
  {#snippet actions()}
    <button class="btn btn-warning btn-sm" onclick={() => (showRotate = true)}>Rotate all keys</button>
  {/snippet}
</PageHeader>

{#if keysError}
  <Alert kind="error" class="mb-3"><span>{keysError}</span></Alert>
{/if}

<div class="flex flex-wrap items-center gap-2 mb-4">
  <select class="select select-bordered select-sm" aria-label="Key" value={selected} onchange={(e) => { selected = e.currentTarget.value; void load(); }}>
    <option value="">Choose a key</option>
    {#each keys as k, i (`${k.backend}/${k.key_id}`)}
      <option value={String(i)}>{k.key_id} ({k.backend})</option>
    {/each}
  </select>
  {#if key}
    <button class="btn btn-ghost btn-sm" onclick={() => setAll(true)} disabled={busy}>Enable all</button>
    <button class="btn btn-ghost btn-sm" onclick={() => setAll(false)} disabled={busy}>Disable all</button>
  {/if}
</div>

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if error}
  <Alert kind="error"><span>{error}</span></Alert>
{:else if data}
  <div class="overflow-x-auto">
    <table class="table table-sm">
      <caption class="sr-only">Versions of {data.key_id}</caption>
      <thead>
        <tr>
          <th scope="col">Version</th>
          <th scope="col">State</th>
          <th scope="col">Created</th>
          <th scope="col"><span class="sr-only">Actions</span></th>
        </tr>
      </thead>
      <tbody>
        {#each data.versions as v (v.version)}
          {@const current = v.current === true || v.version === data.current_version}
          <tr>
            <td>
              {v.version}
              {#if current}<StatusBadge label="current" kind="neutral" />{/if}
            </td>
            <td><StatusBadge label={v.state} ok={v.state === "enabled"} /></td>
            <td>{v.created_at ?? ""}</td>
            <td class="text-right">
              {#if v.state === "disabled"}
                <button class="btn btn-ghost btn-xs" aria-label={`Enable version ${v.version}`} onclick={() => setState(v.version, true)} disabled={busy}>Enable</button>
              {/if}
              {#if !current && v.state === "enabled"}
                <button class="btn btn-ghost btn-xs" aria-label={`Disable version ${v.version}`} onclick={() => setState(v.version, false)} disabled={busy}>Disable</button>
              {/if}
              {#if !current && v.state !== "retired"}
                <button class="btn btn-ghost btn-xs text-error" aria-label={`Retire version ${v.version}`} onclick={() => (retireVersion = v.version)} disabled={busy}>Retire</button>
              {/if}
            </td>
          </tr>
        {/each}
        {#if data.versions.length === 0}
          <tr><td colspan="4" class="text-center text-base-content/60 py-6">No versions.</td></tr>
        {/if}
      </tbody>
    </table>
  </div>
{/if}

{#if retireVersion !== null && key}
  <Modal open={retireVersion !== null} onClose={() => (retireVersion = null)} labelledby="retire-version-title">
    <h3 id="retire-version-title" class="text-lg font-semibold mb-4">Retire version {retireVersion}</h3>
    <p>Retiring version {retireVersion} of {key.key_id} deletes its key material for good.</p>
    <div class="modal-action">
      <button class="btn btn-ghost" onclick={() => (retireVersion = null)}>Cancel</button>
      <button class="btn btn-error" onclick={retire}>Retire</button>
    </div>
  </Modal>
{/if}

{#if showRotate}
  <Modal open={showRotate} onClose={closeRotate} labelledby="rotate-all-title">
    <h3 id="rotate-all-title" class="text-lg font-semibold mb-4">Rotate all keys</h3>
    {#if rotation}
      <ul class="mb-3">
        <li>Rotated: {rotation.rotated}</li>
        <li>Skipped: {rotation.skipped}</li>
        <li>Failed: {rotation.failed}</li>
      </ul>
      {#each rotation.results.filter((r) => r.state === "failed") as r (`${r.backend}/${r.key_id}`)}
        <Alert kind="error" class="mb-2"><span>{r.key_id} ({r.backend}): {r.error ?? r.reason ?? "failed"}</span></Alert>
      {/each}
      <div class="modal-action">
        <button class="btn btn-primary" onclick={closeRotate}>Close</button>
      </div>
    {:else}
      <p>Every key of the tenant gets a new current version.</p>
      <div class="modal-action">
        <button class="btn btn-ghost" onclick={closeRotate} disabled={busy}>Cancel</button>
        <button class="btn btn-warning" onclick={rotate} disabled={busy}>Rotate</button>
      </div>
    {/if}
  </Modal>
{/if}
