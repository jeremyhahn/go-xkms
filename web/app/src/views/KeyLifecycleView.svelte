<script lang="ts">
  import PageHeader from "$components/PageHeader.svelte";
  import StatusBadge from "$components/StatusBadge.svelte";
  import Alert from "$components/Alert.svelte";
  import { showToast } from "$stores/toast.svelte.ts";
  import { revokeKey, setKeyStatus, type SettableKeyStatus } from "$lib/keyLifecycle.ts";

  interface Result {
    key_id: string;
    version?: number;
    status: string;
    timestamp: string;
  }

  let keyId = $state("");
  let backend = $state("");
  // Empty (null) targets the whole key; otherwise a version number >= 1.
  let version = $state<number | null>(null);
  let reason = $state("");
  let confirmId = $state("");

  let busy = $state(false);
  let error = $state<string | null>(null);
  let result = $state<Result | null>(null);

  const versionOk = $derived(version === null || (Number.isInteger(version) && version >= 1));
  const keyReady = $derived(keyId.trim() !== "" && backend.trim() !== "");
  const canSetStatus = $derived(keyReady && versionOk && !busy);
  const canRevoke = $derived(keyReady && confirmId === keyId && !busy);

  async function run(action: () => Promise<Result>, done: string): Promise<void> {
    busy = true;
    error = null;
    try {
      result = await action();
      showToast("success", done);
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  function setStatus(status: SettableKeyStatus): Promise<void> {
    const id = keyId.trim();
    const v = version ?? undefined;
    return run(() => setKeyStatus(id, backend.trim(), status, v), `Key "${id}" ${status}.`);
  }

  function revoke(): Promise<void> {
    if (!canRevoke) return Promise.resolve();
    const id = keyId.trim();
    return run(() => revokeKey(id, backend.trim(), reason.trim() || undefined), `Key "${id}" revoked.`);
  }
</script>

<PageHeader title="Key Lifecycle" subtitle="Enable or disable a key or one of its versions. Revoking a key cannot be undone." />

{#if error}
  <Alert kind="error" class="mb-4"><span>{error}</span></Alert>
{/if}

<div class="grid gap-4 md:grid-cols-2">
  <section class="card bg-base-100 shadow-sm">
    <div class="card-body space-y-3">
      <h2 class="card-title text-base">Key</h2>
      <input class="input input-bordered w-full" aria-label="Key ID" placeholder="Key ID" bind:value={keyId} />
      <input class="input input-bordered w-full" aria-label="Backend" placeholder="Backend (e.g. software)" bind:value={backend} />
      <input
        class="input input-bordered w-full"
        type="number"
        min="1"
        step="1"
        aria-label="Version"
        placeholder="Version (empty = whole key)"
        bind:value={version}
      />
      {#if !versionOk}<p class="text-sm text-error">Version must be a whole number of 1 or more.</p>{/if}
      <div class="card-actions justify-end">
        <button class="btn btn-sm" onclick={() => setStatus("enabled")} disabled={!canSetStatus}>Enable</button>
        <button class="btn btn-sm btn-warning" onclick={() => setStatus("disabled")} disabled={!canSetStatus}>Disable</button>
      </div>
    </div>
  </section>

  <section class="card bg-base-100 shadow-sm border border-error">
    <div class="card-body space-y-3">
      <h2 class="card-title text-base text-error">Revoke key</h2>
      <input class="input input-bordered w-full" aria-label="Reason" placeholder="Reason (optional)" bind:value={reason} />
      <input
        class="input input-bordered w-full"
        aria-label="Confirm key ID"
        placeholder="Type the key ID to confirm"
        bind:value={confirmId}
      />
      <div class="card-actions justify-end">
        <button class="btn btn-sm btn-error" onclick={revoke} disabled={!canRevoke}>Revoke</button>
      </div>
    </div>
  </section>
</div>

{#if busy}
  <div class="flex justify-center py-4"><span class="loading loading-spinner"></span></div>
{/if}

{#if result}
  <div class="mt-4 flex flex-wrap items-center gap-2 text-sm" aria-label="Result">
    <span class="font-semibold">Result:</span>
    <code>{result.key_id}</code>
    {#if result.version}<span>version {result.version}</span>{/if}
    <StatusBadge label={result.status} ok={result.status === "enabled"} />
    <span>{result.timestamp}</span>
  </div>
{/if}
