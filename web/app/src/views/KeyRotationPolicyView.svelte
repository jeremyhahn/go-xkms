<script lang="ts">
  import PageHeader from "$components/PageHeader.svelte";
  import StatusBadge from "$components/StatusBadge.svelte";
  import Alert from "$components/Alert.svelte";
  import { showToast } from "$stores/toast.svelte.ts";
  import {
    deleteRotationPolicy,
    formatInterval,
    fromSeconds,
    getRotationPolicy,
    setRotationPolicy,
    toSeconds,
    type IntervalUnit,
    type RotationPolicy,
  } from "$lib/keyRotationPolicy.ts";

  let keyId = $state("");
  let backend = $state("");

  // The policy last read from or written to the server; `loaded` tells an
  // absent policy apart from one not yet asked for.
  let current = $state<RotationPolicy | null>(null);
  let loaded = $state(false);
  let error = $state<string | null>(null);
  let busy = $state(false);

  let enabled = $state(false);
  let autoRotate = $state(false);
  let interval = $state<number | null>(30);
  let unit = $state<IntervalUnit>("days");
  let retain = $state<number | null>(null);
  let formErr = $state<string | null>(null);

  const ready = $derived(keyId.trim() !== "" && backend.trim() !== "");

  function message(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
  }

  function show(policy: RotationPolicy | undefined): void {
    current = policy ?? null;
    loaded = true;
    if (policy) {
      enabled = policy.enabled;
      autoRotate = policy.auto_rotate ?? false;
      ({ value: interval, unit } = fromSeconds(policy.interval_seconds));
      retain = policy.retain_versions ?? null;
    }
  }

  async function run(action: () => Promise<void>): Promise<void> {
    busy = true;
    error = null;
    try {
      await action();
    } catch (e) {
      error = message(e);
    } finally {
      busy = false;
    }
  }

  function load(): Promise<void> {
    return run(async () => {
      const res = await getRotationPolicy(keyId.trim(), backend.trim());
      show(res.policy);
    });
  }

  function validate(): RotationPolicy | null {
    if (interval === null || !Number.isInteger(interval) || interval <= 0) {
      formErr = "Interval must be a positive whole number.";
      return null;
    }
    if (retain !== null && (!Number.isInteger(retain) || retain < 0)) {
      formErr = "Retain versions must be a whole number of zero or more.";
      return null;
    }
    formErr = null;
    const policy: RotationPolicy = { enabled, interval_seconds: toSeconds(interval, unit), auto_rotate: autoRotate };
    if (retain !== null) policy.retain_versions = retain;
    return policy;
  }

  function save(): Promise<void> {
    const policy = validate();
    if (!policy) return Promise.resolve();
    const id = keyId.trim();
    return run(async () => {
      const res = await setRotationPolicy(id, backend.trim(), policy);
      show(res.policy ?? policy);
      showToast("success", `Rotation policy of key "${id}" saved.`);
    });
  }

  function remove(): Promise<void> {
    const id = keyId.trim();
    if (!window.confirm(`Remove the rotation policy of key "${id}"?`)) return Promise.resolve();
    return run(async () => {
      await deleteRotationPolicy(id, backend.trim());
      show(undefined);
      showToast("success", `Rotation policy of key "${id}" removed.`);
    });
  }

  function versions(n: number): string {
    return `${n} ${n === 1 ? "version" : "versions"}`;
  }
</script>

<PageHeader title="Rotation Policy" subtitle="Scheduled rotation of a key: interval and versions kept" />

<div class="flex flex-wrap items-end gap-2 mb-4">
  <input class="input input-bordered input-sm" aria-label="Key ID" placeholder="Key ID" bind:value={keyId} />
  <input class="input input-bordered input-sm" aria-label="Backend" placeholder="Backend" bind:value={backend} />
  <button class="btn btn-sm" onclick={load} disabled={busy || !ready}>Load</button>
</div>

{#if error}<Alert kind="error" class="mb-4"><span>{error}</span></Alert>{/if}

{#if loaded}
  <div class="card bg-base-200 mb-4">
    <div class="card-body p-4">
      <h2 class="card-title text-base">Current policy</h2>
      {#if current}
        <div class="flex flex-wrap gap-2">
          <StatusBadge label={current.enabled ? "enabled" : "disabled"} ok={current.enabled} />
          {#if current.auto_rotate}<StatusBadge label="auto rotate" kind="neutral" />{/if}
        </div>
        <dl class="grid grid-cols-[max-content_1fr] gap-x-4 gap-y-1 text-sm">
          <dt>Every</dt><dd>{formatInterval(current.interval_seconds)}</dd>
          <dt>Keeps</dt><dd>{versions(current.retain_versions ?? 0)}</dd>
          <dt>Next rotation</dt>
          <dd>{current.next_rotation ? new Date(current.next_rotation * 1000).toLocaleString() : "not scheduled"}</dd>
        </dl>
      {:else}
        <p class="text-base-content/60">No rotation policy</p>
      {/if}
    </div>
  </div>
{/if}

<div class="card bg-base-100 border border-base-300">
  <div class="card-body p-4 space-y-3">
    <h2 class="card-title text-base">Set policy</h2>
    <label class="label cursor-pointer justify-start gap-2">
      <input type="checkbox" class="checkbox checkbox-sm" bind:checked={enabled} />
      <span>Enabled</span>
    </label>
    <label class="label cursor-pointer justify-start gap-2">
      <input type="checkbox" class="checkbox checkbox-sm" bind:checked={autoRotate} />
      <span>Auto rotate</span>
    </label>
    <div class="flex flex-wrap items-center gap-2">
      <input type="number" class="input input-bordered input-sm w-28" aria-label="Interval" min="1" step="1" bind:value={interval} />
      <select class="select select-bordered select-sm" aria-label="Interval unit" bind:value={unit}>
        <option value="hours">hours</option>
        <option value="days">days</option>
      </select>
      <input type="number" class="input input-bordered input-sm w-28" aria-label="Retain versions" placeholder="Retain" min="0" step="1" bind:value={retain} />
    </div>
    {#if formErr}<p class="text-error text-sm">{formErr}</p>{/if}
    <div class="flex gap-2">
      <button class="btn btn-primary btn-sm" onclick={save} disabled={busy || !ready}>Save</button>
      <button class="btn btn-ghost btn-sm text-error" onclick={remove} disabled={busy || !ready}>Remove</button>
    </div>
  </div>
</div>
