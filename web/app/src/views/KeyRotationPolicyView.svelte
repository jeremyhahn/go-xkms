<script lang="ts">
  import PageHeader from "$components/PageHeader.svelte";
  import StatusBadge from "$components/StatusBadge.svelte";
  import Alert from "$components/Alert.svelte";
  import Modal from "$components/Modal.svelte";
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

  // auto_rotate and retain_versions are not offered: the service refuses
  // both (UnenforceablePolicyError), as it runs no rotation scheduler and
  // retires no versions by itself. The policy records the interval; keys
  // are rotated by hand.
  let enabled = $state(false);
  let interval = $state<number | null>(30);
  let unit = $state<IntervalUnit>("days");
  let formErr = $state<string | null>(null);

  const ready = $derived(keyId.trim() !== "" && backend.trim() !== "");

  function message(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
  }

  // The form defaults, restored when the target changes or has no policy.
  function resetForm(): void {
    enabled = false;
    interval = 30;
    unit = "days";
    formErr = null;
  }

  function show(policy: RotationPolicy | undefined): void {
    current = policy ?? null;
    loaded = true;
    if (policy) {
      enabled = policy.enabled;
      ({ value: interval, unit } = fromSeconds(policy.interval_seconds));
    } else {
      resetForm();
    }
  }

  // Each request takes the target generation; editing the key or backend
  // starts a new one, resets the form and drops what is still pending, so
  // one key's policy is never shown for, or saved to, another.
  let gen = 0;

  function targetChanged(): void {
    gen++;
    current = null;
    loaded = false;
    error = null;
    resetForm();
  }

  async function run(action: (live: () => boolean) => Promise<void>): Promise<void> {
    const g = gen;
    const live = (): boolean => g === gen;
    busy = true;
    error = null;
    try {
      await action(live);
    } catch (e) {
      if (live()) error = message(e);
    } finally {
      busy = false;
    }
  }

  function load(): Promise<void> {
    return run(async (live) => {
      const res = await getRotationPolicy(keyId.trim(), backend.trim());
      if (live()) show(res.policy);
    });
  }

  function validate(): RotationPolicy | null {
    if (interval === null || !Number.isInteger(interval) || interval <= 0) {
      formErr = "Interval must be a positive whole number.";
      return null;
    }
    formErr = null;
    return { enabled, interval_seconds: toSeconds(interval, unit) };
  }

  function save(): Promise<void> {
    const policy = validate();
    if (!policy) return Promise.resolve();
    const id = keyId.trim();
    return run(async (live) => {
      const res = await setRotationPolicy(id, backend.trim(), policy);
      if (live()) show(res.policy ?? policy);
      showToast("success", `Rotation policy of key "${id}" saved.`);
    });
  }

  // Remove asks through components/Modal.svelte, never window.confirm; the
  // key and backend are taken when asked, so the dialog names the target.
  let confirmRemove = $state<{ id: string; backend: string } | null>(null);

  function remove(): void {
    confirmRemove = { id: keyId.trim(), backend: backend.trim() };
  }

  function removeConfirmed(): Promise<void> {
    const t = confirmRemove;
    confirmRemove = null;
    if (t === null) return Promise.resolve();
    const id = t.id;
    return run(async (live) => {
      await deleteRotationPolicy(id, t.backend);
      if (live()) show(undefined);
      showToast("success", `Rotation policy of key "${id}" removed.`);
    });
  }

  function versions(n: number): string {
    return `${n} ${n === 1 ? "version" : "versions"}`;
  }
</script>

<PageHeader title="Rotation Policy" subtitle="Scheduled rotation of a key: interval and versions kept" />

<div class="flex flex-wrap items-end gap-2 mb-4">
  <input class="input input-bordered input-sm" aria-label="Key ID" placeholder="Key ID" bind:value={keyId} oninput={targetChanged} />
  <input class="input input-bordered input-sm" aria-label="Backend" placeholder="Backend" bind:value={backend} oninput={targetChanged} />
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
      <input type="checkbox" class="checkbox checkbox-sm" checked={false} disabled aria-describedby="rotation-manual-note" />
      <span>Auto rotate</span>
    </label>
    <div class="flex flex-wrap items-center gap-2">
      <input type="number" class="input input-bordered input-sm w-28" aria-label="Interval" min="1" step="1" bind:value={interval} />
      <select class="select select-bordered select-sm" aria-label="Interval unit" bind:value={unit}>
        <option value="hours">hours</option>
        <option value="days">days</option>
      </select>
      <input type="number" class="input input-bordered input-sm w-28" aria-label="Retain versions" placeholder="Retain" disabled aria-describedby="rotation-manual-note" />
    </div>
    <p id="rotation-manual-note" class="text-sm text-base-content/70">
      Auto rotate and Retain versions are unavailable: the service runs no rotation scheduler and retires no versions by itself.
      The policy records the interval; rotate the key by hand from Key Versions and disable old versions there.
    </p>
    {#if formErr}<p class="text-error text-sm">{formErr}</p>{/if}
    <div class="flex gap-2">
      <button class="btn btn-primary btn-sm" onclick={save} disabled={busy || !ready}>Save</button>
      <button class="btn btn-ghost btn-sm text-error" onclick={remove} disabled={busy || !ready}>Remove</button>
    </div>
  </div>

  {#if confirmRemove !== null}
    <Modal open onClose={() => (confirmRemove = null)} labelledby="rotation-policy-remove-title">
      <h3 id="rotation-policy-remove-title" class="text-lg font-semibold mb-4">Remove the rotation policy</h3>
      <p>Remove the rotation policy of key "{confirmRemove.id}"?</p>
      <div class="modal-action">
        <button class="btn btn-ghost" onclick={() => (confirmRemove = null)}>Cancel</button>
        <button class="btn btn-error" onclick={removeConfirmed}>Remove</button>
      </div>
    </Modal>
  {/if}
</div>
