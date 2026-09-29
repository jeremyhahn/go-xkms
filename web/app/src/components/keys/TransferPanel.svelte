<script lang="ts">
  // Transfer panel: wrapped export and cross-backend copy. Both move a key
  // somewhere else without ever putting plaintext material in this browser —
  // export returns a blob wrapped under a key the destination holds, and copy
  // is entirely server-side.
  import { onMount, untrack } from "svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import Alert from "$components/Alert.svelte";
  import type { KeyInfo, BackendInfo } from "@go-xkms/sdk";

  interface Props {
    keyInfo: KeyInfo;
    onChanged: () => void;
  }
  let { keyInfo, onChanged }: Props = $props();

  const algorithms = [
    "RSAES_OAEP_SHA_256",
    "RSAES_OAEP_SHA_1",
    "AES_KEY_WRAP",
    "AES_KEY_WRAP_PAD",
  ] as const;

  let backends = $state<BackendInfo[]>([]);
  let backendsErr = $state<string | null>(null);

  // ---- export ----
  let xAlgorithm = $state<string>(algorithms[0]);
  let xBusy = $state(false);
  let xErr = $state<string | null>(null);
  let xResult = $state<{ wrapped_key: string; algorithm: string; import_token?: string } | null>(null);

  // ---- copy ----
  let cDestBackend = $state("");
  let cDestKeyId = $state(untrack(() => `${keyInfo.key_id}-copy`));
  // The copy takes its key attributes from the source (go-xkms#1223); the
  // only choice left is how the material is wrapped in transit.
  let cAlgorithm = $state<string>(algorithms[0]);
  let cBusy = $state(false);
  let cErr = $state<string | null>(null);

  // One-shot load on mount: the backend list has no reactive dependencies, so
  // an $effect would only invite re-runs.
  onMount(async () => {
    try {
      const resp = await getSDKClient().backends.list();
      backends = resp.backends;
    } catch (e) {
      backendsErr = e instanceof Error ? e.message : String(e);
    }
  });


  async function doExport(): Promise<void> {
    xBusy = true;
    xErr = null;
    xResult = null;
    try {
      const resp = await getSDKClient().keys.export(keyInfo.key_id, {
        backend: keyInfo.backend,
        algorithm: xAlgorithm,
      });
      xResult = {
        wrapped_key: resp.wrapped_key,
        algorithm: resp.algorithm,
        import_token: resp.import_token,
      };
    } catch (e) {
      xErr = e instanceof Error ? e.message : String(e);
    } finally {
      xBusy = false;
    }
  }

  async function doCopy(): Promise<void> {
    if (cDestBackend === "" || cDestKeyId.trim() === "") {
      cErr = "Destination backend and key ID are required.";
      return;
    }
    if (cDestBackend === keyInfo.backend && cDestKeyId === keyInfo.key_id) {
      cErr = "Destination must differ from the source key.";
      return;
    }
    cBusy = true;
    cErr = null;
    try {
      await getSDKClient().keys.copy({
        source_backend: keyInfo.backend,
        source_key_id: keyInfo.key_id,
        dest_backend: cDestBackend,
        dest_key_id: cDestKeyId.trim(),
        algorithm: cAlgorithm,
      });
      showToast("success", `Key copied to ${cDestBackend} as "${cDestKeyId}".`);
      onChanged();
    } catch (e) {
      cErr = e instanceof Error ? e.message : String(e);
    } finally {
      cBusy = false;
    }
  }

  async function copyText(value: string, label: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(value);
      showToast("success", `${label} copied.`);
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    }
  }
</script>

<div class="space-y-6">
  {#if backendsErr}
    <Alert kind="warning"><span>Could not list backends: {backendsErr}</span></Alert>
  {/if}

  <section class="space-y-3">
    <div>
      <h3 class="font-medium text-sm">Wrapped export</h3>
      <p class="text-xs text-base-content/60">
        Returns this key wrapped under the destination's public wrapping key.
        Unlike raw material export on the Advanced tab, the plaintext never
        leaves the backend.
      </p>
    </div>

    <label class="form-control">
      <span class="label-text">Wrapping algorithm</span>
      <select class="select select-bordered select-sm" bind:value={xAlgorithm}>
        {#each algorithms as a (a)}<option>{a}</option>{/each}
      </select>
    </label>

    <button class="btn btn-sm" onclick={doExport} disabled={xBusy}>
      {xBusy ? "Exporting…" : "Export wrapped"}
    </button>

    {#if xErr}<Alert kind="error"><span>{xErr}</span></Alert>{/if}

    {#if xResult}
      <div class="space-y-2">
        <div>
          <div class="flex items-center justify-between mb-1">
            <span class="text-xs uppercase text-base-content/60">Wrapped key · {xResult.algorithm}</span>
            <button class="btn btn-ghost btn-xs" onclick={() => void copyText(xResult!.wrapped_key, "Wrapped key")}>Copy</button>
          </div>
          <pre class="bg-base-200 rounded p-2 text-xs overflow-x-auto break-all whitespace-pre-wrap">{xResult.wrapped_key}</pre>
        </div>
        {#if xResult.import_token}
          <div>
            <div class="flex items-center justify-between mb-1">
              <span class="text-xs uppercase text-base-content/60">Import token</span>
              <button class="btn btn-ghost btn-xs" onclick={() => void copyText(xResult!.import_token!, "Import token")}>Copy</button>
            </div>
            <pre class="bg-base-200 rounded p-2 text-xs overflow-x-auto break-all whitespace-pre-wrap">{xResult.import_token}</pre>
          </div>
        {/if}
      </div>
    {/if}
  </section>

  <section class="space-y-3">
    <div>
      <h3 class="font-medium text-sm">Copy to another backend</h3>
      <p class="text-xs text-base-content/60">
        Server-side migration of this key into a second backend. The source key
        is left in place.
      </p>
    </div>

    <div class="grid grid-cols-2 gap-3">
      <label class="form-control">
        <span class="label-text">Destination backend</span>
        <select class="select select-bordered select-sm" bind:value={cDestBackend}>
          <option value="">Select a backend…</option>
          {#each backends as b (b.id)}
            <option value={b.id}>{b.id} · {b.type}{b.hardware_backed ? " · hardware" : ""}</option>
          {/each}
        </select>
      </label>
      <label class="form-control">
        <span class="label-text">Destination key ID</span>
        <input class="input input-bordered input-sm" bind:value={cDestKeyId} />
      </label>
      <label class="form-control">
        <span class="label-text">Wrapping algorithm</span>
        <select class="select select-bordered select-sm" bind:value={cAlgorithm}>
          {#each algorithms as a (a)}<option value={a}>{a}</option>{/each}
        </select>
      </label>
    </div>

    <button class="btn btn-sm" onclick={doCopy} disabled={cBusy}>
      {cBusy ? "Copying…" : "Copy key"}
    </button>

    {#if cErr}<Alert kind="error"><span>{cErr}</span></Alert>{/if}
  </section>
</div>
