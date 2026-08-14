<script lang="ts">
  // Wrap / unwrap by key ID. Both halves of a key transfer that never exposes
  // plaintext material to this browser: the server wraps a target key under a
  // wrapping key it also holds, and unwraps a blob straight into a new managed
  // key. That is the difference between this panel and "Export material" on
  // the Advanced tab — nothing secret transits the client here.
  import { untrack } from "svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import { isB64 } from "$lib/b64.ts";
  import Alert from "$components/Alert.svelte";
  import type { KeyInfo } from "@go-xkms/sdk";

  interface Props {
    /** The key this drawer is open on — the wrapping/unwrapping key. */
    keyInfo: KeyInfo;
    /** Every key the operator can see, for the target picker. */
    allKeys: KeyInfo[];
    /** Called after a successful unwrap, which creates a new key. */
    onChanged: () => void;
  }
  let { keyInfo, allKeys, onChanged }: Props = $props();

  type Direction = "wrap" | "unwrap";
  let direction = $state<Direction>("wrap");

  const algorithms = [
    "RSAES_OAEP_SHA_256",
    "RSAES_OAEP_SHA_1",
    "AES_GCM",
    "AES_KEY_WRAP",
    "AES_KEY_WRAP_PAD",
  ] as const;

  // Candidate targets: any key other than the wrapping key itself. Wrapping a
  // key under itself is not a meaningful operation and the backend rejects it.
  const targets = $derived(allKeys.filter((k) => k.key_id !== keyInfo.key_id));

  // ---- wrap ----
  let wTargetId = $state("");
  let wAlgorithm = $state<string>(algorithms[0]);
  let wIv = $state("");
  let wAad = $state("");
  let wTagBits = $state<number | undefined>(undefined);
  let wResult = $state<{ wrapped_key: string; algorithm: string } | null>(null);

  const wTarget = $derived(targets.find((k) => k.key_id === wTargetId) ?? null);

  // ---- unwrap ----
  let uWrapped = $state("");
  let uAlgorithm = $state<string>(algorithms[0]);
  let uIv = $state("");
  let uAad = $state("");
  let uTagBits = $state<number | undefined>(undefined);
  let uTargetId = $state("");
  let uTargetBackend = $state(untrack(() => keyInfo.backend));
  let uTargetType = $state("symmetric");
  let uTargetSize = $state<number | undefined>(undefined);
  let uTargetCurve = $state("");
  let uTargetExportable = $state(false);

  let busy = $state(false);
  let err = $state<string | null>(null);

  function optionalB64(label: string, value: string): boolean {
    if (value !== "" && !isB64(value)) {
      err = `${label} is not valid base64.`;
      return false;
    }
    return true;
  }

  async function doWrap(): Promise<void> {
    if (wTarget === null) {
      err = "Select a target key to wrap.";
      return;
    }
    if (!optionalB64("IV", wIv) || !optionalB64("AAD", wAad)) return;

    busy = true;
    err = null;
    wResult = null;
    try {
      const resp = await getSDKClient().keys.wrapById({
        wrapping_key_id: keyInfo.key_id,
        wrapping_key_backend: keyInfo.backend,
        target_key_id: wTarget.key_id,
        target_key_backend: wTarget.backend,
        algorithm: wAlgorithm,
        ...(wIv !== "" ? { iv: wIv.trim() } : {}),
        ...(wAad !== "" ? { aad: wAad.trim() } : {}),
        ...(wTagBits !== undefined ? { tag_bits: wTagBits } : {}),
      });
      wResult = { wrapped_key: resp.wrapped_key, algorithm: resp.algorithm };
    } catch (e) {
      err = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  async function doUnwrap(): Promise<void> {
    if (uWrapped.trim() === "" || !isB64(uWrapped)) {
      err = "Wrapped key must be valid base64.";
      return;
    }
    if (uTargetId.trim() === "") {
      err = "A key ID for the unwrapped key is required.";
      return;
    }
    if (!optionalB64("IV", uIv) || !optionalB64("AAD", uAad)) return;

    busy = true;
    err = null;
    try {
      await getSDKClient().keys.unwrapById({
        wrapped_key: uWrapped.trim(),
        unwrapping_key_id: keyInfo.key_id,
        unwrapping_key_backend: keyInfo.backend,
        algorithm: uAlgorithm,
        target_key_id: uTargetId,
        target_key_backend: uTargetBackend,
        target_key_type: uTargetType,
        target_exportable: uTargetExportable,
        ...(uIv !== "" ? { iv: uIv.trim() } : {}),
        ...(uAad !== "" ? { aad: uAad.trim() } : {}),
        ...(uTagBits !== undefined ? { tag_bits: uTagBits } : {}),
        ...(uTargetSize !== undefined ? { target_key_size: uTargetSize } : {}),
        ...(uTargetCurve !== "" ? { target_curve: uTargetCurve } : {}),
      });
      showToast("success", `Key "${uTargetId}" unwrapped into ${uTargetBackend}.`);
      uWrapped = "";
      uTargetId = "";
      onChanged();
    } catch (e) {
      err = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  async function copyWrapped(): Promise<void> {
    if (wResult === null) return;
    try {
      await navigator.clipboard.writeText(wResult.wrapped_key);
      showToast("success", "Wrapped key copied.");
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    }
  }

  // AEAD parameters only apply to the AES_GCM algorithm; the RSA-OAEP and
  // key-wrap algorithms ignore them, so hide them rather than invite input the
  // server will discard.
  const aeadWrap = $derived(wAlgorithm === "AES_GCM");
  const aeadUnwrap = $derived(uAlgorithm === "AES_GCM");
</script>

<div class="space-y-3">
  <div role="tablist" class="tabs tabs-boxed tabs-sm w-fit">
    <button role="tab" class="tab" class:tab-active={direction === "wrap"} onclick={() => (direction = "wrap")}>Wrap</button>
    <button role="tab" class="tab" class:tab-active={direction === "unwrap"} onclick={() => (direction = "unwrap")}>Unwrap</button>
  </div>

  {#if err}<Alert kind="error"><span>{err}</span></Alert>{/if}

  {#if direction === "wrap"}
    <p class="text-xs text-base-content/60">
      Wrap another managed key under <span class="font-mono">{keyInfo.key_id}</span>.
      The material is wrapped inside the backend; the wrapped blob is the only
      thing that reaches this browser.
    </p>

    <label class="form-control">
      <span class="label-text">Target key</span>
      <select class="select select-bordered select-sm" bind:value={wTargetId}>
        <option value="">Select a key…</option>
        {#each targets as k (k.backend + k.key_id)}
          <option value={k.key_id}>{k.key_id} · {k.key_type} · {k.backend}</option>
        {/each}
      </select>
      {#if targets.length === 0}
        <span class="label-text-alt">No other keys available to wrap.</span>
      {/if}
    </label>

    <label class="form-control">
      <span class="label-text">Algorithm</span>
      <select class="select select-bordered select-sm" bind:value={wAlgorithm}>
        {#each algorithms as a (a)}<option>{a}</option>{/each}
      </select>
    </label>

    {#if aeadWrap}
      <div class="grid grid-cols-2 gap-3">
        <label class="form-control">
          <span class="label-text">IV (base64)</span>
          <input class="input input-bordered input-sm font-mono text-xs" bind:value={wIv} />
        </label>
        <label class="form-control">
          <span class="label-text">Tag (bits)</span>
          <input type="number" class="input input-bordered input-sm" placeholder="default" bind:value={wTagBits} />
        </label>
      </div>
      <label class="form-control">
        <span class="label-text">AAD (base64, optional)</span>
        <input class="input input-bordered input-sm font-mono text-xs" bind:value={wAad} />
      </label>
    {/if}

    <button class="btn btn-primary btn-sm" onclick={doWrap} disabled={busy || wTargetId === ""}>
      {busy ? "Wrapping…" : "Wrap key"}
    </button>

    {#if wResult}
      <div>
        <div class="flex items-center justify-between mb-1">
          <span class="text-xs uppercase text-base-content/60">Wrapped key · {wResult.algorithm}</span>
          <button class="btn btn-ghost btn-xs" onclick={copyWrapped}>Copy</button>
        </div>
        <pre class="bg-base-200 rounded p-2 text-xs overflow-x-auto break-all whitespace-pre-wrap">{wResult.wrapped_key}</pre>
      </div>
    {/if}
  {:else}
    <p class="text-xs text-base-content/60">
      Unwrap a blob with <span class="font-mono">{keyInfo.key_id}</span> and
      install the result as a new managed key. The plaintext material exists
      only inside the backend.
    </p>

    <label class="form-control">
      <span class="label-text">Wrapped key (base64)</span>
      <textarea class="textarea textarea-bordered font-mono text-xs" rows="3" bind:value={uWrapped}></textarea>
    </label>

    <label class="form-control">
      <span class="label-text">Algorithm</span>
      <select class="select select-bordered select-sm" bind:value={uAlgorithm}>
        {#each algorithms as a (a)}<option>{a}</option>{/each}
      </select>
    </label>

    {#if aeadUnwrap}
      <div class="grid grid-cols-2 gap-3">
        <label class="form-control">
          <span class="label-text">IV (base64)</span>
          <input class="input input-bordered input-sm font-mono text-xs" bind:value={uIv} />
        </label>
        <label class="form-control">
          <span class="label-text">Tag (bits)</span>
          <input type="number" class="input input-bordered input-sm" placeholder="default" bind:value={uTagBits} />
        </label>
      </div>
      <label class="form-control">
        <span class="label-text">AAD (base64, optional)</span>
        <input class="input input-bordered input-sm font-mono text-xs" bind:value={uAad} />
      </label>
    {/if}

    <div class="divider text-xs">New key</div>

    <div class="grid grid-cols-2 gap-3">
      <label class="form-control">
        <span class="label-text">Key ID</span>
        <input class="input input-bordered input-sm" bind:value={uTargetId} />
      </label>
      <label class="form-control">
        <span class="label-text">Backend</span>
        <input class="input input-bordered input-sm" bind:value={uTargetBackend} />
      </label>
      <label class="form-control">
        <span class="label-text">Key type</span>
        <select class="select select-bordered select-sm" bind:value={uTargetType}>
          <option>symmetric</option><option>rsa</option><option>ecdsa</option><option>ed25519</option>
        </select>
      </label>
      {#if uTargetType === "rsa" || uTargetType === "symmetric"}
        <label class="form-control">
          <span class="label-text">Key size (bits)</span>
          <input type="number" class="input input-bordered input-sm" bind:value={uTargetSize} />
        </label>
      {:else if uTargetType === "ecdsa"}
        <label class="form-control">
          <span class="label-text">Curve</span>
          <select class="select select-bordered select-sm" bind:value={uTargetCurve}>
            <option value="">Backend default</option>
            <option>P-256</option><option>P-384</option><option>P-521</option>
          </select>
        </label>
      {/if}
    </div>

    <label class="label cursor-pointer justify-start gap-3">
      <input type="checkbox" class="checkbox checkbox-sm" bind:checked={uTargetExportable} />
      <span class="label-text">Exportable</span>
    </label>

    <button class="btn btn-primary btn-sm" onclick={doUnwrap} disabled={busy}>
      {busy ? "Unwrapping…" : "Unwrap into new key"}
    </button>
  {/if}
</div>
