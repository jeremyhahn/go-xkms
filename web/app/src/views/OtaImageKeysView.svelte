<script lang="ts">
  import PageHeader from "$components/PageHeader.svelte";
  import Alert from "$components/Alert.svelte";
  import { showToast } from "$stores/toast.svelte.ts";
  import { isB64 } from "$lib/b64.ts";
  import {
    createOtaKey,
    rotateOtaKey,
    signOtaImage,
    hexToB64,
    isSha256Hex,
    type OtaSignRequest,
    type OtaSignResponse,
  } from "$lib/otaImageKeys.ts";

  interface KeyResult {
    keyId: string;
    version?: number;
    pem?: string;
  }

  let board = $state("");
  let backend = $state("");
  let busy = $state(false);
  let error = $state<string | null>(null);
  let keyResult = $state<KeyResult | null>(null);

  let raw = $state(false);
  let input = $state("");
  let signing = $state(false);
  let signError = $state<string | null>(null);
  let signResult = $state<OtaSignResponse | null>(null);

  const ready = $derived(board.trim() !== "" && backend.trim() !== "");
  const inputError = $derived.by(() => {
    if (input.trim() === "") return null;
    if (raw) return isB64(input) ? null : "The data must be standard base64.";
    return isSha256Hex(input) ? null : "The digest must be 64 hex characters.";
  });
  const canSign = $derived(ready && input.trim() !== "" && inputError === null && !signing);

  function message(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
  }

  async function create(): Promise<void> {
    busy = true;
    error = null;
    try {
      const r = await createOtaKey(board.trim(), backend.trim());
      keyResult = { keyId: r.key_id, pem: r.public_key_pem };
      showToast("success", `OTA image key for "${board.trim()}" created.`);
    } catch (e) {
      error = message(e);
    } finally {
      busy = false;
    }
  }

  async function rotate(): Promise<void> {
    if (!window.confirm(`Rotate the OTA image key of "${board.trim()}"? Images signed later use the new version.`)) return;
    busy = true;
    error = null;
    try {
      const r = await rotateOtaKey(board.trim(), backend.trim());
      keyResult = { keyId: r.key_id, version: r.key_version, pem: r.public_key_pem };
      showToast("success", `OTA image key for "${board.trim()}" rotated.`);
    } catch (e) {
      error = message(e);
    } finally {
      busy = false;
    }
  }

  async function sign(): Promise<void> {
    if (!canSign) return;
    signing = true;
    signError = null;
    signResult = null;
    const req: OtaSignRequest = raw
      ? { backend: backend.trim(), data: input.trim() }
      : { backend: backend.trim(), data: hexToB64(input), data_is_digest: true };
    try {
      signResult = await signOtaImage(board.trim(), req);
    } catch (e) {
      signError = message(e);
    } finally {
      signing = false;
    }
  }

  async function copy(text: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(text);
      showToast("success", "Copied.");
    } catch (e) {
      showToast("error", message(e));
    }
  }
</script>

<PageHeader title="OTA Image Keys" subtitle="Per-board ES256 image-signing keys" />

<div class="grid gap-4 lg:grid-cols-2">
  <div class="card bg-base-100 border border-base-300">
    <div class="card-body space-y-3">
      <h2 class="card-title text-base">Board key</h2>
      {#if error}<Alert kind="error"><span>{error}</span></Alert>{/if}
      <label class="form-control w-full">
        <span class="label-text">Board</span>
        <input class="input input-bordered w-full" aria-label="Board" placeholder="board-7" bind:value={board} />
      </label>
      <label class="form-control w-full">
        <span class="label-text">Backend</span>
        <input class="input input-bordered w-full" aria-label="Backend" placeholder="software" bind:value={backend} />
      </label>
      <div class="flex gap-2">
        <button class="btn btn-primary btn-sm" onclick={create} disabled={!ready || busy}>Create key</button>
        <button class="btn btn-outline btn-sm" onclick={rotate} disabled={!ready || busy}>Rotate key</button>
        {#if busy}<span class="loading loading-spinner loading-sm" aria-hidden="true"></span>{/if}
      </div>
      {#if keyResult}
        <dl class="text-sm space-y-1">
          <div><dt class="inline font-semibold">Key ID:</dt> <dd class="inline font-mono">{keyResult.keyId}</dd></div>
          {#if keyResult.version !== undefined}
            <div><dt class="inline font-semibold">Version:</dt> <dd class="inline" data-testid="ota-key-version">{keyResult.version}</dd></div>
          {/if}
        </dl>
        {#if keyResult.pem}
          {@const pem = keyResult.pem}
          <pre class="bg-base-200 rounded p-2 text-xs overflow-x-auto" data-testid="ota-key-pem">{pem}</pre>
          <button class="btn btn-ghost btn-xs self-start" onclick={() => copy(pem)}>Copy public key</button>
        {/if}
      {/if}
    </div>
  </div>

  <div class="card bg-base-100 border border-base-300">
    <div class="card-body space-y-3">
      <h2 class="card-title text-base">Sign an image</h2>
      {#if signError}<Alert kind="error"><span>{signError}</span></Alert>{/if}
      <label class="label cursor-pointer justify-start gap-2">
        <input type="checkbox" class="toggle toggle-sm" aria-label="Raw data (base64)" bind:checked={raw} />
        <span class="label-text">Raw data (base64)</span>
      </label>
      {#if raw}
        <textarea class="textarea textarea-bordered w-full font-mono" aria-label="Data (base64)" rows="3" bind:value={input}></textarea>
      {:else}
        <input class="input input-bordered w-full font-mono" aria-label="Digest (hex)" placeholder="SHA-256 digest, 64 hex characters" bind:value={input} />
      {/if}
      {#if inputError}<p class="text-error text-sm">{inputError}</p>{/if}
      <div>
        <button class="btn btn-primary btn-sm" onclick={sign} disabled={!canSign}>Sign</button>
      </div>
      {#if signResult}
        {@const sig = signResult.signature}
        <dl class="text-sm space-y-1">
          {#if signResult.algorithm}
            <div><dt class="inline font-semibold">Algorithm:</dt> <dd class="inline">{signResult.algorithm}</dd></div>
          {/if}
          {#if signResult.key_version !== undefined}
            <div><dt class="inline font-semibold">Key version:</dt> <dd class="inline">{signResult.key_version}</dd></div>
          {/if}
          <div><dt class="font-semibold">Signature (base64):</dt> <dd class="font-mono break-all">{sig}</dd></div>
        </dl>
        <button class="btn btn-ghost btn-xs self-start" onclick={() => copy(sig)}>Copy signature</button>
      {/if}
    </div>
  </div>
</div>
