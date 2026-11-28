<script lang="ts">
  import PageHeader from "$components/PageHeader.svelte";
  import Alert from "$components/Alert.svelte";
  import StatusBadge from "$components/StatusBadge.svelte";
  import { showToast } from "$stores/toast.svelte.ts";
  import { textToB64 } from "$lib/b64.ts";
  import { generateWrappedDataKey, type EncryptResponse } from "$lib/wrappedDataKey.ts";

  let keyId = $state("");
  let backend = $state("");
  let keySize = $state("32");
  let aad = $state("");
  let busy = $state(false);
  let error = $state<string | null>(null);
  let result = $state<EncryptResponse | null>(null);

  const ready = $derived(keyId.trim() !== "" && backend.trim() !== "");

  async function generate(): Promise<void> {
    busy = true;
    error = null;
    result = null;
    try {
      const res = await generateWrappedDataKey(
        keyId.trim(),
        backend.trim(),
        Number(keySize),
        aad === "" ? undefined : textToB64(aad),
      );
      result = res.wrapped;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  async function copy(): Promise<void> {
    if (!result) return;
    try {
      await navigator.clipboard.writeText(JSON.stringify(result));
      showToast("success", "Wrapped data key copied as JSON.");
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    }
  }
</script>

<PageHeader
  title="Data Keys"
  subtitle="The data key is returned only wrapped; the service that uses it unwraps it with a decrypt call."
/>

<div class="card bg-base-100 shadow-sm mb-4">
  <div class="card-body space-y-3">
    <label class="form-control w-full">
      <span class="label-text">Key ID</span>
      <input class="input input-bordered w-full" aria-label="Key ID" placeholder="Wrapping key ID" bind:value={keyId} />
    </label>
    <label class="form-control w-full">
      <span class="label-text">Backend</span>
      <input class="input input-bordered w-full" aria-label="Backend" placeholder="e.g. software" bind:value={backend} />
    </label>
    <label class="form-control w-full">
      <span class="label-text">Key size</span>
      <select class="select select-bordered w-full" aria-label="Key size" bind:value={keySize}>
        <option value="32">32 bytes (AES-256)</option>
        <option value="24">24 bytes (AES-192)</option>
        <option value="16">16 bytes (AES-128)</option>
      </select>
    </label>
    <label class="form-control w-full">
      <span class="label-text">Additional data (optional)</span>
      <input class="input input-bordered w-full" aria-label="Additional data" placeholder="Context bound to the wrap" bind:value={aad} />
    </label>
    <div class="card-actions justify-end">
      <button class="btn btn-primary" onclick={generate} disabled={busy || !ready}>
        {#if busy}<span class="loading loading-spinner loading-sm"></span>{/if}
        Generate
      </button>
    </div>
  </div>
</div>

{#if error}
  <Alert kind="error" class="mb-4"><span>{error}</span></Alert>
{/if}

{#if result}
  <div class="card bg-base-100 shadow-sm">
    <div class="card-body space-y-2">
      <div class="flex items-center gap-2">
        <h2 class="card-title">Result</h2>
        <StatusBadge label="wrapped" kind="neutral" />
      </div>
      <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
        <dt class="font-semibold">Ciphertext</dt><dd class="font-mono break-all">{result.ciphertext}</dd>
        {#if result.nonce}<dt class="font-semibold">Nonce</dt><dd class="font-mono break-all">{result.nonce}</dd>{/if}
        {#if result.tag}<dt class="font-semibold">Tag</dt><dd class="font-mono break-all">{result.tag}</dd>{/if}
        {#if result.iv}<dt class="font-semibold">IV</dt><dd class="font-mono break-all">{result.iv}</dd>{/if}
        {#if result.gcm_nonce_mode}<dt class="font-semibold">GCM nonce mode</dt><dd>{result.gcm_nonce_mode}</dd>{/if}
        {#if result.key_version !== undefined}<dt class="font-semibold">Key version</dt><dd>{result.key_version}</dd>{/if}
      </dl>
      <div class="card-actions justify-end">
        <button class="btn btn-sm" onclick={copy}>Copy as JSON</button>
      </div>
    </div>
  </div>
{/if}
