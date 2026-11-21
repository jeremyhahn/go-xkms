<script lang="ts">
  import PageHeader from "$components/PageHeader.svelte";
  import StatusBadge from "$components/StatusBadge.svelte";
  import Alert from "$components/Alert.svelte";
  import { showToast } from "$stores/toast.svelte.ts";
  import { isB64, textToB64 } from "$lib/b64.ts";
  import { parseCiphertextInput, parsePositiveInt, rewrap, type RewrapRequest, type RewrapResponse } from "$lib/keyRewrap.ts";

  let backend = $state("");
  let keyId = $state("");
  let ciphertext = $state("");
  let nonce = $state("");
  let tag = $state("");
  let additionalData = $state("");
  // Source decryption options (DecryptRequest); empty ones are omitted.
  let mode = $state("");
  let padding = $state("");
  let hash = $state("");
  let label = $state("");
  let tagSize = $state("");
  let keyVersion = $state("");
  let targetBackend = $state("");
  let targetKeyId = $state("");

  let busy = $state(false);
  let inputError = $state<string | null>(null);
  let error = $state<string | null>(null);
  let result = $state<RewrapResponse | null>(null);

  const ready = $derived(backend.trim() !== "" && keyId.trim() !== "" && ciphertext.trim() !== "");

  // Builds the request, or returns an error string; empty optional fields are omitted.
  function buildRequest(): RewrapRequest | string {
    const parsed = parseCiphertextInput(ciphertext);
    if (typeof parsed === "string") return parsed;
    const source: RewrapRequest["source"] = { backend: backend.trim(), key_id: keyId.trim(), ...parsed };
    for (const [name, value] of [["nonce", nonce], ["tag", tag]] as const) {
      const v = value.trim();
      if (v === "") continue;
      if (!isB64(v)) return `The ${name} must be base64.`;
      source[name] = v;
    }
    if (additionalData !== "") source.additional_data = textToB64(additionalData);
    for (const [name, value] of [["mode", mode], ["padding", padding], ["hash", hash]] as const) {
      if (value.trim() !== "") source[name] = value.trim();
    }
    if (label !== "") source.label = textToB64(label);
    const size = parsePositiveInt(tagSize);
    if (size === null) return "The tag size must be a positive integer.";
    if (size !== undefined) source.tag_size = size;
    const ver = parsePositiveInt(keyVersion);
    if (ver === null) return "The key version must be a positive integer.";
    if (ver !== undefined) source.key_version = ver;
    const req: RewrapRequest = { source };
    if (targetKeyId.trim() !== "") req.target_key_id = targetKeyId.trim();
    if (targetBackend.trim() !== "") req.target_backend = targetBackend.trim();
    return req;
  }

  async function submit(): Promise<void> {
    error = null;
    const req = buildRequest();
    if (typeof req === "string") {
      inputError = req;
      return;
    }
    inputError = null;
    busy = true;
    try {
      result = await rewrap(req);
    } catch (e) {
      result = null;
      error = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  async function copy(): Promise<void> {
    if (!result) return;
    try {
      await navigator.clipboard.writeText(JSON.stringify(result.wrapped));
      showToast("success", "Rewrapped ciphertext copied.");
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    }
  }
</script>

<PageHeader title="Rewrap" subtitle="Re-encrypt a ciphertext under a key's current version or another key; the plaintext never leaves the server." />

{#if error}<Alert kind="error" class="mb-4"><span>{error}</span></Alert>{/if}

<div class="grid gap-4 lg:grid-cols-2">
  <section class="card bg-base-100 shadow-sm">
    <div class="card-body space-y-3">
      <h2 class="card-title text-base">Source</h2>
      <input class="input input-bordered w-full" aria-label="Source backend" placeholder="Backend" bind:value={backend} />
      <input class="input input-bordered w-full" aria-label="Source key ID" placeholder="Key ID" bind:value={keyId} />
      <textarea class="textarea textarea-bordered w-full font-mono" aria-label="Ciphertext" placeholder="Base64 ciphertext or an EncryptResponse JSON object" bind:value={ciphertext} rows="4"></textarea>
      <input class="input input-bordered w-full font-mono" aria-label="Nonce" placeholder="Nonce (base64, optional)" bind:value={nonce} />
      <input class="input input-bordered w-full font-mono" aria-label="Tag" placeholder="Tag (base64, optional)" bind:value={tag} />
      <input class="input input-bordered w-full" aria-label="Additional data" placeholder="Additional data (text, optional)" bind:value={additionalData} />
      <div class="grid gap-2 sm:grid-cols-2">
        <input class="input input-bordered w-full" aria-label="Mode" placeholder="Cipher mode, e.g. cbc-pad (optional)" bind:value={mode} />
        <input class="input input-bordered w-full" aria-label="Key version" placeholder="Key version (optional)" inputmode="numeric" bind:value={keyVersion} />
        <input class="input input-bordered w-full" aria-label="Tag size" placeholder="Tag size in bytes (optional)" inputmode="numeric" bind:value={tagSize} />
        <input class="input input-bordered w-full" aria-label="Padding" placeholder="RSA padding: pkcs1v15 or oaep (optional)" bind:value={padding} />
        <input class="input input-bordered w-full" aria-label="OAEP hash" placeholder="OAEP hash, e.g. SHA-256 (optional)" bind:value={hash} />
        <input class="input input-bordered w-full" aria-label="OAEP label" placeholder="OAEP label (text, optional)" bind:value={label} />
      </div>
      {#if inputError}<p class="text-error text-sm" role="alert">{inputError}</p>{/if}
    </div>
  </section>

  <section class="card bg-base-100 shadow-sm">
    <div class="card-body space-y-3">
      <h2 class="card-title text-base">Target</h2>
      <input class="input input-bordered w-full" aria-label="Target backend" placeholder="Target backend (optional)" bind:value={targetBackend} />
      <input class="input input-bordered w-full" aria-label="Target key ID" placeholder="Target key ID (optional)" bind:value={targetKeyId} />
      <p class="text-sm text-base-content/60">Leave both empty to rewrap under the source key's current version.</p>
      <div class="card-actions justify-end">
        <button class="btn btn-primary" onclick={submit} disabled={busy || !ready}>
          {#if busy}<span class="loading loading-spinner loading-sm"></span>{/if}
          Rewrap
        </button>
      </div>
    </div>
  </section>
</div>

{#if result}
  <section class="card bg-base-100 shadow-sm mt-4">
    <div class="card-body space-y-3">
      <div class="flex items-center justify-between">
        <h2 class="card-title text-base">Result</h2>
        <button class="btn btn-ghost btn-sm" onclick={copy}>Copy as JSON</button>
      </div>
      <div class="flex flex-wrap gap-2">
        <StatusBadge label="rewrapped" ok={true} />
      </div>
      <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
        <dt>Source version</dt><dd data-testid="source-version">{result.source_key_version ?? "-"}</dd>
        <dt>New version</dt><dd data-testid="new-version">{result.wrapped.key_version ?? "-"}</dd>
        <dt>Ciphertext</dt><dd class="font-mono break-all" data-testid="new-ciphertext">{result.wrapped.ciphertext}</dd>
        {#if result.wrapped.nonce}<dt>Nonce</dt><dd class="font-mono break-all" data-testid="new-nonce">{result.wrapped.nonce}</dd>{/if}
        {#if result.wrapped.tag}<dt>Tag</dt><dd class="font-mono break-all" data-testid="new-tag">{result.wrapped.tag}</dd>{/if}
        {#if result.wrapped.iv}<dt>IV</dt><dd class="font-mono break-all">{result.wrapped.iv}</dd>{/if}
        {#if result.wrapped.gcm_nonce_mode}<dt>GCM nonce mode</dt><dd>{result.wrapped.gcm_nonce_mode}</dd>{/if}
      </dl>
    </div>
  </section>
{/if}
