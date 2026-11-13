<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import Alert from "$components/Alert.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import { textToB64, b64ToText, isB64 } from "$lib/b64.ts";
  import type { BackendInfo, SealRequest, SealResponse, UnsealRequest } from "@go-xkms/sdk";

  let backends = $state<BackendInfo[]>([]);
  let error = $state<string | null>(null);
  let loading = $state(true);

  let backend = $state("");
  let canSeal = $state<boolean | null>(null);
  let keyId = $state("");
  let text = $state("");
  let aad = $state("");
  let password = $state("");
  let tpmPolicy = $state("");
  let busy = $state(false);
  let result = $state<SealResponse | null>(null);

  let sealedJson = $state("");
  let unsealAad = $state("");
  let unsealErr = $state<string | null>(null);
  let plaintext = $state<string | null>(null);

  function message(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
  }

  async function load(): Promise<void> {
    loading = true;
    error = null;
    try {
      backends = (await getSDKClient().backends.list()).backends;
    } catch (e) {
      error = message(e);
    } finally {
      loading = false;
    }
  }

  async function checkCapability(): Promise<void> {
    const id = backend;
    canSeal = null;
    if (id === "") return;
    try {
      const resp = await getSDKClient().seal.capability(id);
      if (backend === id) canSeal = resp.can_seal;
    } catch (e) {
      showToast("error", message(e));
    }
  }

  async function doSeal(): Promise<void> {
    busy = true;
    try {
      const req: SealRequest = { backend, data: textToB64(text) };
      if (keyId !== "") req.key_id = keyId;
      if (aad !== "") req.aad = textToB64(aad);
      if (password !== "") req.password = password;
      if (tpmPolicy !== "") req.tpm_policy = tpmPolicy;
      result = await getSDKClient().seal.seal(req);
      showToast("success", "Data sealed.");
    } catch (e) {
      showToast("error", message(e));
    } finally {
      busy = false;
    }
  }

  async function copyResult(): Promise<void> {
    try {
      await navigator.clipboard.writeText(JSON.stringify(result, null, 2));
      showToast("success", "Seal result copied.");
    } catch (e) {
      showToast("error", message(e));
    }
  }

  async function doUnseal(): Promise<void> {
    unsealErr = null;
    plaintext = null;
    let parsed: SealResponse;
    try {
      parsed = JSON.parse(sealedJson) as SealResponse;
    } catch {
      unsealErr = "Invalid seal result JSON.";
      return;
    }
    if (parsed === null || typeof parsed !== "object" || typeof parsed.backend !== "string") {
      unsealErr = "Invalid seal result JSON.";
      return;
    }
    if (typeof parsed.ciphertext !== "string" || !isB64(parsed.ciphertext)) {
      unsealErr = "Ciphertext is not base64.";
      return;
    }
    const req: UnsealRequest = { backend: parsed.backend, ciphertext: parsed.ciphertext };
    if (parsed.nonce !== undefined) req.nonce = parsed.nonce;
    if (parsed.tag !== undefined) req.tag = parsed.tag;
    if (parsed.metadata !== undefined) req.metadata = parsed.metadata;
    if (parsed.key_id !== undefined) req.key_id = parsed.key_id;
    if (parsed.key_version !== undefined) req.key_version = parsed.key_version;
    if (unsealAad !== "") req.aad = textToB64(unsealAad);
    busy = true;
    try {
      plaintext = b64ToText((await getSDKClient().seal.unseal(req)).plaintext);
    } catch (e) {
      unsealErr = message(e);
    } finally {
      busy = false;
    }
  }

  onMount(() => {
    void load();
  });
</script>

<PageHeader title="Seal" subtitle="Seal and unseal data with a backend key or a TPM policy" />

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if error}
  <Alert kind="error"><span>{error}</span></Alert>
{:else}
  <div class="grid gap-6 lg:grid-cols-2">
    <section class="space-y-3" aria-labelledby="seal-title">
      <h2 id="seal-title" class="text-lg font-semibold">Seal</h2>
      <select class="select select-bordered w-full" aria-label="Backend" bind:value={backend} onchange={checkCapability}>
        <option value="" disabled>Choose a backend</option>
        {#each backends as b (b.id)}
          <option value={b.id}>{b.id}</option>
        {/each}
      </select>
      {#if canSeal === false}
        <p class="text-sm text-error">Backend {backend} cannot seal.</p>
      {/if}
      <input class="input input-bordered w-full" aria-label="Key ID" placeholder="Key ID (optional)" bind:value={keyId} />
      <textarea class="textarea textarea-bordered w-full" aria-label="Text to seal" placeholder="Text to seal" rows="3" bind:value={text}></textarea>
      <input class="input input-bordered w-full" aria-label="AAD" placeholder="AAD (optional)" bind:value={aad} />
      <input class="input input-bordered w-full" type="password" aria-label="Password" placeholder="Password (optional)" bind:value={password} />
      <input class="input input-bordered w-full" aria-label="TPM policy" placeholder="TPM policy (optional)" bind:value={tpmPolicy} />
      <button class="btn btn-primary" onclick={doSeal} disabled={busy || backend === "" || text === "" || canSeal !== true}>Seal</button>
      {#if result}
        <pre class="bg-base-200 rounded p-3 text-xs overflow-x-auto" aria-label="Seal result">{JSON.stringify(result, null, 2)}</pre>
        <button class="btn btn-ghost btn-sm" onclick={copyResult}>Copy</button>
      {/if}
    </section>

    <section class="space-y-3" aria-labelledby="unseal-title">
      <h2 id="unseal-title" class="text-lg font-semibold">Unseal</h2>
      {#if unsealErr}<Alert kind="error"><span>{unsealErr}</span></Alert>{/if}
      <textarea class="textarea textarea-bordered w-full font-mono text-xs" aria-label="Seal result JSON" placeholder="Paste a seal result JSON" rows="8" bind:value={sealedJson}></textarea>
      <input class="input input-bordered w-full" aria-label="Unseal AAD" placeholder="AAD (optional)" bind:value={unsealAad} />
      <button class="btn btn-primary" onclick={doUnseal} disabled={busy || sealedJson === ""}>Unseal</button>
      {#if plaintext !== null}
        <pre class="bg-base-200 rounded p-3 text-sm whitespace-pre-wrap" aria-label="Plaintext">{plaintext}</pre>
      {/if}
    </section>
  </div>
{/if}
