<script lang="ts">
  // Decrypt panel — the inverse of EncryptPanel. Only symmetric keys reach
  // here: RSA decryption has no REST verb (encrypt-asym is one-way by design;
  // the private half is used through unwrap, which is attested and audited).
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import { b64ToText, isB64, b64Bytes } from "$lib/b64.ts";
  import Alert from "$components/Alert.svelte";
  import type { KeyInfo } from "@go-xkms/sdk";

  interface Props {
    keyInfo: KeyInfo;
  }
  let { keyInfo }: Props = $props();

  let ciphertext = $state("");
  let nonce = $state("");
  let tag = $state("");
  let aad = $state("");
  let mode = $state("");
  let tagSize = $state<number | undefined>(undefined);

  let busy = $state(false);
  let err = $state<string | null>(null);
  let plaintextB64 = $state<string | null>(null);
  let showAsText = $state(true);

  // decoded renders the plaintext as UTF-8 when it is valid; binary output
  // stays on the base64 view so it is never silently mangled.
  const decoded = $derived.by(() => {
    if (plaintextB64 === null) return null;
    try {
      return b64ToText(plaintextB64);
    } catch {
      return null;
    }
  });

  async function run(): Promise<void> {
    for (const [label, value] of [
      ["Ciphertext", ciphertext],
      ["Nonce", nonce],
      ["Tag", tag],
      ["Additional authenticated data", aad],
    ] as const) {
      if (value !== "" && !isB64(value)) {
        err = `${label} is not valid base64.`;
        return;
      }
    }
    if (ciphertext.trim() === "") {
      err = "Ciphertext is required.";
      return;
    }

    busy = true;
    err = null;
    plaintextB64 = null;
    try {
      const resp = await getSDKClient().keys.decrypt(keyInfo.key_id, {
        backend: keyInfo.backend,
        ciphertext: ciphertext.trim(),
        ...(nonce !== "" ? { nonce: nonce.trim() } : {}),
        ...(tag !== "" ? { tag: tag.trim() } : {}),
        ...(aad !== "" ? { additional_data: aad.trim() } : {}),
        ...(mode !== "" ? { mode } : {}),
        ...(tagSize !== undefined ? { tag_size: tagSize } : {}),
      });
      plaintextB64 = resp.plaintext;
    } catch (e) {
      err = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  async function copy(): Promise<void> {
    if (plaintextB64 === null) return;
    try {
      await navigator.clipboard.writeText(showAsText && decoded !== null ? decoded : plaintextB64);
      showToast("success", "Plaintext copied.");
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    }
  }
</script>

<div class="space-y-3">
  <p class="text-xs text-base-content/60">
    AEAD decryption on the server. Authentication is part of the operation: a
    wrong tag, nonce, or additional data fails the request rather than
    returning garbage plaintext.
  </p>

  <label class="form-control">
    <span class="label-text">Ciphertext (base64)</span>
    <textarea class="textarea textarea-bordered font-mono text-xs" rows="3" bind:value={ciphertext}></textarea>
    {#if ciphertext !== "" && !isB64(ciphertext)}
      <span class="label-text-alt text-error">not valid base64</span>
    {/if}
  </label>

  <div class="grid grid-cols-2 gap-3">
    <label class="form-control">
      <span class="label-text">Nonce (base64)</span>
      <input class="input input-bordered input-sm font-mono text-xs" bind:value={nonce} />
      {#if nonce !== "" && isB64(nonce)}
        <span class="label-text-alt">{b64Bytes(nonce)} bytes</span>
      {/if}
    </label>
    <label class="form-control">
      <span class="label-text">Tag (base64)</span>
      <input class="input input-bordered input-sm font-mono text-xs" bind:value={tag} />
      {#if tag !== "" && isB64(tag)}
        <span class="label-text-alt">{b64Bytes(tag)} bytes</span>
      {/if}
    </label>
  </div>

  <label class="form-control">
    <span class="label-text">Additional authenticated data (base64, optional)</span>
    <input class="input input-bordered input-sm font-mono text-xs" bind:value={aad} />
  </label>

  <div class="grid grid-cols-2 gap-3">
    <label class="form-control">
      <span class="label-text">Mode</span>
      <select class="select select-bordered select-sm" bind:value={mode}>
        <option value="">Backend default</option>
        <option value="gcm">gcm</option>
        <option value="cbc">cbc</option>
        <option value="ctr">ctr</option>
      </select>
    </label>
    <label class="form-control">
      <span class="label-text">Tag size (bits)</span>
      <input type="number" class="input input-bordered input-sm" placeholder="default" bind:value={tagSize} />
    </label>
  </div>

  <button class="btn btn-primary btn-sm" onclick={run} disabled={busy}>
    {busy ? "Decrypting…" : "Decrypt"}
  </button>

  {#if err}<Alert kind="error"><span>{err}</span></Alert>{/if}

  {#if plaintextB64 !== null}
    <div>
      <div class="flex items-center justify-between mb-1">
        <span class="text-xs uppercase text-base-content/60">Plaintext</span>
        <div class="flex gap-1">
          {#if decoded !== null}
            <button class="btn btn-ghost btn-xs" onclick={() => (showAsText = !showAsText)}>
              {showAsText ? "Show base64" : "Show text"}
            </button>
          {/if}
          <button class="btn btn-ghost btn-xs" onclick={copy}>Copy</button>
        </div>
      </div>
      <pre class="bg-base-200 rounded p-2 text-xs overflow-x-auto break-all whitespace-pre-wrap">{showAsText && decoded !== null ? decoded : plaintextB64}</pre>
    </div>
  {/if}
</div>
