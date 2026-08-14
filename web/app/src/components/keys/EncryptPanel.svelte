<script lang="ts">
  // Encrypt panel. Which of the two REST operations this drives is decided by
  // the key, not by the operator: a symmetric key goes to POST
  // /keys/{id}/encrypt (AEAD, returns nonce + tag), an asymmetric key to
  // /keys/{id}/encrypt-asym (RSA-OAEP, returns ciphertext only). Presenting
  // one "Encrypt" affordance and routing internally keeps the operator from
  // having to know which verb their key supports.
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import { textToB64, bytesToB64, randomB64, isB64, b64Bytes } from "$lib/b64.ts";
  import Alert from "$components/Alert.svelte";
  import type { KeyInfo } from "@go-xkms/sdk";

  interface Props {
    keyInfo: KeyInfo;
  }
  let { keyInfo }: Props = $props();

  const symmetric = $derived(keyInfo.key_type === "symmetric");

  // Input may be typed text or an uploaded file; a file is the only way to
  // encrypt bytes that are not valid UTF-8.
  let inputMode = $state<"text" | "base64" | "file">("text");
  let plainText = $state("");
  let plainB64 = $state("");
  let fileName = $state<string | null>(null);

  // Symmetric options.
  let mode = $state("");
  let aad = $state("");
  let nonce = $state("");
  let tagSize = $state<number | undefined>(undefined);

  // Asymmetric options.
  let hash = $state("sha256");

  let busy = $state(false);
  let err = $state<string | null>(null);
  let result = $state<{
    ciphertext: string;
    nonce?: string;
    tag?: string;
    iv?: string;
  } | null>(null);

  // Only the fields the operation actually returned, so the template never has
  // to reason about an optional inside an {#each}.
  const outputs = $derived.by((): Array<{ label: string; value: string }> => {
    if (result === null) return [];
    const fields: Array<[string, string | undefined]> = [
      ["Ciphertext", result.ciphertext],
      ["Nonce", result.nonce],
      ["Tag", result.tag],
      ["IV", result.iv],
    ];
    return fields
      .filter((f): f is [string, string] => f[1] !== undefined && f[1] !== "")
      .map(([label, value]) => ({ label, value }));
  });

  async function onFile(event: Event): Promise<void> {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;
    fileName = file.name;
    plainB64 = bytesToB64(new Uint8Array(await file.arrayBuffer()));
  }

  // plaintext resolves the three input modes to the single base64 field the
  // API takes. Returns null when the operator's base64 does not parse, so the
  // request is never sent with a malformed body.
  function plaintext(): string | null {
    if (inputMode === "text") return textToB64(plainText);
    if (!isB64(plainB64)) return null;
    return plainB64.trim();
  }

  async function run(): Promise<void> {
    const pt = plaintext();
    if (pt === null) {
      err = "Plaintext is not valid base64.";
      return;
    }
    if (nonce !== "" && !isB64(nonce)) {
      err = "Nonce is not valid base64.";
      return;
    }
    if (aad !== "" && !isB64(aad)) {
      err = "Additional authenticated data is not valid base64.";
      return;
    }

    busy = true;
    err = null;
    result = null;
    try {
      const client = getSDKClient();
      if (symmetric) {
        const resp = await client.keys.encrypt(keyInfo.key_id, {
          backend: keyInfo.backend,
          plaintext: pt,
          ...(mode !== "" ? { mode } : {}),
          ...(aad !== "" ? { additional_data: aad.trim() } : {}),
          ...(nonce !== "" ? { nonce: nonce.trim() } : {}),
          ...(tagSize !== undefined ? { tag_size: tagSize } : {}),
        });
        result = {
          ciphertext: resp.ciphertext,
          nonce: resp.nonce,
          tag: resp.tag,
          iv: resp.iv,
        };
      } else {
        const resp = await client.keys.encryptAsym(keyInfo.key_id, {
          backend: keyInfo.backend,
          plaintext: pt,
          hash,
        });
        result = { ciphertext: resp.ciphertext };
      }
    } catch (e) {
      err = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  async function copy(value: string, label: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(value);
      showToast("success", `${label} copied.`);
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    }
  }
</script>

<div class="space-y-3">
  <p class="text-xs text-base-content/60">
    {#if symmetric}
      AEAD encryption on the server. The nonce and authentication tag come back
      with the ciphertext — <strong>all three</strong> are required to decrypt.
    {:else}
      RSA-OAEP encryption against this key's public half. Plaintext is limited
      by the modulus size; wrap a symmetric key for anything larger.
    {/if}
  </p>

  <div role="tablist" class="tabs tabs-boxed tabs-sm w-fit">
    <button role="tab" class="tab" class:tab-active={inputMode === "text"} onclick={() => (inputMode = "text")}>Text</button>
    <button role="tab" class="tab" class:tab-active={inputMode === "base64"} onclick={() => (inputMode = "base64")}>Base64</button>
    <button role="tab" class="tab" class:tab-active={inputMode === "file"} onclick={() => (inputMode = "file")}>File</button>
  </div>

  {#if inputMode === "text"}
    <label class="form-control">
      <span class="label-text">Plaintext</span>
      <textarea class="textarea textarea-bordered font-mono text-sm" rows="3" bind:value={plainText}></textarea>
    </label>
  {:else if inputMode === "base64"}
    <label class="form-control">
      <span class="label-text">Plaintext (base64)</span>
      <textarea class="textarea textarea-bordered font-mono text-xs" rows="3" bind:value={plainB64}></textarea>
      {#if plainB64 !== ""}
        <span class="label-text-alt {isB64(plainB64) ? '' : 'text-error'}">
          {isB64(plainB64) ? `${b64Bytes(plainB64)} bytes` : "not valid base64"}
        </span>
      {/if}
    </label>
  {:else}
    <label class="form-control">
      <span class="label-text">File</span>
      <input type="file" class="file-input file-input-bordered file-input-sm" onchange={onFile} />
      {#if fileName}
        <span class="label-text-alt">{fileName} · {b64Bytes(plainB64)} bytes</span>
      {/if}
    </label>
  {/if}

  {#if symmetric}
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
    <label class="form-control">
      <span class="label-text">Additional authenticated data (base64, optional)</span>
      <input class="input input-bordered input-sm font-mono text-xs" bind:value={aad} />
    </label>
    <div class="form-control">
      <div class="flex items-center justify-between">
        <label class="label-text" for="encrypt-nonce">Nonce (base64, optional)</label>
        <button class="btn btn-ghost btn-xs" onclick={() => (nonce = randomB64(12))}>Generate 12 bytes</button>
      </div>
      <input id="encrypt-nonce" class="input input-bordered input-sm font-mono text-xs" bind:value={nonce} />
      <span class="label-text-alt">
        Leave empty and the server generates one. Never reuse a nonce with the
        same key.
      </span>
    </div>
  {:else}
    <label class="form-control">
      <span class="label-text">OAEP hash</span>
      <select class="select select-bordered select-sm" bind:value={hash}>
        <option>sha256</option><option>sha384</option><option>sha512</option>
      </select>
    </label>
  {/if}

  <button class="btn btn-primary btn-sm" onclick={run} disabled={busy}>
    {busy ? "Encrypting…" : "Encrypt"}
  </button>

  {#if err}<Alert kind="error"><span>{err}</span></Alert>{/if}

  {#if result}
    <div class="space-y-2">
      {#each outputs as out (out.label)}
        <div>
          <div class="flex items-center justify-between">
            <span class="text-xs uppercase text-base-content/60">{out.label}</span>
            <button class="btn btn-ghost btn-xs" onclick={() => void copy(out.value, out.label)}>Copy</button>
          </div>
          <pre class="bg-base-200 rounded p-2 text-xs overflow-x-auto break-all whitespace-pre-wrap">{out.value}</pre>
        </div>
      {/each}
    </div>
  {/if}
</div>
