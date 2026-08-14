<script lang="ts">
  // ECDH key agreement. The server multiplies this key's private half by the
  // peer's public point and runs the result through a KDF; the private scalar
  // never leaves the backend, which is the whole reason to do agreement here
  // rather than in the browser's WebCrypto.
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import { isB64, b64Bytes, randomB64, textToB64 } from "$lib/b64.ts";
  import Alert from "$components/Alert.svelte";
  import type { KeyInfo } from "@go-xkms/sdk";

  interface Props {
    keyInfo: KeyInfo;
  }
  let { keyInfo }: Props = $props();

  let peerKey = $state("");
  let kdf = $state("hkdf");
  let kdfHash = $state("sha256");
  let salt = $state("");
  let info = $state("");
  let infoIsText = $state(true);
  let keyLength = $state<number | undefined>(32);

  let busy = $state(false);
  let err = $state<string | null>(null);
  let derived = $state<string | null>(null);

  // PEM is what every other part of this console shows for a public key, so
  // accept it and convert rather than making the operator strip the armor by
  // hand. The API field is raw base64 DER.
  function normalizePeer(input: string): string | null {
    const trimmed = input.trim();
    if (trimmed === "") return null;
    if (trimmed.includes("-----BEGIN")) {
      const body = trimmed
        .replace(/-----BEGIN [^-]+-----/g, "")
        .replace(/-----END [^-]+-----/g, "")
        .replace(/\s+/g, "");
      return isB64(body) ? body : null;
    }
    return isB64(trimmed) ? trimmed : null;
  }

  async function run(): Promise<void> {
    const peer = normalizePeer(peerKey);
    if (peer === null) {
      err = "Peer public key must be PEM or base64 DER.";
      return;
    }
    if (salt !== "" && !isB64(salt)) {
      err = "Salt is not valid base64.";
      return;
    }
    const infoB64 = info === "" ? "" : infoIsText ? textToB64(info) : info.trim();
    if (infoB64 !== "" && !isB64(infoB64)) {
      err = "Info is not valid base64.";
      return;
    }

    busy = true;
    err = null;
    derived = null;
    try {
      const resp = await getSDKClient().keys.deriveECDH({
        key_id: keyInfo.key_id,
        backend: keyInfo.backend,
        peer_public_key: peer,
        kdf_algorithm: kdf,
        kdf_hash: kdfHash,
        ...(salt !== "" ? { kdf_salt: salt.trim() } : {}),
        ...(infoB64 !== "" ? { kdf_info: infoB64 } : {}),
        ...(keyLength !== undefined ? { key_length: keyLength } : {}),
      });
      derived = resp.derived_key;
    } catch (e) {
      err = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  async function copy(): Promise<void> {
    if (derived === null) return;
    try {
      await navigator.clipboard.writeText(derived);
      showToast("success", "Derived key copied.");
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    }
  }
</script>

<div class="space-y-3">
  {#if keyInfo.key_type !== "ecdsa"}
    <Alert kind="warning">
      <span>
        ECDH requires an EC key. <span class="font-mono">{keyInfo.key_id}</span>
        is {keyInfo.key_type}; the backend will reject this request.
      </span>
    </Alert>
  {/if}

  <p class="text-xs text-base-content/60">
    Derives a shared secret from this key and a peer's public key, then runs it
    through a KDF. The raw shared point is never returned — only the derived
    key.
  </p>

  <label class="form-control">
    <span class="label-text">Peer public key (PEM or base64 DER)</span>
    <textarea class="textarea textarea-bordered font-mono text-xs" rows="4" bind:value={peerKey}></textarea>
  </label>

  <div class="grid grid-cols-3 gap-3">
    <label class="form-control">
      <span class="label-text">KDF</span>
      <select class="select select-bordered select-sm" bind:value={kdf}>
        <option>hkdf</option><option>x963</option><option>concat</option>
      </select>
    </label>
    <label class="form-control">
      <span class="label-text">Hash</span>
      <select class="select select-bordered select-sm" bind:value={kdfHash}>
        <option>sha256</option><option>sha384</option><option>sha512</option>
      </select>
    </label>
    <label class="form-control">
      <span class="label-text">Length (bytes)</span>
      <input type="number" class="input input-bordered input-sm" bind:value={keyLength} />
    </label>
  </div>

  <div class="form-control">
    <div class="flex items-center justify-between">
      <label class="label-text" for="derive-salt">Salt (base64, optional)</label>
      <button class="btn btn-ghost btn-xs" onclick={() => (salt = randomB64(32))}>Generate 32 bytes</button>
    </div>
    <input id="derive-salt" class="input input-bordered input-sm font-mono text-xs" bind:value={salt} />
    {#if salt !== "" && isB64(salt)}
      <span class="label-text-alt">{b64Bytes(salt)} bytes</span>
    {/if}
  </div>

  <div class="form-control">
    <div class="flex items-center justify-between">
      <label class="label-text" for="derive-info">Info / context (optional)</label>
      <button class="btn btn-ghost btn-xs" onclick={() => (infoIsText = !infoIsText)}>
        {infoIsText ? "Enter as base64" : "Enter as text"}
      </button>
    </div>
    <input id="derive-info" class="input input-bordered input-sm font-mono text-xs" bind:value={info} />
    <span class="label-text-alt">
      Binds the derived key to a purpose. Both sides must use the same value.
    </span>
  </div>

  <button class="btn btn-primary btn-sm" onclick={run} disabled={busy}>
    {busy ? "Deriving…" : "Derive shared key"}
  </button>

  {#if err}<Alert kind="error"><span>{err}</span></Alert>{/if}

  {#if derived}
    <div>
      <div class="flex items-center justify-between mb-1">
        <span class="text-xs uppercase text-base-content/60">Derived key · {b64Bytes(derived)} bytes</span>
        <button class="btn btn-ghost btn-xs" onclick={copy}>Copy</button>
      </div>
      <pre class="bg-base-200 rounded p-2 text-xs overflow-x-auto break-all whitespace-pre-wrap">{derived}</pre>
    </div>
  {/if}
</div>
