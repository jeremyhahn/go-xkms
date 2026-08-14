<script lang="ts">
  // Bring-your-own-key import. This is the cloud-KMS import ceremony, which is
  // three server round trips in a fixed order, so it is a wizard rather than a
  // form: the backend issues a wrapping public key and a single-use import
  // token, the material is wrapped under that key, and only the wrapped blob
  // is installed. Plaintext key material never has to reach this browser at
  // all when the operator already holds a wrapped blob from elsewhere.
  import { onMount } from "svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import { isB64, b64Bytes, bytesToB64 } from "$lib/b64.ts";
  import Modal from "$components/Modal.svelte";
  import Alert from "$components/Alert.svelte";
  import type { BackendInfo, GetImportParametersResponse } from "@go-xkms/sdk";

  interface Props {
    onClose: () => void;
    onImported: () => void;
  }
  let { onClose, onImported }: Props = $props();

  const algorithms = [
    "RSAES_OAEP_SHA_256",
    "RSAES_OAEP_SHA_1",
    "AES_KEY_WRAP",
    "AES_KEY_WRAP_PAD",
  ] as const;

  type Step = 1 | 2 | 3;
  let step = $state<Step>(1);

  let backends = $state<BackendInfo[]>([]);

  // Step 1 — describe the key slot the material will land in.
  let backend = $state("");
  let keyId = $state("");
  let keyType = $state("symmetric");
  let algorithm = $state<string>(algorithms[0]);
  let keySize = $state<number | undefined>(undefined);
  let curve = $state("");
  let aesKeySize = $state<number | undefined>(256);

  // Step 2 — the parameters the backend issued.
  let params = $state<GetImportParametersResponse | null>(null);

  // Step 3 — the wrapped material.
  let wrappedKey = $state("");
  let haveWrapped = $state(false);
  let plainMaterial = $state("");

  let busy = $state(false);
  let err = $state<string | null>(null);

  // A one-shot load on mount, not an $effect: the backend list does not depend
  // on any reactive state here, and an $effect would re-run on unrelated
  // changes.
  onMount(async () => {
    try {
      const resp = await getSDKClient().backends.list();
      backends = resp.backends;
      const first = resp.backends[0];
      if (first !== undefined) backend = first.id;
    } catch (e) {
      err = e instanceof Error ? e.message : String(e);
    }
  });

  async function fetchParams(): Promise<void> {
    if (backend === "" || keyId.trim() === "") {
      err = "Backend and key ID are required.";
      return;
    }
    busy = true;
    err = null;
    try {
      params = await getSDKClient().keys.importParams({
        backend,
        key_id: keyId.trim(),
        key_type: keyType,
        algorithm,
        ...(keySize !== undefined ? { key_size: keySize } : {}),
        ...(curve !== "" ? { curve } : {}),
        ...(aesKeySize !== undefined && keyType === "symmetric" ? { aes_key_size: aesKeySize } : {}),
      });
      step = 2;
    } catch (e) {
      err = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  // Wrapping plaintext material server-side means it transits this browser
  // once, in the request body. That is strictly worse than arriving already
  // wrapped, so the wizard says so and defaults to the wrapped path.
  async function wrapPlaintext(): Promise<void> {
    if (params === null) return;
    if (!isB64(plainMaterial)) {
      err = "Key material must be base64.";
      return;
    }
    busy = true;
    err = null;
    try {
      const resp = await getSDKClient().keys.wrap({
        backend,
        key_material: plainMaterial.trim(),
        wrapping_public_key_pem: params.wrapping_public_key_pem,
        algorithm: params.algorithm,
        ...(params.import_token ? { import_token: params.import_token } : {}),
      });
      wrappedKey = resp.wrapped_key;
      haveWrapped = true;
      plainMaterial = "";
      showToast("success", "Material wrapped. Review and import.");
    } catch (e) {
      err = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  async function onWrappedFile(event: Event): Promise<void> {
    const input = event.target as HTMLInputElement;
    const file = input.files?.[0];
    if (!file) return;
    wrappedKey = bytesToB64(new Uint8Array(await file.arrayBuffer()));
    haveWrapped = true;
  }

  async function doImport(): Promise<void> {
    if (params === null) return;
    if (!isB64(wrappedKey)) {
      err = "Wrapped key must be base64.";
      return;
    }
    busy = true;
    err = null;
    try {
      await getSDKClient().keys.import({
        backend,
        key_id: keyId.trim(),
        key_type: keyType,
        wrapped_key: wrappedKey.trim(),
        algorithm: params.algorithm,
        ...(params.import_token ? { import_token: params.import_token } : {}),
        ...(keySize !== undefined ? { key_size: keySize } : {}),
        ...(curve !== "" ? { curve } : {}),
        ...(aesKeySize !== undefined && keyType === "symmetric" ? { aes_key_size: aesKeySize } : {}),
      });
      showToast("success", `Key "${keyId}" imported into ${backend}.`);
      onImported();
      onClose();
    } catch (e) {
      err = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  async function copyPEM(): Promise<void> {
    if (params === null) return;
    try {
      await navigator.clipboard.writeText(params.wrapping_public_key_pem);
      showToast("success", "Wrapping public key copied.");
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    }
  }
</script>

<Modal open={true} onClose={onClose} boxClass="modal-box max-w-2xl" labelledby="import-key-title">
    <h3 id="import-key-title" class="text-lg font-semibold mb-1">Import key</h3>
    <p class="text-sm text-base-content/60 mb-4">
      Install externally generated key material under a wrapping key the
      backend issues.
    </p>

    <ul class="steps w-full mb-5 text-xs">
      <li class="step" class:step-primary={step >= 1}>Describe key</li>
      <li class="step" class:step-primary={step >= 2}>Wrapping parameters</li>
      <li class="step" class:step-primary={step >= 3}>Import</li>
    </ul>

    {#if err}<Alert kind="error" class="mb-3"><span>{err}</span></Alert>{/if}

    {#if step === 1}
      <div class="grid grid-cols-2 gap-3">
        <label class="form-control">
          <span class="label-text">Backend</span>
          <select class="select select-bordered select-sm" bind:value={backend}>
            {#each backends as b (b.id)}
              <option value={b.id}>{b.id} · {b.type}</option>
            {/each}
          </select>
        </label>
        <label class="form-control">
          <span class="label-text">Key ID</span>
          <input class="input input-bordered input-sm" bind:value={keyId} />
        </label>
        <label class="form-control">
          <span class="label-text">Key type</span>
          <select class="select select-bordered select-sm" bind:value={keyType}>
            <option>symmetric</option><option>rsa</option><option>ecdsa</option><option>ed25519</option>
          </select>
        </label>
        <label class="form-control">
          <span class="label-text">Wrapping algorithm</span>
          <select class="select select-bordered select-sm" bind:value={algorithm}>
            {#each algorithms as a (a)}<option>{a}</option>{/each}
          </select>
        </label>
        {#if keyType === "symmetric"}
          <label class="form-control">
            <span class="label-text">AES key size (bits)</span>
            <select class="select select-bordered select-sm" bind:value={aesKeySize}>
              <option value={128}>128</option><option value={192}>192</option><option value={256}>256</option>
            </select>
          </label>
        {:else if keyType === "rsa"}
          <label class="form-control">
            <span class="label-text">Key size (bits)</span>
            <input type="number" class="input input-bordered input-sm" bind:value={keySize} />
          </label>
        {:else if keyType === "ecdsa"}
          <label class="form-control">
            <span class="label-text">Curve</span>
            <select class="select select-bordered select-sm" bind:value={curve}>
              <option value="">Backend default</option>
              <option>P-256</option><option>P-384</option><option>P-521</option>
            </select>
          </label>
        {/if}
      </div>

      <div class="modal-action">
        <button class="btn btn-ghost" onclick={onClose} disabled={busy}>Cancel</button>
        <button class="btn btn-primary" onclick={fetchParams} disabled={busy}>
          {busy ? "Requesting…" : "Get wrapping parameters"}
        </button>
      </div>
    {:else if step === 2 && params}
      <div class="space-y-3">
        <div>
          <div class="flex items-center justify-between mb-1">
            <span class="text-xs uppercase text-base-content/60">Wrapping public key</span>
            <button class="btn btn-ghost btn-xs" onclick={copyPEM}>Copy</button>
          </div>
          <pre class="bg-base-200 rounded p-2 text-xs overflow-x-auto max-h-40">{params.wrapping_public_key_pem}</pre>
        </div>
        <div class="text-xs text-base-content/60">
          Algorithm <span class="font-mono">{params.algorithm}</span>
          {#if params.expires_at}· expires {params.expires_at}{/if}
          {#if params.import_token}· single-use import token issued{/if}
        </div>
        <Alert kind="info" class="text-xs">
          <span>
            Wrap your key material under this public key on the machine that
            holds it, then continue. Only wrap it here if the material is
            already exposed to this browser.
          </span>
        </Alert>
      </div>

      <div class="modal-action">
        <button class="btn btn-ghost" onclick={() => (step = 1)} disabled={busy}>Back</button>
        <button class="btn btn-primary" onclick={() => (step = 3)} disabled={busy}>Continue</button>
      </div>
    {:else if step === 3 && params}
      <div class="space-y-3">
        <label class="form-control">
          <span class="label-text">Wrapped key (base64)</span>
          <textarea class="textarea textarea-bordered font-mono text-xs" rows="4" bind:value={wrappedKey}></textarea>
          {#if wrappedKey !== "" && isB64(wrappedKey)}
            <span class="label-text-alt">{b64Bytes(wrappedKey)} bytes</span>
          {:else if wrappedKey !== ""}
            <span class="label-text-alt text-error">not valid base64</span>
          {/if}
        </label>

        <label class="form-control">
          <span class="label-text">…or load a wrapped blob from a file</span>
          <input type="file" class="file-input file-input-bordered file-input-sm" onchange={onWrappedFile} />
        </label>

        {#if !haveWrapped}
          <div class="collapse collapse-arrow bg-base-200">
            <input type="checkbox" />
            <div class="collapse-title text-sm font-medium">Wrap plaintext material here instead</div>
            <div class="collapse-content space-y-2">
              <p class="text-xs text-base-content/60">
                The material transits this browser and the request body. Prefer
                wrapping on the machine that already holds the key.
              </p>
              <textarea
                class="textarea textarea-bordered font-mono text-xs w-full"
                rows="3"
                aria-label="Key material (base64)"
                placeholder="Key material (base64)"
                bind:value={plainMaterial}
              ></textarea>
              <button class="btn btn-warning btn-outline btn-sm" onclick={wrapPlaintext} disabled={busy || plainMaterial === ""}>
                Wrap material
              </button>
            </div>
          </div>
        {/if}
      </div>

      <div class="modal-action">
        <button class="btn btn-ghost" onclick={() => (step = 2)} disabled={busy}>Back</button>
        <button class="btn btn-primary" onclick={doImport} disabled={busy || wrappedKey === ""}>
          {busy ? "Importing…" : "Import key"}
        </button>
      </div>
    {/if}
</Modal>
