<script lang="ts">
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { can } from "$stores/session.svelte.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import { textToB64, randomB64 } from "$lib/b64.ts";
  import Alert from "$components/Alert.svelte";
  import { drawerA11y } from "$components/Modal.svelte";
  import EncryptPanel from "$components/keys/EncryptPanel.svelte";
  import DecryptPanel from "$components/keys/DecryptPanel.svelte";
  import WrapPanel from "$components/keys/WrapPanel.svelte";
  import DerivePanel from "$components/keys/DerivePanel.svelte";
  import TransferPanel from "$components/keys/TransferPanel.svelte";
  import type { KeyInfo } from "@go-xkms/sdk";

  interface Props {
    keyInfo: KeyInfo;
    /** Every visible key — the wrap panel needs them for its target picker. */
    allKeys: KeyInfo[];
    onClose: () => void;
    onChanged: () => void;
  }
  let { keyInfo, allKeys, onClose, onChanged }: Props = $props();

  type Tab =
    | "overview"
    | "sign"
    | "verify"
    | "encrypt"
    | "decrypt"
    | "wrap"
    | "derive"
    | "transfer"
    | "advanced";
  let tab = $state<Tab>("overview");

  // Decryption is symmetric-only: encrypt-asym is one-way by design, and the
  // private half of an asymmetric key is used through sign and unwrap, both of
  // which are separately authorized.
  const symmetric = $derived(keyInfo.key_type === "symmetric");

  // Sign panel.
  let signData = $state("");
  let signHash = $state("sha256");
  let signResult = $state<string | null>(null);
  let signBusy = $state(false);
  let signErr = $state<string | null>(null);

  async function doSign(): Promise<void> {
    signBusy = true;
    signErr = null;
    signResult = null;
    try {
      const resp = await getSDKClient().keys.sign(keyInfo.key_id, {
        backend: keyInfo.backend,
        data: textToB64(signData),
        hash: signHash,
      });
      signResult = resp.signature;
    } catch (e) {
      signErr = e instanceof Error ? e.message : String(e);
    } finally {
      signBusy = false;
    }
  }

  // Verify panel.
  let verifyData = $state("");
  let verifySig = $state("");
  let verifyHash = $state("sha256");
  let verifyResult = $state<boolean | null>(null);
  let verifyBusy = $state(false);
  let verifyErr = $state<string | null>(null);

  async function doVerify(): Promise<void> {
    verifyBusy = true;
    verifyErr = null;
    verifyResult = null;
    try {
      const resp = await getSDKClient().keys.verify(keyInfo.key_id, {
        backend: keyInfo.backend,
        data: textToB64(verifyData),
        signature: verifySig,
        hash: verifyHash,
      });
      verifyResult = resp.valid;
    } catch (e) {
      verifyErr = e instanceof Error ? e.message : String(e);
    } finally {
      verifyBusy = false;
    }
  }

  // Advanced hardware-capability operations. These mirror the xkmsctl verbs
  // (key attest / export-material); a backend that lacks the capability answers
  // 501, which surfaces here as the error rather than a silent no-op.
  let advBusy = $state(false);
  let advErr = $state<string | null>(null);
  let attestResult = $state<string | null>(null);
  let materialResult = $state<string | null>(null);

  async function attest(): Promise<void> {
    advBusy = true;
    advErr = null;
    attestResult = null;
    try {
      const resp = await getSDKClient().keys.attest({
        backend: keyInfo.backend,
        key_id: keyInfo.key_id,
        nonce: randomB64(32),
      });
      attestResult = JSON.stringify(resp, null, 2);
    } catch (e) {
      advErr = e instanceof Error ? e.message : String(e);
    } finally {
      advBusy = false;
    }
  }

  async function exportMaterial(): Promise<void> {
    advBusy = true;
    advErr = null;
    materialResult = null;
    try {
      const resp = await getSDKClient().keys.exportMaterial(keyInfo.key_id, keyInfo.backend);
      materialResult = resp.key_material;
      showToast("warning", "Raw key material exported — handle it as a secret.");
    } catch (e) {
      advErr = e instanceof Error ? e.message : String(e);
    } finally {
      advBusy = false;
    }
  }

  let opBusy = $state(false);

  async function rotate(): Promise<void> {
    opBusy = true;
    try {
      await getSDKClient().keys.rotate(keyInfo.key_id, keyInfo.backend);
      showToast("success", `Key "${keyInfo.key_id}" rotated.`);
      onChanged();
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    } finally {
      opBusy = false;
    }
  }

  async function del(): Promise<void> {
    opBusy = true;
    try {
      await getSDKClient().keys.delete(keyInfo.key_id, keyInfo.backend);
      showToast("success", `Key "${keyInfo.key_id}" deleted.`);
      onChanged();
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    } finally {
      opBusy = false;
    }
  }
</script>

<div class="drawer drawer-end drawer-open">
  <div class="drawer-side">
    <button class="drawer-overlay" aria-label="Close" onclick={onClose}></button>
    <div
      class="w-full max-w-xl bg-base-100 h-full p-6 overflow-y-auto"
      role="dialog"
      aria-modal="true"
      aria-labelledby="key-detail-title"
      tabindex="-1"
      use:drawerA11y={{ onClose }}
    >
      <div class="flex items-start justify-between mb-4">
        <div>
          <h2 id="key-detail-title" class="text-xl font-semibold">{keyInfo.key_id}</h2>
          <p class="text-sm text-base-content/60">{keyInfo.key_type} · {keyInfo.algorithm} · {keyInfo.backend}</p>
        </div>
        <button class="btn btn-ghost btn-sm btn-square" aria-label="Close" onclick={onClose}>✕</button>
      </div>

      <div role="tablist" class="tabs tabs-bordered mb-4">
        <button role="tab" class="tab" class:tab-active={tab === "overview"} onclick={() => (tab = "overview")}>Overview</button>
        {#if can("keys", "sign")}
          <button role="tab" class="tab" class:tab-active={tab === "sign"} onclick={() => (tab = "sign")}>Sign</button>
        {/if}
        {#if can("keys", "verify")}
          <button role="tab" class="tab" class:tab-active={tab === "verify"} onclick={() => (tab = "verify")}>Verify</button>
        {/if}
        {#if can("keys", "encrypt")}
          <button role="tab" class="tab" class:tab-active={tab === "encrypt"} onclick={() => (tab = "encrypt")}>Encrypt</button>
        {/if}
        {#if symmetric && can("keys", "decrypt")}
          <button role="tab" class="tab" class:tab-active={tab === "decrypt"} onclick={() => (tab = "decrypt")}>Decrypt</button>
        {/if}
        {#if can("keys", "wrap")}
          <button role="tab" class="tab" class:tab-active={tab === "wrap"} onclick={() => (tab = "wrap")}>Wrap</button>
        {/if}
        {#if can("keys", "derive")}
          <button role="tab" class="tab" class:tab-active={tab === "derive"} onclick={() => (tab = "derive")}>Derive</button>
        {/if}
        <button role="tab" class="tab" class:tab-active={tab === "transfer"} onclick={() => (tab = "transfer")}>Transfer</button>
        <button role="tab" class="tab" class:tab-active={tab === "advanced"} onclick={() => (tab = "advanced")}>Advanced</button>
      </div>

      {#if tab === "overview"}
        {#if keyInfo.public_key_pem}
          <div class="mb-4">
            <div class="text-xs uppercase text-base-content/60 mb-1">Public key</div>
            <pre class="bg-base-200 rounded p-2 text-xs overflow-x-auto">{keyInfo.public_key_pem}</pre>
          </div>
        {/if}
        <div class="flex gap-2">
          {#if can("keys", "rotate")}
            <button class="btn btn-sm" onclick={rotate} disabled={opBusy}>Rotate</button>
          {/if}
          {#if can("keys", "delete")}
            <button class="btn btn-sm btn-error btn-outline" onclick={del} disabled={opBusy}>Delete</button>
          {/if}
        </div>
      {:else if tab === "sign"}
        <div class="space-y-3">
          <label class="form-control">
            <span class="label-text">Message</span>
            <textarea class="textarea textarea-bordered" bind:value={signData} rows="3"></textarea>
          </label>
          <label class="form-control">
            <span class="label-text">Hash</span>
            <select class="select select-bordered" bind:value={signHash}>
              <option>sha256</option><option>sha384</option><option>sha512</option>
            </select>
          </label>
          <button class="btn btn-primary btn-sm" onclick={doSign} disabled={signBusy}>Sign</button>
          {#if signErr}<Alert kind="error"><span>{signErr}</span></Alert>{/if}
          {#if signResult}
            <div>
              <div class="text-xs uppercase text-base-content/60 mb-1">Signature (base64)</div>
              <pre class="bg-base-200 rounded p-2 text-xs overflow-x-auto break-all">{signResult}</pre>
            </div>
          {/if}
        </div>
      {:else if tab === "verify"}
        <div class="space-y-3">
          <label class="form-control">
            <span class="label-text">Message</span>
            <textarea class="textarea textarea-bordered" bind:value={verifyData} rows="2"></textarea>
          </label>
          <label class="form-control">
            <span class="label-text">Signature (base64)</span>
            <textarea class="textarea textarea-bordered" bind:value={verifySig} rows="2"></textarea>
          </label>
          <label class="form-control">
            <span class="label-text">Hash</span>
            <select class="select select-bordered" bind:value={verifyHash}>
              <option>sha256</option><option>sha384</option><option>sha512</option>
            </select>
          </label>
          <button class="btn btn-primary btn-sm" onclick={doVerify} disabled={verifyBusy}>Verify</button>
          {#if verifyErr}<Alert kind="error"><span>{verifyErr}</span></Alert>{/if}
          {#if verifyResult !== null}
            <Alert kind={verifyResult ? "success" : "error"}>
              <span>{verifyResult ? "Signature is valid." : "Signature is NOT valid."}</span>
            </Alert>
          {/if}
        </div>
      {:else if tab === "encrypt"}
        <EncryptPanel {keyInfo} />
      {:else if tab === "decrypt"}
        <DecryptPanel {keyInfo} />
      {:else if tab === "wrap"}
        <WrapPanel {keyInfo} {allKeys} {onChanged} />
      {:else if tab === "derive"}
        <DerivePanel {keyInfo} />
      {:else if tab === "transfer"}
        <TransferPanel {keyInfo} {onChanged} />
      {:else if tab === "advanced"}
        <div class="space-y-4">
          {#if advErr}<Alert kind="error"><span>{advErr}</span></Alert>{/if}

          <div>
            <h3 class="font-medium text-sm">Attestation</h3>
            <p class="text-xs text-base-content/60 mb-2">
              Ask the backend to prove this key was created in hardware and never
              left it. A fresh 32-byte nonce is generated per request.
            </p>
            <button class="btn btn-sm" onclick={attest} disabled={advBusy}>Request attestation</button>
            {#if attestResult}
              <pre class="bg-base-200 rounded p-2 text-xs overflow-x-auto mt-2 max-h-64">{attestResult}</pre>
            {/if}
          </div>

          {#if can("keys", "export")}
            <div>
              <h3 class="font-medium text-sm">Export raw key material</h3>
              <p class="text-xs text-base-content/60 mb-2">
                Returns the plaintext symmetric key. Only exportable keys on
                capable backends allow this; prefer wrapped export for transfer.
              </p>
              <button class="btn btn-sm btn-warning btn-outline" onclick={exportMaterial} disabled={advBusy}>
                Export material
              </button>
              {#if materialResult}
                <pre class="bg-base-200 rounded p-2 text-xs overflow-x-auto mt-2 break-all">{materialResult}</pre>
              {/if}
            </div>
          {/if}

        </div>
      {/if}
    </div>
  </div>
</div>
