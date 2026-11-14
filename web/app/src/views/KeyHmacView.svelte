<script lang="ts">
  import PageHeader from "$components/PageHeader.svelte";
  import StatusBadge from "$components/StatusBadge.svelte";
  import Alert from "$components/Alert.svelte";
  import { showToast } from "$stores/toast.svelte.ts";
  import { isB64, textToB64 } from "$lib/b64.ts";
  import { b64ToHex, computeHmac, macToB64, verifyHmac, type GenerateHMACResponse } from "$lib/keyHmac.ts";

  let keyId = $state("");
  let backend = $state("");
  let data = $state("");
  let dataIsB64 = $state(false);
  let hash = $state("");
  let macIn = $state("");

  let computed = $state<GenerateHMACResponse | null>(null);
  let valid = $state<boolean | null>(null);
  let computeErr = $state<string | null>(null);
  let verifyErr = $state<string | null>(null);
  let computing = $state(false);
  let verifying = $state(false);

  const ready = $derived(keyId.trim() !== "" && backend.trim() !== "" && data !== "");
  const macHex = $derived(computed ? b64ToHex(computed.mac) : "");

  function message(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
  }

  // dataB64 returns the data as base64, or null (with the error set) when
  // base64 mode holds invalid input.
  function dataB64(setErr: (m: string) => void): string | null {
    if (!dataIsB64) return textToB64(data);
    if (!isB64(data)) {
      setErr("Data is not valid base64.");
      return null;
    }
    return data.trim();
  }

  async function compute(): Promise<void> {
    computeErr = null;
    computed = null;
    const d = dataB64((m) => (computeErr = m));
    if (d === null) return;
    computing = true;
    try {
      computed = await computeHmac(keyId.trim(), backend.trim(), d, hash || undefined);
    } catch (e) {
      computeErr = message(e);
    } finally {
      computing = false;
    }
  }

  async function verify(): Promise<void> {
    verifyErr = null;
    valid = null;
    const d = dataB64((m) => (verifyErr = m));
    if (d === null) return;
    const mac = macToB64(macIn);
    if (mac === null) {
      verifyErr = "MAC must be hex or base64.";
      return;
    }
    verifying = true;
    try {
      valid = (await verifyHmac(keyId.trim(), backend.trim(), d, mac, hash || undefined)).valid;
    } catch (e) {
      verifyErr = message(e);
    } finally {
      verifying = false;
    }
  }

  async function copy(text: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(text);
      showToast("success", "MAC copied.");
    } catch (e) {
      showToast("error", message(e));
    }
  }
</script>

<PageHeader title="HMAC" subtitle="Compute and verify a MAC with a stored HMAC key" />

<div class="card bg-base-100 shadow-sm mb-4">
  <div class="card-body space-y-3">
    <div class="grid gap-3 md:grid-cols-3">
      <input class="input input-bordered w-full" aria-label="Key ID" placeholder="Key ID" bind:value={keyId} />
      <input class="input input-bordered w-full" aria-label="Backend" placeholder="Backend" bind:value={backend} />
      <select class="select select-bordered w-full" aria-label="Hash" bind:value={hash}>
        <option value="">Server default</option>
        <option value="sha256">sha256</option>
        <option value="sha384">sha384</option>
        <option value="sha512">sha512</option>
      </select>
    </div>
    <textarea class="textarea textarea-bordered w-full font-mono" aria-label="Data" placeholder="Data" rows="4" bind:value={data}></textarea>
    <label class="label cursor-pointer justify-start gap-2">
      <input type="checkbox" class="checkbox checkbox-sm" bind:checked={dataIsB64} />
      <span class="label-text">Data is base64</span>
    </label>
  </div>
</div>

<div class="grid gap-4 lg:grid-cols-2">
  <div class="card bg-base-100 shadow-sm">
    <div class="card-body space-y-3">
      <h2 class="card-title">Compute</h2>
      {#if computeErr}<Alert kind="error"><span>{computeErr}</span></Alert>{/if}
      <button class="btn btn-primary" onclick={compute} disabled={!ready || computing}>
        {#if computing}<span class="loading loading-spinner loading-xs"></span>{/if}Compute
      </button>
      {#if computed}
        <dl class="text-sm space-y-1">
          <div><dt class="font-semibold">Hex</dt><dd class="font-mono break-all">{macHex}</dd></div>
          <div><dt class="font-semibold">Base64</dt><dd class="font-mono break-all">{computed.mac}</dd></div>
          <div><dt class="font-semibold">Hash</dt><dd data-testid="hmac-hash">{computed.hash}</dd></div>
          {#if computed.key_version !== undefined}
            <div><dt class="font-semibold">Key version</dt><dd data-testid="hmac-version">{computed.key_version}</dd></div>
          {/if}
        </dl>
        <button class="btn btn-ghost btn-sm" onclick={() => copy(computed?.mac ?? "")}>Copy MAC</button>
      {/if}
    </div>
  </div>

  <div class="card bg-base-100 shadow-sm">
    <div class="card-body space-y-3">
      <h2 class="card-title">Verify</h2>
      {#if verifyErr}<Alert kind="error"><span>{verifyErr}</span></Alert>{/if}
      <input class="input input-bordered w-full font-mono" aria-label="MAC" placeholder="MAC (hex or base64)" bind:value={macIn} />
      <button class="btn btn-primary" onclick={verify} disabled={!ready || macIn.trim() === "" || verifying}>
        {#if verifying}<span class="loading loading-spinner loading-xs"></span>{/if}Verify
      </button>
      {#if valid !== null}
        <div><StatusBadge label={valid ? "valid" : "invalid"} ok={valid} /></div>
      {/if}
    </div>
  </div>
</div>
