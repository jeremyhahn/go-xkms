<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import Alert from "$components/Alert.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import type { BackendInfo } from "@go-xkms/sdk";

  const BEGIN = "-----BEGIN CERTIFICATE-----";
  const END = "-----END CERTIFICATE-----";

  let backends = $state<BackendInfo[]>([]);
  let loadError = $state<string | null>(null);

  let keyId = $state("");
  let backend = $state("");
  let certPem = $state("");
  let chainPem = $state("");

  let busy = $state(false);
  let confirming = $state(false);
  let error = $state<string | null>(null);

  /** Splits PEM text into certificate blocks on the END marker. */
  function pemBlocks(text: string): string[] {
    return text
      .split(END)
      .map((part) => part.trim())
      .filter((part) => part.includes(BEGIN))
      .map((part) => `${part.slice(part.indexOf(BEGIN))}\n${END}`);
  }

  const certError = $derived(
    certPem.trim() !== "" && !certPem.includes(BEGIN) ? `Certificate PEM must contain ${BEGIN}.` : null,
  );
  const chainError = $derived(
    chainPem.trim() !== "" && pemBlocks(chainPem).length === 0 ? `Chain PEM must contain ${BEGIN}.` : null,
  );
  const ready = $derived(
    keyId.trim() !== "" && backend !== "" && certPem.includes(BEGIN) && certError === null && chainError === null,
  );

  function message(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
  }

  async function loadBackends(): Promise<void> {
    try {
      backends = (await getSDKClient().backends.list()).backends;
    } catch (e) {
      loadError = message(e);
    }
  }

  async function startImport(): Promise<void> {
    if (!ready) return;
    busy = true;
    error = null;
    try {
      if (await getSDKClient().certs.exists(keyId.trim(), backend)) {
        confirming = true;
        return;
      }
    } catch (e) {
      error = message(e);
      return;
    } finally {
      busy = false;
    }
    await store();
  }

  async function store(): Promise<void> {
    const id = keyId.trim();
    confirming = false;
    busy = true;
    error = null;
    try {
      try {
        await getSDKClient().certs.save(id, backend, { backend, certificate_pem: certPem });
      } catch (e) {
        error = message(e);
        return;
      }
      const chain = pemBlocks(chainPem);
      if (chain.length > 0) {
        try {
          await getSDKClient().certs.saveChain(id, { backend, cert_chain_pem: chain });
        } catch (e) {
          error = `The certificate was stored but the chain was not: ${message(e)}`;
          return;
        }
      }
      showToast("success", `Certificate stored for key "${id}".`);
    } finally {
      busy = false;
    }
  }

  onMount(() => {
    void loadBackends();
  });
</script>

<PageHeader title="Import Certificate" subtitle="Store a PEM certificate and its chain for an existing key" />

{#if loadError}<Alert kind="error" class="mb-3"><span>{loadError}</span></Alert>{/if}
{#if error}<Alert kind="error" class="mb-3"><span>{error}</span></Alert>{/if}

<div class="space-y-3 max-w-2xl">
  <input class="input input-bordered w-full" aria-label="Key ID" placeholder="Key ID" bind:value={keyId} />
  <select class="select select-bordered w-full" aria-label="Backend" bind:value={backend}>
    <option value="">Select a backend</option>
    {#each backends as b (b.id)}
      <option value={b.id}>{b.id}</option>
    {/each}
  </select>
  <textarea
    class="textarea textarea-bordered w-full font-mono"
    aria-label="Certificate PEM"
    placeholder={BEGIN}
    rows="8"
    bind:value={certPem}
  ></textarea>
  {#if certError}<p class="text-error text-sm">{certError}</p>{/if}
  <textarea
    class="textarea textarea-bordered w-full font-mono"
    aria-label="Chain PEM"
    placeholder="Chain PEM (optional, one or more certificates)"
    rows="8"
    bind:value={chainPem}
  ></textarea>
  {#if chainError}<p class="text-error text-sm">{chainError}</p>{/if}

  {#if confirming}
    <Alert kind="warning">
      <span>A certificate already exists for key "{keyId.trim()}". Overwrite it?</span>
    </Alert>
    <div class="flex gap-2">
      <button class="btn btn-ghost" onclick={() => (confirming = false)} disabled={busy}>Cancel</button>
      <button class="btn btn-warning" onclick={store} disabled={busy}>Confirm</button>
    </div>
  {:else}
    <button class="btn btn-primary" onclick={startImport} disabled={busy || !ready}>Import</button>
  {/if}
</div>
