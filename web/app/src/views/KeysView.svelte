<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import DataTable from "$components/DataTable.svelte";
  import KeyDetail from "$components/KeyDetail.svelte";
  import ImportWizard from "$components/keys/ImportWizard.svelte";
  import Modal from "$components/Modal.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { can } from "$stores/session.svelte.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import Alert from "$components/Alert.svelte";
  import type { KeyInfo } from "@go-xkms/sdk";

  let keys = $state<KeyInfo[]>([]);
  let error = $state<string | null>(null);
  let loading = $state(true);
  let selected = $state<KeyInfo | null>(null);
  let showGenerate = $state(false);
  let showImport = $state(false);

  // Generate-dialog form state. key_type is the crypto algorithm per the
  // REST DTO (rsa | ecdsa | ed25519 | symmetric).
  let gKeyId = $state("");
  let gKeyType = $state("ecdsa");
  let gCurve = $state("P-256");
  let gKeySize = $state(2048);
  let gAlgorithm = $state("aes-256-gcm");
  let gExportable = $state(false);
  let gBusy = $state(false);
  let gError = $state<string | null>(null);

  const columns = [
    { key: "key_id", label: "Key ID" },
    { key: "key_type", label: "Type" },
    { key: "algorithm", label: "Algorithm" },
    { key: "backend", label: "Backend" },
  ];

  async function load(): Promise<void> {
    loading = true;
    error = null;
    try {
      const resp = await getSDKClient().keys.list();
      keys = resp.keys;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  async function generate(): Promise<void> {
    gBusy = true;
    gError = null;
    try {
      const req = {
        key_id: gKeyId,
        key_type: gKeyType,
        exportable: gExportable,
        ...(gKeyType === "rsa" ? { key_size: gKeySize } : {}),
        ...(gKeyType === "ecdsa" ? { curve: gCurve } : {}),
        ...(gKeyType === "symmetric" ? { algorithm: gAlgorithm } : {}),
      };
      await getSDKClient().keys.generate(req);
      showToast("success", `Key "${gKeyId}" generated.`);
      showGenerate = false;
      gKeyId = "";
      await load();
    } catch (e) {
      gError = e instanceof Error ? e.message : String(e);
    } finally {
      gBusy = false;
    }
  }

  function rowClick(row: Record<string, unknown>): void {
    const k = keys.find((x) => x.key_id === row.key_id);
    if (k) selected = k;
  }

  // Mount-time load: the view has no reactive inputs, so onMount is both
  // correct and immune to an $effect re-running on unrelated state.
  onMount(() => {
    void load();
  });
</script>

<PageHeader title="Keys" subtitle="Cryptographic keys across all backends">
  {#snippet actions()}
    {#if can("keys", "import")}
      <button class="btn btn-sm" onclick={() => (showImport = true)}>Import</button>
    {/if}
    {#if can("keys", "create")}
      <button class="btn btn-primary btn-sm" onclick={() => (showGenerate = true)}>
        + Generate
      </button>
    {/if}
  {/snippet}
</PageHeader>

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if error}
  <Alert kind="error"><span>{error}</span></Alert>
{:else}
  <div class="cursor-pointer">
    <DataTable
      {columns}
      rows={keys.map((k) => ({ ...k }))}
      emptyMessage="No keys yet. Generate one to get started."
      onRowClick={rowClick}
      caption="Cryptographic keys"
    />
  </div>
{/if}

{#if showGenerate}
  <Modal open={showGenerate} onClose={() => (showGenerate = false)} labelledby="generate-key-title">
      <h3 id="generate-key-title" class="text-lg font-semibold mb-4">Generate key</h3>
      {#if gError}<Alert kind="error" class="mb-3"><span>{gError}</span></Alert>{/if}
      <div class="space-y-3">
        <label class="form-control">
          <span class="label-text">Key ID</span>
          <input class="input input-bordered" bind:value={gKeyId} placeholder="my-key" />
        </label>
        <label class="form-control">
          <span class="label-text">Key type</span>
          <select class="select select-bordered" bind:value={gKeyType}>
            <option value="ecdsa">ecdsa</option>
            <option value="rsa">rsa</option>
            <option value="ed25519">ed25519</option>
            <option value="symmetric">symmetric</option>
          </select>
        </label>
        {#if gKeyType === "ecdsa"}
          <label class="form-control">
            <span class="label-text">Curve</span>
            <select class="select select-bordered" bind:value={gCurve}>
              <option>P-256</option>
              <option>P-384</option>
              <option>P-521</option>
            </select>
          </label>
        {:else if gKeyType === "rsa"}
          <label class="form-control">
            <span class="label-text">Key size</span>
            <input type="number" class="input input-bordered" bind:value={gKeySize} />
          </label>
        {:else if gKeyType === "symmetric"}
          <label class="form-control">
            <span class="label-text">Algorithm</span>
            <select class="select select-bordered" bind:value={gAlgorithm}>
              <option>aes-256-gcm</option>
              <option>aes-192-gcm</option>
              <option>aes-128-gcm</option>
            </select>
          </label>
        {/if}
        <label class="label cursor-pointer justify-start gap-2">
          <input type="checkbox" class="checkbox" bind:checked={gExportable} />
          <span class="label-text">Exportable</span>
        </label>
      </div>
      <div class="modal-action">
        <button class="btn btn-ghost" onclick={() => (showGenerate = false)} disabled={gBusy}>Cancel</button>
        <button class="btn btn-primary" onclick={generate} disabled={gBusy || gKeyId === ""}>
          {#if gBusy}<span class="loading loading-spinner loading-xs"></span>{/if}
          Generate
        </button>
      </div>
  </Modal>
{/if}

{#if showImport}
  <ImportWizard
    onClose={() => (showImport = false)}
    onImported={() => void load()}
  />
{/if}

{#if selected}
  <KeyDetail
    keyInfo={selected}
    allKeys={keys}
    onClose={() => (selected = null)}
    onChanged={() => {
      selected = null;
      void load();
    }}
  />
{/if}
