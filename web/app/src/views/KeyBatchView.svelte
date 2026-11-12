<script lang="ts">
  import PageHeader from "$components/PageHeader.svelte";
  import StatusBadge from "$components/StatusBadge.svelte";
  import Alert from "$components/Alert.svelte";
  import { showToast } from "$stores/toast.svelte.ts";
  import { b64ToBytes, isB64, textToB64 } from "$lib/b64.ts";
  import {
    MAX_BATCH_ITEMS,
    decryptBatch,
    encryptBatch,
    type DecryptBatchItem,
    type DecryptBatchResult,
    type EncryptBatchItem,
    type EncryptBatchResult,
  } from "$lib/keyBatch.ts";

  type Mode = "encrypt" | "decrypt";

  interface Row {
    plaintext: string;
    ciphertext: string;
    nonce: string;
    tag: string;
    aad: string;
    keyVersion: string;
  }

  function emptyRow(): Row {
    return { plaintext: "", ciphertext: "", nonce: "", tag: "", aad: "", keyVersion: "" };
  }

  let keyId = $state("");
  let backend = $state("");
  let mode = $state<Mode>("encrypt");
  let rows = $state<Row[]>([emptyRow()]);
  let busy = $state(false);
  let error = $state<string | null>(null);
  let encResults = $state<EncryptBatchResult[] | null>(null);
  let decResults = $state<DecryptBatchResult[] | null>(null);

  // Optional base64 fields may be empty; required ones may not.
  function b64Ok(s: string, required: boolean): boolean {
    return s.trim() === "" ? !required : isB64(s);
  }

  function versionOk(s: string): boolean {
    return s.trim() === "" || /^\d+$/.test(s.trim());
  }

  function rowValid(r: Row): boolean {
    if (mode === "encrypt") return r.plaintext !== "";
    return b64Ok(r.ciphertext, true) && b64Ok(r.nonce, false) && b64Ok(r.tag, false) && versionOk(r.keyVersion);
  }

  const canRun = $derived(
    !busy && keyId.trim() !== "" && backend.trim() !== "" && rows.length > 0 && rows.every(rowValid),
  );

  function setMode(m: Mode): void {
    mode = m;
    encResults = null;
    decResults = null;
    error = null;
  }

  function addRow(): void {
    if (rows.length < MAX_BATCH_ITEMS) rows.push(emptyRow());
  }

  function removeRow(i: number): void {
    rows.splice(i, 1);
  }

  function encItem(r: Row): EncryptBatchItem {
    const item: EncryptBatchItem = { plaintext: textToB64(r.plaintext) };
    if (r.aad !== "") item.additional_data = textToB64(r.aad);
    return item;
  }

  function decItem(r: Row): DecryptBatchItem {
    const item: DecryptBatchItem = { ciphertext: r.ciphertext.trim() };
    if (r.aad !== "") item.additional_data = textToB64(r.aad);
    if (r.nonce.trim() !== "") item.nonce = r.nonce.trim();
    if (r.tag.trim() !== "") item.tag = r.tag.trim();
    if (r.keyVersion.trim() !== "") item.key_version = Number(r.keyVersion.trim());
    return item;
  }

  async function run(): Promise<void> {
    busy = true;
    error = null;
    encResults = null;
    decResults = null;
    try {
      if (mode === "encrypt") {
        encResults = (await encryptBatch(keyId.trim(), backend.trim(), rows.map(encItem))).results;
      } else {
        decResults = (await decryptBatch(keyId.trim(), backend.trim(), rows.map(decItem))).results;
      }
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  // Shows decrypted bytes as text when they are valid UTF-8, else as base64.
  function plaintextView(b64: string): { text: string; isText: boolean } {
    try {
      return { text: new TextDecoder("utf-8", { fatal: true }).decode(b64ToBytes(b64)), isText: true };
    } catch {
      return { text: b64, isText: false };
    }
  }

  async function copyJSON(): Promise<void> {
    const data = mode === "encrypt" ? encResults : decResults;
    try {
      await navigator.clipboard.writeText(JSON.stringify({ results: data }, null, 2));
      showToast("success", "Results copied as JSON.");
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    }
  }

  const encFields = ["ciphertext", "nonce", "tag", "iv", "gcm_nonce_mode"] as const;
</script>

<PageHeader title="Batch Crypto" subtitle="Encrypt or decrypt up to 100 items under one key; each item succeeds or fails on its own." />

<div class="card bg-base-100 shadow-sm mb-4">
  <div class="card-body gap-3">
    <div class="flex flex-wrap gap-3 items-end">
      <label class="form-control">
        <span class="label-text">Key ID</span>
        <input class="input input-bordered input-sm" aria-label="Key ID" bind:value={keyId} />
      </label>
      <label class="form-control">
        <span class="label-text">Backend</span>
        <input class="input input-bordered input-sm" aria-label="Backend" placeholder="software" bind:value={backend} />
      </label>
      <div class="join" role="group" aria-label="Mode">
        <button class="btn btn-sm join-item" class:btn-active={mode === "encrypt"} aria-pressed={mode === "encrypt"} onclick={() => setMode("encrypt")}>Encrypt</button>
        <button class="btn btn-sm join-item" class:btn-active={mode === "decrypt"} aria-pressed={mode === "decrypt"} onclick={() => setMode("decrypt")}>Decrypt</button>
      </div>
    </div>
  </div>
</div>

<div class="overflow-x-auto mb-3">
  <table class="table table-sm">
    <caption class="sr-only">Items</caption>
    <thead>
      <tr>
        <th scope="col">#</th>
        {#if mode === "encrypt"}
          <th scope="col">Plaintext</th>
        {:else}
          <th scope="col">Ciphertext</th><th scope="col">Nonce</th><th scope="col">Tag</th><th scope="col">Key version</th>
        {/if}
        <th scope="col">Additional data</th>
        <th scope="col"><span class="sr-only">Actions</span></th>
      </tr>
    </thead>
    <tbody>
      {#each rows as row, i (i)}
        <tr>
          <td>{i + 1}</td>
          {#if mode === "encrypt"}
            <td><textarea class="textarea textarea-bordered textarea-sm w-full" rows="1" aria-label={`Plaintext ${i + 1}`} bind:value={row.plaintext}></textarea></td>
          {:else}
            <td><input class="input input-bordered input-sm w-full font-mono" aria-label={`Ciphertext ${i + 1}`} aria-invalid={row.ciphertext !== "" && !b64Ok(row.ciphertext, true)} bind:value={row.ciphertext} /></td>
            <td><input class="input input-bordered input-sm w-full font-mono" aria-label={`Nonce ${i + 1}`} aria-invalid={!b64Ok(row.nonce, false)} bind:value={row.nonce} /></td>
            <td><input class="input input-bordered input-sm w-full font-mono" aria-label={`Tag ${i + 1}`} aria-invalid={!b64Ok(row.tag, false)} bind:value={row.tag} /></td>
            <td><input class="input input-bordered input-sm w-20" inputmode="numeric" aria-label={`Key version ${i + 1}`} aria-invalid={!versionOk(row.keyVersion)} bind:value={row.keyVersion} /></td>
          {/if}
          <td><input class="input input-bordered input-sm w-full" aria-label={`Additional data ${i + 1}`} bind:value={row.aad} /></td>
          <td class="text-right">
            <button class="btn btn-ghost btn-xs text-error" aria-label={`Remove row ${i + 1}`} onclick={() => removeRow(i)}>Remove</button>
          </td>
        </tr>
      {/each}
      {#if rows.length === 0}
        <tr><td colspan="7" class="text-center text-base-content/60 py-6">No items. Add a row.</td></tr>
      {/if}
    </tbody>
  </table>
</div>

<div class="flex gap-2 mb-4">
  <button class="btn btn-sm" onclick={addRow} disabled={rows.length >= MAX_BATCH_ITEMS}>Add row</button>
  <button class="btn btn-primary btn-sm" onclick={run} disabled={!canRun}>
    {#if busy}<span class="loading loading-spinner loading-xs"></span>{/if}Run
  </button>
  <span class="text-sm text-base-content/60 self-center">{rows.length} / {MAX_BATCH_ITEMS} items</span>
</div>

{#if error}
  <Alert kind="error" class="mb-3"><span>{error}</span></Alert>
{/if}

{#if encResults || decResults}
  <div class="flex justify-end mb-2">
    <button class="btn btn-ghost btn-xs" onclick={copyJSON}>Copy as JSON</button>
  </div>
  <div class="overflow-x-auto">
    <table class="table table-sm">
      <caption class="sr-only">Results</caption>
      <thead>
        <tr><th scope="col">#</th><th scope="col">Status</th><th scope="col">Result</th><th scope="col">Key version</th></tr>
      </thead>
      <tbody>
        {#if encResults}
          {#each encResults as r, i (i)}
            <tr>
              <td>{i + 1}</td>
              <td><StatusBadge label={r.error ? "error" : "ok"} ok={!r.error} /></td>
              <td>
                {#if r.error}
                  <span class="text-error">{r.error}</span>
                {:else if r.result}
                  {#each encFields as f (f)}
                    {#if r.result[f]}
                      <div><span class="text-base-content/60">{f}</span> <code class="break-all">{r.result[f]}</code></div>
                    {/if}
                  {/each}
                {/if}
              </td>
              <td>{r.result?.key_version ?? ""}</td>
            </tr>
          {/each}
        {:else if decResults}
          {#each decResults as r, i (i)}
            <tr>
              <td>{i + 1}</td>
              <td><StatusBadge label={r.error ? "error" : "ok"} ok={!r.error} /></td>
              <td>
                {#if r.error}
                  <span class="text-error">{r.error}</span>
                {:else if r.plaintext !== undefined}
                  {@const pv = plaintextView(r.plaintext)}
                  {#if pv.isText}
                    <code class="break-all">{pv.text}</code>
                  {:else}
                    <span class="text-base-content/60">base64</span> <code class="break-all">{pv.text}</code>
                  {/if}
                {/if}
              </td>
              <td>{r.key_version ?? ""}</td>
            </tr>
          {/each}
        {/if}
      </tbody>
    </table>
  </div>
{/if}
