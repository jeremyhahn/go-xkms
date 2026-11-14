<script lang="ts">
  import PageHeader from "$components/PageHeader.svelte";
  import Alert from "$components/Alert.svelte";
  import StatusBadge from "$components/StatusBadge.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import type { FrostImportKeyResponse, FrostKeyInfo, FrostKeyPackage } from "@go-xkms/sdk";

  // The pasted package carries the participant's secret share. It lives only
  // in this textarea's state, is cleared after every import attempt and is
  // never put into a toast, an error message or the console.
  let packageText = $state("");
  let importErr = $state<string | null>(null);
  let importing = $state(false);
  let imported = $state<FrostImportKeyResponse | null>(null);

  let lookupId = $state("");
  let lookupErr = $state<string | null>(null);
  let looking = $state(false);
  let details = $state<FrostKeyInfo | null>(null);

  const REQUIRED: Array<[keyof FrostKeyPackage, "string" | "number" | "object"]> = [
    ["key_id", "string"],
    ["algorithm", "string"],
    ["threshold", "number"],
    ["total", "number"],
    ["participant_id", "number"],
    ["secret_share", "string"],
    ["group_public_key", "string"],
    ["verification_shares", "object"],
  ];

  function errMsg(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
  }

  // parsePackage returns the package or an error naming the field; it never
  // echoes a value from the pasted text.
  function parsePackage(text: string): FrostKeyPackage | string {
    let raw: unknown;
    try {
      raw = JSON.parse(text);
    } catch {
      return "Key package is not valid JSON.";
    }
    if (raw === null || typeof raw !== "object" || Array.isArray(raw)) {
      return "Key package must be a JSON object.";
    }
    const obj = raw as Record<string, unknown>;
    for (const [field, kind] of REQUIRED) {
      const v = obj[field];
      if (v === undefined || v === null || typeof v !== kind) {
        return `Key package field ${field} is missing or not a ${kind}.`;
      }
    }
    return obj as unknown as FrostKeyPackage;
  }

  async function doImport(): Promise<void> {
    importErr = null;
    imported = null;
    const parsed = parsePackage(packageText);
    packageText = "";
    if (typeof parsed === "string") {
      importErr = parsed;
      return;
    }
    importing = true;
    try {
      imported = await getSDKClient().frost.importKey({ package: parsed });
      showToast("success", `FROST key "${imported.key_id}" imported.`);
    } catch (e) {
      importErr = errMsg(e);
    } finally {
      importing = false;
    }
  }

  async function doLookup(): Promise<void> {
    lookupErr = null;
    details = null;
    looking = true;
    try {
      details = await getSDKClient().frost.getKey(lookupId.trim());
    } catch (e) {
      lookupErr = errMsg(e);
    } finally {
      looking = false;
    }
  }
</script>

<PageHeader title="FROST Key Import" subtitle="Load a participant's FROST key package and look up a key" />

<section class="card bg-base-100 shadow-sm mb-6">
  <div class="card-body space-y-3">
    <h2 class="card-title text-base">Import key package</h2>
    {#if importErr}<Alert kind="error"><span>{importErr}</span></Alert>{/if}
    <textarea
      class="textarea textarea-bordered w-full font-mono text-xs"
      aria-label="Key package JSON"
      placeholder="Paste the key package JSON from the dealer"
      rows="8"
      autocomplete="off"
      spellcheck="false"
      bind:value={packageText}
    ></textarea>
    <div class="flex justify-end">
      <button class="btn btn-primary btn-sm" onclick={doImport} disabled={importing || packageText.trim() === ""}>
        {#if importing}<span class="loading loading-spinner loading-xs"></span>{/if}
        Import
      </button>
    </div>
    {#if imported}
      <div class="rounded-box border border-base-300 p-3 space-y-1" data-testid="import-result">
        <StatusBadge label="imported" ok={imported.success} />
        <div><span class="text-base-content/60">Key ID:</span> {imported.key_id}</div>
        <div><span class="text-base-content/60">Participant ID:</span> {imported.participant_id}</div>
        <div class="text-base-content/60">Group public key:</div>
        <pre class="font-mono text-xs break-all whitespace-pre-wrap">{imported.group_public_key}</pre>
      </div>
    {/if}
  </div>
</section>

<section class="card bg-base-100 shadow-sm">
  <div class="card-body space-y-3">
    <h2 class="card-title text-base">Look up a key</h2>
    {#if lookupErr}<Alert kind="error"><span>{lookupErr}</span></Alert>{/if}
    <div class="flex gap-2">
      <input class="input input-bordered input-sm flex-1" aria-label="Key ID" placeholder="Key ID" bind:value={lookupId} />
      <button class="btn btn-sm" onclick={doLookup} disabled={looking || lookupId.trim() === ""}>
        {#if looking}<span class="loading loading-spinner loading-xs"></span>{/if}
        Look up
      </button>
    </div>
    {#if details}
      <div class="rounded-box border border-base-300 p-3 space-y-1" data-testid="key-details">
        <div><span class="text-base-content/60">Key ID:</span> {details.key_id}</div>
        <div><span class="text-base-content/60">Algorithm:</span> {details.algorithm}</div>
        <div><span class="text-base-content/60">Threshold:</span> {details.threshold} of {details.total}</div>
        <div><span class="text-base-content/60">Participant ID:</span> {details.participant_id}</div>
        <div><span class="text-base-content/60">Created:</span> {details.created_at}</div>
        <div class="text-base-content/60">Group public key:</div>
        <pre class="font-mono text-xs break-all whitespace-pre-wrap" data-testid="key-details-gpk">{details.group_public_key}</pre>
      </div>
    {/if}
  </div>
</section>
