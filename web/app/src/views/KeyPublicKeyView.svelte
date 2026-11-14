<script lang="ts">
  import PageHeader from "$components/PageHeader.svelte";
  import Alert from "$components/Alert.svelte";
  import StatusBadge from "$components/StatusBadge.svelte";
  import { showToast } from "$stores/toast.svelte.ts";
  import { getPublicKey, toPem, type GetPublicKeyResponse } from "$lib/keyPublicKey.ts";

  let keyId = $state("");
  let backend = $state("");
  let version = $state("");
  let busy = $state(false);
  let error = $state<string | null>(null);
  let result = $state<GetPublicKeyResponse | null>(null);

  const versionOk = $derived(version.trim() === "" || /^[1-9]\d*$/.test(version.trim()));
  const canFetch = $derived(!busy && keyId.trim() !== "" && backend.trim() !== "" && versionOk);
  const pem = $derived(result ? toPem(result.public_key) : "");

  async function fetchKey(): Promise<void> {
    busy = true;
    error = null;
    result = null;
    try {
      const v = version.trim() === "" ? undefined : Number(version.trim());
      result = await getPublicKey(keyId.trim(), backend.trim(), v);
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  async function copyPem(): Promise<void> {
    try {
      await navigator.clipboard.writeText(pem);
      showToast("success", "PEM copied to the clipboard.");
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    }
  }

  function downloadPem(): void {
    if (!result) return;
    const url = URL.createObjectURL(new Blob([pem], { type: "application/x-pem-file" }));
    const a = document.createElement("a");
    a.href = url;
    a.download = `${result.key_id}-v${result.version}.pem`;
    a.click();
    URL.revokeObjectURL(url);
  }
</script>

<PageHeader title="Public Keys" subtitle="Only the public half of a key is ever returned." />

<div class="card bg-base-100 shadow-sm mb-4">
  <div class="card-body space-y-3">
    <div class="grid gap-3 md:grid-cols-3">
      <label class="form-control">
        <span class="label-text">Key ID</span>
        <input class="input input-bordered" bind:value={keyId} placeholder="sig1" />
      </label>
      <label class="form-control">
        <span class="label-text">Backend</span>
        <input class="input input-bordered" bind:value={backend} placeholder="software" />
      </label>
      <label class="form-control">
        <span class="label-text">Version</span>
        <input class="input input-bordered" inputmode="numeric" bind:value={version} placeholder="latest" />
      </label>
    </div>
    {#if !versionOk}<p class="text-error text-sm">Version must be a positive integer.</p>{/if}
    <div>
      <button class="btn btn-primary" onclick={fetchKey} disabled={!canFetch}>
        {#if busy}<span class="loading loading-spinner loading-sm"></span>{/if}
        Fetch
      </button>
    </div>
  </div>
</div>

{#if error}
  <Alert kind="error"><span>{error}</span></Alert>
{/if}

{#if result}
  <div class="card bg-base-100 shadow-sm">
    <div class="card-body space-y-3">
      <h2 class="card-title">Result</h2>
      <dl class="grid grid-cols-[auto_1fr] gap-x-4 gap-y-1 text-sm">
        <dt>Key ID</dt><dd class="font-mono">{result.key_id}</dd>
        <dt>Algorithm</dt><dd>{#if result.algorithm}<StatusBadge label={result.algorithm} kind="neutral" />{:else}-{/if}</dd>
        <dt>Version</dt><dd data-testid="pk-version">{result.version}</dd>
        <dt>Timestamp</dt><dd>{result.timestamp}</dd>
      </dl>
      <div>
        <h3 class="font-semibold text-sm mb-1">Base64 (DER)</h3>
        <pre class="font-mono text-xs whitespace-pre-wrap break-all bg-base-200 p-2 rounded" data-testid="pk-b64">{result.public_key}</pre>
      </div>
      <div>
        <h3 class="font-semibold text-sm mb-1">PEM</h3>
        <pre class="font-mono text-xs whitespace-pre bg-base-200 p-2 rounded" data-testid="pk-pem">{pem}</pre>
      </div>
      <div class="flex gap-2">
        <button class="btn btn-sm" onclick={copyPem}>Copy PEM</button>
        <button class="btn btn-sm btn-ghost" onclick={downloadPem}>Download .pem</button>
      </div>
    </div>
  </div>
{/if}
