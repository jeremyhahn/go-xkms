<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import StatusBadge from "$components/StatusBadge.svelte";
  import Alert from "$components/Alert.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import { downloadText } from "$lib/pem.ts";

  const END_MARKER = "-----END CERTIFICATE-----";

  let pem = $state("");
  let error = $state<string | null>(null);
  let loading = $state(true);

  // Count by END markers only; the browser parses no X.509.
  const count = $derived(pem.split(END_MARKER).length - 1);

  async function load(): Promise<void> {
    loading = true;
    error = null;
    try {
      pem = await getSDKClient().ca.bootstrapBundle();
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  function download(): void {
    downloadText("xkms-ca-bundle.pem", pem, "application/pem-certificate-chain");
  }

  async function copy(): Promise<void> {
    try {
      await navigator.clipboard.writeText(pem);
      showToast("success", "Bundle copied to the clipboard.");
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    }
  }

  onMount(() => {
    void load();
  });
</script>

<PageHeader title="Trust Bundle" subtitle="CA bootstrap bundle">
  {#snippet actions()}
    <button class="btn btn-ghost btn-sm" onclick={load} disabled={loading}>Refresh</button>
  {/snippet}
</PageHeader>

<p class="text-sm text-base-content/70 mb-4">
  This is the CA bundle a new client pins on first contact (GET /v1/ca/bootstrap).
</p>

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if error}
  <Alert kind="error"><span>{error}</span></Alert>
{:else if pem.trim() === ""}
  <Alert kind="info"><span>No bootstrap bundle is configured on this server.</span></Alert>
{:else}
  <div class="flex flex-wrap items-center gap-2 mb-3">
    <StatusBadge label={count === 1 ? "1 certificate" : `${count} certificates`} kind="neutral" />
    <button class="btn btn-primary btn-sm" onclick={download}>Download</button>
    <button class="btn btn-ghost btn-sm" onclick={copy}>Copy</button>
  </div>
  <textarea
    class="textarea textarea-bordered w-full font-mono text-xs"
    aria-label="Bootstrap bundle PEM"
    rows="16"
    readonly
    value={pem}
  ></textarea>
{/if}
