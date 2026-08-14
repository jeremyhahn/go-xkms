<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import DataTable from "$components/DataTable.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import Alert from "$components/Alert.svelte";
  import { drawerA11y } from "$components/Modal.svelte";
  import type { CertificateInfo, GetCertResponse } from "@go-xkms/sdk";

  let certs = $state<CertificateInfo[]>([]);
  let error = $state<string | null>(null);
  let loading = $state(true);
  let selected = $state<CertificateInfo | null>(null);
  let detail = $state<GetCertResponse | null>(null);
  let chain = $state<string[]>([]);
  let detailBusy = $state(false);
  let detailErr = $state<string | null>(null);

  const columns = [
    { key: "key_id", label: "Key ID" },
    { key: "subject", label: "Subject" },
    { key: "issuer", label: "Issuer" },
    { key: "not_after", label: "Expires" },
  ];

  async function load(): Promise<void> {
    loading = true;
    error = null;
    try {
      const resp = await getSDKClient().certs.list();
      certs = resp.certificates;
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  async function open(row: Record<string, unknown>): Promise<void> {
    const c = certs.find((x) => x.key_id === row.key_id);
    if (!c) return;
    selected = c;
    detail = null;
    chain = [];
    detailErr = null;
    detailBusy = true;
    const client = getSDKClient();
    const backend = "";
    try {
      detail = await client.certs.get(c.key_id, backend);
    } catch (e) {
      detailErr = e instanceof Error ? e.message : String(e);
    }
    try {
      const ch = await client.certs.getChain(c.key_id);
      chain = ch.cert_chain_pem;
    } catch {
      chain = [];
    }
    detailBusy = false;
  }

  async function copyPEM(pem: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(pem);
      showToast("success", "Copied to clipboard.");
    } catch {
      showToast("warning", "Clipboard unavailable.");
    }
  }

  // Mount-time load: the view has no reactive inputs, so onMount is both
  // correct and immune to an $effect re-running on unrelated state.
  onMount(() => {
    void load();
  });
</script>

<PageHeader title="Certificates" subtitle="Stored certificates and chains" />

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if error}
  <Alert kind="error"><span>{error}</span></Alert>
{:else}
  <DataTable
    {columns}
    rows={certs.map((c) => ({ ...c }))}
    emptyMessage="No certificates stored."
    onRowClick={open}
    caption="Stored certificates"
  />
{/if}

{#if selected}
  <div class="drawer drawer-end drawer-open">
    <div class="drawer-side">
      <button class="drawer-overlay" aria-label="Close" onclick={() => (selected = null)}></button>
      <div
        class="w-full max-w-xl bg-base-100 h-full p-6 overflow-y-auto"
        role="dialog"
        aria-modal="true"
        aria-labelledby="cert-detail-title"
        tabindex="-1"
        use:drawerA11y={{ onClose: () => (selected = null) }}
      >
        <div class="flex items-start justify-between mb-4">
          <h2 id="cert-detail-title" class="text-xl font-semibold">{selected.key_id}</h2>
          <button class="btn btn-ghost btn-sm btn-square" aria-label="Close" onclick={() => (selected = null)}>✕</button>
        </div>

        {#if detailBusy}
          <div class="flex justify-center py-8"><span class="loading loading-spinner"></span></div>
        {:else}
          {#if detailErr}<Alert kind="error" class="mb-3"><span>{detailErr}</span></Alert>{/if}
          <dl class="text-sm space-y-1 mb-4">
            <div class="flex justify-between"><dt class="text-base-content/60">Subject</dt><dd>{selected.subject ?? "—"}</dd></div>
            <div class="flex justify-between"><dt class="text-base-content/60">Issuer</dt><dd>{selected.issuer ?? "—"}</dd></div>
            <div class="flex justify-between"><dt class="text-base-content/60">Serial</dt><dd>{selected.serial_number ?? "—"}</dd></div>
            <div class="flex justify-between"><dt class="text-base-content/60">Not before</dt><dd>{selected.not_before ?? "—"}</dd></div>
            <div class="flex justify-between"><dt class="text-base-content/60">Not after</dt><dd>{selected.not_after ?? "—"}</dd></div>
          </dl>

          {#if detail?.certificate_pem}
            <div class="mb-4">
              <div class="flex items-center justify-between mb-1">
                <span class="text-xs uppercase text-base-content/60">Certificate</span>
                <button class="btn btn-ghost btn-xs" onclick={() => copyPEM(detail?.certificate_pem ?? "")}>Copy</button>
              </div>
              <pre class="bg-base-200 rounded p-2 text-xs overflow-x-auto">{detail.certificate_pem}</pre>
            </div>
          {/if}

          {#if chain.length > 0}
            <div>
              <div class="text-xs uppercase text-base-content/60 mb-1">Chain ({chain.length})</div>
              {#each chain as pem, i (i)}
                <pre class="bg-base-200 rounded p-2 text-xs overflow-x-auto mb-2">{pem}</pre>
              {/each}
            </div>
          {/if}
        {/if}
      </div>
    </div>
  </div>
{/if}
