<script lang="ts">
  import PageHeader from "$components/PageHeader.svelte";
  import Alert from "$components/Alert.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import { decodePEM, encodePEM, downloadText } from "$lib/pem.ts";
  import { isB64 } from "$lib/b64.ts";

  // The TCG verbs of the CA: EK and AK certificates, and a TCG CSR signed
  // into IAK + IDevID certificates. Device enrollment is not offered here:
  // its response carries the credential-activation secret.
  type Tab = "ek" | "ak" | "csr";
  const tabs: Array<{ id: Tab; label: string; input: string }> = [
    { id: "ek", label: "EK", input: "EK public key" },
    { id: "ak", label: "AK", input: "AK public key" },
    { id: "csr", label: "TCG CSR", input: "TCG CSR" },
  ];

  let tab = $state<Tab>("ek");
  let commonName = $state("");
  let organization = $state("");
  let tenantId = $state("");
  let input = $state("");
  let busy = $state(false);
  let error = $state<string | null>(null);
  let inputErr = $state<string | null>(null);
  let cert = $state<{ serial: string; pem: string } | null>(null);
  let signed = $state<{ iak: string; idevid: string } | null>(null);

  const current = $derived(tabs.find((t) => t.id === tab)!);
  const ready = $derived(commonName.trim() !== "" && input.trim() !== "");

  function select(t: Tab): void {
    tab = t;
    input = "";
    clear();
  }

  function clear(): void {
    error = null;
    inputErr = null;
    cert = null;
    signed = null;
  }

  function opt(v: string): string | undefined {
    const t = v.trim();
    return t === "" ? undefined : t;
  }

  // A PEM key is sent as Base64 of its PEM text, a Base64 key as is. A PEM
  // CSR is sent as the Base64 of its body (the DER).
  function encodeInput(raw: string, csr: boolean): string | null {
    const t = raw.trim();
    if (t.startsWith("-----BEGIN")) {
      return csr ? t.split("\n").filter((l) => !l.startsWith("-----")).join("").trim() : encodePEM(t);
    }
    return isB64(t) ? t : null;
  }

  async function submit(): Promise<void> {
    clear();
    const value = encodeInput(input, tab === "csr");
    if (value === null) {
      inputErr = "Input is neither PEM nor Base64.";
      return;
    }
    const base = { common_name: commonName.trim(), organization: opt(organization), tenant_id: opt(tenantId) };
    busy = true;
    try {
      const ca = getSDKClient().ca;
      if (tab === "csr") {
        const r = await ca.signTCGCSR({ ...base, tcg_csr: value });
        signed = { iak: r.iak_cert_der, idevid: r.idevid_cert_der };
        showToast("success", "TCG CSR signed.");
      } else {
        const r = tab === "ek"
          ? await ca.issueEK({ ...base, ek_public_key: value })
          : await ca.issueAK({ ...base, public_key: value });
        cert = { serial: r.serial_number, pem: decodePEM(r.certificate_pem) };
        showToast("success", `${current.label} certificate issued.`);
      }
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      busy = false;
    }
  }

  function fileBase(): string {
    return commonName.trim().replace(/[^A-Za-z0-9._-]/g, "_") || "device";
  }
</script>

<PageHeader title="TCG Certificates" subtitle="EK and AK certificates and TCG CSR signing" />

<div role="tablist" class="tabs tabs-bordered mb-4">
  {#each tabs as t (t.id)}
    <button
      role="tab"
      class="tab"
      class:tab-active={tab === t.id}
      aria-selected={tab === t.id}
      onclick={() => select(t.id)}>{t.label}</button>
  {/each}
</div>

<div class="card bg-base-100 shadow-sm mb-4">
  <div class="card-body space-y-3">
    <input class="input input-bordered w-full" aria-label="Common name" placeholder="Common name" bind:value={commonName} />
    <input class="input input-bordered w-full" aria-label="Organization" placeholder="Organization (optional)" bind:value={organization} />
    <input class="input input-bordered w-full" aria-label="Tenant ID" placeholder="Tenant ID (optional)" bind:value={tenantId} />
    <textarea
      class="textarea textarea-bordered w-full font-mono text-xs"
      aria-label={current.input}
      placeholder={tab === "csr" ? "TCG CSR (Base64)" : `${current.input} (PEM or Base64)`}
      rows="6"
      bind:value={input}></textarea>
    {#if inputErr}<p class="text-error text-sm">{inputErr}</p>{/if}
    <div class="card-actions justify-end">
      <button class="btn btn-primary" onclick={submit} disabled={busy || !ready}>{tab === "csr" ? "Sign" : "Issue"}</button>
    </div>
  </div>
</div>

{#if error}
  <Alert kind="error"><span>{error}</span></Alert>
{/if}

{#if cert}
  {@const c = cert}
  <div class="card bg-base-100 shadow-sm">
    <div class="card-body space-y-2">
      <div class="text-sm">Serial number: <span class="font-mono">{c.serial}</span></div>
      <pre data-testid="tcg-result-pem" class="bg-base-200 p-3 rounded text-xs overflow-x-auto">{c.pem}</pre>
      <div class="card-actions justify-end">
        <button class="btn btn-sm" onclick={() => downloadText(`${fileBase()}-${tab}.pem`, c.pem)}>Download PEM</button>
      </div>
    </div>
  </div>
{/if}

{#if signed}
  {@const s = signed}
  <div class="card bg-base-100 shadow-sm">
    <div class="card-body space-y-2">
      <h3 class="font-semibold">IAK certificate (DER, Base64)</h3>
      <pre class="bg-base-200 p-3 rounded text-xs overflow-x-auto break-all whitespace-pre-wrap">{s.iak}</pre>
      <button class="btn btn-sm self-end" onclick={() => downloadText(`${fileBase()}-iak.der.b64`, s.iak, "text/plain")}>Download IAK</button>
      <h3 class="font-semibold">IDevID certificate (DER, Base64)</h3>
      <pre class="bg-base-200 p-3 rounded text-xs overflow-x-auto break-all whitespace-pre-wrap">{s.idevid}</pre>
      <button class="btn btn-sm self-end" onclick={() => downloadText(`${fileBase()}-idevid.der.b64`, s.idevid, "text/plain")}>Download IDevID</button>
    </div>
  </div>
{/if}
