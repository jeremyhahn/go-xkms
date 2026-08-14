<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import Alert from "$components/Alert.svelte";
  import {
    decodePEM,
    encodePEM,
    downloadText,
    REVOCATION_REASONS,
    reasonLabel,
  } from "$lib/pem.ts";
  import type {
    GetCACertificateResponse,
    IssueCertificateResponse,
    SignCSRResponse,
    IsRevokedResponse,
  } from "@go-xkms/sdk";

  let caCert = $state<GetCACertificateResponse | null>(null);
  let error = $state<string | null>(null);
  let loading = $state(true);

  type Tab = "issue" | "csr" | "revoke";
  let tab = $state<Tab>("issue");

  // ---- issue ----
  let iCN = $state("");
  let iOrg = $state("");
  let iSANs = $state("");
  let iProfile = $state("server");
  let iValidity = $state(365);
  let iBusy = $state(false);
  let iErr = $state<string | null>(null);
  let issued = $state<IssueCertificateResponse | null>(null);

  // ---- sign CSR ----
  let cCsr = $state("");
  let cProfile = $state("server");
  let cValidity = $state(365);
  let cBusy = $state(false);
  let cErr = $state<string | null>(null);
  let signed = $state<SignCSRResponse | null>(null);

  // ---- revoke / status ----
  let rSerial = $state("");
  let rReason = $state(1);
  let rBusy = $state(false);
  let rErr = $state<string | null>(null);
  let status = $state<IsRevokedResponse | null>(null);
  let statusSerial = $state("");

  let bundleBusy = $state(false);
  let crlBusy = $state(false);

  async function load(): Promise<void> {
    loading = true;
    error = null;
    try {
      caCert = await getSDKClient().ca.certificate();
    } catch (e) {
      error = e instanceof Error ? e.message : String(e);
    } finally {
      loading = false;
    }
  }

  async function issue(): Promise<void> {
    iBusy = true;
    iErr = null;
    issued = null;
    try {
      issued = await getSDKClient().ca.issue({
        profile: iProfile,
        common_name: iCN,
        organization: iOrg === "" ? undefined : iOrg,
        sans:
          iSANs === ""
            ? undefined
            : iSANs.split(",").map((s) => s.trim()).filter((s) => s !== ""),
        validity_days: iValidity,
      });
      showToast("success", `Certificate issued (serial ${issued.serial_number}).`);
    } catch (e) {
      iErr = e instanceof Error ? e.message : String(e);
    } finally {
      iBusy = false;
    }
  }

  // Signing a CSR is the path that keeps a private key where it was generated:
  // the requester proves possession, the CA never sees the key. Prefer it over
  // issue() whenever the subject can produce its own CSR.
  async function signCSR(): Promise<void> {
    if (!cCsr.includes("-----BEGIN CERTIFICATE REQUEST-----")) {
      cErr = "Paste a PEM certificate signing request (-----BEGIN CERTIFICATE REQUEST-----).";
      return;
    }
    cBusy = true;
    cErr = null;
    signed = null;
    try {
      signed = await getSDKClient().ca.signCSR({
        csr_pem: encodePEM(cCsr),
        profile: cProfile,
        validity_days: cValidity,
      });
      showToast("success", `CSR signed (serial ${signed.serial_number}).`);
    } catch (e) {
      cErr = e instanceof Error ? e.message : String(e);
    } finally {
      cBusy = false;
    }
  }

  async function revoke(): Promise<void> {
    rBusy = true;
    rErr = null;
    try {
      await getSDKClient().ca.revoke({ serial_number: rSerial.trim(), reason: rReason });
      showToast("success", `Serial ${rSerial} revoked (${reasonLabel(rReason)}).`);
      await checkStatus(rSerial.trim());
    } catch (e) {
      rErr = e instanceof Error ? e.message : String(e);
    } finally {
      rBusy = false;
    }
  }

  async function checkStatus(serial: string): Promise<void> {
    const s = serial.trim();
    if (s === "") return;
    rErr = null;
    status = null;
    try {
      status = await getSDKClient().ca.isRevoked(s);
      statusSerial = s;
    } catch (e) {
      rErr = e instanceof Error ? e.message : String(e);
    }
  }

  async function downloadBundle(): Promise<void> {
    bundleBusy = true;
    try {
      const resp = await getSDKClient().ca.bundle();
      downloadText("xkms-ca-bundle.pem", decodePEM(resp.bundle_pem));
      showToast("success", `Trust bundle downloaded (${resp.certificates.length} certificates).`);
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    } finally {
      bundleBusy = false;
    }
  }

  async function downloadCACert(): Promise<void> {
    if (caCert === null) return;
    downloadText("xkms-ca.pem", decodePEM(caCert.certificate_pem));
  }

  async function generateCRL(): Promise<void> {
    crlBusy = true;
    try {
      const resp = await getSDKClient().ca.generateCRL();
      downloadText("xkms-crl.pem", decodePEM(resp.crl_pem), "application/x-pkcs7-crl");
      showToast("success", "CRL generated and downloaded.");
    } catch (e) {
      showToast("error", e instanceof Error ? e.message : String(e));
    } finally {
      crlBusy = false;
    }
  }

  // Mount-time load: the view has no reactive inputs, so onMount is both
  // correct and immune to an $effect re-running on unrelated state.
  onMount(() => {
    void load();
  });
</script>

<PageHeader title="Certificate Authority" subtitle="Issue, sign, revoke, and distribute trust">
  {#snippet actions()}
    <button class="btn btn-sm" onclick={downloadBundle} disabled={bundleBusy}>
      {bundleBusy ? "Fetching…" : "Download trust bundle"}
    </button>
  {/snippet}
</PageHeader>

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else}
  {#if error}<Alert kind="warning" class="mb-4"><span>{error}</span></Alert>{/if}

  {#if caCert}
    <div class="card bg-base-200 mb-6">
      <div class="card-body">
        <div class="flex items-start justify-between">
          <h2 class="card-title text-base">CA certificate</h2>
          <button class="btn btn-ghost btn-xs" onclick={downloadCACert}>Download</button>
        </div>
        <dl class="text-sm space-y-1">
          <div class="flex justify-between gap-4">
            <dt class="text-base-content/60">Subject</dt><dd class="text-right">{caCert.subject}</dd>
          </div>
          <div class="flex justify-between gap-4">
            <dt class="text-base-content/60">Issuer</dt><dd class="text-right">{caCert.issuer}</dd>
          </div>
          <div class="flex justify-between gap-4">
            <dt class="text-base-content/60">Serial</dt>
            <dd class="font-mono text-xs text-right">{caCert.serial_number}</dd>
          </div>
          <div class="flex justify-between gap-4">
            <dt class="text-base-content/60">Valid</dt>
            <dd class="text-right">{caCert.not_before} → {caCert.not_after}</dd>
          </div>
        </dl>
      </div>
    </div>
  {/if}

  <div role="tablist" class="tabs tabs-bordered mb-4">
    <button role="tab" class="tab" class:tab-active={tab === "issue"} onclick={() => (tab = "issue")}>Issue</button>
    <button role="tab" class="tab" class:tab-active={tab === "csr"} onclick={() => (tab = "csr")}>Sign CSR</button>
    <button role="tab" class="tab" class:tab-active={tab === "revoke"} onclick={() => (tab = "revoke")}>Revoke &amp; CRL</button>
  </div>

  {#if tab === "issue"}
    <div class="card bg-base-200">
      <div class="card-body space-y-3">
        <p class="text-xs text-base-content/60">
          The CA generates the key and returns it with the certificate. When the
          subject can produce its own key, prefer <strong>Sign CSR</strong> — the
          private key then never leaves the machine that will use it.
        </p>
        {#if iErr}<Alert kind="error"><span>{iErr}</span></Alert>{/if}
        <div class="grid grid-cols-1 md:grid-cols-2 gap-3">
          <label class="form-control">
            <span class="label-text">Common name</span>
            <input class="input input-bordered input-sm" bind:value={iCN} />
          </label>
          <label class="form-control">
            <span class="label-text">Organization (optional)</span>
            <input class="input input-bordered input-sm" bind:value={iOrg} />
          </label>
          <label class="form-control md:col-span-2">
            <span class="label-text">Subject alternative names (comma-separated)</span>
            <input class="input input-bordered input-sm" placeholder="host.example.com, 10.0.0.5" bind:value={iSANs} />
          </label>
          <label class="form-control">
            <span class="label-text">Profile</span>
            <select class="select select-bordered select-sm" bind:value={iProfile}>
              <option>server</option><option>client</option>
            </select>
          </label>
          <label class="form-control">
            <span class="label-text">Validity (days)</span>
            <input type="number" class="input input-bordered input-sm" bind:value={iValidity} />
          </label>
        </div>
        <button class="btn btn-primary btn-sm w-fit" onclick={issue} disabled={iBusy || iCN === ""}>
          {iBusy ? "Issuing…" : "Issue certificate"}
        </button>
        {#if issued}
          <div>
            <div class="flex items-center justify-between mb-1">
              <span class="text-xs uppercase text-base-content/60">Certificate · serial {issued.serial_number}</span>
              <button
                class="btn btn-ghost btn-xs"
                onclick={() => downloadText(`${iCN || "certificate"}.pem`, decodePEM(issued!.certificate_pem))}
              >Download</button>
            </div>
            <pre class="bg-base-300 rounded p-2 text-xs overflow-x-auto max-h-64">{decodePEM(issued.certificate_pem)}</pre>
          </div>
        {/if}
      </div>
    </div>
  {:else if tab === "csr"}
    <div class="card bg-base-200">
      <div class="card-body space-y-3">
        <p class="text-xs text-base-content/60">
          Sign a certificate signing request produced elsewhere. The requester
          proves possession of the private key; the CA never sees it.
        </p>
        {#if cErr}<Alert kind="error"><span>{cErr}</span></Alert>{/if}
        <label class="form-control">
          <span class="label-text">Certificate signing request (PEM)</span>
          <textarea
            class="textarea textarea-bordered font-mono text-xs"
            rows="8"
            placeholder="-----BEGIN CERTIFICATE REQUEST-----"
            bind:value={cCsr}
          ></textarea>
        </label>
        <div class="grid grid-cols-2 gap-3 max-w-md">
          <label class="form-control">
            <span class="label-text">Profile</span>
            <select class="select select-bordered select-sm" bind:value={cProfile}>
              <option>server</option><option>client</option>
            </select>
          </label>
          <label class="form-control">
            <span class="label-text">Validity (days)</span>
            <input type="number" class="input input-bordered input-sm" bind:value={cValidity} />
          </label>
        </div>
        <button class="btn btn-primary btn-sm w-fit" onclick={signCSR} disabled={cBusy || cCsr === ""}>
          {cBusy ? "Signing…" : "Sign CSR"}
        </button>
        {#if signed}
          <div class="space-y-2">
            <div>
              <div class="flex items-center justify-between mb-1">
                <span class="text-xs uppercase text-base-content/60">Certificate · serial {signed.serial_number}</span>
                <button
                  class="btn btn-ghost btn-xs"
                  onclick={() => downloadText("signed.pem", decodePEM(signed!.certificate_pem))}
                >Download</button>
              </div>
              <pre class="bg-base-300 rounded p-2 text-xs overflow-x-auto max-h-64">{decodePEM(signed.certificate_pem)}</pre>
            </div>
            {#if signed.chain_pem}
              <div>
                <div class="flex items-center justify-between mb-1">
                  <span class="text-xs uppercase text-base-content/60">Chain</span>
                  <button
                    class="btn btn-ghost btn-xs"
                    onclick={() => downloadText("chain.pem", decodePEM(signed!.chain_pem))}
                  >Download</button>
                </div>
                <pre class="bg-base-300 rounded p-2 text-xs overflow-x-auto max-h-40">{decodePEM(signed.chain_pem)}</pre>
              </div>
            {/if}
          </div>
        {/if}
      </div>
    </div>
  {:else}
    <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
      <div class="card bg-base-200">
        <div class="card-body space-y-3">
          <h2 class="card-title text-base">Revoke certificate</h2>
          {#if rErr}<Alert kind="error"><span>{rErr}</span></Alert>{/if}
          <label class="form-control">
            <span class="label-text">Serial number</span>
            <input class="input input-bordered input-sm font-mono" bind:value={rSerial} />
          </label>
          <label class="form-control">
            <span class="label-text">Reason (RFC 5280)</span>
            <select class="select select-bordered select-sm" bind:value={rReason}>
              {#each REVOCATION_REASONS as r (r.value)}
                <option value={r.value}>{r.value} — {r.label}</option>
              {/each}
            </select>
            <span class="label-text-alt">
              Recorded in the CRL. "keyCompromise" tells relying parties to
              distrust everything that key signed, not just this certificate.
            </span>
          </label>
          <div class="flex gap-2">
            <button class="btn btn-error btn-outline btn-sm" onclick={revoke} disabled={rBusy || rSerial === ""}>
              {rBusy ? "Revoking…" : "Revoke"}
            </button>
            <button class="btn btn-sm" onclick={() => void checkStatus(rSerial)} disabled={rSerial === ""}>
              Check status
            </button>
          </div>
          {#if status}
            <Alert kind={status.revoked ? "error" : "success"}>
              <span>
                <span class="font-mono text-xs">{statusSerial}</span>
                {#if status.revoked}
                  is <strong>revoked</strong> ({reasonLabel(status.reason)}).
                {:else}
                  is <strong>not revoked</strong>.
                {/if}
              </span>
            </Alert>
          {/if}
        </div>
      </div>

      <div class="card bg-base-200">
        <div class="card-body space-y-3">
          <h2 class="card-title text-base">Revocation list</h2>
          <p class="text-xs text-base-content/60">
            Generates a fresh CRL signed by the CA and downloads it. Publish it
            wherever your relying parties fetch their CRL distribution point.
          </p>
          <button class="btn btn-sm w-fit" onclick={generateCRL} disabled={crlBusy}>
            {crlBusy ? "Generating…" : "Generate &amp; download CRL"}
          </button>
          <div class="divider my-1"></div>
          <p class="text-xs text-base-content/60">
            TCG EK/AK issuance and TPM device enrollment run against hardware on
            the device being provisioned, so they stay in
            <code class="font-mono">xkmsctl ca tcg</code>.
          </p>
        </div>
      </div>
    </div>
  {/if}
{/if}
