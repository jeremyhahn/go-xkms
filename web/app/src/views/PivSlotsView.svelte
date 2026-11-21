<script lang="ts">
  import { onMount } from "svelte";
  import PageHeader from "$components/PageHeader.svelte";
  import StatusBadge from "$components/StatusBadge.svelte";
  import Modal from "$components/Modal.svelte";
  import Alert from "$components/Alert.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import type { PIVSlotStatus, GeneratePIVCSRRequest } from "@go-xkms/sdk";

  // The server takes "pem" or "der"; the console always works in PEM text,
  // which travels base64-encoded in the JSON body.
  const FORMAT = "pem";

  let slots = $state<PIVSlotStatus[]>([]);
  let error = $state<string | null>(null);
  let loading = $state(true);
  let busy = $state(false);

  // The PEM dialog shows either a slot certificate (with Export) or a CSR.
  let pemSlot = $state<PIVSlotStatus | null>(null);
  let pemTitle = $state("");
  let pem = $state("");
  let pemIsCert = $state(false);
  let exportHref = $state<string | null>(null);

  let installSlot = $state<PIVSlotStatus | null>(null);
  let installPem = $state("");

  let deleteSlot = $state<PIVSlotStatus | null>(null);

  let csrSlot = $state<PIVSlotStatus | null>(null);
  let csrSubject = $state("");
  let csrOrg = $state("");
  let csrUnit = $state("");
  let csrCountry = $state("");
  let csrState = $state("");
  let csrLocality = $state("");

  function message(e: unknown): string {
    return e instanceof Error ? e.message : String(e);
  }

  async function load(): Promise<void> {
    loading = true;
    error = null;
    try {
      slots = (await getSDKClient().piv.listSlots()).slots;
    } catch (e) {
      error = message(e);
    } finally {
      loading = false;
    }
  }

  function showPem(s: PIVSlotStatus, title: string, b64: string, isCert: boolean): void {
    pemSlot = s;
    pemTitle = title;
    pem = atob(b64);
    pemIsCert = isCert;
    exportHref = null;
  }

  async function view(s: PIVSlotStatus): Promise<void> {
    try {
      const res = await getSDKClient().piv.getCertificate(s.slot, s.backend, FORMAT);
      showPem(s, `Certificate in slot ${s.slot}`, res.certificate, true);
    } catch (e) {
      showToast("error", message(e));
    }
  }

  async function exportCert(): Promise<void> {
    if (!pemSlot) return;
    try {
      const res = await getSDKClient().piv.exportCertificate(pemSlot.slot, pemSlot.backend, FORMAT);
      exportHref = `data:application/x-pem-file;base64,${res.certificate}`;
    } catch (e) {
      showToast("error", message(e));
    }
  }

  async function install(): Promise<void> {
    if (!installSlot) return;
    const s = installSlot;
    busy = true;
    try {
      await getSDKClient().piv.storeCertificate(s.slot, {
        backend: s.backend,
        certificate: btoa(installPem),
        format: FORMAT,
      });
      showToast("success", `Certificate installed in slot ${s.slot}.`);
      installSlot = null;
      installPem = "";
      await load();
    } catch (e) {
      showToast("error", message(e));
    } finally {
      busy = false;
    }
  }

  async function confirmDelete(): Promise<void> {
    if (!deleteSlot) return;
    const s = deleteSlot;
    busy = true;
    try {
      await getSDKClient().piv.deleteCertificate(s.slot, s.backend);
      showToast("success", `Certificate deleted from slot ${s.slot}.`);
      deleteSlot = null;
      await load();
    } catch (e) {
      showToast("error", message(e));
    } finally {
      busy = false;
    }
  }

  function openCsr(s: PIVSlotStatus): void {
    csrSlot = s;
    csrSubject = csrOrg = csrUnit = csrCountry = csrState = csrLocality = "";
  }

  async function makeCsr(): Promise<void> {
    if (!csrSlot) return;
    const s = csrSlot;
    // Optional subject fields are sent only when filled in.
    const req: GeneratePIVCSRRequest = { backend: s.backend, subject: csrSubject };
    if (csrOrg) req.organization = csrOrg;
    if (csrUnit) req.organizational_unit = csrUnit;
    if (csrCountry) req.country = csrCountry;
    if (csrState) req.state = csrState;
    if (csrLocality) req.locality = csrLocality;
    busy = true;
    try {
      const res = await getSDKClient().piv.generateCSR(s.slot, req);
      csrSlot = null;
      showPem(s, `CSR for slot ${s.slot}`, res.csr, false);
    } catch (e) {
      showToast("error", message(e));
    } finally {
      busy = false;
    }
  }

  function algorithm(s: PIVSlotStatus): string {
    if (!s.algorithm) return "";
    return s.key_size ? `${s.algorithm} ${s.key_size}` : s.algorithm;
  }

  onMount(() => {
    void load();
  });
</script>

<PageHeader title="PIV Slots" subtitle="Slot certificates and CSRs from slot keys" />

{#if loading}
  <div class="flex justify-center py-12"><span class="loading loading-spinner loading-lg"></span></div>
{:else if error}
  <Alert kind="error"><span>{error}</span></Alert>
{:else}
  <div class="overflow-x-auto">
    <table class="table table-sm">
      <caption class="sr-only">PIV slots</caption>
      <thead>
        <tr>
          <th scope="col">Slot</th>
          <th scope="col">Name</th>
          <th scope="col">Key</th>
          <th scope="col">Certificate</th>
          <th scope="col">Subject</th>
          <th scope="col">Algorithm</th>
          <th scope="col">Expires</th>
          <th scope="col"><span class="sr-only">Actions</span></th>
        </tr>
      </thead>
      <tbody>
        {#each slots as s (`${s.backend ?? ""}/${s.slot}`)}
          <tr>
            <td class="font-mono">{s.slot}</td>
            <td>{s.name}</td>
            <td><StatusBadge label={s.has_key ? "key" : "no key"} ok={s.has_key} /></td>
            <td><StatusBadge label={s.has_cert ? "certificate" : "no certificate"} ok={s.has_cert} /></td>
            <td>{s.subject ?? ""}</td>
            <td>{algorithm(s)}</td>
            <td>{s.not_after ?? ""}</td>
            <td class="text-right whitespace-nowrap">
              {#if s.has_cert}
                <button class="btn btn-ghost btn-xs" aria-label={`View ${s.slot}`} onclick={() => view(s)}>View</button>
              {/if}
              <button class="btn btn-ghost btn-xs" aria-label={`Install ${s.slot}`} onclick={() => { installSlot = s; installPem = ""; }}>Install</button>
              {#if s.has_key}
                <button class="btn btn-ghost btn-xs" aria-label={`CSR ${s.slot}`} onclick={() => openCsr(s)}>CSR</button>
              {/if}
              {#if s.has_cert}
                <button class="btn btn-ghost btn-xs text-error" aria-label={`Delete ${s.slot}`} onclick={() => (deleteSlot = s)}>Delete</button>
              {/if}
            </td>
          </tr>
        {/each}
        {#if slots.length === 0}
          <tr><td colspan="8" class="text-center text-base-content/60 py-6">No PIV slots.</td></tr>
        {/if}
      </tbody>
    </table>
  </div>
{/if}

{#if pemSlot}
  <Modal open={pemSlot !== null} onClose={() => (pemSlot = null)} labelledby="piv-pem-title">
    <h3 id="piv-pem-title" class="text-lg font-semibold mb-4">{pemTitle}</h3>
    <pre data-testid="pem" class="bg-base-200 p-3 rounded text-xs overflow-x-auto">{pem}</pre>
    <div class="modal-action">
      {#if pemIsCert}
        {#if exportHref}
          <a class="btn btn-ghost" href={exportHref} download={`${pemSlot.slot}.pem`}>Download {pemSlot.slot}.pem</a>
        {/if}
        <button class="btn btn-ghost" onclick={exportCert}>Export</button>
      {/if}
      <button class="btn btn-primary" onclick={() => (pemSlot = null)}>Close</button>
    </div>
  </Modal>
{/if}

{#if installSlot}
  <Modal open={installSlot !== null} onClose={() => (installSlot = null)} labelledby="piv-install-title">
    <h3 id="piv-install-title" class="text-lg font-semibold mb-4">Install certificate in slot {installSlot.slot}</h3>
    <textarea
      class="textarea textarea-bordered w-full font-mono text-xs"
      aria-label="Certificate PEM"
      placeholder="-----BEGIN CERTIFICATE-----"
      rows="8"
      bind:value={installPem}
    ></textarea>
    <div class="modal-action">
      <button class="btn btn-ghost" onclick={() => (installSlot = null)} disabled={busy}>Cancel</button>
      <button class="btn btn-primary" onclick={install} disabled={busy || installPem.trim() === ""}>Install</button>
    </div>
  </Modal>
{/if}

{#if deleteSlot}
  <Modal open={deleteSlot !== null} onClose={() => (deleteSlot = null)} labelledby="piv-delete-title">
    <h3 id="piv-delete-title" class="text-lg font-semibold mb-4">Delete the certificate in slot {deleteSlot.slot}?</h3>
    <p class="text-sm">The slot key stays on the card.</p>
    <div class="modal-action">
      <button class="btn btn-ghost" onclick={() => (deleteSlot = null)} disabled={busy}>Cancel</button>
      <button class="btn btn-error" onclick={confirmDelete} disabled={busy}>Delete certificate</button>
    </div>
  </Modal>
{/if}

{#if csrSlot}
  <Modal open={csrSlot !== null} onClose={() => (csrSlot = null)} labelledby="piv-csr-title">
    <h3 id="piv-csr-title" class="text-lg font-semibold mb-4">CSR from the key in slot {csrSlot.slot}</h3>
    <div class="space-y-3">
      <input class="input input-bordered w-full" aria-label="Common name" placeholder="Common name" bind:value={csrSubject} />
      <input class="input input-bordered w-full" aria-label="Organization" placeholder="Organization" bind:value={csrOrg} />
      <input class="input input-bordered w-full" aria-label="Organizational unit" placeholder="Organizational unit" bind:value={csrUnit} />
      <input class="input input-bordered w-full" aria-label="Country" placeholder="Country" bind:value={csrCountry} />
      <input class="input input-bordered w-full" aria-label="State" placeholder="State" bind:value={csrState} />
      <input class="input input-bordered w-full" aria-label="Locality" placeholder="Locality" bind:value={csrLocality} />
    </div>
    <div class="modal-action">
      <button class="btn btn-ghost" onclick={() => (csrSlot = null)} disabled={busy}>Cancel</button>
      <button class="btn btn-primary" onclick={makeCsr} disabled={busy || csrSubject.trim() === ""}>Generate CSR</button>
    </div>
  </Modal>
{/if}
