<script lang="ts">
  import { onMount } from 'svelte';
  import Card from '$lib/components/Card.svelte';
  import Button from '$lib/components/Button.svelte';
  import StatusBadge from '$lib/components/StatusBadge.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import CSRDialog, { type CSRDialogData } from '$lib/components/CSRDialog.svelte';
  import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
  import GeneratePIVKeyDialog from '$lib/components/GeneratePIVKeyDialog.svelte';
  import {
    mdiArrowLeft, mdiCertificate, mdiCreditCardOutline, mdiKey, mdiExport,
    mdiDelete, mdiShieldCheckOutline, mdiContentCopy, mdiDownload, mdiPlus
  } from '$lib/utils/icons';
  import { navigateTo, appState } from '$lib/stores/app';
  import { formatDateTime, formatFingerprint } from '$lib/utils/format';
  import { addNotification } from '$lib/stores/notifications';
  import { isWailsAvailable, callBackend, callBackendVoid } from '$lib/api/backend';
  import type { PIVSlot } from '$lib/types';

  /** Slot label and purpose lookup by slot ID */
  const slotMeta: Record<string, { label: string; purpose: string }> = {
    '9A': { label: 'PIV Authentication', purpose: 'General authentication, SSH, VPN' },
    '9C': { label: 'Digital Signature', purpose: 'Code signing, document signing' },
    '9D': { label: 'Key Management', purpose: 'Encryption, key exchange' },
    '9E': { label: 'Card Authentication', purpose: 'Physical access, card authentication' },
  };

  /** Response shape from PIVService.GetCertificate */
  interface CertificateResponse {
    slot: string;
    algorithm: string;
    subject: string;
    issuer: string;
    serial_number: string;
    key_size: number;
    not_before: string;
    not_after: string;
    fingerprint: string;
    pem: string;
  }

  let showCSRDialog = false;
  let showDeleteConfirm = false;
  let showGenerateDialog = false;
  let showCSRResult = false;
  let csrPEM = '';
  let loading = true;
  let exporting = false;
  let deleting = false;
  let generatingCSR = false;

  let slot: PIVSlot | null = null;
  let slotId = '';

  $: slotId = ($appState.modalProps?.slotId as string) || '';

  onMount(() => {
    loadCertificate();
  });

  async function loadCertificate(): Promise<void> {
    loading = true;
    const id = slotId;
    const meta = slotMeta[id] || { label: `Slot ${id}`, purpose: '' };

    if (!isWailsAvailable()) {
      slot = {
        slotId: id,
        label: meta.label,
        purpose: meta.purpose,
        loaded: false,
        algorithm: null, subject: null, issuer: null, serialNumber: null,
        notBefore: null, notAfter: null, keyUsage: [], fingerprint: null, daysRemaining: null,
        backend: null,
      };
      loading = false;
      return;
    }

    const cert = await callBackend<CertificateResponse>('PIVService', 'GetCertificate', id);

    if (cert) {
      const daysRemaining = cert.not_after
        ? Math.floor((new Date(cert.not_after).getTime() - Date.now()) / 86400000)
        : null;

      slot = {
        slotId: id,
        label: meta.label,
        purpose: meta.purpose,
        loaded: true,
        algorithm: cert.algorithm || null,
        subject: cert.subject || null,
        issuer: cert.issuer || null,
        serialNumber: cert.serial_number || null,
        notBefore: cert.not_before || null,
        notAfter: cert.not_after || null,
        keyUsage: [],
        fingerprint: cert.fingerprint || null,
        daysRemaining,
        backend: null,
      };
    } else {
      slot = {
        slotId: id,
        label: meta.label,
        purpose: meta.purpose,
        loaded: false,
        algorithm: null, subject: null, issuer: null, serialNumber: null,
        notBefore: null, notAfter: null, keyUsage: [], fingerprint: null, daysRemaining: null,
        backend: null,
      };
    }
    loading = false;
  }

  async function handleExport(): Promise<void> {
    if (!slot) return;
    exporting = true;
    const pem = await callBackend<string>('PIVService', 'ExportCertificate', slot.slotId);
    exporting = false;

    if (pem) {
      try {
        await navigator.clipboard.writeText(pem);
        addNotification('success', 'Certificate PEM copied to clipboard');
      } catch {
        addNotification('error', 'Failed to copy certificate to clipboard');
      }
    } else {
      addNotification('error', 'Failed to export certificate');
    }
  }

  async function handleGenerateCSR(data: CSRDialogData): Promise<void> {
    if (!slot) return;
    generatingCSR = true;
    showCSRDialog = false;

    const subject = {
      common_name: data.commonName,
      organization: data.organization,
      organizational_unit: data.organizationalUnit,
      country: data.country,
      state: data.state,
      locality: data.locality,
    };

    const result = await callBackend<string>('PIVService', 'GenerateCSR', slot.slotId, subject);
    generatingCSR = false;

    if (result) {
      csrPEM = result;
      showCSRResult = true;
      addNotification('success', 'CSR generated successfully');
    } else {
      addNotification('error', 'Failed to generate CSR');
    }
  }

  async function handleCopyCSR(): Promise<void> {
    try {
      await navigator.clipboard.writeText(csrPEM);
      addNotification('success', 'CSR copied to clipboard');
    } catch {
      addNotification('error', 'Failed to copy CSR to clipboard');
    }
  }

  async function handleDelete(): Promise<void> {
    if (!slot) return;
    deleting = true;
    const ok = await callBackendVoid('PIVService', 'DeleteCertificate', slot.slotId);
    deleting = false;
    showDeleteConfirm = false;

    if (ok) {
      addNotification('info', `Slot ${slot.slotId} cleared`);
      navigateTo('piv');
    } else {
      addNotification('error', `Failed to delete key from slot ${slot.slotId}`);
    }
  }

  function handleKeyGenerated(): void {
    showGenerateDialog = false;
    loadCertificate();
  }

  function getDaysColor(days: number | null): string {
    if (days === null) return 'var(--color-on-surface-variant)';
    if (days <= 0) return 'var(--color-error)';
    if (days <= 30) return 'var(--color-security-warning)';
    return 'var(--color-security-verified)';
  }
</script>

<div class="piv-slot-view" data-testid="piv-slot-view">
  <div class="detail-header">
    <button class="back-btn" on:click={() => navigateTo('piv')}>
      <Icon path={mdiArrowLeft} size={20} />
      <span class="text-label-large">PIV Smart Card</span>
    </button>
    {#if slot}
      <h1 class="text-headline-small detail-title">
        Slot {slot.slotId} -- {slot.label}
      </h1>
    {/if}
  </div>

  {#if loading}
    <div class="loading-container">
      <LoadingSpinner size={48} />
      <p class="text-body-medium loading-text">Loading certificate data...</p>
    </div>
  {:else if slot}
    <div class="detail-content">
      {#if slot.loaded}
        <!-- Certificate Details -->
        <Card variant="elevated">
          <div class="section" data-testid="piv-cert-details">
            <h2 class="text-title-medium section-heading">
              <Icon path={mdiCertificate} size={20} />
              Certificate Details
            </h2>
            <div class="detail-grid">
              <div class="detail-field">
                <span class="text-label-small field-label">Subject</span>
                <span class="text-body-medium">{slot.subject}</span>
              </div>
              <div class="detail-field">
                <span class="text-label-small field-label">Issuer</span>
                <span class="text-body-medium">{slot.issuer}</span>
              </div>
              <div class="detail-field">
                <span class="text-label-small field-label">Serial Number</span>
                <span class="text-body-medium font-mono">{slot.serialNumber}</span>
              </div>
              <div class="detail-field">
                <span class="text-label-small field-label">Algorithm</span>
                <span class="text-body-medium">{slot.algorithm}</span>
              </div>
              <div class="detail-field">
                <span class="text-label-small field-label">Valid From</span>
                <span class="text-body-medium">{slot.notBefore ? formatDateTime(slot.notBefore) : 'N/A'}</span>
              </div>
              <div class="detail-field">
                <span class="text-label-small field-label">Valid Until</span>
                <span class="text-body-medium" style="color: {getDaysColor(slot.daysRemaining)}">
                  {slot.notAfter ? formatDateTime(slot.notAfter) : 'N/A'}
                  {#if slot.daysRemaining !== null}
                    ({slot.daysRemaining} days remaining)
                  {/if}
                </span>
              </div>
              <div class="detail-field">
                <span class="text-label-small field-label">Status</span>
                <StatusBadge status={slot.daysRemaining && slot.daysRemaining > 30 ? 'verified' : slot.daysRemaining && slot.daysRemaining > 0 ? 'warning' : 'error'} />
              </div>
            </div>
          </div>
        </Card>

        <!-- Key Usage -->
        {#if slot.keyUsage.length > 0}
          <Card variant="outlined">
            <div class="section">
              <h2 class="text-title-medium section-heading">
                <Icon path={mdiShieldCheckOutline} size={20} />
                Key Usage
              </h2>
              <div class="key-usage-list">
                {#each slot.keyUsage as usage}
                  <div class="key-usage-item">
                    <span class="key-usage-check">&#10003;</span>
                    <span class="text-body-medium">{usage}</span>
                  </div>
                {/each}
              </div>
            </div>
          </Card>
        {/if}

        <!-- Fingerprint -->
        <Card variant="security">
          <div class="section">
            <h2 class="text-title-medium section-heading">
              <Icon path={mdiKey} size={20} />
              Fingerprint (SHA-256)
            </h2>
            <code class="fingerprint text-body-small font-mono">
              {slot.fingerprint ? formatFingerprint(slot.fingerprint) : 'N/A'}
            </code>
          </div>
        </Card>

        <!-- Actions -->
        <Card variant="outlined">
          <div class="section">
            <h2 class="text-title-medium section-heading">Actions</h2>
            <div class="action-buttons">
              <Button variant="primary" size="sm" icon={mdiExport} loading={exporting} on:click={handleExport}>
                Export Certificate (PEM)
              </Button>
              <Button variant="outline" size="sm" on:click={() => (showCSRDialog = true)}>
                Generate CSR
              </Button>
              <Button variant="danger" size="sm" icon={mdiDelete} on:click={() => (showDeleteConfirm = true)}>
                Delete Key and Certificate
              </Button>
            </div>
          </div>
        </Card>
      {:else}
        <!-- Empty Slot -->
        <Card variant="outlined">
          <div class="empty-slot" data-testid="piv-slot-empty">
            <Icon path={mdiCreditCardOutline} size={48} color="var(--color-on-surface-variant)" />
            <h3 class="text-title-medium">Slot {slot.slotId} is empty</h3>
            <p class="text-body-medium empty-desc">{slot.purpose}</p>
            <Button variant="primary" icon={mdiPlus} on:click={() => (showGenerateDialog = true)}>
              Generate Key
            </Button>
          </div>
        </Card>
      {/if}
    </div>
  {/if}

  <CSRDialog
    bind:open={showCSRDialog}
    onClose={() => (showCSRDialog = false)}
    onGenerate={handleGenerateCSR}
  />

  <GeneratePIVKeyDialog
    bind:open={showGenerateDialog}
    slotId={slotId}
    slotLabel={slot?.label || ''}
    onClose={() => (showGenerateDialog = false)}
    onGenerated={handleKeyGenerated}
  />

  <Modal bind:open={showDeleteConfirm} title="Delete Key and Certificate?" maxWidth="400px">
    <p class="text-body-medium">
      This will permanently delete the key and certificate from slot <strong>{slot?.slotId}</strong>.
      This action cannot be undone.
    </p>
    <svelte:fragment slot="actions">
      <Button variant="text" on:click={() => (showDeleteConfirm = false)}>Cancel</Button>
      <Button variant="danger" loading={deleting} on:click={handleDelete}>Delete</Button>
    </svelte:fragment>
  </Modal>

  <Modal bind:open={showCSRResult} title="Certificate Signing Request" maxWidth="560px">
    <div class="csr-result">
      <p class="text-body-medium">
        CSR generated for slot <strong>{slot?.slotId}</strong>. Copy the PEM below and submit it to your certificate authority.
      </p>
      <pre class="csr-pem text-body-small font-mono">{csrPEM}</pre>
    </div>
    <svelte:fragment slot="actions">
      <Button variant="text" on:click={() => (showCSRResult = false)}>Close</Button>
      <Button variant="primary" icon={mdiContentCopy} on:click={handleCopyCSR}>
        Copy to Clipboard
      </Button>
    </svelte:fragment>
  </Modal>
</div>

<style>
  .piv-slot-view {
    height: 100%;
    display: flex;
    flex-direction: column;
  }

  .detail-header {
    padding: 16px 24px;
    display: flex;
    flex-direction: column;
    gap: 8px;
    border-bottom: 1px solid var(--color-outline-variant);
    flex-shrink: 0;
  }

  .back-btn {
    display: inline-flex; align-items: center; gap: 6px;
    border: none; background: transparent; color: var(--color-primary);
    cursor: pointer; font-family: var(--font-sans); padding: 4px 0;
    align-self: flex-start; transition: opacity var(--transition-fast);
  }
  .back-btn:hover { opacity: 0.8; }

  .detail-title { margin: 0; color: var(--color-on-surface); }

  .loading-container {
    flex: 1; display: flex; flex-direction: column;
    align-items: center; justify-content: center; gap: 16px;
  }

  .loading-text {
    color: var(--color-on-surface-variant); margin: 0;
  }

  .detail-content {
    flex: 1; overflow-y: auto; padding: 24px;
    display: flex; flex-direction: column; gap: 20px; max-width: 800px;
  }

  .section { display: flex; flex-direction: column; gap: 16px; }

  .section-heading {
    display: flex; align-items: center; gap: 8px;
    margin: 0; color: var(--color-on-surface);
  }

  .detail-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; }

  .detail-field { display: flex; flex-direction: column; gap: 4px; }

  .field-label {
    color: var(--color-on-surface-variant);
    text-transform: uppercase; letter-spacing: 0.5px;
  }

  .key-usage-list { display: flex; flex-direction: column; gap: 8px; }

  .key-usage-item {
    display: flex; align-items: center; gap: 8px;
    color: var(--color-on-surface);
  }

  .key-usage-check {
    color: var(--color-security-verified);
    font-weight: 600;
    flex-shrink: 0;
  }

  .fingerprint {
    padding: 12px 16px;
    background-color: var(--color-surface-container);
    border-radius: var(--radius-sm);
    word-break: break-all;
    line-height: 1.6;
  }

  .action-buttons {
    display: flex; flex-wrap: wrap; gap: 12px;
  }

  .empty-slot {
    display: flex; flex-direction: column; align-items: center;
    gap: 16px; padding: 48px; text-align: center;
  }

  .empty-slot h3 { margin: 0; color: var(--color-on-surface); }
  .empty-desc { color: var(--color-on-surface-variant); margin: 0; }

  .csr-result {
    display: flex; flex-direction: column; gap: 12px;
  }

  .csr-result p { margin: 0; }

  .csr-pem {
    padding: 12px 16px;
    background-color: var(--color-surface-container);
    border-radius: var(--radius-sm);
    word-break: break-all;
    white-space: pre-wrap;
    line-height: 1.5;
    max-height: 300px;
    overflow-y: auto;
    margin: 0;
    border: 1px solid var(--color-outline-variant);
  }
</style>
