<script lang="ts">
  import { onMount } from 'svelte';
  import Card from '$lib/components/Card.svelte';
  import Button from '$lib/components/Button.svelte';
  import StatusBadge from '$lib/components/StatusBadge.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
  import CopyIconButton from '$lib/components/CopyIconButton.svelte';
  import {
    mdiArrowLeft, mdiCertificate, mdiCreditCardOutline, mdiKey,
    mdiShieldCheckOutline,
  } from '$lib/utils/icons';
  import { navigateTo, appState } from '$lib/stores/app';
  import { formatDateTime, formatFingerprint } from '$lib/utils/format';
  import { isWailsAvailable, callBackend } from '$lib/api/backend';
  import type { BackendPIVSlot } from '$lib/api/backend';
  import type { PIVSlot } from '$lib/types';

  /** Slot label and purpose lookup by slot ID */
  const slotMeta: Record<string, { label: string; purpose: string }> = {
    '9A': { label: 'PIV Authentication', purpose: 'General authentication, SSH, VPN' },
    '9C': { label: 'Digital Signature', purpose: 'Code signing, document signing' },
    '9D': { label: 'Key Management', purpose: 'Encryption, key exchange' },
    '9E': { label: 'Card Authentication', purpose: 'Physical access, card authentication' },
    'F9': { label: 'Attestation', purpose: 'Device attestation certificate' },
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

  let loading = true;
  let certPEM = '';
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
        hasKey: false,
        algorithm: null, subject: null, issuer: null, serialNumber: null,
        notBefore: null, notAfter: null, keyUsage: [], fingerprint: null, daysRemaining: null,
        backend: null, backendDisplayName: null,
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
        hasKey: true,
        algorithm: cert.algorithm || null,
        subject: cert.subject || null,
        issuer: cert.issuer || null,
        serialNumber: cert.serial_number || null,
        notBefore: cert.not_before || null,
        notAfter: cert.not_after || null,
        keyUsage: [],
        fingerprint: cert.fingerprint || null,
        daysRemaining,
        backend: null, backendDisplayName: null,
      };
      certPEM = cert.pem || '';
    } else {
      let hasKey = false;
      let keyAlgorithm: string | null = null;
      const slotList = await callBackend<BackendPIVSlot[]>('PIVService', 'GetSlots');
      if (slotList) {
        const match = slotList.find(s => s.slot.toUpperCase() === id);
        if (match) {
          hasKey = match.has_key || (match.algorithm !== undefined && match.algorithm !== '');
          keyAlgorithm = match.algorithm || null;
        }
      }

      slot = {
        slotId: id,
        label: meta.label,
        purpose: meta.purpose,
        loaded: false,
        hasKey,
        algorithm: keyAlgorithm, subject: null, issuer: null, serialNumber: null,
        notBefore: null, notAfter: null, keyUsage: [], fingerprint: null, daysRemaining: null,
        backend: null, backendDisplayName: null,
      };
    }
    loading = false;
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
              <div class="detail-field detail-field-wide">
                <span class="text-label-small field-label">Fingerprint (SHA-256)</span>
                <code class="text-body-small font-mono">{slot.fingerprint ? formatFingerprint(slot.fingerprint) : 'N/A'}</code>
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

        <!-- PEM section -->
        {#if certPEM}
          <Card variant="outlined">
            <div class="section">
              <div class="pem-header">
                <span class="text-label-medium">Certificate PEM</span>
                <CopyIconButton text={certPEM} tooltip="Copy PEM to clipboard" />
              </div>
              <pre class="pem-content text-body-small font-mono">{certPEM}</pre>
            </div>
          </Card>
        {/if}

        <p class="text-body-small actions-hint">
          Actions for this slot are available from the PIV overview page.
        </p>

      {:else if slot.hasKey}
        <!-- Key-Only: key present but no certificate stored yet -->
        <Card variant="outlined">
          <div class="section" data-testid="piv-slot-key-only">
            <h2 class="text-title-medium section-heading">
              <Icon path={mdiKey} size={20} />
              Key Generated
            </h2>
            <div class="detail-grid">
              <div class="detail-field">
                <span class="text-label-small field-label">Algorithm</span>
                <span class="text-body-medium">{slot.algorithm || 'Unknown'}</span>
              </div>
            </div>
            <p class="text-body-medium key-only-desc">
              A key pair exists in this slot but no certificate has been stored yet.
            </p>
          </div>
        </Card>

        <p class="text-body-small actions-hint">
          Actions for this slot are available from the PIV overview page.
        </p>

      {:else}
        <!-- Empty Slot -->
        <Card variant="outlined">
          <div class="empty-slot" data-testid="piv-slot-empty">
            <Icon path={mdiCreditCardOutline} size={48} color="var(--color-on-surface-variant)" />
            <h3 class="text-title-medium">Slot {slot.slotId} is empty</h3>
            <p class="text-body-medium empty-desc">{slot.purpose}</p>
          </div>
        </Card>

        <p class="text-body-small actions-hint">
          Actions for this slot are available from the PIV overview page.
        </p>
      {/if}
    </div>
  {/if}
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

  .detail-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 14px 20px; }

  .detail-field { display: flex; flex-direction: column; gap: 4px; min-width: 0; }
  .detail-field-wide { grid-column: 1 / -1; }

  .pem-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 8px;
  }

  .pem-content {
    background: var(--color-surface-variant);
    border: 1px solid var(--color-outline-variant);
    border-radius: 8px;
    padding: 12px 14px;
    margin: 0;
    max-height: 260px;
    overflow: auto;
    white-space: pre;
    word-break: break-all;
  }

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

  .empty-slot {
    display: flex; flex-direction: column; align-items: center;
    gap: 16px; padding: 48px; text-align: center;
  }

  .empty-slot h3 { margin: 0; color: var(--color-on-surface); }
  .empty-desc { color: var(--color-on-surface-variant); margin: 0; }

  .key-only-desc {
    color: var(--color-on-surface-variant);
    margin: 0;
  }

  .actions-hint {
    color: var(--color-on-surface-variant);
    opacity: 0.7;
    margin: 0;
    font-style: italic;
  }
</style>
