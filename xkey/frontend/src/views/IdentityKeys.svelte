<script lang="ts">
  import { onMount } from 'svelte';
  import Button from '$lib/components/Button.svelte';
  import StatusBadge from '$lib/components/StatusBadge.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import CertificateViewerDialog from '$lib/components/CertificateViewerDialog.svelte';
  import TPMProvisionKeyDialog from '$lib/components/TPMProvisionKeyDialog.svelte';
  import {
    mdiKey, mdiCertificate, mdiPlus, mdiShieldCheckOutline
  } from '$lib/utils/icons';
  import { addNotification } from '$lib/stores/notifications';
  import { isWailsAvailable, callBackend, callBackendVoid, callBackendWithError } from '$lib/api/backend';
  import type {
    BackendEKInfo, BackendEKECCInfo, BackendIAKInfo,
    BackendIDevIDInfo, KeyViewData
  } from '$lib/api/backend';

  let loading = true;

  // Key data
  let ekInfo: BackendEKInfo | null = null;
  let ekECCInfo: BackendEKECCInfo | null = null;
  let iakInfo: BackendIAKInfo | null = null;
  let idevidInfo: BackendIDevIDInfo | null = null;

  // Certificate viewer dialog state
  let showCertViewer = false;
  let certViewerPEM = '';
  let certViewerTitle = '';

  // Key view dialog state
  let showKeyViewDialog = false;
  let keyViewData: KeyViewData | null = null;
  let keyViewLoading = false;

  // Provision key dialog state
  let showProvisionKeyDialog = false;
  let provisionKeyType: 'IAK' | 'IDevID' = 'IAK';

  // CSR generation state
  let csrData = '';
  let showCSRDialog = false;
  let csrGenerating = false;

  onMount(async () => {
    if (!isWailsAvailable()) {
      loading = false;
      return;
    }

    try {
      const results = await Promise.allSettled([
        callBackend<BackendEKInfo>('TPMService', 'GetEKInfo'),
        callBackend<BackendEKECCInfo>('TPMService', 'GetEKECCInfo'),
        callBackend<BackendIAKInfo>('TPMService', 'GetIAKInfo'),
        callBackend<BackendIDevIDInfo>('TPMService', 'GetIDevIDInfo'),
      ]);

      ekInfo = results[0].status === 'fulfilled' ? results[0].value : null;
      ekECCInfo = results[1].status === 'fulfilled' ? results[1].value : null;
      iakInfo = results[2].status === 'fulfilled' ? results[2].value : null;
      idevidInfo = results[3].status === 'fulfilled' ? results[3].value : null;
    } catch (err) {
      console.error('Failed to load identity key data:', err);
      addNotification('error', 'Failed to load identity key information');
    }

    loading = false;
  });

  function handleViewCert(keyName: string): void {
    let certPEM = '';
    if (keyName.includes('EK-ECC')) {
      certPEM = ekECCInfo?.certificate ?? '';
    } else if (keyName.includes('EK')) {
      certPEM = ekInfo?.certificate ?? '';
    } else if (keyName.includes('IAK')) {
      certPEM = iakInfo?.certificate ?? '';
    } else if (keyName.includes('IDevID')) {
      certPEM = idevidInfo?.certificate ?? '';
    }
    if (certPEM) {
      certViewerPEM = certPEM;
      certViewerTitle = `${keyName} Certificate`;
      showCertViewer = true;
    } else {
      addNotification('warning', `No certificate available for ${keyName}`);
    }
  }

  async function handleViewKey(keyName: string): Promise<void> {
    keyViewLoading = true;
    keyViewData = await callBackend<KeyViewData>('TPMService', 'ViewKey', keyName);
    keyViewLoading = false;
    if (keyViewData) {
      showKeyViewDialog = true;
    } else {
      addNotification('error', `Failed to load ${keyName} details`);
    }
  }

  async function copyToClipboard(text: string, label: string): Promise<void> {
    try {
      await navigator.clipboard.writeText(text);
      addNotification('success', `${label} copied to clipboard`);
    } catch {
      addNotification('error', 'Failed to copy to clipboard');
    }
  }

  async function handleExportCert(method: string, keyName: string): Promise<void> {
    const result = await callBackend<string>('TPMService', method, 'PEM');
    if (result) {
      if (typeof navigator !== 'undefined' && navigator.clipboard) {
        await navigator.clipboard.writeText(result);
        addNotification('success', `${keyName} certificate copied to clipboard`);
      }
    } else {
      addNotification('error', `Failed to export ${keyName} certificate`);
    }
  }

  async function handleImportCert(method: string, keyName: string): Promise<void> {
    if (typeof navigator === 'undefined' || !navigator.clipboard) {
      addNotification('error', 'Clipboard API not available');
      return;
    }
    try {
      const certPEM = await navigator.clipboard.readText();
      if (!certPEM.includes('BEGIN CERTIFICATE')) {
        addNotification('error', 'Clipboard does not contain a valid PEM certificate');
        return;
      }
      const ok = await callBackendVoid('TPMService', method, certPEM);
      if (ok) {
        addNotification('success', `${keyName} certificate imported successfully`);
        if (method === 'ImportEKCert') {
          ekInfo = await callBackend<BackendEKInfo>('TPMService', 'GetEKInfo');
        } else if (method === 'ImportEKECCCert') {
          ekECCInfo = await callBackend<BackendEKECCInfo>('TPMService', 'GetEKECCInfo');
        } else if (method === 'ImportIAKCert') {
          iakInfo = await callBackend<BackendIAKInfo>('TPMService', 'GetIAKInfo');
        } else if (method === 'ImportIDevIDCert') {
          idevidInfo = await callBackend<BackendIDevIDInfo>('TPMService', 'GetIDevIDInfo');
        }
      } else {
        addNotification('error', `Failed to import ${keyName} certificate`);
      }
    } catch {
      addNotification('error', 'Failed to read from clipboard');
    }
  }

  async function handleGenerateCSR(): Promise<void> {
    if (!ekInfo?.certificate) {
      addNotification('error', 'EK certificate is required to generate an IDevID CSR');
      return;
    }
    if (!iakInfo?.present) {
      addNotification('error', 'IAK must be provisioned before generating an IDevID CSR');
      return;
    }
    if (!idevidInfo?.present) {
      addNotification('error', 'IDevID must be provisioned before generating a CSR');
      return;
    }

    csrGenerating = true;
    const { result, error } = await callBackendWithError<string>('TPMService', 'GenerateIDevIDCSR');
    csrGenerating = false;
    if (result) {
      csrData = result;
      showCSRDialog = true;
    } else {
      addNotification('error', error || 'Failed to generate IDevID CSR');
    }
  }

  function handleProvisionComplete(): void {
    showProvisionKeyDialog = false;
    if (isWailsAvailable()) {
      Promise.allSettled([
        callBackend<BackendEKInfo>('TPMService', 'GetEKInfo'),
        callBackend<BackendEKECCInfo>('TPMService', 'GetEKECCInfo'),
        callBackend<BackendIAKInfo>('TPMService', 'GetIAKInfo'),
        callBackend<BackendIDevIDInfo>('TPMService', 'GetIDevIDInfo'),
      ]).then((results) => {
        ekInfo = results[0].status === 'fulfilled' ? results[0].value : ekInfo;
        ekECCInfo = results[1].status === 'fulfilled' ? results[1].value : ekECCInfo;
        iakInfo = results[2].status === 'fulfilled' ? results[2].value : iakInfo;
        idevidInfo = results[3].status === 'fulfilled' ? results[3].value : idevidInfo;
      });
    }
  }
</script>

{#if loading}
  <div class="loading-container">
    <LoadingSpinner size={40} />
    <p class="text-body-medium loading-text">Loading identity keys...</p>
  </div>
{:else}
  <div class="identity-keys-list">
    <!-- EK-RSA -->
    <div class="identity-key-row">
      <div class="key-info">
        <span class="text-title-small">Endorsement Key (EK-RSA)</span>
        <span class="text-body-small key-type font-mono">
          {ekInfo?.present ? (ekInfo.key_size > 0 ? `${ekInfo.algorithm} ${ekInfo.key_size}` : ekInfo.algorithm) : 'N/A'}
        </span>
      </div>
      {#if ekInfo?.verified}
        <StatusBadge status="verified" />
      {/if}
      {#if ekInfo?.present}
        <Button variant="text" size="sm" icon={mdiKey} on:click={() => handleViewKey('Endorsement Key (EK-RSA)')}>
          View Key
        </Button>
        {#if ekInfo?.certificate}
          <Button variant="text" size="sm" icon={mdiCertificate} on:click={() => handleViewCert('Endorsement Key (EK-RSA)')}>
            View Cert
          </Button>
        {/if}
      {:else}
        <StatusBadge status="neutral" />
      {/if}
    </div>

    <!-- EK-ECC -->
    <div class="identity-key-row">
      <div class="key-info">
        <span class="text-title-small">Endorsement Key (EK-ECC)</span>
        <span class="text-body-small key-type font-mono">
          {ekECCInfo?.present ? (ekECCInfo.key_size > 0 ? `${ekECCInfo.algorithm} ${ekECCInfo.key_size}` : ekECCInfo.algorithm) : 'N/A'}
        </span>
      </div>
      {#if ekECCInfo?.verified}
        <StatusBadge status="verified" />
      {/if}
      {#if ekECCInfo?.present}
        <Button variant="text" size="sm" icon={mdiKey} on:click={() => handleViewKey('Endorsement Key (EK-ECC)')}>
          View Key
        </Button>
        {#if ekECCInfo?.certificate}
          <Button variant="text" size="sm" icon={mdiCertificate} on:click={() => handleViewCert('Endorsement Key (EK-ECC)')}>
            View Cert
          </Button>
        {/if}
      {:else}
        <StatusBadge status="neutral" />
      {/if}
    </div>

    <!-- IAK -->
    <div class="identity-key-row">
      <div class="key-info">
        <span class="text-title-small">Initial Attestation Key (IAK)</span>
        <span class="text-body-small key-type font-mono">
          {iakInfo?.present ? (iakInfo.key_size > 0 ? `${iakInfo.algorithm} ${iakInfo.key_size}` : iakInfo.algorithm) : 'N/A'}
        </span>
      </div>
      {#if iakInfo?.present}
        <Button variant="text" size="sm" icon={mdiKey} on:click={() => handleViewKey('Initial Attestation Key (IAK)')}>
          View Key
        </Button>
        {#if iakInfo?.certificate}
          <Button variant="text" size="sm" icon={mdiCertificate} on:click={() => handleViewCert('Initial Attestation Key (IAK)')}>
            View Cert
          </Button>
        {/if}
      {:else}
        <StatusBadge status="neutral" />
        <Button variant="outline" size="sm" icon={mdiPlus} on:click={() => { provisionKeyType = 'IAK'; showProvisionKeyDialog = true; }}>
          Provision
        </Button>
      {/if}
    </div>

    <!-- IDevID -->
    <div class="identity-key-row">
      <div class="key-info">
        <span class="text-title-small">Initial Device ID (IDevID)</span>
        <span class="text-body-small key-type font-mono">
          {idevidInfo?.present ? (idevidInfo.key_size > 0 ? `${idevidInfo.algorithm} ${idevidInfo.key_size}` : idevidInfo.algorithm) : 'N/A'}
        </span>
      </div>
      {#if idevidInfo?.verified}
        <StatusBadge status="verified" />
      {/if}
      {#if idevidInfo?.present}
        <Button variant="text" size="sm" icon={mdiKey} on:click={() => handleViewKey('Initial Device ID (IDevID)')}>
          View Key
        </Button>
        {#if idevidInfo?.certificate}
          <Button variant="text" size="sm" icon={mdiCertificate} on:click={() => handleViewCert('Initial Device ID (IDevID)')}>
            View Cert
          </Button>
        {/if}
      {:else}
        <StatusBadge status="neutral" />
        <Button variant="outline" size="sm" icon={mdiPlus} on:click={() => { provisionKeyType = 'IDevID'; showProvisionKeyDialog = true; }}>
          Provision
        </Button>
      {/if}
    </div>
  </div>

  {#if idevidInfo?.present && !idevidInfo?.certificate}
    <div class="csr-actions" style="margin-top: 8px;">
      <Button variant="outline" icon={mdiCertificate} loading={csrGenerating} on:click={handleGenerateCSR}>
        Generate IDevID CSR
      </Button>
    </div>
  {/if}
{/if}

<!-- Dialogs -->
  <CertificateViewerDialog
    bind:open={showCertViewer}
    certPEM={certViewerPEM}
    title={certViewerTitle}
    onClose={() => (showCertViewer = false)}
  />

  <TPMProvisionKeyDialog
    bind:open={showProvisionKeyDialog}
    keyType={provisionKeyType}
    onClose={() => (showProvisionKeyDialog = false)}
    onComplete={handleProvisionComplete}
  />

  <!-- Key View Dialog -->
  <Modal bind:open={showKeyViewDialog} title={keyViewData?.name ?? 'Key Details'} maxWidth="600px">
    {#if keyViewData}
      <div class="key-view-content">
        <div class="details-grid">
          <div class="detail-item">
            <span class="text-label-small field-label">Algorithm</span>
            <span class="text-body-medium">{keyViewData.algorithm}</span>
          </div>
          {#if keyViewData.key_size > 0}
            <div class="detail-item">
              <span class="text-label-small field-label">Key Size</span>
              <span class="text-body-medium">{keyViewData.key_size} bits</span>
            </div>
          {/if}
          {#if keyViewData.handle}
            <div class="detail-item">
              <span class="text-label-small field-label">Handle</span>
              <span class="text-body-medium font-mono">{keyViewData.handle}</span>
            </div>
          {/if}
        </div>

        {#if keyViewData.public_key_pem}
          <div class="pem-section">
            <div class="pem-header">
              <span class="text-label-medium">Public Key</span>
              <Button variant="text" size="sm" on:click={() => keyViewData && copyToClipboard(keyViewData.public_key_pem, 'Public key')}>Copy</Button>
            </div>
            <pre class="pem-display font-mono text-body-small">{keyViewData.public_key_pem}</pre>
          </div>
        {/if}
      </div>
    {/if}
    <svelte:fragment slot="actions">
      <Button variant="primary" on:click={() => (showKeyViewDialog = false)}>Close</Button>
    </svelte:fragment>
  </Modal>

  <!-- CSR Result Dialog -->
  <Modal bind:open={showCSRDialog} title="TCG-CSR-IDEVID" maxWidth="560px">
    <div class="key-view-content">
      <p class="text-body-small">
        Submit this CSR to your Certificate Authority for signing.
        After receiving the signed certificate, use the Import Cert button on the IDevID key to install it.
      </p>
      <div class="pem-section">
        <div class="pem-header">
          <span class="text-label-medium">CSR Data (hex)</span>
          <Button variant="text" size="sm" on:click={() => copyToClipboard(csrData, 'CSR data')}>Copy</Button>
        </div>
        <pre class="pem-display font-mono text-body-small">{csrData}</pre>
      </div>
    </div>
    <svelte:fragment slot="actions">
      <Button variant="text" on:click={() => (showCSRDialog = false)}>Close</Button>
    </svelte:fragment>
  </Modal>

<style>
  .loading-container {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 12px;
    padding: 24px;
  }

  .loading-text {
    color: var(--color-on-surface-variant);
    margin: 0;
  }

  .field-label {
    color: var(--color-on-surface-variant);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .identity-keys-list {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .identity-key-row {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 16px;
    border-radius: var(--radius-md);
    background-color: var(--color-surface-container-low);
  }

  .key-info {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .key-info span:first-child {
    color: var(--color-on-surface);
  }

  .key-type {
    color: var(--color-on-surface-variant);
    font-family: var(--font-mono);
  }

  .csr-actions {
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
  }

  /* Key View / CSR dialogs */
  .key-view-content {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .details-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 16px;
  }

  .detail-item {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .pem-section {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .pem-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
  }

  .pem-display {
    background: var(--md-sys-color-surface-container);
    border-radius: 8px;
    padding: 12px;
    overflow-x: auto;
    white-space: pre-wrap;
    word-break: break-all;
    max-height: 200px;
    overflow-y: auto;
    font-size: 11px;
    line-height: 1.4;
  }
</style>
