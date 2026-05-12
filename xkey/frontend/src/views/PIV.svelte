<script lang="ts">
  import { onMount } from 'svelte';
  import GradientHeader from '$lib/components/GradientHeader.svelte';
  import ViewToolbar from '$lib/components/ViewToolbar.svelte';
  import Card from '$lib/components/Card.svelte';
  import Button from '$lib/components/Button.svelte';
  import StatusBadge from '$lib/components/StatusBadge.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import GeneratePIVKeyDialog from '$lib/components/GeneratePIVKeyDialog.svelte';
  import BackendSelector from '$lib/components/BackendSelector.svelte';
  import ActionMenu from '$lib/components/ActionMenu.svelte';
  import CSRDialog, { type CSRDialogData } from '$lib/components/CSRDialog.svelte';
  import CopyIconButton from '$lib/components/CopyIconButton.svelte';
  import type { ActionItem } from '$lib/components/ActionMenu.types';
  import {
    mdiCreditCardOutline, mdiKey, mdiCertificate, mdiEye, mdiPlus, mdiUpload,
    mdiExport, mdiDelete, mdiContentCopy, mdiDownload, mdiImport,
    mdiFileDocumentOutline, mdiContentSaveOutline,
  } from '$lib/utils/icons';
  import { appState, pivBackend, setPIVBackend } from '$lib/stores/app';
  import { addNotification } from '$lib/stores/notifications';
  import { formatDateTime, formatFingerprint } from '$lib/utils/format';
  import { isWailsAvailable, callBackend, callBackendVoid, callBackendWithError } from '$lib/api/backend';
  import type { BackendPIVSlot } from '$lib/api/backend';
  import type { PIVSlot } from '$lib/types';
  import { isHardwareBackend as sharedIsHardwareBackend } from '$lib/utils/backends';

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

  let slots: PIVSlot[] = [];

  // Generate key dialog state
  let showGenerateDialog = false;
  let generateSlotId = '';
  let generateSlotLabel = '';

  // Active slot for modal operations
  let activeSlot: PIVSlot | null = null;

  // Modal visibility flags
  let showCertViewer = false;
  let showImportCertModal = false;
  let showDeleteConfirm = false;
  let showCSRDialog = false;
  let showCSRResult = false;

  // Async state
  let certPEM = '';
  let importCertPEM = '';
  let csrPEM = '';
  let importing = false;
  let deleting = false;
  let generatingCSR = false;
  let exporting = false;

  // Use stateful store — persists across navigation
  $: selectedBackend = $pivBackend;

  const defaultSlots: PIVSlot[] = [
    { slotId: '9A', label: 'PIV Authentication', purpose: 'General authentication, SSH, VPN', loaded: false, hasKey: false, algorithm: null, subject: null, issuer: null, serialNumber: null, notBefore: null, notAfter: null, keyUsage: [], fingerprint: null, daysRemaining: null, backend: null, backendDisplayName: null },
    { slotId: '9C', label: 'Digital Signature', purpose: 'Code signing, document signing', loaded: false, hasKey: false, algorithm: null, subject: null, issuer: null, serialNumber: null, notBefore: null, notAfter: null, keyUsage: [], fingerprint: null, daysRemaining: null, backend: null, backendDisplayName: null },
    { slotId: '9D', label: 'Key Management', purpose: 'Encryption, key exchange', loaded: false, hasKey: false, algorithm: null, subject: null, issuer: null, serialNumber: null, notBefore: null, notAfter: null, keyUsage: [], fingerprint: null, daysRemaining: null, backend: null, backendDisplayName: null },
    { slotId: '9E', label: 'Card Authentication', purpose: 'Physical access, card authentication', loaded: false, hasKey: false, algorithm: null, subject: null, issuer: null, serialNumber: null, notBefore: null, notAfter: null, keyUsage: [], fingerprint: null, daysRemaining: null, backend: null, backendDisplayName: null },
    { slotId: 'F9', label: 'Attestation', purpose: 'Device attestation certificate', loaded: false, hasKey: false, algorithm: null, subject: null, issuer: null, serialNumber: null, notBefore: null, notAfter: null, keyUsage: [], fingerprint: null, daysRemaining: null, backend: null, backendDisplayName: null },
  ];

  async function loadSlots(): Promise<void> {
    if (isWailsAvailable()) {
      const backendSlots = await callBackend<BackendPIVSlot[]>('PIVService', 'GetSlots');
      if (backendSlots && backendSlots.length > 0) {
        slots = backendSlots.map(s => ({
          slotId: s.slot.toUpperCase(),
          label: s.name,
          purpose: s.description,
          loaded: s.has_cert,
          hasKey: s.has_key || s.has_cert,
          algorithm: s.algorithm || null,
          subject: s.subject || null,
          issuer: s.issuer || null,
          serialNumber: null,
          notBefore: s.not_before || null,
          notAfter: s.not_after || null,
          keyUsage: [],
          fingerprint: s.fingerprint || null,
          daysRemaining: s.not_after ? Math.floor((new Date(s.not_after).getTime() - Date.now()) / 86400000) : null,
          backend: s.backend || null,
          backendDisplayName: s.backend_display_name || null,
        }));
        return;
      }
    }
    slots = defaultSlots;
  }

  onMount(async () => {
    if ($pivBackend && isWailsAvailable()) {
      await callBackend('PIVService', 'SetBackend', $pivBackend);
    }
    loadSlots();
  });

  async function handleBackendChange(e: CustomEvent<string>): Promise<void> {
    const backend = e.detail;
    setPIVBackend(backend);
    if (isWailsAvailable() && backend) {
      await callBackend('PIVService', 'SetBackend', backend);
      loadSlots();
    }
  }

  $: filteredSlots = (() => {
    const base = selectedBackend
      ? slots.filter(s => !s.backend || s.backend === selectedBackend)
      : slots;
    const slotIds = new Set(base.map(s => s.slotId));
    const missing = defaultSlots.filter(d => !slotIds.has(d.slotId));
    return [...base, ...missing].sort((a, b) => a.slotId.localeCompare(b.slotId));
  })();

  function viewSlot(slot: PIVSlot): void {
    appState.update((s) => ({
      ...s,
      currentView: 'piv-slot',
      modalProps: { slotId: slot.slotId },
    }));
  }

  function openGenerateDialog(slot: PIVSlot): void {
    generateSlotId = slot.slotId;
    generateSlotLabel = slot.label;
    showGenerateDialog = true;
  }

  function handleKeyGenerated(): void {
    showGenerateDialog = false;
    loadSlots();
  }

  function getCertStatus(slot: PIVSlot): 'connected' | 'warning' | 'error' | 'neutral' {
    if (slot.daysRemaining === null) return 'neutral';
    if (slot.daysRemaining <= 0) return 'error';
    if (slot.daysRemaining <= 30) return 'warning';
    return 'connected';
  }

  function getExpiryLabel(days: number | null): string {
    if (days === null) return 'N/A';
    if (days <= 0) return 'Expired';
    if (days <= 30) return 'Expiring';
    return 'Valid';
  }

  function isHardwareBacked(backend: string | null): boolean {
    return backend !== null && sharedIsHardwareBackend(backend);
  }

  function getDaysColor(days: number | null): string {
    if (days === null) return 'var(--color-on-surface-variant)';
    if (days <= 0) return 'var(--color-error)';
    if (days <= 30) return 'var(--color-security-warning)';
    return 'var(--color-security-verified)';
  }

  // ── Card action handlers — each takes the slot it acts on ────────────────

  async function handleViewCertificate(slot: PIVSlot): Promise<void> {
    activeSlot = slot;
    if (!certPEM || activeSlot?.slotId !== slot.slotId) {
      certPEM = '';
      const pem = await callBackend<string>('PIVService', 'ExportCertificate', slot.slotId);
      if (pem) certPEM = pem;
    }
    showCertViewer = true;
  }

  async function handleExport(slot: PIVSlot): Promise<void> {
    exporting = true;
    const pem = await callBackend<string>('PIVService', 'ExportCertificate', slot.slotId);
    exporting = false;

    if (pem) {
      certPEM = pem;
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

  async function handleSaveCert(slot: PIVSlot): Promise<void> {
    let pem = activeSlot?.slotId === slot.slotId ? certPEM : '';
    if (!pem) {
      pem = (await callBackend<string>('PIVService', 'ExportCertificate', slot.slotId)) ?? '';
      if (pem && activeSlot?.slotId === slot.slotId) certPEM = pem;
    }
    if (!pem) {
      addNotification('error', 'Failed to fetch certificate for download');
      return;
    }
    const suggested = `slot-${slot.slotId.toLowerCase()}-cert.pem`;
    const { result, error } = await callBackendWithError<string>('AppService', 'SavePEMFile', suggested, pem);
    if (result) {
      addNotification('success', `Saved to ${result}`);
    } else if (error) {
      addNotification('error', error);
    }
    // result == '' && no error means user cancelled — stay silent.
  }

  async function handleExportPublicKey(slot: PIVSlot): Promise<void> {
    const { result, error } = await callBackendWithError<string>('PIVService', 'ExportPublicKey', slot.slotId);
    if (result) {
      try {
        await navigator.clipboard.writeText(result);
        addNotification('success', 'Public key PEM copied to clipboard');
      } catch {
        addNotification('error', 'Failed to copy public key to clipboard');
      }
    } else {
      addNotification('error', error || 'Failed to export public key');
    }
  }

  async function handleSavePublicKey(slot: PIVSlot): Promise<void> {
    const { result: pem, error } = await callBackendWithError<string>('PIVService', 'ExportPublicKey', slot.slotId);
    if (!pem) {
      addNotification('error', error || 'Failed to export public key');
      return;
    }
    const suggested = `slot-${slot.slotId.toLowerCase()}-public.pem`;
    const { result: saved, error: saveErr } = await callBackendWithError<string>('AppService', 'SavePEMFile', suggested, pem);
    if (saved) {
      addNotification('success', `Saved to ${saved}`);
    } else if (saveErr) {
      addNotification('error', saveErr);
    }
  }

  async function handleSelfSign(slot: PIVSlot): Promise<void> {
    const commonName = slot.label || `PIV Key ${slot.slotId.toUpperCase()}`;
    const { result, error } = await callBackendWithError<string>(
      'PIVService', 'SelfSignExistingKey', slot.slotId, commonName, 3650,
    );
    if (result) {
      addNotification('success', `Self-signed certificate issued for slot ${slot.slotId}`);
      await loadSlots();
    } else {
      addNotification('error', error || 'Failed to create self-signed certificate');
    }
  }

  function openCSRDialog(slot: PIVSlot): void {
    activeSlot = slot;
    csrPEM = '';
    showCSRDialog = true;
  }

  async function handleGenerateCSR(data: CSRDialogData): Promise<void> {
    if (!activeSlot) return;
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

    const result = await callBackend<string>('PIVService', 'GenerateCSR', activeSlot.slotId, subject);
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

  async function handleSaveCSR(): Promise<void> {
    if (!activeSlot || !csrPEM) return;
    const suggested = `slot-${activeSlot.slotId.toLowerCase()}-csr.pem`;
    const { result, error } = await callBackendWithError<string>('AppService', 'SavePEMFile', suggested, csrPEM);
    if (result) {
      addNotification('success', `Saved to ${result}`);
    } else if (error) {
      addNotification('error', error);
    }
  }

  function openDeleteConfirm(slot: PIVSlot): void {
    activeSlot = slot;
    showDeleteConfirm = true;
  }

  async function handleDelete(): Promise<void> {
    if (!activeSlot) return;
    deleting = true;
    const ok = await callBackendVoid('PIVService', 'DeleteCertificate', activeSlot.slotId);
    deleting = false;
    showDeleteConfirm = false;

    if (ok) {
      addNotification('info', `Slot ${activeSlot.slotId} cleared`);
      await loadSlots();
    } else {
      addNotification('error', `Failed to delete key from slot ${activeSlot.slotId}`);
    }
  }

  function openImportModal(slot: PIVSlot): void {
    activeSlot = slot;
    importCertPEM = '';
    showImportCertModal = true;
  }

  async function handleImportCertificate(): Promise<void> {
    if (!activeSlot || !importCertPEM.trim()) return;
    importing = true;
    const ok = await callBackendVoid('PIVService', 'ImportCertificate', activeSlot.slotId, importCertPEM);
    importing = false;

    if (ok) {
      showImportCertModal = false;
      importCertPEM = '';
      addNotification('success', `Certificate imported into slot ${activeSlot.slotId}`);
      await loadSlots();
    } else {
      addNotification('error', `Failed to import certificate into slot ${activeSlot.slotId}`);
    }
  }

  // ── ActionMenu definitions per slot ──────────────────────────────────────

  function certStateActions(slot: PIVSlot): ActionItem[] {
    return [
      { label: 'View Certificate', icon: mdiEye, onClick: () => handleViewCertificate(slot), testid: 'piv-action-view-cert' },
      { divider: true },
      { label: 'Export Certificate (PEM)', icon: mdiExport, onClick: () => handleExport(slot), testid: 'piv-action-export-cert' },
      { label: 'Save Certificate...', icon: mdiContentSaveOutline, onClick: () => handleSaveCert(slot), testid: 'piv-action-save-cert' },
      { label: 'Export Public Key', icon: mdiExport, onClick: () => handleExportPublicKey(slot), testid: 'piv-action-export-pubkey' },
      { label: 'Save Public Key...', icon: mdiContentSaveOutline, onClick: () => handleSavePublicKey(slot), testid: 'piv-action-save-pubkey' },
      { label: 'Generate CSR', icon: mdiFileDocumentOutline, onClick: () => openCSRDialog(slot), testid: 'piv-action-gen-csr' },
      { divider: true },
      { label: 'Delete Key and Certificate', icon: mdiDelete, onClick: () => openDeleteConfirm(slot), destructive: true, testid: 'piv-action-delete' },
    ];
  }

  function keyOnlyActions(slot: PIVSlot): ActionItem[] {
    return [
      { label: 'Import Certificate', icon: mdiImport, onClick: () => openImportModal(slot), testid: 'piv-action-import-cert' },
      { label: 'Generate Self-Signed Certificate', icon: mdiCertificate, onClick: () => handleSelfSign(slot), testid: 'piv-action-self-sign' },
      { label: 'Generate CSR', icon: mdiFileDocumentOutline, onClick: () => openCSRDialog(slot), testid: 'piv-action-gen-csr' },
      { divider: true },
      { label: 'Export Public Key', icon: mdiExport, onClick: () => handleExportPublicKey(slot), testid: 'piv-action-export-pubkey' },
      { label: 'Save Public Key...', icon: mdiContentSaveOutline, onClick: () => handleSavePublicKey(slot), testid: 'piv-action-save-pubkey' },
      { divider: true },
      { label: 'Delete Key', icon: mdiDelete, onClick: () => openDeleteConfirm(slot), destructive: true, testid: 'piv-action-delete' },
    ];
  }
</script>

<div class="piv-view" data-testid="piv-view">
  <GradientHeader title="PIV Smart Card" subtitle="NIST SP 800-73 certificate slots" />

  <ViewToolbar>
    <BackendSelector
      capability="piv"
      selected={$pivBackend}
      showAll={false}
      connectedOnly={false}
      on:change={handleBackendChange}
    />
  </ViewToolbar>

  <div class="piv-content">
    <div class="piv-grid">
      {#each filteredSlots as slot}
        <Card variant={slot.loaded ? 'elevated' : 'outlined'} hoverable on:click={() => viewSlot(slot)}>
          <div class="slot-card" data-testid="piv-slot-card-{slot.slotId}">
            <!-- Overflow action menu in upper-right corner (only for cert / key-only states) -->
            {#if slot.loaded || slot.hasKey}
              <!-- svelte-ignore a11y-click-events-have-key-events -->
              <div class="slot-menu-corner" on:click|stopPropagation role="none">
                <ActionMenu
                  actions={slot.loaded ? certStateActions(slot) : keyOnlyActions(slot)}
                />
              </div>
            {/if}

            <div class="slot-header">
              <div class="slot-id-badge" class:slot-loaded={slot.loaded}>
                <span class="text-label-large">{slot.slotId}</span>
              </div>
              <div class="slot-info">
                <h3 class="text-title-small">{slot.label}</h3>
                <span class="text-body-small slot-purpose">{slot.purpose}</span>
                {#if slot.backend && !slot.loaded}
                  <span class="backend-chip" class:hardware={isHardwareBacked(slot.backend)}>{slot.backendDisplayName || slot.backend || ''}</span>
                {/if}
              </div>
            </div>

            {#if slot.loaded}
              <!-- Certificate present -->
              <div class="slot-details" data-testid="piv-slot-details-{slot.slotId}">
                <div class="slot-detail-row">
                  <Icon path={mdiKey} size={16} />
                  <span class="text-body-small">{slot.algorithm}</span>
                  {#if slot.backend}
                    <span class="backend-chip" class:hardware={isHardwareBacked(slot.backend)}>{slot.backendDisplayName || slot.backend || ''}</span>
                  {/if}
                </div>
                <div class="slot-detail-row">
                  <Icon path={mdiCertificate} size={16} />
                  <span class="text-body-small">{slot.subject}</span>
                </div>
                <div class="slot-expiry-row">
                  <StatusBadge status={getCertStatus(slot)} />
                  <span class="text-body-small">
                    {getExpiryLabel(slot.daysRemaining)}
                    {#if slot.daysRemaining !== null && slot.daysRemaining > 0}
                      &mdash; {slot.daysRemaining} days remaining
                    {/if}
                  </span>
                </div>
              </div>

            {:else if slot.hasKey}
              <!-- Key present but no certificate -->
              <div class="slot-key-only" data-testid="piv-slot-key-only-{slot.slotId}">
                <div class="slot-detail-row">
                  <Icon path={mdiKey} size={16} />
                  <span class="text-body-small">{slot.algorithm || 'Key generated'}</span>
                  {#if slot.backend}
                    <span class="backend-chip" class:hardware={isHardwareBacked(slot.backend)}>{slot.backendDisplayName || slot.backend || ''}</span>
                  {/if}
                </div>
                <span class="text-body-small slot-key-only-text">Key generated — no certificate</span>
              </div>

            {:else}
              <!-- Empty slot -->
              <div class="slot-empty" data-testid="piv-slot-empty-{slot.slotId}">
                <span class="text-body-medium slot-empty-text">Empty slot</span>
                <!-- svelte-ignore a11y-click-events-have-key-events -->
                <div on:click|stopPropagation role="none">
                  {#if slot.slotId === 'F9'}
                    <Button variant="outline" size="sm" icon={mdiPlus} on:click={() => openGenerateDialog(slot)} data-testid="piv-slot-action-{slot.slotId}">Import Certificate</Button>
                  {:else}
                    <Button variant="outline" size="sm" icon={mdiPlus} on:click={() => openGenerateDialog(slot)} data-testid="piv-slot-action-{slot.slotId}">Generate Key</Button>
                  {/if}
                </div>
              </div>
            {/if}
          </div>
        </Card>
      {/each}
    </div>
  </div>

  <GeneratePIVKeyDialog
    bind:open={showGenerateDialog}
    slotId={generateSlotId}
    slotLabel={generateSlotLabel}
    backend={selectedBackend}
    onClose={() => (showGenerateDialog = false)}
    onGenerated={handleKeyGenerated}
  />

  <CSRDialog
    bind:open={showCSRDialog}
    onClose={() => (showCSRDialog = false)}
    onGenerate={handleGenerateCSR}
  />

  <!-- Certificate viewer modal -->
  <Modal bind:open={showCertViewer} title="Certificate — Slot {activeSlot?.slotId}" maxWidth="640px">
    <div class="cert-viewer" data-testid="piv-cert-viewer">
      {#if activeSlot?.loaded}
        <div class="detail-grid">
          <div class="detail-field">
            <span class="text-label-small field-label">Subject</span>
            <span class="text-body-medium">{activeSlot.subject}</span>
          </div>
          <div class="detail-field">
            <span class="text-label-small field-label">Issuer</span>
            <span class="text-body-medium">{activeSlot.issuer}</span>
          </div>
          <div class="detail-field">
            <span class="text-label-small field-label">Serial Number</span>
            <span class="text-body-medium font-mono">{activeSlot.serialNumber}</span>
          </div>
          <div class="detail-field">
            <span class="text-label-small field-label">Algorithm</span>
            <span class="text-body-medium">{activeSlot.algorithm}</span>
          </div>
          <div class="detail-field">
            <span class="text-label-small field-label">Valid From</span>
            <span class="text-body-medium">{activeSlot.notBefore ? formatDateTime(activeSlot.notBefore) : 'N/A'}</span>
          </div>
          <div class="detail-field">
            <span class="text-label-small field-label">Valid Until</span>
            <span class="text-body-medium" style="color: {getDaysColor(activeSlot.daysRemaining)}">
              {activeSlot.notAfter ? formatDateTime(activeSlot.notAfter) : 'N/A'}
              {#if activeSlot.daysRemaining !== null}
                ({activeSlot.daysRemaining} days remaining)
              {/if}
            </span>
          </div>
          <div class="detail-field detail-field-wide">
            <span class="text-label-small field-label">Fingerprint (SHA-256)</span>
            <code class="text-body-small font-mono">{activeSlot.fingerprint ? formatFingerprint(activeSlot.fingerprint) : 'N/A'}</code>
          </div>
        </div>
        {#if certPEM}
          <div class="pem-section">
            <div class="pem-header">
              <span class="text-label-medium">PEM</span>
              <CopyIconButton text={certPEM} tooltip="Copy PEM to clipboard" />
            </div>
            <pre class="pem-content text-body-small font-mono">{certPEM}</pre>
          </div>
        {/if}
      {/if}
    </div>
    <svelte:fragment slot="actions">
      <Button variant="text" on:click={() => (showCertViewer = false)}>Close</Button>
      {#if certPEM && activeSlot}
        <Button variant="primary" icon={mdiDownload} on:click={() => activeSlot && handleSaveCert(activeSlot)}>Save...</Button>
      {/if}
    </svelte:fragment>
  </Modal>

  <!-- Delete confirm modal -->
  <Modal bind:open={showDeleteConfirm} title="Delete Key and Certificate?" maxWidth="400px">
    <p class="text-body-medium">
      This will permanently delete the key and certificate from slot <strong>{activeSlot?.slotId}</strong>.
      This action cannot be undone.
    </p>
    <svelte:fragment slot="actions">
      <Button variant="text" on:click={() => (showDeleteConfirm = false)}>Cancel</Button>
      <Button variant="danger" loading={deleting} on:click={handleDelete}>Delete</Button>
    </svelte:fragment>
  </Modal>

  <!-- Import certificate modal -->
  <Modal bind:open={showImportCertModal} title="Import Certificate" maxWidth="560px">
    <div class="import-cert-form">
      <p class="text-body-medium">
        Paste a PEM-encoded certificate below. The certificate must match the key pair in slot <strong>{activeSlot?.slotId}</strong>.
      </p>
      <textarea
        class="pem-textarea text-body-small font-mono"
        placeholder="-----BEGIN CERTIFICATE-----&#10;...&#10;-----END CERTIFICATE-----"
        rows={10}
        bind:value={importCertPEM}
        disabled={importing}
        aria-label="Certificate PEM"
      ></textarea>
    </div>
    <svelte:fragment slot="actions">
      <Button variant="text" on:click={() => { showImportCertModal = false; importCertPEM = ''; }} disabled={importing}>Cancel</Button>
      <Button variant="primary" icon={mdiImport} loading={importing} on:click={handleImportCertificate} disabled={!importCertPEM.trim()}>
        Import
      </Button>
    </svelte:fragment>
  </Modal>

  <!-- CSR result modal -->
  <Modal bind:open={showCSRResult} title="Certificate Signing Request" maxWidth="560px">
    <div class="csr-result">
      <p class="text-body-medium">
        CSR generated for slot <strong>{activeSlot?.slotId}</strong>. Copy the PEM below and submit it to your certificate authority.
      </p>
      <pre class="csr-pem text-body-small font-mono">{csrPEM}</pre>
    </div>
    <svelte:fragment slot="actions">
      <Button variant="text" on:click={() => (showCSRResult = false)}>Close</Button>
      <Button variant="outline" icon={mdiContentCopy} on:click={handleCopyCSR}>
        Copy to Clipboard
      </Button>
      <Button variant="primary" icon={mdiDownload} on:click={handleSaveCSR}>
        Save...
      </Button>
    </svelte:fragment>
  </Modal>
</div>

<style>
  .piv-view {
    height: 100%;
    display: flex;
    flex-direction: column;
  }

  .piv-content {
    flex: 1;
    overflow-y: auto;
    padding: 24px;
  }

  .piv-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 20px;
  }

  .slot-card {
    display: flex;
    flex-direction: column;
    gap: 16px;
    min-height: 180px;
    /* position: relative so the corner kebab anchors to the card */
    position: relative;
  }

  /* Upper-right kebab overflow menu on each slot card.
     High z-index so the opened popover floats above sibling cards in the
     grid. The .card ancestor does not create a stacking context (no explicit
     z-index), so absolute-positioned descendants participate in the
     .piv-grid stacking context and can paint above neighbouring cards. */
  .slot-menu-corner {
    position: absolute;
    top: 8px;
    right: 8px;
    z-index: 1000;
  }

  .slot-header {
    display: flex;
    align-items: center;
    gap: 12px;
    /* Reserve space on the right so the upper-right kebab never overlaps
       the slot label or backend chip. 32px kebab + 8px inset + 8px breathing. */
    padding-right: 48px;
    min-height: 44px;
  }

  .slot-info {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .slot-info h3 {
    margin: 0;
    color: var(--color-on-surface);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .slot-purpose {
    color: var(--color-on-surface-variant);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .slot-id-badge {
    width: 44px;
    height: 44px;
    border-radius: var(--radius-md);
    background-color: var(--color-surface-container-high);
    color: var(--color-on-surface-variant);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    font-weight: 600;
  }

  .slot-id-badge.slot-loaded {
    background: var(--gradient-primary);
    color: #FFFFFF;
  }

  .slot-details {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .slot-detail-row {
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--color-on-surface-variant);
  }

  .slot-expiry-row {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .slot-expiry-row span {
    color: var(--color-on-surface-variant);
  }

  .slot-action {
    display: flex;
    justify-content: flex-end;
    margin-top: auto;
  }

  .slot-empty {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 16px;
    padding: 16px 0;
    flex: 1;
    justify-content: center;
  }

  .slot-empty-text {
    color: var(--color-on-surface-variant);
    opacity: 0.6;
  }

  .slot-key-only {
    display: flex;
    flex-direction: column;
    gap: 8px;
    flex: 1;
  }

  .slot-key-only-text {
    color: var(--color-on-surface-variant);
    font-style: italic;
  }

  .backend-chip {
    display: inline-flex;
    align-items: center;
    padding: 2px 8px;
    border-radius: var(--radius-sm, 4px);
    font-size: 11px;
    font-weight: 500;
    background-color: var(--color-surface-container-high);
    color: var(--color-on-surface-variant);
    line-height: 1.4;
  }

  .backend-chip.hardware {
    background-color: var(--color-primary-container, rgba(0, 120, 120, 0.12));
    color: var(--color-on-primary-container, #006a6a);
  }

  /* ── Modal shared styles ─────────────────────────────────────────────────── */

  .detail-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 14px 20px;
  }

  .detail-field {
    display: flex;
    flex-direction: column;
    gap: 4px;
    min-width: 0;
  }

  .detail-field-wide {
    grid-column: 1 / -1;
  }

  /* Long monospace values (fingerprint, serial) must wrap inside the field
     column, not overflow the modal surface. */
  .detail-field .font-mono {
    overflow-wrap: anywhere;
    word-break: break-all;
  }

  .field-label {
    color: var(--color-on-surface-variant);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .cert-viewer {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .pem-section {
    margin-top: 8px;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

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

  .import-cert-form {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .import-cert-form p {
    margin: 0;
  }

  .pem-textarea {
    width: 100%;
    padding: 12px 14px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-md);
    background-color: var(--color-surface-container);
    color: var(--color-on-surface);
    font-size: 12px;
    line-height: 1.5;
    resize: vertical;
    outline: none;
    box-sizing: border-box;
    white-space: pre;
    overflow-x: auto;
  }

  .csr-result {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .csr-result p {
    margin: 0;
  }

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

  @media (max-width: 800px) {
    .piv-grid {
      grid-template-columns: 1fr;
    }
  }
</style>
