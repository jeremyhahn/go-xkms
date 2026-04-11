<script lang="ts">
  import { onMount } from 'svelte';
  import GradientHeader from '$lib/components/GradientHeader.svelte';
  import ViewToolbar from '$lib/components/ViewToolbar.svelte';
  import Button from '$lib/components/Button.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import DataTable from '$lib/components/DataTable.svelte';
  import type { Column } from '$lib/components/DataTable.svelte';
  import CertificateViewerDialog from '$lib/components/CertificateViewerDialog.svelte';
  import SudoPromptDialog from '$lib/components/SudoPromptDialog.svelte';
  import {
    mdiCertificate, mdiDelete, mdiShieldCheckOutline, mdiAlert,
    mdiImport, mdiRefresh, mdiDownload, mdiUpload, mdiFilter, mdiWeb
  } from '$lib/utils/icons';
  import { addNotification } from '$lib/stores/notifications';
  import { isWailsAvailable, callBackend, callBackendVoid, callBackendWithError } from '$lib/api/backend';
  import type { TrustCertInfo } from '$lib/api/backend';

  type PurposeFilter = 'all' | 'tpm-manufacturer' | 'idevid-issuer' | 'user-ca' | 'bootstrap-ca' | 'android-hardware' | 'general';

  interface PurposeTab {
    value: PurposeFilter;
    label: string;
  }

  const purposeTabs: PurposeTab[] = [
    { value: 'all', label: 'All' },
    { value: 'tpm-manufacturer', label: 'TPM Manufacturer' },
    { value: 'idevid-issuer', label: 'IDevID Issuer' },
    { value: 'user-ca', label: 'User CA' },
    { value: 'bootstrap-ca', label: 'Bootstrap CA' },
    { value: 'android-hardware', label: 'Android Hardware' },
    { value: 'general', label: 'General' },
  ];

  const purposeColors: Record<string, { bg: string; fg: string }> = {
    'tpm-manufacturer':  { bg: 'var(--color-primary-container)', fg: 'var(--color-on-primary-container)' },
    'idevid-issuer':     { bg: 'var(--color-tertiary-container, #f3e8fd)', fg: 'var(--color-on-tertiary-container, #4a1e73)' },
    'user-ca':           { bg: 'var(--color-secondary-container)', fg: 'var(--color-on-secondary-container)' },
    'bootstrap-ca':      { bg: '#d4edda', fg: '#155724' },
    'android-hardware':  { bg: '#fff3cd', fg: '#856404' },
    'general':           { bg: 'var(--color-surface-container)', fg: 'var(--color-on-surface-variant)' },
  };

  let certificates: TrustCertInfo[] = [];
  let certCount = 0;
  let loading = true;
  let activeFilter: PurposeFilter = 'all';

  // Import modal state
  let showImportDialog = false;
  let importPemData = '';
  let importing = false;
  type ImportTab = 'paste' | 'file' | 'dane' | 'noise' | 'spki' | 'direct';
  let importTab: ImportTab = 'paste';
  let importingFile = false;

  // Truststrap import form state. The Server field is shared across all
  // four truststrap tabs; method-specific fields are conditionally rendered.
  let truststrapServer = '';
  let truststrapBundlePath = '';
  let truststrapDNSServer = '';
  let truststrapDNSOverTLS = false;
  let truststrapServerStaticKey = '';
  let truststrapSPKIPin = '';
  let truststrapImporting = false;

  const truststrapTabs: { value: ImportTab; label: string }[] = [
    { value: 'paste',  label: 'Paste PEM' },
    { value: 'file',   label: 'Browse File' },
    { value: 'dane',   label: 'DANE' },
    { value: 'noise',  label: 'Noise' },
    { value: 'spki',   label: 'SPKI' },
    { value: 'direct', label: 'Direct' },
  ];

  function isTruststrapTab(tab: ImportTab): boolean {
    return tab === 'dane' || tab === 'noise' || tab === 'spki' || tab === 'direct';
  }

  function truststrapServerPlaceholder(tab: ImportTab): string {
    return tab === 'noise' ? 'kms.example.com:8445' : 'https://kms.example.com:8443';
  }

  function resetTruststrapForm(): void {
    truststrapServer = '';
    truststrapBundlePath = '';
    truststrapDNSServer = '';
    truststrapDNSOverTLS = false;
    truststrapServerStaticKey = '';
    truststrapSPKIPin = '';
  }

  // Remove confirmation state
  let showRemoveConfirm = false;
  let removeFingerprint = '';
  let removeSubject = '';

  // Certificate viewer state
  let selectedCertPEM = '';
  let showCertViewer = false;
  let selectedCertTitle = '';

  // Sudo prompt state
  let showSudoPrompt = false;
  let sudoAction: 'install' | 'uninstall' = 'install';
  let sudoFingerprint = '';

  $: filteredCertificates = activeFilter === 'all'
    ? certificates
    : certificates.filter((c) => c.purpose === activeFilter);

  async function loadData(): Promise<void> {
    if (!isWailsAvailable()) {
      loading = false;
      return;
    }

    const [certs, count] = await Promise.all([
      callBackend<TrustCertInfo[]>('TrustService', 'ListCertificates'),
      callBackend<number>('TrustService', 'CertificateCount'),
    ]);

    certificates = certs ?? [];
    certCount = count ?? certificates.length;
    loading = false;
  }

  async function handleImport(): Promise<void> {
    if (!importPemData.trim()) {
      addNotification('error', 'PEM data is required');
      return;
    }
    if (!importPemData.includes('BEGIN CERTIFICATE')) {
      addNotification('error', 'Input does not contain valid PEM certificate data');
      return;
    }

    importing = true;
    const added = await callBackend<number>('TrustService', 'AddCertificatesPEM', importPemData);
    importing = false;

    if (added !== null && added > 0) {
      addNotification('success', `Imported ${added} certificate${added > 1 ? 's' : ''} successfully`);
      importPemData = '';
      showImportDialog = false;
      await loadData();
    } else if (added === 0) {
      addNotification('warning', 'No new certificates were added (may already exist)');
    } else {
      addNotification('error', 'Failed to import certificates');
    }
  }

  function confirmRemove(fingerprint: string, subject: string): void {
    removeFingerprint = fingerprint;
    removeSubject = subject;
    showRemoveConfirm = true;
  }

  async function handleRemove(): Promise<void> {
    const ok = await callBackendVoid('TrustService', 'RemoveCertificate', removeFingerprint);
    if (ok) {
      certificates = certificates.filter((c) => c.fingerprint !== removeFingerprint);
      certCount = Math.max(0, certCount - 1);
      addNotification('info', 'Certificate removed from trust store');
    } else {
      addNotification('error', 'Failed to remove certificate');
    }
    showRemoveConfirm = false;
  }

  async function handleViewCert(cert: TrustCertInfo): Promise<void> {
    const pem = await callBackend<string>('TrustService', 'GetCertificatePEM', cert.fingerprint);
    if (pem) {
      selectedCertPEM = pem;
      selectedCertTitle = truncateSubject(cert.subject, 40);
      showCertViewer = true;
    } else {
      addNotification('error', 'Failed to load certificate details');
    }
  }

  async function handleImportFile(): Promise<void> {
    importingFile = true;
    const added = await callBackend<number>('TrustService', 'ImportCertificateFile');
    importingFile = false;

    if (added !== null && added > 0) {
      addNotification('success', `Imported ${added} certificate${added > 1 ? 's' : ''} from file`);
      showImportDialog = false;
      await loadData();
    } else if (added === 0) {
      addNotification('warning', 'No new certificates were added (may already exist or file was cancelled)');
    } else {
      addNotification('error', 'Failed to import certificate file');
    }
  }

  async function handleTrustStrapImport(): Promise<void> {
    if (!isTruststrapTab(importTab)) return;
    const method = importTab;

    if (!truststrapServer.trim()) {
      addNotification('error', 'Server is required');
      return;
    }
    if (method === 'noise' && !truststrapServerStaticKey.trim()) {
      addNotification('error', 'Server static key is required for Noise');
      return;
    }
    if (method === 'spki' && !truststrapSPKIPin.trim()) {
      addNotification('error', 'SPKI pin is required for SPKI');
      return;
    }

    truststrapImporting = true;
    const { result, error } = await callBackendWithError<number>(
      'TrustService',
      'ImportFromTrustStrap',
      {
        method,
        server: truststrapServer.trim(),
        bundle_path: truststrapBundlePath.trim(),
        dns_server: truststrapDNSServer.trim(),
        dns_over_tls: truststrapDNSOverTLS,
        server_static_key: truststrapServerStaticKey.trim(),
        spki_pin_sha256: truststrapSPKIPin.trim(),
      },
    );
    truststrapImporting = false;

    if (error) {
      addNotification('error', `Import via ${method.toUpperCase()} failed: ${error}`);
      return;
    }
    const added = result ?? 0;
    if (added > 0) {
      addNotification('success',
        `Imported ${added} certificate${added > 1 ? 's' : ''} via ${method.toUpperCase()}`);
      resetTruststrapForm();
      showImportDialog = false;
      await loadData();
    } else {
      addNotification('warning', 'No new certificates were added (may already exist)');
    }
  }

  function hasBrowserExport(cert: TrustCertInfo): boolean {
    return (cert.tags ?? []).includes('browser-export');
  }

  async function toggleBrowserExport(cert: TrustCertInfo): Promise<void> {
    const enabled = !hasBrowserExport(cert);
    const ok = await callBackendVoid('TrustService', 'SetBrowserExport', cert.fingerprint, enabled);
    if (ok) {
      // Update local state.
      certificates = certificates.map((c) => {
        if (c.fingerprint !== cert.fingerprint) return c;
        const tags = (c.tags ?? []).filter((t) => t !== 'browser-export');
        if (enabled) tags.push('browser-export');
        return { ...c, tags };
      });
      addNotification('info', enabled
        ? 'Certificate will be included in browser trust bundle'
        : 'Certificate removed from browser trust bundle');
    } else {
      addNotification('error', 'Failed to update browser export setting');
    }
  }

  function promptSudo(action: 'install' | 'uninstall', fingerprint: string): void {
    sudoAction = action;
    sudoFingerprint = fingerprint;
    showSudoPrompt = true;
  }

  async function handleSudoAuthenticate(password: string): Promise<void> {
    showSudoPrompt = false;

    if (sudoAction === 'install') {
      const ok = await callBackendVoid('TrustService', 'InstallToSystem', sudoFingerprint, password);
      if (ok) {
        certificates = certificates.map((c) =>
          c.fingerprint === sudoFingerprint ? { ...c, system_installed: true } : c
        );
        addNotification('success', 'Certificate installed to system trust store');
      } else {
        addNotification('error', 'Failed to install certificate to system. Check your password and try again.');
      }
    } else {
      const ok = await callBackendVoid('TrustService', 'RemoveFromSystem', sudoFingerprint, password);
      if (ok) {
        certificates = certificates.map((c) =>
          c.fingerprint === sudoFingerprint ? { ...c, system_installed: false } : c
        );
        addNotification('info', 'Certificate removed from system trust store');
      } else {
        addNotification('error', 'Failed to remove certificate from system. Check your password and try again.');
      }
    }

    // Clear sensitive state
    sudoFingerprint = '';
  }

  function formatDate(iso: string): string {
    try {
      return new Date(iso).toLocaleDateString(undefined, {
        year: 'numeric', month: 'short', day: 'numeric',
      });
    } catch {
      return iso;
    }
  }

  function getPurposeStyle(purpose: string): string {
    const colors = purposeColors[purpose] ?? purposeColors['general'];
    return `background-color: ${colors.bg}; color: ${colors.fg};`;
  }

  function getPurposeLabel(purpose: string): string {
    const labels: Record<string, string> = {
      'tpm-manufacturer': 'TPM Manufacturer',
      'idevid-issuer': 'IDevID Issuer',
      'user-ca': 'User CA',
      'bootstrap-ca': 'Bootstrap CA',
      'android-hardware': 'Android Hardware',
      'general': 'General',
    };
    return labels[purpose] ?? purpose;
  }

  function truncateSubject(subject: string, maxLen: number = 80): string {
    return subject.length > maxLen ? subject.slice(0, maxLen) + '...' : subject;
  }

  const certColumns: Column[] = [
    { key: 'subject',     label: 'Subject',     sortable: true },
    { key: 'purpose',     label: 'Purpose',     width: '140px', sortable: true },
    { key: 'algorithm',   label: 'Algorithm',   width: '100px' },
    { key: 'not_after',   label: 'Expires',     width: '120px', sortable: true },
    { key: 'fingerprint', label: 'Fingerprint', width: '180px' },
  ];

  onMount(loadData);
</script>

<div class="trust-store-view">
  <GradientHeader title="Trust Store" subtitle="Trusted root certificates" />
  <ViewToolbar>
    <span class="cert-count-badge">{certCount}</span>
    <div class="toolbar-spacer" />
    <Button variant="outline" size="sm" icon={mdiRefresh} on:click={loadData}>Refresh</Button>
    <Button variant="primary" icon={mdiImport} data-testid="truststore-import-btn" on:click={() => { importPemData = ''; importTab = 'paste'; resetTruststrapForm(); showImportDialog = true; }}>
      Import
    </Button>
  </ViewToolbar>

  <div class="view-content">
    <!-- Purpose filter tabs -->
    <div class="filter-bar">
      <Icon path={mdiFilter} size={18} />
      {#each purposeTabs as tab}
        <button
          class="filter-chip"
          class:active={activeFilter === tab.value}
          on:click={() => (activeFilter = tab.value)}
        >
          {tab.label}
          {#if tab.value !== 'all'}
            <span class="filter-count">
              {certificates.filter((c) => c.purpose === tab.value).length}
            </span>
          {/if}
        </button>
      {/each}
    </div>

    <!-- Certificate table -->
    <DataTable
      columns={certColumns}
      rows={filteredCertificates}
      rowKey="fingerprint"
      pageSize={25}
      {loading}
      emptyIcon={mdiCertificate}
      emptyTitle="No Certificates"
      emptyDescription={activeFilter === 'all'
        ? 'Import PEM certificates to populate the trust store.'
        : `No certificates found with purpose "${getPurposeLabel(activeFilter)}".`}
      on:rowclick={(e) => handleViewCert(e.detail.row)}
    >
      <svelte:fragment slot="cell" let:row let:column>
        {#if column.key === 'subject'}
          <div class="cell-subject">
            <span class="cell-icon" class:cell-icon-expired={row.is_expired}>
              <Icon path={row.is_expired ? mdiAlert : mdiShieldCheckOutline} size={16} />
            </span>
            <div class="cell-subject-body">
              <span class="subject-text">{truncateSubject(row.subject)}</span>
              <div class="cert-badges">
                {#if row.is_ca}
                  <span class="ca-badge">CA</span>
                {/if}
                {#if row.is_expired}
                  <span class="expired-badge">Expired</span>
                {/if}
                {#if row.system_installed}
                  <span class="system-badge">System</span>
                {/if}
                {#if hasBrowserExport(row)}
                  <span class="browser-badge">Browser</span>
                {/if}
              </div>
            </div>
          </div>
        {:else if column.key === 'purpose'}
          <span class="purpose-badge" style={getPurposeStyle(row.purpose)}>
            {getPurposeLabel(row.purpose)}
          </span>
        {:else if column.key === 'algorithm'}
          <span class="font-mono cell-algo">{row.algorithm}</span>
        {:else if column.key === 'not_after'}
          <span class:cell-date-expired={row.is_expired}>
            {formatDate(row.not_after)}
          </span>
        {:else if column.key === 'fingerprint'}
          <span class="font-mono cell-fingerprint">{row.fingerprint}</span>
        {/if}
      </svelte:fragment>

      <svelte:fragment slot="actions" let:row>
        <!-- svelte-ignore a11y-click-events-have-key-events -->
        <!-- svelte-ignore a11y-no-static-element-interactions -->
        <div class="row-actions" on:click|stopPropagation>
          {#if row.system_installed}
            <Button variant="outline" size="sm" icon={mdiUpload}
              on:click={() => promptSudo('uninstall', row.fingerprint)}>
              Uninstall
            </Button>
          {:else}
            <Button variant="outline" size="sm" icon={mdiDownload}
              on:click={() => promptSudo('install', row.fingerprint)}>
              Install
            </Button>
          {/if}
          <Button
            variant={hasBrowserExport(row) ? 'outline' : 'text'}
            size="sm"
            icon={mdiWeb}
            on:click={() => toggleBrowserExport(row)}
          >
            {hasBrowserExport(row) ? 'Browser ✓' : 'Browser'}
          </Button>
          <Button
            variant="text"
            size="sm"
            icon={mdiDelete}
            on:click={() => confirmRemove(row.fingerprint, row.subject)}
          >
            Remove
          </Button>
        </div>
      </svelte:fragment>
    </DataTable>
  </div>

  <!-- Import Certificates Modal -->
  <Modal bind:open={showImportDialog} title="Import Certificates" maxWidth="640px">
    <div class="import-form">
      <div class="import-tabs" data-testid="import-tabs">
        {#each truststrapTabs as tab}
          <button
            class="import-tab"
            class:active={importTab === tab.value}
            on:click={() => (importTab = tab.value)}
            data-testid="import-tab-{tab.value}"
          >
            {tab.label}
          </button>
        {/each}
      </div>

      {#if importTab === 'paste'}
        <p class="text-body-medium import-hint">
          Paste one or more PEM-encoded certificates below. Each certificate must begin with
          <code>-----BEGIN CERTIFICATE-----</code>.
        </p>
        <div class="form-field">
          <label class="text-label-large" for="import-pem">PEM Data</label>
          <textarea
            id="import-pem"
            class="form-textarea"
            rows="10"
            placeholder="-----BEGIN CERTIFICATE-----&#10;MIIBxTCCAW...&#10;-----END CERTIFICATE-----"
            bind:value={importPemData}
          ></textarea>
        </div>
      {:else if importTab === 'file'}
        <p class="text-body-medium import-hint">
          Select a certificate file to import. Supports PEM (.pem, .crt) and DER (.der, .cer) formats.
        </p>
        <div class="file-import-action">
          <Button
            variant="outline"
            icon={mdiImport}
            loading={importingFile}
            on:click={handleImportFile}
          >
            Browse File...
          </Button>
        </div>
      {:else}
        <!-- Shared truststrap header: Server input is common to all four methods. -->
        <p class="text-body-medium import-hint">
          Retrieve a CA certificate bundle from a remote go-xkms server using the
          go-truststrap bootstrap mechanism. All certificates returned by the server
          will be added to this trust store.
        </p>

        <div class="form-field">
          <label class="text-label-large" for="truststrap-server">
            {importTab === 'noise' ? 'Server Address' : 'Server URL'}
          </label>
          <input
            id="truststrap-server"
            type="text"
            class="form-input"
            placeholder={truststrapServerPlaceholder(importTab)}
            bind:value={truststrapServer}
            data-testid="truststrap-server-input"
          />
        </div>

        {#if importTab !== 'noise'}
          <div class="form-field">
            <label class="text-label-large" for="truststrap-bundle-path">Bundle Path (optional)</label>
            <input
              id="truststrap-bundle-path"
              type="text"
              class="form-input"
              placeholder="/v1/ca/bootstrap"
              bind:value={truststrapBundlePath}
            />
          </div>
        {/if}

        {#if importTab === 'dane'}
          <div class="form-field">
            <label class="text-label-large" for="truststrap-dns">DNS Server (optional)</label>
            <input
              id="truststrap-dns"
              type="text"
              class="form-input"
              placeholder="8.8.8.8:53"
              bind:value={truststrapDNSServer}
            />
          </div>
          <label class="truststrap-checkbox">
            <input type="checkbox" bind:checked={truststrapDNSOverTLS} />
            <span class="text-body-medium">Use DNS-over-TLS (DoT)</span>
          </label>
          <p class="text-body-small import-hint">
            DANE uses DNSSEC-validated TLSA records to verify the server's CA bundle.
            DNSSEC is always enforced.
          </p>
        {:else if importTab === 'noise'}
          <div class="form-field">
            <label class="text-label-large" for="truststrap-noise-key">Server Static Key</label>
            <input
              id="truststrap-noise-key"
              type="text"
              class="form-input font-mono"
              placeholder="64 hex characters (32-byte Curve25519 public key)"
              bind:value={truststrapServerStaticKey}
              autocomplete="off"
              spellcheck="false"
              data-testid="truststrap-noise-key-input"
            />
          </div>
          <p class="text-body-small import-hint">
            The Noise_NK protocol authenticates the server using its pre-shared
            public key distributed out-of-band (QR code, provisioning config).
          </p>
        {:else if importTab === 'spki'}
          <div class="form-field">
            <label class="text-label-large" for="truststrap-spki-pin">SPKI Pin (SHA-256)</label>
            <input
              id="truststrap-spki-pin"
              type="text"
              class="form-input font-mono"
              placeholder="64 hex characters (SHA-256 of server SPKI)"
              bind:value={truststrapSPKIPin}
              autocomplete="off"
              spellcheck="false"
              data-testid="truststrap-spki-pin-input"
            />
          </div>
          <p class="text-body-small import-hint">
            SPKI pinning verifies the server certificate against a pre-shared
            SHA-256 hash of its Subject Public Key Info.
          </p>
        {:else}
          <p class="text-body-small import-hint">
            Direct HTTPS uses the operating system's trust store to validate the server.
            This is the least secure option and should only be used when you already
            trust the system root CAs.
          </p>
        {/if}
      {/if}
    </div>
    <svelte:fragment slot="actions">
      <Button
        variant="text"
        on:click={() => (showImportDialog = false)}
        disabled={importing || importingFile || truststrapImporting}
      >
        Cancel
      </Button>
      {#if importTab === 'paste'}
        <Button
          variant="primary"
          loading={importing}
          on:click={handleImport}
          disabled={!importPemData.trim()}
        >
          Import
        </Button>
      {:else if isTruststrapTab(importTab)}
        <Button
          variant="primary"
          icon={mdiImport}
          loading={truststrapImporting}
          on:click={handleTrustStrapImport}
          disabled={!truststrapServer.trim()
            || (importTab === 'noise' && !truststrapServerStaticKey.trim())
            || (importTab === 'spki' && !truststrapSPKIPin.trim())}
          data-testid="truststrap-fetch-btn"
        >
          Fetch & Import
        </Button>
      {/if}
    </svelte:fragment>
  </Modal>

  <!-- Remove Confirmation Modal -->
  <Modal bind:open={showRemoveConfirm} title="Remove Certificate?" maxWidth="440px">
    <p class="text-body-medium">
      Are you sure you want to remove this certificate from the trust store?
    </p>
    <div class="remove-cert-detail">
      <span class="text-label-small field-label">Subject</span>
      <span class="text-body-medium">{removeSubject}</span>
    </div>
    <p class="text-body-small remove-warning">
      This action cannot be undone. Applications relying on this certificate for trust chain
      verification will no longer be able to validate it.
    </p>
    <svelte:fragment slot="actions">
      <Button variant="text" on:click={() => (showRemoveConfirm = false)}>Cancel</Button>
      <Button variant="danger" on:click={handleRemove}>Remove</Button>
    </svelte:fragment>
  </Modal>

  <!-- Certificate Viewer Dialog -->
  <CertificateViewerDialog
    bind:open={showCertViewer}
    certPEM={selectedCertPEM}
    title={selectedCertTitle}
    onClose={() => { showCertViewer = false; selectedCertPEM = ''; }}
  />

  <!-- Sudo Authentication Prompt -->
  <SudoPromptDialog
    bind:open={showSudoPrompt}
    message={sudoAction === 'install'
      ? 'Installing a certificate to the system trust store requires administrator privileges.'
      : 'Removing a certificate from the system trust store requires administrator privileges.'}
    onAuthenticate={handleSudoAuthenticate}
    onCancel={() => { showSudoPrompt = false; sudoFingerprint = ''; }}
  />
</div>

<style>
  .trust-store-view {
    height: 100%;
    display: flex;
    flex-direction: column;
  }

  .cert-count-badge {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    min-width: 28px;
    height: 28px;
    padding: 0 8px;
    border-radius: var(--radius-full);
    background-color: var(--color-primary);
    color: var(--color-on-primary);
    font-size: 13px;
    font-weight: 600;
    font-family: var(--font-sans);
  }

  .view-content {
    flex: 1;
    overflow-y: auto;
    padding: 24px;
    display: flex;
    flex-direction: column;
    gap: 20px;
  }

  /* Filter bar */
  .filter-bar {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
    color: var(--color-on-surface-variant);
  }

  .filter-chip {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 6px 14px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-full);
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    font-family: var(--font-sans);
    font-size: 13px;
    transition: all var(--transition-fast);
  }

  .filter-chip:hover {
    background-color: var(--color-surface-container);
  }

  .filter-chip.active {
    background-color: var(--color-primary-95);
    color: var(--color-primary);
    border-color: var(--color-primary);
    font-weight: 600;
  }

  :global([data-theme="dark"]) .filter-chip.active {
    background-color: var(--color-primary-container);
    color: var(--color-on-primary-container);
  }

  .filter-count {
    font-size: 11px;
    opacity: 0.7;
  }

  /* DataTable cell content */
  .cell-subject {
    display: flex;
    align-items: flex-start;
    gap: 8px;
  }

  .cell-icon {
    display: flex;
    align-items: center;
    justify-content: center;
    width: 28px;
    height: 28px;
    border-radius: var(--radius-sm);
    background: var(--color-primary-95);
    color: var(--color-primary);
    flex-shrink: 0;
  }

  :global([data-theme="dark"]) .cell-icon {
    background: var(--color-primary-container);
    color: var(--color-on-primary-container);
  }

  .cell-icon-expired {
    background: var(--color-error-container);
    color: var(--color-error);
  }

  .cell-subject-body {
    display: flex;
    flex-direction: column;
    gap: 4px;
    min-width: 0;
  }

  .subject-text {
    font-weight: 600;
    color: var(--color-on-surface);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .cert-badges {
    display: flex;
    align-items: center;
    gap: 4px;
    flex-wrap: wrap;
  }

  .purpose-badge {
    display: inline-flex;
    align-items: center;
    padding: 2px 10px;
    border-radius: var(--radius-full);
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.3px;
    white-space: nowrap;
  }

  .ca-badge {
    display: inline-flex;
    align-items: center;
    padding: 2px 8px;
    border-radius: var(--radius-full);
    font-size: 11px;
    font-weight: 600;
    background-color: var(--color-primary-container);
    color: var(--color-on-primary-container);
  }

  .expired-badge {
    display: inline-flex;
    align-items: center;
    padding: 2px 8px;
    border-radius: var(--radius-full);
    font-size: 11px;
    font-weight: 600;
    background-color: var(--color-error-container);
    color: var(--color-error);
  }

  .system-badge {
    display: inline-flex;
    align-items: center;
    padding: 2px 8px;
    border-radius: var(--radius-full);
    font-size: 11px;
    font-weight: 600;
    background-color: var(--color-secondary-container);
    color: var(--color-on-secondary-container);
  }

  .browser-badge {
    display: inline-flex;
    align-items: center;
    padding: 2px 8px;
    border-radius: var(--radius-full);
    font-size: 11px;
    font-weight: 600;
    background-color: var(--color-tertiary-container, #e8f0fe);
    color: var(--color-on-tertiary-container, #1a73e8);
  }

  .cell-algo {
    color: var(--color-on-surface-variant);
    font-size: 12px;
  }

  .cell-date-expired {
    color: var(--color-error);
    font-weight: 600;
  }

  .cell-fingerprint {
    color: var(--color-on-surface-variant);
    font-size: 11px;
    opacity: 0.8;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    display: block;
    max-width: 170px;
  }

  .row-actions {
    display: flex;
    align-items: center;
    gap: 4px;
    justify-content: flex-end;
  }

  /* Import Modal */
  .import-form {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .import-tabs {
    display: flex;
    flex-wrap: wrap;
    gap: 0;
    border-bottom: 2px solid var(--color-outline-variant);
    margin-bottom: 16px;
  }

  .import-tab {
    flex: 1 1 auto;
    min-width: 88px;
    padding: 10px 14px;
    border: none;
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    font-family: var(--font-sans);
    font-size: 14px;
    font-weight: 500;
    border-bottom: 2px solid transparent;
    margin-bottom: -2px;
    transition: all var(--transition-fast);
  }

  .import-tab:hover {
    color: var(--color-on-surface);
    background-color: var(--color-surface-container);
  }

  .import-tab.active {
    color: var(--color-primary);
    border-bottom-color: var(--color-primary);
  }

  .file-import-action {
    display: flex;
    flex-direction: column;
    align-items: center;
    padding: 32px 16px;
    gap: 12px;
  }

  .import-hint {
    margin: 0;
    color: var(--color-on-surface-variant);
    line-height: 1.5;
  }

  .import-hint code {
    font-family: var(--font-mono, monospace);
    font-size: 12px;
    padding: 2px 6px;
    border-radius: 4px;
    background-color: var(--color-surface-container);
  }

  .form-field {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .form-field label {
    color: var(--color-on-surface-variant);
  }

  .form-textarea {
    padding: 10px 12px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    background: var(--color-surface);
    color: var(--color-on-surface);
    font-family: var(--font-mono, monospace);
    font-size: 13px;
    outline: none;
    resize: vertical;
    min-height: 160px;
    transition: border-color var(--transition-fast);
  }

  .form-textarea:focus {
    border-color: var(--color-primary);
  }

  .form-input {
    padding: 10px 12px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    background: var(--color-surface);
    color: var(--color-on-surface);
    font-family: var(--font-sans);
    font-size: 14px;
    outline: none;
    transition: border-color var(--transition-fast);
  }

  .form-input.font-mono {
    font-family: var(--font-mono, monospace);
    font-size: 13px;
  }

  .form-input:focus {
    border-color: var(--color-primary);
  }

  .truststrap-checkbox {
    display: flex;
    align-items: center;
    gap: 8px;
    cursor: pointer;
    color: var(--color-on-surface-variant);
  }

  .truststrap-checkbox input[type="checkbox"] {
    width: 16px;
    height: 16px;
    cursor: pointer;
    accent-color: var(--color-primary);
  }

  /* Remove Confirmation Modal */
  .remove-cert-detail {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding: 12px;
    border-radius: var(--radius-sm);
    background-color: var(--color-surface-container-low);
    margin: 8px 0;
  }

  .field-label {
    color: var(--color-on-surface-variant);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .remove-warning {
    color: var(--color-error);
    margin: 4px 0 0;
    font-style: italic;
  }
</style>
