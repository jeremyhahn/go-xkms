<script lang="ts">
  import { onMount } from 'svelte';
  import Card from '$lib/components/Card.svelte';
  import GradientHeader from '$lib/components/GradientHeader.svelte';
  import ViewToolbar from '$lib/components/ViewToolbar.svelte';
  import Button from '$lib/components/Button.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
  import EmptyState from '$lib/components/EmptyState.svelte';
  import BackendSelector from '$lib/components/BackendSelector.svelte';
  import {
    mdiCertificate, mdiRefresh, mdiAlert,
    mdiDownload
  } from '$lib/utils/icons';
  import { isWailsAvailable, callBackend } from '$lib/api/backend';
  import type { RemoteCertificateInfo } from '$lib/api/backend';

  let certificates: RemoteCertificateInfo[] = [];
  let selectedBackend = 'all';
  let loading = true;

  const backendColors: Record<string, { bg: string; fg: string }> = {
    software:  { bg: 'var(--color-secondary-container)', fg: 'var(--color-on-secondary-container)' },
    tpm2:      { bg: 'var(--color-primary-container)', fg: 'var(--color-on-primary-container)' },
    pkcs11:    { bg: 'var(--color-tertiary-container, #f3e8fd)', fg: 'var(--color-on-tertiary-container, #4a1e73)' },
    phone:     { bg: '#fff3cd', fg: '#856404' },
    awskms:    { bg: '#d4edda', fg: '#155724' },
    gcpkms:    { bg: '#d4edda', fg: '#155724' },
    azurekv:   { bg: '#cce5ff', fg: '#004085' },
    vault:     { bg: 'var(--color-surface-container)', fg: 'var(--color-on-surface-variant)' },
  };

  $: filteredCertificates = selectedBackend === 'all'
    ? certificates
    : certificates.filter((c) => c.backend === selectedBackend);

  async function loadData(): Promise<void> {
    if (!isWailsAvailable()) {
      loading = false;
      return;
    }
    loading = true;
    const certList = await callBackend<RemoteCertificateInfo[]>('CertificateService', 'ListAllCertificates');
    certificates = certList ?? [];
    loading = false;
  }

  async function exportPem(cert: RemoteCertificateInfo): Promise<void> {
    if (!cert.pem) return;
    try {
      const blob = new Blob([cert.pem], { type: 'application/x-pem-file' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${cert.key_id || 'certificate'}.pem`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch {
      // download may not be supported in all Wails environments
    }
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

  function getBackendStyle(backend: string): string {
    const colors = backendColors[backend] ?? backendColors['vault'];
    return `background-color: ${colors.bg}; color: ${colors.fg};`;
  }

  function truncateSubject(subject: string, maxLen: number = 80): string {
    return subject.length > maxLen ? subject.slice(0, maxLen) + '...' : subject;
  }

  onMount(loadData);
</script>

<div class="certificates-view">
  <GradientHeader title="Certificates" subtitle="X.509 certificate management" />
  <ViewToolbar>
    <span class="cert-count-badge">{certificates.length}</span>
    <div class="toolbar-spacer" />
    <Button variant="outline" size="sm" icon={mdiRefresh} on:click={loadData}>Refresh</Button>
  </ViewToolbar>

  {#if loading}
    <div class="loading-container">
      <LoadingSpinner size={48} />
      <p class="text-body-medium loading-text">Loading certificates...</p>
    </div>
  {:else}
    <div class="view-content">
      <!-- Backend filter chips via shared component -->
      <BackendSelector
        capability="signing"
        bind:selected={selectedBackend}
        on:change={(e) => (selectedBackend = e.detail)}
      />

      <!-- Certificate list -->
      {#if filteredCertificates.length === 0}
        <Card variant="outlined">
          <EmptyState
            icon={mdiCertificate}
            title="No Certificates Found"
            description={selectedBackend === 'all'
              ? 'No certificates are available across any backend.'
              : `No certificates found in the "${selectedBackend}" backend.`}
          />
        </Card>
      {:else}
        <div class="cert-list">
          {#each filteredCertificates as cert (cert.fingerprint)}
            <div class="cert-row" class:cert-expired={cert.is_expired}>
              <div class="cert-icon">
                <Icon path={cert.is_expired ? mdiAlert : mdiCertificate} size={20} />
              </div>

              <div class="cert-info">
                <div class="cert-primary">
                  <span class="text-title-small cert-subject">{truncateSubject(cert.subject)}</span>
                  <div class="cert-badges">
                    <span class="backend-badge" style={getBackendStyle(cert.backend)}>
                      {cert.backend}
                    </span>
                    {#if cert.is_ca}
                      <span class="ca-badge">CA</span>
                    {/if}
                    {#if cert.is_expired}
                      <span class="expired-badge">Expired</span>
                    {/if}
                  </div>
                </div>
                <div class="cert-secondary">
                  <span class="text-body-small cert-issuer">Issuer: {truncateSubject(cert.issuer, 60)}</span>
                  <span class="cert-detail-sep">&middot;</span>
                  <span class="text-body-small cert-algo">{cert.algorithm}</span>
                  <span class="cert-detail-sep">&middot;</span>
                  <span class="text-body-small" class:cert-date-expired={cert.is_expired}>
                    Expires: {formatDate(cert.not_after)}
                  </span>
                </div>
                <div class="cert-tertiary">
                  <span class="text-body-small cert-key-id">Key: {cert.key_id}</span>
                  <span class="cert-detail-sep">&middot;</span>
                  <span class="text-body-small cert-fingerprint font-mono">{cert.fingerprint}</span>
                </div>
              </div>

              <div class="cert-actions">
                {#if cert.pem}
                  <Button
                    variant="outline"
                    size="sm"
                    icon={mdiDownload}
                    on:click={() => exportPem(cert)}
                  >
                    Export
                  </Button>
                {/if}
              </div>
            </div>
          {/each}
        </div>
      {/if}
    </div>
  {/if}
</div>

<style>
  .certificates-view {
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

  .loading-container {
    flex: 1;
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 16px;
    padding: 48px;
  }

  .loading-text {
    color: var(--color-on-surface-variant);
    margin: 0;
  }

  /* Certificate list */
  .cert-list {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .cert-row {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 14px 16px;
    border-radius: var(--radius-md);
    background-color: var(--color-surface-container-low);
    border: 1px solid var(--color-outline-variant);
    transition: border-color var(--transition-fast);
  }

  .cert-row:hover {
    border-color: var(--color-outline);
  }

  .cert-row.cert-expired {
    border-color: var(--color-error);
    background-color: var(--color-error-container);
  }

  :global([data-theme="dark"]) .cert-row.cert-expired {
    background-color: rgba(var(--color-error-rgb, 179, 38, 30), 0.12);
  }

  .cert-icon {
    width: 40px;
    height: 40px;
    border-radius: var(--radius-md);
    background: var(--color-primary-95);
    display: flex;
    align-items: center;
    justify-content: center;
    color: var(--color-primary);
    flex-shrink: 0;
    margin-top: 2px;
  }

  :global([data-theme="dark"]) .cert-icon {
    background: var(--color-primary-container);
    color: var(--color-on-primary-container);
  }

  .cert-expired .cert-icon {
    background: var(--color-error-container);
    color: var(--color-error);
  }

  .cert-info {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 4px;
    min-width: 0;
  }

  .cert-primary {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-wrap: wrap;
  }

  .cert-subject {
    color: var(--color-on-surface);
    font-weight: 600;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    max-width: 400px;
  }

  .cert-badges {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
  }

  .backend-badge {
    display: inline-flex;
    align-items: center;
    padding: 2px 10px;
    border-radius: var(--radius-full);
    font-size: 11px;
    font-weight: 600;
    letter-spacing: 0.3px;
    text-transform: uppercase;
    white-space: nowrap;
    font-family: var(--font-mono);
  }

  .ca-badge {
    display: inline-flex;
    align-items: center;
    padding: 2px 8px;
    border-radius: var(--radius-full);
    font-size: 11px;
    font-weight: 600;
    background-color: #d4edda;
    color: #155724;
  }

  :global([data-theme="dark"]) .ca-badge {
    background-color: rgba(21, 87, 36, 0.3);
    color: #a3d9a5;
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

  .cert-secondary {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
  }

  .cert-tertiary {
    display: flex;
    align-items: center;
    gap: 6px;
    flex-wrap: wrap;
  }

  .cert-issuer {
    color: var(--color-on-surface-variant);
  }

  .cert-detail-sep {
    color: var(--color-outline-variant);
    font-size: 10px;
  }

  .cert-algo {
    color: var(--color-on-surface-variant);
    font-family: var(--font-mono);
  }

  .cert-date-expired {
    color: var(--color-error);
    font-weight: 600;
  }

  .cert-key-id {
    color: var(--color-on-surface-variant);
    font-family: var(--font-mono);
  }

  .cert-fingerprint {
    color: var(--color-on-surface-variant);
    font-size: 11px;
    opacity: 0.7;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .cert-actions {
    display: flex;
    align-items: center;
    gap: 4px;
    flex-shrink: 0;
    margin-top: 4px;
  }
</style>
