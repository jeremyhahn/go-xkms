<script lang="ts">
  import { onMount } from 'svelte';
  import Card from '$lib/components/Card.svelte';
  import GradientHeader from '$lib/components/GradientHeader.svelte';
  import ViewToolbar from '$lib/components/ViewToolbar.svelte';
  import Button from '$lib/components/Button.svelte';
  import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
  import EmptyState from '$lib/components/EmptyState.svelte';
  import { mdiCertificate, mdiRefresh } from '$lib/utils/icons';
  import { isWailsAvailable, callBackend, callBackendWithError } from '$lib/api/backend';
  import { addNotification } from '$lib/stores/notifications';

  /** CA certificate fields from CAService.GetCAInfo. */
  interface CACertInfo {
    subject: string;
    issuer: string;
    serial: string;
    algorithm: string;
    not_before: string;
    not_after: string;
    is_ca: boolean;
  }

  /** An issued certificate from CAService.IssueCertificate. */
  interface IssuedCertInfo {
    serial: string;
    subject: string;
    certificate_pem: string;
  }

  type CAMode = 'local' | 'remote' | 'none';

  const MODE_LABELS: Record<CAMode, string> = {
    local: 'Local CA',
    remote: 'Server CA',
    none: 'No CA available',
  };

  let mode: CAMode = 'none';
  let info: CACertInfo | null = null;
  let loading = true;

  let profile = 'server';
  let commonName = '';
  let organization = '';
  let sans = '';
  let validityDays = 365;
  let algorithm = '';
  let issuing = false;
  let issued: IssuedCertInfo | null = null;

  async function loadData(): Promise<void> {
    if (!isWailsAvailable()) {
      loading = false;
      return;
    }
    loading = true;
    mode = (await callBackend<CAMode>('CAService', 'GetCAMode')) ?? 'none';
    info = null;
    if (mode !== 'none') {
      const { result, error } = await callBackendWithError<CACertInfo>('CAService', 'GetCAInfo');
      if (error) {
        addNotification('error', `Failed to load the CA certificate: ${error}`);
      }
      info = result;
    }
    loading = false;
  }

  async function issue(): Promise<void> {
    if (!commonName.trim()) {
      addNotification('error', 'Common name is required');
      return;
    }
    issuing = true;
    issued = null;
    const { result, error } = await callBackendWithError<IssuedCertInfo>(
      'CAService', 'IssueCertificate',
      profile, commonName.trim(), organization, sans, Number(validityDays), algorithm,
    );
    issuing = false;
    if (error || !result) {
      addNotification('error', `Failed to issue the certificate${error ? `: ${error}` : ''}`);
      return;
    }
    issued = result;
    addNotification('success', `Issued a certificate for "${commonName.trim()}"`);
  }

  onMount(loadData);
</script>

<div class="ca-view">
  <GradientHeader title="Certificate Authority" subtitle="The local CA, or the connected server's CA" />
  <ViewToolbar>
    <span class="mode-badge mode-{mode}" data-testid="ca-mode">{MODE_LABELS[mode]}</span>
    <div class="toolbar-spacer" />
    <Button variant="outline" size="sm" icon={mdiRefresh} on:click={loadData}>Refresh</Button>
  </ViewToolbar>

  {#if loading}
    <div class="loading-container">
      <LoadingSpinner size={48} />
      <p class="text-body-medium loading-text">Loading the CA...</p>
    </div>
  {:else}
    <div class="view-content">
      {#if !info}
        <Card variant="outlined">
          <EmptyState
            icon={mdiCertificate}
            title="No CA available"
            description="Connect to an xkms server, or unlock xKey to use its local CA."
          />
        </Card>
      {:else}
        <Card variant="outlined">
          <dl class="ca-fields" data-testid="ca-info">
            <dt>Subject</dt><dd>{info.subject}</dd>
            <dt>Issuer</dt><dd>{info.issuer}</dd>
            <dt>Serial</dt><dd class="mono">{info.serial}</dd>
            <dt>Algorithm</dt><dd>{info.algorithm || '—'}</dd>
            <dt>Valid from</dt><dd>{info.not_before}</dd>
            <dt>Valid until</dt><dd>{info.not_after}</dd>
            <dt>CA</dt><dd>{info.is_ca ? 'Yes' : 'No'}</dd>
          </dl>
        </Card>

        <Card variant="outlined">
          <form class="issue-form" on:submit|preventDefault={issue}>
            <h3 class="text-title-medium">Issue a certificate</h3>
            <label>
              <span>Profile</span>
              <select bind:value={profile} aria-label="Profile">
                <option value="server">server</option>
                <option value="client">client</option>
                <option value="code-signing">code-signing</option>
              </select>
            </label>
            <label>
              <span>Common name</span>
              <input type="text" bind:value={commonName} aria-label="Common name" />
            </label>
            <label>
              <span>Organization</span>
              <input type="text" bind:value={organization} aria-label="Organization" />
            </label>
            <label>
              <span>SANs (comma-separated)</span>
              <input type="text" bind:value={sans} aria-label="SANs" />
            </label>
            <label>
              <span>Validity (days)</span>
              <input type="number" min="1" bind:value={validityDays} aria-label="Validity days" />
            </label>
            <label>
              <span>Algorithm</span>
              <input type="text" bind:value={algorithm} placeholder="default" aria-label="Algorithm" />
            </label>
            <div class="form-actions">
              <Button type="submit" disabled={issuing}>Issue</Button>
            </div>
          </form>
          {#if issued}
            <pre class="issued-pem" data-testid="ca-issued-pem">{issued.certificate_pem}</pre>
          {/if}
        </Card>
      {/if}
    </div>
  {/if}
</div>

<style>
  .ca-view {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }
  .view-content {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }
  .toolbar-spacer {
    flex: 1;
  }
  .mode-badge {
    padding: 2px 10px;
    border-radius: 12px;
    font-size: 0.8rem;
    background: var(--md-sys-color-surface-variant);
    color: var(--md-sys-color-on-surface-variant);
  }
  .mode-local,
  .mode-remote {
    background: var(--md-sys-color-primary-container);
    color: var(--md-sys-color-on-primary-container);
  }
  .loading-container {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 12px;
    padding: 48px;
  }
  .ca-fields {
    display: grid;
    grid-template-columns: max-content 1fr;
    gap: 6px 16px;
    margin: 0;
  }
  .ca-fields dt {
    font-weight: 500;
  }
  .ca-fields dd {
    margin: 0;
    word-break: break-all;
  }
  .mono,
  .issued-pem {
    font-family: monospace;
  }
  .issue-form {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }
  .issue-form label {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }
  .form-actions {
    display: flex;
    justify-content: flex-end;
  }
  .issued-pem {
    white-space: pre-wrap;
    word-break: break-all;
    font-size: 0.75rem;
    margin-top: 12px;
  }
</style>
