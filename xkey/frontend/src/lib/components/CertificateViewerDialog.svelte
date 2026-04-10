<script lang="ts">
  import Modal from './Modal.svelte';
  import Button from './Button.svelte';
  import Icon from './Icon.svelte';
  import LoadingSpinner from './LoadingSpinner.svelte';
  import { mdiContentCopy, mdiCertificate } from '$lib/utils/icons';
  import { addNotification } from '$lib/stores/notifications';
  import { callBackend } from '$lib/api/backend';
  import type { CertificateDetails } from '$lib/api/backend';

  export let open: boolean = false;
  export let certPEM: string = '';
  export let title: string = 'Certificate';
  export let onClose: () => void = () => {};

  let details: CertificateDetails | null = null;
  let loading = false;
  let parseError = '';

  let expandedSections: Record<string, boolean> = {
    identity: true,
    subject: true,
    issuer: false,
    validity: true,
    fingerprints: false,
    publicKey: false,
    basicConstraints: false,
    keyUsage: true,
    extensions: false,
    san: false,
    signature: false,
  };

  $: if (open && certPEM) {
    loadCertDetails(certPEM);
  }

  async function loadCertDetails(pem: string): Promise<void> {
    loading = true;
    parseError = '';
    const result = await callBackend<CertificateDetails>('TPMService', 'ParseCertificate', pem);
    if (result) {
      details = result;
    } else {
      parseError = 'Failed to parse certificate';
    }
    loading = false;
  }

  function toggleSection(name: string): void {
    expandedSections[name] = !expandedSections[name];
    expandedSections = expandedSections;
  }

  async function handleCopyPEM(): Promise<void> {
    if (typeof navigator !== 'undefined' && navigator.clipboard) {
      await navigator.clipboard.writeText(certPEM);
      addNotification('success', 'Certificate PEM copied to clipboard');
    }
  }
</script>

<Modal bind:open title={title} maxWidth="640px">
  <div class="cert-viewer">
    <div class="cert-header">
      <Icon path={mdiCertificate} size={24} />
      <span class="text-title-small">X.509 Certificate</span>
    </div>

    {#if loading}
      <div class="loading-container">
        <LoadingSpinner size={32} />
        <span class="text-body-medium">Parsing certificate...</span>
      </div>
    {:else if parseError}
      <p class="text-body-medium no-cert">{parseError}</p>
    {:else if details}
      <!-- Identity -->
      <button class="section-header" on:click={() => toggleSection('identity')}>
        <span class="text-label-medium section-label">IDENTITY</span>
        <span class="section-toggle">{expandedSections.identity ? '\u2212' : '+'}</span>
      </button>
      {#if expandedSections.identity}
        <div class="section-content">
          <div class="cert-field">
            <span class="text-label-medium cert-label">Version</span>
            <span class="text-body-medium cert-value">{details.version}</span>
          </div>
          <div class="cert-field">
            <span class="text-label-medium cert-label">Serial Number</span>
            <span class="text-body-medium cert-value font-mono">{details.serial_number}</span>
          </div>
        </div>
      {/if}

      <!-- Subject -->
      <button class="section-header" on:click={() => toggleSection('subject')}>
        <span class="text-label-medium section-label">SUBJECT</span>
        <span class="section-toggle">{expandedSections.subject ? '\u2212' : '+'}</span>
      </button>
      {#if expandedSections.subject}
        <div class="section-content">
          {#if details.subject_cn}
            <div class="cert-field">
              <span class="text-label-medium cert-label">Common Name</span>
              <span class="text-body-medium cert-value">{details.subject_cn}</span>
            </div>
          {/if}
          {#if details.subject_org}
            <div class="cert-field">
              <span class="text-label-medium cert-label">Organization</span>
              <span class="text-body-medium cert-value">{details.subject_org}</span>
            </div>
          {/if}
          {#if details.subject_org_unit}
            <div class="cert-field">
              <span class="text-label-medium cert-label">Organizational Unit</span>
              <span class="text-body-medium cert-value">{details.subject_org_unit}</span>
            </div>
          {/if}
          {#if details.subject_country}
            <div class="cert-field">
              <span class="text-label-medium cert-label">Country</span>
              <span class="text-body-medium cert-value">{details.subject_country}</span>
            </div>
          {/if}
          {#if details.subject_province}
            <div class="cert-field">
              <span class="text-label-medium cert-label">Province</span>
              <span class="text-body-medium cert-value">{details.subject_province}</span>
            </div>
          {/if}
          {#if details.subject_locality}
            <div class="cert-field">
              <span class="text-label-medium cert-label">Locality</span>
              <span class="text-body-medium cert-value">{details.subject_locality}</span>
            </div>
          {/if}
          {#if details.subject_serial_number}
            <div class="cert-field">
              <span class="text-label-medium cert-label">Serial Number</span>
              <span class="text-body-medium cert-value">{details.subject_serial_number}</span>
            </div>
          {/if}
        </div>
      {/if}

      <!-- Issuer -->
      <button class="section-header" on:click={() => toggleSection('issuer')}>
        <span class="text-label-medium section-label">ISSUER</span>
        <span class="section-toggle">{expandedSections.issuer ? '\u2212' : '+'}</span>
      </button>
      {#if expandedSections.issuer}
        <div class="section-content">
          {#if details.issuer_cn}
            <div class="cert-field">
              <span class="text-label-medium cert-label">Common Name</span>
              <span class="text-body-medium cert-value">{details.issuer_cn}</span>
            </div>
          {/if}
          {#if details.issuer_org}
            <div class="cert-field">
              <span class="text-label-medium cert-label">Organization</span>
              <span class="text-body-medium cert-value">{details.issuer_org}</span>
            </div>
          {/if}
          {#if details.issuer_org_unit}
            <div class="cert-field">
              <span class="text-label-medium cert-label">Organizational Unit</span>
              <span class="text-body-medium cert-value">{details.issuer_org_unit}</span>
            </div>
          {/if}
          {#if details.issuer_country}
            <div class="cert-field">
              <span class="text-label-medium cert-label">Country</span>
              <span class="text-body-medium cert-value">{details.issuer_country}</span>
            </div>
          {/if}
        </div>
      {/if}

      <!-- Validity -->
      <button class="section-header" on:click={() => toggleSection('validity')}>
        <span class="text-label-medium section-label">VALIDITY</span>
        <span class="section-toggle">{expandedSections.validity ? '\u2212' : '+'}</span>
      </button>
      {#if expandedSections.validity}
        <div class="section-content">
          <div class="cert-dates">
            <div class="cert-field">
              <span class="text-label-medium cert-label">Not Before</span>
              <span class="text-body-medium cert-value">{details.not_before}</span>
            </div>
            <div class="cert-field">
              <span class="text-label-medium cert-label">Not After</span>
              <span class="text-body-medium cert-value">{details.not_after}</span>
            </div>
          </div>
          <div class="cert-field">
            <span class="text-label-medium cert-label">Signature Algorithm</span>
            <span class="text-body-medium cert-value">{details.signature_algorithm}</span>
          </div>
        </div>
      {/if}

      <!-- Fingerprints -->
      <button class="section-header" on:click={() => toggleSection('fingerprints')}>
        <span class="text-label-medium section-label">FINGERPRINTS</span>
        <span class="section-toggle">{expandedSections.fingerprints ? '\u2212' : '+'}</span>
      </button>
      {#if expandedSections.fingerprints}
        <div class="section-content">
          <div class="cert-field">
            <span class="text-label-medium cert-label">SHA-256</span>
            <span class="text-body-medium cert-value font-mono">{details.fingerprint_sha256}</span>
          </div>
          <div class="cert-field">
            <span class="text-label-medium cert-label">SHA-1</span>
            <span class="text-body-medium cert-value font-mono">{details.fingerprint_sha1}</span>
          </div>
          <div class="cert-field">
            <span class="text-label-medium cert-label">MD5</span>
            <span class="text-body-medium cert-value font-mono">{details.fingerprint_md5}</span>
          </div>
        </div>
      {/if}

      <!-- Public Key -->
      <button class="section-header" on:click={() => toggleSection('publicKey')}>
        <span class="text-label-medium section-label">PUBLIC KEY</span>
        <span class="section-toggle">{expandedSections.publicKey ? '\u2212' : '+'}</span>
      </button>
      {#if expandedSections.publicKey}
        <div class="section-content">
          <div class="cert-field">
            <span class="text-label-medium cert-label">Algorithm</span>
            <span class="text-body-medium cert-value">{details.public_key_algorithm}</span>
          </div>
          <div class="cert-field">
            <span class="text-label-medium cert-label">Key Size</span>
            <span class="text-body-medium cert-value">{details.public_key_size} bits</span>
          </div>
          {#if details.subject_key_id}
            <div class="cert-field">
              <span class="text-label-medium cert-label">Subject Key ID</span>
              <span class="text-body-medium cert-value font-mono">{details.subject_key_id}</span>
            </div>
          {/if}
          {#if details.public_key_hex}
            <div class="cert-field">
              <span class="text-label-medium cert-label">Public Key</span>
              <span class="text-body-medium cert-value font-mono">{details.public_key_hex.length > 64 ? details.public_key_hex.substring(0, 64) + '...' : details.public_key_hex}</span>
            </div>
          {/if}
        </div>
      {/if}

      <!-- Basic Constraints -->
      <button class="section-header" on:click={() => toggleSection('basicConstraints')}>
        <span class="text-label-medium section-label">BASIC CONSTRAINTS</span>
        <span class="section-toggle">{expandedSections.basicConstraints ? '\u2212' : '+'}</span>
      </button>
      {#if expandedSections.basicConstraints}
        <div class="section-content">
          <div class="cert-field">
            <span class="text-label-medium cert-label">Is CA</span>
            <span class="text-body-medium cert-value">{details.is_ca ? 'Yes' : 'No'}</span>
          </div>
          {#if details.is_ca}
            <div class="cert-field">
              <span class="text-label-medium cert-label">Max Path Length</span>
              <span class="text-body-medium cert-value">{details.max_path_len_zero ? 0 : details.max_path_len}</span>
            </div>
          {/if}
        </div>
      {/if}

      <!-- Key Usage -->
      <button class="section-header" on:click={() => toggleSection('keyUsage')}>
        <span class="text-label-medium section-label">KEY USAGE</span>
        <span class="section-toggle">{expandedSections.keyUsage ? '\u2212' : '+'}</span>
      </button>
      {#if expandedSections.keyUsage}
        <div class="section-content">
          {#if details.key_usage}
            <div class="cert-field">
              <span class="text-label-medium cert-label">Key Usage</span>
              <span class="text-body-medium cert-value">{details.key_usage}</span>
            </div>
          {/if}
          {#if details.ext_key_usage && details.ext_key_usage.length > 0}
            <div class="cert-field">
              <span class="text-label-medium cert-label">Extended Key Usage</span>
              <span class="text-body-medium cert-value">{details.ext_key_usage.join(', ')}</span>
            </div>
          {/if}
        </div>
      {/if}

      <!-- Subject Alt Names -->
      {#if details.subject_alt_names}
        <button class="section-header" on:click={() => toggleSection('san')}>
          <span class="text-label-medium section-label">SUBJECT ALT NAMES</span>
          <span class="section-toggle">{expandedSections.san ? '\u2212' : '+'}</span>
        </button>
        {#if expandedSections.san}
          <div class="section-content">
            <div class="cert-field">
              <span class="text-label-medium cert-label">SAN</span>
              <span class="text-body-medium cert-value">{details.subject_alt_names}</span>
            </div>
          </div>
        {/if}
      {/if}

      <!-- Extensions -->
      {#if details.extensions && details.extensions.length > 0}
        <button class="section-header" on:click={() => toggleSection('extensions')}>
          <span class="text-label-medium section-label">EXTENSIONS</span>
          <span class="section-toggle">{expandedSections.extensions ? '\u2212' : '+'}</span>
        </button>
        {#if expandedSections.extensions}
          <div class="section-content">
            {#each details.extensions as ext}
              <div class="ext-row">
                <div>
                  <span class="ext-name">{ext.name || ext.oid}</span>
                  {#if ext.critical}
                    <span class="critical-badge">CRITICAL</span>
                  {/if}
                </div>
                <div class="ext-oid">{ext.oid}</div>
                {#if ext.value}
                  <span class="text-body-medium cert-value">{ext.value}</span>
                {/if}
              </div>
            {/each}
          </div>
        {/if}
      {/if}

      <!-- Signature -->
      <button class="section-header" on:click={() => toggleSection('signature')}>
        <span class="text-label-medium section-label">SIGNATURE</span>
        <span class="section-toggle">{expandedSections.signature ? '\u2212' : '+'}</span>
      </button>
      {#if expandedSections.signature}
        <div class="section-content">
          {#if details.signature_hex}
            <div class="cert-field">
              <span class="text-label-medium cert-label">Signature</span>
              <span class="text-body-medium cert-value font-mono">{details.signature_hex.length > 128 ? details.signature_hex.substring(0, 128) + '...' : details.signature_hex}</span>
            </div>
          {/if}
        </div>
      {/if}

      <!-- PEM Data -->
      <div class="cert-pem-section">
        <div class="cert-pem-header">
          <span class="text-label-medium">PEM Data</span>
          <button class="copy-btn" on:click={handleCopyPEM} title="Copy PEM to clipboard" aria-label="Copy PEM to clipboard">
            <Icon path={mdiContentCopy} size={16} />
          </button>
        </div>
        <pre class="cert-pem-content text-body-small font-mono">{certPEM}</pre>
      </div>
    {:else}
      <p class="text-body-medium no-cert">No certificate data available.</p>
    {/if}
  </div>

  <svelte:fragment slot="actions">
    <Button variant="outline" icon={mdiContentCopy} on:click={handleCopyPEM}>Copy PEM</Button>
    <Button variant="text" on:click={() => { open = false; onClose(); }}>Close</Button>
  </svelte:fragment>
</Modal>

<style>
  .cert-viewer {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .cert-header {
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--color-primary);
    padding-bottom: 8px;
    border-bottom: 1px solid var(--color-outline-variant);
  }

  .section-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    width: 100%;
    padding: 8px 0;
    border: none;
    background: transparent;
    cursor: pointer;
    border-bottom: 1px solid var(--color-outline-variant);
    color: var(--color-on-surface);
  }

  .section-header:hover {
    color: var(--color-primary);
  }

  .section-label {
    text-transform: uppercase;
    letter-spacing: 0.5px;
    color: var(--color-on-surface-variant);
  }

  .section-toggle {
    font-size: 16px;
    color: var(--color-on-surface-variant);
  }

  .section-content {
    padding: 8px 0 16px 0;
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .cert-field {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .cert-label {
    color: var(--color-on-surface-variant);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    font-size: 11px;
  }

  .cert-value {
    color: var(--color-on-surface);
    word-break: break-all;
  }

  .cert-dates {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 12px;
  }

  .ext-row {
    padding: 6px 0;
    border-bottom: 1px solid var(--color-outline-variant);
  }

  .ext-row:last-child {
    border-bottom: none;
  }

  .ext-name {
    font-weight: 500;
    color: var(--color-on-surface);
  }

  .ext-oid {
    font-size: 11px;
    color: var(--color-on-surface-variant);
  }

  .critical-badge {
    display: inline-block;
    padding: 1px 6px;
    border-radius: 4px;
    font-size: 10px;
    font-weight: 600;
    background-color: var(--color-security-danger-container);
    color: var(--color-error);
    margin-left: 4px;
  }

  .loading-container {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 12px;
    padding: 24px;
  }

  .cert-pem-section {
    margin-top: 8px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-md);
    overflow: hidden;
  }

  .cert-pem-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 8px 12px;
    background-color: var(--color-surface-container);
    color: var(--color-on-surface-variant);
  }

  .copy-btn {
    width: 28px;
    height: 28px;
    border: none;
    border-radius: var(--radius-sm);
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: background-color var(--transition-fast);
  }

  .copy-btn:hover {
    background-color: var(--color-surface-variant);
  }

  .cert-pem-content {
    margin: 0;
    padding: 12px;
    max-height: 200px;
    overflow: auto;
    background-color: var(--color-surface-container-lowest);
    color: var(--color-on-surface);
    font-size: 11px;
    line-height: 1.4;
    white-space: pre-wrap;
    word-break: break-all;
  }

  .no-cert {
    color: var(--color-on-surface-variant);
    text-align: center;
    padding: 24px;
    margin: 0;
  }
</style>
