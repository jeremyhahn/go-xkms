<script lang="ts">
  import Card from '$lib/components/Card.svelte';
  import Button from '$lib/components/Button.svelte';
  import StatusBadge from '$lib/components/StatusBadge.svelte';
  import Toggle from '$lib/components/Toggle.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import {
    mdiArrowLeft, mdiCellphone, mdiShieldCheckOutline, mdiKey,
    mdiBluetoothConnect, mdiFingerprint, mdiConnection, mdiDelete,
    mdiChevronDown, mdiChevronUp, mdiLock, mdiLockOpen, mdiCertificate,
    mdiLanConnect, mdiPuzzleOutline
  } from '$lib/utils/icons';
  import { navigateTo, appState } from '$lib/stores/app';
  import { pairedDevices, updateDeviceAttestation, updateDevicePolicy, removeDevice } from '$lib/stores/pairing';
  import { formatRelativeTime, formatDateTime, formatFingerprint } from '$lib/utils/format';
  import type { PairedDevice, DeviceAttestation, AttestationPolicy, PairedDeviceType } from '$lib/stores/pairing';
  import { addNotification } from '$lib/stores/notifications';
  import { callBackend, callBackendVoid } from '$lib/api/backend';

  const typeIcons: Record<PairedDeviceType, string> = {
    phone: mdiCellphone,
    extension: mdiPuzzleOutline,
    agent: mdiLanConnect,
  };

  const typeLabels: Record<PairedDeviceType, string> = {
    phone: 'BLE Phone',
    extension: 'Browser Extension',
    agent: 'Remote Agent',
  };

  let showUnpairConfirm = false;
  let attesting = false;
  let showCertChain = false;

  // Get device from store based on modal props
  let device: PairedDevice | null = null;

  $: {
    const addr = $appState.modalProps?.deviceAddress as string | undefined;
    device = $pairedDevices.find((d) => d.address === addr) || $pairedDevices[0] || null;
  }

  $: isConnected = device?.attestationStatus === 'connected';
  $: attestation = device?.attestation || null;
  $: policy = device?.policy || null;
  $: hasAttestation = attestation !== null && attestation.chain_length > 0;

  function getBootStateColor(state: string): string {
    const colors: Record<string, string> = {
      'Verified': 'var(--color-success)',
      'Self-Signed': 'var(--color-warning)',
      'Unverified': 'var(--color-error)',
      'Failed': 'var(--color-error)',
    };
    return colors[state] || 'var(--color-on-surface-variant)';
  }

  async function handleAttestNow(): Promise<void> {
    if (!device) return;
    attesting = true;
    try {
      const result = await callBackend<DeviceAttestation>('PhoneService', 'AttestDevice', device.name);
      if (result) {
        updateDeviceAttestation(device.address, result);
        if (result.verified) {
          addNotification('success', `Attestation verified for ${device.name}`);
        } else {
          addNotification('warning', `Attestation completed but unverified: ${result.error_message || 'chain verification failed'}`);
        }
      }
    } catch (err) {
      addNotification('error', `Attestation failed: ${err}`);
    } finally {
      attesting = false;
    }
  }

  async function handleSetPolicy(): Promise<void> {
    if (!device) return;
    try {
      await callBackend('PhoneService', 'SetAttestationPolicy', device.name);
      // Refetch policy
      const pol = await callBackend<AttestationPolicy>('PhoneService', 'GetAttestationPolicy', device.name);
      if (pol) {
        updateDevicePolicy(device.address, pol);
      }
      addNotification('success', 'Attestation connection policy set');
    } catch (err) {
      addNotification('error', `Failed to set policy: ${err}`);
    }
  }

  async function handleClearPolicy(): Promise<void> {
    if (!device) return;
    try {
      await callBackend('PhoneService', 'ClearAttestationPolicy', device.name);
      updateDevicePolicy(device.address, null);
      addNotification('info', 'Attestation connection policy cleared');
    } catch (err) {
      addNotification('error', `Failed to clear policy: ${err}`);
    }
  }

  async function handleUnpair(): Promise<void> {
    if (!device) return;
    showUnpairConfirm = false;
    const ok = await callBackendVoid('PhoneService', 'Unpair', device.name);
    if (ok) {
      removeDevice(device.address);
      addNotification('info', `Device ${device.name} unpaired`);
      navigateTo('pairing');
    } else {
      addNotification('error', `Failed to unpair ${device.name}`);
    }
  }
</script>

<div class="device-detail">
  <div class="detail-header">
    <button class="back-btn" on:click={() => navigateTo('pairing')}>
      <Icon path={mdiArrowLeft} size={20} />
      <span class="text-label-large">Pairing</span>
    </button>
    {#if device}
      <div class="detail-title-row">
        <Icon path={typeIcons[device.type] || mdiCellphone} size={24} />
        <h1 class="text-headline-small detail-title">{device.name}</h1>
        <span class="type-label text-label-small">{typeLabels[device.type] || device.type}</span>
      </div>
    {/if}
  </div>

  {#if device}
    <div class="detail-content">
      <!-- Connection Section -->
      <Card variant="elevated">
        <div class="section">
          <h2 class="text-title-medium section-heading">
            <Icon path={mdiConnection} size={20} />
            Connection
          </h2>
          <div class="detail-grid">
            <div class="detail-field">
              <span class="text-label-small field-label">Status</span>
              <StatusBadge status={isConnected ? 'connected' : 'disconnected'} />
            </div>
            <div class="detail-field">
              <span class="text-label-small field-label">
                {#if device.type === 'phone'}BLE Address{:else if device.type === 'agent'}Host:Port{:else}Origin{/if}
              </span>
              <span class="text-body-medium font-mono">{device.address}</span>
            </div>
          </div>
        </div>
      </Card>

      <!-- Attestation Section (phone and agent types) -->
      {#if device.type === 'phone' || device.type === 'agent'}
        <Card variant="elevated">
          <div class="section">
            <h2 class="text-title-medium section-heading">
              <Icon path={mdiFingerprint} size={20} />
              Attestation
            </h2>

            <div class="detail-grid">
              <div class="detail-field">
                <span class="text-label-small field-label">Last Attested</span>
                <span class="text-body-medium">
                  {device.lastAttestation ? formatDateTime(device.lastAttestation) : 'Never'}
                </span>
              </div>
              <div class="detail-field">
                <span class="text-label-small field-label">Status</span>
                {#if hasAttestation}
                  <StatusBadge status={attestation?.verified ? 'verified' : 'unverified'} />
                {:else}
                  <span class="text-body-medium" style="color: var(--color-on-surface-variant)">Not attested</span>
                {/if}
              </div>
            </div>

            {#if hasAttestation && attestation}
              <!-- Boot Security -->
              <div class="subsection">
                <h3 class="text-label-large subsection-heading">Boot Security</h3>
                <div class="detail-grid">
                  <div class="detail-field">
                    <span class="text-label-small field-label">Boot State</span>
                    <span class="text-body-medium" style="color: {getBootStateColor(attestation.boot_state)}; font-weight: 600;">
                      {attestation.boot_state || 'Unknown'}
                    </span>
                  </div>
                  <div class="detail-field">
                    <span class="text-label-small field-label">Device Locked</span>
                    <span class="text-body-medium" style="display: flex; align-items: center; gap: 4px;">
                      <Icon path={attestation.device_locked ? mdiLock : mdiLockOpen} size={16} />
                      {attestation.device_locked ? 'Yes' : 'No'}
                    </span>
                  </div>
                </div>

                {#if attestation.boot_hash}
                  <div class="detail-field" style="margin-top: 8px;">
                    <span class="text-label-small field-label">Boot Hash</span>
                    <span class="text-body-small font-mono hash-value">{attestation.boot_hash}</span>
                  </div>
                {/if}
                {#if attestation.boot_key_hash}
                  <div class="detail-field" style="margin-top: 4px;">
                    <span class="text-label-small field-label">Boot Key Hash</span>
                    <span class="text-body-small font-mono hash-value">{attestation.boot_key_hash}</span>
                  </div>
                {/if}
              </div>

              <!-- Key Properties -->
              <div class="subsection">
                <h3 class="text-label-large subsection-heading">Key Properties</h3>
                <div class="detail-grid">
                  <div class="detail-field">
                    <span class="text-label-small field-label">Security Level</span>
                    <span class="text-body-medium">{attestation.security_level}</span>
                  </div>
                  <div class="detail-field">
                    <span class="text-label-small field-label">Algorithm</span>
                    <span class="text-body-medium">{attestation.key_algorithm || 'N/A'}{attestation.key_size ? ` (${attestation.key_size} bits)` : ''}</span>
                  </div>
                  <div class="detail-field">
                    <span class="text-label-small field-label">Purposes</span>
                    <span class="text-body-medium">{attestation.key_purposes?.join(', ') || 'N/A'}</span>
                  </div>
                  <div class="detail-field">
                    <span class="text-label-small field-label">Origin</span>
                    <span class="text-body-medium">{attestation.key_origin || 'N/A'}</span>
                  </div>
                  <div class="detail-field">
                    <span class="text-label-small field-label">Attestation Version</span>
                    <span class="text-body-medium">{attestation.attest_version}</span>
                  </div>
                  <div class="detail-field">
                    <span class="text-label-small field-label">Keymaster Version</span>
                    <span class="text-body-medium">{attestation.keymaster_version} ({attestation.keymaster_security})</span>
                  </div>
                </div>
              </div>

              <!-- Trust Anchor -->
              {#if attestation.trust_anchor_subject}
                <div class="subsection">
                  <h3 class="text-label-large subsection-heading">Trust Anchor</h3>
                  <div class="detail-field">
                    <span class="text-label-small field-label">Root CA</span>
                    <span class="text-body-medium">{attestation.trust_anchor_subject}</span>
                  </div>
                  {#if attestation.trust_anchor_fingerprint}
                    <div class="detail-field" style="margin-top: 4px;">
                      <span class="text-label-small field-label">Fingerprint</span>
                      <span class="text-body-small font-mono hash-value">{attestation.trust_anchor_fingerprint}</span>
                    </div>
                  {/if}
                </div>
              {/if}

              <!-- Certificate Chain (Expandable) -->
              {#if attestation.certificates && attestation.certificates.length > 0}
                <div class="subsection">
                  <button class="expand-btn" on:click={() => showCertChain = !showCertChain}>
                    <Icon path={mdiCertificate} size={16} />
                    <span class="text-label-large">Certificate Chain ({attestation.certificates.length})</span>
                    <Icon path={showCertChain ? mdiChevronUp : mdiChevronDown} size={16} />
                  </button>

                  {#if showCertChain}
                    <div class="cert-chain">
                      {#each attestation.certificates as cert, i}
                        <div class="cert-entry" class:trust-anchor={cert.is_trust_anchor}>
                          <div class="cert-header">
                            <span class="cert-label">[{i}] {cert.label}</span>
                            {#if cert.is_trust_anchor}
                              <span class="trust-badge">TRUST ANCHOR</span>
                            {/if}
                          </div>
                          <div class="cert-details">
                            <div class="cert-row">
                              <span class="cert-key">Subject</span>
                              <span class="cert-val">{cert.subject}</span>
                            </div>
                            <div class="cert-row">
                              <span class="cert-key">Issuer</span>
                              <span class="cert-val">{cert.issuer}</span>
                            </div>
                            <div class="cert-row">
                              <span class="cert-key">Algorithm</span>
                              <span class="cert-val">{cert.algorithm}</span>
                            </div>
                            <div class="cert-row">
                              <span class="cert-key">Validity</span>
                              <span class="cert-val">{cert.not_before} - {cert.not_after}</span>
                            </div>
                            <div class="cert-row">
                              <span class="cert-key">Fingerprint</span>
                              <span class="cert-val font-mono">{cert.cert_fp}</span>
                            </div>
                            <div class="cert-row">
                              <span class="cert-key">Is CA</span>
                              <span class="cert-val">{cert.is_ca ? 'Yes' : 'No'}</span>
                            </div>
                          </div>
                        </div>
                      {/each}
                    </div>
                  {/if}
                </div>
              {/if}

              {#if attestation.error_message}
                <div class="attest-error">
                  <span class="text-body-small">{attestation.error_message}</span>
                </div>
              {/if}
            {/if}

            <!-- Policy Info -->
            {#if policy && policy.enabled}
              <div class="subsection policy-info">
                <h3 class="text-label-large subsection-heading">Connection Policy</h3>
                <div class="detail-grid">
                  <div class="detail-field">
                    <span class="text-label-small field-label">Policy Set</span>
                    <span class="text-body-medium">{formatDateTime(policy.set_at)}</span>
                  </div>
                  <div class="detail-field">
                    <span class="text-label-small field-label">Enforced Boot State</span>
                    <span class="text-body-medium">{policy.boot_state}</span>
                  </div>
                  <div class="detail-field">
                    <span class="text-label-small field-label">Min Security Level</span>
                    <span class="text-body-medium">{policy.min_security_level}</span>
                  </div>
                  <div class="detail-field">
                    <span class="text-label-small field-label">Require Locked</span>
                    <span class="text-body-medium">{policy.device_locked ? 'Yes' : 'No'}</span>
                  </div>
                </div>
              </div>
            {/if}

            <div class="section-actions">
              <Button variant="tertiary" size="sm" on:click={handleAttestNow} disabled={attesting}>
                {attesting ? 'Attesting...' : 'Attest Now'}
              </Button>
              {#if hasAttestation && attestation?.verified}
                {#if policy && policy.enabled}
                  <Button variant="outline" size="sm" on:click={handleClearPolicy}>Clear Policy</Button>
                {:else}
                  <Button variant="outline" size="sm" on:click={handleSetPolicy}>Set as Connection Policy</Button>
                {/if}
              {/if}
            </div>
          </div>
        </Card>
      {/if}

      <!-- Security Section -->
      <Card variant="security">
        <div class="section">
          <h2 class="text-title-medium section-heading">
            <Icon path={mdiShieldCheckOutline} size={20} />
            Security
          </h2>
          <div class="detail-grid">
            <div class="detail-field">
              <span class="text-label-small field-label">Keystore Type</span>
              <span class="text-body-medium">{attestation?.security_level || device.securityLevel || 'Unknown'}</span>
            </div>
            <div class="detail-field">
              <span class="text-label-small field-label">Boot State</span>
              <span class="text-body-medium">{attestation?.boot_state || 'Unknown'}</span>
            </div>
            <div class="detail-field">
              <span class="text-label-small field-label">Device Locked</span>
              <span class="text-body-medium">{attestation ? (attestation.device_locked ? 'Yes' : 'No') : 'Unknown'}</span>
            </div>
          </div>
        </div>
      </Card>

      <!-- Keys on Device Section -->
      <Card variant="outlined">
        <div class="section">
          <h2 class="text-title-medium section-heading">
            <Icon path={mdiKey} size={20} />
            Keys on Device
          </h2>
          <p class="text-body-medium" style="color: var(--color-on-surface-variant);">
            Key management is available through the individual backend views.
          </p>
          <div class="section-actions">
            <Button variant="outline" size="sm" on:click={() => navigateTo('keys')}>View Keys</Button>
          </div>
        </div>
      </Card>

      <!-- Pairing Info Section -->
      <Card variant="outlined">
        <div class="section">
          <h2 class="text-title-medium section-heading">
            <Icon path={device.type === 'phone' ? mdiBluetoothConnect : device.type === 'agent' ? mdiLanConnect : mdiPuzzleOutline} size={20} />
            Pairing
          </h2>
          <div class="detail-grid">
            <div class="detail-field">
              <span class="text-label-small field-label">Paired Date</span>
              <span class="text-body-medium">{formatDateTime(device.paired)}</span>
            </div>
            <div class="detail-field">
              <span class="text-label-small field-label">Type</span>
              <span class="text-body-medium">{typeLabels[device.type] || device.type}</span>
            </div>
          </div>
        </div>
      </Card>

      <!-- Danger Zone -->
      <Card variant="outlined">
        <div class="section danger-zone">
          <h2 class="text-title-medium section-heading danger-heading">
            <Icon path={mdiDelete} size={20} />
            Danger Zone
          </h2>
          <p class="text-body-medium danger-description">
            Unpair this device. All keys stored on this device will become inaccessible from this desktop.
          </p>
          <Button variant="danger" size="sm" on:click={() => (showUnpairConfirm = true)}>
            Unpair Device
          </Button>
        </div>
      </Card>
    </div>
  {:else}
    <div class="detail-empty">
      <p class="text-body-large">Device not found. It may have been unpaired.</p>
      <Button variant="primary" on:click={() => navigateTo('pairing')}>Back to Pairing</Button>
    </div>
  {/if}

  <Modal bind:open={showUnpairConfirm} title="Unpair Device?" maxWidth="400px">
    <p class="text-body-medium">
      Are you sure you want to unpair <strong>{device?.name}</strong>?
      You will lose access to all keys stored on this device.
    </p>
    <svelte:fragment slot="actions">
      <Button variant="text" on:click={() => (showUnpairConfirm = false)}>Cancel</Button>
      <Button variant="danger" on:click={handleUnpair}>Unpair</Button>
    </svelte:fragment>
  </Modal>
</div>

<style>
  .device-detail {
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
    display: inline-flex;
    align-items: center;
    gap: 6px;
    border: none;
    background: transparent;
    color: var(--color-primary);
    cursor: pointer;
    font-family: var(--font-sans);
    padding: 4px 0;
    transition: opacity var(--transition-fast);
    align-self: flex-start;
  }

  .back-btn:hover {
    opacity: 0.8;
  }

  .detail-title-row {
    display: flex;
    align-items: center;
    gap: 10px;
    color: var(--color-on-surface);
  }

  .detail-title {
    margin: 0;
    color: var(--color-on-surface);
  }

  .type-label {
    padding: 2px 10px;
    border-radius: var(--radius-full);
    background-color: var(--color-surface-container);
    color: var(--color-on-surface-variant);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .detail-content {
    flex: 1;
    overflow-y: auto;
    padding: 24px;
    display: flex;
    flex-direction: column;
    gap: 20px;
    max-width: 800px;
  }

  .section {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .section-heading {
    display: flex;
    align-items: center;
    gap: 8px;
    margin: 0;
    color: var(--color-on-surface);
  }

  .detail-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 16px;
  }

  .detail-field {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .field-label {
    color: var(--color-on-surface-variant);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .section-actions {
    display: flex;
    gap: 8px;
    padding-top: 4px;
  }

  .danger-zone {
    border: none;
  }

  .danger-heading {
    color: var(--color-error);
  }

  .danger-description {
    color: var(--color-on-surface-variant);
    margin: 0;
  }

  .detail-empty {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 16px;
    padding: 48px;
    color: var(--color-on-surface-variant);
  }

  .subsection {
    padding-top: 8px;
  }

  .subsection-heading {
    margin: 0 0 8px 0;
    color: var(--color-on-surface-variant);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .hash-value {
    word-break: break-all;
    color: var(--color-on-surface);
    line-height: 1.4;
  }

  .expand-btn {
    display: flex;
    align-items: center;
    gap: 6px;
    background: transparent;
    border: none;
    color: var(--color-primary);
    cursor: pointer;
    padding: 4px 0;
    font-family: var(--font-sans);
  }

  .expand-btn:hover {
    opacity: 0.8;
  }

  .cert-chain {
    display: flex;
    flex-direction: column;
    gap: 12px;
    margin-top: 8px;
  }

  .cert-entry {
    padding: 12px;
    border-radius: 8px;
    background: var(--color-surface-variant);
  }

  .cert-entry.trust-anchor {
    border: 1px solid var(--color-success);
    background: color-mix(in srgb, var(--color-success) 5%, var(--color-surface-variant));
  }

  .cert-header {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 8px;
  }

  .cert-label {
    font-weight: 600;
    font-size: 0.85rem;
    color: var(--color-on-surface);
  }

  .trust-badge {
    font-size: 0.65rem;
    font-weight: 700;
    color: var(--color-success);
    background: color-mix(in srgb, var(--color-success) 15%, transparent);
    padding: 2px 6px;
    border-radius: 4px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .cert-details {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .cert-row {
    display: flex;
    gap: 8px;
    font-size: 0.8rem;
    line-height: 1.5;
  }

  .cert-key {
    flex-shrink: 0;
    width: 80px;
    color: var(--color-on-surface-variant);
    font-weight: 500;
  }

  .cert-val {
    color: var(--color-on-surface);
    word-break: break-all;
  }

  .attest-error {
    padding: 8px 12px;
    background: color-mix(in srgb, var(--color-error) 10%, transparent);
    border-radius: 6px;
    color: var(--color-error);
  }

  .policy-info {
    padding: 12px;
    background: color-mix(in srgb, var(--color-primary) 5%, transparent);
    border-radius: 8px;
  }
</style>
