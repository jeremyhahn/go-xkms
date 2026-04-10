<script lang="ts">
  import Card from '$lib/components/Card.svelte';
  import Button from '$lib/components/Button.svelte';
  import StatusBadge from '$lib/components/StatusBadge.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import {
    mdiArrowLeft, mdiShieldCheckOutline, mdiDelete, mdiKey, mdiConnection, mdiOpenInNew
  } from '$lib/utils/icons';
  import { navigateTo, appState } from '$lib/stores/app';
  import { fido2State, removeCredential, setCredentials } from '$lib/stores/fido2';
  import { formatDateTime, formatRelativeTime, truncateMiddle } from '$lib/utils/format';
  import { addNotification } from '$lib/stores/notifications';
  import { isWailsAvailable, callBackendVoid, callBackend } from '$lib/api/backend';
  import type { BackendFIDO2Credential } from '$lib/api/backend';
  import type { FIDO2Credential as CredType } from '$lib/stores/fido2';

  let showDeleteConfirm = false;
  let credential: CredType | null = null;

  $: {
    const credId = $appState.modalProps?.credentialId as string | undefined;
    credential = $fido2State.credentials.find((c) => c.id === credId) || null;
  }

  const credProtectLabels: Record<number, string> = {
    0: 'None',
    1: 'UV Optional',
    2: 'UV Optional + Allow List',
    3: 'UV Required',
  };

  function mapCredential(c: BackendFIDO2Credential): CredType {
    return {
      id: c.id,
      relyingPartyId: c.relying_party_id,
      relyingPartyName: c.relying_party,
      userName: c.user_name,
      userDisplayName: c.user_display_name,
      algorithm: c.algorithm,
      keyType: c.key_type,
      credProtect: c.cred_protect,
      backendType: c.backend_type,
      useCount: c.use_count,
      discoverable: c.discoverable,
      created: c.created_at,
      lastUsed: c.last_used || null,
    };
  }

  async function openRP(rpId: string): Promise<void> {
    if (!rpId) return;
    const url = `https://${rpId}`;
    const ok = await callBackendVoid('BrowserService', 'OpenURL', url);
    if (!ok) {
      addNotification('error', 'Failed to open browser');
    }
  }

  let deleting = false;

  async function handleDelete(): Promise<void> {
    if (!credential || deleting) return;
    deleting = true;

    if (isWailsAvailable()) {
      const ok = await callBackendVoid('FIDO2Service', 'DeleteCredential', credential.id);
      if (!ok) {
        addNotification('error', 'Failed to delete credential');
        deleting = false;
        return;
      }
      // Re-fetch the credential list from the backend to stay in sync.
      const creds = await callBackend<BackendFIDO2Credential[]>('FIDO2Service', 'ListCredentials');
      if (creds) {
        setCredentials(creds.map(mapCredential));
      }
    } else {
      removeCredential(credential.id);
    }

    addNotification('success', 'Credential deleted');
    showDeleteConfirm = false;
    deleting = false;
    navigateTo('fido2');
  }
</script>

<div class="cred-detail">
  <div class="detail-header">
    <button class="back-btn" on:click={() => navigateTo('fido2')} data-testid="fido2-detail-back">
      <Icon path={mdiArrowLeft} size={20} />
      <span class="text-label-large">FIDO2 Credentials</span>
    </button>
    {#if credential}
      <h1 class="text-headline-small detail-title">{credential.relyingPartyName}</h1>
    {/if}
  </div>

  {#if credential}
    <div class="detail-content">
      <!-- RP Info -->
      <Card variant="elevated" data-testid="fido2-detail-rp">
        <div class="section">
          <div class="cred-rp-header">
            <div class="rp-icon">
              <Icon path={mdiConnection} size={28} />
            </div>
            <div>
              <h2 class="text-title-large">{credential.relyingPartyName}</h2>
              <span class="text-body-medium font-mono rp-domain">{credential.relyingPartyId}</span>
            </div>
            <Button variant="primary" size="sm" icon={mdiOpenInNew} on:click={() => credential && openRP(credential.relyingPartyId)} data-testid="fido2-detail-login">
              Login
            </Button>
          </div>
        </div>
      </Card>

      <!-- Credential Details -->
      <Card variant="outlined" data-testid="fido2-detail-user">
        <div class="section">
          <h3 class="text-title-medium section-heading">
            <Icon path={mdiKey} size={20} />
            Credential Details
          </h3>
          <div class="detail-grid">
            <div class="detail-field">
              <span class="text-label-small field-label">Username</span>
              <span class="text-body-medium">{credential.userName}</span>
            </div>
            <div class="detail-field">
              <span class="text-label-small field-label">Display Name</span>
              <span class="text-body-medium">{credential.userDisplayName}</span>
            </div>
            <div class="detail-field full-width">
              <span class="text-label-small field-label">Credential ID</span>
              <span class="text-body-small font-mono cred-id">{truncateMiddle(credential.id, 48)}</span>
            </div>
            <div class="detail-field">
              <span class="text-label-small field-label">Created</span>
              <span class="text-body-medium">{formatDateTime(credential.created)}</span>
            </div>
            <div class="detail-field">
              <span class="text-label-small field-label">Last Used</span>
              <span class="text-body-medium">
                {credential.lastUsed ? formatRelativeTime(credential.lastUsed) : 'Never'}
              </span>
            </div>
            <div class="detail-field">
              <span class="text-label-small field-label">Usage Count</span>
              <span class="text-body-medium">{credential.useCount} authentications</span>
            </div>
          </div>
        </div>
      </Card>

      <!-- Key Properties -->
      <Card variant="security">
        <div class="section">
          <h3 class="text-title-medium section-heading">
            <Icon path={mdiShieldCheckOutline} size={20} />
            Key Properties
          </h3>
          <div class="detail-grid">
            <div class="detail-field">
              <span class="text-label-small field-label">Algorithm</span>
              <span class="text-body-medium">{credential.algorithm}</span>
            </div>
            <div class="detail-field">
              <span class="text-label-small field-label">Key Type</span>
              <span class="text-body-medium">{credential.keyType}</span>
            </div>
            <div class="detail-field">
              <span class="text-label-small field-label">Backend</span>
              <span class="text-body-medium capitalize">{credential.backendType}</span>
            </div>
            <div class="detail-field">
              <span class="text-label-small field-label">Discoverable</span>
              <StatusBadge status={credential.discoverable ? 'verified' : 'disconnected'} />
            </div>
            <div class="detail-field">
              <span class="text-label-small field-label">Credential Protection</span>
              <span class="text-body-medium">{credProtectLabels[credential.credProtect] ?? 'Unknown'}</span>
            </div>
          </div>
        </div>
      </Card>

      <!-- Danger Zone -->
      <Card variant="outlined">
        <div class="section">
          <h3 class="text-title-medium section-heading danger-heading">
            <Icon path={mdiDelete} size={20} />
            Danger Zone
          </h3>
          <p class="text-body-medium danger-desc">
            Delete this credential. You will no longer be able to authenticate with
            {credential.relyingPartyName} using this passkey.
          </p>
          <Button variant="danger" size="sm" on:click={() => (showDeleteConfirm = true)} data-testid="fido2-detail-delete">
            Delete Credential
          </Button>
        </div>
      </Card>
    </div>
  {:else}
    <div class="detail-empty">
      <p class="text-body-large">Credential not found.</p>
      <Button variant="primary" on:click={() => navigateTo('fido2')}>Back to FIDO2</Button>
    </div>
  {/if}

  <Modal bind:open={showDeleteConfirm} title="Delete Credential?" maxWidth="400px">
    <p class="text-body-medium">
      This will permanently delete the credential for
      <strong>{credential?.relyingPartyName}</strong>. You will need to re-register
      with this website to use a passkey again.
    </p>
    <svelte:fragment slot="actions">
      <Button variant="text" on:click={() => (showDeleteConfirm = false)}>Cancel</Button>
      <Button variant="danger" on:click={handleDelete}>Delete</Button>
    </svelte:fragment>
  </Modal>
</div>

<style>
  .cred-detail {
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
    align-self: flex-start;
    transition: opacity var(--transition-fast);
  }

  .back-btn:hover { opacity: 0.8; }

  .detail-title { margin: 0; color: var(--color-on-surface); }

  .detail-content {
    flex: 1;
    overflow-y: auto;
    padding: 24px;
    display: flex;
    flex-direction: column;
    gap: 20px;
    max-width: 800px;
  }

  .section { display: flex; flex-direction: column; gap: 16px; }

  .cred-rp-header { display: flex; align-items: center; gap: 16px; }

  .rp-icon {
    width: 56px; height: 56px;
    border-radius: var(--radius-lg);
    background: var(--gradient-primary);
    color: #FFFFFF;
    display: flex; align-items: center; justify-content: center;
    flex-shrink: 0;
  }

  .cred-rp-header h2 { margin: 0; color: var(--color-on-surface); }
  .rp-domain { color: var(--color-on-surface-variant); }

  .section-heading {
    display: flex; align-items: center; gap: 8px;
    margin: 0; color: var(--color-on-surface);
  }

  .detail-grid {
    display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px;
  }

  .detail-field { display: flex; flex-direction: column; gap: 4px; }
  .detail-field.full-width { grid-column: 1 / -1; }

  .field-label {
    color: var(--color-on-surface-variant);
    text-transform: uppercase; letter-spacing: 0.5px;
  }

  .cred-id { word-break: break-all; }
  .capitalize { text-transform: capitalize; }
  .danger-heading { color: var(--color-error); }
  .danger-desc { color: var(--color-on-surface-variant); margin: 0; }

  .detail-empty {
    display: flex; flex-direction: column; align-items: center;
    gap: 16px; padding: 48px; color: var(--color-on-surface-variant);
  }
</style>
