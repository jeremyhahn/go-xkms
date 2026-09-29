<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import GradientHeader from '$lib/components/GradientHeader.svelte';
  import ViewToolbar from '$lib/components/ViewToolbar.svelte';
  import Card from '$lib/components/Card.svelte';
  import Button from '$lib/components/Button.svelte';
  import DataTable from '$lib/components/DataTable.svelte';
  import EmptyState from '$lib/components/EmptyState.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import Input from '$lib/components/Input.svelte';
  import BackendBadge from '$lib/components/BackendBadge.svelte';
  import SealPolicyPicker from '$lib/components/SealPolicyPicker.svelte';
  import { mdiFilter } from '$lib/utils/icons';
  import {
    mdiPlus, mdiLockOutline, mdiDelete,
    mdiShieldCheckOutline, mdiContentCopy, mdiShieldOutline
  } from '$lib/utils/icons';
  import { addNotification } from '$lib/stores/notifications';
  import { appLocked } from '$lib/stores/events';
  import { isWailsAvailable, callBackend, callBackendVoid } from '$lib/api/backend';
  import type { SealedBlobEntry, SealRequest } from '$lib/api/backend';
  import type { SealerInfo } from '$lib/types/setup';

  let blobs: SealedBlobEntry[] = [];
  let canSeal = false;
  let loading = true;
  let selectedBackend: string = 'all';
  let availableSealers: SealerInfo[] = [];

  // Seal dialog
  let showSealDialog = false;
  let sealLabel = '';
  let sealData = '';
  let sealTPMPolicy = 'platform';
  let sealRequirePassword = false;
  let sealPassword = '';
  let sealPasswordConfirm = '';
  let sealing = false;
  let sealBackend: string = '';
  let sealStorageType: string = 'disk';

  // Effective backend: use sealBackend directly, fallback to first available
  $: effectiveBackend = sealBackend || (availableSealers.length > 0 ? availableSealers[0].id : '');

  // Reset the TPM-only storage type when switching away from TPM2
  $: if (effectiveBackend !== 'tpm2' && sealStorageType === 'nvram') {
    sealStorageType = 'disk';
  }

  // Clipboard / auto-clear timeout (seconds), loaded from backend config
  let clipboardTimeout = 30;

  // Unseal dialog
  let showUnsealDialog = false;
  let unsealBlobId = '';
  let unsealBlobLabel = '';
  let unsealedData = '';
  let unsealing = false;
  let unsealTimer: ReturnType<typeof setTimeout> | null = null;

  // Password unseal dialog
  let showPasswordUnsealDialog = false;
  let unsealPassword = '';
  let pendingUnsealId = '';
  let pendingUnsealLabel = '';
  let passwordUnsealReason = '';

  // Delete confirmation
  let showDeleteConfirm = false;
  let deleteBlobId = '';
  let deleteBlobLabel = '';

  // Selection state for table
  let selectedBlobIds: Set<string> = new Set();

  async function loadData(): Promise<void> {
    if (!isWailsAvailable()) {
      loading = false;
      return;
    }

    loading = true;

    const [configResult, blobResult, canSealResult, sealersResult] = await Promise.all([
      callBackend<{ clipboard_timeout: number }>('AppService', 'GetConfig'),
      callBackend<SealedBlobEntry[]>('SealService', 'ListBlobs'),
      callBackend<boolean>('SealService', 'CanSeal'),
      callBackend<SealerInfo[]>('SealService', 'AvailableSealers'),
    ]);

    blobs = blobResult ?? [];
    canSeal = canSealResult ?? false;
    availableSealers = sealersResult ?? [];

    if (configResult?.clipboard_timeout && configResult.clipboard_timeout > 0) {
      clipboardTimeout = configResult.clipboard_timeout;
    }

    loading = false;
  }

  onMount(() => {
    loadData();
  });

  // Re-fetch sealed blob data when the app unlocks.
  const unsubLock = appLocked.subscribe((locked) => {
    if (!locked) {
      loadData();
    }
  });
  onDestroy(unsubLock);

  // Filter blobs by selected sealer backend.
  $: filteredBlobs = selectedBackend === 'all'
    ? blobs
    : blobs.filter(b => b.backend_id === selectedBackend);

  async function handleBulkDelete(): Promise<void> {
    const ids = [...selectedBlobIds];
    if (ids.length === 0) return;

    let deleted = 0;
    for (const id of ids) {
      const ok = await callBackendVoid('SealService', 'DeleteBlob', id);
      if (ok || !isWailsAvailable()) {
        deleted++;
      }
    }

    if (deleted > 0) {
      blobs = blobs.filter(b => !selectedBlobIds.has(b.id));
      addNotification('info', `Deleted ${deleted} sealed blob(s)`);
    }
    selectedBlobIds = new Set();
  }

  async function handleSeal(): Promise<void> {
    if (!sealLabel.trim()) {
      addNotification('error', 'Label is required');
      return;
    }
    if (!sealData.trim()) {
      addNotification('error', 'Data is required');
      return;
    }

    if (sealRequirePassword) {
      if (!sealPassword) {
        addNotification('error', 'Password is required');
        return;
      }
      if (sealPassword.length < 8) {
        addNotification('error', 'Password must be at least 8 characters');
        return;
      }
      if (sealPassword !== sealPasswordConfirm) {
        addNotification('error', 'Passwords do not match');
        return;
      }
    }

    sealing = true;

    const encoded = btoa(sealData);

    const req: SealRequest = {
      label: sealLabel,
      data: encoded,
      tpm_policy: effectiveBackend === 'tpm2' ? sealTPMPolicy : '',
      password: sealRequirePassword ? sealPassword : '',
      backend: sealBackend || undefined,
      storage_type: sealStorageType,
    };

    const result = await callBackend<SealedBlobEntry>('SealService', 'SealData', req);
    sealing = false;

    if (result) {
      blobs = [result, ...blobs];
      addNotification('success', `Data sealed as "${sealLabel}"`);
      resetSealForm();
      showSealDialog = false;
    } else {
      addNotification('error', 'Failed to seal data');
    }
  }

  function askUnsealPassword(blob: SealedBlobEntry, reason: string): void {
    pendingUnsealId = blob.id;
    pendingUnsealLabel = blob.label;
    passwordUnsealReason = reason;
    unsealPassword = '';
    showPasswordUnsealDialog = true;
  }

  async function initiateUnseal(blob: SealedBlobEntry): Promise<void> {
    // A blob with only a password needs it. One with a TPM policy tries the
    // policy first; if the platform state changed, its password (when it
    // has one) still unseals it.
    if (blob.password_protected && !blob.tpm_policy) {
      askUnsealPassword(blob, 'This sealed data is password protected.');
      return;
    }
    const ok = await performUnseal(blob.id, blob.label, '', !blob.password_protected);
    if (!ok && blob.password_protected) {
      askUnsealPassword(blob, 'The TPM policy is not satisfied (the platform state changed). Its password still unseals it.');
    }
  }

  async function handlePasswordUnsealSubmit(): Promise<void> {
    if (!unsealPassword) {
      addNotification('error', 'Password is required');
      return;
    }
    showPasswordUnsealDialog = false;
    await performUnseal(pendingUnsealId, pendingUnsealLabel, unsealPassword);
  }

  async function performUnseal(id: string, label: string, password: string, reportFailure = true): Promise<boolean> {
    unsealBlobId = id;
    unsealBlobLabel = label;
    unsealedData = '';
    unsealing = true;
    showUnsealDialog = true;

    const result = await callBackend<string>('SealService', 'UnsealData', id, password);
    unsealing = false;

    if (result) {
      try {
        unsealedData = atob(result);
      } catch {
        unsealedData = result;
      }
      if (unsealTimer) clearTimeout(unsealTimer);
      unsealTimer = setTimeout(() => {
        unsealedData = '';
        showUnsealDialog = false;
        callBackendVoid('ClipboardService', 'ClearClipboard');
        addNotification('info', 'Unsealed data cleared for security');
      }, clipboardTimeout * 1000);
      return true;
    }
    if (reportFailure) {
      addNotification('error', `Failed to unseal "${label}"`);
    }
    showUnsealDialog = false;
    return false;
  }

  function handleCloseUnseal(): void {
    showUnsealDialog = false;
    unsealedData = '';
    if (unsealTimer) {
      clearTimeout(unsealTimer);
      unsealTimer = null;
    }
    callBackendVoid('ClipboardService', 'ClearClipboard');
  }

  async function handleDelete(): Promise<void> {
    const ok = await callBackendVoid('SealService', 'DeleteBlob', deleteBlobId);
    if (ok || !isWailsAvailable()) {
      blobs = blobs.filter(b => b.id !== deleteBlobId);
      addNotification('info', `Sealed blob "${deleteBlobLabel}" deleted`);
    } else {
      addNotification('error', `Failed to delete sealed blob "${deleteBlobLabel}"`);
    }
    showDeleteConfirm = false;
  }

  function confirmDelete(id: string, label: string): void {
    deleteBlobId = id;
    deleteBlobLabel = label;
    showDeleteConfirm = true;
  }

  async function copyToClipboard(text: string): Promise<void> {
    if (isWailsAvailable()) {
      const ok = await callBackendVoid('ClipboardService', 'CopyWithClear', text);
      if (ok) {
        addNotification('success', `Copied to clipboard (auto-clears in ${clipboardTimeout}s)`);
        return;
      }
    }
    // Fallback to browser clipboard API when Wails is unavailable
    try {
      await navigator.clipboard.writeText(text);
      addNotification('success', 'Copied to clipboard');
    } catch {
      addNotification('error', 'Failed to copy');
    }
  }

  function resetSealForm(): void {
    sealLabel = '';
    sealData = '';
    sealTPMPolicy = 'platform';
    sealRequirePassword = false;
    sealPassword = '';
    sealPasswordConfirm = '';
    sealBackend = availableSealers.length > 0 ? availableSealers[0].id : '';
    sealStorageType = 'disk';
  }

  function formatDate(iso: string): string {
    try {
      return new Date(iso).toLocaleDateString(undefined, {
        year: 'numeric', month: 'short', day: 'numeric',
        hour: '2-digit', minute: '2-digit',
      });
    } catch {
      return iso;
    }
  }

  function policyLabel(blob: SealedBlobEntry): string {
    if (!blob.tpm_policy) {
      return blob.password_protected ? 'Password' : '';
    }
    const name = blob.tpm_policy === 'platform' ? 'Platform' : blob.tpm_policy;
    return blob.password_protected ? `${name} or password` : name;
  }
</script>

<div class="seal-view">
  <GradientHeader title="Sealed Data" subtitle="Encrypted data storage" />

  <ViewToolbar>
    <div class="sealer-filter">
      <Icon path={mdiFilter} size={14} />
      <button
        class="filter-chip"
        class:active={selectedBackend === 'all'}
        on:click={() => { selectedBackend = 'all'; }}
      >All</button>
      {#each availableSealers as sealer}
        <button
          class="filter-chip"
          class:active={selectedBackend === sealer.id}
          on:click={() => { selectedBackend = sealer.id; }}
        >{sealer.label || sealer.id}</button>
      {/each}
    </div>
    <div class="toolbar-spacer" />
    <Button
      icon={mdiDelete}
      variant="outline"
      on:click={handleBulkDelete}
      disabled={selectedBlobIds.size === 0}
    >Delete ({selectedBlobIds.size})</Button>
    <Button
      icon={mdiPlus}
      variant="primary"
      on:click={() => { resetSealForm(); showSealDialog = true; }}
      disabled={!canSeal}
    >Seal New Data</Button>
  </ViewToolbar>

  <div class="content">
    {#if !canSeal && !loading}
      <Card variant="outlined">
        <div class="tpm-warning">
          <Icon path={mdiShieldOutline} size={24} />
          <div>
            <p class="text-title-small">No Sealing Backends Available</p>
            <p class="text-body-small">Configure a backend in Management to enable seal/unseal operations.</p>
          </div>
        </div>
      </Card>
    {/if}

    {#if blobs.length === 0 && !loading}
      <EmptyState
        icon={mdiLockOutline}
        title="No sealed data"
        description="Seal sensitive data for encrypted storage."
      />
    {:else if !loading}
      <DataTable
        columns={[
          { key: 'label', label: 'Label', sortable: true },
          { key: 'backend_id', label: 'Backend', width: '120px', sortable: true },
          { key: 'tpm_policy', label: 'Policy', width: '150px', sortable: true },
          { key: 'created_at', label: 'Created', width: '160px', sortable: true },
        ]}
        rows={filteredBlobs}
        rowKey="id"
        selectable={true}
        bind:selectedIds={selectedBlobIds}
        emptyIcon={mdiLockOutline}
        emptyTitle="No matching sealed data"
        emptyDescription="Try selecting a different backend filter."
        loading={loading}
        on:rowdblclick={(e) => initiateUnseal(e.detail.row)}
      >
        <svelte:fragment slot="cell" let:row let:column let:value>
          {#if column.key === 'label'}
            <div class="label-cell">
              <Icon path={mdiShieldCheckOutline} size={16} />
              <span class="text-body-medium">{value}</span>
            </div>
          {:else if column.key === 'backend_id'}
            <BackendBadge backend={value} compact />
          {:else if column.key === 'tpm_policy'}
            {#if policyLabel(row)}
              <span class="policy-badge">
                <Icon path={row.tpm_policy ? mdiShieldOutline : mdiLockOutline} size={14} />
                {policyLabel(row)}
              </span>
            {:else}
              <span class="text-body-small policy-none">None</span>
            {/if}
          {:else if column.key === 'created_at'}
            <span class="text-body-small">{formatDate(value)}</span>
          {:else}
            {value ?? ''}
          {/if}
        </svelte:fragment>
        <svelte:fragment slot="actions" let:row>
          <div class="action-buttons">
            <button class="action-btn" title="Unseal & Copy" on:click|stopPropagation={() => initiateUnseal(row)}>
              <Icon path={mdiContentCopy} size={18} />
            </button>
            <button class="action-btn action-btn-danger" title="Delete" on:click|stopPropagation={() => confirmDelete(row.id, row.label)} disabled={row.category === 'system'}>
              <Icon path={mdiDelete} size={18} />
            </button>
          </div>
        </svelte:fragment>
      </DataTable>
    {/if}
  </div>

  <!-- Seal Dialog -->
  <Modal bind:open={showSealDialog} title="Seal Data" maxWidth="520px">
    <div class="seal-form">
      <Input label="Label" placeholder="e.g. API Secret" bind:value={sealLabel} />
      <div class="form-field">
        <label class="text-label-large" for="seal-data">Data</label>
        <textarea
          id="seal-data"
          class="form-textarea"
          rows="4"
          placeholder="Enter sensitive data to seal..."
          bind:value={sealData}
        ></textarea>
      </div>

      <!-- Backend Selector -->
      {#if availableSealers.length > 0}
        <div class="form-field">
          <label class="text-label-large" for="seal-backend">Backend</label>
          <select id="seal-backend" class="form-select" bind:value={sealBackend}>
            {#each availableSealers as sealer}
              <option value={sealer.id}>{sealer.label || sealer.id}</option>
            {/each}
          </select>
        </div>
      {/if}

      <!-- Storage Location (only shown when TPM2 offers NV RAM option) -->
      {#if effectiveBackend === 'tpm2'}
        <div class="form-field">
          <span class="text-label-large">Storage Location</span>
          <div class="storage-options">
            <label class="storage-radio" class:storage-radio-selected={sealStorageType === 'disk'}>
              <input type="radio" name="storage-type" value="disk" bind:group={sealStorageType} class="storage-radio-input" />
              <div class="storage-radio-indicator">
                {#if sealStorageType === 'disk'}
                  <div class="storage-radio-dot"></div>
                {/if}
              </div>
              <div class="storage-radio-content">
                <span class="text-title-small">Disk</span>
                <span class="text-body-small storage-radio-desc">Store sealed blob on filesystem (barrier-encrypted)</span>
              </div>
            </label>
            <label class="storage-radio" class:storage-radio-selected={sealStorageType === 'nvram'}>
              <input type="radio" name="storage-type" value="nvram" bind:group={sealStorageType} class="storage-radio-input" />
              <div class="storage-radio-indicator">
                {#if sealStorageType === 'nvram'}
                  <div class="storage-radio-dot"></div>
                {/if}
              </div>
              <div class="storage-radio-content">
                <span class="text-title-small">NV RAM</span>
                <span class="text-body-small storage-radio-desc">Store sealed blob in TPM non-volatile memory</span>
              </div>
            </label>
          </div>
        </div>
      {/if}

      <!-- Protection Policy -->
      <div class="policy-section">
        <span class="text-title-small policy-heading">Protection Policy</span>
        <SealPolicyPicker
          backend={effectiveBackend}
          bind:tpmPolicy={sealTPMPolicy}
          bind:requirePassword={sealRequirePassword}
          bind:password={sealPassword}
          bind:passwordConfirm={sealPasswordConfirm}
        />
      </div>
    </div>
    <svelte:fragment slot="actions">
      <Button variant="text" on:click={() => (showSealDialog = false)} disabled={sealing}>Cancel</Button>
      <Button variant="primary" loading={sealing} on:click={handleSeal} disabled={!sealLabel.trim() || !sealData.trim()}>
        Seal
      </Button>
    </svelte:fragment>
  </Modal>

  <!-- Password Unseal Dialog -->
  <Modal bind:open={showPasswordUnsealDialog} title="Enter Password" maxWidth="400px">
    <div class="password-unseal-form">
      <p class="text-body-medium">
        {passwordUnsealReason} Enter the password to unseal "<strong>{pendingUnsealLabel}</strong>".
      </p>
      <Input
        label="Password"
        type="password"
        placeholder="Enter password"
        bind:value={unsealPassword}
      />
    </div>
    <svelte:fragment slot="actions">
      <Button variant="text" on:click={() => (showPasswordUnsealDialog = false)}>Cancel</Button>
      <Button variant="primary" on:click={handlePasswordUnsealSubmit} disabled={!unsealPassword}>
        Unseal
      </Button>
    </svelte:fragment>
  </Modal>

  <!-- Unseal Result Dialog -->
  <Modal bind:open={showUnsealDialog} title="Unsealed: {unsealBlobLabel}" maxWidth="500px">
    <div class="unseal-result">
      {#if unsealing}
        <p class="text-body-medium">Unsealing data...</p>
      {:else if unsealedData}
        <div class="unseal-data-box">
          <pre class="unseal-data-text">{unsealedData}</pre>
        </div>
        <p class="text-body-small unseal-warning">This data will auto-clear in {clipboardTimeout} seconds for security.</p>
      {:else}
        <p class="text-body-medium">No data available.</p>
      {/if}
    </div>
    <svelte:fragment slot="actions">
      {#if unsealedData}
        <Button variant="outline" size="sm" icon={mdiContentCopy} on:click={() => copyToClipboard(unsealedData)}>
          Copy
        </Button>
      {/if}
      <Button variant="text" on:click={handleCloseUnseal}>Close</Button>
    </svelte:fragment>
  </Modal>

  <!-- Delete Confirmation -->
  <Modal bind:open={showDeleteConfirm} title="Delete Sealed Data?" maxWidth="400px">
    <p class="text-body-medium">
      Are you sure you want to delete "<strong>{deleteBlobLabel}</strong>"? This action cannot be undone.
    </p>
    <svelte:fragment slot="actions">
      <Button variant="text" on:click={() => (showDeleteConfirm = false)}>Cancel</Button>
      <Button variant="danger" on:click={handleDelete}>Delete</Button>
    </svelte:fragment>
  </Modal>
</div>

<style>
  .sealer-filter {
    display: flex;
    align-items: center;
    gap: 6px;
    color: var(--color-on-surface-variant);
  }
  .filter-chip {
    display: inline-flex;
    align-items: center;
    padding: 2px 8px;
    border-radius: var(--radius-full);
    border: 1px solid var(--color-outline-variant);
    background: transparent;
    color: var(--color-on-surface-variant);
    font-size: 12px;
    font-family: var(--font-sans);
    cursor: pointer;
    transition: all var(--transition-fast);
    white-space: nowrap;
  }
  .filter-chip:hover {
    background-color: var(--color-surface-container);
    border-color: var(--color-outline);
  }
  .filter-chip.active {
    background-color: var(--color-secondary-container);
    color: var(--color-on-secondary-container);
    border-color: var(--color-secondary-container);
    font-weight: 500;
  }

  .seal-view {
    height: 100%;
    display: flex;
    flex-direction: column;
  }

  .content {
    flex: 1;
    padding: 24px 32px;
    overflow-y: auto;
    display: flex;
    flex-direction: column;
    gap: 20px;
  }

  .tpm-warning {
    display: flex;
    align-items: flex-start;
    gap: 16px;
    padding: 8px;
    color: var(--color-on-surface-variant);
  }

  .tpm-warning p {
    margin: 0;
  }

  .tpm-warning p:first-child {
    color: var(--color-on-surface);
  }

  .label-cell {
    display: flex;
    align-items: center;
    gap: 0.5rem;
  }

  .policy-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
    font-size: 0.75rem;
    color: var(--md-sys-color-on-surface-variant);
  }

  .policy-none {
    color: var(--md-sys-color-outline);
  }

  .action-buttons {
    display: flex;
    gap: 0.25rem;
  }

  .action-btn {
    background: none;
    border: none;
    cursor: pointer;
    padding: 0.375rem;
    border-radius: 8px;
    color: var(--md-sys-color-on-surface-variant);
    transition: all 0.1s ease;
    display: flex;
    align-items: center;
  }

  .action-btn:hover {
    background: var(--md-sys-color-surface-container-highest);
    color: var(--md-sys-color-primary);
  }

  .action-btn-danger:hover {
    color: var(--md-sys-color-error);
    background: var(--md-sys-color-error-container);
  }

  .action-btn:disabled {
    opacity: 0.38;
    cursor: not-allowed;
  }

  /* Seal Dialog */
  .seal-form {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .form-field {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .form-field label {
    color: var(--color-on-surface-variant);
  }

  .form-select {
    padding: 10px 12px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    background: var(--color-surface);
    color: var(--color-on-surface);
    font-family: var(--font-sans);
    font-size: 13px;
    outline: none;
    transition: border-color var(--transition-fast);
    cursor: pointer;
    appearance: auto;
  }

  .form-select:focus {
    border-color: var(--color-primary);
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
    min-height: 80px;
    transition: border-color var(--transition-fast);
  }

  .form-textarea:focus {
    border-color: var(--color-primary);
  }

  /* Policy Section */
  .policy-section {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .policy-heading {
    color: var(--color-on-surface);
  }

  /* Password Unseal Dialog */
  .password-unseal-form {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .password-unseal-form p {
    margin: 0;
    color: var(--color-on-surface-variant);
  }

  /* Unseal Dialog */
  .unseal-result {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .unseal-data-box {
    background: var(--color-surface-container-lowest);
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    padding: 12px;
    max-height: 300px;
    overflow: auto;
  }

  .unseal-data-text {
    margin: 0;
    font-family: var(--font-mono, monospace);
    font-size: 13px;
    color: var(--color-on-surface);
    white-space: pre-wrap;
    word-break: break-all;
  }

  .unseal-warning {
    color: var(--color-security-warning);
    margin: 0;
    font-style: italic;
  }

  /* Storage Location (TPM2 disk vs NVRAM) */
  .storage-options {
    display: flex;
    flex-direction: column;
    gap: 0.5rem;
  }

  .storage-radio {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 10px 12px;
    border: 1px solid var(--color-outline-variant);
    border-radius: 12px;
    cursor: pointer;
    transition: all 0.15s ease;
  }

  .storage-radio:hover {
    background: var(--color-surface-variant);
  }

  .storage-radio-selected {
    border-color: var(--color-primary);
    background-color: var(--color-primary-95);
  }

  :global([data-theme="dark"]) .storage-radio-selected {
    background-color: var(--color-primary-container);
  }

  .storage-radio-input {
    position: absolute;
    opacity: 0;
    width: 0;
    height: 0;
  }

  .storage-radio-indicator {
    width: 18px;
    height: 18px;
    border-radius: 50%;
    border: 2px solid var(--color-outline);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    margin-top: 2px;
  }

  .storage-radio-selected .storage-radio-indicator {
    border-color: var(--color-primary);
  }

  .storage-radio-dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background: var(--color-primary);
  }

  .storage-radio-content {
    display: flex;
    flex-direction: column;
    gap: 0.125rem;
  }

  .storage-radio-desc {
    color: var(--color-on-surface-variant);
  }

</style>
