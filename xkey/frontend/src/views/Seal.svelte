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
  import StatusBadge from '$lib/components/StatusBadge.svelte';
  import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
  import { mdiFilter } from '$lib/utils/icons';
  import {
    mdiPlus, mdiLockOutline, mdiDelete,
    mdiShieldCheckOutline, mdiChip, mdiContentCopy, mdiShieldOutline
  } from '$lib/utils/icons';
  import { addNotification } from '$lib/stores/notifications';
  import { appLocked } from '$lib/stores/events';
  import { isWailsAvailable, callBackend, callBackendVoid } from '$lib/api/backend';
  import type { SealedBlobEntry, SealRequest, PlatformPolicyStatus } from '$lib/api/backend';
  import type { SealerInfo } from '$lib/types/setup';

  type PolicyType = 'none' | 'password' | 'platform_policy' | 'custom_pcr';

  let blobs: SealedBlobEntry[] = [];
  let canSeal = false;
  let loading = true;
  let selectedBackend: string = 'all';
  let availableSealers: SealerInfo[] = [];

  // Seal dialog
  let showSealDialog = false;
  let sealLabel = '';
  let sealData = '';
  let sealPolicyType: PolicyType = 'none';
  let sealPassword = '';
  let sealPasswordConfirm = '';
  let sealPCRs: number[] = [];
  let sealing = false;
  let sealBackend: string = '';
  let sealStorageType: string = 'disk';

  // Effective backend: use sealBackend directly, fallback to first available
  $: effectiveBackend = sealBackend || (availableSealers.length > 0 ? availableSealers[0].id : '');

  // Reset storage type and TPM-only policy when switching away from TPM2
  $: if (effectiveBackend !== 'tpm2') {
    if (sealStorageType === 'nvram') {
      sealStorageType = 'disk';
    }
    if (sealPolicyType === 'platform_policy' || sealPolicyType === 'custom_pcr') {
      sealPolicyType = 'none';
    }
  }

  // Platform policy status (loaded when platform_policy is selected)
  let platformPolicyStatus: PlatformPolicyStatus | null = null;
  let platformPolicyLoading = false;

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

  function isPlainPolicy(policyType: string): boolean {
    return !policyType || policyType === 'none';
  }

  async function loadPlatformPolicyStatus(): Promise<void> {
    platformPolicyLoading = true;
    const result = await callBackend<PlatformPolicyStatus>('PlatformPolicyService', 'GetStatus');
    platformPolicyStatus = result;
    platformPolicyLoading = false;
  }

  $: if (sealPolicyType === 'platform_policy' && showSealDialog && !platformPolicyStatus && !platformPolicyLoading) {
    loadPlatformPolicyStatus();
  }

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

    if (sealPolicyType === 'password') {
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

    if (sealPolicyType === 'custom_pcr' && sealPCRs.length === 0) {
      addNotification('error', 'Select at least one PCR for custom PCR binding');
      return;
    }

    if (sealPolicyType === 'platform_policy' && (!platformPolicyStatus || !platformPolicyStatus.configured)) {
      addNotification('error', 'Platform policy must be configured before use');
      return;
    }

    sealing = true;

    const encoded = btoa(sealData);

    const req: SealRequest = {
      label: sealLabel,
      data: encoded,
      pcrs: sealPolicyType === 'custom_pcr' ? sealPCRs : [],
      pcr_bank: 'sha256',
      policy_type: sealPolicyType,
      password: sealPolicyType === 'password' ? sealPassword : '',
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

  function initiateUnseal(id: string, label: string, policyType: string): void {
    if (policyType === 'password') {
      pendingUnsealId = id;
      pendingUnsealLabel = label;
      unsealPassword = '';
      showPasswordUnsealDialog = true;
    } else {
      performUnseal(id, label, '');
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

  async function performUnseal(id: string, label: string, password: string): Promise<void> {
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
    } else {
      addNotification('error', `Failed to unseal "${label}"`);
      showUnsealDialog = false;
    }
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

  function togglePCR(index: number): void {
    if (sealPCRs.includes(index)) {
      sealPCRs = sealPCRs.filter(p => p !== index);
    } else {
      sealPCRs = [...sealPCRs, index].sort((a, b) => a - b);
    }
  }

  function resetSealForm(): void {
    sealLabel = '';
    sealData = '';
    sealPolicyType = 'none';
    sealPassword = '';
    sealPasswordConfirm = '';
    sealPCRs = [];
    sealBackend = availableSealers.length > 0 ? availableSealers[0].id : '';
    sealStorageType = 'disk';
    platformPolicyStatus = null;
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

  function getPolicyIcon(policyType: string): string {
    const iconMap: Record<string, string> = {
      password: mdiLockOutline,
      platform_policy: mdiShieldOutline,
      custom_pcr: mdiChip,
    };
    return iconMap[policyType] ?? '';
  }

  function getPolicyLabel(policyType: string): string {
    const labelMap: Record<string, string> = {
      password: 'Password Protected',
      platform_policy: 'Platform Policy',
      custom_pcr: 'Custom PCR',
    };
    return labelMap[policyType] ?? '';
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
          { key: 'policy_type', label: 'Policy', width: '150px', sortable: true },
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
        on:rowdblclick={(e) => initiateUnseal(e.detail.row.id, e.detail.row.label, e.detail.row.policy_type || 'none')}
      >
        <svelte:fragment slot="cell" let:row let:column let:value>
          {#if column.key === 'label'}
            <div class="label-cell">
              <Icon path={mdiShieldCheckOutline} size={16} />
              <span class="text-body-medium">{value}</span>
            </div>
          {:else if column.key === 'backend_id'}
            <span class="backend-badge" class:backend-tpm={value === 'tpm2'} class:backend-sw={value !== 'tpm2'}>
              {#if value === 'tpm2'}
                <Icon path={mdiChip} size={14} />
                TPM 2.0
              {:else}
                Software
              {/if}
            </span>
          {:else if column.key === 'policy_type'}
            {#if value && value !== 'none'}
              <span class="policy-badge">
                <Icon path={getPolicyIcon(value)} size={14} />
                {getPolicyLabel(value)}
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
            <button class="action-btn" title="Unseal & Copy" on:click|stopPropagation={() => initiateUnseal(row.id, row.label, row.policy_type || 'none')}>
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
        <div class="policy-options">
          {#each (effectiveBackend === 'tpm2'
            ? [
                { value: 'none', label: 'None', desc: 'Basic sealing without additional policy' },
                { value: 'password', label: 'Password', desc: 'Require a password to unseal' },
                { value: 'platform_policy', label: 'Platform Policy', desc: 'Bind to platform PCR measurements' },
                { value: 'custom_pcr', label: 'Custom PCR', desc: 'Select specific PCRs to bind' },
              ]
            : [
                { value: 'none', label: 'None', desc: 'Basic sealing without additional policy' },
                { value: 'password', label: 'Password', desc: 'Require a password to unseal' },
              ]
          ) as option}
            <label class="policy-radio" class:policy-radio-selected={sealPolicyType === option.value}>
              <input
                type="radio"
                name="policy-type"
                value={option.value}
                bind:group={sealPolicyType}
                class="policy-radio-input"
              />
              <div class="policy-radio-indicator">
                {#if sealPolicyType === option.value}
                  <div class="policy-radio-dot"></div>
                {/if}
              </div>
              <div class="policy-radio-content">
                <span class="text-title-small">{option.label}</span>
                <span class="text-body-small policy-radio-desc">{option.desc}</span>
              </div>
            </label>
          {/each}
        </div>
      </div>

      <!-- Password fields (shown when password policy selected) -->
      {#if sealPolicyType === 'password'}
        <div class="policy-detail-section">
          <Input
            label="Password"
            type="password"
            placeholder="Enter password for sealed data"
            bind:value={sealPassword}
          />
          <Input
            label="Confirm Password"
            type="password"
            placeholder="Re-enter password"
            bind:value={sealPasswordConfirm}
          />
          {#if sealPassword && sealPasswordConfirm && sealPassword !== sealPasswordConfirm}
            <span class="text-body-small password-mismatch">Passwords do not match</span>
          {/if}
        </div>
      {/if}

      <!-- Platform Policy status (TPM2 only, shown when platform_policy selected) -->
      {#if effectiveBackend === 'tpm2' && sealPolicyType === 'platform_policy'}
        <div class="policy-detail-section">
          {#if platformPolicyLoading}
            <div class="pp-status-loading">
              <LoadingSpinner size={20} />
              <span class="text-body-small">Loading platform policy status...</span>
            </div>
          {:else if platformPolicyStatus && platformPolicyStatus.configured}
            <div class="pp-status-card">
              <div class="pp-status-row">
                <StatusBadge status={platformPolicyStatus.valid ? 'verified' : 'error'} />
                <span class="text-body-medium">
                  {platformPolicyStatus.valid ? 'Policy is valid and current' : 'Policy validation failed'}
                </span>
              </div>
              <div class="pp-status-detail">
                <span class="text-label-small pp-detail-label">Bank</span>
                <span class="text-body-small">{platformPolicyStatus.bank.toUpperCase()}</span>
              </div>
              <div class="pp-status-detail">
                <span class="text-label-small pp-detail-label">PCRs</span>
                <span class="text-body-small">{platformPolicyStatus.pcrs.join(', ')}</span>
              </div>
            </div>
          {:else}
            <div class="pp-status-card pp-not-configured">
              <Icon path={mdiShieldOutline} size={20} />
              <span class="text-body-medium">Platform policy is not configured. Configure it in Settings before using this option.</span>
            </div>
          {/if}
        </div>
      {/if}

      <!-- Custom PCR grid (TPM2 only, shown when custom_pcr selected) -->
      {#if effectiveBackend === 'tpm2' && sealPolicyType === 'custom_pcr'}
        <div class="policy-detail-section">
          <p class="text-body-small pcr-desc">Select PCRs to bind. Data can only be unsealed when these PCR values match.</p>
          <div class="pcr-grid">
            {#each Array.from({length: 24}, (_, i) => i) as idx}
              <button
                class="pcr-chip"
                class:pcr-selected={sealPCRs.includes(idx)}
                on:click={() => togglePCR(idx)}
              >
                {idx}
              </button>
            {/each}
          </div>
        </div>
      {/if}
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
        This sealed data is password protected. Enter the password to unseal "<strong>{pendingUnsealLabel}</strong>".
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

  .backend-badge {
    display: inline-flex;
    align-items: center;
    gap: 0.25rem;
    padding: 0.125rem 0.5rem;
    border-radius: 99px;
    font-size: 0.75rem;
    font-weight: 500;
  }

  .backend-tpm {
    background: var(--md-sys-color-tertiary-container);
    color: var(--md-sys-color-on-tertiary-container);
  }

  .backend-sw {
    background: var(--md-sys-color-surface-container-highest);
    color: var(--md-sys-color-on-surface-variant);
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

  .policy-options {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .policy-radio {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 10px 12px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-md);
    background: var(--color-surface);
    cursor: pointer;
    transition: border-color var(--transition-fast), background-color var(--transition-fast);
  }

  .policy-radio:hover {
    background-color: var(--color-surface-container-low);
  }

  .policy-radio-selected {
    border-color: var(--color-primary);
    background-color: var(--color-primary-95);
  }

  :global([data-theme="dark"]) .policy-radio-selected {
    background-color: var(--color-primary-container);
  }

  .policy-radio-input {
    position: absolute;
    opacity: 0;
    width: 0;
    height: 0;
  }

  .policy-radio-indicator {
    width: 18px;
    height: 18px;
    border-radius: 50%;
    border: 2px solid var(--color-outline);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    margin-top: 2px;
    transition: border-color var(--transition-fast);
  }

  .policy-radio-selected .policy-radio-indicator {
    border-color: var(--color-primary);
  }

  .policy-radio-dot {
    width: 10px;
    height: 10px;
    border-radius: 50%;
    background-color: var(--color-primary);
  }

  .policy-radio-content {
    display: flex;
    flex-direction: column;
    gap: 1px;
  }

  .policy-radio-content span:first-child {
    color: var(--color-on-surface);
  }

  .policy-radio-desc {
    color: var(--color-on-surface-variant);
  }

  /* Policy detail sections */
  .policy-detail-section {
    display: flex;
    flex-direction: column;
    gap: 12px;
    padding: 12px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-md);
    background-color: var(--color-surface-container-lowest);
  }

  .password-mismatch {
    color: var(--color-error);
  }

  /* Platform Policy status in seal dialog */
  .pp-status-loading {
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--color-on-surface-variant);
  }

  .pp-status-card {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .pp-status-row {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .pp-status-detail {
    display: flex;
    align-items: center;
    gap: 8px;
    padding-left: 4px;
  }

  .pp-detail-label {
    color: var(--color-on-surface-variant);
    text-transform: uppercase;
    letter-spacing: 0.5px;
    min-width: 40px;
  }

  .pp-not-configured {
    flex-direction: row;
    align-items: flex-start;
    gap: 10px;
    color: var(--color-on-surface-variant);
  }

  .pp-not-configured span {
    line-height: 1.4;
  }

  /* PCR Grid */
  .pcr-desc {
    color: var(--color-on-surface-variant);
    margin: 0;
  }

  .pcr-grid {
    display: grid;
    grid-template-columns: repeat(8, 1fr);
    gap: 4px;
  }

  .pcr-chip {
    width: 100%;
    aspect-ratio: 1;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-sm);
    background: var(--color-surface);
    color: var(--color-on-surface-variant);
    font-size: 12px;
    font-weight: 500;
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: all var(--transition-fast);
    font-family: var(--font-sans);
  }

  .pcr-chip:hover {
    background: var(--color-surface-container);
  }

  .pcr-selected {
    background: var(--color-primary);
    color: var(--color-on-primary);
    border-color: var(--color-primary);
  }

  .pcr-selected:hover {
    filter: brightness(1.1);
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
