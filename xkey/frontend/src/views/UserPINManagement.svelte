<script lang="ts">
  import { onMount } from 'svelte';
  import { callBackend, callBackendVoidWithError } from '$lib/api/backend';
  import type { PINStatus, LockoutStatus } from '$lib/api/backend';
  import GradientHeader from '$lib/components/GradientHeader.svelte';
  import Card from '$lib/components/Card.svelte';
  import Button from '$lib/components/Button.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import StatusBadge from '$lib/components/StatusBadge.svelte';
  import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
  import PINDialog from '$lib/components/PINDialog.svelte';
  import Modal from '$lib/components/Modal.svelte';
  import Input from '$lib/components/Input.svelte';
  import {
    mdiLockReset, mdiCheck, mdiClose,
    mdiLockAlert, mdiFormTextboxPassword
  } from '$lib/utils/icons';
  import { addNotification } from '$lib/stores/notifications';

  let pinStatus: PINStatus | null = null;
  let lockoutStatus: LockoutStatus | null = null;
  let pinLoading = true;
  let lockoutLoading = true;

  let showPINDialog = false;
  let pinDialogMode: 'set-user' | 'change-user' = 'set-user';

  let showResetLockoutConfirm = false;
  let resetLockoutSOPIN = '';
  let resettingLockout = false;

  async function loadPINStatus(): Promise<void> {
    pinLoading = true;
    const result = await callBackend<PINStatus>('PINService', 'GetPINStatus');
    if (result) {
      pinStatus = result;
    }
    pinLoading = false;
  }

  async function loadLockoutStatus(): Promise<void> {
    lockoutLoading = true;
    const result = await callBackend<LockoutStatus>('PINService', 'GetLockoutStatus');
    if (result) {
      lockoutStatus = result;
    }
    lockoutLoading = false;
  }

  async function loadStatus(): Promise<void> {
    await Promise.all([loadPINStatus(), loadLockoutStatus()]);
  }

  onMount(loadStatus);

  function openPINDialog(mode: 'set-user' | 'change-user'): void {
    pinDialogMode = mode;
    showPINDialog = true;
  }

  function handlePINSuccess(): void {
    showPINDialog = false;
    addNotification('success', 'User PIN updated successfully');
    loadStatus();
  }

  async function handleResetLockout(): Promise<void> {
    if (!resetLockoutSOPIN) {
      addNotification('error', 'SO PIN is required to reset lockout');
      return;
    }
    resettingLockout = true;
    const result = await callBackendVoidWithError('PINService', 'ResetLockout', resetLockoutSOPIN);
    resettingLockout = false;
    if (result.ok) {
      addNotification('success', 'Lockout reset successfully');
      showResetLockoutConfirm = false;
      resetLockoutSOPIN = '';
      loadLockoutStatus();
    } else {
      addNotification('error', result.error || 'Failed to reset lockout');
    }
  }

  function formatPINStrategy(strategy: string): string {
    if (!strategy) return 'Unknown';
    const map: Record<string, string> = {
      'software': 'Software',
      'tpm2': 'TPM 2.0',
      'tpm': 'TPM 2.0',
      'pkcs11': 'PKCS#11',
    };
    return map[strategy.toLowerCase()] || strategy;
  }
</script>

<div class="pin-mgmt-view">
  <GradientHeader title="User PIN Management" subtitle="Manage user PINs and lockout recovery" />

  <div class="pin-mgmt-content">
    <!-- PIN Status Section -->
    <Card variant="elevated">
      <div class="section">
        <h2 class="text-title-medium section-heading">PIN Status</h2>

        {#if pinLoading}
          <div class="loading-row">
            <LoadingSpinner size={32} />
            <span class="text-body-medium loading-text">Loading PIN status...</span>
          </div>
        {:else if pinStatus}
          <div class="field-row">
            <div class="field-info">
              <span class="text-title-small">Strategy</span>
              <span class="text-body-small field-desc">PIN management backend</span>
            </div>
            <span class="strategy-badge">{formatPINStrategy(pinStatus.strategy)}</span>
          </div>

          <div class="field-row">
            <div class="field-info">
              <span class="text-title-small">SO PIN</span>
              <span class="text-body-small field-desc">Security Officer PIN for administrative operations</span>
            </div>
            <div class="check-indicator">
              {#if pinStatus.so_pin_set}
                <Icon path={mdiCheck} size={18} color="var(--color-security-verified)" />
                <span class="text-label-small" style="color: var(--color-security-verified);">Configured</span>
              {:else}
                <Icon path={mdiClose} size={18} color="var(--color-on-surface-variant)" />
                <span class="text-label-small" style="color: var(--color-on-surface-variant);">Not Set</span>
              {/if}
            </div>
          </div>

          <div class="field-row">
            <div class="field-info">
              <span class="text-title-small">User PIN</span>
              <span class="text-body-small field-desc">User PIN for cryptographic operations</span>
            </div>
            <div class="check-indicator">
              {#if pinStatus.user_pin_set}
                <Icon path={mdiCheck} size={18} color="var(--color-security-verified)" />
                <span class="text-label-small" style="color: var(--color-security-verified);">Configured</span>
              {:else}
                <Icon path={mdiClose} size={18} color="var(--color-on-surface-variant)" />
                <span class="text-label-small" style="color: var(--color-on-surface-variant);">Not Set</span>
              {/if}
            </div>
          </div>
        {:else}
          <p class="text-body-medium empty-msg">Unable to load PIN status.</p>
          <Button variant="outline" on:click={loadPINStatus}>Retry</Button>
        {/if}
      </div>
    </Card>

    <!-- User PIN Actions -->
    {#if pinStatus}
      <Card variant="outlined">
        <div class="section">
          <h2 class="text-title-medium section-heading">User PIN Actions</h2>
          <div class="actions-list">
            {#if pinStatus.user_pin_set}
              <div class="action-row">
                <div class="field-info">
                  <span class="text-title-small">Change User PIN</span>
                  <span class="text-body-small field-desc">Update the user's PIN</span>
                </div>
                <Button variant="outline" icon={mdiFormTextboxPassword} on:click={() => openPINDialog('change-user')}>
                  Change
                </Button>
              </div>
            {:else}
              <div class="action-row">
                <div class="field-info">
                  <span class="text-title-small">Set User PIN</span>
                  <span class="text-body-small field-desc">
                    Configure the User PIN for cryptographic operations
                    {#if !pinStatus.so_pin_set}
                      (requires SO PIN to be set first)
                    {/if}
                  </span>
                </div>
                <Button variant="primary" icon={mdiFormTextboxPassword} on:click={() => openPINDialog('set-user')} disabled={!pinStatus.so_pin_set}>
                  Set User PIN
                </Button>
              </div>
            {/if}
          </div>
        </div>
      </Card>
    {/if}

    <!-- Lockout Status (only shown for backends that support lockout) -->
    {#if pinStatus && pinStatus.strategy !== 'software'}
    <Card variant="outlined">
      <div class="section">
        <h2 class="text-title-medium section-heading">Lockout Status</h2>

        {#if lockoutLoading}
          <div class="loading-row">
            <LoadingSpinner size={32} />
            <span class="text-body-medium loading-text">Loading lockout status...</span>
          </div>
        {:else if lockoutStatus}
          <div class="lockout-grid">
            <div class="lockout-stat">
              <span class="text-label-small lockout-stat-label">Failed Attempts</span>
              <span class="text-body-medium">{lockoutStatus.failed_attempts} / {lockoutStatus.max_attempts}</span>
            </div>
            <div class="lockout-stat">
              <span class="text-label-small lockout-stat-label">Status</span>
              {#if lockoutStatus.is_locked}
                <StatusBadge status="error" />
              {:else}
                <StatusBadge status="verified" />
              {/if}
            </div>
            {#if lockoutStatus.is_locked && lockoutStatus.recovery_seconds > 0}
              <div class="lockout-stat">
                <span class="text-label-small lockout-stat-label">Recovery Time</span>
                <span class="text-body-medium lockout-recovery">{Math.ceil(lockoutStatus.recovery_seconds / 60)} minutes remaining</span>
              </div>
            {/if}
          </div>

          {#if lockoutStatus.is_locked}
            <div class="lockout-alert" role="alert">
              <Icon path={mdiLockAlert} size={20} color="var(--color-security-danger)" />
              <span class="text-body-small">
                PIN entry is locked due to too many failed attempts.
                {#if lockoutStatus.recovery_seconds > 0}
                  Recovery in {Math.ceil(lockoutStatus.recovery_seconds / 60)} minutes,
                  or use the SO PIN to reset immediately.
                {/if}
              </span>
            </div>
          {/if}

          <div class="actions-list">
            <div class="action-row">
              <div class="field-info">
                <span class="text-title-small">Reset Lockout</span>
                <span class="text-body-small field-desc">Reset the failed attempts counter using the SO PIN</span>
              </div>
              <Button
                variant="outline"
                icon={mdiLockReset}
                on:click={() => { resetLockoutSOPIN = ''; showResetLockoutConfirm = true; }}
                disabled={!lockoutStatus.is_locked && lockoutStatus.failed_attempts === 0}
              >
                Reset
              </Button>
            </div>
          </div>
        {:else}
          <p class="text-body-medium empty-msg">Unable to load lockout status.</p>
          <Button variant="outline" on:click={loadLockoutStatus}>Retry</Button>
        {/if}
      </div>
    </Card>
    {/if}
  </div>

  <!-- Dialogs -->
  <PINDialog
    bind:open={showPINDialog}
    mode={pinDialogMode}
    on:close={() => (showPINDialog = false)}
    on:success={handlePINSuccess}
  />

  <Modal bind:open={showResetLockoutConfirm} title="Reset Lockout" maxWidth="400px">
    <div class="reset-form">
      <p class="text-body-medium">Enter the Security Officer PIN to reset the lockout counter.</p>
      <Input
        label="SO PIN"
        type="password"
        placeholder="Enter SO PIN"
        bind:value={resetLockoutSOPIN}
        disabled={resettingLockout}
      />
    </div>
    <svelte:fragment slot="actions">
      <Button variant="text" on:click={() => { showResetLockoutConfirm = false; resetLockoutSOPIN = ''; }} disabled={resettingLockout}>
        Cancel
      </Button>
      <Button variant="primary" loading={resettingLockout} on:click={handleResetLockout} disabled={!resetLockoutSOPIN}>
        Reset Lockout
      </Button>
    </svelte:fragment>
  </Modal>
</div>

<style>
  .pin-mgmt-view {
    height: 100%;
    display: flex;
    flex-direction: column;
  }

  .pin-mgmt-content {
    flex: 1;
    overflow-y: auto;
    padding: 24px;
    display: flex;
    flex-direction: column;
    gap: 20px;
    max-width: 700px;
  }

  .section {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .section-heading {
    margin: 0;
    color: var(--color-on-surface);
    padding-bottom: 8px;
    border-bottom: 1px solid var(--color-outline-variant);
  }

  .loading-row {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 16px 0;
    color: var(--color-on-surface-variant);
  }

  .loading-text {
    color: var(--color-on-surface-variant);
  }

  .field-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 24px;
    padding: 12px 0;
  }

  .field-row + .field-row {
    border-top: 1px solid var(--color-surface-variant);
  }

  .field-info {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .field-info span:first-child {
    color: var(--color-on-surface);
  }

  .field-desc {
    color: var(--color-on-surface-variant);
  }

  .check-indicator {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .strategy-badge {
    display: inline-flex;
    align-items: center;
    padding: 4px 12px;
    border-radius: var(--radius-full);
    background-color: var(--color-primary-95);
    color: var(--color-primary);
    font-size: 12px;
    font-weight: 600;
    letter-spacing: 0.3px;
  }

  :global([data-theme="dark"]) .strategy-badge {
    background-color: var(--color-primary-container);
    color: var(--color-on-primary-container);
  }

  .empty-msg {
    color: var(--color-on-surface-variant);
    margin: 0;
  }

  /* Actions */
  .actions-list {
    display: flex;
    flex-direction: column;
    gap: 0;
  }

  .action-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 24px;
    padding: 12px 0;
  }

  /* Lockout */
  .lockout-grid {
    display: grid;
    grid-template-columns: repeat(2, 1fr);
    gap: 12px;
  }

  .lockout-stat {
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .lockout-stat-label {
    color: var(--color-on-surface-variant);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .lockout-recovery {
    color: var(--color-security-danger);
    font-weight: 500;
  }

  .lockout-alert {
    display: flex;
    align-items: flex-start;
    gap: 10px;
    padding: 12px 16px;
    background-color: var(--color-security-danger-container);
    border-radius: var(--radius-sm);
    color: var(--color-on-security-danger-container);
  }

  /* Dialog */
  .reset-form {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .reset-form p {
    margin: 0;
    color: var(--color-on-surface-variant);
  }
</style>
