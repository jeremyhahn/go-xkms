<script lang="ts">
  import { onMount } from 'svelte';
  import { callBackend } from '$lib/api/backend';
  import type { PINStatus, BackendTPMStatus } from '$lib/api/backend';
  import { isPolicyVerified, isTamperDetected } from '$lib/stores/auth';
  import Icon from '$lib/components/Icon.svelte';
  import GradientHeader from '$lib/components/GradientHeader.svelte';
  import Card from '$lib/components/Card.svelte';
  import StatusBadge from '$lib/components/StatusBadge.svelte';
  import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
  import {
    mdiShieldCheckOutline, mdiChip, mdiLockOutline,
    mdiAlert, mdiCheck, mdiClose, mdiShieldLockOutline
  } from '$lib/utils/icons';

  let pinStatus: PINStatus | null = null;
  let tpmStatus: BackendTPMStatus | null = null;
  let loading = true;

  onMount(async () => {
    const [pinResult, tpmResult] = await Promise.all([
      callBackend<PINStatus>('PINService', 'GetPINStatus'),
      callBackend<BackendTPMStatus>('TPMService', 'GetTPMStatus'),
    ]);
    pinStatus = pinResult;
    tpmStatus = tpmResult;
    loading = false;
  });
</script>

<div class="admin-dashboard">
  <GradientHeader title="Admin Dashboard" subtitle="Security Officer overview and system status" />

  <div class="dashboard-content">
    {#if loading}
      <div class="loading-container">
        <LoadingSpinner size={48} />
        <span class="text-body-medium loading-text">Loading system status...</span>
      </div>
    {:else}
      <div class="status-grid">
        <!-- Security Policy Card -->
        <Card variant="outlined">
          <div class="status-card">
            <div class="status-card-header">
              <div class="status-card-icon" class:status-good={$isPolicyVerified && !$isTamperDetected} class:status-bad={$isTamperDetected}>
                <Icon path={mdiShieldLockOutline} size={24} color="#FFFFFF" />
              </div>
              <h3 class="text-title-medium status-card-title">Security Policy</h3>
            </div>

            <div class="status-card-body">
              <div class="status-row">
                <span class="text-body-medium status-label">Policy Verified</span>
                <div class="status-indicator">
                  {#if $isPolicyVerified}
                    <Icon path={mdiCheck} size={18} color="var(--color-security-verified)" />
                    <span class="text-label-small" style="color: var(--color-security-verified);">Verified</span>
                  {:else}
                    <Icon path={mdiClose} size={18} color="var(--color-on-surface-variant)" />
                    <span class="text-label-small" style="color: var(--color-on-surface-variant);">Not Verified</span>
                  {/if}
                </div>
              </div>

              <div class="status-row">
                <span class="text-body-medium status-label">Tamper Status</span>
                <div class="status-indicator">
                  {#if $isTamperDetected}
                    <Icon path={mdiAlert} size={18} color="var(--color-error)" />
                    <span class="text-label-small" style="color: var(--color-error);">Tamper Detected</span>
                  {:else}
                    <Icon path={mdiShieldCheckOutline} size={18} color="var(--color-security-verified)" />
                    <span class="text-label-small" style="color: var(--color-security-verified);">Clean</span>
                  {/if}
                </div>
              </div>
            </div>
          </div>
        </Card>

        <!-- Hardware Status Card -->
        <Card variant="outlined">
          <div class="status-card">
            <div class="status-card-header">
              <div class="status-card-icon" class:status-good={tpmStatus?.available} class:status-warning={!tpmStatus?.available && tpmStatus?.device_exists} class:status-neutral={!tpmStatus?.available && !tpmStatus?.device_exists}>
                <Icon path={mdiChip} size={24} color="#FFFFFF" />
              </div>
              <h3 class="text-title-medium status-card-title">Hardware</h3>
            </div>

            <div class="status-card-body">
              <div class="status-row">
                <span class="text-body-medium status-label">TPM 2.0</span>
                <StatusBadge status={tpmStatus?.available ? 'connected' : tpmStatus?.device_exists ? 'warning' : 'disconnected'} />
              </div>

              {#if tpmStatus?.available}
                <div class="status-row">
                  <span class="text-body-medium status-label">Provisioned</span>
                  <div class="status-indicator">
                    {#if tpmStatus.provisioned}
                      <Icon path={mdiCheck} size={18} color="var(--color-security-verified)" />
                      <span class="text-label-small" style="color: var(--color-security-verified);">Yes</span>
                    {:else}
                      <Icon path={mdiClose} size={18} color="var(--color-on-surface-variant)" />
                      <span class="text-label-small" style="color: var(--color-on-surface-variant);">No</span>
                    {/if}
                  </div>
                </div>

                {#if tpmStatus.manufacturer}
                  <div class="status-row">
                    <span class="text-body-medium status-label">Manufacturer</span>
                    <span class="text-body-small font-mono">{tpmStatus.manufacturer}</span>
                  </div>
                {/if}

                {#if tpmStatus.firmware_version}
                  <div class="status-row">
                    <span class="text-body-medium status-label">Firmware</span>
                    <span class="text-body-small font-mono">{tpmStatus.firmware_version}</span>
                  </div>
                {/if}
              {:else if tpmStatus?.device_exists}
                <p class="text-body-small status-unavailable">
                  TPM device detected but not initialized. {tpmStatus?.init_error || ''}
                </p>
                {#if tpmStatus?.device_path}
                  <div class="status-row">
                    <span class="text-body-medium status-label">Device</span>
                    <span class="text-body-small font-mono">{tpmStatus.device_path}</span>
                  </div>
                {/if}
              {:else}
                <p class="text-body-small status-unavailable">
                  No TPM hardware detected on this system.
                </p>
              {/if}
            </div>
          </div>
        </Card>

        <!-- PIN Status Card -->
        <Card variant="outlined">
          <div class="status-card">
            <div class="status-card-header">
              <div class="status-card-icon" class:status-good={pinStatus?.so_pin_set && pinStatus?.user_pin_set} class:status-neutral={!pinStatus?.so_pin_set || !pinStatus?.user_pin_set}>
                <Icon path={mdiLockOutline} size={24} color="#FFFFFF" />
              </div>
              <h3 class="text-title-medium status-card-title">PIN Status</h3>
            </div>

            <div class="status-card-body">
              {#if pinStatus}
                <div class="status-row">
                  <span class="text-body-medium status-label">SO PIN</span>
                  <div class="status-indicator">
                    {#if pinStatus.so_pin_set}
                      <Icon path={mdiCheck} size={18} color="var(--color-security-verified)" />
                      <span class="text-label-small" style="color: var(--color-security-verified);">Configured</span>
                    {:else}
                      <Icon path={mdiClose} size={18} color="var(--color-on-surface-variant)" />
                      <span class="text-label-small" style="color: var(--color-on-surface-variant);">Not Set</span>
                    {/if}
                  </div>
                </div>

                <div class="status-row">
                  <span class="text-body-medium status-label">User PIN</span>
                  <div class="status-indicator">
                    {#if pinStatus.user_pin_set}
                      <Icon path={mdiCheck} size={18} color="var(--color-security-verified)" />
                      <span class="text-label-small" style="color: var(--color-security-verified);">Configured</span>
                    {:else}
                      <Icon path={mdiClose} size={18} color="var(--color-on-surface-variant)" />
                      <span class="text-label-small" style="color: var(--color-on-surface-variant);">Not Set</span>
                    {/if}
                  </div>
                </div>

                {#if pinStatus.strategy}
                  <div class="status-row">
                    <span class="text-body-medium status-label">Strategy</span>
                    <span class="pin-strategy-badge">{pinStatus.strategy}</span>
                  </div>
                {/if}
              {:else}
                <p class="text-body-small status-unavailable">Unable to retrieve PIN status.</p>
              {/if}
            </div>
          </div>
        </Card>
      </div>
    {/if}
  </div>
</div>

<style>
  .admin-dashboard {
    height: 100%;
    display: flex;
    flex-direction: column;
  }

  .dashboard-content {
    flex: 1;
    overflow-y: auto;
    padding: 24px;
  }

  .loading-container {
    display: flex;
    flex-direction: column;
    align-items: center;
    justify-content: center;
    gap: 16px;
    padding: 64px 0;
  }

  .loading-text {
    color: var(--color-on-surface-variant);
  }

  .status-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
    gap: 16px;
  }

  .status-card {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .status-card-header {
    display: flex;
    align-items: center;
    gap: 12px;
    padding-bottom: 12px;
    border-bottom: 1px solid var(--color-outline-variant);
  }

  .status-card-icon {
    width: 40px;
    height: 40px;
    border-radius: var(--radius-md);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    background-color: var(--color-on-surface-variant);
  }

  .status-card-icon.status-good {
    background-color: var(--color-security-verified);
  }

  .status-card-icon.status-bad {
    background-color: var(--color-error);
  }

  .status-card-icon.status-neutral {
    background-color: var(--color-on-surface-variant);
    opacity: 0.6;
  }

  .status-card-title {
    margin: 0;
    color: var(--color-on-surface);
  }

  .status-card-body {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .status-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
  }

  .status-label {
    color: var(--color-on-surface);
  }

  .status-indicator {
    display: flex;
    align-items: center;
    gap: 6px;
  }

  .status-unavailable {
    color: var(--color-on-surface-variant);
    margin: 0;
    font-style: italic;
  }

  .pin-strategy-badge {
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

  :global([data-theme="dark"]) .pin-strategy-badge {
    background-color: var(--color-primary-container);
    color: var(--color-on-primary-container);
  }
</style>
