<script lang="ts">
  import { onMount } from 'svelte';
  import { callBackend } from '$lib/api/backend';
  import GradientHeader from '$lib/components/GradientHeader.svelte';
  import Card from '$lib/components/Card.svelte';
  import StatusBadge from '$lib/components/StatusBadge.svelte';
  import Icon from '$lib/components/Icon.svelte';
  import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
  import EmptyState from '$lib/components/EmptyState.svelte';
  import {
    mdiShieldLockOutline, mdiCheck, mdiAlert, mdiShieldCheckOutline
  } from '$lib/utils/icons';
  import { isPolicyVerified, isTamperDetected } from '$lib/stores/auth';

  let policy: Record<string, unknown> | null = null;
  let loading = true;
  let loadError = false;

  /** Human-readable labels for known policy fields. */
  const fieldLabels: Record<string, string> = {
    organization: 'Organization',
    admin_email: 'Admin Email',
    require_tpm: 'Require TPM',
    require_pin: 'Require PIN',
    require_encryption: 'Require Encryption',
    min_pin_length: 'Minimum PIN Length',
    max_pin_attempts: 'Maximum PIN Attempts',
    lockout_duration_seconds: 'Lockout Duration (seconds)',
    allowed_algorithms: 'Allowed Algorithms',
    allowed_backends: 'Allowed Backends',
    enforce_key_rotation: 'Enforce Key Rotation',
    key_rotation_days: 'Key Rotation Period (days)',
    audit_enabled: 'Audit Logging Enabled',
    fido2_enabled: 'FIDO2 Enabled',
    webauthn_enabled: 'WebAuthn Enabled',
    piv_enabled: 'PIV Enabled',
    oath_enabled: 'OATH Enabled',
    sealed_storage: 'Sealed Storage',
    hmac_key: 'HMAC Key',
    version: 'Policy Version',
    created_at: 'Created At',
    updated_at: 'Updated At',
  };

  function getFieldLabel(key: string): string {
    return fieldLabels[key] || key.replace(/_/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
  }

  function formatFieldValue(value: unknown): string {
    if (value === null || value === undefined) return '--';
    if (typeof value === 'boolean') return value ? 'Yes' : 'No';
    if (Array.isArray(value)) return value.length > 0 ? value.join(', ') : '--';
    if (typeof value === 'object') return JSON.stringify(value, null, 2);
    return String(value);
  }

  function isBooleanField(value: unknown): boolean {
    return typeof value === 'boolean';
  }

  function isSensitiveField(key: string): boolean {
    return key === 'hmac_key' || key.includes('secret') || key.includes('password');
  }

  onMount(async () => {
    const result = await callBackend<Record<string, unknown>>('SetupWizardService', 'GetPolicy');
    if (result) {
      policy = result;
    } else {
      loadError = true;
    }
    loading = false;
  });
</script>

<div class="policy-view">
  <GradientHeader title="Security Policy" subtitle="Enterprise policy configuration (read-only)" />

  <div class="policy-content">
    <!-- Policy Integrity Status -->
    <Card variant={$isTamperDetected ? 'security' : 'outlined'}>
      <div class="integrity-section">
        <div class="integrity-header">
          <Icon path={$isTamperDetected ? mdiAlert : mdiShieldCheckOutline} size={24} color={$isTamperDetected ? 'var(--color-error)' : 'var(--color-security-verified)'} />
          <div class="integrity-info">
            <h3 class="text-title-medium integrity-title">
              {$isTamperDetected ? 'Policy Integrity Compromised' : 'Policy Integrity Verified'}
            </h3>
            <p class="text-body-small integrity-desc">
              {#if $isTamperDetected}
                The HMAC signature does not match. The policy may have been tampered with.
              {:else if $isPolicyVerified}
                The policy HMAC signature has been verified successfully.
              {:else}
                Policy verification has not been performed.
              {/if}
            </p>
          </div>
          <StatusBadge status={$isTamperDetected ? 'error' : $isPolicyVerified ? 'verified' : 'warning'} />
        </div>
      </div>
    </Card>

    <!-- Policy Fields -->
    {#if loading}
      <div class="loading-container">
        <LoadingSpinner size={48} />
        <span class="text-body-medium loading-text">Loading policy...</span>
      </div>
    {:else if loadError || !policy}
      <EmptyState
        icon={mdiShieldLockOutline}
        title="Policy not available"
        description="Unable to load the security policy. Ensure the policy has been configured during setup."
      />
    {:else}
      <Card variant="elevated">
        <div class="policy-table-section">
          <h3 class="text-title-medium section-heading">Policy Configuration</h3>
          <div class="policy-table">
            {#each Object.entries(policy) as [key, value]}
              <div class="policy-field">
                <span class="text-body-medium policy-field-label">{getFieldLabel(key)}</span>
                <span class="text-body-medium policy-field-value" class:font-mono={!isBooleanField(value)}>
                  {#if isSensitiveField(key)}
                    <span class="sensitive-value">********</span>
                  {:else if isBooleanField(value)}
                    <span class="bool-indicator" class:bool-true={value} class:bool-false={!value}>
                      <Icon path={value ? mdiCheck : mdiAlert} size={16} />
                      {value ? 'Enabled' : 'Disabled'}
                    </span>
                  {:else}
                    {formatFieldValue(value)}
                  {/if}
                </span>
              </div>
            {/each}
          </div>
        </div>
      </Card>
    {/if}
  </div>
</div>

<style>
  .policy-view {
    height: 100%;
    display: flex;
    flex-direction: column;
  }

  .policy-content {
    flex: 1;
    overflow-y: auto;
    padding: 24px;
    display: flex;
    flex-direction: column;
    gap: 20px;
    max-width: 800px;
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

  /* Integrity Status */
  .integrity-section {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .integrity-header {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .integrity-info {
    flex: 1;
  }

  .integrity-title {
    margin: 0;
    color: var(--color-on-surface);
  }

  .integrity-desc {
    margin: 0;
    color: var(--color-on-surface-variant);
  }

  /* Policy Table */
  .policy-table-section {
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

  .policy-table {
    display: flex;
    flex-direction: column;
    gap: 0;
  }

  .policy-field {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 24px;
    padding: 12px 0;
  }

  .policy-field + .policy-field {
    border-top: 1px solid var(--color-surface-variant);
  }

  .policy-field-label {
    color: var(--color-on-surface);
    flex-shrink: 0;
    min-width: 200px;
  }

  .policy-field-value {
    color: var(--color-on-surface-variant);
    text-align: right;
    word-break: break-word;
  }

  .sensitive-value {
    color: var(--color-on-surface-variant);
    opacity: 0.5;
    letter-spacing: 2px;
  }

  .bool-indicator {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    padding: 2px 10px;
    border-radius: var(--radius-full);
    font-size: 13px;
    font-weight: 500;
  }

  .bool-true {
    color: var(--color-security-verified);
    background-color: var(--color-security-verified-container);
  }

  .bool-false {
    color: var(--color-on-surface-variant);
    background-color: var(--color-surface-variant);
  }
</style>
