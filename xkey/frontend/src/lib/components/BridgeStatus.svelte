<script lang="ts">
  import Card from './Card.svelte';
  import StatusBadge from './StatusBadge.svelte';
  import Toggle from './Toggle.svelte';
  import Icon from './Icon.svelte';
  import { mdiConnection, mdiClockOutline, mdiShieldCheckOutline } from '$lib/utils/icons';
  import { formatRelativeTime, formatDuration } from '$lib/utils/format';
  import type { BridgeStatus as BridgeStatusType } from '$lib/stores/fido2';

  export let status: BridgeStatusType;
  export let onToggle: ((enabled: boolean) => void) | null = null;
</script>

<Card variant="security">
  <div class="bridge-status" data-testid="bridge-status">
    <div class="bridge-header">
      <div class="bridge-title-row">
        <h3 class="text-title-medium bridge-title">FIDO2 Phone Bridge</h3>
        <StatusBadge status={status.running ? 'connected' : 'disconnected'} data-testid="bridge-badge" />
      </div>
      <Toggle
        checked={status.running}
        label={status.running ? 'Active' : 'Inactive'}
        onChange={(v) => onToggle?.(v)}
        data-testid="bridge-toggle"
      />
    </div>

    {#if status.running}
      <div class="bridge-details" data-testid="bridge-details">
        {#if status.deviceName}
          <div class="detail-row" data-testid="bridge-device-name">
            <Icon path={mdiConnection} size={18} />
            <span class="text-body-medium">Device: {status.deviceName}</span>
          </div>
        {/if}
        {#if status.connectionType}
          <div class="detail-row">
            <Icon path={mdiShieldCheckOutline} size={18} />
            <span class="text-body-medium">Transport: {status.connectionType}</span>
          </div>
        {/if}
        <div class="detail-row" data-testid="bridge-uptime">
          <Icon path={mdiClockOutline} size={18} />
          <span class="text-body-medium">Uptime: {formatDuration(status.uptime)}</span>
        </div>
      </div>

      {#if status.recentAuthentications.length > 0}
        <div class="bridge-auth-list" data-testid="bridge-auth-list">
          <h4 class="text-label-large auth-list-title">Recent Authentications</h4>
          {#each status.recentAuthentications.slice(0, 5) as auth}
            <div class="auth-item" class:auth-success={auth.success} class:auth-failure={!auth.success}>
              <span class="auth-rp text-body-medium">{auth.relyingParty}</span>
              <span class="auth-time text-body-small">{formatRelativeTime(auth.timestamp)}</span>
              <span class="auth-result text-label-small">{auth.success ? 'Success' : 'Failed'}</span>
            </div>
          {/each}
        </div>
      {/if}
    {:else}
      <p class="text-body-medium bridge-inactive-text" data-testid="bridge-inactive-text">
        Enable the bridge to relay WebAuthn requests to your phone for biometric authentication.
      </p>
    {/if}
  </div>
</Card>

<style>
  .bridge-status {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .bridge-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
  }

  .bridge-title-row {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .bridge-title {
    margin: 0;
    color: var(--color-on-surface);
  }

  .bridge-details {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .detail-row {
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--color-on-surface-variant);
  }

  .bridge-auth-list {
    display: flex;
    flex-direction: column;
    gap: 8px;
    padding-top: 8px;
    border-top: 1px solid var(--color-outline-variant);
  }

  .auth-list-title {
    color: var(--color-on-surface-variant);
    margin: 0;
  }

  .auth-item {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 8px 12px;
    border-radius: var(--radius-sm);
    background-color: var(--color-surface-container-low);
  }

  .auth-rp {
    flex: 1;
    color: var(--color-on-surface);
  }

  .auth-time {
    color: var(--color-on-surface-variant);
  }

  .auth-result {
    padding: 2px 8px;
    border-radius: var(--radius-full);
  }

  .auth-success .auth-result {
    background-color: var(--color-security-verified-container);
    color: var(--color-on-security-verified-container);
  }

  .auth-failure .auth-result {
    background-color: var(--color-security-danger-container);
    color: var(--color-on-security-danger-container);
  }

  .bridge-inactive-text {
    color: var(--color-on-surface-variant);
    margin: 0;
  }
</style>
