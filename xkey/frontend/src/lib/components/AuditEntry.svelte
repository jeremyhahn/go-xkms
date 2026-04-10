<script lang="ts">
  import Icon from './Icon.svelte';
  import { mdiCheckCircle, mdiCloseCircle, mdiKey, mdiShieldCheckOutline, mdiCellphone, mdiConnection } from '$lib/utils/icons';
  import { formatRelativeTime, formatDateTime } from '$lib/utils/format';

  export let entry: {
    id: string;
    timestamp: string;
    operation: string;
    device: string;
    backend: string;
    keyId: string;
    success: boolean;
    details: string;
    ipAddress: string;
  };

  const operationIcons: Record<string, string> = {
    sign: mdiKey,
    verify: mdiShieldCheckOutline,
    connect: mdiConnection,
    pair: mdiCellphone,
    attest: mdiShieldCheckOutline,
  };

  $: iconPath = operationIcons[entry.operation.toLowerCase()] || mdiKey;
</script>

<div class="audit-entry" class:audit-success={entry.success} class:audit-failure={!entry.success}>
  <div class="audit-icon">
    <Icon path={iconPath} size={20} />
  </div>
  <div class="audit-content">
    <div class="audit-header-row">
      <span class="text-title-small audit-operation">{entry.operation}</span>
      <span class="audit-status">
        <Icon path={entry.success ? mdiCheckCircle : mdiCloseCircle} size={16} />
      </span>
    </div>
    <p class="text-body-small audit-details">{entry.details}</p>
    <div class="audit-meta">
      {#if entry.device}
        <span class="text-label-small audit-meta-item">Device: {entry.device}</span>
      {/if}
      {#if entry.backend}
        <span class="text-label-small audit-meta-item">Backend: {entry.backend}</span>
      {/if}
      {#if entry.keyId}
        <span class="text-label-small audit-meta-item font-mono">Key: {entry.keyId.substring(0, 12)}...</span>
      {/if}
    </div>
  </div>
  <div class="audit-time">
    <span class="text-body-small" title={formatDateTime(entry.timestamp)}>{formatRelativeTime(entry.timestamp)}</span>
  </div>
</div>

<style>
  .audit-entry {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    padding: 12px 16px;
    border-radius: var(--radius-md);
    background-color: var(--color-surface-container-low);
    transition: background-color var(--transition-fast);
  }

  .audit-entry:hover {
    background-color: var(--color-surface-container);
  }

  .audit-icon {
    width: 36px;
    height: 36px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  .audit-success .audit-icon {
    background-color: var(--color-security-verified-container);
    color: var(--color-security-verified);
  }

  .audit-failure .audit-icon {
    background-color: var(--color-security-danger-container);
    color: var(--color-security-danger);
  }

  .audit-content {
    flex: 1;
    min-width: 0;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .audit-header-row {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .audit-operation {
    color: var(--color-on-surface);
    text-transform: capitalize;
  }

  .audit-success .audit-status {
    color: var(--color-security-verified);
  }

  .audit-failure .audit-status {
    color: var(--color-security-danger);
  }

  .audit-details {
    color: var(--color-on-surface-variant);
    margin: 0;
  }

  .audit-meta {
    display: flex;
    flex-wrap: wrap;
    gap: 12px;
  }

  .audit-meta-item {
    color: var(--color-on-surface-variant);
    opacity: 0.8;
  }

  .audit-time {
    flex-shrink: 0;
    color: var(--color-on-surface-variant);
  }
</style>
