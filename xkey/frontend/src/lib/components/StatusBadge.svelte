<script lang="ts">
  export let status: 'connected' | 'disconnected' | 'advertising' | 'error' | 'pairing' | 'verified' | 'unverified' | 'warning' | 'neutral' | 'success' | 'inactive' = 'disconnected';
  export let label: string = '';
  export let text: string = '';

  const labelMap: Record<string, string> = {
    connected: 'Connected',
    disconnected: 'Disconnected',
    advertising: 'Advertising',
    error: 'Error',
    pairing: 'Pairing',
    verified: 'Verified',
    unverified: 'Unverified',
    warning: 'Warning',
    neutral: 'N/A',
    success: 'Success',
    inactive: 'Inactive',
  };

  $: displayText = text || label || labelMap[status];
  $: cssClass = status === 'success' ? 'verified' : status === 'inactive' ? 'disconnected' : status;
</script>

<span class="badge badge-{cssClass}" role="status" aria-label={displayText} {...$$restProps}>
  <span class="badge-dot"></span>
  <span class="badge-text text-label-small">{displayText}</span>
</span>

<style>
  .badge {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 4px 12px;
    border-radius: var(--radius-full);
    font-weight: 500;
  }

  .badge-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
  }

  .badge-connected {
    background-color: var(--color-security-verified-container);
    color: var(--color-on-security-verified-container);
  }
  .badge-connected .badge-dot {
    background-color: var(--color-security-verified);
    animation: pulse-indicator 2s ease-in-out infinite;
  }

  .badge-disconnected {
    background-color: var(--color-security-neutral-container);
    color: var(--color-on-security-neutral-container);
  }
  .badge-disconnected .badge-dot {
    background-color: var(--color-security-neutral);
  }

  .badge-advertising {
    background-color: var(--color-security-warning-container);
    color: var(--color-on-security-warning-container);
  }
  .badge-advertising .badge-dot {
    background-color: var(--color-security-warning);
    animation: pulse-indicator 1.5s ease-in-out infinite;
  }

  .badge-error {
    background-color: var(--color-security-danger-container);
    color: var(--color-on-security-danger-container);
  }
  .badge-error .badge-dot {
    background-color: var(--color-security-danger);
  }

  .badge-pairing {
    background-color: var(--color-primary-95);
    color: var(--color-primary-10);
  }
  :global([data-theme="dark"]) .badge-pairing {
    background-color: var(--color-primary-container);
    color: var(--color-on-primary-container);
  }
  .badge-pairing .badge-dot {
    background-color: var(--color-status-pairing);
    animation: pulse-indicator 1s ease-in-out infinite;
  }

  .badge-verified {
    background-color: var(--color-security-verified-container);
    color: var(--color-on-security-verified-container);
  }
  .badge-verified .badge-dot {
    background-color: var(--color-security-verified);
  }

  .badge-unverified {
    background-color: var(--color-security-warning-container);
    color: var(--color-on-security-warning-container);
  }
  .badge-unverified .badge-dot {
    background-color: var(--color-security-warning);
  }

  .badge-warning {
    background-color: var(--color-security-warning-container);
    color: var(--color-on-security-warning-container);
  }
  .badge-warning .badge-dot {
    background-color: var(--color-security-warning);
  }

  .badge-neutral {
    background-color: var(--color-security-neutral-container);
    color: var(--color-on-security-neutral-container);
  }
  .badge-neutral .badge-dot {
    background-color: var(--color-security-neutral);
    opacity: 0.5;
  }

  @keyframes pulse-indicator {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.4; }
  }
</style>
