<script lang="ts">
  import Card from './Card.svelte';
  import Icon from './Icon.svelte';
  import ProgressRing from './ProgressRing.svelte';
  import { mdiContentCopy, mdiCheckCircle, mdiDelete } from '$lib/utils/icons';
  import { formatTOTPCode } from '$lib/utils/format';
  import type { OATHAccount } from '$lib/stores/oath';

  export let account: OATHAccount;
  export let code: string = '';
  export let timeRemaining: number = 30;
  export let period: number = 30;
  export let onCopy: ((code: string) => void) | null = null;
  export let onDelete: ((accountId: string) => void) | null = null;

  let copied = false;
  let copyTimeout: ReturnType<typeof setTimeout> | null = null;
  let confirmDelete = false;

  $: progress = timeRemaining / period;
  $: displayCode = code ? formatTOTPCode(code) : '--- ---';
  $: isLow = timeRemaining <= 5;
  $: initial = account.issuer ? account.issuer.charAt(0).toUpperCase() : '?';

  function handleCopy(): void {
    if (!code) return;
    onCopy?.(code);
    copied = true;
    if (copyTimeout) clearTimeout(copyTimeout);
    copyTimeout = setTimeout(() => { copied = false; }, 2000);
  }

  function handleDelete(): void {
    if (!confirmDelete) {
      confirmDelete = true;
      setTimeout(() => { confirmDelete = false; }, 3000);
      return;
    }
    onDelete?.(account.id);
    confirmDelete = false;
  }
</script>

<Card variant="elevated">
  <div class="totp-card">
    <div class="totp-header">
      <div class="totp-issuer-icon">
        <span class="text-title-medium">{initial}</span>
      </div>
      <div class="totp-info">
        <span class="text-title-small totp-issuer">{account.issuer}</span>
        <span class="text-body-small totp-account">{account.accountName}</span>
      </div>
    </div>

    <div class="totp-code-row">
      <div class="totp-code-container">
        <span class="totp-code" class:totp-code-low={isLow}>{displayCode}</span>
      </div>
      <div class="totp-timer">
        <ProgressRing progress={progress} size={44} strokeWidth={3}>
          <text
            x="22"
            y="22"
            text-anchor="middle"
            dominant-baseline="central"
            class="timer-text"
            fill={isLow ? 'var(--color-error)' : 'var(--color-on-surface-variant)'}
          >
            {timeRemaining}
          </text>
        </ProgressRing>
      </div>
    </div>

    <div class="totp-actions">
      <button class="totp-copy" class:totp-copied={copied} on:click={handleCopy} aria-label="Copy code">
        <Icon path={copied ? mdiCheckCircle : mdiContentCopy} size={18} />
        <span class="text-label-medium">{copied ? 'Copied' : 'Copy'}</span>
      </button>
      <button class="totp-delete" class:totp-delete-confirm={confirmDelete} on:click={handleDelete} aria-label="Delete account">
        <Icon path={mdiDelete} size={18} />
        <span class="text-label-medium">{confirmDelete ? 'Confirm?' : 'Delete'}</span>
      </button>
    </div>
  </div>
</Card>

<style>
  .totp-card {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .totp-header {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .totp-issuer-icon {
    width: 40px;
    height: 40px;
    border-radius: var(--radius-md);
    background: var(--gradient-secondary);
    color: var(--color-on-secondary);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    font-weight: 600;
  }

  .totp-info {
    display: flex;
    flex-direction: column;
    min-width: 0;
  }

  .totp-issuer {
    color: var(--color-on-surface);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .totp-account {
    color: var(--color-on-surface-variant);
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .totp-code-row {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 16px;
  }

  .totp-code-container {
    flex: 1;
  }

  .totp-code {
    font-family: var(--font-mono);
    font-size: 32px;
    font-weight: 600;
    letter-spacing: 4px;
    color: var(--color-on-surface);
    transition: color var(--transition-fast);
  }

  .totp-code-low {
    color: var(--color-error);
    animation: pulse-indicator 0.5s ease-in-out infinite;
  }

  .timer-text {
    font-family: var(--font-mono);
    font-size: 12px;
    font-weight: 600;
  }

  .totp-actions {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .totp-copy, .totp-delete {
    display: inline-flex;
    align-items: center;
    gap: 6px;
    padding: 8px 16px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-full);
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    font-family: var(--font-sans);
    transition: background-color var(--transition-fast),
                color var(--transition-fast),
                border-color var(--transition-fast);
  }

  .totp-copy:hover, .totp-delete:hover {
    background-color: var(--color-surface-container);
    border-color: var(--color-outline);
  }

  .totp-copied {
    color: var(--color-security-verified);
    border-color: var(--color-security-verified);
  }

  .totp-delete:hover {
    color: var(--color-error);
    border-color: var(--color-error);
  }

  .totp-delete-confirm {
    color: var(--color-error);
    border-color: var(--color-error);
    background-color: var(--color-security-danger-container);
  }

  @keyframes pulse-indicator {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
  }
</style>
