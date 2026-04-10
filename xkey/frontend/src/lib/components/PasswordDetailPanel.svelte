<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import Icon from './Icon.svelte';
  import Button from './Button.svelte';
  import EmptyState from './EmptyState.svelte';
  import {
    mdiLockOutline,
    mdiContentCopy,
    mdiEye,
    mdiEyeOff,
    mdiOpenInNew,
    mdiPencil,
    mdiDelete,
    mdiAccount,
    mdiWeb,
    mdiCalendarClock,
    mdiFolder,
  } from '$lib/utils/icons';
  import { addNotification } from '$lib/stores/notifications';
  import { callBackendVoid } from '$lib/api/backend';
  import type { StaticPasswordEntry } from '$lib/api/backend';

  export let entry: StaticPasswordEntry | null = null;

  const dispatch = createEventDispatcher<{
    edit: StaticPasswordEntry;
    delete: StaticPasswordEntry;
  }>();

  let passwordRevealed = false;

  $: if (entry) {
    passwordRevealed = false;
  }

  function maskPassword(pw: string): string {
    return '\u2022'.repeat(Math.min(pw.length, 24));
  }

  function copyToClipboard(text: string, label: string): void {
    navigator.clipboard.writeText(text).then(() => {
      addNotification('success', `${label} copied to clipboard`);
    }).catch(() => {
      addNotification('error', `Failed to copy ${label.toLowerCase()}`);
    });
  }

  function formatDate(dateStr: string): string {
    if (!dateStr) return 'Not set';
    try {
      const d = new Date(dateStr);
      return d.toLocaleDateString(undefined, {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit',
      });
    } catch {
      return dateStr;
    }
  }

  interface ExpiryDisplay {
    text: string;
    color: string;
  }

  function getExpiryDisplay(e: StaticPasswordEntry): ExpiryDisplay {
    if (e.days_until_expiry === -1 || !e.expires_at) {
      return { text: 'Never', color: 'var(--color-on-surface-variant)' };
    }
    if (e.is_expired) {
      return { text: 'Expired', color: 'var(--color-error)' };
    }
    if (e.days_until_expiry <= 30) {
      return { text: `${e.days_until_expiry} days remaining`, color: '#f59e0b' };
    }
    return { text: `${e.days_until_expiry} days remaining`, color: 'var(--color-success, #22c55e)' };
  }

  async function openUrl(url: string): Promise<void> {
    if (!url) return;
    const fullUrl = url.startsWith('http') ? url : `https://${url}`;
    const ok = await callBackendVoid('BrowserService', 'OpenURL', fullUrl);
    if (!ok) {
      addNotification('error', 'Failed to open URL');
    }
  }
</script>

<div class="detail-panel">
  {#if !entry}
    <div class="empty-container">
      <EmptyState
        icon={mdiLockOutline}
        title="Select a password"
        description="Choose a password from the list to view its details."
      />
    </div>
  {:else}
    {@const expiryInfo = getExpiryDisplay(entry)}

    <div class="detail-header">
      {#if !entry.read_only}
        <div class="detail-header-actions">
          <Button variant="outline" size="sm" icon={mdiPencil} on:click={() => dispatch('edit', entry)}>
            Edit
          </Button>
          <Button variant="danger" size="sm" icon={mdiDelete} on:click={() => dispatch('delete', entry)}>
            Delete
          </Button>
        </div>
      {:else}
        <div class="detail-header-actions">
          <span class="read-only-badge">Read-only</span>
        </div>
      {/if}
    </div>

    <div class="detail-fields">
      {#if entry.username}
        <div class="field-row">
          <div class="field-icon">
            <Icon path={mdiAccount} size={18} />
          </div>
          <div class="field-content">
            <span class="field-label">Username</span>
            <span class="field-value">{entry.username}</span>
          </div>
          <button class="field-action" on:click={() => copyToClipboard(entry.username, 'Username')} title="Copy username">
            <Icon path={mdiContentCopy} size={16} />
          </button>
        </div>
      {/if}

      <div class="field-row">
        <div class="field-icon">
          <Icon path={mdiLockOutline} size={18} />
        </div>
        <div class="field-content">
          <span class="field-label">Password</span>
          <span class="field-value font-mono">
            {passwordRevealed ? entry.password : maskPassword(entry.password)}
          </span>
        </div>
        <button class="field-action" on:click={() => (passwordRevealed = !passwordRevealed)} title={passwordRevealed ? 'Hide password' : 'Reveal password'}>
          <Icon path={passwordRevealed ? mdiEyeOff : mdiEye} size={16} />
        </button>
        <button class="field-action" on:click={() => copyToClipboard(entry.password, 'Password')} title="Copy password">
          <Icon path={mdiContentCopy} size={16} />
        </button>
      </div>

      {#if entry.url}
        <div class="field-row">
          <div class="field-icon">
            <Icon path={mdiWeb} size={18} />
          </div>
          <div class="field-content">
            <span class="field-label">URL</span>
            <button class="field-value field-url" on:click={() => openUrl(entry.url)} title="Open in browser">{entry.url}</button>
          </div>
          <button class="field-action" on:click={() => copyToClipboard(entry.url, 'URL')} title="Copy URL">
            <Icon path={mdiContentCopy} size={16} />
          </button>
        </div>
      {/if}

      {#if entry.match_patterns && entry.match_patterns.length > 0}
        <div class="field-row field-row-top">
          <div class="field-icon">
            <Icon path={mdiWeb} size={18} />
          </div>
          <div class="field-content">
            <span class="field-label">URL Match Patterns</span>
            <span class="field-value font-mono field-patterns">{entry.match_patterns.join('\n')}</span>
          </div>
        </div>
      {/if}

      {#if entry.notes}
        <div class="field-row field-row-top">
          <div class="field-icon">
            <Icon path={mdiLockOutline} size={18} />
          </div>
          <div class="field-content">
            <span class="field-label">Notes</span>
            <pre class="field-notes">{entry.notes}</pre>
          </div>
        </div>
      {/if}

      {#if entry.folder_path}
        <div class="field-row">
          <div class="field-icon">
            <Icon path={mdiFolder} size={18} />
          </div>
          <div class="field-content">
            <span class="field-label">Folder</span>
            <span class="field-value">{entry.folder_path}</span>
          </div>
        </div>
      {/if}

      {#if entry.backend_id}
        <div class="field-row">
          <div class="field-icon">
            <Icon path={mdiLockOutline} size={18} />
          </div>
          <div class="field-content">
            <span class="field-label">Backend</span>
            <span class="field-value">{entry.backend_id}</span>
          </div>
        </div>
      {/if}

      <div class="field-row">
        <div class="field-icon">
          <Icon path={mdiCalendarClock} size={18} />
        </div>
        <div class="field-content">
          <span class="field-label">Expires</span>
          <span class="field-value" style="color: {expiryInfo.color}">
            {#if entry.expires_at}
              {formatDate(entry.expires_at)} ({expiryInfo.text})
            {:else}
              {expiryInfo.text}
            {/if}
          </span>
        </div>
      </div>

      <div class="field-divider"></div>

      <div class="field-row">
        <div class="field-content">
          <span class="field-label">Created</span>
          <span class="field-value field-value-muted">{formatDate(entry.created_at)}</span>
        </div>
      </div>

      <div class="field-row">
        <div class="field-content">
          <span class="field-label">Updated</span>
          <span class="field-value field-value-muted">{formatDate(entry.updated_at)}</span>
        </div>
      </div>
    </div>
  {/if}
</div>

<style>
  .detail-panel {
    height: 100%;
    display: flex;
    flex-direction: column;
    overflow-y: auto;
  }

  .empty-container {
    flex: 1;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .detail-header {
    padding: 12px 20px;
    display: flex;
    align-items: center;
    justify-content: flex-end;
    gap: 12px;
    border-bottom: 1px solid var(--color-outline-variant);
  }

  .detail-header-actions {
    display: flex;
    gap: 6px;
    flex-shrink: 0;
    align-items: center;
  }

  .read-only-badge {
    font-size: 11px;
    font-weight: 500;
    color: var(--color-on-surface-variant);
    background-color: var(--color-surface-container);
    border: 1px solid var(--color-outline-variant);
    border-radius: 12px;
    padding: 4px 10px;
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .detail-fields {
    padding: 12px 20px 20px;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .field-row {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 8px 4px;
    border-radius: var(--radius-sm);
    transition: background-color var(--transition-fast);
  }

  .field-row:hover {
    background-color: var(--color-surface-container);
  }

  .field-row-top {
    align-items: flex-start;
  }

  .field-icon {
    color: var(--color-on-surface-variant);
    display: flex;
    flex-shrink: 0;
    opacity: 0.7;
  }

  .field-content {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 2px;
    min-width: 0;
  }

  .field-label {
    font-size: 11px;
    font-weight: 500;
    color: var(--color-on-surface-variant);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .field-value {
    font-size: 14px;
    color: var(--color-on-surface);
    word-break: break-all;
  }

  .field-value-muted {
    font-size: 13px;
    color: var(--color-on-surface-variant);
  }

  .field-url {
    color: var(--color-primary);
    cursor: pointer;
    text-decoration: none;
    background: none;
    border: none;
    padding: 0;
    font: inherit;
    text-align: left;
  }

  .field-url:hover {
    text-decoration: underline;
  }

  .field-patterns {
    font-size: 13px;
    white-space: pre-line;
    color: var(--color-primary);
  }

  .field-notes {
    font-size: 13px;
    color: var(--color-on-surface-variant);
    margin: 0;
    font-family: var(--font-sans);
    white-space: pre-wrap;
    word-break: break-word;
    background-color: var(--color-surface-container-low);
    padding: 8px 12px;
    border-radius: var(--radius-sm);
    border: 1px solid var(--color-outline-variant);
    max-height: 200px;
    overflow-y: auto;
  }

  .font-mono {
    font-family: var(--font-mono, monospace);
    letter-spacing: 0.5px;
  }

  .field-action {
    width: 28px;
    height: 28px;
    border: none;
    border-radius: 50%;
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    transition: background-color var(--transition-fast);
    padding: 0;
  }

  .field-action:hover {
    background-color: var(--color-surface-variant);
  }

  .field-divider {
    height: 1px;
    background-color: var(--color-outline-variant);
    margin: 8px 0;
    opacity: 0.5;
  }
</style>
