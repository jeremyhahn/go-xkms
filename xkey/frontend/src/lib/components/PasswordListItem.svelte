<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import Icon from './Icon.svelte';
  import { mdiContentCopy, mdiDelete } from '$lib/utils/icons';
  import type { StaticPasswordEntry } from '$lib/api/backend';

  export let entry: StaticPasswordEntry;
  export let selected: boolean = false;

  const dispatch = createEventDispatcher<{
    select: StaticPasswordEntry;
    copyPassword: StaticPasswordEntry;
    delete: StaticPasswordEntry;
  }>();

  $: displayTitle = entry.title || entry.name;

  $: domain = extractDomain(entry.url);

  $: expiryStatus = getExpiryStatus(entry);

  function extractDomain(url: string): string {
    if (!url) return '';
    try {
      const parsed = new URL(url.startsWith('http') ? url : `https://${url}`);
      return parsed.hostname;
    } catch {
      return url;
    }
  }

  interface ExpiryInfo {
    color: string;
    visible: boolean;
  }

  function getExpiryStatus(e: StaticPasswordEntry): ExpiryInfo {
    if (e.days_until_expiry === -1 || !e.expires_at) {
      return { color: '', visible: false };
    }
    if (e.is_expired) {
      return { color: 'var(--color-error)', visible: true };
    }
    if (e.days_until_expiry <= 30) {
      return { color: '#f59e0b', visible: true };
    }
    return { color: '', visible: false };
  }
</script>

<div
  class="list-item"
  class:selected
  on:click={() => dispatch('select', entry)}
  on:keydown={(e) => e.key === 'Enter' && dispatch('select', entry)}
  role="option"
  aria-selected={selected}
  tabindex="0"
>
  <div class="item-content">
    <div class="item-main">
      <div class="item-title-row">
        <span class="item-title">{displayTitle}</span>
        {#if expiryStatus.visible}
          <span class="expiry-dot" style="background-color: {expiryStatus.color}" title={entry.is_expired ? 'Expired' : `Expires in ${entry.days_until_expiry} days`}></span>
        {/if}
      </div>
      {#if entry.username}
        <span class="item-username">{entry.username}</span>
      {/if}
      {#if domain}
        <span class="item-domain">{domain}</span>
      {/if}
    </div>
  </div>

  <div class="item-actions">
    <button
      class="action-btn"
      on:click|stopPropagation={() => dispatch('copyPassword', entry)}
      title="Copy password"
    >
      <Icon path={mdiContentCopy} size={16} />
    </button>
    <button
      class="action-btn action-btn-danger"
      on:click|stopPropagation={() => dispatch('delete', entry)}
      title="Delete"
    >
      <Icon path={mdiDelete} size={16} />
    </button>
  </div>
</div>

<style>
  .list-item {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 10px 12px;
    border-bottom: 1px solid var(--color-outline-variant);
    cursor: pointer;
    transition: background-color var(--transition-fast);
    gap: 8px;
  }

  .list-item:hover {
    background-color: var(--color-surface-container);
  }

  .list-item.selected {
    background-color: var(--color-primary-container, var(--color-surface-variant));
  }

  .item-content {
    flex: 1;
    min-width: 0;
  }

  .item-main {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .item-title-row {
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .item-title {
    font-size: 14px;
    font-weight: 500;
    color: var(--color-on-surface);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .selected .item-title {
    color: var(--color-on-primary-container, var(--color-primary));
  }

  .expiry-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    flex-shrink: 0;
  }

  .item-username {
    font-size: 12px;
    color: var(--color-on-surface-variant);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .item-domain {
    font-size: 11px;
    color: var(--color-on-surface-variant);
    opacity: 0.7;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .item-actions {
    display: flex;
    gap: 2px;
    flex-shrink: 0;
    opacity: 0;
    transition: opacity var(--transition-fast);
  }

  .list-item:hover .item-actions {
    opacity: 1;
  }

  .action-btn {
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
    transition: background-color var(--transition-fast);
    padding: 0;
  }

  .action-btn:hover {
    background-color: var(--color-surface-variant);
  }

  .action-btn-danger:hover {
    background-color: var(--color-error-container);
    color: var(--color-on-error-container);
  }
</style>
