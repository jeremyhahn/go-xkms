<script lang="ts">
  import Card from './Card.svelte';
  import Button from './Button.svelte';
  import StatusBadge from './StatusBadge.svelte';
  import Icon from './Icon.svelte';
  import {
    mdiPlay, mdiStop, mdiRefresh, mdiPencil, mdiDelete, mdiClockOutline, mdiTimer,
    mdiCodeBraces, mdiCogPlay, mdiDotsVertical, mdiLogout, mdiLogin
  } from '$lib/utils/icons';
  import type { OIDCProviderEntry, OIDCTokenInfo, OIDCRefreshStatus } from '$lib/api/backend';

  export let provider: OIDCProviderEntry;
  export let token: OIDCTokenInfo | undefined = undefined;
  export let refreshStatus: OIDCRefreshStatus | undefined = undefined;
  export let onLogin: (name: string) => void = () => {};
  export let onLogout: (name: string) => void = () => {};
  export let onRefresh: (name: string) => void = () => {};
  export let onEdit: (provider: OIDCProviderEntry) => void = () => {};
  export let onDelete: (name: string) => void = () => {};
  export let onStartAutoRefresh: (name: string) => void = () => {};
  export let onStopAutoRefresh: (name: string) => void = () => {};
  export let onViewToken: (name: string) => void = () => {};
  export let onRunExec: (provider: OIDCProviderEntry) => void = () => {};
  export let loginLoading: boolean = false;
  export let refreshLoading: boolean = false;

  $: hasToken = token !== undefined && !token.is_expired;
  $: isExpired = token !== undefined && token.is_expired;
  $: tokenStatus = (hasToken ? 'connected' : isExpired ? 'warning' : 'disconnected') as 'connected' | 'warning' | 'disconnected';
  $: isAutoRefreshing = refreshStatus?.running ?? false;

  let menuOpen = false;

  function toggleMenu(): void {
    menuOpen = !menuOpen;
  }

  function closeMenu(): void {
    menuOpen = false;
  }

  function menuAction(fn: () => void): void {
    fn();
    closeMenu();
  }

  function formatExpiry(expiresIn: number): string {
    if (expiresIn <= 0) return 'Expired';
    if (expiresIn < 60) return `${expiresIn}s`;
    if (expiresIn < 3600) return `${Math.floor(expiresIn / 60)}m`;
    return `${Math.floor(expiresIn / 3600)}h ${Math.floor((expiresIn % 3600) / 60)}m`;
  }

  function formatTime(iso: string | undefined): string {
    if (!iso) return '--';
    try {
      return new Date(iso).toLocaleTimeString(undefined, {
        hour: '2-digit', minute: '2-digit',
      });
    } catch {
      return iso;
    }
  }
</script>

<!-- svelte-ignore a11y-no-static-element-interactions -->
<div class="card-root" on:click|self={closeMenu} on:keydown>
<Card variant="outlined">
  <div class="provider-card">
    <div class="card-header">
      <div class="card-title-row">
        <h3 class="text-title-medium card-name">{provider.name}</h3>
        <span class="type-badge text-label-small">{provider.type.toUpperCase()}</span>
        {#if token?.has_dpop}
          <span class="dpop-badge text-label-small">DPoP</span>
        {/if}
      </div>
      <div class="header-actions">
        <StatusBadge status={tokenStatus} />
        <div class="menu-wrapper">
          <button class="menu-trigger" on:click|stopPropagation={toggleMenu} title="Actions">
            <Icon path={mdiDotsVertical} size={20} />
          </button>
          {#if menuOpen}
            <div class="menu-dropdown">
              {#if hasToken}
                <button class="menu-item" on:click={() => menuAction(() => onRefresh(provider.name))}>
                  <Icon path={mdiRefresh} size={16} />
                  <span>Refresh</span>
                </button>
                <button class="menu-item" on:click={() => menuAction(() => onViewToken(provider.name))}>
                  <Icon path={mdiCodeBraces} size={16} />
                  <span>View Token</span>
                </button>
                {#if provider.exec}
                  <button class="menu-item" on:click={() => menuAction(() => onRunExec(provider))}>
                    <Icon path={mdiCogPlay} size={16} />
                    <span>Run Exec</span>
                  </button>
                {/if}
                {#if provider.auto_refresh > 0}
                  {#if isAutoRefreshing}
                    <button class="menu-item" on:click={() => menuAction(() => onStopAutoRefresh(provider.name))}>
                      <Icon path={mdiStop} size={16} />
                      <span>Stop Auto</span>
                    </button>
                  {:else}
                    <button class="menu-item" on:click={() => menuAction(() => onStartAutoRefresh(provider.name))}>
                      <Icon path={mdiClockOutline} size={16} />
                      <span>Auto Refresh</span>
                    </button>
                  {/if}
                {/if}
                <div class="menu-divider"></div>
                <button class="menu-item menu-item-danger" on:click={() => menuAction(() => onLogout(provider.name))}>
                  <Icon path={mdiLogout} size={16} />
                  <span>Logout</span>
                </button>
              {:else}
                <button class="menu-item menu-item-primary" on:click={() => menuAction(() => onLogin(provider.name))}>
                  <Icon path={mdiLogin} size={16} />
                  <span>Login</span>
                </button>
              {/if}
              <div class="menu-divider"></div>
              <button class="menu-item" on:click={() => menuAction(() => onEdit(provider))}>
                <Icon path={mdiPencil} size={16} />
                <span>Edit</span>
              </button>
              <button class="menu-item menu-item-danger" on:click={() => menuAction(() => onDelete(provider.name))}>
                <Icon path={mdiDelete} size={16} />
                <span>Delete</span>
              </button>
            </div>
          {/if}
        </div>
      </div>
    </div>

    <div class="card-details">
      <div class="detail-row">
        <span class="text-label-small detail-label">Issuer</span>
        <span class="text-body-small detail-value">{provider.issuer}</span>
      </div>

      {#if provider.scopes.length > 0}
        <div class="detail-row">
          <span class="text-label-small detail-label">Scopes</span>
          <div class="scope-tags">
            {#each provider.scopes as scope}
              <span class="scope-tag text-label-small">{scope}</span>
            {/each}
          </div>
        </div>
      {/if}

      {#if token}
        <div class="token-info">
          {#if token.subject}
            <div class="detail-row">
              <span class="text-label-small detail-label">Subject</span>
              <span class="text-body-small detail-value">{token.subject}</span>
            </div>
          {/if}
          {#if token.email}
            <div class="detail-row">
              <span class="text-label-small detail-label">Email</span>
              <span class="text-body-small detail-value">{token.email}</span>
            </div>
          {/if}
          <div class="detail-row">
            <span class="text-label-small detail-label">Expires</span>
            <span class="text-body-small detail-value" class:expired={token.is_expired}>
              {formatExpiry(token.expires_in)}
            </span>
          </div>
        </div>
      {/if}

      {#if isAutoRefreshing && refreshStatus}
        <div class="refresh-info">
          <Icon path={mdiTimer} size={14} />
          <span class="text-body-small">
            Refreshing ({refreshStatus.refresh_count}x)
            {#if refreshStatus.next_refresh}
              &middot; Next: {formatTime(refreshStatus.next_refresh)}
            {/if}
          </span>
        </div>
      {/if}
    </div>

    <!-- Inline primary action -->
    <div class="card-primary-action">
      {#if hasToken}
        <Button variant="outline" size="sm" icon={mdiRefresh} loading={refreshLoading} on:click={() => onRefresh(provider.name)}>Refresh</Button>
        <Button variant="outline" size="sm" icon={mdiCodeBraces} on:click={() => onViewToken(provider.name)}>Token</Button>
      {:else}
        <Button variant="primary" size="sm" icon={mdiLogin} loading={loginLoading} on:click={() => onLogin(provider.name)}>Login</Button>
      {/if}
    </div>
  </div>
</Card>
</div>

{#if menuOpen}
  <!-- svelte-ignore a11y-no-static-element-interactions -->
  <div class="menu-backdrop" on:click={closeMenu} on:keydown></div>
{/if}

<style>
  .card-root {
    position: relative;
  }

  .provider-card {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .card-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    gap: 12px;
  }

  .card-title-row {
    display: flex;
    align-items: center;
    gap: 8px;
    min-width: 0;
    flex: 1;
  }

  .card-name {
    margin: 0;
    color: var(--color-on-surface);
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
  }

  .type-badge {
    padding: 2px 8px;
    border-radius: var(--radius-full);
    background-color: var(--color-secondary-container);
    color: var(--color-on-secondary-container);
    font-weight: 600;
    flex-shrink: 0;
  }

  .dpop-badge {
    padding: 2px 8px;
    border-radius: var(--radius-full);
    background-color: var(--color-security-verified-container, var(--color-tertiary-container));
    color: var(--color-on-security-verified-container, var(--color-on-tertiary-container));
    font-weight: 600;
    flex-shrink: 0;
  }

  .header-actions {
    display: flex;
    align-items: center;
    gap: 8px;
    flex-shrink: 0;
  }

  /* Context menu */
  .menu-wrapper {
    position: relative;
  }

  .menu-trigger {
    width: 32px;
    height: 32px;
    display: flex;
    align-items: center;
    justify-content: center;
    border: none;
    border-radius: var(--radius-full);
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    transition: background-color var(--transition-fast);
  }

  .menu-trigger:hover {
    background-color: var(--color-surface-container);
  }

  .menu-dropdown {
    position: absolute;
    top: 100%;
    right: 0;
    z-index: 50;
    min-width: 180px;
    margin-top: 4px;
    padding: 4px 0;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-md);
    background-color: var(--color-surface-container-lowest);
    box-shadow: var(--shadow-md, 0 4px 12px rgba(0,0,0,0.15));
  }

  .menu-item {
    display: flex;
    align-items: center;
    gap: 10px;
    width: 100%;
    padding: 8px 14px;
    border: none;
    background: transparent;
    color: var(--color-on-surface);
    font-size: 13px;
    font-family: var(--font-sans);
    cursor: pointer;
    text-align: left;
    transition: background-color var(--transition-fast);
  }

  .menu-item:hover {
    background-color: var(--color-surface-container);
  }

  .menu-item-primary {
    color: var(--color-primary);
    font-weight: 600;
  }

  .menu-item-danger {
    color: var(--color-error);
  }

  .menu-item-danger:hover {
    background-color: var(--color-error-container);
  }

  .menu-divider {
    height: 1px;
    margin: 4px 0;
    background-color: var(--color-outline-variant);
  }

  .menu-backdrop {
    position: fixed;
    inset: 0;
    z-index: 40;
  }

  /* Card content */
  .card-details {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .detail-row {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .detail-label {
    color: var(--color-on-surface-variant);
    text-transform: uppercase;
    letter-spacing: 0.5px;
  }

  .detail-value {
    color: var(--color-on-surface);
    word-break: break-all;
  }

  .expired {
    color: var(--color-error);
    font-weight: 500;
  }

  .scope-tags {
    display: flex;
    flex-wrap: wrap;
    gap: 4px;
  }

  .scope-tag {
    padding: 2px 8px;
    background-color: var(--color-primary-95);
    color: var(--color-primary);
    border-radius: var(--radius-full);
    font-weight: 500;
  }

  :global([data-theme="dark"]) .scope-tag {
    background-color: var(--color-primary-container);
    color: var(--color-on-primary-container);
  }

  .token-info {
    padding: 8px 12px;
    background-color: var(--color-surface-container);
    border-radius: var(--radius-md);
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .refresh-info {
    display: flex;
    align-items: center;
    gap: 6px;
    padding: 6px 12px;
    background-color: var(--color-security-verified-container);
    color: var(--color-on-security-verified-container);
    border-radius: var(--radius-sm);
  }

  .card-primary-action {
    display: flex;
    align-items: center;
    gap: 8px;
    padding-top: 8px;
    border-top: 1px solid var(--color-outline-variant);
  }
</style>
