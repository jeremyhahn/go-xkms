<script lang="ts">
  import Icon from './Icon.svelte';
  import XKeyBrandIcon from './XKeyBrandIcon.svelte';
  import {
    mdiViewDashboard,
    mdiLanConnect,
    mdiShieldCheckOutline,
    mdiNumeric,
    mdiCreditCardOutline,
    mdiLockOutline,
    mdiCog,
    mdiClipboardTextOutline,
    mdiWrenchOutline,
    mdiChevronLeft,
    mdiChevronRight,
    mdiThemeLightDark,
  } from '$lib/utils/icons';
  import { appState, navigateTo, toggleSidebar, currentView, sidebarCollapsed, isAdmin, tpmAvailable } from '$lib/stores/app';
  import { toggleTheme, theme } from '$lib/stores/theme';
  import { keyCount } from '$lib/stores/keys';
  import { oathCount } from '$lib/stores/oath';
  import { fido2CredentialCount } from '$lib/stores/fido2';
  import { deviceCount } from '$lib/stores/pairing';

  interface NavItem {
    id: string;
    label: string;
    icon: string;
    badge?: number;
    dividerAfter?: boolean;
    adminOnly?: boolean;
  }

  $: navItems = ([
    { id: 'dashboard', label: 'Dashboard', icon: mdiViewDashboard },
    { id: 'pairing', label: 'Pairing', icon: mdiLanConnect, badge: $deviceCount },
    { id: 'fido2', label: 'FIDO2', icon: mdiShieldCheckOutline, badge: $fido2CredentialCount },
    { id: 'oath', label: 'OATH', icon: mdiNumeric, badge: $oathCount },
    { id: 'piv', label: 'PIV', icon: mdiCreditCardOutline },
    ...($tpmAvailable ? [{ id: 'tpm', label: 'TPM', icon: mdiLockOutline, dividerAfter: true }] : []),
    { id: 'settings', label: 'Settings', icon: mdiCog },
    { id: 'audit', label: 'Audit Log', icon: mdiClipboardTextOutline },
    { id: 'admin', label: 'Admin', icon: mdiWrenchOutline, adminOnly: true },
  ] as NavItem[]);

  function handleNavClick(id: string): void {
    navigateTo(id);
  }

  function handleNavKeydown(event: KeyboardEvent, id: string): void {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      navigateTo(id);
    }
  }
</script>

<aside class="sidebar" class:sidebar-collapsed={$sidebarCollapsed}>
  <!-- Brand header -->
  <div class="sidebar-brand">
    <div class="brand-logo">
      <XKeyBrandIcon size={28} />
    </div>
    {#if !$sidebarCollapsed}
      <div class="brand-text">
        <span class="brand-name">xKey</span>
        <span class="brand-subtitle">Security Key</span>
      </div>
    {/if}
  </div>

  <!-- Navigation -->
  <nav class="sidebar-nav" aria-label="Main navigation">
    {#each navItems as item (item.id)}
      {#if !item.adminOnly || $isAdmin}
        <div
          class="nav-item"
          class:nav-item-active={$currentView === item.id}
          on:click={() => handleNavClick(item.id)}
          on:keydown={(e) => handleNavKeydown(e, item.id)}
          role="button"
          tabindex="0"
          aria-current={$currentView === item.id ? 'page' : undefined}
          title={$sidebarCollapsed ? item.label : undefined}
        >
          <span class="nav-active-indicator" />
          <span class="nav-icon">
            <Icon path={item.icon} size={22} />
          </span>
          {#if !$sidebarCollapsed}
            <span class="nav-label">{item.label}</span>
            {#if item.badge !== undefined && item.badge > 0}
              <span class="nav-badge">{item.badge}</span>
            {/if}
          {/if}
        </div>
        {#if item.dividerAfter}
          <div class="nav-divider" />
        {/if}
      {/if}
    {/each}
  </nav>

  <!-- Footer -->
  <div class="sidebar-footer">
    <button class="sidebar-action" on:click={toggleTheme} aria-label="Toggle theme" title="Toggle theme">
      <Icon path={mdiThemeLightDark} size={20} />
      {#if !$sidebarCollapsed}
        <span class="action-label">{$theme === 'system' ? 'System' : $theme === 'dark' ? 'Dark' : 'Light'}</span>
      {/if}
    </button>

    <button class="sidebar-action sidebar-collapse-btn" on:click={toggleSidebar} aria-label={$sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}>
      <Icon path={$sidebarCollapsed ? mdiChevronRight : mdiChevronLeft} size={20} />
      {#if !$sidebarCollapsed}
        <span class="action-label">Collapse</span>
      {/if}
    </button>

    {#if !$sidebarCollapsed}
      <div class="sidebar-version">v{$appState.version}</div>
    {/if}
  </div>
</aside>

<style>
  .sidebar {
    width: 240px;
    height: 100%;
    display: flex;
    flex-direction: column;
    background-color: var(--color-surface-container-low);
    border-right: 1px solid var(--color-outline-variant);
    transition: width var(--transition-normal);
    overflow: hidden;
    flex-shrink: 0;
  }

  .sidebar-collapsed {
    width: 64px;
  }

  /* Brand */
  .sidebar-brand {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-4) var(--space-4);
    background: var(--gradient-primary);
    min-height: 64px;
  }

  .brand-logo {
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  .brand-text {
    display: flex;
    flex-direction: column;
    min-width: 0;
    overflow: hidden;
  }

  .brand-name {
    font-size: 18px;
    font-weight: 600;
    color: #FFFFFF;
    line-height: 1.2;
    letter-spacing: 0.5px;
  }

  .brand-subtitle {
    font-size: 11px;
    color: rgba(255, 255, 255, 0.75);
    line-height: 1.2;
    white-space: nowrap;
  }

  /* Navigation */
  .sidebar-nav {
    flex: 1;
    overflow-y: auto;
    overflow-x: hidden;
    padding: var(--space-2) var(--space-2);
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .nav-item {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-2) var(--space-3);
    border-radius: var(--radius-md);
    cursor: pointer;
    position: relative;
    color: var(--color-on-surface-variant);
    transition: background-color var(--transition-fast),
                color var(--transition-fast);
    white-space: nowrap;
    min-height: 44px;
  }

  .nav-item:hover {
    background-color: var(--color-surface-container-high);
    color: var(--color-on-surface);
  }

  .nav-item-active {
    background-color: var(--color-primary-container);
    color: var(--color-on-primary-container);
  }

  :global([data-theme="dark"]) .nav-item-active {
    background-color: var(--color-surface-container-highest);
    color: var(--color-primary);
  }

  .nav-active-indicator {
    position: absolute;
    left: 0;
    top: 50%;
    transform: translateY(-50%);
    width: 3px;
    height: 0;
    background-color: var(--color-secondary);
    border-radius: 0 var(--radius-full) var(--radius-full) 0;
    transition: height var(--transition-spring);
  }

  .nav-item-active .nav-active-indicator {
    height: 24px;
  }

  .nav-icon {
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    width: 24px;
    height: 24px;
  }

  .nav-label {
    font-size: 14px;
    font-weight: 500;
    letter-spacing: 0.1px;
    overflow: hidden;
    text-overflow: ellipsis;
    flex: 1;
  }

  .nav-badge {
    font-size: 11px;
    font-weight: 600;
    background-color: var(--color-secondary);
    color: var(--color-on-secondary);
    padding: 1px 6px;
    border-radius: var(--radius-full);
    min-width: 20px;
    text-align: center;
    line-height: 16px;
  }

  .nav-divider {
    height: 1px;
    margin: var(--space-2) var(--space-3);
    background-color: var(--color-outline-variant);
  }

  /* Footer */
  .sidebar-footer {
    border-top: 1px solid var(--color-outline-variant);
    padding: var(--space-2);
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .sidebar-action {
    display: flex;
    align-items: center;
    gap: var(--space-3);
    padding: var(--space-2) var(--space-3);
    border-radius: var(--radius-sm);
    border: none;
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    font-family: var(--font-sans);
    font-size: 13px;
    white-space: nowrap;
    transition: background-color var(--transition-fast);
    min-height: 36px;
  }

  .sidebar-action:hover {
    background-color: var(--color-surface-container-high);
  }

  .action-label {
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .sidebar-version {
    font-size: 11px;
    color: var(--color-on-surface-variant);
    opacity: 0.6;
    padding: 4px var(--space-3);
    text-align: center;
  }
</style>
