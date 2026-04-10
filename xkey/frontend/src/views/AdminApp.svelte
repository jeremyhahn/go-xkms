<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import Icon from '$lib/components/Icon.svelte';
  import XKeyBrandIcon from '$lib/components/XKeyBrandIcon.svelte';
  import Toast from '$lib/components/Toast.svelte';
  import { initTheme, theme, toggleTheme } from '$lib/stores/theme';
  import {
    mdiViewDashboard, mdiChip, mdiShieldLockOutline, mdiLockOutline,
    mdiClipboardTextOutline, mdiCog, mdiMenu, mdiChevronLeft,
    mdiWeatherSunny, mdiWeatherNight, mdiThemeLightDark,
    mdiAccountSwitch, mdiLogout, mdiDeleteSweep
  } from '$lib/utils/icons';

  import AdminDashboard from './AdminDashboard.svelte';
  import PolicyEditor from './PolicyEditor.svelte';
  import UserPINManagement from './UserPINManagement.svelte';
  import AuditLog from './AuditLog.svelte';
  import Settings from './Settings.svelte';
  import TPM from './TPM.svelte';
  import FactoryReset from './FactoryReset.svelte';

  const dispatch = createEventDispatcher<{ switchToUser: void; logout: void }>();

  interface NavItem {
    id: string;
    label: string;
    icon: string;
    section: string;
  }

  const navItems: NavItem[] = [
    { id: 'dashboard', label: 'Dashboard', icon: mdiViewDashboard, section: 'overview' },
    { id: 'device-status', label: 'Device Status', icon: mdiChip, section: 'overview' },
    { id: 'policy', label: 'Policy', icon: mdiShieldLockOutline, section: 'security' },
    { id: 'pin-management', label: 'PIN Management', icon: mdiLockOutline, section: 'security' },
    { id: 'audit-log', label: 'Audit Log', icon: mdiClipboardTextOutline, section: 'system' },
    { id: 'factory-reset', label: 'Factory Reset', icon: mdiDeleteSweep, section: 'system' },
    { id: 'settings', label: 'Settings', icon: mdiCog, section: 'system' },
  ];

  const themeIcons: Record<string, string> = {
    light: mdiWeatherSunny,
    dark: mdiWeatherNight,
    system: mdiThemeLightDark,
  };

  let currentView = 'dashboard';
  let sidebarCollapsed = false;

  $: themeIcon = themeIcons[$theme] || mdiThemeLightDark;

  function navigateTo(viewId: string): void {
    currentView = viewId;
  }

  function isNavActive(navId: string): boolean {
    return navId === currentView;
  }

  function handleToggleSidebar(): void {
    sidebarCollapsed = !sidebarCollapsed;
  }
</script>

<div class="app-shell" class:sidebar-collapsed={sidebarCollapsed}>
  <nav class="sidebar" aria-label="Admin navigation">
    <div class="sidebar-header">
      {#if !sidebarCollapsed}
        <div class="brand">
          <div class="brand-icon admin-brand">
            <XKeyBrandIcon size={28} />
          </div>
          <div class="brand-info">
            <span class="brand-text text-title-large">xKey</span>
            <span class="brand-badge text-label-small">SO ADMIN</span>
          </div>
        </div>
      {/if}
      <button
        class="sidebar-toggle"
        on:click={handleToggleSidebar}
        aria-label={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
      >
        <Icon path={sidebarCollapsed ? mdiMenu : mdiChevronLeft} size={20} />
      </button>
    </div>

    <div class="nav-sections">
      <div class="nav-section">
        {#if !sidebarCollapsed}
          <span class="nav-section-label text-label-small">OVERVIEW</span>
        {/if}
        {#each navItems.filter(n => n.section === 'overview') as item}
          <button
            class="nav-item"
            class:nav-active={isNavActive(item.id)}
            on:click={() => navigateTo(item.id)}
            title={sidebarCollapsed ? item.label : ''}
          >
            <Icon path={item.icon} size={20} />
            {#if !sidebarCollapsed}
              <span class="nav-label text-label-large">{item.label}</span>
            {/if}
          </button>
        {/each}
      </div>

      <div class="nav-section">
        {#if !sidebarCollapsed}
          <span class="nav-section-label text-label-small">SECURITY</span>
        {/if}
        {#each navItems.filter(n => n.section === 'security') as item}
          <button
            class="nav-item"
            class:nav-active={isNavActive(item.id)}
            on:click={() => navigateTo(item.id)}
            title={sidebarCollapsed ? item.label : ''}
          >
            <Icon path={item.icon} size={20} />
            {#if !sidebarCollapsed}
              <span class="nav-label text-label-large">{item.label}</span>
            {/if}
          </button>
        {/each}
      </div>

      <div class="nav-section">
        {#if !sidebarCollapsed}
          <span class="nav-section-label text-label-small">SYSTEM</span>
        {/if}
        {#each navItems.filter(n => n.section === 'system') as item}
          <button
            class="nav-item"
            class:nav-active={isNavActive(item.id)}
            on:click={() => navigateTo(item.id)}
            title={sidebarCollapsed ? item.label : ''}
          >
            <Icon path={item.icon} size={20} />
            {#if !sidebarCollapsed}
              <span class="nav-label text-label-large">{item.label}</span>
            {/if}
          </button>
        {/each}
      </div>
    </div>

    <div class="sidebar-footer">
      <button class="nav-item" on:click={toggleTheme} title="Toggle theme">
        <Icon path={themeIcon} size={20} />
        {#if !sidebarCollapsed}
          <span class="nav-label text-label-large">Theme</span>
        {/if}
      </button>
      <button
        class="nav-item"
        on:click={() => dispatch('switchToUser')}
        title={sidebarCollapsed ? 'Switch to User Mode' : ''}
      >
        <Icon path={mdiAccountSwitch} size={20} />
        {#if !sidebarCollapsed}
          <span class="nav-label text-label-large">User Mode</span>
        {/if}
      </button>
      <button
        class="nav-item logout-btn"
        on:click={() => dispatch('logout')}
        title={sidebarCollapsed ? 'Logout' : ''}
      >
        <Icon path={mdiLogout} size={20} />
        {#if !sidebarCollapsed}
          <span class="nav-label text-label-large">Logout</span>
        {/if}
      </button>
    </div>
  </nav>

  <main class="main-content">
    <div class="app-header">
      <div class="admin-indicator">
        <span class="admin-indicator-dot"></span>
        <span class="text-label-small admin-indicator-text">Security Officer Mode</span>
      </div>
      <div class="header-spacer"></div>
    </div>
    <div class="view-container">
      {#if currentView === 'dashboard'}
        <AdminDashboard />
      {:else if currentView === 'device-status'}
        <TPM />
      {:else if currentView === 'policy'}
        <PolicyEditor />
      {:else if currentView === 'pin-management'}
        <UserPINManagement />
      {:else if currentView === 'audit-log'}
        <AuditLog />
      {:else if currentView === 'factory-reset'}
        <FactoryReset />
      {:else if currentView === 'settings'}
        <Settings />
      {/if}
    </div>
  </main>
</div>

<Toast />

<style>
  .app-shell {
    display: flex;
    width: 100vw;
    height: 100vh;
    overflow: hidden;
  }

  /* Sidebar */
  .sidebar {
    width: 240px;
    min-width: 240px;
    height: 100vh;
    display: flex;
    flex-direction: column;
    background-color: var(--color-surface-container-lowest);
    border-right: 1px solid var(--color-outline-variant);
    transition: width var(--transition-normal), min-width var(--transition-normal);
    overflow: hidden;
  }

  .sidebar-collapsed .sidebar {
    width: 64px;
    min-width: 64px;
  }

  .sidebar-header {
    display: flex;
    align-items: center;
    justify-content: space-between;
    padding: 16px;
    height: 64px;
    flex-shrink: 0;
  }

  .sidebar-collapsed .sidebar-header {
    justify-content: center;
    padding: 16px 12px;
  }

  .brand {
    display: flex;
    align-items: center;
    gap: 12px;
  }

  .brand-icon {
    width: 36px;
    height: 36px;
    border-radius: var(--radius-md);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  .admin-brand {
    background: none;
  }

  .brand-info {
    display: flex;
    flex-direction: column;
    gap: 0;
  }

  .brand-text {
    color: var(--color-on-surface);
    font-weight: 700;
    white-space: nowrap;
    line-height: 1.2;
  }

  .brand-badge {
    color: var(--color-error);
    font-weight: 700;
    letter-spacing: 1.2px;
    white-space: nowrap;
  }

  .sidebar-toggle {
    width: 36px;
    height: 36px;
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
  }

  .sidebar-toggle:hover {
    background-color: var(--color-surface-variant);
  }

  /* Navigation */
  .nav-sections {
    flex: 1;
    overflow-y: auto;
    padding: 8px;
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .nav-section {
    display: flex;
    flex-direction: column;
    gap: 2px;
    padding-bottom: 8px;
  }

  .nav-section + .nav-section {
    padding-top: 8px;
    border-top: 1px solid var(--color-outline-variant);
  }

  .nav-section-label {
    color: var(--color-on-surface-variant);
    opacity: 0.6;
    padding: 8px 12px 4px;
    text-transform: uppercase;
    letter-spacing: 1px;
    white-space: nowrap;
  }

  .nav-item {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 12px;
    border: none;
    border-radius: var(--radius-full);
    background: transparent;
    color: var(--color-on-surface-variant);
    cursor: pointer;
    transition: background-color var(--transition-fast),
                color var(--transition-fast);
    font-family: var(--font-sans);
    white-space: nowrap;
    text-align: left;
    width: 100%;
  }

  .sidebar-collapsed .nav-item {
    justify-content: center;
    padding: 10px;
  }

  .nav-item:hover {
    background-color: var(--color-surface-container);
    color: var(--color-on-surface);
  }

  .nav-active {
    background-color: var(--color-primary-95);
    color: var(--color-primary);
    font-weight: 600;
  }

  :global([data-theme="dark"]) .nav-active {
    background-color: var(--color-primary-container);
    color: var(--color-on-primary-container);
  }

  .nav-label {
    white-space: nowrap;
    overflow: hidden;
    text-overflow: ellipsis;
  }

  .sidebar-footer {
    padding: 8px;
    border-top: 1px solid var(--color-outline-variant);
    display: flex;
    flex-direction: column;
    gap: 2px;
    flex-shrink: 0;
  }

  .logout-btn:hover {
    color: var(--color-error);
  }

  /* Main Content */
  .main-content {
    flex: 1;
    overflow: hidden;
    background-color: var(--color-background);
    display: flex;
    flex-direction: column;
  }

  .app-header {
    display: flex;
    align-items: center;
    justify-content: flex-end;
    padding: 8px 16px;
    height: 48px;
    flex-shrink: 0;
    border-bottom: 1px solid var(--color-outline-variant);
  }

  .header-spacer {
    flex: 1;
  }

  .admin-indicator {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 4px 12px;
    border-radius: var(--radius-full);
    background-color: var(--color-security-danger-container);
  }

  .admin-indicator-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background-color: var(--color-error);
    animation: admin-pulse 2s ease-in-out infinite;
  }

  .admin-indicator-text {
    color: var(--color-on-security-danger-container);
    font-weight: 600;
    letter-spacing: 0.3px;
  }

  @keyframes admin-pulse {
    0%, 100% { opacity: 1; }
    50% { opacity: 0.5; }
  }

  .view-container {
    width: 100%;
    flex: 1;
    overflow-y: auto;
    animation: fade-in 200ms ease;
  }

  @keyframes fade-in {
    from { opacity: 0; }
    to { opacity: 1; }
  }
</style>
