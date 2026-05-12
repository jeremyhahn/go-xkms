<script lang="ts">
  import { onMount } from 'svelte';
  import { initTransport } from '@trustedca/shared/api/transport';
  import { initTheme } from '@trustedca/shared/stores/theme';
  import Sidebar from '@trustedca/shared/components/Sidebar.svelte';
  import Toast from '@trustedca/shared/components/Toast.svelte';
  import { setupApi } from '@trustedca/shared/api/setup';
  import { barrierApi } from '@trustedca/shared/api/barrier';
  import SetupWizard from './components/wizard/setup/SetupWizard.svelte';

  import Dashboard from './views/Dashboard.svelte';
  import Certificates from './views/Certificates.svelte';
  import Accounts from './views/Accounts.svelte';
  import Orders from './views/Orders.svelte';
  import OrderDetail from './views/OrderDetail.svelte';
  import Tenants from './views/Tenants.svelte';
  import TenantDetail from './views/TenantDetail.svelte';
  import ConnectionSettings from './views/ConnectionSettings.svelte';
  import Settings from './views/Settings.svelte';
  import SealManager from './views/SealManager.svelte';
  import CAManager from './views/CAManager.svelte';
  import AuditLog from './views/AuditLog.svelte';

  // ---------------------------------------------------------------------------
  // App-level state
  // ---------------------------------------------------------------------------

  type AppState = 'loading' | 'setup' | 'sealed' | 'app';

  let appState: AppState = $state('loading');

  let activeView = $state('dashboard');
  let selectedTenantId: string | null = $state(null);
  let selectedOrderId: string | null = $state(null);

  const navItems = [
    // Overview
    { label: 'Dashboard',    icon: 'dashboard',   view: 'dashboard' },
    // Security
    { label: 'Seal Manager', icon: 'lock',         view: 'seal' },
    { label: 'Certificates', icon: 'certificate',  view: 'certificates' },
    { label: 'Accounts',     icon: 'accounts',     view: 'accounts' },
    // CA
    { label: 'CA Manager',   icon: 'ca',           view: 'ca-manager' },
    { label: 'Orders',       icon: 'orders',       view: 'orders' },
    // Tenants
    { label: 'Tenants',      icon: 'tenants',      view: 'tenants' },
    // System
    { label: 'Audit Log',    icon: 'audit',        view: 'audit' },
    { label: 'Connection',   icon: 'connection',   view: 'connection' },
    { label: 'Settings',     icon: 'settings',     view: 'settings' },
  ];

  function handleNavigate(event: CustomEvent<string>) {
    activeView = event.detail;
    selectedTenantId = null;
    selectedOrderId = null;
  }

  function handleViewTenant(tenantId: string) {
    selectedTenantId = tenantId;
    activeView = 'tenant-detail';
  }

  function handleViewOrder(event: CustomEvent<string>) {
    selectedOrderId = event.detail;
    activeView = 'order-detail';
  }

  function handleOrderBack() {
    activeView = 'orders';
    selectedOrderId = null;
  }

  function handleSetupComplete(): void {
    appState = 'app';
  }

  // ---------------------------------------------------------------------------
  // Bootstrap: determine which screen to show on load
  // ---------------------------------------------------------------------------

  onMount(async () => {
    initTheme();
    await initTransport();

    try {
      const [setupStatus, barrierStatus] = await Promise.all([
        setupApi.status(),
        barrierApi.status(),
      ]);

      if (setupStatus.status === 'pending' && setupStatus.mode === 'embedded') {
        appState = 'setup';
        return;
      }

      if (barrierStatus.sealed && barrierStatus.mode === 'embedded') {
        appState = 'sealed';
        return;
      }

      appState = 'app';
    } catch (_e) {
      // If the status endpoints are unreachable, fall through to the app
      // shell so the user can configure the connection.
      appState = 'app';
    }
  });
</script>

{#if appState === 'loading'}
  <div class="flex h-screen items-center justify-center">
    <span class="loading loading-spinner loading-lg text-primary"></span>
  </div>
{:else if appState === 'setup'}
  <SetupWizard onComplete={handleSetupComplete} />
{:else if appState === 'sealed'}
  <div class="flex h-screen flex-col overflow-hidden bg-white dark:bg-slate-900">
    <main class="flex-1 overflow-y-auto">
      <SealManager />
    </main>
    <Toast />
  </div>
{:else}
  <div class="flex h-screen overflow-hidden bg-white dark:bg-slate-900">
    <Sidebar
      items={navItems}
      activeView={activeView}
      title="Trusted CA"
      on:navigate={handleNavigate}
    />

    <main class="flex-1 overflow-y-auto">
      {#if activeView === 'dashboard'}
        <Dashboard />
      {:else if activeView === 'certificates'}
        <Certificates />
      {:else if activeView === 'accounts'}
        <Accounts />
      {:else if activeView === 'orders'}
        <Orders on:viewOrder={handleViewOrder} />
      {:else if activeView === 'order-detail' && selectedOrderId}
        <OrderDetail orderId={selectedOrderId} on:back={handleOrderBack} />
      {:else if activeView === 'ca-manager'}
        <CAManager />
      {:else if activeView === 'tenants'}
        <Tenants onviewTenant={handleViewTenant} />
      {:else if activeView === 'tenant-detail' && selectedTenantId}
        <TenantDetail tenantId={selectedTenantId} />
      {:else if activeView === 'seal'}
        <SealManager />
      {:else if activeView === 'audit'}
        <AuditLog />
      {:else if activeView === 'connection'}
        <ConnectionSettings />
      {:else if activeView === 'settings'}
        <Settings />
      {/if}
    </main>

    <Toast />
  </div>
{/if}
