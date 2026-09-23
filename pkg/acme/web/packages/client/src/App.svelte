<script lang="ts">
  import { onMount } from 'svelte';
  import { initTransport } from '@trustedca/shared/api/transport';
  import { initTheme } from '@trustedca/shared/stores/theme';
  import Sidebar from '@trustedca/shared/components/Sidebar.svelte';
  import Toast from '@trustedca/shared/components/Toast.svelte';

  import Dashboard from './views/Dashboard.svelte';
  import Accounts from './views/Accounts.svelte';
  import Certificates from './views/Certificates.svelte';
  import Register from './views/Register.svelte';
  import RequestCert from './views/RequestCert.svelte';
  import RenewCert from './views/RenewCert.svelte';
  import RevokeCert from './views/RevokeCert.svelte';
  import DeviceEnroll from './views/DeviceEnroll.svelte';
  import DeviceAttest from './views/DeviceAttest.svelte';
  import ChallengeConfig from './views/ChallengeConfig.svelte';
  import Settings from './views/Settings.svelte';

  let activeView = 'dashboard';

  const navItems = [
    { label: 'Dashboard', icon: 'dashboard', view: 'dashboard' },
    { label: 'Accounts', icon: 'accounts', view: 'accounts' },
    { label: 'Certificates', icon: 'certificates', view: 'certificates' },
    { label: 'Register', icon: 'register', view: 'register' },
    { label: 'Request Cert', icon: 'request', view: 'request-cert' },
    { label: 'Renew Cert', icon: 'renew', view: 'renew-cert' },
    { label: 'Revoke Cert', icon: 'revoke', view: 'revoke-cert' },
    { label: 'Device Enroll', icon: 'device', view: 'device-enroll' },
    { label: 'Device Attest', icon: 'device', view: 'device-attest' },
    { label: 'Challenges', icon: 'challenge', view: 'challenges' },
    { label: 'Settings', icon: 'settings', view: 'settings' },
  ];

  function handleNavigate(event: CustomEvent<string>) {
    activeView = event.detail;
  }

  onMount(async () => {
    initTheme();
    await initTransport();
  });
</script>

<div class="flex h-screen overflow-hidden bg-white dark:bg-slate-900">
  <Sidebar
    items={navItems}
    {activeView}
    title="ACME Client"
    on:navigate={handleNavigate}
  />

  <main class="flex-1 overflow-y-auto">
    {#if activeView === 'dashboard'}
      <Dashboard />
    {:else if activeView === 'accounts'}
      <Accounts />
    {:else if activeView === 'certificates'}
      <Certificates />
    {:else if activeView === 'register'}
      <Register />
    {:else if activeView === 'request-cert'}
      <RequestCert />
    {:else if activeView === 'renew-cert'}
      <RenewCert />
    {:else if activeView === 'revoke-cert'}
      <RevokeCert />
    {:else if activeView === 'device-enroll'}
      <DeviceEnroll />
    {:else if activeView === 'device-attest'}
      <DeviceAttest />
    {:else if activeView === 'challenges'}
      <ChallengeConfig />
    {:else if activeView === 'settings'}
      <Settings />
    {/if}
  </main>

  <Toast />
</div>
