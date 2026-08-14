<script lang="ts">
  import { authStore } from "@go-xkms/svelte-auth";
  import { routerStore, navigateTo } from "$stores/router.svelte.ts";
  import { sessionStore, loadSession } from "$stores/session.svelte.ts";
  import AppShell from "$components/AppShell.svelte";
  import ToastContainer from "$components/ToastContainer.svelte";
  import PlaceholderView from "$components/PlaceholderView.svelte";
  import LoginView from "$views/LoginView.svelte";
  import RegisterView from "$views/RegisterView.svelte";
  import DashboardView from "$views/DashboardView.svelte";
  import BackendsView from "$views/BackendsView.svelte";
  import ClusterView from "$views/ClusterView.svelte";
  import SettingsView from "$views/SettingsView.svelte";
  import KeysView from "$views/KeysView.svelte";
  import CertificatesView from "$views/CertificatesView.svelte";
  import BarrierView from "$views/BarrierView.svelte";
  import PinView from "$views/PinView.svelte";
  import PoliciesView from "$views/PoliciesView.svelte";
  import UsersView from "$views/UsersView.svelte";
  import TenantsView from "$views/TenantsView.svelte";
  import PasswordsView from "$views/PasswordsView.svelte";
  import PlatformView from "$views/PlatformView.svelte";
  import PivView from "$views/PivView.svelte";
  import CaView from "$views/CaView.svelte";
  import CustodiansView from "$views/CustodiansView.svelte";
  import SharesView from "$views/SharesView.svelte";
  import CeremonyView from "$views/CeremonyView.svelte";
  import SshView from "$views/SshView.svelte";
  import FactorsView from "$views/FactorsView.svelte";
  import FrostView from "$views/FrostView.svelte";
  import AuditView from "$views/AuditView.svelte";

  // Once authenticated, ensure the session (permissions + capabilities) is
  // loaded before the shell gates navigation. Runs whenever auth status flips.
  $effect(() => {
    if (authStore.status === "authenticated" && sessionStore.me === null && !sessionStore.loading) {
      void loadSession();
    }
  });

  const authenticated = $derived(authStore.status === "authenticated");
</script>

{#if !authenticated}
  <!-- Signed out: only the two credential-acquisition screens exist. -->
  {#if routerStore.name === "register"}
    <RegisterView />
  {:else}
    <LoginView />
  {/if}
{:else}
  <AppShell>
    {#if routerStore.name === "dashboard"}
      <DashboardView />
    {:else if routerStore.name === "backends"}
      <BackendsView />
    {:else if routerStore.name === "keys"}
      <KeysView />
    {:else if routerStore.name === "certificates"}
      <CertificatesView />
    {:else if routerStore.name === "ca"}
      <CaView />
    {:else if routerStore.name === "barrier"}
      <BarrierView />
    {:else if routerStore.name === "pin"}
      <PinView />
    {:else if routerStore.name === "piv"}
      <PivView />
    {:else if routerStore.name === "ssh"}
      <SshView />
    {:else if routerStore.name === "policies"}
      <PoliciesView />
    {:else if routerStore.name === "users"}
      <UsersView />
    {:else if routerStore.name === "factors"}
      <FactorsView />
    {:else if routerStore.name === "frost"}
      <FrostView />
    {:else if routerStore.name === "audit"}
      <AuditView />
    {:else if routerStore.name === "tenants"}
      <TenantsView />
    {:else if routerStore.name === "custodians"}
      <CustodiansView />
    {:else if routerStore.name === "shares"}
      <SharesView />
    {:else if routerStore.name === "passwords"}
      <PasswordsView />
    {:else if routerStore.name === "platform"}
      <PlatformView />
    {:else if routerStore.name === "ceremony"}
      <CeremonyView />
    {:else if routerStore.name === "cluster"}
      <ClusterView />
    {:else if routerStore.name === "settings"}
      <SettingsView />
    {:else if routerStore.name === "login" || routerStore.name === "register"}
      <!-- Already authenticated; send credential screens to the dashboard. -->
      {(navigateTo("/dashboard"), "")}
    {:else}
      <PlaceholderView title="Not found" />
    {/if}
  </AppShell>
{/if}

<ToastContainer />
