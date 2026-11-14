<script lang="ts">
  import { authStore } from "@go-xkms/svelte-auth";
  import { routerStore, navigateTo } from "$stores/router.svelte.ts";
  import { sessionStore, loadSession } from "$stores/session.svelte.ts";
  import AppShell from "$components/AppShell.svelte";
  import FrostSigningView from "$views/FrostSigningView.svelte";
  import ToastContainer from "$components/ToastContainer.svelte";
  import PlaceholderView from "$components/PlaceholderView.svelte";
  import TenantEntitlementsView from "$views/TenantEntitlementsView.svelte";
  import LoginView from "$views/LoginView.svelte";
  import UserCertBindingView from "$views/UserCertBindingView.svelte";
  import RegisterView from "$views/RegisterView.svelte";
  import PlatformSecretNamesView from "$views/PlatformSecretNamesView.svelte";
  import DashboardView from "$views/DashboardView.svelte";
  import TrustBundleView from "$views/TrustBundleView.svelte";
  import BackendsView from "$views/BackendsView.svelte";
  import SshKeyImportView from "$views/SshKeyImportView.svelte";
  import SettingsView from "$views/SettingsView.svelte";
  import FrostKeyImportView from "$views/FrostKeyImportView.svelte";
  import KeysView from "$views/KeysView.svelte";
  import TenantQuotasView from "$views/TenantQuotasView.svelte";
  import KeySafetyView from "$views/KeySafetyView.svelte";
  import OtaImageKeysView from "$views/OtaImageKeysView.svelte";
  import CryptoToolsView from "$views/CryptoToolsView.svelte";
  import CertificatesView from "$views/CertificatesView.svelte";
  import CertImportView from "$views/CertImportView.svelte";
  import PinView from "$views/PinView.svelte";
  import PinSetupView from "$views/PinSetupView.svelte";
  import TpmPoliciesView from "$views/TpmPoliciesView.svelte";
  import SealView from "$views/SealView.svelte";
  import TpmKeyPolicyView from "$views/TpmKeyPolicyView.svelte";
  import UsersView from "$views/UsersView.svelte";
  import AddPasskeyView from "$views/AddPasskeyView.svelte";
  import TenantsView from "$views/TenantsView.svelte";
  import TenantTpmView from "$views/TenantTpmView.svelte";
  import PasswordsView from "$views/PasswordsView.svelte";
  import PasswordAccessModeView from "$views/PasswordAccessModeView.svelte";
  import OidcCredentialsView from "$views/OidcCredentialsView.svelte";
  import PlatformView from "$views/PlatformView.svelte";
  import BootCredentialsView from "$views/BootCredentialsView.svelte";
  import PivView from "$views/PivView.svelte";
  import PivSlotsView from "$views/PivSlotsView.svelte";
  import CaView from "$views/CaView.svelte";
  import TcgCertsView from "$views/TcgCertsView.svelte";
  import SshView from "$views/SshView.svelte";
  import SshTrustView from "$views/SshTrustView.svelte";
  import FrostView from "$views/FrostView.svelte";
  import KeyVersionsView from "$views/KeyVersionsView.svelte";
  import SystemHealthView from "$views/SystemHealthView.svelte";

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
    {:else if routerStore.name === "trustBundle"}<TrustBundleView />
    {:else if routerStore.name === "backends"}
      <BackendsView />
    {:else if routerStore.name === "sshKeyImport"}<SshKeyImportView />
    {:else if routerStore.name === "keys"}
      <KeysView />
    {:else if routerStore.name === "keyVersions"}<KeyVersionsView />
    {:else if routerStore.name === "frostSigning"}<FrostSigningView />
    {:else if routerStore.name === "certificates"}
      <CertificatesView />
    {:else if routerStore.name === "certImport"}<CertImportView />
    {:else if routerStore.name === "ca"}
      <CaView />
    {:else if routerStore.name === "caTcg"}<TcgCertsView />
    {:else if routerStore.name === "pin"}
      <PinView />
    {:else if routerStore.name === "pinSetup"}<PinSetupView />
    {:else if routerStore.name === "piv"}
      <PivView />
    {:else if routerStore.name === "pivSlots"}<PivSlotsView />
    {:else if routerStore.name === "userCertBinding"}<UserCertBindingView />
    {:else if routerStore.name === "ssh"}
      <SshView />
    {:else if routerStore.name === "sshTrust"}<SshTrustView />
    {:else if routerStore.name === "tpmPolicies"}
      <TpmPoliciesView />
    {:else if routerStore.name === "seal"}<SealView />
    {:else if routerStore.name === "tpmKeyPolicy"}<TpmKeyPolicyView />
    {:else if routerStore.name === "users"}
      <UsersView />
    {:else if routerStore.name === "addPasskey"}<AddPasskeyView />
    {:else if routerStore.name === "frost"}
      <FrostView />
    {:else if routerStore.name === "tenantQuotas"}<TenantQuotasView />
    {:else if routerStore.name === "frostKeyImport"}<FrostKeyImportView />
    {:else if routerStore.name === "keySafety"}<KeySafetyView />
    {:else if routerStore.name === "otaImageKeys"}<OtaImageKeysView />
    {:else if routerStore.name === "cryptoTools"}<CryptoToolsView />
    {:else if routerStore.name === "tenants"}
      <TenantsView />
    {:else if routerStore.name === "tenantTpm"}<TenantTpmView />
    {:else if routerStore.name === "passwords"}
      <PasswordsView />
    {:else if routerStore.name === "passwordAccessMode"}<PasswordAccessModeView />
    {:else if routerStore.name === "oidcCredentials"}
      <OidcCredentialsView />
    {:else if routerStore.name === "platform"}
      <PlatformView />
    {:else if routerStore.name === "systemHealth"}<SystemHealthView />
    {:else if routerStore.name === "bootCredentials"}<BootCredentialsView />
    {:else if routerStore.name === "settings"}
      <SettingsView />
    {:else if routerStore.name === "platformSecretNames"}<PlatformSecretNamesView />
    {:else if routerStore.name === "login" || routerStore.name === "register"}
      <!-- Already authenticated; send credential screens to the dashboard. -->
      {(navigateTo("/dashboard"), "")}
    {:else if routerStore.name === "tenantEntitlements"}<TenantEntitlementsView />
    {:else}
      <PlaceholderView title="Not found" />
    {/if}
  </AppShell>
{/if}

<ToastContainer />
