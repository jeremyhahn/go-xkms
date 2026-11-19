<!--
  InviteView redeems an invite link (/#/invite/<tenant>/<token>, built by
  pkg/xkms/servicer_invite.go buildInviteURL) with a passkey.

  Flow:
    1. GET /api/v1/capabilities: with webauthn off show the disabled state
       naming webauthn.enabled and stop (ruling 972 (1)).
    2. GET /api/v1/invites/{tenant}/{token}: 404 is the unusable-link state.
    3. On "Register passkey": invites.beginRegistration ->
       provider.createCredential -> invites.finishRegistration, then a
       passkey sign-in (auth.webAuthnBeginLogin / getAssertion / finish) so
       the user lands signed in. The ceremonies go through the shared
       svelte-auth CredentialProvider; there is no second WebAuthn path.
-->
<script lang="ts">
  import { onMount } from "svelte";
  import { isNetworkFailure, isUserDeclined, setAuthenticated } from "@go-xkms/svelte-auth";
  import type { InviteInfo } from "@go-xkms/sdk";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { getAuthContext } from "$lib/auth.ts";
  import { loadSession } from "$stores/session.svelte.ts";
  import { navigateTo } from "$stores/router.svelte.ts";

  interface Props {
    tenant: string;
    token: string;
  }

  let { tenant, token }: Props = $props();

  type Stage = "loading" | "disabled" | "unusable" | "ready" | "ceremony" | "error";

  const client = getSDKClient();
  const provider = getAuthContext().provider;

  let stage: Stage = $state("loading");
  let invite: InviteInfo | null = $state(null);
  let errorMessage = $state("");

  function statusOf(e: unknown): number | undefined {
    return (e as { status?: number } | null)?.status;
  }

  function describe(e: unknown, fallback: string): string {
    if (isNetworkFailure(e)) return "Can't reach the server right now.";
    if (isUserDeclined(e)) {
      return "Credential creation was declined or cancelled. Try again with your hardware key.";
    }
    return e instanceof Error && e.message ? e.message : fallback;
  }

  onMount(() => {
    void load();
  });

  async function load(): Promise<void> {
    try {
      const caps = await client.capabilities.get();
      if (!caps.webauthn_enabled) {
        stage = "disabled";
        return;
      }
    } catch (e: unknown) {
      errorMessage = describe(e, "Could not read the server capabilities.");
      stage = "error";
      return;
    }
    try {
      invite = await client.invites.get(tenant, token);
      stage = "ready";
    } catch (e: unknown) {
      if (statusOf(e) === 404) {
        stage = "unusable";
        return;
      }
      errorMessage = describe(e, "Could not read the invite.");
      stage = "error";
    }
  }

  async function register(): Promise<void> {
    if (stage === "ceremony") return;
    stage = "ceremony";
    errorMessage = "";
    try {
      const begin = await client.invites.beginRegistration(tenant, token);
      const credential = await provider.createCredential(begin.options);
      await client.invites.finishRegistration(tenant, token, begin.sessionId, credential);
    } catch (e: unknown) {
      if (statusOf(e) === 404) {
        stage = "unusable";
        return;
      }
      errorMessage = describe(e, "Registration failed. Please try again.");
      stage = "ready";
      return;
    }
    try {
      const login = await client.auth.webAuthnBeginLogin(
        invite?.email ? { email: invite.email } : undefined,
      );
      const assertion = await provider.getAssertion(login.options);
      const resp = await client.auth.webAuthnFinishLogin(login.sessionId, assertion);
      setAuthenticated({ access_token: resp.token, refresh_token: resp.refresh_token });
      await loadSession();
      navigateTo("/dashboard");
    } catch {
      // The passkey is registered and the invite is spent; only the
      // follow-on sign-in failed, so send the user to the sign-in screen.
      navigateTo("/login");
    }
  }
</script>

<div class="min-h-screen flex items-center justify-center bg-base-200 p-4">
  <div class="card w-full max-w-md bg-base-100 shadow">
    <div class="card-body space-y-3">
      <h1 class="card-title">Accept your invitation</h1>
      <p class="text-sm">Tenant <span class="font-mono" data-testid="invite-tenant">{tenant}</span></p>

      {#if stage === "loading"}
        <span class="loading loading-spinner" aria-label="Loading"></span>
      {:else if stage === "disabled"}
        <div role="alert" class="alert alert-warning">
          <span>
            Passkey sign-in is turned off on this server, so this invite cannot be
            redeemed here. An administrator must set <code>webauthn.enabled</code>.
          </span>
        </div>
      {:else if stage === "unusable"}
        <div role="alert" class="alert alert-error">
          <span>This invite link is not valid. It may have expired or already been used; ask your admin for a new one.</span>
        </div>
      {:else if stage === "error"}
        <div role="alert" class="alert alert-error"><span>{errorMessage}</span></div>
      {:else}
        {#if invite?.email}
          <p class="text-sm">Invited address <span class="font-mono">{invite.email}</span></p>
        {/if}
        {#if errorMessage}
          <div role="alert" class="alert alert-error"><span>{errorMessage}</span></div>
        {/if}
        <button
          class="btn btn-primary"
          disabled={stage === "ceremony"}
          onclick={() => void register()}
        >
          {#if stage === "ceremony"}<span class="loading loading-spinner loading-sm"></span>{/if}
          Register passkey
        </button>
      {/if}
    </div>
  </div>
</div>
