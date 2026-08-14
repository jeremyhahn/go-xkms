<script lang="ts">
  // Passkey enrollment. Without this the console has no way to create the
  // credential its own login page asks for: the WebAuthn registration
  // ceremony is a browser API, so no CLI can stand in for it.
  //
  // The route is deliberately reachable while signed out. xkmsd decides
  // whether an unknown identifier may enroll (webauthn.allow_public_registration,
  // and the adaptive authenticator's first-boot window); the panel surfaces
  // that answer rather than second-guessing it.
  import { RegisterPanel } from "@go-xkms/svelte-auth";
  import type { AuthTokens } from "@go-xkms/svelte-auth";
  import type { AuthMeResponse } from "@go-xkms/sdk";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { getAuthContext } from "$lib/auth.ts";
  import { loadSession } from "$stores/session.svelte.ts";
  import { navigateTo } from "$stores/router.svelte.ts";

  const client = getSDKClient();
  const provider = getAuthContext().provider;

  async function onSuccess(
    _tokens: AuthTokens,
    _me: AuthMeResponse | null,
  ): Promise<void> {
    // RegisterPanel already persisted the tokens; a successful enrollment
    // signs the operator straight in, same as LoginView.
    await loadSession();
    navigateTo("/dashboard");
  }
</script>

<div class="min-h-screen flex items-center justify-center bg-base-200 p-4">
  <div class="w-full max-w-md space-y-4">
    <RegisterPanel
      {client}
      {provider}
      title="Enroll a passkey"
      subtitle="Register a hardware-backed credential for xKMS"
      {onSuccess}
    />
    <div class="text-center">
      <button class="btn btn-ghost btn-sm" onclick={() => navigateTo("/login")}>
        Already enrolled? Sign in
      </button>
    </div>
  </div>
</div>
