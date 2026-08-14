<script lang="ts">
  import { LoginPanel } from "@go-xkms/svelte-auth";
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
    // LoginPanel already persisted the tokens. Refresh the full session from
    // /auth/me (permission + capability maps) before entering the app.
    await loadSession();
    navigateTo("/dashboard");
  }
</script>

<div class="min-h-screen flex items-center justify-center bg-base-200 p-4">
  <div class="w-full max-w-md space-y-4">
    <LoginPanel
      {client}
      {provider}
      title="xKMS Console"
      subtitle="Hardware-backed, passwordless sign-in"
      {onSuccess}
    />
    <div class="text-center">
      <button class="btn btn-ghost btn-sm" onclick={() => navigateTo("/register")}>
        No passkey yet? Enroll one
      </button>
    </div>
  </div>
</div>
