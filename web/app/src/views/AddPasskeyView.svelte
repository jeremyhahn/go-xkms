<script lang="ts">
  import PageHeader from "$components/PageHeader.svelte";
  import Alert from "$components/Alert.svelte";
  import { getSDKClient } from "$stores/sdkClient.ts";
  import { showToast } from "$stores/toast.svelte.ts";
  import { parseCreationOptions, encodeAttestationResponse } from "@go-xkms/sdk";

  // Checked once at mount: a browser without the Credential Management API
  // cannot run the ceremony at all.
  const supported =
    typeof navigator !== "undefined" &&
    navigator.credentials != null &&
    typeof navigator.credentials.create === "function";

  let busy = $state(false);
  let error = $state<string | null>(null);
  let added = $state(false);

  async function addPasskey(): Promise<void> {
    busy = true;
    error = null;
    added = false;
    try {
      const auth = getSDKClient().auth;
      const { options, sessionId } = await auth.webAuthnAddCredentialBegin();
      const cred = await navigator.credentials.create({ publicKey: parseCreationOptions(options) });
      if (!cred) {
        throw new Error("The browser returned no credential.");
      }
      // The response carries a fresh token; the current session stays as it
      // is, so the token is neither stored nor shown.
      await auth.webAuthnRegisterFinish(sessionId, encodeAttestationResponse(cred as PublicKeyCredential));
      added = true;
      showToast("success", "Passkey added.");
    } catch (e) {
      if (e instanceof DOMException && e.name === "NotAllowedError") {
        error = "Passkey creation was cancelled.";
      } else {
        error = e instanceof Error ? e.message : String(e);
      }
    } finally {
      busy = false;
    }
  }
</script>

<PageHeader title="Add Passkey" subtitle="Register another passkey for your account" />

<p class="mb-4 text-base-content/80">
  A second passkey, on another device or a security key, lets you sign in if your first one is lost.
</p>

{#if !supported}
  <Alert kind="info" class="mb-4"><span>This browser does not support passkeys.</span></Alert>
{/if}

{#if error}
  <Alert kind="error" class="mb-4"><span>{error}</span></Alert>
{/if}

{#if added}
  <p class="mb-4 text-success">Passkey added. You can now sign in with it.</p>
{/if}

<button class="btn btn-primary" onclick={addPasskey} disabled={!supported || busy}>
  {#if busy}<span class="loading loading-spinner loading-sm"></span>{/if}
  Add passkey
</button>
