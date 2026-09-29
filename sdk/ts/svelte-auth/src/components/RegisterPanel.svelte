<!--
  Copyright (c) 2026 Jeremy Hahn
  Copyright (c) 2026 Automate The Things, LLC

  This file is part of go-xkms.

  go-xkms is dual-licensed:

  1. GNU Affero General Public License v3.0 (AGPL-3.0)
     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html

  2. Commercial License
     Contact licensing@automatethethings.com for commercial licensing options.
-->

<!--
  RegisterPanel drives the self-service passkey registration ceremony
  (generalized from the go-quicbaas RegisterView).

  Flow:
    1. User enters an identifier (email) and optional display name.
    2. client.auth.webAuthnRegisterBegin -> creation-options envelope.
    3. provider.createCredential runs the attestation ceremony.
    4. client.auth.webAuthnRegisterFinish -> tokens.
    5. Tokens are handed to the shared auth store (setAuthenticated) and the
       host is notified via onSuccess.

  All transport goes through the injected client, all authenticator
  interaction through the injected CredentialProvider. Styling is daisyUI
  class names only.
-->
<script lang="ts">
  import type { Snippet } from 'svelte';
  import type { AuthMeResponse, WebAuthnBeginRegistrationRequest } from '@go-xkms/sdk';
  import type { AuthClientHost } from '../config.ts';
  import {
    isNetworkFailure,
    isUserDeclined,
    type CredentialProvider,
  } from '../provider.ts';
  import { setAuthenticated, type AuthTokens } from '../stores/auth.svelte.ts';

  interface Props {
    /** Credential source (browser WebAuthn or an injected desktop provider). */
    provider: CredentialProvider;
    /** SDK client (or anything auth-shaped) carrying the ceremonies. */
    client: AuthClientHost;
    title?: string;
    subtitle?: string;
    /** Optional brand snippet rendered instead of the title/subtitle block. */
    brand?: Snippet;
    /** Label for the identifier input. */
    identifierLabel?: string;
    /** Called after tokens are persisted; `me` is null when /me is unavailable. */
    onSuccess: (tokens: AuthTokens, me: AuthMeResponse | null) => void;
  }

  let {
    provider,
    client,
    title = 'Create account',
    subtitle = 'Register a hardware-backed passkey',
    brand,
    identifierLabel = 'Email',
    onSuccess,
  }: Props = $props();

  const DECLINED_MESSAGE =
    'Credential creation was declined or cancelled. Try again with your hardware key.';
  const NETWORK_MESSAGE = "Can't reach the server right now.";

  type Stage = 'form' | 'ceremony' | 'done';

  let stage: Stage = $state('form');
  let identifier = $state('');
  let displayName = $state('');
  let busy = $state(false);
  let errorMessage = $state('');

  async function handleSubmit(): Promise<void> {
    if (busy) return;
    const trimmedIdentifier = identifier.trim();
    if (!trimmedIdentifier) {
      errorMessage = `Please enter your ${identifierLabel.toLowerCase()}.`;
      return;
    }
    const trimmedDisplay = displayName.trim();

    busy = true;
    errorMessage = '';
    stage = 'ceremony';

    try {
      // Step 1: begin — server returns the WebAuthn creation challenge.
      let begin;
      try {
        const req: WebAuthnBeginRegistrationRequest = { email: trimmedIdentifier };
        if (trimmedDisplay) req.display_name = trimmedDisplay;
        begin = await client.auth.webAuthnRegisterBegin(req);
      } catch (e: unknown) {
        const status = (e as { status?: number }).status;
        if (status === 403) {
          // One refusal for "no such account while sign-up is off" and
          // "account already has a passkey" — the server does not say which
          // (go-xkms#1294, go-xkms#1296).
          errorMessage =
            'Registration is not available for this address. If you already have a passkey, sign in and add another from your account; otherwise ask your admin.';
        } else if (status === 400 || status === 409) {
          errorMessage =
            (e as { message?: string }).message ??
            'Invalid registration request. Check your inputs and try again.';
        } else if (isNetworkFailure(e)) {
          errorMessage = NETWORK_MESSAGE;
        } else {
          errorMessage =
            e instanceof Error ? e.message : 'Registration failed. Please try again.';
        }
        stage = 'form';
        return;
      }

      // Step 2: run the attestation ceremony through the provider.
      let credential;
      try {
        credential = await provider.createCredential(begin.options);
      } catch (e: unknown) {
        errorMessage = isUserDeclined(e)
          ? DECLINED_MESSAGE
          : e instanceof Error
            ? e.message
            : 'Authenticator interaction failed.';
        stage = 'form';
        return;
      }

      // Step 3: finish — server verifies the attestation and issues tokens.
      let resp;
      try {
        resp = await client.auth.webAuthnRegisterFinish(begin.sessionId, credential);
      } catch (e: unknown) {
        errorMessage = isNetworkFailure(e)
          ? NETWORK_MESSAGE
          : e instanceof Error
            ? e.message
            : 'Registration failed. Please try again.';
        stage = 'form';
        return;
      }

      if (!resp.token) {
        errorMessage =
          'Registration did not return a session token. Please try signing in.';
        stage = 'form';
        return;
      }

      const tokens: AuthTokens = {
        access_token: resp.token,
        refresh_token: resp.refresh_token,
      };
      setAuthenticated(tokens);
      let me: AuthMeResponse | null = null;
      try {
        me = await client.auth.me();
      } catch {
        me = null;
      }
      stage = 'done';
      onSuccess(tokens, me);
    } finally {
      busy = false;
    }
  }
</script>

<div class="card bg-base-200 w-full max-w-sm shadow-xl">
  <div class="card-body gap-5">

    <!-- Header / brand -->
    {#if brand}
      {@render brand()}
    {:else}
      <div class="text-center">
        <div class="text-2xl font-bold">{title}</div>
        <div class="text-sm text-base-content/50 mt-1">{subtitle}</div>
      </div>
    {/if}

    <!-- Error alert -->
    {#if errorMessage}
      <div class="alert alert-error py-2 px-3 text-sm" role="alert">
        <span>{errorMessage}</span>
      </div>
    {/if}

    {#if stage === 'form'}
      <div class="flex flex-col gap-3">
        <label class="form-control">
          <div class="label">
            <span class="label-text text-sm">{identifierLabel}</span>
          </div>
          <input
            id="svelte-auth-register-identifier"
            type="text"
            class="input input-bordered input-sm"
            bind:value={identifier}
            autocomplete="email"
            required
            aria-label={identifierLabel}
            onkeydown={(e) => {
              if (e.key === 'Enter') void handleSubmit();
            }}
          />
        </label>

        <label class="form-control">
          <div class="label">
            <span class="label-text text-sm">Display name</span>
          </div>
          <input
            id="svelte-auth-register-display-name"
            type="text"
            class="input input-bordered input-sm"
            bind:value={displayName}
            autocomplete="name"
            aria-label="Display name"
            onkeydown={(e) => {
              if (e.key === 'Enter') void handleSubmit();
            }}
          />
        </label>

        <button
          class="btn btn-primary w-full"
          onclick={() => void handleSubmit()}
          disabled={busy || identifier.trim() === ''}
          aria-label="Create account with passkey"
        >
          {#if busy}
            <span class="loading loading-spinner loading-sm"></span>
          {:else}
            Create account
          {/if}
        </button>
      </div>

    {:else if stage === 'ceremony'}
      <div class="flex flex-col items-center gap-4 py-4">
        <span class="loading loading-spinner loading-lg"></span>
        <p class="text-sm text-base-content/70 text-center">
          Touch your hardware security key when prompted by the browser…
        </p>
      </div>

    {:else if stage === 'done'}
      <div class="flex flex-col items-center gap-3 py-2 text-center">
        <p class="font-semibold">Account created</p>
        <p class="text-sm text-base-content/60">
          Your passkey is registered and you are signed in.
        </p>
      </div>
    {/if}

  </div>
</div>
