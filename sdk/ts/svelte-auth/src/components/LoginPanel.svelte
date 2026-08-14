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
  LoginPanel renders the hardware-only authentication chooser (generalized
  from the go-quicbaas LoginView).

  Two methods are offered, gated on what the injected CredentialProvider
  reports:
    1. Passkey (FIDO2 / WebAuthn) — identifier-then-assertion flow.
    2. Certificate (PIV / mTLS) — TLS client-cert exchange via the provider.

  Anti-enumeration: the server answers every identity-resolution failure on
  begin/finish with the same 401, and this panel collapses ALL of them into
  ONE generic failure string — the UI cannot be used to probe which
  organization or account exists. The copy is overridable (failureMessage)
  but never split per cause.

  Organization (tenant) entry: rendered only when defaultTenant is provided.
  It is free text by design — a dropdown would need an unauthenticated
  tenant-listing endpoint, which is a cross-tenant namespace disclosure. The
  last SUCCESSFULLY used organization id is remembered in localStorage
  (only a value that completed a login is stored, so a typo never becomes a
  sticky default).

  All network calls go through the injected SDK client (client.auth.*) and
  all credential ceremonies through the injected CredentialProvider, so a
  desktop shell can swap in local hardware without touching this component.

  Styling is daisyUI class names only (btn, card, input, alert) — the host
  app's theme supplies the palette.
-->
<script lang="ts">
  import type { Snippet } from 'svelte';
  import type { AuthMeResponse, WebAuthnBeginLoginRequest } from '@go-xkms/sdk';
  import type { AuthClientHost } from '../config.ts';
  import {
    isNetworkFailure,
    isUserDeclined,
    type AuthMethod,
    type CredentialProvider,
  } from '../provider.ts';
  import {
    authConfig,
    isAuthStoreConfigured,
    setAuthenticated,
    type AuthTokens,
  } from '../stores/auth.svelte.ts';

  interface Props {
    /** Credential source (browser WebAuthn or an injected desktop provider). */
    provider: CredentialProvider;
    /** SDK client (or anything auth-shaped) carrying the ceremonies. */
    client: AuthClientHost;
    title?: string;
    subtitle?: string;
    /** Optional brand snippet rendered instead of the title/subtitle block. */
    brand?: Snippet;
    /**
     * When set, an organization field is shown (prefilled with the last
     * successfully used id, falling back to this default) and its value is
     * sent as tenant_id on the begin request.
     */
    defaultTenant?: string;
    /** Label for the identifier input. */
    identifierLabel?: string;
    /** The single generic message shown for every rejected sign-in. */
    failureMessage?: string;
    /** Called after tokens are persisted; `me` is null when /me is unavailable. */
    onSuccess: (tokens: AuthTokens, me: AuthMeResponse | null) => void;
  }

  let {
    provider,
    client,
    title = 'Sign in',
    subtitle = 'Hardware-backed, passwordless',
    brand,
    defaultTenant,
    identifierLabel = 'Email',
    failureMessage = 'Sign-in failed. Check your details and try again.',
    onSuccess,
  }: Props = $props();

  const DECLINED_MESSAGE =
    'Authentication declined or canceled. Try again with your hardware key.';
  const NETWORK_MESSAGE = "Can't reach the server right now.";

  type Mode = 'chooser' | 'passkey';

  let mode: Mode = $state('chooser');
  let identifier = $state('');
  let busy = $state(false);
  let errorMessage = $state('');
  let methods = $state<AuthMethod[]>([]);

  // -------------------------------------------------------------------------
  // Provider capability discovery
  // -------------------------------------------------------------------------

  // What the client can perform (provider) intersected with what this
  // deployment accepts (server capabilities). Offering a method the server has
  // disabled sends the operator down a path that can only fail — the
  // capabilities endpoint exists precisely to prevent that.
  //
  // Capability keys map to methods: webauthn_enabled -> passkey,
  // piv_login_enabled -> certificate. A key the server omits is treated as
  // enabled, so an older daemon that reports neither still offers both.
  const CAPABILITY_FOR: Record<AuthMethod, string> = {
    passkey: 'webauthn_enabled',
    certificate: 'piv_login_enabled',
  };

  $effect(() => {
    let cancelled = false;

    void (async () => {
      let offered: AuthMethod[];
      try {
        offered = await provider.methods();
      } catch {
        offered = ['passkey'];
      }

      // A capabilities probe that fails must not lock the operator out, so an
      // error here leaves the provider's list untouched.
      let caps: Record<string, boolean> | null = null;
      try {
        caps = (await client.capabilities?.get()) ?? null;
      } catch {
        caps = null;
      }

      if (cancelled) return;
      methods =
        caps === null
          ? offered
          : offered.filter((m) => caps[CAPABILITY_FOR[m]] !== false);
    })();

    return () => {
      cancelled = true;
    };
  });

  // -------------------------------------------------------------------------
  // Organization (tenant) memory — only a SUCCESSFUL login earns the prefill.
  // -------------------------------------------------------------------------

  function tenantMemoryKey(): string | null {
    if (!isAuthStoreConfigured()) return null;
    return `${authConfig().storagePrefix}_login_tenant`;
  }

  function initialTenant(): string {
    if (defaultTenant === undefined) return '';
    const key = tenantMemoryKey();
    if (key !== null && typeof window !== 'undefined') {
      return window.localStorage.getItem(key) ?? defaultTenant;
    }
    return defaultTenant;
  }

  let tenant = $state(initialTenant());

  function rememberTenant(id: string): void {
    const key = tenantMemoryKey();
    if (key !== null && typeof window !== 'undefined') {
      window.localStorage.setItem(key, id);
    }
  }

  // -------------------------------------------------------------------------
  // Completion — persist tokens, flip status, resolve identity, notify host.
  // -------------------------------------------------------------------------

  async function completeLogin(tokens: AuthTokens, usedTenant?: string): Promise<void> {
    // setAuthenticated persists the tokens AND flips the shared auth status
    // in THIS tab, so a host route guard sees 'authenticated' immediately.
    setAuthenticated(tokens);
    if (usedTenant) rememberTenant(usedTenant);
    let me: AuthMeResponse | null = null;
    try {
      me = await client.auth.me();
    } catch {
      me = null;
    }
    onSuccess(tokens, me);
  }

  // -------------------------------------------------------------------------
  // Passkey (FIDO2 / WebAuthn) flow
  // -------------------------------------------------------------------------

  function startPasskeyFlow(): void {
    mode = 'passkey';
    errorMessage = '';
  }

  async function submitPasskey(): Promise<void> {
    if (busy) return;
    const trimmedIdentifier = identifier.trim();
    if (!trimmedIdentifier) {
      errorMessage = `Please enter your ${identifierLabel.toLowerCase()}.`;
      return;
    }
    const trimmedTenant = tenant.trim();
    if (defaultTenant !== undefined && !trimmedTenant) {
      errorMessage = 'Please enter your organization.';
      return;
    }

    busy = true;
    errorMessage = '';
    try {
      // Step 1: begin — the server answers every identity-resolution failure
      // with the SAME 401, so this branch cannot tell an unknown organization
      // from an unknown account — and neither can the message shown to the
      // user. Reporting them separately would rebuild an enumeration oracle.
      let begin;
      try {
        const req: WebAuthnBeginLoginRequest & { tenant_id?: string } = {
          email: trimmedIdentifier,
        };
        if (defaultTenant !== undefined && trimmedTenant) {
          req.tenant_id = trimmedTenant;
        }
        begin = await client.auth.webAuthnBeginLogin(req);
      } catch (e: unknown) {
        errorMessage = isNetworkFailure(e) ? NETWORK_MESSAGE : failureMessage;
        return;
      }

      // Step 2: run the assertion ceremony through the provider.
      let credential;
      try {
        credential = await provider.getAssertion(begin.options);
      } catch (e: unknown) {
        errorMessage = isUserDeclined(e) ? DECLINED_MESSAGE : failureMessage;
        return;
      }

      // Step 3: finish — same anti-enumeration collapse as begin.
      let resp;
      try {
        resp = await client.auth.webAuthnFinishLogin(
          begin.sessionId,
          credential,
          begin.userId,
        );
      } catch (e: unknown) {
        errorMessage = isNetworkFailure(e) ? NETWORK_MESSAGE : failureMessage;
        return;
      }

      if (!resp.token) {
        // A 200 with no usable token is a server contract violation, not a
        // success — surface it instead of silently routing to a dead session.
        errorMessage = 'Sign-in did not return a session token. Please try again.';
        return;
      }

      await completeLogin(
        { access_token: resp.token, refresh_token: resp.refresh_token },
        defaultTenant !== undefined ? trimmedTenant : undefined,
      );
    } finally {
      busy = false;
    }
  }

  // -------------------------------------------------------------------------
  // Certificate (PIV / mTLS) flow — tenant-agnostic: the server resolves the
  // identity from the presented certificate.
  // -------------------------------------------------------------------------

  async function submitCertificate(): Promise<void> {
    if (busy) return;
    busy = true;
    errorMessage = '';
    try {
      const pair = await provider.loginCertificate();
      await completeLogin({
        access_token: pair.access_token,
        refresh_token: pair.refresh_token,
      });
    } catch (e: unknown) {
      const status = (e as { status?: number }).status;
      if (status === 401 || status === 403) {
        errorMessage =
          "Your certificate isn't recognized. Confirm it is enrolled with your administrator.";
      } else if (status === 400) {
        errorMessage =
          'No matching certificate identity. Make sure your smartcard is inserted and your browser is configured to send client certificates.';
      } else if (isNetworkFailure(e)) {
        errorMessage = NETWORK_MESSAGE;
      } else {
        errorMessage =
          e instanceof Error ? e.message : 'Certificate authentication failed.';
      }
    } finally {
      busy = false;
    }
  }

  function backToChooser(): void {
    mode = 'chooser';
    errorMessage = '';
    identifier = '';
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
        <button
          class="btn btn-xs btn-ghost ml-auto"
          onclick={backToChooser}
          aria-label="Try again"
        >
          Try again
        </button>
      </div>
    {/if}

    {#if mode === 'chooser'}
      <!-- Organization id (passkey path only). Free text by design. -->
      {#if defaultTenant !== undefined}
        <div class="form-control">
          <label class="label pb-1" for="svelte-auth-login-tenant">
            <span class="label-text text-sm">Organization</span>
          </label>
          <input
            id="svelte-auth-login-tenant"
            type="text"
            class="input input-bordered input-sm w-full"
            bind:value={tenant}
            autocomplete="organization"
            autocapitalize="none"
            spellcheck="false"
            aria-label="Organization"
            placeholder={defaultTenant}
          />
        </div>
      {/if}

      <!-- Passkey option -->
      {#if methods.includes('passkey')}
        <div class="flex flex-col gap-1">
          <button
            class="btn btn-primary btn-lg w-full flex flex-col items-center gap-1 h-auto py-4"
            onclick={startPasskeyFlow}
            aria-label="Sign in with passkey"
          >
            <span class="font-semibold">Sign in with passkey</span>
            <span class="text-xs font-normal opacity-80">FIDO2 / WebAuthn</span>
          </button>
          <p class="text-xs text-base-content/40 text-center px-2">
            Use a hardware security key or a device-bound passkey.
          </p>
        </div>
      {/if}

      <!-- Certificate option -->
      {#if methods.includes('certificate')}
        <div class="flex flex-col gap-1">
          <button
            class="btn btn-ghost btn-lg w-full flex flex-col items-center gap-1 h-auto py-4 border border-base-content/10"
            onclick={() => void submitCertificate()}
            disabled={busy}
            aria-label="Sign in with certificate"
          >
            <span class="font-semibold">Sign in with certificate</span>
            <span class="text-xs font-normal opacity-70">PIV / mTLS client cert</span>
          </button>
          <p class="text-xs text-base-content/40 text-center px-2">
            Use a PIV-compatible smartcard or an enrolled client certificate.
          </p>
        </div>
      {/if}

    {:else if mode === 'passkey'}
      <div class="flex flex-col gap-3">
        <label class="form-control">
          <div class="label">
            <span class="label-text text-sm">{identifierLabel}</span>
          </div>
          <input
            id="svelte-auth-login-identifier"
            type="text"
            class="input input-bordered input-sm"
            bind:value={identifier}
            autocomplete="email"
            required
            aria-label={identifierLabel}
            onkeydown={(e) => {
              if (e.key === 'Enter') void submitPasskey();
            }}
          />
        </label>

        <button
          class="btn btn-primary w-full"
          onclick={() => void submitPasskey()}
          disabled={busy || identifier.trim() === ''}
          aria-label="Authenticate with passkey"
        >
          {#if busy}
            <span class="loading loading-spinner loading-sm"></span>
          {:else}
            Authenticate
          {/if}
        </button>

        <button
          class="btn btn-ghost btn-sm w-full"
          onclick={backToChooser}
          aria-label="Back to login options"
        >
          Back
        </button>
      </div>
    {/if}

  </div>
</div>
