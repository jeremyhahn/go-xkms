<script lang="ts">
  /**
   * MultiFactorLoginGate — login screen for the platform server connection.
   *
   * Auto-detects available factor types (mTLS cert on disk / FIDO2 CTAP2 /
   * PIV PC/SC) and shows the appropriate buttons. Pixel-equivalent to the
   * web UI /auth/login page per §5e of the bootstrap-auth-architecture.
   *
   * This component is shown when xkey connects to a platform server and needs
   * to authenticate the user. It is distinct from AuthLoginGate, which gates
   * the local app unlock (User PIN / SO PIN).
   */

  import { createEventDispatcher, onMount } from 'svelte';
  import Icon from '$lib/components/Icon.svelte';
  import XKeyBrandIcon from '$lib/components/XKeyBrandIcon.svelte';
  import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
  import StatusBadge from '$lib/components/StatusBadge.svelte';
  import {
    mdiKey, mdiFingerprint, mdiCreditCardOutline,
    mdiLinkVariant, mdiAlert,
  } from '$lib/utils/icons';
  import { callBackend, isWailsAvailable } from '$lib/api/backend';

  // ----- props -----
  export let serverAddress: string = '';

  // ----- events -----
  const dispatch = createEventDispatcher<{ authenticated: { token: string; method: string } }>();

  // ----- local state -----

  interface Availability {
    mtls: boolean;
    fido2: boolean;
    piv: boolean;
    loading: boolean;
  }

  let availability: Availability = { mtls: false, fido2: false, piv: false, loading: true };
  let username = '';
  let activeMethod: string | null = null;
  let error = '';
  let busy = false;

  // ----- lifecycle -----

  onMount(async () => {
    const [mtls, fido2, piv] = await Promise.all([
      probeMTLS(),
      probeFIDO2(),
      probePIV(),
    ]);
    availability = { mtls, fido2, piv, loading: false };
  });

  // ----- detection probes -----

  async function probeMTLS(): Promise<boolean> {
    // xkey: check if ~/.xkey/admin.pem exists via backend service.
    if (!isWailsAvailable()) return false;
    const result = await callBackend<{ exists: boolean }>('SecurityFactorService', 'ProbeAdminCert');
    return result?.exists ?? false;
  }

  async function probeFIDO2(): Promise<boolean> {
    if (!isWailsAvailable()) return false;
    const status = await callBackend<{ running: boolean; authenticator_available: boolean }>(
      'FIDO2DeviceService', 'GetStatus'
    );
    return status?.authenticator_available ?? false;
  }

  async function probePIV(): Promise<boolean> {
    if (!isWailsAvailable()) return false;
    const cards = await callBackend<Array<{ has_piv_applet: boolean }>>(
      'SecurityFactorService', 'EnumeratePIVCards'
    );
    return (cards ?? []).some((c) => c.has_piv_applet);
  }

  // ----- login actions -----

  async function loginMTLS(): Promise<void> {
    activeMethod = 'mtls';
    busy = true;
    error = '';
    try {
      const result = await callBackend<{ token: string }>(
        'SecurityFactorService', 'LoginMTLS'
      );
      if (!result?.token) {
        error = 'mTLS authentication failed — no token returned.';
        return;
      }
      dispatch('authenticated', { token: result.token, method: 'mtls' });
    } catch (err) {
      error = err instanceof Error ? err.message : 'mTLS login failed';
    } finally {
      busy = false;
      activeMethod = null;
    }
  }

  async function loginFIDO2(): Promise<void> {
    if (!username.trim()) {
      error = 'Enter your username to use FIDO2 login.';
      return;
    }
    activeMethod = 'fido2';
    busy = true;
    error = '';
    try {
      const result = await callBackend<{ token: string }>(
        'SecurityFactorService', 'LoginFIDO2', username
      );
      if (!result?.token) {
        error = 'FIDO2 authentication failed — no token returned.';
        return;
      }
      dispatch('authenticated', { token: result.token, method: 'fido2' });
    } catch (err) {
      error = err instanceof Error ? err.message : 'FIDO2 login failed';
    } finally {
      busy = false;
      activeMethod = null;
    }
  }

  async function loginPIV(): Promise<void> {
    activeMethod = 'piv';
    busy = true;
    error = '';
    try {
      const result = await callBackend<{ token: string }>(
        'SecurityFactorService', 'LoginPIV'
      );
      if (!result?.token) {
        error = 'PIV authentication failed — no token returned.';
        return;
      }
      dispatch('authenticated', { token: result.token, method: 'piv' });
    } catch (err) {
      error = err instanceof Error ? err.message : 'PIV login failed';
    } finally {
      busy = false;
      activeMethod = null;
    }
  }

  async function loginCrossDevice(): Promise<void> {
    // Cross-device CTAP2 (BLE/QR) — delegate to FIDO2 with cross-device hint.
    activeMethod = 'fido2-cross';
    busy = true;
    error = '';
    try {
      const result = await callBackend<{ token: string }>(
        'SecurityFactorService', 'LoginFIDO2CrossDevice', username
      );
      if (!result?.token) {
        error = 'Cross-device authentication failed.';
        return;
      }
      dispatch('authenticated', { token: result.token, method: 'fido2' });
    } catch (err) {
      error = err instanceof Error ? err.message : 'Cross-device login failed';
    } finally {
      busy = false;
      activeMethod = null;
    }
  }

  $: availableMethods = [
    availability.mtls ? 'mtls' : null,
    availability.fido2 ? 'fido2' : null,
    availability.piv ? 'piv' : null,
  ].filter(Boolean) as string[];
</script>

<div class="login-overlay">
  <div class="login-card">
    <!-- Brand -->
    <div class="brand-section">
      <XKeyBrandIcon size={48} />
      <h1 class="text-headline-medium">xKey</h1>
      <p class="text-body-large">Sign in to {serverAddress || 'platform'}</p>
    </div>

    <!-- Username input -->
    <div class="field-group">
      <label class="text-label-medium field-label" for="mfa-username">Username</label>
      <input
        id="mfa-username"
        type="text"
        bind:value={username}
        placeholder="your@email.com"
        autocomplete="username"
        class="field-input"
        on:keydown={(e) => { if (e.key === 'Enter' && availability.fido2) loginFIDO2(); }}
        aria-label="Username"
      />
    </div>

    {#if error}
      <div class="error-banner">
        <Icon path={mdiAlert} size={16} />
        <span class="text-body-small">{error}</span>
      </div>
    {/if}

    {#if availability.loading}
      <div class="detection-row">
        <LoadingSpinner size={18} />
        <span class="text-body-small">Detecting available sign-in methods…</span>
      </div>
    {:else}
      <div class="method-buttons">
        <!-- mTLS -->
        <button
          class="method-btn"
          class:active={availability.mtls}
          class:disabled-btn={!availability.mtls}
          disabled={!availability.mtls || busy}
          on:click={loginMTLS}
          aria-label="Sign in with mTLS certificate"
        >
          {#if busy && activeMethod === 'mtls'}
            <LoadingSpinner size={18} />
          {:else}
            <Icon path={mdiKey} size={18} color={availability.mtls ? '#3b82f6' : 'var(--on-surface-variant)'} />
          {/if}
          <div class="method-label">
            <span class="method-title">mTLS Certificate</span>
            {#if !availability.mtls}
              <span class="method-hint">No client cert found at ~/.xkey/admin.pem</span>
            {/if}
          </div>
        </button>

        <!-- FIDO2 -->
        <button
          class="method-btn"
          class:active={availability.fido2}
          class:disabled-btn={!availability.fido2}
          disabled={!availability.fido2 || busy}
          on:click={loginFIDO2}
          aria-label="Sign in with FIDO2 / passkey"
        >
          {#if busy && activeMethod === 'fido2'}
            <LoadingSpinner size={18} />
          {:else}
            <Icon path={mdiFingerprint} size={18} color={availability.fido2 ? '#8b5cf6' : 'var(--on-surface-variant)'} />
          {/if}
          <div class="method-label">
            <span class="method-title">FIDO2 / Passkey</span>
            {#if !availability.fido2}
              <span class="method-hint">No CTAP2 device detected</span>
            {/if}
          </div>
        </button>

        <!-- PIV -->
        <button
          class="method-btn"
          class:active={availability.piv}
          class:disabled-btn={!availability.piv}
          disabled={!availability.piv || busy}
          on:click={loginPIV}
          aria-label="Sign in with PIV smartcard"
        >
          {#if busy && activeMethod === 'piv'}
            <LoadingSpinner size={18} />
          {:else}
            <Icon path={mdiCreditCardOutline} size={18} color={availability.piv ? '#22c55e' : 'var(--on-surface-variant)'} />
          {/if}
          <div class="method-label">
            <span class="method-title">PIV Smartcard</span>
            {#if !availability.piv}
              <span class="method-hint">No PC/SC reader or card detected</span>
            {/if}
          </div>
        </button>
      </div>

      <!-- Cross-device WebAuthn -->
      <div class="cross-device">
        <button
          class="link-btn"
          on:click={loginCrossDevice}
          disabled={busy}
          aria-label="Use a security key on another device"
        >
          <Icon path={mdiLinkVariant} size={14} />
          Other device?
        </button>
        <p class="text-body-small hint">
          Sign in with a security key on a different device (CTAP2 over BLE or QR code).
        </p>
      </div>
    {/if}
  </div>
</div>

<style>
  .login-overlay {
    position: fixed;
    inset: 0;
    display: flex;
    align-items: center;
    justify-content: center;
    background: var(--color-scrim, rgba(0, 0, 0, 0.4));
    z-index: 200;
  }

  .login-card {
    background: var(--color-surface, #fff);
    border-radius: var(--radius-xl, 16px);
    padding: 40px 32px;
    width: 360px;
    max-width: 92vw;
    display: flex;
    flex-direction: column;
    gap: 20px;
    box-shadow: var(--elevation-3, 0 8px 24px rgba(0,0,0,0.16));
  }

  .brand-section {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 6px;
    text-align: center;
  }

  .field-group {
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .field-label {
    color: var(--color-on-surface-variant, #49454f);
  }

  .field-input {
    padding: 10px 14px;
    border-radius: var(--radius-md, 8px);
    border: 1px solid var(--color-outline-variant, #cac4d0);
    background: var(--color-surface, #fff);
    color: var(--color-on-surface, #1c1b1f);
    font-size: 14px;
    font-family: inherit;
    transition: border-color 0.15s;
  }

  .field-input:focus {
    outline: none;
    border-color: var(--color-primary);
    box-shadow: 0 0 0 1px var(--color-primary);
  }

  .error-banner {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 10px 14px;
    border-radius: var(--radius-md, 8px);
    background: var(--color-error-container, #fdecea);
    color: var(--color-on-error-container, #5f2120);
    font-size: 13px;
  }

  .detection-row {
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--color-on-surface-variant);
    font-size: 13px;
    justify-content: center;
    padding: 8px 0;
  }

  .method-buttons {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .method-btn {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 16px;
    border-radius: var(--radius-md, 8px);
    border: 1px solid var(--color-outline-variant, #cac4d0);
    background: var(--color-surface, #fff);
    cursor: pointer;
    text-align: left;
    transition: border-color 0.15s, background 0.15s;
    font-family: inherit;
  }

  .method-btn.active {
    border-color: var(--color-primary);
  }

  .method-btn.active:hover:not(:disabled) {
    background: color-mix(in srgb, var(--color-primary) 6%, transparent);
  }

  .method-btn.disabled-btn {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .method-label {
    display: flex;
    flex-direction: column;
    gap: 1px;
  }

  .method-title {
    font-size: 14px;
    font-weight: 600;
    color: var(--color-on-surface, #1c1b1f);
  }

  .method-hint {
    font-size: 11px;
    color: var(--color-on-surface-variant, #49454f);
  }

  .cross-device {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 4px;
    padding-top: 4px;
  }

  .link-btn {
    display: inline-flex;
    align-items: center;
    gap: 4px;
    background: none;
    border: none;
    cursor: pointer;
    color: var(--color-primary);
    font-size: 13px;
    font-family: inherit;
    text-decoration: underline;
    text-underline-offset: 3px;
    padding: 4px;
  }

  .link-btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .hint {
    color: var(--color-on-surface-variant, #49454f);
    text-align: center;
  }
</style>
