<script lang="ts">
  import { createEventDispatcher } from 'svelte';
  import { callBackend } from '$lib/api/backend';
  import type { LoginResult } from '$lib/types/setup';
  import { setAuthMode, setPolicyVerified, setTamperDetected } from '$lib/stores/auth';
  import { isTamperDetected } from '$lib/stores/auth';
  import Icon from '$lib/components/Icon.svelte';
  import XKeyBrandIcon from '$lib/components/XKeyBrandIcon.svelte';
  import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
  import {
    mdiShieldLockOutline, mdiAccountKey, mdiAlert, mdiArrowLeft
  } from '$lib/utils/icons';

  export let requireSOVerification = false;

  const dispatch = createEventDispatcher<{ authenticated: { mode: string } }>();

  type LoginMode = 'select' | 'user' | 'so';
  let loginMode: LoginMode = 'select';
  let pin = '';
  let loading = false;
  let error = '';

  const MIN_PIN_LENGTH = 6;

  $: pinValid = pin.length >= MIN_PIN_LENGTH;
  $: tamperWarning = $isTamperDetected;

  function selectMode(mode: 'user' | 'so'): void {
    loginMode = mode;
    pin = '';
    error = '';
  }

  function goBack(): void {
    loginMode = 'select';
    pin = '';
    error = '';
  }

  async function handleLogin(): Promise<void> {
    if (!pinValid) return;
    loading = true;
    error = '';

    const method = loginMode === 'so' ? 'LoginSO' : 'LoginUser';
    const result = await callBackend<LoginResult>('AuthService', method, pin);

    loading = false;

    if (result && result.success) {
      setAuthMode(result.mode as 'locked' | 'user' | 'so_admin');
      setPolicyVerified(result.policy_verified);
      setTamperDetected(result.tamper_detected);
      dispatch('authenticated', { mode: result.mode });
    } else {
      error = result?.error || 'Authentication failed';
    }

    pin = '';
  }

  function handleKeydown(e: KeyboardEvent): void {
    if (e.key === 'Enter' && pinValid && !loading) {
      handleLogin();
    }
  }
</script>

<div class="auth-overlay">
  <div class="auth-container">
    <div class="auth-content">
      <!-- Brand -->
      <div class="brand-section">
        <div class="brand-icon">
          <XKeyBrandIcon size={48} />
        </div>
        <h1 class="text-headline-medium">xKey</h1>
        <p class="text-body-large">Sign in to continue</p>
      </div>

      <!-- Tamper warning banner -->
      {#if tamperWarning}
        <div class="info-banner warning" role="alert">
          <Icon path={mdiAlert} size={18} />
          <span class="text-body-medium">Platform integrity check failed. Possible policy tampering detected. Contact your administrator.</span>
        </div>
      {/if}

      <!-- SO verification info banner -->
      {#if requireSOVerification}
        <div class="info-banner info">
          <Icon path={mdiShieldLockOutline} size={18} />
          <span class="text-body-medium">Administrator authorization required for policy verification</span>
        </div>
      {/if}

      <!-- Mode selection -->
      {#if loginMode === 'select'}
        <div class="mode-options">
          <button class="mode-card" on:click={() => selectMode('so')}>
            <div class="mode-icon">
              <Icon path={mdiShieldLockOutline} size={28} />
            </div>
            <div class="mode-info">
              <span class="text-title-medium">Administrator</span>
              <span class="text-body-small">Sign in with Security Officer PIN for full administrative access.</span>
            </div>
          </button>
          <button class="mode-card" on:click={() => selectMode('user')}>
            <div class="mode-icon">
              <Icon path={mdiAccountKey} size={28} />
            </div>
            <div class="mode-info">
              <span class="text-title-medium">User</span>
              <span class="text-body-small">Sign in with User PIN for standard operations.</span>
            </div>
          </button>
        </div>

      <!-- PIN entry -->
      {:else}
        <div class="pin-section">
          <button class="btn btn-text back-btn" on:click={goBack}>
            <Icon path={mdiArrowLeft} size={18} />
            Back
          </button>

          <div class="pin-header">
            <Icon path={loginMode === 'so' ? mdiShieldLockOutline : mdiAccountKey} size={24} />
            <h2 class="text-title-large">
              {loginMode === 'so' ? 'Administrator Login' : 'User Login'}
            </h2>
          </div>

          <div class="pin-fields">
            <label class="field-label text-label-medium" for="auth-pin-input">
              {loginMode === 'so' ? 'Security Officer PIN' : 'User PIN'}
            </label>
            <input
              id="auth-pin-input"
              type="password"
              class="field-input"
              class:field-input-error={pin.length > 0 && !pinValid}
              placeholder="Enter PIN"
              bind:value={pin}
              on:keydown={handleKeydown}
              disabled={loading}
              autocomplete="off"
            />
            {#if pin.length > 0 && !pinValid}
              <span class="field-hint text-body-small">PIN must be at least {MIN_PIN_LENGTH} characters</span>
            {/if}
          </div>

          {#if error}
            <div class="error-banner" role="alert">
              <Icon path={mdiAlert} size={16} />
              <span class="text-body-small">{error}</span>
            </div>
          {/if}

          <button
            class="btn btn-primary login-btn"
            on:click={handleLogin}
            disabled={!pinValid || loading}
          >
            {#if loading}
              <LoadingSpinner size={18} />
              Authenticating...
            {:else}
              Sign In
            {/if}
          </button>
        </div>
      {/if}
    </div>
  </div>
</div>

<style>
  .auth-overlay {
    position: fixed;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    background: var(--color-background);
    z-index: 1000;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .auth-container {
    width: 100%;
    max-width: 420px;
    padding: 32px;
  }

  .auth-content {
    background: var(--color-surface-container-lowest);
    border-radius: var(--radius-lg);
    border: 1px solid var(--color-outline-variant);
    padding: 32px;
    display: flex;
    flex-direction: column;
    gap: 24px;
  }

  /* Brand section */
  .brand-section {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 8px;
    text-align: center;
  }

  .brand-icon {
    width: 80px;
    height: 80px;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .brand-section h1 {
    color: var(--color-on-surface);
    margin: 0;
  }

  .brand-section p {
    color: var(--color-on-surface-variant);
    margin: 0;
  }

  /* Info banners */
  .info-banner {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 16px;
    border-radius: var(--radius-md);
  }

  .info-banner.warning {
    background: var(--color-error-container, #fdecea);
    color: var(--color-on-error-container, #5f2120);
  }

  .info-banner.info {
    background: var(--color-primary-container);
    color: var(--color-on-primary-container);
  }

  /* Mode selection */
  .mode-options {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .mode-card {
    display: flex;
    align-items: center;
    gap: 16px;
    padding: 16px;
    border-radius: var(--radius-md);
    border: 2px solid var(--color-outline-variant);
    background: transparent;
    cursor: pointer;
    transition: all 150ms ease;
    text-align: left;
    font-family: var(--font-sans);
  }

  .mode-card:hover {
    border-color: var(--color-primary);
    background: var(--color-primary-container);
  }

  .mode-icon {
    width: 48px;
    height: 48px;
    border-radius: var(--radius-md);
    background: var(--color-surface-container);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    color: var(--color-primary);
  }

  .mode-card:hover .mode-icon {
    background: var(--color-surface);
  }

  .mode-info {
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .mode-info .text-title-medium {
    color: var(--color-on-surface);
  }

  .mode-info .text-body-small {
    color: var(--color-on-surface-variant);
  }

  /* PIN entry section */
  .pin-section {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .back-btn {
    align-self: flex-start;
  }

  .pin-header {
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--color-on-surface);
  }

  .pin-header h2 {
    margin: 0;
    color: var(--color-on-surface);
  }

  .pin-fields {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .field-label {
    color: var(--color-on-surface);
    margin-top: 4px;
  }

  .field-input {
    padding: 10px 16px;
    border-radius: var(--radius-md);
    border: 1px solid var(--color-outline-variant);
    background: var(--color-surface);
    color: var(--color-on-surface);
    font-family: var(--font-sans);
    font-size: 14px;
  }

  .field-input:focus {
    outline: none;
    border-color: var(--color-primary);
    box-shadow: 0 0 0 1px var(--color-primary);
  }

  .field-input:disabled {
    opacity: 0.6;
    cursor: not-allowed;
  }

  .field-input-error {
    border-color: var(--color-error, #d32f2f);
    box-shadow: 0 0 0 1px var(--color-error, #d32f2f);
  }

  .field-hint {
    color: var(--color-error);
  }

  /* Error banner */
  .error-banner {
    display: flex;
    align-items: center;
    gap: 8px;
    padding: 10px 14px;
    border-radius: var(--radius-md);
    background: var(--color-error-container, #fdecea);
    color: var(--color-on-error-container, #5f2120);
  }

  /* Buttons */
  .btn {
    display: inline-flex;
    align-items: center;
    gap: 8px;
    padding: 10px 24px;
    border-radius: var(--radius-full);
    border: none;
    cursor: pointer;
    font-family: var(--font-sans);
    font-weight: 600;
    font-size: 14px;
    transition: all 150ms ease;
  }

  .btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .btn-primary {
    background: var(--color-primary);
    color: var(--color-on-primary);
  }

  .btn-primary:hover:not(:disabled) {
    filter: brightness(1.1);
  }

  .btn-text {
    background: transparent;
    color: var(--color-primary);
    border: none;
    padding: 8px 12px;
  }

  .btn-text:hover {
    background: var(--color-surface-variant);
  }

  .login-btn {
    width: 100%;
    justify-content: center;
    padding: 12px 24px;
  }
</style>
