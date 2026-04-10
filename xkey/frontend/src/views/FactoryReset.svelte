<script lang="ts">
  import { callBackendWithError } from '$lib/api/backend';
  import Icon from '$lib/components/Icon.svelte';
  import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
  import {
    mdiAlert, mdiDeleteSweep, mdiShieldAlert, mdiCheck, mdiKey,
    mdiShieldLockOutline, mdiLockOutline, mdiCreditCardOutline,
    mdiChip, mdiDatabaseLock, mdiCog
  } from '$lib/utils/icons';

  const CONFIRMATION_PHRASE = 'FACTORY RESET';
  const MIN_SO_PIN_LENGTH = 6;

  /** Items that will be permanently destroyed. */
  const impactItems: Array<{ icon: string; label: string }> = [
    { icon: mdiKey, label: 'All FIDO2 credentials and authenticator state' },
    { icon: mdiLockOutline, label: 'All stored passwords and OATH tokens' },
    { icon: mdiCreditCardOutline, label: 'All PIV certificates and keys' },
    { icon: mdiChip, label: 'TPM provisioned keys and platform policy' },
    { icon: mdiDatabaseLock, label: 'Barrier encrypted storage and sealed data' },
    { icon: mdiShieldLockOutline, label: 'Security policy and HMAC integrity data' },
    { icon: mdiCog, label: 'All configuration and preferences' },
  ];

  // Confirmation flow state
  let confirmationText = '';
  let soPin = '';

  // Execution state
  let resetting = false;
  let resetComplete = false;
  let resetError = '';

  $: step1Valid = confirmationText === CONFIRMATION_PHRASE;
  $: step2Valid = soPin.length >= MIN_SO_PIN_LENGTH;
  $: canReset = step1Valid && step2Valid && !resetting && !resetComplete;

  async function performFactoryReset(): Promise<void> {
    resetting = true;
    resetError = '';

    const result = await callBackendWithError<void>(
      'SetupWizardService', 'FactoryReset', soPin
    );
    if (result.error) {
      resetting = false;
      resetError = result.error;
      return;
    }

    resetting = false;
    resetComplete = true;
  }

  function handleRestart(): void {
    window.location.reload();
  }
</script>

<div class="view-container">

  {#if resetComplete}
    <!-- Success State -->
    <div class="success-card">
      <div class="success-icon-wrapper">
        <Icon path={mdiCheck} size={48} color="var(--color-primary)" />
      </div>
      <h1 class="text-headline-small success-heading">Factory Reset Complete</h1>
      <p class="text-body-medium success-desc">
        The device has been fully erased and returned to its factory state.
        The application will restart to complete the process.
      </p>
      <button class="restart-btn text-label-large" on:click={handleRestart}>
        Restart Application
      </button>
    </div>

  {:else}
    <!-- Warning Banner -->
    <div class="warning-banner" role="alert">
      <div class="warning-banner-icon">
        <Icon path={mdiShieldAlert} size={32} color="var(--color-on-error-container)" />
      </div>
      <div class="warning-banner-content">
        <h1 class="text-headline-small warning-heading">Factory Reset</h1>
        <p class="text-body-medium warning-desc">
          This will permanently erase all keys, credentials, certificates,
          and configuration from this device. This action cannot be undone.
        </p>
      </div>
    </div>

    <!-- Impact Summary -->
    <div class="impact-section">
      <h2 class="text-title-medium impact-heading">
        <Icon path={mdiDeleteSweep} size={20} />
        Data That Will Be Destroyed
      </h2>
      <ul class="impact-list">
        {#each impactItems as item}
          <li class="impact-item">
            <div class="impact-item-icon">
              <Icon path={item.icon} size={18} />
            </div>
            <span class="text-body-medium">{item.label}</span>
          </li>
        {/each}
      </ul>
    </div>

    <!-- Confirmation Flow -->
    <div class="confirmation-section">
      <h2 class="text-title-medium confirmation-heading">Confirm Factory Reset</h2>

      <!-- Step 1: Type confirmation phrase -->
      <div class="confirm-step">
        <div class="step-header">
          <div class="step-number" class:step-complete={step1Valid}>
            {#if step1Valid}
              <Icon path={mdiCheck} size={16} color="#FFFFFF" />
            {:else}
              <span class="text-label-small">1</span>
            {/if}
          </div>
          <div class="step-info">
            <span class="text-title-small">Type confirmation phrase</span>
            <span class="text-body-small step-desc">
              Type <strong>{CONFIRMATION_PHRASE}</strong> exactly to confirm
            </span>
          </div>
        </div>
        <div class="step-input-wrapper">
          <input
            class="step-input text-body-medium font-mono"
            type="text"
            placeholder="Type {CONFIRMATION_PHRASE}"
            bind:value={confirmationText}
            disabled={resetting}
            autocomplete="off"
            spellcheck="false"
          />
          {#if confirmationText.length > 0 && !step1Valid}
            <span class="text-body-small input-hint-error">Does not match</span>
          {/if}
        </div>
      </div>

      <!-- Step 2: SO PIN -->
      <div class="confirm-step">
        <div class="step-header">
          <div class="step-number" class:step-complete={step2Valid}>
            {#if step2Valid}
              <Icon path={mdiCheck} size={16} color="#FFFFFF" />
            {:else}
              <span class="text-label-small">2</span>
            {/if}
          </div>
          <div class="step-info">
            <span class="text-title-small">Enter Security Officer PIN</span>
            <span class="text-body-small step-desc">
              The SO PIN is required to authorize the factory reset
            </span>
          </div>
        </div>
        <div class="step-input-wrapper">
          <input
            class="step-input text-body-medium"
            type="password"
            placeholder="Enter SO PIN (min {MIN_SO_PIN_LENGTH} characters)"
            bind:value={soPin}
            disabled={resetting}
            autocomplete="off"
          />
          {#if soPin.length > 0 && !step2Valid}
            <span class="text-body-small input-hint-error">
              PIN must be at least {MIN_SO_PIN_LENGTH} characters
            </span>
          {/if}
        </div>
      </div>

      <!-- Step 3: Execute -->
      <div class="confirm-step">
        <div class="step-header">
          <div class="step-number" class:step-complete={resetComplete}>
            {#if resetComplete}
              <Icon path={mdiCheck} size={16} color="#FFFFFF" />
            {:else}
              <span class="text-label-small">3</span>
            {/if}
          </div>
          <div class="step-info">
            <span class="text-title-small">Execute Factory Reset</span>
            <span class="text-body-small step-desc">
              This is the final step. The reset begins immediately.
            </span>
          </div>
        </div>

        {#if resetting}
          <div class="resetting-indicator">
            <LoadingSpinner size={24} />
            <span class="text-body-medium resetting-text">Performing factory reset...</span>
          </div>
        {:else}
          <button
            class="reset-btn text-label-large"
            disabled={!canReset}
            on:click={performFactoryReset}
          >
            <Icon path={mdiDeleteSweep} size={20} />
            Erase All Data and Reset Device
          </button>
        {/if}

        {#if resetError}
          <div class="error-banner" role="alert">
            <Icon path={mdiAlert} size={18} />
            <span class="text-body-small">{resetError}</span>
          </div>
        {/if}
      </div>
    </div>
  {/if}
</div>

<style>
  .view-container {
    max-width: 640px;
    margin: 0 auto;
    padding: 32px;
    display: flex;
    flex-direction: column;
    gap: 24px;
  }

  /* Warning Banner */
  .warning-banner {
    display: flex;
    align-items: flex-start;
    gap: 16px;
    padding: 20px;
    background-color: var(--color-error-container);
    border-radius: var(--radius-lg);
  }

  .warning-banner-icon {
    width: 56px;
    height: 56px;
    border-radius: var(--radius-md);
    background-color: var(--color-error);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  .warning-banner-icon :global(.icon) {
    color: #FFFFFF !important;
  }

  .warning-banner-content {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 6px;
  }

  .warning-heading {
    margin: 0;
    color: var(--color-on-error-container);
  }

  .warning-desc {
    margin: 0;
    color: var(--color-on-error-container);
    line-height: 1.5;
    opacity: 0.9;
  }

  /* Impact Summary */
  .impact-section {
    display: flex;
    flex-direction: column;
    gap: 16px;
    padding: 20px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-lg);
    background-color: var(--color-surface-container-lowest);
  }

  .impact-heading {
    margin: 0;
    color: var(--color-on-surface);
    display: flex;
    align-items: center;
    gap: 8px;
  }

  .impact-list {
    list-style: none;
    margin: 0;
    padding: 0;
    display: flex;
    flex-direction: column;
    gap: 0;
  }

  .impact-item {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 10px 0;
  }

  .impact-item + .impact-item {
    border-top: 1px solid var(--color-outline-variant);
  }

  .impact-item-icon {
    width: 32px;
    height: 32px;
    border-radius: var(--radius-md);
    background-color: var(--color-error-container);
    color: var(--color-on-error-container);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  .impact-item span {
    color: var(--color-on-surface);
  }

  /* Confirmation Section */
  .confirmation-section {
    display: flex;
    flex-direction: column;
    gap: 20px;
    padding: 20px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-lg);
    background-color: var(--color-surface-container-lowest);
  }

  .confirmation-heading {
    margin: 0;
    color: var(--color-on-surface);
    padding-bottom: 8px;
    border-bottom: 1px solid var(--color-outline-variant);
  }

  /* Confirm Steps */
  .confirm-step {
    display: flex;
    flex-direction: column;
    gap: 12px;
  }

  .confirm-step + .confirm-step {
    padding-top: 16px;
    border-top: 1px solid var(--color-outline-variant);
  }

  .step-header {
    display: flex;
    align-items: flex-start;
    gap: 12px;
  }

  .step-number {
    width: 28px;
    height: 28px;
    border-radius: var(--radius-full);
    border: 2px solid var(--color-outline-variant);
    background-color: var(--color-surface);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    color: var(--color-on-surface-variant);
    transition: all var(--transition-fast);
  }

  .step-number.step-complete {
    border-color: var(--color-primary);
    background-color: var(--color-primary);
    color: #FFFFFF;
  }

  .step-info {
    flex: 1;
    display: flex;
    flex-direction: column;
    gap: 2px;
  }

  .step-info span:first-child {
    color: var(--color-on-surface);
  }

  .step-desc {
    color: var(--color-on-surface-variant);
  }

  .step-input-wrapper {
    display: flex;
    flex-direction: column;
    gap: 4px;
    padding-left: 40px;
  }

  .step-input {
    padding: 10px 12px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-md);
    background: var(--color-surface);
    color: var(--color-on-surface);
    font-family: inherit;
    font-size: 14px;
    outline: none;
    transition: border-color var(--transition-fast);
  }

  .step-input::placeholder {
    color: var(--color-on-surface-variant);
    opacity: 0.6;
  }

  .step-input:focus {
    border-color: var(--color-primary);
  }

  .step-input:disabled {
    opacity: 0.5;
    cursor: not-allowed;
  }

  .input-hint-error {
    color: var(--color-error);
    padding-left: 2px;
  }

  /* Reset Button */
  .reset-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    padding: 12px 24px;
    margin-left: 40px;
    border: none;
    border-radius: var(--radius-md);
    background-color: var(--color-error);
    color: #FFFFFF;
    cursor: pointer;
    font-family: inherit;
    font-weight: 600;
    transition: opacity var(--transition-fast), filter var(--transition-fast);
    align-self: flex-start;
  }

  .reset-btn:hover:not(:disabled) {
    filter: brightness(1.1);
  }

  .reset-btn:active:not(:disabled) {
    filter: brightness(0.95);
  }

  .reset-btn:disabled {
    opacity: 0.4;
    cursor: not-allowed;
  }

  /* Resetting Indicator */
  .resetting-indicator {
    display: flex;
    align-items: center;
    gap: 12px;
    padding: 12px 0;
    margin-left: 40px;
  }

  .resetting-text {
    color: var(--color-on-surface-variant);
  }

  /* Error Banner */
  .error-banner {
    display: flex;
    align-items: flex-start;
    gap: 8px;
    padding: 10px 14px;
    margin-left: 40px;
    background-color: var(--color-error-container);
    border-radius: var(--radius-md);
    color: var(--color-on-error-container);
  }

  /* Success State */
  .success-card {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 16px;
    padding: 48px 32px;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-lg);
    background-color: var(--color-surface-container-lowest);
    text-align: center;
  }

  .success-icon-wrapper {
    width: 80px;
    height: 80px;
    border-radius: var(--radius-full);
    background-color: var(--color-surface-container);
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .success-heading {
    margin: 0;
    color: var(--color-on-surface);
  }

  .success-desc {
    margin: 0;
    color: var(--color-on-surface-variant);
    line-height: 1.5;
    max-width: 420px;
  }

  .restart-btn {
    display: inline-flex;
    align-items: center;
    justify-content: center;
    gap: 8px;
    padding: 12px 32px;
    margin-top: 8px;
    border: none;
    border-radius: var(--radius-md);
    background-color: var(--color-primary);
    color: var(--color-on-primary);
    cursor: pointer;
    font-family: inherit;
    font-weight: 600;
    transition: filter var(--transition-fast);
  }

  .restart-btn:hover {
    filter: brightness(1.1);
  }

  .restart-btn:active {
    filter: brightness(0.95);
  }
</style>
