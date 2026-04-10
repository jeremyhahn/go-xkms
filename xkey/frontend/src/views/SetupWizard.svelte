<script lang="ts">
  import { onMount, createEventDispatcher } from 'svelte';
  import { callBackend, callBackendWithError, callBackendVoid } from '$lib/api/backend';
  import {
    wizardState, wizardStep, wizardFlow, wizardProbe, wizardChoices,
    wizardOnboardingChoices, wizardApplying, wizardResult, wizardProgress,
    wizardDeploymentMode, wizardMaxStep, wizardIsQuickSetup,
    navigateStep, setChoice, setOnboardingChoice, setDeploymentMode,
    setProbe, setApplying, setResult, setError, resetWizard, setWizardFlow,
    setQuickSetup
  } from '$lib/stores/wizard';
  import type { EnvironmentProbe, SetupChoices, SetupResult, BarrierStrategyInfo, UserOnboardingChoices, DeploymentMode, StartupState, GeneratedPINs } from '$lib/types/setup';
  import { addNotification } from '$lib/stores/notifications';
  import Icon from '$lib/components/Icon.svelte';
  import XKeyBrandIcon from '$lib/components/XKeyBrandIcon.svelte';
  import LoadingSpinner from '$lib/components/LoadingSpinner.svelte';
  import {
    mdiKey, mdiCheck, mdiAlert, mdiArrowLeft, mdiArrowRight,
    mdiRocketLaunchOutline, mdiChip, mdiShieldLockOutline, mdiInformation,
    mdiAccount, mdiShieldKey, mdiAccountMultiple, mdiContentCopy, mdiEye, mdiEyeOff
  } from '$lib/utils/icons';

  export let mode: string = '';

  const dispatch = createEventDispatcher();

  let confirmPassphrase = '';
  let confirmMasterPW = '';
  let confirmBarrierPW = '';
  let confirmSoPin = '';
  let confirmUserPin = '';
  let confirmUserPinOnboarding = '';
  let securityError = '';
  let onboardingError = '';
  let policyData: Record<string, any> | null = null;

  // Quick setup state
  let showSOPin = false;
  let showUserPin = false;
  let soPinCopied = false;
  let userPinCopied = false;
  let soPinTimer = 0;
  let userPinTimer = 0;
  let soPinTimerInterval: ReturnType<typeof setInterval> | null = null;
  let userPinTimerInterval: ReturnType<typeof setInterval> | null = null;
  let quickSetupAcknowledged = false;

  /** Labels for personal setup backend steps (must match setupTotalSteps in Go). */
  const setupStepLabels = [
    'Creating encrypted storage',
    'Initializing built-in encryption',
    'Initializing data directory',
    'Creating platform policy',
    'Configuring PINs',
    'Provisioning TPM keys',
    'Initializing platform key store',
    'Configuring password protection',
    'Configuring auto-unseal',
    'Saving configuration',
  ];

  /** Labels for SO provisioning backend steps. */
  const soProvisioningLabels = [
    'Initializing built-in encryption',
    'Initializing data directory',
    'Configuring SO PIN',
    'Provisioning TPM keys',
    'Initializing platform key store',
    'Writing security policy',
    'Computing policy integrity HMAC',
  ];

  /** Labels for user onboarding backend steps. */
  const onboardingLabels = [
    'Verifying SO PIN',
    'Configuring User PIN',
    'Initializing encrypted storage',
    'Saving configuration',
  ];

  $: step = $wizardStep;
  $: flow = $wizardFlow;
  $: probe = $wizardProbe;
  $: choices = $wizardChoices;
  $: onboardingChoices = $wizardOnboardingChoices;
  $: applying = $wizardApplying;
  $: result = $wizardResult;
  $: progress = $wizardProgress;
  $: error = $wizardState.error;
  $: passphraseMatch = choices.storage_passphrase === confirmPassphrase;
  $: masterPWMatch = choices.master_password === confirmMasterPW;
  $: barrierPWMatch = choices.barrier_password === confirmBarrierPW;
  $: soPinValid = choices.so_pin.length >= 6;
  $: userPinValid = choices.user_pin.length >= 6;
  $: soPinMatch = choices.so_pin === confirmSoPin;
  $: userPinMatch = choices.user_pin === confirmUserPin;
  $: canProceedStep3 = soPinValid && userPinValid;

  // Onboarding validations
  $: onboardingSoPinValid = onboardingChoices.so_pin.length >= 6;
  $: onboardingUserPinValid = onboardingChoices.user_pin.length >= 6;
  $: onboardingUserPinMatch = onboardingChoices.user_pin === confirmUserPinOnboarding;

  $: isQuickSetup = $wizardIsQuickSetup;
  $: steps = getStepsForFlow($wizardFlow, choices.deployment_mode, isQuickSetup);

  /** Return the active progress labels for the current flow and deployment mode. */
  $: activeProgressLabels = getProgressLabels(flow, choices.deployment_mode);

  function getStepsForFlow(flow: string, deploymentMode: string, quickSetup: boolean = false) {
    if (flow === 'user_onboarding') {
      return [
        { num: 1, label: 'Welcome' },
        { num: 2, label: 'User PIN' },
        { num: 3, label: 'Complete' },
      ];
    }
    if (quickSetup && deploymentMode === 'personal') {
      return [
        { num: 1, label: 'Welcome' },
        { num: 2, label: 'Deployment' },
        { num: 4, label: 'Credentials' },
        { num: 6, label: 'Summary' },
      ];
    }
    if (deploymentMode === 'enterprise') {
      return [
        { num: 1, label: 'Welcome' },
        { num: 2, label: 'Deployment' },
        { num: 3, label: 'Policy' },
        { num: 4, label: 'Storage' },
        { num: 5, label: 'TPM' },
        { num: 6, label: 'Summary' },
      ];
    }
    // Personal mode (or deployment not yet chosen - shows first 2)
    return [
      { num: 1, label: 'Welcome' },
      { num: 2, label: 'Deployment' },
      { num: 3, label: 'Mode' },
      { num: 4, label: 'Security' },
      { num: 5, label: 'Storage' },
      { num: 6, label: 'Summary' },
    ];
  }

  function getProgressLabels(flow: string, deploymentMode: string): string[] {
    if (flow === 'user_onboarding') return onboardingLabels;
    if (deploymentMode === 'enterprise') return soProvisioningLabels;
    return setupStepLabels;
  }

  async function probeEnvironment(): Promise<void> {
    const env = await callBackend<EnvironmentProbe>('SetupWizardService', 'ProbeEnvironment');
    if (env) {
      setProbe(env);
      if (env.server_address) {
        setChoice('server_address', env.server_address);
      }
      // Default password store to TPM if available or device exists
      if (env.tpm_available || env.tpm_device_exists) {
        setChoice('password_store_mode', 'tpm_sealed');
        setChoice('tpm_seal_passwords', true);
      } else {
        setChoice('password_store_mode', 'aes_software');
        setChoice('use_user_pin_as_master', true);
      }
      // Default storage type to barrier (cross-platform)
      setChoice('storage_type', 'barrier');
    }
  }

  async function loadPolicy(): Promise<void> {
    const data = await callBackend<Record<string, any>>('SetupWizardService', 'GetPolicy');
    if (data) {
      policyData = data;
    }
  }

  async function quickSetup(): Promise<void> {
    setQuickSetup(true);
    // DO NOT force hierarchy auth - let user decide. The PINManager works with
    // software backends and does not require TPM hierarchy authorization.
    // Setting hierarchy auth locks the TPM and requires a TPM clear to recover.
    // Generate PINs from the backend
    const pins = await callBackend<GeneratedPINs>('SetupWizardService', 'GenerateSetupPINs');
    if (pins) {
      setChoice('so_pin', pins.so_pin);
      setChoice('user_pin', pins.user_pin);
    }
    // Auto-select sealer backend based on TPM availability
    if (probe && (probe.tpm_available || probe.tpm_device_exists)) {
      setChoice('sealer_backend', 'tpm2');
    } else {
      setChoice('sealer_backend', 'software');
    }
    if (choices.deployment_mode === 'personal') {
      // Deployment already chosen, skip to credentials step
      navigateStep(4);
    } else {
      // Need to choose deployment mode first
      navigateStep(2);
    }
  }

  function startClipboardTimer(which: 'so' | 'user'): void {
    const timeout = 30;
    if (which === 'so') {
      if (soPinTimerInterval) clearInterval(soPinTimerInterval);
      soPinCopied = true;
      soPinTimer = timeout;
      soPinTimerInterval = setInterval(() => {
        soPinTimer--;
        if (soPinTimer <= 0) {
          soPinCopied = false;
          if (soPinTimerInterval) clearInterval(soPinTimerInterval);
          soPinTimerInterval = null;
          callBackendVoid('ClipboardService', 'ClearClipboard');
        }
      }, 1000);
    } else {
      if (userPinTimerInterval) clearInterval(userPinTimerInterval);
      userPinCopied = true;
      userPinTimer = timeout;
      userPinTimerInterval = setInterval(() => {
        userPinTimer--;
        if (userPinTimer <= 0) {
          userPinCopied = false;
          if (userPinTimerInterval) clearInterval(userPinTimerInterval);
          userPinTimerInterval = null;
          callBackendVoid('ClipboardService', 'ClearClipboard');
        }
      }, 1000);
    }
  }

  async function copyPin(which: 'so' | 'user'): Promise<void> {
    const pin = which === 'so' ? choices.so_pin : choices.user_pin;
    const ok = await callBackendVoid('ClipboardService', 'CopyWithClear', pin);
    if (!ok) {
      // Fallback to browser clipboard API.
      try {
        await navigator.clipboard.writeText(pin);
      } catch {
        // If all clipboard methods fail, show a notification.
        addNotification('error', 'Failed to copy to clipboard. No clipboard tool available.');
        return;
      }
    }
    startClipboardTimer(which);
  }

  function nextStep(): void {
    // Reset quick setup flag when using normal flow from step 1.
    // This ensures that if user clicked Quick Setup, went back, then clicked Next,
    // they get the full manual setup flow instead of the abbreviated quick setup flow.
    if (step === 1) {
      setQuickSetup(false);
    }
    navigateStep(step + 1);
  }

  function prevStep(): void {
    resetConfirmFields();
    if (isQuickSetup && choices.deployment_mode === 'personal') {
      // Quick setup: 1 → 2 → 4 → 6
      if (step === 4) { navigateStep(2); return; }
      if (step === 6) { navigateStep(4); return; }
    }
    navigateStep(step - 1);
  }

  function nextStepSecurity(): void {
    if (!soPinValid) {
      securityError = 'SO PIN is required (minimum 6 characters)';
      return;
    }
    if (!confirmSoPin || !soPinMatch) {
      securityError = 'Please confirm your SO PIN';
      return;
    }
    if (!userPinValid) {
      securityError = 'User PIN is required (minimum 6 characters)';
      return;
    }
    if (!confirmUserPin || !userPinMatch) {
      securityError = 'Please confirm your User PIN';
      return;
    }
    securityError = '';
    nextStep();
  }

  function nextStepEnterprisePolicy(): void {
    if (!soPinValid) {
      securityError = 'SO PIN is required (minimum 6 characters)';
      return;
    }
    if (!confirmSoPin || !soPinMatch) {
      securityError = 'Please confirm your SO PIN';
      return;
    }
    securityError = '';
    nextStep();
  }

  function resetConfirmFields(): void {
    confirmSoPin = '';
    confirmUserPin = '';
  }

  function selectDeploymentMode(dm: DeploymentMode): void {
    resetConfirmFields();
    setDeploymentMode(dm);
    if (isQuickSetup && dm === 'personal') {
      navigateStep(4);
    } else {
      nextStep();
    }
  }

  function selectPasswordStoreMode(pwMode: string): void {
    setChoice('password_store_mode', pwMode);
    if (pwMode === 'tpm_sealed') {
      setChoice('tpm_seal_passwords', true);
    } else {
      setChoice('tpm_seal_passwords', false);
    }
  }

  /** Format sealer backend for display. */
  function sealerBackendLabel(backend: string): string {
    if (!backend) {
      const dflt = probe?.available_sealers?.find(s => s.is_default && s.available);
      return dflt ? `${dflt.label} (Auto)` : 'Auto';
    }
    const info = probe?.available_sealers?.find(s => s.id === backend);
    return info ? info.label : backend;
  }

  /** Format password store mode for display. */
  function passwordStoreModeLabel(pwMode: string): string {
    if (pwMode === 'tpm_sealed') return 'TPM-Sealed';
    if (pwMode === 'aes_software') return 'Software AES-256';
    return 'None';
  }

  /** Return a human-readable label for the barrier strategy that will be used.
   *  Respects the user's sealer_backend choice, falling back to probe auto-detection. */
  function barrierStrategyLabel(): string {
    // When the user (or quickSetup) has explicitly chosen a sealer backend,
    // the barrier will use the same backend — show its label.
    if (choices.sealer_backend === 'tpm2') return 'TPM 2.0 Hardware';
    if (choices.sealer_backend === 'pkcs11') return 'PKCS#11 Hardware';
    if (choices.sealer_backend === 'software') return 'Software (AES-256-GCM)';

    // No explicit choice: auto-detect from probe, preferring hardware.
    const best = probe?.barrier_strategies?.find(s => s.available && s.hardware_backed);
    if (best) return best.label;
    const sw = probe?.barrier_strategies?.find(s => s.available);
    if (sw) return sw.label;
    return 'AES-256-GCM';
  }

  async function applySetup(): Promise<void> {
    setApplying(true);
    const payload = { ...choices, quick_setup: isQuickSetup };
    const { result: res, error: err } = await callBackendWithError<SetupResult>('SetupWizardService', 'ApplySetup', payload);
    if (res) {
      setResult(res);
    } else {
      setError(err || 'Failed to apply setup');
    }
  }

  async function applySOProvisioning(): Promise<void> {
    setApplying(true);
    const { result: res, error: err } = await callBackendWithError<SetupResult>('SetupWizardService', 'ApplySOProvisioning', choices);
    if (res) {
      setResult(res);
    } else {
      setError(err || 'Failed to apply SO provisioning');
    }
  }

  async function applyUserOnboarding(): Promise<void> {
    if (!onboardingSoPinValid) {
      onboardingError = 'SO PIN is required (minimum 6 characters)';
      return;
    }
    if (!onboardingUserPinValid) {
      onboardingError = 'User PIN is required (minimum 6 characters)';
      return;
    }
    if (!onboardingUserPinMatch) {
      onboardingError = 'User PINs do not match';
      return;
    }
    onboardingError = '';
    setApplying(true);
    const { result: res, error: err } = await callBackendWithError<SetupResult>('SetupWizardService', 'ApplyUserOnboarding', onboardingChoices);
    if (res) {
      setResult(res);
    } else {
      setError(err || 'Failed to apply user onboarding');
    }
  }

  async function skipSetup(): Promise<void> {
    clearWizardClipboard();
    await callBackend<void>('SetupWizardService', 'SkipSetup');
    dispatch('complete');
  }

  function finish(): void {
    clearWizardClipboard();
    resetWizard();
    dispatch('complete');
  }

  /** Clear any PINs remaining on the clipboard and stop visual timers. */
  function clearWizardClipboard(): void {
    if (soPinTimerInterval) { clearInterval(soPinTimerInterval); soPinTimerInterval = null; }
    if (userPinTimerInterval) { clearInterval(userPinTimerInterval); userPinTimerInterval = null; }
    callBackendVoid('ClipboardService', 'ClearClipboard');
  }

  onMount(() => {
    if (mode === 'user_onboarding') {
      setWizardFlow('user_onboarding');
      loadPolicy();
    }
    probeEnvironment();
  });
</script>

<div class="wizard-overlay">
  <div class="wizard-container">
    <!-- Progress indicator -->
    <div class="wizard-progress">
      {#each steps as s, i}
        <div class="progress-step" class:active={step === s.num} class:completed={step > s.num}>
          <div class="step-circle">
            {#if step > s.num}
              <Icon path={mdiCheck} size={14} />
            {:else}
              {i + 1}
            {/if}
          </div>
          <span class="step-label text-label-small">{s.label}</span>
        </div>
        {#if i < steps.length - 1}
          <div class="progress-line" class:filled={step > s.num}></div>
        {/if}
      {/each}
    </div>

    <!-- Step content -->
    <div class="wizard-content">
      {#if result}
        <!-- Success / Result screen -->
        <div class="step-content result-screen">
          <div class="result-icon" class:success={result.success} class:has-errors={!result.success}>
            <Icon path={result.success ? mdiCheck : mdiAlert} size={48} />
          </div>
          <h2 class="text-headline-medium">
            {#if flow === 'user_onboarding'}
              {result.success ? 'Onboarding Complete!' : 'Onboarding Completed with Issues'}
            {:else if choices.deployment_mode === 'enterprise'}
              {result.success ? 'Provisioning Complete!' : 'Provisioning Completed with Issues'}
            {:else}
              {result.success ? 'Setup Complete!' : 'Setup Completed with Issues'}
            {/if}
          </h2>
          {#if result.errors.length > 0}
            <div class="result-messages errors">
              <h3 class="text-title-small">Errors</h3>
              {#each result.errors as err}
                <p class="text-body-medium">{err}</p>
              {/each}
            </div>
          {/if}
          {#if result.warnings.length > 0}
            <div class="result-messages warnings">
              <h3 class="text-title-small">Warnings</h3>
              {#each result.warnings as warn}
                <p class="text-body-medium">{warn}</p>
              {/each}
            </div>
          {/if}
          <button class="btn btn-primary" on:click={finish}>
            <Icon path={mdiRocketLaunchOutline} size={18} />
            Get Started
          </button>
        </div>

      <!-- ========== USER ONBOARDING FLOW ========== -->
      {:else if flow === 'user_onboarding' && step === 1}
        <!-- Onboarding Welcome -->
        <div class="step-content">
          <div class="welcome-icon">
            <XKeyBrandIcon size={80} />
          </div>
          <h2 class="text-headline-medium">User Onboarding</h2>
          <p class="text-body-large">Your organization's Security Officer has configured this device. Complete the steps below to begin using xKey.</p>

          <div class="info-banner info">
            <Icon path={mdiInformation} size={18} />
            <span class="text-body-medium">This device is managed by your organization. Security policy has been pre-configured.</span>
          </div>

          {#if policyData}
            <div class="section-group">
              <div class="section-header">
                <Icon path={mdiShieldLockOutline} size={20} />
                <span class="text-title-medium">Policy Summary</span>
              </div>
              <div class="summary-table">
                {#if policyData.organization_name}
                  <div class="summary-row">
                    <span class="summary-label text-label-medium">Organization</span>
                    <span class="summary-value text-body-medium">{policyData.organization_name}</span>
                  </div>
                {/if}
                {#if policyData.require_encrypted_storage !== undefined}
                  <div class="summary-row">
                    <span class="summary-label text-label-medium">Encrypted Storage</span>
                    <span class="summary-value text-body-medium">{policyData.require_encrypted_storage ? 'Required' : 'Optional'}</span>
                  </div>
                {/if}
                {#if policyData.require_tpm !== undefined}
                  <div class="summary-row">
                    <span class="summary-label text-label-medium">TPM</span>
                    <span class="summary-value text-body-medium">{policyData.require_tpm ? 'Required' : 'Optional'}</span>
                  </div>
                {/if}
                {#if policyData.min_pin_length}
                  <div class="summary-row">
                    <span class="summary-label text-label-medium">Minimum PIN Length</span>
                    <span class="summary-value text-body-medium">{policyData.min_pin_length} characters</span>
                  </div>
                {/if}
                {#if policyData.pin_max_attempts}
                  <div class="summary-row">
                    <span class="summary-label text-label-medium">Max Failed PIN Attempts</span>
                    <span class="summary-value text-body-medium">{policyData.pin_max_attempts}</span>
                  </div>
                {/if}
              </div>
            </div>
          {/if}

          <div class="step-actions">
            <button class="btn btn-primary" on:click={nextStep}>Begin Onboarding</button>
          </div>
        </div>

      {:else if flow === 'user_onboarding' && step === 2}
        <!-- Set User PIN -->
        <div class="step-content">
          <h2 class="text-headline-medium">Set User PIN</h2>
          <p class="text-body-large">Set your personal PIN to unlock xKey.</p>

          {#if onboardingError}
            <div class="info-banner warning">
              <Icon path={mdiAlert} size={18} />
              <span class="text-body-medium">{onboardingError}</span>
            </div>
          {/if}

          <div class="section-group">
            <div class="section-header">
              <Icon path={mdiShieldKey} size={20} />
              <span class="text-title-medium">SO PIN Verification</span>
              <span class="badge badge-success text-label-small">Required</span>
            </div>
            <div class="security-fields">
              <label class="field-label text-label-medium" for="wizard-onboarding-so-pin">Security Officer PIN</label>
              <input id="wizard-onboarding-so-pin" type="password" class="field-input" class:field-input-error={onboardingChoices.so_pin.length > 0 && !onboardingSoPinValid} placeholder="Enter the SO PIN provided by your administrator" value={onboardingChoices.so_pin} on:input={(e) => { setOnboardingChoice('so_pin', e.currentTarget.value); onboardingError = ''; }} />
              <span class="field-help text-body-small">Enter the SO PIN provided by your administrator to authorize this onboarding.</span>
            </div>
          </div>

          <div class="section-group">
            <div class="section-header">
              <Icon path={mdiShieldLockOutline} size={20} />
              <span class="text-title-medium">User PIN</span>
              <span class="badge badge-success text-label-small">Required</span>
            </div>
            <div class="security-fields">
              <label class="field-label text-label-medium" for="wizard-onboarding-user-pin">New User PIN</label>
              <input id="wizard-onboarding-user-pin" type="password" class="field-input" class:field-input-error={onboardingChoices.user_pin.length > 0 && !onboardingUserPinValid} placeholder="Minimum 6 characters" value={onboardingChoices.user_pin} on:input={(e) => { setOnboardingChoice('user_pin', e.currentTarget.value); onboardingError = ''; }} />
              <span class="field-help text-body-small">Choose a personal PIN to unlock FIDO2, PKCS#11, password store, and encrypted storage.</span>

              <label class="field-label text-label-medium" for="wizard-onboarding-user-pin-confirm">Confirm User PIN</label>
              <input id="wizard-onboarding-user-pin-confirm" type="password" class="field-input" placeholder="Re-enter your User PIN" bind:value={confirmUserPinOnboarding} on:input={() => { onboardingError = ''; }} />
              {#if confirmUserPinOnboarding && !onboardingUserPinMatch}
                <span class="field-error text-body-small">PINs do not match</span>
              {/if}
            </div>
          </div>

          <div class="section-group">
            <div class="section-header">
              <Icon path={mdiShieldLockOutline} size={20} />
              <span class="text-title-medium">Encryption Password</span>
            </div>
            <div class="security-fields">
              <label class="field-label text-label-medium" for="wizard-onboarding-barrier-pw">Barrier Password (Optional)</label>
              <input id="wizard-onboarding-barrier-pw" type="password" class="field-input" placeholder="Leave blank to use your User PIN" value={onboardingChoices.barrier_password} on:input={(e) => setOnboardingChoice('barrier_password', e.currentTarget.value)} />
              <span class="field-help text-body-small">If left blank, your User PIN will be used as the encryption password for sealed storage.</span>
            </div>
          </div>

          <div class="step-actions">
            <button class="btn btn-text" on:click={prevStep}>Back</button>
            <button class="btn btn-primary" on:click={nextStep}>Next</button>
          </div>
        </div>

      {:else if flow === 'user_onboarding' && step === 3}
        <!-- Onboarding Apply / Complete -->
        <div class="step-content">
          <h2 class="text-headline-medium">Complete Onboarding</h2>
          <p class="text-body-large">Review and apply your configuration.</p>

          <div class="summary-table">
            <div class="summary-row">
              <span class="summary-label text-label-medium">SO PIN</span>
              <span class="summary-value text-body-medium">{onboardingChoices.so_pin ? 'Provided' : 'Not set'}</span>
              <button class="btn-edit text-label-small" on:click={() => navigateStep(2)}>Edit</button>
            </div>
            <div class="summary-row">
              <span class="summary-label text-label-medium">User PIN</span>
              <span class="summary-value text-body-medium">{onboardingChoices.user_pin ? 'Configured' : 'Not set'}</span>
              <button class="btn-edit text-label-small" on:click={() => navigateStep(2)}>Edit</button>
            </div>
            <div class="summary-row">
              <span class="summary-label text-label-medium">Barrier Password</span>
              <span class="summary-value text-body-medium">{onboardingChoices.barrier_password ? 'Custom password set' : 'Using User PIN'}</span>
              <button class="btn-edit text-label-small" on:click={() => navigateStep(2)}>Edit</button>
            </div>
          </div>

          {#if error}
            <div class="info-banner warning" style="margin-top: 12px;">
              <Icon path={mdiAlert} size={18} />
              <span class="text-body-medium">{error}</span>
            </div>
          {/if}

          {#if applying && progress}
            <div class="setup-progress">
              {#each onboardingLabels as label, i}
                {@const stepNum = i + 1}
                {@const isCompleted = stepNum < progress.step}
                {@const isActive = stepNum === progress.step}
                <div class="setup-progress-step" class:completed={isCompleted} class:active={isActive}>
                  <div class="setup-progress-indicator">
                    {#if isCompleted}
                      <div class="setup-progress-check">
                        <Icon path={mdiCheck} size={12} />
                      </div>
                    {:else if isActive}
                      <LoadingSpinner size={20} />
                    {:else}
                      <div class="setup-progress-dot"></div>
                    {/if}
                  </div>
                  <span class="setup-progress-label text-body-medium">{label}</span>
                </div>
              {/each}
              <div class="setup-progress-bar">
                <div class="setup-progress-fill" style="width: {Math.round((progress.step / progress.total_steps) * 100)}%"></div>
              </div>
              <span class="setup-progress-pct text-label-small">{Math.round((progress.step / progress.total_steps) * 100)}%</span>
            </div>
          {:else if applying}
            <div class="setup-progress">
              <LoadingSpinner size={24} />
              <span class="text-body-medium">Preparing...</span>
            </div>
          {/if}

          <div class="step-actions">
            <button class="btn btn-text" on:click={prevStep} disabled={applying}>Back</button>
            <button class="btn btn-primary" on:click={applyUserOnboarding} disabled={applying}>
              {#if applying}
                Applying...
              {:else}
                Complete Onboarding
              {/if}
            </button>
          </div>
        </div>

      <!-- ========== SETUP FLOW: STEP 1 - WELCOME ========== -->
      {:else if flow === 'setup' && step === 1}
        <div class="step-content">
          <div class="welcome-icon">
            <XKeyBrandIcon size={80} />
          </div>
          <h2 class="text-headline-medium">Welcome to xKey</h2>
          <p class="text-body-large">Your personal key management system. This wizard will help you configure xKey for first use.</p>

          {#if probe}
            <div class="capability-cards">
              <div class="capability-card" class:available={probe.tpm_available || probe.tpm_device_exists}>
                <span class="cap-label text-label-medium">TPM 2.0</span>
                <span class="cap-status text-body-small">{probe.tpm_available ? 'Available' : probe.tpm_device_exists ? 'Detected' : 'Not detected'}</span>
              </div>
              <div class="capability-card" class:available={probe.luks_available}>
                <span class="cap-label text-label-medium">Encrypted Storage</span>
                <span class="cap-status text-body-small">{probe.luks_available ? 'Available' : 'Not available'}</span>
              </div>
              <div class="capability-card">
                <span class="cap-label text-label-medium">Platform</span>
                <span class="cap-status text-body-small">{probe.platform}</span>
              </div>
            </div>
          {/if}

          <div class="step-actions">
            <button class="btn btn-text" on:click={skipSetup}>Skip Setup</button>
            <button class="btn btn-outlined" on:click={quickSetup}>Quick Setup</button>
            <button class="btn btn-primary" on:click={nextStep}>Next</button>
          </div>
        </div>

      <!-- ========== SETUP FLOW: STEP 2 - DEPLOYMENT MODE ========== -->
      {:else if flow === 'setup' && step === 2}
        <div class="step-content">
          <h2 class="text-headline-medium">Deployment Mode</h2>
          <p class="text-body-large">Choose how xKey will be managed.</p>

          <div class="mode-options">
            <button class="mode-card" class:selected={choices.deployment_mode === 'personal'} on:click={() => selectDeploymentMode('personal')}>
              <div class="mode-card-icon">
                <Icon path={mdiAccount} size={28} />
              </div>
              <div class="mode-info">
                <span class="text-title-medium">Personal</span>
                <span class="text-body-small">Single-user setup. All keys and credentials are managed locally with your own PINs.</span>
              </div>
            </button>
            <button class="mode-card" class:selected={choices.deployment_mode === 'enterprise'} on:click={() => selectDeploymentMode('enterprise')}>
              <div class="mode-card-icon">
                <Icon path={mdiShieldKey} size={28} />
              </div>
              <div class="mode-info">
                <span class="text-title-medium">Enterprise</span>
                <span class="text-body-small">Managed deployment. A Security Officer configures security policy, then users onboard separately.</span>
              </div>
            </button>
          </div>

          <div class="step-actions">
            <button class="btn btn-text" on:click={prevStep}>Back</button>
          </div>
        </div>

      <!-- ========== PERSONAL FLOW: STEP 3 - OPERATING MODE ========== -->
      {:else if flow === 'setup' && step === 3 && choices.deployment_mode === 'personal'}
        <div class="step-content">
          <h2 class="text-headline-medium">Operating Mode</h2>
          <p class="text-body-large">Choose how xKey should operate.</p>

          <div class="mode-options">
            <label class="mode-card" class:selected={choices.mode === 'standalone'}>
              <input type="radio" name="mode" value="standalone" checked={choices.mode === 'standalone'} on:change={() => setChoice('mode', 'standalone')} />
              <div class="mode-info">
                <span class="text-title-medium">Standalone</span>
                <span class="text-body-small">All keys and credentials stored locally. No server needed.</span>
              </div>
            </label>
            <label class="mode-card" class:selected={choices.mode === 'server'}>
              <input type="radio" name="mode" value="server" checked={choices.mode === 'server'} on:change={() => setChoice('mode', 'server')} />
              <div class="mode-info">
                <span class="text-title-medium">Server</span>
                <span class="text-body-small">Connect to an xkmsd server for centralized key management.</span>
              </div>
            </label>
            <label class="mode-card" class:selected={choices.mode === 'both'}>
              <input type="radio" name="mode" value="both" checked={choices.mode === 'both'} on:change={() => setChoice('mode', 'both')} />
              <div class="mode-info">
                <span class="text-title-medium">Both</span>
                <span class="text-body-small">Local storage with server connection for remote operations.</span>
              </div>
            </label>
          </div>

          {#if choices.mode === 'server' || choices.mode === 'both'}
            <div class="server-config">
              <label class="field-label text-label-medium" for="wizard-server-address">Server Address</label>
              <input id="wizard-server-address" type="text" class="field-input" placeholder="localhost:9443" value={choices.server_address} on:input={(e) => setChoice('server_address', e.currentTarget.value)} />
              <label class="field-label text-label-medium" for="wizard-server-protocol">Protocol</label>
              <select id="wizard-server-protocol" class="field-input" value={choices.server_protocol} on:change={(e) => setChoice('server_protocol', e.currentTarget.value)}>
                <option value="grpc">gRPC</option>
                <option value="rest">REST</option>
                <option value="quic">QUIC</option>
                <option value="unix">Unix Socket</option>
                <option value="mcp">MCP</option>
              </select>
            </div>
          {/if}

          <div class="step-actions">
            <button class="btn btn-text" on:click={prevStep}>Back</button>
            <button class="btn btn-primary" on:click={nextStep}>Next</button>
          </div>
        </div>

      <!-- ========== ENTERPRISE FLOW: STEP 3 - SECURITY POLICY ========== -->
      {:else if flow === 'setup' && step === 3 && choices.deployment_mode === 'enterprise'}
        <div class="step-content">
          <h2 class="text-headline-medium">Security Policy</h2>
          <p class="text-body-large">Configure the organization's security policy for managed devices.</p>

          {#if securityError}
            <div class="info-banner warning">
              <Icon path={mdiAlert} size={18} />
              <span class="text-body-medium">{securityError}</span>
            </div>
          {/if}

          <!-- Organization -->
          <div class="section-group">
            <div class="section-header">
              <Icon path={mdiAccountMultiple} size={20} />
              <span class="text-title-medium">Organization</span>
            </div>
            <div class="security-fields">
              <label class="field-label text-label-medium" for="wizard-org-name">Organization Name</label>
              <input id="wizard-org-name" type="text" class="field-input" placeholder="Your organization name" value={choices.organization_name || ''} on:input={(e) => setChoice('organization_name', e.currentTarget.value)} />
            </div>
          </div>

          <!-- PIN Policy -->
          <div class="section-group">
            <div class="section-header">
              <Icon path={mdiShieldLockOutline} size={20} />
              <span class="text-title-medium">PIN Policy</span>
              <span class="badge badge-success text-label-small">Required</span>
            </div>
            <div class="security-fields">
              <label class="field-label text-label-medium" for="wizard-enterprise-so-pin">Security Officer PIN</label>
              <input id="wizard-enterprise-so-pin" type="password" class="field-input" class:field-input-error={choices.so_pin.length > 0 && !soPinValid} placeholder="Minimum 6 characters (required)" value={choices.so_pin} on:input={(e) => { setChoice('so_pin', e.currentTarget.value); securityError = ''; }} />
              <span class="field-help text-body-small">Required. The SO PIN controls all administrative operations and policy management.</span>

              <label class="field-label text-label-medium" for="wizard-enterprise-so-pin-confirm">Confirm SO PIN</label>
              <input id="wizard-enterprise-so-pin-confirm" type="password" class="field-input" placeholder="Re-enter your SO PIN" bind:value={confirmSoPin} on:input={() => { securityError = ''; }} />
              {#if confirmSoPin && !soPinMatch}
                <span class="field-error text-body-small">PINs do not match</span>
              {/if}

              <label class="field-label text-label-medium" for="wizard-enterprise-min-pin">Minimum PIN Length for Users</label>
              <input id="wizard-enterprise-min-pin" type="number" class="field-input" min="6" max="32" value={choices.min_pin_length || 6} on:input={(e) => setChoice('min_pin_length', parseInt(e.currentTarget.value) || 6)} />
              <span class="field-help text-body-small">Minimum number of characters required for user PINs (default: 6).</span>

              <label class="field-label text-label-medium" for="wizard-enterprise-pin-max-attempts">Maximum Failed PIN Attempts</label>
              <input id="wizard-enterprise-pin-max-attempts" type="number" class="field-input" min="1" max="20" value={choices.pin_max_attempts || 5} on:input={(e) => setChoice('pin_max_attempts', parseInt(e.currentTarget.value) || 5)} />
              <span class="field-help text-body-small">Number of failed PIN attempts before lockout (default: 5).</span>
            </div>
          </div>

          <!-- Security Requirements -->
          <div class="section-group">
            <div class="section-header">
              <Icon path={mdiShieldLockOutline} size={20} />
              <span class="text-title-medium">Security Requirements</span>
            </div>
            <div class="security-fields">
              <label class="toggle-row">
                <input type="checkbox" checked={choices.require_encrypted_storage ?? true} on:change={(e) => setChoice('require_encrypted_storage', e.currentTarget.checked)} />
                <span class="text-body-large">Require encrypted storage</span>
              </label>
              <span class="field-help text-body-small">All user data must be stored in encrypted volumes.</span>

              <label class="toggle-row">
                <input type="checkbox" checked={choices.require_tpm ?? false} on:change={(e) => setChoice('require_tpm', e.currentTarget.checked)} />
                <span class="text-body-large">Require TPM</span>
              </label>
              <span class="field-help text-body-small">Device must have a TPM 2.0 module for hardware-backed security.</span>

              <label class="toggle-row">
                <input type="checkbox" checked={choices.require_platform_policy ?? false} on:change={(e) => setChoice('require_platform_policy', e.currentTarget.checked)} />
                <span class="text-body-large">Require platform policy</span>
              </label>
              <span class="field-help text-body-small">Enforce platform integrity measurement via PCR policy.</span>
            </div>
          </div>

          <!-- User Permissions -->
          <div class="section-group">
            <div class="section-header">
              <Icon path={mdiAccount} size={20} />
              <span class="text-title-medium">User Permissions</span>
            </div>
            <div class="security-fields">
              <label class="toggle-row">
                <input type="checkbox" checked={choices.allow_auto_unseal ?? true} on:change={(e) => setChoice('allow_auto_unseal', e.currentTarget.checked)} />
                <span class="text-body-large">Users can configure auto-unseal</span>
              </label>

              <label class="toggle-row">
                <input type="checkbox" checked={choices.allow_theme ?? true} on:change={(e) => setChoice('allow_theme', e.currentTarget.checked)} />
                <span class="text-body-large">Users can configure theme</span>
              </label>

              <label class="toggle-row">
                <input type="checkbox" checked={choices.allow_trust_store ?? false} on:change={(e) => setChoice('allow_trust_store', e.currentTarget.checked)} />
                <span class="text-body-large">Users can manage trust store</span>
              </label>

              <label class="toggle-row">
                <input type="checkbox" checked={choices.allow_audit_log ?? true} on:change={(e) => setChoice('allow_audit_log', e.currentTarget.checked)} />
                <span class="text-body-large">Users can view audit log</span>
              </label>

              <label class="toggle-row">
                <input type="checkbox" checked={choices.allow_sealed_data ?? true} on:change={(e) => setChoice('allow_sealed_data', e.currentTarget.checked)} />
                <span class="text-body-large">Users can manage sealed data</span>
              </label>

              <label class="toggle-row">
                <input type="checkbox" checked={choices.allow_change_pin ?? true} on:change={(e) => setChoice('allow_change_pin', e.currentTarget.checked)} />
                <span class="text-body-large">Users can change own PIN</span>
              </label>
            </div>
          </div>

          <!-- Browser Extension -->
          <div class="section-group">
            <div class="section-header">
              <Icon path={mdiShieldLockOutline} size={20} />
              <span class="text-title-medium">Browser Extension</span>
            </div>
            <div class="security-fields">
              <label class="toggle-row">
                <input type="checkbox" checked={choices.allow_extension ?? true} on:change={(e) => setChoice('allow_extension', e.currentTarget.checked)} />
                <span class="text-body-large">Allow browser extension</span>
              </label>
              <span class="field-help text-body-small">Users can connect the xKey browser extension.</span>

              <label class="toggle-row">
                <input type="checkbox" checked={choices.force_extension_auth ?? true} on:change={(e) => setChoice('force_extension_auth', e.currentTarget.checked)} />
                <span class="text-body-large">Force CTAP2 authentication</span>
              </label>
              <span class="field-help text-body-small">Require PIN and touch before filling credentials.</span>

              <label class="toggle-row">
                <input type="checkbox" checked={choices.force_extension_pairing ?? true} on:change={(e) => setChoice('force_extension_pairing', e.currentTarget.checked)} />
                <span class="text-body-large">Require extension pairing</span>
              </label>
              <span class="field-help text-body-small">Extension must be paired with a verification code.</span>

              <label class="toggle-row">
                <input type="checkbox" checked={choices.force_extension_audit ?? true} on:change={(e) => setChoice('force_extension_audit', e.currentTarget.checked)} />
                <span class="text-body-large">Force audit logging</span>
              </label>
              <span class="field-help text-body-small">All extension operations are logged.</span>

              <label class="toggle-row">
                <input type="checkbox" checked={choices.allow_configure_extension ?? true} on:change={(e) => setChoice('allow_configure_extension', e.currentTarget.checked)} />
                <span class="text-body-large">Users can configure extension settings</span>
              </label>
              <span class="field-help text-body-small">Allow users to change extension behavior.</span>
            </div>
          </div>

          <!-- FIDO2 Authenticator -->
          <div class="section-group">
            <div class="section-header">
              <Icon path={mdiKey} size={20} />
              <span class="text-title-medium">FIDO2 Authenticator</span>
            </div>
            <div class="security-fields">
              <label class="toggle-row">
                <input type="checkbox" checked={choices.fido2_require_user_presence ?? true} on:change={(e) => setChoice('fido2_require_user_presence', e.currentTarget.checked)} />
                <span class="text-body-large">Require user presence (touch)</span>
              </label>
              <span class="field-help text-body-small">Require physical touch confirmation for FIDO2 operations.</span>

              <label class="toggle-row">
                <input type="checkbox" checked={choices.fido2_user_intent_check ?? true} on:change={(e) => setChoice('fido2_user_intent_check', e.currentTarget.checked)} />
                <span class="text-body-large">Multi-key intent check</span>
              </label>
              <span class="field-help text-body-small">Show confirmation before entering PIN flow to allow choosing a different security key.</span>
            </div>
          </div>

          <div class="step-actions">
            <button class="btn btn-text" on:click={prevStep}>Back</button>
            <button class="btn btn-primary" on:click={nextStepEnterprisePolicy}>Next</button>
          </div>
        </div>

      <!-- ========== QUICK SETUP: STEP 4 - GENERATED CREDENTIALS ========== -->
      {:else if flow === 'setup' && step === 4 && isQuickSetup && choices.deployment_mode === 'personal'}
        <div class="step-content">
          <h2 class="text-headline-medium">Generated Credentials</h2>
          <p class="text-body-large">Your PINs have been securely generated and will be saved to the password store automatically.</p>

          <div class="info-banner info">
            <Icon path={mdiInformation} size={18} />
            <span class="text-body-small">Both the SO PIN and User PIN will be stored in the <strong>xKey</strong> folder of your password store during setup. You can view them there after setup completes.</span>
          </div>

          <div class="section-group">
            <div class="section-header">
              <Icon path={mdiShieldKey} size={20} />
              <span class="text-title-medium">Security Officer (SO) PIN</span>
              <span class="badge badge-success text-label-small">16 chars — auto-generated</span>
            </div>
            <p class="text-body-medium">Stored in password store → xKey folder. Required to change the User PIN.</p>
          </div>

          <div class="section-group">
            <div class="section-header">
              <Icon path={mdiShieldLockOutline} size={20} />
              <span class="text-title-medium">User PIN</span>
              <span class="badge badge-success text-label-small">12 chars — auto-generated</span>
            </div>
            <p class="text-body-medium">Stored in password store → xKey folder. Used to unlock the app.</p>
          </div>

          <label class="toggle-row acknowledge-row">
            <input type="checkbox" bind:checked={quickSetupAcknowledged} />
            <span class="text-body-large">I understand my PINs will be saved to the password store.</span>
          </label>

          <div class="step-actions">
            <button class="btn btn-text" on:click={prevStep}>Back</button>
            <button class="btn btn-primary" disabled={!quickSetupAcknowledged} on:click={() => navigateStep(6)}>Continue to Summary</button>
          </div>
        </div>

      <!-- ========== PERSONAL FLOW: STEP 4 - SECURITY ========== -->
      {:else if flow === 'setup' && step === 4 && choices.deployment_mode === 'personal'}
        <div class="step-content">
          <h2 class="text-headline-medium">Security</h2>
          <p class="text-body-large">Configure PINs, platform security, and password storage.</p>

          {#if securityError}
            <div class="info-banner warning">
              <Icon path={mdiAlert} size={18} />
              <span class="text-body-medium">{securityError}</span>
            </div>
          {/if}

          <!-- PIN Management (always visible, required) -->
          <div class="section-group">
            <div class="section-header">
              <Icon path={mdiShieldLockOutline} size={20} />
              <span class="text-title-medium">PIN Management</span>
              <span class="badge badge-success text-label-small">Required</span>
            </div>

            <div class="security-fields">
              <label class="field-label text-label-medium" for="wizard-so-pin">Security Officer PIN</label>
              <input id="wizard-so-pin" type="password" class="field-input" class:field-input-error={choices.so_pin.length > 0 && !soPinValid} placeholder="Minimum 6 characters (required)" value={choices.so_pin} on:input={(e) => { setChoice('so_pin', e.currentTarget.value); securityError = ''; }} />
              <span class="field-help text-body-small">Required. Controls admin operations and authorizes User PIN changes.</span>

              <label class="field-label text-label-medium" for="wizard-so-pin-confirm">Confirm SO PIN</label>
              <input id="wizard-so-pin-confirm" type="password" class="field-input" placeholder="Re-enter your SO PIN" bind:value={confirmSoPin} on:input={() => { securityError = ''; }} />
              {#if confirmSoPin && !soPinMatch}
                <span class="field-error text-body-small">PINs do not match</span>
              {/if}

              <label class="field-label text-label-medium" for="wizard-user-pin">User PIN</label>
              <input id="wizard-user-pin" type="password" class="field-input" class:field-input-error={choices.user_pin.length > 0 && !userPinValid} placeholder="Minimum 6 characters (required)" value={choices.user_pin} on:input={(e) => { setChoice('user_pin', e.currentTarget.value); securityError = ''; }} />
              <span class="field-help text-body-small">Required. Unlocks FIDO2, PKCS#11, password store, and encrypted storage.</span>

              <label class="field-label text-label-medium" for="wizard-user-pin-confirm">Confirm User PIN</label>
              <input id="wizard-user-pin-confirm" type="password" class="field-input" placeholder="Re-enter your User PIN" bind:value={confirmUserPin} on:input={() => { securityError = ''; }} />
              {#if confirmUserPin && !userPinMatch}
                <span class="field-error text-body-small">PINs do not match</span>
              {/if}

              <label class="toggle-row" style="margin-top: 12px;">
                <input type="checkbox" checked={choices.save_pins_to_store} on:change={(e) => setChoice('save_pins_to_store', e.currentTarget.checked)} />
                <span class="text-body-large">Save PINs to password store</span>
              </label>
              <span class="field-help text-body-small">Store the SO PIN and User PIN in the password store for easy retrieval. You can delete them later.</span>

              {#if choices.use_user_pin_as_master}
                <div class="info-banner info">
                  <Icon path={mdiInformation} size={18} />
                  <span class="text-body-small">Your User PIN will be used as the master password for all encrypted data.</span>
                </div>
              {/if}
            </div>
          </div>

          <!-- TPM 2.0 Section (conditional) -->
          {#if probe && (probe.tpm_available || probe.tpm_device_exists)}
            <div class="section-group">
              <div class="section-header">
                <Icon path={mdiChip} size={20} />
                <span class="text-title-medium">TPM 2.0</span>
                <span class="badge badge-success text-label-small">Detected</span>
              </div>

              <div class="security-fields">
                <label class="toggle-row">
                  <input type="checkbox" checked={choices.set_hierarchy_auth} on:change={(e) => setChoice('set_hierarchy_auth', e.currentTarget.checked)} />
                  <span class="text-body-large">Set TPM Hierarchy Authorization Passwords</span>
                </label>
                <span class="field-help text-body-small">Uses the SO PIN to set authorization passwords on the TPM Endorsement, Owner, and Lockout hierarchies. Leave unchecked to keep default (empty) hierarchy passwords.</span>
              </div>
            </div>
          {/if}

          <!-- Password Storage Mode -->
          <div class="section-group">
            <div class="section-header">
              <Icon path={mdiShieldLockOutline} size={20} />
              <span class="text-title-medium">Password Storage</span>
            </div>

            <div class="mode-options">
              {#if probe && (probe.tpm_available || probe.tpm_device_exists)}
                <label class="mode-card" class:selected={choices.password_store_mode === 'tpm_sealed'}>
                  <input type="radio" name="pw-store" value="tpm_sealed" checked={choices.password_store_mode === 'tpm_sealed'} on:change={() => selectPasswordStoreMode('tpm_sealed')} />
                  <div class="mode-info">
                    <span class="text-title-medium">TPM-Sealed (Recommended)</span>
                    <span class="text-body-small">Master key sealed to TPM with platform policy. Auto-unlocks when system boots with expected firmware configuration.</span>
                  </div>
                </label>
              {/if}
              <label class="mode-card" class:selected={choices.password_store_mode === 'aes_software'}>
                <input type="radio" name="pw-store" value="aes_software" checked={choices.password_store_mode === 'aes_software'} on:change={() => selectPasswordStoreMode('aes_software')} />
                <div class="mode-info">
                  <span class="text-title-medium">Software AES-256</span>
                  <span class="text-body-small">Encrypt with a master password using Argon2id key derivation. The encryption key is stored on disk and protected only by filesystem permissions. A TPM-sealed backend is strongly recommended for production use.</span>
                </div>
              </label>
              <label class="mode-card" class:selected={choices.password_store_mode === 'none'}>
                <input type="radio" name="pw-store" value="none" checked={choices.password_store_mode === 'none'} on:change={() => selectPasswordStoreMode('none')} />
                <div class="mode-info">
                  <span class="text-title-medium">None</span>
                  <span class="text-body-small">Passwords stored in plaintext. Not recommended.</span>
                </div>
              </label>
            </div>

            <!-- Inline master password for Software AES-256 -->
            {#if choices.password_store_mode === 'aes_software'}
              <div class="security-fields">
                <label class="toggle-row">
                  <input type="checkbox" checked={choices.use_user_pin_as_master} on:change={(e) => setChoice('use_user_pin_as_master', e.currentTarget.checked)} />
                  <span class="text-body-large">Use User PIN as master password (recommended)</span>
                </label>
                <span class="field-help text-body-small">Your User PIN will also serve as the encryption key for the password store</span>

                {#if !choices.use_user_pin_as_master}
                  <label class="toggle-row">
                    <input type="checkbox" checked={choices.enable_master_password} on:change={(e) => setChoice('enable_master_password', e.currentTarget.checked)} />
                    <span class="text-body-large">Set master password</span>
                  </label>

                  {#if choices.enable_master_password}
                    <label class="field-label text-label-medium" for="wizard-master-password">Master Password</label>
                    <input id="wizard-master-password" type="password" class="field-input" placeholder="Enter master password" value={choices.master_password} on:input={(e) => setChoice('master_password', e.currentTarget.value)} />
                    <label class="field-label text-label-medium" for="wizard-master-confirm">Confirm Password</label>
                    <input id="wizard-master-confirm" type="password" class="field-input" placeholder="Confirm master password" bind:value={confirmMasterPW} />
                    {#if confirmMasterPW && !masterPWMatch}
                      <span class="field-error text-body-small">Passwords do not match</span>
                    {/if}
                  {/if}
                {/if}
              </div>
            {/if}
          </div>

          <!-- Data Sealing Backend -->
          {#if probe && probe.available_sealers && probe.available_sealers.filter(s => s.available).length > 0}
            {@const availableSealers = probe.available_sealers.filter(s => s.available)}
            <div class="section-group">
              <div class="section-header">
                <Icon path={mdiShieldKey} size={20} />
                <span class="text-title-medium">Data Sealing</span>
              </div>
              <span class="field-help text-body-small">
                Choose how sensitive data (PINs, credentials, auto-unseal keys) is encrypted at rest.
              </span>

              {#if availableSealers.length === 1}
                <div class="info-banner">
                  <Icon path={mdiInformation} size={18} />
                  <span class="text-body-medium">
                    Using <strong>{availableSealers[0].label}</strong>: {availableSealers[0].description}
                  </span>
                </div>
              {:else}
                <div class="mode-options">
                  {#each availableSealers as sealer}
                    <label class="mode-card" class:selected={choices.sealer_backend === sealer.id || (choices.sealer_backend === '' && sealer.is_default)}>
                      <input type="radio" name="sealer-backend" value={sealer.id}
                             checked={choices.sealer_backend === sealer.id || (choices.sealer_backend === '' && sealer.is_default)}
                             on:change={() => setChoice('sealer_backend', sealer.id)} />
                      <div class="mode-info">
                        <span class="text-title-medium">
                          {sealer.label}
                          {#if sealer.hardware_backed}
                            <span class="badge badge-success text-label-small">Hardware</span>
                          {/if}
                          {#if sealer.is_default}
                            <span class="badge text-label-small">Recommended</span>
                          {/if}
                        </span>
                        <span class="text-body-small">{sealer.description}</span>
                      </div>
                    </label>
                  {/each}
                </div>
              {/if}
            </div>
          {/if}

          <div class="step-actions">
            <button class="btn btn-text" on:click={prevStep}>Back</button>
            <button class="btn btn-primary" on:click={nextStepSecurity}>Next</button>
          </div>
        </div>

      <!-- ========== ENTERPRISE FLOW: STEP 4 - STORAGE ========== -->
      {:else if flow === 'setup' && step === 4 && choices.deployment_mode === 'enterprise'}
        <div class="step-content">
          <h2 class="text-headline-medium">Encrypted Storage</h2>
          <p class="text-body-large">xKey uses layered encryption. Choose a storage backend and configure barrier encryption.</p>

          <!-- Barrier always-active indicator -->
          <div class="section-group">
            <div class="section-header">
              <Icon path={mdiShieldLockOutline} size={20} />
              <span class="text-title-medium">Barrier Encryption</span>
              <span class="badge badge-success text-label-small">Always Active</span>
            </div>
            <div class="barrier-always-info">
              <span class="text-body-small">All data is encrypted at the application layer using AES-256-GCM barrier encryption, regardless of storage backend. The best available strategy is selected automatically.</span>
              {#if probe && probe.barrier_strategies}
                <div class="strategy-chips">
                  {#each probe.barrier_strategies as strat}
                    <span class="strategy-chip" class:available={strat.available} class:hardware={strat.hardware_backed}>
                      {strat.label}: {strat.available ? 'Available' : 'Unavailable'}
                    </span>
                  {/each}
                </div>
              {/if}
            </div>
          </div>

          <!-- Storage Backend Selection -->
          <div class="section-group">
            <div class="section-header">
              <Icon path={mdiShieldLockOutline} size={20} />
              <span class="text-title-medium">Storage Backend</span>
            </div>

            <div class="mode-options">
              <label class="mode-card" class:selected={choices.storage_type === 'barrier'}>
                <input type="radio" name="storage-type" value="barrier" checked={choices.storage_type === 'barrier'} on:change={() => { setChoice('storage_type', 'barrier'); setChoice('enable_storage', false); }} />
                <div class="mode-info">
                  <span class="text-title-medium">Standard Filesystem</span>
                  <span class="text-body-small">Data stored on the local filesystem. Barrier encryption protects all data at the application layer.</span>
                </div>
              </label>

              {#if probe && probe.luks_available}
                <label class="mode-card" class:selected={choices.storage_type === 'luks'}>
                  <input type="radio" name="storage-type" value="luks" checked={choices.storage_type === 'luks'} on:change={() => { setChoice('storage_type', 'luks'); setChoice('enable_storage', true); }} />
                  <div class="mode-info">
                    <span class="text-title-medium">LUKS Encrypted Volume</span>
                    <span class="text-body-small">Linux-native full-disk encryption as a base layer underneath barrier encryption. Provides defense-in-depth. Requires administrator privileges.</span>
                  </div>
                </label>
              {/if}
            </div>
          </div>

          <!-- LUKS fields (when LUKS selected) -->
          {#if choices.storage_type === 'luks' && choices.enable_storage}
            <div class="info-banner info">
              <Icon path={mdiInformation} size={18} />
              <span class="text-body-medium">Administrator password will be required to create the encrypted volume. Barrier encryption runs on top of LUKS for defense-in-depth.</span>
            </div>

            <div class="storage-fields">
              <label class="field-label text-label-medium" for="wizard-ent-storage-size">Volume Size (GB)</label>
              <input id="wizard-ent-storage-size" type="number" class="field-input" min="1" max="100" value={choices.storage_size_gb} on:input={(e) => setChoice('storage_size_gb', parseInt(e.currentTarget.value) || 2)} />
              <label class="field-label text-label-medium" for="wizard-ent-storage-passphrase">LUKS Passphrase</label>
              <input id="wizard-ent-storage-passphrase" type="password" class="field-input" placeholder="Minimum 8 characters" value={choices.storage_passphrase} on:input={(e) => setChoice('storage_passphrase', e.currentTarget.value)} />
              <label class="field-label text-label-medium" for="wizard-ent-storage-confirm">Confirm LUKS Passphrase</label>
              <input id="wizard-ent-storage-confirm" type="password" class="field-input" placeholder="Confirm passphrase" bind:value={confirmPassphrase} />
              {#if confirmPassphrase && !passphraseMatch}
                <span class="field-error text-body-small">Passphrases do not match</span>
              {/if}
            </div>
          {/if}

          <!-- Barrier password (both storage types) -->
          <div class="section-group">
            <div class="section-header">
              <Icon path={mdiShieldLockOutline} size={20} />
              <span class="text-title-medium">Barrier Password</span>
            </div>
            {#if probe?.barrier_strategies?.some(s => s.available && s.hardware_backed)}
              <div class="info-banner info">
                <Icon path={mdiInformation} size={18} />
                <span class="text-body-medium">TPM 2.0 hardware will be used to protect the barrier encryption key. No password required.</span>
              </div>
            {:else}
              <div class="storage-fields">
                <label class="field-label text-label-medium" for="wizard-ent-barrier-password">Encryption Password</label>
                <input id="wizard-ent-barrier-password" type="password" class="field-input" placeholder="Password for barrier encryption" value={choices.barrier_password} on:input={(e) => setChoice('barrier_password', e.currentTarget.value)} />
                <label class="field-label text-label-medium" for="wizard-ent-barrier-confirm">Confirm Password</label>
                <input id="wizard-ent-barrier-confirm" type="password" class="field-input" placeholder="Confirm password" bind:value={confirmBarrierPW} />
                {#if confirmBarrierPW && !barrierPWMatch}
                  <span class="field-error text-body-small">Passwords do not match</span>
                {/if}
                <span class="field-help text-body-small">Required for software-based barrier encryption. With TPM 2.0 hardware, no password is needed.</span>
              </div>
            {/if}

            <!-- Auto-unseal toggle -->
            <label class="toggle-row">
              <input type="checkbox" checked={choices.enable_auto_unseal} on:change={(e) => setChoice('enable_auto_unseal', e.currentTarget.checked)} />
              <span class="text-body-large">Enable auto-unseal on startup</span>
            </label>
          </div>

          <div class="step-actions">
            <button class="btn btn-text" on:click={prevStep}>Back</button>
            <button class="btn btn-primary" on:click={nextStep}>Next</button>
          </div>
        </div>

      <!-- ========== PERSONAL FLOW: STEP 5 - STORAGE ========== -->
      {:else if flow === 'setup' && step === 5 && choices.deployment_mode === 'personal'}
        <div class="step-content">
          <h2 class="text-headline-medium">Encrypted Storage</h2>
          <p class="text-body-large">xKey uses layered encryption. Choose a storage backend and configure barrier encryption.</p>

          <!-- Barrier always-active indicator -->
          <div class="section-group">
            <div class="section-header">
              <Icon path={mdiShieldLockOutline} size={20} />
              <span class="text-title-medium">Barrier Encryption</span>
              <span class="badge badge-success text-label-small">Always Active</span>
            </div>
            <div class="barrier-always-info">
              <span class="text-body-small">All data is encrypted at the application layer using AES-256-GCM barrier encryption, regardless of storage backend. The best available strategy is selected automatically.</span>
              {#if probe && probe.barrier_strategies}
                <div class="strategy-chips">
                  {#each probe.barrier_strategies as strat}
                    <span class="strategy-chip" class:available={strat.available} class:hardware={strat.hardware_backed}>
                      {strat.label}: {strat.available ? 'Available' : 'Unavailable'}
                    </span>
                  {/each}
                </div>
              {/if}
            </div>
          </div>

          <!-- Storage Backend Selection -->
          <div class="section-group">
            <div class="section-header">
              <Icon path={mdiShieldLockOutline} size={20} />
              <span class="text-title-medium">Storage Backend</span>
            </div>

            <div class="mode-options">
              <label class="mode-card" class:selected={choices.storage_type === 'barrier'}>
                <input type="radio" name="storage-type" value="barrier" checked={choices.storage_type === 'barrier'} on:change={() => { setChoice('storage_type', 'barrier'); setChoice('enable_storage', false); }} />
                <div class="mode-info">
                  <span class="text-title-medium">Standard Filesystem</span>
                  <span class="text-body-small">Data stored on the local filesystem. Barrier encryption protects all data at the application layer.</span>
                </div>
              </label>

              {#if probe && probe.luks_available}
                <label class="mode-card" class:selected={choices.storage_type === 'luks'}>
                  <input type="radio" name="storage-type" value="luks" checked={choices.storage_type === 'luks'} on:change={() => { setChoice('storage_type', 'luks'); setChoice('enable_storage', true); }} />
                  <div class="mode-info">
                    <span class="text-title-medium">LUKS Encrypted Volume</span>
                    <span class="text-body-small">Linux-native full-disk encryption as a base layer underneath barrier encryption. Provides defense-in-depth. Requires administrator privileges.</span>
                  </div>
                </label>
              {/if}
            </div>
          </div>

          <!-- LUKS fields (when LUKS selected) -->
          {#if choices.storage_type === 'luks' && choices.enable_storage}
            <div class="info-banner info">
              <Icon path={mdiInformation} size={18} />
              <span class="text-body-medium">Administrator password will be required to create the encrypted volume. Barrier encryption runs on top of LUKS for defense-in-depth.</span>
            </div>

            <div class="storage-fields">
              <label class="field-label text-label-medium" for="wizard-storage-size">Volume Size (GB)</label>
              <input id="wizard-storage-size" type="number" class="field-input" min="1" max="100" value={choices.storage_size_gb} on:input={(e) => setChoice('storage_size_gb', parseInt(e.currentTarget.value) || 2)} />
              <label class="field-label text-label-medium" for="wizard-storage-passphrase">LUKS Passphrase</label>
              <input id="wizard-storage-passphrase" type="password" class="field-input" placeholder="Minimum 8 characters" value={choices.storage_passphrase} on:input={(e) => setChoice('storage_passphrase', e.currentTarget.value)} />
              <label class="field-label text-label-medium" for="wizard-storage-confirm">Confirm LUKS Passphrase</label>
              <input id="wizard-storage-confirm" type="password" class="field-input" placeholder="Confirm passphrase" bind:value={confirmPassphrase} />
              {#if confirmPassphrase && !passphraseMatch}
                <span class="field-error text-body-small">Passphrases do not match</span>
              {/if}
            </div>
          {/if}

          <!-- Barrier password (both storage types) -->
          <div class="section-group">
            <div class="section-header">
              <Icon path={mdiShieldLockOutline} size={20} />
              <span class="text-title-medium">Barrier Password</span>
            </div>
            {#if probe?.barrier_strategies?.some(s => s.available && s.hardware_backed)}
              <div class="info-banner info">
                <Icon path={mdiInformation} size={18} />
                <span class="text-body-medium">TPM 2.0 hardware will be used to protect the barrier encryption key. No password required.</span>
              </div>
            {:else if choices.use_user_pin_as_master}
              <div class="info-banner info">
                <Icon path={mdiInformation} size={18} />
                <span class="text-body-medium">Your User PIN will be used as the barrier encryption password.</span>
              </div>
            {:else}
              <div class="storage-fields">
                <label class="field-label text-label-medium" for="wizard-barrier-password">Encryption Password</label>
                <input id="wizard-barrier-password" type="password" class="field-input" placeholder="Password for barrier encryption" value={choices.barrier_password} on:input={(e) => setChoice('barrier_password', e.currentTarget.value)} />
                <label class="field-label text-label-medium" for="wizard-barrier-confirm">Confirm Password</label>
                <input id="wizard-barrier-confirm" type="password" class="field-input" placeholder="Confirm password" bind:value={confirmBarrierPW} />
                {#if confirmBarrierPW && !barrierPWMatch}
                  <span class="field-error text-body-small">Passwords do not match</span>
                {/if}
                <span class="field-help text-body-small">Required for software-based barrier encryption. With TPM 2.0 hardware, no password is needed.</span>
              </div>
            {/if}

            <!-- Auto-unseal toggle -->
            <label class="toggle-row">
              <input type="checkbox" checked={choices.enable_auto_unseal} on:change={(e) => setChoice('enable_auto_unseal', e.currentTarget.checked)} />
              <span class="text-body-large">Enable auto-unseal on startup</span>
            </label>
          </div>

          <div class="step-actions">
            <button class="btn btn-text" on:click={prevStep}>Back</button>
            <button class="btn btn-primary" on:click={nextStep}>Next</button>
          </div>
        </div>

      <!-- ========== ENTERPRISE FLOW: STEP 5 - TPM ========== -->
      {:else if flow === 'setup' && step === 5 && choices.deployment_mode === 'enterprise'}
        <div class="step-content">
          <h2 class="text-headline-medium">TPM Configuration</h2>
          <p class="text-body-large">Configure Trusted Platform Module settings for hardware-backed security.</p>

          {#if probe && (probe.tpm_available || probe.tpm_device_exists)}
            <div class="section-group">
              <div class="section-header">
                <Icon path={mdiChip} size={20} />
                <span class="text-title-medium">TPM 2.0</span>
                <span class="badge badge-success text-label-small">Detected</span>
              </div>

              <div class="security-fields">
                <label class="toggle-row">
                  <input type="checkbox" checked={choices.set_hierarchy_auth} on:change={(e) => setChoice('set_hierarchy_auth', e.currentTarget.checked)} />
                  <span class="text-body-large">Set TPM Hierarchy Authorization Passwords</span>
                </label>
                <span class="field-help text-body-small">Uses the SO PIN to set authorization passwords on the TPM Endorsement, Owner, and Lockout hierarchies.</span>
              </div>
            </div>

            <!-- Password Storage Mode -->
            <div class="section-group">
              <div class="section-header">
                <Icon path={mdiShieldLockOutline} size={20} />
                <span class="text-title-medium">Password Storage</span>
              </div>

              <div class="mode-options">
                <label class="mode-card" class:selected={choices.password_store_mode === 'tpm_sealed'}>
                  <input type="radio" name="pw-store-ent" value="tpm_sealed" checked={choices.password_store_mode === 'tpm_sealed'} on:change={() => selectPasswordStoreMode('tpm_sealed')} />
                  <div class="mode-info">
                    <span class="text-title-medium">TPM-Sealed (Recommended)</span>
                    <span class="text-body-small">Master key sealed to TPM with platform policy. Auto-unlocks when system boots with expected firmware configuration.</span>
                  </div>
                </label>
                <label class="mode-card" class:selected={choices.password_store_mode === 'aes_software'}>
                  <input type="radio" name="pw-store-ent" value="aes_software" checked={choices.password_store_mode === 'aes_software'} on:change={() => selectPasswordStoreMode('aes_software')} />
                  <div class="mode-info">
                    <span class="text-title-medium">Software AES-256</span>
                    <span class="text-body-small">Encrypt with a master password using Argon2id key derivation. The encryption key is stored on disk and protected only by filesystem permissions. TPM-Sealed is recommended for enterprise use.</span>
                  </div>
                </label>
                <label class="mode-card" class:selected={choices.password_store_mode === 'none'}>
                  <input type="radio" name="pw-store-ent" value="none" checked={choices.password_store_mode === 'none'} on:change={() => selectPasswordStoreMode('none')} />
                  <div class="mode-info">
                    <span class="text-title-medium">None</span>
                    <span class="text-body-small">Passwords stored in plaintext. Not recommended.</span>
                  </div>
                </label>
              </div>
            </div>
          {:else}
            <div class="info-banner warning">
              <Icon path={mdiAlert} size={18} />
              <span class="text-body-medium">TPM 2.0 is not available on this device. Software-only encryption will be used. The encryption key is stored on disk and protected by filesystem permissions only. For production or enterprise use, a system with TPM 2.0 hardware is strongly recommended.</span>
            </div>

            <!-- Software-only password storage mode -->
            <div class="section-group">
              <div class="section-header">
                <Icon path={mdiShieldLockOutline} size={20} />
                <span class="text-title-medium">Password Storage</span>
              </div>

              <div class="mode-options">
                <label class="mode-card" class:selected={choices.password_store_mode === 'aes_software'}>
                  <input type="radio" name="pw-store-ent" value="aes_software" checked={choices.password_store_mode === 'aes_software'} on:change={() => selectPasswordStoreMode('aes_software')} />
                  <div class="mode-info">
                    <span class="text-title-medium">Software AES-256</span>
                    <span class="text-body-small">Encrypt with a master password using Argon2id key derivation. The encryption key is stored on disk and protected only by filesystem permissions.</span>
                  </div>
                </label>
                <label class="mode-card" class:selected={choices.password_store_mode === 'none'}>
                  <input type="radio" name="pw-store-ent" value="none" checked={choices.password_store_mode === 'none'} on:change={() => selectPasswordStoreMode('none')} />
                  <div class="mode-info">
                    <span class="text-title-medium">None</span>
                    <span class="text-body-small">Passwords stored in plaintext. Not recommended.</span>
                  </div>
                </label>
              </div>
            </div>
          {/if}

          <!-- Data Sealing Backend (Enterprise) -->
          {#if probe && probe.available_sealers && probe.available_sealers.filter(s => s.available).length > 0}
            {@const availableSealersEnt = probe.available_sealers.filter(s => s.available)}
            <div class="section-group">
              <div class="section-header">
                <Icon path={mdiShieldKey} size={20} />
                <span class="text-title-medium">Data Sealing</span>
              </div>
              <span class="field-help text-body-small">
                Choose how sensitive data (PINs, credentials, auto-unseal keys) is encrypted at rest.
              </span>

              {#if availableSealersEnt.length === 1}
                <div class="info-banner">
                  <Icon path={mdiInformation} size={18} />
                  <span class="text-body-medium">
                    Using <strong>{availableSealersEnt[0].label}</strong>: {availableSealersEnt[0].description}
                  </span>
                </div>
              {:else}
                <div class="mode-options">
                  {#each availableSealersEnt as sealer}
                    <label class="mode-card" class:selected={choices.sealer_backend === sealer.id || (choices.sealer_backend === '' && sealer.is_default)}>
                      <input type="radio" name="sealer-backend-ent" value={sealer.id}
                             checked={choices.sealer_backend === sealer.id || (choices.sealer_backend === '' && sealer.is_default)}
                             on:change={() => setChoice('sealer_backend', sealer.id)} />
                      <div class="mode-info">
                        <span class="text-title-medium">
                          {sealer.label}
                          {#if sealer.hardware_backed}
                            <span class="badge badge-success text-label-small">Hardware</span>
                          {/if}
                          {#if sealer.is_default}
                            <span class="badge text-label-small">Recommended</span>
                          {/if}
                        </span>
                        <span class="text-body-small">{sealer.description}</span>
                      </div>
                    </label>
                  {/each}
                </div>
              {/if}
            </div>
          {/if}

          <div class="step-actions">
            <button class="btn btn-text" on:click={prevStep}>Back</button>
            <button class="btn btn-primary" on:click={nextStep}>Next</button>
          </div>
        </div>

      <!-- ========== SETUP FLOW: STEP 6 - SUMMARY ========== -->
      {:else if flow === 'setup' && step === 6}
        <div class="step-content">
          <h2 class="text-headline-medium">Review &amp; Apply</h2>
          <p class="text-body-large">Review your choices before applying.</p>

          {#if isQuickSetup && choices.deployment_mode === 'personal'}
            <div class="info-banner warning" style="margin-bottom: 1rem;">
              <Icon path={mdiAlert} size={18} />
              <span class="text-body-small"><strong>Important:</strong> After setup completes, check the <strong>xKey</strong> folder in your password store for your User PIN. Note it down before the app lock screen activates — you'll need it to unlock the app.</span>
            </div>
          {/if}

          <div class="summary-table">
            <div class="summary-row">
              <span class="summary-label text-label-medium">Deployment Mode</span>
              <span class="summary-value text-body-medium">{choices.deployment_mode === 'enterprise' ? 'Enterprise' : 'Personal'}</span>
              <button class="btn-edit text-label-small" on:click={() => navigateStep(2)}>Edit</button>
            </div>

            {#if choices.deployment_mode === 'personal'}
              <!-- Personal summary rows -->
              <div class="summary-row">
                <span class="summary-label text-label-medium">Operating Mode</span>
                <span class="summary-value text-body-medium">{choices.mode === 'standalone' ? 'Standalone' : choices.mode === 'server' ? 'Server' : 'Both'}</span>
                <button class="btn-edit text-label-small" on:click={() => navigateStep(3)}>Edit</button>
              </div>
              {#if choices.mode === 'server' || choices.mode === 'both'}
                <div class="summary-row">
                  <span class="summary-label text-label-medium">Server</span>
                  <span class="summary-value text-body-medium">{choices.server_address || 'Not set'} ({choices.server_protocol})</span>
                  <button class="btn-edit text-label-small" on:click={() => navigateStep(3)}>Edit</button>
                </div>
              {/if}
              <div class="summary-row">
                <span class="summary-label text-label-medium">Password Storage</span>
                <span class="summary-value text-body-medium">{passwordStoreModeLabel(choices.password_store_mode)}</span>
                <button class="btn-edit text-label-small" on:click={() => navigateStep(4)}>Edit</button>
              </div>
              <div class="summary-row">
                <span class="summary-label text-label-medium">Data Sealing</span>
                <span class="summary-value text-body-medium">{sealerBackendLabel(choices.sealer_backend)}</span>
                <button class="btn-edit text-label-small" on:click={() => navigateStep(4)}>Edit</button>
              </div>
              <div class="summary-row">
                <span class="summary-label text-label-medium">SO PIN</span>
                <span class="summary-value text-body-medium">
                  {#if isQuickSetup && choices.so_pin}
                    Auto-generated (16 chars)
                  {:else if choices.so_pin}
                    Configured
                  {:else}
                    Not set
                  {/if}
                </span>
                <button class="btn-edit text-label-small" on:click={() => navigateStep(4)}>Edit</button>
              </div>
              <div class="summary-row">
                <span class="summary-label text-label-medium">User PIN</span>
                <span class="summary-value text-body-medium">
                  {#if isQuickSetup && choices.user_pin}
                    Auto-generated (12 chars)
                  {:else if choices.user_pin}
                    Configured{choices.use_user_pin_as_master ? ' (unified with password store)' : ''}
                  {:else}
                    Not set
                  {/if}
                </span>
                <button class="btn-edit text-label-small" on:click={() => navigateStep(4)}>Edit</button>
              </div>
              {#if probe && (probe.tpm_available || probe.tpm_device_exists)}
                <div class="summary-row">
                  <span class="summary-label text-label-medium">Hierarchy Auth</span>
                  <span class="summary-value text-body-medium">{choices.set_hierarchy_auth ? 'Set via SO PIN' : 'Default (empty)'}</span>
                  <button class="btn-edit text-label-small" on:click={() => navigateStep(4)}>Edit</button>
                </div>
              {/if}
              <div class="summary-row">
                <span class="summary-label text-label-medium">Storage</span>
                <span class="summary-value text-body-medium">
                  {#if choices.storage_type === 'luks'}
                    LUKS Encrypted Volume ({choices.storage_size_gb} GB) + Barrier ({barrierStrategyLabel()})
                  {:else}
                    Standard Filesystem + Barrier ({barrierStrategyLabel()})
                  {/if}
                </span>
                <button class="btn-edit text-label-small" on:click={() => navigateStep(5)}>Edit</button>
              </div>
              <div class="summary-row">
                <span class="summary-label text-label-medium">Master Password</span>
                <span class="summary-value text-body-medium">
                  {#if choices.password_store_mode === 'tpm_sealed'}
                    N/A (TPM-Sealed)
                  {:else if choices.use_user_pin_as_master && choices.user_pin}
                    Using User PIN
                  {:else if choices.enable_master_password}
                    Enabled
                  {:else}
                    Disabled
                  {/if}
                </span>
                <button class="btn-edit text-label-small" on:click={() => navigateStep(4)}>Edit</button>
              </div>
            {:else}
              <!-- Enterprise summary rows -->
              {#if choices.organization_name}
                <div class="summary-row">
                  <span class="summary-label text-label-medium">Organization</span>
                  <span class="summary-value text-body-medium">{choices.organization_name}</span>
                  <button class="btn-edit text-label-small" on:click={() => navigateStep(3)}>Edit</button>
                </div>
              {/if}
              <div class="summary-row">
                <span class="summary-label text-label-medium">SO PIN</span>
                <span class="summary-value text-body-medium">{choices.so_pin ? 'Configured' : 'Not set'}</span>
                <button class="btn-edit text-label-small" on:click={() => navigateStep(3)}>Edit</button>
              </div>
              <div class="summary-row">
                <span class="summary-label text-label-medium">Min PIN Length</span>
                <span class="summary-value text-body-medium">{choices.min_pin_length || 6} characters</span>
                <button class="btn-edit text-label-small" on:click={() => navigateStep(3)}>Edit</button>
              </div>
              <div class="summary-row">
                <span class="summary-label text-label-medium">Max Failed PIN Attempts</span>
                <span class="summary-value text-body-medium">{choices.pin_max_attempts || 5}</span>
                <button class="btn-edit text-label-small" on:click={() => navigateStep(3)}>Edit</button>
              </div>
              <div class="summary-row">
                <span class="summary-label text-label-medium">Require Encrypted Storage</span>
                <span class="summary-value text-body-medium">{choices.require_encrypted_storage ?? true ? 'Yes' : 'No'}</span>
                <button class="btn-edit text-label-small" on:click={() => navigateStep(3)}>Edit</button>
              </div>
              <div class="summary-row">
                <span class="summary-label text-label-medium">Require TPM</span>
                <span class="summary-value text-body-medium">{choices.require_tpm ?? false ? 'Yes' : 'No'}</span>
                <button class="btn-edit text-label-small" on:click={() => navigateStep(3)}>Edit</button>
              </div>
              <div class="summary-row">
                <span class="summary-label text-label-medium">Password Storage</span>
                <span class="summary-value text-body-medium">{passwordStoreModeLabel(choices.password_store_mode)}</span>
                <button class="btn-edit text-label-small" on:click={() => navigateStep(5)}>Edit</button>
              </div>
              <div class="summary-row">
                <span class="summary-label text-label-medium">Data Sealing</span>
                <span class="summary-value text-body-medium">{sealerBackendLabel(choices.sealer_backend)}</span>
                <button class="btn-edit text-label-small" on:click={() => navigateStep(5)}>Edit</button>
              </div>
              <div class="summary-row">
                <span class="summary-label text-label-medium">Storage</span>
                <span class="summary-value text-body-medium">
                  {#if choices.storage_type === 'luks'}
                    LUKS Encrypted Volume ({choices.storage_size_gb} GB) + Barrier ({barrierStrategyLabel()})
                  {:else}
                    Standard Filesystem + Barrier ({barrierStrategyLabel()})
                  {/if}
                </span>
                <button class="btn-edit text-label-small" on:click={() => navigateStep(4)}>Edit</button>
              </div>
              {#if probe && (probe.tpm_available || probe.tpm_device_exists)}
                <div class="summary-row">
                  <span class="summary-label text-label-medium">Hierarchy Auth</span>
                  <span class="summary-value text-body-medium">{choices.set_hierarchy_auth ? 'Set via SO PIN' : 'Default (empty)'}</span>
                  <button class="btn-edit text-label-small" on:click={() => navigateStep(5)}>Edit</button>
                </div>
              {/if}
            {/if}
          </div>

          {#if error}
            <div class="info-banner warning" style="margin-top: 12px;">
              <Icon path={mdiAlert} size={18} />
              <span class="text-body-medium">{error}</span>
            </div>
          {/if}

          {#if applying && progress}
            <div class="setup-progress">
              {#each activeProgressLabels as label, i}
                {@const stepNum = i + 1}
                {@const isCompleted = stepNum < progress.step}
                {@const isActive = stepNum === progress.step}
                <div class="setup-progress-step" class:completed={isCompleted} class:active={isActive}>
                  <div class="setup-progress-indicator">
                    {#if isCompleted}
                      <div class="setup-progress-check">
                        <Icon path={mdiCheck} size={12} />
                      </div>
                    {:else if isActive}
                      <LoadingSpinner size={20} />
                    {:else}
                      <div class="setup-progress-dot"></div>
                    {/if}
                  </div>
                  <span class="setup-progress-label text-body-medium">{label}</span>
                </div>
              {/each}
              <div class="setup-progress-bar">
                <div class="setup-progress-fill" style="width: {Math.round((progress.step / progress.total_steps) * 100)}%"></div>
              </div>
              <span class="setup-progress-pct text-label-small">{Math.round((progress.step / progress.total_steps) * 100)}%</span>
            </div>
          {:else if applying}
            <div class="setup-progress">
              <LoadingSpinner size={24} />
              <span class="text-body-medium">Preparing...</span>
            </div>
          {/if}

          <div class="step-actions">
            <button class="btn btn-text" on:click={prevStep} disabled={applying}>Back</button>
            {#if choices.deployment_mode === 'enterprise'}
              <button class="btn btn-primary" on:click={applySOProvisioning} disabled={applying}>
                {#if applying}
                  Applying...
                {:else}
                  Apply Provisioning
                {/if}
              </button>
            {:else}
              <button class="btn btn-primary" on:click={applySetup} disabled={applying}>
                {#if applying}
                  Applying...
                {:else}
                  Apply Setup
                {/if}
              </button>
            {/if}
          </div>
        </div>
      {/if}
    </div>
  </div>
</div>

<style>
  .wizard-overlay {
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

  .wizard-container {
    width: 100%;
    max-width: 640px;
    padding: 32px;
    display: flex;
    flex-direction: column;
    gap: 32px;
    max-height: 100vh;
    overflow-y: auto;
  }

  .wizard-progress {
    display: flex;
    align-items: center;
    justify-content: center;
    gap: 0;
  }

  .progress-step {
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 4px;
  }

  .step-circle {
    width: 32px;
    height: 32px;
    border-radius: 50%;
    border: 2px solid var(--color-outline-variant);
    display: flex;
    align-items: center;
    justify-content: center;
    font-size: 14px;
    font-weight: 600;
    color: var(--color-on-surface-variant);
    background: var(--color-surface);
    transition: all 200ms ease;
  }

  .progress-step.active .step-circle {
    border-color: var(--color-primary);
    background: var(--color-primary);
    color: var(--color-on-primary);
  }

  .progress-step.completed .step-circle {
    border-color: var(--color-primary);
    background: var(--color-primary-container);
    color: var(--color-on-primary-container);
  }

  .step-label {
    color: var(--color-on-surface-variant);
    white-space: nowrap;
  }

  .progress-step.active .step-label {
    color: var(--color-primary);
    font-weight: 600;
  }

  .progress-line {
    height: 2px;
    width: 36px;
    background: var(--color-outline-variant);
    margin: 0 2px;
    margin-bottom: 20px;
    transition: background 200ms ease;
  }

  .progress-line.filled {
    background: var(--color-primary);
  }

  .wizard-content {
    background: var(--color-surface-container-lowest);
    border-radius: var(--radius-lg);
    border: 1px solid var(--color-outline-variant);
    padding: 32px;
  }

  .step-content {
    display: flex;
    flex-direction: column;
    gap: 16px;
  }

  .step-content h2 {
    color: var(--color-on-surface);
    margin: 0;
  }

  .step-content p {
    color: var(--color-on-surface-variant);
    margin: 0;
  }

  .welcome-icon {
    width: 80px;
    height: 80px;
    margin: 0 auto;
  }

  .capability-cards {
    display: flex;
    gap: 12px;
    flex-wrap: wrap;
  }

  .capability-card {
    flex: 1;
    min-width: 140px;
    padding: 12px 16px;
    border-radius: var(--radius-md);
    border: 1px solid var(--color-outline-variant);
    background: var(--color-surface-container);
    display: flex;
    flex-direction: column;
    gap: 4px;
  }

  .capability-card.available {
    border-color: var(--color-primary);
    background: var(--color-primary-container);
  }

  .capability-card.available .cap-label {
    color: var(--color-on-primary-container);
  }

  .capability-card.available .cap-status {
    color: var(--color-on-primary-container);
  }

  .cap-label {
    color: var(--color-on-surface);
  }

  .cap-status {
    color: var(--color-on-surface-variant);
  }

  .step-actions {
    display: flex;
    justify-content: flex-end;
    gap: 8px;
    margin-top: 16px;
  }

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

  .btn-outlined {
    background: transparent;
    color: var(--color-primary);
    border: 1px solid var(--color-outline);
  }

  .btn-outlined:hover:not(:disabled) {
    background: var(--color-primary-container);
  }

  .btn-text {
    background: transparent;
    color: var(--color-primary);
    border: none;
  }

  .btn-text:hover {
    background: var(--color-surface-variant);
  }

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
    cursor: pointer;
    transition: all 150ms ease;
  }

  .mode-card:hover {
    border-color: var(--color-outline);
  }

  .mode-card.selected {
    border-color: var(--color-primary);
    background: var(--color-primary-container);
  }

  .mode-card input[type="radio"] {
    accent-color: var(--color-primary);
    width: 18px;
    height: 18px;
  }

  .mode-card-icon {
    width: 48px;
    height: 48px;
    border-radius: var(--radius-md);
    background: var(--color-surface-container);
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
    color: var(--color-on-surface-variant);
  }

  .mode-card.selected .mode-card-icon {
    background: var(--color-primary);
    color: var(--color-on-primary);
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

  .server-config, .storage-fields, .security-fields {
    display: flex;
    flex-direction: column;
    gap: 8px;
    margin-top: 12px;
    padding: 16px;
    border-radius: var(--radius-md);
    background: var(--color-surface-container);
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

  .field-error {
    color: var(--color-error);
  }

  .field-help {
    color: var(--color-on-surface-variant);
    margin-bottom: 4px;
  }

  .toggle-row {
    display: flex;
    align-items: center;
    gap: 12px;
    cursor: pointer;
    padding: 8px 0;
  }

  .toggle-row input[type="checkbox"] {
    accent-color: var(--color-primary);
    width: 18px;
    height: 18px;
  }

  .section-group {
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .section-header {
    display: flex;
    align-items: center;
    gap: 8px;
    color: var(--color-on-surface);
  }

  .badge {
    display: inline-flex;
    align-items: center;
    padding: 2px 10px;
    border-radius: var(--radius-full);
    font-weight: 600;
  }

  .badge-success {
    background: var(--color-primary-container);
    color: var(--color-on-primary-container);
  }

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

  .summary-table {
    display: flex;
    flex-direction: column;
    gap: 0;
    border: 1px solid var(--color-outline-variant);
    border-radius: var(--radius-md);
    overflow: hidden;
  }

  .summary-row {
    display: flex;
    align-items: center;
    padding: 12px 16px;
    background: var(--color-surface);
  }

  .summary-row:not(:last-child) {
    border-bottom: 1px solid var(--color-outline-variant);
  }

  .summary-label {
    width: 160px;
    flex-shrink: 0;
    color: var(--color-on-surface-variant);
  }

  .summary-value {
    flex: 1;
    color: var(--color-on-surface);
  }

  .btn-edit {
    background: transparent;
    border: none;
    color: var(--color-primary);
    cursor: pointer;
    padding: 4px 8px;
    border-radius: var(--radius-sm);
  }

  .btn-edit:hover {
    background: var(--color-surface-variant);
  }

  .result-screen {
    align-items: center;
    text-align: center;
    padding: 32px 0;
  }

  .result-icon {
    width: 80px;
    height: 80px;
    border-radius: 50%;
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .result-icon.success {
    background: var(--color-primary-container);
    color: var(--color-on-primary-container);
  }

  .result-icon.has-errors {
    background: var(--color-error-container, #fdecea);
    color: var(--color-on-error-container, #5f2120);
  }

  .result-messages {
    text-align: left;
    width: 100%;
    padding: 12px 16px;
    border-radius: var(--radius-md);
  }

  .result-messages.errors {
    background: var(--color-error-container, #fdecea);
    color: var(--color-on-error-container, #5f2120);
  }

  .result-messages.warnings {
    background: var(--color-tertiary-container, #fff8e1);
    color: var(--color-on-tertiary-container, #5d4037);
  }

  .result-messages h3 {
    margin: 0 0 4px 0;
  }

  .result-messages p {
    margin: 2px 0;
  }

  /* Setup progress panel */
  .setup-progress {
    display: flex;
    flex-direction: column;
    gap: 6px;
    padding: 16px;
    border-radius: var(--radius-md);
    background: var(--color-surface-container);
    margin-top: 12px;
  }

  .setup-progress-step {
    display: flex;
    align-items: center;
    gap: 10px;
    padding: 4px 0;
    opacity: 0.4;
    transition: opacity 0.2s ease;
  }

  .setup-progress-step.completed {
    opacity: 1;
  }

  .setup-progress-step.active {
    opacity: 1;
  }

  .setup-progress-indicator {
    width: 20px;
    height: 20px;
    display: flex;
    align-items: center;
    justify-content: center;
    flex-shrink: 0;
  }

  .setup-progress-check {
    width: 18px;
    height: 18px;
    border-radius: 50%;
    background: var(--color-primary);
    color: var(--color-on-primary);
    display: flex;
    align-items: center;
    justify-content: center;
  }

  .setup-progress-dot {
    width: 8px;
    height: 8px;
    border-radius: 50%;
    background: var(--color-outline-variant);
  }

  .setup-progress-label {
    color: var(--color-on-surface);
  }

  .setup-progress-step:not(.completed):not(.active) .setup-progress-label {
    color: var(--color-on-surface-variant);
  }

  .setup-progress-bar {
    height: 4px;
    border-radius: 2px;
    background: var(--color-surface-container-high);
    margin-top: 8px;
    overflow: hidden;
  }

  .setup-progress-fill {
    height: 100%;
    border-radius: 2px;
    background: var(--color-primary);
    transition: width 0.3s ease;
  }

  .setup-progress-pct {
    text-align: right;
    color: var(--color-on-surface-variant);
    margin-top: 2px;
  }

  .field-input-error {
    border-color: var(--color-error, #d32f2f);
    box-shadow: 0 0 0 1px var(--color-error, #d32f2f);
  }

  .barrier-always-info {
    padding: 12px 16px;
    background: var(--color-surface-container);
    border-radius: var(--radius-medium, 8px);
    border-left: 3px solid var(--color-primary);
    display: flex;
    flex-direction: column;
    gap: 8px;
  }

  .strategy-chips {
    display: flex;
    gap: 6px;
    flex-wrap: wrap;
    margin-top: 4px;
  }

  .strategy-chip {
    font-size: 11px;
    padding: 2px 8px;
    border-radius: var(--radius-full);
    background: var(--color-surface-container);
    color: var(--color-on-surface-variant);
  }

  .strategy-chip.available {
    background: var(--color-primary-container);
    color: var(--color-on-primary-container);
  }

  .strategy-chip.hardware {
    font-weight: 600;
  }


  .acknowledge-row {
    padding: 12px 16px;
    border-radius: var(--radius-md);
    background: var(--color-surface-container);
    border: 1px solid var(--color-outline-variant);
  }
</style>
