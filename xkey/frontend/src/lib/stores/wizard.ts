import { writable, derived } from 'svelte/store';
import type { DeploymentMode, EnvironmentProbe, SetupChoices, SetupResult, UserOnboardingChoices } from '$lib/types/setup';

export interface SetupProgressStep {
  step: number;
  total_steps: number;
  label: string;
}

/** Which wizard flow is active. */
export type WizardFlow = 'setup' | 'user_onboarding';

export interface WizardState {
  flow: WizardFlow;
  step: number;
  isQuickSetup: boolean;
  probe: EnvironmentProbe | null;
  choices: SetupChoices;
  onboardingChoices: UserOnboardingChoices;
  applying: boolean;
  result: SetupResult | null;
  error: string | null;
  progress: SetupProgressStep | null;
}

const defaultChoices: SetupChoices = {
  mode: 'standalone',
  deployment_mode: '',
  server_address: '',
  server_protocol: 'grpc',
  enable_storage: false,
  storage_size_gb: 2,
  storage_passphrase: '',
  enable_master_password: false,
  master_password: '',
  enable_platform_policy: true,
  tpm_seal_passwords: true,
  password_store_mode: 'aes_software',
  so_pin: '',
  user_pin: '',
  use_user_pin_as_master: true,
  save_pins_to_store: false,
  set_hierarchy_auth: false,
  storage_type: 'barrier',
  barrier_password: '',
  sealer_backend: '',
  allow_extension: true,
  force_extension_auth: true,
  force_extension_pairing: true,
  force_extension_audit: true,
  allow_configure_extension: true,
  fido2_require_user_presence: true,
  fido2_user_intent_check: true,
};

const defaultOnboardingChoices: UserOnboardingChoices = {
  so_pin: '',
  user_pin: '',
  barrier_password: '',
};

const initialState: WizardState = {
  flow: 'setup',
  step: 1,
  isQuickSetup: false,
  probe: null,
  choices: { ...defaultChoices },
  onboardingChoices: { ...defaultOnboardingChoices },
  applying: false,
  result: null,
  error: null,
  progress: null,
};

export const wizardState = writable<WizardState>(initialState);

export const wizardStep = derived(wizardState, ($s) => $s.step);
export const wizardFlow = derived(wizardState, ($s) => $s.flow);
export const wizardProbe = derived(wizardState, ($s) => $s.probe);
export const wizardChoices = derived(wizardState, ($s) => $s.choices);
export const wizardOnboardingChoices = derived(wizardState, ($s) => $s.onboardingChoices);
export const wizardApplying = derived(wizardState, ($s) => $s.applying);
export const wizardResult = derived(wizardState, ($s) => $s.result);
export const wizardProgress = derived(wizardState, ($s) => $s.progress);
export const wizardDeploymentMode = derived(wizardState, ($s) => $s.choices.deployment_mode);
export const wizardIsQuickSetup = derived(wizardState, ($s) => $s.isQuickSetup);

/** Maximum step for the current flow and deployment mode. */
export const wizardMaxStep = derived(wizardState, ($s) => {
  if ($s.flow === 'user_onboarding') return 3;
  // Setup flow: both personal and enterprise have 6 steps.
  // Before deployment mode is chosen, cap at 2 (Welcome + Deployment).
  if ($s.choices.deployment_mode === '') return 2;
  return 6;
});

export function setWizardFlow(flow: WizardFlow): void {
  wizardState.update((s) => ({ ...s, flow, step: 1 }));
}

export function navigateStep(step: number): void {
  wizardState.update((s) => {
    const max = s.flow === 'user_onboarding' ? 3 : (s.choices.deployment_mode === '' ? 2 : 6);
    if (step < 1) step = 1;
    if (step > max) step = max;
    return { ...s, step, error: null };
  });
}

export function setChoice<K extends keyof SetupChoices>(key: K, value: SetupChoices[K]): void {
  wizardState.update((s) => ({
    ...s,
    choices: { ...s.choices, [key]: value },
  }));
}

export function setOnboardingChoice<K extends keyof UserOnboardingChoices>(key: K, value: UserOnboardingChoices[K]): void {
  wizardState.update((s) => ({
    ...s,
    onboardingChoices: { ...s.onboardingChoices, [key]: value },
  }));
}

export function setQuickSetup(isQuick: boolean): void {
  wizardState.update((s) => ({ ...s, isQuickSetup: isQuick }));
}

export function setDeploymentMode(mode: DeploymentMode): void {
  wizardState.update((s) => ({
    ...s,
    choices: { ...s.choices, deployment_mode: mode },
  }));
}

export function setProbe(probe: EnvironmentProbe): void {
  wizardState.update((s) => ({ ...s, probe }));
}

export function setApplying(applying: boolean): void {
  wizardState.update((s) => ({ ...s, applying, progress: null }));
}

export function setResult(result: SetupResult): void {
  wizardState.update((s) => ({ ...s, result, applying: false, progress: null }));
}

export function setError(error: string): void {
  wizardState.update((s) => ({ ...s, error, applying: false, progress: null }));
}

export function setProgress(progress: SetupProgressStep): void {
  wizardState.update((s) => ({ ...s, progress }));
}

export function resetWizard(): void {
  wizardState.set(initialState);
}
