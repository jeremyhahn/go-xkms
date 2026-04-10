/**
 * xKey Setup Wizard - Type Definitions
 */

/** Backend info returned by AdminService.ListBackends(). */
export interface BackendInfo {
  id: string;
  type: string;
  enabled: boolean;
  connected: boolean;
  key_count: number;
  algorithms: string[];
  description: string;
  display_name: string;
  device_name: string;
  metadata: Record<string, string>;
}

/** Environment capabilities detected during wizard probe. */
export interface EnvironmentProbe {
  tpm_available: boolean;
  tpm_device_exists: boolean;
  tpm_device_path: string;
  tpm_init_error?: string;
  luks_available: boolean;
  server_reachable: boolean;
  server_address: string;
  platform: string;
  setup_complete: boolean;
  storage_exists: boolean;
  storage_mounted: boolean;
  barrier_strategies: BarrierStrategyInfo[];
  available_sealers: SealerInfo[];
  available_backends: BackendInfo[];
}

/** Deployment mode: personal (single user) or enterprise (SO + user). */
export type DeploymentMode = '' | 'personal' | 'enterprise';

/** User's selections from the setup wizard. */
export interface SetupChoices {
  mode: string;
  deployment_mode: DeploymentMode; // frontend-only: determines which backend method to call
  server_address: string;
  server_protocol: string;
  enable_storage: boolean;
  storage_size_gb: number;
  storage_passphrase: string;
  enable_master_password: boolean;
  master_password: string;
  enable_platform_policy: boolean;
  tpm_seal_passwords: boolean;
  password_store_mode: string;
  so_pin: string;
  user_pin: string;
  use_user_pin_as_master: boolean;
  save_pins_to_store: boolean;
  set_hierarchy_auth: boolean;
  enable_auto_unseal?: boolean;
  storage_type: string;
  barrier_password: string;
  sealer_backend: string;
  // Enterprise policy fields (frontend-only, used in enterprise wizard)
  organization_name?: string;
  min_pin_length?: number;
  require_encrypted_storage?: boolean;
  require_tpm?: boolean;
  require_platform_policy?: boolean;
  allow_auto_unseal?: boolean;
  allow_theme?: boolean;
  allow_trust_store?: boolean;
  allow_audit_log?: boolean;
  allow_sealed_data?: boolean;
  allow_change_pin?: boolean;
  allow_api_explorer?: boolean;
  api_explorer_sandbox_policy?: string;
  allow_extension?: boolean;
  force_extension_auth?: boolean;
  force_extension_pairing?: boolean;
  force_extension_audit?: boolean;
  allow_configure_extension?: boolean;
  // FIDO2 authenticator policy fields
  fido2_require_user_presence?: boolean;
  fido2_user_intent_check?: boolean;
  quick_setup?: boolean;
}

/** Describes an available sealing backend. */
export interface SealerInfo {
  id: string;
  available: boolean;
  hardware_backed: boolean;
  security_level: number;
  label: string;
  description: string;
  is_default: boolean;
  details?: Record<string, string>;
}

/** Describes a barrier seal strategy's availability. */
export interface BarrierStrategyInfo {
  id: string;
  available: boolean;
  hardware_backed: boolean;
  label: string;
}

/** Result of applying wizard choices. */
export interface SetupResult {
  success: boolean;
  errors: string[];
  warnings: string[];
  setup_complete: boolean;
}

/** Startup state returned by SetupWizardService.GetStartupState(). */
export interface StartupState {
  setup_complete: boolean;
  enterprise_mode: boolean;
  enterprise_wizard_mode: string; // "" | "so_provisioning" | "user_onboarding"
  so_pin_set: boolean;
  user_pin_set: boolean;
  policy_verified: boolean;
}

/** Result of AuthService.LoginUser() or AuthService.LoginSO(). */
export interface LoginResult {
  success: boolean;
  mode: string; // "locked" | "user" | "so_admin"
  policy_verified: boolean;
  tamper_detected: boolean;
  error?: string;
}

/** Authentication mode values. */
export type AuthMode = 'locked' | 'user' | 'so_admin';

/** Auto-generated PINs returned by SetupWizardService.GenerateSetupPINs(). */
export interface GeneratedPINs {
  so_pin: string;
  user_pin: string;
}

/** Choices for enterprise user onboarding flow. */
export interface UserOnboardingChoices {
  so_pin: string;
  user_pin: string;
  barrier_password: string;
}
