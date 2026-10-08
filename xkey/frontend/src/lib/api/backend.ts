// Wails RPC wrapper for Go backend services.

/**
 * Generic paginated response envelope used by server-side paginated endpoints.
 * When a backend method supports pagination it returns this shape so the
 * frontend can drive the Pagination component with accurate totals without
 * loading the entire dataset.
 */
export interface PagedResponse<T> {
  items: T[];
  page: number;
  page_size: number;
  total: number;
  has_more: boolean;
}

declare global {
  interface Window {
    go: {
      services: Record<string, Record<string, (...args: unknown[]) => Promise<unknown>>>;
    };
  }
}

// Type definitions matching Go structs (JSON field names).

export interface AppStatus {
  version: string;
  uptime: string;
  phone_connected: boolean;
  key_count: number;
  bridge_running: boolean;
  platform: string;
  go_version: string;
  server_connected: boolean;
  server_address: string;
  remote_key_count: number;
  oath_account_count: number;
  fido2_cred_count: number;
  piv_cert_count: number;
  tpm_available: boolean;
  tpm_device_exists: boolean;
  tpm_provisioned: boolean;
  storage_encrypted: boolean;
  storage_mounted: boolean;
  mode: string;
  sealed: boolean;
  pin_configured: boolean;
  pin_locked: boolean;
  pin_strategy: string;
  seal_strategy: string;
  hardware_backed: boolean;
}

export interface GUIConfig {
  auto_tray: boolean;
  theme: string;
  start_minimized: boolean;
  notifications: boolean;
  window_width: number;
  window_height: number;
  remember_position: boolean;
  window_x: number;
  window_y: number;
  server_address: string;
  server_protocol: string;
  server_tls_enabled: boolean;
  server_tls_skip_verify: boolean;
  server_tls_ca_file: string;
  server_auto_connect: boolean;
  auto_unseal_enabled: boolean;
  auto_unseal_blob_id: string;
  /** TPM policy the LUKS auto-unseal passphrase is sealed under ("platform", a named policy, or empty for none). */
  auto_unseal_tpm_policy: string;
  fido2_authenticator_enabled: boolean;
  clipboard_timeout: number;
  require_auth: boolean;
  app_auto_lock_minutes: number;
  app_lock_on_screen_lock: boolean;
  setup_complete: boolean;
  api_explorer_sandbox_policy: string;
  browser_extension_enabled: boolean;
  fido2_require_user_presence: boolean;
  fido2_user_intent_check: boolean;
  developer_tools: boolean;
  barrier_auto_unseal_enabled: boolean;
  /** The default sealing backend ("tpm2", "passphrase", ...); empty for the software default. */
  sealer_backend?: string;
}

export interface AutoUnsealStatus {
  available: boolean;
  configured: boolean;
  blob_id: string;
}

export interface AutoUnsealResult {
  success: boolean;
  message: string;
}

export interface BarrierAutoUnsealStatus {
  /** False when there is no local TPM policy service (no TPM, or the data
   * directory is not open yet); the frontend renders an "unavailable" panel
   * instead of retrying. */
  available: boolean;
  /** Human-readable explanation, populated only when available is false. */
  reason?: string;
  barrier_sealed: boolean;
  /** Whether a named TPM policy carries the auto-unseal mark, and its name. */
  policy_configured: boolean;
  policy_name: string;
  /** Whether the barrier password is sealed in the TPM under that policy. */
  credential_sealed: boolean;
  /** Whether the live PCRs satisfy the policy (advisory; the TPM decides). */
  pcrs_match: boolean;
}

export interface BackendOATHAccount {
  id: string;
  name: string;
  issuer: string;
  account_name: string;
  type: string;
  algorithm: string;
  digits: number;
  period: number;
  counter: number;
}

export interface TOTPCode {
  code: string;
  time_left: number;
  period: number;
  account_id: string;
}

export interface HOTPCode {
  code: string;
  counter: number;
  account_id: string;
}

export interface BackendFIDO2Credential {
  id: string;
  relying_party_id: string;
  relying_party: string;
  user_name: string;
  user_display_name: string;
  algorithm: string;
  key_type: string;
  cred_protect: number;
  backend_type: string;
  use_count: number;
  discoverable: boolean;
  created_at: string;
  last_used: string;
}

export interface BackendRelyingParty {
  id: string;
  name: string;
  credential_count: number;
}

export interface BackendBridgeStatus {
  running: boolean;
  uptime: string;
  started_at: string;
}

export interface BackendPIVSlot {
  slot: string;
  name: string;
  description: string;
  has_cert: boolean;
  has_key?: boolean;
  algorithm?: string;
  key_size?: number;
  subject?: string;
  issuer?: string;
  not_before?: string;
  not_after?: string;
  fingerprint?: string;
  backend?: string;
  backend_display_name?: string;
}

export interface PIVGenerateKeyResult {
  slot: string;
  algorithm: string;
  key_size: number;
  subject: string;
  message: string;
}

export interface PIVGenerateOptions {
  slot: string;
  algorithm: string;
  subject: string;
  organization: string;
  country: string;
  output_format: string;
  validity_days: number;
  ca_source: string;
}

export interface PIVGenerateAdvancedResult {
  slot: string;
  algorithm: string;
  key_size: number;
  subject: string;
  message: string;
  output_format: string;
  cert_pem?: string;
  public_key_pem?: string;
  csr_pem?: string;
  chain_pem?: string;
}

export interface PIVCAAvailability {
  local: boolean;
  remote: boolean;
}

export interface BackendPairedDevice {
  name: string;
  address: string;
  security_level: string;
  paired_at: string;
  last_seen: string;
  connected: boolean;
  is_backend: boolean;
  type: 'phone' | 'extension' | 'agent';
}

export interface BackendTPMStatus {
  available: boolean;
  device_exists: boolean;
  provisioned: boolean;
  status_level: string;
  manufacturer: string;
  firmware_version: string;
  device_path: string;
  init_error?: string;
}

export interface SealedBlobEntry {
  id: string;
  label: string;
  size_bytes: number;
  /** TPM policy the blob is bound to: "platform", a named policy, or "" for none. */
  tpm_policy: string;
  password_protected: boolean;
  created_at: string;
  category: string;
  backend_id: string;
  storage_type: string;  // "disk" or "nvram"
}

export interface SealRequest {
  label: string;
  data: string;
  /** TPM policy (tpm2 backend only): "platform", a named policy, or "" for none. */
  tpm_policy: string;
  /** Optional password also required to unseal. */
  password: string;
  backend?: string;
  storage_type?: string;  // "disk" (default) or "nvram"
}

export interface SealProtectionStatus {
  is_locked: boolean;
  blob_count: number;
}

export interface PasswordProtectionStatus {
  mode: string;
  tpm_available: boolean;
  key_source: string;
  is_locked: boolean;
  password_count: number;
}

export interface BackendTPMInfo {
  manufacturer: string;
  vendor_id: string;
  firmware_version: string;
  family: string;
  level: number;
  revision: string;
  max_rsa_key_size: number;
  max_ecc_key_size: number;
  pcr_banks: string[];
  algorithms: string[];
  fips_mode: boolean;
  capabilities: string[];
  max_nv_buffer_size: number;
  lockout_counter: number;
  max_auth_fail: number;
  model: string;
  active_sessions_max: number;
  auth_sessions_loaded: number;
  auth_sessions_active: number;
  persistent_loaded: number;
  persistent_avail: number;
  transient_avail: number;
  nv_indexes_defined: number;
  nv_indexes_max: number;
  commands: Array<{ code: string; name: string; description: string }>;
  ecc_curves: string[];
  input_buffer_max: number;
  max_digest_size: number;
  max_object_context: number;
  lockout_interval: number;
  lockout_recovery: number;
  fixed_properties?: Array<{ name: string; raw: string; value: string }>;
  variable_properties?: Array<{ name: string; raw: string; value: string }>;
}

export interface BackendEKInfo {
  present: boolean;
  algorithm: string;
  key_size: number;
  certificate: string;
  verified: boolean;
}

export interface BackendEKECCInfo {
  present: boolean;
  algorithm: string;
  key_size: number;
  certificate: string;
  verified: boolean;
}

export interface BackendIAKInfo {
  present: boolean;
  algorithm: string;
  key_size: number;
  handle: string;
  certificate: string;
}

export interface BackendIDevIDInfo {
  present: boolean;
  algorithm: string;
  key_size: number;
  certificate: string;
  verified: boolean;
}

export interface BackendServerStatus {
  running: boolean;
  version: string;
  address: string;
  uptime: string;
  platform: string;
  backend_count: number;
}

export interface BackendBackendInfo {
  id: string;
  type: string;
  enabled: boolean;
  connected: boolean;
  key_count: number;
  algorithms: string[];
  description: string;
  display_name?: string;
  device_name?: string;
  capabilities?: BackendCapabilityInfo;
  metadata?: Record<string, string>;
}

export interface BackendCapabilityInfo {
  signing: boolean;
  encryption: boolean;
  decryption: boolean;
  key_encapsulation: boolean;
  sealing: boolean;
  attestation: boolean;
  hardware_backed: boolean;
  quantum_signing: boolean;
  fido2: boolean;
  piv: boolean;
  oath: boolean;
  passwords: boolean;
}

export interface SupportedKeyTypes {
  algorithms: string[];
  purposes: string[];
  curves: string[];
  key_sizes: number[];
}

export interface ServerEntry {
  url: string;
  name: string;
  protocol: string;
  tls_enabled: boolean;
  spki_pin?: string;
  auto_connect: boolean;
  added_at: string;
}

export interface ServerConnectionInfo {
  url: string;
  state: string;
  version?: string;
  protocol: string;
  tls: boolean;
  error?: string;
  backend_count: number;
}

export interface ConnectionInfo {
  state: string;
  protocol: string;
  address: string;
  tls: boolean;
  version: string;
  error: string;
}

export interface RemoteKeyInfo {
  key_id: string;
  key_type: string;
  algorithm: string;
  backend: string;
  public_key_pem: string;
}

export interface BackendCapabilities {
  Keys: boolean;
  HardwareBacked: boolean;
  Signing: boolean;
  Decryption: boolean;
  KeyRotation: boolean;
  SymmetricEncryption: boolean;
  Sealing: boolean;
  Import: boolean;
  Export: boolean;
  KeyAgreement: boolean;
  ECIES: boolean;
  Attestation: boolean;
  QuantumSigning: boolean;
  KeyEncapsulation: boolean;
}

export interface RemoteBackendInfo {
  id: string;
  type: string;
  hardware_backed: boolean;
  capabilities: BackendCapabilities;
}

export interface GenerateKeyParams {
  key_id: string;
  backend: string;
  purpose?: string;
  algorithm: string;
  key_size?: number;
  curve?: string;
  exportable?: boolean;
  // TPM-specific fields
  /** TPM policy the key is bound to: "" or "platform" for the built-in policy, or a named policy. */
  tpm_policy?: string;
  hierarchy?: string;
  handle?: number;
  is_primary?: boolean;
  parent_handle?: number;
}

export interface GenerateKeyResult {
  key_id: string;
  key_type: string;
  public_key_pem: string;
  message: string;
}

export interface AttestKeyResult {
  format: string;
  certificate_chain: string[];
  attestation_data: string;
  signature: string;
}

export interface BackendPCRValue {
  index: number;
  bank: string;
  digest: string;
}

export interface BackendQuote {
  quote_data: string;
  signature: string;
  pcr_digest: string;
  nonce: string;
  created_at: string;
}

export interface BackendSharedSRKInfo {
  present: boolean;
  algorithm: string;
  handle: string;
}

export interface BackendPlatformSRKInfo {
  present: boolean;
  algorithm: string;
  handle: string;
  policy_enabled: boolean;
  policy_name: string;
  initialized: boolean;
}

export interface BackendEventLogEntry {
  pcr_index: number;
  event_type: string;
  digest_hex: string;
  event_data: string;
}

export interface BackendCertifyKeyResult {
  attested: string;
  signature: string;
  nonce: string;
}

export interface BackendStorageStatus {
  volume_exists: boolean;
  is_luks: boolean;
  is_mounted: boolean;
  is_open: boolean;
  volume_path: string;
  mount_point: string;
  volume_size_bytes: number;
  elevation_available: boolean;
}

export interface QRScanResult {
  uri: string;
  display_index: number;
}

export interface NotificationRequest {
  title: string;
  message: string;
}

export interface BackendTPMKey {
  id: string;
  algorithm: string;
  key_size: number;
  persistent: boolean;
  purpose: string;
}

/** One enrolled factor of the caller's personal password vault (no key material). */
export interface PasswordVaultFactor {
  id: string;
  /** "passphrase", "passkey", "piv", "certificate", "tpm" or "recovery". */
  factor: string;
  label: string;
  created_at: string;
  /** Key factors: the key's fingerprint and where it lives in xKey. */
  key_fingerprint?: string;
  key_backend?: string;
  key_id?: string;
  tpm_policy?: string;
  certificate_subject?: string;
}

/** The caller's personal password vault on the connected xkmsd server. */
export interface PasswordVaultStatus {
  initialized: boolean;
  unlocked: boolean;
  factors: PasswordVaultFactor[];
}

/**
 * An enrolled vault factor and, on the first enrollment or a recovery, the
 * recovery code the server shows exactly once.
 */
export interface PasswordVaultEnrollResult {
  factor: PasswordVaultFactor;
  recovery_code?: string;
}

export interface StaticPasswordEntry {
  id: string;
  name: string;
  title: string;
  username: string;
  password: string;
  url: string;
  match_patterns?: string[];
  notes: string;
  folder_path: string;
  backend_id: string;
  expires_at: string;
  created_at: string;
  updated_at: string;
  is_expired: boolean;
  days_until_expiry: number;
  read_only: boolean;
}

export interface AddPasswordParams {
  name: string;
  title: string;
  username: string;
  password: string;
  url: string;
  match_patterns?: string[];
  notes: string;
  folder_path: string;
  expires_at: string;
  /** Marks the entry read-only. */
  read_only?: boolean;
}

export interface UpdatePasswordParams {
  id: string;
  name: string;
  title: string;
  username: string;
  password: string;
  url: string;
  match_patterns?: string[];
  notes: string;
  folder_path: string;
  expires_at: string;
}

// Password import types
export interface ImportParams {
  file_path: string;
  format: string;  // "csv", "xml", "kdbx" or empty for auto-detect
  password: string;  // Required for KDBX
  target_folder: string;  // Optional folder prefix
  skip_duplicates: boolean;
  overwrite_duplicates: boolean;
  import_totp: boolean;
}

export interface ImportError {
  entry_name: string;
  error: string;
}

export interface ImportResult {
  imported: number;
  skipped: number;
  failed: number;
  errors: ImportError[];
  totp_imported: number;
  duration_ms: number;
}

export interface ImportPreviewEntry {
  title: string;
  username: string;
  url: string;
  folder_path: string;
  has_totp: boolean;
  tags: string[];
}

export interface ImportPreviewResult {
  entries: ImportPreviewEntry[];
  total: number;
  format: string;
}

export interface FIDO2DeviceStatus {
  running: boolean;
  device_name: string;
  vendor_id: string;
  product_id: string;
  has_pending_touch: boolean;
  authenticator_available: boolean;
  reason?: string;
  raw_reason?: string;
}

export interface HandleInfo {
  handle: string;
  algorithm: string;
  type: string;
  description: string;
}

export interface LockoutInfo {
  counter: number;
  max_fail: number;
  interval: number;
  recovery: number;
  is_locked: boolean;
}

export interface NVIndexEntry {
  handle: string;
  type: string;
  size: number;
  auth_read: boolean;
  auth_write: boolean;
}

export interface NVSummary {
  indexes_defined: number;
  indexes_max: number;
  indexes: NVIndexEntry[];
}

export interface KeyViewData {
  name: string;
  algorithm: string;
  key_size: number;
  handle: string;
  public_key_pem: string;
  certificate: string;
}

export interface VerificationStatus {
  status: string;
  issuer: string;
  subject: string;
  not_before: string;
  not_after: string;
  ca_imported: boolean;
  error: string;
}

export interface ExtensionInfo {
  oid: string;
  name: string;
  critical: boolean;
  value: string;
}

export interface CertificateDetails {
  version: number;
  serial_number: string;
  subject_cn: string;
  subject_org: string;
  subject_org_unit: string;
  subject_country: string;
  subject_province: string;
  subject_locality: string;
  subject_serial_number: string;
  issuer_cn: string;
  issuer_org: string;
  issuer_org_unit: string;
  issuer_country: string;
  not_before: string;
  not_after: string;
  signature_algorithm: string;
  signature_hex: string;
  fingerprint_sha256: string;
  fingerprint_sha1: string;
  fingerprint_md5: string;
  public_key_algorithm: string;
  public_key_size: number;
  public_key_hex: string;
  subject_key_id: string;
  is_ca: boolean;
  max_path_len: number;
  max_path_len_zero: boolean;
  key_usage: string;
  ext_key_usage: string[];
  subject_alt_names: string;
  extensions: ExtensionInfo[];
}

/** A TPM policy condition type (transport.TPMPolicyCondition). */
export type TPMPolicyConditionType = 'pcr' | 'auth_value' | 'locality';

/** One condition of a policy branch (transport.TPMPolicyCondition). */
export interface TPMPolicyCondition {
  type: TPMPolicyConditionType;
  bank?: string;
  pcrs?: number[];
  /** Hex PCR values captured from the TPM, keyed by PCR index; reported only. */
  pcr_values?: Record<string, string>;
  pcr_digest?: string;
  localities?: number[];
}

/** One branch of a policy: the AND of its conditions (transport.TPMPolicyBranch). */
export interface TPMPolicyBranch {
  conditions: TPMPolicyCondition[];
  /** Whether the branch holds an approval; reported only. */
  approved?: boolean;
}

/** A named TPM policy (services.TPMPolicyInfo): an OR of branches. */
export interface TPMPolicyInfo {
  name: string;
  /** The built-in platform policy: the platform PCR or the object's password. */
  builtin: boolean;
  description?: string;
  /** The policy's branches, tried in order; the built-in policy has none. */
  branches?: TPMPolicyBranch[];
  index?: number;
  approved: boolean;
  epoch?: number;
  authority_generation?: number;
  auto_unseal: boolean;
  object_count: number;
  created_at?: string;
  updated_at?: string;
}

/** One branch's verification (transport.TPMPolicyBranchVerification). */
export interface TPMPolicyBranchVerification {
  match: boolean;
  mismatched?: number[];
  approved: boolean;
}

/** Live PCRs compared with a policy's captured values, per branch (services.TPMPolicyVerification). */
export interface TPMPolicyVerification {
  name: string;
  match: boolean;
  approved: boolean;
  branches: TPMPolicyBranchVerification[];
}

/** Where TPM policy operations run (services.TPMPolicyStatus). */
export interface TPMPolicyStatus {
  available: boolean;
  /** "local", "server" or "unavailable". */
  mode: string;
  scope: string;
}

/** The policy authority a rotation installed (services.TPMAuthorityInfo). */
export interface TPMAuthorityInfo {
  generation: number;
  authority_name: string;
  epoch: number;
}

/** The policy a TPM object was created under (services.TPMObjectPolicyInfo). */
export interface TPMObjectPolicyInfo {
  object_id: string;
  kind: string;
  policy: string;
  auth_policy?: string;
  created_at?: string;
}

export interface PCRReplayEntry {
  pcr_index: number;
  bank: string;
  expected: string;
  actual: string;
  match: boolean;
}

export interface EventLogReplayResult {
  success: boolean;
  total_pcrs: number;
  match_count: number;
  mismatch_count: number;
  entries: PCRReplayEntry[];
  banks: string[];
  event_count: number;
  error?: string;
}

export interface TrustCertInfo {
  fingerprint: string;
  subject: string;
  issuer: string;
  algorithm: string;
  not_before: string;
  not_after: string;
  is_ca: boolean;
  is_expired: boolean;
  purpose: string;
  source: string;
  tags: string[];
  system_installed: boolean;
}

export type OIDCProviderType = 'oidc' | 'aws';

export interface OIDCProviderEntry {
  name: string;
  type: OIDCProviderType;
  template?: string;
  issuer: string;
  client_id: string;
  client_secret?: string;
  redirect_url: string;
  scopes: string[];
  exec?: string;
  auto_refresh: number;
  background: boolean;
  log_file?: string;
  dpop?: boolean;
  aws_region?: string;
  aws_profile?: string;
  aws_credentials_file?: string;
  aws_output?: string;
  aws_cross_device?: boolean;
  aws_session_store?: string;
}

export interface OIDCProviderTemplateInfo {
  name: string;
  description: string;
  issuer: string;
  scopes: string[];
  requires_region: boolean;
  requires_issuer: boolean;
  type: OIDCProviderType;
  dpop?: boolean;
}

/** A server credential's scope: shared with the tenant, or personal. */
export type OIDCServerScope = 'tenant' | 'user';

/** A server credential's status (transport.OIDCCredentialStatus*). */
export type OIDCServerStatus = 'pending' | 'active' | 'relogin_required' | 'expired';

/** Names a server credential (transport.OIDCCredentialRef). */
export interface OIDCServerCredentialRef {
  tenant_id?: string;
  scope: OIDCServerScope;
  owner?: string;
  name: string;
}

/** A server credential's provider configuration (transport.OIDCCredentialConfig). */
export interface OIDCServerCredentialConfig {
  template?: string;
  issuer?: string;
  client_id?: string;
  client_secret?: string;
  scopes?: string[];
  device_authorization_endpoint?: string;
}

/** Tokens imported into a server credential (services.OIDCServerTokens). */
export interface OIDCServerTokens {
  access_token: string;
  refresh_token?: string;
  id_token?: string;
  /** RFC 3339; empty lets the server date the token. */
  expires_at?: string;
}

/** A device login in progress (services.OIDCServerDeviceLogin). */
export interface OIDCServerDeviceLogin {
  user_code: string;
  verification_uri: string;
  verification_uri_complete?: string;
  interval_seconds: number;
  expires_at: string;
}

/** A server credential's public view (services.OIDCServerCredentialInfo); it never carries a token. */
export interface OIDCServerCredentialInfo extends OIDCServerCredentialRef {
  template?: string;
  issuer?: string;
  client_id?: string;
  scopes?: string[];
  status: OIDCServerStatus;
  status_reason?: string;
  expires_at?: string;
  refreshable: boolean;
  last_refresh?: string;
  last_error?: string;
  device_login?: OIDCServerDeviceLogin;
  created_at?: string;
  updated_at?: string;
  created_by?: string;
  supports_device: boolean;
}

/** A template a server credential can be created from (services.OIDCServerTemplateInfo). */
export interface OIDCServerTemplateInfo {
  name: string;
  description: string;
  issuer?: string;
  scopes?: string[];
  requires_issuer: boolean;
  supports_device: boolean;
  supports_import: boolean;
  no_refresh: boolean;
}

export interface OIDCTokenInfo {
  provider: string;
  issuer: string;
  subject: string;
  email: string;
  name: string;
  expires_at: string;
  expires_in: number;
  scopes: string[];
  is_expired: boolean;
  has_refresh: boolean;
  has_dpop: boolean;
}

export interface OIDCLoginResult {
  success: boolean;
  token?: OIDCTokenInfo;
  error?: string;
}

export interface OIDCRefreshStatus {
  provider: string;
  running: boolean;
  last_refresh?: string;
  next_refresh?: string;
  refresh_count: number;
  last_status?: string;
  last_error?: string;
}

export interface OIDCExecResult {
  success: boolean;
  exit_code: number;
  stdout: string;
  stderr: string;
  error?: string;
}

export interface OIDCSavedScript {
  name: string;
  file_name: string;
}

export interface AvailableToken {
  id: string;
  source: string;
  label: string;
  token: string;
  expires_at: string;
  is_expired: boolean;
}

export interface IdentityConfig {
  common_name: string;
  organization: string;
  organizational_unit: string;
  country: string;
  province: string;
  locality: string;
}

export interface BarrierStatus {
  sealed: boolean;
  strategy: string;
  hardware_backed: boolean;
  initialized_at: string;
}

export interface BarrierSealInfo {
  initialized: boolean;
  sealed: boolean;
  strategy: string;
  strategy_label: string;
  hardware_backed: boolean;
  data_dir: string;
  root_key_entry: string;
}

export interface PINStatus {
  so_pin_set: boolean;
  user_pin_set: boolean;
  initialized: boolean;
  strategy: string;
  so_pin_supported: boolean;
}

export interface LockoutStatus {
  failed_attempts: number;
  max_attempts: number;
  is_locked: boolean;
  lockout_until: string;
  recovery_seconds: number;
}

export interface RemoteCertificateInfo {
  backend: string;
  key_id: string;
  subject: string;
  issuer: string;
  not_before: string;
  not_after: string;
  algorithm: string;
  is_ca: boolean;
  is_expired: boolean;
  fingerprint: string;
  pem: string;
}

// PKCS#11 Token Management Types
export interface PKCS11ProbeResult {
  library_path: string;
  display_name: string;
}

export interface PKCS11SlotInfo {
  slot_id: number;
  label: string;
  serial: string;
  manufacturer: string;
  model: string;
  token_present: boolean;
  initialized: boolean;
  hardware_version: string;
  firmware_version: string;
}

export interface PKCS11ModuleInfo {
  id: string;
  display_name: string;
  library_path: string;
  state: string;
  slots: PKCS11SlotInfo[];
  error_msg?: string;
}

export interface PKCS11TokenInfo {
  module_id: string;
  module_name: string;
  slot_id: number;
  label: string;
  manufacturer: string;
  model: string;
  serial: string;
  initialized: boolean;
  connected: boolean;
}

export interface PKCS11ConnectionInfo {
  module_id: string;
  slot_id: number;
  token_label: string;
}

// Team management types.

export interface TeamInfo {
  id: number;
  name: string;
  tenant_id: string;
  owner_id: string;
  members: string[];
  created_at: string;
  updated_at: string;
}

export interface CreateTeamParams {
  name: string;
}

// SSH key management types.

export interface SSHKeyInfo {
  name: string;
  algorithm: string;
  public_key: string;
  fingerprint: string;
  comment: string;
  backend: string;
  /** Underlying backend key CN for a backend-backed key; '' for software keys. */
  backend_key_id: string;
  created_at: string;
}

export interface SSHBackendInfo {
  id: string;
  display_name: string;
  category: string;
  location: string;
  is_default: boolean;
}

export interface SSHGenerateParams {
  name: string;
  algorithm: string;
  rsa_bits: number;
  comment: string;
  backend: string;
}

// SSH profile management types.

export interface SSHProfileEntry {
  id: string;
  name: string;
  folder_path: string;
  host: string;
  port: number;
  user: string;
  key_scope: string;
  key_owner: string;
  key_name: string;
  /** '' = xkey-managed key (key_name); 'local' = operator's agent/~/.ssh keys. */
  key_source: '' | 'local';
  /** ssh_config Host alias used when key_source is 'local' (optional). */
  ssh_config_alias: string;
  /**
   * Pins one specific local key when key_source is 'local': an identity file
   * path or "agent:<SHA256-fingerprint>". Empty offers every local identity.
   */
  local_identity: string;
  /**
   * Records embedded-console sessions from this profile in the persistent
   * session store (tabs restored after reload/restart). Default false =
   * memory-only sessions.
   */
  persist_session: boolean;
  options?: string[];
  notes: string;
  /** Per-profile console mode override. Empty string means use the global default. */
  console_mode: 'system' | 'embedded' | '';
  created_at: string;
  updated_at: string;
}

export interface SSHProfileParams {
  id?: string;
  name: string;
  folder_path: string;
  host: string;
  port: number;
  user: string;
  key_scope: string;
  key_owner: string;
  key_name: string;
  /** '' = xkey-managed key (key_name); 'local' = operator's agent/~/.ssh keys. */
  key_source?: '' | 'local';
  /** ssh_config Host alias used when key_source is 'local' (optional). */
  ssh_config_alias?: string;
  /** Identity file path or "agent:<fp>" pin when key_source is 'local'. */
  local_identity?: string;
  /** Persist embedded-console sessions from this profile (default false). */
  persist_session?: boolean;
  options?: string[];
  notes: string;
  /** Per-profile console mode override. Empty string means use the global default. */
  console_mode: 'system' | 'embedded' | '';
}

/** Response from SSHConsoleService.OpenProfileConsole / OpenConsole. */
export interface SSHConsoleInfo {
  url: string;
  token: string;
}

/**
 * A persisted embedded-console session: a display title plus its reconnect
 * origin (one-time connection fields, a profile ID, or an ssh_config alias).
 * Only sessions explicitly started with persistence enabled are recorded.
 */
export interface SSHConsoleSessionRecord {
  id?: string;
  title: string;
  host?: string;
  port?: number;
  user?: string;
  key_scope?: string;
  key_owner?: string;
  key_name?: string;
  key_source?: string;
  local_identity?: string;
  profile_id?: string;
  alias?: string;
  created_at?: string;
  last_connected_at?: string;
}

// SSH one-time connection params.

export interface SSHConnectParams {
  host: string;
  port: number;
  user: string;
  key_scope: string;
  key_owner: string;
  key_name: string;
  /** '' = xkey-managed key (key_name); 'local' = operator's agent/~/.ssh keys. */
  key_source?: '' | 'local';
  /** ssh_config Host alias for a 'local' passthrough connection (optional). */
  ssh_config_alias?: string;
  /** Identity file path or "agent:<fp>" pin when key_source is 'local'. */
  local_identity?: string;
}

// SSH local-integration types (ssh-agent + ~/.ssh discovery).

/** A key discovered from the local ssh-agent or ~/.ssh directory (read-only). */
export interface SSHLocalKeyInfo {
  source: 'agent' | 'file';
  path: string;
  key_type: string;
  fingerprint: string;
  comment: string;
}

/** A host entry parsed from ~/.ssh/config. */
export interface SSHConfigHostEntry {
  alias: string;
  hostname: string;
  user: string;
  port: number;
  identity_files: string[];
}

// SSHProfileService wraps the Go SSHProfileService Wails bindings.
export const SSHProfileService = {
  async listProfiles(): Promise<SSHProfileEntry[] | null> {
    return callBackend<SSHProfileEntry[]>('SSHProfileService', 'ListProfiles');
  },
  async listProfilesByFolder(folderPath: string): Promise<SSHProfileEntry[] | null> {
    return callBackend<SSHProfileEntry[]>('SSHProfileService', 'ListProfilesByFolder', folderPath);
  },
  async listFolders(): Promise<string[] | null> {
    return callBackend<string[]>('SSHProfileService', 'ListFolders');
  },
  async getProfile(idOrName: string): Promise<SSHProfileEntry | null> {
    return callBackend<SSHProfileEntry>('SSHProfileService', 'GetProfile', idOrName);
  },
  async addProfile(params: SSHProfileParams): Promise<SSHProfileEntry | null> {
    return callBackend<SSHProfileEntry>('SSHProfileService', 'AddProfile', params);
  },
  async updateProfile(params: SSHProfileParams): Promise<boolean> {
    return callBackendVoid('SSHProfileService', 'UpdateProfile', params);
  },
  async deleteProfile(idOrName: string): Promise<boolean> {
    return callBackendVoid('SSHProfileService', 'DeleteProfile', idOrName);
  },
  async moveProfile(idOrName: string, folderPath: string): Promise<boolean> {
    return callBackendVoid('SSHProfileService', 'MoveProfile', idOrName, folderPath);
  },
  async createFolder(path: string): Promise<boolean> {
    return callBackendVoid('SSHProfileService', 'CreateFolder', path);
  },
  async renameFolder(oldPath: string, newPath: string): Promise<boolean> {
    return callBackendVoid('SSHProfileService', 'RenameFolder', oldPath, newPath);
  },
  async deleteFolder(path: string): Promise<boolean> {
    return callBackendVoid('SSHProfileService', 'DeleteFolder', path);
  },
  async searchProfiles(query: string): Promise<SSHProfileEntry[] | null> {
    return callBackend<SSHProfileEntry[]>('SSHProfileService', 'SearchProfiles', query);
  },
};

// SSHConnectService wraps the Go SSHConnectService Wails bindings.
export const SSHConnectService = {
  async connectProfile(profileID: string): Promise<boolean> {
    return callBackendVoid('SSHConnectService', 'ConnectProfile', profileID);
  },
  async connectOneTime(params: SSHConnectParams): Promise<boolean> {
    return callBackendVoid('SSHConnectService', 'ConnectOneTime', params);
  },
  async connectOneTimeWithError(params: SSHConnectParams): Promise<{ ok: boolean; error?: string }> {
    return callBackendVoidWithError('SSHConnectService', 'ConnectOneTime', params);
  },
  async setTerminalCommand(cmd: string): Promise<boolean> {
    return callBackendVoid('SSHConnectService', 'SetTerminalCommand', cmd);
  },
  async setStrictHostKeyChecking(policy: string): Promise<boolean> {
    return callBackendVoid('SSHConnectService', 'SetStrictHostKeyChecking', policy);
  },
  async setKnownHostsPolicy(policy: string): Promise<boolean> {
    return callBackendVoid('SSHConnectService', 'SetKnownHostsPolicy', policy);
  },
  async connectConfigHost(alias: string): Promise<boolean> {
    return callBackendVoid('SSHConnectService', 'ConnectConfigHost', alias);
  },
};

// SSHConsoleService wraps the Go SSHConsoleService Wails bindings.
export const SSHConsoleService = {
  async openProfileConsole(profileID: string): Promise<SSHConsoleInfo | null> {
    return callBackend<SSHConsoleInfo>('SSHConsoleService', 'OpenProfileConsole', profileID);
  },
  async openProfileConsoleWithError(profileID: string): Promise<{ result: SSHConsoleInfo | null; error?: string }> {
    return callBackendWithError<SSHConsoleInfo>('SSHConsoleService', 'OpenProfileConsole', profileID);
  },
  async openConsole(params: SSHConnectParams): Promise<SSHConsoleInfo | null> {
    return callBackend<SSHConsoleInfo>('SSHConsoleService', 'OpenConsole', params);
  },
  async openConsoleWithError(params: SSHConnectParams): Promise<{ result: SSHConsoleInfo | null; error?: string }> {
    return callBackendWithError<SSHConsoleInfo>('SSHConsoleService', 'OpenConsole', params);
  },
  async openConfigHostConsole(alias: string): Promise<SSHConsoleInfo | null> {
    return callBackend<SSHConsoleInfo>('SSHConsoleService', 'OpenConfigHostConsole', alias);
  },
  async openConfigHostConsoleWithError(alias: string): Promise<{ result: SSHConsoleInfo | null; error?: string }> {
    return callBackendWithError<SSHConsoleInfo>('SSHConsoleService', 'OpenConfigHostConsole', alias);
  },
  async setHostKeyPolicy(policy: string): Promise<boolean> {
    return callBackendVoid('SSHConsoleService', 'SetHostKeyPolicy', policy);
  },
  async saveSession(record: SSHConsoleSessionRecord): Promise<SSHConsoleSessionRecord | null> {
    return callBackend<SSHConsoleSessionRecord>('SSHConsoleService', 'SaveSession', record);
  },
  async listSessions(): Promise<SSHConsoleSessionRecord[] | null> {
    return callBackend<SSHConsoleSessionRecord[]>('SSHConsoleService', 'ListSessions');
  },
  async deleteSession(id: string): Promise<boolean> {
    return callBackendVoid('SSHConsoleService', 'DeleteSession', id);
  },
  async setKnownHostsPolicy(policy: string): Promise<boolean> {
    return callBackendVoid('SSHConsoleService', 'SetKnownHostsPolicy', policy);
  },
};

// SSHLocalService wraps the Go SSHLocalService Wails bindings (ssh-agent +
// ~/.ssh discovery: local keys and ssh_config hosts).
export const SSHLocalService = {
  async listConfigHosts(): Promise<SSHConfigHostEntry[] | null> {
    return callBackend<SSHConfigHostEntry[]>('SSHLocalService', 'ListConfigHosts');
  },
  async listLocalKeys(): Promise<SSHLocalKeyInfo[] | null> {
    return callBackend<SSHLocalKeyInfo[]>('SSHLocalService', 'ListLocalKeys');
  },
};

// TeamService wraps the Go TeamService Wails bindings.
export const TeamService = {
  async createTeam(name: string): Promise<TeamInfo | null> {
    return callBackend<TeamInfo>('TeamService', 'CreateTeam', name);
  },
  async listTeams(): Promise<TeamInfo[] | null> {
    return callBackend<TeamInfo[]>('TeamService', 'ListTeams');
  },
  async getTeam(name: string): Promise<TeamInfo | null> {
    return callBackend<TeamInfo>('TeamService', 'GetTeam', name);
  },
  async deleteTeam(name: string): Promise<boolean> {
    return callBackendVoid('TeamService', 'DeleteTeam', name);
  },
  async addMember(teamName: string, memberID: string): Promise<boolean> {
    return callBackendVoid('TeamService', 'AddMember', teamName, memberID);
  },
  async removeMember(teamName: string, memberID: string): Promise<boolean> {
    return callBackendVoid('TeamService', 'RemoveMember', teamName, memberID);
  },
};

export function isWailsAvailable(): boolean {
  return typeof window !== 'undefined' && window.go !== undefined;
}

/**
 * notifyBackendUnavailable shows an error toast when a user-initiated action
 * cannot proceed because no backend is connected. The same operations are
 * available via the xkey CLI and via the Wails desktop runtime — only this
 * standalone browser preview lacks a backend connection.
 */
export function notifyBackendUnavailable(action: string): void {
  // Dynamically import to avoid a top-level circular dependency between
  // the API module and the Svelte store layer.
  import('$lib/stores/notifications').then(({ addNotification }) => {
    addNotification('error', `${action} is not available — no backend connection`);
  });
}

export async function callBackend<T>(
  service: string,
  method: string,
  ...args: unknown[]
): Promise<T | null> {
  if (!isWailsAvailable()) return null;
  try {
    return await (window.go.services as any)[service][method](...args) as T;
  } catch (err) {
    console.error(`Backend call ${service}.${method} failed:`, err);
    return null;
  }
}

/**
 * callBackendWithError calls a Go backend method and returns both the result
 * and any error message, allowing callers to distinguish between a successful
 * null/empty result and a backend error.
 */
export async function callBackendWithError<T>(
  service: string,
  method: string,
  ...args: unknown[]
): Promise<{ result: T | null; error?: string }> {
  if (!isWailsAvailable()) return { result: null };
  try {
    const result = await (window.go.services as any)[service][method](...args) as T;
    return { result };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`Backend call ${service}.${method} failed:`, message);
    return { result: null, error: message };
  }
}

/**
 * callBackendVoidWithError calls a Go backend method that returns only `error`,
 * returning both the success status and the error message string so callers
 * can inspect the failure reason (e.g. to detect TPM authorization errors).
 */
export async function callBackendVoidWithError(
  service: string,
  method: string,
  ...args: unknown[]
): Promise<{ ok: boolean; error?: string }> {
  if (!isWailsAvailable()) return { ok: true };
  try {
    await (window.go.services as any)[service][method](...args);
    return { ok: true };
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error(`Backend call ${service}.${method} failed:`, message);
    return { ok: false, error: message };
  }
}

/** Checks if a backend error indicates TPM authorization is required. */
export function isTPMAuthError(error?: string): boolean {
  if (!error) return false;
  return error.includes('authorization required');
}

/**
 * callBackendVoid calls a Go backend method that returns only `error`.
 * On success (Go nil error), Wails returns JSON null which is indistinguishable
 * from the null returned by callBackend on failure. This variant uses a
 * try/catch to distinguish success (true) from failure (false).
 */
export async function callBackendVoid(
  service: string,
  method: string,
  ...args: unknown[]
): Promise<boolean> {
  if (!isWailsAvailable()) return true;
  try {
    await (window.go.services as any)[service][method](...args);
    return true;
  } catch (err) {
    console.error(`Backend call ${service}.${method} failed:`, err);
    return false;
  }
}
