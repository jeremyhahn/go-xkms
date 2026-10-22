/**
 * TypeScript types matching the Go structs in pkg/admin/types.go.
 */

// ---------------------------------------------------------------------------
// Pagination & Response envelope
// ---------------------------------------------------------------------------

export interface Pagination {
  page: number;
  per_page: number;
  total: number;
}

export interface ApiResponse<T = unknown> {
  success: boolean;
  data?: T;
  error?: ApiError;
  pagination?: Pagination;
}

export interface ApiError {
  code: string;
  message: string;
}

export interface PaginatedResponse<T> {
  data: T[];
  pagination: Pagination;
}

export interface ListParams {
  page?: number;
  per_page?: number;
  status?: string;
}

// ---------------------------------------------------------------------------
// CA Status & Stats
// ---------------------------------------------------------------------------

export interface CAKeyInfo {
  algorithm: string;
  signature_algorithm: string;
  store: string;
  key_size?: number;
  curve?: string;
  default: boolean;
}

export interface CAStatus {
  identity: string;
  initialized: boolean;
  version: string;
  started_at: string;
  key_algorithm: string;
  signature_algorithm: string;
  root_ca: string;
  intermediate_ca?: string;
  keys?: CAKeyInfo[];
}

export interface CAStats {
  total_certificates: number;
  valid_certificates: number;
  revoked_certificates: number;
  expired_certificates: number;
  total_accounts: number;
  active_accounts: number;
  total_orders: number;
  pending_orders: number;
  completed_orders: number;
}

// ---------------------------------------------------------------------------
// Certificates
// ---------------------------------------------------------------------------

export interface CertificateInfo {
  id: number;
  serial_number: string;
  subject: string;
  issuer: string;
  not_before: string;
  not_after: string;
  status: string;
  issued_at: string;
  cert_url?: string;
}

export interface ListCertificatesParams extends ListParams {
  subject?: string;
  expires_days?: number;
}

export interface RevokeRequest {
  reason?: string;
}

// ---------------------------------------------------------------------------
// Accounts
// ---------------------------------------------------------------------------

export interface AccountInfo {
  id: number;
  status: string;
  contact?: string[];
  created_at: string;
  terms_of_service_agreed: boolean;
  orders_url: string;
  order_count: number;
}

export interface ListAccountsParams extends ListParams {}

// ---------------------------------------------------------------------------
// Orders
// ---------------------------------------------------------------------------

export interface OrderInfo {
  id: number;
  account_id: number;
  status: string;
  identifiers: string[];
  not_before?: string;
  not_after?: string;
  expires?: string;
  certificate?: string;
  created_at: string;
}

export interface ListOrdersParams extends ListParams {
  account_id?: number;
}

// ---------------------------------------------------------------------------
// Tenants
// ---------------------------------------------------------------------------

export interface TenantInfo {
  id: string;
  name: string;
  status: string;
  root_ca?: TenantRootCAInfo;
  intermediate_cas?: TenantIntCAInfo[];
  default_intermediate_ca_id?: string;
  settings?: TenantSettingsInfo;
  created_at: string;
  updated_at: string;
  created_by?: string;
}

/** A page of the core tenant collection (GET /api/v1/tenants/). */
export interface TenantListResponse {
  tenants: TenantInfo[];
  pagination: {
    page: number;
    page_size: number;
    total: number;
    has_more: boolean;
  };
}

export interface TenantRootCAInfo {
  common_name: string;
  serial_number?: string;
  key_algorithm: string;
  not_before: string;
  not_after: string;
  status: string;
  created_at: string;
}

export interface TenantIntCAInfo {
  id: string;
  common_name: string;
  serial_number?: string;
  parent_type: string;
  purpose?: string;
  key_algorithm: string;
  not_before: string;
  not_after: string;
  status: string;
  created_at: string;
  updated_at?: string;
}

export interface TenantSettingsInfo {
  max_certificates?: number;
  max_accounts?: number;
  allowed_key_algorithms?: string[];
  allowed_challenge_types?: string[];
  certificate_validity_days?: number;
  require_eab?: boolean;
  allow_endorse_01?: boolean;
  allow_enroll_01?: boolean;
  compliance_config?: ComplianceConfigInfo;
}

export interface ComplianceConfigInfo {
  enabled: boolean;
  require_signed_report: boolean;
  custom_policy_path?: string;
  fail_open: boolean;
}

export interface TenantCAStatusInfo {
  tenant_id: string;
  root_ca?: TenantRootCAInfo;
  intermediate_cas?: TenantIntCAInfo[];
  default_intermediate_ca_id?: string;
  active_ca_count: number;
  can_issue_certificates: boolean;
}

export interface CreateTenantRequest {
  id: string;
  name: string;
  settings?: TenantSettingsInfo;
}

export interface UpdateTenantRequest {
  name?: string;
  settings?: TenantSettingsInfo;
}

export interface UpdateTenantStatusRequest {
  status: string;
}

export interface CreateTenantRootCARequest {
  common_name: string;
  key_algorithm: string;
  validity_years: number;
}

export interface CreateTenantIntermediateCARequest {
  common_name: string;
  parent_type: string;
  purpose?: string;
  key_algorithm: string;
  validity_years: number;
  set_as_default?: boolean;
}

export interface UpdateTenantDefaultCARequest {
  intermediate_ca_id: string;
}

export interface UpdateIntermediateCAStatusRequest {
  status: string;
}

// ---------------------------------------------------------------------------
// EAB (External Account Binding)
// ---------------------------------------------------------------------------

export interface EABInfo {
  id: string;
  tenant_id?: string;
  status: string;
  purpose: string;
  account_id?: number;
  external_account_id?: string;
  device_info?: EABDeviceInfoDTO;
  contact?: string[];
  created_at: string;
  created_by?: string;
  used_at?: string;
  expires_at?: string;
}

export interface EABDeviceInfoDTO {
  device_id?: string;
  manufacturer?: string;
  model?: string;
  ek_public_key_hash?: string;
  tpm_manufacturer?: string;
  tpm_firmware_version?: string;
  metadata?: Record<string, string>;
}

export interface CreateEABRequest {
  purpose?: string;
  external_account_id?: string;
  device_info?: EABDeviceInfoDTO;
  contact?: string[];
  expires_in_days?: number;
  metadata?: Record<string, string>;
}

export interface CreateEABResponse {
  id: string;
  mac_key: string;
  algorithm: string;
  expires_at?: string;
}

export interface ListEABParams extends ListParams {
  purpose?: string;
}

// ---------------------------------------------------------------------------
// Audit
// ---------------------------------------------------------------------------

export interface AuditLog {
  id: number;
  timestamp: string;
  actor: string;
  action: string;
  resource: string;
  details?: string;
  success: boolean;
}

export interface ListAuditLogsParams extends ListParams {
  start_time?: string;
  end_time?: string;
  actor?: string;
  action?: string;
  resource?: string;
}

// ---------------------------------------------------------------------------
// ACME Client types
// ---------------------------------------------------------------------------

// registerRequest mirrors pkg/gui/client/api/acme_handlers.go:registerRequest.
// The handler only accepts {email}; the legacy contact/EAB fields are not
// supported by the current Go backend.
export interface RegisterRequest {
  email: string;
}

// registerResponse mirrors pkg/gui/client/api/acme_handlers.go:registerResponse.
export interface RegisterResponse {
  accountUrl?: string;
  status: string;
  contact: string[];
}

// AddAccountRequest mirrors pkg/gui/client/api/acme_handlers.go:addAccountRequest.
// Use via POST /api/v1/accounts to register a new ACME account with the
// directory URL, email, and key configuration.
export interface AddAccountKey {
  algorithm: 'ECDSA' | 'RSA' | string;
  store: string;
  ecc?: { curve: string };
  rsa?: { bits: number };
}

export interface AddAccountEAB {
  kid: string;
  hmac_key: string;
}

export interface AddAccountRequest {
  name: string;
  email: string;
  directory: string;
  key?: AddAccountKey;
  transport?: string;
  server_addr?: string;
  eab?: AddAccountEAB;
  trusted_roots?: string[];
  request_server_bundle?: boolean;
}

// AddAccountResponse mirrors the writeJSON body in addAccount handler:
// {"status":"created","name":"..."}.
export interface AddAccountResponse {
  status: string;
  name: string;
}

// certNameRequest mirrors pkg/gui/client/api/acme_handlers.go:certNameRequest.
export interface CertRequest {
  name: string;
}

// certResponseBody mirrors pkg/gui/client/api/acme_handlers.go:certResponseBody.
export interface CertResponse {
  subject: string;
  notBefore?: string;
  notAfter?: string;
}

// RenewRequest mirrors pkg/gui/client/api/acme_handlers.go:certNameRequest
// (the renew handler reuses the same request shape).
export interface RenewRequest {
  name: string;
}

// RevokeClientRequest mirrors pkg/gui/client/api/acme_handlers.go:revokeRequestBody.
// The service-layer path (used when no SDK workflow is wired) requires `name`
// — the managed certificate spec identifier — plus an optional numeric reason.
// The legacy `certificate` (PEM) and `certFile` (path) fields are only consumed
// by the workflow path and are not required.
export interface RevokeClientRequest {
  name: string;
  reason?: number;
  certificate?: string;
  certFile?: string;
}

export interface EnrollRequest {
  ek_cert_pem: string;
  ak_name: string;
  device_info?: EABDeviceInfoDTO;
}

export interface EnrollResponse {
  credential_url: string;
  eab_kid: string;
  eab_hmac_key: string;
  expires_at?: string;
}

export interface AttestRequest {
  ak_name: string;
  quote: string;
  signature: string;
  pcr_values: Record<string, string>;
  nonce: string;
}

export interface AttestResponse {
  status: string;
  certificate_url?: string;
  certificate_pem?: string;
}

// ---------------------------------------------------------------------------
// Multi-account client types
//
// There is no single-account ClientConfig/RenewalConfig any more: the
// service is multi-account (Accounts/Certificates) end to end. Per-account
// settings (directory, email, key, ...) live on AccountConfig below, read
// and written through /api/v1/accounts[/{name}]; per-certificate renewal
// policy (auto/days-before) is CertificateSpec.renewal, read through
// /api/v1/certificates[/{name}]. Neither carries a process-wide "renewal
// check interval" or "threshold" concept — the global config that used to
// pretend they did was removed outright, since nothing ever read the
// stored values back into renewal behavior.
// ---------------------------------------------------------------------------

export interface KeyConfig {
  algorithm: string;
  store: string;
  hash?: string;
  ecc?: { curve: string };
  rsa?: { key_size: number };
}

export interface EABConfig {
  kid: string;
  hmac_key: string;
}

export interface AccountConfig {
  directory: string;
  email: string;
  key: KeyConfig;
  transport?: string;
  server_addr?: string;
  eab?: EABConfig;
  trusted_roots?: string[];
  request_server_bundle?: boolean;
}

export interface CertificateSpec {
  account: string;
  subject: { cn: string; organization?: string[]; country?: string[] };
  sans?: { dns?: string[]; ip?: string[]; email?: string[]; uri?: string[] };
  key: KeyConfig;
  challenge: string;
  valid?: number;
  deploy?: { cert_path: string; key_path: string; post_hook?: string };
  renewal?: { auto: boolean; days_before: number };
}

// ManagedCertInfo mirrors pkg/gui/client/api/acme_handlers.go:certInfoResponse.
// Returned by GET /api/v1/certificates/{name} when the certificate has been issued.
// When the certificate has not yet been issued the handler falls back to returning
// the raw CertificateSpec instead, so callers must handle both shapes.
export interface ManagedCertInfo {
  name: string;
  subject: string;
  account: string;
  issuedAt: string;
  expiresAt: string;
  deployedAt?: string;
}
