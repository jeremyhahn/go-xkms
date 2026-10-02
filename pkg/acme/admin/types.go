// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/acme/audit"
	"github.com/jeremyhahn/go-xkms/pkg/errs"

	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

// Error types for admin operations
var (
	ErrUnauthorized           = errors.New("admin: unauthorized")
	ErrForbidden              = errors.New("admin: forbidden")
	ErrInvalidAPIKey          = errors.New("admin: invalid API key")
	ErrInsufficientPrivileges = errors.New("admin: insufficient privileges")
	ErrInvalidRequest         = errors.New("admin: invalid request")
	ErrCertificateNotFound    = errors.New("admin: certificate not found")
	ErrAccountNotFound        = errors.New("admin: account not found")
	ErrOrderNotFound          = errors.New("admin: order not found")
	ErrRevocationFailed       = errors.New("admin: certificate revocation failed")
	// ErrNilSignOptions is returned by the ceremony CA adapter when go-qrdb
	// passes no SignCSROptions: there is then no registered holder and no
	// tenant to name, and signing would fall back to the CSR's own subject.
	ErrNilSignOptions = errors.New("admin: holder certificate signing requires the ceremony's sign options")
	// ErrCANotConfigured is returned by AdminService methods that read from
	// the ACME certificate authority (GetStatus, RevokeCertificate) when the
	// service was constructed with a nil ca.TCGCA. This is the ordinary,
	// non-error shape of an admin surface mounted with ACME disabled
	// (cmd/xkmsd/admin.go finalizeAdminModule passes acme.CA(), which is nil
	// for a nil *acmeServer) rather than a misconfiguration: the surface
	// degrades the affected routes instead of failing to mount.
	ErrCANotConfigured = errors.New("admin: certificate authority not configured")
	// ErrStorageNotConfigured is returned by AdminService methods that read
	// from the ACME storage factory (certificate, account, and order
	// listing/lookup, and GetStats) when the service was constructed with a
	// nil storage.Factory — the same ACME-disabled degradation as
	// ErrCANotConfigured, for the storage-backed routes instead of the
	// CA-backed ones.
	ErrStorageNotConfigured = errors.New("admin: ACME storage not configured")
	// ErrRESTOnly marks ACME admin operations that are intentionally exposed
	// over REST only. ACME is an HTTP protocol (RFC 8555), so order management
	// and tenant-CA administration are served exclusively over the REST surface;
	// the gRPC / QUIC / MCP adapters return this error by design rather than
	// duplicating the ACME admin surface onto non-HTTP transports.
	ErrRESTOnly = errors.New("admin: operation is available over REST only (ACME is HTTP-based per RFC 8555)")
)

// IsNotFoundError returns true if the error is a "not found" type error.
func IsNotFoundError(err error) bool {
	return errors.Is(err, ErrCertificateNotFound) ||
		errors.Is(err, ErrAccountNotFound) ||
		errors.Is(err, ErrOrderNotFound) ||
		errors.Is(err, ErrTenantNotFound) ||
		errors.Is(err, ErrTenantRootCANotFound) ||
		errors.Is(err, ErrTenantIntCANotFound) ||
		errors.Is(err, ErrEABNotFound) ||
		errors.Is(err, ErrRoleNotFound) ||
		errors.Is(err, ErrUserNotFound)
}

// IsValidationError returns true if the error is a validation error.
func IsValidationError(err error) bool {
	return errors.Is(err, ErrInvalidRequest) ||
		errors.Is(err, ErrInvalidTenantID) ||
		errors.Is(err, ErrInvalidEABPurpose) ||
		errors.Is(err, ErrInvalidKeyAlgorithm)
}

// IsAlreadyExistsError returns true if the error indicates a resource already exists.
func IsAlreadyExistsError(err error) bool {
	return errors.Is(err, ErrTenantAlreadyExists) ||
		errors.Is(err, ErrTenantRootCAExists) ||
		errors.Is(err, ErrTenantIntCAExists)
}

// IsUnauthorizedError returns true if the error is an authorization error.
func IsUnauthorizedError(err error) bool {
	return errors.Is(err, ErrUnauthorized) ||
		errors.Is(err, ErrForbidden) ||
		errors.Is(err, ErrInvalidAPIKey) ||
		errors.Is(err, ErrInsufficientPrivileges)
}

// Config defines the admin API configuration.
type Config struct {
	Enabled    bool   `yaml:"enabled" json:"enabled"`
	ListenAddr string `yaml:"listen_addr" json:"listen_addr"`
	TLSEnabled bool   `yaml:"tls_enabled" json:"tls_enabled"`
	TLSCert    string `yaml:"tls_cert" json:"tls_cert,omitempty"`
	TLSKey     string `yaml:"tls_key" json:"tls_key,omitempty"`
}

// ProblemDetail represents an RFC 7807 Problem Details response.
type ProblemDetail struct {
	Type   string `json:"type"`
	Title  string `json:"title"`
	Detail string `json:"detail"`
	Status int    `json:"status"`
}

// ListResponse is a paginated list response for admin endpoints.
type ListResponse struct {
	Items   interface{} `json:"items"`
	Total   int         `json:"total"`
	Page    int         `json:"page"`
	PerPage int         `json:"per_page"`
}

// Pagination represents pagination information used for query parsing.
type Pagination struct {
	Page    int `json:"page"`
	PerPage int `json:"per_page"`
	Total   int `json:"total"`
}

// CertificateInfo represents certificate information for admin responses.
// SerialNumber is the certificate's identity: use it for any certificate
// lookup, fetch, or revocation. There is no separate numeric ID - the DAO's
// own row key is an internal storage detail (an FNV-1a hash of the serial;
// see entities.ACMECertificate.EntityID) that this response never exposes.
type CertificateInfo struct {
	SerialNumber string    `json:"serial_number"`
	Subject      string    `json:"subject"`
	Issuer       string    `json:"issuer"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	Status       string    `json:"status"`
	IssuedAt     time.Time `json:"issued_at"`
	CertURL      string    `json:"cert_url,omitempty"`
}

// AccountInfo represents account information for admin responses
type AccountInfo struct {
	ID                   FlexUint64 `json:"id"`
	Status               string     `json:"status"`
	Contact              []string   `json:"contact,omitempty"`
	CreatedAt            time.Time  `json:"created_at"`
	TermsOfServiceAgreed bool       `json:"terms_of_service_agreed"`
	OrdersURL            string     `json:"orders_url"`
	OrderCount           int        `json:"order_count"`
}

// FlexUint64 is a uint64 that can unmarshal from both JSON numbers and
// quoted strings (protojson encodes uint64 as strings per proto3 spec).
type FlexUint64 uint64

// UnmarshalJSON handles both "123" (protojson) and 123 (standard JSON).
func (f *FlexUint64) UnmarshalJSON(data []byte) error {
	// Try number first
	var n uint64
	if err := json.Unmarshal(data, &n); err == nil {
		*f = FlexUint64(n)
		return nil
	}
	// Try string
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return err
		}
		*f = FlexUint64(n)
		return nil
	}
	return &errs.Message{Msg: fmt.Sprintf("cannot unmarshal %s into FlexUint64", string(data))}
}

// MarshalJSON outputs as a regular number.
func (f FlexUint64) MarshalJSON() ([]byte, error) {
	return json.Marshal(uint64(f))
}

// OrderInfo represents order information for admin responses
type OrderInfo struct {
	ID          uint64    `json:"id"`
	AccountID   uint64    `json:"account_id"`
	Status      string    `json:"status"`
	Identifiers []string  `json:"identifiers"`
	NotBefore   string    `json:"not_before,omitempty"`
	NotAfter    string    `json:"not_after,omitempty"`
	Expires     string    `json:"expires,omitempty"`
	Certificate string    `json:"certificate,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
}

// KeyInfo describes a single key configuration in a CA's key set.
type KeyInfo struct {
	Algorithm          string `json:"algorithm"`           // "ECDSA", "RSA", "Ed25519"
	SignatureAlgorithm string `json:"signature_algorithm"` // "ECDSAWithSHA256", "SHA256-RSAPSS", etc.
	Store              string `json:"store"`               // "software", "tpm2", "pkcs11"
	KeySize            int    `json:"key_size,omitempty"`  // RSA: 2048, 4096
	Curve              string `json:"curve,omitempty"`     // ECDSA: "P-256", "P-384", "P-521"
	Default            bool   `json:"default"`             // true for the primary signing key
}

// KeyInfoFromKeyConfig converts a go-xkms KeyConfig to a KeyInfo for API responses.
// The isDefault parameter indicates whether this key is the primary signing key.
func KeyInfoFromKeyConfig(kc *xkmssdk.KeyConfig, isDefault bool) KeyInfo {
	ki := KeyInfo{
		Algorithm:          string(kc.KeyAlgorithm),
		SignatureAlgorithm: string(kc.SignatureAlgorithm),
		Store:              string(kc.StoreType),
		Default:            isDefault,
	}
	if kc.RSAConfig != nil {
		ki.KeySize = kc.RSAConfig.KeySize
	}
	if kc.ECCConfig != nil {
		ki.Curve = string(kc.ECCConfig.Curve)
	}
	return ki
}

// CAStatus represents CA status information
type CAStatus struct {
	Identity       string    `json:"identity"`
	Initialized    bool      `json:"initialized"`
	Version        string    `json:"version"`
	StartedAt      time.Time `json:"started_at"`
	KeyAlgorithm   string    `json:"key_algorithm"`
	SignatureAlgo  string    `json:"signature_algorithm"`
	RootCA         string    `json:"root_ca"`
	IntermediateCA string    `json:"intermediate_ca,omitempty"`
	Keys           []KeyInfo `json:"keys,omitempty"`
}

// CAStats represents CA statistics
type CAStats struct {
	TotalCertificates   int `json:"total_certificates"`
	ValidCertificates   int `json:"valid_certificates"`
	RevokedCertificates int `json:"revoked_certificates"`
	ExpiredCertificates int `json:"expired_certificates"`
	TotalAccounts       int `json:"total_accounts"`
	ActiveAccounts      int `json:"active_accounts"`
	TotalOrders         int `json:"total_orders"`
	PendingOrders       int `json:"pending_orders"`
	CompletedOrders     int `json:"completed_orders"`
}

// AuditLog represents an audit log entry
type AuditLog struct {
	ID        uint64    `json:"id"`
	Timestamp time.Time `json:"timestamp"`
	Actor     string    `json:"actor"`
	Action    string    `json:"action"`
	Resource  string    `json:"resource"`
	Details   string    `json:"details,omitempty"`
	Success   bool      `json:"success"`
}

// RevokeRequest represents a certificate revocation request
type RevokeRequest struct {
	Reason string `json:"reason,omitempty"`
}

// ListCertificatesRequest represents a request to list certificates
type ListCertificatesRequest struct {
	Page        int    `json:"page,omitempty"`
	PerPage     int    `json:"per_page,omitempty"`
	Status      string `json:"status,omitempty"`
	Subject     string `json:"subject,omitempty"`
	ExpiresDays int    `json:"expires_days,omitempty"`
}

// ListAccountsRequest represents a request to list accounts
type ListAccountsRequest struct {
	Page    int    `json:"page,omitempty"`
	PerPage int    `json:"per_page,omitempty"`
	Status  string `json:"status,omitempty"`
}

// ListOrdersRequest represents a request to list orders
type ListOrdersRequest struct {
	Page      int    `json:"page,omitempty"`
	PerPage   int    `json:"per_page,omitempty"`
	AccountID uint64 `json:"account_id,omitempty"`
	Status    string `json:"status,omitempty"`
}

// ListAuditLogsRequest represents a request to list audit logs
type ListAuditLogsRequest struct {
	Page      int       `json:"page,omitempty"`
	PerPage   int       `json:"per_page,omitempty"`
	StartTime time.Time `json:"start_time,omitempty"`
	EndTime   time.Time `json:"end_time,omitempty"`
	Actor     string    `json:"actor,omitempty"`
	Action    string    `json:"action,omitempty"`
	Resource  string    `json:"resource,omitempty"`
	EventType string    `json:"event_type,omitempty"`
	Result    string    `json:"result,omitempty"`
	RequestID string    `json:"request_id,omitempty"`
}

// auditQuery converts the admin request into an audit trail query.
func (r ListAuditLogsRequest) auditQuery() audit.Query {
	return audit.Query{
		Page:      r.Page,
		PerPage:   r.PerPage,
		EventType: audit.EventType(r.EventType),
		Actor:     r.Actor,
		Resource:  r.Resource,
		Action:    r.Action,
		Result:    audit.Result(r.Result),
		RequestID: r.RequestID,
		Since:     r.StartTime,
		Until:     r.EndTime,
	}
}

// TenantInfo represents tenant information for admin responses
type TenantInfo struct {
	ID                      string              `json:"id"`
	Name                    string              `json:"name"`
	Status                  string              `json:"status"`
	RootCA                  *TenantRootCAInfo   `json:"root_ca,omitempty"`
	IntermediateCAs         []*TenantIntCAInfo  `json:"intermediate_cas,omitempty"`
	DefaultIntermediateCAID string              `json:"default_intermediate_ca_id,omitempty"`
	Settings                *TenantSettingsInfo `json:"settings,omitempty"`
	CreatedAt               time.Time           `json:"created_at"`
	UpdatedAt               time.Time           `json:"updated_at"`
	CreatedBy               string              `json:"created_by,omitempty"`
}

// TenantRootCAInfo represents tenant root CA information
type TenantRootCAInfo struct {
	CommonName   string    `json:"common_name"`
	SerialNumber string    `json:"serial_number,omitempty"`
	KeyAlgorithm string    `json:"key_algorithm"`
	Keys         []KeyInfo `json:"keys,omitempty"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
}

// TenantIntCAInfo represents tenant intermediate CA information
type TenantIntCAInfo struct {
	ID           string    `json:"id"`
	CommonName   string    `json:"common_name"`
	SerialNumber string    `json:"serial_number,omitempty"`
	ParentType   string    `json:"parent_type"`       // "global" or "tenant"
	Purpose      string    `json:"purpose,omitempty"` // "general", "server-auth", "client-auth", etc.
	KeyAlgorithm string    `json:"key_algorithm"`
	Keys         []KeyInfo `json:"keys,omitempty"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at,omitempty"`
}

// TenantSettingsInfo represents tenant settings
type TenantSettingsInfo struct {
	MaxCertificates         int                   `json:"max_certificates,omitempty"`
	MaxAccounts             int                   `json:"max_accounts,omitempty"`
	AllowedKeyAlgorithms    []string              `json:"allowed_key_algorithms,omitempty"`
	AllowedChallengeTypes   []string              `json:"allowed_challenge_types,omitempty"`
	CertificateValidityDays int                   `json:"certificate_validity_days,omitempty"`
	RequireEAB              bool                  `json:"require_eab,omitempty"`
	AllowEndorse01          bool                  `json:"allow_endorse_01,omitempty"`
	AllowEnroll01           bool                  `json:"allow_enroll_01,omitempty"`
	ComplianceConfig        *ComplianceConfigInfo `json:"compliance_config,omitempty"`
}

// ComplianceConfigInfo represents compliance configuration for certificate issuance
type ComplianceConfigInfo struct {
	// Enabled indicates whether compliance validation is active
	Enabled bool `json:"enabled"`

	// RequireSignedReport indicates whether the compliance report must be signed
	RequireSignedReport bool `json:"require_signed_report"`

	// CustomPolicyPath is the path to a custom Rego policy file
	CustomPolicyPath string `json:"custom_policy_path,omitempty"`

	// FailOpen determines behavior when compliance data is missing
	// If true, missing report = pass (fail-open)
	// If false, missing report = fail (fail-closed)
	FailOpen bool `json:"fail_open"`
}

// GlobalComplianceConfigInfo is the server-wide default compliance configuration
type GlobalComplianceConfigInfo struct {
	ComplianceConfigInfo

	// Enforce determines how global config applies to tenants:
	// If true, global config is enforced on ALL tenants (override)
	// If false, tenants can define their own config (global is fallback only)
	Enforce bool `json:"enforce"`
}

// CreateTenantRequest represents a request to create a tenant
type CreateTenantRequest struct {
	ID       string              `json:"id"`
	Name     string              `json:"name"`
	Settings *TenantSettingsInfo `json:"settings,omitempty"`
}

// UpdateTenantRequest represents a request to update a tenant
type UpdateTenantRequest struct {
	Name     string              `json:"name,omitempty"`
	Settings *TenantSettingsInfo `json:"settings,omitempty"`
}

// UpdateTenantStatusRequest represents a request to update tenant status
type UpdateTenantStatusRequest struct {
	Status string `json:"status"`
}

// CreateTenantRootCARequest represents a request to create a tenant root CA
type CreateTenantRootCARequest struct {
	CommonName    string `json:"common_name"`
	KeyAlgorithm  string `json:"key_algorithm"`
	ValidityYears int    `json:"validity_years"`
}

// CreateTenantIntermediateCARequest represents a request to create a tenant intermediate CA
type CreateTenantIntermediateCARequest struct {
	CommonName    string `json:"common_name"`
	ParentType    string `json:"parent_type"`       // "global" or "tenant"
	Purpose       string `json:"purpose,omitempty"` // "general", "server-auth", "client-auth", etc.
	KeyAlgorithm  string `json:"key_algorithm"`
	ValidityYears int    `json:"validity_years"`
	SetAsDefault  bool   `json:"set_as_default,omitempty"` // Set this CA as the default for the tenant
}

// ListTenantsRequest represents a request to list tenants
type ListTenantsRequest struct {
	Page    int    `json:"page,omitempty"`
	PerPage int    `json:"per_page,omitempty"`
	Status  string `json:"status,omitempty"`
}

// TenantCAStatusInfo represents tenant CA status
type TenantCAStatusInfo struct {
	TenantID                string             `json:"tenant_id"`
	RootCA                  *TenantRootCAInfo  `json:"root_ca,omitempty"`
	IntermediateCAs         []*TenantIntCAInfo `json:"intermediate_cas,omitempty"`
	DefaultIntermediateCAID string             `json:"default_intermediate_ca_id,omitempty"`
	ActiveCACount           int                `json:"active_ca_count"`
	CanIssueCerts           bool               `json:"can_issue_certificates"`
}

// UpdateTenantDefaultCARequest represents a request to update the default intermediate CA
type UpdateTenantDefaultCARequest struct {
	IntermediateCAID string `json:"intermediate_ca_id"`
}

// UpdateIntermediateCAStatusRequest represents a request to update an intermediate CA's status
type UpdateIntermediateCAStatusRequest struct {
	Status string `json:"status"` // "active", "pending-rotation", "revoked"
}

// EABInfo represents external account binding information for admin responses
type EABInfo struct {
	ID                string            `json:"id"`
	TenantID          string            `json:"tenant_id,omitempty"`
	Status            string            `json:"status"`
	Purpose           string            `json:"purpose"`
	AccountID         uint64            `json:"account_id,omitempty"`
	ExternalAccountID string            `json:"external_account_id,omitempty"`
	DeviceInfo        *EABDeviceInfoDTO `json:"device_info,omitempty"`
	Contact           []string          `json:"contact,omitempty"`
	CreatedAt         time.Time         `json:"created_at"`
	CreatedBy         string            `json:"created_by,omitempty"`
	UsedAt            *time.Time        `json:"used_at,omitempty"`
	ExpiresAt         *time.Time        `json:"expires_at,omitempty"`
}

// EABDeviceInfoDTO represents device info in EAB responses
type EABDeviceInfoDTO struct {
	DeviceID           string            `json:"device_id,omitempty"`
	Manufacturer       string            `json:"manufacturer,omitempty"`
	Model              string            `json:"model,omitempty"`
	EKPublicKeyHash    string            `json:"ek_public_key_hash,omitempty"`
	TPMManufacturer    string            `json:"tpm_manufacturer,omitempty"`
	TPMFirmwareVersion string            `json:"tpm_firmware_version,omitempty"`
	Metadata           map[string]string `json:"metadata,omitempty"`
}

// CreateEABRequest represents a request to create an EAB
type CreateEABRequest struct {
	Purpose           string            `json:"purpose,omitempty"` // "account-binding", "endorse-01", "enroll-01"
	ExternalAccountID string            `json:"external_account_id,omitempty"`
	DeviceInfo        *EABDeviceInfoDTO `json:"device_info,omitempty"`
	Contact           []string          `json:"contact,omitempty"`
	ExpiresInDays     int               `json:"expires_in_days,omitempty"`
	Metadata          map[string]string `json:"metadata,omitempty"`
}

// CreateEABResponse represents the response when creating an EAB
type CreateEABResponse struct {
	ID        string     `json:"id"`
	MACKey    string     `json:"mac_key"` // Base64url-encoded, shown only once
	Algorithm string     `json:"algorithm"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// ListEABRequest represents a request to list EABs
type ListEABRequest struct {
	Page    int    `json:"page,omitempty"`
	PerPage int    `json:"per_page,omitempty"`
	Status  string `json:"status,omitempty"`
	Purpose string `json:"purpose,omitempty"`
}

// Tenant error types
var (
	// ErrTenantServiceUnavailable is returned by CreateTenant, GetTenant,
	// UpdateTenant, DeleteTenant, and ListTenants when no qrdb
	// ServiceTenantServicer has been wired via SetTenantService. qrdb is the
	// single authority for tenant identity; these methods never fall back to
	// a local-only tenant model, so a caller that has not wired a tenant
	// service gets this typed error instead of a silently divergent result.
	ErrTenantServiceUnavailable = errors.New("admin: tenant service not configured")
	ErrTenantNotFound           = errors.New("admin: tenant not found")
	ErrTenantAlreadyExists      = errors.New("admin: tenant already exists")
	ErrTenantSuspended          = errors.New("admin: tenant is suspended")
	ErrTenantDeleted            = errors.New("admin: tenant is deleted")
	ErrInvalidTenantID          = errors.New("admin: invalid tenant ID")
	ErrTenantCANotConfigured    = errors.New("admin: tenant CA not configured")
	ErrTenantRootCAExists       = errors.New("admin: tenant root CA already exists")
	ErrTenantRootCANotFound     = errors.New("admin: tenant root CA not found")
	ErrTenantIntCANotFound      = errors.New("admin: tenant intermediate CA not found")
	ErrTenantIntCAExists        = errors.New("admin: tenant intermediate CA already exists")
	ErrEABNotFound              = errors.New("admin: external account binding not found")
	ErrInvalidEABPurpose        = errors.New("admin: invalid EAB purpose")
	ErrInvalidKeyAlgorithm      = errors.New("admin: invalid key algorithm")
	ErrNoSigningCAAvailable     = errors.New("admin: no signing CA available for tenant")
	ErrRBACNotAvailable         = errors.New("admin: RBAC service not available")

	// ErrRoleNotFound is returned by the tenant role operations when the
	// role does not exist or does not belong to the tenant the request
	// names; the two are deliberately indistinguishable.
	ErrRoleNotFound = errors.New("admin: role not found")

	// ErrUserNotFound is returned by the tenant user operations when the
	// user does not exist or does not belong to the tenant the request
	// names; the two are deliberately indistinguishable.
	ErrUserNotFound = errors.New("admin: user not found")
)
