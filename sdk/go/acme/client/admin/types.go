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

// Package admin provides the Admin SDK client for the Trusted CA server.
//
// The admin client mirrors the AdminAdapter interface and provides tenant,
// EAB, role, user, certificate, account, order, and status management operations
// over the SDK transport layer.
package admin

import (
	"encoding/json"
	"strconv"
	"time"
)

// =============================================================================
// Pagination
// =============================================================================

// Pagination contains pagination metadata for list responses.
type Pagination struct {
	Page    int `json:"page"`
	PerPage int `json:"per_page"`
	Total   int `json:"total"`
}

// =============================================================================
// Tenant Types
// =============================================================================

// TenantInfo represents tenant information.
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

// TenantRootCAInfo represents tenant root CA information.
type TenantRootCAInfo struct {
	CommonName   string    `json:"common_name"`
	SerialNumber string    `json:"serial_number,omitempty"`
	KeyAlgorithm string    `json:"key_algorithm"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
}

// TenantIntCAInfo represents tenant intermediate CA information.
type TenantIntCAInfo struct {
	ID           string    `json:"id"`
	CommonName   string    `json:"common_name"`
	SerialNumber string    `json:"serial_number,omitempty"`
	ParentType   string    `json:"parent_type"`
	Purpose      string    `json:"purpose,omitempty"`
	KeyAlgorithm string    `json:"key_algorithm"`
	NotBefore    time.Time `json:"not_before"`
	NotAfter     time.Time `json:"not_after"`
	Status       string    `json:"status"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at,omitempty"`
}

// TenantSettingsInfo represents tenant settings.
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

// ComplianceConfigInfo represents compliance configuration for certificate issuance.
type ComplianceConfigInfo struct {
	Enabled             bool   `json:"enabled"`
	RequireSignedReport bool   `json:"require_signed_report"`
	CustomPolicyPath    string `json:"custom_policy_path,omitempty"`
	FailOpen            bool   `json:"fail_open"`
}

// TenantCAStatusInfo represents tenant CA status.
type TenantCAStatusInfo struct {
	TenantID                string             `json:"tenant_id"`
	RootCA                  *TenantRootCAInfo  `json:"root_ca,omitempty"`
	IntermediateCAs         []*TenantIntCAInfo `json:"intermediate_cas,omitempty"`
	DefaultIntermediateCAID string             `json:"default_intermediate_ca_id,omitempty"`
	ActiveCACount           int                `json:"active_ca_count"`
	CanIssueCerts           bool               `json:"can_issue_certificates"`
}

// CreateTenantRequest contains parameters for creating a tenant.
type CreateTenantRequest struct {
	ID       string              `json:"id"`
	Name     string              `json:"name"`
	Settings *TenantSettingsInfo `json:"settings,omitempty"`
}

// UpdateTenantRequest contains parameters for updating a tenant.
type UpdateTenantRequest struct {
	Name     string              `json:"name,omitempty"`
	Settings *TenantSettingsInfo `json:"settings,omitempty"`
}

// UpdateTenantStatusRequest contains parameters for updating a tenant's status.
type UpdateTenantStatusRequest struct {
	Status string `json:"status"`
}

// CreateTenantRootCARequest contains parameters for creating a tenant root CA.
type CreateTenantRootCARequest struct {
	CommonName    string `json:"common_name"`
	KeyAlgorithm  string `json:"key_algorithm"`
	ValidityYears int    `json:"validity_years"`
}

// CreateTenantIntermediateCARequest contains parameters for creating a tenant intermediate CA.
type CreateTenantIntermediateCARequest struct {
	CommonName    string `json:"common_name"`
	ParentType    string `json:"parent_type"`
	Purpose       string `json:"purpose,omitempty"`
	KeyAlgorithm  string `json:"key_algorithm"`
	ValidityYears int    `json:"validity_years"`
	SetAsDefault  bool   `json:"set_as_default,omitempty"`
}

// UpdateIntermediateCAStatusRequest contains parameters for updating an intermediate CA's status.
type UpdateIntermediateCAStatusRequest struct {
	Status string `json:"status"`
}

// ListTenantsRequest contains parameters for listing tenants.
type ListTenantsRequest struct {
	Page    int    `json:"page,omitempty"`
	PerPage int    `json:"per_page,omitempty"`
	Status  string `json:"status,omitempty"`
}

// ListTenantsResponse contains the response from listing tenants.
type ListTenantsResponse struct {
	Tenants    []*TenantInfo `json:"tenants"`
	Pagination *Pagination   `json:"pagination,omitempty"`
}

// =============================================================================
// EAB Types
// =============================================================================

// EABInfo represents external account binding information.
type EABInfo struct {
	ID                string            `json:"id"`
	TenantID          string            `json:"tenant_id,omitempty"`
	Status            string            `json:"status"`
	Purpose           string            `json:"purpose"`
	AccountID         uint64            `json:"account_id,omitempty"`
	ExternalAccountID string            `json:"external_account_id,omitempty"`
	DeviceInfo        *EABDeviceInfo    `json:"device_info,omitempty"`
	Contact           []string          `json:"contact,omitempty"`
	CreatedAt         time.Time         `json:"created_at"`
	CreatedBy         string            `json:"created_by,omitempty"`
	UsedAt            *time.Time        `json:"used_at,omitempty"`
	ExpiresAt         *time.Time        `json:"expires_at,omitempty"`
	Metadata          map[string]string `json:"metadata,omitempty"`
}

// EABDeviceInfo represents device information in EAB responses.
type EABDeviceInfo struct {
	DeviceID           string            `json:"device_id,omitempty"`
	Manufacturer       string            `json:"manufacturer,omitempty"`
	Model              string            `json:"model,omitempty"`
	EKPublicKeyHash    string            `json:"ek_public_key_hash,omitempty"`
	TPMManufacturer    string            `json:"tpm_manufacturer,omitempty"`
	TPMFirmwareVersion string            `json:"tpm_firmware_version,omitempty"`
	Metadata           map[string]string `json:"metadata,omitempty"`
}

// CreateEABRequest contains parameters for creating an EAB.
type CreateEABRequest struct {
	Purpose           string            `json:"purpose,omitempty"`
	ExternalAccountID string            `json:"external_account_id,omitempty"`
	DeviceInfo        *EABDeviceInfo    `json:"device_info,omitempty"`
	Contact           []string          `json:"contact,omitempty"`
	ExpiresInDays     int               `json:"expires_in_days,omitempty"`
	Metadata          map[string]string `json:"metadata,omitempty"`
}

// CreateEABResponse contains the response from creating an EAB.
type CreateEABResponse struct {
	ID        string     `json:"id"`
	MACKey    string     `json:"mac_key"`
	Algorithm string     `json:"algorithm"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// ListEABRequest contains parameters for listing EABs.
type ListEABRequest struct {
	Page    int    `json:"page,omitempty"`
	PerPage int    `json:"per_page,omitempty"`
	Status  string `json:"status,omitempty"`
	Purpose string `json:"purpose,omitempty"`
}

// ListEABResponse contains the response from listing EABs.
type ListEABResponse struct {
	EABs       []*EABInfo  `json:"eabs"`
	Pagination *Pagination `json:"pagination,omitempty"`
}

// =============================================================================
// Role Types
// =============================================================================

// Role represents an RBAC role entity.
type Role struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	TenantID    string   `json:"tenantID"`
	Permissions []string `json:"permissions"`
	System      bool     `json:"system"`
	CreatedAt   string   `json:"createdAt"`
	UpdatedAt   string   `json:"updatedAt"`
}

// CreateRoleRequest contains parameters for creating a role.
type CreateRoleRequest struct {
	Name        string   `json:"name"`
	TenantID    string   `json:"tenantID,omitempty"`
	Permissions []string `json:"permissions"`
}

// UpdateRoleRequest contains parameters for updating a role.
type UpdateRoleRequest struct {
	ID          string   `json:"id"`
	Name        string   `json:"name,omitempty"`
	Permissions []string `json:"permissions,omitempty"`
}

// ListRolesRequest contains parameters for listing roles.
type ListRolesRequest struct {
	TenantID string `json:"tenantID,omitempty"`
	Page     int    `json:"page,omitempty"`
	PageSize int    `json:"pageSize,omitempty"`
}

// ListRolesResponse contains the response from listing roles.
type ListRolesResponse struct {
	Roles   []*Role `json:"roles"`
	Total   int     `json:"total"`
	HasMore bool    `json:"hasMore"`
}

// =============================================================================
// User Types
// =============================================================================

// User represents a passwordless user entity.
type User struct {
	ID        string   `json:"id"`
	Username  string   `json:"username"`
	TenantID  string   `json:"tenantID"`
	RoleIDs   []string `json:"roleIDs"`
	Enabled   bool     `json:"enabled"`
	System    bool     `json:"system"`
	CreatedAt string   `json:"createdAt"`
	UpdatedAt string   `json:"updatedAt"`
}

// CreateUserRequest contains parameters for creating a user.
type CreateUserRequest struct {
	Username string   `json:"username"`
	TenantID string   `json:"tenantID,omitempty"`
	RoleIDs  []string `json:"roleIDs,omitempty"`
}

// UpdateUserRequest contains parameters for updating a user.
type UpdateUserRequest struct {
	ID       string   `json:"id"`
	Username string   `json:"username,omitempty"`
	RoleIDs  []string `json:"roleIDs,omitempty"`
}

// ListUsersRequest contains parameters for listing users.
type ListUsersRequest struct {
	TenantID string `json:"tenantID,omitempty"`
	Page     int    `json:"page,omitempty"`
	PageSize int    `json:"pageSize,omitempty"`
}

// ListUsersResponse contains the response from listing users.
type ListUsersResponse struct {
	Users   []*User `json:"users"`
	Total   int     `json:"total"`
	HasMore bool    `json:"hasMore"`
}

// =============================================================================
// Certificate Types
// =============================================================================

// CertificateInfo represents certificate information for admin responses.
// SerialNumber is the certificate's identity: use it for any certificate
// lookup, fetch, or revocation. There is no separate numeric ID - the
// server's DAO row key is an internal storage detail this response never
// exposes.
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

// ListCertificatesRequest contains parameters for listing certificates.
type ListCertificatesRequest struct {
	Page        int    `json:"page,omitempty"`
	PerPage     int    `json:"per_page,omitempty"`
	Status      string `json:"status,omitempty"`
	Subject     string `json:"subject,omitempty"`
	ExpiresDays int    `json:"expires_days,omitempty"`
}

// ListCertificatesResponse contains the response from listing certificates.
type ListCertificatesResponse struct {
	Certificates []*CertificateInfo `json:"certificates"`
	Pagination   *Pagination        `json:"pagination,omitempty"`
}

// =============================================================================
// Account Types
// =============================================================================

// AccountInfo represents account information for admin responses.
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

// UnmarshalJSON handles both "123" and 123.
func (f *FlexUint64) UnmarshalJSON(data []byte) error {
	var n uint64
	if err := json.Unmarshal(data, &n); err == nil {
		*f = FlexUint64(n)
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return err
		}
		*f = FlexUint64(n)
		return nil
	}
	return &FlexUint64UnmarshalError{Data: string(data)}
}

// MarshalJSON outputs as a regular number.
func (f FlexUint64) MarshalJSON() ([]byte, error) {
	return json.Marshal(uint64(f))
}

// ListAccountsRequest contains parameters for listing accounts.
type ListAccountsRequest struct {
	Page    int    `json:"page,omitempty"`
	PerPage int    `json:"per_page,omitempty"`
	Status  string `json:"status,omitempty"`
}

// ListAccountsResponse contains the response from listing accounts.
type ListAccountsResponse struct {
	Accounts   []*AccountInfo `json:"accounts"`
	Pagination *Pagination    `json:"pagination,omitempty"`
}

// =============================================================================
// Order Types
// =============================================================================

// OrderInfo represents order information for admin responses.
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

// ListOrdersRequest contains parameters for listing orders.
type ListOrdersRequest struct {
	Page      int    `json:"page,omitempty"`
	PerPage   int    `json:"per_page,omitempty"`
	AccountID uint64 `json:"account_id,omitempty"`
	Status    string `json:"status,omitempty"`
}

// ListOrdersResponse contains the response from listing orders.
type ListOrdersResponse struct {
	Orders     []*OrderInfo `json:"orders"`
	Pagination *Pagination  `json:"pagination,omitempty"`
}

// =============================================================================
// Status Types
// =============================================================================

// CAStatus represents CA status information.
type CAStatus struct {
	Identity       string    `json:"identity"`
	Initialized    bool      `json:"initialized"`
	Version        string    `json:"version"`
	StartedAt      time.Time `json:"started_at"`
	KeyAlgorithm   string    `json:"key_algorithm"`
	SignatureAlgo  string    `json:"signature_algorithm"`
	RootCA         string    `json:"root_ca"`
	IntermediateCA string    `json:"intermediate_ca,omitempty"`
}

// CAStats represents CA statistics.
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
