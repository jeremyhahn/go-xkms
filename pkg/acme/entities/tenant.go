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

package entities

import "time"

// Tenant represents a tenant in a multi-tenant deployment.
// Each tenant has isolated data, its own CA hierarchy, and users.
type Tenant struct {
	// NumericID is the auto-generated numeric entity ID derived from the string ID
	// via FNV-1a hashing. This enables the Entity interface required by GenericDAO.
	NumericID uint64 `json:"numericId" yaml:"numericId"`

	// ID is the unique identifier for this tenant.
	ID string `json:"id" yaml:"id" index:"true"`

	// Name is the human-readable name of the tenant.
	Name string `json:"name" yaml:"name"`

	// Status indicates the current state of the tenant.
	// Possible values: "active", "suspended", "deleted"
	Status string `json:"status" yaml:"status" index:"true"`

	// DEKKeyID is the KMS key ID for this tenant's Data Encryption Key.
	// All tenant data is encrypted with this key for cryptographic isolation.
	DEKKeyID string `json:"dekKeyId,omitempty" yaml:"dekKeyId,omitempty"`

	// RootCA contains the tenant's optional root CA configuration.
	// If nil, the tenant uses the global root CA.
	RootCA *TenantRootCA `json:"rootCA,omitempty" yaml:"rootCA,omitempty"`

	// IntermediateCAs contains the tenant's intermediate CA configurations.
	// At least one is required for certificate issuance.
	// Multiple CAs support key rotation and different purposes.
	IntermediateCAs []*TenantIntermediateCA `json:"intermediateCAs,omitempty" yaml:"intermediateCAs,omitempty"`

	// DefaultIntermediateCAID is the ID of the default intermediate CA for issuing certificates.
	// If not set, the first active CA in IntermediateCAs is used.
	DefaultIntermediateCAID string `json:"defaultIntermediateCAId,omitempty" yaml:"defaultIntermediateCAId,omitempty"`

	// Settings contains tenant-specific configuration.
	Settings *TenantSettings `json:"settings,omitempty" yaml:"settings,omitempty"`

	// CreatedAt is the timestamp when this tenant was created.
	CreatedAt time.Time `json:"createdAt" yaml:"createdAt"`

	// UpdatedAt is the timestamp when this tenant was last updated.
	UpdatedAt time.Time `json:"updatedAt" yaml:"updatedAt"`

	// CreatedBy is the user ID that created this tenant.
	CreatedBy string `json:"createdBy,omitempty" yaml:"createdBy,omitempty"`
}

// TenantRootCA represents a tenant's optional root CA.
// Tenants can create their own root CA or use the global root CA.
type TenantRootCA struct {
	// CommonName is the CN of the root CA certificate.
	CommonName string `json:"commonName" yaml:"commonName"`

	// SerialNumber is the serial number of the root CA certificate.
	SerialNumber string `json:"serialNumber,omitempty" yaml:"serialNumber,omitempty"`

	// KeyID is the KMS key ID for the root CA private key.
	KeyID string `json:"keyId,omitempty" yaml:"keyId,omitempty"`

	// KeyAlgorithm is the key algorithm (e.g., "EC-P384", "RSA-4096").
	KeyAlgorithm string `json:"keyAlgorithm" yaml:"keyAlgorithm"`

	// NotBefore is the start of the certificate validity period.
	NotBefore time.Time `json:"notBefore" yaml:"notBefore"`

	// NotAfter is the end of the certificate validity period.
	NotAfter time.Time `json:"notAfter" yaml:"notAfter"`

	// Status indicates the current state of the root CA.
	// Possible values: "active", "pending-rotation", "revoked"
	Status string `json:"status" yaml:"status"`

	// CertificatePEM is the PEM-encoded root CA certificate.
	CertificatePEM string `json:"certificatePEM,omitempty" yaml:"certificatePEM,omitempty"`

	// CreatedAt is the timestamp when this root CA was created.
	CreatedAt time.Time `json:"createdAt" yaml:"createdAt"`
}

// TenantIntermediateCA represents a tenant's intermediate CA.
// At least one is required for certificate issuance.
// Multiple CAs can exist for key rotation and different purposes.
type TenantIntermediateCA struct {
	// ID is the unique identifier for this intermediate CA within the tenant.
	ID string `json:"id" yaml:"id"`

	// CommonName is the CN of the intermediate CA certificate.
	CommonName string `json:"commonName" yaml:"commonName"`

	// SerialNumber is the serial number of the intermediate CA certificate.
	SerialNumber string `json:"serialNumber,omitempty" yaml:"serialNumber,omitempty"`

	// ParentType indicates whether the intermediate CA is signed by
	// the global root ("global") or the tenant's root CA ("tenant").
	ParentType string `json:"parentType" yaml:"parentType"`

	// Purpose describes the intended use of this CA.
	// Examples: "general", "server-auth", "client-auth", "code-signing"
	Purpose string `json:"purpose,omitempty" yaml:"purpose,omitempty"`

	// KeyID is the KMS key ID for the intermediate CA private key.
	KeyID string `json:"keyId,omitempty" yaml:"keyId,omitempty"`

	// KeyAlgorithm is the key algorithm (e.g., "EC-P384", "RSA-4096").
	KeyAlgorithm string `json:"keyAlgorithm" yaml:"keyAlgorithm"`

	// NotBefore is the start of the certificate validity period.
	NotBefore time.Time `json:"notBefore" yaml:"notBefore"`

	// NotAfter is the end of the certificate validity period.
	NotAfter time.Time `json:"notAfter" yaml:"notAfter"`

	// Status indicates the current state of the intermediate CA.
	// Possible values: "active", "pending-rotation", "revoked"
	Status string `json:"status" yaml:"status"`

	// CertificatePEM is the PEM-encoded intermediate CA certificate.
	CertificatePEM string `json:"certificatePEM,omitempty" yaml:"certificatePEM,omitempty"`

	// ChainPEM is the PEM-encoded certificate chain (intermediate + root).
	ChainPEM string `json:"chainPEM,omitempty" yaml:"chainPEM,omitempty"`

	// CreatedAt is the timestamp when this intermediate CA was created.
	CreatedAt time.Time `json:"createdAt" yaml:"createdAt"`

	// UpdatedAt is the timestamp when this intermediate CA was last updated.
	UpdatedAt time.Time `json:"updatedAt,omitempty" yaml:"updatedAt,omitempty"`
}

// TenantSettings contains tenant-specific configuration options.
type TenantSettings struct {
	// MaxCertificates is the maximum number of certificates this tenant can issue.
	// 0 means unlimited.
	MaxCertificates int `json:"maxCertificates,omitempty" yaml:"maxCertificates,omitempty"`

	// MaxAccounts is the maximum number of ACME accounts this tenant can have.
	// 0 means unlimited.
	MaxAccounts int `json:"maxAccounts,omitempty" yaml:"maxAccounts,omitempty"`

	// AllowedKeyAlgorithms is the list of allowed key algorithms for certificates.
	// If empty, all supported algorithms are allowed.
	AllowedKeyAlgorithms []string `json:"allowedKeyAlgorithms,omitempty" yaml:"allowedKeyAlgorithms,omitempty"`

	// AllowedChallengeTypes is the list of allowed ACME challenge types.
	// If empty, all configured challenge types are allowed.
	AllowedChallengeTypes []string `json:"allowedChallengeTypes,omitempty" yaml:"allowedChallengeTypes,omitempty"`

	// CertificateValidityDays is the default certificate validity in days.
	CertificateValidityDays int `json:"certificateValidityDays,omitempty" yaml:"certificateValidityDays,omitempty"`

	// RequireEAB indicates whether External Account Binding is required for this tenant.
	RequireEAB bool `json:"requireEAB,omitempty" yaml:"requireEAB,omitempty"`

	// AllowEndorse01 indicates whether endorse-01 challenges are allowed for this tenant.
	AllowEndorse01 bool `json:"allowEndorse01,omitempty" yaml:"allowEndorse01,omitempty"`

	// AllowEnroll01 indicates whether enroll-01 challenges are allowed for this tenant.
	AllowEnroll01 bool `json:"allowEnroll01,omitempty" yaml:"allowEnroll01,omitempty"`

	// ComplianceConfig contains pre-issuance compliance validation settings.
	// If nil, the global compliance configuration is used (if set).
	ComplianceConfig *ComplianceConfig `json:"complianceConfig,omitempty" yaml:"complianceConfig,omitempty"`

	// CustomMetadata contains additional tenant-specific settings.
	CustomMetadata map[string]string `json:"customMetadata,omitempty" yaml:"customMetadata,omitempty"`
}

// ComplianceConfig defines compliance requirements for certificate issuance.
// This can be configured globally or per-tenant.
type ComplianceConfig struct {
	// Enabled indicates whether compliance validation is active
	Enabled bool `json:"enabled" yaml:"enabled"`

	// RequireSignedReport indicates whether the compliance report must be signed
	RequireSignedReport bool `json:"requireSignedReport" yaml:"requireSignedReport"`

	// CustomPolicyPath is the path to a custom Rego policy file for additional validation
	CustomPolicyPath string `json:"customPolicyPath,omitempty" yaml:"customPolicyPath,omitempty"`

	// FailOpen determines behavior when compliance data is missing
	// If true, missing report = pass (fail-open)
	// If false, missing report = fail (fail-closed)
	FailOpen bool `json:"failOpen" yaml:"failOpen"`
}

// GlobalComplianceConfig is the server-wide default compliance configuration.
type GlobalComplianceConfig struct {
	ComplianceConfig `json:",inline" yaml:",inline"`

	// Enforce determines how global config applies to tenants:
	// If true, global config is enforced on ALL tenants (override)
	// If false, tenants can define their own config (global is fallback only)
	Enforce bool `json:"enforce" yaml:"enforce"`
}

// ResolveComplianceConfig determines the effective compliance configuration
// for an enrollment based on the global and tenant settings.
func ResolveComplianceConfig(global *GlobalComplianceConfig, tenant *TenantSettings) *ComplianceConfig {
	// If no global config, return nil
	if global == nil {
		return nil
	}

	// If global enforcement is enabled, use global config
	if global.Enforce {
		return &global.ComplianceConfig
	}

	// Check for tenant-specific config
	if tenant != nil && tenant.ComplianceConfig != nil {
		return tenant.ComplianceConfig
	}

	// Fall back to global config
	return &global.ComplianceConfig
}

// Tenant status constants
const (
	// TenantStatusActive indicates the tenant is active and operational.
	TenantStatusActive = "active"

	// TenantStatusSuspended indicates the tenant is suspended and cannot issue certificates.
	TenantStatusSuspended = "suspended"

	// TenantStatusDeleted indicates the tenant has been soft-deleted.
	TenantStatusDeleted = "deleted"
)

// CA status constants
const (
	// CAStatusActive indicates the CA is active and can sign certificates.
	CAStatusActive = "active"

	// CAStatusPendingRotation indicates the CA is pending key rotation.
	CAStatusPendingRotation = "pending-rotation"

	// CAStatusRevoked indicates the CA has been revoked.
	CAStatusRevoked = "revoked"
)

// Parent type constants for intermediate CA
const (
	// CAParentTypeGlobal indicates the intermediate CA is signed by the global root.
	CAParentTypeGlobal = "global"

	// CAParentTypeTenant indicates the intermediate CA is signed by the tenant's root.
	CAParentTypeTenant = "tenant"
)

// CA purpose constants
const (
	// CAPurposeGeneral is the default purpose for general certificate issuance.
	CAPurposeGeneral = "general"

	// CAPurposeServerAuth indicates CA is for server authentication certificates.
	CAPurposeServerAuth = "server-auth"

	// CAPurposeClientAuth indicates CA is for client authentication certificates.
	CAPurposeClientAuth = "client-auth"

	// CAPurposeCodeSigning indicates CA is for code signing certificates.
	CAPurposeCodeSigning = "code-signing"

	// CAPurposeTPMEndorsement indicates CA is for TPM EK certificates (endorse-01).
	CAPurposeTPMEndorsement = "tpm-endorsement"
)

// EntityID returns the numeric entity ID for GenericDAO compatibility.
// The numeric ID is derived from the string ID via FNV-1a hashing.
func (t *Tenant) EntityID() uint64 {
	if t.NumericID == 0 && t.ID != "" {
		t.NumericID = StringToEntityID(t.ID)
	}
	return t.NumericID
}

// SetEntityID sets the numeric entity ID.
func (t *Tenant) SetEntityID(id uint64) {
	t.NumericID = id
}

// IsActive returns true if the tenant is active.
func (t *Tenant) IsActive() bool {
	return t.Status == TenantStatusActive
}

// HasRootCA returns true if the tenant has its own root CA.
func (t *Tenant) HasRootCA() bool {
	return t.RootCA != nil && t.RootCA.Status == CAStatusActive
}

// HasIntermediateCA returns true if the tenant has at least one active intermediate CA.
func (t *Tenant) HasIntermediateCA() bool {
	return t.GetDefaultIntermediateCA() != nil
}

// GetDefaultIntermediateCA returns the default intermediate CA for certificate issuance.
// Returns nil if no active intermediate CA is available.
func (t *Tenant) GetDefaultIntermediateCA() *TenantIntermediateCA {
	if len(t.IntermediateCAs) == 0 {
		return nil
	}

	// If a default is specified, find it
	if t.DefaultIntermediateCAID != "" {
		for _, ca := range t.IntermediateCAs {
			if ca.ID == t.DefaultIntermediateCAID && ca.Status == CAStatusActive {
				return ca
			}
		}
	}

	// Otherwise, return the first active CA
	for _, ca := range t.IntermediateCAs {
		if ca.Status == CAStatusActive {
			return ca
		}
	}

	return nil
}

// GetIntermediateCA returns a specific intermediate CA by ID.
// Returns nil if not found.
func (t *Tenant) GetIntermediateCA(id string) *TenantIntermediateCA {
	for _, ca := range t.IntermediateCAs {
		if ca.ID == id {
			return ca
		}
	}
	return nil
}

// GetActiveIntermediateCAs returns all active intermediate CAs.
func (t *Tenant) GetActiveIntermediateCAs() []*TenantIntermediateCA {
	var active []*TenantIntermediateCA
	for _, ca := range t.IntermediateCAs {
		if ca.Status == CAStatusActive {
			active = append(active, ca)
		}
	}
	return active
}

// GetIntermediateCAsByPurpose returns intermediate CAs matching the given purpose.
func (t *Tenant) GetIntermediateCAsByPurpose(purpose string) []*TenantIntermediateCA {
	var matched []*TenantIntermediateCA
	for _, ca := range t.IntermediateCAs {
		if ca.Purpose == purpose && ca.Status == CAStatusActive {
			matched = append(matched, ca)
		}
	}
	return matched
}

// CanIssueCertificates returns true if the tenant can issue certificates.
func (t *Tenant) CanIssueCertificates() bool {
	return t.IsActive() && t.HasIntermediateCA()
}

// IsActive returns true if this intermediate CA is active.
func (ca *TenantIntermediateCA) IsActive() bool {
	return ca.Status == CAStatusActive
}

// SigningCAInfo contains information about which CA should be used for signing.
// This is returned by GetSigningCA to indicate the signing authority.
type SigningCAInfo struct {
	// Type indicates the type of signing CA: "intermediate", "root", or "global"
	Type string

	// IntermediateCA is set when Type is "intermediate"
	IntermediateCA *TenantIntermediateCA

	// RootCA is set when Type is "root"
	RootCA *TenantRootCA

	// UseGlobalDefault indicates fallback to the global default intermediate CA
	UseGlobalDefault bool

	// TenantID is the tenant that owns this signing authority
	TenantID string
}

// SigningCAType constants
const (
	// SigningCATypeIntermediate indicates signing with tenant's intermediate CA
	SigningCATypeIntermediate = "intermediate"

	// SigningCATypeRoot indicates signing directly with tenant's root CA
	SigningCATypeRoot = "root"

	// SigningCATypeGlobal indicates fallback to global default CA
	SigningCATypeGlobal = "global"
)

// GetSigningCA determines the signing CA to use following the fallback hierarchy:
//  1. Tenant's configured intermediate CA (if exists and active)
//  2. Tenant's root CA directly (if exists and active)
//  3. Global default intermediate CA (fallback)
//
// Parameters:
//   - purpose: Optional purpose filter (e.g., "tpm-endorsement", "server-auth").
//     If provided, preference is given to CAs matching this purpose.
//     If no matching purpose CA is found, falls back to the default hierarchy.
//
// Returns SigningCAInfo indicating which CA should be used for signing operations.
func (t *Tenant) GetSigningCA(purpose string) *SigningCAInfo {
	// Priority 1: Check for intermediate CA matching the requested purpose
	if purpose != "" {
		purposeCAs := t.GetIntermediateCAsByPurpose(purpose)
		if len(purposeCAs) > 0 {
			return &SigningCAInfo{
				Type:           SigningCATypeIntermediate,
				IntermediateCA: purposeCAs[0],
				TenantID:       t.ID,
			}
		}
	}

	// Priority 2: Tenant's default intermediate CA
	if defaultCA := t.GetDefaultIntermediateCA(); defaultCA != nil {
		return &SigningCAInfo{
			Type:           SigningCATypeIntermediate,
			IntermediateCA: defaultCA,
			TenantID:       t.ID,
		}
	}

	// Priority 3: Tenant's root CA (sign directly if no intermediate)
	if t.HasRootCA() {
		return &SigningCAInfo{
			Type:     SigningCATypeRoot,
			RootCA:   t.RootCA,
			TenantID: t.ID,
		}
	}

	// Priority 4: Fall back to global default
	return &SigningCAInfo{
		Type:             SigningCATypeGlobal,
		UseGlobalDefault: true,
		TenantID:         t.ID,
	}
}

// GetSigningCAForEndorsement returns the signing CA specifically for endorse-01 challenges.
// This is a convenience method that calls GetSigningCA with the tpm-endorsement purpose.
func (t *Tenant) GetSigningCAForEndorsement() *SigningCAInfo {
	return t.GetSigningCA(CAPurposeTPMEndorsement)
}
