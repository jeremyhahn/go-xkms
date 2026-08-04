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

// ExternalAccountBinding represents an external account binding for enterprise
// account registration per RFC 8555 Section 7.3.4.
//
// This allows enterprises to bind ACME accounts to existing customer accounts
// in non-ACME systems (e.g., CA customer databases). The CA provides the client
// with a MAC key and key identifier outside of ACME, which the client uses to
// prove ownership of the external account during ACME account registration.
type ExternalAccountBinding struct {
	// NumericID is the auto-generated numeric entity ID derived from the string ID
	// via FNV-1a hashing. This enables the Entity interface required by GenericDAO.
	NumericID uint64 `json:"numericId" yaml:"numericId"`

	// ID is the unique identifier for this binding (key identifier per RFC 8555)
	// This MUST be an ASCII string provided to the client out-of-band.
	ID string `json:"kid" yaml:"kid" index:"kid"`

	// MACKey is the base64url-encoded MAC key used to sign the binding JWS.
	// Per RFC 8555, this should be provided in base64url-encoded form.
	MACKey string `json:"macKey" yaml:"macKey"`

	// MACAlgorithm is the algorithm used for MAC computation (e.g., "HS256", "HS384", "HS512").
	// Per RFC 8555, only "HS256" is required, but "HS384" and "HS512" are recommended.
	MACAlgorithm string `json:"alg" yaml:"alg"`

	// AccountID is the ID of the ACME account that has been bound to this external account.
	// This is set when the binding is consumed during account registration.
	AccountID uint64 `json:"accountId,omitempty" yaml:"accountId,omitempty" index:"accountId"`

	// ExternalAccountID is an optional reference to the external system's account ID.
	// This allows the CA to correlate the ACME account with the enterprise customer database.
	ExternalAccountID string `json:"externalAccountId,omitempty" yaml:"externalAccountId,omitempty"`

	// TenantID is the tenant this EAB belongs to in multi-tenant deployments.
	// Required when multi-tenancy is enabled.
	TenantID string `json:"tenantId,omitempty" yaml:"tenantId,omitempty" index:"tenantId"`

	// CreatedBy is the user ID or API key identifier that created this EAB.
	// Used for audit trail purposes.
	CreatedBy string `json:"createdBy,omitempty" yaml:"createdBy,omitempty"`

	// Purpose indicates the intended use of this EAB.
	// Values: "account-binding" (default), "endorse-01", "enroll-01"
	Purpose string `json:"purpose,omitempty" yaml:"purpose,omitempty" index:"purpose"`

	// DeviceInfo contains device-specific information for TPM-based challenges.
	// Used with endorse-01 and enroll-01 challenges.
	DeviceInfo *EABDeviceInfo `json:"deviceInfo,omitempty" yaml:"deviceInfo,omitempty"`

	// Status indicates the current state of the binding.
	// Possible values: "active" (ready to use), "used" (already bound to an account), "revoked".
	Status string `json:"status" yaml:"status" index:"status"`

	// Contact contains optional contact information for the external account holder.
	Contact []string `json:"contact,omitempty" yaml:"contact,omitempty"`

	// CreatedAt is the timestamp when this binding was created.
	CreatedAt time.Time `json:"createdAt" yaml:"createdAt"`

	// UsedAt is the timestamp when this binding was used to create an ACME account.
	UsedAt *time.Time `json:"usedAt,omitempty" yaml:"usedAt,omitempty"`

	// ExpiresAt is the optional expiration time for this binding.
	// If set and expired, the binding cannot be used.
	ExpiresAt *time.Time `json:"expiresAt,omitempty" yaml:"expiresAt,omitempty"`

	// Metadata contains optional custom metadata for the external account.
	// This can be used to store enterprise-specific information.
	Metadata map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// EABDeviceInfo contains device-specific information for TPM-based EAB bindings.
type EABDeviceInfo struct {
	// DeviceID is the unique identifier for the device (e.g., serial number, asset tag).
	DeviceID string `json:"deviceId,omitempty" yaml:"deviceId,omitempty"`

	// Manufacturer is the device manufacturer name.
	Manufacturer string `json:"manufacturer,omitempty" yaml:"manufacturer,omitempty"`

	// Model is the device model name or number.
	Model string `json:"model,omitempty" yaml:"model,omitempty"`

	// EKPublicKeyHash is the SHA-256 hash of the EK public key (hex-encoded).
	// Used for device identity verification in endorse-01 challenges.
	EKPublicKeyHash string `json:"ekPublicKeyHash,omitempty" yaml:"ekPublicKeyHash,omitempty"`

	// TPMManufacturer is the TPM manufacturer identifier.
	TPMManufacturer string `json:"tpmManufacturer,omitempty" yaml:"tpmManufacturer,omitempty"`

	// TPMFirmwareVersion is the TPM firmware version.
	TPMFirmwareVersion string `json:"tpmFirmwareVersion,omitempty" yaml:"tpmFirmwareVersion,omitempty"`

	// Metadata contains additional device metadata.
	Metadata map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
}

// EAB Purpose constants
const (
	// EABPurposeAccountBinding is the default purpose for standard ACME account binding.
	EABPurposeAccountBinding = "account-binding"

	// EABPurposeEndorse01 indicates the EAB is for endorse-01 EK certificate issuance.
	EABPurposeEndorse01 = "endorse-01"

	// EABPurposeEnroll01 indicates the EAB is for enroll-01 device enrollment.
	EABPurposeEnroll01 = "enroll-01"
)

// External account binding status constants.
const (
	// EABStatusActive indicates the binding is ready to be used.
	EABStatusActive = "active"

	// EABStatusUsed indicates the binding has been used to create an ACME account.
	EABStatusUsed = "used"

	// EABStatusRevoked indicates the binding has been revoked and cannot be used.
	EABStatusRevoked = "revoked"

	// EABStatusExpired indicates the binding has expired and cannot be used.
	EABStatusExpired = "expired"
)

// ExternalAccountBindingJWS represents the JWS structure sent by clients
// in the externalAccountBinding field of a newAccount request per RFC 8555 Section 7.3.4.
type ExternalAccountBindingJWS struct {
	// Protected is the base64url-encoded protected header containing:
	// - alg: MAC algorithm (e.g., "HS256")
	// - kid: Key identifier from CA
	// - url: The newAccount URL
	Protected string `json:"protected"`

	// Payload is the base64url-encoded JWK of the ACME account key.
	// This binds the external account to the specific ACME account key.
	Payload string `json:"payload"`

	// Signature is the base64url-encoded MAC signature.
	Signature string `json:"signature"`
}

// ExternalAccountBindingProtectedHeader represents the protected header
// of the external account binding JWS.
type ExternalAccountBindingProtectedHeader struct {
	// Alg is the MAC algorithm (MUST be symmetric: HS256, HS384, or HS512).
	Alg string `json:"alg"`

	// KID is the key identifier provided by the CA.
	KID string `json:"kid"`

	// URL is the URL of the newAccount endpoint.
	URL string `json:"url"`

	// Nonce MUST NOT be present per RFC 8555 Section 7.3.4.
	// This field is used to detect and reject invalid EAB JWS that include a nonce.
	Nonce string `json:"nonce,omitempty"`
}

// EntityID returns the numeric entity ID for GenericDAO compatibility.
// The numeric ID is derived from the string ID (kid) via FNV-1a hashing.
func (eab *ExternalAccountBinding) EntityID() uint64 {
	if eab.NumericID == 0 && eab.ID != "" {
		eab.NumericID = StringToEntityID(eab.ID)
	}
	return eab.NumericID
}

// SetEntityID sets the numeric entity ID.
func (eab *ExternalAccountBinding) SetEntityID(id uint64) {
	eab.NumericID = id
}

// IsActive returns true if the binding is in active status.
func (eab *ExternalAccountBinding) IsActive() bool {
	return eab.Status == EABStatusActive
}

// IsExpired returns true if the binding has expired.
func (eab *ExternalAccountBinding) IsExpired() bool {
	if eab.ExpiresAt == nil {
		return false
	}
	return time.Now().After(*eab.ExpiresAt)
}

// CanBeUsed returns true if the binding can be used for account registration.
func (eab *ExternalAccountBinding) CanBeUsed() bool {
	return eab.IsActive() && !eab.IsExpired()
}

// MarkUsed marks the binding as used and records the bound account ID.
func (eab *ExternalAccountBinding) MarkUsed(accountID uint64) {
	now := time.Now()
	eab.Status = EABStatusUsed
	eab.AccountID = accountID
	eab.UsedAt = &now
}
