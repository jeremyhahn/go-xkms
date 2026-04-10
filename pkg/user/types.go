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

// Package user provides user management for the xkms service.
// Users authenticate using FIDO2/WebAuthn security keys and can
// manage the xkms through CLI or web UI based on their role.
package user

import (
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// Role represents a user's role for access control.
// Aligned with FIPS 140-2/3 separation of duties: admin, operator, user, auditor, custodian, so.
type Role string

const (
	// RoleAdmin has full access to manage the xkms and other users.
	RoleAdmin Role = "admin"
	// RoleOperator can manage keys and certificates but not users.
	RoleOperator Role = "operator"
	// RoleAuditor can only view audit logs and key metadata.
	RoleAuditor Role = "auditor"
	// RoleUser can use keys for cryptographic operations but not manage them.
	RoleUser Role = "user"
	// RoleCustodian participates in key ceremonies and manages key shares
	// per FIPS 140-2/3 and PCI DSS separation of duties requirements.
	RoleCustodian Role = "custodian"
	// RoleSO is the Security Officer role per FIPS 140-2/3 separation of duties.
	// The SO can initialize modules, manage PINs, sign CSRs, and manage tenants.
	// Per FIPS 140-2 AS10.03: "Crypto Officer and User roles are mutually exclusive."
	// The SO CANNOT sign data, encrypt, or decrypt — these are reserved for operational roles.
	RoleSO Role = "so"
)

// User represents a user who can access the xkms.
// Implements the webauthn.User interface for WebAuthn compatibility.
type User struct {
	// ID is the unique identifier for the user (WebAuthn user handle).
	ID []byte `json:"id"`

	// Username is the user's username (unique, typically email).
	Username string `json:"username"`

	// DisplayName is the human-readable name for display.
	DisplayName string `json:"display_name"`

	// Role defines the user's primary access level.
	Role Role `json:"role"`

	// Roles holds additional roles for multi-role support.
	Roles []Role `json:"roles,omitempty"`

	// TenantID scopes the user to a specific tenant. Empty means system-level.
	TenantID string `json:"tenant_id,omitempty"`

	// Credentials are the FIDO2/WebAuthn credentials registered for this user.
	Credentials []Credential `json:"credentials"`

	// CertBindings are X.509 client certificates bound to this user for mTLS authentication.
	CertBindings []CertBinding `json:"cert_bindings,omitempty"`

	// CreatedAt is when the user was created.
	CreatedAt time.Time `json:"created_at"`

	// LastLoginAt is the last successful login time.
	LastLoginAt *time.Time `json:"last_login_at,omitempty"`

	// Enabled indicates if the user account is active.
	Enabled bool `json:"enabled"`

	// sessionData holds temporary WebAuthn session data during ceremonies.
	sessionData []byte `json:"-"`
}

// Credential represents a FIDO2/WebAuthn credential for a user.
type Credential struct {
	// ID is the credential identifier from the authenticator.
	ID []byte `json:"id"`

	// PublicKey is the credential's public key in COSE format.
	PublicKey []byte `json:"public_key"`

	// AttestationType indicates the attestation type used.
	AttestationType string `json:"attestation_type"`

	// AAGUID is the authenticator's unique identifier.
	AAGUID []byte `json:"aaguid"`

	// SignCount is the signature counter for clone detection.
	SignCount uint32 `json:"sign_count"`

	// Name is a user-friendly name for this credential.
	Name string `json:"name"`

	// CreatedAt is when the credential was registered.
	CreatedAt time.Time `json:"created_at"`

	// LastUsedAt is when the credential was last used.
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`

	// Salt is the FIDO2 hmac-secret salt for this credential (for key derivation).
	Salt []byte `json:"salt,omitempty"`
}

// CertBinding represents a bound X.509 client certificate for mTLS authentication.
type CertBinding struct {
	// Fingerprint is the SHA-256 hex digest of the DER-encoded certificate.
	Fingerprint string `json:"fingerprint"`
	// Subject is the certificate's Subject Distinguished Name.
	Subject string `json:"subject"`
	// Issuer is the certificate's Issuer Distinguished Name.
	Issuer string `json:"issuer"`
	// Serial is the certificate's serial number as a string.
	Serial string `json:"serial"`
	// NotAfter is the certificate's expiration time.
	NotAfter time.Time `json:"not_after"`
	// Name is a user-friendly label for this binding (e.g., "xkey PIV 9a").
	Name string `json:"name"`
	// CreatedAt is when the binding was created.
	CreatedAt time.Time `json:"created_at"`
}

// WebAuthnID returns the user's WebAuthn ID (user handle).
func (u *User) WebAuthnID() []byte {
	return u.ID
}

// WebAuthnName returns the user's username.
func (u *User) WebAuthnName() string {
	return u.Username
}

// WebAuthnDisplayName returns the user's display name.
func (u *User) WebAuthnDisplayName() string {
	if u.DisplayName == "" {
		return u.Username
	}
	return u.DisplayName
}

// WebAuthnCredentials returns the user's WebAuthn credentials.
func (u *User) WebAuthnCredentials() []webauthn.Credential {
	creds := make([]webauthn.Credential, len(u.Credentials))
	for i, c := range u.Credentials {
		creds[i] = webauthn.Credential{
			ID:              c.ID,
			PublicKey:       c.PublicKey,
			AttestationType: c.AttestationType,
			Authenticator: webauthn.Authenticator{
				AAGUID:    c.AAGUID,
				SignCount: c.SignCount,
			},
		}
	}
	return creds
}

// AddCredential adds a new credential to the user.
func (u *User) AddCredential(cred *Credential) {
	u.Credentials = append(u.Credentials, *cred)
}

// UpdateCredential updates an existing credential (e.g., sign counter, last used).
func (u *User) UpdateCredential(credID []byte, signCount uint32) {
	now := time.Now().UTC()
	for i := range u.Credentials {
		if string(u.Credentials[i].ID) == string(credID) {
			u.Credentials[i].SignCount = signCount
			u.Credentials[i].LastUsedAt = &now
			return
		}
	}
}

// RemoveCredential removes a credential by ID.
func (u *User) RemoveCredential(credID []byte) bool {
	for i, c := range u.Credentials {
		if string(c.ID) == string(credID) {
			u.Credentials = append(u.Credentials[:i], u.Credentials[i+1:]...)
			return true
		}
	}
	return false
}

// GetCredential returns a credential by ID, or nil if not found.
func (u *User) GetCredential(credID []byte) *Credential {
	for i := range u.Credentials {
		if string(u.Credentials[i].ID) == string(credID) {
			return &u.Credentials[i]
		}
	}
	return nil
}

// AddCertBinding adds a certificate binding to the user.
func (u *User) AddCertBinding(binding *CertBinding) {
	u.CertBindings = append(u.CertBindings, *binding)
}

// RemoveCertBinding removes a certificate binding by fingerprint.
func (u *User) RemoveCertBinding(fingerprint string) bool {
	for i, b := range u.CertBindings {
		if b.Fingerprint == fingerprint {
			u.CertBindings = append(u.CertBindings[:i], u.CertBindings[i+1:]...)
			return true
		}
	}
	return false
}

// GetCertBinding returns a certificate binding by fingerprint, or nil if not found.
func (u *User) GetCertBinding(fingerprint string) *CertBinding {
	for i := range u.CertBindings {
		if u.CertBindings[i].Fingerprint == fingerprint {
			return &u.CertBindings[i]
		}
	}
	return nil
}

// HasCertBinding checks if the user has a certificate binding with the given fingerprint.
func (u *User) HasCertBinding(fingerprint string) bool {
	return u.GetCertBinding(fingerprint) != nil
}

// SetSessionData stores WebAuthn session data during ceremonies.
func (u *User) SetSessionData(data []byte) {
	u.sessionData = data
}

// SessionData returns the stored session data.
func (u *User) SessionData() []byte {
	return u.sessionData
}

// HasRole checks if the user has the specified role.
func (u *User) HasRole(role Role) bool {
	return u.Role == role
}

// HasAnyRole checks if the user has any of the specified roles.
// It checks both the primary Role field and the Roles slice.
func (u *User) HasAnyRole(roles ...Role) bool {
	for _, r := range roles {
		if u.Role == r {
			return true
		}
		for _, ur := range u.Roles {
			if ur == r {
				return true
			}
		}
	}
	return false
}

// CanParticipateCeremony reports whether the user is eligible to participate
// in a key ceremony. The user must be enabled and hold the custodian role
// (either as primary role or in the Roles slice).
func (u *User) CanParticipateCeremony() bool {
	return u.Enabled && u.HasAnyRole(RoleCustodian)
}

// IsAdmin checks if the user has admin role.
func (u *User) IsAdmin() bool {
	return u.Role == RoleAdmin
}

// CanManageUsers checks if the user can create/modify other users.
// Users with Admin or SO roles are permitted.
func (u *User) CanManageUsers() bool {
	return u.Enabled && (u.Role == RoleAdmin || u.Role == RoleSO)
}

// CanManageKeys checks if the user can create/modify/delete keys.
func (u *User) CanManageKeys() bool {
	return u.Enabled && (u.Role == RoleAdmin || u.Role == RoleOperator)
}

// CanUseKeys checks if the user can use keys for cryptographic operations.
func (u *User) CanUseKeys() bool {
	return u.Enabled && (u.Role == RoleAdmin || u.Role == RoleOperator || u.Role == RoleUser)
}

// CanViewAuditLogs checks if the user can view audit logs.
func (u *User) CanViewAuditLogs() bool {
	return u.Enabled && (u.Role == RoleAdmin || u.Role == RoleOperator || u.Role == RoleAuditor)
}

// CanListKeys checks if the user can list keys.
// Enabled users with any valid FIPS 140-2 role can list keys.
func (u *User) CanListKeys() bool {
	return u.Enabled
}

// CanInitializeModule reports whether the user can initialize the PKCS#11 module.
// Only users with the SO role are permitted.
func (u *User) CanInitializeModule() bool {
	return u.Enabled && u.HasAnyRole(RoleSO)
}

// CanSignCSR reports whether the user can sign certificate signing requests.
// Only users with the SO role are permitted.
func (u *User) CanSignCSR() bool {
	return u.Enabled && u.HasAnyRole(RoleSO)
}

// CanManageSecurityPolicy reports whether the user can manage security policies.
// Only users with the SO role are permitted.
func (u *User) CanManageSecurityPolicy() bool {
	return u.Enabled && u.HasAnyRole(RoleSO)
}

// CanZeroize reports whether the user can zeroize cryptographic material.
// Only users with the SO role are permitted.
func (u *User) CanZeroize() bool {
	return u.Enabled && u.HasAnyRole(RoleSO)
}

// CanResetPIN reports whether the user can reset PINs for other users.
// Only users with the SO role are permitted.
func (u *User) CanResetPIN() bool {
	return u.Enabled && u.HasAnyRole(RoleSO)
}

// CanManageTenants reports whether the user can create and delete tenants.
// Users with SO or Admin roles are permitted.
func (u *User) CanManageTenants() bool {
	return u.Enabled && u.HasAnyRole(RoleSO, RoleAdmin)
}

// NewCredentialFromWebAuthn creates a Credential from a WebAuthn credential.
func NewCredentialFromWebAuthn(cred *webauthn.Credential, name string, salt []byte) *Credential {
	return &Credential{
		ID:              cred.ID,
		PublicKey:       cred.PublicKey,
		AttestationType: cred.AttestationType,
		AAGUID:          cred.Authenticator.AAGUID,
		SignCount:       cred.Authenticator.SignCount,
		Name:            name,
		CreatedAt:       time.Now().UTC(),
		Salt:            salt,
	}
}

// IsValidRole checks if a role string is a valid Role.
func IsValidRole(role Role) bool {
	switch role {
	case RoleAdmin, RoleOperator, RoleAuditor, RoleUser, RoleCustodian, RoleSO:
		return true
	default:
		return false
	}
}
