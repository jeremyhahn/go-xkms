// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

// Package user provides user management for the keychain service.
// Users authenticate using FIDO2/WebAuthn security keys and can
// manage the keychain through CLI or web UI based on their role.
package user

import (
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
)

// Role represents a user's role for access control.
type Role string

const (
	// RoleAdmin has full access to manage the keychain and other users.
	RoleAdmin Role = "admin"
	// RoleOperator can manage keys and certificates but not users.
	RoleOperator Role = "operator"
	// RoleAuditor can only view audit logs and key metadata.
	RoleAuditor Role = "auditor"
	// RoleUser can use keys for cryptographic operations but not manage them.
	RoleUser Role = "user"
	// RoleReadOnly can only list and read non-sensitive information.
	RoleReadOnly Role = "readonly"
	// RoleGuest has minimal access (list keys only).
	RoleGuest Role = "guest"
)

// User represents a user who can access the keychain.
// Implements the webauthn.User interface for WebAuthn compatibility.
type User struct {
	// ID is the unique identifier for the user (WebAuthn user handle).
	ID []byte `json:"id"`

	// Username is the user's username (unique, typically email).
	Username string `json:"username"`

	// DisplayName is the human-readable name for display.
	DisplayName string `json:"display_name"`

	// Role defines the user's access level.
	Role Role `json:"role"`

	// Credentials are the FIDO2/WebAuthn credentials registered for this user.
	Credentials []Credential `json:"credentials"`

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

// IsAdmin checks if the user has admin role.
func (u *User) IsAdmin() bool {
	return u.Role == RoleAdmin
}

// CanManageUsers checks if the user can create/modify other users.
func (u *User) CanManageUsers() bool {
	return u.Enabled && u.Role == RoleAdmin
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
func (u *User) CanListKeys() bool {
	return u.Enabled // All roles can list keys
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
	case RoleAdmin, RoleOperator, RoleAuditor, RoleUser, RoleReadOnly, RoleGuest:
		return true
	default:
		return false
	}
}
