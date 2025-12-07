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

package webauthn

import (
	"encoding/binary"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

// User represents a WebAuthn user. Applications should implement this
// interface to integrate with their existing user model.
//
// The interface embeds webauthn.User from the go-webauthn library to ensure
// compatibility with the underlying WebAuthn operations.
type User interface {
	webauthn.User

	// AddCredential adds a new credential to the user.
	AddCredential(cred *Credential)

	// UpdateCredential updates an existing credential (e.g., sign counter).
	UpdateCredential(cred *Credential)

	// SetSessionData stores WebAuthn session data on the user.
	// This is used during the login flow to persist session state.
	SetSessionData(data []byte)

	// SessionData returns the stored WebAuthn session data.
	SessionData() []byte

	// Email returns the user's email address.
	Email() string

	// DisplayName returns the user's display name.
	DisplayName() string
}

// Credential represents a WebAuthn credential stored by the Relying Party.
// This wraps the go-webauthn Credential type with additional metadata.
type Credential struct {
	// ID is the credential identifier assigned by the authenticator.
	ID []byte `json:"id"`

	// UserID is the user handle (WebAuthn user ID) this credential belongs to.
	UserID []byte `json:"user_id"`

	// PublicKey is the credential's public key in COSE format.
	PublicKey []byte `json:"public_key"`

	// AttestationType indicates the type of attestation used.
	AttestationType string `json:"attestation_type"`

	// Transport lists the transports supported by the authenticator.
	Transport []protocol.AuthenticatorTransport `json:"transport,omitempty"`

	// Flags contains authenticator flags.
	Flags CredentialFlags `json:"flags"`

	// Authenticator contains authenticator-specific data.
	Authenticator AuthenticatorData `json:"authenticator"`

	// CreatedAt is when the credential was registered.
	CreatedAt time.Time `json:"created_at"`

	// LastUsedAt is when the credential was last used for authentication.
	LastUsedAt time.Time `json:"last_used_at,omitempty"`
}

// CredentialFlags contains authenticator capability flags.
type CredentialFlags struct {
	// UserPresent indicates the user was present during the operation.
	UserPresent bool `json:"user_present"`

	// UserVerified indicates the user was verified (e.g., biometric, PIN).
	UserVerified bool `json:"user_verified"`

	// BackupEligible indicates the credential can be backed up.
	BackupEligible bool `json:"backup_eligible"`

	// BackupState indicates the credential is currently backed up.
	BackupState bool `json:"backup_state"`
}

// AuthenticatorData contains authenticator-specific information.
type AuthenticatorData struct {
	// AAGUID is the authenticator's unique identifier.
	AAGUID []byte `json:"aaguid"`

	// SignCount is the signature counter for clone detection.
	SignCount uint32 `json:"sign_count"`

	// CloneWarning indicates a potential cloned authenticator.
	CloneWarning bool `json:"clone_warning"`

	// Attachment indicates how the authenticator is attached.
	Attachment protocol.AuthenticatorAttachment `json:"attachment"`
}

// ToWebAuthn converts a Credential to the go-webauthn library's Credential type.
func (c *Credential) ToWebAuthn() webauthn.Credential {
	return webauthn.Credential{
		ID:              c.ID,
		PublicKey:       c.PublicKey,
		AttestationType: c.AttestationType,
		Transport:       c.Transport,
		Flags: webauthn.CredentialFlags{
			UserPresent:    c.Flags.UserPresent,
			UserVerified:   c.Flags.UserVerified,
			BackupEligible: c.Flags.BackupEligible,
			BackupState:    c.Flags.BackupState,
		},
		Authenticator: webauthn.Authenticator{
			AAGUID:       c.Authenticator.AAGUID,
			SignCount:    c.Authenticator.SignCount,
			CloneWarning: c.Authenticator.CloneWarning,
			Attachment:   c.Authenticator.Attachment,
		},
	}
}

// FromWebAuthnCredential creates a Credential from the go-webauthn library's type.
func FromWebAuthnCredential(userID []byte, wc *webauthn.Credential) *Credential {
	return &Credential{
		ID:              wc.ID,
		UserID:          userID,
		PublicKey:       wc.PublicKey,
		AttestationType: wc.AttestationType,
		Transport:       wc.Transport,
		Flags: CredentialFlags{
			UserPresent:    wc.Flags.UserPresent,
			UserVerified:   wc.Flags.UserVerified,
			BackupEligible: wc.Flags.BackupEligible,
			BackupState:    wc.Flags.BackupState,
		},
		Authenticator: AuthenticatorData{
			AAGUID:       wc.Authenticator.AAGUID,
			SignCount:    wc.Authenticator.SignCount,
			CloneWarning: wc.Authenticator.CloneWarning,
			Attachment:   wc.Authenticator.Attachment,
		},
		CreatedAt: time.Now().UTC(),
	}
}

// DefaultUser is a simple implementation of the User interface.
// Applications can use this directly or as a reference for their own implementation.
type DefaultUser struct {
	id          []byte
	email       string
	displayName string
	credentials []*Credential
	sessionData []byte
}

// NewDefaultUser creates a new DefaultUser with the given parameters.
func NewDefaultUser(id []byte, email, displayName string) *DefaultUser {
	return &DefaultUser{
		id:          id,
		email:       email,
		displayName: displayName,
		credentials: make([]*Credential, 0),
	}
}

// NewDefaultUserFromEmail creates a new DefaultUser with an ID derived from the email.
func NewDefaultUserFromEmail(email, displayName string) *DefaultUser {
	// Generate a deterministic ID from the email
	id := GenerateUserID(email)
	return NewDefaultUser(id, email, displayName)
}

// GenerateUserID generates a deterministic user ID from an email address.
// The ID is an 8-byte value suitable for WebAuthn user handles.
func GenerateUserID(email string) []byte {
	// Use FNV-1a hash for a deterministic, stable ID
	var h uint64 = 14695981039346656037 // FNV offset basis
	for _, b := range []byte(email) {
		h ^= uint64(b)
		h *= 1099511628211 // FNV prime
	}
	id := make([]byte, 8)
	binary.BigEndian.PutUint64(id, h)
	return id
}

// WebAuthnID returns the user's WebAuthn ID (user handle).
func (u *DefaultUser) WebAuthnID() []byte {
	return u.id
}

// WebAuthnName returns the user's username (typically email).
func (u *DefaultUser) WebAuthnName() string {
	return u.email
}

// WebAuthnDisplayName returns the user's display name.
func (u *DefaultUser) WebAuthnDisplayName() string {
	if u.displayName == "" {
		return u.email
	}
	return u.displayName
}

// WebAuthnCredentials returns the user's registered credentials.
func (u *DefaultUser) WebAuthnCredentials() []webauthn.Credential {
	creds := make([]webauthn.Credential, len(u.credentials))
	for i, c := range u.credentials {
		creds[i] = c.ToWebAuthn()
	}
	return creds
}

// AddCredential adds a new credential to the user.
func (u *DefaultUser) AddCredential(cred *Credential) {
	u.credentials = append(u.credentials, cred)
}

// UpdateCredential updates an existing credential.
func (u *DefaultUser) UpdateCredential(cred *Credential) {
	for i, c := range u.credentials {
		if string(c.ID) == string(cred.ID) {
			u.credentials[i] = cred
			return
		}
	}
}

// SetSessionData stores WebAuthn session data.
func (u *DefaultUser) SetSessionData(data []byte) {
	u.sessionData = data
}

// SessionData returns the stored session data.
func (u *DefaultUser) SessionData() []byte {
	return u.sessionData
}

// Email returns the user's email address.
func (u *DefaultUser) Email() string {
	return u.email
}

// DisplayName returns the user's display name.
func (u *DefaultUser) DisplayName() string {
	return u.displayName
}

// Credentials returns the user's credentials.
func (u *DefaultUser) Credentials() []*Credential {
	return u.credentials
}

// SetCredentials replaces the user's credentials.
func (u *DefaultUser) SetCredentials(creds []*Credential) {
	u.credentials = creds
}
