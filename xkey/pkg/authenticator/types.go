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

package authenticator

import (
	"crypto"
	"crypto/ecdsa"
	"sync/atomic"
	"time"
)

// credProtect levels as defined in the CTAP2 credProtect extension.
const (
	// CredProtectNone indicates no credential protection.
	CredProtectNone uint8 = 0

	// CredProtectUserVerificationOptional indicates credential is always visible.
	CredProtectUserVerificationOptional uint8 = 1

	// CredProtectUserVerificationOptionalWithList indicates credential is visible
	// only when in allowList or when user verification is performed.
	CredProtectUserVerificationOptionalWithList uint8 = 2

	// CredProtectUserVerificationRequired indicates credential requires user verification.
	CredProtectUserVerificationRequired uint8 = 3
)

// Credential represents a stored FIDO2 credential.
// It contains all the information needed to generate assertions.
type Credential struct {
	// ID is the unique credential identifier (32 bytes).
	// This is returned to the relying party during registration.
	ID []byte

	// RPID is the relying party identifier (domain name).
	RPID string

	// RPName is the relying party display name.
	RPName string

	// UserID is the user handle provided by the relying party.
	// This is opaque to the authenticator.
	UserID []byte

	// UserName is the human-readable user name.
	UserName string

	// UserDisplayName is the user's preferred display name.
	UserDisplayName string

	// PrivateKey is the credential private key.
	// Supported types: *ecdsa.PrivateKey, *rsa.PrivateKey, ed25519.PrivateKey
	PrivateKey crypto.PrivateKey

	// PublicKeyCOSE is the COSE-encoded public key.
	// This is included in the attestation object during registration.
	PublicKeyCOSE []byte

	// Algorithm is the COSE algorithm identifier.
	// Common values: -7 (ES256), -257 (RS256), -8 (EdDSA)
	Algorithm int

	// SignCount is the signature counter.
	// Incremented on each assertion to help detect cloned authenticators.
	SignCount uint32

	// CreatedAt is the credential creation timestamp.
	CreatedAt time.Time

	// Discoverable indicates if this is a discoverable credential (resident key).
	// Discoverable credentials can be used without an allowList.
	Discoverable bool

	// CredProtect is the credential protection level (0-3).
	// See CredProtect* constants for valid values.
	CredProtect uint8

	// HMACSecretKey is the 32-byte secret key for the hmac-secret extension.
	// This is used to derive symmetric secrets during assertions.
	HMACSecretKey []byte
}

// AuthenticatorState contains mutable authenticator state.
// This structure maintains the authenticator's configuration and security state.
type AuthenticatorState struct {
	// AAGUID is the Authenticator Attestation GUID.
	// This uniquely identifies the authenticator model.
	AAGUID [16]byte

	// PINHash stores SHA-256(left16(SHA-256(PIN))).
	// The PIN itself is never stored.
	PINHash []byte

	// pinRetries stores the remaining PIN attempts atomically.
	pinRetries atomic.Int32

	// PINSet indicates whether a PIN has been configured.
	PINSet bool

	// uvRetries stores the remaining user verification attempts atomically.
	uvRetries atomic.Int32

	// AttestationKey is the self-attestation signing key.
	// Used to sign attestation statements during credential creation.
	// When SO PIN is enabled, this key is protected via key wrapping.
	AttestationKey *ecdsa.PrivateKey

	// AttestationCert is the DER-encoded attestation certificate.
	// This is included in attestation statements.
	AttestationCert []byte

	// --- SO PIN fields ---

	// SOPINManager manages Security Officer PIN state.
	// When non-nil, SO PIN protection is enabled for admin operations.
	SOPINManager *SOPINManager

	// --- Wrapped Keys (SO PIN protection) ---
	// These fields store encrypted key material when SO PIN is enabled.
	// Keys are wrapped using AES-256-GCM with keys derived from PINs.

	// WrappedAK is the Admin Key encrypted with the SO PIN-derived SMK.
	// Format: nonce (12 bytes) || ciphertext || tag (16 bytes)
	WrappedAK []byte

	// WrappedCMKUser is the Credential Master Key encrypted with user PIN-derived UMK.
	// This allows users to access credentials with their PIN.
	WrappedCMKUser []byte

	// WrappedCMKSO is the Credential Master Key encrypted with Admin Key (AK).
	// This allows SO to reset user PIN (re-wrap CMK with new UMK).
	WrappedCMKSO []byte

	// WrappedAttestUser is the attestation key encrypted with CMK.
	// Allows users to sign attestations during MakeCredential.
	WrappedAttestUser []byte

	// WrappedAttestSO is the attestation key encrypted with AK.
	// Allows SO to replace/regenerate the attestation key.
	WrappedAttestSO []byte

	// AttestedConfigHash is the SHA-256 hash of the config when SO installed
	// the attestation key. Used for config integrity verification in FIDO2 extensions.
	AttestedConfigHash []byte

	// PINSyncPending indicates that a FIDO2 PIN was set before the SO PIN
	// was configured, so KeyManager sync is deferred until SO unlock.
	PINSyncPending bool

	// --- Policy HMAC integrity fields ---

	// PolicyHMACTag is the HMAC tag over the canonical policy fields.
	// Computed by SO operations, verified on startup to detect tampering.
	PolicyHMACTag []byte

	// SignedPolicyFields is a snapshot of the policy fields at the time
	// the HMAC was computed. Used for diagnostics on mismatch to identify
	// exactly which fields were modified.
	SignedPolicyFields *PolicyFields
}

// NewAuthenticatorState creates a new AuthenticatorState with default values.
func NewAuthenticatorState() *AuthenticatorState {
	state := &AuthenticatorState{}
	state.pinRetries.Store(int32(DefaultPINMaxRetries))
	state.uvRetries.Store(int32(DefaultUVRetries))
	return state
}

// DefaultUVRetries is the default number of user verification retry attempts.
const DefaultUVRetries = 3

// PINRetries returns the current number of remaining PIN attempts.
func (s *AuthenticatorState) PINRetries() int {
	return int(s.pinRetries.Load())
}

// SetPINRetries sets the number of remaining PIN attempts.
func (s *AuthenticatorState) SetPINRetries(retries int) {
	s.pinRetries.Store(int32(retries))
}

// DecrementPINRetries decrements the PIN retry counter and returns the new value.
func (s *AuthenticatorState) DecrementPINRetries() int {
	return int(s.pinRetries.Add(-1))
}

// ResetPINRetries resets the PIN retry counter to the default value.
func (s *AuthenticatorState) ResetPINRetries() {
	s.pinRetries.Store(int32(DefaultPINMaxRetries))
}

// UVRetries returns the current number of remaining user verification attempts.
func (s *AuthenticatorState) UVRetries() int {
	return int(s.uvRetries.Load())
}

// SetUVRetries sets the number of remaining user verification attempts.
func (s *AuthenticatorState) SetUVRetries(retries int) {
	s.uvRetries.Store(int32(retries))
}

// DecrementUVRetries decrements the UV retry counter and returns the new value.
func (s *AuthenticatorState) DecrementUVRetries() int {
	return int(s.uvRetries.Add(-1))
}

// ResetUVRetries resets the UV retry counter to the default value.
func (s *AuthenticatorState) ResetUVRetries() {
	s.uvRetries.Store(int32(DefaultUVRetries))
}

// RelyingParty represents a WebAuthn relying party.
// The relying party is typically a web application or service.
type RelyingParty struct {
	// ID is the relying party identifier (typically a domain name).
	// This must match the origin of the requesting web application.
	ID string

	// Name is the human-readable relying party name.
	Name string

	// Icon is an optional URL to the relying party's icon.
	// Deprecated in WebAuthn Level 2 but maintained for compatibility.
	Icon string
}

// User represents a WebAuthn user entity.
// This contains information about the user being registered or authenticated.
type User struct {
	// ID is the user handle provided by the relying party.
	// This should be an opaque identifier that does not contain PII.
	ID []byte

	// Name is the human-readable user name (e.g., email or username).
	Name string

	// DisplayName is the user's preferred display name.
	DisplayName string

	// Icon is an optional URL to the user's avatar.
	// Deprecated in WebAuthn Level 2 but maintained for compatibility.
	Icon string
}

// PublicKeyCredentialParam specifies a supported credential type and algorithm.
// This is used during credential creation to indicate preferred algorithms.
type PublicKeyCredentialParam struct {
	// Type is the credential type. Must be "public-key" for WebAuthn.
	Type string

	// Alg is the COSE algorithm identifier.
	// Common values: -7 (ES256), -257 (RS256), -8 (EdDSA)
	Alg int
}

// CredentialDescriptor identifies a specific credential.
// Used in allowList and excludeList during WebAuthn operations.
type CredentialDescriptor struct {
	// Type is the credential type. Must be "public-key" for WebAuthn.
	Type string

	// ID is the credential identifier.
	ID []byte

	// Transports is an optional list of supported transports.
	// Valid values: "usb", "nfc", "ble", "internal", "hybrid"
	Transports []string
}
