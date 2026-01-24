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

package authenticator

import "errors"

// Storage errors
var (
	// ErrStorageClosed indicates the storage has been closed.
	ErrStorageClosed = errors.New("authenticator: storage closed")

	// ErrCredentialExists indicates a credential with the same ID already exists.
	ErrCredentialExists = errors.New("authenticator: credential already exists")

	// ErrStateNotFound indicates no authenticator state has been saved.
	ErrStateNotFound = errors.New("authenticator: state not found")

	// ErrInvalidCredentialID indicates the credential ID is nil or empty.
	ErrInvalidCredentialID = errors.New("authenticator: invalid credential ID")

	// ErrInvalidRPIDEmpty indicates the relying party ID is empty.
	ErrInvalidRPIDEmpty = errors.New("authenticator: relying party ID is empty")

	// ErrSerializationFailed indicates serialization of a credential or state failed.
	ErrSerializationFailed = errors.New("authenticator: serialization failed")

	// ErrDeserializationFailed indicates deserialization of a credential or state failed.
	ErrDeserializationFailed = errors.New("authenticator: deserialization failed")
)

// StatefulCredentialStorage extends CredentialStorage with state persistence
// and resource management capabilities. This interface provides complete
// storage functionality for a FIDO2 authenticator including credential
// storage, authenticator state persistence, and proper resource cleanup.
//
// All implementations must be safe for concurrent use.
type StatefulCredentialStorage interface {
	CredentialStorage

	// SaveState persists authenticator state (PIN hash, retry counters, etc.).
	// The state is serialized and stored atomically.
	SaveState(state *AuthenticatorState) error

	// LoadState retrieves the persisted authenticator state.
	// Returns ErrStateNotFound if no state has been saved.
	LoadState() (*AuthenticatorState, error)

	// Close releases any resources held by the storage.
	// After Close is called, all other methods should return ErrStorageClosed.
	Close() error
}

// SerializableState represents the serializable portion of AuthenticatorState.
// This is used for JSON marshaling since AuthenticatorState contains atomic
// values and crypto keys that require special handling.
type SerializableState struct {
	// AAGUID is the Authenticator Attestation GUID.
	AAGUID [16]byte `json:"aaguid"`

	// PINHash stores SHA-256(left16(SHA-256(PIN))).
	PINHash []byte `json:"pin_hash,omitempty"`

	// PINRetries is the current PIN retry count.
	PINRetries int `json:"pin_retries"`

	// PINSet indicates whether a PIN has been configured.
	PINSet bool `json:"pin_set"`

	// UVRetries is the current user verification retry count.
	UVRetries int `json:"uv_retries"`

	// AttestationKeyPKCS8 is the DER-encoded PKCS#8 attestation private key.
	AttestationKeyPKCS8 []byte `json:"attestation_key_pkcs8,omitempty"`

	// AttestationCert is the DER-encoded attestation certificate.
	AttestationCert []byte `json:"attestation_cert,omitempty"`
}
