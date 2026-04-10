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
	// Only used when SO PIN is not enabled.
	AttestationKeyPKCS8 []byte `json:"attestation_key_pkcs8,omitempty"`

	// AttestationCert is the DER-encoded attestation certificate.
	AttestationCert []byte `json:"attestation_cert,omitempty"`

	// --- SO PIN Serializable Fields ---

	// SOPINSet indicates whether SO PIN has been configured.
	SOPINSet bool `json:"so_pin_set,omitempty"`

	// SOPINSalt is the random salt for SO PIN Argon2id derivation.
	SOPINSalt []byte `json:"so_pin_salt,omitempty"`

	// SOPINIterations is the Argon2id time parameter for SO PIN.
	SOPINIterations uint32 `json:"so_pin_iterations,omitempty"`

	// SOPINMemory is the Argon2id memory parameter in KiB for SO PIN.
	SOPINMemory uint32 `json:"so_pin_memory,omitempty"`

	// SOPINParallelism is the Argon2id parallelism parameter for SO PIN.
	SOPINParallelism uint8 `json:"so_pin_parallelism,omitempty"`

	// SOPINRetries is the current SO PIN retry count.
	SOPINRetries int `json:"so_pin_retries,omitempty"`

	// --- Wrapped Keys ---

	// WrappedAK is the Admin Key encrypted with SO PIN-derived SMK.
	WrappedAK []byte `json:"wrapped_ak,omitempty"`

	// WrappedCMKUser is the CMK encrypted with user PIN-derived UMK.
	WrappedCMKUser []byte `json:"wrapped_cmk_user,omitempty"`

	// WrappedCMKSO is the CMK encrypted with Admin Key.
	WrappedCMKSO []byte `json:"wrapped_cmk_so,omitempty"`

	// WrappedAttestUser is the attestation key encrypted with CMK.
	WrappedAttestUser []byte `json:"wrapped_attest_user,omitempty"`

	// WrappedAttestSO is the attestation key encrypted with AK.
	WrappedAttestSO []byte `json:"wrapped_attest_so,omitempty"`

	// AttestedConfigHash is the config hash when SO installed attestation key.
	AttestedConfigHash []byte `json:"attested_config_hash,omitempty"`

	// PINSyncPending indicates that a PIN was set before SO PIN was configured,
	// so KeyManager sync is deferred until SO unlock.
	PINSyncPending bool `json:"pin_sync_pending,omitempty"`

	// --- Policy HMAC integrity fields ---

	// PolicyHMACTag is the HMAC tag over the canonical policy fields.
	PolicyHMACTag []byte `json:"policy_hmac_tag,omitempty"`

	// SignedPolicyFields is the snapshot of policy fields when HMAC was computed.
	SignedPolicyFields *PolicyFields `json:"signed_policy_fields,omitempty"`
}
