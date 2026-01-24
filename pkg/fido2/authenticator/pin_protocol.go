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

// PIN Protocol interface for CTAP2 client PIN operations.
// This interface defines the cryptographic operations required for secure
// PIN handling between the platform and authenticator.
//
// The PIN protocol uses ECDH key agreement with P-256 to establish a shared
// secret, which is then used to encrypt PIN values using AES-256-CBC and
// authenticate messages using HMAC-SHA-256.
//
// Two versions of the PIN protocol are defined in CTAP2:
//   - PIN Protocol 1: Uses simple ECDH with SHA-256 and AES-256-CBC
//   - PIN Protocol 2: Adds HKDF key derivation and uses AES-256-GCM
//
// Reference: FIDO CTAP2 specification, section 6.5
// https://fidoalliance.org/specs/fido-v2.1-ps-20210615/fido-client-to-authenticator-protocol-v2.1-ps-20210615.html#authenticatorClientPIN

// PINProtocol defines the interface for CTAP2 PIN protocol operations.
// Implementations must be safe for concurrent use after initialization.
type PINProtocol interface {
	// Version returns the PIN protocol version number.
	// Valid values are 1 (CTAP2.0) or 2 (CTAP2.1).
	Version() int

	// Initialize generates a new ECDH P-256 key agreement pair.
	// This must be called before any other cryptographic operations.
	// Returns an error if key generation fails.
	Initialize() error

	// GetKeyAgreementKey returns the authenticator's public key in COSE format.
	// The key is encoded as a COSE_Key structure using CBOR.
	// Returns an error if the protocol has not been initialized.
	GetKeyAgreementKey() ([]byte, error)

	// SetPeerPublicKey sets the platform's COSE-encoded public key.
	// This establishes the shared secret used for encryption and authentication.
	// The publicKey parameter must be a valid COSE_Key encoded EC2 key.
	// Returns an error if the key is invalid or cannot be decoded.
	SetPeerPublicKey(publicKey []byte) error

	// Encapsulate encrypts data using the established shared secret.
	// For PIN Protocol 1, this uses AES-256-CBC with a zero IV.
	// For PIN Protocol 2, this uses AES-256-GCM.
	// Returns an error if the shared secret has not been established.
	Encapsulate(data []byte) ([]byte, error)

	// Decapsulate decrypts data using the established shared secret.
	// The input must be properly encrypted using the corresponding Encapsulate.
	// Returns an error if decryption fails or the shared secret is not established.
	Decapsulate(data []byte) ([]byte, error)

	// Authenticate creates an HMAC-SHA-256 authentication tag over the message.
	// For PIN Protocol 1, returns the first 16 bytes of HMAC-SHA-256.
	// For PIN Protocol 2, returns the full 32 bytes of HMAC-SHA-256.
	// Returns an error if the shared secret has not been established.
	Authenticate(message []byte) ([]byte, error)

	// Verify verifies an HMAC-SHA-256 authentication tag against the message.
	// Returns nil if the MAC is valid, or an error if verification fails.
	Verify(message, mac []byte) error

	// ResetSharedSecret clears the shared secret and peer public key.
	// This should be called after PIN operations complete or on error.
	// The key agreement pair is retained for subsequent operations.
	ResetSharedSecret()
}

// PIN protocol errors.
var (
	// ErrPINProtocolNotInitialized indicates the PIN protocol has not
	// been initialized with a call to Initialize().
	ErrPINProtocolNotInitialized = errors.New("authenticator: PIN protocol not initialized")

	// ErrPINProtocolMismatch indicates a mismatch between the requested
	// PIN protocol version and the one in use.
	ErrPINProtocolMismatch = errors.New("authenticator: PIN protocol version mismatch")

	// ErrSharedSecretNotEstablished indicates the shared secret has not
	// been established via SetPeerPublicKey().
	ErrSharedSecretNotEstablished = errors.New("authenticator: shared secret not established")

	// ErrInvalidPeerPublicKey indicates the peer's public key is invalid
	// or could not be decoded from COSE format.
	ErrInvalidPeerPublicKey = errors.New("authenticator: invalid peer public key")

	// ErrPINEncryptionFailed indicates encryption of PIN data failed.
	ErrPINEncryptionFailed = errors.New("authenticator: PIN encryption failed")

	// ErrPINDecryptionFailed indicates decryption of PIN data failed.
	ErrPINDecryptionFailed = errors.New("authenticator: PIN decryption failed")

	// ErrPINAuthenticationFailed indicates HMAC verification failed.
	ErrPINAuthenticationFailed = errors.New("authenticator: PIN authentication failed")
)

// PIN protocol version constants.
const (
	// PINProtocolVersion1 is CTAP2.0 PIN protocol using
	// ECDH + SHA-256 + AES-256-CBC + HMAC-SHA-256.
	PINProtocolVersion1 = 1

	// PINProtocolVersion2 is CTAP2.1 PIN protocol using
	// ECDH + HKDF-SHA-256 + AES-256-GCM + HMAC-SHA-256.
	PINProtocolVersion2 = 2
)
