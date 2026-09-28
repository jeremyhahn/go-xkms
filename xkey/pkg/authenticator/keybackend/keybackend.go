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

// Package keybackend provides pluggable key storage backends for FIDO2 authenticator.
package keybackend

import (
	"crypto/x509"

	xkms "github.com/jeremyhahn/go-xkms/sdk/go"
)

// FIDO2KeyCapabilities describes what a key backend can do.
type FIDO2KeyCapabilities struct {
	// SupportedAlgorithms lists COSE algorithm IDs the backend supports.
	SupportedAlgorithms []int

	// SupportsExport indicates if private keys can be exported.
	SupportsExport bool

	// SupportsImport indicates if private keys can be imported.
	SupportsImport bool

	// SupportsAttestation indicates if the backend can provide attestation.
	SupportsAttestation bool

	// HardwareBacked indicates if keys are stored in hardware.
	HardwareBacked bool

	// HandlesUserPresence indicates if the backend handles user presence
	// internally (e.g., phone backend prompts for biometrics). When true, the
	// authenticator should skip local user presence requests since they happen
	// as part of the key operation (GenerateCredentialKey, Sign).
	HandlesUserPresence bool

	// HandlesUserVerification indicates if the backend performs user verification
	// inside its own key operations (e.g., a phone biometric gating
	// GenerateCredentialKey and Sign). When true and the backend's operation
	// succeeds, the UV flag should be set in the authenticator response even
	// without a pinUvAuthParam from the platform.
	//
	// It is NOT a standalone user verification method: the authenticator
	// cannot ask the backend to verify a user on demand, so it never mints a
	// pinUvAuthToken on the strength of this capability (#1145).
	HandlesUserVerification bool
}

// KeyHandle is an opaque reference to a key in the backend.
type KeyHandle interface {
	// CredentialID returns the credential ID associated with this key.
	CredentialID() []byte

	// Algorithm returns the COSE algorithm identifier.
	Algorithm() int

	// BackendID returns the type of the backend that manages this key.
	BackendID() xkms.BackendType
}

// FIDO2AttestationStatement contains attestation data.
type FIDO2AttestationStatement struct {
	// Format is the attestation statement format (e.g., "packed", "tpm", "none").
	Format string

	// Algorithm is the COSE algorithm used for signing.
	Algorithm int

	// Signature is the attestation signature. For "packed" this is a raw
	// signature over authData‖clientDataHash; for "tpm" this is the IAK's
	// ordinary signature over CertInfo -- ASN.1 DER for ECDSA, the raw
	// big-endian value for RSA -- in the same encoding every other WebAuthn
	// format's "sig" uses (WebAuthn L2 §8.3 "sig").
	Signature []byte

	// CertificateChain is the X.509 certificate chain for verification.
	CertificateChain []*x509.Certificate

	// Ver is the attestation statement format version, required by the "tpm"
	// format's "ver" field. WebAuthn L2 §8.3 defines only "2.0".
	Ver string

	// CertInfo is the raw TPMS_ATTEST structure TPM2_Certify produced over the
	// credential key, required by the "tpm" format's "certInfo" field.
	CertInfo []byte

	// PubArea is the credential key's raw TPMT_PUBLIC structure, required by
	// the "tpm" format's "pubArea" field. Its Name must match the Name
	// TPM2_Certify attested to in CertInfo.
	PubArea []byte
}

// FIDO2KeyBackend abstracts key operations for FIDO2 credentials.
// Implementations must be safe for concurrent use.
type FIDO2KeyBackend interface {
	// Type returns the backend type identifier.
	Type() xkms.BackendType

	// Capabilities returns what this backend supports.
	Capabilities() FIDO2KeyCapabilities

	// GenerateCredentialKey creates a new key pair for a credential.
	// Returns the key handle, COSE-encoded public key, and any error.
	GenerateCredentialKey(algorithm int, credentialID []byte) (KeyHandle, []byte, error)

	// Sign creates a signature over the data using the specified key.
	Sign(handle KeyHandle, algorithm int, data []byte) ([]byte, error)

	// LoadKey loads a previously generated key by credential ID.
	LoadKey(credentialID []byte, algorithm int) (KeyHandle, error)

	// DeleteKey removes a key from the backend.
	DeleteKey(handle KeyHandle) error

	// ExportPrivateKey exports the private key in PKCS#8 format.
	// Returns ErrExportNotSupported for hardware-backed keys.
	ExportPrivateKey(handle KeyHandle) ([]byte, error)

	// ImportPrivateKey imports a PKCS#8 encoded private key.
	// Returns ErrImportNotSupported if not supported.
	ImportPrivateKey(credentialID []byte, algorithm int, pkcs8Key []byte) (KeyHandle, error)

	// Close releases backend resources.
	Close() error
}

// FIDO2AttestingKeyBackend extends FIDO2KeyBackend with attestation support.
// AttestingBackend implements it for the device attestation identity a Security
// Officer provisions; a backend that holds its own attestation key in hardware
// (TPM2, PKCS#11) implements it directly and takes precedence.
type FIDO2AttestingKeyBackend interface {
	FIDO2KeyBackend

	// GenerateAttestationKey creates or loads the attestation signing key.
	GenerateAttestationKey() (KeyHandle, []byte, error)

	// GetAttestationStatement generates an attestation statement.
	GetAttestationStatement(format string, authData, clientDataHash []byte) (*FIDO2AttestationStatement, error)

	// AttestationCertificateChain returns the attestation certificate chain.
	AttestationCertificateChain() ([]*x509.Certificate, error)
}
