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

// Package keybackend provides pluggable key storage backends for FIDO2 authenticator.
package keybackend

import (
	"crypto/x509"
)

// FIDO2KeyBackendType identifies the key backend type.
type FIDO2KeyBackendType string

const (
	BackendTypeSoftware FIDO2KeyBackendType = "software"
	BackendTypeTPM2     FIDO2KeyBackendType = "tpm2"
	BackendTypePKCS11   FIDO2KeyBackendType = "pkcs11"
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
}

// KeyHandle is an opaque reference to a key in the backend.
type KeyHandle interface {
	// CredentialID returns the credential ID associated with this key.
	CredentialID() []byte

	// Algorithm returns the COSE algorithm identifier.
	Algorithm() int
}

// FIDO2AttestationStatement contains attestation data.
type FIDO2AttestationStatement struct {
	// Format is the attestation statement format (e.g., "packed", "tpm", "none").
	Format string

	// Algorithm is the COSE algorithm used for signing.
	Algorithm int

	// Signature is the attestation signature.
	Signature []byte

	// CertificateChain is the X.509 certificate chain for verification.
	CertificateChain []*x509.Certificate

	// TPMData contains TPM-specific attestation data (for "tpm" format).
	TPMData []byte
}

// FIDO2KeyBackend abstracts key operations for FIDO2 credentials.
// Implementations must be safe for concurrent use.
type FIDO2KeyBackend interface {
	// Type returns the backend type identifier.
	Type() FIDO2KeyBackendType

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
type FIDO2AttestingKeyBackend interface {
	FIDO2KeyBackend

	// GenerateAttestationKey creates or loads the attestation signing key.
	GenerateAttestationKey() (KeyHandle, []byte, error)

	// GetAttestationStatement generates an attestation statement.
	GetAttestationStatement(format string, authData, clientDataHash []byte) (*FIDO2AttestationStatement, error)

	// AttestationCertificateChain returns the attestation certificate chain.
	AttestationCertificateChain() ([]*x509.Certificate, error)
}
