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

package xkms

import (
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	tpm2backend "github.com/jeremyhahn/go-xkms/pkg/backend/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/pkcs8"
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/symmetric"
)

// ---------------------------------------------------------------------------
// Shared backend types (from pkg/backend/)
// ---------------------------------------------------------------------------

// WrappingAlgorithm identifies the algorithm used to wrap key material for
// secure transport between backends.
type WrappingAlgorithm = backend.WrappingAlgorithm

// Wrapping algorithm constants.
const (
	WrappingAlgorithmRSAES_OAEP_SHA_1             = backend.WrappingAlgorithmRSAES_OAEP_SHA_1
	WrappingAlgorithmRSAES_OAEP_SHA_256           = backend.WrappingAlgorithmRSAES_OAEP_SHA_256
	WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1       = backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1
	WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256     = backend.WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256
	WrappingAlgorithmRSA_OAEP_3072_SHA256_AES_256 = backend.WrappingAlgorithmRSA_OAEP_3072_SHA256_AES_256
	WrappingAlgorithmRSA_OAEP_4096_SHA256_AES_256 = backend.WrappingAlgorithmRSA_OAEP_4096_SHA256_AES_256
	WrappingAlgorithmRSA_OAEP_4096_SHA256         = backend.WrappingAlgorithmRSA_OAEP_4096_SHA256
)

// ImportParameters contains the parameters needed to import a key into a
// backend. Obtained via ImportExportBackend.GetImportParameters.
type ImportParameters = backend.ImportParameters

// WrappedKeyMaterial represents key material that has been wrapped for secure
// transport between backends.
type WrappedKeyMaterial = backend.WrappedKeyMaterial

// ImportExportBackend extends types.KeyProvider with key import/export
// capabilities for secure key transport between systems.
type ImportExportBackend = backend.ImportExportBackend

// NewMemoryAEADTracker creates an in-memory AEAD safety tracker suitable for
// testing and short-lived processes. Production systems should use a persistent
// tracker.
var NewMemoryAEADTracker = backend.NewMemoryAEADTracker

// NOTE: AEADSafetyTracker is already re-exported in types.go as part of the
// core type re-exports. Use xkms.AEADSafetyTracker directly.

// ---------------------------------------------------------------------------
// Shared backend error sentinels (from pkg/backend/errors.go)
// ---------------------------------------------------------------------------

var (
	// ErrBackendFileAlreadyExists is returned when saving a file that already exists.
	ErrBackendFileAlreadyExists = backend.ErrFileAlreadyExists

	// ErrBackendFileNotFound is returned when a file does not exist.
	ErrBackendFileNotFound = backend.ErrFileNotFound

	// ErrBackendKeyNotFound is returned when a key does not exist.
	ErrBackendKeyNotFound = backend.ErrKeyNotFound

	// ErrBackendKeyAlreadyExists is returned when generating a key that already exists.
	ErrBackendKeyAlreadyExists = backend.ErrKeyAlreadyExists

	// ErrBackendInvalidKeyType is returned for unsupported key types.
	ErrBackendInvalidKeyType = backend.ErrInvalidKeyType

	// ErrBackendNotSupported is returned for unsupported operations.
	ErrBackendNotSupported = backend.ErrNotSupported

	// ErrBackendInvalidAlgorithm is returned for unsupported algorithms.
	ErrBackendInvalidAlgorithm = backend.ErrInvalidAlgorithm

	// ErrBackendNonceReused is returned when AEAD nonce reuse is detected.
	ErrBackendNonceReused = backend.ErrNonceReused

	// ErrBackendBytesLimitExceeded is returned when encrypted bytes exceed safety limits.
	ErrBackendBytesLimitExceeded = backend.ErrBytesLimitExceeded

	// ErrBackendExportNotSupported is returned when a backend does not support export.
	ErrBackendExportNotSupported = backend.ErrExportNotSupported

	// ErrBackendImportNotSupported is returned when a backend does not support import.
	ErrBackendImportNotSupported = backend.ErrImportNotSupported

	// ErrBackendKeyNotExportable is returned when a key is not marked exportable.
	ErrBackendKeyNotExportable = backend.ErrKeyNotExportable

	// ErrBackendAsymmetricKeyExportNotAllowed is returned when raw export of
	// asymmetric key material is attempted.
	ErrBackendAsymmetricKeyExportNotAllowed = backend.ErrAsymmetricKeyExportNotAllowed
)

// ---------------------------------------------------------------------------
// Software backend (from pkg/backend/software/)
//
// SoftwareBackend is the unified backend providing both asymmetric (PKCS#8)
// and symmetric (AES-GCM, ChaCha20-Poly1305) operations in software.
// ---------------------------------------------------------------------------

// SoftwareBackend provides a unified interface for asymmetric and symmetric
// cryptographic operations using software-based implementations.
type SoftwareBackend = software.SoftwareBackend

// SoftwareBackendConfig configures the unified SoftwareBackend.
type SoftwareBackendConfig = software.Config

// NewSoftwareBackend creates a new unified software backend. The returned
// value implements types.SymmetricKeyProvider, types.KeyProvider,
// ImportExportBackend, and types.Sealer.
var NewSoftwareBackend = software.NewBackend

// ---------------------------------------------------------------------------
// PKCS8 backend (from pkg/backend/pkcs8/)
//
// PKCS8Backend handles asymmetric key operations (RSA, ECDSA, Ed25519,
// X25519) with keys stored in PKCS#8 format.
// ---------------------------------------------------------------------------

// PKCS8Backend implements asymmetric key operations using PKCS#8 encoding.
type PKCS8Backend = pkcs8.PKCS8Backend

// PKCS8BackendConfig configures the PKCS8Backend.
type PKCS8BackendConfig = pkcs8.Config

// NewPKCS8Backend creates a new PKCS#8 backend. The returned value implements
// types.KeyProvider and types.KeyAgreement.
var NewPKCS8Backend = pkcs8.NewBackend

// ---------------------------------------------------------------------------
// Symmetric backend (from pkg/backend/symmetric/)
//
// SymmetricBackend handles symmetric key operations (AES-GCM,
// ChaCha20-Poly1305, XChaCha20-Poly1305) with AEAD safety tracking.
// ---------------------------------------------------------------------------

// SymmetricBackend implements symmetric encryption operations with AEAD
// safety tracking for nonce uniqueness and encrypted bytes limits.
type SymmetricBackend = symmetric.Backend

// SymmetricBackendConfig configures the SymmetricBackend.
type SymmetricBackendConfig = symmetric.Config

// NewSymmetricBackend creates a new symmetric backend. The returned value
// implements types.SymmetricKeyProvider and ImportExportBackend.
var NewSymmetricBackend = symmetric.NewBackend

// ---------------------------------------------------------------------------
// TPM2 backend (from pkg/backend/tpm2/)
//
// TPM2Backend provides hardware-backed key operations using a TPM 2.0 module.
// ---------------------------------------------------------------------------

// TPM2BackendExternalConfig holds configuration for creating a TPM2Backend
// with an externally managed TPM instance.
type TPM2BackendExternalConfig = tpm2backend.ExternalTPMConfig

// NewTPM2BackendWithTPM creates a new TPM2 backend using an existing TPM
// instance provided via TPM2BackendExternalConfig.
var NewTPM2BackendWithTPM = tpm2backend.NewBackendWithTPM

// ---------------------------------------------------------------------------
// Quantum backend (from pkg/backend/quantum/)
//
// Post-quantum cryptographic backend using pure-Go implementations:
// cloudflare/circl for ML-DSA (FIPS 204) and crypto/mlkem for ML-KEM (FIPS 203).
// No CGO or external libraries required.
//
// Available types (re-exported in backends_quantum.go):
//
//   xkms.QuantumBackend       - Post-quantum backend (ML-DSA, ML-KEM)
//   xkms.QuantumBackendConfig - Quantum backend configuration
//   xkms.NewQuantumBackend    - Constructor (storage.Backend) -> (*QuantumBackend, error)
//   xkms.NewQuantumBackendWithConfig - Constructor with config
//   xkms.MLDSAPrivateKey      - ML-DSA signing private key
//   xkms.MLDSAPublicKey       - ML-DSA public key
//   xkms.MLKEMPrivateKey      - ML-KEM encapsulation private key
//   xkms.MLKEMPublicKey       - ML-KEM public key
// ---------------------------------------------------------------------------
