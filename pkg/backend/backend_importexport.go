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

package backend

import (
	"context"
	"crypto"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// WrappingAlgorithm identifies the algorithm used to wrap key material for secure transport.
// WrappingAlgorithm is an alias of types.KeyWrapAlgorithm, not a second type.
//
// The two were separate types carrying identical strings, so the same
// algorithm had two Go identities depending on which package a caller reached
// for, and a value could not cross between them without a conversion. Aliasing
// makes them one type; the strings are unchanged, so nothing on the wire moves.
type WrappingAlgorithm = types.KeyWrapAlgorithm

// The shared algorithms are defined once, in pkg/types, and named here for the
// callers that already spell them WrappingAlgorithm*.
const (
	// RSA-based wrapping algorithms (PKCS#1 OAEP)
	WrappingAlgorithmRSAES_OAEP_SHA_1   = types.WrapRSAOAEPSHA1
	WrappingAlgorithmRSAES_OAEP_SHA_256 = types.WrapRSAOAEPSHA256

	// Hybrid wrapping algorithms (RSA + AES-KWP)
	// These use RSA to wrap a temporary AES key, then use that AES key to wrap the target key.
	// Required for wrapping RSA private keys which may exceed RSA key size limits.
	WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_1   = types.WrapRSAAESKWSHA1
	WrappingAlgorithmRSA_AES_KEY_WRAP_SHA_256 = types.WrapRSAAESKWSHA256
)

// GCP-specific hybrid algorithms. These stay declared here rather than in
// pkg/types: they name a single cloud provider's import scheme, not a
// construction the project's own vocabulary needs. They share the aliased
// type, so they interoperate with every canonical constant.
const (
	WrappingAlgorithmRSA_OAEP_3072_SHA256_AES_256 WrappingAlgorithm = "RSA_OAEP_3072_SHA256_AES_256"
	WrappingAlgorithmRSA_OAEP_4096_SHA256_AES_256 WrappingAlgorithm = "RSA_OAEP_4096_SHA256_AES_256"
	WrappingAlgorithmRSA_OAEP_4096_SHA256         WrappingAlgorithm = "RSA_OAEP_4096_SHA256"

	// WrappingAlgorithmVaultTransitBYOK identifies HashiCorp Vault Transit's
	// own "bring your own key" wrapping format, used to import key material
	// into Vault: an ephemeral AES-256 key wrapped with RSA-OAEP-SHA256 under
	// the public half of Vault's own wrapping key (obtained from
	// transit/wrapping_key), concatenated with the target key material
	// encrypted under that ephemeral key with AES-256-GCM and an all-zero
	// 96-bit nonce -- safe only because the ephemeral key is used exactly
	// once. This is Vault's own defined wire format (see HashiCorp's Transit
	// "Importing Keys" documentation), not a construction this project
	// invented, and it stays declared here rather than in pkg/backend/vault
	// for the same reason the GCP constants above do: every wrapping
	// algorithm this project speaks shares one vocabulary and one type.
	WrappingAlgorithmVaultTransitBYOK WrappingAlgorithm = "VAULT_TRANSIT_BYOK_RSA_OAEP_SHA256_AES256_GCM96"
)

// ImportParameters contains the parameters needed to import a key into a backend.
// These parameters are typically obtained from GetImportParameters and may have
// a limited validity period (e.g., 24 hours for AWS KMS).
type ImportParameters struct {
	// WrappingPublicKey is the public key used to wrap key material for secure transport.
	// The corresponding private key is held securely by the backend (e.g., in an HSM).
	WrappingPublicKey crypto.PublicKey

	// ImportToken is backend-specific metadata required for the import operation.
	// For AWS KMS, this contains metadata that ensures key material is imported correctly.
	// May be nil for backends that don't require it.
	ImportToken []byte

	// Algorithm is the required wrapping algorithm for this import.
	// The algorithm must be supported by the WrappingPublicKey.
	Algorithm WrappingAlgorithm

	// ExpiresAt indicates when these import parameters expire.
	// After expiration, new parameters must be obtained via GetImportParameters.
	// May be nil for backends that don't expire import parameters.
	ExpiresAt *time.Time

	// KeySpec describes the type of key that can be imported with these parameters.
	// For example, "RSA_2048", "AES_256", etc.
	KeySpec string
}

// WrappedKeyMaterial represents key material that has been wrapped for secure transport.
// The wrapped material can be safely transmitted over untrusted channels and imported
// into a backend that holds the corresponding unwrapping key.
type WrappedKeyMaterial struct {
	// WrappedKey is the encrypted key material.
	// For hybrid algorithms, this contains both the wrapped AES key and the
	// AES-encrypted target key concatenated together.
	WrappedKey []byte

	// Algorithm is the wrapping algorithm that was used.
	// This must match the algorithm specified in ImportParameters.
	Algorithm WrappingAlgorithm

	// ImportToken is the token from the corresponding ImportParameters.
	// Required by some backends (e.g., AWS KMS) to associate the wrapped
	// key with the correct import operation.
	ImportToken []byte

	// Metadata contains additional backend-specific information about the wrapped key.
	// This may include key type, size, usage flags, etc.
	Metadata map[string]string
}

// ImportBackend extends Backend with the key-import half of the ceremony:
// obtaining wrapping parameters, wrapping and unwrapping key material for
// transport, and importing it. It is split out from ExportBackend because
// import and export are genuinely independent capabilities on real hardware
// and cloud services -- AWS KMS is the canonical example: it supports
// importing externally generated key material into an HSM-backed key, but
// the HSM boundary that makes the import meaningful also makes exporting the
// material back out impossible by design, not by omission. A caller that
// only needs the import half must be able to reach it without a backend's
// inability to export blocking the whole ceremony (see ImportExportBackend's
// interface-satisfaction rule below).
type ImportBackend interface {
	types.KeyProvider

	// GetImportParameters retrieves the parameters needed to import a key.
	// This typically includes a wrapping public key generated by the backend's HSM,
	// and may include an import token for associating the import with these parameters.
	//
	// The returned parameters may have a limited validity period (e.g., 24 hours for AWS).
	// After expiration, new parameters must be obtained.
	//
	// The algorithm parameter specifies the wrapping algorithm to use. Different algorithms
	// may be required for different key types (e.g., hybrid algorithms for RSA private keys).
	//
	// Returns an error if the backend doesn't support import or the algorithm is not supported.
	GetImportParameters(ctx context.Context, attrs *types.KeyAttributes, algorithm WrappingAlgorithm) (*ImportParameters, error)

	// WrapKey wraps key material for secure transport using the specified parameters.
	// This operation is typically performed locally (outside the backend) before
	// importing the key material.
	//
	// For RSA-based algorithms, the key material is encrypted directly with the
	// wrapping public key.
	//
	// For hybrid algorithms (RSA + AES-KWP):
	//   1. Generate a random AES-256 key
	//   2. Encrypt the AES key with the RSA public key using OAEP
	//   3. Encrypt the target key material with the AES key using AES-KWP
	//   4. Concatenate the wrapped AES key and wrapped target key
	//
	// Returns WrappedKeyMaterial that can be passed to ImportKey.
	WrapKey(ctx context.Context, keyMaterial []byte, params *ImportParameters) (*WrappedKeyMaterial, error)

	// UnwrapKey unwraps key material that was previously wrapped with WrapKey.
	// This operation is typically performed by the backend's HSM using the
	// private key corresponding to the wrapping public key.
	//
	// For testing and software backends, this operation may be performed locally.
	// For hardware backends (HSM/KMS), the unwrapping happens securely within
	// the hardware and the plaintext key material never leaves the secure boundary.
	//
	// Returns the unwrapped (plaintext) key material.
	// Returns an error if unwrapping fails (e.g., due to incorrect parameters or corruption).
	UnwrapKey(ctx context.Context, wrapped *WrappedKeyMaterial, params *ImportParameters) ([]byte, error)

	// ImportKey imports externally generated key material into the backend.
	// The key material must be wrapped using parameters obtained from GetImportParameters.
	//
	// The import process:
	//   1. Validates the import token (if required)
	//   2. Unwraps the key material using the backend's private unwrapping key (in HSM)
	//   3. Stores the key material securely in the backend
	//   4. Associates the key with the provided attributes
	//
	// After successful import, the key can be used like any other key in the backend
	// (e.g., for signing, decryption, etc.).
	//
	// Security note: The unwrapping private key never leaves the HSM, ensuring that
	// even though the key material traverses an untrusted channel, it remains protected.
	//
	// Returns an error if:
	//   - The import token is invalid or expired
	//   - Unwrapping fails (wrong algorithm, corrupted data, etc.)
	//   - A key with the same attributes already exists
	//   - The backend doesn't support import
	ImportKey(ctx context.Context, attrs *types.KeyAttributes, wrapped *WrappedKeyMaterial) error
}

// ExportBackend extends Backend with the key-export half of the ceremony:
// wrapping a key for transport out, and reading raw material for keys that
// are marked extractable. See ImportBackend's doc comment for why this is a
// separate interface rather than folded into one that only a subset of
// backends could satisfy in full.
type ExportBackend interface {
	types.KeyProvider

	// ExportKey exports a key in wrapped form for secure transport.
	// This allows migrating keys from one backend to another while maintaining security.
	//
	// The export process wraps the key material using the specified algorithm.
	// The recipient must have the corresponding unwrapping key to recover the key material.
	//
	// Important security considerations:
	//   - Not all backends support key export (e.g., AWS KMS)
	//   - Some backends may restrict export to backup/recovery scenarios
	//   - Hardware-backed keys may have policies that prevent export
	//   - Export should only be used when absolutely necessary
	//
	// Returns WrappedKeyMaterial that can be unwrapped by the recipient.
	// Returns ErrNotSupported if the backend doesn't support key export.
	// Returns ErrOperationNotPermitted if the key's policy prevents export.
	ExportKey(ctx context.Context, attrs *types.KeyAttributes, algorithm WrappingAlgorithm) (*WrappedKeyMaterial, error)

	// ExportKeyTo exports a key wrapped for dstParams -- the DESTINATION
	// backend's own import parameters, obtained by calling that backend's
	// GetImportParameters -- rather than a wrapping key this backend mints
	// and tracks for itself the way ExportKey does.
	//
	// This is the one export path that produces material a DIFFERENT backend
	// instance can actually unwrap. ExportKey's ImportToken names a wrapping
	// key that exists only in the exporting backend's own state (an
	// in-memory map, an HSM object, a cloud import job); handing that token
	// to a second backend's ImportKey names nothing it has ever heard of.
	// ExportKeyTo closes that gap by wrapping under the caller-supplied
	// destination parameters directly, so the caller is responsible for
	// having obtained dstParams from the actual destination first (see
	// CopyKey for the canonical caller).
	//
	// Not every backend can honour an externally supplied wrapping key:
	// PKCS#11's C_WrapKey, TPM2 duplication, and every cloud KMS's BYOK
	// ceremony wrap under a key object the backend itself manages, not an
	// arbitrary public key handed to it. Those backends return
	// ErrExportToUnsupported rather than emulate a wrap their hardware or
	// service does not actually perform.
	//
	// Returns ErrExportNotSupported if the backend doesn't support key
	// export at all. Returns ErrKeyNotExportable if the key's policy
	// prevents export. Returns ErrExportToUnsupported if the backend can
	// export but cannot wrap for a foreign destination's parameters.
	ExportKeyTo(ctx context.Context, attrs *types.KeyAttributes, dstParams *ImportParameters) (*WrappedKeyMaterial, error)

	// ExportKeyMaterial returns the raw key material for extractable symmetric keys only.
	// This method provides direct access to the plaintext key bytes without wrapping.
	//
	// Security restrictions:
	//   - ONLY works for symmetric keys (AES, ChaCha20, etc.)
	//   - Returns ErrAsymmetricKeyExportNotAllowed for asymmetric keys (RSA, ECDSA, Ed25519)
	//   - Key must have Exportable=true (equivalent to PKCS#11 CKA_EXTRACTABLE=true)
	//   - Returns ErrKeyNotExportable if the key is not marked as exportable
	//
	// Use cases:
	//   - Extracting symmetric keys for use in external systems
	//   - Key backup scenarios where raw material is needed
	//   - Testing and development environments
	//
	// For secure key transport between backends, prefer ExportKey which wraps the material.
	ExportKeyMaterial(ctx context.Context, attrs *types.KeyAttributes) ([]byte, error)
}

// ImportExportBackend is the union of ImportBackend and ExportBackend, for a
// backend that supports the full ceremony in both directions -- the software
// backend, PKCS#11 HSMs, and most cloud KMS providers among them. It is
// declared as the embedding of the two halves, not as its own independent
// method list, so every existing type assertion against it
// (`provider.(backend.ImportExportBackend)`) keeps meaning exactly what it
// always did: every caller that only needs one half should assert
// ImportBackend or ExportBackend instead, so a backend missing the other half
// -- AWS KMS is the one that exists today; a future backend may be
// import-only or export-only for its own hardware reasons -- does not block
// the half it does support.
type ImportExportBackend interface {
	ImportBackend
	ExportBackend
}
