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

package backend

import "errors"

var (
	// ErrFileAlreadyExists is returned when attempting to save a file that already exists
	// without the overwrite flag set to true.
	ErrFileAlreadyExists = errors.New("backend: file already exists")

	// ErrFileNotFound is returned when attempting to retrieve a file that does not exist.
	ErrFileNotFound = errors.New("backend: file not found")

	// ErrKeyNotFound is returned when attempting to retrieve a key that does not exist.
	ErrKeyNotFound = errors.New("backend: key not found")

	// ErrKeyAlreadyExists is returned when attempting to generate a key that already exists.
	ErrKeyAlreadyExists = errors.New("backend: key already exists")

	// ErrInvalidKeyType is returned when an invalid or unsupported key type is provided.
	ErrInvalidKeyType = errors.New("backend: invalid key type")

	// ErrInvalidKeyPartition is returned when an invalid partition is requested.
	ErrInvalidKeyPartition = errors.New("backend: invalid key partition")

	// ErrInvalidExtension is returned when an invalid file extension is provided.
	ErrInvalidExtension = errors.New("backend: invalid extension")

	// ErrInvalidAttributes is returned when key attributes are invalid or incomplete.
	ErrInvalidAttributes = errors.New("backend: invalid key attributes")

	// ErrNotSupported is returned when an operation is not supported by the backend.
	// Commonly used by hardware-backed keys that cannot expose raw key material.
	ErrNotSupported = errors.New("backend: operation not supported")

	// ErrInvalidAlgorithm is returned when an invalid or unsupported algorithm is specified.
	ErrInvalidAlgorithm = errors.New("backend: invalid algorithm")

	// ErrNonceReused is returned when attempting to encrypt with a nonce that has been used before.
	// Nonce reuse in AEAD encryption (AES-GCM, ChaCha20-Poly1305) is a catastrophic security failure
	// that allows attackers to recover the authentication key and forge messages.
	// When this error occurs, the key should be rotated immediately.
	ErrNonceReused = errors.New("backend: nonce reused - key rotation required")

	// ErrBytesLimitExceeded is returned when the bytes encrypted with a key exceeds safety limits.
	// For AES-GCM with 96-bit nonces, NIST recommends a limit of 2^32 blocks (~350 GB).
	// When this error occurs, the key should be rotated to maintain cryptographic security.
	ErrBytesLimitExceeded = errors.New("backend: bytes encrypted limit exceeded - key rotation required")

	// ErrInvalidOptions is returned when AEAD options are invalid or incomplete.
	ErrInvalidOptions = errors.New("backend: invalid AEAD options")

	// ErrExportNotSupported is returned when the backend does not support key export.
	// Some backends (e.g., Azure Key Vault) only support import for security reasons.
	ErrExportNotSupported = errors.New("backend: key export not supported")

	// ErrImportNotSupported is returned when the backend does not support key import.
	ErrImportNotSupported = errors.New("backend: key import not supported")

	// ErrKeyNotExportable is returned when attempting to export a key that is not marked as exportable.
	// Hardware-backed keys (TPM with FixedTPM=true, HSM with CKA_EXTRACTABLE=false) cannot be exported.
	ErrKeyNotExportable = errors.New("backend: key is not exportable")

	// ErrOperationNotSupported is returned when a specific operation is not supported by the backend.
	// This is more specific than ErrNotSupported and indicates the operation exists but isn't implemented.
	ErrOperationNotSupported = errors.New("backend: operation not supported by this backend")
)
