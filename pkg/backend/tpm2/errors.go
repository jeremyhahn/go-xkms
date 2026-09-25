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

package tpm2

import (
	"errors"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
)

var (
	// ErrNotInitialized indicates the TPM2 backend has not been initialized
	ErrNotInitialized = errors.New("tpm2: backend not initialized")

	// ErrAlreadyInitialized indicates the TPM2 backend is already initialized
	ErrAlreadyInitialized = errors.New("tpm2: backend already initialized")

	// ErrInvalidConfig indicates the configuration is invalid
	ErrInvalidConfig = errors.New("tpm2: invalid configuration")

	// ErrKeyNotFound indicates the requested key was not found. It is an
	// alias of backend.ErrKeyNotFound (rather than a distinct sentinel) so
	// errors.Is(err, backend.ErrKeyNotFound) recognizes it without any
	// wrapping, keeping this backend's not-found signal identical to every
	// other backend's.
	ErrKeyNotFound = backend.ErrKeyNotFound

	// ErrKeyRetrievalFailed indicates GetKey could not determine whether the
	// requested key exists because the underlying key store (file, TPM
	// context, etc.) returned an error other than "not found" -- a
	// transient I/O failure, permission error, or corrupt blob. Callers
	// must not treat this as ErrKeyNotFound: doing so risks silently
	// generating a replacement for a key the backend merely failed to read.
	ErrKeyRetrievalFailed = errors.New("tpm2: key retrieval failed")

	// ErrUnsupportedKeyAlgorithm indicates the key algorithm is not supported
	ErrUnsupportedKeyAlgorithm = errors.New("tpm2: unsupported key algorithm")

	// ErrUnsupportedOperation indicates the operation is not supported
	ErrUnsupportedOperation = errors.New("tpm2: operation not supported")

	// ErrKeyRotationNotSupported indicates key rotation is not supported for TPM2 keys
	ErrKeyRotationNotSupported = errors.New("tpm2: key rotation not supported for hardware-backed keys")

	// ErrDecryptionNotSupported indicates decryption is not supported for this key type
	ErrDecryptionNotSupported = errors.New("tpm2: decryption not supported for this key type")

	// ErrInvalidKeyAttributes indicates the key attributes are invalid
	ErrInvalidKeyAttributes = errors.New("tpm2: invalid key attributes")

	// ErrInvalidKDFParams indicates the key derivation parameters supplied
	// for an ECDH derivation are missing or unusable
	ErrInvalidKDFParams = errors.New("tpm2: invalid KDF parameters")

	// ErrTPMNotAvailable indicates the TPM device is not available
	ErrTPMNotAvailable = errors.New("tpm2: TPM device not available")

	// ErrSessionCreationFailed indicates a TPM session could not be created
	ErrSessionCreationFailed = errors.New("tpm2: failed to create session")

	// ErrAttestationFailed indicates that TPM2_Certify or attestation processing failed
	ErrAttestationFailed = errors.New("tpm2: attestation failed")

	// ErrIAKNotProvisioned indicates the IAK is not provisioned on the TPM
	ErrIAKNotProvisioned = errors.New("tpm2: IAK not provisioned")

	// ErrAuthVerifyFailed indicates that auth verification failed on the SRK
	ErrAuthVerifyFailed = errors.New("tpm2: auth verification failed")

	// ErrAuthProbeFailed indicates that the SRK auth probe failed for a reason
	// OTHER than a wrong PIN (e.g. a malformed probe surfacing as
	// TPM_RC_ATTRIBUTES, a missing handle, or a transport fault). It must not be
	// treated as an invalid-PIN signal.
	ErrAuthProbeFailed = errors.New("tpm2: auth probe failed (not an auth failure)")

	// ErrAuthChangeFailed indicates that changing the auth value failed
	ErrAuthChangeFailed = errors.New("tpm2: auth change failed")

	// ErrLockoutQueryFailed indicates that querying the DA lockout status failed
	ErrLockoutQueryFailed = errors.New("tpm2: lockout status query failed")

	// ErrLockoutResetFailed indicates that resetting the DA lockout counter failed
	ErrLockoutResetFailed = errors.New("tpm2: lockout reset failed")

	// ErrNilSealedData indicates that nil sealed data was provided to Unseal
	ErrNilSealedData = errors.New("tpm2: sealed data is required")

	// ErrKeyDirRequired indicates Config.KeyDir was left unset. There is no
	// cwd-relative default: Config is constructed by callers with no
	// meaningful process working directory (an embedded service, a daemon
	// started from an arbitrary cwd, a unit test), so defaulting KeyDir would
	// scatter key material or leave stray tpm2-keys/ directories behind (see
	// pkg/server's resolveTPM2KeyDir, which derives KeyDir from storage.path
	// for exactly this reason). Callers must supply KeyDir explicitly.
	ErrKeyDirRequired = errors.New("tpm2: key_dir is required")
)
