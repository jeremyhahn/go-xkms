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

import "errors"

var (
	// ErrNotInitialized indicates the TPM2 backend has not been initialized
	ErrNotInitialized = errors.New("tpm2: backend not initialized")

	// ErrAlreadyInitialized indicates the TPM2 backend is already initialized
	ErrAlreadyInitialized = errors.New("tpm2: backend already initialized")

	// ErrInvalidConfig indicates the configuration is invalid
	ErrInvalidConfig = errors.New("tpm2: invalid configuration")

	// ErrKeyNotFound indicates the requested key was not found
	ErrKeyNotFound = errors.New("tpm2: key not found")

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

	// ErrAuthChangeFailed indicates that changing the auth value failed
	ErrAuthChangeFailed = errors.New("tpm2: auth change failed")

	// ErrLockoutQueryFailed indicates that querying the DA lockout status failed
	ErrLockoutQueryFailed = errors.New("tpm2: lockout status query failed")

	// ErrLockoutResetFailed indicates that resetting the DA lockout counter failed
	ErrLockoutResetFailed = errors.New("tpm2: lockout reset failed")

	// ErrNilSealedData indicates that nil sealed data was provided to Unseal
	ErrNilSealedData = errors.New("tpm2: sealed data is required")
)
