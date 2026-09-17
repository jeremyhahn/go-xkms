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

package seal

import (
	"errors"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// --- xkms-local seal errors ---

var (
	// ErrNoSealingKey is returned when a cloud KMS sealing strategy is asked
	// to seal or unseal a root key but was constructed without the
	// KeyAttributes that identify the cloud-managed sealing key. Every cloud
	// KMS backend (AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault)
	// requires this identity; without it the backend rejects the request.
	ErrNoSealingKey = errors.New("seal: no sealing key configured for cloud KMS strategy")

	// ErrNoStrategySpecified is returned when a sealer/barrier is constructed
	// without an explicit strategy selection. There is no implicit default
	// preference order — the caller must specify which strategy to use.
	ErrNoStrategySpecified = errors.New("seal: no sealing strategy specified (explicit selection required)")
)

// --- Re-exported errors from go-qrdb/sdk/go seal ---

var (
	// ErrSealed is returned when an operation is attempted on a sealed barrier.
	ErrSealed = qrdbsdk.ErrSealed

	// ErrAlreadyUnsealed is returned when attempting to unseal a barrier that
	// is already in the unsealed state.
	ErrAlreadyUnsealed = qrdbsdk.ErrAlreadyUnsealed

	// ErrAlreadyInitialized is returned when Initialize is called on a barrier
	// that has already been initialized with a root key.
	ErrAlreadyInitialized = qrdbsdk.ErrAlreadyInitialized

	// ErrNotInitialized is returned when Unseal is called on a barrier that
	// has not been initialized. Call Initialize first.
	ErrNotInitialized = qrdbsdk.ErrNotInitialized

	// ErrInvalidCredentials is returned when the provided credentials fail to
	// unseal the root key. Raised by the HARDWARE strategies (TPM2, PKCS#11,
	// cloud KMS) via hardware_encryptor.go; a software passphrase strategy
	// reports ErrDecryptionFailed instead.
	ErrInvalidCredentials = qrdbsdk.ErrInvalidCredentials

	// ErrDecryptionFailed is returned when a wrong passphrase fails to unseal
	// the root key under the software strategy. It arrives wrapped in
	// go-quicraft's *UnsealError, so test it with errors.Is, never ==.
	//
	// Callers mapping "wrong credential" to a status code must handle BOTH
	// this and ErrInvalidCredentials: which one surfaces depends on whether
	// the barrier is software- or hardware-backed, not on what went wrong.
	ErrDecryptionFailed = qrdbsdk.ErrDecryptionFailed

	// ErrNoAvailableStrategy is returned when no registered sealing strategy
	// reports itself as available.
	ErrNoAvailableStrategy = qrdbsdk.ErrNoAvailableStrategy

	// ErrStrategyNotFound is returned when a requested strategy ID is not
	// registered with the barrier or platform sealer.
	ErrStrategyNotFound = qrdbsdk.ErrStrategyNotFound

	// ErrStrategyMismatch is returned when attempting to unseal data with a
	// different strategy than the one that sealed it.
	ErrStrategyMismatch = qrdbsdk.ErrStrategyMismatch

	// ErrCorruptRootKey is returned when the root key blob stored in the
	// backend fails to deserialize or has an unexpected format.
	ErrCorruptRootKey = qrdbsdk.ErrCorruptRootKey

	// ErrNilSealedData is returned when a nil SealedData pointer is passed
	// to an unseal operation.
	ErrNilSealedData = qrdbsdk.ErrNilSealedData

	// ErrEncryptorNotAvailable is returned when the barrier's encryptor
	// is not available (barrier not unsealed or encryptor not initialized).
	ErrEncryptorNotAvailable = qrdbsdk.ErrEncryptorNotAvailable

	// ErrHardwareEncryptorRequired is returned when GetMasterKey is called
	// on a hardware-backed strategy that keeps keys in hardware.
	ErrHardwareEncryptorRequired = qrdbsdk.ErrHardwareEncryptorRequired

	// ErrShamirNotConfigured is returned when a Shamir operation is attempted
	// on a barrier that does not have Shamir secret sharing configured.
	ErrShamirNotConfigured = qrdbsdk.ErrShamirNotConfigured

	// ErrShamirThresholdInvalid is returned when the Shamir threshold is less
	// than 2 or greater than the total number of shares.
	ErrShamirThresholdInvalid = qrdbsdk.ErrShamirThresholdInvalid

	// ErrShamirDuplicateShare is returned when a share that has already been
	// submitted is submitted again to the quorum accumulator.
	ErrShamirDuplicateShare = qrdbsdk.ErrShamirDuplicateShare

	// ErrShamirQuorumExpired is returned when the quorum TTL has elapsed and
	// all accumulated shares have been discarded.
	ErrShamirQuorumExpired = qrdbsdk.ErrShamirQuorumExpired

	// ErrShamirQuorumIncomplete is returned when not enough shares have been
	// provided to meet the reconstruction threshold.
	ErrShamirQuorumIncomplete = qrdbsdk.ErrShamirQuorumIncomplete

	// ErrShamirNoQuorum is returned when no active quorum accumulator exists.
	ErrShamirNoQuorum = qrdbsdk.ErrShamirNoQuorum

	// ErrShamirCombineFailed is returned when the Shamir combine operation
	// fails to reconstruct the secret from the provided shares.
	ErrShamirCombineFailed = qrdbsdk.ErrShamirCombineFailed

	// ErrShamirShareNotFound is returned when a requested Shamir share does
	// not exist in storage.
	ErrShamirShareNotFound = qrdbsdk.ErrShamirShareNotFound

	// ErrShamirVerificationFailed is returned when share verification detects
	// inconsistent or corrupted shares.
	ErrShamirVerificationFailed = qrdbsdk.ErrShamirVerificationFailed

	// ErrShamirNoSharesFound is returned when no shares exist in storage.
	ErrShamirNoSharesFound = qrdbsdk.ErrShamirNoSharesFound

	// ErrShamirStorageFailed is returned when a share storage operation fails.
	ErrShamirStorageFailed = qrdbsdk.ErrShamirStorageFailed

	// ErrShamirNilStorage is returned when a nil storage backend is provided
	// to the Shamir strategy constructor.
	ErrShamirNilStorage = qrdbsdk.ErrShamirNilStorage

	// ErrShamirSplitFailed is returned when the Shamir secret splitting
	// operation fails.
	ErrShamirSplitFailed = qrdbsdk.ErrShamirSplitFailed

	// ErrShamirSerializationFailed is returned when JSON serialization or
	// deserialization of a Shamir share fails.
	ErrShamirSerializationFailed = qrdbsdk.ErrShamirSerializationFailed

	// ErrNilSealedBackend is returned when a nil sealed backend is provided.
	ErrNilSealedBackend = qrdbsdk.ErrNilSealedBackend

	// ErrSecretNotFound is returned when a named secret is not found.
	ErrSecretNotFound = qrdbsdk.ErrSecretNotFound

	// ErrInvalidSecretName is returned when a secret name is empty.
	ErrInvalidSecretName = qrdbsdk.ErrInvalidSecretName

	// ErrResealFailed is returned when re-sealing a secret fails.
	ErrResealFailed = qrdbsdk.ErrResealFailed

	// ErrRecoveryKeysNotFound is returned when recovery key metadata does
	// not exist in storage.
	ErrRecoveryKeysNotFound = qrdbsdk.ErrRecoveryKeysNotFound

	// ErrRootTokenVerificationFailed is returned when the reconstructed
	// secret from Shamir shares does not produce a valid DEK that can
	// decrypt the barrier's stored data.
	ErrRootTokenVerificationFailed = qrdbsdk.ErrRootTokenVerificationFailed

	// ErrTenantNotFound is returned when a requested tenant ID is not
	// registered in the barrier registry.
	ErrTenantNotFound = qrdbsdk.ErrTenantNotFound

	// ErrTenantAlreadyExists is returned when attempting to register a
	// tenant that is already registered in the barrier registry.
	ErrTenantAlreadyExists = qrdbsdk.ErrTenantAlreadyExists

	// ErrEmptyTenantID is returned when an empty tenant ID is provided
	// to a tenant barrier operation.
	ErrEmptyTenantID = qrdbsdk.ErrEmptyTenantID

	// ErrNilSystemBarrier is returned when a nil system barrier is provided
	// to the barrier registry or tenant barrier constructor.
	ErrNilSystemBarrier = qrdbsdk.ErrNilSystemBarrier

	// ErrTenantSealed is returned when an operation is attempted on a
	// sealed tenant barrier.
	ErrTenantSealed = qrdbsdk.ErrTenantSealed

	// ErrTenantAlreadyInitialized is returned when Initialize is called
	// on a tenant barrier that already has a root key.
	ErrTenantAlreadyInitialized = qrdbsdk.ErrTenantAlreadyInitialized

	// ErrTenantNotInitialized is returned when Unseal is called on a
	// tenant barrier that has not been initialized.
	ErrTenantNotInitialized = qrdbsdk.ErrTenantNotInitialized

	// ErrTenantAlreadyUnsealed is returned when Unseal is called on a
	// tenant barrier that is already unsealed.
	ErrTenantAlreadyUnsealed = qrdbsdk.ErrTenantAlreadyUnsealed

	// ErrNoStrategy is returned when a tenant is registered without a
	// sealing strategy.
	ErrNoStrategy = qrdbsdk.ErrNoStrategy

	// ErrNilStorageBackend is returned when a nil storage backend is
	// provided to the tenant barrier constructor.
	ErrNilStorageBackend = qrdbsdk.ErrNilStorageBackend
)
