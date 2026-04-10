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

// Package seal provides barrier encryption for go-xkms's storage layer.
// Core types (StrategyID, SealingStrategy, SymmetricEncrypter, etc.) are
// defined in go-quicraft/pkg/seal and re-exported here via go-qrdb/sdk/go
// as type aliases, so that go-xkms consumers do not need to import
// go-quicraft or go-qrdb directly.
//
// The Barrier, TenantBarrier, and BarrierRegistry types are thin wrappers
// around go-qrdb/sdk/go to bridge the storage.Backend interface (which
// includes *Options on Put) with go-qrdb's StorageBackend (2-arg Put).
package seal

import (
	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
)

// --- Re-exported types from go-qrdb/sdk/go (which re-exports go-quicraft) ---

// StrategyID uniquely identifies a sealing strategy.
type StrategyID = qrdbsdk.StrategyID

// SealingStrategy defines the interface for root key seal/unseal operations.
type SealingStrategy = qrdbsdk.SealingStrategy

// SymmetricEncrypter provides symmetric encryption/decryption operations.
type SymmetricEncrypter = qrdbsdk.SymmetricEncrypter

// Credentials holds authentication material for seal/unseal operations.
type Credentials = qrdbsdk.Credentials

// SealedRootKey is the persisted form of an encrypted root key.
type SealedRootKey = qrdbsdk.SealedRootKey

// ShamirConfig configures Shamir secret sharing for barrier operations.
type ShamirConfig = qrdbsdk.ShamirConfig

// ShamirInitResult contains the output of Shamir initialization.
type ShamirInitResult = qrdbsdk.ShamirInitResult

// QuorumProgress reports the current state of a quorum accumulator.
type QuorumProgress = qrdbsdk.QuorumProgress

// BarrierStatus reports the current state of a Barrier.
type BarrierStatus = qrdbsdk.BarrierStatus

// RecoveryKeyResult contains disaster recovery key output.
type RecoveryKeyResult = qrdbsdk.RecoveryKeyResult

// RootToken is a one-time administrative token derived from the master key.
type RootToken = qrdbsdk.RootToken

// MemoryBackend is an in-memory StorageBackend implementation.
type MemoryBackend = qrdbsdk.MemoryBackend

// NamespacedBackend wraps a StorageBackend with a key prefix for isolation.
type NamespacedBackend = qrdbsdk.NamespacedBackend

// ShamirStrategy provides M-of-N threshold secret sharing for root key
// protection.
type ShamirStrategy = qrdbsdk.ShamirStrategy

// --- Re-exported constructors ---

// NewMemoryBackend creates a new in-memory storage backend.
var NewMemoryBackend = qrdbsdk.NewMemoryBackend

// NewNamespacedBackend creates a storage backend with a key prefix.
var NewNamespacedBackend = qrdbsdk.NewNamespacedBackend

// --- Re-exported constants ---

const (
	// StrategyTPM2 uses TPM 2.0 hardware for root key protection.
	StrategyTPM2 = qrdbsdk.StrategyTPM2

	// StrategyPKCS11 uses PKCS#11 HSM tokens for root key protection.
	StrategyPKCS11 = qrdbsdk.StrategyPKCS11

	// StrategyAWSKMS uses AWS Key Management Service for root key protection.
	StrategyAWSKMS = qrdbsdk.StrategyAWSKMS

	// StrategyGCPKMS uses Google Cloud KMS for root key protection.
	StrategyGCPKMS = qrdbsdk.StrategyGCPKMS

	// StrategyAzureKV uses Azure Key Vault for root key protection.
	StrategyAzureKV = qrdbsdk.StrategyAzureKV

	// StrategyVault uses HashiCorp Vault for root key protection.
	StrategyVault = qrdbsdk.StrategyVault

	// StrategyShamir splits the root key itself into M-of-N Shamir shares.
	StrategyShamir = qrdbsdk.StrategyShamir

	// StrategySoftware uses password-based encryption (Argon2id + AES-256-GCM).
	StrategySoftware = qrdbsdk.StrategySoftware

	// DefaultQuorumTTL is the default time-to-live for a quorum accumulator
	// session, re-exported from go-quicraft via go-qrdb.
	DefaultQuorumTTL = qrdbsdk.DefaultQuorumTTL
)

// sealedRootKeyVersion is the format version for SealedRootKey blobs.
const sealedRootKeyVersion = 1

// DefaultPreferenceOrder defines the default strategy selection order.
// Hardware-backed strategies are preferred over software-only fallback.
var DefaultPreferenceOrder = []StrategyID{
	StrategyTPM2,
	StrategyPKCS11,
	StrategyAWSKMS,
	StrategyGCPKMS,
	StrategyAzureKV,
	StrategyVault,
	StrategyShamir,
	StrategySoftware,
}
