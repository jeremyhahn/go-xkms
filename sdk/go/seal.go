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

import "github.com/jeremyhahn/go-xkms/pkg/seal"

// Seal sealing-strategy surface, re-exported so consumers (e.g. go-quicbaas)
// implement seal services against the go-xkms SDK rather than importing
// go-xkms/pkg/seal directly. go-xkms OWNS the hardware/cloud strategies
// (TPM2/PKCS11/cloud KMS); the strategy-ID type and the none/passphrase/shamir
// IDs are aliased up from the go-qrdb / go-quicraft layers.

// --- Hardware/cloud sealing-strategy implementations (owned by go-xkms) ---

// TPM2Strategy seals the root key with a TPM 2.0 device.
type TPM2Strategy = seal.TPM2Strategy

// PKCS11Strategy seals the root key with a PKCS#11 HSM token.
type PKCS11Strategy = seal.PKCS11Strategy

// CloudKMSStrategy seals the root key with a cloud KMS (AWS/GCP/Azure/Vault).
type CloudKMSStrategy = seal.CloudKMSStrategy

// NewTPM2Strategy constructs a TPM 2.0 sealing strategy.
var NewTPM2Strategy = seal.NewTPM2Strategy

// NewPKCS11Strategy constructs a PKCS#11 HSM sealing strategy.
var NewPKCS11Strategy = seal.NewPKCS11Strategy

// NewCloudKMSStrategy constructs a cloud-KMS sealing strategy for the given
// strategy ID (StrategyAWSKMS / StrategyGCPKMS / StrategyAzureKV / StrategyVault).
var NewCloudKMSStrategy = seal.NewCloudKMSStrategy

// BuildCloudKMSStrategy is the ONE cloud-KMS strategy composition path xkmsd
// (pkg/server/seal_strategies.go) and xkey both call: given an
// already-constructed, already-configured cloud KMS backend (implementing
// types.KeyProvider), it provisions the named symmetric wrapping key
// (creating it on first init, reusing it thereafter) and returns the
// matching CloudKMSStrategy. id must be one of StrategyAWSKMS / StrategyGCPKMS
// / StrategyAzureKV / StrategyVault; store is the matching StoreType
// (StoreAWSKMS, etc). Sharing this path is what lets a barrier initialized
// by xkmsd unseal under xkey and vice versa (go-xkms#757).
var BuildCloudKMSStrategy = seal.BuildCloudKMSStrategy

// IsCloudSealStrategy reports whether id is one of the cloud KMS strategies
// BuildCloudKMSStrategy composes.
var IsCloudSealStrategy = seal.IsCloudSealStrategy

// SealKeyAttributes builds the KeyAttributes identifying the symmetric
// wrapping key a hardware/cloud seal strategy seals the barrier root key
// under, for the given StoreType.
var SealKeyAttributes = seal.SealKeyAttributes

// SealKeyCN is the canonical common name of that symmetric wrapping key.
const SealKeyCN = seal.SealKeyCN

// EnsurePrivateSealKey guarantees the private key identified by keyAttrs
// exists on provider, generating it on first use and reusing it thereafter.
// It is the asymmetric counterpart to EnsureSealKey (below), for backends
// (software, PKCS#8) whose Sealer derives its wrapping key from an existing
// private key rather than a dedicated symmetric primitive.
var EnsurePrivateSealKey = seal.EnsurePrivateSealKey

// EnsureSealKey guarantees the symmetric wrapping key identified by keyAttrs
// is resolvable by provider, creating it on first use (PKCS#11 login, AWS
// KMS operator-key metadata seeding, then idempotent
// GetSymmetricKey/GenerateSymmetricKey check-and-skip) and reusing it
// thereafter.
var EnsureSealKey = seal.EnsureSealKey

// ErrSealBackendUnavailable indicates a hardware/cloud backend does not
// implement the interface (Sealer / SymmetricKeyProvider) a seal strategy
// requires.
type ErrSealBackendUnavailable = seal.ErrSealBackendUnavailable

// ErrNotCloudSealStrategy indicates BuildCloudKMSStrategy was called with a
// strategy ID that is not a cloud KMS strategy.
type ErrNotCloudSealStrategy = seal.ErrNotCloudSealStrategy

// --- Hardware/cloud strategy IDs (owned by go-xkms) ---

const (
	// StrategyTPM2 uses TPM 2.0 hardware for root key protection.
	StrategyTPM2 = seal.StrategyTPM2

	// StrategyPKCS11 uses a PKCS#11 HSM token for root key protection.
	StrategyPKCS11 = seal.StrategyPKCS11

	// StrategyAWSKMS uses AWS Key Management Service for root key protection.
	StrategyAWSKMS = seal.StrategyAWSKMS

	// StrategyGCPKMS uses Google Cloud KMS for root key protection.
	StrategyGCPKMS = seal.StrategyGCPKMS

	// StrategyAzureKV uses Azure Key Vault for root key protection.
	StrategyAzureKV = seal.StrategyAzureKV

	// StrategyVault uses HashiCorp Vault for root key protection.
	StrategyVault = seal.StrategyVault

	// StrategyShamir splits the root key into M-of-N Shamir shares (impl: go-qrdb).
	StrategyShamir = seal.StrategyShamir

	// StrategyPassphrase is the passphrase-protected software strategy (impl: go-quicraft).
	StrategyPassphrase = seal.StrategyPassphrase
)

// --- Barrier lifecycle (storage barrier owned by go-qrdb, surfaced here) ---

// StrategyID identifies a sealing strategy.
type StrategyID = seal.StrategyID

// SealingStrategy is the interface implemented by every sealing strategy.
type SealingStrategy = seal.SealingStrategy

// Barrier is the storage barrier that encrypts all sensitive data at rest.
type Barrier = seal.Barrier

// BarrierBackend adapts a Barrier to the storage.Backend interface. The
// underlying qrdb StorageBarrier natively implements every Backend method
// including PutIfAbsent; this type is pure embedding retained for API
// stability.
type BarrierBackend = seal.BarrierBackend

// BarrierConfig configures a storage barrier.
type BarrierConfig = seal.BarrierConfig

// BarrierStatus reports a barrier's seal/initialization state.
type BarrierStatus = seal.BarrierStatus

// SealCredentials are the credentials used to unseal a barrier.
type SealCredentials = seal.Credentials

// NewCredentials moves a secret into protected memory, WIPING the source slice
// on return. Use it only where the caller owns the buffer and will not read it
// again; an empty secret is refused. A caller that reads its buffer after the
// call — to set a token PIN, to hash a verifier, to retry — must use
// CredentialsFor instead, or it will read the zeroed slice.
var NewCredentials = seal.NewCredentials

// CredentialsFor copies a borrowed secret into protected memory and leaves the
// caller's slice untouched. Use it for material the caller still owns: request
// fields, config values, a password typed into a UI. An empty secret yields the
// zero SealCredentials ("no credentials supplied") rather than an error.
var CredentialsFor = seal.CredentialsFor

// DestroyCredentials destroys a credential's protected secret; it is nil-safe,
// so it also takes the zero SealCredentials CredentialsFor yields for an empty
// secret.
var DestroyCredentials = seal.DestroyCredentials

// MustCredentials is NewCredentials for fixtures; it panics where
// NewCredentials would return an error.
var MustCredentials = seal.MustCredentials

// SealedRootKey is a root key sealed by a strategy.
type SealedRootKey = seal.SealedRootKey

// NewBarrier constructs a storage barrier.
var NewBarrier = seal.NewBarrier

// NewBarrierBackend wraps a Barrier as a storage.Backend that supports
// PutIfAbsent.
var NewBarrierBackend = seal.NewBarrierBackend

// NewSoftwareSealStrategy constructs the passphrase-protected software strategy.
var NewSoftwareSealStrategy = seal.NewSoftwareStrategy

// ErrNoAvailableSealStrategy is returned when no sealing strategy can be selected.
var ErrNoAvailableSealStrategy = seal.ErrNoAvailableStrategy

// --- Canonical hardware-seal autodetect (owned by go-xkms) ---

// SealAutodetectOptions configures the single bounded, non-provisioning TPM
// probe used to select the best available hardware seal strategy.
type SealAutodetectOptions = seal.AutodetectOptions

// TPM2ProbeConfig is the subset of TPM2 backend config the autodetect probe
// needs; callers map their own config onto it.
type TPM2ProbeConfig = seal.TPM2ProbeConfig

// SealAutodetectResult holds the selected hardware strategy (if any) plus the
// underlying open sealer for reuse in sealed key stores. Close it on shutdown.
type SealAutodetectResult = seal.AutodetectResult

// BuildBestSealStrategy runs the canonical TPM probe and returns the best
// available hardware seal strategy (nil Strategy when none — caller falls back
// to software). This is the ONE stack-wide autodetect; consumers (go-quicbaas,
// xkey, cluster CA key protection) call this instead of re-implementing it.
var BuildBestSealStrategy = seal.BuildBestStrategy

// ProbeSealStrategies lists the currently available seal strategy IDs (for a
// UI such as the xkey setup wizard) sharing the one probe with
// BuildBestSealStrategy.
var ProbeSealStrategies = seal.ProbeStrategies

// DefaultSealProbeTimeout bounds the single autodetect TPM open.
const DefaultSealProbeTimeout = seal.DefaultProbeTimeout
