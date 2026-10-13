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

//go:build frost

package xkms

import (
	"github.com/jeremyhahn/go-xkms/pkg/keyprovider/frost"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// FROST (Flexible Round-Optimized Schnorr Threshold) re-exports.
//
// These aliases expose the build-tagged pkg/keyprovider/frost package through
// the SDK so that SDK consumers (xkmsctl, downstream tooling) can drive FROST
// threshold-signing operations without importing internal packages directly.
//
// Generic frost type names are given a "Frost" prefix to avoid collisions with
// the flat SDK namespace, matching the existing FrostAlgorithm/FrostAttributes
// convention already established in this package.
//
// This file compiles only under the "frost" build tag, mirroring the build
// constraints on the underlying pkg/keyprovider/frost implementation.

// FROST type aliases re-exported from pkg/keyprovider/frost.
type (
	// FrostBackend is the FROST threshold-signing key provider. It manages key
	// generation (via a trusted dealer), nonce/commitment rounds, signature
	// aggregation, and verification.
	FrostBackend = frost.FrostBackend

	// FrostBackendConfig configures a FrostBackend, wiring its DAO factory,
	// secret backend, default ciphersuite, and M-of-N parameters.
	FrostBackendConfig = frost.Config

	// FrostConfig holds the parameters for a single trusted-dealer key
	// generation: threshold, total, algorithm, participants, and participant ID.
	FrostConfig = frost.FrostConfig

	// FrostKeyHandle is the in-memory handle returned for a generated or loaded
	// FROST key, exposing the algorithm, participant ID, and group public key.
	FrostKeyHandle = frost.FrostKeyHandle

	// FrostKeyMetadata describes a stored FROST key (ID, algorithm, threshold,
	// total, participant ID, creation time, and secret backend type).
	FrostKeyMetadata = frost.KeyMetadata

	// FrostKeyPackage contains the FROST key material for a single participant:
	// secret share, group public key, verification shares, and M/N bounds.
	FrostKeyPackage = frost.KeyPackage

	// FrostSecretKeyShare holds a participant's secret scalar bytes.
	FrostSecretKeyShare = frost.SecretKeyShare

	// FrostCommitment pairs a participant ID with their signing commitments for
	// a round of threshold signing.
	FrostCommitment = frost.Commitment

	// FrostNoncePackage holds a participant's per-session nonces and commitments
	// used to produce a signature share.
	FrostNoncePackage = frost.NoncePackage

	// FrostSignatureShare is a participant's contribution toward the final
	// aggregated signature.
	FrostSignatureShare = frost.SignatureShare

	// FrostSigningCommitments are the public commitments a participant publishes
	// in round one of FROST signing.
	FrostSigningCommitments = frost.SigningCommitments

	// FrostSigningNonces are the secret nonces a participant retains between
	// round one and round two of FROST signing.
	FrostSigningNonces = frost.SigningNonces
)

// FROST constructors re-exported from pkg/keyprovider/frost.
var (
	// NewFrostBackend creates a FrostBackend from the given configuration.
	NewFrostBackend = frost.NewBackend

	// NewFrostKeyStore creates a FROST KeyStore over the given DAO factory
	// and secret key provider.
	NewFrostKeyStore = frost.NewKeyStore

	// NewFrostTrustedDealer creates a trusted-dealer key generator used to
	// produce all participant key packages for a FROST group.
	NewFrostTrustedDealer = frost.NewTrustedDealer

	// ErrFrostThresholdSigningNotSupported reports that a crypto.Signer was
	// requested for a threshold-2+ key, which needs the round-based
	// distributed signing API instead.
	ErrFrostThresholdSigningNotSupported = frost.ErrThresholdSigningNotSupported

	// FrostSymmetricSecretSealKeyAttributes builds the KeyAttributes for the
	// AES-256-GCM wrapping key a types.SymmetricKeyProvider secret backend
	// (PKCS#11, cloud KMS) seals/unseals every FROST secret share with.
	// Provision it with EnsureSealKey before use.
	FrostSymmetricSecretSealKeyAttributes = frost.SymmetricSecretSealKeyAttributes

	// FrostAsymmetricSecretSealKeyAttributes builds the KeyAttributes for
	// the Ed25519 private key the software and PKCS#8 secret backends'
	// Sealer derives an AES-256-GCM wrapping key from (HKDF). Provision it
	// with EnsurePrivateSealKey before use.
	FrostAsymmetricSecretSealKeyAttributes = frost.AsymmetricSecretSealKeyAttributes

	// FrostTPM2SecretSealKeyAttributes builds the wrapping-key template for
	// a TPM2 secret backend (Parent = the Platform SRK attributes, no CN --
	// FrostBackend fills one in per FROST key). TPM2 needs no provisioning
	// step.
	FrostTPM2SecretSealKeyAttributes = frost.TPM2SecretSealKeyAttributes
)

// FrostSecretSealKeyCN is the fixed common name of the wrapping key a FROST
// secret backend that seals via a reusable key provisions to seal/unseal
// every participant's secret share. Distinct from SealKeyCN, the barrier's
// own wrapping key, so a backend serving both roles never shares one key
// between them.
const FrostSecretSealKeyCN = frost.SecretSealKeyCN

// FROST ciphersuite constants re-exported from pkg/types. These are surfaced
// here (rather than the always-compiled types.go) because they are only needed
// by frost-tagged consumers.
const (
	// FrostAlgorithmEd25519 is the default, recommended FROST ciphersuite.
	FrostAlgorithmEd25519 = types.FrostAlgorithmEd25519

	// FrostAlgorithmRistretto255 is the ristretto255 FROST ciphersuite.
	FrostAlgorithmRistretto255 = types.FrostAlgorithmRistretto255

	// FrostAlgorithmEd448 is the Ed448 FROST ciphersuite.
	FrostAlgorithmEd448 = types.FrostAlgorithmEd448

	// FrostAlgorithmP256 is the FIPS-compliant P-256 FROST ciphersuite.
	FrostAlgorithmP256 = types.FrostAlgorithmP256

	// FrostAlgorithmSecp256k1 is the blockchain-compatible secp256k1 FROST
	// ciphersuite.
	FrostAlgorithmSecp256k1 = types.FrostAlgorithmSecp256k1
)
