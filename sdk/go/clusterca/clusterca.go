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

// Package clusterca is the SDK re-export of the canonical Raft cluster-node
// identity provisioner (pkg/trust/clusterca). Downstream composition roots
// (go-quicbaas) import this package to resolve inter-node mTLS material —
// operator files, ACME-attested enrollment, hardware-key, or software
// auto-enrollment — through one call, instead of reimplementing the wiring.
package clusterca

import (
	pkgclusterca "github.com/jeremyhahn/go-xkms/pkg/trust/clusterca"
)

// Re-exported core types.
type (
	// Provisioner resolves cluster-node mTLS material per the package precedence.
	Provisioner = pkgclusterca.Provisioner

	// Options holds the provisioning parameters (seams + config).
	Options = pkgclusterca.Options

	// Result is the provisioning outcome (MTLS material + optional Advertiser).
	Result = pkgclusterca.Result

	// CAIssuer is the minimal certificate-authority surface the provisioner needs.
	CAIssuer = pkgclusterca.CAIssuer

	// ExplicitFiles holds operator-supplied PEM file paths (precedence 1).
	ExplicitFiles = pkgclusterca.ExplicitFiles

	// ACMEOptions configures ACME-attested enrollment (precedence 2).
	ACMEOptions = pkgclusterca.ACMEOptions
)

// Re-exported constructor + entry point.
var New = pkgclusterca.New

// NodeLocalBackendsParams configures NewNodeLocalBackends — the product-agnostic
// description of how a composition root builds the pre-node key backends the
// cluster ACME provisioner needs.
type NodeLocalBackendsParams = pkgclusterca.NodeLocalBackendsParams

// NewNodeLocalBackends builds the shared PRE-NODE key-backend resolver every
// product's composition root uses so cluster CA key protection (KeyProtection
// over a node-local software keystore, with hardware-TPM reuse) works
// identically across xkmsd, quicbaasd, and any other SDK consumer.
var NewNodeLocalBackends = pkgclusterca.NewNodeLocalBackends

// Cluster CA key custody strategy — the seam that decides which node(s) can
// issue cluster certificates and where the signing key lives.
type (
	// ClusterCAKeyStrategy resolves the keystore backend that holds the cluster
	// CA signing key, per the configured custody model.
	ClusterCAKeyStrategy = pkgclusterca.ClusterCAKeyStrategy

	// KeyStrategyName identifies a cluster CA key custody strategy.
	KeyStrategyName = pkgclusterca.KeyStrategyName

	// StrategyDeps carries the composition-root dependencies a strategy needs.
	StrategyDeps = pkgclusterca.StrategyDeps
)

const (
	// KeyStrategyBarrier stores the cluster CA key in the replicated
	// barrier-encrypted datastore; any node loads it and can issue (default).
	KeyStrategyBarrier = pkgclusterca.KeyStrategyBarrier

	// KeyStrategyHSM keeps the cluster CA key inside a shared PKCS#11 HSM.
	KeyStrategyHSM = pkgclusterca.KeyStrategyHSM

	// KeyStrategyTPMKEK wraps the replicated cluster CA key under a KEK derived
	// from a cluster seed sealed to each node's local TPM.
	KeyStrategyTPMKEK = pkgclusterca.KeyStrategyTPMKEK
)

// NewClusterCAKeyStrategy returns the cluster CA key strategy for the given name
// (empty selects the barrier default). It fails closed for unknown or
// not-yet-implemented strategies.
var NewClusterCAKeyStrategy = pkgclusterca.NewKeyStrategy

// Cluster CA key strategy error sentinels.
var (
	ErrUnknownKeyStrategy        = pkgclusterca.ErrUnknownKeyStrategy
	ErrKeyStrategyNotImplemented = pkgclusterca.ErrKeyStrategyNotImplemented
	ErrIssuanceNotLocal          = pkgclusterca.ErrIssuanceNotLocal
	ErrStrategyMisconfigured     = pkgclusterca.ErrStrategyMisconfigured
)

// Enrollment secret delivery — the decoupled seam that lets a custody strategy
// (e.g. tpm-kek) deliver wrapped provisioning material to a node during attested
// enrollment, and the post-enrollment fetch transport every product reuses.
type (
	// NodeSecretProvider wraps provisioning material for an enrolling node.
	NodeSecretProvider = pkgclusterca.NodeSecretProvider

	// NodeSecretRequest identifies the enrolling node material is wrapped for.
	NodeSecretRequest = pkgclusterca.NodeSecretRequest

	// ProvisionedSecret is a piece of wrapped provisioning material.
	ProvisionedSecret = pkgclusterca.ProvisionedSecret

	// EnrollmentSecretStrategy is optionally implemented by a key strategy that
	// delivers enrollment material (discover via EnrollmentSecretStrategyOf).
	EnrollmentSecretStrategy = pkgclusterca.EnrollmentSecretStrategy

	// CredentialActivator is the minimal TPM credential-activation surface the
	// tpm-kek strategy uses (satisfied by pkg/tpm2.TrustedPlatformModule).
	CredentialActivator = pkgclusterca.CredentialActivator

	// SecretDeliveryService orchestrates registered NodeSecretProviders and
	// serves the post-enrollment fetch.
	SecretDeliveryService = pkgclusterca.SecretDeliveryService
)

// EnrollmentSecretStrategyOf returns the EnrollmentSecretStrategy view of a key
// strategy, or (nil, false) when it delivers no enrollment material.
var EnrollmentSecretStrategyOf = pkgclusterca.EnrollmentSecretStrategyOf

// NewSecretDeliveryService builds the provider-orchestration delivery service.
var NewSecretDeliveryService = pkgclusterca.NewSecretDeliveryService

// FetchClusterSecrets is the joiner-side client that fetches wrapped material
// from an existing node after enrollment.
var FetchClusterSecrets = pkgclusterca.FetchClusterSecrets

// SecretDeliveryPath is the HTTP path the post-enrollment secret fetch is served
// on.
const SecretDeliveryPath = pkgclusterca.SecretDeliveryPath

// Re-exported key-protection surface (node-local CA keystore protection).
type (
	// KeyProtection resolves the node-local cluster CA keystore password,
	// reusing the stack's seal machinery (TPM/HSM sealer or passphrase).
	KeyProtection = pkgclusterca.KeyProtection

	// KeyProtectionMode selects how the CA keystore password is protected.
	KeyProtectionMode = pkgclusterca.KeyProtectionMode
)

// Re-exported key-protection modes (canonical seal vocabulary).
const (
	// KeyProtectAuto selects the strongest available protection (default).
	KeyProtectAuto = pkgclusterca.KeyProtectAuto
	// KeyProtectNone stores CA keys in plaintext (dev/testing only).
	KeyProtectNone = pkgclusterca.KeyProtectNone
	// KeyProtectPassphrase encrypts the CA keystore with an operator passphrase.
	KeyProtectPassphrase = pkgclusterca.KeyProtectPassphrase
	// KeyProtectTPM2 seals the CA keystore key to the TPM.
	KeyProtectTPM2 = pkgclusterca.KeyProtectTPM2
	// KeyProtectPKCS11 seals the CA keystore key to an HSM.
	KeyProtectPKCS11 = pkgclusterca.KeyProtectPKCS11
)

// Re-exported typed errors.
type (
	// ErrMissingOption is returned by New when a required Options field is unset.
	ErrMissingOption = pkgclusterca.ErrMissingOption
	// ErrFileRead is returned when an operator-supplied PEM file cannot be read.
	ErrFileRead = pkgclusterca.ErrFileRead
	// ErrLeafDecode is returned when a node leaf PEM cannot be decoded.
	ErrLeafDecode = pkgclusterca.ErrLeafDecode
	// ErrExistingCAWithoutStagedCerts guards against forking a second root.
	ErrExistingCAWithoutStagedCerts = pkgclusterca.ErrExistingCAWithoutStagedCerts
	// ErrAnchorMismatch is returned when a node cert does not chain to the anchor.
	ErrAnchorMismatch = pkgclusterca.ErrAnchorMismatch
	// ErrSPIFFEMismatch is returned on a SPIFFE node-SAN mismatch.
	ErrSPIFFEMismatch = pkgclusterca.ErrSPIFFEMismatch
	// ErrACMEBackendUnsupported is returned for an unimplemented ACME key backend.
	ErrACMEBackendUnsupported = pkgclusterca.ErrACMEBackendUnsupported
	// ErrNoTPM is returned when a TPM is required but unavailable.
	ErrNoTPM = pkgclusterca.ErrNoTPM
	// ErrNoSecureCAKeyProtection is returned when no secure CA-key protection exists.
	ErrNoSecureCAKeyProtection = pkgclusterca.ErrNoSecureCAKeyProtection
	// ErrSealerUnavailable is returned when a hardware protection mode lacks a sealer.
	ErrSealerUnavailable = pkgclusterca.ErrSealerUnavailable
	// ErrSealBlobCorrupt is returned when the cached sealed CA-key blob is corrupt.
	ErrSealBlobCorrupt = pkgclusterca.ErrSealBlobCorrupt
)

// AnchorCachePath returns the path of the cached trust-anchor bundle beneath
// dataDir (read by a composition root during first-node CA adoption).
var AnchorCachePath = pkgclusterca.AnchorCachePath

// StagedCACertsPath returns the path of the full CA certificate set the ACME
// first-node pre-stage persists beneath dataDir. A composition root reads this
// during CA initialization to adopt every configured intermediate before the
// CA's Load runs (which verifies the whole hierarchy), so Load succeeds without
// re-running Init and forking a second root.
var StagedCACertsPath = pkgclusterca.StagedCACertsPath
