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

import "github.com/jeremyhahn/go-xkms/pkg/attestation"

// Attestation verification (go-xkms#1548): the one verifier for attestation
// statements and for purpose-pooled TPM EK, Android hardware and IDevID
// chains. The canonical implementation is pkg/attestation; these aliases are
// the SDK surface xkey and downstream consumers reach it through. Identifiers
// carry an Attestation prefix because Verifier and VerifyOptions already name
// other surfaces in this flat namespace.

// AttestationVerifier verifies attestation statements against configured
// roots and, when built WithAttestationTrustStore, certificate chains against
// the trust store's anchors for a certificate purpose.
type AttestationVerifier = attestation.Verifier

// AttestationVerifierOption configures an AttestationVerifier.
type AttestationVerifierOption = attestation.VerifierOption

// AttestationVerificationResult is the outcome of a purpose-pooled check.
type AttestationVerificationResult = attestation.VerificationResult

// AttestationTrustLevel indicates the level of trust for a verified
// attestation.
type AttestationTrustLevel = attestation.TrustLevel

// AttestationEmbeddedRootsLoader supplies compiled-in roots for a purpose.
type AttestationEmbeddedRootsLoader = attestation.EmbeddedRootsLoader

const (
	// AttestationTrustLevelHardware means the key is backed by hardware
	// security (TPM, Android TEE/StrongBox).
	AttestationTrustLevelHardware = attestation.TrustLevelHardware
	// AttestationTrustLevelSoftware means the key is software-backed.
	AttestationTrustLevelSoftware = attestation.TrustLevelSoftware
	// AttestationTrustLevelExternalCA means the key was verified by an
	// external CA.
	AttestationTrustLevelExternalCA = attestation.TrustLevelExternalCA
	// AttestationTrustLevelUnknown means the trust level could not be
	// determined.
	AttestationTrustLevelUnknown = attestation.TrustLevelUnknown
)

var (
	// NewAttestationVerifier builds an AttestationVerifier over the given
	// statement roots and options.
	NewAttestationVerifier = attestation.NewVerifier

	// WithAttestationTrustStore backs the purpose-pooled checks with a trust
	// store and an optional embedded-roots loader.
	WithAttestationTrustStore = attestation.WithTrustStore
)

var (
	// ErrAttestationNilTrustStore means a purpose-pooled check ran on a
	// verifier built without a trust store.
	ErrAttestationNilTrustStore = attestation.ErrNilTrustStore
	// ErrAttestationTrustStoreQuery means the trust store could not be queried.
	ErrAttestationTrustStoreQuery = attestation.ErrTrustStoreQuery
	// ErrAttestationEmptyCertificateChain means an empty chain was supplied.
	ErrAttestationEmptyCertificateChain = attestation.ErrEmptyCertificateChain
	// ErrAttestationCertificateParseFailed means a certificate in a DER chain
	// could not be parsed.
	ErrAttestationCertificateParseFailed = attestation.ErrCertificateParseFailed
	// ErrAttestationNoTrustAnchors means no trust anchors were supplied.
	ErrAttestationNoTrustAnchors = attestation.ErrNoTrustAnchors
	// ErrAttestationChainNotAnchored means the chain does not reach a
	// trusted anchor.
	ErrAttestationChainNotAnchored = attestation.ErrChainNotAnchored
)

// AndroidDeviceTrust is the trust a hardware-held Android device key is
// verified against: the attestation roots and the application policy.
type AndroidDeviceTrust = attestation.AndroidDeviceTrust

// AndroidDeviceKey is a verified Android device-key attestation.
type AndroidDeviceKey = attestation.AndroidDeviceKey

// VerifyAndroidDeviceKey verifies a DER Android key-attestation chain as a
// hardware-held device key: anchored, TEE or StrongBox, generated, able to
// sign, locked and verified boot, and an allowed application.
var VerifyAndroidDeviceKey = attestation.VerifyAndroidDeviceKey

// ParseAttestationDERChain parses a DER certificate chain, leaf first.
var ParseAttestationDERChain = attestation.ParseDERChain

// VerifiedAttestationTrustAnchor verifies a chain against roots and
// returns the root the verified path ends in.
var VerifiedAttestationTrustAnchor = attestation.VerifiedTrustAnchor

// FormatAttestationTrustAnchor names a trust anchor for display.
var FormatAttestationTrustAnchor = attestation.FormatTrustAnchor
