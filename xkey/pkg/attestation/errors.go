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

package attestation

import "errors"

var (
	// ErrNilTrustStore indicates the trust store provided to the verifier is nil.
	ErrNilTrustStore = errors.New("attestation: nil trust store")

	// ErrNilCertificate indicates a nil certificate was provided for verification.
	ErrNilCertificate = errors.New("attestation: nil certificate")

	// ErrEmptyCertChain indicates an empty certificate chain was provided.
	ErrEmptyCertChain = errors.New("attestation: empty certificate chain")

	// ErrNoTrustAnchors indicates no trust anchors were found for the requested purpose.
	ErrNoTrustAnchors = errors.New("attestation: no trust anchors found for purpose")

	// ErrChainVerification indicates the X.509 chain verification failed.
	ErrChainVerification = errors.New("attestation: chain verification failed")

	// ErrUnsupportedPurpose indicates the certificate purpose is not recognized.
	ErrUnsupportedPurpose = errors.New("attestation: unsupported certificate purpose")

	// ErrTrustStoreQuery indicates a failure querying the trust store.
	ErrTrustStoreQuery = errors.New("attestation: trust store query failed")

	// ErrMissingNonce indicates an attestation was submitted without the
	// challenge it must be bound to. Verifying without a challenge accepts
	// replayed attestations, so the verifier refuses instead.
	ErrMissingNonce = errors.New("attestation: challenge nonce is required")

	// ErrChallengeVerification indicates the attestation challenge could not be
	// bound to the supplied nonce: the key attestation extension was absent,
	// unparseable, or carried a different challenge.
	ErrChallengeVerification = errors.New("attestation: challenge verification failed")

	// ErrAttestationKeyOriginNotGenerated indicates the attested key's
	// TEE-enforced Origin claim is not GENERATED: the key was derived,
	// imported, or the TEE made no origin claim at all (go-xkms#132).
	ErrAttestationKeyOriginNotGenerated = errors.New("attestation: attested key's TEE-enforced origin is not GENERATED")

	// ErrAttestationKeyPurposeNotSign indicates the attested key's
	// TEE-enforced Purpose set does not include SIGN (go-xkms#132).
	ErrAttestationKeyPurposeNotSign = errors.New("attestation: attested key's TEE-enforced purpose does not include SIGN")
)

// SentinelCauseError attaches an underlying cause to a package sentinel
// error so errors.Is matches both the sentinel and the cause.
type SentinelCauseError struct {
	Sentinel error
	Cause    error
}

// Error implements the error interface.
func (e *SentinelCauseError) Error() string {
	return e.Sentinel.Error() + ": " + e.Cause.Error()
}

// Unwrap returns the sentinel and the cause for errors.Is / errors.As.
func (e *SentinelCauseError) Unwrap() []error {
	return []error{e.Sentinel, e.Cause}
}
