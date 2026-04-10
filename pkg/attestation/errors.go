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
	// ErrSignatureVerificationFailed indicates the cryptographic signature did not verify.
	ErrSignatureVerificationFailed = errors.New("attestation: signature verification failed")

	// ErrChainVerificationFailed indicates the certificate chain could not be verified.
	ErrChainVerificationFailed = errors.New("attestation: certificate chain verification failed")

	// ErrNonceMismatch indicates the attestation nonce does not match the expected value.
	ErrNonceMismatch = errors.New("attestation: nonce mismatch")

	// ErrEmptyCertificateChain indicates no certificates were provided in the chain.
	ErrEmptyCertificateChain = errors.New("attestation: empty certificate chain")

	// ErrCertificateExpired indicates a certificate in the chain has expired.
	ErrCertificateExpired = errors.New("attestation: certificate expired")

	// ErrCertificateNotYetValid indicates a certificate in the chain is not yet valid.
	ErrCertificateNotYetValid = errors.New("attestation: certificate not yet valid")

	// ErrEmptySignature indicates the signature field is empty.
	ErrEmptySignature = errors.New("attestation: empty signature")

	// ErrNilAttestingKey indicates the attesting public key is nil.
	ErrNilAttestingKey = errors.New("attestation: attesting key public is nil")

	// ErrNilAttestedKey indicates the attested public key is nil.
	ErrNilAttestedKey = errors.New("attestation: attested key public is nil")

	// ErrUnsupportedKeyType indicates the public key type is not supported for verification.
	ErrUnsupportedKeyType = errors.New("attestation: unsupported public key type")

	// ErrUnsupportedSignatureAlgorithm indicates the signature algorithm is not supported.
	ErrUnsupportedSignatureAlgorithm = errors.New("attestation: unsupported signature algorithm")

	// ErrInvalidSelfSignedCert indicates a self-signed certificate failed signature validation.
	ErrInvalidSelfSignedCert = errors.New("attestation: invalid self-signed certificate")

	// ErrInvalidChainSignature indicates a certificate chain signature is invalid.
	ErrInvalidChainSignature = errors.New("attestation: invalid certificate chain signature")

	// ErrMissingTimestamp indicates the created timestamp is absent.
	ErrMissingTimestamp = errors.New("attestation: created timestamp is missing")

	// ErrInvalidTimestamp indicates the created timestamp could not be parsed.
	ErrInvalidTimestamp = errors.New("attestation: invalid created timestamp")

	// ErrFutureTimestamp indicates the attestation created time is in the future.
	ErrFutureTimestamp = errors.New("attestation: created time is in the future")

	// ErrAttestationExpired indicates the attestation is older than the freshness window.
	ErrAttestationExpired = errors.New("attestation: too old")

	// ErrMissingPCRs indicates PCRs were expected but none were provided.
	ErrMissingPCRs = errors.New("attestation: expected PCRs but none provided")

	// ErrPCRMissing indicates a specific PCR index was not provided in the attestation.
	ErrPCRMissing = errors.New("attestation: PCR not provided in attestation")

	// ErrPCRMismatch indicates a PCR value does not match the expected value.
	ErrPCRMismatch = errors.New("attestation: PCR value mismatch")

	// ErrNilVerifyOptions indicates the verification options are nil.
	ErrNilVerifyOptions = errors.New("attestation: verify options cannot be nil")

	// ErrNegativeFreshnessWindow indicates the freshness window is negative.
	ErrNegativeFreshnessWindow = errors.New("attestation: freshness window cannot be negative")

	// ErrMarshalAttestedKey indicates the attested public key could not be marshaled.
	ErrMarshalAttestedKey = errors.New("attestation: failed to marshal attested key")
)
