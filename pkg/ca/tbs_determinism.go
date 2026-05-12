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

// Package ca provides TBS (To-Be-Signed) determinism verification used by
// the ACME pre-certificate flow. The TBS portion of a certificate is the
// ASN.1-encoded body that the CA signs; verifying it matches between a
// lint-time certificate and the final signed certificate protects against
// non-deterministic signing (HSM firmware quirks, encoding skew, subtle
// bugs) that could otherwise cause misissuance.
package ca

import (
	"bytes"
	"errors"

	"golang.org/x/crypto/cryptobyte"
	cryptobyte_asn1 "golang.org/x/crypto/cryptobyte/asn1"
)

// =============================================================================
// TBS Determinism Errors
// =============================================================================

var (
	// ErrTBSDeterminismFailure indicates that the TBS (To-Be-Signed) bytes
	// of two certificates do not match. This points at a bug in signing
	// code, HSM firmware, or DER encoding and must abort issuance.
	ErrTBSDeterminismFailure = errors.New("ca: tbs certificate determinism verification failed")

	// ErrTBSNilInput indicates the caller passed a nil or empty byte slice
	// where DER certificate bytes were expected.
	ErrTBSNilInput = errors.New("ca: nil or empty input provided")

	// ErrMalformedCertificate indicates the DER-encoded certificate could
	// not be parsed as a Certificate SEQUENCE.
	ErrMalformedCertificate = errors.New("ca: malformed certificate der encoding")

	// ErrMalformedTBSCertificate indicates the TBS portion could not be
	// extracted from the Certificate SEQUENCE.
	ErrMalformedTBSCertificate = errors.New("ca: malformed tbs certificate")

	// ErrEmptyTBSCertificate indicates the extracted TBS bytes were empty.
	ErrEmptyTBSCertificate = errors.New("ca: empty tbs certificate")
)

// =============================================================================
// TBS Determinism Verification
// =============================================================================

// VerifyTBSDeterminism compares the TBS bytes of two DER-encoded
// certificates. When the lint certificate produced prior to signing and the
// actual signed certificate produce identical TBS bytes the signing path is
// deterministic; any divergence returns ErrTBSDeterminismFailure.
//
// Parameters:
//   - lintCertDER:   the pre-sign lint certificate in DER form
//   - actualCertDER: the final signed certificate in DER form
//
// Returns nil when both TBS byte strings match exactly. Callers should
// treat any error as a hard failure and abort the issuance.
func VerifyTBSDeterminism(lintCertDER, actualCertDER []byte) error {
	if len(lintCertDER) == 0 || len(actualCertDER) == 0 {
		return ErrTBSNilInput
	}

	lintTBS, err := ExtractTBSBytes(lintCertDER)
	if err != nil {
		return err
	}
	actualTBS, err := ExtractTBSBytes(actualCertDER)
	if err != nil {
		return err
	}

	if !bytes.Equal(lintTBS, actualTBS) {
		return ErrTBSDeterminismFailure
	}
	return nil
}

// ExtractTBSBytes pulls the RawTBSCertificate SEQUENCE out of a DER-encoded
// certificate without parsing the whole certificate. RFC 5280 §4.1 defines:
//
//	Certificate  ::=  SEQUENCE  {
//	    tbsCertificate       TBSCertificate,
//	    signatureAlgorithm   AlgorithmIdentifier,
//	    signatureValue       BIT STRING }
//
// This is cheaper than full x509 parsing and has no side effects — safe to
// call on untrusted input.
func ExtractTBSBytes(certDER []byte) ([]byte, error) {
	if len(certDER) == 0 {
		return nil, ErrTBSNilInput
	}

	input := cryptobyte.String(certDER)
	if !input.ReadASN1(&input, cryptobyte_asn1.SEQUENCE) {
		return nil, ErrMalformedCertificate
	}

	var tbs cryptobyte.String
	if !input.ReadASN1(&tbs, cryptobyte_asn1.SEQUENCE) {
		return nil, ErrMalformedTBSCertificate
	}
	if tbs.Empty() {
		return nil, ErrEmptyTBSCertificate
	}
	return tbs, nil
}
