// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package ca

import (
	"crypto"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// OIDAttestationEvidence is tp-attestationEvidence
// (1.3.6.1.4.1.29377.101.23), a private, non-critical extension in which the
// issuing caller records the attestation verdict that admitted the
// certificate's subject. The CA never derives it from a CSR: a requester able
// to name its own evidence would be attesting to itself.
//
//	AttestationEvidence ::= SEQUENCE {
//	    verdictID           UTF8String,
//	    pcrDigestAlgorithm  OBJECT IDENTIFIER,  -- id-sha256 / id-sha384 / id-sha512
//	    pcrDigest           OCTET STRING,
//	    attestedAt          GeneralizedTime
//	}
var OIDAttestationEvidence = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 29377, 101, 23}

// ErrInvalidAttestationEvidence reports evidence that cannot be encoded, or an
// extension that does not decode to valid evidence.
var ErrInvalidAttestationEvidence = errors.New("ca: invalid attestation evidence")

// AttestationEvidence is the content of the tp-attestationEvidence extension.
type AttestationEvidence struct {
	// VerdictID identifies the verifier's attestation result.
	VerdictID string
	// PCRDigestAlgorithm names the hash of PCRDigest: SHA-256, SHA-384 or
	// SHA-512.
	PCRDigestAlgorithm crypto.Hash
	// PCRDigest is the digest of the attested PCR values.
	PCRDigest []byte
	// AttestedAt is when the evidence was appraised. It is encoded in UTC at
	// one-second precision, the resolution of GeneralizedTime as DER encodes
	// it.
	AttestedAt time.Time
}

// attestationEvidenceASN1 is the DER form of AttestationEvidence.
type attestationEvidenceASN1 struct {
	VerdictID          string `asn1:"utf8"`
	PCRDigestAlgorithm asn1.ObjectIdentifier
	PCRDigest          []byte
	AttestedAt         time.Time `asn1:"generalized"`
}

// evidenceHashOIDs maps the accepted digest algorithms to their NIST OIDs
// (RFC 5758 §2).
var evidenceHashOIDs = map[crypto.Hash]asn1.ObjectIdentifier{
	crypto.SHA256: {2, 16, 840, 1, 101, 3, 4, 2, 1},
	crypto.SHA384: {2, 16, 840, 1, 101, 3, 4, 2, 2},
	crypto.SHA512: {2, 16, 840, 1, 101, 3, 4, 2, 3},
}

// validate checks every field and returns the normalised attestation time.
func (e *AttestationEvidence) validate() (time.Time, error) {
	if strings.TrimSpace(e.VerdictID) == "" {
		return time.Time{}, &errs.Detail{Err: ErrInvalidAttestationEvidence, Detail: "verdict id required"}
	}
	if _, ok := evidenceHashOIDs[e.PCRDigestAlgorithm]; !ok {
		return time.Time{}, &errs.Detail{Err: ErrInvalidAttestationEvidence, Detail: "pcr digest algorithm must be SHA-256, SHA-384 or SHA-512"}
	}
	if len(e.PCRDigest) != e.PCRDigestAlgorithm.Size() {
		return time.Time{}, &errs.Detail{Err: ErrInvalidAttestationEvidence, Detail: "pcr digest length does not match its algorithm"}
	}
	if e.AttestedAt.IsZero() {
		return time.Time{}, &errs.Detail{Err: ErrInvalidAttestationEvidence, Detail: "attestation time required"}
	}
	return e.AttestedAt.UTC().Truncate(time.Second), nil
}

// CreateAttestationEvidenceExtension encodes evidence as a non-critical
// tp-attestationEvidence extension, for SignOptions.ExtraExtensions.
func CreateAttestationEvidenceExtension(evidence AttestationEvidence) (pkix.Extension, error) {
	at, err := evidence.validate()
	if err != nil {
		return pkix.Extension{}, err
	}
	value, err := asn1.Marshal(attestationEvidenceASN1{
		VerdictID:          evidence.VerdictID,
		PCRDigestAlgorithm: evidenceHashOIDs[evidence.PCRDigestAlgorithm],
		PCRDigest:          evidence.PCRDigest,
		AttestedAt:         at,
	})
	if err != nil {
		return pkix.Extension{}, &errs.Detail{Err: ErrInvalidAttestationEvidence, Detail: err.Error()}
	}
	return pkix.Extension{Id: OIDAttestationEvidence, Value: value}, nil
}

// ParseAttestationEvidenceExtension returns the evidence a certificate carries.
// The boolean is false, with a nil error, when the certificate has no such
// extension. A certificate carrying it more than once, or carrying a value
// that does not decode to valid evidence, is an error.
func ParseAttestationEvidenceExtension(cert *x509.Certificate) (*AttestationEvidence, bool, error) {
	if cert == nil {
		return nil, false, &errs.Detail{Err: ErrInvalidAttestationEvidence, Detail: "nil certificate"}
	}
	return parseAttestationEvidence(cert.Extensions)
}

// parseAttestationEvidence finds and decodes the evidence among exts.
func parseAttestationEvidence(exts []pkix.Extension) (*AttestationEvidence, bool, error) {
	var found *pkix.Extension
	for i := range exts {
		if !exts[i].Id.Equal(OIDAttestationEvidence) {
			continue
		}
		if found != nil {
			return nil, true, &errs.Detail{Err: ErrInvalidAttestationEvidence, Detail: "extension present more than once"}
		}
		found = &exts[i]
	}
	if found == nil {
		return nil, false, nil
	}
	if found.Critical {
		return nil, true, &errs.Detail{Err: ErrInvalidAttestationEvidence, Detail: "extension must not be critical"}
	}

	var raw attestationEvidenceASN1
	rest, err := asn1.Unmarshal(found.Value, &raw)
	if err != nil {
		return nil, true, &errs.Detail{Err: ErrInvalidAttestationEvidence, Detail: err.Error()}
	}
	if len(rest) > 0 {
		return nil, true, &errs.Detail{Err: ErrInvalidAttestationEvidence, Detail: "trailing data after evidence"}
	}

	evidence := &AttestationEvidence{
		VerdictID:  raw.VerdictID,
		PCRDigest:  raw.PCRDigest,
		AttestedAt: raw.AttestedAt.UTC(),
	}
	for h, oid := range evidenceHashOIDs {
		if oid.Equal(raw.PCRDigestAlgorithm) {
			evidence.PCRDigestAlgorithm = h
		}
	}
	if _, err := evidence.validate(); err != nil {
		return nil, true, err
	}
	return evidence, true, nil
}
