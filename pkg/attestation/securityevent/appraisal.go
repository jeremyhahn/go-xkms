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

// Package securityevent appraises a device's security-event record: RFC 9334
// Evidence about the device's Attesting Environment, bound by a
// Detached-Submodule-Digest (RFC 9711 §4.2.18.2) inside EAT evidence the
// device signed over the Verifier's eat_nonce (RFC 9711 §4.1).
//
// Appraise recomputes the record's digest, compares it with the digest in
// the signed evidence, checks the signature through the DICE chain and
// checks the eat_nonce. When it succeeds, the device's key vouched for this
// exact record, and the record is fresh (RFC 9334 §10).
package securityevent

import (
	"bytes"
	"crypto"
	"crypto/subtle"
	"crypto/x509"

	// Registers SHA-256, SHA-384 and SHA-512 with crypto.Hash.
	_ "crypto/sha256"
	_ "crypto/sha512"

	"github.com/fxamacker/cbor/v2"
	cose "github.com/veraison/go-cose"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/dice"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

const (
	// ClaimSubmods is the submods claim key (RFC 9711 §4.2.18, §10.2).
	ClaimSubmods int64 = 266

	// SubmoduleName labels the record's entry in the submods map. EAT
	// registers no name for a security-event record, so the label is
	// go-xkms's own (RFC 9711 §4.2.18: the attester documents its submodule
	// semantics for the Verifier).
	SubmoduleName = "security-events"

	// cborMajorTypeShift moves a CBOR initial byte's major type into the low
	// three bits (RFC 8949 §3).
	cborMajorTypeShift = 5

	// cborMajorTypeArray and cborMajorTypeMap are the CBOR major types of an
	// array and a map (RFC 8949 §3.1).
	cborMajorTypeArray = 4
	cborMajorTypeMap   = 5
)

// hashByCOSEAlgorithm maps the COSE Algorithms registry identifiers of the
// hashes this Verifier computes to their implementations. RFC 9711
// §4.2.18.2 lets the digest name its algorithm by integer or by string, and
// only from that registry.
var hashByCOSEAlgorithm = map[any]crypto.Hash{
	int64(-16): crypto.SHA256,
	int64(-43): crypto.SHA384,
	int64(-44): crypto.SHA512,
	"SHA-256":  crypto.SHA256,
	"SHA-384":  crypto.SHA384,
	"SHA-512":  crypto.SHA512,
}

// decMode decodes the evidence's submods claim and its digest. Duplicate map
// keys and indefinite lengths are refused so that a claim has exactly one
// reading, and an integer outside the int64 range is refused so that a hash
// algorithm always decodes to a comparable map key.
var decMode = mustDecMode()

func mustDecMode() cbor.DecMode {
	mode, err := cbor.DecOptions{
		DupMapKey:   cbor.DupMapKeyEnforcedAPF,
		IndefLength: cbor.IndefLengthForbidden,
		IntDec:      cbor.IntDecConvertSignedOrFail,
	}.DecMode()
	if err != nil {
		panic(err)
	}
	return mode
}

// Options are the trust inputs of an appraisal.
type Options struct {
	// Nonce is the challenge this Verifier passed to AttestSecurityEvents.
	// It is required: the evidence's eat_nonce is the only thing that tells a
	// fresh answer from a replayed one.
	Nonce []byte

	// DICE verifies the chain of the key that signed the evidence; its
	// TrustedRoots anchor the chain and are required: dice.Verify skips the
	// chain check when they are nil. Its ExpectedNonce is the nonce the leaf
	// certificate's own UCCS evidence was minted over, which is not Nonce
	// unless the device minted the leaf for this challenge.
	DICE dice.VerifyOptions
}

// Result is what an accepted appraisal established.
type Result struct {
	// Record is the security-event Claims-Set the device's key vouched for.
	Record []byte

	// Device is the verified DICE evidence of the signing key's chain.
	Device *dice.Evidence
}

// detachedDigest is the Detached-Submodule-Digest of RFC 9711 §4.2.18.2:
// [hash-algorithm: text / int, digest: binary-data].
type detachedDigest struct {
	_         struct{} `cbor:",toarray"`
	Algorithm any
	Digest    []byte
}

// Appraise checks a security-event record against the evidence the device
// signed over it, and returns the record once the device's key is shown to
// have vouched for it in answer to opts.Nonce.
func Appraise(evidence *types.SecurityEventEvidence, opts *Options) (*Result, error) {
	if evidence == nil {
		return nil, ErrNilEvidence
	}
	if opts == nil {
		return nil, ErrNilOptions
	}
	if len(opts.Nonce) == 0 {
		return nil, ErrNonceRequired
	}
	if opts.DICE.TrustedRoots == nil {
		return nil, ErrTrustedRootsRequired
	}

	chain, err := parseChain(evidence.Chain)
	if err != nil {
		return nil, err
	}
	device, err := dice.Verify(chain, &opts.DICE)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrUntrustedSigner, Cause: err}
	}

	payload, err := verifySignature(evidence.Evidence, chain[0])
	if err != nil {
		return nil, err
	}
	claims, err := dice.ParseClaimsSet(payload)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrMalformedEvidence, Cause: err}
	}
	if subtle.ConstantTimeCompare(claims.Nonce, opts.Nonce) != 1 {
		return nil, ErrNonceMismatch
	}

	digest, err := recordDigest(claims.Other[ClaimSubmods])
	if err != nil {
		return nil, err
	}
	if err := verifyRecord(evidence.Record, digest); err != nil {
		return nil, err
	}
	return &Result{Record: bytes.Clone(evidence.Record), Device: device}, nil
}

// parseChain parses the signer's DER certificate chain, leaf first.
func parseChain(ders [][]byte) ([]*x509.Certificate, error) {
	if len(ders) == 0 {
		return nil, &errs.Detail{Err: ErrMalformedChain, Detail: "the chain is empty"}
	}
	chain := make([]*x509.Certificate, 0, len(ders))
	for _, der := range ders {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return nil, &errs.Joined{Lead: ErrMalformedChain, Cause: err}
		}
		chain = append(chain, cert)
	}
	return chain, nil
}

// verifySignature verifies the evidence's COSE_Sign1_Tagged structure
// (RFC 9052 §4.2) under the DICE leaf's key and returns its payload. The
// algorithm is pinned to ES256, the one signature a DICE device performs
// (dice.ErrUnsupportedSignatureAlgorithm), so the protected header cannot
// choose a weaker one.
func verifySignature(evidence []byte, leaf *x509.Certificate) ([]byte, error) {
	msg := cose.NewSign1Message()
	if err := msg.UnmarshalCBOR(evidence); err != nil {
		return nil, &errs.Joined{Lead: ErrMalformedEvidence, Cause: err}
	}
	alg, err := msg.Headers.Protected.Algorithm()
	if err != nil {
		return nil, &errs.Joined{Lead: ErrSignature, Cause: err}
	}
	if alg != cose.AlgorithmES256 {
		return nil, &errs.Detail{Err: ErrSignature, Detail: "the evidence is signed with " + alg.String() + ", not ES256"}
	}
	verifier, err := cose.NewVerifier(alg, leaf.PublicKey)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrSignature, Cause: err}
	}
	if err := msg.Verify(nil, verifier); err != nil {
		return nil, &errs.Joined{Lead: ErrSignature, Cause: err}
	}
	return msg.Payload, nil
}

// recordDigest finds the record's Detached-Submodule-Digest in the submods
// claim (RFC 9711 §4.2.18). A CBOR array is the only encoding of a detached
// digest there; a map would be an inline Claims-Set (§4.2.18.1), which the
// owner's ruling did not choose.
func recordDigest(submods []byte) (*detachedDigest, error) {
	if len(submods) == 0 {
		return nil, &errs.Detail{Err: ErrNoDetachedDigest, Detail: "the evidence has no submods claim"}
	}
	var entries map[string]cbor.RawMessage
	if err := decMode.Unmarshal(submods, &entries); err != nil {
		return nil, &errs.Joined{Lead: ErrMalformedEvidence, Detail: "the submods claim", Cause: err}
	}
	entry, ok := entries[SubmoduleName]
	if !ok {
		return nil, &errs.Detail{Err: ErrNoDetachedDigest, Detail: "submods has no " + SubmoduleName + " entry"}
	}
	if entry[0]>>cborMajorTypeShift != cborMajorTypeArray {
		return nil, &errs.Detail{Err: ErrNoDetachedDigest, Detail: "the " + SubmoduleName + " submodule is not a detached digest"}
	}
	var digest detachedDigest
	if err := decMode.Unmarshal(entry, &digest); err != nil {
		return nil, &errs.Joined{Lead: ErrMalformedEvidence, Detail: "the detached digest", Cause: err}
	}
	return &digest, nil
}

// verifyRecord recomputes the record's digest over its CBOR encoding, with
// no wrapping (RFC 9711 §4.2.18.2), compares it with the signed digest, and
// checks the record is one well-formed Claims-Set.
func verifyRecord(record []byte, signed *detachedDigest) error {
	// Algorithm is decoded into any: only the two key types of the map may
	// reach the lookup, since a byte string, array or map does not hash.
	switch signed.Algorithm.(type) {
	case int64, string:
	case uint64:
		return ErrUnsupportedHashAlgorithm
	default:
		return &errs.Joined{Lead: ErrMalformedEvidence, Detail: "the detached digest algorithm"}
	}
	hash, ok := hashByCOSEAlgorithm[signed.Algorithm]
	if !ok {
		return ErrUnsupportedHashAlgorithm
	}
	h := hash.New()
	h.Write(record)
	if subtle.ConstantTimeCompare(h.Sum(nil), signed.Digest) != 1 {
		return ErrRecordDigestMismatch
	}

	if len(record) == 0 || record[0]>>cborMajorTypeShift != cborMajorTypeMap {
		return &errs.Detail{Err: ErrMalformedRecord, Detail: "the record is not a CBOR map"}
	}
	if err := decMode.Wellformed(record); err != nil {
		return &errs.Joined{Lead: ErrMalformedRecord, Cause: err}
	}
	return nil
}
