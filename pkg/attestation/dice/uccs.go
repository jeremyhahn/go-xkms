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

package dice

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"strconv"

	"github.com/fxamacker/cbor/v2"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// The tcg-dice-UCCS-evidence extension, TCG DICE Attestation Architecture
// v1.00 r0.23 section 6.1.4:
//
//	tcg-dice-UCCS-evidence OBJECT IDENTIFIER ::= {tcg-dice 6}
//	UccsEvidence ::= SEQUENCE {
//	    uccs OCTET STRING
//	}
//
// The octet string holds an Unprotected CWT Claims Set: the CBOR map of a CWT
// (RFC 8392) with no COSE protection around it. The specification says why the
// protection is absent -- "the certificate signature authenticates, and
// integrity protects UCCS contents" -- which is also why nothing in this file
// verifies a signature: the only thing that authenticates these claims is the
// issuer's signature over the certificate that carries them, and that has
// already been checked by the time the claims are read.
//
// Section 6.1.4 also states the extension "MAY be used in addition to or in
// place of DiceTcbInfoSeq or DiceTcbInfo", and that "the issuer MUST ensure
// that non-constant elements of this field contributed to the CDI that
// generated the subject key".

// ClaimEatNonce is the CWT claim key of the EAT nonce, 10.
//
// It is the claim this profile reads. The key is assigned in the IANA "CBOR
// Web Token (CWT) Claims" registry to eat_nonce, defined by the Entity
// Attestation Token specification the DICE architecture cites as reference [4]
// for UEIDs and claims sets. Using the registry-assigned key rather than a
// private one is the whole point of moving the challenge here: another DICE
// verifier reading this certificate finds the nonce where it expects it.
const ClaimEatNonce = 10

// ClaimUeid is the CWT claim key of the EAT ueid, 256.
//
// It is how a device that cannot afford a tcg-dice-Ueid extension states its
// identifier: a constrained device that mints a fixed-template alias
// certificate and carries the ueid here instead. The value is
// an RFC 9711 UEID, a byte string whose first byte is the type.
const ClaimUeid = 256

// ClaimMeasurements is the CWT claim key of the EAT measurements claim, 273.
//
// A template-minting device states its firmware measurement here, beside its
// ueid. The value is kept verbatim in ClaimsSet.Other like every claim this
// package does not model.
const ClaimMeasurements = 273

// nonceMinLen is the shortest nonce this verifier will read, 8 bytes, which is
// the lower bound EAT places on eat_nonce.
//
// It is the security-relevant bound: a shorter challenge is guessable, and a
// guessable challenge establishes no freshness at all, so evidence carrying
// one is refused rather than weighed.
//
// EAT also says a nonce MUST NOT exceed 64 bytes and that bound is NOT
// enforced here, deliberately. The challenge is chosen by the verifier, not
// the device, and this stack already issues one that is longer: the ACME
// device-attest-01 flow uses the key authorization, "<token>.<thumbprint>",
// where the RFC 7638 thumbprint alone is 43 base64url characters. Refusing it
// would mean a verifier refusing the echo of its own challenge. A longer nonce
// is harder to guess, never easier, so the leniency runs in the direction that
// costs nothing; what it does cost is that an attester echoing such a
// challenge emits evidence a strictly conforming EAT verifier will reject, and
// the fix for that is for the issuing profile to choose a challenge inside the
// bound -- a decision that belongs to whoever owns the challenge, not to this
// parser.
const nonceMinLen = 8

// CBOR head bytes and major types this parser inspects before decoding.
//
// The first byte is read directly so a refusal can name what arrived -- an
// array, a tagged item, an indefinite-length map -- rather than reporting the
// decoder's failure to fit it into a Go map.
const (
	cborMajorTypeShift      = 5
	cborMajorTypeByteString = 2
	cborMajorTypeArray      = 4
	cborMajorTypeMap        = 5
	cborMajorTypeTag        = 6

	// cborHeadIndefiniteMap is 0xBF, a map of indefinite length.
	cborHeadIndefiniteMap = 0xBF

	// cborMaxNestedLevels bounds how deep a claim value may nest. A claims set
	// arrives inside a certificate an unauthenticated peer supplies, so the
	// depth is bounded before it is walked.
	cborMaxNestedLevels = 16
)

// uccsTagNumber is the CBOR tag RFC 9781 registers for a UCCS, 601.
//
// This parser refuses a tagged claims set; see ParseClaimsSet.
const uccsTagNumber = 601

// uccsDecMode decodes a claims set under the strictest profile the library
// offers, because the claims set is attacker-reachable: it arrives inside a
// certificate presented by whoever is enrolling.
//
// Each option refuses an encoding a conforming issuer never produces and a
// permissive reader would accept:
//
//   - DupMapKeyEnforcedAPF: a claim key twice leaves this verifier and any
//     other reader free to disagree about which value the device meant. It is
//     the same hazard ErrTcbInfoFieldOrder exists for.
//   - IndefLengthForbidden: an indefinite-length item has more than one
//     encoding for one value, and the issuer must make this field contribute
//     to the CDI, which a re-encoding would change.
//   - TagsForbidden: a tag changes what a value means, and this profile reads
//     no tagged claim.
//   - UTF8RejectInvalid: a text value that is not UTF-8 renders differently to
//     different readers.
var uccsDecMode = mustUccsDecMode(cbor.DecOptions{
	DupMapKey:       cbor.DupMapKeyEnforcedAPF,
	IndefLength:     cbor.IndefLengthForbidden,
	TagsMd:          cbor.TagsForbidden,
	UTF8:            cbor.UTF8RejectInvalid,
	MaxNestedLevels: cborMaxNestedLevels,
})

// uccsEncMode encodes a claims set under RFC 8949 core deterministic encoding,
// so one claims set has exactly one encoding.
//
// Section 6.1.4 requires the issuer to make this field contribute to the CDI
// that generated the subject key. A field with more than one encoding would
// make that contribution depend on which encoder ran.
var uccsEncMode = mustUccsEncMode(cbor.CoreDetEncOptions())

// mustUccsDecMode builds the decode mode. The options are compile-time
// constants, so a failure is a programming error rather than a runtime one.
func mustUccsDecMode(opts cbor.DecOptions) cbor.DecMode {
	mode, err := opts.DecMode()
	if err != nil {
		panic("dice: invalid CBOR decode options: " + err.Error())
	}
	return mode
}

// mustUccsEncMode builds the encode mode, panicking for the same reason.
func mustUccsEncMode(opts cbor.EncOptions) cbor.EncMode {
	mode, err := opts.EncMode()
	if err != nil {
		panic("dice: invalid CBOR encode options: " + err.Error())
	}
	return mode
}

// uccsEvidence is the ASN.1 shape of the extension value.
type uccsEvidence struct {
	Uccs []byte
}

// ClaimsSet is a decoded Unprotected CWT Claims Set.
//
// Only the nonce is modelled. Every other claim is kept verbatim in Other
// rather than interpreted, because a CWT claims set is an open registry and
// not a closed structure: refusing a claim key this verifier does not know
// would refuse every attester that says more about itself than this profile
// reads, which is the interoperability the UCCS extension exists to provide.
// That is the opposite of the stance ParseTcbInfo takes on an unknown
// DiceTcbInfo field, and deliberately so -- DiceTcbInfo is a SEQUENCE with ten
// members and an eleventh names nothing.
//
// Keeping the unread claims rather than discarding them is what makes the
// leniency honest: a relying party can see everything the device said, not
// only the part this profile understood.
type ClaimsSet struct {
	// Nonce is the eat_nonce claim (key 10): the challenge this verifier
	// issued, echoed back by the device.
	Nonce []byte

	// Other holds every claim except the nonce, keyed by CWT claim key, with
	// the value as the raw CBOR item it was encoded as. Nil when the claims
	// set carried nothing else.
	Other map[int64][]byte
}

// Ueid returns the device identifier the claims set carries at ClaimUeid, type
// byte included. It returns ErrUeidNotFound when there is no such claim,
// ErrMalformedUeid when the claim is not a byte string, and ErrEmptyUeid when
// that byte string is empty.
func (c *ClaimsSet) Ueid() ([]byte, error) {
	raw, present := c.Other[ClaimUeid]
	if !present {
		return nil, ErrUeidNotFound
	}
	if len(raw) == 0 || raw[0]>>cborMajorTypeShift != cborMajorTypeByteString {
		return nil, &errs.Detail{Err: ErrMalformedUeid, Detail: "the ueid claim is not a byte string"}
	}
	var ueid []byte
	if err := uccsDecMode.Unmarshal(raw, &ueid); err != nil {
		return nil, &errs.Joined{Lead: ErrMalformedUeid, Detail: "the ueid claim could not be decoded", Cause: err}
	}
	if len(ueid) == 0 {
		return nil, ErrEmptyUeid
	}
	return ueid, nil
}

// ParseUccsEvidence decodes a tcg-dice-UCCS-evidence extension value.
//
// The SEQUENCE is walked element by element rather than unmarshalled into the
// struct, for the reason ParseTcbInfo walks its own: encoding/asn1 stops at
// the last field the Go type declares and reports success on whatever follows.
// UccsEvidence declares exactly one member, so a second element would leave
// which of the two is the evidence undecidable -- and silently decided by
// position.
func ParseUccsEvidence(der []byte) (*ClaimsSet, error) {
	elements, err := sequenceElements(der, ErrMalformedUccsEvidence)
	if err != nil {
		return nil, err
	}
	if len(elements) != 1 {
		return nil, &errs.Detail{
			Err:    ErrMalformedUccsEvidence,
			Detail: "the sequence holds " + strconv.Itoa(len(elements)) + " elements and UccsEvidence declares one",
		}
	}

	uccs := elements[0]
	if uccs.Class != asn1.ClassUniversal || uccs.Tag != asn1.TagOctetString || uccs.IsCompound {
		return nil, &errs.Detail{Err: ErrMalformedUccsEvidence, Detail: "the uccs member is not a primitive OCTET STRING"}
	}
	if len(uccs.Bytes) == 0 {
		return nil, &errs.Detail{Err: ErrMalformedUccsEvidence, Detail: "the uccs octet string is empty"}
	}
	return ParseClaimsSet(uccs.Bytes)
}

// MarshalUccsEvidence encodes a tcg-dice-UCCS-evidence extension value.
func MarshalUccsEvidence(claims *ClaimsSet) ([]byte, error) {
	uccs, err := MarshalClaimsSet(claims)
	if err != nil {
		return nil, err
	}
	der, err := asn1.Marshal(uccsEvidence{Uccs: uccs})
	if err != nil {
		return nil, &errs.Joined{Lead: ErrMalformedUccsEvidence, Detail: "could not encode the UccsEvidence sequence", Cause: err}
	}
	return der, nil
}

// CreateUccsEvidenceExtension builds the tcg-dice-UCCS-evidence certificate
// extension.
//
// It is marked critical for the same reason the TcbInfo extension is: the
// extension carries the claims that make the certificate an attestation, and a
// relying party that cannot read them must not read the certificate as one.
// Section 6.1.4 does not state a criticality, so this is a choice rather than
// a requirement -- chain verification in this package clears the OID from the
// unhandled set, which is correct precisely because the package does handle
// it.
func CreateUccsEvidenceExtension(claims *ClaimsSet) (pkix.Extension, error) {
	value, err := MarshalUccsEvidence(claims)
	if err != nil {
		return pkix.Extension{}, err
	}
	return pkix.Extension{Id: OIDUccsEvidence, Critical: true, Value: value}, nil
}

// UccsFromCertificate extracts and decodes the tcg-dice-UCCS-evidence
// extension. It returns ErrUccsEvidenceNotFound when the certificate carries
// none.
func UccsFromCertificate(cert *x509.Certificate) (*ClaimsSet, error) {
	value, err := extensionValue(cert, OIDUccsEvidence, ErrUccsEvidenceNotFound)
	if err != nil {
		return nil, err
	}
	return ParseUccsEvidence(value)
}

// ParseClaimsSet decodes the CBOR claims set carried in the uccs octet string.
//
// The top-level item must be a definite-length CBOR map. A tag -- including
// the UCCS tag 601 -- is refused: the extension OID already says the content
// is a UCCS, so a tag adds no information and accepting both framings would
// put two encodings of the same evidence on the wire.
func ParseClaimsSet(uccs []byte) (*ClaimsSet, error) {
	if err := checkClaimsSetHead(uccs); err != nil {
		return nil, err
	}

	raw := make(map[int64]cbor.RawMessage)
	decoder := uccsDecMode.NewDecoder(bytes.NewReader(uccs))
	if err := decoder.Decode(&raw); err != nil {
		return nil, claimsSetDecodeError(err)
	}
	if decoder.NumBytesRead() != len(uccs) {
		return nil, &errs.Detail{Err: ErrMalformedClaimsSet, Detail: "trailing data after the claims set map"}
	}
	if len(raw) == 0 {
		return nil, &errs.Detail{Err: ErrMalformedClaimsSet, Detail: "the claims set is empty, so it states nothing"}
	}

	nonceRaw, present := raw[ClaimEatNonce]
	if !present {
		return nil, ErrNonceClaimMissing
	}
	nonce, err := decodeNonceClaim(nonceRaw)
	if err != nil {
		return nil, err
	}

	claims := &ClaimsSet{Nonce: nonce}
	for key, value := range raw {
		if key == ClaimEatNonce {
			continue
		}
		if claims.Other == nil {
			claims.Other = make(map[int64][]byte, len(raw)-1)
		}
		claims.Other[key] = bytes.Clone(value)
	}
	return claims, nil
}

// MarshalClaimsSet encodes a claims set as the CBOR the uccs octet string
// carries.
func MarshalClaimsSet(claims *ClaimsSet) ([]byte, error) {
	if claims == nil {
		return nil, ErrNilClaimsSet
	}
	if err := checkNonceLength(len(claims.Nonce)); err != nil {
		return nil, err
	}

	nonce, err := uccsEncMode.Marshal(claims.Nonce)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrMalformedClaimsSet, Detail: "could not encode the eat_nonce claim", Cause: err}
	}

	raw := make(map[int64]cbor.RawMessage, len(claims.Other)+1)
	raw[ClaimEatNonce] = nonce
	for key, value := range claims.Other {
		if key == ClaimEatNonce {
			// Two sources for one claim. Which one the encoder picked would
			// decide what the device is taken to have said.
			return nil, &errs.Detail{
				Err:    ErrDuplicateClaim,
				Detail: "claim " + strconv.FormatInt(ClaimEatNonce, 10) + " is the nonce and cannot also be supplied verbatim",
			}
		}
		if err := checkClaimValue(value); err != nil {
			return nil, err
		}
		raw[key] = value
	}

	encoded, err := uccsEncMode.Marshal(raw)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrMalformedClaimsSet, Detail: "could not encode the claims set", Cause: err}
	}
	return encoded, nil
}

// checkClaimsSetHead refuses a top-level item that is not a definite-length
// map before the decoder is asked to fit it into one.
func checkClaimsSetHead(uccs []byte) error {
	if len(uccs) == 0 {
		return &errs.Detail{Err: ErrMalformedClaimsSet, Detail: "the claims set is zero bytes long"}
	}

	head := uccs[0]
	if head == cborHeadIndefiniteMap {
		return &errs.Detail{Err: ErrMalformedClaimsSet, Detail: "the claims set map is indefinite-length"}
	}

	switch head >> cborMajorTypeShift {
	case cborMajorTypeMap:
		return nil
	case cborMajorTypeTag:
		return &errs.Detail{
			Err: ErrMalformedClaimsSet,
			Detail: "the claims set is tagged, and this profile reads the untagged map the " +
				"extension OID already identifies; CBOR tag " + strconv.Itoa(uccsTagNumber) + " is the UCCS tag",
		}
	default:
		return &errs.Detail{Err: ErrMalformedClaimsSet, Detail: "the claims set is not a CBOR map"}
	}
}

// claimsSetDecodeError names what the decoder refused, so an operator reading
// the refusal learns which rule the evidence broke.
func claimsSetDecodeError(err error) error {
	var duplicate *cbor.DupMapKeyError
	if errors.As(err, &duplicate) {
		return &errs.Joined{Lead: ErrDuplicateClaim, Detail: "the claims set repeats a claim key", Cause: err}
	}

	var indefinite *cbor.IndefiniteLengthError
	if errors.As(err, &indefinite) {
		return &errs.Joined{Lead: ErrMalformedClaimsSet, Detail: "the claims set carries an indefinite-length item", Cause: err}
	}

	var extraneous *cbor.ExtraneousDataError
	if errors.As(err, &extraneous) {
		return &errs.Joined{Lead: ErrMalformedClaimsSet, Detail: "trailing data after the claims set map", Cause: err}
	}

	var mistyped *cbor.UnmarshalTypeError
	if errors.As(err, &mistyped) {
		// The values decode into cbor.RawMessage, which accepts any item, so
		// the only thing that can fail to fit is a claim key.
		return &errs.Joined{Lead: ErrMalformedClaimsSet, Detail: "a claim key is not an integer", Cause: err}
	}

	return &errs.Joined{Lead: ErrMalformedClaimsSet, Detail: "the claims set could not be decoded", Cause: err}
}

// decodeNonceClaim reads the eat_nonce claim.
//
// EAT encodes a nonce as a byte string, or as an array of two or more byte
// strings when several verifiers each contributed one. The array form is
// refused here: this profile issues one challenge, and a set of candidates
// leaves "did the device answer me" without a single answer.
func decodeNonceClaim(raw []byte) ([]byte, error) {
	if len(raw) == 0 {
		return nil, &errs.Detail{Err: ErrMalformedNonceClaim, Detail: "the eat_nonce claim is empty"}
	}

	switch raw[0] >> cborMajorTypeShift {
	case cborMajorTypeByteString:
	case cborMajorTypeArray:
		return nil, &errs.Detail{
			Err:    ErrMalformedNonceClaim,
			Detail: "the eat_nonce claim carries several nonces, and this profile issues one challenge",
		}
	default:
		return nil, &errs.Detail{Err: ErrMalformedNonceClaim, Detail: "the eat_nonce claim is not a byte string"}
	}

	var nonce []byte
	if err := uccsDecMode.Unmarshal(raw, &nonce); err != nil {
		return nil, &errs.Joined{Lead: ErrMalformedNonceClaim, Detail: "the eat_nonce claim could not be decoded", Cause: err}
	}
	if err := checkNonceLength(len(nonce)); err != nil {
		return nil, err
	}
	return nonce, nil
}

// checkNonceLength enforces the lower bound EAT places on a nonce.
func checkNonceLength(length int) error {
	if length < nonceMinLen {
		return &errs.Detail{
			Err:    ErrNonceClaimLength,
			Detail: "the eat_nonce claim is " + strconv.Itoa(length) + " bytes",
		}
	}
	return nil
}

// checkClaimValue refuses a caller-supplied raw claim that is not exactly one
// well-formed CBOR item under this profile's rules.
//
// A claims set assembled from raw items is only as sound as the items, and an
// encoder that emitted something this package's own parser refuses would
// produce evidence no verifier could read.
func checkClaimValue(value []byte) error {
	if len(value) == 0 {
		return &errs.Detail{Err: ErrMalformedClaimsSet, Detail: "a claim value is zero bytes long"}
	}

	var item cbor.RawMessage
	decoder := uccsDecMode.NewDecoder(bytes.NewReader(value))
	if err := decoder.Decode(&item); err != nil {
		return &errs.Joined{Lead: ErrMalformedClaimsSet, Detail: "a claim value is not a well-formed CBOR item", Cause: err}
	}
	if decoder.NumBytesRead() != len(value) {
		return &errs.Detail{Err: ErrMalformedClaimsSet, Detail: "trailing data after a claim value"}
	}
	return nil
}
