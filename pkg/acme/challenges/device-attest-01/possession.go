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

package deviceattest01

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"math/big"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/dice"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/jeremyhahn/go-xkms/pkg/errs"
)

// The possession certificate request
//
// A template-minting DICE device cannot build a PKCS#10 request the ordinary
// way: it has no ASN.1 encoder, and its alias key is its static DeviceID key,
// so the leaf it presents at the challenge says nothing about which finalize it
// belongs to. It proves possession at finalize instead, by signing a
// CertificationRequestInfo it fills in from a fixed template. Its one
// host-supplied input is b = SHA-256(keyAuthorization), the same b the
// challenge carried, so a request signed for one order cannot be replayed
// into another.
//
// The template, byte for byte, is what BuildPossessionCRI writes:
//
//	CertificationRequestInfo ::= SEQUENCE {
//	  version       INTEGER 0
//	  subject       Name, empty (30 00)
//	  subjectPKInfo id-ecPublicKey, prime256v1, uncompressed point
//	  attributes    [0] { extensionRequest { SEQUENCE OF Extension {
//	    subjectAltName, critical (RFC 5280 4.2.1.6: the subject is empty)
//	      otherName id-on-permanentIdentifier (RFC 4043)
//	        identifierValue = lower-case hex(DeviceID), no assigner
//	    tcg-dice-UCCS-evidence, not critical
//	      uccs = CBOR { 10 (eat_nonce): b }
//	  } } }
//	}
//
// The binding is the UCCS nonce inside extensionRequest, where any DICE
// verifier already looks for a challenge, and not challengePassword. The UCCS
// extension is not critical because it is never issued: it is evidence about
// this request, and the CA copies no requested extension onto the
// certificate.
//
// The host wraps the device's signature with ecdsa-with-SHA256
// (AssemblePossessionCSR); the server reverses the template exactly
// (ParsePossessionCSR) and refuses any request that is not byte-for-byte what
// the template produces for the values it carries.

// PossessionNonceSize is the length of the nonce a possession request
// carries: SHA-256 of the key authorization, as DICENonce computes it.
const PossessionNonceSize = 32

// PossessionIdentifierType is the ACME identifier type a possession request
// names its device by.
const PossessionIdentifierType = common.AuthzTypePermanentIdentifier

// OIDExtensionRequest is the PKCS#9 extensionRequest attribute (RFC 2985
// section 5.4.2), the attribute a possession request carries its extensions
// in.
var OIDExtensionRequest = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 14}

var (
	// ErrPossessionCSRMalformed is returned when a certificate request is not
	// the possession template: wrong subject, key, signature algorithm,
	// attributes or extensions, or any byte the template would not have
	// written for the values the request carries.
	ErrPossessionCSRMalformed = errors.New("device-attest-01: the certificate request does not follow the possession template")

	// ErrPossessionSignatureInvalid is returned when a possession request's
	// signature does not verify under the key it carries.
	ErrPossessionSignatureInvalid = errors.New("device-attest-01: the possession request signature does not verify")

	// ErrPossessionSigningFailed is returned when the device's key could not
	// sign a possession request.
	ErrPossessionSigningFailed = errors.New("device-attest-01: the possession request could not be signed")

	// ErrPossessionKeyMismatch is returned when a possession request's
	// SubjectPublicKeyInfo is not byte-equal to the key the device attested
	// at the challenge.
	ErrPossessionKeyMismatch = errors.New("device-attest-01: the possession request key is not the attested key")

	// ErrPossessionNonceMismatch is returned when a possession request's UCCS
	// nonce is not SHA-256 of this order's key authorization: the request was
	// signed for some other order.
	ErrPossessionNonceMismatch = errors.New("device-attest-01: the possession request nonce is not this order's challenge")

	// ErrPossessionIdentifierMismatch is returned when the identifiers a
	// possession request names are not exactly the order's identifiers.
	ErrPossessionIdentifierMismatch = errors.New("device-attest-01: the possession request identifiers are not the order's identifiers")
)

// PossessionRequest is what a possession certificate request states.
type PossessionRequest struct {
	// DeviceID is the device identifier the request names, the bytes whose
	// hex is the permanentIdentifier's identifierValue.
	DeviceID []byte

	// Nonce is the UCCS eat_nonce, b = SHA-256(keyAuthorization).
	Nonce []byte

	// PublicKey is the key the request is for.
	PublicKey *ecdsa.PublicKey
}

// Identifier is the ACME identifier the request names its device by.
func (p *PossessionRequest) Identifier() entities.ACMEIdentifier {
	return entities.ACMEIdentifier{Type: PossessionIdentifierType, Value: hex.EncodeToString(p.DeviceID)}
}

// possessionCRI is the CertificationRequestInfo of RFC 2986 section 4.1.
type possessionCRI struct {
	Version    int
	Subject    asn1.RawValue
	PublicKey  asn1.RawValue
	Attributes []possessionAttribute `asn1:"tag:0"`
}

// possessionAttribute is an RFC 2986 Attribute whose values are DER already.
type possessionAttribute struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// possessionCSR is the CertificationRequest of RFC 2986 section 4.2.
type possessionCSR struct {
	Info      asn1.RawValue
	Algorithm pkix.AlgorithmIdentifier
	Signature asn1.BitString
}

// ecdsaSignature is the ECDSA-Sig-Value of RFC 3279 section 2.2.3.
type ecdsaSignature struct {
	R, S *big.Int
}

// emptyName is the DER of an empty RDNSequence.
var emptyName = []byte{0x30, 0x00}

// oidSignatureECDSAWithSHA256 is ecdsa-with-SHA256 (RFC 5758 section 3.2),
// whose AlgorithmIdentifier carries no parameters.
var oidSignatureECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}

// BuildPossessionCRI returns the DER CertificationRequestInfo the possession
// template produces for pub, deviceID and nonce: the bytes the device signs.
func BuildPossessionCRI(pub *ecdsa.PublicKey, deviceID, nonce []byte) ([]byte, error) {
	if pub == nil || pub.Curve != elliptic.P256() {
		return nil, &errs.Detail{Err: ErrPossessionCSRMalformed, Detail: "the key must be ECDSA P-256"}
	}
	if len(deviceID) == 0 {
		return nil, &errs.Detail{Err: ErrPossessionCSRMalformed, Detail: "the device identifier is empty"}
	}
	if len(nonce) != PossessionNonceSize {
		return nil, &errs.Detail{Err: ErrPossessionCSRMalformed, Detail: "the nonce must be SHA-256 of the key authorization"}
	}

	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrPossessionCSRMalformed, Detail: "the key does not encode", Cause: err}
	}
	extensions, err := possessionExtensions(deviceID, nonce)
	if err != nil {
		return nil, err
	}
	extensionsDER, err := asn1.Marshal(extensions)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrPossessionCSRMalformed, Detail: "the extensions do not encode", Cause: err}
	}

	cri, err := asn1.Marshal(possessionCRI{
		Subject:   asn1.RawValue{FullBytes: emptyName},
		PublicKey: asn1.RawValue{FullBytes: spki},
		Attributes: []possessionAttribute{{
			Type:   OIDExtensionRequest,
			Values: []asn1.RawValue{{FullBytes: extensionsDER}},
		}},
	})
	if err != nil {
		return nil, &errs.Joined{Lead: ErrPossessionCSRMalformed, Detail: "the request info does not encode", Cause: err}
	}
	return cri, nil
}

// possessionExtensions returns the template's two extensions, in template
// order: the subjectAltName naming the device, then the UCCS evidence
// carrying the nonce.
func possessionExtensions(deviceID, nonce []byte) ([]pkix.Extension, error) {
	identifier, err := ca.MarshalPermanentIdentifier(hex.EncodeToString(deviceID), nil)
	if err != nil {
		return nil, err
	}
	san, err := ca.BuildSubjectAltName(pkix.Name{}, nil, nil, nil, nil,
		[]ca.OtherName{{TypeID: ca.OIDPermanentIdentifier, Value: identifier}}, nil)
	if err != nil {
		return nil, err
	}
	uccs, err := dice.MarshalUccsEvidence(&dice.ClaimsSet{Nonce: nonce})
	if err != nil {
		return nil, err
	}
	return []pkix.Extension{san, {Id: dice.OIDUccsEvidence, Value: uccs}}, nil
}

// AssemblePossessionCSR wraps a CertificationRequestInfo and the device's
// signature over it into a DER CertificationRequest. signature is a DER
// ECDSA-Sig-Value over SHA-256 of cri.
func AssemblePossessionCSR(cri, signature []byte) ([]byte, error) {
	var info asn1.RawValue
	if rest, err := asn1.Unmarshal(cri, &info); err != nil || len(rest) != 0 {
		return nil, &errs.Detail{Err: ErrPossessionCSRMalformed, Detail: "the request info is not one DER value"}
	}
	var sig ecdsaSignature
	if rest, err := asn1.Unmarshal(signature, &sig); err != nil || len(rest) != 0 {
		return nil, &errs.Detail{Err: ErrPossessionSignatureInvalid, Detail: "the signature is not a DER ECDSA-Sig-Value"}
	}

	csr, err := asn1.Marshal(possessionCSR{
		Info:      asn1.RawValue{FullBytes: cri},
		Algorithm: pkix.AlgorithmIdentifier{Algorithm: oidSignatureECDSAWithSHA256},
		Signature: asn1.BitString{Bytes: signature, BitLength: len(signature) * 8},
	})
	if err != nil {
		return nil, &errs.Joined{Lead: ErrPossessionCSRMalformed, Detail: "the request does not encode", Cause: err}
	}
	return csr, nil
}

// SignPossessionCSR builds the possession request for deviceID and nonce and
// has signer -- the device's key -- sign it: the whole host side of the
// exchange for a device reachable as a crypto.Signer.
func SignPossessionCSR(signer crypto.Signer, deviceID, nonce []byte) ([]byte, error) {
	if signer == nil {
		return nil, &errs.Detail{Err: ErrPossessionSigningFailed, Detail: "no signer"}
	}
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, &errs.Detail{Err: ErrPossessionCSRMalformed, Detail: "the key must be ECDSA P-256"}
	}
	cri, err := BuildPossessionCRI(pub, deviceID, nonce)
	if err != nil {
		return nil, err
	}
	digest := sha256.Sum256(cri)
	signature, err := signer.Sign(rand.Reader, digest[:], crypto.SHA256)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrPossessionSigningFailed, Detail: "the device did not sign the request info", Cause: err}
	}
	return AssemblePossessionCSR(cri, signature)
}

// ParsePossessionCSR reads a possession request back into the values it
// carries, and refuses any request whose CertificationRequestInfo is not
// exactly what BuildPossessionCRI writes for those values. It does not verify
// the signature; VerifyPossessionCSR does.
func ParsePossessionCSR(csr *x509.CertificateRequest) (*PossessionRequest, error) {
	if csr == nil {
		return nil, &errs.Detail{Err: ErrPossessionCSRMalformed, Detail: "no certificate request"}
	}
	if csr.SignatureAlgorithm != x509.ECDSAWithSHA256 {
		return nil, &errs.Detail{Err: ErrPossessionCSRMalformed, Detail: "the signature algorithm is not ecdsa-with-SHA256"}
	}
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, &errs.Detail{Err: ErrPossessionCSRMalformed, Detail: "the key is not ECDSA P-256"}
	}

	deviceID, err := possessionDeviceID(csr.Extensions)
	if err != nil {
		return nil, err
	}
	nonce, err := possessionNonce(csr.Extensions)
	if err != nil {
		return nil, err
	}

	template, err := BuildPossessionCRI(pub, deviceID, nonce)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(template, csr.RawTBSCertificateRequest) {
		return nil, &errs.Detail{Err: ErrPossessionCSRMalformed, Detail: "the request info is not the template's encoding of the values it carries"}
	}
	return &PossessionRequest{DeviceID: deviceID, Nonce: nonce, PublicKey: pub}, nil
}

// possessionDeviceID reads the device identifier out of the request's one
// permanentIdentifier otherName.
func possessionDeviceID(extensions []pkix.Extension) ([]byte, error) {
	others, err := ca.ParseOtherNames(extensions)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrPossessionCSRMalformed, Detail: "the subjectAltName does not parse", Cause: err}
	}
	if len(others) != 1 || !others[0].TypeID.Equal(ca.OIDPermanentIdentifier) {
		return nil, &errs.Detail{Err: ErrPossessionCSRMalformed, Detail: "the subjectAltName must be exactly one permanentIdentifier"}
	}
	identifier, err := ca.ParsePermanentIdentifierExtension(others[0].Value)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrPossessionCSRMalformed, Detail: "the permanentIdentifier does not parse", Cause: err}
	}
	deviceID, err := hex.DecodeString(identifier.IdentifierValue)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrPossessionCSRMalformed, Detail: "the permanentIdentifier is not hex", Cause: err}
	}
	return deviceID, nil
}

// possessionNonce reads the eat_nonce out of the request's UCCS evidence
// extension, through the same parser the challenge verifier uses.
func possessionNonce(extensions []pkix.Extension) ([]byte, error) {
	for _, ext := range extensions {
		if !ext.Id.Equal(dice.OIDUccsEvidence) {
			continue
		}
		claims, err := dice.ParseUccsEvidence(ext.Value)
		if err != nil {
			return nil, &errs.Joined{Lead: ErrPossessionCSRMalformed, Detail: "the UCCS evidence does not parse", Cause: err}
		}
		return claims.Nonce, nil
	}
	return nil, &errs.Detail{Err: ErrPossessionCSRMalformed, Detail: "no UCCS evidence extension"}
}

// VerifyPossessionCSR runs the four finalize checks a DICE device's
// possession request must pass, each refusing with its own error:
//
//  1. the request signature verifies       ErrPossessionSignatureInvalid
//  2. its key is the attested key           ErrPossessionKeyMismatch
//  3. its nonce is this order's challenge   ErrPossessionNonceMismatch
//  4. its identifiers are the order's       ErrPossessionIdentifierMismatch
//
// A request that is not the possession template at all is
// ErrPossessionCSRMalformed, and none of the checks run.
func (v *VerifiedAttestation) VerifyPossessionCSR(csr *x509.CertificateRequest, orderIdentifiers []entities.ACMEIdentifier) error {
	if v == nil {
		return ErrNoVerifiedAttestation
	}
	if v.Format != FormatDICE {
		return &errs.Detail{Err: ErrKeyBindingUnavailable, Detail: string(v.Format) + " does not prove possession through a possession request"}
	}
	leaf, err := v.verifiedLeaf()
	if err != nil {
		return err
	}
	request, err := ParsePossessionCSR(csr)
	if err != nil {
		return err
	}

	if err := csr.CheckSignature(); err != nil {
		return &errs.Joined{Lead: ErrPossessionSignatureInvalid, Detail: "under the request's own key", Cause: err}
	}
	if !bytes.Equal(csr.RawSubjectPublicKeyInfo, leaf.RawSubjectPublicKeyInfo) {
		return ErrPossessionKeyMismatch
	}
	if subtle.ConstantTimeCompare(request.Nonce, DICENonce(v.KeyAuthorization)) != 1 {
		return ErrPossessionNonceMismatch
	}
	if len(orderIdentifiers) != 1 || orderIdentifiers[0] != request.Identifier() {
		return &errs.Detail{
			Err:    ErrPossessionIdentifierMismatch,
			Detail: "the request names only " + request.Identifier().Type + " " + request.Identifier().Value,
		}
	}
	return nil
}
