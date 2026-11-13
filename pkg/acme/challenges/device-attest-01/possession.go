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
	"slices"
	"strconv"

	"github.com/fxamacker/cbor/v2"

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
// CertificationRequestInfo it fills in from a fixed template. Its inputs are
// the attested key, the claims set its alias certificate carries, and one
// host-supplied value, b = SHA-256(keyAuthorization), the same b the
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
//	        identifierValue = lower-case hex(ueid), no assigner
//	    tcg-dice-UCCS-evidence, critical
//	      uccs = the alias certificate's claims set with eat_nonce = b:
//	        CBOR { 10 (eat_nonce): b, 256 (ueid), 273 (measurements) }
//	  } } }
//	}
//
// The binding is the UCCS nonce inside extensionRequest, where any DICE
// verifier already looks for a challenge, and not challengePassword. The
// identifierValue is the hex of the claims set's own ueid, so the name the
// request asks for and the evidence it carries cannot disagree. The UCCS
// extension is critical, as dice.CreateUccsEvidenceExtension writes it on
// the alias certificate; it is evidence about this request, and the CA copies
// no requested extension onto the certificate.
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

	// ErrPossessionMeasurementsShape is returned, with
	// ErrPossessionCSRMalformed, when a possession set's measurements claim
	// (273) is not the one shape that carries the application evidence.
	ErrPossessionMeasurementsShape = errors.New("device-attest-01: the measurements claim is not the application evidence shape")

	// ErrPossessionApplicationEvidenceMismatch is a possession request whose
	// application evidence is not the reference registered for the device,
	// or a device the policy requires a reference for that has none.
	ErrPossessionApplicationEvidenceMismatch = errors.New("device-attest-01: the possession request application evidence is not the device's registered reference")
)

// PossessionRequest is what a possession certificate request states.
type PossessionRequest struct {
	// Claims is the claims set the UCCS evidence carries: the alias
	// certificate's claims, with Nonce the eat_nonce b =
	// SHA-256(keyAuthorization).
	Claims *dice.ClaimsSet

	// DeviceID is the claims set's ueid, the bytes whose hex is the
	// permanentIdentifier's identifierValue.
	DeviceID []byte

	// ApplicationEvidence is the 32-byte hash-entry value the measurements
	// claim carries: the application evidence, opaque to go-xkms.
	ApplicationEvidence []byte

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
// template produces for pub, the alias certificate's claims and nonce: the
// bytes the device signs. claims.Nonce is ignored; the request carries nonce
// in its place.
func BuildPossessionCRI(pub *ecdsa.PublicKey, claims *dice.ClaimsSet, nonce []byte) ([]byte, error) {
	cri, _, err := possessionTemplate(pub, claims, nonce)
	return cri, err
}

// possessionTemplate writes the CertificationRequestInfo and returns it with
// the values it carries: claims, the ueid it names the device by, the
// application evidence and pub.
func possessionTemplate(pub *ecdsa.PublicKey, claims *dice.ClaimsSet, nonce []byte) ([]byte, *PossessionRequest, error) {
	if pub == nil || pub.Curve != elliptic.P256() {
		return nil, nil, &errs.Detail{Err: ErrPossessionCSRMalformed, Detail: "the key must be ECDSA P-256"}
	}
	if len(nonce) != PossessionNonceSize {
		return nil, nil, &errs.Detail{Err: ErrPossessionCSRMalformed, Detail: "the nonce must be SHA-256 of the key authorization"}
	}
	deviceID, evidence, err := possessionSet(claims)
	if err != nil {
		return nil, nil, err
	}

	spki, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, nil, &errs.Joined{Lead: ErrPossessionCSRMalformed, Detail: "the key does not encode", Cause: err}
	}
	extensions, err := possessionExtensions(deviceID, &dice.ClaimsSet{Nonce: nonce, Other: claims.Other})
	if err != nil {
		return nil, nil, err
	}
	extensionsDER, err := asn1.Marshal(extensions)
	if err != nil {
		return nil, nil, &errs.Joined{Lead: ErrPossessionCSRMalformed, Detail: "the extensions do not encode", Cause: err}
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
		return nil, nil, &errs.Joined{Lead: ErrPossessionCSRMalformed, Detail: "the request info does not encode", Cause: err}
	}
	return cri, &PossessionRequest{Claims: claims, DeviceID: deviceID, ApplicationEvidence: evidence, PublicKey: pub}, nil
}

// possessionSet returns the ueid and the application evidence of a claims set
// the template can carry: exactly the ueid and measurements claims beside the
// nonce, the claims set a template-minting device's alias certificate
// carries, its measurements in the one shape applicationEvidence reads.
func possessionSet(claims *dice.ClaimsSet) (deviceID, evidence []byte, err error) {
	if claims == nil {
		return nil, nil, &errs.Detail{Err: ErrPossessionCSRMalformed, Detail: "no claims set"}
	}
	ueid, err := claims.Ueid()
	if err != nil {
		return nil, nil, &errs.Joined{Lead: ErrPossessionCSRMalformed, Detail: "the claims set names no ueid", Cause: err}
	}
	measurements, present := claims.Other[dice.ClaimMeasurements]
	if !present {
		return nil, nil, &errs.Detail{Err: ErrPossessionCSRMalformed, Detail: "the claims set carries no measurements claim"}
	}
	if len(claims.Other) != 2 {
		return nil, nil, &errs.Detail{Err: ErrPossessionCSRMalformed, Detail: "the claims set carries a claim beside the nonce, ueid and measurements"}
	}
	evidence, err = applicationEvidence(measurements)
	if err != nil {
		return nil, nil, err
	}
	return ueid, evidence, nil
}

// The measurements claim
//
// A possession set's measurements claim (273) has one shape, fixed by go-xkms
// (docs/SPEC.md, acme-issuance) and pinned by the vector in
// possession_test.go. RFC 9711 section 4.2.16 makes the claim a list of
// measurements-format pairs [content-type, content-format] and requires a
// CoSWID there to be an evidence CoSWID (RFC 9393), untagged:
//
//	273: [ [ 258,                           / CoAP content-format of CoSWID /
//	         << {                           / evidence CoSWID /
//	           0: tstr / bstr .size 16,     / tag-id /
//	           1: tstr,                     / software-name /
//	           2: { 31: tstr, 33: role },   / entity: entity-name, tag-creator /
//	           3: { 17: {                   / evidence: one file /
//	             7: [1, h'<32 bytes>'],     / hash: sha-256 hash-entry /
//	             24: "app" } },             / fs-name /
//	           12: int                      / tag-version /
//	         } >> ] ]
//
// The 32 bytes are the application evidence, opaque to go-xkms. The tag-id,
// tag-version, software-name and entity are the producer's (RFC 9393 section
// 2.3, CA m463): they are checked for presence and type, never for value. The
// shape holds no other field, and the claim and its CoSWID are each accepted
// only in RFC 8949 core deterministic encoding.

// The CoSWID keys (RFC 9393 section 6.1) and values the shape uses.
const (
	coapContentFormatCoSWID = 258
	coswidTagID             = 0
	coswidSoftwareName      = 1
	coswidEntity            = 2
	coswidEvidence          = 3
	coswidHash              = 7
	coswidTagVersion        = 12
	coswidFile              = 17
	coswidFsName            = 24
	coswidEntityName        = 31
	coswidRole              = 33
	coswidRoleTagCreator    = 1

	// coswidTagIDSize is the size of a byte-string tag-id, a UUID (RFC 9393
	// section 2.3).
	coswidTagIDSize = 16

	// hashAlgSHA256 is sha-256's Named Information Hash Algorithm
	// Registry identifier, the hash-alg-id of an RFC 9393 hash-entry.
	hashAlgSHA256 = 1

	// applicationFileName is the fs-name of the shape's one file.
	applicationFileName = "app"
)

// measurementsFormat is RFC 9711's measurements-format pair.
type measurementsFormat struct {
	_             struct{} `cbor:",toarray"`
	ContentType   uint64
	ContentFormat []byte
}

// hashEntry is RFC 9393's hash-entry.
type hashEntry struct {
	_         struct{} `cbor:",toarray"`
	Algorithm int64
	Value     []byte
}

// measurementsDecMode refuses what the shape's encoding never contains: a key
// twice, an indefinite length, a tag, invalid UTF-8.
var measurementsDecMode = mustMeasurementsDecMode(cbor.DecOptions{
	DupMapKey:   cbor.DupMapKeyEnforcedAPF,
	IndefLength: cbor.IndefLengthForbidden,
	TagsMd:      cbor.TagsForbidden,
	UTF8:        cbor.UTF8RejectInvalid,
})

// measurementsEncMode re-encodes a decoded claim in RFC 8949 core
// deterministic encoding, the one encoding the claim is accepted in.
var measurementsEncMode = mustMeasurementsEncMode(cbor.CoreDetEncOptions())

func mustMeasurementsDecMode(opts cbor.DecOptions) cbor.DecMode {
	mode, err := opts.DecMode()
	if err != nil {
		panic("device-attest-01: invalid CBOR decode options: " + err.Error())
	}
	return mode
}

func mustMeasurementsEncMode(opts cbor.EncOptions) cbor.EncMode {
	mode, err := opts.EncMode()
	if err != nil {
		panic("device-attest-01: invalid CBOR encode options: " + err.Error())
	}
	return mode
}

// applicationEvidence reads the application evidence out of a measurements
// claim, and refuses a claim that is not the shape.
func applicationEvidence(measurements []byte) ([]byte, error) {
	if err := deterministic(measurements, "the claim"); err != nil {
		return nil, err
	}
	var entries []cbor.RawMessage
	if err := measurementsDecMode.Unmarshal(measurements, &entries); err != nil {
		return nil, measurementsShapeError("the claim is not a list", err)
	}
	if len(entries) != 1 {
		return nil, measurementsShapeError("the claim holds "+strconv.Itoa(len(entries))+" entries, not one", nil)
	}
	var format measurementsFormat
	if err := measurementsDecMode.Unmarshal(entries[0], &format); err != nil {
		return nil, measurementsShapeError("the entry is not a content-type and a byte string", err)
	}
	if format.ContentType != coapContentFormatCoSWID {
		return nil, measurementsShapeError("the content-type is "+strconv.FormatUint(format.ContentType, 10)+", not CoSWID's 258", nil)
	}
	if err := deterministic(format.ContentFormat, "the payload"); err != nil {
		return nil, err
	}
	var coswid map[int64]cbor.RawMessage
	if err := measurementsDecMode.Unmarshal(format.ContentFormat, &coswid); err != nil {
		return nil, measurementsShapeError("the payload is not an untagged CoSWID", err)
	}
	file, err := evidenceFile(coswid)
	if err != nil {
		return nil, err
	}
	if err := producerFields(coswid); err != nil {
		return nil, err
	}
	return fileEvidence(file)
}

// deterministic refuses data that is not one CBOR item in RFC 8949 core
// deterministic encoding: data must be what re-encoding its decoding writes.
func deterministic(data []byte, what string) error {
	var decoded any
	if err := measurementsDecMode.Unmarshal(data, &decoded); err != nil {
		return measurementsShapeError(what+" is not one CBOR item", err)
	}
	encoded, err := measurementsEncMode.Marshal(decoded)
	if err != nil {
		return measurementsShapeError(what+" does not re-encode", err)
	}
	if !bytes.Equal(encoded, data) {
		return measurementsShapeError(what+" is not in core deterministic encoding", nil)
	}
	return nil
}

// onlyFields refuses a map that holds a key other than keys; what names the
// map in the error.
func onlyFields(m map[int64]cbor.RawMessage, what string, keys ...int64) error {
	for key := range m {
		if !slices.Contains(keys, key) {
			return measurementsShapeError(what+" holds field "+strconv.FormatInt(key, 10)+", which the shape does not carry", nil)
		}
	}
	return nil
}

// decodeField decodes the field of m at key into a Go value of the CBOR type
// it holds, and refuses a missing field; name names it in the error.
func decodeField(m map[int64]cbor.RawMessage, key int64, name string) (any, error) {
	raw, present := m[key]
	if !present {
		return nil, measurementsShapeError("the "+name+" is missing", nil)
	}
	var value any
	if err := measurementsDecMode.Unmarshal(raw, &value); err != nil {
		return nil, measurementsShapeError("the "+name+" does not decode", err)
	}
	return value, nil
}

// producerFields checks the fields RFC 9393 section 2.3 requires of every
// CoSWID by their CBOR type only: tag-id (text or a 16-byte UUID),
// tag-version (an integer), software-name (text) and an entity with the
// tag-creator role. Their values are the producer's (CA m463).
func producerFields(coswid map[int64]cbor.RawMessage) error {
	if err := onlyFields(coswid, "the CoSWID", coswidTagID, coswidSoftwareName, coswidEntity, coswidEvidence, coswidTagVersion); err != nil {
		return err
	}
	tagID, err := decodeField(coswid, coswidTagID, "tag-id")
	if err != nil {
		return err
	}
	switch id := tagID.(type) {
	case string:
	case []byte:
		if len(id) != coswidTagIDSize {
			return measurementsShapeError("the tag-id is "+strconv.Itoa(len(id))+" bytes, not a 16-byte UUID", nil)
		}
	default:
		return measurementsShapeError("the tag-id is neither text nor a byte string", nil)
	}
	tagVersion, err := decodeField(coswid, coswidTagVersion, "tag-version")
	if err != nil {
		return err
	}
	if !isInteger(tagVersion) {
		return measurementsShapeError("the tag-version is not an integer", nil)
	}
	softwareName, err := decodeField(coswid, coswidSoftwareName, "software-name")
	if err != nil {
		return err
	}
	if _, ok := softwareName.(string); !ok {
		return measurementsShapeError("the software-name is not text", nil)
	}
	return tagCreator(coswid[coswidEntity])
}

// tagCreator checks the CoSWID's entity: one entity-entry whose entity-name
// is text and whose role, one role or a list of them, includes tag-creator.
func tagCreator(rawEntity cbor.RawMessage) error {
	if rawEntity == nil {
		return measurementsShapeError("the entity is missing", nil)
	}
	var entity map[int64]cbor.RawMessage
	if err := measurementsDecMode.Unmarshal(rawEntity, &entity); err != nil {
		return measurementsShapeError("the entity is not one entity-entry", err)
	}
	if err := onlyFields(entity, "the entity", coswidEntityName, coswidRole); err != nil {
		return err
	}
	name, err := decodeField(entity, coswidEntityName, "entity-name")
	if err != nil {
		return err
	}
	if _, ok := name.(string); !ok {
		return measurementsShapeError("the entity-name is not text", nil)
	}
	role, err := decodeField(entity, coswidRole, "entity role")
	if err != nil {
		return err
	}
	roles, ok := role.([]any)
	if !ok {
		roles = []any{role}
	}
	creator := false
	for _, r := range roles {
		if _, text := r.(string); !text && !isInteger(r) {
			return measurementsShapeError("the entity role is neither an integer nor text", nil)
		}
		if r == uint64(coswidRoleTagCreator) {
			creator = true
		}
	}
	if !creator {
		return measurementsShapeError("the entity is not the tag-creator", nil)
	}
	return nil
}

// isInteger reports whether a decoded CBOR value is an integer.
func isInteger(value any) bool {
	switch value.(type) {
	case uint64, int64:
		return true
	}
	return false
}

// evidenceFile returns the one file-entry of an evidence CoSWID. RFC 9393's
// file is one-or-more<file-entry>: one entry as itself, more as a list.
func evidenceFile(coswid map[int64]cbor.RawMessage) (map[int64]cbor.RawMessage, error) {
	rawEvidence, present := coswid[coswidEvidence]
	if !present {
		return nil, measurementsShapeError("the payload is not an evidence CoSWID", nil)
	}
	var evidence map[int64]cbor.RawMessage
	if err := measurementsDecMode.Unmarshal(rawEvidence, &evidence); err != nil {
		return nil, measurementsShapeError("the evidence is not a map", err)
	}
	if err := onlyFields(evidence, "the evidence", coswidFile); err != nil {
		return nil, err
	}
	rawFile, present := evidence[coswidFile]
	if !present {
		return nil, measurementsShapeError("the evidence holds no file", nil)
	}
	var file map[int64]cbor.RawMessage
	if err := measurementsDecMode.Unmarshal(rawFile, &file); err != nil {
		return nil, measurementsShapeError("the evidence does not hold exactly one file", err)
	}
	if err := onlyFields(file, "the file", coswidFsName, coswidHash); err != nil {
		return nil, err
	}
	return file, nil
}

// fileEvidence returns the hash-entry value of the shape's one file.
func fileEvidence(file map[int64]cbor.RawMessage) ([]byte, error) {
	name, err := decodeField(file, coswidFsName, "file's fs-name")
	if err != nil {
		return nil, err
	}
	if name != applicationFileName {
		return nil, measurementsShapeError("the file's fs-name is not \""+applicationFileName+"\"", nil)
	}
	var hash hashEntry
	if err := measurementsDecMode.Unmarshal(file[coswidHash], &hash); err != nil {
		return nil, measurementsShapeError("the file's hash is not a hash-entry", err)
	}
	if hash.Algorithm != hashAlgSHA256 {
		return nil, measurementsShapeError("the file's hash algorithm is not sha-256", nil)
	}
	if len(hash.Value) != sha256.Size {
		return nil, measurementsShapeError("the file's digest is "+strconv.Itoa(len(hash.Value))+" bytes, not 32", nil)
	}
	return hash.Value, nil
}

// measurementsShapeError reports a measurements claim that is not the shape,
// for the reason detail names and, when the claim did not decode, the
// decoder's cause. It is a malformed possession request.
func measurementsShapeError(detail string, cause error) error {
	malformed := ErrPossessionCSRMalformed
	if cause != nil {
		malformed = &errs.Joined{Lead: ErrPossessionCSRMalformed, Cause: cause}
	}
	return &errs.Joined{Lead: ErrPossessionMeasurementsShape, Detail: detail, Cause: malformed}
}

// possessionExtensions returns the template's two extensions, in template
// order: the subjectAltName naming the device, then the UCCS evidence
// carrying the claims.
func possessionExtensions(deviceID []byte, claims *dice.ClaimsSet) ([]pkix.Extension, error) {
	identifier, err := ca.MarshalPermanentIdentifier(hex.EncodeToString(deviceID), nil)
	if err != nil {
		return nil, err
	}
	san, err := ca.BuildSubjectAltName(pkix.Name{}, nil, nil, nil, nil,
		[]ca.OtherName{{TypeID: ca.OIDPermanentIdentifier, Value: identifier}}, nil)
	if err != nil {
		return nil, err
	}
	uccs, err := dice.CreateUccsEvidenceExtension(claims)
	if err != nil {
		return nil, &errs.Joined{Lead: ErrPossessionCSRMalformed, Detail: "the claims set does not encode", Cause: err}
	}
	return []pkix.Extension{san, uccs}, nil
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

// SignPossessionCSR builds the possession request for the alias certificate's
// claims and nonce and has signer -- the device's key -- sign it: the whole
// host side of the exchange for a device reachable as a crypto.Signer.
func SignPossessionCSR(signer crypto.Signer, claims *dice.ClaimsSet, nonce []byte) ([]byte, error) {
	if signer == nil {
		return nil, &errs.Detail{Err: ErrPossessionSigningFailed, Detail: "no signer"}
	}
	pub, ok := signer.Public().(*ecdsa.PublicKey)
	if !ok {
		return nil, &errs.Detail{Err: ErrPossessionCSRMalformed, Detail: "the key must be ECDSA P-256"}
	}
	cri, err := BuildPossessionCRI(pub, claims, nonce)
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
// exactly what BuildPossessionCRI writes for those values. The rebuild
// starts from the whole claims set the request carries, so every claim, the
// subjectAltName and both criticalities are covered by the comparison. It
// does not verify the signature; VerifyPossessionCSR does.
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

	claims, err := possessionClaims(csr.Extensions)
	if err != nil {
		return nil, err
	}
	template, request, err := possessionTemplate(pub, claims, claims.Nonce)
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(template, csr.RawTBSCertificateRequest) {
		return nil, &errs.Detail{Err: ErrPossessionCSRMalformed, Detail: "the request info is not the template's encoding of the values it carries"}
	}
	return request, nil
}

// possessionClaims reads the claims set out of the request's UCCS evidence
// extension, through the same parser the challenge verifier uses.
func possessionClaims(extensions []pkix.Extension) (*dice.ClaimsSet, error) {
	for _, ext := range extensions {
		if !ext.Id.Equal(dice.OIDUccsEvidence) {
			continue
		}
		claims, err := dice.ParseUccsEvidence(ext.Value)
		if err != nil {
			return nil, &errs.Joined{Lead: ErrPossessionCSRMalformed, Detail: "the UCCS evidence does not parse", Cause: err}
		}
		return claims, nil
	}
	return nil, &errs.Detail{Err: ErrPossessionCSRMalformed, Detail: "no UCCS evidence extension"}
}

// VerifyPossessionCSR runs the five finalize checks a DICE device's
// possession request must pass, each refusing with its own error:
//
//  1. the request signature verifies       ErrPossessionSignatureInvalid
//  2. its key is the attested key           ErrPossessionKeyMismatch
//  3. its nonce is this order's challenge   ErrPossessionNonceMismatch
//  4. its identifiers are the order's       ErrPossessionIdentifierMismatch
//  5. its application evidence is           ErrPossessionApplicationEvidenceMismatch
//     applicationReference, the device's registered reference
//     (VerifiedAttestation.ApplicationReference); nil skips only this check
//
// A request that is not the possession template at all is
// ErrPossessionCSRMalformed, and none of the checks run.
func (v *VerifiedAttestation) VerifyPossessionCSR(csr *x509.CertificateRequest, orderIdentifiers []entities.ACMEIdentifier, applicationReference []byte) error {
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
	if subtle.ConstantTimeCompare(request.Claims.Nonce, DICENonce(v.KeyAuthorization)) != 1 {
		return ErrPossessionNonceMismatch
	}
	if len(orderIdentifiers) != 1 || orderIdentifiers[0] != request.Identifier() {
		return &errs.Detail{
			Err:    ErrPossessionIdentifierMismatch,
			Detail: "the request names only " + request.Identifier().Type + " " + request.Identifier().Value,
		}
	}
	// A nil reference is a device the registry's policy admits without one
	// (VerifiedAttestation.ApplicationReference); any other value, of any
	// length, must be exactly the request's evidence.
	if applicationReference != nil && subtle.ConstantTimeCompare(request.ApplicationEvidence, applicationReference) != 1 {
		return ErrPossessionApplicationEvidenceMismatch
	}
	return nil
}
