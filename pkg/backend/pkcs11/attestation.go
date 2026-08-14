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

//go:build pkcs11

package pkcs11

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/errs"
	"github.com/miekg/pkcs11"

	"github.com/jeremyhahn/go-xkms/pkg/attestation"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// DeviceAttestationKeyLabel is the CKA_LABEL (equivalently CKA_ID) under which
// a token publishes the private key it uses to attest other keys, and the
// X.509 certificate that gives that key its provenance.
//
// PKCS#11 defines no standard object for a device attestation key: the
// specification has no notion of "the key that speaks for this token". Vendors
// therefore expose it under vendor-specific labels, or not at all. This
// constant is the one label go-xkms looks for, so a token can attest exactly
// when its manufacturer (or the operator, during provisioning under the
// Security Officer) has published the device key and its certificate under
// this label. Tokens that have not are refused with ErrNoDeviceAttestationKey
// rather than being given a signature from some other key, which would be a
// lie about who is vouching for the attested key.
const DeviceAttestationKeyLabel = "device-attestation-key"

const (
	// attestationFormat is the value written to AttestationStatement.Format and
	// into the signed body, so a verifier cannot be tricked into interpreting a
	// statement of one format under the rules of another.
	attestationFormat = "pkcs11"

	// attestationInfoVersion is the version of the signed ASN.1 body. It is
	// inside the signature, so the encoding a statement was produced under
	// cannot be changed by an attacker without invalidating the signature.
	attestationInfoVersion = 1

	// maxDeviceChainDepth bounds certificate chain construction from the token's
	// own certificate objects. Certificates on a token are attacker-influenced
	// on any token that permits object creation, so chain building must
	// terminate even if the objects form a cycle.
	maxDeviceChainDepth = 8

	// maxTokenCertificates bounds how many CKO_CERTIFICATE objects are read
	// while looking for issuers of the device certificate.
	maxTokenCertificates = 64
)

var (
	// ErrHSMNotInitialized is returned when attestation is attempted before the
	// backend has a PKCS#11 context and session pool (i.e. before Login).
	ErrHSMNotInitialized = errors.New("pkcs11: HSM not initialized")

	// ErrAttestationUnsupported is returned when the device cannot be identified
	// well enough to attest anything about it.
	ErrAttestationUnsupported = errors.New("pkcs11: HSM does not support key attestation")

	// ErrNoDeviceAttestationKey is returned when the token holds no device
	// attestation key. This is the honest outcome for a token that cannot
	// attest -- SoftHSM2 is the common example, because a software token has no
	// manufacturer-installed key and no hardware boundary to vouch for.
	// AttestKey fails with this error rather than returning a statement signed
	// by anything else.
	ErrNoDeviceAttestationKey = errors.New("pkcs11: token holds no device attestation key: this token cannot attest keys")

	// ErrDeviceCertificateNotFound is returned when the device attestation key
	// has no X.509 certificate on the token. Attestation still proceeds, but the
	// resulting statement carries an empty certificate chain and therefore
	// proves only that some key on this token signed it -- not that the token is
	// a genuine device from a known manufacturer.
	ErrDeviceCertificateNotFound = errors.New("pkcs11: token holds no device identity certificate")

	// ErrAttestedKeyNotFound is returned when the key named by the caller does
	// not exist on the token.
	ErrAttestedKeyNotFound = errors.New("pkcs11: attested key not found on token")

	// ErrAttestedKeyPublicMissing is returned when a private key exists but the
	// token exposes neither a public key object nor a certificate from which the
	// public key could be recovered. There is then nothing to attest to, because
	// a verifier has no key to bind the statement to.
	ErrAttestedKeyPublicMissing = errors.New("pkcs11: attested key has no public part on the token")

	// ErrUnsupportedAttestingKey is returned when the device attestation key uses
	// an algorithm this backend cannot produce a verifiable signature with.
	ErrUnsupportedAttestingKey = errors.New("pkcs11: unsupported device attestation key algorithm")

	// ErrMalformedAttestationInfo is returned when attestation data cannot be
	// encoded or does not decode to a well-formed statement body.
	ErrMalformedAttestationInfo = errors.New("pkcs11: malformed attestation data")
)

// AttestationInfo is the signed body of a PKCS#11 attestation statement: the
// exact ASN.1 DER that AttestationStatement.Signature covers and that
// AttestationStatement.AttestationData carries.
//
// DER is used rather than an ad-hoc concatenation because a verifier has to
// recover the individual claims from the same bytes the signature was computed
// over. Every field is length-delimited and tagged, so no two distinct claim
// sets can produce the same encoding -- an attacker cannot, for example, shift
// bytes between the key identifier and the nonce to make one statement read as
// another. DER is also canonical, so re-encoding a parsed body reproduces the
// signed bytes exactly.
//
// ASN.1 definition:
//
//	PKCS11AttestationInfo ::= SEQUENCE {
//	    version      INTEGER,
//	    format       UTF8String,
//	    keyID        UTF8String,
//	    attestedKey  SubjectPublicKeyInfo,
//	    device       DeviceInfo,
//	    properties   KeyProperties,
//	    timestamp    GeneralizedTime,
//	    nonce        OCTET STRING }
type AttestationInfo struct {
	// Version is the version of this structure (attestationInfoVersion).
	Version int

	// Format is the attestation format, always "pkcs11" for this backend.
	Format string `asn1:"utf8"`

	// KeyID is the token's CKA_ID for the attested key.
	KeyID string `asn1:"utf8"`

	// AttestedKey is the DER SubjectPublicKeyInfo of the attested key, held
	// verbatim so the signed bytes bind the exact key encoding a verifier sees.
	AttestedKey asn1.RawValue

	// Device identifies the token that produced the statement.
	Device DeviceInfo

	// Properties are the PKCS#11 attributes that make the statement worth
	// anything: whether the key was generated on the token and whether it can
	// leave it.
	Properties KeyProperties

	// Timestamp is when the statement was produced, truncated to whole seconds
	// so that re-encoding a parsed body is byte-identical.
	Timestamp time.Time `asn1:"generalized"`

	// Nonce is the caller's freshness challenge, empty when none was supplied.
	Nonce []byte
}

// DeviceInfo identifies the token, as reported by C_GetTokenInfo, plus the
// PKCS#11 module the daemon loaded to reach it. A verifier uses these fields to
// decide whether the attesting device is one it is willing to trust; they are
// inside the signature so a relaying party cannot rewrite them.
type DeviceInfo struct {
	// Manufacturer is CK_TOKEN_INFO.manufacturerID.
	Manufacturer string `asn1:"utf8"`

	// Model is CK_TOKEN_INFO.model.
	Model string `asn1:"utf8"`

	// Serial is CK_TOKEN_INFO.serialNumber.
	Serial string `asn1:"utf8"`

	// TokenLabel is CK_TOKEN_INFO.label.
	TokenLabel string `asn1:"utf8"`

	// Library is the filesystem path of the PKCS#11 module. It is a claim about
	// the host, not about the device, and a verifier must not treat it as
	// evidence of anything.
	Library string `asn1:"utf8"`
}

// KeyProperties are the PKCS#11 object attributes of the attested private key.
//
// These carry the substance of a key attestation. CKA_LOCAL true means the
// token generated the key itself, so no copy ever existed outside it.
// CKA_NEVER_EXTRACTABLE true means no wrapped copy has ever been permitted to
// leave. A statement whose Local or NeverExtractable is false is still a
// truthful statement -- it simply does not claim hardware exclusivity, and a
// relying party that requires hardware exclusivity must reject it.
type KeyProperties struct {
	// Local reports CKA_LOCAL: the key was generated on this token.
	Local bool

	// Sensitive reports CKA_SENSITIVE: the plaintext key value cannot be read.
	Sensitive bool

	// AlwaysSensitive reports CKA_ALWAYS_SENSITIVE: the key has been sensitive
	// for its entire life, so no window existed in which it could be read.
	AlwaysSensitive bool

	// NeverExtractable reports CKA_NEVER_EXTRACTABLE: the key has never been
	// permitted to be wrapped out of the token.
	NeverExtractable bool

	// Extractable reports CKA_EXTRACTABLE: the key may currently be wrapped out
	// of the token under another key.
	Extractable bool
}

// AttestedPublicKey parses the SubjectPublicKeyInfo carried in the signed body.
func (i *AttestationInfo) AttestedPublicKey() (crypto.PublicKey, error) {
	pub, err := x509.ParsePKIXPublicKey(i.AttestedKey.FullBytes)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "pkcs11: parse attested public key", Err: err}
	}
	return pub, nil
}

// ParseAttestationInfo decodes the signed body of a PKCS#11 attestation
// statement, i.e. AttestationStatement.AttestationData.
//
// Decoding proves nothing on its own. A verifier must first check the signature
// over these exact bytes against a device key it trusts, and only then read the
// claims out of them.
func ParseAttestationInfo(der []byte) (*AttestationInfo, error) {
	if len(der) == 0 {
		return nil, &errs.Detail{Err: ErrMalformedAttestationInfo, Detail: "empty attestation data"}
	}

	info := &AttestationInfo{}
	rest, err := asn1.Unmarshal(der, info)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "pkcs11: parse attestation data", Err: err}
	}
	if len(rest) > 0 {
		return nil, &errs.Detail{Err: ErrMalformedAttestationInfo, Detail: fmt.Sprintf("%d trailing bytes", len(rest))}
	}
	if info.Version != attestationInfoVersion {
		return nil, &errs.Detail{Err: ErrMalformedAttestationInfo, Detail: fmt.Sprintf("unsupported version %d", info.Version)}
	}
	if info.Format != attestationFormat {
		return nil, &errs.Detail{Err: ErrMalformedAttestationInfo, Detail: fmt.Sprintf("unexpected format %q", info.Format)}
	}

	return info, nil
}

// AttestKey produces a statement, signed by the token's device attestation key,
// that the named key exists on this token with the PKCS#11 properties reported
// in the statement.
//
// What a verifier may conclude from a returned statement:
//
//   - The signature was produced by the private key of
//     AttestationStatement.AttestingKeyPublic. That key never leaves the token,
//     so the statement was produced by the token.
//   - The claims in AttestationData -- attested public key, key identifier,
//     token identity, CKA_LOCAL / CKA_SENSITIVE / CKA_NEVER_EXTRACTABLE, the
//     timestamp and the caller's nonce -- are what the token asserted, because
//     they are covered by that signature.
//
// What a verifier may NOT conclude:
//
//   - Anything at all, until it has checked CertificateChain to an anchor it
//     trusts. A signature verifies against whatever key is carried in the same
//     statement; that is circular. Only a chain from AttestingKeyPublic to a
//     manufacturer (or operator) root turns "some key signed this" into "this
//     device signed this". When the token holds no device certificate the chain
//     is empty and ClaimData["device_certificate"] is "absent"; such a statement
//     must be treated as unauthenticated evidence.
//   - That the key is hardware-exclusive unless Properties.Local and
//     Properties.NeverExtractable are both true.
//
// Parameters:
//   - attrs: attributes identifying the key to attest
//   - nonce: optional challenge bound into the signed body for freshness
//
// Returns *attestation.AttestationStatement on success, or a typed error:
// ErrHSMNotInitialized, ErrAttestationUnsupported, ErrNoDeviceAttestationKey
// (the token cannot attest), or ErrAttestedKeyNotFound.
func (b *Backend) AttestKey(ctx context.Context, attrs *types.KeyAttributes, nonce []byte) (interface{}, error) {
	if attrs == nil {
		return nil, &errs.Wrapped{Msg: "pkcs11: invalid key attributes", Err: ErrInvalidKeyAttributes}
	}
	if err := attrs.Validate(); err != nil {
		return nil, &errs.Wrapped{Msg: "pkcs11: invalid key attributes", Err: err}
	}
	// A cancelled caller gets no token work done on its behalf. The check is nil
	// tolerant so a caller that forgot the context gets an attestation rather
	// than a panic.
	if ctx != nil {
		if err := ctx.Err(); err != nil {
			return nil, &errs.Wrapped{Msg: "pkcs11: attestation cancelled", Err: err}
		}
	}

	b.mu.Lock()
	defer b.mu.Unlock()

	if b.pool == nil {
		return nil, ErrHSMNotInitialized
	}

	supportsAttestation, err := b.supportsAttestation()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "pkcs11: failed to check attestation support", Err: err}
	}
	if !supportsAttestation {
		return nil, ErrAttestationUnsupported
	}

	// The device key is resolved before anything else: if the token cannot sign
	// an attestation, no work done afterwards could produce a valid one, and no
	// statement must be emitted.
	device, err := b.deviceAttestationKey()
	if err != nil {
		return nil, err
	}

	keyObj, err := b.findKeyObject(attrs)
	if err != nil {
		return nil, err
	}

	pubKey, err := b.getPublicKeyFromObject(keyObj)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "pkcs11: failed to get public key", Err: err}
	}

	properties, err := b.keyProperties(keyObj.private)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "pkcs11: failed to read attested key properties", Err: err}
	}

	deviceInfo, err := b.tokenDeviceInfo()
	if err != nil {
		return nil, &errs.Wrapped{Msg: "pkcs11: failed to read token identity", Err: err}
	}

	// A missing device certificate is a legitimate token configuration, not a
	// failure: the statement is still signed by the token, it simply cannot be
	// chained to a manufacturer. Any other lookup failure is fatal, because it
	// means the chain that is present could not be read correctly.
	deviceCert, certChain, err := b.getDeviceIdentityCertificate()
	if err != nil && !errors.Is(err, ErrDeviceCertificateNotFound) {
		return nil, &errs.Wrapped{Msg: "pkcs11: failed to read device identity certificate", Err: err}
	}
	if certChain == nil {
		certChain = []*x509.Certificate{}
	}

	attestData := &attestationData{
		KeyID:      string(keyObj.id),
		KeyPublic:  pubKey,
		Device:     deviceInfo,
		Properties: properties,
		Timestamp:  time.Now().UTC().Truncate(time.Second),
		Nonce:      nonce,
	}

	encoded, err := encodeAttestationData(attestData)
	if err != nil {
		return nil, err
	}

	signature, err := b.signAttestationData(device, encoded)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "pkcs11: failed to sign attestation", Err: err}
	}

	deviceCertificatePresence := []byte("absent")
	if deviceCert != nil {
		deviceCertificatePresence = []byte("present")
	}

	stmt := &attestation.AttestationStatement{
		Format:                attestationFormat,
		AttestingKeyAlgorithm: device.keyAlgorithm,
		AttestingKeyPublic:    device.publicKey,
		Signature:             signature,
		SignatureAlgorithm:    device.signatureAlgorithm,
		CertificateChain:      certChain,
		AttestedKeyPublic:     pubKey,
		AttestationData:       encoded,
		CreatedAt:             attestData.Timestamp.Format(time.RFC3339),
		Backend:               attestationFormat,
		Nonce:                 nonce,
		// HSMs have no platform configuration registers; the map is empty rather
		// than nil so a verifier iterating it needs no nil check.
		PCRValues: make(map[uint32][]byte),
		ClaimData: map[string][]byte{
			"hsm_manufacturer":      []byte(deviceInfo.Manufacturer),
			"hsm_model":             []byte(deviceInfo.Model),
			"hsm_serial":            []byte(deviceInfo.Serial),
			"token_label":           []byte(deviceInfo.TokenLabel),
			"library":               []byte(deviceInfo.Library),
			"key_cn":                []byte(attrs.CN),
			"key_id":                keyObj.id,
			"key_local":             []byte(boolClaim(properties.Local)),
			"key_never_extractable": []byte(boolClaim(properties.NeverExtractable)),
			"device_certificate":    deviceCertificatePresence,
		},
	}

	return stmt, nil
}

// boolClaim renders a boolean claim value for ClaimData, which carries opaque
// bytes rather than typed values.
func boolClaim(value bool) string {
	if value {
		return "true"
	}
	return "false"
}

// attestationData is the in-memory form of the facts being attested, before DER
// encoding. It exists so that the encoding is produced in exactly one place.
type attestationData struct {
	// KeyID is the token's CKA_ID for the attested key.
	KeyID string

	// KeyPublic is the public key of the attested key pair.
	KeyPublic crypto.PublicKey

	// Device identifies the attesting token.
	Device DeviceInfo

	// Properties are the PKCS#11 attributes of the attested private key.
	Properties KeyProperties

	// Timestamp is the statement's creation time in UTC, whole seconds.
	Timestamp time.Time

	// Nonce is the caller's freshness challenge, possibly empty.
	Nonce []byte
}

// tokenKeyObjects are the token objects that together make up one key: the
// private key, and whichever of the public key object or certificate the token
// exposes the public material through. A YubiKey PIV slot, for example, has no
// CKO_PUBLIC_KEY object and publishes the public key only inside the slot
// certificate.
type tokenKeyObjects struct {
	id          []byte
	private     pkcs11.ObjectHandle
	public      pkcs11.ObjectHandle
	certificate pkcs11.ObjectHandle
}

// deviceAttestationKey is a resolved signing identity for the token: the device
// key itself plus the algorithm identifiers a verifier needs to check its
// signatures.
type deviceAttestationKey struct {
	signer             crypto.Signer
	publicKey          crypto.PublicKey
	keyAlgorithm       x509.PublicKeyAlgorithm
	signatureAlgorithm x509.SignatureAlgorithm

	// hash is the digest applied before signing. It is crypto.Hash(0) for
	// Ed25519, which signs the message itself rather than a digest.
	hash crypto.Hash
}

// ecdsaDeviceSignatureAlgorithms pairs each supported curve with the digest of
// matching strength, so the signature's security level is not capped below the
// curve's.
var ecdsaDeviceSignatureAlgorithms = map[elliptic.Curve]struct {
	hash   crypto.Hash
	sigAlg x509.SignatureAlgorithm
}{
	elliptic.P256(): {crypto.SHA256, x509.ECDSAWithSHA256},
	elliptic.P384(): {crypto.SHA384, x509.ECDSAWithSHA384},
	elliptic.P521(): {crypto.SHA512, x509.ECDSAWithSHA512},
}

// supportsAttestation reports whether this backend can identify the device well
// enough to attest anything about it.
//
// This is only the outer gate: it answers "do we know what device we are
// talking to", which is false when no PKCS#11 module is configured. Whether the
// device actually holds an attestation key is answered by
// deviceAttestationKey, which fails with ErrNoDeviceAttestationKey rather than
// a bare false so the caller can report why the token cannot attest.
func (b *Backend) supportsAttestation() (bool, error) {
	if b.config == nil {
		return false, nil
	}
	if b.config.Library == "" {
		return false, nil
	}
	return true, nil
}

// findKeyObject resolves the attested key to its token objects.
//
// The key is located by CKA_ID first and CKA_LABEL second: this package writes
// both when generating a key, but an imported or vendor-provisioned key may
// carry only one of them.
func (b *Backend) findKeyObject(attrs *types.KeyAttributes) (*tokenKeyObjects, error) {
	if attrs == nil {
		return nil, &errs.Detail{Err: ErrInvalidKeyAttributes, Detail: "nil key attributes"}
	}
	if b.pool == nil || b.p11ctx == nil {
		return nil, ErrHSMNotInitialized
	}

	id, err := b.resolveKeyID(attrs)
	if err != nil {
		return nil, err
	}

	objs := &tokenKeyObjects{id: id}
	if err := b.pool.WithSession(func(session pkcs11.SessionHandle) error {
		private, err := b.findObjectByIDOrLabel(session, pkcs11.CKO_PRIVATE_KEY, id)
		if err != nil {
			return err
		}
		if private == 0 {
			return &errs.Detail{Err: ErrAttestedKeyNotFound, Detail: attrs.CN}
		}
		objs.private = private

		if objs.public, err = b.findObjectByIDOrLabel(session, pkcs11.CKO_PUBLIC_KEY, id); err != nil {
			return err
		}
		objs.certificate, err = b.findObjectByIDOrLabel(session, pkcs11.CKO_CERTIFICATE, id)
		return err
	}); err != nil {
		return nil, err
	}

	if objs.public == 0 && objs.certificate == 0 {
		return nil, &errs.Detail{Err: ErrAttestedKeyPublicMissing, Detail: attrs.CN}
	}

	return objs, nil
}

// findObjectByIDOrLabel returns the first object of the given class whose
// CKA_ID matches, falling back to CKA_LABEL. It returns CK_INVALID_HANDLE (0)
// when neither search matches.
//
// Each search is finalized before the next begins: PKCS#11 3.2 section 5.7.7
// allows at most one active search per session, so a second C_FindObjectsInit
// on an unfinalized session fails with CKR_OPERATION_ACTIVE.
func (b *Backend) findObjectByIDOrLabel(session pkcs11.SessionHandle, class uint, id []byte) (pkcs11.ObjectHandle, error) {
	handle, err := b.findOneObject(session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
		pkcs11.NewAttribute(pkcs11.CKA_ID, id),
	})
	if err != nil {
		return 0, err
	}
	if handle != 0 {
		return handle, nil
	}

	return b.findOneObject(session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, class),
		pkcs11.NewAttribute(pkcs11.CKA_LABEL, id),
	})
}

// getPublicKeyFromObject builds a crypto.PublicKey from the token's own
// attribute values: CKA_MODULUS and CKA_PUBLIC_EXPONENT for RSA, CKA_EC_PARAMS
// and CKA_EC_POINT for EC and Edwards keys. When the token exposes no public
// key object, the public key is recovered from the certificate published under
// the same CKA_ID, which is how PIV-style tokens present it.
func (b *Backend) getPublicKeyFromObject(obj *tokenKeyObjects) (crypto.PublicKey, error) {
	if obj == nil {
		return nil, &errs.Detail{Err: ErrInvalidKeyAttributes, Detail: "nil key object"}
	}
	if b.pool == nil || b.p11ctx == nil {
		return nil, ErrHSMNotInitialized
	}

	if obj.public == 0 {
		if obj.certificate == 0 {
			return nil, &errs.Detail{Err: ErrAttestedKeyPublicMissing, Detail: string(obj.id)}
		}
		cert, err := b.readCertificate(obj.certificate)
		if err != nil {
			return nil, err
		}
		return cert.PublicKey, nil
	}

	keyType, err := b.objectKeyType(obj.public)
	if err != nil {
		return nil, err
	}

	switch keyType {
	case pkcs11.CKK_RSA:
		pub, err := exportRSAPublicKey(b.pool, obj.public)
		if err != nil {
			return nil, err
		}
		return pub, nil

	case pkcs11.CKK_EC:
		pub, err := exportECDSAPublicKey(b.pool, obj.public)
		if err != nil {
			return nil, err
		}
		return pub, nil

	case CKK_EC_EDWARDS:
		// The Ed25519 signer owns the CKA_EC_POINT decoding for Edwards keys;
		// reusing it keeps one decoder for the token's point encoding.
		pub := (&pkcs11Ed25519Signer{pool: b.pool, publicHandle: obj.public}).Public()
		edPub, ok := pub.(ed25519.PublicKey)
		if !ok || len(edPub) != ed25519.PublicKeySize {
			return nil, &errs.Detail{Err: ErrInvalidKeyAttributes, Detail: "could not read Ed25519 CKA_EC_POINT"}
		}
		return edPub, nil

	default:
		return nil, &errs.Detail{Err: ErrUnsupportedKeyAlgorithm, Detail: fmt.Sprintf("key type 0x%08x", keyType)}
	}
}

// getDeviceIdentityCertificate returns the token's device identity certificate
// and the chain that can be built for it from certificates the token itself
// holds.
//
// The returned chain starts with the device certificate and continues with each
// issuer found on the token whose signature over the previous certificate
// verifies, stopping at a self-signed certificate. Chain building is bounded:
// certificate objects are attacker-influenced on any token that permits object
// creation, so a cycle must not hang the caller.
//
// A token with no such certificate returns ErrDeviceCertificateNotFound. That
// is not an attestation failure, but it does change what the statement can
// prove -- see AttestKey.
func (b *Backend) getDeviceIdentityCertificate() (*x509.Certificate, []*x509.Certificate, error) {
	if b.pool == nil || b.p11ctx == nil {
		return nil, nil, ErrHSMNotInitialized
	}

	label := []byte(DeviceAttestationKeyLabel)

	var leafDER []byte
	var candidateDERs [][]byte
	if err := b.pool.WithSession(func(session pkcs11.SessionHandle) error {
		handle, err := b.findObjectByIDOrLabel(session, pkcs11.CKO_CERTIFICATE, label)
		if err != nil {
			return err
		}
		if handle == 0 {
			return ErrDeviceCertificateNotFound
		}
		if leafDER, err = b.readCertificateValue(session, handle); err != nil {
			return err
		}
		candidateDERs, err = b.allCertificateValues(session)
		return err
	}); err != nil {
		return nil, nil, err
	}

	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		return nil, nil, &errs.Wrapped{Msg: "pkcs11: parse device identity certificate", Err: err}
	}

	// Unparseable certificate objects are skipped rather than fatal: a token may
	// hold certificates written by unrelated applications, and one bad object
	// must not make a valid device chain unbuildable.
	candidates := make([]*x509.Certificate, 0, len(candidateDERs))
	for _, der := range candidateDERs {
		cert, parseErr := x509.ParseCertificate(der)
		if parseErr != nil {
			continue
		}
		candidates = append(candidates, cert)
	}

	return leaf, buildDeviceChain(leaf, candidates), nil
}

// buildDeviceChain walks from the device certificate towards a self-signed
// certificate using only certificates present on the token. Each link is
// accepted only when the candidate's signature over the previous certificate
// verifies, so an attacker cannot lengthen the chain with an unrelated
// certificate that merely carries a matching subject name.
func buildDeviceChain(leaf *x509.Certificate, candidates []*x509.Certificate) []*x509.Certificate {
	chain := []*x509.Certificate{leaf}

	current := leaf
	for len(chain) < maxDeviceChainDepth {
		if err := current.CheckSignatureFrom(current); err == nil {
			// Self-signed: this is as far as the token can testify.
			return chain
		}

		var next *x509.Certificate
		for _, candidate := range candidates {
			if candidate.Equal(current) || containsCertificate(chain, candidate) {
				continue
			}
			if !bytes.Equal(candidate.RawSubject, current.RawIssuer) {
				continue
			}
			if err := current.CheckSignatureFrom(candidate); err != nil {
				continue
			}
			next = candidate
			break
		}
		if next == nil {
			return chain
		}

		chain = append(chain, next)
		current = next
	}

	return chain
}

// containsCertificate reports whether chain already holds cert, which stops a
// cycle among token certificate objects from repeating forever.
func containsCertificate(chain []*x509.Certificate, cert *x509.Certificate) bool {
	for _, existing := range chain {
		if existing.Equal(cert) {
			return true
		}
	}
	return false
}

// deviceAttestationKey resolves the token's attestation signing identity.
//
// It returns ErrNoDeviceAttestationKey when the token publishes no such key.
// Refusing here is the whole safety property of this file: without a device key
// there is nothing that can honestly sign a statement, and the caller must fail
// rather than emit one.
func (b *Backend) deviceAttestationKey() (*deviceAttestationKey, error) {
	if b.pool == nil || b.p11ctx == nil {
		return nil, ErrHSMNotInitialized
	}

	label := []byte(DeviceAttestationKeyLabel)
	objs := &tokenKeyObjects{id: label}
	if err := b.pool.WithSession(func(session pkcs11.SessionHandle) error {
		private, err := b.findObjectByIDOrLabel(session, pkcs11.CKO_PRIVATE_KEY, label)
		if err != nil {
			return err
		}
		if private == 0 {
			return &errs.Detail{Err: ErrNoDeviceAttestationKey, Detail: fmt.Sprintf("no private key labelled %q", DeviceAttestationKeyLabel)}
		}
		objs.private = private

		if objs.public, err = b.findObjectByIDOrLabel(session, pkcs11.CKO_PUBLIC_KEY, label); err != nil {
			return err
		}
		objs.certificate, err = b.findObjectByIDOrLabel(session, pkcs11.CKO_CERTIFICATE, label)
		return err
	}); err != nil {
		return nil, err
	}

	publicKey, err := b.getPublicKeyFromObject(objs)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "pkcs11: read device attestation public key", Err: err}
	}

	switch pub := publicKey.(type) {
	case *rsa.PublicKey:
		return &deviceAttestationKey{
			signer: &pkcs11RSASigner{
				pool:          b.pool,
				privateHandle: objs.private,
				publicKey:     pub,
				label:         DeviceAttestationKeyLabel,
			},
			publicKey:          pub,
			keyAlgorithm:       x509.RSA,
			signatureAlgorithm: x509.SHA256WithRSA,
			hash:               crypto.SHA256,
		}, nil

	case *ecdsa.PublicKey:
		algorithms, ok := ecdsaDeviceSignatureAlgorithms[pub.Curve]
		if !ok {
			return nil, &errs.Detail{Err: ErrUnsupportedAttestingKey, Detail: fmt.Sprintf("curve %s", pub.Curve.Params().Name)}
		}
		return &deviceAttestationKey{
			signer: &pkcs11ECDSASigner{
				pool:          b.pool,
				privateHandle: objs.private,
				publicKey:     pub,
				label:         DeviceAttestationKeyLabel,
			},
			publicKey:          pub,
			keyAlgorithm:       x509.ECDSA,
			signatureAlgorithm: algorithms.sigAlg,
			hash:               algorithms.hash,
		}, nil

	case ed25519.PublicKey:
		return &deviceAttestationKey{
			signer: &pkcs11Ed25519Signer{
				pool:           b.pool,
				publicHandle:   objs.public,
				privateHandle:  objs.private,
				label:          DeviceAttestationKeyLabel,
				publicKeyBytes: pub,
			},
			publicKey:          pub,
			keyAlgorithm:       x509.Ed25519,
			signatureAlgorithm: x509.PureEd25519,
			// Ed25519 signs the message, not a digest of it.
			hash: crypto.Hash(0),
		}, nil

	default:
		return nil, &errs.Detail{Err: ErrUnsupportedAttestingKey, Detail: fmt.Sprintf("%T", publicKey)}
	}
}

// signAttestationData signs the encoded statement body with the device key,
// which is held by the token: the signing operation runs inside the module via
// C_SignInit / C_Sign and the private key never appears in this process.
//
// There is deliberately no fallback path. If the token cannot sign, the caller
// gets an error, never a placeholder value that would present as a signature.
func (b *Backend) signAttestationData(device *deviceAttestationKey, encoded []byte) ([]byte, error) {
	if device == nil || device.signer == nil {
		return nil, ErrNoDeviceAttestationKey
	}
	if len(encoded) == 0 {
		return nil, &errs.Detail{Err: ErrMalformedAttestationInfo, Detail: "refusing to sign empty attestation data"}
	}

	// Ed25519 hashes internally; handing it a digest would sign the wrong bytes.
	if device.hash == crypto.Hash(0) {
		signature, err := device.signer.Sign(rand.Reader, encoded, crypto.Hash(0))
		if err != nil {
			return nil, &errs.Wrapped{Msg: "pkcs11: device attestation key sign", Err: err}
		}
		return signature, nil
	}

	digester := device.hash.New()
	if _, err := digester.Write(encoded); err != nil {
		return nil, &errs.Wrapped{Msg: "pkcs11: digest attestation data", Err: err}
	}

	signature, err := device.signer.Sign(rand.Reader, digester.Sum(nil), device.hash)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "pkcs11: device attestation key sign", Err: err}
	}
	return signature, nil
}

// encodeAttestationData serializes the attested facts to ASN.1 DER, the exact
// bytes that get signed and shipped as AttestationStatement.AttestationData.
//
// The encoding is deterministic: DER is canonical, the timestamp is truncated
// to whole seconds in UTC, and the public key is embedded as the verbatim DER
// SubjectPublicKeyInfo. A verifier that parses a statement and re-encodes it
// therefore reproduces the signed bytes exactly.
func encodeAttestationData(data *attestationData) ([]byte, error) {
	if data == nil {
		return nil, &errs.Detail{Err: ErrMalformedAttestationInfo, Detail: "nil attestation data"}
	}
	if data.KeyPublic == nil {
		return nil, &errs.Detail{Err: ErrMalformedAttestationInfo, Detail: "attested public key is required"}
	}

	spki, err := x509.MarshalPKIXPublicKey(data.KeyPublic)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "pkcs11: marshal attested public key", Err: err}
	}

	nonce := data.Nonce
	if nonce == nil {
		nonce = []byte{}
	}

	der, err := asn1.Marshal(AttestationInfo{
		Version:     attestationInfoVersion,
		Format:      attestationFormat,
		KeyID:       data.KeyID,
		AttestedKey: asn1.RawValue{FullBytes: spki},
		Device:      data.Device,
		Properties:  data.Properties,
		Timestamp:   data.Timestamp.UTC().Truncate(time.Second),
		Nonce:       nonce,
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "pkcs11: encode attestation data", Err: err}
	}

	return der, nil
}

// tokenDeviceInfo reads the token's identity with C_GetTokenInfo. The strings
// CK_TOKEN_INFO returns are blank-padded fixed-width fields, so they are
// trimmed to keep the signed encoding stable across modules that pad
// differently.
func (b *Backend) tokenDeviceInfo() (DeviceInfo, error) {
	if b.p11ctx == nil {
		return DeviceInfo{}, ErrHSMNotInitialized
	}

	slot, err := b.resolveSlot()
	if err != nil {
		return DeviceInfo{}, err
	}

	info, err := b.p11ctx.GetTokenInfo(slot)
	if err != nil {
		return DeviceInfo{}, &errs.Wrapped{Msg: "pkcs11: C_GetTokenInfo", Err: err}
	}

	return DeviceInfo{
		Manufacturer: strings.TrimSpace(info.ManufacturerID),
		Model:        strings.TrimSpace(info.Model),
		Serial:       strings.TrimSpace(info.SerialNumber),
		TokenLabel:   strings.TrimSpace(info.Label),
		Library:      b.config.Library,
	}, nil
}

// keyProperties reads the attested private key's PKCS#11 attributes.
//
// Attributes are read one at a time because C_GetAttributeValue fails the whole
// call when any single attribute in the template is unavailable, and tokens
// differ in which of these they implement. An attribute the token does not
// implement is reported as false, which understates rather than overstates what
// the token guarantees -- the safe direction for a security claim.
func (b *Backend) keyProperties(private pkcs11.ObjectHandle) (KeyProperties, error) {
	if b.pool == nil || b.p11ctx == nil {
		return KeyProperties{}, ErrHSMNotInitialized
	}
	if private == 0 {
		return KeyProperties{}, &errs.Detail{Err: ErrAttestedKeyNotFound, Detail: "invalid private key handle"}
	}

	var properties KeyProperties
	targets := []struct {
		attribute uint
		field     *bool
	}{
		{pkcs11.CKA_LOCAL, &properties.Local},
		{pkcs11.CKA_SENSITIVE, &properties.Sensitive},
		{pkcs11.CKA_ALWAYS_SENSITIVE, &properties.AlwaysSensitive},
		{pkcs11.CKA_NEVER_EXTRACTABLE, &properties.NeverExtractable},
		{pkcs11.CKA_EXTRACTABLE, &properties.Extractable},
	}

	if err := b.pool.WithSession(func(session pkcs11.SessionHandle) error {
		for _, target := range targets {
			value, err := b.readBoolAttribute(session, private, target.attribute)
			if err != nil {
				return err
			}
			*target.field = value
		}
		return nil
	}); err != nil {
		return KeyProperties{}, err
	}

	return properties, nil
}

// readBoolAttribute reads a single CK_BBOOL attribute, treating an attribute the
// token does not implement or refuses to disclose as false. Any other Cryptoki
// failure is returned, because it means the token's answer is unknown for a
// reason the caller must not paper over.
func (b *Backend) readBoolAttribute(session pkcs11.SessionHandle, handle pkcs11.ObjectHandle, attribute uint) (bool, error) {
	values, err := b.p11ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(attribute, nil),
	})
	if err != nil {
		var ckErr pkcs11.Error
		if errors.As(err, &ckErr) &&
			(ckErr == pkcs11.Error(pkcs11.CKR_ATTRIBUTE_TYPE_INVALID) ||
				ckErr == pkcs11.Error(pkcs11.CKR_ATTRIBUTE_SENSITIVE)) {
			return false, nil
		}
		return false, &errs.Wrapped{Msg: fmt.Sprintf("pkcs11: read attribute 0x%08x", attribute), Err: err}
	}

	if len(values) == 0 || len(values[0].Value) == 0 {
		return false, nil
	}

	return values[0].Value[0] != 0, nil
}

// objectKeyType reads CKA_KEY_TYPE from a key object.
func (b *Backend) objectKeyType(handle pkcs11.ObjectHandle) (uint, error) {
	if b.pool == nil || b.p11ctx == nil {
		return 0, ErrHSMNotInitialized
	}

	var keyType uint
	if err := b.pool.WithSession(func(session pkcs11.SessionHandle) error {
		values, err := b.p11ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{
			pkcs11.NewAttribute(pkcs11.CKA_KEY_TYPE, nil),
		})
		if err != nil {
			return &errs.Wrapped{Msg: "pkcs11: read CKA_KEY_TYPE", Err: err}
		}
		if len(values) == 0 || len(values[0].Value) == 0 {
			return &errs.Detail{Err: ErrInvalidKeyAttributes, Detail: "CKA_KEY_TYPE is empty"}
		}
		keyType = decodeCKULong(values[0].Value)
		return nil
	}); err != nil {
		return 0, err
	}

	return keyType, nil
}

// decodeCKULong decodes a CK_ULONG as Cryptoki delivers it: native byte order,
// which on every platform go-xkms targets is little-endian.
func decodeCKULong(value []byte) uint {
	var decoded uint
	for i, b := range value {
		decoded |= uint(b) << (8 * i)
	}
	return decoded
}

// readCertificate reads and parses the X.509 certificate held in a
// CKO_CERTIFICATE object.
func (b *Backend) readCertificate(handle pkcs11.ObjectHandle) (*x509.Certificate, error) {
	if b.pool == nil || b.p11ctx == nil {
		return nil, ErrHSMNotInitialized
	}
	if handle == 0 {
		return nil, &errs.Detail{Err: ErrDeviceCertificateNotFound, Detail: "invalid certificate handle"}
	}

	var der []byte
	if err := b.pool.WithSession(func(session pkcs11.SessionHandle) error {
		var err error
		der, err = b.readCertificateValue(session, handle)
		return err
	}); err != nil {
		return nil, err
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, &errs.Wrapped{Msg: "pkcs11: parse certificate object", Err: err}
	}
	return cert, nil
}

// readCertificateValue reads CKA_VALUE, the DER certificate, from a certificate
// object in an already-open session.
func (b *Backend) readCertificateValue(session pkcs11.SessionHandle, handle pkcs11.ObjectHandle) ([]byte, error) {
	values, err := b.p11ctx.GetAttributeValue(session, handle, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_VALUE, nil),
	})
	if err != nil {
		return nil, &errs.Wrapped{Msg: "pkcs11: read CKA_VALUE of certificate", Err: err}
	}
	if len(values) == 0 || len(values[0].Value) == 0 {
		return nil, &errs.Detail{Err: ErrDeviceCertificateNotFound, Detail: "certificate object has empty CKA_VALUE"}
	}
	return values[0].Value, nil
}

// allCertificateValues returns the DER of every certificate object on the
// token, bounded by maxTokenCertificates. The search is finalized before any
// attribute is read so the session is left with no operation active.
func (b *Backend) allCertificateValues(session pkcs11.SessionHandle) ([][]byte, error) {
	if err := b.p11ctx.FindObjectsInit(session, []*pkcs11.Attribute{
		pkcs11.NewAttribute(pkcs11.CKA_CLASS, pkcs11.CKO_CERTIFICATE),
	}); err != nil {
		return nil, &errs.Wrapped{Msg: "pkcs11: init certificate search", Err: err}
	}

	handles, _, findErr := b.p11ctx.FindObjects(session, maxTokenCertificates)

	// C_FindObjectsFinal must run even when C_FindObjects failed, or every later
	// search on this session returns CKR_OPERATION_ACTIVE.
	if err := b.p11ctx.FindObjectsFinal(session); err != nil {
		return nil, &errs.Wrapped{Msg: "pkcs11: finalize certificate search", Err: err}
	}
	if findErr != nil {
		return nil, &errs.Wrapped{Msg: "pkcs11: find certificates", Err: findErr}
	}

	ders := make([][]byte, 0, len(handles))
	for _, handle := range handles {
		der, err := b.readCertificateValue(session, handle)
		if err != nil {
			// A certificate object with no readable value cannot contribute to a
			// chain; skipping it keeps one unreadable object from hiding the rest.
			continue
		}
		ders = append(ders, der)
	}

	return ders, nil
}
