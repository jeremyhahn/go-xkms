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
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/acme/common"
	"github.com/jeremyhahn/go-xkms/pkg/acme/entities"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/dice"
	"github.com/jeremyhahn/go-xkms/pkg/ca"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The possession vector is the ADR's wire contract with trusted-firmware: the
// 365-byte CertificationRequestInfo a device signs with ATTEST_CSR and this
// package must rebuild byte for byte. Its inputs are b = 00 01 .. 1f, the
// device's key (the point the vector carries) and the claims set of the
// device's alias certificate -- eat_nonce, ueid 01 a1b2..8f90 and a
// measurements claim -- which is the CBOR inside the UCCS extension. Never
// regenerate it: a change here is a change to every device's firmware.
const (
	vectorCRI       = "3082016902010030003059301306072a8648ce3d020106082a8648ce3d03010703420004798953e7e8134fdf3c139f63d3fbccc252a28b6ca5059e618374a81231240f3fc83267aec725e18b66176c3685d1257201a67033819585a22a296350159ae70ba08201053082010106092a864886f70d01090e3181f33081f030400603551d110101ff04363034a03206082b06010505070803a02630240c22303161316232633364346535663630373138323933613462356336643765386639303081ab06066781050504060101ff04819d30819a048197a30a5820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f1901005101a1b2c3d4e5f60718293a4b5c6d7e8f9019011181821901025854a50050bcc710071a6653c1967ef0d3d5ede421016374667702a2181f6374667718210103a111a20782015820ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad1818636170700c00"
	vectorCRISHA256 = "32f4879deefe716bfeaa468494a4eb19eb6a13075da20ec157c232d8b63f3765"

	vectorNonce    = "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f"
	vectorDeviceID = "01a1b2c3d4e5f60718293a4b5c6d7e8f90"
	vectorClaims   = "a30a5820000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f1901005101a1b2c3d4e5f60718293a4b5c6d7e8f9019011181821901025854a50050bcc710071a6653c1967ef0d3d5ede421016374667702a2181f6374667718210103a111a20782015820ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad1818636170700c00"
)

// The signing vector is the possession vector's claims and nonce under a key
// whose private half is public, the P-256 key of RFC 6979 appendix A.2.5. Its
// signature is the deterministic one RFC 6979 gives for that key over the
// request info, so any implementation can reproduce every byte.
const (
	signingPrivateKey = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"
	signingSignature  = "3045022100988e2c169e224acc501b7d6726feab417d9a122279f0cc5af3e90469a3bf77fb02202804c18ee8905d81103b627d87606da1d074b1a01faaa05044fa99b0725f0956"
	signingCSRSHA256  = "4dfccbaa3825ba37a3378621efff198ddc58b00a0bb52111cde87519f4dab6d2"
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func signingKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), mustHex(t, signingPrivateKey))
	require.NoError(t, err)
	return key
}

// vectorPublicKey is the device key the possession vector carries.
func vectorPublicKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	var cri possessionCRI
	rest, err := asn1.Unmarshal(mustHex(t, vectorCRI), &cri)
	require.NoError(t, err)
	require.Empty(t, rest)
	pub, err := x509.ParsePKIXPublicKey(cri.PublicKey.FullBytes)
	require.NoError(t, err)
	key, ok := pub.(*ecdsa.PublicKey)
	require.True(t, ok)
	return key
}

// vectorClaimsSet is the possession vector's claims set, freshly decoded so a
// test may edit it.
func vectorClaimsSet(t *testing.T) *dice.ClaimsSet {
	t.Helper()
	claims, err := dice.ParseClaimsSet(mustHex(t, vectorClaims))
	require.NoError(t, err)
	return claims
}

// vectorClaimsWith is the possession vector's claims set after edit.
func vectorClaimsWith(t *testing.T, edit func(other map[int64][]byte)) *dice.ClaimsSet {
	t.Helper()
	claims := vectorClaimsSet(t)
	edit(claims.Other)
	return claims
}

// possessionRequest signs the possession request for claims and keyAuth with
// key and parses it as the server receives it.
func possessionRequest(t *testing.T, key crypto.Signer, claims *dice.ClaimsSet, keyAuth string) *x509.CertificateRequest {
	t.Helper()
	der, err := SignPossessionCSR(key, claims, DICENonce(keyAuth))
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	return csr
}

// TestPossessionVector pins the profile byte for byte against the ADR's
// vector. A change to any template byte -- an extension's criticality, the
// identifier encoding, a claim, the extension order -- fails here before it
// can strand a device whose firmware carries the template.
func TestPossessionVector(t *testing.T) {
	cri, err := BuildPossessionCRI(vectorPublicKey(t), vectorClaimsSet(t), mustHex(t, vectorNonce))
	require.NoError(t, err)
	assert.Equal(t, vectorCRI, hex.EncodeToString(cri))
	digest := sha256.Sum256(cri)
	assert.Equal(t, vectorCRISHA256, hex.EncodeToString(digest[:]))

	t.Run("the server reads the vector back", func(t *testing.T) {
		csr := assembled(t, cri, mustHex(t, signingSignature))
		request, err := ParsePossessionCSR(csr)
		require.NoError(t, err)
		assert.Equal(t, mustHex(t, vectorDeviceID), request.DeviceID)
		assert.Equal(t, mustHex(t, vectorNonce), request.Claims.Nonce)
		assert.Equal(t, vectorClaimsSet(t), request.Claims)
		assert.True(t, vectorPublicKey(t).Equal(request.PublicKey))
		assert.Equal(t, entities.ACMEIdentifier{Type: "permanent-identifier", Value: vectorDeviceID}, request.Identifier())
	})
}

// TestPossessionSigningVector pins the request a known key signs: the
// signature is RFC 6979's, so the assembled request is reproducible.
func TestPossessionSigningVector(t *testing.T) {
	key := signingKey(t)
	cri, err := BuildPossessionCRI(&key.PublicKey, vectorClaimsSet(t), mustHex(t, vectorNonce))
	require.NoError(t, err)

	// A nil random source makes crypto/ecdsa sign deterministically, per RFC 6979.
	digest := sha256.Sum256(cri)
	signature, err := key.Sign(nil, digest[:], crypto.SHA256)
	require.NoError(t, err)
	assert.Equal(t, signingSignature, hex.EncodeToString(signature))

	csrDER, err := AssemblePossessionCSR(cri, signature)
	require.NoError(t, err)
	csrDigest := sha256.Sum256(csrDER)
	assert.Equal(t, signingCSRSHA256, hex.EncodeToString(csrDigest[:]))

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)
	require.NoError(t, csr.CheckSignature(), "the pinned signature must verify over the request info")
	request, err := ParsePossessionCSR(csr)
	require.NoError(t, err)
	assert.Equal(t, mustHex(t, vectorDeviceID), request.DeviceID)
	assert.True(t, key.PublicKey.Equal(request.PublicKey))
}

// TestPossessionTemplateIsAnOrdinaryPKCS10 shows the template is no private
// dialect: crypto/x509, asked for the same request, writes the same bytes.
func TestPossessionTemplateIsAnOrdinaryPKCS10(t *testing.T) {
	key := signingKey(t)
	extensions, err := possessionExtensions(mustHex(t, vectorDeviceID), vectorClaimsSet(t))
	require.NoError(t, err)
	cri, err := BuildPossessionCRI(&key.PublicKey, vectorClaimsSet(t), mustHex(t, vectorNonce))
	require.NoError(t, err)

	csr := x509Request(t, key, &x509.CertificateRequest{ExtraExtensions: extensions})
	assert.Equal(t, cri, csr.RawTBSCertificateRequest)
}

// TestPossessionExtensionCriticality pins the two criticality decisions: the
// subjectAltName is critical because the subject is empty (RFC 5280 section
// 4.2.1.6), and the UCCS evidence is critical as it is on the alias
// certificate.
func TestPossessionExtensionCriticality(t *testing.T) {
	csr := possessionRequest(t, signingKey(t), vectorClaimsSet(t), diceKeyAuth)

	require.Len(t, csr.Extensions, 2)
	assert.True(t, csr.Extensions[0].Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}))
	assert.True(t, csr.Extensions[0].Critical, "subjectAltName must be critical under an empty subject")
	assert.True(t, csr.Extensions[1].Id.Equal(dice.OIDUccsEvidence))
	assert.True(t, csr.Extensions[1].Critical, "the UCCS evidence is critical")
	assert.Empty(t, csr.Subject.Names)
}

func TestBuildPossessionCRIRefusesWhatTheTemplateCannotCarry(t *testing.T) {
	key := signingKey(t)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	nonce := mustHex(t, vectorNonce)

	cases := map[string]struct {
		pub    *ecdsa.PublicKey
		claims *dice.ClaimsSet
		nonce  []byte
	}{
		"no key":          {nil, vectorClaimsSet(t), nonce},
		"a P-384 key":     {&p384.PublicKey, vectorClaimsSet(t), nonce},
		"no claims set":   {&key.PublicKey, nil, nonce},
		"a short nonce":   {&key.PublicKey, vectorClaimsSet(t), nonce[:16]},
		"a 48-byte nonce": {&key.PublicKey, vectorClaimsSet(t), append(nonce, nonce[:16]...)},
		"the raw keyauth": {&key.PublicKey, vectorClaimsSet(t), []byte(diceKeyAuth)},
		"no ueid": {&key.PublicKey, vectorClaimsWith(t, func(other map[int64][]byte) {
			delete(other, dice.ClaimUeid)
		}), nonce},
		"an empty ueid": {&key.PublicKey, vectorClaimsWith(t, func(other map[int64][]byte) {
			other[dice.ClaimUeid] = []byte{0x40}
		}), nonce},
		"no measurements": {&key.PublicKey, vectorClaimsWith(t, func(other map[int64][]byte) {
			delete(other, dice.ClaimMeasurements)
		}), nonce},
		"an extra claim": {&key.PublicKey, vectorClaimsWith(t, func(other map[int64][]byte) {
			other[274] = []byte{0x01}
		}), nonce},
		"a measurements claim that is not CBOR": {&key.PublicKey, vectorClaimsWith(t, func(other map[int64][]byte) {
			other[dice.ClaimMeasurements] = []byte{0xff}
		}), nonce},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			cri, err := BuildPossessionCRI(c.pub, c.claims, c.nonce)
			assert.ErrorIs(t, err, ErrPossessionCSRMalformed)
			assert.Nil(t, cri)
		})
	}
}

func TestAssemblePossessionCSRRefusesMalformedInput(t *testing.T) {
	cri := mustHex(t, vectorCRI)
	signature := mustHex(t, signingSignature)

	t.Run("request info with trailing bytes", func(t *testing.T) {
		der, err := AssemblePossessionCSR(append(append([]byte(nil), cri...), 0x00), signature)
		assert.ErrorIs(t, err, ErrPossessionCSRMalformed)
		assert.Nil(t, der)
	})
	t.Run("request info that is not DER", func(t *testing.T) {
		der, err := AssemblePossessionCSR([]byte{0x30, 0x05}, signature)
		assert.ErrorIs(t, err, ErrPossessionCSRMalformed)
		assert.Nil(t, der)
	})
	t.Run("a raw r||s signature", func(t *testing.T) {
		der, err := AssemblePossessionCSR(cri, make([]byte, 64))
		assert.ErrorIs(t, err, ErrPossessionSignatureInvalid)
		assert.Nil(t, der)
	})
}

// failingSigner is a device that refuses to sign.
type failingSigner struct{ public crypto.PublicKey }

func (s failingSigner) Public() crypto.PublicKey { return s.public }

func (failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("element busy")
}

func TestSignPossessionCSR(t *testing.T) {
	key := signingKey(t)
	claims := vectorClaimsSet(t)
	nonce := mustHex(t, vectorNonce)

	t.Run("signs the template", func(t *testing.T) {
		cri, err := BuildPossessionCRI(&key.PublicKey, claims, nonce)
		require.NoError(t, err)
		der, err := SignPossessionCSR(key, claims, nonce)
		require.NoError(t, err)
		csr, err := x509.ParseCertificateRequest(der)
		require.NoError(t, err)
		require.NoError(t, csr.CheckSignature())
		assert.Equal(t, cri, csr.RawTBSCertificateRequest)
	})
	t.Run("no signer", func(t *testing.T) {
		_, err := SignPossessionCSR(nil, claims, nonce)
		assert.ErrorIs(t, err, ErrPossessionSigningFailed)
	})
	t.Run("a key that is not ECDSA", func(t *testing.T) {
		_, edKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		_, err = SignPossessionCSR(edKey, claims, nonce)
		assert.ErrorIs(t, err, ErrPossessionCSRMalformed)
	})
	t.Run("a device that does not sign", func(t *testing.T) {
		_, err := SignPossessionCSR(failingSigner{public: key.Public()}, claims, nonce)
		assert.ErrorIs(t, err, ErrPossessionSigningFailed)
	})
	t.Run("a nonce the template cannot carry", func(t *testing.T) {
		_, err := SignPossessionCSR(key, claims, nonce[:8])
		assert.ErrorIs(t, err, ErrPossessionCSRMalformed)
	})
	t.Run("no claims set", func(t *testing.T) {
		_, err := SignPossessionCSR(key, nil, nonce)
		assert.ErrorIs(t, err, ErrPossessionCSRMalformed)
	})
}

// x509Request builds a request with crypto/x509, for shapes the possession
// template would never write.
func x509Request(t *testing.T, key crypto.Signer, template *x509.CertificateRequest) *x509.CertificateRequest {
	t.Helper()
	der, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	return csr
}

// uccsExtension is a critical UCCS evidence extension carrying claims.
func uccsExtension(t *testing.T, claims *dice.ClaimsSet) pkix.Extension {
	t.Helper()
	extension, err := dice.CreateUccsEvidenceExtension(claims)
	require.NoError(t, err)
	return extension
}

// reorderedUccs is the vector's claims set with measurements encoded before
// ueid: the same claims, in an order deterministic CBOR never writes.
func reorderedUccs(t *testing.T) pkix.Extension {
	t.Helper()
	claims := vectorClaimsSet(t)
	cbor := append([]byte{0xa3, 0x0a, 0x58, 0x20}, claims.Nonce...)
	cbor = append(cbor, 0x19, 0x01, 0x11)
	cbor = append(cbor, claims.Other[dice.ClaimMeasurements]...)
	cbor = append(cbor, 0x19, 0x01, 0x00)
	cbor = append(cbor, claims.Other[dice.ClaimUeid]...)
	value, err := asn1.Marshal(struct{ Uccs []byte }{cbor})
	require.NoError(t, err)

	parsed, err := dice.ParseUccsEvidence(value)
	require.NoError(t, err, "the reordered claims set must still parse, or the test proves nothing")
	assert.Equal(t, claims, parsed)
	return pkix.Extension{Id: dice.OIDUccsEvidence, Critical: true, Value: value}
}

func TestParsePossessionCSRRefusesAnythingButTheTemplate(t *testing.T) {
	key := signingKey(t)
	extensions, err := possessionExtensions(mustHex(t, vectorDeviceID), vectorClaimsSet(t))
	require.NoError(t, err)
	san, uccs := extensions[0], extensions[1]

	nonCriticalUCCS := uccs
	nonCriticalUCCS.Critical = false

	upper, err := ca.MarshalPermanentIdentifier(strings.ToUpper(vectorDeviceID), nil)
	require.NoError(t, err)
	upperSAN, err := ca.BuildSubjectAltName(pkix.Name{}, nil, nil, nil, nil,
		[]ca.OtherName{{TypeID: ca.OIDPermanentIdentifier, Value: upper}}, nil)
	require.NoError(t, err)

	anotherSAN, err := ca.BuildSubjectAltName(pkix.Name{}, nil, nil, nil, nil,
		[]ca.OtherName{{TypeID: ca.OIDPermanentIdentifier, Value: mustPermanentIdentifier(t, "02"+vectorDeviceID[2:])}}, nil)
	require.NoError(t, err)

	notHex, err := ca.MarshalPermanentIdentifier("device-a", nil)
	require.NoError(t, err)
	notHexSAN, err := ca.BuildSubjectAltName(pkix.Name{}, nil, nil, nil, nil,
		[]ca.OtherName{{TypeID: ca.OIDPermanentIdentifier, Value: notHex}}, nil)
	require.NoError(t, err)

	withAssigner, err := ca.MarshalPermanentIdentifier(vectorDeviceID, ca.OIDTCGOnEKPermIdSha256)
	require.NoError(t, err)
	assignerSAN, err := ca.BuildSubjectAltName(pkix.Name{}, nil, nil, nil, nil,
		[]ca.OtherName{{TypeID: ca.OIDPermanentIdentifier, Value: withAssigner}}, nil)
	require.NoError(t, err)

	dnsSAN, err := ca.BuildSubjectAltName(pkix.Name{}, []string{"device.example.com"}, nil, nil, nil,
		[]ca.OtherName{{TypeID: ca.OIDPermanentIdentifier, Value: mustPermanentIdentifier(t, vectorDeviceID)}}, nil)
	require.NoError(t, err)

	noUeid := uccsExtension(t, vectorClaimsWith(t, func(other map[int64][]byte) { delete(other, dice.ClaimUeid) }))
	noMeasurements := uccsExtension(t, vectorClaimsWith(t, func(other map[int64][]byte) { delete(other, dice.ClaimMeasurements) }))
	extraClaim := uccsExtension(t, vectorClaimsWith(t, func(other map[int64][]byte) { other[274] = []byte{0x01} }))
	shortNonce := uccsExtension(t, &dice.ClaimsSet{Nonce: mustHex(t, vectorNonce)[:16], Other: vectorClaimsSet(t).Other})

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	request := func(extensions ...pkix.Extension) *x509.CertificateRequest {
		return x509Request(t, key, &x509.CertificateRequest{ExtraExtensions: extensions})
	}
	cases := map[string]*x509.CertificateRequest{
		"a subject":                         x509Request(t, key, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "device"}, ExtraExtensions: extensions}),
		"a non-critical UCCS extension":     request(san, nonCriticalUCCS),
		"the extensions reversed":           request(uccs, san),
		"no UCCS extension":                 request(san),
		"no subjectAltName":                 request(uccs),
		"a ueid that is not the SAN's":      request(anotherSAN, uccs),
		"an upper-case identifier":          request(upperSAN, uccs),
		"an identifier that is text":        request(notHexSAN, uccs),
		"an identifier assigner":            request(assignerSAN, uccs),
		"a dns name beside it":              request(dnsSAN, uccs),
		"a claims set without ueid":         request(san, noUeid),
		"a claims set without measurements": request(san, noMeasurements),
		"an extra claim":                    request(san, extraClaim),
		"the claims reordered":              request(san, reorderedUccs(t)),
		"a 16-byte nonce":                   request(san, shortNonce),
		"a third extension": request(san, uccs,
			pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Value: []byte{0x03, 0x02, 0x07, 0x80}}),
		"ecdsa-with-SHA384": x509Request(t, key, &x509.CertificateRequest{SignatureAlgorithm: x509.ECDSAWithSHA384, ExtraExtensions: extensions}),
		"a P-384 key":       x509Request(t, p384, &x509.CertificateRequest{ExtraExtensions: extensions}),
		"no request":        nil,
	}
	for name, csr := range cases {
		t.Run(name, func(t *testing.T) {
			request, err := ParsePossessionCSR(csr)
			assert.ErrorIs(t, err, ErrPossessionCSRMalformed)
			assert.Nil(t, request)
		})
	}
}

func TestParsePossessionCSRRefusesUnparsableEvidence(t *testing.T) {
	key := signingKey(t)
	extensions, err := possessionExtensions(mustHex(t, vectorDeviceID), vectorClaimsSet(t))
	require.NoError(t, err)

	csr := x509Request(t, key, &x509.CertificateRequest{ExtraExtensions: []pkix.Extension{
		extensions[0], {Id: dice.OIDUccsEvidence, Value: []byte{0x30, 0x00}},
	}})
	_, err = ParsePossessionCSR(csr)
	assert.ErrorIs(t, err, ErrPossessionCSRMalformed)
	assert.ErrorIs(t, err, dice.ErrMalformedUccsEvidence, "the nonce is read by the dice parser, not a second one")
}

func mustPermanentIdentifier(t *testing.T, value string) []byte {
	t.Helper()
	der, err := ca.MarshalPermanentIdentifier(value, nil)
	require.NoError(t, err)
	return der
}

// possessionFixture is a DICE device that answered the challenge for
// diceKeyAuth, as finalization sees it.
type possessionFixture struct {
	verified *VerifiedAttestation
	key      *ecdsa.PrivateKey
	claims   *dice.ClaimsSet
	order    []entities.ACMEIdentifier
}

func newPossessionFixture(t *testing.T) *possessionFixture {
	t.Helper()
	leafDER, key := newDICEAlias(t, DICENonce(diceKeyAuth))
	attestedSPKI, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	return &possessionFixture{
		verified: &VerifiedAttestation{Format: FormatDICE, KeyAuthorization: diceKeyAuth, LeafDER: leafDER, AttestedSPKI: attestedSPKI},
		key:      key,
		claims:   vectorClaimsSet(t),
		order:    []entities.ACMEIdentifier{{Type: common.AuthzTypePermanentIdentifier, Value: vectorDeviceID}},
	}
}

func TestVerifyPossessionCSRAcceptsTheDevicesRequest(t *testing.T) {
	f := newPossessionFixture(t)
	csr := possessionRequest(t, f.key, f.claims, diceKeyAuth)

	require.NoError(t, f.verified.VerifyPossessionCSR(csr, f.order))
	require.NoError(t, f.verified.BindCSRKey(csr), "a possession request also passes the alias binding")
}

func TestVerifyPossessionCSRSignature(t *testing.T) {
	f := newPossessionFixture(t)
	cri, err := BuildPossessionCRI(&f.key.PublicKey, f.claims, DICENonce(diceKeyAuth))
	require.NoError(t, err)

	t.Run("a signature over the request info verifies", func(t *testing.T) {
		digest := sha256.Sum256(cri)
		signature, err := ecdsa.SignASN1(rand.Reader, f.key, digest[:])
		require.NoError(t, err)
		require.NoError(t, f.verified.VerifyPossessionCSR(assembled(t, cri, signature), f.order))
	})
	t.Run("a signature over anything else is refused", func(t *testing.T) {
		digest := sha256.Sum256([]byte("some other message"))
		signature, err := ecdsa.SignASN1(rand.Reader, f.key, digest[:])
		require.NoError(t, err)
		err = f.verified.VerifyPossessionCSR(assembled(t, cri, signature), f.order)
		assert.ErrorIs(t, err, ErrPossessionSignatureInvalid)
	})
}

func assembled(t *testing.T, cri, signature []byte) *x509.CertificateRequest {
	t.Helper()
	der, err := AssemblePossessionCSR(cri, signature)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	return csr
}

func TestVerifyPossessionCSRKey(t *testing.T) {
	f := newPossessionFixture(t)

	t.Run("the attested key is accepted", func(t *testing.T) {
		require.NoError(t, f.verified.VerifyPossessionCSR(possessionRequest(t, f.key, f.claims, diceKeyAuth), f.order))
	})
	t.Run("any other key is refused", func(t *testing.T) {
		software, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		err = f.verified.VerifyPossessionCSR(possessionRequest(t, software, f.claims, diceKeyAuth), f.order)
		assert.ErrorIs(t, err, ErrPossessionKeyMismatch)
	})
}

func TestVerifyPossessionCSRNonce(t *testing.T) {
	f := newPossessionFixture(t)

	t.Run("this order's challenge is accepted", func(t *testing.T) {
		require.NoError(t, f.verified.VerifyPossessionCSR(possessionRequest(t, f.key, f.claims, diceKeyAuth), f.order))
	})
	t.Run("a request signed for another order is refused", func(t *testing.T) {
		replayed := possessionRequest(t, f.key, f.claims, "another-token.another-thumbprint")
		assert.ErrorIs(t, f.verified.VerifyPossessionCSR(replayed, f.order), ErrPossessionNonceMismatch)
	})
}

func TestVerifyPossessionCSRIdentifiers(t *testing.T) {
	f := newPossessionFixture(t)
	csr := possessionRequest(t, f.key, f.claims, diceKeyAuth)

	t.Run("the order's one identifier is accepted", func(t *testing.T) {
		require.NoError(t, f.verified.VerifyPossessionCSR(csr, f.order))
	})

	refused := map[string][]entities.ACMEIdentifier{
		"another device": {{Type: common.AuthzTypePermanentIdentifier, Value: "02" + vectorDeviceID[2:]}},
		"a dns identifier beside it": append([]entities.ACMEIdentifier{{Type: common.AuthzTypeDNS, Value: "device.example.com"}},
			f.order...),
		"the same value under another type": {{Type: common.AuthzTypeDNS, Value: vectorDeviceID}},
		"no identifiers":                    nil,
	}
	for name, order := range refused {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, f.verified.VerifyPossessionCSR(csr, order), ErrPossessionIdentifierMismatch)
		})
	}
}

func TestVerifyPossessionCSRRefusesWhatItCannotCheck(t *testing.T) {
	f := newPossessionFixture(t)
	csr := possessionRequest(t, f.key, f.claims, diceKeyAuth)

	t.Run("no verified attestation", func(t *testing.T) {
		var missing *VerifiedAttestation
		assert.ErrorIs(t, missing.VerifyPossessionCSR(csr, f.order), ErrNoVerifiedAttestation)
	})
	t.Run("a tpm attestation", func(t *testing.T) {
		tpm := &VerifiedAttestation{Format: FormatTPM, KeyAuthorization: diceKeyAuth, LeafDER: f.verified.LeafDER}
		assert.ErrorIs(t, tpm.VerifyPossessionCSR(csr, f.order), ErrKeyBindingUnavailable)
	})
	t.Run("no leaf", func(t *testing.T) {
		bare := &VerifiedAttestation{Format: FormatDICE, KeyAuthorization: diceKeyAuth}
		assert.ErrorIs(t, bare.VerifyPossessionCSR(csr, f.order), ErrKeyBindingUnavailable)
	})
	t.Run("an ordinary certificate request", func(t *testing.T) {
		assert.ErrorIs(t, f.verified.VerifyPossessionCSR(csrFor(t, f.key), f.order), ErrPossessionCSRMalformed)
	})
}
