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

// The possession vector. The key is the P-256 key of RFC 6979 appendix
// A.2.5, the device identifier a 17-byte random-type UEID, and b the nonce
// for the key authorization "vector-token.vector-thumbprint". The signature
// is the deterministic one RFC 6979 gives for that key over the request info,
// so any implementation can reproduce every byte.
const (
	vectorPrivateKey = "c9afa9d845ba75166b5c215767b1d6934e50c3db36e89b127b8a622b120f6721"
	vectorDeviceID   = "0100112233445566778899aabbccddeeff"
	vectorKeyAuth    = "vector-token.vector-thumbprint"
	vectorNonce      = "d0b52047e8404e2af7b2032e26071106b8f02eefbf2d9508b1dc3e06655117ee"

	vectorCRI = "3081eb02010030003059301306072a8648ce3d020106082a8648ce3d03010703420004" +
		"60fed4ba255a9d31c961eb74c6356d68c049b8923b61fa6ce669622e60f29fb6" +
		"7903fe1008b8bc99a41ae9e95628bc64f2f1b20c2d7e9f5177a3c294d4462299" +
		"a0818830818506092a864886f70d01090e31783076" +
		"30400603551d110101ff04363034a03206082b06010505070803a02630240c22" +
		"3031303031313232333334343535363637373838393961616262636364646565" + "6666" +
		"303206066781050504060428302604" + "24a10a5820" +
		"d0b52047e8404e2af7b2032e26071106b8f02eefbf2d9508b1dc3e06655117ee"

	vectorSignature = "3045022100835d4fa691e5611955f0e69d86754489424177d7c786f384c7aeca6b6c4fa72d" +
		"0220740f8dca06e89008b20e1007c455fb0ec100d629628500d9e4f7cb08f47fd9f5"

	vectorCSR = "30820144" + vectorCRI + "300a06082a8648ce3d040302034800" + vectorSignature
)

func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	require.NoError(t, err)
	return b
}

func vectorKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.ParseRawPrivateKey(elliptic.P256(), mustHex(t, vectorPrivateKey))
	require.NoError(t, err)
	return key
}

// possessionRequest signs the possession request for deviceID and keyAuth
// with key and parses it as the server receives it.
func possessionRequest(t *testing.T, key crypto.Signer, deviceID []byte, keyAuth string) *x509.CertificateRequest {
	t.Helper()
	der, err := SignPossessionCSR(key, deviceID, DICENonce(keyAuth))
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)
	return csr
}

// TestPossessionVector pins the profile byte for byte. A change to any
// template byte -- an extension's criticality, the identifier encoding, the
// extension order -- fails here before it can strand a device whose firmware
// carries the template.
func TestPossessionVector(t *testing.T) {
	key := vectorKey(t)
	deviceID := mustHex(t, vectorDeviceID)
	require.Equal(t, vectorNonce, hex.EncodeToString(DICENonce(vectorKeyAuth)))

	cri, err := BuildPossessionCRI(&key.PublicKey, deviceID, DICENonce(vectorKeyAuth))
	require.NoError(t, err)
	assert.Equal(t, vectorCRI, hex.EncodeToString(cri))

	csrDER, err := AssemblePossessionCSR(cri, mustHex(t, vectorSignature))
	require.NoError(t, err)
	assert.Equal(t, vectorCSR, hex.EncodeToString(csrDER))

	csr, err := x509.ParseCertificateRequest(csrDER)
	require.NoError(t, err)
	require.NoError(t, csr.CheckSignature(), "the pinned signature must verify over the pinned request info")

	request, err := ParsePossessionCSR(csr)
	require.NoError(t, err)
	assert.Equal(t, deviceID, request.DeviceID)
	assert.Equal(t, DICENonce(vectorKeyAuth), request.Nonce)
	assert.True(t, key.PublicKey.Equal(request.PublicKey))
	assert.Equal(t, entities.ACMEIdentifier{Type: "permanent-identifier", Value: vectorDeviceID}, request.Identifier())
}

// TestPossessionTemplateIsAnOrdinaryPKCS10 shows the template is no private
// dialect: crypto/x509, asked for the same request, writes the same bytes.
func TestPossessionTemplateIsAnOrdinaryPKCS10(t *testing.T) {
	key := vectorKey(t)
	extensions, err := possessionExtensions(mustHex(t, vectorDeviceID), mustHex(t, vectorNonce))
	require.NoError(t, err)

	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{ExtraExtensions: extensions}, key)
	require.NoError(t, err)
	csr, err := x509.ParseCertificateRequest(der)
	require.NoError(t, err)

	assert.Equal(t, vectorCRI, hex.EncodeToString(csr.RawTBSCertificateRequest))
}

// TestPossessionExtensionCriticality pins the two criticality decisions: the
// subjectAltName is critical because the subject is empty (RFC 5280 section
// 4.2.1.6), and the UCCS evidence is not, because it is never issued.
func TestPossessionExtensionCriticality(t *testing.T) {
	csr := possessionRequest(t, vectorKey(t), mustHex(t, vectorDeviceID), vectorKeyAuth)

	require.Len(t, csr.Extensions, 2)
	assert.True(t, csr.Extensions[0].Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 17}))
	assert.True(t, csr.Extensions[0].Critical, "subjectAltName must be critical under an empty subject")
	assert.True(t, csr.Extensions[1].Id.Equal(dice.OIDUccsEvidence))
	assert.False(t, csr.Extensions[1].Critical, "the UCCS evidence is not critical")
	assert.Empty(t, csr.Subject.Names)
}

func TestBuildPossessionCRIRefusesWhatTheTemplateCannotCarry(t *testing.T) {
	key := vectorKey(t)
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	deviceID := mustHex(t, vectorDeviceID)
	nonce := DICENonce(vectorKeyAuth)

	cases := map[string]func() ([]byte, error){
		"no key":        func() ([]byte, error) { return BuildPossessionCRI(nil, deviceID, nonce) },
		"a P-384 key":   func() ([]byte, error) { return BuildPossessionCRI(&p384.PublicKey, deviceID, nonce) },
		"no device id":  func() ([]byte, error) { return BuildPossessionCRI(&key.PublicKey, nil, nonce) },
		"a short nonce": func() ([]byte, error) { return BuildPossessionCRI(&key.PublicKey, deviceID, nonce[:16]) },
		"a 48-byte nonce": func() ([]byte, error) {
			return BuildPossessionCRI(&key.PublicKey, deviceID, append(nonce, nonce[:16]...))
		},
		"the raw keyauth": func() ([]byte, error) {
			return BuildPossessionCRI(&key.PublicKey, deviceID, []byte(vectorKeyAuth))
		},
	}
	for name, build := range cases {
		t.Run(name, func(t *testing.T) {
			cri, err := build()
			assert.ErrorIs(t, err, ErrPossessionCSRMalformed)
			assert.Nil(t, cri)
		})
	}
}

func TestAssemblePossessionCSRRefusesMalformedInput(t *testing.T) {
	cri := mustHex(t, vectorCRI)
	signature := mustHex(t, vectorSignature)

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
	key := vectorKey(t)
	deviceID := mustHex(t, vectorDeviceID)
	nonce := DICENonce(vectorKeyAuth)

	t.Run("signs the template", func(t *testing.T) {
		der, err := SignPossessionCSR(key, deviceID, nonce)
		require.NoError(t, err)
		csr, err := x509.ParseCertificateRequest(der)
		require.NoError(t, err)
		require.NoError(t, csr.CheckSignature())
		assert.Equal(t, vectorCRI, hex.EncodeToString(csr.RawTBSCertificateRequest))
	})
	t.Run("no signer", func(t *testing.T) {
		_, err := SignPossessionCSR(nil, deviceID, nonce)
		assert.ErrorIs(t, err, ErrPossessionSigningFailed)
	})
	t.Run("a key that is not ECDSA", func(t *testing.T) {
		_, edKey, err := ed25519.GenerateKey(rand.Reader)
		require.NoError(t, err)
		_, err = SignPossessionCSR(edKey, deviceID, nonce)
		assert.ErrorIs(t, err, ErrPossessionCSRMalformed)
	})
	t.Run("a device that does not sign", func(t *testing.T) {
		_, err := SignPossessionCSR(failingSigner{public: key.Public()}, deviceID, nonce)
		assert.ErrorIs(t, err, ErrPossessionSigningFailed)
	})
	t.Run("a nonce the template cannot carry", func(t *testing.T) {
		_, err := SignPossessionCSR(key, deviceID, nonce[:8])
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

func TestParsePossessionCSRRefusesAnythingButTheTemplate(t *testing.T) {
	key := vectorKey(t)
	deviceID := mustHex(t, vectorDeviceID)
	nonce := mustHex(t, vectorNonce)
	extensions, err := possessionExtensions(deviceID, nonce)
	require.NoError(t, err)
	san, uccs := extensions[0], extensions[1]

	criticalUCCS := uccs
	criticalUCCS.Critical = true

	upper, err := ca.MarshalPermanentIdentifier(strings.ToUpper(vectorDeviceID), nil)
	require.NoError(t, err)
	upperSAN, err := ca.BuildSubjectAltName(pkix.Name{}, nil, nil, nil, nil,
		[]ca.OtherName{{TypeID: ca.OIDPermanentIdentifier, Value: upper}}, nil)
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

	extraClaims, err := dice.MarshalUccsEvidence(&dice.ClaimsSet{Nonce: nonce, Other: map[int64][]byte{256: {0x41, 0x01}}})
	require.NoError(t, err)

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	cases := map[string]*x509.CertificateRequest{
		"a subject":                  x509Request(t, key, &x509.CertificateRequest{Subject: pkix.Name{CommonName: "device"}, ExtraExtensions: extensions}),
		"a critical UCCS extension":  x509Request(t, key, &x509.CertificateRequest{ExtraExtensions: []pkix.Extension{san, criticalUCCS}}),
		"the extensions reversed":    x509Request(t, key, &x509.CertificateRequest{ExtraExtensions: []pkix.Extension{uccs, san}}),
		"no UCCS extension":          x509Request(t, key, &x509.CertificateRequest{ExtraExtensions: []pkix.Extension{san}}),
		"no subjectAltName":          x509Request(t, key, &x509.CertificateRequest{ExtraExtensions: []pkix.Extension{uccs}}),
		"an upper-case identifier":   x509Request(t, key, &x509.CertificateRequest{ExtraExtensions: []pkix.Extension{upperSAN, uccs}}),
		"an identifier that is text": x509Request(t, key, &x509.CertificateRequest{ExtraExtensions: []pkix.Extension{notHexSAN, uccs}}),
		"an identifier assigner":     x509Request(t, key, &x509.CertificateRequest{ExtraExtensions: []pkix.Extension{assignerSAN, uccs}}),
		"a dns name beside it":       x509Request(t, key, &x509.CertificateRequest{ExtraExtensions: []pkix.Extension{dnsSAN, uccs}}),
		"a claim beside the nonce":   x509Request(t, key, &x509.CertificateRequest{ExtraExtensions: []pkix.Extension{san, {Id: dice.OIDUccsEvidence, Value: extraClaims}}}),
		"a third extension": x509Request(t, key, &x509.CertificateRequest{ExtraExtensions: []pkix.Extension{san, uccs,
			{Id: asn1.ObjectIdentifier{2, 5, 29, 15}, Value: []byte{0x03, 0x02, 0x07, 0x80}}}}),
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
	key := vectorKey(t)
	extensions, err := possessionExtensions(mustHex(t, vectorDeviceID), mustHex(t, vectorNonce))
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
	deviceID []byte
	order    []entities.ACMEIdentifier
}

func newPossessionFixture(t *testing.T) *possessionFixture {
	t.Helper()
	leafDER, key := newDICEAlias(t, DICENonce(diceKeyAuth))
	deviceID := mustHex(t, vectorDeviceID)
	return &possessionFixture{
		verified: &VerifiedAttestation{Format: FormatDICE, KeyAuthorization: diceKeyAuth, LeafDER: leafDER},
		key:      key,
		deviceID: deviceID,
		order:    []entities.ACMEIdentifier{{Type: common.AuthzTypePermanentIdentifier, Value: vectorDeviceID}},
	}
}

func TestVerifyPossessionCSRAcceptsTheDevicesRequest(t *testing.T) {
	f := newPossessionFixture(t)
	csr := possessionRequest(t, f.key, f.deviceID, diceKeyAuth)

	require.NoError(t, f.verified.VerifyPossessionCSR(csr, f.order))
	require.NoError(t, f.verified.BindCSRKey(csr), "a possession request also passes the alias binding")
}

func TestVerifyPossessionCSRSignature(t *testing.T) {
	f := newPossessionFixture(t)
	cri, err := BuildPossessionCRI(&f.key.PublicKey, f.deviceID, DICENonce(diceKeyAuth))
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
		require.NoError(t, f.verified.VerifyPossessionCSR(possessionRequest(t, f.key, f.deviceID, diceKeyAuth), f.order))
	})
	t.Run("any other key is refused", func(t *testing.T) {
		software, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		err = f.verified.VerifyPossessionCSR(possessionRequest(t, software, f.deviceID, diceKeyAuth), f.order)
		assert.ErrorIs(t, err, ErrPossessionKeyMismatch)
	})
}

func TestVerifyPossessionCSRNonce(t *testing.T) {
	f := newPossessionFixture(t)

	t.Run("this order's challenge is accepted", func(t *testing.T) {
		require.NoError(t, f.verified.VerifyPossessionCSR(possessionRequest(t, f.key, f.deviceID, diceKeyAuth), f.order))
	})
	t.Run("a request signed for another order is refused", func(t *testing.T) {
		replayed := possessionRequest(t, f.key, f.deviceID, "another-token.another-thumbprint")
		assert.ErrorIs(t, f.verified.VerifyPossessionCSR(replayed, f.order), ErrPossessionNonceMismatch)
	})
}

func TestVerifyPossessionCSRIdentifiers(t *testing.T) {
	f := newPossessionFixture(t)
	csr := possessionRequest(t, f.key, f.deviceID, diceKeyAuth)

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
	csr := possessionRequest(t, f.key, f.deviceID, diceKeyAuth)

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
