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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/dice"
)

// diceUeid is the device identifier the DICE fixtures carry.
var diceUeid = []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08}

// diceFixture is a DICE root and the alias certificate it signed.
type diceFixture struct {
	root    *x509.Certificate
	leafDER []byte
	key     *ecdsa.PrivateKey
}

// newDICEFixture mints a DICE CA and an alias certificate it signs. challenge
// is echoed in the alias's eat_nonce (nil echoes nothing), withUeid and
// withTcbInfo choose which evidence extensions the alias carries, and
// withMeasurement whether DiceTcbInfo carries a firmware measurement.
func newDICEFixture(t *testing.T, challenge []byte, withUeid, withTcbInfo, withMeasurement bool) *diceFixture {
	t.Helper()
	return newDICEFixtureSignedOn(t, elliptic.P256(), challenge, withUeid, withTcbInfo, withMeasurement)
}

// newDICEFixtureSignedOn is newDICEFixture with the root on curve, which
// decides the signature algorithm of the alias it signs: P-256 gives
// ECDSA-SHA256, the one a secure element performs, and P-384 gives SHA-384.
func newDICEFixtureSignedOn(t *testing.T, curve elliptic.Curve, challenge []byte, withUeid, withTcbInfo, withMeasurement bool) *diceFixture {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(curve, rand.Reader)
	require.NoError(t, err)
	rootTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "DICE Test Root"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTemplate, rootTemplate, rootKey.Public(), rootKey)
	require.NoError(t, err)
	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	var extensions []pkix.Extension
	if withTcbInfo {
		info := &dice.TcbInfo{Vendor: "Automate The Things", Model: "AVR-DICE", Version: "1.0.0"}
		if withMeasurement {
			info.FWIDs = []dice.FWID{{HashAlg: asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}, Digest: make([]byte, 32)}}
		}
		extension, err := dice.CreateTcbInfoExtension(info)
		require.NoError(t, err)
		extensions = append(extensions, extension)
	}
	if withUeid {
		extension, err := dice.CreateUeidExtension(diceUeid)
		require.NoError(t, err)
		extensions = append(extensions, extension)
	}
	if challenge != nil {
		extension, err := dice.CreateUccsEvidenceExtension(&dice.ClaimsSet{Nonce: challenge})
		require.NoError(t, err)
		extensions = append(extensions, extension)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTemplate := &x509.Certificate{
		SerialNumber:    big.NewInt(2),
		Subject:         pkix.Name{CommonName: "Test DICE Alias"},
		NotBefore:       time.Now().Add(-time.Hour),
		NotAfter:        time.Now().Add(time.Hour),
		ExtraExtensions: extensions,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, root, key.Public(), rootKey)
	require.NoError(t, err)
	return &diceFixture{root: root, leafDER: leafDER, key: key}
}

func (f *diceFixture) object() *AttestationObject {
	return &AttestationObject{
		Format:       string(FormatDICE),
		AttStatement: AttestationStatement{X5c: []interface{}{f.leafDER}},
	}
}

// aikObject is a "tpm" attestation object holding only the AIK chain: all the
// anchoring verifier reads.
func aikObject(chain ...[]byte) *AttestationObject {
	x5c := make([]interface{}, 0, len(chain))
	for _, der := range chain {
		x5c = append(x5c, der)
	}
	return &AttestationObject{Format: string(FormatTPM), AttStatement: AttestationStatement{X5c: x5c}}
}

func aikPublicKey(t *testing.T) *ecdsa.PublicKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	return &key.PublicKey
}

func TestNewTrustAnchorVerifier(t *testing.T) {
	issuer := newAIKIssuer(t, "AIK CA")
	fixture := newDICEFixture(t, nil, true, true, true)

	t.Run("one format's roots are enough", func(t *testing.T) {
		for name, anchors := range map[string]TrustAnchors{
			"tpm":  {TPMRoots: []*x509.Certificate{issuer.cert}},
			"dice": {DICERoots: []*x509.Certificate{fixture.root}},
			"both": {TPMRoots: []*x509.Certificate{issuer.cert}, DICERoots: []*x509.Certificate{fixture.root}},
		} {
			verifier, err := NewTrustAnchorVerifier(anchors)
			require.NoError(t, err, name)
			assert.NotNil(t, verifier, name)
		}
	})

	t.Run("no roots at all is refused", func(t *testing.T) {
		verifier, err := NewTrustAnchorVerifier(TrustAnchors{})
		assert.ErrorIs(t, err, ErrNoTrustAnchors)
		assert.Nil(t, verifier)
	})

	t.Run("a nil root is refused rather than anchoring nothing", func(t *testing.T) {
		_, err := NewTrustAnchorVerifier(TrustAnchors{TPMRoots: []*x509.Certificate{issuer.cert, nil}})
		assert.ErrorIs(t, err, ErrNoTrustAnchors)
		_, err = NewTrustAnchorVerifier(TrustAnchors{DICERoots: []*x509.Certificate{nil}})
		assert.ErrorIs(t, err, ErrNoTrustAnchors)
	})
}

func TestTrustAnchorVerifierTPMChain(t *testing.T) {
	issuer := newAIKIssuer(t, "AIK CA")
	stranger := newAIKIssuer(t, "Not Configured")
	verifier, err := NewTrustAnchorVerifier(TrustAnchors{TPMRoots: []*x509.Certificate{issuer.cert}})
	require.NoError(t, err)

	t.Run("an AIK certified by a configured root is anchored", func(t *testing.T) {
		aik := issuer.issue(t, aikPublicKey(t), nil)
		require.NoError(t, verifier.VerifyAttestationObject(aikObject(aik), []byte(tpmKeyAuth)))
	})

	t.Run("an AIK certified by a root nobody configured is refused", func(t *testing.T) {
		aik := stranger.issue(t, aikPublicKey(t), nil)
		err := verifier.VerifyAttestationObject(aikObject(aik), []byte(tpmKeyAuth))
		assert.ErrorIs(t, err, ErrCertificateChainInvalid)
	})

	t.Run("a chain the device minted for itself is refused", func(t *testing.T) {
		// A self-signed AIK that the device also lists as its own root in
		// x5c: nothing the device sends can act as an anchor.
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		template := aikTemplate(t)
		der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
		require.NoError(t, err)
		err = verifier.VerifyAttestationObject(aikObject(der, der), []byte(tpmKeyAuth))
		assert.ErrorIs(t, err, ErrCertificateChainInvalid)
	})

	t.Run("a certificate that is not an AIK is refused", func(t *testing.T) {
		notAIK := issuer.issue(t, aikPublicKey(t), func(c *x509.Certificate) {
			c.ExtraExtensions = nil
		})
		err := verifier.VerifyAttestationObject(aikObject(notAIK), []byte(tpmKeyAuth))
		assert.ErrorIs(t, err, ErrAIKCertificateInvalid)
	})

	t.Run("an expired AIK is refused", func(t *testing.T) {
		expired := issuer.issue(t, aikPublicKey(t), func(c *x509.Certificate) {
			c.NotBefore = time.Now().Add(-2 * time.Hour)
			c.NotAfter = time.Now().Add(-time.Hour)
		})
		err := verifier.VerifyAttestationObject(aikObject(expired), []byte(tpmKeyAuth))
		assert.ErrorIs(t, err, ErrCertificateChainInvalid)
	})

	t.Run("the caller's certificate is not marked handled", func(t *testing.T) {
		aikDER := issuer.issue(t, aikPublicKey(t), nil)
		aik, err := x509.ParseCertificate(aikDER)
		require.NoError(t, err)
		require.NotEmpty(t, aik.UnhandledCriticalExtensions, "fixture lost its critical subjectAltName")
		before := len(aik.UnhandledCriticalExtensions)

		handled := withSubjectAltNameHandled(aik)
		assert.Empty(t, handled.UnhandledCriticalExtensions)
		assert.Len(t, aik.UnhandledCriticalExtensions, before)
	})
}

func TestTrustAnchorVerifierDICEChain(t *testing.T) {
	challenge := DICENonce(diceKeyAuth)
	genuine := newDICEFixture(t, challenge, true, true, true)
	verifier, err := NewTrustAnchorVerifier(TrustAnchors{DICERoots: []*x509.Certificate{genuine.root}})
	require.NoError(t, err)

	t.Run("an alias under a configured root echoing this challenge is accepted", func(t *testing.T) {
		require.NoError(t, verifier.VerifyAttestationObject(genuine.object(), []byte(diceKeyAuth)))
	})

	t.Run("a replayed answer to another challenge is refused", func(t *testing.T) {
		err := verifier.VerifyAttestationObject(genuine.object(), []byte("a different token.thumbprint"))
		assert.ErrorIs(t, err, ErrCertificateChainInvalid)
	})

	t.Run("an alias under a root nobody configured is refused", func(t *testing.T) {
		other := newDICEFixture(t, challenge, true, true, true)
		err := verifier.VerifyAttestationObject(other.object(), []byte(diceKeyAuth))
		assert.ErrorIs(t, err, ErrCertificateChainInvalid)
	})

	t.Run("an alias with no Ueid is refused: the identity is read from it", func(t *testing.T) {
		noUeid := newDICEFixture(t, challenge, false, true, true)
		v, err := NewTrustAnchorVerifier(TrustAnchors{DICERoots: []*x509.Certificate{noUeid.root}})
		require.NoError(t, err)
		assert.ErrorIs(t, v.VerifyAttestationObject(noUeid.object(), []byte(diceKeyAuth)), ErrCertificateChainInvalid)
	})

	t.Run("no key authorization to bind to is refused", func(t *testing.T) {
		err := verifier.VerifyAttestationObject(genuine.object(), nil)
		assert.ErrorIs(t, err, ErrInvalidAttestationObject)
	})

	t.Run("the configured policy is enforced", func(t *testing.T) {
		noMeasurement := newDICEFixture(t, challenge, true, true, false)
		noTcbInfo := newDICEFixture(t, challenge, true, false, false)
		sha384Signed := newDICEFixtureSignedOn(t, elliptic.P384(), challenge, true, true, true)
		for name, tc := range map[string]struct {
			fixture *diceFixture
			policy  DICEPolicy
		}{
			"a measurement is required":                       {noMeasurement, DICEPolicy{RequireMeasurement: true}},
			"a DiceTcbInfo is required":                       {noTcbInfo, DICEPolicy{RequireTcbInfo: true}},
			"a device-signed leaf must be ECDSA with SHA-256": {sha384Signed, DICEPolicy{RequireDeviceSignedLeaf: true}},
		} {
			t.Run(name, func(t *testing.T) {
				strict, err := NewTrustAnchorVerifier(TrustAnchors{DICERoots: []*x509.Certificate{tc.fixture.root}, DICE: tc.policy})
				require.NoError(t, err)
				err = strict.VerifyAttestationObject(tc.fixture.object(), []byte(diceKeyAuth))
				assert.ErrorIs(t, err, ErrCertificateChainInvalid)

				// The same fixture passes without the requirement, so the
				// refusal is the policy and not the fixture.
				lax, err := NewTrustAnchorVerifier(TrustAnchors{DICERoots: []*x509.Certificate{tc.fixture.root}})
				require.NoError(t, err)
				assert.NoError(t, lax.VerifyAttestationObject(tc.fixture.object(), []byte(diceKeyAuth)))
			})
		}
	})

	t.Run("a device-signed leaf is accepted when it is ECDSA with SHA-256", func(t *testing.T) {
		strict, err := NewTrustAnchorVerifier(TrustAnchors{
			DICERoots: []*x509.Certificate{genuine.root},
			DICE:      DICEPolicy{RequireDeviceSignedLeaf: true, RequireMeasurement: true, RequireTcbInfo: true},
		})
		require.NoError(t, err)
		assert.NoError(t, strict.VerifyAttestationObject(genuine.object(), []byte(diceKeyAuth)))
	})
}

func TestTrustAnchorVerifierFormatIsolation(t *testing.T) {
	issuer := newAIKIssuer(t, "AIK CA")
	fixture := newDICEFixture(t, DICENonce(diceKeyAuth), true, true, true)

	t.Run("a format with no configured root is refused, not checked against the other's", func(t *testing.T) {
		tpmOnly, err := NewTrustAnchorVerifier(TrustAnchors{TPMRoots: []*x509.Certificate{issuer.cert}})
		require.NoError(t, err)
		assert.ErrorIs(t, tpmOnly.VerifyAttestationObject(fixture.object(), []byte(diceKeyAuth)), ErrNoTrustAnchors)

		diceOnly, err := NewTrustAnchorVerifier(TrustAnchors{DICERoots: []*x509.Certificate{fixture.root}})
		require.NoError(t, err)
		aik := issuer.issue(t, aikPublicKey(t), nil)
		assert.ErrorIs(t, diceOnly.VerifyAttestationObject(aikObject(aik), []byte(tpmKeyAuth)), ErrNoTrustAnchors)
	})

	t.Run("a chain anchored to the other format's roots does not satisfy this one", func(t *testing.T) {
		// The DICE root vouches for DICE aliases only. An AIK it signed,
		// presented as a "tpm" statement, is not anchored by the TPM roots.
		verifier, err := NewTrustAnchorVerifier(TrustAnchors{
			TPMRoots:  []*x509.Certificate{issuer.cert},
			DICERoots: []*x509.Certificate{fixture.root},
		})
		require.NoError(t, err)
		other := newAIKIssuer(t, "DICE root used as an AIK issuer")
		aik := other.issue(t, aikPublicKey(t), nil)
		assert.ErrorIs(t, verifier.VerifyAttestationObject(aikObject(aik), []byte(tpmKeyAuth)), ErrCertificateChainInvalid)
	})
}

func TestTrustAnchorVerifierRefusesMalformedObjects(t *testing.T) {
	issuer := newAIKIssuer(t, "AIK CA")
	verifier, err := NewTrustAnchorVerifier(TrustAnchors{TPMRoots: []*x509.Certificate{issuer.cert}})
	require.NoError(t, err)

	tests := []struct {
		name   string
		object *AttestationObject
		want   error
	}{
		{"no object", nil, ErrInvalidAttestationObject},
		{"no x5c", &AttestationObject{Format: string(FormatTPM)}, ErrCertificateChainInvalid},
		{"x5c entry not a byte string", &AttestationObject{Format: string(FormatTPM), AttStatement: AttestationStatement{X5c: []interface{}{"text"}}}, ErrCertificateChainInvalid},
		{"x5c entry not a certificate", aikObject([]byte("not a certificate")), ErrCertificateChainInvalid},
		{"unknown format", &AttestationObject{Format: "apple", AttStatement: AttestationStatement{X5c: []interface{}{issuer.cert.Raw}}}, ErrInvalidAttestationFormat},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorIs(t, verifier.VerifyAttestationObject(tt.object, []byte(tpmKeyAuth)), tt.want)
		})
	}
}

func TestTrustAnchorVerifierAKCertificateChain(t *testing.T) {
	issuer := newAIKIssuer(t, "AIK CA")
	stranger := newAIKIssuer(t, "Not Configured")
	fixture := newDICEFixture(t, DICENonce(diceKeyAuth), true, true, true)
	verifier, err := NewTrustAnchorVerifier(TrustAnchors{
		TPMRoots:  []*x509.Certificate{issuer.cert},
		DICERoots: []*x509.Certificate{fixture.root},
	})
	require.NoError(t, err)

	t.Run("a chain reaching a configured root of either kind passes", func(t *testing.T) {
		require.NoError(t, verifier.VerifyAKCertificateChain([][]byte{issuer.issue(t, aikPublicKey(t), nil)}))
		require.NoError(t, verifier.VerifyAKCertificateChain([][]byte{fixture.leafDER}))
	})

	t.Run("a chain that ends at the root itself passes", func(t *testing.T) {
		require.NoError(t, verifier.VerifyAKCertificateChain([][]byte{issuer.issue(t, aikPublicKey(t), nil), issuer.cert.Raw}))
	})

	t.Run("a chain to a root nobody configured is refused", func(t *testing.T) {
		err := verifier.VerifyAKCertificateChain([][]byte{stranger.issue(t, aikPublicKey(t), nil)})
		assert.ErrorIs(t, err, ErrCertificateChainInvalid)
	})

	t.Run("a link that is not signed by the next is refused", func(t *testing.T) {
		err := verifier.VerifyAKCertificateChain([][]byte{
			issuer.issue(t, aikPublicKey(t), nil),
			stranger.cert.Raw,
		})
		assert.ErrorIs(t, err, ErrCertificateChainInvalid)
	})

	t.Run("an expired certificate is refused", func(t *testing.T) {
		expired := issuer.issue(t, aikPublicKey(t), func(c *x509.Certificate) {
			c.NotBefore = time.Now().Add(-2 * time.Hour)
			c.NotAfter = time.Now().Add(-time.Hour)
		})
		assert.ErrorIs(t, verifier.VerifyAKCertificateChain([][]byte{expired}), ErrCertificateChainInvalid)
	})

	t.Run("an empty or unparseable chain is refused", func(t *testing.T) {
		assert.ErrorIs(t, verifier.VerifyAKCertificateChain(nil), ErrCertificateChainInvalid)
		assert.ErrorIs(t, verifier.VerifyAKCertificateChain([][]byte{[]byte("garbage")}), ErrCertificateChainInvalid)
	})
}

// TestTrustAnchorVerifierDrivesVerifyAttestation runs the production verifier
// through the whole challenge path: the payload a device sends, the anchoring,
// the DICE evidence, the identity it carries and the key binding at
// finalization.
func TestTrustAnchorVerifierDrivesVerifyAttestation(t *testing.T) {
	fixture := newDICEFixture(t, DICENonce(diceKeyAuth), true, true, true)
	verifier, err := NewTrustAnchorVerifier(TrustAnchors{DICERoots: []*x509.Certificate{fixture.root}})
	require.NoError(t, err)

	verified, err := VerifyAttestation(verifier, attestationPayload(t, fixture.object()), diceKeyAuth)
	require.NoError(t, err)

	identity, err := verified.DeviceIdentity()
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(diceUeid), identity)
	require.NoError(t, verified.BindCSRKey(csrFor(t, fixture.key)), "the device's own key binds")

	software, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	assert.Error(t, verified.BindCSRKey(csrFor(t, software)), "a software key does not")

	t.Run("an attestation under no configured root never reaches the evidence", func(t *testing.T) {
		stranger := newDICEFixture(t, DICENonce(diceKeyAuth), true, true, true)
		_, err := VerifyAttestation(verifier, attestationPayload(t, stranger.object()), diceKeyAuth)
		require.Error(t, err)
	})
}

// An AIK issued by an intermediate CA is anchored by configuring that issuing
// CA as the root: Setup sends only the AIK certificate, and a certificate in
// the root set anchors a chain whether or not it is self-signed.
func TestTrustAnchorVerifierIntermediateConfiguredAsRoot(t *testing.T) {
	root := newAIKIssuer(t, "AIK Root")
	intermediateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: "AIK Issuing CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, root.cert, intermediateKey.Public(), root.key)
	require.NoError(t, err)
	intermediate, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	issuing := &aikIssuer{cert: intermediate, key: intermediateKey}
	aik := issuing.issue(t, aikPublicKey(t), nil)

	t.Run("the issuing CA as the root anchors the AIK alone", func(t *testing.T) {
		verifier, err := NewTrustAnchorVerifier(TrustAnchors{TPMRoots: []*x509.Certificate{intermediate}})
		require.NoError(t, err)
		require.NoError(t, verifier.VerifyAttestationObject(aikObject(aik), []byte(tpmKeyAuth)))
		require.NoError(t, verifier.VerifyAKCertificateChain([][]byte{aik}))
	})

	t.Run("the top root alone does not, without the intermediate in x5c", func(t *testing.T) {
		verifier, err := NewTrustAnchorVerifier(TrustAnchors{TPMRoots: []*x509.Certificate{root.cert}})
		require.NoError(t, err)
		assert.ErrorIs(t, verifier.VerifyAttestationObject(aikObject(aik), []byte(tpmKeyAuth)), ErrCertificateChainInvalid)
		assert.NoError(t, verifier.VerifyAttestationObject(aikObject(aik, intermediate.Raw), []byte(tpmKeyAuth)),
			"the same root anchors it once the device sends the intermediate")
	})
}
