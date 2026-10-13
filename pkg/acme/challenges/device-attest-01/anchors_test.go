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
	"context"
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

// diceUeid is the device identifier the DICE fixtures carry: a random-type
// UEID, 0x01 followed by the 16-byte DeviceID.
var diceUeid = []byte{
	0x01,
	0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
	0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
}

// diceFixture is a device provisioned with a DeviceID certificate: a
// manufacturer root, the DeviceID certificate it issued for the device's
// DeviceID key and UEID, and an alias certificate the device signed with that
// key, for that key.
type diceFixture struct {
	root     *x509.Certificate
	rootKey  *ecdsa.PrivateKey
	deviceID *x509.Certificate
	leafDER  []byte
	key      *ecdsa.PrivateKey
}

// newDICEFixture mints an endorsed DICE device. challenge is echoed in the
// alias's eat_nonce (nil echoes nothing), withUeid and withTcbInfo choose
// which evidence extensions the alias carries, and withMeasurement whether
// DiceTcbInfo carries a firmware measurement.
func newDICEFixture(t *testing.T, challenge []byte, withUeid, withTcbInfo, withMeasurement bool) *diceFixture {
	t.Helper()
	return newDICEFixtureSignedWith(t, x509.ECDSAWithSHA256, challenge, withUeid, withTcbInfo, withMeasurement)
}

// newDICEFixtureSignedWith is newDICEFixture with the alias signed under
// algorithm: ECDSA-SHA256 is the one a secure element performs.
func newDICEFixtureSignedWith(t *testing.T, algorithm x509.SignatureAlgorithm, challenge []byte, withUeid, withTcbInfo, withMeasurement bool) *diceFixture {
	t.Helper()

	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
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

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	fixture := &diceFixture{root: root, rootKey: rootKey, key: key}
	fixture.deviceID = fixture.issueDeviceID(t, diceUeid)

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

	leafTemplate := &x509.Certificate{
		SerialNumber:       big.NewInt(3),
		Subject:            pkix.Name{CommonName: "Test DICE Alias"},
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(time.Hour),
		SignatureAlgorithm: algorithm,
		ExtraExtensions:    extensions,
	}
	fixture.leafDER, err = x509.CreateCertificate(rand.Reader, leafTemplate, fixture.deviceID, key.Public(), key)
	require.NoError(t, err)
	return fixture
}

// issueDeviceID has the fixture's root issue a DeviceID certificate for its
// DeviceID key, naming ueid.
func (f *diceFixture) issueDeviceID(t *testing.T, ueid []byte) *x509.Certificate {
	t.Helper()
	extension, err := dice.CreateUeidExtension(ueid)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "Test DICE DeviceID"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		ExtraExtensions:       []pkix.Extension{extension},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, f.root, f.key.Public(), f.rootKey)
	require.NoError(t, err)
	deviceID, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return deviceID
}

func (f *diceFixture) object() *AttestationObject {
	return diceLeafObject(f.leafDER)
}

// registry provisions the fixture's device with its DeviceID certificate.
func (f *diceFixture) registry() testRegistry {
	return testRegistry{hex.EncodeToString(diceUeid): {DeviceIDCertificate: f.deviceID.Raw}}
}

// verifier is the production verifier anchoring the fixture's device in its
// registry record and roots, under policy.
func (f *diceFixture) verifier(t *testing.T, policy DICEPolicy) *TrustAnchorVerifier {
	t.Helper()
	return registryVerifier(t, TrustAnchors{DICERoots: []*x509.Certificate{f.root}, Devices: f.registry(), DICE: policy})
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
			// The raw-key path is anchored in the registry, not in a root.
			"a device registry": {Devices: testRegistry{}},
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
	verifier := genuine.verifier(t, DICEPolicy{})
	verify := func(v *TrustAnchorVerifier, f *diceFixture, keyAuth string) error {
		_, err := VerifyAttestation(context.Background(), v, attestationPayload(t, f.object()), keyAuth)
		return err
	}

	t.Run("an alias endorsed by its provisioned DeviceID certificate echoing this challenge is accepted", func(t *testing.T) {
		require.NoError(t, verify(verifier, genuine, diceKeyAuth))
	})

	t.Run("a chain alone never anchors dice evidence", func(t *testing.T) {
		err := verifier.VerifyAttestationObject(genuine.object(), []byte(diceKeyAuth))
		assert.ErrorIs(t, err, ErrDeviceNotAuthorized)
	})

	t.Run("a replayed answer to another challenge is refused", func(t *testing.T) {
		assert.ErrorIs(t, verify(verifier, genuine, "a different token.thumbprint"), ErrCertificateChainInvalid)
	})

	t.Run("an alias with no Ueid is refused: the identity is read from it", func(t *testing.T) {
		noUeid := newDICEFixture(t, challenge, false, true, true)
		assert.ErrorIs(t, verify(noUeid.verifier(t, DICEPolicy{}), noUeid, diceKeyAuth), ErrDeviceNotAuthorized)
	})

	t.Run("no key authorization to bind to is refused", func(t *testing.T) {
		leaf, err := x509.ParseCertificate(genuine.leafDER)
		require.NoError(t, err)
		_, err = verifier.VerifyRegisteredDevice(context.Background(), leaf, "")
		assert.ErrorIs(t, err, ErrInvalidAttestationObject)
		assert.Error(t, verify(verifier, genuine, ""))
	})

	t.Run("the configured policy is enforced", func(t *testing.T) {
		noMeasurement := newDICEFixture(t, challenge, true, true, false)
		noTcbInfo := newDICEFixture(t, challenge, true, false, false)
		for name, tc := range map[string]struct {
			fixture *diceFixture
			policy  DICEPolicy
		}{
			"a measurement is required": {noMeasurement, DICEPolicy{RequireMeasurement: true}},
			"a DiceTcbInfo is required": {noTcbInfo, DICEPolicy{RequireTcbInfo: true}},
		} {
			t.Run(name, func(t *testing.T) {
				err := verify(tc.fixture.verifier(t, tc.policy), tc.fixture, diceKeyAuth)
				assert.ErrorIs(t, err, ErrCertificateChainInvalid)

				// The same fixture passes without the requirement, so the
				// refusal is the policy and not the fixture.
				assert.NoError(t, verify(tc.fixture.verifier(t, DICEPolicy{}), tc.fixture, diceKeyAuth))
			})
		}
	})

	t.Run("an alias its DeviceID key signed with anything but ECDSA with SHA-256 is refused under any policy", func(t *testing.T) {
		// dice.Verify holds every certificate a device key signs to
		// ECDSA-SHA256, so the endorsement path cannot be relaxed below it.
		sha384Signed := newDICEFixtureSignedWith(t, x509.ECDSAWithSHA384, challenge, true, true, true)
		err := verify(sha384Signed.verifier(t, DICEPolicy{}), sha384Signed, diceKeyAuth)
		assert.ErrorIs(t, err, ErrCertificateChainInvalid)
		assert.ErrorIs(t, err, dice.ErrUnsupportedSignatureAlgorithm)
	})

	t.Run("a device-signed leaf is accepted when it is ECDSA with SHA-256", func(t *testing.T) {
		strict := genuine.verifier(t, DICEPolicy{RequireDeviceSignedLeaf: true, RequireMeasurement: true, RequireTcbInfo: true})
		assert.NoError(t, verify(strict, genuine, diceKeyAuth))
	})
}

func TestTrustAnchorVerifierFormatIsolation(t *testing.T) {
	issuer := newAIKIssuer(t, "AIK CA")
	fixture := newDICEFixture(t, DICENonce(diceKeyAuth), true, true, true)

	t.Run("a format with no configured root is refused, not checked against the other's", func(t *testing.T) {
		tpmOnly, err := NewTrustAnchorVerifier(TrustAnchors{TPMRoots: []*x509.Certificate{issuer.cert}})
		require.NoError(t, err)
		_, err = VerifyAttestation(context.Background(), tpmOnly, attestationPayload(t, fixture.object()), diceKeyAuth)
		assert.ErrorIs(t, err, ErrDeviceNotAuthorized)
		assert.ErrorIs(t, err, ErrNoDeviceResolver)

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
		require.NoError(t, verifier.VerifyAKCertificateChain([][]byte{fixture.deviceID.Raw}))
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
	verifier := fixture.verifier(t, DICEPolicy{})

	verified, err := VerifyAttestation(context.Background(), verifier, attestationPayload(t, fixture.object()), diceKeyAuth)
	require.NoError(t, err)
	assert.Equal(t, fixture.deviceID.RawSubjectPublicKeyInfo, verified.AttestedSPKI,
		"the attested SPKI is the provisioned DeviceID certificate's key")

	identity, err := verified.DeviceIdentity()
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(diceUeid), identity)
	require.NoError(t, verified.BindCSRKey(csrFor(t, fixture.key)), "the device's own key binds")
	require.NoError(t, verified.ConfirmRegistration(context.Background(), verifier), "the registry still vouches for it")

	software, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	assert.Error(t, verified.BindCSRKey(csrFor(t, software)), "a software key does not")

	t.Run("an attestation under no configured root never reaches the evidence", func(t *testing.T) {
		stranger := newDICEFixture(t, DICENonce(diceKeyAuth), true, true, true)
		_, err := VerifyAttestation(context.Background(), verifier, attestationPayload(t, stranger.object()), diceKeyAuth)
		assert.ErrorIs(t, err, ErrDeviceNotAuthorized)
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
