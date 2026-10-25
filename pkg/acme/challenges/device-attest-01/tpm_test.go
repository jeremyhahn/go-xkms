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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/certstore"
)

const tpmKeyAuth = "token.thumbprint-of-the-account-key"

// coseES256 is the COSE identifier for ECDSA with SHA-256, the algorithm the
// simulated AIK signs with.
const coseES256 = int64(-7)

// aikIssuer is a CA that issues AIK certificates, standing in for a TPM
// manufacturer or an enterprise attestation CA.
type aikIssuer struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newAIKIssuer(t *testing.T, name string) *aikIssuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return &aikIssuer{cert: cert, key: key}
}

// tcgSubjectAltName is the subjectAltName the TCG EK Credential Profile
// section 3.2.9 defines: a directoryName naming the TPM. It is critical
// because the subject is empty (RFC 5280 section 4.2.1.6).
func tcgSubjectAltName(t *testing.T, manufacturer, model, version string) pkix.Extension {
	t.Helper()
	var attributes []pkix.AttributeTypeAndValue
	for _, attribute := range []struct {
		oid   asn1.ObjectIdentifier
		value string
	}{
		{certstore.OIDTCGAttributeTPMManufacturer, manufacturer},
		{certstore.OIDTCGAttributeTPMModel, model},
		{certstore.OIDTCGAttributeTPMVersion, version},
	} {
		if attribute.value != "" {
			attributes = append(attributes, pkix.AttributeTypeAndValue{Type: attribute.oid, Value: attribute.value})
		}
	}
	name, err := asn1.Marshal(pkix.Name{ExtraNames: attributes}.ToRDNSequence())
	require.NoError(t, err)
	value, err := asn1.Marshal([]asn1.RawValue{{Class: asn1.ClassContextSpecific, Tag: 4, IsCompound: true, Bytes: name}})
	require.NoError(t, err)
	return pkix.Extension{Id: oidSubjectAltName, Critical: true, Value: value}
}

// aikTemplate is a certificate meeting WebAuthn Level 2 section 8.3.1.
func aikTemplate(t *testing.T) *x509.Certificate {
	t.Helper()
	return &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{certstore.OIDTCGKpAIKCertificate},
		BasicConstraintsValid: true,
		ExtraExtensions:       []pkix.Extension{tcgSubjectAltName(t, "id:53494D00", "SIM", "id:00020000")},
	}
}

// issue certifies an attestation key, letting a test bend the template to
// produce a certificate that breaks one requirement.
func (i *aikIssuer) issue(t *testing.T, pub crypto.PublicKey, bend func(*x509.Certificate)) []byte {
	t.Helper()
	template := aikTemplate(t)
	if bend != nil {
		bend(template)
	}
	der, err := x509.CreateCertificate(rand.Reader, template, i.cert, pub, i.key)
	require.NoError(t, err)
	return der
}

// anchoredVerifier is the server's trust policy: x5c must chain to roots.
//
// An AIK certificate's subjectAltName is critical and holds only a
// directoryName, which crypto/x509 reports as an unhandled critical extension.
// Having read it -- checkAIKCertificate does -- the verifier marks it handled,
// which is what any anchoring implementation for this format has to do.
type anchoredVerifier struct {
	roots        *x509.CertPool
	chainChecked bool
}

func anchoredTo(issuers ...*aikIssuer) *anchoredVerifier {
	roots := x509.NewCertPool()
	for _, issuer := range issuers {
		roots.AddCert(issuer.cert)
	}
	return &anchoredVerifier{roots: roots}
}

func (a *anchoredVerifier) VerifyAttestationObject(*AttestationObject, []byte) error { return nil }

func (a *anchoredVerifier) VerifyAKCertificateChain(chain [][]byte) error {
	a.chainChecked = true
	leaf, err := x509.ParseCertificate(chain[0])
	if err != nil {
		return err
	}
	handled := leaf.UnhandledCriticalExtensions[:0]
	for _, oid := range leaf.UnhandledCriticalExtensions {
		if !oid.Equal(oidSubjectAltName) {
			handled = append(handled, oid)
		}
	}
	leaf.UnhandledCriticalExtensions = handled

	intermediates := x509.NewCertPool()
	for _, der := range chain[1:] {
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			return err
		}
		intermediates.AddCert(cert)
	}
	_, err = leaf.Verify(x509.VerifyOptions{
		Roots:         a.roots,
		Intermediates: intermediates,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	})
	return err
}

func TestTPMExtraDataHashesTheKeyAuthorizationWithAlg(t *testing.T) {
	es256, err := TPMExtraData(coseES256, tpmKeyAuth)
	require.NoError(t, err)
	sum256 := sha256.Sum256([]byte(tpmKeyAuth))
	assert.Equal(t, sum256[:], es256)
	assert.Equal(t, DICENonce(tpmKeyAuth), es256, "for SHA-256 algorithms the tpm and dice digests coincide")

	// ES384: alg chooses the hash, so a device signing with it answers with
	// SHA-384 -- the difference from DICENonce this function exists for.
	es384, err := TPMExtraData(-35, tpmKeyAuth)
	require.NoError(t, err)
	sum384 := sha512.Sum384([]byte(tpmKeyAuth))
	assert.Equal(t, sum384[:], es384)
}

func TestTPMExtraDataRefusesWhatItCannotHash(t *testing.T) {
	_, err := TPMExtraData(coseES256, "")
	assert.ErrorIs(t, err, ErrTPMAttestationInvalid)

	// An identifier that names no signature algorithm is refused, never
	// defaulted to a hash: a guess about what the device hashed is not a check.
	_, err = TPMExtraData(0, tpmKeyAuth)
	assert.ErrorIs(t, err, ErrTPMAttestationInvalid)
}

func TestCOSESignatureAlgorithm(t *testing.T) {
	cases := map[int64]x509.SignatureAlgorithm{
		-7:   x509.ECDSAWithSHA256,
		-35:  x509.ECDSAWithSHA384,
		-257: x509.SHA256WithRSA,
		-37:  x509.SHA256WithRSAPSS,
	}
	for alg, want := range cases {
		got, err := coseSignatureAlgorithm(alg)
		require.NoError(t, err)
		assert.Equal(t, want, got, "alg %d", alg)
	}

	_, err := coseSignatureAlgorithm(12345)
	assert.ErrorIs(t, err, ErrTPMAttestationInvalid)
}

func TestCheckAIKCertificateAppliesSection831(t *testing.T) {
	issuer := newAIKIssuer(t, "AIK CA")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	parse := func(der []byte) *x509.Certificate {
		cert, err := x509.ParseCertificate(der)
		require.NoError(t, err)
		return cert
	}

	require.NoError(t, checkAIKCertificate(parse(issuer.issue(t, key.Public(), nil))))

	cases := []struct {
		name string
		bend func(*x509.Certificate)
	}{
		{"a subject", func(c *x509.Certificate) { c.Subject = pkix.Name{CommonName: "aik"} }},
		{"no subjectAltName", func(c *x509.Certificate) { c.ExtraExtensions = nil }},
		{"a subjectAltName without the model", func(c *x509.Certificate) {
			c.ExtraExtensions = []pkix.Extension{tcgSubjectAltName(t, "id:53494D00", "", "id:00020000")}
		}},
		{"a CA", func(c *x509.Certificate) { c.IsCA = true }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := checkAIKCertificate(parse(issuer.issue(t, key.Public(), tc.bend)))
			assert.ErrorIs(t, err, ErrAIKCertificateInvalid)
		})
	}

	t.Run("not version 3", func(t *testing.T) {
		// crypto/x509 only writes v3, so the parsed field is set directly.
		cert := parse(issuer.issue(t, key.Public(), nil))
		cert.Version = 1
		assert.ErrorIs(t, checkAIKCertificate(cert), ErrAIKCertificateInvalid)
	})
}

func TestVerifyTPMEvidenceRefusesMalformedStatements(t *testing.T) {
	issuer := newAIKIssuer(t, "AIK CA")
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	aikDER := issuer.issue(t, key.Public(), nil)

	statement := func() AttestationStatement {
		return AttestationStatement{
			Ver:      "2.0",
			Alg:      coseES256,
			X5c:      []interface{}{aikDER},
			Sig:      []byte{0x01},
			CertInfo: []byte{0x02},
			PubArea:  []byte{0x03},
		}
	}
	cases := []struct {
		name    string
		bend    func(*AttestationStatement)
		keyAuth string
		want    error
	}{
		{"another ver", func(s *AttestationStatement) { s.Ver = "1.2" }, tpmKeyAuth, ErrTPMAttestationInvalid},
		{"no x5c", func(s *AttestationStatement) { s.X5c = nil }, tpmKeyAuth, ErrTPMAttestationInvalid},
		{"an x5c entry that is not bytes", func(s *AttestationStatement) { s.X5c = []interface{}{"aik"} }, tpmKeyAuth, ErrTPMAttestationInvalid},
		{"an AIK that does not parse", func(s *AttestationStatement) { s.X5c = []interface{}{[]byte{0x30, 0x00}} }, tpmKeyAuth, ErrTPMAttestationInvalid},
		{"no pubArea", func(s *AttestationStatement) { s.PubArea = nil }, tpmKeyAuth, ErrTPMAttestationInvalid},
		{"an unknown alg", func(s *AttestationStatement) { s.Alg = 12345 }, tpmKeyAuth, ErrTPMAttestationInvalid},
		{"no key authorization", func(*AttestationStatement) {}, "", ErrTPMAttestationInvalid},
		{"a certification that does not verify", func(*AttestationStatement) {}, tpmKeyAuth, ErrTPMAttestationInvalid},
		{"an AIK certificate with a subject", func(s *AttestationStatement) {
			s.X5c = []interface{}{issuer.issue(t, key.Public(), func(c *x509.Certificate) { c.Subject = pkix.Name{CommonName: "aik"} })}
		}, tpmKeyAuth, ErrAIKCertificateInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := statement()
			tc.bend(&s)
			verified, err := verifyTPMEvidence(&AttestationObject{Format: string(FormatTPM), AttStatement: s}, nil, tc.keyAuth)
			assert.ErrorIs(t, err, tc.want)
			assert.Nil(t, verified, "a refused attestation must carry nothing forward")
		})
	}
}

// Every x5c entry must be a certificate. Dropping one that is not would anchor
// a chain other than the one the device sent.
func TestVerifyAttestationRefusesAnX5cEntryThatIsNotACertificate(t *testing.T) {
	payload := attestationPayload(t, &AttestationObject{
		Format: string(FormatTPM),
		AttStatement: AttestationStatement{
			Ver: "2.0", Alg: coseES256,
			X5c: []interface{}{[]byte{0x30, 0x00}, 12345},
		},
	})
	ca := &mockCA{}

	_, err := VerifyAttestation(context.Background(), ca, payload, tpmKeyAuth)
	assert.ErrorIs(t, err, ErrCertificateChainInvalid)
	assert.False(t, ca.verifyAKChainCalled, "a partial chain was handed to the anchor")
}

// Section 8.3 requires x5c. Without it there is nothing to anchor and no key
// to verify sig under, so the statement is refused rather than skipped past.
func TestVerifyAttestationRefusesATPMStatementWithoutX5c(t *testing.T) {
	payload := attestationPayload(t, &AttestationObject{
		Format:       string(FormatTPM),
		AttStatement: AttestationStatement{Ver: "2.0", Alg: coseES256},
	})

	_, err := VerifyAttestation(context.Background(), &mockCA{}, payload, tpmKeyAuth)
	assert.ErrorIs(t, err, ErrTPMAttestationInvalid)
}

func TestTPMCSREvidenceRefusesAnIncompleteRecord(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	issuer := newAIKIssuer(t, "AIK CA")

	incomplete := &VerifiedAttestation{
		Format:           FormatTPM,
		KeyAuthorization: tpmKeyAuth,
		LeafDER:          issuer.issue(t, key.Public(), nil),
		Algorithm:        coseES256,
	}
	assert.ErrorIs(t, incomplete.BindCSRKey(csrFor(t, key)), ErrKeyBindingUnavailable)

	leafless := &VerifiedAttestation{
		Format:           FormatTPM,
		KeyAuthorization: tpmKeyAuth,
		Algorithm:        coseES256,
		CertInfo:         []byte{0x01},
		Signature:        []byte{0x02},
		PubArea:          []byte{0x03},
	}
	assert.ErrorIs(t, leafless.BindCSRKey(csrFor(t, key)), ErrKeyBindingUnavailable)
}
