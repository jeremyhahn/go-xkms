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

package attestation

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	gotpm "github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/certstore"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2"
)

// certifiedByAIK is a TPM2_Certify whose attester is identified by an AIK
// certificate, the shape the WebAuthn "tpm" statement delivers. It is built in
// software so the gate can be driven through every branch; the device-attest-01
// tests drive the same gate with a simulated TPM.
type certifiedByAIK struct {
	aik         *x509.Certificate
	subjectKey  *ecdsa.PrivateKey
	subjectArea []byte
	certifyInfo []byte
	signature   []byte
	extraData   []byte
}

// tpmECCArea is the TPMT_PUBLIC of a P-256 signing key.
func tpmECCArea(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	point, err := key.PublicKey.Bytes()
	require.NoError(t, err)
	return gotpm.Marshal(gotpm.TPMTPublic{
		Type:    gotpm.TPMAlgECC,
		NameAlg: gotpm.TPMAlgSHA256,
		ObjectAttributes: gotpm.TPMAObject{
			FixedTPM: true, FixedParent: true, SensitiveDataOrigin: true,
			UserWithAuth: true, SignEncrypt: true,
		},
		Parameters: gotpm.NewTPMUPublicParms(gotpm.TPMAlgECC, &gotpm.TPMSECCParms{
			CurveID: gotpm.TPMECCNistP256,
			Scheme: gotpm.TPMTECCScheme{
				Scheme:  gotpm.TPMAlgECDSA,
				Details: gotpm.NewTPMUAsymScheme(gotpm.TPMAlgECDSA, &gotpm.TPMSSigSchemeECDSA{HashAlg: gotpm.TPMAlgSHA256}),
			},
		}),
		Unique: gotpm.NewTPMUPublicID(gotpm.TPMAlgECC, &gotpm.TPMSECCPoint{
			X: gotpm.TPM2BECCParameter{Buffer: point[1:33]},
			Y: gotpm.TPM2BECCParameter{Buffer: point[33:]},
		}),
	})
}

func newCertifiedByAIK(t *testing.T) *certifiedByAIK {
	t.Helper()

	aikKey := newKey(t)
	template := &x509.Certificate{
		SerialNumber:       big.NewInt(1),
		NotBefore:          time.Now().Add(-time.Hour),
		NotAfter:           time.Now().Add(time.Hour),
		UnknownExtKeyUsage: []asn1.ObjectIdentifier{certstore.OIDTCGKpAIKCertificate},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, aikKey.Public(), aikKey)
	require.NoError(t, err)
	aik, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	subjectKey := newKey(t)
	subjectArea := tpmECCArea(t, subjectKey)
	subject, err := gotpm.Unmarshal[gotpm.TPMTPublic](subjectArea)
	require.NoError(t, err)
	name, err := gotpm.ObjectName(subject)
	require.NoError(t, err)

	extraData := sha256.Sum256([]byte("token.thumbprint"))
	certifyInfo := gotpm.Marshal(gotpm.TPMSAttest{
		Magic:     gotpm.TPMGeneratedValue,
		Type:      gotpm.TPMSTAttestCertify,
		ExtraData: gotpm.TPM2BData{Buffer: extraData[:]},
		Attested: gotpm.NewTPMUAttest(gotpm.TPMSTAttestCertify,
			&gotpm.TPMSCertifyInfo{Name: *name, QualifiedName: *name}),
	})
	digest := sha256.Sum256(certifyInfo)
	signature, err := ecdsa.SignASN1(rand.Reader, aikKey, digest[:])
	require.NoError(t, err)

	return &certifiedByAIK{
		aik:         aik,
		subjectKey:  subjectKey,
		subjectArea: subjectArea,
		certifyInfo: certifyInfo,
		signature:   signature,
		extraData:   extraData[:],
	}
}

// evidence is the certification as the gate receives it, bound to spki.
func (c *certifiedByAIK) evidence(spki []byte) *Evidence {
	return &Evidence{
		Format:                    FormatTPM2,
		AttesterCertificate:       c.aik,
		CertifySignatureAlgorithm: x509.ECDSAWithSHA256,
		SubjectPublicArea:         c.subjectArea,
		CertifyInfo:               c.certifyInfo,
		CertifySignature:          c.signature,
		SubjectSPKI:               spki,
		ExpectedChallenge:         c.extraData,
	}
}

func spkiOf(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	require.NoError(t, err)
	return der
}

func TestVerifyInvariants_TPM2BindsTheCertifiedKeyToTheCSRKey(t *testing.T) {
	c := newCertifiedByAIK(t)

	require.NoError(t, VerifyInvariants(c.evidence(spkiOf(t, c.subjectKey))))

	// A genuine certification of the device's key, presented beside a key the
	// requester made in software. Everything about the certification verifies;
	// it is simply about a different key.
	err := VerifyInvariants(c.evidence(spkiOf(t, newKey(t))))
	assert.ErrorIs(t, err, ErrKeyNotBound)
}

// With no subject key the gate checks the certification alone, which is what a
// challenge that has not yet seen the CSR -- or a TCG-CSR-IDEVID, whose subject
// public area is the key being certified -- asks of it.
func TestVerifyInvariants_TPM2WithoutASubjectKeyChecksTheCertification(t *testing.T) {
	c := newCertifiedByAIK(t)
	require.NoError(t, VerifyInvariants(c.evidence(nil)))

	tampered := c.evidence(nil)
	tampered.CertifySignature = append([]byte{}, c.signature...)
	tampered.CertifySignature[len(tampered.CertifySignature)-1] ^= 0xFF
	assert.ErrorIs(t, VerifyInvariants(tampered), ErrKeyNotBound)
}

// The challenge of a TPM2_Certify is its extraData, so a certification made for
// another exchange is stale rather than unbound: it may be a recording.
func TestVerifyInvariants_TPM2ChallengeIsTheCertifyExtraData(t *testing.T) {
	c := newCertifiedByAIK(t)
	ev := c.evidence(spkiOf(t, c.subjectKey))
	ev.ExpectedChallenge = []byte("another exchange's challenge")

	err := VerifyInvariants(ev)
	assert.ErrorIs(t, err, ErrStaleEvidence)
	assert.ErrorIs(t, err, tpm2.ErrCertifyQualifyingDataMismatch)
}

func TestVerifyInvariants_TPM2RefusesWhatItCannotCheck(t *testing.T) {
	c := newCertifiedByAIK(t)

	t.Run("no attester", func(t *testing.T) {
		ev := c.evidence(nil)
		ev.AttesterCertificate = nil
		assert.ErrorIs(t, VerifyInvariants(ev), ErrBindingUnavailable)
	})

	t.Run("two attester identities", func(t *testing.T) {
		ev := c.evidence(nil)
		ev.AttesterPublicArea = c.subjectArea
		assert.ErrorIs(t, VerifyInvariants(ev), ErrBindingUnavailable)
	})

	t.Run("no subject public area", func(t *testing.T) {
		ev := c.evidence(nil)
		ev.SubjectPublicArea = nil
		assert.ErrorIs(t, VerifyInvariants(ev), ErrBindingUnavailable)
	})

	t.Run("an attester that is not an attestation key", func(t *testing.T) {
		ev := c.evidence(nil)
		ordinary := *c.aik
		ordinary.UnknownExtKeyUsage = nil
		ev.AttesterCertificate = &ordinary
		err := VerifyInvariants(ev)
		assert.ErrorIs(t, err, ErrKeyNotBound)
		assert.ErrorIs(t, err, tpm2.ErrCertifyAttesterUnrestricted)
	})

	t.Run("a subject key that does not parse", func(t *testing.T) {
		assert.ErrorIs(t, VerifyInvariants(c.evidence([]byte{0x30, 0x00})), ErrKeyNotBound)
	})
}

func TestVerifyCertifiedKeyIsSubjectKey(t *testing.T) {
	key := newKey(t)
	area := tpmECCArea(t, key)

	require.NoError(t, verifyCertifiedKeyIsSubjectKey(area, spkiOf(t, key)))
	assert.ErrorIs(t, verifyCertifiedKeyIsSubjectKey(area, spkiOf(t, newKey(t))), ErrKeyNotBound)
	assert.ErrorIs(t, verifyCertifiedKeyIsSubjectKey([]byte{0x00, 0x01}, spkiOf(t, key)), ErrKeyNotBound,
		"a public area holding no key must never compare equal to one")
}
