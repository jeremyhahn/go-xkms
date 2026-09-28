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

package tpm2

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"

	"github.com/google/go-tpm/tpm2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/certstore"
)

// attestingCertificate certifies key the way an AIK certificate does, or --
// with asAIK false -- as an ordinary signing certificate that makes no claim
// the key is a TPM attestation key.
func attestingCertificate(t *testing.T, key *ecdsa.PrivateKey, asAIK bool) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
	if asAIK {
		template.UnknownExtKeyUsage = []asn1.ObjectIdentifier{certstore.OIDTCGKpAIKCertificate}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)
	require.NoError(t, err)
	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return cert
}

// signASN1 signs certifyInfo the way a WebAuthn "tpm" statement carries sig
// for ES256: an ASN.1 DER ECDSA signature over SHA-256 of the bytes.
func signASN1(t *testing.T, key *ecdsa.PrivateKey, data []byte) []byte {
	t.Helper()
	digest := sha256.Sum256(data)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	require.NoError(t, err)
	return sig
}

func TestVerifyCertifyByCertificate_AcceptsAGenuineCertification(t *testing.T) {
	f := newCertifyFixture(t)
	aik := attestingCertificate(t, f.attesterKey, true)

	result, err := VerifyCertifyByCertificate(
		f.certifyInfo, signASN1(t, f.attesterKey, f.certifyInfo),
		x509.ECDSAWithSHA256, aik, f.subjectPub,
		&VerifyCertifyOptions{ExpectedQualifyingData: f.qualifyingIn},
	)

	require.NoError(t, err)
	assert.Equal(t, f.qualifyingIn, result.QualifyingData)
	assert.NotEmpty(t, result.SubjectName)
	assert.Equal(t, aik.PublicKey, result.AttesterPublicKey)
}

// TestVerifyCertifyByCertificate_RequiresAnAttestationKeyCertificate is the
// stand-in for the restricted-key check.
//
// With no public area there is no restricted attribute to read. What says the
// key will not sign caller-composed bytes is its certificate naming it a TPM
// attestation key; a certificate for an ordinary signing key says nothing of
// the kind, and that key could have signed a hand-built TPMS_ATTEST.
func TestVerifyCertifyByCertificate_RequiresAnAttestationKeyCertificate(t *testing.T) {
	f := newCertifyFixture(t)
	ordinary := attestingCertificate(t, f.attesterKey, false)
	sig := signASN1(t, f.attesterKey, f.certifyInfo)

	_, err := VerifyCertifyByCertificate(f.certifyInfo, sig, x509.ECDSAWithSHA256, ordinary, f.subjectPub, nil)
	assert.ErrorIs(t, err, ErrCertifyAttesterUnrestricted)

	_, err = VerifyCertifyByCertificate(f.certifyInfo, sig, x509.ECDSAWithSHA256, ordinary, f.subjectPub,
		&VerifyCertifyOptions{AllowUnrestrictedAttester: true})
	assert.NoError(t, err, "the option that exists for tests must still switch the check off")
}

func TestVerifyCertifyByCertificate_RejectsAForeignSignature(t *testing.T) {
	f := newCertifyFixture(t)
	aik := attestingCertificate(t, f.attesterKey, true)
	stranger, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	_, err = VerifyCertifyByCertificate(f.certifyInfo, signASN1(t, stranger, f.certifyInfo),
		x509.ECDSAWithSHA256, aik, f.subjectPub, nil)

	assert.ErrorIs(t, err, ErrCertifySignature)
}

// The algorithm is the statement's, not the certificate's: naming one the key
// cannot have signed with must fail verification rather than be ignored.
func TestVerifyCertifyByCertificate_RejectsTheWrongAlgorithm(t *testing.T) {
	f := newCertifyFixture(t)
	aik := attestingCertificate(t, f.attesterKey, true)

	_, err := VerifyCertifyByCertificate(f.certifyInfo, signASN1(t, f.attesterKey, f.certifyInfo),
		x509.SHA256WithRSA, aik, f.subjectPub, nil)

	assert.ErrorIs(t, err, ErrCertifySignature)
}

func TestVerifyCertifyByCertificate_AppliesTheCertificationChecks(t *testing.T) {
	f := newCertifyFixture(t)
	aik := attestingCertificate(t, f.attesterKey, true)

	t.Run("a quote", func(t *testing.T) {
		quote := tpm2.Marshal(tpm2.TPMSAttest{
			Magic:     tpm2.TPMGeneratedValue,
			Type:      tpm2.TPMSTAttestQuote,
			ExtraData: tpm2.TPM2BData{Buffer: f.qualifyingIn},
			Attested: tpm2.NewTPMUAttest(tpm2.TPMSTAttestQuote,
				&tpm2.TPMSQuoteInfo{PCRDigest: tpm2.TPM2BDigest{Buffer: make([]byte, 32)}}),
		})
		_, err := VerifyCertifyByCertificate(quote, signASN1(t, f.attesterKey, quote),
			x509.ECDSAWithSHA256, aik, f.subjectPub, nil)
		assert.ErrorIs(t, err, ErrCertifyWrongType)
	})

	t.Run("another subject", func(t *testing.T) {
		stranger, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)
		area := eccPublicArea(t, stranger, false)
		_, err = VerifyCertifyByCertificate(f.certifyInfo, signASN1(t, f.attesterKey, f.certifyInfo),
			x509.ECDSAWithSHA256, aik, tpm2.Marshal(area), nil)
		assert.ErrorIs(t, err, ErrCertifyNameMismatch)
	})

	t.Run("another challenge", func(t *testing.T) {
		_, err := VerifyCertifyByCertificate(f.certifyInfo, signASN1(t, f.attesterKey, f.certifyInfo),
			x509.ECDSAWithSHA256, aik, f.subjectPub,
			&VerifyCertifyOptions{ExpectedQualifyingData: []byte("a-different-nonce")})
		assert.ErrorIs(t, err, ErrCertifyQualifyingDataMismatch)
	})

	t.Run("bytes no TPM generated", func(t *testing.T) {
		forged := tpm2.Marshal(tpm2.TPMSAttest{
			Magic:     tpm2.TPMGenerated(0xDEADBEEF),
			Type:      tpm2.TPMSTAttestCertify,
			ExtraData: tpm2.TPM2BData{Buffer: f.qualifyingIn},
			Attested:  tpm2.NewTPMUAttest(tpm2.TPMSTAttestCertify, &tpm2.TPMSCertifyInfo{}),
		})
		_, err := VerifyCertifyByCertificate(forged, signASN1(t, f.attesterKey, forged),
			x509.ECDSAWithSHA256, aik, f.subjectPub, nil)
		assert.ErrorIs(t, err, ErrCertifyNotTPMGenerated)
	})
}

func TestVerifyCertifyByCertificate_RejectsMalformedInput(t *testing.T) {
	f := newCertifyFixture(t)
	aik := attestingCertificate(t, f.attesterKey, true)
	sig := signASN1(t, f.attesterKey, f.certifyInfo)

	cases := []struct {
		name          string
		info, sig     []byte
		attester      *x509.Certificate
		subjectPublic []byte
	}{
		{"no certify info", nil, sig, aik, f.subjectPub},
		{"no signature", f.certifyInfo, nil, aik, f.subjectPub},
		{"no attester certificate", f.certifyInfo, sig, nil, f.subjectPub},
		{"garbage subject area", f.certifyInfo, sig, aik, []byte{0x01, 0x02}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := VerifyCertifyByCertificate(tc.info, tc.sig, x509.ECDSAWithSHA256, tc.attester, tc.subjectPublic, nil)
			assert.ErrorIs(t, err, ErrCertifyMalformed)
		})
	}
}
