//go:build tpm_simulator
// +build tpm_simulator

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

package tpm2

import (
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// idevidTestConfig returns an IDevID configuration differing from the harness
// default only in the fields these tests vary.
func idevidTestConfig(cn, signatureAlgorithm string) *IDevIDConfig {
	return &IDevIDConfig{
		CN:                 cn,
		Hash:               crypto.SHA256.String(),
		Handle:             0x81020000,
		KeyAlgorithm:       x509.RSA.String(),
		Manufacturer:       "ATT",
		Model:              "xkms-test-device",
		RSAConfig:          &store.RSAConfig{KeySize: 2048},
		Serial:             "SN-0000-0001",
		SignatureAlgorithm: signatureAlgorithm,
	}
}

// TestCreateIDevID_CertificationSignatureIsTheAKs proves the certification
// recorded on the IDevID is a signature the AK really produced, for every
// combination of AK and IDevID padding.
//
// TPM2_Certify is issued with InScheme = TPM_ALG_NULL, so the TPM signs under
// the AK's own scheme: both the algorithm and the RSA padding of the response
// belong to the AK, not to the IDevID. Unpacking the response under the
// IDevID's configured padding made a device with a PSS AK and an SSA IDevID --
// or the reverse -- fail to enroll at all, with "did not contain rsassa
// (selector value was 22)". Both mixed rows fail on the pre-fix code; the two
// matched rows pass either way, which is why nothing caught it: every
// configuration in the repository, the harness included, set both alike.
//
// Verifying the recorded signature under the AK's public key is the assertion
// that a successful call is not enough on its own -- it pins which key the
// signature belongs to, not merely that some bytes were unpacked.
func TestCreateIDevID_CertificationSignatureIsTheAKs(t *testing.T) {
	ssa := x509.SHA256WithRSA.String()
	pss := x509.SHA256WithRSAPSS.String()

	tests := []struct {
		name      string
		iakSig    string
		idevidSig string
	}{
		{"both RSASSA", ssa, ssa},
		{"both RSAPSS", pss, pss},
		{"RSASSA AK, RSAPSS IDevID", ssa, pss},
		{"RSAPSS AK, RSASSA IDevID", pss, ssa},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			h := newSimHarness(t, func(c *Config) {
				c.IdentityProvisioningStrategy = string(EnrollmentStrategyIAK_IDEVID_SINGLE_PASS)
				c.IAK.SignatureAlgorithm = tc.iakSig
				c.IDevID = idevidTestConfig("device-id-001", tc.idevidSig)
			})

			iakAttrs, err := h.TPM.IAKAttributes()
			require.NoError(t, err)
			ekPub, err := h.TPM.EKRSA()
			require.NoError(t, err)

			idevidAttrs, csr, err := h.TPM.CreateIDevID(iakAttrs, selfSignedCertForKey(t, ekPub), nil)
			require.NoError(t, err, "a mixed-padding AK/IDevID pair must still enroll")
			require.NotNil(t, csr)
			require.NotNil(t, idevidAttrs.TPMAttributes)

			certifyInfo := idevidAttrs.TPMAttributes.CertifyInfo
			signature := idevidAttrs.TPMAttributes.Signature
			require.NotEmpty(t, certifyInfo, "the certification must be recorded")
			require.NotEmpty(t, signature, "the certification signature must be recorded")

			// The TPM signed a digest of the TPMS_ATTEST bytes under the AK's
			// scheme hash, which the harness configures as SHA-256.
			digest := sha256.Sum256(certifyInfo)
			akPublic := rsaPublicKeyOf(t, iakAttrs)

			if store.IsRSAPSS(iakAttrs.SignatureAlgorithm) {
				// SaltLengthAuto accepts whatever salt length the TPM chose.
				assert.NoError(t,
					rsa.VerifyPSS(akPublic, crypto.SHA256, digest[:], signature,
						&rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto}),
					"the recorded signature must verify under the AK's public key as PSS")
			} else {
				assert.NoError(t,
					rsa.VerifyPKCS1v15(akPublic, crypto.SHA256, digest[:], signature),
					"the recorded signature must verify under the AK's public key as PKCS#1 v1.5")
			}

			// The recorded public key is the IDevID's, not the AK's -- the two
			// are read from different public areas and must not be conflated.
			idevidPublic := rsaPublicKeyOf(t, idevidAttrs)
			assert.NotEqual(t, akPublic.N, idevidPublic.N,
				"the IDevID public key must not be the AK's")

			readBack, err := tpm2.ReadPublic{
				ObjectHandle: idevidAttrs.TPMAttributes.Handle,
			}.Execute(h.TPM.transport)
			require.NoError(t, err)
			readPub, err := readBack.OutPublic.Contents()
			require.NoError(t, err)
			readUnique, err := readPub.Unique.RSA()
			require.NoError(t, err)
			assert.Equal(t, readUnique.Buffer, idevidPublic.N.Bytes(),
				"the recorded IDevID public key must be the key persisted at the handle")
		})
	}
}

// TestCreateIDevID_RejectsInvalidAttestationKey covers the two bad-input paths
// CreateIDevID guards before it touches the TPM. Both must report a typed
// error rather than dereferencing a nil.
func TestCreateIDevID_RejectsInvalidAttestationKey(t *testing.T) {
	h := newSimHarness(t, func(c *Config) {
		c.IdentityProvisioningStrategy = string(EnrollmentStrategyIAK_IDEVID_SINGLE_PASS)
		c.IDevID = idevidTestConfig("device-id-001", x509.SHA256WithRSA.String())
	})

	ekPub, err := h.TPM.EKRSA()
	require.NoError(t, err)
	ekCert := selfSignedCertForKey(t, ekPub)

	t.Run("nil AK attributes", func(t *testing.T) {
		attrs, csr, err := h.TPM.CreateIDevID(nil, ekCert, nil)
		assert.Nil(t, attrs)
		assert.Nil(t, csr)
		assert.ErrorIs(t, err, ErrInvalidAKAttributes)
	})

	t.Run("AK with no parent EK", func(t *testing.T) {
		iakAttrs, err := h.TPM.IAKAttributes()
		require.NoError(t, err)

		orphan := *iakAttrs
		orphan.Parent = nil

		attrs, csr, err := h.TPM.CreateIDevID(&orphan, ekCert, nil)
		assert.Nil(t, attrs)
		assert.Nil(t, csr)
		assert.ErrorIs(t, err, ErrInvalidEKAttributes)
	})
}
