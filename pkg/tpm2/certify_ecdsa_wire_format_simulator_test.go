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

//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"math/big"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// This file covers the wire format of the TPM2_Certify signature an ECDSA IAK
// or IDevID packs into TPMAttributes.Signature. TCG "TPM 2.0 Keys for Device
// Identity and Attestation" v1.00 r12 section 13.1 carries
// atCertifyInfoSignature and sgnCertifyInfoSignature as the bare signature
// value, with no algorithm identifier alongside it, and [VerifyCertifyRaw]'s
// signatureFromScheme recovers r and s from an ECDSA signature by splitting
// the buffer exactly in half. CreateIAK and CreateIDevID used to pack the
// signature as ASN.1 DER instead -- valid input to no wire-format consumer,
// including the verifier next to it in this package -- because the only
// existing ECDSA test verified a CSR against itself, producer and consumer
// sharing one (mistaken) idea of the format (#1182).

// newECDSAIAKHarness provisions a simulator with a P-256 IAK and mints an
// IDevID under it, so both certification signatures CreateIAK and
// CreateIDevID pack are ECDSA and available to inspect.
//
// The IDevID key itself is RSA. What packRawECDSASignature produces is
// determined solely by the attesting key -- the IAK -- so the IDevID's own
// algorithm plays no part in either signature under test.
func newECDSAIAKHarness(t *testing.T) *identityHarness {
	t.Helper()

	h := newSimHarness(t, func(c *Config) {
		c.IAK.RSAConfig = nil
		c.IAK.ECCConfig = &store.ECCConfig{Curve: "P-256"}
		c.IAK.KeyAlgorithm = x509.ECDSA.String()
		c.IAK.SignatureAlgorithm = "ECDSA-SHA256"
		c.IDevID = &IDevIDConfig{
			CN:                 "device-id-001",
			Debug:              true,
			Hash:               crypto.SHA256.String(),
			Handle:             0x81020000,
			KeyAlgorithm:       x509.RSA.String(),
			Manufacturer:       "ATT",
			Model:              "xkms-test-device",
			RSAConfig:          &store.RSAConfig{KeySize: 2048},
			Serial:             "SN-0000-0001",
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		}
	})

	iakAttrs, err := h.TPM.IAKAttributes()
	require.NoError(t, err, "provisioning must leave a usable ECDSA IAK behind")

	ekPub, err := h.TPM.EKRSA()
	require.NoError(t, err, "the provisioned EK must be readable")
	ekCert := selfSignedCertForKey(t, ekPub)

	idevidAttrs, csr, err := h.TPM.CreateIDevID(iakAttrs, ekCert, nil)
	require.NoError(t, err, "the TPM must be able to mint an IDevID under an ECDSA IAK")
	require.NotNil(t, idevidAttrs)
	require.NotNil(t, csr)

	return &identityHarness{
		simHarness: h,
		IAK:        iakAttrs,
		IDevID:     idevidAttrs,
		EKCert:     ekCert,
	}
}

// derEncodeSignature repacks a raw r||s pair as the ASN.1 DER SEQUENCE{r,s}
// CreateIAK and CreateIDevID used to produce, so a test can assert the
// verifier no longer accepts it.
func derEncodeSignature(t *testing.T, raw []byte) []byte {
	t.Helper()
	require.Zero(t, len(raw)%2, "precondition: a raw ECDSA signature has two equal halves")
	half := len(raw) / 2
	r := new(big.Int).SetBytes(raw[:half])
	s := new(big.Int).SetBytes(raw[half:])
	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	require.NoError(t, err)
	return der
}

// TestCreateIAK_ECDSA_CertifySignatureIsRawWireFormat proves CreateIAK packs
// its P-256 self-certification as the 64-byte raw r||s pair the TCG wire
// format requires, not ASN.1 DER.
//
// CreateIAK's certification is a TPM2_CertifyCreation over the IAK's own
// creation data -- TPMS_ATTEST.type is TPM_ST_ATTEST_CREATION, not
// TPM_ST_ATTEST_CERTIFY -- so [VerifyCertifyRaw] itself cannot be the
// verifier here: it refuses any attestation that is not a TPM2_Certify
// before it ever looks at the signature. This exercises the same
// signatureFromScheme the CSR's real TPM2_Certify verification runs, which
// is the part that changed and the part that must agree with what CreateIAK
// packs.
func TestCreateIAK_ECDSA_CertifySignatureIsRawWireFormat(t *testing.T) {
	h := newECDSAIAKHarness(t)

	certifyInfo := h.IAK.TPMAttributes.CertifyInfo
	signature := h.IAK.TPMAttributes.Signature
	require.NotEmpty(t, certifyInfo, "CreateIAK must record its self-certification")
	require.NotEmpty(t, signature, "CreateIAK must record the certification signature")

	assert.Len(t, signature, 64,
		"a P-256 ECDSA signature packed as raw r||s is exactly 64 bytes (32+32)")

	iakPubBytes := h.IAK.TPMAttributes.BPublic.Bytes()
	attester, err := tpm2.Unmarshal[tpm2.TPMTPublic](iakPubBytes)
	require.NoError(t, err)

	sig, err := signatureFromScheme(attester, signature)
	require.NoError(t, err, "the raw wire-format signature must parse under the attester's declared scheme")
	_, err = verifyCertifySignature(attester, certifyInfo, sig)
	require.NoError(t, err, "the raw wire-format signature must verify")

	t.Run("a DER-encoded signature is rejected", func(t *testing.T) {
		der := derEncodeSignature(t, signature)
		require.NotEqual(t, signature, der, "precondition: DER re-encoding changes the bytes")

		badSig, err := signatureFromScheme(attester, der)
		if err == nil {
			_, err = verifyCertifySignature(attester, certifyInfo, badSig)
		}
		assert.Error(t, err, "a DER-encoded signature must not verify as the raw wire format")
	})
}
