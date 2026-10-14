//go:build tpm_simulator

package tpm2

import (
	"crypto/x509"
	"encoding/binary"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newSinglePassECCIdentity returns an all-ECC identity harness whose CSRs
// the IDevID signs, which is what VerifyTCG_CSR_IDevID verifies.
func newSinglePassECCIdentity(t *testing.T) *identityHarness {
	t.Helper()
	h := newECCIdentityHarness(t)
	h.TPM.config.IdentityProvisioningStrategy = string(EnrollmentStrategyIAK_IDEVID_SINGLE_PASS)
	return h
}

// withPublicArea returns a copy of csr whose IAK (attest) or IDevID
// (signing) public area has been rewritten by mutate.
func withPublicArea(t *testing.T, csr *TCG_CSR_IDEVID, signing bool, mutate func(*tpm2.TPMTPublic)) *TCG_CSR_IDEVID {
	t.Helper()
	bad := *csr
	field, size := &bad.CsrContents.AttestPub, &bad.CsrContents.AttestPubSZ
	if signing {
		field, size = &bad.CsrContents.SigningPub, &bad.CsrContents.SigningPubSZ
	}
	pub, err := tpm2.Unmarshal[tpm2.TPMTPublic](*field)
	require.NoError(t, err)
	mutate(pub)
	*field = tpm2.Marshal(pub)
	binary.BigEndian.PutUint32(size[:], uint32(len(*field)))
	return &bad
}

// TestVerifyTCG_CSR_IDevID_RefusesKeyShapes proves the verifier refuses a
// CSR whose attacker-supplied public areas do not describe a restricted,
// TPM-bound IAK and an unrestricted, TPM-bound IDevID signing key. These
// checks run before any signature is verified, so each tampered CSR is
// refused for its key shape alone.
func TestVerifyTCG_CSR_IDevID_RefusesKeyShapes(t *testing.T) {
	h := newSinglePassECCIdentity(t)
	csr := h.csr(t)

	tests := []struct {
		name    string
		signing bool
		mutate  func(*tpm2.TPMTPublic)
	}{
		{"IAK not restricted", false, func(p *tpm2.TPMTPublic) { p.ObjectAttributes.Restricted = false }},
		{"IAK not fixedTPM", false, func(p *tpm2.TPMTPublic) { p.ObjectAttributes.FixedTPM = false }},
		{"IAK not fixedParent", false, func(p *tpm2.TPMTPublic) {
			p.ObjectAttributes.FixedTPM = false
			p.ObjectAttributes.FixedParent = false
		}},
		{"IDevID restricted", true, func(p *tpm2.TPMTPublic) { p.ObjectAttributes.Restricted = true }},
		{"IDevID not fixedTPM", true, func(p *tpm2.TPMTPublic) { p.ObjectAttributes.FixedTPM = false }},
		{"IDevID not fixedParent", true, func(p *tpm2.TPMTPublic) {
			p.ObjectAttributes.FixedTPM = false
			p.ObjectAttributes.FixedParent = false
		}},
		{"IDevID a decryption key", true, func(p *tpm2.TPMTPublic) {
			p.ObjectAttributes.SignEncrypt = false
			p.ObjectAttributes.Decrypt = true
			p.Parameters = tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
				Symmetric: tpm2.TPMTSymDefObject{Algorithm: tpm2.TPMAlgNull},
				Scheme:    tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgNull},
				CurveID:   tpm2.TPMECCNistP256,
				KDF:       tpm2.TPMTKDFScheme{Scheme: tpm2.TPMAlgNull},
			})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			bad := withPublicArea(t, csr, tt.signing, tt.mutate)

			attrs, unpacked, err := h.TPM.VerifyTCG_CSR_IDevID(bad, x509.ECDSAWithSHA256)
			assert.ErrorIs(t, err, store.ErrInvalidKeyAttributes)
			assert.Nil(t, attrs)
			assert.Nil(t, unpacked)
		})
	}

	// The untampered CSR verifies under its ECC IDevID, so the refusals
	// above are the mutations' doing.
	attrs, _, err := h.TPM.VerifyTCG_CSR_IDevID(csr, x509.ECDSAWithSHA256)
	require.NoError(t, err)
	assert.Equal(t, x509.ECDSA, attrs.KeyAlgorithm)
}

// TestVerifyTCG_CSR_IDevID_RefusesMalformedContent proves the verifier
// refuses a hash algorithm it cannot use and public areas the TPM cannot
// load.
func TestVerifyTCG_CSR_IDevID_RefusesMalformedContent(t *testing.T) {
	h := newSinglePassECCIdentity(t)
	csr := h.csr(t)

	t.Run("hash algorithm ID beyond a TPM_ALG_ID", func(t *testing.T) {
		bad := *csr
		binary.BigEndian.PutUint32(bad.CsrContents.HashAlgoId[:], 0x00010000)
		_, _, err := h.TPM.VerifyTCG_CSR_IDevID(&bad, x509.ECDSAWithSHA256)
		assert.Error(t, err)
	})

	t.Run("hash algorithm that is not a hash", func(t *testing.T) {
		bad := *csr
		binary.BigEndian.PutUint32(bad.CsrContents.HashAlgoId[:], uint32(tpm2.TPMAlgRSA))
		_, _, err := h.TPM.VerifyTCG_CSR_IDevID(&bad, x509.ECDSAWithSHA256)
		assert.Error(t, err)
	})

	t.Run("IAK public area the TPM cannot load", func(t *testing.T) {
		bad := withPublicArea(t, csr, false, func(p *tpm2.TPMTPublic) { p.NameAlg = tpm2.TPMAlgNull })
		_, _, err := h.TPM.VerifyTCG_CSR_IDevID(bad, x509.ECDSAWithSHA256)
		assert.Error(t, err)
	})

	t.Run("IDevID public area the TPM cannot load", func(t *testing.T) {
		bad := withPublicArea(t, csr, true, func(p *tpm2.TPMTPublic) { p.NameAlg = tpm2.TPMAlgNull })
		_, _, err := h.TPM.VerifyTCG_CSR_IDevID(bad, x509.ECDSAWithSHA256)
		assert.Error(t, err)
	})
}
