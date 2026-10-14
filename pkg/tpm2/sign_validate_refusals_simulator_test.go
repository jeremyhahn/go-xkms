//go:build tpm_simulator

package tpm2

import (
	"crypto/sha256"
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSignValidate_RefusesUnsignableRSAKeys proves SignValidate refuses an
// RSA public area whose parameters are not RSA parameters, and PKCS#1 v1.5
// from a key whose scheme is fixed to RSA-PSS, before asking the TPM to sign.
func TestSignValidate_RefusesUnsignableRSAKeys(t *testing.T) {
	h := newRSALAKHarness(t)
	lakAttrs, err := h.TPM.CreateLAK(nil, h.Backend, false)
	require.NoError(t, err)
	digest := sha256.Sum256([]byte("payload"))

	t.Run("PKCS#1 v1.5 from a PSS key", func(t *testing.T) {
		attrs := *lakAttrs
		attrs.SignatureAlgorithm = x509.SHA256WithRSA

		signature, err := h.TPM.SignValidate(&attrs, digest[:], nil)
		assert.ErrorIs(t, err, ErrSignSchemeMismatch)
		assert.Nil(t, signature)
	})

	t.Run("RSA type with ECC parameters", func(t *testing.T) {
		attrs := *lakAttrs
		tpmAttrs := *lakAttrs.TPMAttributes
		tpmAttrs.Public.Parameters = tpm2.NewTPMUPublicParms(tpm2.TPMAlgECC, &tpm2.TPMSECCParms{
			CurveID: tpm2.TPMECCNistP256,
			Scheme:  tpm2.TPMTECCScheme{Scheme: tpm2.TPMAlgNull},
		})
		attrs.TPMAttributes = &tpmAttrs

		signature, err := h.TPM.SignValidate(&attrs, digest[:], nil)
		assert.Error(t, err)
		assert.Nil(t, signature)
	})

	t.Run("no TPM attributes", func(t *testing.T) {
		signature, err := h.TPM.SignValidate(&types.KeyAttributes{CN: "no-tpm-attributes"}, digest[:], nil)
		assert.ErrorIs(t, err, ErrSignValidatePublicRequired)
		assert.Nil(t, signature)
	})
}
