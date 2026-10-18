//go:build tpm_simulator

package tpm2

import (
	"crypto/elliptic"
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// createTransientPrimary creates a transient primary under the owner
// hierarchy from template and flushes it when the test ends.
func createTransientPrimary(t *testing.T, h *simHarness, template tpm2.TPMTPublic) tpm2.TPMHandle {
	t.Helper()
	rsp, err := tpm2.CreatePrimary{
		PrimaryHandle: tpm2.TPMRHOwner,
		InPublic:      tpm2.New2B(template),
	}.Execute(h.TPM.transport)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, flushErr := tpm2.FlushContext{FlushHandle: rsp.ObjectHandle}.Execute(h.TPM.transport)
		assert.NoError(t, flushErr)
	})
	return rsp.ObjectHandle
}

// TestKeyAttributes_FillsKeyDetailsFromThePublicArea proves KeyAttributes
// reports the RSA key size (TPMS_RSA_PARMS.keyBits) and the ECC curve
// (TPMS_ECC_PARMS.curveID) of the key it reads, so callers such as
// `xkey tpm lak show` can print them.
func TestKeyAttributes_FillsKeyDetailsFromThePublicArea(t *testing.T) {
	h := newSimHarness(t, nil)

	t.Run("RSA-2048", func(t *testing.T) {
		handle := createTransientPrimary(t, h, tpm2.RSASRKTemplate)

		attrs, err := h.TPM.KeyAttributes(handle)
		require.NoError(t, err)
		assert.Equal(t, x509.RSA, attrs.KeyAlgorithm)
		require.NotNil(t, attrs.RSAAttributes, "an RSA key must carry its key size")
		assert.Equal(t, 2048, attrs.RSAAttributes.KeySize)
		assert.Nil(t, attrs.ECCAttributes)
	})

	t.Run("ECC-P256", func(t *testing.T) {
		handle := createTransientPrimary(t, h, tpm2.ECCSRKTemplate)

		attrs, err := h.TPM.KeyAttributes(handle)
		require.NoError(t, err)
		assert.Equal(t, x509.ECDSA, attrs.KeyAlgorithm)
		require.NotNil(t, attrs.ECCAttributes, "an ECC key must carry its curve")
		assert.Equal(t, elliptic.P256(), attrs.ECCAttributes.Curve)
		assert.Nil(t, attrs.RSAAttributes)
	})
}

// TestKeyAttributes_RejectsAnUnsupportedPublicType proves an object that is
// neither RSA nor ECC (a keyed-hash HMAC key) is refused with the typed
// invalid-algorithm error instead of being reported as an RSA key.
func TestKeyAttributes_RejectsAnUnsupportedPublicType(t *testing.T) {
	h := newSimHarness(t, nil)
	handle := createTransientPrimary(t, h, tpm2.TPMTPublic{
		Type:    tpm2.TPMAlgKeyedHash,
		NameAlg: tpm2.TPMAlgSHA256,
		ObjectAttributes: tpm2.TPMAObject{
			FixedTPM:            true,
			FixedParent:         true,
			SensitiveDataOrigin: true,
			UserWithAuth:        true,
			SignEncrypt:         true,
		},
		Parameters: tpm2.NewTPMUPublicParms(tpm2.TPMAlgKeyedHash, &tpm2.TPMSKeyedHashParms{
			Scheme: tpm2.TPMTKeyedHashScheme{
				Scheme: tpm2.TPMAlgHMAC,
				Details: tpm2.NewTPMUSchemeKeyedHash(tpm2.TPMAlgHMAC,
					&tpm2.TPMSSchemeHMAC{HashAlg: tpm2.TPMAlgSHA256}),
			},
		}),
		Unique: tpm2.NewTPMUPublicID(tpm2.TPMAlgKeyedHash, &tpm2.TPM2BDigest{}),
	})

	attrs, err := h.TPM.KeyAttributes(handle)
	require.ErrorIs(t, err, store.ErrInvalidKeyAlgorithm)
	assert.Nil(t, attrs)
}
