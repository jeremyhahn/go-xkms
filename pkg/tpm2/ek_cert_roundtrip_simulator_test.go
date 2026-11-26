//go:build tpm_simulator

package tpm2

import (
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestEKCertificate_RoundTripsByKeyType(t *testing.T) {
	eccEK := func(curve string) func(*Config) {
		return func(c *Config) {
			c.EK.KeyAlgorithm = x509.ECDSA.String()
			c.EK.RSAConfig = nil
			c.EK.ECCConfig = &store.ECCConfig{Curve: curve}
		}
	}

	for _, curve := range []string{"P-256", "P-384", "P-521"} {
		t.Run(curve, func(t *testing.T) {
			soPIN := []byte("so-pin-1960-" + curve)
			h := newOwnedSimHarness(t, eccEK(curve), soPIN)
			certDER := createTestCertDER(t)

			require.NoError(t, h.TPM.ProvisionEKCert(soPIN, certDER))

			got, err := h.TPM.EKCertificate()
			require.NoError(t, err)
			assert.Equal(t, certDER, got.Raw)
		})
	}

	t.Run("P-256 with an RSA certificate at the RSA index", func(t *testing.T) {
		soPIN := []byte("so-pin-1960-p256-rsa")
		h := newOwnedSimHarness(t, eccEK("P-256"), soPIN)
		rsaDER := createTestCertDER(t)
		eccDER := createTestCertDER(t)

		require.NoError(t, h.TPM.writeEKCertToNV(tpm2.TPMHandle(ekCertIndexRSA2048), soPIN, rsaDER))
		require.NoError(t, h.TPM.ProvisionEKCert(soPIN, eccDER))

		got, err := h.TPM.EKCertificate()
		require.NoError(t, err)
		assert.Equal(t, eccDER, got.Raw, "the ECC certificate is returned, not the RSA one")
	})
}
