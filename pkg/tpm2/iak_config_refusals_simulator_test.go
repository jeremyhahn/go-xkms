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

// TestCreateIAK_ConfigRefusals proves CreateIAK refuses a configuration it
// cannot honour before it touches the TPM, so the provisioned IAK survives.
func TestCreateIAK_ConfigRefusals(t *testing.T) {
	h := newSimHarness(t, nil)
	ekAttrs, err := h.TPM.EKAttributes()
	require.NoError(t, err)
	iakHandle := tpm2.TPMHandle(h.TPM.config.IAK.Handle)
	_, before, err := h.TPM.ReadHandle(iakHandle)
	require.NoError(t, err)

	tests := []struct {
		name    string
		mutate  func(*Config)
		wantErr error
	}{
		{"unknown curve", func(c *Config) {
			c.IAK.KeyAlgorithm = x509.ECDSA.String()
			c.IAK.RSAConfig = nil
			c.IAK.ECCConfig = &store.ECCConfig{Curve: "no-such-curve"}
		}, ErrIAKConfigFailed},
		{"no common name", func(c *Config) {
			c.IAK.CN = ""
			c.IDevID = nil
		}, nil},
		{"unknown PCR bank", func(c *Config) { c.PlatformPCRBank = "no-such-bank" }, nil},
		{"RSA key size beyond a TPM key", func(c *Config) {
			c.IAK.RSAConfig = &store.RSAConfig{KeySize: 1 << 17}
		}, ErrInvalidKeySize},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			saved := *h.TPM.config
			savedIAK := *h.TPM.config.IAK
			t.Cleanup(func() {
				*h.TPM.config = saved
				*h.TPM.config.IAK = savedIAK
			})
			tt.mutate(h.TPM.config)

			attrs, err := h.TPM.CreateIAK(ekAttrs, nil)
			require.Error(t, err)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			}
			assert.Nil(t, attrs)

			_, after, err := h.TPM.ReadHandle(iakHandle)
			require.NoError(t, err, "a refused config must leave the IAK in place")
			assert.Equal(t, before.Unique, after.Unique)
		})
	}
}
