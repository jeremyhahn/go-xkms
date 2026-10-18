//go:build tpm_simulator
// +build tpm_simulator

package tpm2

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestIAKSignatureScheme_SurvivesReopen creates the IAK under one RSA
// signature scheme, then opens a fresh TPM2 on the same simulator state with
// a configuration naming the other one, as the next invocation of a CLI does
// after "tpm iak create --template". The IAK is Restricted, so its public
// area fixes the scheme (Template H-1, TCG "TPM 2.0 Keys for Device Identity
// and Attestation" v1.00 r12, section 7.3.4) and Quote signs under it alone:
// the reopened TPM has to describe the key by its object, not its config.
func TestIAKSignatureScheme_SurvivesReopen(t *testing.T) {
	tests := []struct {
		name       string
		created    x509.SignatureAlgorithm
		configured x509.SignatureAlgorithm
	}{
		{"RSASSA key, RSA-PSS config", x509.SHA256WithRSA, x509.SHA256WithRSAPSS},
		{"RSA-PSS key, RSASSA config", x509.SHA256WithRSAPSS, x509.SHA256WithRSA},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := newSimHarness(t, func(c *Config) {
				c.IAK.SignatureAlgorithm = tt.created.String()
			})
			require.Equal(t, tt.created, h.TPM.iakAttrs.SignatureAlgorithm,
				"provisioning created the IAK under the configured scheme")

			config := newSimConfig(t)
			config.IAK.SignatureAlgorithm = tt.configured.String()
			reopened, err := NewTPM2(&Params{
				Logger:    h.Logger,
				Config:    config,
				Backend:   h.Backend,
				Transport: h.TPM.transport,
				FQDN:      "node1.example.com",
			})
			require.NoError(t, err)
			t.Cleanup(func() { assert.NoError(t, reopened.Close()) })

			iakAttrs, err := reopened.IAKAttributes()
			require.NoError(t, err)
			assert.Equal(t, tt.created, iakAttrs.SignatureAlgorithm,
				"the reopened TPM describes the IAK by the scheme its public area fixes")

			quote, err := reopened.Quote([]uint{0, 7}, []byte("nonce"))
			require.NoError(t, err, "Quote unpacks the signature under the IAK's own scheme")
			assert.NotEmpty(t, quote.Signature)
		})
	}
}
