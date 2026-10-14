package tpm2

import (
	"crypto"
	"crypto/x509"
	"testing"

	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// lakAttributes builds LAK attributes from config and releases their
// password enclave when the test ends.
func lakAttributes(t *testing.T, config *LAKConfig) (*types.KeyAttributes, error) {
	t.Helper()
	attrs, err := LAKAttributesFromConfig(nil, config)
	if attrs != nil && attrs.Password != nil {
		t.Cleanup(attrs.Password.Clear)
	}
	return attrs, err
}

// TestLAKAttributesFromConfig_Builds proves a LAK config yields owner
// hierarchy, persistent-handle attributes, and that a missing key algorithm
// is inferred from whichever key config is present.
func TestLAKAttributesFromConfig_Builds(t *testing.T) {
	tests := []struct {
		name    string
		config  LAKConfig
		wantAlg x509.PublicKeyAlgorithm
		wantCN  string
	}{
		{"explicit ECDSA", LAKConfig{
			CN: "lak-ecc", Handle: 0x81010003, KeyAlgorithm: x509.ECDSA.String(),
			ECCConfig: &store.ECCConfig{Curve: "P-256"}, Hash: "SHA-256",
			SignatureAlgorithm: x509.ECDSAWithSHA256.String(),
		}, x509.ECDSA, "lak-ecc"},
		{"RSA inferred from its config", LAKConfig{
			RSAConfig: &store.RSAConfig{KeySize: 2048}, Hash: "SHA-256",
			SignatureAlgorithm: x509.SHA256WithRSAPSS.String(),
		}, x509.RSA, "lak"},
		{"ECDSA inferred from its config", LAKConfig{
			ECCConfig: &store.ECCConfig{Curve: "P-256"}, Hash: "SHA-256",
			SignatureAlgorithm: x509.ECDSAWithSHA256.String(),
		}, x509.ECDSA, "lak"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs, err := lakAttributes(t, &tt.config)
			require.NoError(t, err)
			assert.Equal(t, tt.wantAlg, attrs.KeyAlgorithm)
			assert.Equal(t, tt.wantCN, attrs.CN)
			assert.Equal(t, types.KeyTypeLAK, attrs.KeyType)
			assert.Equal(t, crypto.SHA256, attrs.Hash)
			assert.Equal(t, tpm2.TPMAlgSHA256, attrs.TPMAttributes.HashAlg)
			assert.Equal(t, tpm2.TPMRHOwner, attrs.TPMAttributes.Hierarchy)
			assert.Equal(t, tpm2.TPMHandle(tt.config.Handle), attrs.TPMAttributes.Handle)
			assert.Equal(t, tt.config.RSAConfig != nil, attrs.RSAAttributes != nil)
			assert.Equal(t, tt.config.ECCConfig != nil, attrs.ECCAttributes != nil)
		})
	}
}

// TestLAKAttributesFromConfig_Refusals proves a LAK config with no usable
// key algorithm, signature algorithm or hash is refused, without leaving a
// password enclave locked.
func TestLAKAttributesFromConfig_Refusals(t *testing.T) {
	valid := LAKConfig{
		KeyAlgorithm: x509.ECDSA.String(), ECCConfig: &store.ECCConfig{Curve: "P-256"},
		Hash: "SHA-256", SignatureAlgorithm: x509.ECDSAWithSHA256.String(),
	}
	tests := []struct {
		name    string
		mutate  func(*LAKConfig)
		wantErr error
	}{
		{"no algorithm and no key config", func(c *LAKConfig) {
			c.KeyAlgorithm, c.ECCConfig = "", nil
		}, nil},
		{"unknown signature algorithm", func(c *LAKConfig) { c.SignatureAlgorithm = "no-such-algorithm" }, nil},
		{"unknown hash", func(c *LAKConfig) { c.Hash = "no-such-hash" }, ErrInvalidHashFunction},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := valid
			tt.mutate(&config)

			before := lockedBytesInUse(t)
			attrs, err := lakAttributes(t, &config)
			require.Error(t, err)
			if tt.wantErr != nil {
				assert.ErrorIs(t, err, tt.wantErr)
			}
			assert.Nil(t, attrs)
			assert.Equal(t, before, lockedBytesInUse(t))
		})
	}
}
