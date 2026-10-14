package tpm2

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAttributesFromConfig_InvalidCurveReleasesPasswords proves every
// config builder refuses an unknown ECC curve without leaving a password
// enclave locked: the curve is checked before any password is allocated.
func TestAttributesFromConfig_InvalidCurveReleasesPasswords(t *testing.T) {
	// The secret is resolved before the baseline is taken, so only the
	// builders' own allocations are measured.
	configured, err := types.NewLiteralSecretValue(context.Background(), []byte("configured-secret"))
	require.NoError(t, err)
	secret := func() *types.SecretValue { return configured }
	badCurve := &store.ECCConfig{Curve: "no-such-curve"}
	ecdsa := x509.ECDSA.String()
	sigAlg := x509.ECDSAWithSHA256.String()

	builders := map[string]func() (*types.KeyAttributes, error){
		"EK": func() (*types.KeyAttributes, error) {
			return EKAttributesFromConfig(EKConfig{
				KeyAlgorithm: ecdsa, ECCConfig: badCurve, Password: secret(), HierarchyAuth: secret(),
			}, nil, nil)
		},
		"SRK": func() (*types.KeyAttributes, error) {
			return SRKAttributesFromConfig(SRKConfig{
				KeyAlgorithm: ecdsa, ECCConfig: badCurve, Password: secret(), HierarchyAuth: secret(),
			})
		},
		"IAK": func() (*types.KeyAttributes, error) {
			return IAKAttributesFromConfig(nil, &IAKConfig{
				KeyAlgorithm: ecdsa, ECCConfig: badCurve, Hash: "SHA-256", SignatureAlgorithm: sigAlg, Password: secret(),
			})
		},
		"LAK": func() (*types.KeyAttributes, error) {
			return LAKAttributesFromConfig(nil, &LAKConfig{
				KeyAlgorithm: ecdsa, ECCConfig: badCurve, Hash: "SHA-256", SignatureAlgorithm: sigAlg, Password: secret(),
			})
		},
		"IDevID": func() (*types.KeyAttributes, error) {
			return IDevIDAttributesFromConfig(IDevIDConfig{
				CN: "idevid", Model: "model", Serial: "0001",
				KeyAlgorithm: ecdsa, ECCConfig: badCurve, Hash: "SHA-256", SignatureAlgorithm: sigAlg, Password: secret(),
			})
		},
		"LDevID": func() (*types.KeyAttributes, error) {
			return LDevIDAttributesFromConfig(LDevIDConfig{
				KeyAlgorithm: ecdsa, ECCConfig: badCurve, Hash: "SHA-256", SignatureAlgorithm: sigAlg, Password: secret(),
			})
		},
	}
	for name, build := range builders {
		t.Run(name, func(t *testing.T) {
			before := lockedBytesInUse(t)
			attrs, err := build()
			require.Error(t, err)
			assert.Nil(t, attrs)
			assert.Equal(t, before, lockedBytesInUse(t), "a refused config must not leave a password enclave locked")
		})
	}
}
