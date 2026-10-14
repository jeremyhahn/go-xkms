//go:build frost

package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/config"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// srkKeyProvider is a key provider exposing the SRKAttributes view the TPM2
// secret backend is detected by.
type srkKeyProvider struct {
	types.KeyProvider
	srk *types.KeyAttributes
}

func (p *srkKeyProvider) SRKAttributes() *types.KeyAttributes { return p.srk }

func TestEnsureFrostSecretSealKey_TPM2SealsUnderTheSRK(t *testing.T) {
	s := newMinimalServer(t, &config.Config{})
	srk := &types.KeyAttributes{CN: "psrk"}
	provider := &srkKeyProvider{KeyProvider: newSoftwareKeyProviderForTest(t), srk: srk}

	attrs, err := s.ensureFrostSecretSealKey("tpm2", provider)
	require.NoError(t, err)
	assert.Same(t, srk, attrs.Parent)
}

// TestEnsureFrostSecretSealKey_SymmetricBackends checks every symmetric
// secret backend provisions a FROST key in its own store. The software
// backend stands in for the HSM and cloud KMS providers.
func TestEnsureFrostSecretSealKey_SymmetricBackends(t *testing.T) {
	stores := map[string]types.StoreType{
		"pkcs11":  types.StorePKCS11,
		"awskms":  types.StoreAWSKMS,
		"gcpkms":  types.StoreGCPKMS,
		"azurekv": types.StoreAzureKV,
		"vault":   types.StoreVault,
	}
	for name, store := range stores {
		t.Run(name, func(t *testing.T) {
			s := newMinimalServer(t, &config.Config{})
			attrs, err := s.ensureFrostSecretSealKey(name, newSoftwareKeyProviderForTest(t))
			require.NoError(t, err)
			assert.Equal(t, store, attrs.StoreType)
		})
	}
}

// TestInitializeBackends_FrostFailureWraps names a FROST secret backend that
// was never initialized: backend initialization fails and names FROST.
func TestInitializeBackends_FrostFailureWraps(t *testing.T) {
	s := newMinimalServer(t, &config.Config{
		Backends: config.BackendsConfig{
			Frost: &config.FrostConfig{
				Enabled:          true,
				SecretBackend:    "software",
				Algorithm:        "FROST-Ed25519-SHA512",
				DefaultThreshold: 2,
				DefaultTotal:     3,
			},
		},
	})

	err := s.initializeBackends()
	var initErr *ErrBackendInit
	require.ErrorAs(t, err, &initErr)
	assert.Equal(t, "FROST", initErr.Backend)
	assert.NotContains(t, s.keyProviders, "frost")
}

func TestEnsureFrostSecretSealKey_UnsupportedProvider(t *testing.T) {
	s := newMinimalServer(t, &config.Config{})
	provider := newSoftwareKeyProviderForTest(t)

	for _, name := range []string{"tpm2", "unknown"} {
		t.Run(name, func(t *testing.T) {
			attrs, err := s.ensureFrostSecretSealKey(name, provider)
			assert.Nil(t, attrs)
			var unavailable *ErrFrostSecretBackendUnavailable
			require.ErrorAs(t, err, &unavailable)
			assert.Equal(t, name, unavailable.Backend)
		})
	}
}
