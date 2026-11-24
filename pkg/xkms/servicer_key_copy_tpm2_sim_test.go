//go:build tpm_simulator

package xkms

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestCopyKeySoftwareToSimulatedTPM2WithNoAlgorithm copies an exportable key
// from a real software backend to a real TPM2 backend on the simulator with
// no wrapping algorithm named. CopyKey picks the destination's default
// (TPM2_DUPLICATE); the software source must be able to wrap for it, which
// the mock destination in servicer_key_tenant_copy_test.go cannot prove.
func TestCopyKeySoftwareToSimulatedTPM2WithNoAlgorithm(t *testing.T) {
	Reset()
	t.Cleanup(Reset)

	srcProvider, err := software.NewBackend(&software.Config{KeyStorage: storage.NewMemory()})
	require.NoError(t, err)
	srcBackend, err := New(&BackendConfig{Backend: srcProvider, CertStorage: storage.NewMemory()})
	require.NoError(t, err)

	dstBackend := newRealTPM2Backend(t)
	require.NoError(t, Initialize(&ServiceConfig{
		Backends: map[string]Backend{
			"software": srcBackend,
			"tpm2":     dstBackend,
		},
		DefaultBackend: "software",
	}))
	svc, err := Get()
	require.NoError(t, err)
	ctx := context.Background()

	_, err = srcBackend.GenerateRSA(ctx, &types.KeyAttributes{
		CN:            "sw-to-tpm2-kek",
		KeyType:       types.KeyTypeEncryption,
		StoreType:     types.StoreSoftware,
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
		Exportable:    true,
	})
	require.NoError(t, err)

	resp, err := svc.CopyKey(ctx, &transport.CopyKeyRequest{
		SourceBackend: "software",
		SourceKeyID:   "sw-to-tpm2-kek",
		DestBackend:   "tpm2",
		DestKeyID:     "sw-to-tpm2-kek-copy",
		Algorithm:     "",
	})
	require.NoError(t, err)
	require.True(t, resp.Success)

	dstKeys, err := dstBackend.ListKeys(ctx)
	require.NoError(t, err)
	found := false
	for _, a := range dstKeys {
		if a != nil && a.CN == "sw-to-tpm2-kek-copy" {
			found = true
			break
		}
	}
	require.True(t, found, "the simulated TPM2 destination must hold the copied key")
}
