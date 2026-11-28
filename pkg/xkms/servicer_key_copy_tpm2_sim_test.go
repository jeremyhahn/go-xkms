//go:build tpm_simulator

// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-xkms.
//
// go-xkms is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

package xkms

import (
	"context"
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	tpmstore "github.com/jeremyhahn/go-xkms/pkg/tpm2/store"
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

	// A TPM sealed object holds at most 128 bytes, so the key is symmetric.
	_, err = srcProvider.GenerateSymmetricKey(ctx, &types.KeyAttributes{
		CN:                 "sw-to-tpm2-kek",
		KeyType:            types.KeyTypeSecret,
		StoreType:          types.StoreSoftware,
		SymmetricAlgorithm: types.SymmetricAES256GCM,
		Exportable:         true,
	})
	require.NoError(t, err)

	// The TPM2 backend stores an imported key as a sealed object only and
	// cannot yet encrypt or decrypt with it as a symmetric key, so a copy
	// that would land an unusable key is refused fail-closed.
	resp, err := svc.CopyKey(ctx, &transport.CopyKeyRequest{
		SourceBackend: "software",
		SourceKeyID:   "sw-to-tpm2-kek",
		DestBackend:   "tpm2",
		DestKeyID:     "sw-to-tpm2-kek-copy",
		Algorithm:     "",
	})
	require.ErrorIs(t, err, backend.ErrExportToUnsupported,
		"a symmetric key copy to TPM2 must be refused until the TPM2 copy can decrypt")
	require.Nil(t, resp)

	dstKeys, err := dstBackend.ListKeys(ctx)
	require.NoError(t, err)
	for _, a := range dstKeys {
		require.False(t, a != nil && a.CN == "sw-to-tpm2-kek-copy",
			"a refused copy must leave no destination key")
	}
}

// TestCopyKeySoftwareToSimulatedTPM2WithNoAlgorithmAsymmetric copies an
// exportable Ed25519 key, whose PKCS#8 encoding fits a TPM sealed object,
// with no wrapping algorithm named: CopyKey picks TPM2_DUPLICATE and the
// software source wraps for it.
func TestCopyKeySoftwareToSimulatedTPM2WithNoAlgorithmAsymmetric(t *testing.T) {
	svc, srcProvider, dstBackend, _ := setupSoftwareToTPM2Copy(t)
	ctx := context.Background()
	generateEd25519Source(t, srcProvider, "sw-to-tpm2-ed")

	// The TPM2 backend would store the PKCS#8 bytes as a sealed object it
	// cannot sign with, so the copy is refused before any destination write.
	resp, err := svc.CopyKey(ctx, &transport.CopyKeyRequest{
		SourceBackend: "software",
		SourceKeyID:   "sw-to-tpm2-ed",
		DestBackend:   "tpm2",
		DestKeyID:     "sw-to-tpm2-ed-copy",
	})
	require.ErrorIs(t, err, backend.ErrExportToUnsupported,
		"an asymmetric key copy to TPM2 must be refused until the TPM2 copy can sign")
	require.Nil(t, resp)

	dstKeys, err := dstBackend.ListKeys(ctx)
	require.NoError(t, err)
	for _, a := range dstKeys {
		require.False(t, a != nil && a.CN == "sw-to-tpm2-ed-copy",
			"a refused copy must leave no destination key")
	}
}

// setupSoftwareToTPM2Copy registers a real software backend as "software"
// and a simulator TPM2 backend as "tpm2", and returns the service.
func setupSoftwareToTPM2Copy(t *testing.T) (*XKMSService, types.SymmetricKeyProvider, Backend, tpmstore.KeyBackend) {
	t.Helper()
	Reset()
	t.Cleanup(Reset)

	srcProvider, err := software.NewBackend(&software.Config{KeyStorage: storage.NewMemory()})
	require.NoError(t, err)
	srcBackend, err := New(&BackendConfig{Backend: srcProvider, CertStorage: storage.NewMemory()})
	require.NoError(t, err)

	dstBackend, dstKeys := newRealTPM2BackendWithKeys(t)
	require.NoError(t, Initialize(&ServiceConfig{
		Backends:       map[string]Backend{"software": srcBackend, "tpm2": dstBackend},
		DefaultBackend: "software",
	}))
	svc, err := Get()
	require.NoError(t, err)
	return svc, srcProvider, dstBackend, dstKeys
}

// generateEd25519Source generates an exportable Ed25519 key on the software
// backend.
func generateEd25519Source(t *testing.T, sw types.SymmetricKeyProvider, cn string) {
	t.Helper()
	_, err := sw.GenerateKey(context.Background(), &types.KeyAttributes{
		CN:           cn,
		KeyType:      types.KeyTypeSigning,
		StoreType:    types.StoreSoftware,
		KeyAlgorithm: x509.Ed25519,
		Exportable:   true,
	})
	require.NoError(t, err)
}

// TestCopyKeySoftwareToSimulatedTPM2RefusesExistingDest pins that a copy onto
// an existing TPM2 key fails and leaves the existing key's blobs untouched.
func TestCopyKeySoftwareToSimulatedTPM2RefusesExistingDest(t *testing.T) {
	svc, srcProvider, dstBackend, dstKeys := setupSoftwareToTPM2Copy(t)
	ctx := context.Background()
	generateEd25519Source(t, srcProvider, "sw-src-second")
	_, err := dstBackend.GenerateRSA(ctx, &types.KeyAttributes{
		CN:            "tpm2-existing-dest",
		KeyType:       types.KeyTypeSigning,
		StoreType:     types.StoreTPM2,
		KeyAlgorithm:  x509.RSA,
		RSAAttributes: &types.RSAAttributes{KeySize: 2048},
	})
	require.NoError(t, err)

	copyTo := func(src string) (*transport.CopyKeyResponse, error) {
		return svc.CopyKey(ctx, &transport.CopyKeyRequest{
			SourceBackend: "software",
			SourceKeyID:   src,
			DestBackend:   "tpm2",
			DestKeyID:     "tpm2-existing-dest",
		})
	}
	destBlobs := func() ([]byte, []byte) {
		keys, lerr := dstBackend.ListKeys(ctx)
		require.NoError(t, lerr)
		for _, a := range keys {
			if a != nil && a.CN == "tpm2-existing-dest" {
				priv, gerr := dstKeys.Get(a, tpmstore.FSEXT_PRIVATE_BLOB)
				require.NoError(t, gerr)
				pub, gerr := dstKeys.Get(a, tpmstore.FSEXT_PUBLIC_BLOB)
				require.NoError(t, gerr)
				return priv, pub
			}
		}
		t.Fatal("the TPM2 destination key is not listed")
		return nil, nil
	}
	privBefore, pubBefore := destBlobs()

	resp, err := copyTo("sw-src-second")
	require.Error(t, err, "a copy onto an existing TPM2 key must fail")
	require.ErrorIs(t, err, backend.ErrExportToUnsupported)
	require.Nil(t, resp)

	privAfter, pubAfter := destBlobs()
	require.Equal(t, privBefore, privAfter, "the existing private blob was overwritten")
	require.Equal(t, pubBefore, pubAfter, "the existing public blob was overwritten")
}
