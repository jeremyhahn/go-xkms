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
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/api/transport"
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

// TestCopyKeySoftwareToSimulatedTPM2RefusesExistingDest pins that a copy onto
// an existing TPM2 key fails and leaves the existing key's blobs untouched.
func TestCopyKeySoftwareToSimulatedTPM2RefusesExistingDest(t *testing.T) {
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
	ctx := context.Background()

	for _, cn := range []string{"sw-src-first", "sw-src-second"} {
		_, err = srcProvider.GenerateSymmetricKey(ctx, &types.KeyAttributes{
			CN:                 cn,
			KeyType:            types.KeyTypeSecret,
			StoreType:          types.StoreSoftware,
			SymmetricAlgorithm: types.SymmetricAES256GCM,
			Exportable:         true,
		})
		require.NoError(t, err)
	}

	copyTo := func(src string) (*transport.CopyKeyResponse, error) {
		return svc.CopyKey(ctx, &transport.CopyKeyRequest{
			SourceBackend: "software",
			SourceKeyID:   src,
			DestBackend:   "tpm2",
			DestKeyID:     "tpm2-existing-dest",
		})
	}
	resp, err := copyTo("sw-src-first")
	require.NoError(t, err)
	require.True(t, resp.Success)

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

	resp, err = copyTo("sw-src-second")
	require.Error(t, err, "a copy onto an existing TPM2 key must fail")
	require.Nil(t, resp)

	privAfter, pubAfter := destBlobs()
	require.Equal(t, privBefore, privAfter, "the existing private blob was overwritten")
	require.Equal(t, pubBefore, pubAfter, "the existing public blob was overwritten")
}
