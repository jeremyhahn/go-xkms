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
	"crypto/ecdsa"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/backend/software"
	"github.com/jeremyhahn/go-xkms/pkg/pivcert"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestBackendPIVKeyGenerator_RegenerateReplacesTheSlotKey proves generating
// into a slot that already holds a key replaces that key, as on a PIV
// token: with a backend that persists keys, the first key used to block
// the second ("key already exists"), so a slot could never be re-keyed.
func TestBackendPIVKeyGenerator_RegenerateReplacesTheSlotKey(t *testing.T) {
	provider, err := software.NewBackend(&software.Config{KeyStorage: storage.NewMemory()})
	require.NoError(t, err)
	backend, err := New(&BackendConfig{Backend: provider, CertStorage: storage.NewMemory()})
	require.NoError(t, err)
	gen := newBackendPIVKeyGenerator(backend, types.StoreSoftware)
	slot := pivcert.PIVSlot(pivcert.PIVSlotAuthentication)

	first, err := gen.GeneratePIVKey(slot, "ecdsap256", "piv-9a")
	require.NoError(t, err)
	second, err := gen.GeneratePIVKey(slot, "ecdsap256", "piv-9a")
	require.NoError(t, err, "re-keying the slot replaces its key")
	assert.False(t, first.Public().(*ecdsa.PublicKey).Equal(second.Public()), "a new key, not the old one")

	current, err := gen.GetPIVSigner(slot, "piv-9a")
	require.NoError(t, err)
	assert.True(t, second.Public().(*ecdsa.PublicKey).Equal(current.Public()), "the slot signs with the new key")

	keys, err := backend.ListKeys(t.Context())
	require.NoError(t, err)
	assert.Len(t, keys, 1, "the old key is gone, not orphaned")
}

// TestBackendPIVKeyGenerator_RegenerateAcrossAlgorithms proves a slot is
// re-keyed with a different algorithm, replacing the old key of the other
// algorithm.
func TestBackendPIVKeyGenerator_RegenerateAcrossAlgorithms(t *testing.T) {
	provider, err := software.NewBackend(&software.Config{KeyStorage: storage.NewMemory()})
	require.NoError(t, err)
	backend, err := New(&BackendConfig{Backend: provider, CertStorage: storage.NewMemory()})
	require.NoError(t, err)
	gen := newBackendPIVKeyGenerator(backend, types.StoreSoftware)
	slot := pivcert.PIVSlot(pivcert.PIVSlotAuthentication)

	_, err = gen.GeneratePIVKey(slot, "ecdsap256", "piv-9a")
	require.NoError(t, err)
	_, err = gen.GeneratePIVKey(slot, "ed25519", "piv-9a")
	require.NoError(t, err)

	keys, err := backend.ListKeys(t.Context())
	require.NoError(t, err)
	require.Len(t, keys, 1)
	assert.Equal(t, "piv-9a", keys[0].CN)
}

// TestBackendPIVKeyGenerator_RekeyFailuresSurface proves a slot whose
// previous key cannot be listed or removed is not re-keyed blindly.
func TestBackendPIVKeyGenerator_RekeyFailuresSurface(t *testing.T) {
	slot := pivcert.PIVSlot(pivcert.PIVSlotAuthentication)

	listFails := &mockXKMSBackend{listKeysErr: assert.AnError}
	_, err := newBackendPIVKeyGenerator(listFails, types.StoreSoftware).GeneratePIVKey(slot, "ecdsap256", "piv-9a")
	var rekey *PIVRekeyError
	require.ErrorAs(t, err, &rekey)
	assert.ErrorIs(t, err, assert.AnError)

	deleteFails := &mockXKMSBackend{
		keys:         []*types.KeyAttributes{{CN: "piv-9a"}},
		deleteKeyErr: assert.AnError,
	}
	_, err = newBackendPIVKeyGenerator(deleteFails, types.StoreSoftware).GeneratePIVKey(slot, "ecdsap256", "piv-9a")
	require.ErrorAs(t, err, &rekey)
	assert.Empty(t, deleteFails.generateCalls, "nothing is generated over a key that could not be removed")
}
