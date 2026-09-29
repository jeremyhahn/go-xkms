// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

//go:build tpm_simulator

package tpm2

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestAttachPlatformKeyStore_CreatesOnceAndReuses proves the helper xkmsd and
// xKey share attaches exactly one PlatformKeyStore to a TPM: the first call
// creates it, and every later call returns
// that same store rather than a second one with its own PIN state.
func TestAttachPlatformKeyStore_CreatesOnceAndReuses(t *testing.T) {
	h := newSimHarness(t, nil)
	t.Cleanup(func() { h.TPM.SetPlatformKeyStore(nil) })

	first, err := AttachPlatformKeyStore(h.Logger, h.TPM, h.Backend)
	require.NoError(t, err)
	require.NotNil(t, first)
	assert.Same(t, first, h.TPM.PlatformKeyStore())

	second, err := AttachPlatformKeyStore(h.Logger, h.TPM, h.Backend)
	require.NoError(t, err)
	assert.Same(t, first, second)
}

// TestAttachPlatformKeyStore_RejectsNilInputs proves the helper fails with the
// store's own typed errors rather than attaching a broken store.
func TestAttachPlatformKeyStore_RejectsNilInputs(t *testing.T) {
	h := newSimHarness(t, nil)

	_, err := AttachPlatformKeyStore(h.Logger, nil, h.Backend)
	assert.ErrorIs(t, err, ErrPlatformKeyStoreNilTPM)

	_, err = AttachPlatformKeyStore(h.Logger, h.TPM, nil)
	assert.ErrorIs(t, err, ErrPlatformKeyStoreNilBackend)
	assert.Nil(t, h.TPM.PlatformKeyStore(), "a failed attach must leave the TPM without a store")
}
