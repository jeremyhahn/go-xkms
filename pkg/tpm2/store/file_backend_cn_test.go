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

package store

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The storage key is CN + extension. Before the guard, an empty CN composed
// the bare extension -- ".key", ".crt" -- so every nameless key in a backend
// addressed one slot and the last writer silently replaced the rest. These
// tests pin the refusal on every path that composes a key, and prove the
// collision the guard exists to prevent.

func TestFileBackend_EmptyCN_IsRefusedOnEveryPath(t *testing.T) {
	fb := NewFileBackend(testLogger(), storage.NewMemory())
	empty := &types.KeyAttributes{CN: ""}
	ext := types.FSExtension(FSEXT_PRIVATE_BLOB)

	err := fb.Save(empty, []byte("blob"), ext, true)
	assert.ErrorIs(t, err, ErrEmptyKeyCN, "Save must refuse an empty CN")

	_, err = fb.Get(empty, ext)
	assert.ErrorIs(t, err, ErrEmptyKeyCN, "Get must refuse an empty CN")

	err = fb.Delete(empty)
	assert.ErrorIs(t, err, ErrEmptyKeyCN, "Delete must refuse an empty CN")

	err = fb.Save(nil, []byte("blob"), ext, true)
	assert.ErrorIs(t, err, ErrEmptyKeyCN, "nil attributes have no CN either")
}

// Two keys that differ only in having a CN must not share a slot. This is
// the property that was violated: with the guard removed, the second Save
// below overwrites the first and the two Gets return the same bytes.
func TestFileBackend_DistinctCNs_DoNotCollide(t *testing.T) {
	fb := NewFileBackend(testLogger(), storage.NewMemory())
	ext := types.FSExtension(FSEXT_PUBLIC_BLOB)
	iak := &types.KeyAttributes{CN: "edge-001"}
	idevid := &types.KeyAttributes{CN: "edge-002"}

	require.NoError(t, fb.Save(iak, []byte("iak-public"), ext, true))
	require.NoError(t, fb.Save(idevid, []byte("idevid-public"), ext, true))

	got, err := fb.Get(iak, ext)
	require.NoError(t, err)
	assert.Equal(t, []byte("iak-public"), got, "the IAK's artifact survives the IDevID's write")

	got, err = fb.Get(idevid, ext)
	require.NoError(t, err)
	assert.Equal(t, []byte("idevid-public"), got)
}

func TestStorageKey_ComposesCNAndExtension(t *testing.T) {
	key, err := storageKey(&types.KeyAttributes{CN: "edge-001"}, FSEXT_PRIVATE_BLOB)
	require.NoError(t, err)
	assert.Equal(t, "edge-001"+FSEXT_PRIVATE_BLOB, key)

	_, err = storageKey(&types.KeyAttributes{}, FSEXT_PRIVATE_BLOB)
	assert.ErrorIs(t, err, ErrEmptyKeyCN)
}
