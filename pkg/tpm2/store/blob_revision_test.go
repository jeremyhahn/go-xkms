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

package store

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/types"
)

// TestBlobStore_CompareAndSwapRevision: a blob rewritten with the same bytes
// after its revision was read fails the revision swap and stays unchanged.
func TestBlobStore_CompareAndSwapRevision(t *testing.T) {
	factory, err := NewMemoryStorageFactory(testLogger())
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, factory.Close()) })
	var kb KeyBackend = factory.KeyBackend()
	backend, ok := kb.(KeyBlobRevisionSwapper)
	require.True(t, ok, "the blob store must offer revision swaps")
	attrs := &types.KeyAttributes{CN: "revision"}

	_, _, err = backend.GetRevision(attrs, FSEXT_PRIVATE_BLOB)
	require.ErrorIs(t, err, ErrBlobNotFound)
	swapped, err := backend.CompareAndSwapRevision(attrs, FSEXT_PRIVATE_BLOB, 0, []byte("next"))
	require.NoError(t, err)
	require.False(t, swapped, "an absent blob must not be swapped")

	require.NoError(t, factory.KeyBackend().Save(attrs, []byte("A"), FSEXT_PRIVATE_BLOB, false))
	data, rev, err := backend.GetRevision(attrs, FSEXT_PRIVATE_BLOB)
	require.NoError(t, err)
	require.Equal(t, "A", string(data))
	require.NotZero(t, rev)

	require.NoError(t, factory.KeyBackend().Save(attrs, []byte("A"), FSEXT_PRIVATE_BLOB, true))
	swapped, err = backend.CompareAndSwapRevision(attrs, FSEXT_PRIVATE_BLOB, rev, []byte("B"))
	require.NoError(t, err)
	require.False(t, swapped, "a same-bytes rewrite must change the revision")
	got, err := factory.KeyBackend().Get(attrs, FSEXT_PRIVATE_BLOB)
	require.NoError(t, err)
	require.Equal(t, "A", string(got))

	_, rev, err = backend.GetRevision(attrs, FSEXT_PRIVATE_BLOB)
	require.NoError(t, err)
	swapped, err = backend.CompareAndSwapRevision(attrs, FSEXT_PRIVATE_BLOB, rev, []byte("B"))
	require.NoError(t, err)
	require.True(t, swapped)
	data, next, err := backend.GetRevision(attrs, FSEXT_PRIVATE_BLOB)
	require.NoError(t, err)
	require.Equal(t, "B", string(data))
	require.NotEqual(t, rev, next, "a swap must store a fresh revision")
}
