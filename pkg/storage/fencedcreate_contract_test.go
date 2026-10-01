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

package storage_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/storagetest"
)

func TestEngineBackend_FencedCreateContract(t *testing.T) {
	storagetest.RunFencedCreateContract(t, storagetest.Config{
		NewBackend: func(t *testing.T) storage.Backend {
			b := storage.NewMemory()
			t.Cleanup(func() { _ = b.Close() })
			return b
		},
	})
}

func TestPrefixBackend_FencedCreateContract(t *testing.T) {
	storagetest.RunFencedCreateContract(t, storagetest.Config{
		NewBackend: func(t *testing.T) storage.Backend {
			inner := storage.NewMemory()
			t.Cleanup(func() { _ = inner.Close() })
			p, err := storage.NewPrefixBackend(inner, "tenant-a/")
			require.NoError(t, err)
			return p
		},
	})
}

// The prefix applies to the fences too: a fence outside the namespace must
// not refuse a create inside it, and one inside must.
func TestPrefixBackend_FencedCreateNamespacesTheFences(t *testing.T) {
	ctx := context.Background()
	inner := storage.NewMemory()
	t.Cleanup(func() { _ = inner.Close() })
	p, err := storage.NewPrefixBackend(inner, "tenant-a/")
	require.NoError(t, err)
	require.NoError(t, inner.Put(ctx, "fence", []byte("bare")))

	created, err := p.PutIfAllAbsent(ctx, "key", []byte("v"), "fence")
	require.NoError(t, err)
	assert.True(t, created, "a fence outside the namespace is not this namespace's fence")
	ok, err := inner.Exists(ctx, "tenant-a/key")
	require.NoError(t, err)
	assert.True(t, ok)

	require.NoError(t, inner.Put(ctx, "tenant-a/fence2", []byte("x")))
	created, err = p.PutIfAllAbsent(ctx, "key2", []byte("v"), "fence2")
	require.NoError(t, err)
	assert.False(t, created)
}

// A wrapper over a backend without the capability refuses rather than
// checking and then writing.
func TestPrefixBackend_FencedCreateUnsupportedInner(t *testing.T) {
	p, err := storage.NewPrefixBackend(withoutFencedCreate{storage.NewMemory()}, "x/")
	require.NoError(t, err)
	_, err = p.PutIfAllAbsent(context.Background(), "k", []byte("v"))
	assert.ErrorIs(t, err, storage.ErrFencedCreateUnsupported)
}

// withoutFencedCreate exposes only storage.Backend's methods, hiding the
// wrapped backend's optional capabilities.
type withoutFencedCreate struct{ storage.Backend }
