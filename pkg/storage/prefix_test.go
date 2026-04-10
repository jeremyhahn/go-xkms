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

package storage

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewPrefixBackend(t *testing.T) {
	inner := newMockBackend()

	t.Run("valid creation", func(t *testing.T) {
		pb, err := NewPrefixBackend(inner, "ns/")
		require.NoError(t, err)
		assert.NotNil(t, pb)
		assert.Equal(t, "ns/", pb.Prefix())
	})

	t.Run("nil inner returns error", func(t *testing.T) {
		pb, err := NewPrefixBackend(nil, "ns/")
		assert.ErrorIs(t, err, ErrInvalidData)
		assert.Nil(t, pb)
	})

	t.Run("empty prefix returns error", func(t *testing.T) {
		pb, err := NewPrefixBackend(inner, "")
		assert.ErrorIs(t, err, ErrEmptyPrefix)
		assert.Nil(t, pb)
	})
}

func TestPrefixBackend_PutGet(t *testing.T) {
	ctx := context.Background()
	inner := newMockBackend()

	t.Run("put and get with prefix", func(t *testing.T) {
		pb, err := NewPrefixBackend(inner, "tpm2/")
		require.NoError(t, err)

		err = pb.Put(ctx, "certificates/9a.der", []byte("cert-data"))
		require.NoError(t, err)

		// Verify the inner backend has the prefixed key.
		val, err := inner.Get(ctx, "tpm2/certificates/9a.der")
		require.NoError(t, err)
		assert.Equal(t, []byte("cert-data"), val)

		// Verify the PrefixBackend returns the value via unprefixed key.
		val, err = pb.Get(ctx, "certificates/9a.der")
		require.NoError(t, err)
		assert.Equal(t, []byte("cert-data"), val)
	})

	t.Run("get nonexistent key returns not found", func(t *testing.T) {
		pb, err := NewPrefixBackend(newMockBackend(), "ns/")
		require.NoError(t, err)

		_, err = pb.Get(ctx, "missing")
		assert.ErrorIs(t, err, ErrNotFound)
	})
}

func TestPrefixBackend_Delete(t *testing.T) {
	ctx := context.Background()

	t.Run("delete existing key", func(t *testing.T) {
		inner := newMockBackend()
		pb, err := NewPrefixBackend(inner, "sw/")
		require.NoError(t, err)

		err = pb.Put(ctx, "key1", []byte("data"))
		require.NoError(t, err)

		err = pb.Delete(ctx, "key1")
		require.NoError(t, err)

		_, err = pb.Get(ctx, "key1")
		assert.ErrorIs(t, err, ErrNotFound)
	})

	t.Run("delete nonexistent key returns not found", func(t *testing.T) {
		inner := newMockBackend()
		pb, err := NewPrefixBackend(inner, "sw/")
		require.NoError(t, err)

		err = pb.Delete(ctx, "missing")
		assert.ErrorIs(t, err, ErrNotFound)
	})
}

func TestPrefixBackend_List(t *testing.T) {
	ctx := context.Background()
	inner := newMockBackend()

	t.Run("list strips prefix from results", func(t *testing.T) {
		pb, err := NewPrefixBackend(inner, "tpm2/")
		require.NoError(t, err)

		err = pb.Put(ctx, "certificates/9a.der", []byte("a"))
		require.NoError(t, err)
		err = pb.Put(ctx, "certificates/9c.der", []byte("b"))
		require.NoError(t, err)

		keys, err := pb.List(ctx, "certificates/")
		require.NoError(t, err)
		assert.ElementsMatch(t, []string{"certificates/9a.der", "certificates/9c.der"}, keys)
	})

	t.Run("list is isolated between prefixes", func(t *testing.T) {
		shared := newMockBackend()

		pbA, err := NewPrefixBackend(shared, "alpha/")
		require.NoError(t, err)
		pbB, err := NewPrefixBackend(shared, "beta/")
		require.NoError(t, err)

		err = pbA.Put(ctx, "key1", []byte("a"))
		require.NoError(t, err)
		err = pbB.Put(ctx, "key2", []byte("b"))
		require.NoError(t, err)

		keysA, err := pbA.List(ctx, "")
		require.NoError(t, err)
		assert.Equal(t, []string{"key1"}, keysA)

		keysB, err := pbB.List(ctx, "")
		require.NoError(t, err)
		assert.Equal(t, []string{"key2"}, keysB)
	})

	t.Run("list empty namespace returns empty", func(t *testing.T) {
		pb, err := NewPrefixBackend(newMockBackend(), "empty/")
		require.NoError(t, err)

		keys, err := pb.List(ctx, "")
		require.NoError(t, err)
		assert.Empty(t, keys)
	})
}

func TestPrefixBackend_Scan(t *testing.T) {
	ctx := context.Background()
	inner := newMockBackend()

	t.Run("scan strips prefix from keys", func(t *testing.T) {
		pb, err := NewPrefixBackend(inner, "scan-ns/")
		require.NoError(t, err)

		err = pb.Put(ctx, "a", []byte("1"))
		require.NoError(t, err)
		err = pb.Put(ctx, "b", []byte("2"))
		require.NoError(t, err)

		collected := make(map[string]string)
		err = pb.Scan(ctx, "", func(key string, value []byte) error {
			collected[key] = string(value)
			return nil
		})
		require.NoError(t, err)
		assert.Equal(t, map[string]string{"a": "1", "b": "2"}, collected)
	})

	t.Run("scan propagates callback error", func(t *testing.T) {
		pb, err := NewPrefixBackend(inner, "scan-ns/")
		require.NoError(t, err)

		scanErr := pb.Scan(ctx, "", func(key string, value []byte) error {
			return ErrClosed
		})
		assert.ErrorIs(t, scanErr, ErrClosed)
	})
}

func TestPrefixBackend_Exists(t *testing.T) {
	ctx := context.Background()

	t.Run("exists returns true for present key", func(t *testing.T) {
		inner := newMockBackend()
		pb, err := NewPrefixBackend(inner, "ex/")
		require.NoError(t, err)

		err = pb.Put(ctx, "k1", []byte("v"))
		require.NoError(t, err)

		ok, err := pb.Exists(ctx, "k1")
		require.NoError(t, err)
		assert.True(t, ok)
	})

	t.Run("exists returns false for absent key", func(t *testing.T) {
		pb, err := NewPrefixBackend(newMockBackend(), "ex/")
		require.NoError(t, err)

		ok, err := pb.Exists(ctx, "missing")
		require.NoError(t, err)
		assert.False(t, ok)
	})
}

func TestPrefixBackend_Close(t *testing.T) {
	pb, err := NewPrefixBackend(newMockBackend(), "ns/")
	require.NoError(t, err)

	// Close is a no-op and should not error.
	err = pb.Close()
	assert.NoError(t, err)
}

func TestPrefixBackend_Isolation(t *testing.T) {
	// Verify that two PrefixBackends sharing the same inner backend
	// have completely isolated certificate storage namespaces.
	ctx := context.Background()
	shared := newMockBackend()

	sw, err := NewPrefixBackend(shared, "backends/software/")
	require.NoError(t, err)
	tpm, err := NewPrefixBackend(shared, "backends/tpm2/")
	require.NoError(t, err)

	// Store certificates in both namespaces.
	err = sw.Put(ctx, "certificates/9a.der", []byte("sw-cert"))
	require.NoError(t, err)
	err = tpm.Put(ctx, "certificates/9a.der", []byte("tpm-cert"))
	require.NoError(t, err)

	// Each namespace returns its own data.
	swData, err := sw.Get(ctx, "certificates/9a.der")
	require.NoError(t, err)
	assert.Equal(t, []byte("sw-cert"), swData)

	tpmData, err := tpm.Get(ctx, "certificates/9a.der")
	require.NoError(t, err)
	assert.Equal(t, []byte("tpm-cert"), tpmData)

	// List only shows keys from the respective namespace.
	swKeys, err := sw.List(ctx, "certificates/")
	require.NoError(t, err)
	assert.Equal(t, []string{"certificates/9a.der"}, swKeys)

	tpmKeys, err := tpm.List(ctx, "certificates/")
	require.NoError(t, err)
	assert.Equal(t, []string{"certificates/9a.der"}, tpmKeys)
}
