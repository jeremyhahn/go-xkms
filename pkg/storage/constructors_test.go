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

	"github.com/stretchr/testify/require"
)

// Compile-time check: qrdb.Backend implements Backend interface.
// This verifies that the constructors return objects that satisfy the Backend interface.

func TestNewFile(t *testing.T) {
	dir := t.TempDir()
	backend, err := NewFile(dir)
	require.NoError(t, err)
	require.NotNil(t, backend)
	defer func() { _ = backend.Close() }()

	// Verify it implements Backend interface by using all methods
	ctx := context.Background()

	// Put
	err = backend.Put(ctx, "test/key", []byte("test-value"))
	require.NoError(t, err)

	// Get
	value, err := backend.Get(ctx, "test/key")
	require.NoError(t, err)
	require.Equal(t, []byte("test-value"), value)

	// Exists
	exists, err := backend.Exists(ctx, "test/key")
	require.NoError(t, err)
	require.True(t, exists)

	// List
	keys, err := backend.List(ctx, "test/")
	require.NoError(t, err)
	require.Equal(t, 1, len(keys))

	// Scan
	pairs := make(map[string][]byte)
	err = backend.Scan(ctx, "test/", func(key string, value []byte) error {
		pairs[key] = value
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, 1, len(pairs))

	// Delete
	err = backend.Delete(ctx, "test/key")
	require.NoError(t, err)
}

func TestNewFile_InvalidPath(t *testing.T) {
	_, err := NewFile("")
	require.Error(t, err)
}

func TestNewPebble(t *testing.T) {
	dir := t.TempDir()
	backend, err := NewPebble(dir)
	require.NoError(t, err)
	require.NotNil(t, backend)
	defer func() { _ = backend.Close() }()

	// Verify it implements Backend interface by using all methods
	ctx := context.Background()

	// Put
	err = backend.Put(ctx, "test/key", []byte("test-value"))
	require.NoError(t, err)

	// Get
	value, err := backend.Get(ctx, "test/key")
	require.NoError(t, err)
	require.Equal(t, []byte("test-value"), value)

	// Exists
	exists, err := backend.Exists(ctx, "test/key")
	require.NoError(t, err)
	require.True(t, exists)

	// List
	keys, err := backend.List(ctx, "test/")
	require.NoError(t, err)
	require.Equal(t, 1, len(keys))

	// Scan
	pairs2 := make(map[string][]byte)
	err = backend.Scan(ctx, "test/", func(key string, value []byte) error {
		pairs2[key] = value
		return nil
	})
	require.NoError(t, err)
	require.Equal(t, 1, len(pairs2))

	// Delete
	err = backend.Delete(ctx, "test/key")
	require.NoError(t, err)
}

func TestNewPebble_InvalidPath(t *testing.T) {
	_, err := NewPebble("")
	require.Error(t, err)
}
