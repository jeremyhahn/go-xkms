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

// The CAS gap measured at the PUBLIC layer, which is where the finding on
// PR #74 says the contract is read -- and it is right that this is the layer
// that matters. pkg/storage/qrdb has its own characterization tests; this one
// exists because a caller reads Backend and these constructors, not the
// package underneath them.
//
// It pins the deviation as DOCUMENTED behaviour rather than leaving the
// interface comment as the only record. Making these constructors satisfy the
// contract instead is go-xkms#61, blocked on go-qrdb#62 pending an owner
// ruling on the standalone-mode transaction service; building a local
// compare-and-swap here instead is explicitly out of scope.
//
// EXPECTED TO FAIL when #61 lands. That is the point: the failure is what
// forces the contract note above to be removed rather than left to rot.
func TestPublicConstructors_CASUnavailableUntilIssue61(t *testing.T) {
	backends := []struct {
		name string
		open func(t *testing.T) (Backend, error)
	}{
		{"file", func(t *testing.T) (Backend, error) { return NewFile(t.TempDir()) }},
		{"pebble", func(t *testing.T) (Backend, error) { return NewPebble(t.TempDir()) }},
	}

	for _, tc := range backends {
		t.Run(tc.name, func(t *testing.T) {
			b, err := tc.open(t)
			if err != nil {
				t.Fatalf("%s: %v", tc.name, err)
			}
			t.Cleanup(func() {
				if err := b.Close(); err != nil {
					t.Errorf("close: %v", err)
				}
			})

			ctx := context.Background()

			// Plain writes work, which is what makes the gap a trap rather
			// than an outage: the store looks healthy.
			if err := b.Put(ctx, "k", []byte("v")); err != nil {
				t.Fatalf("Put: %v", err)
			}

			stored, err := b.PutIfAbsent(ctx, "cas-probe", []byte("v"))
			if err == nil {
				t.Fatalf("PutIfAbsent succeeded (stored=%t): the transaction service is "+
					"wired now, so the limitation documented on these constructors and on "+
					"the Backend contract must be removed -- see #61", stored)
			}
			// An error is NOT stored=false. A caller that conflated them would
			// read "the key was already present" and skip its own write.
			if stored {
				t.Error("a failed PutIfAbsent reported stored=true")
			}
		})
	}
}
