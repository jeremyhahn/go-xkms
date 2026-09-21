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

// Guarded writes measured at the PUBLIC layer, which is where the finding on
// PR #74 says the contract is read -- and it is right that this is the layer
// that matters. pkg/storage/qrdb has its own characterization tests; this one
// exists because a caller reads Backend and these constructors, not the
// package underneath them.
//
// It used to pin the CAS gap as DOCUMENTED behaviour rather than leaving the
// interface comment as the only record (go-xkms#61/#125): NewFile and
// NewPebble delegate to pkg/storage/qrdb, whose PutIfAbsent and CompareAndSwap
// dispatched to a transaction the embedded transport wires no service for.
// That is fixed -- both methods now prefer the transport's own
// transport.GuardedKVClient capability first, the same dispatch
// CompareAndDelete already used -- so this test now pins the corrected
// behaviour: PutIfAbsent, CompareAndSwap and CompareAndDelete all execute
// through these public constructors.
func TestPublicConstructors_GuardedWritesAvailable(t *testing.T) {
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

			// Plain writes are unaffected, as they always were.
			if err := b.Put(ctx, "k", []byte("v")); err != nil {
				t.Fatalf("Put: %v", err)
			}

			// PutIfAbsent: first writer wins, a second is a clean refusal.
			stored, err := b.PutIfAbsent(ctx, "cas-probe", []byte("v1"))
			if err != nil {
				t.Fatalf("PutIfAbsent: %v", err)
			}
			if !stored {
				t.Fatal("the first PutIfAbsent must succeed")
			}
			stored, err = b.PutIfAbsent(ctx, "cas-probe", []byte("v2"))
			if err != nil {
				t.Fatalf("PutIfAbsent: %v", err)
			}
			if stored {
				t.Fatal("a present key must refuse PutIfAbsent")
			}

			swapper, ok := b.(CompareAndSwapper)
			if !ok {
				t.Fatalf("%s: Backend does not implement CompareAndSwapper", tc.name)
			}
			swapped, current, err := swapper.CompareAndSwap(ctx, "cas-probe", []byte("stale"), []byte("v3"))
			if err != nil {
				t.Fatalf("CompareAndSwap: %v", err)
			}
			if swapped {
				t.Fatal("a stale guard must refuse CompareAndSwap")
			}
			if string(current) != "v1" {
				t.Fatalf("CompareAndSwap current = %q, want %q", current, "v1")
			}
			swapped, _, err = swapper.CompareAndSwap(ctx, "cas-probe", []byte("v1"), []byte("v3"))
			if err != nil {
				t.Fatalf("CompareAndSwap: %v", err)
			}
			if !swapped {
				t.Fatal("a matching guard must swap")
			}

			deleter, ok := b.(CompareAndDeleter)
			if !ok {
				t.Fatalf("%s: Backend does not implement CompareAndDeleter", tc.name)
			}
			deleted, err := deleter.CompareAndDelete(ctx, "cas-probe", []byte("v3"))
			if err != nil {
				t.Fatalf("CompareAndDelete: %v", err)
			}
			if !deleted {
				t.Fatal("a matching guard must delete")
			}
		})
	}
}
