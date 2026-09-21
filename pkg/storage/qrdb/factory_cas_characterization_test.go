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

package qrdb

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// eachEmbeddedConstructor runs fn against a fresh Backend from each embedded
// constructor (memory, file, pebble), closing it on cleanup. Shared by every
// characterization test in this package, including
// backend_compareanddelete_test.go's, so all three verbs are measured through
// the same construction path.
func eachEmbeddedConstructor(t *testing.T, fn func(t *testing.T, name string, b *Backend)) {
	t.Helper()

	constructors := []struct {
		name string
		open func(t *testing.T) (*Backend, error)
	}{
		{"memory", func(*testing.T) (*Backend, error) { return NewMemory() }},
		{"file", func(t *testing.T) (*Backend, error) { return NewFile(t.TempDir()) }},
		{"pebble", func(t *testing.T) (*Backend, error) { return NewPebble(t.TempDir()) }},
	}

	for _, c := range constructors {
		t.Run(c.name, func(t *testing.T) {
			b, err := c.open(t)
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			t.Cleanup(func() {
				if err := b.Close(); err != nil {
					t.Errorf("close: %v", err)
				}
			})
			fn(t, c.name, b)
		})
	}
}

// The compare-and-swap notes on the constructors are a claim about behaviour,
// so they are pinned by exercising THE CONSTRUCTORS -- not by reasoning about
// which engine qrdb would select on some other path. An earlier version of
// that documentation described the KVEngine/MVCCEngine split from
// pkg/server/lifecycle.NewLocalEngine, which newEmbedded does not use; these
// tests exist so the next such claim has to survive contact with the code.
//
// They are characterization tests: they record what happens TODAY. This file
// used to pin PutIfAbsent and CompareAndSwap as UNAVAILABLE on every embedded
// constructor (#125): newEmbedded wires no transaction service, and both
// methods dispatched to transport.TransactionClient alone. The fix was not a
// transaction service -- it was dispatching to transport.GuardedKVClient
// first, the same preference backend_compareanddelete.go already used, since
// newEmbedded's transport implements that capability by delegating straight
// to the KV service. These tests were written to FAIL the day that dispatch
// changed, which is exactly what happened; what follows is the re-derivation
// that failure asked for.
func TestEmbeddedConstructors_PutIfAbsentAndCompareAndSwap(t *testing.T) {
	eachEmbeddedConstructor(t, func(t *testing.T, name string, b *Backend) {
		ctx := context.Background()

		// PutIfAbsent: the first writer wins, and a second call is a clean
		// refusal that leaves the stored value untouched.
		key := "cas-characterization/put-if-absent"
		stored, err := b.PutIfAbsent(ctx, key, []byte("v1"))
		require.NoError(t, err, "%s: PutIfAbsent", name)
		assert.True(t, stored, "%s: the first PutIfAbsent must succeed", name)

		stored, err = b.PutIfAbsent(ctx, key, []byte("v2"))
		require.NoError(t, err, "%s: PutIfAbsent", name)
		assert.False(t, stored, "%s: a present key must refuse PutIfAbsent", name)
		got, err := b.Get(ctx, key)
		require.NoError(t, err)
		assert.Equal(t, []byte("v1"), got, "%s: a refused PutIfAbsent must not overwrite", name)

		// CompareAndSwap: a stale guard refuses and reports the value actually
		// present without mutating it; a matching guard swaps.
		swapKey := "cas-characterization/compare-and-swap"
		require.NoError(t, b.Put(ctx, swapKey, []byte("v1")))

		swapped, current, err := b.CompareAndSwap(ctx, swapKey, []byte("stale"), []byte("v2"))
		require.NoError(t, err, "%s: CompareAndSwap", name)
		assert.False(t, swapped, "%s: a stale guard must refuse", name)
		assert.Equal(t, []byte("v1"), current, "%s: a refusal must report the current value", name)
		got, err = b.Get(ctx, swapKey)
		require.NoError(t, err)
		assert.Equal(t, []byte("v1"), got, "%s: a refused swap must not mutate the stored value", name)

		swapped, _, err = b.CompareAndSwap(ctx, swapKey, []byte("v1"), []byte("v2"))
		require.NoError(t, err, "%s: CompareAndSwap", name)
		assert.True(t, swapped, "%s: a matching guard must swap", name)
		got, err = b.Get(ctx, swapKey)
		require.NoError(t, err)
		assert.Equal(t, []byte("v2"), got, "%s: a successful swap must store the new value", name)
	})
}

// TestEmbeddedConstructors_PutIfAbsentAndCompareAndSwapTakeTheGuardedPath pins
// WHICH route serves the verbs, which the conformance test above cannot see: a
// transaction fallback that happened to produce the same answers would satisfy
// it too. newEmbedded wires no transaction service, so if the guarded path
// were not answering, every case above would be an error rather than a
// refusal or a success -- calling straight through the capability, bypassing
// Backend's dispatch, is the in-package evidence that the guarded path, not a
// fallback, is what runs. Mirrors
// TestEmbeddedConstructors_CompareAndDeleteTakesTheGuardedPath in
// backend_compareanddelete_test.go.
func TestEmbeddedConstructors_PutIfAbsentAndCompareAndSwapTakeTheGuardedPath(t *testing.T) {
	eachEmbeddedConstructor(t, func(t *testing.T, name string, b *Backend) {
		ctx := context.Background()

		guarded, ok := b.client.(transport.GuardedKVClient)
		require.True(t, ok, "%s: the embedded transport must implement GuardedKVClient", name)

		key := "cas-characterization/guarded-path"
		stored, err := guarded.PutIfAbsent(ctx, key, []byte("v1"))
		require.NoError(t, err, "%s: the guarded capability must serve PutIfAbsent", name)
		assert.True(t, stored)

		swapped, err := guarded.CompareAndSwap(ctx, key, []byte("v1"), []byte("v2"))
		require.NoError(t, err, "%s: the guarded capability must serve CompareAndSwap", name)
		assert.True(t, swapped)
	})
}

// Plain Put/Get must be unaffected, which is what made the CAS gap a trap
// while it existed: a caller saw a working store and only discovered the
// missing operations on the path that needed them.
func TestEmbeddedConstructors_PlainPutGetUnaffected(t *testing.T) {
	eachEmbeddedConstructor(t, func(t *testing.T, name string, b *Backend) {
		ctx := context.Background()
		key, want := "plain-roundtrip", []byte("value")

		if err := b.Put(ctx, key, want); err != nil {
			t.Fatalf("Put: %v", err)
		}
		got, err := b.Get(ctx, key)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if string(got) != string(want) {
			t.Fatalf("Get = %q, want %q", got, want)
		}
	})
}
