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

package file

import (
	"bytes"
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// TestFileStorage_CompareAndSwap verifies the file backend's atomic
// compare-and-swap (#186): an absent key refuses regardless of expected (a
// swap does not create), a matching-value swap succeeds, and a stale-value
// rejection returns the current value and leaves the stored value intact.
func TestFileStorage_CompareAndSwap(t *testing.T) {
	ctx := context.Background()
	fs, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = fs.Close() })
	cas := fs.(storage.CompareAndSwapper)

	const key = "counters/lockout"

	swapped, current, err := cas.CompareAndSwap(ctx, key, nil, []byte("0"))
	if err != nil {
		t.Fatalf("CompareAndSwap (absent, nil expected) error: %v", err)
	}
	if swapped {
		t.Fatalf("CompareAndSwap (absent, nil expected) = swapped true, want false -- a swap must not create")
	}
	if current != nil {
		t.Fatalf("CompareAndSwap (absent) current = %q, want nil", current)
	}

	v0 := []byte("0")
	if stored, err := fs.PutIfAbsent(ctx, key, v0); err != nil || !stored {
		t.Fatalf("PutIfAbsent(seed) = (%v, %v), want (true, nil)", stored, err)
	}

	v1 := []byte("1")
	swapped, _, err = cas.CompareAndSwap(ctx, key, v0, v1)
	if err != nil || !swapped {
		t.Fatalf("CompareAndSwap (match) = (%v, %v), want (true, nil)", swapped, err)
	}

	swapped, current, err = cas.CompareAndSwap(ctx, key, v0, []byte("2"))
	if err != nil {
		t.Fatalf("CompareAndSwap (stale) error: %v", err)
	}
	if swapped {
		t.Fatalf("CompareAndSwap (stale) = swapped true, want false")
	}
	if !bytes.Equal(current, v1) {
		t.Fatalf("CompareAndSwap (stale) current = %q, want %q", current, v1)
	}
	if got, err := fs.Get(ctx, key); err != nil || !bytes.Equal(got, v1) {
		t.Fatalf("value after rejected swap = (%q, %v), want unchanged %q", got, err, v1)
	}
}

// TestFileStorage_CompareAndSwap_InvalidKey verifies key validation runs before
// any delegation, so a traversal key is rejected and never swapped.
func TestFileStorage_CompareAndSwap_InvalidKey(t *testing.T) {
	ctx := context.Background()
	fs, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = fs.Close() })
	cas := fs.(storage.CompareAndSwapper)

	if swapped, _, err := cas.CompareAndSwap(ctx, "../escape", nil, []byte("x")); err == nil || swapped {
		t.Fatalf("CompareAndSwap(traversal key) = (%v, %v), want (false, error)", swapped, err)
	}
}
