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
	"bytes"
	"context"
	"testing"
)

// TestEngineBackend_CompareAndSwap verifies the compare-and-swap contract on the
// canonical go-qrdb-engine-backed memory backend: create-if-absent (expected
// nil), a matching-value swap, a stale-value rejection that returns the current
// value, and a create-if-absent rejection once the key exists.
func TestEngineBackend_CompareAndSwap(t *testing.T) {
	ctx := context.Background()
	b := NewMemory()
	t.Cleanup(func() { _ = b.Close() })

	cas := b.(CompareAndSwapper)
	const key = "counters/lockout"

	// Create-if-absent: expected nil against a missing key must swap.
	v0 := []byte("0")
	swapped, current, err := cas.CompareAndSwap(ctx, key, nil, v0)
	if err != nil {
		t.Fatalf("CompareAndSwap (create) error: %v", err)
	}
	if !swapped {
		t.Fatalf("CompareAndSwap (create) = swapped false, want true (current=%q)", current)
	}

	// Create-if-absent against a now-present key must fail and report current.
	swapped, current, err = cas.CompareAndSwap(ctx, key, nil, []byte("99"))
	if err != nil {
		t.Fatalf("CompareAndSwap (create-existing) error: %v", err)
	}
	if swapped {
		t.Fatalf("CompareAndSwap (create-existing) = swapped true, want false")
	}
	if !bytes.Equal(current, v0) {
		t.Fatalf("CompareAndSwap (create-existing) current = %q, want %q", current, v0)
	}

	// Matching-value swap: expected equals the stored value, must swap.
	v1 := []byte("1")
	swapped, _, err = cas.CompareAndSwap(ctx, key, v0, v1)
	if err != nil {
		t.Fatalf("CompareAndSwap (match) error: %v", err)
	}
	if !swapped {
		t.Fatalf("CompareAndSwap (match) = swapped false, want true")
	}
	if got, err := b.Get(ctx, key); err != nil || !bytes.Equal(got, v1) {
		t.Fatalf("value after matched swap = (%q, %v), want %q", got, err, v1)
	}

	// Stale-value rejection: expected no longer matches; must not swap and must
	// return the current value so a caller can recompute and retry.
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
	if got, err := b.Get(ctx, key); err != nil || !bytes.Equal(got, v1) {
		t.Fatalf("value after rejected swap = (%q, %v), want unchanged %q", got, err, v1)
	}
}

// TestPrefixBackend_CompareAndSwap verifies the prefix wrapper namespaces the
// key and delegates the atomic compare-and-swap to the wrapped backend.
func TestPrefixBackend_CompareAndSwap(t *testing.T) {
	ctx := context.Background()
	inner := NewMemory()
	t.Cleanup(func() { _ = inner.Close() })

	p, err := NewPrefixBackend(inner, "tenant-a/")
	if err != nil {
		t.Fatalf("NewPrefixBackend: %v", err)
	}
	var cas CompareAndSwapper = p

	first := []byte("alpha")
	swapped, _, err := cas.CompareAndSwap(ctx, "counters/c1", nil, first)
	if err != nil || !swapped {
		t.Fatalf("CompareAndSwap (create) = (%v, %v), want (true, nil)", swapped, err)
	}

	// The wrapped backend must hold the prefixed key.
	if got, err := inner.Get(ctx, "tenant-a/counters/c1"); err != nil || !bytes.Equal(got, first) {
		t.Fatalf("inner.Get(prefixed) = (%q, %v), want (%q, nil)", got, err, first)
	}

	// A stale expected value against the prefixed key must be rejected and
	// return the current value.
	swapped, current, err := cas.CompareAndSwap(ctx, "counters/c1", []byte("wrong"), []byte("beta"))
	if err != nil {
		t.Fatalf("CompareAndSwap (stale) error: %v", err)
	}
	if swapped {
		t.Fatalf("CompareAndSwap (stale) = swapped true, want false")
	}
	if !bytes.Equal(current, first) {
		t.Fatalf("CompareAndSwap (stale) current = %q, want %q", current, first)
	}
}
