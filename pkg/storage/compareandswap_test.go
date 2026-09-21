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
	"errors"
	"testing"
)

// TestEngineBackend_CompareAndSwap verifies the compare-and-swap contract on the
// canonical go-qrdb-engine-backed memory backend (#186): an absent key refuses
// regardless of expected (nil included -- a swap does not create), a
// matching-value swap succeeds, and a stale-value rejection returns the
// current value.
func TestEngineBackend_CompareAndSwap(t *testing.T) {
	ctx := context.Background()
	b := NewMemory()
	t.Cleanup(func() { _ = b.Close() })

	cas := b.(CompareAndSwapper)
	const key = "counters/lockout"

	// An absent key refuses no matter what expected is; a swap is not a
	// create. PutIfAbsent is the verb for that precondition.
	swapped, current, err := cas.CompareAndSwap(ctx, key, nil, []byte("0"))
	if err != nil {
		t.Fatalf("CompareAndSwap (absent, nil expected) error: %v", err)
	}
	if swapped {
		t.Fatalf("CompareAndSwap (absent, nil expected) = swapped true, want false -- a swap must not create (#186)")
	}
	if current != nil {
		t.Fatalf("CompareAndSwap (absent, nil expected) current = %q, want nil", current)
	}
	if _, err := b.Get(ctx, key); !errors.Is(err, ErrNotFound) {
		t.Fatalf("key must remain absent after a refused create-attempt, Get error = %v", err)
	}

	// Establish a value the ordinary way -- PutIfAbsent, not CompareAndSwap.
	v0 := []byte("0")
	stored, err := b.PutIfAbsent(ctx, key, v0)
	if err != nil || !stored {
		t.Fatalf("PutIfAbsent(seed) = (%v, %v), want (true, nil)", stored, err)
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

	// nil expected against a now-present, non-empty value is a refusal too --
	// nil compares like any other value and this key does not hold an empty one.
	swapped, current, err = cas.CompareAndSwap(ctx, key, nil, []byte("3"))
	if err != nil {
		t.Fatalf("CompareAndSwap (present, nil expected) error: %v", err)
	}
	if swapped {
		t.Fatalf("CompareAndSwap (present, nil expected) = swapped true, want false")
	}
	if !bytes.Equal(current, v1) {
		t.Fatalf("CompareAndSwap (present, nil expected) current = %q, want %q", current, v1)
	}
}

// TestEngineBackend_CompareAndSwap_NilMatchesStoredEmptyValue pins the other
// half of the convention CompareAndDelete already documents: nil is not a
// wildcard for absence, it is equivalent to an empty slice, so it matches a
// stored empty value and nothing else.
func TestEngineBackend_CompareAndSwap_NilMatchesStoredEmptyValue(t *testing.T) {
	ctx := context.Background()
	b := NewMemory()
	t.Cleanup(func() { _ = b.Close() })

	cas := b.(CompareAndSwapper)
	const key = "counters/empty"

	if stored, err := b.PutIfAbsent(ctx, key, []byte{}); err != nil || !stored {
		t.Fatalf("PutIfAbsent(seed empty) = (%v, %v), want (true, nil)", stored, err)
	}

	swapped, _, err := cas.CompareAndSwap(ctx, key, nil, []byte("filled"))
	if err != nil {
		t.Fatalf("CompareAndSwap (nil vs stored empty) error: %v", err)
	}
	if !swapped {
		t.Fatal("a nil expected must match a stored empty value")
	}
	if got, err := b.Get(ctx, key); err != nil || !bytes.Equal(got, []byte("filled")) {
		t.Fatalf("value after swap = (%q, %v), want %q", got, err, "filled")
	}
}

// TestPrefixBackend_CompareAndSwap verifies the prefix wrapper namespaces the
// key and delegates the atomic compare-and-swap to the wrapped backend,
// including the absent-key refusal on the prefixed key.
func TestPrefixBackend_CompareAndSwap(t *testing.T) {
	ctx := context.Background()
	inner := NewMemory()
	t.Cleanup(func() { _ = inner.Close() })

	p, err := NewPrefixBackend(inner, "tenant-a/")
	if err != nil {
		t.Fatalf("NewPrefixBackend: %v", err)
	}
	var cas CompareAndSwapper = p

	// An absent key refuses through the wrapper too.
	swapped, current, err := cas.CompareAndSwap(ctx, "counters/c1", nil, []byte("alpha"))
	if err != nil {
		t.Fatalf("CompareAndSwap (absent) error: %v", err)
	}
	if swapped {
		t.Fatal("CompareAndSwap (absent, nil expected) = swapped true, want false")
	}
	if current != nil {
		t.Fatalf("CompareAndSwap (absent) current = %q, want nil", current)
	}

	first := []byte("alpha")
	if stored, err := p.PutIfAbsent(ctx, "counters/c1", first); err != nil || !stored {
		t.Fatalf("PutIfAbsent(seed) = (%v, %v), want (true, nil)", stored, err)
	}

	// The wrapped backend must hold the prefixed key.
	if got, err := inner.Get(ctx, "tenant-a/counters/c1"); err != nil || !bytes.Equal(got, first) {
		t.Fatalf("inner.Get(prefixed) = (%q, %v), want (%q, nil)", got, err, first)
	}

	// A stale expected value against the prefixed key must be rejected and
	// return the current value.
	swapped, current, err = cas.CompareAndSwap(ctx, "counters/c1", []byte("wrong"), []byte("beta"))
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
