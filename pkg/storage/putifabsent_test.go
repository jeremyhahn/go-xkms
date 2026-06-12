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

// TestEngineBackend_PutIfAbsent verifies the atomic check-then-write on the
// canonical go-qrdb-engine-backed memory backend: a fresh key is written and
// reports stored=true; a second write to the same key is rejected (stored=false)
// and leaves the original value intact.
func TestEngineBackend_PutIfAbsent(t *testing.T) {
	ctx := context.Background()
	b := NewMemory()
	t.Cleanup(func() { _ = b.Close() })

	const key = "keys/example"
	first := []byte("first-value")

	stored, err := b.PutIfAbsent(ctx, key, first)
	if err != nil {
		t.Fatalf("PutIfAbsent (fresh) returned error: %v", err)
	}
	if !stored {
		t.Fatalf("PutIfAbsent (fresh) = stored false, want true")
	}

	got, err := b.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get after first PutIfAbsent: %v", err)
	}
	if !bytes.Equal(got, first) {
		t.Fatalf("stored value = %q, want %q", got, first)
	}

	stored, err = b.PutIfAbsent(ctx, key, []byte("second-value"))
	if err != nil {
		t.Fatalf("PutIfAbsent (existing) returned error: %v", err)
	}
	if stored {
		t.Fatalf("PutIfAbsent (existing) = stored true, want false")
	}

	got, err = b.Get(ctx, key)
	if err != nil {
		t.Fatalf("Get after second PutIfAbsent: %v", err)
	}
	if !bytes.Equal(got, first) {
		t.Fatalf("value after rejected PutIfAbsent = %q, want original %q", got, first)
	}
}

// TestPrefixBackend_PutIfAbsent verifies the prefix wrapper namespaces the key
// and delegates the atomic check-then-write to the wrapped backend.
func TestPrefixBackend_PutIfAbsent(t *testing.T) {
	ctx := context.Background()
	inner := NewMemory()
	t.Cleanup(func() { _ = inner.Close() })

	p, err := NewPrefixBackend(inner, "tenant-a/")
	if err != nil {
		t.Fatalf("NewPrefixBackend: %v", err)
	}

	first := []byte("alpha")
	stored, err := p.PutIfAbsent(ctx, "keys/k1", first)
	if err != nil || !stored {
		t.Fatalf("PutIfAbsent (fresh) = (%v, %v), want (true, nil)", stored, err)
	}

	// The wrapped backend must hold the prefixed key.
	if got, err := inner.Get(ctx, "tenant-a/keys/k1"); err != nil || !bytes.Equal(got, first) {
		t.Fatalf("inner.Get(prefixed) = (%q, %v), want (%q, nil)", got, err, first)
	}

	stored, err = p.PutIfAbsent(ctx, "keys/k1", []byte("beta"))
	if err != nil {
		t.Fatalf("PutIfAbsent (existing) error: %v", err)
	}
	if stored {
		t.Fatalf("PutIfAbsent (existing) = stored true, want false")
	}

	if got, err := p.Get(ctx, "keys/k1"); err != nil || !bytes.Equal(got, first) {
		t.Fatalf("value after rejected PutIfAbsent = (%q, %v), want original %q", got, err, first)
	}
}

// TestSaveKeyIfAbsent exercises the adapter helper: empty id is rejected, an
// absent key is stored, and a present key is not overwritten.
func TestSaveKeyIfAbsent(t *testing.T) {
	ctx := context.Background()
	b := NewMemory()
	t.Cleanup(func() { _ = b.Close() })

	if _, err := SaveKeyIfAbsent(ctx, b, "", []byte("x")); !errors.Is(err, ErrInvalidID) {
		t.Fatalf("SaveKeyIfAbsent(empty id) error = %v, want ErrInvalidID", err)
	}

	first := []byte("key-material")
	stored, err := SaveKeyIfAbsent(ctx, b, "my-key", first)
	if err != nil || !stored {
		t.Fatalf("SaveKeyIfAbsent (absent) = (%v, %v), want (true, nil)", stored, err)
	}

	got, err := GetKey(ctx, b, "my-key")
	if err != nil || !bytes.Equal(got, first) {
		t.Fatalf("GetKey = (%q, %v), want (%q, nil)", got, err, first)
	}

	stored, err = SaveKeyIfAbsent(ctx, b, "my-key", []byte("replacement"))
	if err != nil {
		t.Fatalf("SaveKeyIfAbsent (present) error: %v", err)
	}
	if stored {
		t.Fatalf("SaveKeyIfAbsent (present) = stored true, want false")
	}

	got, err = GetKey(ctx, b, "my-key")
	if err != nil || !bytes.Equal(got, first) {
		t.Fatalf("value after rejected SaveKeyIfAbsent = (%q, %v), want original %q", got, err, first)
	}
}
