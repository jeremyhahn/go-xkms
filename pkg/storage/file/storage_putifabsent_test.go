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
)

// TestFileStorage_PutIfAbsent verifies the file backend's atomic
// check-then-write: a fresh key is written (stored=true) and a second write to
// the same key is rejected (stored=false), leaving the original value intact.
func TestFileStorage_PutIfAbsent(t *testing.T) {
	ctx := context.Background()
	fs, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = fs.Close() })

	const key = "keys/example"
	first := []byte("first")

	stored, err := fs.PutIfAbsent(ctx, key, first)
	if err != nil || !stored {
		t.Fatalf("PutIfAbsent (fresh) = (%v, %v), want (true, nil)", stored, err)
	}

	if got, err := fs.Get(ctx, key); err != nil || !bytes.Equal(got, first) {
		t.Fatalf("Get = (%q, %v), want (%q, nil)", got, err, first)
	}

	stored, err = fs.PutIfAbsent(ctx, key, []byte("second"))
	if err != nil {
		t.Fatalf("PutIfAbsent (existing) error: %v", err)
	}
	if stored {
		t.Fatalf("PutIfAbsent (existing) = stored true, want false")
	}

	if got, err := fs.Get(ctx, key); err != nil || !bytes.Equal(got, first) {
		t.Fatalf("value after rejected PutIfAbsent = (%q, %v), want original %q", got, err, first)
	}
}

// TestFileStorage_PutIfAbsent_InvalidKey verifies key validation runs before
// any write, so a traversal key is rejected with an error and never stored.
func TestFileStorage_PutIfAbsent_InvalidKey(t *testing.T) {
	ctx := context.Background()
	fs, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = fs.Close() })

	if stored, err := fs.PutIfAbsent(ctx, "../escape", []byte("x")); err == nil || stored {
		t.Fatalf("PutIfAbsent(traversal key) = (%v, %v), want (false, error)", stored, err)
	}
}
