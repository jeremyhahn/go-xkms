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

package luks

import (
	"bytes"
	"context"
	"errors"
	"testing"
)

// TestBackend_PutIfAbsent verifies the LUKS backend delegates the atomic
// check-then-write to its unlocked file delegate: a fresh key is written
// (stored=true) and a second write is rejected (stored=false), leaving the
// original value intact.
func TestBackend_PutIfAbsent(t *testing.T) {
	ctx := context.Background()
	mock := newMockVolumeOperator(t.TempDir())
	mock.exists = false
	b := NewBackend(mock)

	if err := b.Initialize(64*1024*1024, "test-passphrase"); err != nil {
		t.Fatalf("Initialize: %v", err)
	}

	const key = "keys/example"
	first := []byte("first")

	stored, err := b.PutIfAbsent(ctx, key, first)
	if err != nil || !stored {
		t.Fatalf("PutIfAbsent (fresh) = (%v, %v), want (true, nil)", stored, err)
	}

	if got, err := b.Get(ctx, key); err != nil || !bytes.Equal(got, first) {
		t.Fatalf("Get = (%q, %v), want (%q, nil)", got, err, first)
	}

	stored, err = b.PutIfAbsent(ctx, key, []byte("second"))
	if err != nil {
		t.Fatalf("PutIfAbsent (existing) error: %v", err)
	}
	if stored {
		t.Fatalf("PutIfAbsent (existing) = stored true, want false")
	}

	if got, err := b.Get(ctx, key); err != nil || !bytes.Equal(got, first) {
		t.Fatalf("value after rejected PutIfAbsent = (%q, %v), want original %q", got, err, first)
	}
}

// TestBackend_PutIfAbsent_Locked verifies PutIfAbsent refuses to write while
// the volume is locked, returning ErrVolumeLocked and stored=false.
func TestBackend_PutIfAbsent_Locked(t *testing.T) {
	ctx := context.Background()
	mock := newMockVolumeOperator(t.TempDir())
	b := NewBackend(mock)

	stored, err := b.PutIfAbsent(ctx, "keys/example", []byte("x"))
	if !errors.Is(err, ErrVolumeLocked) || stored {
		t.Fatalf("PutIfAbsent (locked) = (%v, %v), want (false, ErrVolumeLocked)", stored, err)
	}
}
