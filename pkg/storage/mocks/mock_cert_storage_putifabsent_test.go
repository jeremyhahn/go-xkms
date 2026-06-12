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

package mocks

import (
	"bytes"
	"context"
	"testing"
)

// TestMockCertStorage_PutIfAbsent verifies the mock's map-based
// check-then-write: a fresh key is stored (stored=true) and a second write is
// rejected (stored=false), leaving the original value intact.
func TestMockCertStorage_PutIfAbsent(t *testing.T) {
	ctx := context.Background()
	m := NewMockCertStorage()
	t.Cleanup(func() { _ = m.Close() })

	const key = "keys/example"
	first := []byte("first")

	stored, err := m.PutIfAbsent(ctx, key, first)
	if err != nil || !stored {
		t.Fatalf("PutIfAbsent (fresh) = (%v, %v), want (true, nil)", stored, err)
	}

	if got, err := m.Get(ctx, key); err != nil || !bytes.Equal(got, first) {
		t.Fatalf("Get = (%q, %v), want (%q, nil)", got, err, first)
	}

	stored, err = m.PutIfAbsent(ctx, key, []byte("second"))
	if err != nil {
		t.Fatalf("PutIfAbsent (existing) error: %v", err)
	}
	if stored {
		t.Fatalf("PutIfAbsent (existing) = stored true, want false")
	}

	if got, err := m.Get(ctx, key); err != nil || !bytes.Equal(got, first) {
		t.Fatalf("value after rejected PutIfAbsent = (%q, %v), want original %q", got, err, first)
	}
}

// TestMockCertStorage_PutIfAbsent_Closed verifies PutIfAbsent fails after the
// store is closed.
func TestMockCertStorage_PutIfAbsent_Closed(t *testing.T) {
	ctx := context.Background()
	m := NewMockCertStorage()
	_ = m.Close()

	if stored, err := m.PutIfAbsent(ctx, "keys/example", []byte("x")); err == nil || stored {
		t.Fatalf("PutIfAbsent (closed) = (%v, %v), want (false, error)", stored, err)
	}
}
