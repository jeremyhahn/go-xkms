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

package sealed

import (
	"bytes"
	"context"
	"testing"
)

// TestBackend_PutIfAbsent verifies the sealed backend seals the value and
// delegates the atomic check-then-write: a fresh key is stored (stored=true,
// round-trips through Get) and a second write is rejected (stored=false),
// leaving the original sealed value intact.
func TestBackend_PutIfAbsent(t *testing.T) {
	ctx := context.Background()
	b := newTestBackend(t)
	t.Cleanup(func() { _ = b.Close() })

	const key = "keys/example"
	first := []byte("plaintext-one")

	stored, err := b.PutIfAbsent(ctx, key, first)
	if err != nil || !stored {
		t.Fatalf("PutIfAbsent (fresh) = (%v, %v), want (true, nil)", stored, err)
	}

	// Get unseals; the round-tripped plaintext must match.
	if got, err := b.Get(ctx, key); err != nil || !bytes.Equal(got, first) {
		t.Fatalf("Get = (%q, %v), want (%q, nil)", got, err, first)
	}

	stored, err = b.PutIfAbsent(ctx, key, []byte("plaintext-two"))
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
