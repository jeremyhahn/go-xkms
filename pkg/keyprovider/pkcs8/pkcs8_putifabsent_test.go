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

package pkcs8

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/errs"

	"github.com/jeremyhahn/go-xkms/pkg/backend"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// PutIfAbsent overrides the embedded backend so the new GenerateKey
// uniqueness path (which guards on PutIfAbsent rather than a separate
// KeyExists pre-check) surfaces a storage error. This keeps
// TestGenerateKey_StorageCheckError exercising storage-error propagation
// through the path GenerateKey actually uses.
func (m *mockStorageErrorOnExists) PutIfAbsent(_ context.Context, _ string, _ []byte) (bool, error) {
	return false, &errs.Message{Msg: "mock PutIfAbsent error"}
}

// TestGenerateKey_ConcurrentSameID verifies that the PutIfAbsent-based
// uniqueness guard admits exactly one writer when many goroutines race to
// generate the SAME key ID against an in-memory engine backend. Exactly one
// GenerateKey must succeed, the rest must observe ErrKeyAlreadyExists, and
// exactly one key must be persisted. Ed25519 is used so keygen is fast and the
// test stays in-memory.
func TestGenerateKey_ConcurrentSameID(t *testing.T) {
	be, keyStorage := createTestBackend(t)
	defer func() { _ = be.Close() }()

	const goroutines = 20

	type result struct {
		err error
	}
	results := make([]result, goroutines)

	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	done.Add(goroutines)

	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer done.Done()
			// All goroutines target the identical key ID.
			attrs := createEd25519Attrs("race.example")
			start.Wait() // release all goroutines together to maximize contention
			_, err := be.GenerateKey(context.Background(), attrs)
			results[idx] = result{err: err}
		}(i)
	}

	start.Done()
	done.Wait()

	var successes, alreadyExists, others int
	for _, r := range results {
		switch {
		case r.err == nil:
			successes++
		case errors.Is(r.err, backend.ErrKeyAlreadyExists):
			alreadyExists++
		default:
			others++
			t.Errorf("unexpected error from GenerateKey: %v", r.err)
		}
	}

	if successes != 1 {
		t.Fatalf("successes = %d, want exactly 1", successes)
	}
	if alreadyExists != goroutines-1 {
		t.Fatalf("ErrKeyAlreadyExists count = %d, want %d", alreadyExists, goroutines-1)
	}
	if others != 0 {
		t.Fatalf("unexpected errors = %d, want 0", others)
	}

	// Exactly one key must be persisted under the keys/ namespace.
	keyIDs, err := storage.ListKeys(context.Background(), keyStorage)
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if len(keyIDs) != 1 {
		t.Fatalf("stored key count = %d (%v), want exactly 1", len(keyIDs), keyIDs)
	}
}
