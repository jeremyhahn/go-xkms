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
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/storagetest"
)

// The contract body lives in storagetest so every backend is held to one
// definition. Running it against the MOCK is the point of the mock implementing
// the verb for real rather than stubbing it: a test that swaps a real backend
// for this one keeps the same guarantees, so a guarded release exercised here
// means what it means in production.
//
// The mock stores arbitrary bytes in m.data, so the generic defaults apply.
// AllowsEmptyValue is TRUE, measured: Put(key, []byte{}) stores an entry that
// Exists reports, and a nil guard matches it.
func TestMockCertStorage_CompareAndDeleteContract(t *testing.T) {
	storagetest.RunCompareAndDeleteContract(t, storagetest.Config{
		NewBackend: func(t *testing.T) storage.Backend {
			m := NewMockCertStorage()
			t.Cleanup(func() { _ = m.Close() })
			return m
		},
		AllowsEmptyValue: true,
	})
}

// A closed store is an ERROR, not deleted=false: the guard was never evaluated,
// and reporting a refusal would tell the caller it lost a comparison that never
// ran. This mirrors TestMockCertStorage_PutIfAbsent_Closed.
func TestMockCertStorage_CompareAndDelete_Closed(t *testing.T) {
	ctx := context.Background()
	m := NewMockCertStorage()

	if err := m.Put(ctx, "keys/example", []byte("x")); err != nil {
		t.Fatalf("Put: %v", err)
	}
	_ = m.Close()

	if deleted, err := m.CompareAndDelete(ctx, "keys/example", []byte("x")); err == nil || deleted {
		t.Fatalf("CompareAndDelete (closed) = (%v, %v), want (false, error)", deleted, err)
	}
}
