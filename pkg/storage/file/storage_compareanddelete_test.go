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
	"context"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/storagetest"
	"github.com/stretchr/testify/require"
)

// The contract body lives in storagetest so every backend is held to one
// definition of the semantics. This file supplies only the fixture.
//
// The key shape matches the other guarded-verb tests in this package
// ("keys/..."), because CompareAndDelete runs validateStorageKey before it
// delegates and a bare key would be rejected for a reason unrelated to the
// guard.
//
// AllowsEmptyValue is TRUE, measured rather than assumed: Put(key, []byte{})
// succeeds, Exists then reports true and Get returns a zero-length value, so
// the empty value is a value this backend really holds and a nil guard must
// match it.
func TestFileStorage_CompareAndDeleteContract(t *testing.T) {
	storagetest.RunCompareAndDeleteContract(t, storagetest.Config{
		NewBackend: func(t *testing.T) storage.Backend {
			fs, err := New(t.TempDir())
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			t.Cleanup(func() { _ = fs.Close() })
			return fs
		},
		Key:              "keys/contract-subject",
		AllowsEmptyValue: true,
	})
}

// Key validation must run BEFORE the guard is evaluated, so a traversal key is
// an error rather than a quiet deleted=false. Reporting a refusal would tell
// the caller its guard lost a comparison that never happened.
func TestFileStorage_CompareAndDelete_InvalidKey(t *testing.T) {
	ctx := context.Background()
	fs, err := New(t.TempDir())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	t.Cleanup(func() { _ = fs.Close() })

	cad, ok := fs.(storage.CompareAndDeleter)
	require.True(t, ok, "file storage claims the guarded-delete capability")

	if deleted, err := cad.CompareAndDelete(ctx, "../escape", []byte("x")); err == nil || deleted {
		t.Fatalf("CompareAndDelete(traversal key) = (%v, %v), want (false, error)", deleted, err)
	}
}
