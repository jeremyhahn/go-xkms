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
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/storagetest"
)

// The contract body lives in storagetest so every backend is held to one
// definition. This file supplies only the fixture.
//
// No root, cryptsetup or real device is needed: the package's existing tests
// drive the backend through mockVolumeOperator, whose mount point is a t.TempDir()
// and whose Unlock is a flag flip, so Initialize produces a genuinely unlocked
// backend delegating to a real pkg/storage/file backend on that directory. The
// LUKS layer adds no writer of its own, so what is under contract here is the
// delegation and the locked-state gate; the guard itself is the file backend's,
// which runs the same contract in its own package.
//
// AllowsEmptyValue is TRUE, inherited from that delegate and measured through
// this backend rather than assumed from it: Put(key, []byte{}) succeeds and
// Exists then reports the key.
func TestBackend_CompareAndDeleteContract(t *testing.T) {
	storagetest.RunCompareAndDeleteContract(t, storagetest.Config{
		NewBackend: func(t *testing.T) storage.Backend {
			mock := newMockVolumeOperator(t.TempDir())
			mock.exists = false
			b := NewBackend(mock)
			if err := b.Initialize(64*1024*1024, "test-passphrase"); err != nil {
				t.Fatalf("Initialize: %v", err)
			}
			t.Cleanup(func() { _ = b.Close() })
			return b
		},
		Key:              "keys/contract-subject",
		AllowsEmptyValue: true,
	})
}

// A locked volume is an ERROR, not deleted=false, and the distinction is the
// whole point of testing it separately: the store may well still hold the key,
// so reporting a refusal would tell the caller its release was evaluated and
// lost when in fact the guard never ran. Mirrors
// TestBackend_PutIfAbsent_Locked.
func TestBackend_CompareAndDelete_Locked(t *testing.T) {
	ctx := context.Background()
	mock := newMockVolumeOperator(t.TempDir())
	b := NewBackend(mock)

	deleted, err := b.CompareAndDelete(ctx, "keys/example", []byte("x"))
	if !errors.Is(err, ErrVolumeLocked) || deleted {
		t.Fatalf("CompareAndDelete (locked) = (%v, %v), want (false, ErrVolumeLocked)", deleted, err)
	}
}
