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

package storage_test

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/storagetest"
)

// The absent-key contract body lives in storagetest. This file supplies the
// fixtures for the backends reachable from pkg/storage's own constructors,
// which is where go-xkms#252 was measured.
//
// The split these fixtures record is NOT memory-versus-disk, which is the
// obvious reading and the wrong one. It is engineBackend versus everything
// that reaches the embedded QRDB client: storage.NewMemory conforms, while
// NewFile, NewPebble and qrdb.NewMemory diverge identically. The divergence
// travels with the client, not with the storage medium.
//
// It has NARROWED. go-qrdb v0.16.3-alpha fixed Exists and Get, so those two
// verbs are now held to the correct answer on every backend here; only Delete
// still reports success for a key that was never written, which is what
// AbsentDeleteDivergence declares (go-xkms#252, narrowed in #406).
//
// PutIfAbsent's separate divergence (go-xkms#61/#125, Config.PutIfAbsentUnavailable)
// is gone from these two fixtures entirely: NewFile and NewPebble now dispatch
// PutIfAbsent through the embedded transport's transport.GuardedKVClient
// capability, which needs no transaction service, so the suite holds them to
// the same "stores and reports true" answer as every conforming backend.

func TestEngineBackend_AbsentKeyContract(t *testing.T) {
	storagetest.RunAbsentKeyContract(t, storagetest.Config{
		NewBackend: func(t *testing.T) storage.Backend {
			b := storage.NewMemory()
			t.Cleanup(func() { _ = b.Close() })
			return b
		},
	})
}

func TestPrefixBackend_AbsentKeyContract(t *testing.T) {
	storagetest.RunAbsentKeyContract(t, storagetest.Config{
		NewBackend: func(t *testing.T) storage.Backend {
			inner := storage.NewMemory()
			t.Cleanup(func() { _ = inner.Close() })
			p, err := storage.NewPrefixBackend(inner, "tenant-a/")
			if err != nil {
				t.Fatalf("NewPrefixBackend: %v", err)
			}
			return p
		},
	})
}

// NewFile is the DEFAULT engine, which is what makes its divergence expensive:
// pkg/server/backend_factory.go selects through these constructors, so the
// wrong answers are the ones production gets.
func TestNewFile_AbsentKeyContract(t *testing.T) {
	storagetest.RunAbsentKeyContract(t, storagetest.Config{
		NewBackend: func(t *testing.T) storage.Backend {
			b, err := storage.NewFile(t.TempDir())
			if err != nil {
				t.Fatalf("NewFile: %v", err)
			}
			t.Cleanup(func() { _ = b.Close() })
			return b
		},
		AbsentDeleteDivergence: true,
	})
}

func TestNewPebble_AbsentKeyContract(t *testing.T) {
	storagetest.RunAbsentKeyContract(t, storagetest.Config{
		NewBackend: func(t *testing.T) storage.Backend {
			b, err := storage.NewPebble(t.TempDir())
			if err != nil {
				t.Fatalf("NewPebble: %v", err)
			}
			t.Cleanup(func() { _ = b.Close() })
			return b
		},
		AbsentDeleteDivergence: true,
	})
}
