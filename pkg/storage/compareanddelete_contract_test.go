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
	"bytes"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/storagetest"
)

// The contract body lives in storagetest so every backend is held to one
// definition. This file only supplies the fixtures for the two backends that
// live in pkg/storage itself; the other backends run the same body from their
// own packages.

func TestEngineBackend_CompareAndDeleteContract(t *testing.T) {
	storagetest.RunCompareAndDeleteContract(t, storagetest.Config{
		NewBackend: func(t *testing.T) storage.Backend {
			b := storage.NewMemory()
			t.Cleanup(func() { _ = b.Close() })
			return b
		},
		AllowsEmptyValue: true,
	})
}

func TestPrefixBackend_CompareAndDeleteContract(t *testing.T) {
	storagetest.RunCompareAndDeleteContract(t, storagetest.Config{
		NewBackend: func(t *testing.T) storage.Backend {
			inner := storage.NewMemory()
			t.Cleanup(func() { _ = inner.Close() })
			p, err := storage.NewPrefixBackend(inner, "tenant-a/")
			if err != nil {
				t.Fatalf("NewPrefixBackend: %v", err)
			}
			return p
		},
		AllowsEmptyValue: true,
	})
}

// The prefix must actually be applied: a guarded delete through the wrapper has
// to act on the namespaced key, not the bare one. A wrapper that dropped the
// prefix would still pass the shared contract, because every operation in it
// goes through the same wrapper.
func TestPrefixBackend_CompareAndDeleteNamespacesTheKey(t *testing.T) {
	ctx := t.Context()
	inner := storage.NewMemory()
	t.Cleanup(func() { _ = inner.Close() })

	p, err := storage.NewPrefixBackend(inner, "tenant-a/")
	if err != nil {
		t.Fatalf("NewPrefixBackend: %v", err)
	}
	if err := p.Put(ctx, "secret", []byte("A")); err != nil {
		t.Fatalf("Put: %v", err)
	}

	// The unprefixed key is a different key and must be untouched by the guard.
	if err := inner.Put(ctx, "secret", []byte("A")); err != nil {
		t.Fatalf("inner Put: %v", err)
	}

	deleted, err := p.CompareAndDelete(ctx, "secret", []byte("A"))
	if err != nil || !deleted {
		t.Fatalf("CompareAndDelete: deleted=%v err=%v", deleted, err)
	}
	if ok, _ := inner.Exists(ctx, "tenant-a/secret"); ok {
		t.Fatal("the namespaced key should have been deleted")
	}
	if ok, _ := inner.Exists(ctx, "secret"); !ok {
		t.Fatal("the unprefixed key must not be touched")
	}
}

// A guarded delete must be serialized against the UNCONDITIONAL writers too,
// not merely against other guarded verbs. This is the property that makes the
// guard real, and it is stated as an invariant over serial orders rather than
// as a timing assertion.
//
// One racer runs CompareAndDelete(A) while another runs Put(B). There are only
// two valid serializations, and BOTH end with the key holding B:
//
//   - the release goes first: it observes A, deletes, and then Put stores B;
//   - the put goes first: the release then observes B, does not match A, and
//     refuses, leaving B.
//
// The outcome the invariant excludes is the interleaving where the release
// reads A, the Put stores B, and the release then deletes B — removing a value
// it never observed. That leaves the key ABSENT, which no serial order can
// produce, so an absent key at the end is proof the guard was defeated. It is
// exactly the race the verb exists to close, and a mutex covering only the
// guarded verbs would not close it.
func TestEngineBackend_CompareAndDeleteIsSerializedAgainstPlainPut(t *testing.T) {
	const key = "keys/race-subject"
	valueA := []byte("value-A")
	valueB := []byte("value-B")

	// Many short iterations: the window between the guard's read and its delete
	// is narrow, so one pass would rarely land inside it.
	for i := range 2000 {
		b := storage.NewMemory()

		if err := b.Put(t.Context(), key, valueA); err != nil {
			t.Fatalf("seed Put: %v", err)
		}

		// Hoisted before the goroutines: the assertion reports through t, and
		// t.Fatalf from a non-test goroutine does not stop the test.
		cad, ok := b.(storage.CompareAndDeleter)
		if !ok {
			t.Fatalf("memory backend must implement storage.CompareAndDeleter, got %T", b)
		}

		var wg sync.WaitGroup
		wg.Add(2)
		start := make(chan struct{})
		var cadErr, putErr error
		go func() {
			defer wg.Done()
			<-start
			_, cadErr = cad.CompareAndDelete(t.Context(), key, valueA)
		}()
		go func() {
			defer wg.Done()
			<-start
			putErr = b.Put(t.Context(), key, valueB)
		}()
		close(start)
		wg.Wait()

		if cadErr != nil {
			t.Fatalf("iteration %d: CompareAndDelete: %v", i, cadErr)
		}
		if putErr != nil {
			t.Fatalf("iteration %d: Put: %v", i, putErr)
		}

		got, err := b.Get(t.Context(), key)
		if err != nil {
			t.Fatalf("iteration %d: the key must still hold %q, but it is gone: %v "+
				"(the guarded delete removed a value it never observed)", i, valueB, err)
		}
		if !bytes.Equal(got, valueB) {
			t.Fatalf("iteration %d: key = %q, want %q", i, got, valueB)
		}
		_ = b.Close()
	}
}
