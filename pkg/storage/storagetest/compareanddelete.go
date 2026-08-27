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

// Package storagetest holds the executable contract for storage.Backend's
// guarded verbs, so every backend is held to one definition of the semantics
// instead of each package restating them in its own tests.
//
// It lives in a normal (non-_test) package because the backends it exercises
// are spread across pkg/storage, pkg/storage/file, pkg/storage/luks,
// pkg/storage/sealed, pkg/storage/qrdb, pkg/storage/hardware and
// pkg/storage/mocks; a helper in any one of them could not be imported by the
// rest. Tests in pkg/storage itself use it from the external storage_test
// package, which is what keeps the import from becoming a cycle.
package storagetest

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// Config describes one backend under contract test.
type Config struct {
	// NewBackend returns a fresh backend with no value stored at Key. It is
	// called once per subtest, so the subtests cannot contaminate each other.
	// Registering any cleanup (Close, temp dirs) is the factory's job.
	NewBackend func(t *testing.T) storage.Backend

	// Key is the key the contract exercises. Backends that constrain their key
	// space set it (pkg/storage/hardware accepts only certs/*.pem). Defaults to
	// "keys/contract-subject".
	Key string

	// ValueA and ValueB are two DISTINCT stored values. Backends that constrain
	// their value space set them (again, hardware: DER certificates). Both
	// default to short generic byte strings.
	ValueA, ValueB []byte

	// AllowsEmptyValue reports whether the backend can store a zero-length
	// value. When true the contract additionally pins that a nil expected
	// matches a stored empty value. Backends whose values are structured
	// (a certificate, a sealed envelope) leave it false.
	AllowsEmptyValue bool

	// Racers is the number of concurrent releasers the one-winner subtest
	// starts. Zero selects 16; a negative value skips the subtest, which is for
	// backends whose test double is not safe for concurrent use.
	Racers int
}

func (c Config) key() string {
	if c.Key == "" {
		return "keys/contract-subject"
	}
	return c.Key
}

func (c Config) valueA() []byte {
	if c.ValueA == nil {
		return []byte("value-A")
	}
	return c.ValueA
}

func (c Config) valueB() []byte {
	if c.ValueB == nil {
		return []byte("value-B")
	}
	return c.ValueB
}

// requireCapability asserts the backend under test actually claims the optional
// capability. The suite is the conformance body for CompareAndDeleter, so a
// fixture whose backend does not implement it is a mistake in the fixture, not
// a property of the backend -- and it must fail loudly rather than silently
// exercise nothing.
func requireCapability(t *testing.T, b storage.Backend) storage.CompareAndDeleter {
	t.Helper()
	cad, ok := b.(storage.CompareAndDeleter)
	if !ok {
		t.Fatalf("storagetest: %T does not implement storage.CompareAndDeleter; "+
			"run this suite only against backends that claim the capability", b)
	}
	return cad
}

// present reports whether key currently holds a value, tolerating the two ways
// a backend may signal absence (Exists=false, or Get returning ErrNotFound).
func present(ctx context.Context, t *testing.T, b storage.Backend, key string) bool {
	t.Helper()
	ok, err := b.Exists(ctx, key)
	if err != nil {
		t.Fatalf("Exists(%q): %v", key, err)
	}
	return ok
}

// RunCompareAndDeleteContract executes the storage.Backend.CompareAndDelete
// contract against one backend. Run it under -race: the final subtest is a
// concurrency property and is only meaningful with the detector on.
func RunCompareAndDeleteContract(t *testing.T, cfg Config) {
	t.Helper()
	if cfg.NewBackend == nil {
		t.Fatal("storagetest: Config.NewBackend must not be nil")
	}

	key := cfg.key()
	valueA := cfg.valueA()
	valueB := cfg.valueB()
	if bytes.Equal(valueA, valueB) {
		t.Fatal("storagetest: Config.ValueA and Config.ValueB must differ")
	}

	// An absent key is a refusal, NOT an error. A replicated backend that
	// errored here would stall consensus over a deterministic consequence of
	// valid input, and Delete's ErrNotFound must not leak into this verb.
	t.Run("absent key refuses without an error", func(t *testing.T) {
		ctx := context.Background()
		b := cfg.NewBackend(t)
		g := requireCapability(t, b)

		deleted, err := g.CompareAndDelete(ctx, key, valueA)
		if err != nil {
			t.Fatalf("absent key must not be an error, got %v", err)
		}
		if deleted {
			t.Fatal("absent key must report deleted=false")
		}
		if errors.Is(err, storage.ErrNotFound) {
			t.Fatal("absent key must not surface ErrNotFound; that is Delete's contract, not this one")
		}
	})

	t.Run("mismatched guard refuses and leaves the value intact", func(t *testing.T) {
		ctx := context.Background()
		b := cfg.NewBackend(t)
		g := requireCapability(t, b)
		if err := b.Put(ctx, key, valueA); err != nil {
			t.Fatalf("Put: %v", err)
		}

		deleted, err := g.CompareAndDelete(ctx, key, valueB)
		if err != nil {
			t.Fatalf("mismatched guard must not be an error, got %v", err)
		}
		if deleted {
			t.Fatal("mismatched guard must report deleted=false")
		}
		if !present(ctx, t, b, key) {
			t.Fatal("a refused delete must leave the store unchanged")
		}
		got, err := b.Get(ctx, key)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if !bytes.Equal(got, valueA) {
			t.Fatalf("a refused delete must not alter the value, got %q want %q", got, valueA)
		}
	})

	t.Run("matching guard deletes", func(t *testing.T) {
		ctx := context.Background()
		b := cfg.NewBackend(t)
		g := requireCapability(t, b)
		if err := b.Put(ctx, key, valueA); err != nil {
			t.Fatalf("Put: %v", err)
		}

		deleted, err := g.CompareAndDelete(ctx, key, valueA)
		if err != nil {
			t.Fatalf("matching guard: %v", err)
		}
		if !deleted {
			t.Fatal("matching guard must report deleted=true")
		}
		if present(ctx, t, b, key) {
			t.Fatal("key must be gone after a successful CompareAndDelete")
		}
	})

	// nil is not a wildcard. A backend that treated it as "delete whatever is
	// there" would turn every guarded release into an unguarded one, silently.
	t.Run("nil guard does not match a non-empty value", func(t *testing.T) {
		ctx := context.Background()
		b := cfg.NewBackend(t)
		g := requireCapability(t, b)
		if err := b.Put(ctx, key, valueA); err != nil {
			t.Fatalf("Put: %v", err)
		}

		deleted, err := g.CompareAndDelete(ctx, key, nil)
		if err != nil {
			t.Fatalf("nil guard must not be an error, got %v", err)
		}
		if deleted {
			t.Fatal("a nil expected must NOT act as a wildcard")
		}
		if !present(ctx, t, b, key) {
			t.Fatal("a refused delete must leave the store unchanged")
		}
	})

	if cfg.AllowsEmptyValue {
		t.Run("nil guard matches a stored empty value", func(t *testing.T) {
			ctx := context.Background()
			b := cfg.NewBackend(t)
			g := requireCapability(t, b)
			if err := b.Put(ctx, key, []byte{}); err != nil {
				t.Fatalf("Put: %v", err)
			}

			deleted, err := g.CompareAndDelete(ctx, key, nil)
			if err != nil {
				t.Fatalf("nil guard against an empty value: %v", err)
			}
			if !deleted {
				t.Fatal("a nil expected is equivalent to an empty slice and must match a stored empty value")
			}
		})
	}

	// This is the defect the verb exists to close (go-qrdb#41). A stale releaser
	// that read holder A, and never observed B at all, must not be able to
	// remove B's claim after B legitimately acquired the key.
	t.Run("stale releaser cannot remove the next holder", func(t *testing.T) {
		ctx := context.Background()
		b := cfg.NewBackend(t)
		g := requireCapability(t, b)
		if err := b.Put(ctx, key, valueA); err != nil {
			t.Fatalf("Put: %v", err)
		}

		// Two releasers both observe holder A.
		observedByReleaser1 := append([]byte(nil), valueA...)
		observedByReleaser2 := append([]byte(nil), valueA...)

		if deleted, err := g.CompareAndDelete(ctx, key, observedByReleaser1); err != nil || !deleted {
			t.Fatalf("releaser 1 should release A: deleted=%v err=%v", deleted, err)
		}

		// B claims the now-absent key.
		if err := b.Put(ctx, key, valueB); err != nil {
			t.Fatalf("Put B: %v", err)
		}

		// Releaser 2 now runs, still holding its stale view of A. With a plain
		// Delete this removes B's value. Guarded, it must refuse.
		deleted, err := g.CompareAndDelete(ctx, key, observedByReleaser2)
		if err != nil {
			t.Fatalf("stale releaser: %v", err)
		}
		if deleted {
			t.Fatal("a stale releaser must NOT remove the next holder's value")
		}
		got, err := b.Get(ctx, key)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if !bytes.Equal(got, valueB) {
			t.Fatalf("B's claim must survive the stale release, got %q want %q", got, valueB)
		}
	})

	if cfg.Racers >= 0 {
		racers := cfg.Racers
		if racers == 0 {
			racers = 16
		}
		// The guarantee is only as good as its serialization: concurrent
		// releasers all holding the same observed value must produce exactly one
		// winner, the same property PutIfAbsent has on the acquire side.
		t.Run("concurrent releasers admit exactly one winner", func(t *testing.T) {
			ctx := context.Background()
			b := cfg.NewBackend(t)
			g := requireCapability(t, b)
			if err := b.Put(ctx, key, valueA); err != nil {
				t.Fatalf("Put: %v", err)
			}

			var wg sync.WaitGroup
			results := make([]bool, racers)
			errs := make([]error, racers)
			start := make(chan struct{})
			for i := range racers {
				wg.Add(1)
				go func(i int) {
					defer wg.Done()
					<-start
					results[i], errs[i] = g.CompareAndDelete(ctx, key, valueA)
				}(i)
			}
			close(start)
			wg.Wait()

			winners := 0
			for i := range racers {
				if errs[i] != nil {
					t.Errorf("releaser %d: %v", i, errs[i])
				}
				if results[i] {
					winners++
				}
			}
			if t.Failed() {
				return
			}
			if winners != 1 {
				t.Fatalf("expected exactly one releaser to win, got %d", winners)
			}
			if present(ctx, t, b, key) {
				t.Fatal("key must be gone after the winning release")
			}
		})
	}
}
