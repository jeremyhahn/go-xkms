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

package storagetest

import (
	"bytes"
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// RunAbsentKeyContract executes the storage.Backend contract for a key that was
// never written, against one backend.
//
// The contract is not invented here. storage.Backend documents it on the
// methods themselves: Get "returns ErrNotFound if the key does not exist",
// Delete likewise, Exists "checks if a key exists". Four implementations
// disagreed about all three, which is go-xkms#252. Exists and Get are FIXED
// upstream as of go-qrdb v0.16.3-alpha and are now asserted unconditionally
// (go-xkms#406); Delete is the remainder, and the only verb a fixture can
// still declare divergent.
//
// # This is a characterization suite, and the distinction matters
//
// A conformance suite that simply pinned today's behaviour would encode the
// DEFECT as the contract: "Exists returns true for a key that was never
// written" would become the blessed answer, and fixing the engines would then
// look like a regression. So the assertions below state the CORRECT semantics,
// and a backend that does not satisfy them yet declares that with an explicit
// Config flag naming the issue.
//
// The flagged branches assert the WRONG answer on purpose and fail the moment
// it becomes right. That is deliberate: the day the engines are fixed, these
// tests fail with a message telling the reader to delete the flag, so the
// characterization cannot outlive the defect it describes. It is the same
// design as pkg/storage/qrdb/factory_cas_characterization_test.go, which fails
// when the transaction service is finally wired.
//
// Run it against every implementation, including the ones that conform: the
// suite is what stops a conforming backend from quietly regressing into the
// divergent behaviour.
func RunAbsentKeyContract(t *testing.T, cfg Config) {
	t.Helper()
	if cfg.NewBackend == nil {
		t.Fatal("storagetest: Config.NewBackend must not be nil")
	}

	// A key this suite never writes. Deliberately distinct from Config.Key, so
	// that a fixture reusing a backend across subtests cannot make an absent
	// key look present.
	key := cfg.key() + "-never-written"

	t.Run("Exists reports false", func(t *testing.T) {
		ctx := context.Background()
		b := cfg.NewBackend(t)

		exists, err := b.Exists(ctx, key)
		if err != nil {
			t.Fatalf("Exists(%q) on an absent key must not error, got %v", key, err)
		}

		if exists {
			t.Fatalf("Exists(%q) reports true for a key that was never written", key)
		}
	})

	t.Run("Get returns ErrNotFound", func(t *testing.T) {
		ctx := context.Background()
		b := cfg.NewBackend(t)

		value, err := b.Get(ctx, key)

		if !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("Get(%q) error = %v, want storage.ErrNotFound", key, err)
		}
		if len(value) != 0 {
			t.Fatalf("Get(%q) returned %d bytes alongside its error", key, len(value))
		}
	})

	t.Run("Delete returns ErrNotFound", func(t *testing.T) {
		ctx := context.Background()
		b := cfg.NewBackend(t)

		err := b.Delete(ctx, key)

		if cfg.AbsentDeleteDivergence {
			if errors.Is(err, storage.ErrNotFound) {
				t.Fatalf("Delete(%q) now correctly returns ErrNotFound. The engine is "+
					"fixed: remove Config.AbsentDeleteDivergence from this fixture and "+
					"delete this branch (go-xkms#252)", key)
			}
			if err != nil {
				t.Fatalf("Delete(%q) returned an unexpected error %v; the divergence being "+
					"characterized is a NIL error", key, err)
			}
			t.Logf("KNOWN DIVERGENCE (go-xkms#252): Delete reports success for a key that " +
				"was never written. Correct answer: storage.ErrNotFound. A caller cannot " +
				"tell a delete that removed something from one that removed nothing.")
			return
		}

		if !errors.Is(err, storage.ErrNotFound) {
			t.Fatalf("Delete(%q) error = %v, want storage.ErrNotFound", key, err)
		}
	})

	// PutIfAbsent's divergence has a DIFFERENT cause from the three above and a
	// different fix, so it carries its own flag: the embedded QRDB transport is
	// built with no transaction service, so the request never reaches an engine
	// (go-xkms#61). storage.Backend explicitly permits reporting the operation
	// as unavailable, which is why an error here is a declared state rather than
	// a contract violation.
	t.Run("PutIfAbsent stores and reports true", func(t *testing.T) {
		ctx := context.Background()
		b := cfg.NewBackend(t)

		stored, err := b.PutIfAbsent(ctx, key, cfg.valueA())

		if cfg.PutIfAbsentUnavailable {
			if err == nil {
				t.Fatalf("PutIfAbsent(%q) now succeeds. The transaction service is wired: "+
					"remove Config.PutIfAbsentUnavailable from this fixture, delete this "+
					"branch, and re-derive the notes on pkg/storage/constructors.go from "+
					"measurement (go-xkms#61)", key)
			}
			if stored {
				t.Fatalf("PutIfAbsent(%q) reported stored=true alongside an error %v", key, err)
			}
			t.Logf("KNOWN DIVERGENCE (go-xkms#61): PutIfAbsent is unavailable on this "+
				"backend -- %v. storage.Backend permits this, but a caller must handle the "+
				"error and must NOT read it as 'the key was present', which is what "+
				"stored=false means and an error does not.", err)
			return
		}

		if err != nil {
			t.Fatalf("PutIfAbsent(%q) on an absent key must succeed, got %v", key, err)
		}
		if !stored {
			t.Fatalf("PutIfAbsent(%q) reported stored=false for a key that was never written", key)
		}

		// And it must actually be there afterwards, or "stored" meant nothing.
		got, err := b.Get(ctx, key)
		if err != nil {
			t.Fatalf("Get after a successful PutIfAbsent: %v", err)
		}
		if !bytes.Equal(got, cfg.valueA()) {
			t.Fatalf("PutIfAbsent stored %q, want %q", got, cfg.valueA())
		}
	})
}
