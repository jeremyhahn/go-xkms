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

package qrdb

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-qrdb/sdk/go/transport/embedded"
)

// The compare-and-swap notes on the constructors are a claim about behaviour,
// so they are pinned by exercising THE CONSTRUCTORS -- not by reasoning about
// which engine qrdb would select on some other path. An earlier version of
// that documentation described the KVEngine/MVCCEngine split from
// pkg/server/lifecycle.NewLocalEngine, which newEmbedded does not use; these
// tests exist so the next such claim has to survive contact with the code.
//
// They are characterization tests: they record what happens TODAY, including
// the parts that are defects. When #61 lands they are expected to fail, and
// the failure is the point -- it forces the documentation to be re-derived
// from measurement rather than left to drift.
func eachEmbeddedConstructor(t *testing.T, fn func(t *testing.T, name string, b *Backend)) {
	t.Helper()

	constructors := []struct {
		name string
		open func(t *testing.T) (*Backend, error)
	}{
		{"memory", func(*testing.T) (*Backend, error) { return NewMemory() }},
		{"file", func(t *testing.T) (*Backend, error) { return NewFile(t.TempDir()) }},
		{"pebble", func(t *testing.T) (*Backend, error) { return NewPebble(t.TempDir()) }},
	}

	for _, c := range constructors {
		t.Run(c.name, func(t *testing.T) {
			b, err := c.open(t)
			if err != nil {
				t.Fatalf("%s: %v", c.name, err)
			}
			t.Cleanup(func() {
				if err := b.Close(); err != nil {
					t.Errorf("close: %v", err)
				}
			})
			fn(t, c.name, b)
		})
	}
}

// Every embedded constructor refuses PutIfAbsent and CompareAndSwap the same
// way, and the reason is the same for all three: newEmbedded builds its
// transport with embedded.New(kvSvc, adminSvc) and no transaction service.
//
// The uniformity is the finding. There is no memory-vs-file asymmetry to
// document here, because the request never reaches an engine.
func TestEmbeddedConstructors_CASUnavailableWithoutTransactionService(t *testing.T) {
	eachEmbeddedConstructor(t, func(t *testing.T, name string, b *Backend) {
		ctx := context.Background()
		key := "cas-characterization"

		if _, err := b.PutIfAbsent(ctx, key, []byte("v1")); err == nil {
			t.Fatal("PutIfAbsent succeeded: the transaction service is now wired, " +
				"so the CAS notes on these constructors must be re-derived by " +
				"measurement (see #61)")
		} else {
			requireMissingTransactionService(t, "PutIfAbsent", err)
		}

		if _, _, err := b.CompareAndSwap(ctx, key, []byte("v1"), []byte("v2")); err == nil {
			t.Fatal("CompareAndSwap succeeded: see #61, the notes need re-deriving")
		} else {
			requireMissingTransactionService(t, "CompareAndSwap", err)
		}
	})
}

// Plain Put/Get must be unaffected, which is what makes the CAS gap a trap
// rather than an obvious outage: a caller sees a working store and only
// discovers the missing operations on the path that needs them.
func TestEmbeddedConstructors_PlainPutGetUnaffected(t *testing.T) {
	eachEmbeddedConstructor(t, func(t *testing.T, name string, b *Backend) {
		ctx := context.Background()
		key, want := "plain-roundtrip", []byte("value")

		if err := b.Put(ctx, key, want); err != nil {
			t.Fatalf("Put: %v", err)
		}
		got, err := b.Get(ctx, key)
		if err != nil {
			t.Fatalf("Get: %v", err)
		}
		if string(got) != string(want) {
			t.Fatalf("Get = %q, want %q", got, want)
		}
	})
}

// requireMissingTransactionService identifies the cause structurally rather
// than by matching the rendered message.
//
// These assertions read go-qrdb's typed error and its Service FIELD, not
// strings.Contains on the text. A reworded diagnostic upstream would otherwise
// fail these tests while the behaviour they characterize was unchanged, which
// turns a dependency bump into a false alarm -- and, worse, would be "fixed"
// by loosening the assertion.
func requireMissingTransactionService(t *testing.T, op string, err error) {
	t.Helper()

	// The local wrapper first: crossing this package's boundary must produce a
	// *BackendError naming the operation, whatever the cause underneath.
	var backendErr *BackendError
	if !errors.As(err, &backendErr) {
		t.Fatalf("%s error type = %T, want *BackendError: %v", op, err, err)
	}

	var nilSvc *embedded.NilServiceError
	if !errors.As(err, &nilSvc) {
		t.Fatalf("%s failed for an unexpected reason: %v", op, err)
	}
	if nilSvc.Service != "TransactionServicer" {
		t.Fatalf("%s reports a missing %q; the CAS gap is the transaction service",
			op, nilSvc.Service)
	}
}
