// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package phone

import (
	"bytes"
	"runtime"
	"testing"
	"time"

	"github.com/flynn/noise"

	"github.com/jeremyhahn/go-xkms/sdk/go/bootstrap"
)

// TestRetainedPagesSurviveLosingEveryGoReference settles, by execution, a
// claim that four separate review findings rested on: that a shutdown which
// "retains" a protected key by dropping its *StaticKey lets the pages be
// finalized and reclaimed while a live goroutine still reads them through an
// aliased DHKey.
//
// The claim is plausible and wrong. go-enclave maps its pages outside the Go
// heap, so a slice into them genuinely does NOT keep the owning object alive —
// that half is right. What it misses is that go-enclave records every enclave
// it constructs in a package-level ledger (registry.go: `live`, a map from
// *MemoryEnclave, added on construction and removed on release) which holds a
// strong reference for the enclave's whole life. That ledger is how WipeAll
// finds every enclave to wipe. go-enclave registers no finalizer or cleanup
// outside its own tests. So an unreferenced StaticKey's scalar is not
// collectable, nothing runs to release it, and the only releases are an
// explicit Destroy or a process-wide WipeAll.
//
// This test exists rather than a rebuttal in prose because the assumption is
// upstream and invisible from here: if go-enclave ever adds a finalizer, or
// stops registering enclaves, the retention paths in this package silently
// become the use-after-free they were written to avoid — and this fails
// instead.
func TestRetainedPagesSurviveLosingEveryGoReference(t *testing.T) {
	if !noiseOutsideFIPS(t) {
		return
	}
	key, err := bootstrap.GenerateNoiseStaticKey()
	if err != nil {
		t.Fatalf("GenerateStaticKey: %v", err)
	}

	// What a live session holds: flynn/noise keeps the DHKey it was handed,
	// whose Private slice aliases the protected pages past the borrow that
	// lent it. This is the reader a retention path is protecting.
	var alias []byte
	var want []byte
	if err := key.WithDHKey(func(dh noise.DHKey) error {
		alias = dh.Private
		want = bytes.Clone(dh.Private)
		return nil
	}); err != nil {
		t.Fatalf("WithDHKey: %v", err)
	}
	if len(want) == 0 {
		t.Fatal("generated key has no private scalar")
	}

	// Drop every reference a retention path might have dropped. From here the
	// alias is the only thing pointing anywhere near the key, and it points at
	// memory the Go collector does not manage.
	key = nil
	_ = key

	// Give the collector, and any finalizer that might exist, a real chance:
	// finalizers run asynchronously on a goroutine after the collection that
	// queues them, so one GC is not enough to conclude anything.
	for i := 0; i < 3; i++ {
		runtime.GC()
		time.Sleep(10 * time.Millisecond)
	}

	if !bytes.Equal(alias, want) {
		t.Fatal("the protected pages were wiped after the owning StaticKey " +
			"became unreachable; go-enclave's ledger or finalizer " +
			"behaviour has changed and every retention path in this package " +
			"is now a use-after-free")
	}
}
