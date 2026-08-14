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
	"fmt"
	"path/filepath"
	"testing"
)

// TestClose_FlushesPendingWrites is the data-loss regression test.
//
// FastBackend applies each Put on a detached goroutine, and the only join point
// is FastStateMachine.Close. The SDK client's Close reaches the embedded
// transport, whose Close merely flips a closed flag, so before newEmbedded
// drained the state machine explicitly a write issued just before shutdown
// could land after Close returned — or never, with the failure reported only by
// a log line from a goroutine nobody waits on.
//
// Writing and closing immediately, then reopening the same directory, is what
// exercises it: the reopened backend reads the storage engine from disk, so a
// value that never made it out of the pending queue is simply absent.
func TestClose_FlushesPendingWrites(t *testing.T) {
	for _, engine := range []struct {
		name string
		open func(string) (*Backend, error)
	}{
		{"file", NewFile},
		{"pebble", NewPebble},
	} {
		t.Run(engine.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "store")
			ctx := context.Background()

			// Enough keys that at least one is still in flight when Close is
			// called; a single key can win the race on its own.
			const keys = 64

			backend, err := engine.open(dir)
			if err != nil {
				t.Fatalf("open: %v", err)
			}
			for i := 0; i < keys; i++ {
				k := fmt.Sprintf("durability/key-%02d", i)
				if perr := backend.Put(ctx, k, []byte(k)); perr != nil {
					t.Fatalf("Put %s: %v", k, perr)
				}
			}
			// No sleep, no sync: Close alone must be sufficient.
			if cerr := backend.Close(); cerr != nil {
				t.Fatalf("Close: %v", cerr)
			}

			reopened, err := engine.open(dir)
			if err != nil {
				t.Fatalf("reopen: %v", err)
			}
			t.Cleanup(func() { _ = reopened.Close() })

			for i := 0; i < keys; i++ {
				k := fmt.Sprintf("durability/key-%02d", i)
				got, gerr := reopened.Get(ctx, k)
				if gerr != nil {
					t.Fatalf("%s lost across Close: %v", k, gerr)
				}
				if string(got) != k {
					t.Errorf("%s = %q, want %q", k, got, k)
				}
			}
		})
	}
}

// TestClose_IsIdempotent verifies a second Close does not panic or wedge on the
// state-machine drain, since Close is routinely called from a defer as well as
// an explicit shutdown path.
func TestClose_IsIdempotent(t *testing.T) {
	backend, err := NewMemory()
	if err != nil {
		t.Fatalf("NewMemory: %v", err)
	}
	if cerr := backend.Close(); cerr != nil {
		t.Fatalf("first Close: %v", cerr)
	}
	// The second call must return rather than block on wg.Wait.
	done := make(chan error, 1)
	go func() { done <- backend.Close() }()
	select {
	case <-done:
	case <-context.Background().Done():
	}
}
