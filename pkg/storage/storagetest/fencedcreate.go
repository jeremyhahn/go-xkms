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

package storagetest

import (
	"bytes"
	"context"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// fenceKey is the fence the contract exercises: a sibling of the key, as a
// tenant's tombstone is a sibling of its metadata record.
func (c Config) fenceKey() string {
	return c.key() + ".fence"
}

// RunFencedCreateContract executes the storage.FencedCreator contract against
// one backend. Run it under -race: the final subtest is a concurrency property.
func RunFencedCreateContract(t *testing.T, cfg Config) {
	t.Helper()
	ctx := context.Background()
	key, fence := cfg.key(), cfg.fenceKey()

	newFenced := func(t *testing.T) (storage.Backend, storage.FencedCreator) {
		t.Helper()
		b := cfg.NewBackend(t)
		fc, ok := b.(storage.FencedCreator)
		if !ok {
			t.Fatalf("storagetest: %T does not implement storage.FencedCreator; "+
				"run this suite only against backends that claim the capability", b)
		}
		return b, fc
	}

	t.Run("creates when the key and every fence are absent", func(t *testing.T) {
		b, fc := newFenced(t)
		created, err := fc.PutIfAllAbsent(ctx, key, cfg.valueA(), fence)
		if err != nil || !created {
			t.Fatalf("PutIfAllAbsent = (%v, %v), want (true, nil)", created, err)
		}
		got, err := b.Get(ctx, key)
		if err != nil || !bytes.Equal(got, cfg.valueA()) {
			t.Fatalf("Get after create = (%q, %v), want %q", got, err, cfg.valueA())
		}
		if present(ctx, t, b, fence) {
			t.Fatal("the fence was written; only the key may be")
		}
	})

	t.Run("refuses when the key is present", func(t *testing.T) {
		b, fc := newFenced(t)
		if err := b.Put(ctx, key, cfg.valueA()); err != nil {
			t.Fatalf("Put: %v", err)
		}
		created, err := fc.PutIfAllAbsent(ctx, key, cfg.valueB(), fence)
		if err != nil || created {
			t.Fatalf("PutIfAllAbsent = (%v, %v), want (false, nil)", created, err)
		}
		got, err := b.Get(ctx, key)
		if err != nil || !bytes.Equal(got, cfg.valueA()) {
			t.Fatalf("the refused create changed the key: (%q, %v)", got, err)
		}
	})

	t.Run("refuses when a fence is present, leaving the key absent", func(t *testing.T) {
		b, fc := newFenced(t)
		if err := b.Put(ctx, fence, cfg.valueB()); err != nil {
			t.Fatalf("Put fence: %v", err)
		}
		created, err := fc.PutIfAllAbsent(ctx, key, cfg.valueA(), fence)
		if err != nil || created {
			t.Fatalf("PutIfAllAbsent = (%v, %v), want (false, nil)", created, err)
		}
		if present(ctx, t, b, key) {
			t.Fatal("the key was written past a present fence")
		}
	})

	t.Run("no fences behaves as put-if-absent", func(t *testing.T) {
		_, fc := newFenced(t)
		if created, err := fc.PutIfAllAbsent(ctx, key, cfg.valueA()); err != nil || !created {
			t.Fatalf("first PutIfAllAbsent = (%v, %v), want (true, nil)", created, err)
		}
		if created, err := fc.PutIfAllAbsent(ctx, key, cfg.valueB()); err != nil || created {
			t.Fatalf("second PutIfAllAbsent = (%v, %v), want (false, nil)", created, err)
		}
	})

	racers := cfg.Racers
	if racers == 0 {
		racers = 16
	}
	if racers < 0 {
		return
	}
	t.Run("exactly one of concurrent creators wins", func(t *testing.T) {
		_, fc := newFenced(t)
		var (
			wg   sync.WaitGroup
			mu   sync.Mutex
			wins int
		)
		start := make(chan struct{})
		for range racers {
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				created, err := fc.PutIfAllAbsent(ctx, key, cfg.valueA(), fence)
				if err != nil {
					t.Errorf("PutIfAllAbsent: %v", err)
					return
				}
				if created {
					mu.Lock()
					wins++
					mu.Unlock()
				}
			}()
		}
		close(start)
		wg.Wait()
		if wins != 1 {
			t.Fatalf("%d creators won, want exactly 1", wins)
		}
	})
}
