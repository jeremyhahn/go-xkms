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

package aead

import (
	"context"
	"encoding/hex"
	"errors"
	"sync"
	"testing"
)

// fakePersistentStore is a minimal, in-process PersistentNonceStore backed by
// a mutex-guarded map, standing in for pkg/aeadnonce.Store (which wraps a real
// storage.Backend) so this package's tests stay free of a storage dependency.
// Its ClaimNonce is genuinely atomic -- the one property UseContext requires
// of any implementation -- so a test built on it exercises the real race
// rather than assuming the fake serialises calls for it.
type fakePersistentStore struct {
	mu      sync.Mutex
	claimed map[string]bool
	err     error
}

func newFakePersistentStore() *fakePersistentStore {
	return &fakePersistentStore{claimed: make(map[string]bool)}
}

func (s *fakePersistentStore) ClaimNonce(_ context.Context, entry []byte) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return false, s.err
	}
	key := hex.EncodeToString(entry)
	if s.claimed[key] {
		return false, nil
	}
	s.claimed[key] = true
	return true, nil
}

// TestKeyNonceGuardUseContextWithoutStoreBehavesLikeUse proves UseContext is a
// strict superset of Use when no PersistentNonceStore is attached: the
// in-memory tracker alone decides the outcome.
func TestKeyNonceGuardUseContextWithoutStoreBehavesLikeUse(t *testing.T) {
	guard := newTestGuard(t, 0)
	key := []byte("no-store-key")
	nonce := []byte("no-store-nonce")
	ctx := context.Background()

	if err := guard.UseContext(ctx, key, nonce); err != nil {
		t.Fatalf("first claim with no store attached must be accepted: %v", err)
	}
	if err := guard.UseContext(ctx, key, nonce); !errors.Is(err, ErrNonceReuse) {
		t.Fatalf("a repeat must still be refused by the in-memory tracker, got %v", err)
	}
}

// TestKeyNonceGuardUseContextRefusesAStoreClaimedPair is the property
// go-xkms#1201 asked for at the level of one guard instance: a pair the
// attached store already holds is refused even though this guard's own
// in-memory tracker has never seen it.
func TestKeyNonceGuardUseContextRefusesAStoreClaimedPair(t *testing.T) {
	guard := newTestGuard(t, 0)
	store := newFakePersistentStore()
	guard.SetPersistentStore(store)

	key := []byte("store-key")
	nonce := []byte("store-nonce")
	ctx := context.Background()

	if err := guard.UseContext(ctx, key, nonce); err != nil {
		t.Fatalf("the first claim must be accepted: %v", err)
	}
	if err := guard.UseContext(ctx, key, nonce); !errors.Is(err, ErrNonceReuse) {
		t.Fatalf("a repeat claimed in the store must be refused, got %v", err)
	}
}

// TestKeyNonceGuardUseContextSurvivesARestart is the scenario the whole
// feature exists for: a fresh guard (an empty in-memory tracker, exactly what
// a process restart produces) attached to a store an EARLIER guard already
// claimed the pair in must still refuse it.
func TestKeyNonceGuardUseContextSurvivesARestart(t *testing.T) {
	store := newFakePersistentStore()
	ctx := context.Background()
	key := []byte("restart-key")
	nonce := []byte("restart-nonce")

	before := newTestGuard(t, 0)
	before.SetPersistentStore(store)
	if err := before.UseContext(ctx, key, nonce); err != nil {
		t.Fatalf("the pre-restart claim must be accepted: %v", err)
	}

	// A fresh KeyNonceGuard, exactly what SharedAEADNonceGuard's
	// sync.OnceValues would build again after a process restart: new salt,
	// empty tracker, no memory of the claim above.
	after := newTestGuard(t, 0)
	after.SetPersistentStore(store)
	if err := after.UseContext(ctx, key, nonce); !errors.Is(err, ErrNonceReuse) {
		t.Fatalf("a pair claimed before a restart must still be refused after one, got %v", err)
	}
}

// TestKeyNonceGuardUseContextIsAtomicAcrossTwoGuardsSharingOneStore is the
// concurrent form of the restart test: two guards -- standing in for two
// xkmsd nodes, or a node before and after a restart racing a slow client's
// retry -- claim one pair through one shared store at once. Exactly one may
// win, because the store's PutIfAbsent, not either guard's own lock, is the
// only thing both sides actually share.
func TestKeyNonceGuardUseContextIsAtomicAcrossTwoGuardsSharingOneStore(t *testing.T) {
	store := newFakePersistentStore()
	one := newTestGuard(t, 0)
	one.SetPersistentStore(store)
	two := newTestGuard(t, 0)
	two.SetPersistentStore(store)

	key := []byte("cross-guard-key")
	nonce := []byte("cross-guard-nonce")
	ctx := context.Background()

	const callersPerGuard = 16
	var succeeded, refused int
	var mu sync.Mutex
	var wg sync.WaitGroup
	start := make(chan struct{})

	claim := func(g *KeyNonceGuard) {
		defer wg.Done()
		<-start
		err := g.UseContext(ctx, key, nonce)
		mu.Lock()
		defer mu.Unlock()
		switch {
		case err == nil:
			succeeded++
		case errors.Is(err, ErrNonceReuse):
			refused++
		default:
			t.Errorf("unexpected error: %v", err)
		}
	}

	wg.Add(callersPerGuard * 2)
	for i := 0; i < callersPerGuard; i++ {
		go claim(one)
		go claim(two)
	}
	close(start)
	wg.Wait()

	if succeeded != 1 {
		t.Fatalf("exactly one claim across both guards may succeed, %d did", succeeded)
	}
	if refused != callersPerGuard*2-1 {
		t.Fatalf("every other claim must be refused as a reuse, got %d refusals", refused)
	}
}

// TestKeyNonceGuardSetPersistentStoreNilDetaches proves a guard can be
// returned to in-memory-only operation, the case pkg/server's shutdown path
// relies on to avoid leaving the shared guard pointed at a closed backend.
func TestKeyNonceGuardSetPersistentStoreNilDetaches(t *testing.T) {
	guard := newTestGuard(t, 0)
	store := newFakePersistentStore()
	guard.SetPersistentStore(store)

	key := []byte("detach-key")
	nonce := []byte("detach-nonce")
	ctx := context.Background()

	if err := guard.UseContext(ctx, key, nonce); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Detach the store and forget the in-memory record too, so the only
	// thing left to prove the store is no longer consulted is whether this
	// claim succeeds.
	guard.SetPersistentStore(nil)
	guard.Reset()

	if err := guard.UseContext(ctx, key, nonce); err != nil {
		t.Fatalf("a detached guard must not consult the store it no longer holds: %v", err)
	}
}

// TestKeyNonceGuardUseContextPropagatesAStoreError proves a store failure is
// reported as itself, not silently treated as either success or reuse: a
// caller that could not tell "refused" from "the store is unreachable" would
// have no way to decide whether retrying is safe.
func TestKeyNonceGuardUseContextPropagatesAStoreError(t *testing.T) {
	guard := newTestGuard(t, 0)
	store := newFakePersistentStore()
	store.err = errors.New("store unavailable")
	guard.SetPersistentStore(store)

	err := guard.UseContext(context.Background(), []byte("err-key"), []byte("err-nonce"))
	if err == nil {
		t.Fatal("a store failure must be reported")
	}
	if errors.Is(err, ErrNonceReuse) {
		t.Fatal("a store failure must not be reported as a reuse")
	}
}
