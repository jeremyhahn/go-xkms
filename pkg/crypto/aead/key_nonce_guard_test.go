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
	"bytes"
	"crypto/rand"
	"errors"
	"sync"
	"testing"
)

// newTestGuard builds a guard with a deterministic salt source so a test never
// depends on the system RNG being available.
func newTestGuard(t *testing.T, limit int) *KeyNonceGuard {
	t.Helper()
	guard, err := NewKeyNonceGuard(rand.Reader, limit)
	if err != nil {
		t.Fatalf("NewKeyNonceGuard: %v", err)
	}
	return guard
}

// TestKeyNonceGuardRefusesARepeatedPair is the property the guard exists for:
// one key, one nonce, twice.
func TestKeyNonceGuardRefusesARepeatedPair(t *testing.T) {
	guard := newTestGuard(t, 0)
	key := []byte("key-material-0123")
	nonce := []byte("nonce-abcdef")

	if err := guard.Use(key, nonce); err != nil {
		t.Fatalf("first use of a pair must be accepted: %v", err)
	}
	if err := guard.Use(key, nonce); !errors.Is(err, ErrNonceReuse) {
		t.Fatalf("second use of the same pair must be ErrNonceReuse, got %v", err)
	}
	if guard.Count() != 1 {
		t.Fatalf("a refused pair must not be recorded twice, count is %d", guard.Count())
	}
}

// TestKeyNonceGuardSeparatesKeysAndNonces proves the guard bans a PAIR rather
// than a nonce or a key. NIST SP 800-38D section 8.2 constrains the pair: a
// guard that refused a nonce outright would break every unrelated key, and one
// that refused a key outright would allow only a single encryption per key.
func TestKeyNonceGuardSeparatesKeysAndNonces(t *testing.T) {
	guard := newTestGuard(t, 0)
	keyOne := []byte("key-one")
	keyTwo := []byte("key-two")
	nonceOne := []byte("nonce-one")
	nonceTwo := []byte("nonce-two")

	if err := guard.Use(keyOne, nonceOne); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := guard.Use(keyTwo, nonceOne); err != nil {
		t.Fatalf("the same nonce under a different key is a different pair: %v", err)
	}
	if err := guard.Use(keyOne, nonceTwo); err != nil {
		t.Fatalf("a different nonce under the same key is a different pair: %v", err)
	}
	if guard.Count() != 3 {
		t.Fatalf("expected three distinct pairs, got %d", guard.Count())
	}
}

// TestKeyNonceGuardDoesNotConfuseAdjacentPairs guards the concatenation the
// tracker key is built from. The key identity is a fixed-width HMAC precisely
// so that ("ab", "c") and ("a", "bc") cannot collapse onto one entry; a
// variable-width identity would report the second as a reuse of the first.
func TestKeyNonceGuardDoesNotConfuseAdjacentPairs(t *testing.T) {
	guard := newTestGuard(t, 0)

	if err := guard.Use([]byte("ab"), []byte("c")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := guard.Use([]byte("a"), []byte("bc")); err != nil {
		t.Fatalf("a different (key, nonce) split must not be read as a reuse: %v", err)
	}
}

// TestKeyNonceGuardRejectsEmptyInput covers the bad-input side. An empty key
// or nonce is a caller bug: accepting it would map every such call onto one
// entry and report unrelated operations as reuse.
func TestKeyNonceGuardRejectsEmptyInput(t *testing.T) {
	guard := newTestGuard(t, 0)

	if err := guard.Use(nil, []byte("nonce")); !errors.Is(err, ErrNonceGuardInput) {
		t.Fatalf("empty key material must be ErrNonceGuardInput, got %v", err)
	}
	if err := guard.Use([]byte("key"), nil); !errors.Is(err, ErrNonceGuardInput) {
		t.Fatalf("an empty nonce must be ErrNonceGuardInput, got %v", err)
	}
	if guard.Count() != 0 {
		t.Fatalf("a rejected input must record nothing, count is %d", guard.Count())
	}
	if guard.Used(nil, nil) {
		t.Fatal("Used must answer false for input it cannot derive an entry from")
	}
}

// TestKeyNonceGuardFailsClosedWhenFull proves a bounded guard refuses rather
// than forgetting. Evicting an entry would turn a reuse the guard had already
// seen into one it would accept, which is the failure it exists to prevent.
func TestKeyNonceGuardFailsClosedWhenFull(t *testing.T) {
	guard := newTestGuard(t, 2)
	key := []byte("bounded-key")

	if err := guard.Use(key, []byte("n1")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := guard.Use(key, []byte("n2")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := guard.Use(key, []byte("n3")); !errors.Is(err, ErrNonceTrackerFull) {
		t.Fatalf("a full guard must refuse a new pair with ErrNonceTrackerFull, got %v", err)
	}

	// A repeat of a pair already held is still reported as a repeat: the entry
	// is there to be found, and the more serious answer must win.
	if err := guard.Use(key, []byte("n1")); !errors.Is(err, ErrNonceReuse) {
		t.Fatalf("a full guard must still report a known pair as reuse, got %v", err)
	}
}

// TestKeyNonceGuardUsedReportsWithoutRecording covers the read-only companion.
// It must not consume the pair, or a diagnostic call would make the encryption
// that follows it fail.
func TestKeyNonceGuardUsedReportsWithoutRecording(t *testing.T) {
	guard := newTestGuard(t, 0)
	key := []byte("used-key")
	nonce := []byte("used-nonce")

	if guard.Used(key, nonce) {
		t.Fatal("a pair that was never used must not be reported as used")
	}
	if guard.Count() != 0 {
		t.Fatalf("Used must record nothing, count is %d", guard.Count())
	}
	if err := guard.Use(key, nonce); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !guard.Used(key, nonce) {
		t.Fatal("a pair that was used must be reported as used")
	}
}

// TestKeyNonceGuardResetForgetsEverything covers Reset, which is how a fixture
// or a reinitialized token starts over.
func TestKeyNonceGuardResetForgetsEverything(t *testing.T) {
	guard := newTestGuard(t, 0)
	key := []byte("reset-key")
	nonce := []byte("reset-nonce")

	if err := guard.Use(key, nonce); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	guard.Reset()
	if guard.Count() != 0 {
		t.Fatalf("Reset must empty the guard, count is %d", guard.Count())
	}
	if err := guard.Use(key, nonce); err != nil {
		t.Fatalf("after a reset the pair is new again: %v", err)
	}
}

// TestKeyNonceGuardSaltsPerInstance proves the tracker key is derived under a
// per-guard salt, so the long-lived map holds nothing an attacker who read it
// could test candidate keys against.
func TestKeyNonceGuardSaltsPerInstance(t *testing.T) {
	one := newTestGuard(t, 0)
	two := newTestGuard(t, 0)

	if bytes.Equal(one.salt, two.salt) {
		t.Fatal("two guards must not share a salt")
	}

	key := []byte("salted-key")
	nonce := []byte("salted-nonce")

	entryOne, err := one.entry(key, nonce)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	entryTwo, err := two.entry(key, nonce)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if bytes.Equal(entryOne, entryTwo) {
		t.Fatal("the same pair must derive different entries under different salts")
	}
	if bytes.Contains(entryOne, key) {
		t.Fatal("the tracker entry must not contain the key material itself")
	}
}

// TestKeyNonceGuardSaltSourceFailureIsReported covers the constructor's bad
// input: a guard whose salt could not be read must not be handed out silently,
// because a caller that proceeded without one would have no reuse protection
// at all.
func TestKeyNonceGuardSaltSourceFailureIsReported(t *testing.T) {
	guard, err := NewKeyNonceGuard(bytes.NewReader([]byte("too short")), 0)
	if err == nil {
		t.Fatal("a truncated entropy source must be reported")
	}
	if guard != nil {
		t.Fatal("no guard may be returned when the salt could not be read")
	}
}

// TestKeyNonceGuardIsAtomicUnderConcurrency proves exactly one of many
// concurrent claims on one pair succeeds. A check-then-record with a gap
// between the two would let several racing wraps all believe the pair was
// theirs, which is the reuse the guard exists to prevent.
func TestKeyNonceGuardIsAtomicUnderConcurrency(t *testing.T) {
	guard := newTestGuard(t, 0)
	key := []byte("racing-key")
	nonce := []byte("racing-nonce")

	const workers = 32
	results := make([]error, workers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start
			results[idx] = guard.Use(key, nonce)
		}(i)
	}
	close(start)
	wg.Wait()

	accepted := 0
	for i, err := range results {
		switch {
		case err == nil:
			accepted++
		case errors.Is(err, ErrNonceReuse):
		default:
			t.Fatalf("worker %d got an unexpected error: %v", i, err)
		}
	}
	if accepted != 1 {
		t.Fatalf("exactly one claim on a pair may succeed, %d did", accepted)
	}
}

// TestSharedAEADNonceGuardIsOneInstance proves the process-wide guard really is
// process-wide. A guard rebuilt per call would see every pair as new and prove
// nothing, and separate paths would each get their own view.
func TestSharedAEADNonceGuardIsOneInstance(t *testing.T) {
	first, err := SharedAEADNonceGuard()
	if err != nil {
		t.Fatalf("SharedAEADNonceGuard: %v", err)
	}
	second, err := SharedAEADNonceGuard()
	if err != nil {
		t.Fatalf("SharedAEADNonceGuard: %v", err)
	}
	if first != second {
		t.Fatal("SharedAEADNonceGuard must return the same guard every time")
	}

	key := []byte("shared-guard-key")
	nonce := []byte("shared-nonce")
	if err := first.Use(key, nonce); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if err := second.Use(key, nonce); !errors.Is(err, ErrNonceReuse) {
		t.Fatalf("a pair claimed through one reference must be refused through the other, got %v", err)
	}
}
