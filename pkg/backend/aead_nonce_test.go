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

package backend

import (
	"context"
	"crypto/rand"
	"errors"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/aead"
)

// randomBytes returns n random bytes, for material and nonces a test needs
// to be unique from every other test's -- including one racing it through
// the process-wide shared guard.
func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		t.Fatalf("failed to read random bytes: %v", err)
	}
	return b
}

// TestClaimAEADNonceInRefusesAReusedMaterialNonce is the core property: the
// same key material and the same nonce, claimed twice, is refused the second
// time -- this is what closes go-xkms#1201's TOCTOU race, since the check
// and the record are now one atomic step in aead.KeyNonceGuard rather than
// two separate tracker calls.
func TestClaimAEADNonceInRefusesAReusedMaterialNonce(t *testing.T) {
	guard, err := aead.NewKeyNonceGuard(rand.Reader, 0)
	if err != nil {
		t.Fatalf("NewKeyNonceGuard: %v", err)
	}
	key := randomBytes(t, 32)
	nonce := randomBytes(t, 12)
	ctx := context.Background()

	if err := ClaimAEADNonceIn(ctx, guard, key, nil, "", nonce); err != nil {
		t.Fatalf("first claim of a fresh pair must succeed: %v", err)
	}
	err = ClaimAEADNonceIn(ctx, guard, key, nil, "", nonce)
	if !errors.Is(err, aead.ErrNonceReuse) {
		t.Fatalf("second claim of the same pair must be refused as reuse, got %v", err)
	}
}

// TestClaimAEADNonceInSealedIdentityIsDistinctFromMaterial proves a sealed
// key's identity (backend + key ID, for a backend that cannot release
// material) can never collide with a key claimed by its own bytes, even if
// the sealedID happens to spell the same bytes as some other key's material.
func TestClaimAEADNonceInSealedIdentityIsDistinctFromMaterial(t *testing.T) {
	guard, err := aead.NewKeyNonceGuard(rand.Reader, 0)
	if err != nil {
		t.Fatalf("NewKeyNonceGuard: %v", err)
	}
	nonce := randomBytes(t, 12)
	ctx := context.Background()

	sealedID := "pkcs11:secret:collide:aes256gcm"

	// Claim once under the sealed identity.
	if err := ClaimAEADNonceIn(ctx, guard, nil, ErrNotSupported, sealedID, nonce); err != nil {
		t.Fatalf("sealed claim must succeed: %v", err)
	}
	// The same nonce, presented as literal key material spelling the sealed
	// ID's own bytes, must be treated as an unrelated key -- domain
	// separation, not a coincidental collision.
	if err := ClaimAEADNonceIn(ctx, guard, []byte(sealedID), nil, "", nonce); err != nil {
		t.Fatalf("material identity must not collide with a sealed identity of the same bytes: %v", err)
	}
	// But two backends whose keys resolve to the SAME sealedID (a
	// misconfiguration bug in the caller) do collide -- the guard cannot see
	// the difference.
	err = ClaimAEADNonceIn(ctx, guard, nil, ErrNotSupported, sealedID, nonce)
	if !errors.Is(err, aead.ErrNonceReuse) {
		t.Fatalf("a repeated sealedID and nonce must be refused as reuse, got %v", err)
	}
}

// TestClaimAEADNonceInUnresolvedKeyMaterial is the bad-input half for a
// caller that reports success but supplies no key material: silently keying
// on empty bytes would collapse every such call onto one guard entry.
func TestClaimAEADNonceInUnresolvedKeyMaterial(t *testing.T) {
	guard, err := aead.NewKeyNonceGuard(rand.Reader, 0)
	if err != nil {
		t.Fatalf("NewKeyNonceGuard: %v", err)
	}
	err = ClaimAEADNonceIn(context.Background(), guard, nil, nil, "irrelevant", randomBytes(t, 12))
	if !errors.Is(err, errAEADKeyMaterialUnresolved) {
		t.Fatalf("expected errAEADKeyMaterialUnresolved, got %v", err)
	}
}

// TestClaimAEADNonceInPropagatesAnUnrelatedResolutionError proves a failure
// to resolve the key for any reason other than "sealed" is reported as-is,
// rather than folded into a sealed or reuse identity nobody could reason
// about.
func TestClaimAEADNonceInPropagatesAnUnrelatedResolutionError(t *testing.T) {
	guard, err := aead.NewKeyNonceGuard(rand.Reader, 0)
	if err != nil {
		t.Fatalf("NewKeyNonceGuard: %v", err)
	}
	readErr := errors.New("key store is offline")
	err = ClaimAEADNonceIn(context.Background(), guard, nil, readErr, "irrelevant", randomBytes(t, 12))
	if !errors.Is(err, readErr) {
		t.Fatalf("expected the backend's own resolution error, got %v", err)
	}
}

// TestClaimGeneratedAEADNonceInToleratesAFullGuard pins the one policy that
// differs between the strict and generated claims. Once the guard's bounded
// in-memory tracker is full, a caller-supplied nonce is refused -- the guard
// can no longer promise it would notice a repeat -- while a generated nonce,
// fresh by construction, still encrypts. A genuine repeat is refused either
// way.
func TestClaimGeneratedAEADNonceInToleratesAFullGuard(t *testing.T) {
	guard, err := aead.NewKeyNonceGuard(rand.Reader, 1)
	if err != nil {
		t.Fatalf("NewKeyNonceGuard: %v", err)
	}
	key := randomBytes(t, 32)
	ctx := context.Background()

	recorded := randomBytes(t, 12)
	if err := ClaimGeneratedAEADNonceIn(ctx, guard, key, nil, "", recorded); err != nil {
		t.Fatalf("the guard has room for the first claim: %v", err)
	}

	if err := ClaimGeneratedAEADNonceIn(ctx, guard, key, nil, "", randomBytes(t, 12)); err != nil {
		t.Fatalf("a generated nonce must still encrypt once the guard is full: %v", err)
	}

	err = ClaimAEADNonceIn(ctx, guard, key, nil, "", randomBytes(t, 12))
	if !errors.Is(err, aead.ErrNonceTrackerFull) {
		t.Fatalf("a caller nonce cannot be vouched for by a full guard, got %v", err)
	}

	err = ClaimGeneratedAEADNonceIn(ctx, guard, key, nil, "", recorded)
	if !errors.Is(err, aead.ErrNonceReuse) {
		t.Fatalf("a repeat is a repeat, full guard or not, got %v", err)
	}
}

// TestClaimAEADNonceAdmitsExactlyOneOfConcurrentSameNonceCalls is the race
// the old, two-step AEADSafetyTracker (check under RLock, record after Seal)
// could lose: two callers presenting one (key, nonce) pair at once could
// both pass its separate check. ClaimAEADNonce claims in one atomic step
// against the process-wide shared guard, so exactly one caller wins.
func TestClaimAEADNonceAdmitsExactlyOneOfConcurrentSameNonceCalls(t *testing.T) {
	key := randomBytes(t, 32)
	nonce := randomBytes(t, 12)

	const callers = 32
	var succeeded, refused atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range callers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			err := ClaimAEADNonce(context.Background(), key, nil, "", nonce)
			switch {
			case err == nil:
				succeeded.Add(1)
			case errors.Is(err, aead.ErrNonceReuse):
				refused.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()

	if succeeded.Load() != 1 {
		t.Errorf("exactly one caller may consume the pair, got %d", succeeded.Load())
	}
	if refused.Load() != callers-1 {
		t.Errorf("every other caller must be refused as a reuse, got %d", refused.Load())
	}
}
