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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"sync"
	"sync/atomic"
)

// DefaultKeyNonceGuardLimit bounds the process-wide guard returned by
// SharedAEADNonceGuard. It is deliberately the same bound the PKCS#11 module's
// own C_Encrypt tracker uses, so one AES-GCM vocabulary covers every path.
const DefaultKeyNonceGuardLimit = 1 << 20

// KeyNonceGuard refuses an AEAD (key, nonce) pair that has already been used
// for encryption in this process.
//
// It exists because the safety property AES-GCM depends on is a property of
// the key MATERIAL and the nonce, not of whatever handle, object, session or
// manager instance happens to name that material on a given call. NIST SP
// 800-38D section 8.2 requires that a (key, IV) pair never repeat: two
// encryptions under one pair leak the XOR of their plaintexts, and -- because
// both messages then share the same GHASH subkey H -- also disclose enough to
// forge tags on further messages under that key. When the plaintext is itself
// key material, as it is for an authenticated key wrap, that XOR hands an
// attacker holding both blobs the contents of both wrapped keys.
//
// Identity is therefore derived from the key bytes rather than from a key
// identifier: the same AES key reachable under two object handles, two
// sessions, two slots or two backend names is one key as far as GCM is
// concerned, and a guard keyed by the identifier would miss every one of those
// aliases.
//
// The derivation is HMAC-SHA-256 under a per-process random salt rather than a
// bare digest, so the long-lived map this guard keeps holds nothing an
// attacker who reads it could test candidate keys against offline.
//
// A KeyNonceGuard is safe for concurrent use.
type KeyNonceGuard struct {
	tracker *NonceTracker
	salt    []byte

	// store is the optional durable backing UseContext also claims through.
	// A *PersistentNonceStore rather than a PersistentNonceStore so the zero
	// value (no SetPersistentStore call) is a nil pointer atomic.Pointer can
	// report cheaply, without allocating an interface value up front.
	store atomic.Pointer[PersistentNonceStore]
}

// PersistentNonceStore is the optional durable backing a KeyNonceGuard
// consults from UseContext, in addition to its in-memory tracker, so a claim
// survives a process restart and is visible to every process sharing the
// store -- the property go-xkms#1201 asked for and that the in-memory
// tracker alone cannot offer (see SharedAEADNonceGuard's own doc comment).
//
// ClaimNonce must itself be the one atomic step. An implementation built on a
// linearizable conditional write -- storage.Backend.PutIfAbsent, or a qrdb
// KVStore's PutIfAbsent when the store is the embedded qrdb node -- satisfies
// this. One that performs a separate read and then a write reintroduces
// exactly the check-then-record race this guard exists to close; see
// go-qrdb's AtomicKVStore doc for why the composed alternative (Exists then
// Put) is not equivalent.
//
// Defined here, rather than taking a storage.Backend or a qrdb KVStore
// directly, so this package -- shared by the PKCS#11 module, a cgo-loaded
// client library with no reason to carry a storage or qrdb dependency --
// stays free of both. pkg/aeadnonce implements this interface over
// storage.Backend for the server side; see pkg/xkms/aead_nonce_guard.go for
// where it is attached.
type PersistentNonceStore interface {
	// ClaimNonce atomically records entry as consumed, reporting
	// claimed=false when it was already recorded -- by this process, an
	// earlier instance of it, or another node sharing the store.
	ClaimNonce(ctx context.Context, entry []byte) (claimed bool, err error)
}

// NewKeyNonceGuard creates a guard whose tracker holds at most limit entries.
// A limit of zero means unbounded; see NonceTracker.CheckAndRecordNonce for
// what reaching the limit does.
//
// The salt is read from the supplied entropy source. Callers that have no
// reason to prefer another source should pass crypto/rand.Reader, which is
// what SharedAEADNonceGuard does.
func NewKeyNonceGuard(entropy io.Reader, limit int) (*KeyNonceGuard, error) {
	salt := make([]byte, sha256.Size)
	if _, err := io.ReadFull(entropy, salt); err != nil {
		return nil, err
	}
	return &KeyNonceGuard{
		tracker: NewNonceTrackerWithLimit(true, limit),
		salt:    salt,
	}, nil
}

// Use atomically records that nonce is about to be consumed for an encryption
// under keyMaterial, and reports an error if that exact pair was already
// consumed in this process.
//
// Callers must treat a non-nil result as fatal to the operation: continuing
// would perform the encryption SP 800-38D section 8.2 forbids. The two errors
// it can return are ErrNonceReuse, meaning the pair repeats, and
// ErrNonceTrackerFull, meaning the guard can no longer promise it would
// notice.
//
// Empty key material or an empty nonce is a caller bug rather than a reuse,
// and is reported as ErrNonceGuardInput: a guard that silently accepted them
// would collapse every such call onto one tracker entry.
func (g *KeyNonceGuard) Use(keyMaterial, nonce []byte) error {
	entry, err := g.entry(keyMaterial, nonce)
	if err != nil {
		return err
	}
	return g.tracker.CheckAndRecordNonce(entry)
}

// SetPersistentStore attaches (or, given nil, detaches) the durable backing
// UseContext also claims through. It is safe to call concurrently with
// UseContext, but is meant to be called once, before the guard serves any
// request that needs the durability guarantee -- see pkg/server's
// initializeAEADNonceStore, which calls it on SharedAEADNonceGuard.
//
// Detaching (nil) matters for a process that tears the store's backing
// storage.Backend down and rebuilds it, such as a test suite constructing
// many *server.Server in one binary: a guard left pointing at a closed
// backend would fail every subsequent claim with a storage error rather than
// the refusal a genuine reuse produces.
func (g *KeyNonceGuard) SetPersistentStore(store PersistentNonceStore) {
	g.store.Store(&store)
}

// UseContext is Use plus the durable claim: when a PersistentNonceStore is
// attached (SetPersistentStore), the pair must ALSO be claimed there, so a
// repeat is caught across a process restart or across every process sharing
// the store, exactly as a repeat within this process already is by the
// in-memory tracker alone.
//
// The in-memory check runs first. It is strictly cheaper than a store round
// trip, it alone decides ErrNonceTrackerFull (a store has no bound to reach),
// and two callers racing on one pair within this process are already
// resolved by its single lock -- only the winner reaches the store. A pair
// this process has not seen before still goes to the store when one is
// attached, because the in-memory tracker remembers nothing from before a
// restart and nothing another process has claimed.
//
// Callers that can supply a context should always prefer this over Use. Use
// remains for callers that have no context to thread through and no
// persistent store to consult -- the PKCS#11 module's own in-process guard
// among them, which sits behind a C ABI with no context parameter and claims
// only for the lifetime of its own process; see
// pkg/pkcs11/module/module_authwrap.go's guardGCMNonce.
func (g *KeyNonceGuard) UseContext(ctx context.Context, keyMaterial, nonce []byte) error {
	entry, err := g.entry(keyMaterial, nonce)
	if err != nil {
		return err
	}
	if err := g.tracker.CheckAndRecordNonce(entry); err != nil {
		return err
	}

	storePtr := g.store.Load()
	if storePtr == nil || *storePtr == nil {
		return nil
	}

	// persistentEntry, not entry: entry is salted with THIS guard's own
	// per-instance random salt (see the type's doc comment), so the same
	// (key material, nonce) pair derives a different value from every guard
	// instance -- deliberately, for the in-memory tracker, but fatal for the
	// store. A claim made before a restart, or by another node, has to be
	// findable by a guard that was never handed that salt, and only a
	// deterministic derivation can do that.
	persistent, err := persistentEntry(keyMaterial, nonce)
	if err != nil {
		return err
	}
	claimed, err := (*storePtr).ClaimNonce(ctx, persistent)
	if err != nil {
		return err
	}
	if !claimed {
		return ErrNonceReuse
	}
	return nil
}

// Used reports whether the pair was already consumed, without recording it.
// It is the read-only companion to Use and exists for diagnostics; deciding
// whether to encrypt must go through Use, because only Use makes the check and
// the record one atomic step.
func (g *KeyNonceGuard) Used(keyMaterial, nonce []byte) bool {
	entry, err := g.entry(keyMaterial, nonce)
	if err != nil {
		return false
	}
	return g.tracker.Contains(entry)
}

// Count returns the number of (key, nonce) pairs the guard is holding.
func (g *KeyNonceGuard) Count() int {
	return g.tracker.Count()
}

// Reset forgets every pair the in-memory tracker has seen. It does not clear
// an attached PersistentNonceStore: that store is the durable record, and a
// caller that wants it forgotten too must clear it directly (through its own
// backend) rather than through this guard.
//
// Forgetting a pair turns a reuse this guard would have detected into one it
// will not, so this must only be called when the keys those pairs belong to
// can no longer be used -- for example when a test builds a fresh fixture, or
// when a token is reinitialized and its key material destroyed.
func (g *KeyNonceGuard) Reset() {
	g.tracker.Clear()
}

// entry derives the tracker key for one (key material, nonce) pair. The key
// identity is a fixed-width HMAC, so concatenating it with the nonce cannot
// make two different pairs collide on one entry.
func (g *KeyNonceGuard) entry(keyMaterial, nonce []byte) ([]byte, error) {
	if len(keyMaterial) == 0 || len(nonce) == 0 {
		return nil, ErrNonceGuardInput
	}
	mac := hmac.New(sha256.New, g.salt)
	// hash.Hash.Write is documented never to return an error, but the error is
	// still checked rather than discarded, because a Write that failed would
	// leave the identity derived from less material than the caller supplied.
	if _, err := mac.Write(keyMaterial); err != nil {
		return nil, err
	}
	return append(mac.Sum(nil), nonce...), nil
}

// persistentNonceDomain labels the HMAC persistentEntry derives under. It is
// a fixed, public constant rather than a secret: the value it domain-separates
// is AES-256 or ChaCha20 key material, which carries 256 bits of entropy, so
// a reader of the persisted store who knows this label gains nothing a reader
// who does not know it could not also compute by testing the same candidate
// key against a bare SHA-256 digest. What the label buys is that this
// package's persisted identity can never collide with an unrelated HMAC some
// other consumer of the same PersistentNonceStore backend happens to compute
// under the same key material for a different purpose.
const persistentNonceDomain = "go-xkms/pkg/crypto/aead persistent nonce guard v1"

// persistentEntry derives the identity a PersistentNonceStore is asked to
// claim. Unlike entry (the in-memory tracker's key), this derivation is NOT
// salted with anything specific to one KeyNonceGuard instance: two guards
// built after two different restarts, or running as two different xkmsd
// nodes, must compute the IDENTICAL identity for the identical (key
// material, nonce) pair, or a claim persisted by one could never be found by
// the other -- silently reopening exactly the reuse window go-xkms#1201
// reported. Called only after entry has already validated its input (from
// UseContext), so it performs no validation of its own.
func persistentEntry(keyMaterial, nonce []byte) ([]byte, error) {
	mac := hmac.New(sha256.New, []byte(persistentNonceDomain))
	// hash.Hash.Write is documented never to return an error, but the error
	// is still checked rather than discarded; see entry's identical comment.
	if _, err := mac.Write(keyMaterial); err != nil {
		return nil, err
	}
	return append(mac.Sum(nil), nonce...), nil
}

// sharedAEADNonceGuard builds the process-wide guard once, on first use.
//
// It is package state on purpose. Every AEAD path that accepts a
// caller-supplied nonce must consult the SAME guard or the guard proves nothing:
// a tracker owned by one manager instance cannot see the IV a second instance
// -- or a code path that performs GCM in process without going through any
// manager at all -- just consumed under the same key. This package is the
// lowest common dependency of those paths, which is what makes it the one
// place they can all reach without depending on each other.
var sharedAEADNonceGuard = sync.OnceValues(func() (*KeyNonceGuard, error) {
	return NewKeyNonceGuard(rand.Reader, DefaultKeyNonceGuardLimit)
})

// SharedAEADNonceGuard returns the process-wide AEAD (key, nonce) guard.
//
// It serves AES-GCM and ChaCha20-Poly1305 alike. Neither construction survives
// a repeated (key, nonce) pair -- both are a stream cipher with a polynomial
// MAC keyed from the same key and nonce -- and nothing in the guard depends on
// which one is in use: the identity names the key and the entry carries the
// nonce verbatim, whatever its length.
//
// The guard's own tracker is process memory: its salt is drawn at first use
// and its entries die with the process. On its own it catches a repeat within
// one process lifetime and nothing across a restart or between two processes.
// pkg/server attaches a PersistentNonceStore to this shared instance at
// startup (initializeAEADNonceStore, go-xkms#1201), so UseContext -- which
// every service-layer caller uses -- also survives a restart and is visible
// to every node sharing the configured storage backend; only a caller using
// the plain Use method, such as the PKCS#11 module's own in-process guard,
// is limited to the in-memory tracker's lifetime.
//
// The error is the one from reading the guard's salt out of the system RNG.
// It is returned rather than panicked on so that a caller can refuse the
// operation with its own error vocabulary; a caller must not proceed with the
// encryption when it is non-nil, because without the guard the reuse SP
// 800-38D section 8.2 forbids would go unnoticed.
func SharedAEADNonceGuard() (*KeyNonceGuard, error) {
	return sharedAEADNonceGuard()
}
