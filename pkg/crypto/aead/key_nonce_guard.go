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
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"io"
	"sync"
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

// Reset forgets every pair the guard has seen.
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
// The guard is process memory. Its salt is drawn at first use and its entries
// die with the process, so it catches a repeat within one process lifetime and
// nothing across a restart or between two processes.
//
// The error is the one from reading the guard's salt out of the system RNG.
// It is returned rather than panicked on so that a caller can refuse the
// operation with its own error vocabulary; a caller must not proceed with the
// encryption when it is non-nil, because without the guard the reuse SP
// 800-38D section 8.2 forbids would go unnoticed.
func SharedAEADNonceGuard() (*KeyNonceGuard, error) {
	return sharedAEADNonceGuard()
}
