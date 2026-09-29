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

// Package aeadnonce is the durable backing for the process-wide AEAD
// (key, nonce) guard, pkg/crypto/aead.KeyNonceGuard, so a claim it makes on
// behalf of the Encrypt RPC or the AES-GCM key wrap survives a process
// restart and is visible to every xkmsd node sharing the configured storage
// backend (go-xkms#1201).
//
// It is a thin, namespacing wrapper over a storage.Backend -- the same
// pattern pkg/pkcs11state and pkg/staticpw use -- so it inherits the
// backend's atomic PutIfAbsent and whatever at-rest protection and
// replication the backend has, rather than maintaining a second storage
// implementation. xkmsd builds ONE store over one backend for the whole
// process (pkg/server's initializeAEADNonceStore) and attaches it to
// pkg/crypto/aead's shared guard; nothing about the claim is scoped to a
// tenant or a backend name, because the guard's identity already is -- the
// key's own material where a backend releases it, so two names for one key
// collide on one claim regardless of which tenant or backend reached it
// through.
package aeadnonce

import (
	"context"
	"encoding/hex"

	"github.com/jeremyhahn/go-xkms/pkg/crypto/aead"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// Compile-time interface compliance check.
var _ aead.PersistentNonceStore = (*Store)(nil)

// keyPrefix namespaces every record this package writes so it cannot
// collide with other consumers of the same backend.
const keyPrefix = "aeadnonce/"

// claimedMarker is the value written for a claimed entry. Its contents are
// never read back -- ClaimNonce answers from PutIfAbsent's own stored=true
// result -- so any non-nil value would do; a single fixed byte avoids an
// allocation per claim.
var claimedMarker = []byte{1}

// NilBackendError is returned by NewStore when constructed without a
// backend.
type NilBackendError struct{}

// Error implements the error interface.
func (NilBackendError) Error() string {
	return "aeadnonce: storage backend is required"
}

// Store persists AEAD (key, nonce) claims on a storage.Backend, implementing
// pkg/crypto/aead.PersistentNonceStore.
type Store struct {
	backend storage.Backend
}

// NewStore wraps a storage.Backend. The store adds only key namespacing and
// the PutIfAbsent-based claim semantics on top; it performs no encryption or
// scoping of its own, so isolation and at-rest protection are whatever the
// backend already provides.
func NewStore(backend storage.Backend) (*Store, error) {
	if backend == nil {
		return nil, NilBackendError{}
	}
	return &Store{backend: backend}, nil
}

// ClaimNonce atomically records entry -- the HMAC(key material) || nonce
// bytes pkg/crypto/aead.KeyNonceGuard derives -- as consumed, reporting
// claimed=false when it was already recorded by this or any other process
// sharing the backend. It delegates entirely to storage.Backend.PutIfAbsent,
// which every storage.Backend implementation must make atomic across nodes
// when replicated (see storage.Backend's own doc comment on PutIfAbsent), so
// this method performs no read-then-write of its own that could reintroduce
// the race the guard exists to close.
func (s *Store) ClaimNonce(ctx context.Context, entry []byte) (claimed bool, err error) {
	key := keyPrefix + hex.EncodeToString(entry)
	return s.backend.PutIfAbsent(ctx, key, claimedMarker)
}
