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

package kvadapter

import (
	"context"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
)

// atomicKVStoreAdapter is the KVStoreAdapter a backend gets when it can
// actually perform the guarded operations: it adds go-qrdb's three atomic
// methods over the same wrapped backend.
//
// WHY THIS IS A SEPARATE TYPE (go-xkms#89)
//
// go-qrdb's DAO layer discovers atomicity by TYPE ASSERTION
// (store.(AtomicKVStore)), not from a declared capability, and fails closed
// when the assertion does not hold. So the assertion is the contract: a type
// that satisfies AtomicKVStore is claiming every one of the three operations
// works. A single adapter type that always carried the methods and returned
// "unsupported" from them would pass the assertion and fail at call time,
// which is strictly worse than failing the assertion — the caller has already
// committed to the guarded path by then.
//
// The capability varies per wrapped backend rather than per type, and Go has
// no way to add a method conditionally, so New picks the type.
type atomicKVStoreAdapter struct {
	*KVStoreAdapter

	swapper storage.CompareAndSwapper
	deleter storage.CompareAndDeleter
}

// Compile-time interface compliance check: this is the claim New makes on the
// caller's behalf when the backend supports all three.
var _ qrdbsdk.AtomicKVStore = (*atomicKVStoreAdapter)(nil)

// PutIfAbsent atomically stores value under key only when key is absent,
// delegating to the wrapped backend. Every storage.Backend declares
// PutIfAbsent, but an implementation may report the operation as unavailable;
// that arrives here as an error, which is the honest answer (the outcome is
// unknown, not "the key was present").
func (a *atomicKVStoreAdapter) PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	stored, err := a.backend.PutIfAbsent(ctx, key, value)
	if err != nil {
		return false, &PutError{Key: key, Err: err}
	}
	return stored, nil
}

// CompareAndDelete atomically removes key only when its stored value still
// equals expected. The two contracts agree exactly — an absent key or a
// different value is deleted=false with a nil error on both sides — so this is
// a straight delegation.
func (a *atomicKVStoreAdapter) CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error) {
	deleted, err := a.deleter.CompareAndDelete(ctx, key, expected)
	if err != nil {
		return false, &DeleteError{Key: key, Err: err}
	}
	return deleted, nil
}

// CompareAndSwap atomically replaces key's value with next only when its
// stored value still equals expected.
//
// THE TWO CONTRACTS NOW AGREE EXACTLY (#186), so this is a straight
// delegation, the same shape as CompareAndDelete below. go-qrdb's
// CompareAndSwap never creates a key: "an absent key is NOT created — a swap
// is not a create". go-xkms's storage.CompareAndSwapper gives a nil expected
// the identical meaning: it is compared like any other value (matching only a
// stored empty one), never as "require absent", so an absent key refuses on
// both sides of this adapter regardless of what expected was. A caller that
// wants a guarded create uses PutIfAbsent on this same interface.
func (a *atomicKVStoreAdapter) CompareAndSwap(ctx context.Context, key string, expected, next []byte) (bool, error) {
	swapped, _, err := a.swapper.CompareAndSwap(ctx, key, expected, next)
	if err != nil {
		return false, &PutError{Key: key, Err: err}
	}
	return swapped, nil
}
