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

package importtoken

import (
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestStore_TakeConsumesToken verifies a used token is gone: a second Take
// for the same token reports *NotFoundError.
func TestStore_TakeConsumesToken(t *testing.T) {
	var destroyed []string
	store := New(time.Hour, 10, func(v string) { destroyed = append(destroyed, v) })

	_, err := store.Put("token-1", "secret-1")
	require.NoError(t, err)

	got, err := store.Take("token-1")
	require.NoError(t, err)
	assert.Equal(t, "secret-1", got)

	_, err = store.Take("token-1")
	require.Error(t, err)
	var notFound *NotFoundError
	require.True(t, errors.As(err, &notFound))
	assert.Equal(t, "token-1", notFound.Token)

	// Take transfers ownership to the caller; the Store must not have
	// destroyed the value it successfully returned.
	assert.Empty(t, destroyed)
}

// TestStore_ExpiredTokenIsSwept verifies an expired token is swept: Put of
// a second token triggers the sweep, and the expired entry's value is
// destroyed rather than merely dropped.
func TestStore_ExpiredTokenIsSwept(t *testing.T) {
	var destroyed []string
	store := New(10*time.Millisecond, 10, func(v string) { destroyed = append(destroyed, v) })

	_, err := store.Put("expiring", "secret-1")
	require.NoError(t, err)
	require.Equal(t, 1, store.Len())

	time.Sleep(20 * time.Millisecond)

	// Put of an unrelated token sweeps the expired one first.
	_, err = store.Put("other", "secret-2")
	require.NoError(t, err)

	assert.Equal(t, 1, store.Len(), "the expired entry must have been swept")
	assert.Equal(t, []string{"secret-1"}, destroyed)

	_, err = store.Take("expiring")
	require.Error(t, err)
	var notFound *NotFoundError
	require.True(t, errors.As(err, &notFound))
}

// TestStore_ExpiredTokenSweptOnTake verifies Take also enforces expiry
// (not only Put), destroying and reporting *NotFoundError for a token that
// is still present but past its TTL.
func TestStore_ExpiredTokenSweptOnTake(t *testing.T) {
	var destroyed []string
	store := New(10*time.Millisecond, 10, func(v string) { destroyed = append(destroyed, v) })

	_, err := store.Put("expiring", "secret-1")
	require.NoError(t, err)

	time.Sleep(20 * time.Millisecond)

	_, err = store.Take("expiring")
	require.Error(t, err)
	var notFound *NotFoundError
	require.True(t, errors.As(err, &notFound))
	assert.Equal(t, []string{"secret-1"}, destroyed)
}

// TestStore_CapHoldsUnderManyCalls verifies the hard cap holds under many
// Put calls: once the store is at capacity, Put refuses new tokens with
// *LimitExceededError rather than growing past the limit, and it destroys
// the value it refused so a rejected token cannot linger either.
func TestStore_CapHoldsUnderManyCalls(t *testing.T) {
	var destroyedCount int
	store := New(time.Hour, 5, func(int) { destroyedCount++ })

	for i := 0; i < 5; i++ {
		_, err := store.Put(string(rune('a'+i)), i)
		require.NoError(t, err)
	}
	require.Equal(t, 5, store.Len())

	for i := 5; i < 1000; i++ {
		_, err := store.Put(string(rune('a'+i)), i)
		require.Error(t, err, "call %d must be refused once the store is at capacity", i)
		var limitErr *LimitExceededError
		require.True(t, errors.As(err, &limitErr))
		assert.Equal(t, 5, limitErr.Limit)
	}

	assert.Equal(t, 5, store.Len(), "the cap must hold, not merely slow growth")
	assert.Equal(t, 995, destroyedCount, "every refused value must still be destroyed")
}

// TestStore_PutReplacesAndDestroysExisting verifies Put on an existing
// token destroys the value it replaces, so re-issuing a token for the same
// key (a backend keyed by CN rather than a random UUID, for example)
// cannot leak the earlier value.
func TestStore_PutReplacesAndDestroysExisting(t *testing.T) {
	var destroyed []string
	store := New(time.Hour, 10, func(v string) { destroyed = append(destroyed, v) })

	_, err := store.Put("token-1", "first")
	require.NoError(t, err)
	_, err = store.Put("token-1", "second")
	require.NoError(t, err)

	assert.Equal(t, []string{"first"}, destroyed)
	got, err := store.Take("token-1")
	require.NoError(t, err)
	assert.Equal(t, "second", got)
}

// TestStore_PeekDoesNotConsume verifies Peek reads a token's value without
// removing it, so a caller can read metadata before the single-use Take.
func TestStore_PeekDoesNotConsume(t *testing.T) {
	store := New(time.Hour, 10, func(string) {})

	_, err := store.Put("token-1", "secret-1")
	require.NoError(t, err)

	got, err := store.Peek("token-1")
	require.NoError(t, err)
	assert.Equal(t, "secret-1", got)

	// Still present: Peek must not have consumed it.
	got, err = store.Take("token-1")
	require.NoError(t, err)
	assert.Equal(t, "secret-1", got)
}

// TestStore_DeleteDestroysAndIsIdempotent verifies eviction wipes the
// material: Delete destroys the value it removes, and is safe to call
// again (or on a token that was never present) without error.
func TestStore_DeleteDestroysAndIsIdempotent(t *testing.T) {
	var destroyed []string
	store := New(time.Hour, 10, func(v string) { destroyed = append(destroyed, v) })

	_, err := store.Put("token-1", "secret-1")
	require.NoError(t, err)

	store.Delete("token-1")
	assert.Equal(t, []string{"secret-1"}, destroyed)
	assert.Equal(t, 0, store.Len())

	// Idempotent: deleting an absent token is a no-op, not an error.
	store.Delete("token-1")
	assert.Equal(t, []string{"secret-1"}, destroyed)
}

// TestStore_CloseDestroysEveryEntry verifies eviction by Close also wipes
// the material for every remaining token, matching Delete and the sweep.
func TestStore_CloseDestroysEveryEntry(t *testing.T) {
	var destroyed []string
	store := New(time.Hour, 10, func(v string) { destroyed = append(destroyed, v) })

	_, err := store.Put("token-1", "secret-1")
	require.NoError(t, err)
	_, err = store.Put("token-2", "secret-2")
	require.NoError(t, err)

	store.Close()

	assert.ElementsMatch(t, []string{"secret-1", "secret-2"}, destroyed)
	assert.Equal(t, 0, store.Len())
}

// TestNew_DefaultsAppliedForInvalidInput verifies New falls back to its
// documented defaults for a non-positive TTL or cap, and tolerates a nil
// destroy callback, rather than constructing a Store that can never expire
// or hold anything.
func TestNew_DefaultsAppliedForInvalidInput(t *testing.T) {
	store := New[string](0, 0, nil)

	_, err := store.Put("token-1", "secret-1")
	require.NoError(t, err)
	got, err := store.Take("token-1")
	require.NoError(t, err)
	assert.Equal(t, "secret-1", got)
}
