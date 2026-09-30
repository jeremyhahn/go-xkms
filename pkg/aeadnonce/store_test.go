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

package aeadnonce

import (
	"context"
	"errors"
	"sync"
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(storage.NewMemory())
	require.NoError(t, err)
	return s
}

// TestNewStoreRejectsNilBackend covers the constructor's error path: a store
// built over no backend could not persist anything, and must not be handed
// out looking usable.
func TestNewStoreRejectsNilBackend(t *testing.T) {
	_, err := NewStore(nil)
	require.Error(t, err)
	var nilBackend NilBackendError
	assert.ErrorAs(t, err, &nilBackend)
}

// TestClaimNonceAcceptsTheFirstClaim covers the ordinary case: an entry
// nobody has claimed before is accepted and reported as claimed.
func TestClaimNonceAcceptsTheFirstClaim(t *testing.T) {
	s := newTestStore(t)
	claimed, err := s.ClaimNonce(context.Background(), []byte("first-entry"))
	require.NoError(t, err)
	assert.True(t, claimed, "an entry claimed for the first time must report claimed=true")
}

// TestClaimNonceRefusesARepeat is the property this whole package exists
// for: the same entry claimed twice reports claimed=false the second time,
// with no error -- a refusal, not a failure.
func TestClaimNonceRefusesARepeat(t *testing.T) {
	s := newTestStore(t)
	entry := []byte("repeated-entry")
	ctx := context.Background()

	claimed, err := s.ClaimNonce(ctx, entry)
	require.NoError(t, err)
	require.True(t, claimed)

	claimed, err = s.ClaimNonce(ctx, entry)
	require.NoError(t, err, "a repeat is a refusal, not an error")
	assert.False(t, claimed, "a second claim on the same entry must be refused")
}

// TestClaimNonceSurvivesAFreshStoreOverTheSameBackend reproduces a restart at
// this package's level: a second *Store built over the SAME storage.Backend
// (a fresh instance never told about the earlier claim, exactly what a
// process restart produces) must still see it.
func TestClaimNonceSurvivesAFreshStoreOverTheSameBackend(t *testing.T) {
	backend := storage.NewMemory()
	entry := []byte("restart-entry")
	ctx := context.Background()

	before, err := NewStore(backend)
	require.NoError(t, err)
	claimed, err := before.ClaimNonce(ctx, entry)
	require.NoError(t, err)
	require.True(t, claimed)

	after, err := NewStore(backend)
	require.NoError(t, err)
	claimed, err = after.ClaimNonce(ctx, entry)
	require.NoError(t, err)
	assert.False(t, claimed, "a claim made before a restart must still hold after one")
}

// TestClaimNonceDistinguishesEntries proves the store namespaces by the
// entry's own bytes rather than collapsing every claim onto one record.
func TestClaimNonceDistinguishesEntries(t *testing.T) {
	s := newTestStore(t)
	ctx := context.Background()

	claimedOne, err := s.ClaimNonce(ctx, []byte("entry-one"))
	require.NoError(t, err)
	claimedTwo, err := s.ClaimNonce(ctx, []byte("entry-two"))
	require.NoError(t, err)

	assert.True(t, claimedOne)
	assert.True(t, claimedTwo, "an unrelated entry must not be refused as a repeat of the first")
}

// TestClaimNonceIsAtomicUnderConcurrency proves exactly one of many
// concurrent claims on one entry succeeds, the property KeyNonceGuard.
// UseContext depends on this store to provide.
func TestClaimNonceIsAtomicUnderConcurrency(t *testing.T) {
	s := newTestStore(t)
	entry := []byte("racing-entry")
	ctx := context.Background()

	const workers = 32
	results := make([]bool, workers)
	errs := make([]error, workers)
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(workers)

	for i := 0; i < workers; i++ {
		go func(idx int) {
			defer wg.Done()
			<-start
			results[idx], errs[idx] = s.ClaimNonce(ctx, entry)
		}(i)
	}
	close(start)
	wg.Wait()

	claimedCount := 0
	for i, err := range errs {
		require.NoError(t, err, "worker %d", i)
		if results[i] {
			claimedCount++
		}
	}
	assert.Equal(t, 1, claimedCount, "exactly one concurrent claim on one entry may succeed")
}

// errBackend is a storage.Backend whose PutIfAbsent always fails, so
// ClaimNonce's error propagation can be exercised without a real storage
// failure.
type errBackend struct {
	storage.Backend
	err error
}

func (b *errBackend) PutIfAbsent(context.Context, string, []byte) (bool, error) {
	return false, b.err
}

// TestClaimNoncePropagatesABackendError proves a backend failure is reported
// as itself, not folded into a false "already claimed" refusal a caller could
// mistake for a genuine reuse.
func TestClaimNoncePropagatesABackendError(t *testing.T) {
	backendErr := errors.New("backend unavailable")
	s, err := NewStore(&errBackend{Backend: storage.NewMemory(), err: backendErr})
	require.NoError(t, err)

	claimed, err := s.ClaimNonce(context.Background(), []byte("err-entry"))
	require.ErrorIs(t, err, backendErr)
	assert.False(t, claimed)
}
