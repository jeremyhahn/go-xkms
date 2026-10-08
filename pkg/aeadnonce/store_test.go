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

package aeadnonce

import (
	"context"
	"encoding/hex"
	"errors"
	"sync"
	"testing"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := NewStore(testutil.NewMemoryDAOFactory())
	require.NoError(t, err)
	return s
}

// TestNewStore proves a store needs a factory serving its database: a store
// that could not persist anything must not be handed out looking usable.
func TestNewStore(t *testing.T) {
	_, err := NewStore(nil)
	assert.ErrorIs(t, err, ErrNilDAOFactory)

	_, err = NewStore(dao.NewStoreFactory(nil))
	var storeErr *StoreError
	require.ErrorAs(t, err, &storeErr)
	assert.Equal(t, "open", storeErr.Op)
	var unavailable *dao.DatabaseUnavailableError
	assert.ErrorAs(t, err, &unavailable)
}

// TestClaimNonceAcceptsTheFirstClaim covers the ordinary case: an entry
// nobody has claimed before is accepted, reported as claimed, and stored as
// one entity named by the entry's hex.
func TestClaimNonceAcceptsTheFirstClaim(t *testing.T) {
	daos := testutil.NewMemoryDAOFactory()
	s, err := NewStore(daos)
	require.NoError(t, err)
	entry := []byte("first-entry")

	claimed, err := s.ClaimNonce(context.Background(), entry)
	require.NoError(t, err)
	assert.True(t, claimed, "an entry claimed for the first time must report claimed=true")

	raw, err := newClaimDAO(daos)
	require.NoError(t, err)
	stored, err := raw.GetByNaturalKey(context.Background(), hex.EncodeToString(entry))
	require.NoError(t, err)
	assert.Equal(t, hex.EncodeToString(entry), stored.Entry)
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

// TestClaimNonceSurvivesAFreshStoreOverTheSameDatabase reproduces a restart
// at this package's level: a second *Store over the SAME database (a fresh
// instance never told about the earlier claim, exactly what a process
// restart produces) must still see it.
func TestClaimNonceSurvivesAFreshStoreOverTheSameDatabase(t *testing.T) {
	daos := testutil.NewMemoryDAOFactory()
	entry := []byte("restart-entry")
	ctx := context.Background()

	before, err := NewStore(daos)
	require.NoError(t, err)
	claimed, err := before.ClaimNonce(ctx, entry)
	require.NoError(t, err)
	require.True(t, claimed)

	after, err := NewStore(daos)
	require.NoError(t, err)
	claimed, err = after.ClaimNonce(ctx, entry)
	require.NoError(t, err)
	assert.False(t, claimed, "a claim made before a restart must still hold after one")
}

// TestClaimNonceDistinguishesEntries proves the store keys by the entry's
// own bytes rather than collapsing every claim onto one record.
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
// concurrent claims on one entry succeeds -- across two stores over one
// database, as two nodes sharing a datastore are -- the property
// KeyNonceGuard.UseContext depends on this store to provide.
func TestClaimNonceIsAtomicUnderConcurrency(t *testing.T) {
	daos := testutil.NewMemoryDAOFactory()
	stores := make([]*Store, 2)
	for i := range stores {
		s, err := NewStore(daos)
		require.NoError(t, err)
		stores[i] = s
	}
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
			results[idx], errs[idx] = stores[idx%len(stores)].ClaimNonce(ctx, entry)
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

// failingKV is an atomic KVStore whose conditional create fails, so
// ClaimNonce's error reporting can be exercised without a real outage.
type failingKV struct {
	*qrdbsdk.MemoryKVStore
	err error
}

func (f failingKV) PutIfAbsent(context.Context, string, []byte) (bool, error) {
	return false, f.err
}

// TestClaimNonceReportsAStoreFailure proves a datastore failure is reported
// as a *StoreError carrying the cause, not folded into a false "already
// claimed" refusal a caller could mistake for a genuine reuse.
func TestClaimNonceReportsAStoreFailure(t *testing.T) {
	cause := errors.New("datastore unavailable")
	kv := failingKV{MemoryKVStore: qrdbsdk.NewMemoryKVStore(), err: cause}
	s, err := NewStore(dao.NewStoreFactory(kv))
	require.NoError(t, err)

	claimed, err := s.ClaimNonce(context.Background(), []byte("err-entry"))
	var storeErr *StoreError
	require.ErrorAs(t, err, &storeErr)
	assert.Equal(t, "claim", storeErr.Op)
	assert.ErrorIs(t, err, cause)
	assert.False(t, claimed)
}
