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

package peergate_test

import (
	"context"
	"errors"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/peer"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/peergate"
	"github.com/jeremyhahn/go-xkms/pkg/dao"
	"github.com/jeremyhahn/go-xkms/pkg/testutil"
)

func record(thumbprint string, collectedAt time.Time) peergate.Record {
	return peergate.Record{
		Thumbprint:     thumbprint,
		Evidence:       peer.Evidence{Quote: []byte("quote"), PCRs: map[int][]byte{0: fill(1)}, CollectedAt: collectedAt},
		ChannelBinding: make([]byte, peer.ChannelBindingLength),
	}
}

func TestDAOStore_StoresAndWithdrawsRecords(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)

	_, ok, err := store.Get(ctx, "peer")
	require.NoError(t, err)
	assert.False(t, ok)

	require.NoError(t, store.Put(ctx, record("peer", time.Now())))
	got, ok, err := store.Get(ctx, "peer")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, []byte("quote"), got.Evidence.Quote)

	require.NoError(t, store.Delete(ctx, "peer"))
	require.NoError(t, store.Delete(ctx, "peer"), "deleting an absent record is not an error")
	_, ok, err = store.Get(ctx, "peer")
	require.NoError(t, err)
	assert.False(t, ok)
}

// Every field the verifier reads must survive the datastore, and a second
// store over the same datastore (another node, or a restart) must see it.
func TestDAOStore_RoundTripsEveryFieldAcrossStores(t *testing.T) {
	ctx := context.Background()
	daos := testutil.NewMemoryDAOFactory()
	writer, err := peergate.NewDAOStore(peergate.DAOStoreConfig{DAOs: daos})
	require.NoError(t, err)

	collected := time.Date(2026, 10, 15, 12, 0, 0, 123456789, time.UTC)
	in := peergate.Record{
		Thumbprint: "peer",
		Evidence: peer.Evidence{
			Quote:            []byte("quote"),
			Signature:        []byte("signature"),
			Nonce:            fill(7),
			PCRs:             map[int][]byte{0: fill(1), 7: fill(2), 23: fill(3)},
			AKCertificatePEM: []byte("-----BEGIN CERTIFICATE-----"),
			CollectedAt:      collected,
		},
		ChannelBinding: fill(9),
	}
	require.NoError(t, writer.Put(ctx, in))

	reader, err := peergate.NewDAOStore(peergate.DAOStoreConfig{DAOs: daos})
	require.NoError(t, err)
	out, ok, err := reader.Get(ctx, "peer")
	require.NoError(t, err)
	require.True(t, ok)
	assert.True(t, collected.Equal(out.Evidence.CollectedAt), "CollectedAt = %v", out.Evidence.CollectedAt)
	out.Evidence.CollectedAt = collected
	assert.Equal(t, in, out)
}

// The latest submission replaces the earlier one, so a peer whose state
// turned bad cannot keep presenting an older passing quote.
func TestDAOStore_LatestEvidenceWins(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	first := record("peer", time.Now())
	second := record("peer", time.Now())
	second.Evidence.Quote = []byte("newer")

	require.NoError(t, store.Put(ctx, first))
	require.NoError(t, store.Put(ctx, second))
	got, ok, err := store.Get(ctx, "peer")
	require.NoError(t, err)
	require.True(t, ok)
	assert.Equal(t, []byte("newer"), got.Evidence.Quote)
}

func TestDAOStore_BoundsPeersAndEvictsOnlyExpiredEvidence(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	store, err := peergate.NewDAOStore(peergate.DAOStoreConfig{
		DAOs: testutil.NewMemoryDAOFactory(), MaxPeers: 2, Retention: time.Hour,
	}, peergate.WithClock(c.Now))
	require.NoError(t, err)

	require.NoError(t, store.Put(ctx, record("old", c.now.Add(-2*time.Hour))))
	require.NoError(t, store.Put(ctx, record("fresh", c.now)))
	require.NoError(t, store.Put(ctx, record("fresh", c.now)), "replacing a peer's record needs no room")

	require.NoError(t, store.Put(ctx, record("new", c.now)), "evidence past retention makes room")
	_, ok, err := store.Get(ctx, "old")
	require.NoError(t, err)
	assert.False(t, ok, "the expired record was evicted")

	err = store.Put(ctx, record("another", c.now))
	var capacity *peergate.CapacityError
	require.True(t, errors.As(err, &capacity), "Put = %v", err)
	assert.Equal(t, 2, capacity.Limit)
	for _, current := range []string{"fresh", "new"} {
		_, ok, err := store.Get(ctx, current)
		require.NoError(t, err)
		assert.True(t, ok, "a refused peer evicts nobody current: %s", current)
	}
}

// A peer that refreshes its evidence after eviction has scanned it but before
// the delete keeps the fresh record, and that record still holds its place:
// the newcomer is refused rather than admitted on room that never opened.
func TestDAOStore_EvictionSparesEvidenceRefreshedAfterTheScan(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	kv := &refreshingKV{MemoryKVStore: qrdbsdk.NewMemoryKVStore()}
	store, err := peergate.NewDAOStore(peergate.DAOStoreConfig{
		DAOs: dao.NewStoreFactory(kv), MaxPeers: 1, Retention: time.Hour,
	}, peergate.WithClock(c.Now))
	require.NoError(t, err)
	require.NoError(t, store.Put(ctx, record("peer", c.now.Add(-2*time.Hour))))

	kv.beforeDelete = func() {
		require.NoError(t, store.Put(ctx, record("peer", c.now)))
	}
	err = store.Put(ctx, record("newcomer", c.now))
	var capacity *peergate.CapacityError
	require.True(t, errors.As(err, &capacity), "Put = %v", err)
	require.Nil(t, kv.beforeDelete, "eviction reached its delete")

	got, ok, err := store.Get(ctx, "peer")
	require.NoError(t, err)
	require.True(t, ok, "the refreshed record survived eviction")
	assert.True(t, got.Evidence.CollectedAt.Equal(c.now))
	_, ok, err = store.Get(ctx, "newcomer")
	require.NoError(t, err)
	assert.False(t, ok)
}

// refreshingKV runs beforeDelete once, ahead of the first delete of either
// kind, to interleave a concurrent write between a read and its delete.
type refreshingKV struct {
	*qrdbsdk.MemoryKVStore
	beforeDelete func()
}

func (r *refreshingKV) interleave() {
	if hook := r.beforeDelete; hook != nil {
		r.beforeDelete = nil
		hook()
	}
}

func (r *refreshingKV) Delete(ctx context.Context, key string) error {
	r.interleave()
	return r.MemoryKVStore.Delete(ctx, key)
}

func (r *refreshingKV) CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error) {
	r.interleave()
	return r.MemoryKVStore.CompareAndDelete(ctx, key, expected)
}

func TestDAOStore_HonoursTheContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store := newStore(t)
	var ctxErr *peer.ContextError
	require.True(t, errors.As(store.Put(ctx, record("peer", time.Now())), &ctxErr))
	_, _, err := store.Get(ctx, "peer")
	require.True(t, errors.As(err, &ctxErr))
	require.True(t, errors.As(store.Delete(ctx, "peer"), &ctxErr))
}

// faultyKV fails the reads a DAOStore depends on, so the store's error
// reporting can be exercised without a real outage.
type faultyKV struct {
	*qrdbsdk.MemoryKVStore
	failGet  bool
	failScan bool
	err      error
}

func (f *faultyKV) Get(ctx context.Context, key string) ([]byte, error) {
	if f.failGet {
		return nil, f.err
	}
	return f.MemoryKVStore.Get(ctx, key)
}

func (f *faultyKV) List(ctx context.Context, prefix string) ([]string, error) {
	if f.failScan {
		return nil, f.err
	}
	return f.MemoryKVStore.List(ctx, prefix)
}

func (f *faultyKV) Scan(ctx context.Context, prefix string, fn func(string, []byte) error) error {
	if f.failScan {
		return f.err
	}
	return f.MemoryKVStore.Scan(ctx, prefix, fn)
}

// A datastore that cannot answer is reported, never read as "no evidence":
// the verifier turns a store error into a refusal, not an Absence verdict.
func TestDAOStore_ReportsDatastoreFailures(t *testing.T) {
	ctx := context.Background()
	cause := errors.New("datastore unavailable")
	kv := &faultyKV{MemoryKVStore: qrdbsdk.NewMemoryKVStore(), err: cause}
	store, err := peergate.NewDAOStore(peergate.DAOStoreConfig{DAOs: dao.NewStoreFactory(kv), MaxPeers: 1})
	require.NoError(t, err)
	require.NoError(t, store.Put(ctx, record("peer", time.Now())))

	kv.failScan = true
	assert.ErrorIs(t, store.Put(ctx, record("other", time.Now())), cause, "a full store that cannot count or scan refuses")
	kv.failScan = false

	kv.failGet = true
	_, ok, err := store.Get(ctx, "peer")
	assert.ErrorIs(t, err, cause)
	assert.False(t, ok)
	assert.ErrorIs(t, store.Put(ctx, record("peer", time.Now())), cause)
	assert.ErrorIs(t, store.Delete(ctx, "peer"), cause)
}

func TestNewDAOStore_RefusesAnInvalidConfig(t *testing.T) {
	daos := testutil.NewMemoryDAOFactory()
	for field, cfg := range map[string]peergate.DAOStoreConfig{
		"DAOs":      {},
		"MaxPeers":  {DAOs: daos, MaxPeers: -1},
		"Retention": {DAOs: daos, Retention: -time.Second},
	} {
		t.Run(field, func(t *testing.T) {
			_, err := peergate.NewDAOStore(cfg)
			var cfgErr *peergate.ConfigError
			require.True(t, errors.As(err, &cfgErr), "NewDAOStore = %v", err)
			assert.Equal(t, field, cfgErr.Field)
		})
	}
}
