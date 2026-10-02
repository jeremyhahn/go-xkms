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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/peer"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/peergate"
)

func record(thumbprint string, collectedAt time.Time) peergate.Record {
	return peergate.Record{
		Thumbprint:     thumbprint,
		Evidence:       peer.Evidence{Quote: []byte("quote"), PCRs: map[int][]byte{0: fill(1)}, CollectedAt: collectedAt},
		ChannelBinding: make([]byte, peer.ChannelBindingLength),
	}
}

func TestMemoryStore_StoresAndWithdrawsRecords(t *testing.T) {
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

// A record handed in or out must not alias the stored one: a caller that
// reuses its buffers must not rewrite another request's evidence.
func TestMemoryStore_DoesNotAliasRecords(t *testing.T) {
	ctx := context.Background()
	store := newStore(t)
	in := record("peer", time.Now())
	require.NoError(t, store.Put(ctx, in))
	in.Evidence.Quote[0] = 'X'
	in.Evidence.PCRs[0][0] = 0xff

	out, _, err := store.Get(ctx, "peer")
	require.NoError(t, err)
	assert.Equal(t, []byte("quote"), out.Evidence.Quote)
	assert.Equal(t, fill(1), out.Evidence.PCRs[0])

	out.ChannelBinding[0] = 0xff
	again, _, err := store.Get(ctx, "peer")
	require.NoError(t, err)
	assert.Equal(t, make([]byte, peer.ChannelBindingLength), again.ChannelBinding)
}

func TestMemoryStore_BoundsPeersAndEvictsOnlyExpiredEvidence(t *testing.T) {
	ctx := context.Background()
	c := newClock()
	store, err := peergate.NewMemoryStore(peergate.MemoryStoreConfig{MaxPeers: 2, Retention: time.Hour}, peergate.WithClock(c.Now))
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
	assert.Equal(t, 2, store.Len(), "a refused peer evicts nobody current")
}

func TestMemoryStore_HonoursTheContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	store := newStore(t)
	var ctxErr *peer.ContextError
	require.True(t, errors.As(store.Put(ctx, record("peer", time.Now())), &ctxErr))
	_, _, err := store.Get(ctx, "peer")
	require.True(t, errors.As(err, &ctxErr))
	require.True(t, errors.As(store.Delete(ctx, "peer"), &ctxErr))
}

func TestNewMemoryStore_RefusesNegativeBounds(t *testing.T) {
	for field, cfg := range map[string]peergate.MemoryStoreConfig{
		"MaxPeers":  {MaxPeers: -1},
		"Retention": {Retention: -time.Second},
	} {
		t.Run(field, func(t *testing.T) {
			_, err := peergate.NewMemoryStore(cfg)
			var cfgErr *peergate.ConfigError
			require.True(t, errors.As(err, &cfgErr), "NewMemoryStore = %v", err)
			assert.Equal(t, field, cfgErr.Field)
		})
	}
}
