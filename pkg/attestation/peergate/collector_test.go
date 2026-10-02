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
	"crypto/tls"
	"errors"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/attestation/peer"
	"github.com/jeremyhahn/go-xkms/pkg/attestation/peergate"
)

// clock is a settable test clock.
type clock struct{ now time.Time }

func (c *clock) Now() time.Time { return c.now }

func newClock() *clock { return &clock{now: time.Now().UTC()} }

func newStore(t *testing.T, opts ...peergate.Option) *peergate.MemoryStore {
	t.Helper()
	store, err := peergate.NewMemoryStore(peergate.MemoryStoreConfig{}, opts...)
	require.NoError(t, err)
	return store
}

func newCollector(t *testing.T, store peergate.EvidenceStore, c *clock) *peergate.Collector {
	t.Helper()
	collector, err := peergate.NewCollector(peergate.CollectorConfig{Store: store}, peergate.WithClock(c.Now))
	require.NoError(t, err)
	return collector
}

func TestCollector_StoresBoundEvidenceForTheAuthenticatedPeer(t *testing.T) {
	ctx := context.Background()
	p := newPKI(t)
	client, leaf := p.clientCert(t, device{})
	conn := p.connect(t, client)
	ak := p.newAK(t, device{})
	c := newClock()
	store := newStore(t)
	collector := newCollector(t, store, c)

	challenge, err := collector.Challenge(ctx, conn.server)
	require.NoError(t, err)
	require.Len(t, challenge.Nonce, peergate.NonceLength)
	assert.Equal(t, c.now.Add(peergate.DefaultChallengeTTL), challenge.ExpiresAt)

	reported := ak.evidence(t, conn, challenge.Nonce, goldenPCRs())
	reported.CollectedAt = c.now.Add(-48 * time.Hour) // a peer's own claim is ignored
	require.NoError(t, collector.Submit(ctx, conn.server, reported))

	record, ok, err := store.Get(ctx, qrdbsdk.ComputeSPKIThumbprint(leaf))
	require.NoError(t, err)
	require.True(t, ok, "evidence must be stored under the connection certificate's thumbprint")
	assert.Equal(t, c.now, record.Evidence.CollectedAt, "the collector stamps receipt time")
	binding, err := peer.ChannelBinding(conn.server)
	require.NoError(t, err)
	assert.Equal(t, binding, record.ChannelBinding)
	assert.Equal(t, reported.Quote, record.Evidence.Quote)
}

func TestCollector_RefusesConnectionsWithoutAVerifiedPeer(t *testing.T) {
	ctx := context.Background()
	collector := newCollector(t, newStore(t), newClock())
	unverified := &tls.ConnectionState{HandshakeComplete: true}

	for name, state := range map[string]*tls.ConnectionState{"nil state": nil, "no verified chain": unverified} {
		t.Run(name, func(t *testing.T) {
			var certErr *peergate.PeerCertificateError
			_, err := collector.Challenge(ctx, state)
			require.True(t, errors.As(err, &certErr), "Challenge = %v", err)
			err = collector.Submit(ctx, state, peer.Evidence{})
			require.True(t, errors.As(err, &certErr), "Submit = %v", err)
		})
	}
}

func TestCollector_RefusesEvidenceThatAnswersNoChallenge(t *testing.T) {
	ctx := context.Background()
	p := newPKI(t)
	client, _ := p.clientCert(t, device{})
	conn := p.connect(t, client)
	ak := p.newAK(t, device{})

	t.Run("never challenged", func(t *testing.T) {
		store := newStore(t)
		collector := newCollector(t, store, newClock())
		err := collector.Submit(ctx, conn.server, ak.evidence(t, conn, []byte("unissued-nonce-unissued-nonce-00"), goldenPCRs()))
		var challengeErr *peergate.ChallengeError
		require.True(t, errors.As(err, &challengeErr), "Submit = %v", err)
		assert.Zero(t, store.Len())
	})

	t.Run("wrong nonce consumes the challenge", func(t *testing.T) {
		store := newStore(t)
		collector := newCollector(t, store, newClock())
		challenge, err := collector.Challenge(ctx, conn.server)
		require.NoError(t, err)

		err = collector.Submit(ctx, conn.server, ak.evidence(t, conn, []byte("another-nonce-another-nonce-0000"), goldenPCRs()))
		var challengeErr *peergate.ChallengeError
		require.True(t, errors.As(err, &challengeErr), "Submit = %v", err)

		// The nonce cannot be answered after a failed attempt: a guess costs
		// the challenge.
		err = collector.Submit(ctx, conn.server, ak.evidence(t, conn, challenge.Nonce, goldenPCRs()))
		require.True(t, errors.As(err, &challengeErr), "replayed Submit = %v", err)
		assert.Zero(t, store.Len())
	})

	t.Run("expired challenge", func(t *testing.T) {
		store := newStore(t)
		c := newClock()
		collector := newCollector(t, store, c)
		challenge, err := collector.Challenge(ctx, conn.server)
		require.NoError(t, err)
		c.now = challenge.ExpiresAt.Add(time.Second)

		err = collector.Submit(ctx, conn.server, ak.evidence(t, conn, challenge.Nonce, goldenPCRs()))
		var challengeErr *peergate.ChallengeError
		require.True(t, errors.As(err, &challengeErr), "Submit = %v", err)
		assert.Contains(t, challengeErr.Reason, "expired")
		assert.Zero(t, store.Len())
	})

	t.Run("answered twice", func(t *testing.T) {
		store := newStore(t)
		collector := newCollector(t, store, newClock())
		challenge, err := collector.Challenge(ctx, conn.server)
		require.NoError(t, err)
		evidence := ak.evidence(t, conn, challenge.Nonce, goldenPCRs())
		require.NoError(t, collector.Submit(ctx, conn.server, evidence))

		err = collector.Submit(ctx, conn.server, evidence)
		var challengeErr *peergate.ChallengeError
		require.True(t, errors.As(err, &challengeErr), "a nonce must be single-use; Submit = %v", err)
	})
}

func TestCollector_RefusesAConnectionThatCannotBind(t *testing.T) {
	ctx := context.Background()
	p := newPKI(t)
	client, _ := p.clientCert(t, device{})
	conn := p.connect(t, client)
	store := newStore(t)
	collector := newCollector(t, store, newClock())
	challenge, err := collector.Challenge(ctx, conn.server)
	require.NoError(t, err)

	incomplete := *conn.server
	incomplete.HandshakeComplete = false
	err = collector.Submit(ctx, &incomplete, peer.Evidence{Nonce: challenge.Nonce})
	var bindingErr *peer.ChannelBindingError
	require.True(t, errors.As(err, &bindingErr), "Submit = %v", err)
	assert.Zero(t, store.Len(), "unbound evidence is never stored")
}

func TestCollector_BoundsOutstandingChallenges(t *testing.T) {
	ctx := context.Background()
	p := newPKI(t)
	first, _ := p.clientCert(t, device{})
	second, _ := p.clientCert(t, device{})
	firstConn, secondConn := p.connect(t, first), p.connect(t, second)
	c := newClock()
	collector, err := peergate.NewCollector(peergate.CollectorConfig{
		Store:                newStore(t),
		ChallengeTTL:         time.Minute,
		MaxPendingChallenges: 1,
	}, peergate.WithClock(c.Now))
	require.NoError(t, err)

	_, err = collector.Challenge(ctx, firstConn.server)
	require.NoError(t, err)
	_, err = collector.Challenge(ctx, firstConn.server)
	require.NoError(t, err, "re-challenging the same peer replaces its challenge")

	_, err = collector.Challenge(ctx, secondConn.server)
	var capacity *peergate.CapacityError
	require.True(t, errors.As(err, &capacity), "Challenge = %v", err)
	assert.Equal(t, 1, capacity.Limit)

	c.now = c.now.Add(2 * time.Minute)
	_, err = collector.Challenge(ctx, secondConn.server)
	require.NoError(t, err, "an expired challenge makes room")
}

// failingStore refuses every operation, standing in for a shared store that
// is down.
type failingStore struct{}

var errStoreDown = errors.New("store down")

func (failingStore) Put(context.Context, peergate.Record) error { return errStoreDown }
func (failingStore) Get(context.Context, string) (peergate.Record, bool, error) {
	return peergate.Record{}, false, errStoreDown
}
func (failingStore) Delete(context.Context, string) error { return errStoreDown }

func TestCollector_ReportsAStoreFailure(t *testing.T) {
	ctx := context.Background()
	p := newPKI(t)
	client, _ := p.clientCert(t, device{})
	conn := p.connect(t, client)
	ak := p.newAK(t, device{})
	collector := newCollector(t, failingStore{}, newClock())
	challenge, err := collector.Challenge(ctx, conn.server)
	require.NoError(t, err)

	err = collector.Submit(ctx, conn.server, ak.evidence(t, conn, challenge.Nonce, goldenPCRs()))
	var storeErr *peergate.StoreError
	require.True(t, errors.As(err, &storeErr), "Submit = %v", err)
	assert.Equal(t, "put", storeErr.Op)
	assert.ErrorIs(t, err, errStoreDown)
}

func TestCollector_HonoursTheContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	collector := newCollector(t, newStore(t), newClock())
	var ctxErr *peer.ContextError
	_, err := collector.Challenge(ctx, nil)
	require.True(t, errors.As(err, &ctxErr), "Challenge = %v", err)
	err = collector.Submit(ctx, nil, peer.Evidence{})
	require.True(t, errors.As(err, &ctxErr), "Submit = %v", err)
}

func TestNewCollector_RefusesAnUnusableConfiguration(t *testing.T) {
	store := newStore(t)
	cases := map[string]struct {
		cfg   peergate.CollectorConfig
		field string
	}{
		"no store":             {peergate.CollectorConfig{}, "Store"},
		"negative TTL":         {peergate.CollectorConfig{Store: store, ChallengeTTL: -time.Second}, "ChallengeTTL"},
		"negative pending cap": {peergate.CollectorConfig{Store: store, MaxPendingChallenges: -1}, "MaxPendingChallenges"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := peergate.NewCollector(tc.cfg)
			var cfgErr *peergate.ConfigError
			require.True(t, errors.As(err, &cfgErr), "NewCollector = %v", err)
			assert.Equal(t, tc.field, cfgErr.Field)
		})
	}
}
