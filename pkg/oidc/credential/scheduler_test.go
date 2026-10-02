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

package credential

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	qrdbtransport "github.com/jeremyhahn/go-qrdb/sdk/go/transport"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// awaitEvent waits for an event of typ, failing the test after a bound.
func awaitEvent(t *testing.T, events <-chan Event, typ EventType) Event {
	t.Helper()
	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()
	for {
		select {
		case ev := <-events:
			if ev.Type == typ {
				return ev
			}
		case <-timeout.C:
			t.Fatalf("no %s event", typ)
			return Event{}
		}
	}
}

// TestSchedulerRefreshesBeforeExpiry proves the scheduler refreshes a
// credential inside its refresh margin with no consumer asking for it.
func TestSchedulerRefreshesBeforeExpiry(t *testing.T) {
	e := newEnv(t)
	alice := user(tenantA, "alice")
	e.importDue(t, alice, shared("codex"))
	events := make(chan Event, 8)
	defer e.svc.Subscribe(func(ev Event) { events <- ev })()

	e.svc.Start(10 * time.Millisecond)
	ev := awaitEvent(t, events, EventRefreshed)
	assert.Equal(t, "codex", ev.Ref.Name)
	assert.Equal(t, tenantA, ev.Ref.TenantID)

	c, err := e.svc.Get(context.Background(), alice, shared("codex"))
	require.NoError(t, err)
	assert.True(t, c.ExpiresAt.After(time.Now().Add(30*time.Minute)), "the new token is fresh")
	assert.Equal(t, 1, e.idp.refreshCount(), "a fresh token is not refreshed again")
}

// TestSchedulerOnlyLeaderRefreshes runs two services, as two nodes would,
// over one lease table: only the lease holder refreshes, and the other
// takes over once the leader's lease lapses.
func TestSchedulerOnlyLeaderRefreshes(t *testing.T) {
	leases := newFakeLeases()
	e := newEnv(t, WithLeases(leases))
	follower, err := New(RegistryBarriers(e.registry), WithLeases(leases),
		WithHTTPClient(e.idp.srv.Client()), WithClock(e.clock.now))
	require.NoError(t, err)
	defer func() { require.NoError(t, follower.Close()) }()

	leaderEvents := make(chan Event, 8)
	followerEvents := make(chan Event, 8)
	defer e.svc.Subscribe(func(ev Event) { leaderEvents <- ev })()
	defer follower.Subscribe(func(ev Event) { followerEvents <- ev })()

	// The leader takes the lease before the follower campaigns.
	lease, err := leases.AcquireLease(context.Background(), schedulerLeaseKey, time.Minute)
	require.NoError(t, err)
	require.NoError(t, lease.Release(context.Background()))
	e.svc.Start(10 * time.Millisecond)
	waitHeld(t, leases, schedulerLeaseKey)
	follower.Start(10 * time.Millisecond)

	alice := user(tenantA, "alice")
	e.importDue(t, alice, shared("codex"))
	awaitEvent(t, leaderEvents, EventRefreshed)
	select {
	case ev := <-followerEvents:
		t.Fatalf("the follower refreshed: %+v", ev)
	default:
	}

	// The leader's lease lapses; the follower takes over and refreshes the
	// next credential that falls due.
	require.NoError(t, e.svc.Close())
	leases.revoke(schedulerLeaseKey)
	e.importDue(t, alice, shared("second"))
	ev := awaitEvent(t, followerEvents, EventRefreshed)
	assert.Equal(t, "second", ev.Ref.Name)
}

// waitHeld waits until key is held in leases.
func waitHeld(t *testing.T, leases *fakeLeases, key string) {
	t.Helper()
	ticker := time.NewTicker(time.Millisecond)
	defer ticker.Stop()
	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()
	for {
		leases.mu.Lock()
		_, ok := leases.held[key]
		leases.mu.Unlock()
		if ok {
			return
		}
		select {
		case <-ticker.C:
		case <-timeout.C:
			t.Fatalf("%s never held", key)
		}
	}
}

// scriptedLeases answers AcquireLease from a script of errors.
type scriptedLeases struct {
	errs  []error
	calls int
}

func (s *scriptedLeases) AcquireLease(ctx context.Context, key string, ttl time.Duration) (qrdbsdk.Lease, error) {
	i := s.calls
	s.calls++
	if i < len(s.errs) && s.errs[i] != nil {
		return nil, s.errs[i]
	}
	return newFakeLeases().AcquireLease(ctx, key, ttl)
}

func TestLockerRetriesHeldLease(t *testing.T) {
	leases := &scriptedLeases{errs: []error{&qrdbsdk.LeaseHeldError{Key: "k"}, &qrdbsdk.LeaseHeldError{Key: "k"}}}
	l := newLocker(leases, discardLogger())
	unlock, err := l.lock(context.Background(), "k")
	require.NoError(t, err)
	assert.Equal(t, 3, leases.calls, "a held lease is retried until it is free")
	unlock()
}

// TestLockerStandaloneNode proves a node that refuses the lease family with
// a typed capability error (a lease-less backend) serializes in-process, and
// asks qrdb only once.
func TestLockerStandaloneNode(t *testing.T) {
	leases := &scriptedLeases{errs: []error{&qrdbtransport.CapabilityUnsupportedError{Message: "lease: requires mode: raft"}}}
	l := newLocker(leases, discardLogger())
	for range 3 {
		unlock, err := l.lock(context.Background(), "k")
		require.NoError(t, err)
		unlock()
	}
	assert.Equal(t, 1, leases.calls)
	assert.True(t, l.standalone.Load())
}

func TestLockerSurfacesLeaseFailure(t *testing.T) {
	boom := errors.New("raft unavailable")
	l := newLocker(&scriptedLeases{errs: []error{boom}}, discardLogger())
	_, err := l.lock(context.Background(), "k")
	assert.ErrorIs(t, err, boom)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	held := newLocker(&scriptedLeases{errs: []error{&qrdbsdk.LeaseHeldError{Key: "k"}}}, discardLogger())
	_, err = held.lock(ctx, "k")
	assert.ErrorIs(t, err, context.Canceled)
}

func discardLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }
