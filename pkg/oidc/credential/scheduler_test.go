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
	"net/http"
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

// logWatch is an slog.Handler that hands a test the error the first record
// of each watched message carries, so the test can wait on a failure the
// code only reports in its log.
type logWatch struct {
	watched map[string]chan error // fixed at construction; read only
}

func newLogWatch(messages ...string) *logWatch {
	w := &logWatch{watched: make(map[string]chan error, len(messages))}
	for _, m := range messages {
		w.watched[m] = make(chan error, 1)
	}
	return w
}

func (w *logWatch) Enabled(context.Context, slog.Level) bool { return true }

func (w *logWatch) WithAttrs([]slog.Attr) slog.Handler { return w }

func (w *logWatch) WithGroup(string) slog.Handler { return w }

func (w *logWatch) Handle(_ context.Context, r slog.Record) error {
	ch, ok := w.watched[r.Message]
	if !ok {
		return nil
	}
	var logged error
	r.Attrs(func(a slog.Attr) bool {
		err, isErr := a.Value.Any().(error)
		if isErr {
			logged = err
		}
		return !isErr
	})
	select {
	case ch <- logged:
	default:
	}
	return nil
}

// await returns the error logged with message, failing the test if the
// message is not logged within ten seconds.
func (w *logWatch) await(t *testing.T, message string) error {
	t.Helper()
	timeout := time.NewTimer(10 * time.Second)
	defer timeout.Stop()
	select {
	case err := <-w.watched[message]:
		return err
	case <-timeout.C:
		t.Fatalf("%q was never logged", message)
		return nil
	}
}

const (
	logCampaignFailed = "oidc credential: scheduler campaign failed"
	logRefreshFailed  = "oidc credential: scheduled refresh had failures"
	logLeadershipLost = "oidc credential: scheduler leadership lost"
	logNotRenewed     = "oidc credential: scheduler leadership not renewed"
	logReleaseFailed  = "oidc credential: scheduler lease release failed"
)

// TestSchedulerReportsFailures checks that the scheduler reports each
// failure of its lease and of its refresh pass, and keeps going.
func TestSchedulerReportsFailures(t *testing.T) {
	alice := user(tenantA, "alice")
	newScheduler := func(t *testing.T) (*env, *faultyLeases, *logWatch) {
		t.Helper()
		leases := newFaultyLeases()
		logs := newLogWatch(logCampaignFailed, logRefreshFailed, logLeadershipLost, logNotRenewed, logReleaseFailed)
		return newEnv(t, WithLeases(leases), WithLogger(slog.New(logs))), leases, logs
	}

	t.Run("a refused campaign is retried", func(t *testing.T) {
		e, leases, logs := newScheduler(t)
		e.importDue(t, alice, shared("codex"))
		events := make(chan Event, 8)
		defer e.svc.Subscribe(func(ev Event) { events <- ev })()
		leases.failAcquire.Store(true)

		e.svc.Start(10 * time.Millisecond)
		assert.ErrorIs(t, logs.await(t, logCampaignFailed), errInjected)
		leases.failAcquire.Store(false)
		ev := awaitEvent(t, events, EventRefreshed)
		assert.Equal(t, "codex", ev.Ref.Name, "the next campaign leads and refreshes")
	})

	t.Run("a refused refresh is reported", func(t *testing.T) {
		e, _, logs := newScheduler(t)
		e.importDue(t, alice, shared("codex"))
		e.idp.set(func(f *fakeIdP) { f.failRefresh = http.StatusServiceUnavailable })

		e.svc.Start(10 * time.Millisecond)
		var refreshErr *RefreshError
		require.ErrorAs(t, logs.await(t, logRefreshFailed), &refreshErr)
		assert.Equal(t, "codex", refreshErr.Name)
	})

	t.Run("a lost lease ends the leadership", func(t *testing.T) {
		e, leases, logs := newScheduler(t)
		e.svc.Start(10 * time.Millisecond)
		waitHeld(t, leases.fakeLeases, schedulerLeaseKey)

		leases.revoke(schedulerLeaseKey)
		assert.NoError(t, logs.await(t, logLeadershipLost))
		waitHeld(t, leases.fakeLeases, schedulerLeaseKey)
	})

	t.Run("an unrenewed lease ends the leadership", func(t *testing.T) {
		e, leases, logs := newScheduler(t)
		leases.failRenew.Store(true)
		leases.failRelease.Store(true)

		e.svc.Start(10 * time.Millisecond)
		assert.ErrorIs(t, logs.await(t, logNotRenewed), errInjected)
		assert.ErrorIs(t, logs.await(t, logReleaseFailed), errInjected, "the stepped-down leader still releases its lease")
	})
}
