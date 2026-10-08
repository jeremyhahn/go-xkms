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
	"sync"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type boundKey struct{}

// bindMarker is a CallContext that marks the context it derives.
func bindMarker(ctx context.Context) (context.Context, error) {
	return context.WithValue(ctx, boundKey{}, true), nil
}

var errBind = errors.New("no service principal")

func failingBind(context.Context) (context.Context, error) { return nil, errBind }

// recordingLeases is a fakeLeases that records each lease call and whether
// it ran on a context bindMarker derived.
type recordingLeases struct {
	*fakeLeases
	mu      sync.Mutex
	calls   []string
	unbound []string
}

func newRecordingLeases() *recordingLeases {
	return &recordingLeases{fakeLeases: newFakeLeases()}
}

func (r *recordingLeases) record(ctx context.Context, op string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, op)
	if ctx.Value(boundKey{}) == nil {
		r.unbound = append(r.unbound, op)
	}
}

func (r *recordingLeases) snapshot() (calls, unbound []string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.calls...), append([]string(nil), r.unbound...)
}

func (r *recordingLeases) AcquireLease(ctx context.Context, key string, ttl time.Duration) (qrdbsdk.Lease, error) {
	r.record(ctx, "acquire")
	lease, err := r.fakeLeases.AcquireLease(ctx, key, ttl)
	if err != nil {
		return nil, err
	}
	return &recordingLease{Lease: lease, rec: r}, nil
}

type recordingLease struct {
	qrdbsdk.Lease
	rec *recordingLeases
}

func (l *recordingLease) Renew(ctx context.Context) error {
	l.rec.record(ctx, "renew")
	return l.Lease.Renew(ctx)
}

func (l *recordingLease) Release(ctx context.Context) error {
	l.rec.record(ctx, "release")
	return l.Lease.Release(ctx)
}

// TestWithLeaseContext_LockRunsBound proves a refresh lock's acquire and
// release run on the context WithLeaseContext derives.
func TestWithLeaseContext_LockRunsBound(t *testing.T) {
	leases := newRecordingLeases()
	e := newEnv(t, WithLeases(leases), WithLeaseContext(bindMarker))

	unlock, err := e.svc.locks.lock(context.Background(), "k")
	require.NoError(t, err)
	unlock()

	calls, unbound := leases.snapshot()
	assert.Equal(t, []string{"acquire", "release"}, calls)
	assert.Empty(t, unbound)
}

// TestWithLeaseContext_BindErrorFailsLock proves a bind failure fails the
// lock before any lease call.
func TestWithLeaseContext_BindErrorFailsLock(t *testing.T) {
	leases := newRecordingLeases()
	e := newEnv(t, WithLeases(leases), WithLeaseContext(failingBind))

	unlock, err := e.svc.locks.lock(context.Background(), "k")
	require.ErrorIs(t, err, errBind)
	assert.Nil(t, unlock)
	calls, _ := leases.snapshot()
	assert.Empty(t, calls)
}

// TestWithLeaseContext_SchedulerRunsBound proves the scheduler's leadership
// lease -- acquire, renew, release -- runs on the bound context.
func TestWithLeaseContext_SchedulerRunsBound(t *testing.T) {
	leases := newRecordingLeases()
	e := newEnv(t, WithLeases(leases), WithLeaseContext(bindMarker))

	e.svc.Start(5 * time.Millisecond)
	require.Eventually(t, func() bool {
		calls, _ := leases.snapshot()
		return len(calls) >= 2
	}, 10*time.Second, time.Millisecond, "the leader renews its lease")
	require.NoError(t, e.svc.Close())

	calls, unbound := leases.snapshot()
	assert.Equal(t, "acquire", calls[0])
	assert.Contains(t, calls, "renew")
	assert.Contains(t, calls, "release")
	assert.Empty(t, unbound)
}

// TestWithLeaseContext_SchedulerBindErrorStops proves a scheduler that
// cannot bind its context makes no lease call and stops cleanly.
func TestWithLeaseContext_SchedulerBindErrorStops(t *testing.T) {
	leases := newRecordingLeases()
	e := newEnv(t, WithLeases(leases), WithLeaseContext(failingBind))

	e.svc.Start(5 * time.Millisecond)
	require.NoError(t, e.svc.Close())

	calls, _ := leases.snapshot()
	assert.Empty(t, calls)
}
