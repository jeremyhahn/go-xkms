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
	"log/slog"
	"net/http"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/oidc"
	"github.com/jeremyhahn/go-xkms/pkg/scope"
)

var errInjected = errors.New("injected barrier fault")

// faultyBackend wraps a real barrier and fails, or loses the race of, the
// guarded writes on demand.
type faultyBackend struct {
	Backend
	failWrites atomic.Bool
	loseCAS    atomic.Bool
	failList   atomic.Bool
	sealed     atomic.Bool // the tenant this backend serves refuses its barrier
}

func (f *faultyBackend) PutIfAbsent(ctx context.Context, key string, value []byte) (bool, error) {
	if f.failWrites.Load() {
		return false, errInjected
	}
	return f.Backend.PutIfAbsent(ctx, key, value)
}

func (f *faultyBackend) CompareAndSwap(ctx context.Context, key string, expected, next []byte) (bool, error) {
	if f.failWrites.Load() {
		return false, errInjected
	}
	if f.loseCAS.Load() {
		return false, nil
	}
	return f.Backend.CompareAndSwap(ctx, key, expected, next)
}

func (f *faultyBackend) CompareAndDelete(ctx context.Context, key string, expected []byte) (bool, error) {
	if f.failWrites.Load() {
		return false, errInjected
	}
	if f.loseCAS.Load() {
		return false, nil
	}
	return f.Backend.CompareAndDelete(ctx, key, expected)
}

func (f *faultyBackend) List(ctx context.Context, prefix string) ([]string, error) {
	if f.failList.Load() {
		return nil, errInjected
	}
	return f.Backend.List(ctx, prefix)
}

// faultyBarriers serves one faultyBackend for tenant A.
type faultyBarriers struct {
	Barriers
	back *faultyBackend
}

func (f *faultyBarriers) Barrier(tenantID string) (Backend, error) {
	switch {
	case tenantID != tenantA:
		return f.Barriers.Barrier(tenantID)
	case f.back.sealed.Load():
		return nil, errInjected
	default:
		return f.back, nil
	}
}

func newFaultyEnv(t *testing.T, opts ...Option) (*env, *faultyBackend) {
	t.Helper()
	e := newEnv(t)
	inner, err := RegistryBarriers(e.registry).Barrier(tenantA)
	require.NoError(t, err)
	back := &faultyBackend{Backend: inner}
	all := append([]Option{WithHTTPClient(e.idp.srv.Client()), WithClock(e.clock.now), WithLogger(discardLogger())}, opts...)
	svc, err := New(&faultyBarriers{Barriers: RegistryBarriers(e.registry), back: back}, all...)
	require.NoError(t, err)
	e.svc = svc
	return e, back
}

// faultyLeases wraps the in-memory lease table and fails, on demand,
// acquiring a lease or renewing or releasing a held one with errInjected.
type faultyLeases struct {
	*fakeLeases
	failAcquire atomic.Bool
	failRenew   atomic.Bool
	failRelease atomic.Bool
}

func newFaultyLeases() *faultyLeases { return &faultyLeases{fakeLeases: newFakeLeases()} }

func (f *faultyLeases) AcquireLease(ctx context.Context, key string, ttl time.Duration) (qrdbsdk.Lease, error) {
	if f.failAcquire.Load() {
		return nil, errInjected
	}
	lease, err := f.fakeLeases.AcquireLease(ctx, key, ttl)
	if err != nil {
		return nil, err
	}
	return &faultyLease{Lease: lease, owner: f}, nil
}

type faultyLease struct {
	qrdbsdk.Lease
	owner *faultyLeases
}

func (l *faultyLease) Renew(ctx context.Context) error {
	if l.owner.failRenew.Load() {
		return errInjected
	}
	return l.Lease.Renew(ctx)
}

func (l *faultyLease) Release(ctx context.Context) error {
	if l.owner.failRelease.Load() {
		return errInjected
	}
	return l.Lease.Release(ctx)
}

// TestLeaseAcquireRefusal checks that a refresh lease the cluster refuses
// stops every write it guards: the refusal is returned and the stored
// credential, the provider and the subscribers see nothing.
func TestLeaseAcquireRefusal(t *testing.T) {
	leases := newFaultyLeases()
	e := newEnv(t, WithLeases(leases))
	ctx := context.Background()
	alice := user(tenantA, "alice")
	e.importDue(t, alice, shared("codex"))
	_, err := e.svc.Create(ctx, alice, shared("device"), e.customConfig(), nil)
	require.NoError(t, err)
	refreshable, err := e.svc.Get(ctx, alice, shared("codex"))
	require.NoError(t, err)
	pending, err := e.svc.Get(ctx, alice, shared("device"))
	require.NoError(t, err)
	events := make(chan Event, 4)
	defer e.svc.Subscribe(func(ev Event) { events <- ev })()

	leases.failAcquire.Store(true)
	_, err = e.svc.Refresh(ctx, alice, shared("codex"))
	assert.ErrorIs(t, err, errInjected, "Refresh")
	_, err = e.svc.StartDeviceLogin(ctx, alice, shared("device"))
	assert.ErrorIs(t, err, errInjected, "StartDeviceLogin")

	after, err := e.svc.Get(ctx, alice, shared("codex"))
	require.NoError(t, err)
	assert.Equal(t, refreshable, after, "a refused refresh leaves the credential as it was")
	after, err = e.svc.Get(ctx, alice, shared("device"))
	require.NoError(t, err)
	assert.Equal(t, pending, after, "a refused device login records no device authorisation")
	assert.Zero(t, e.idp.refreshCount(), "no refresh reaches the provider without the lease")
	select {
	case ev := <-events:
		t.Fatalf("a refused lease emitted %+v", ev)
	default:
	}
}

// TestLeaseReleaseFailureKeepsRefresh checks that a refresh whose lease
// cannot be released still stores its tokens and reports the release.
func TestLeaseReleaseFailureKeepsRefresh(t *testing.T) {
	leases := newFaultyLeases()
	logs := newLogWatch("oidc credential: refresh lease release failed")
	e := newEnv(t, WithLeases(leases), WithLogger(slog.New(logs)))
	ctx := context.Background()
	alice := user(tenantA, "alice")
	e.importDue(t, alice, shared("codex"))

	leases.failRelease.Store(true)
	_, err := e.svc.Refresh(ctx, alice, shared("codex"))
	require.NoError(t, err)
	assert.ErrorIs(t, logs.await(t, "oidc credential: refresh lease release failed"), errInjected)
	tok, err := e.svc.GetAccessToken(ctx, alice, shared("codex"))
	require.NoError(t, err)
	assert.Equal(t, "at-1", tok.AccessToken, "the refreshed token was stored before the release")
}

// TestStartDeviceLoginRefusals checks that a device login the provider
// refuses, or whose stored key cannot build a client, returns its error
// and records no device authorisation.
func TestStartDeviceLoginRefusals(t *testing.T) {
	ctx := context.Background()
	alice := user(tenantA, "alice")

	t.Run("provider refuses device authorisation", func(t *testing.T) {
		e := newEnv(t)
		_, err := e.svc.Create(ctx, alice, shared("g"), e.customConfig(), nil)
		require.NoError(t, err)
		e.idp.set(func(f *fakeIdP) { f.refuseDevice = "unauthorized_client" })

		_, err = e.svc.StartDeviceLogin(ctx, alice, shared("g"))
		assert.ErrorIs(t, err, oidc.ErrDeviceAuthorizationFailed)
		var tokenErr *oidc.TokenRequestError
		require.ErrorAs(t, err, &tokenErr)
		assert.Equal(t, "unauthorized_client", tokenErr.Code)
		c, err := e.svc.Get(ctx, alice, shared("g"))
		require.NoError(t, err)
		assert.Nil(t, c.DeviceLogin, "a refused authorisation records no device login")
	})

	t.Run("stored DPoP key is corrupt", func(t *testing.T) {
		e := newEnv(t)
		e.importDue(t, alice, shared("g"))
		back, err := RegistryBarriers(e.registry).Barrier(tenantA)
		require.NoError(t, err)
		k, err := recordKey(Ref{TenantID: tenantA, Scope: scope.Tenant, Name: "g"})
		require.NoError(t, err)
		cur, err := load(ctx, back, k)
		require.NoError(t, err)
		next := cur.rec.clone()
		next.Tokens.DPoPKeyPEM = "not a key"
		_, err = cur.replace(ctx, next, time.Now())
		require.NoError(t, err)

		_, err = e.svc.StartDeviceLogin(ctx, alice, shared("g"))
		require.Error(t, err)
		c, err := e.svc.Get(ctx, alice, shared("g"))
		require.NoError(t, err)
		assert.Nil(t, c.DeviceLogin, "a login that cannot build its client records nothing")
	})
}

// TestRefreshDueReportsFailures checks how one pass of the refresh sweep
// treats a sealed tenant, a refused refresh and an expiry it cannot record.
func TestRefreshDueReportsFailures(t *testing.T) {
	ctx := context.Background()
	alice := user(tenantA, "alice")

	t.Run("a sealed tenant is skipped", func(t *testing.T) {
		e, back := newFaultyEnv(t)
		e.importDue(t, user(tenantB, "bob"), shared("codex"))
		back.sealed.Store(true)

		n, err := e.svc.RefreshDue(ctx)
		require.NoError(t, err, "a sealed tenant is retried on a later pass")
		assert.Equal(t, 1, n, "the other tenants are still refreshed")
	})

	t.Run("a refused refresh is reported", func(t *testing.T) {
		e := newEnv(t)
		e.importDue(t, alice, shared("codex"))
		e.idp.set(func(f *fakeIdP) { f.failRefresh = http.StatusServiceUnavailable })

		n, err := e.svc.RefreshDue(ctx)
		var refreshErr *RefreshError
		require.ErrorAs(t, err, &refreshErr)
		assert.Equal(t, "codex", refreshErr.Name)
		assert.False(t, refreshErr.Relogin, "an unavailable provider needs no new login")
		assert.Zero(t, n)
	})

	expiring := func(t *testing.T, e *env) {
		t.Helper()
		_, err := e.svc.Create(ctx, alice, shared("claude"), Config{Template: "anthropic"}, &Tokens{AccessToken: "sk-ant-oat01-x"})
		require.NoError(t, err)
		e.clock.advance(366 * 24 * time.Hour)
	}
	assertStillActive := func(t *testing.T, e *env) {
		t.Helper()
		c, err := e.svc.Get(ctx, alice, shared("claude"))
		require.NoError(t, err)
		assert.Equal(t, StatusActive, c.Status, "an expiry that was not recorded leaves the credential active")
	}

	t.Run("an expiry the lease refuses", func(t *testing.T) {
		leases := newFaultyLeases()
		e := newEnv(t, WithLeases(leases))
		expiring(t, e)
		leases.failAcquire.Store(true)

		_, err := e.svc.RefreshDue(ctx)
		assert.ErrorIs(t, err, errInjected)
		_, err = e.svc.GetAccessToken(ctx, alice, shared("claude"))
		assert.ErrorIs(t, err, errInjected, "an expired token is never served while its expiry cannot be recorded")
		assertStillActive(t, e)
	})

	t.Run("an expiry whose write fails", func(t *testing.T) {
		e, back := newFaultyEnv(t)
		expiring(t, e)
		back.failWrites.Store(true)

		_, err := e.svc.RefreshDue(ctx)
		assert.ErrorIs(t, err, errInjected)
		assertStillActive(t, e)
	})
}

func TestBarrierFaults(t *testing.T) {
	e, back := newFaultyEnv(t)
	ctx := context.Background()
	alice := user(tenantA, "alice")
	tokens := Tokens{AccessToken: "at", RefreshToken: e.idp.currentToken(), ExpiresAt: time.Now().Add(time.Minute)}

	back.failWrites.Store(true)
	_, err := e.svc.Create(ctx, alice, shared("x"), e.customConfig(), &tokens)
	assert.ErrorIs(t, err, errInjected)
	back.failWrites.Store(false)
	_, err = e.svc.Create(ctx, alice, shared("x"), e.customConfig(), &tokens)
	require.NoError(t, err)

	back.loseCAS.Store(true)
	_, err = e.svc.ImportTokens(ctx, alice, shared("x"), tokens)
	assert.ErrorIs(t, err, ErrConcurrentUpdate)
	assert.ErrorIs(t, e.svc.Delete(ctx, alice, shared("x")), ErrConcurrentUpdate)
	_, err = e.svc.Refresh(ctx, alice, shared("x"))
	assert.ErrorIs(t, err, ErrConcurrentUpdate, "a refresh whose write loses the race reports it")
	back.loseCAS.Store(false)

	back.failWrites.Store(true)
	_, err = e.svc.StartDeviceLogin(ctx, alice, shared("x"))
	assert.ErrorIs(t, err, errInjected)
	back.failWrites.Store(false)

	back.failList.Store(true)
	_, err = e.svc.List(ctx, alice, "")
	assert.ErrorIs(t, err, errInjected)
	n, err := e.svc.RefreshDue(ctx)
	assert.NoError(t, err, "an unreadable tenant is skipped until it can be read")
	assert.Zero(t, n)
	back.failList.Store(false)

	_, err = e.svc.ImportTokens(ctx, alice, shared("missing"), tokens)
	assert.ErrorIs(t, err, ErrNotFound)
	_, err = e.svc.ImportTokens(ctx, alice, shared("x"), Tokens{})
	assert.ErrorIs(t, err, ErrInvalidTokens)
	assert.ErrorIs(t, e.svc.Delete(ctx, alice, shared("missing")), ErrNotFound)
	_, err = e.svc.Refresh(ctx, alice, shared("missing"))
	assert.ErrorIs(t, err, ErrNotFound)
}

// TestDeviceLoginRefusals checks that a device login the caller, the store
// or the provider refuses returns its typed error and leaves the pending
// device login in place, with no tokens recorded.
func TestDeviceLoginRefusals(t *testing.T) {
	alice := user(tenantA, "alice")
	tests := []struct {
		name   string
		ref    Ref
		start  bool // StartDeviceLogin rather than PollDeviceLogin
		setup  func(e *env, back *faultyBackend)
		assert func(t *testing.T, err error)
	}{
		{
			name:   "start with an invalid name",
			ref:    shared(""),
			start:  true,
			assert: func(t *testing.T, err error) { assert.ErrorIs(t, err, ErrInvalidName) },
		},
		{
			name:   "poll with an invalid name",
			ref:    shared(""),
			assert: func(t *testing.T, err error) { assert.ErrorIs(t, err, ErrInvalidName) },
		},
		{
			name:   "poll a missing credential",
			ref:    shared("missing"),
			assert: func(t *testing.T, err error) { assert.ErrorIs(t, err, ErrNotFound) },
		},
		{
			name: "provider answers an unknown poll error",
			ref:  shared("g"),
			setup: func(e *env, _ *faultyBackend) {
				e.idp.set(func(f *fakeIdP) { f.deviceError = "invalid_grant" })
			},
			assert: func(t *testing.T, err error) {
				var tokenErr *oidc.TokenRequestError
				require.ErrorAs(t, err, &tokenErr)
				assert.Equal(t, "invalid_grant", tokenErr.Code)
			},
		},
		{
			name: "denied login whose clearing write fails",
			ref:  shared("g"),
			setup: func(e *env, back *faultyBackend) {
				e.idp.set(func(f *fakeIdP) { f.deviceError = "access_denied" })
				back.failWrites.Store(true)
			},
			assert: func(t *testing.T, err error) { assert.ErrorIs(t, err, errInjected) },
		},
		{
			name: "granted login whose write fails",
			ref:  shared("g"),
			setup: func(e *env, back *faultyBackend) {
				e.idp.set(func(f *fakeIdP) { f.deviceGranted = true })
				back.failWrites.Store(true)
			},
			assert: func(t *testing.T, err error) { assert.ErrorIs(t, err, errInjected) },
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e, back := newFaultyEnv(t)
			ctx := context.Background()
			_, err := e.svc.Create(ctx, alice, shared("g"), e.customConfig(), nil)
			require.NoError(t, err)
			_, err = e.svc.StartDeviceLogin(ctx, alice, shared("g"))
			require.NoError(t, err)
			if tt.setup != nil {
				tt.setup(e, back)
			}

			if tt.start {
				_, err = e.svc.StartDeviceLogin(ctx, alice, tt.ref)
			} else {
				_, err = e.svc.PollDeviceLogin(ctx, alice, tt.ref)
			}
			tt.assert(t, err)

			back.failWrites.Store(false)
			c, err := e.svc.Get(ctx, alice, shared("g"))
			require.NoError(t, err)
			assert.Equal(t, StatusPending, c.Status, "a refused login records no tokens")
			assert.NotNil(t, c.DeviceLogin, "a refused login keeps the device login pending")
			_, err = e.svc.GetAccessToken(ctx, alice, shared("g"))
			assert.ErrorIs(t, err, ErrNoLogin, "a refused login leaves no access token to serve")
		})
	}
}

// TestDPoPBoundCredentialRefreshes proves a credential whose tokens are
// DPoP-bound refreshes with its stored key.
func TestDPoPBoundCredentialRefreshes(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	alice := user(tenantA, "alice")
	e.importDue(t, alice, shared("dpop"))

	key, err := oidc.GenerateDPoPKey()
	require.NoError(t, err)
	pem, err := key.SerializePrivateKey()
	require.NoError(t, err)
	back, err := RegistryBarriers(e.registry).Barrier(tenantA)
	require.NoError(t, err)
	k, err := recordKey(Ref{TenantID: tenantA, Scope: "tenant", Name: "dpop"})
	require.NoError(t, err)
	cur, err := load(ctx, back, k)
	require.NoError(t, err)
	next := cur.rec.clone()
	next.Tokens.DPoPKeyPEM = pem
	_, err = cur.replace(ctx, next, time.Now())
	require.NoError(t, err)

	tok, err := e.svc.GetAccessToken(ctx, alice, shared("dpop"))
	require.NoError(t, err)
	assert.Equal(t, "at-1", tok.AccessToken)

	cur, err = load(ctx, back, k)
	require.NoError(t, err)
	assert.Equal(t, pem, cur.rec.Tokens.DPoPKeyPEM, "the DPoP key survives the refresh")

	next = cur.rec.clone()
	next.Tokens.DPoPKeyPEM = "not a key"
	next.Tokens.Expiry = time.Now()
	_, err = cur.replace(ctx, next, time.Now())
	require.NoError(t, err)
	_, err = e.svc.Refresh(ctx, alice, shared("dpop"))
	assert.Error(t, err, "a corrupt DPoP key fails the refresh")
}
