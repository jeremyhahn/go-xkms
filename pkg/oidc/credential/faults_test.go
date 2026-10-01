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
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/oidc"
)

var errInjected = errors.New("injected barrier fault")

// faultyBackend wraps a real barrier and fails, or loses the race of, the
// guarded writes on demand.
type faultyBackend struct {
	Backend
	failWrites atomic.Bool
	loseCAS    atomic.Bool
	failList   atomic.Bool
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
	if tenantID == tenantA {
		return f.back, nil
	}
	return f.Barriers.Barrier(tenantID)
}

func newFaultyEnv(t *testing.T) (*env, *faultyBackend) {
	t.Helper()
	e := newEnv(t)
	inner, err := RegistryBarriers(e.registry).Barrier(tenantA)
	require.NoError(t, err)
	back := &faultyBackend{Backend: inner}
	svc, err := New(&faultyBarriers{Barriers: RegistryBarriers(e.registry), back: back},
		WithHTTPClient(e.idp.srv.Client()), WithClock(e.clock.now), WithLogger(discardLogger()))
	require.NoError(t, err)
	e.svc = svc
	return e, back
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
