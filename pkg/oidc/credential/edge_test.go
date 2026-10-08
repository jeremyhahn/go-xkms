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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/audit/audittest"
	"github.com/jeremyhahn/go-xkms/pkg/oidc"
	"github.com/jeremyhahn/go-xkms/pkg/scope"
)

func TestEventsReachAuditAndStopAfterUnsubscribe(t *testing.T) {
	rec := &audittest.Recorder{}
	e := newEnv(t, WithAudit(rec), WithLogger(discardLogger()))
	ctx := context.Background()
	alice := user(tenantA, "alice")
	e.importDue(t, alice, shared("codex"))

	var got []Event
	unsubscribe := e.svc.Subscribe(func(ev Event) { got = append(got, ev) })
	_, err := e.svc.GetAccessToken(ctx, alice, shared("codex"))
	require.NoError(t, err)
	unsubscribe()
	_, err = e.svc.Refresh(ctx, alice, shared("codex"))
	require.NoError(t, err)

	require.Len(t, got, 1, "an unsubscribed function gets no more events")
	assert.Equal(t, EventRefreshed, got[0].Type)
	events := rec.Events()
	require.Len(t, events, 2)
	assert.Equal(t, string(EventRefreshed), events[0].Action)
	assert.Equal(t, "oidc_credential", events[0].Resource)
	assert.Equal(t, tenantA, events[0].Details["tenant"])
}

func TestAuditFailureDoesNotFailRefresh(t *testing.T) {
	e := newEnv(t, WithAudit(&audittest.Failing{Err: errors.New("audit down")}), WithLogger(discardLogger()))
	alice := user(tenantA, "alice")
	e.importDue(t, alice, shared("codex"))
	_, err := e.svc.GetAccessToken(context.Background(), alice, shared("codex"))
	require.NoError(t, err)
}

func TestDeviceLoginEnds(t *testing.T) {
	for code, want := range map[string]error{
		"access_denied": oidc.ErrDeviceAccessDenied,
		"expired_token": oidc.ErrDeviceCodeExpired,
	} {
		t.Run(code, func(t *testing.T) {
			e := newEnv(t)
			ctx := context.Background()
			alice := user(tenantA, "alice")
			_, err := e.svc.Create(ctx, alice, shared("g"), e.customConfig(), nil)
			require.NoError(t, err)
			_, err = e.svc.StartDeviceLogin(ctx, alice, shared("g"))
			require.NoError(t, err)

			e.idp.set(func(f *fakeIdP) { f.deviceError = code })
			_, err = e.svc.PollDeviceLogin(ctx, alice, shared("g"))
			assert.ErrorIs(t, err, want)
			c, err := e.svc.Get(ctx, alice, shared("g"))
			require.NoError(t, err)
			assert.Nil(t, c.DeviceLogin, "an ended device login is cleared")
		})
	}
}

func TestDeviceLoginSlowDown(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	alice := user(tenantA, "alice")
	_, err := e.svc.Create(ctx, alice, shared("g"), e.customConfig(), nil)
	require.NoError(t, err)
	c, err := e.svc.StartDeviceLogin(ctx, alice, shared("g"))
	require.NoError(t, err)
	before := c.DeviceLogin.Interval

	e.idp.set(func(f *fakeIdP) { f.deviceError = "slow_down" })
	c, err = e.svc.PollDeviceLogin(ctx, alice, shared("g"))
	require.NoError(t, err)
	assert.Equal(t, before+oidc.SlowDownStep, c.DeviceLogin.Interval)
}

func TestCorruptRecord(t *testing.T) {
	e := newEnv(t, WithLogger(discardLogger()))
	ctx := context.Background()
	back, err := RegistryBarriers(e.registry).Barrier(tenantA)
	require.NoError(t, err)
	ok, err := back.PutIfAbsent(ctx, tenantA+"/oidc/shared/bad.json", []byte("{not json"))
	require.NoError(t, err)
	require.True(t, ok)

	_, err = e.svc.Get(ctx, user(tenantA, "alice"), shared("bad"))
	assert.ErrorIs(t, err, ErrCorruptRecord)
	_, err = e.svc.RefreshDue(ctx)
	assert.ErrorIs(t, err, ErrCorruptRecord)
	_, err = e.svc.List(ctx, user(tenantA, "alice"), "")
	assert.ErrorIs(t, err, ErrCorruptRecord)
}

func TestRegistryBarriers(t *testing.T) {
	e := newEnv(t)
	b := RegistryBarriers(e.registry)
	assert.ElementsMatch(t, []string{scope.SystemTenant, tenantA, tenantB}, b.Tenants())
	_, err := b.Barrier(scope.SystemTenant)
	require.NoError(t, err)
	_, err = b.Barrier("unknown")
	assert.Error(t, err)

	// The system tenant holds credentials of its own.
	root := platform("root")
	_, err = e.svc.Create(context.Background(), root, shared("platform"), Config{Template: "anthropic"}, &Tokens{AccessToken: "x"})
	require.NoError(t, err)
	list, err := e.svc.List(context.Background(), root, "")
	require.NoError(t, err)
	assert.Equal(t, []string{"platform"}, names(list))
}

func TestStartAndCloseLifecycle(t *testing.T) {
	e := newEnv(t)
	e.svc.Start(0)
	e.svc.Start(time.Millisecond) // a second Start is a no-op
	require.NoError(t, e.svc.Close())
	require.NoError(t, e.svc.Close())
	e.svc.Start(time.Millisecond) // Start after Close is a no-op
	require.NoError(t, e.svc.Close())
}

func TestErrorStrings(t *testing.T) {
	refresh := &RefreshError{Name: "codex", Relogin: true, Reason: "invalid_grant", Err: errors.New("rejected")}
	assert.Contains(t, refresh.Error(), "codex")
	assert.Contains(t, refresh.Error(), "invalid_grant")
	assert.ErrorIs(t, refresh, ErrReloginRequired)
	transient := &RefreshError{Name: "codex", Err: errors.New("down")}
	assert.NotErrorIs(t, transient, ErrReloginRequired)
	assert.Contains(t, transient.Error(), "down")

	cfg := &ConfigError{Detail: "bad", Err: errors.New("cause")}
	assert.Equal(t, "oidc credential: invalid configuration: bad: cause", cfg.Error())
	assert.ErrorIs(t, &ConfigError{}, ErrInvalidConfig)

	rec := &RecordError{Key: "k", Err: errors.New("eof")}
	assert.Contains(t, rec.Error(), "k")
	assert.ErrorIs(t, rec, ErrCorruptRecord)
}

func TestRecordDueRules(t *testing.T) {
	now := time.Now()
	r := &record{Status: StatusActive, Tokens: &oidc.TokenResponse{AccessToken: "opaque", RefreshToken: "rt"}}
	assert.True(t, r.refreshDue(now), "a login never refreshed, with no known expiry, is due")
	r.LastRefresh = now
	assert.False(t, r.refreshDue(now))
	assert.True(t, r.refreshDue(now.Add(unknownExpiryRefreshAge)))

	r.Tokens.Expiry = now.Add(time.Hour)
	r.Config.RefreshMargin = 2 * time.Hour
	assert.True(t, r.refreshDue(now), "a configured margin wider than the lifetime makes it due")
	r.Status = StatusReloginRequired
	assert.False(t, r.refreshDue(now))
}
