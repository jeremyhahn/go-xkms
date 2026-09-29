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

package webauthn

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testClock is an injectable clock a test advances instead of sleeping.
type testClock struct{ now atomic.Int64 }

func newTestClock() *testClock {
	c := &testClock{}
	c.now.Store(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano())
	return c
}

// Now reports the clock's current time.
func (c *testClock) Now() time.Time { return time.Unix(0, c.now.Load()) }

// Advance moves the clock forward by d.
func (c *testClock) Advance(d time.Duration) { c.now.Add(int64(d)) }

// saveSession saves one ceremony session.
func saveSession(s *MemorySessionStore) error {
	_, err := s.Save(context.Background(), &webauthn.SessionData{Challenge: "c"})
	return err
}

// fillSessions saves n ceremony sessions.
func fillSessions(t *testing.T, s *MemorySessionStore, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		require.NoError(t, saveSession(s))
	}
}

// TestMemorySessionStore_CapRefusesThenRecoversAfterSweep proves a full store
// refuses a new ceremony with *SessionLimitError while every held session is
// live, and admits new ceremonies again once a sweep has removed the expired
// ones.
func TestMemorySessionStore_CapRefusesThenRecoversAfterSweep(t *testing.T) {
	clock := newTestClock()
	store := NewMemorySessionStoreWithTTL(time.Minute, WithClock(clock.Now), WithMaxSessions(3))
	fillSessions(t, store, 3)

	err := saveSession(store)
	var limitErr *SessionLimitError
	require.ErrorAs(t, err, &limitErr)
	assert.Equal(t, 3, limitErr.Limit)
	assert.True(t, IsSessionLimit(err))
	assert.Contains(t, err.Error(), "3")
	assert.Equal(t, 3, store.Count())

	clock.Advance(2 * time.Minute)
	assert.Equal(t, 3, store.Cleanup())
	assert.Equal(t, 0, store.Count())
	require.NoError(t, saveSession(store))
}

// TestMemorySessionStore_FullStoreSweepsExpiredOnSave proves a store whose
// owner runs no sweeper still recovers: at the cap, Save removes expired
// sessions itself before deciding to refuse.
func TestMemorySessionStore_FullStoreSweepsExpiredOnSave(t *testing.T) {
	clock := newTestClock()
	store := NewMemorySessionStoreWithTTL(time.Minute, WithClock(clock.Now), WithMaxSessions(2))
	fillSessions(t, store, 2)

	clock.Advance(2 * time.Minute)
	require.NoError(t, saveSession(store), "expired sessions must not hold the cap")
	assert.Equal(t, 1, store.Count())
}

// TestMemorySessionStore_DefaultCap pins the default cap, and that a
// non-positive WithMaxSessions keeps it.
func TestMemorySessionStore_DefaultCap(t *testing.T) {
	assert.Equal(t, DefaultMaxSessions, NewMemorySessionStore().maxSessions)
	assert.Equal(t, DefaultMaxSessions, NewMemorySessionStore(WithMaxSessions(0)).maxSessions)
	assert.Equal(t, DefaultMaxSessions, (&MemorySessionStore{}).limit())
}

// TestSweepSessions_RemovesExpiredAndStops proves the sweeper removes expired
// sessions on its own, keeps live ones, and returns once its context ends.
func TestSweepSessions_RemovesExpiredAndStops(t *testing.T) {
	clock := newTestClock()
	store := NewMemorySessionStoreWithTTL(time.Minute, WithClock(clock.Now))
	fillSessions(t, store, 3)
	clock.Advance(2 * time.Minute)
	fillSessions(t, store, 1) // live

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		SweepSessions(ctx, store, time.Millisecond)
		close(done)
	}()

	require.Eventually(t, func() bool { return store.Count() == 1 }, 5*time.Second, time.Millisecond,
		"the sweeper must remove the three expired sessions and keep the live one")

	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("SweepSessions did not return after its context was cancelled")
	}
}

// nonCleaningStore is a SessionStore without a Cleanup method.
type nonCleaningStore struct{ SessionStore }

// TestSweepSessions_StoreWithoutCleanupReturns proves the sweeper does not
// hold a goroutine for a store that expires sessions itself.
func TestSweepSessions_StoreWithoutCleanupReturns(t *testing.T) {
	done := make(chan struct{})
	go func() {
		SweepSessions(context.Background(), nonCleaningStore{}, time.Millisecond)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("SweepSessions blocked on a store that has no Cleanup")
	}
}

// TestService_SweepSessions proves the service sweeps its own store, with a
// non-positive interval selecting the default.
func TestService_SweepSessions(t *testing.T) {
	clock := newTestClock()
	store := NewMemorySessionStoreWithTTL(time.Minute, WithClock(clock.Now))
	svc, err := NewService(ServiceParams{
		Config:          &Config{RPID: "kms.example.com", RPDisplayName: "xkms", RPOrigins: []string{"https://kms.example.com"}},
		UserStore:       NewMemoryUserStore(),
		SessionStore:    store,
		CredentialStore: NewMemoryCredentialStore(),
	})
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	svc.SweepSessions(ctx, 0) // returns at once: the context is already done

	fillSessions(t, store, 2)
	clock.Advance(2 * time.Minute)
	ctx, cancel = context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		svc.SweepSessions(ctx, time.Millisecond)
		close(done)
	}()
	require.Eventually(t, func() bool { return store.Count() == 0 }, 5*time.Second, time.Millisecond)
	cancel()
	<-done
}

// TestService_BeginLoginRefusedWhenSessionStoreFull proves the service
// surfaces the store's refusal as a *SessionLimitError a transport can map.
func TestService_BeginLoginRefusedWhenSessionStoreFull(t *testing.T) {
	store := NewMemorySessionStore(WithMaxSessions(1))
	svc, err := NewService(ServiceParams{
		Config:          &Config{RPID: "kms.example.com", RPDisplayName: "xkms", RPOrigins: []string{"https://kms.example.com"}},
		UserStore:       NewMemoryUserStore(),
		SessionStore:    store,
		CredentialStore: NewMemoryCredentialStore(),
	})
	require.NoError(t, err)

	_, _, err = svc.BeginLogin(context.Background(), nil)
	require.NoError(t, err, "a discoverable login fits under the cap")
	_, _, err = svc.BeginLogin(context.Background(), nil)
	assert.True(t, IsSessionLimit(err), "want a session-limit error, got %v", err)
}
