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

package rest

import (
	"context"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	pkgwebauthn "github.com/jeremyhahn/go-xkms/pkg/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewWebAuthnStores(t *testing.T) {
	tests := []struct {
		name string
		cfg  *WebAuthnStoresConfig
	}{
		{
			name: "nil config uses defaults",
			cfg:  nil,
		},
		{
			name: "custom session TTL",
			cfg: &WebAuthnStoresConfig{
				SessionTTL: 10 * time.Minute,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			stores := NewWebAuthnStores(tt.cfg)

			assert.NotNil(t, stores)
			assert.NotNil(t, stores.UserStore())
			assert.NotNil(t, stores.SessionStore())
			assert.NotNil(t, stores.CredentialStore())
		})
	}
}

func TestWebAuthnStores_UserStore(t *testing.T) {
	stores := NewWebAuthnStores(nil)
	ctx := context.Background()

	// Create a user
	user, err := stores.UserStore().Create(ctx, "test@example.com", "Test User")
	require.NoError(t, err)
	assert.NotNil(t, user)

	// Retrieve the user
	retrieved, err := stores.UserStore().GetByEmail(ctx, "test@example.com")
	require.NoError(t, err)
	assert.Equal(t, user.WebAuthnID(), retrieved.WebAuthnID())
}

func TestWebAuthnStores_SessionStore(t *testing.T) {
	// The TTL is measured against an injected clock, so "still valid" and
	// "expired" are exact rather than probable. The Get below used to require
	// success within 100ms of the Save two statements earlier -- an assertion
	// about how busy the machine was, not about the store (go-xkms#287).
	clock := newFakeClock()
	stores := NewWebAuthnStores(&WebAuthnStoresConfig{
		SessionTTL: 100 * time.Millisecond,
		Clock:      clock.Now,
	})
	ctx := context.Background()

	// Save a session
	sessionData := &webauthn.SessionData{
		Challenge: "test-challenge",
		UserID:    []byte{1, 2, 3},
	}
	sessionID, err := stores.SessionStore().Save(ctx, sessionData)
	require.NoError(t, err)
	assert.NotEmpty(t, sessionID)

	// Retrieve the session
	retrieved, err := stores.SessionStore().Get(ctx, sessionID)
	require.NoError(t, err)
	assert.Equal(t, sessionData.Challenge, retrieved.Challenge)

	// Past the TTL, exactly and without waiting for it.
	clock.Advance(101 * time.Millisecond)

	// Session should be expired
	_, err = stores.SessionStore().Get(ctx, sessionID)
	assert.ErrorIs(t, err, pkgwebauthn.ErrSessionExpired)
}

func TestWebAuthnStores_CredentialStore(t *testing.T) {
	stores := NewWebAuthnStores(nil)
	ctx := context.Background()

	userID := []byte{1, 2, 3}
	cred := &pkgwebauthn.Credential{
		ID:        []byte{4, 5, 6},
		UserID:    userID,
		PublicKey: []byte{7, 8, 9},
	}

	// Save a credential
	err := stores.CredentialStore().Save(ctx, cred)
	require.NoError(t, err)

	// Retrieve credentials by user ID
	creds, err := stores.CredentialStore().GetByUserID(ctx, userID)
	require.NoError(t, err)
	assert.Len(t, creds, 1)
	assert.Equal(t, cred.ID, creds[0].ID)

	// Retrieve by credential ID
	retrieved, err := stores.CredentialStore().GetByCredentialID(ctx, cred.ID)
	require.NoError(t, err)
	assert.Equal(t, cred.ID, retrieved.ID)
}

func TestWebAuthnStores_CleanupSessions(t *testing.T) {
	clock := newFakeClock()
	stores := NewWebAuthnStores(&WebAuthnStoresConfig{
		SessionTTL: 50 * time.Millisecond,
		Clock:      clock.Now,
	})
	ctx := context.Background()

	// Save some sessions
	_, _ = stores.SessionStore().Save(ctx, &webauthn.SessionData{Challenge: "1"})
	_, _ = stores.SessionStore().Save(ctx, &webauthn.SessionData{Challenge: "2"})
	_, _ = stores.SessionStore().Save(ctx, &webauthn.SessionData{Challenge: "3"})

	// Past the TTL for all three.
	clock.Advance(51 * time.Millisecond)

	// Cleanup should remove all expired sessions
	removed := stores.CleanupSessions()
	assert.Equal(t, 3, removed)
}

func TestWebAuthnStores_StartCleanupRoutine(t *testing.T) {
	// This one deliberately keeps REAL time. The cleanup goroutine ticks on a
	// real time.Ticker, so a fake store clock would mean the session never
	// expires by the routine's reckoning and the routine would never remove it
	// -- the test would wait forever for an event that cannot happen. What was
	// wrong here was not the clock but the synchronisation: it slept 150ms and
	// assumed a goroutine on a 60ms tick had fired, which Go does not promise.
	//
	// So the TTL and interval stay short and real, and the test waits on the
	// EVENT -- the store becoming empty -- through the already-exported Count().
	// The old assertion could not observe the event at all, which its own
	// comment admitted: "We can't directly check the count, but the cleanup ran".
	store := pkgwebauthn.NewMemorySessionStoreWithTTL(20 * time.Millisecond)
	stores := &WebAuthnStores{
		users:       pkgwebauthn.NewMemoryUserStore(),
		sessions:    store,
		credentials: pkgwebauthn.NewMemoryCredentialStore(),
	}
	ctx := context.Background()

	// Save a session
	_, err := stores.SessionStore().Save(ctx, &webauthn.SessionData{Challenge: "test"})
	require.NoError(t, err)
	require.Equal(t, 1, store.Count(), "the session should be present before the routine runs")

	// Start cleanup routine with short interval
	cancel := stores.StartCleanupRoutine(ctx, 5*time.Millisecond)
	defer cancel()

	// Wait for the routine to have removed the expired session.
	waitFor(t, "the cleanup routine to remove the expired session", func() bool {
		return store.Count() == 0
	})

	// And a manual pass now finds nothing left to remove.
	assert.Equal(t, 0, stores.CleanupSessions())
}

func TestWebAuthnStores_Clear(t *testing.T) {
	stores := NewWebAuthnStores(nil)
	ctx := context.Background()

	// Add some data
	_, _ = stores.UserStore().Create(ctx, "test@example.com", "Test")
	_, _ = stores.SessionStore().Save(ctx, &webauthn.SessionData{Challenge: "test"})
	_ = stores.CredentialStore().Save(ctx, &pkgwebauthn.Credential{
		ID:     []byte{1},
		UserID: []byte{1},
	})

	// Clear all stores
	stores.Clear()

	// Verify everything is cleared
	_, err := stores.UserStore().GetByEmail(ctx, "test@example.com")
	assert.ErrorIs(t, err, pkgwebauthn.ErrUserNotFound)

	creds, err := stores.CredentialStore().GetByUserID(ctx, []byte{1})
	require.NoError(t, err)
	assert.Empty(t, creds)
}

func TestWebAuthnStores_CleanupSessions_NonMemoryStore(t *testing.T) {
	// This tests the case where the session store is not a MemorySessionStore
	// For now we just test that it doesn't panic
	stores := NewWebAuthnStores(nil)

	// Force a non-matching type by creating a mock scenario
	// In this case we just test the normal flow works
	removed := stores.CleanupSessions()
	assert.GreaterOrEqual(t, removed, 0)
}
