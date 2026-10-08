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
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMemorySessionStore(t *testing.T) {
	ctx := context.Background()
	store := NewMemorySessionStore()

	// Save session
	sessionData := &webauthn.SessionData{
		Challenge: "test-challenge",
		UserID:    []byte{1, 2, 3},
	}
	sessionID, err := store.Save(ctx, sessionData)
	require.NoError(t, err)
	assert.NotEmpty(t, sessionID)
	assert.Equal(t, 1, store.Count())

	// Get session
	retrieved, err := store.Get(ctx, sessionID)
	require.NoError(t, err)
	assert.Equal(t, sessionData.Challenge, retrieved.Challenge)
	assert.Equal(t, sessionData.UserID, retrieved.UserID)

	// Get non-existent
	_, err = store.Get(ctx, "nonexistent")
	assert.ErrorIs(t, err, ErrSessionNotFound)

	// Delete session
	err = store.Delete(ctx, sessionID)
	require.NoError(t, err)
	assert.Equal(t, 0, store.Count())

	// Delete non-existent (should not error)
	err = store.Delete(ctx, "nonexistent")
	require.NoError(t, err)

	// Clear
	_, _ = store.Save(ctx, &webauthn.SessionData{})
	_, _ = store.Save(ctx, &webauthn.SessionData{})
	assert.Equal(t, 2, store.Count())
	store.Clear()
	assert.Equal(t, 0, store.Count())
}

func TestMemorySessionStore_Expiration(t *testing.T) {
	ctx := context.Background()
	store := NewMemorySessionStoreWithTTL(100 * time.Millisecond)

	sessionData := &webauthn.SessionData{
		Challenge: "test",
	}
	sessionID, err := store.Save(ctx, sessionData)
	require.NoError(t, err)

	// Should be retrievable immediately
	_, err = store.Get(ctx, sessionID)
	require.NoError(t, err)

	// Wait for expiration
	time.Sleep(150 * time.Millisecond)

	// Should be expired
	_, err = store.Get(ctx, sessionID)
	assert.ErrorIs(t, err, ErrSessionExpired)
}

func TestMemorySessionStore_Cleanup(t *testing.T) {
	ctx := context.Background()
	store := NewMemorySessionStoreWithTTL(50 * time.Millisecond)

	// Add some sessions
	_, _ = store.Save(ctx, &webauthn.SessionData{Challenge: "1"})
	_, _ = store.Save(ctx, &webauthn.SessionData{Challenge: "2"})
	_, _ = store.Save(ctx, &webauthn.SessionData{Challenge: "3"})

	assert.Equal(t, 3, store.Count())

	// Wait for expiration
	time.Sleep(100 * time.Millisecond)

	// Cleanup
	removed := store.Cleanup()
	assert.Equal(t, 3, removed)
	assert.Equal(t, 0, store.Count())
}
