// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-keychain.
//
// go-keychain is dual-licensed:
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

func TestMemoryUserStore(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryUserStore()

	// Create user
	user, err := store.Create(ctx, "test@example.com", "Test User")
	require.NoError(t, err)
	assert.NotNil(t, user)
	assert.Equal(t, "test@example.com", user.Email())
	assert.Equal(t, "Test User", user.DisplayName())
	assert.Equal(t, 1, store.Count())

	// Get by ID
	retrieved, err := store.GetByID(ctx, user.WebAuthnID())
	require.NoError(t, err)
	assert.Equal(t, user.WebAuthnID(), retrieved.WebAuthnID())

	// Get by email
	retrieved, err = store.GetByEmail(ctx, "test@example.com")
	require.NoError(t, err)
	assert.Equal(t, user.WebAuthnID(), retrieved.WebAuthnID())

	// Get non-existent by ID
	_, err = store.GetByID(ctx, []byte{1, 2, 3})
	assert.ErrorIs(t, err, ErrUserNotFound)

	// Get non-existent by email
	_, err = store.GetByEmail(ctx, "nonexistent@example.com")
	assert.ErrorIs(t, err, ErrUserNotFound)

	// Create duplicate
	_, err = store.Create(ctx, "test@example.com", "Another User")
	assert.ErrorIs(t, err, ErrUserAlreadyExists)

	// Update user
	user.AddCredential(&Credential{ID: []byte{1, 2, 3}})
	err = store.Save(ctx, user)
	require.NoError(t, err)

	retrieved, err = store.GetByID(ctx, user.WebAuthnID())
	require.NoError(t, err)
	assert.Len(t, retrieved.(*DefaultUser).Credentials(), 1)

	// Delete user
	err = store.Delete(ctx, user.WebAuthnID())
	require.NoError(t, err)
	assert.Equal(t, 0, store.Count())

	// Delete non-existent
	err = store.Delete(ctx, []byte{1, 2, 3})
	assert.ErrorIs(t, err, ErrUserNotFound)

	// Clear
	_, _ = store.Create(ctx, "user1@example.com", "User 1")
	_, _ = store.Create(ctx, "user2@example.com", "User 2")
	assert.Equal(t, 2, store.Count())
	store.Clear()
	assert.Equal(t, 0, store.Count())
}

func TestMemoryUserStore_SaveInvalidUser(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryUserStore()

	// Try to save a non-DefaultUser type
	mockUser := &mockUser{id: []byte{1, 2, 3}}
	err := store.Save(ctx, mockUser)
	assert.ErrorIs(t, err, ErrInvalidRequest)
}

type mockUser struct {
	id []byte
}

func (m *mockUser) WebAuthnID() []byte                         { return m.id }
func (m *mockUser) WebAuthnName() string                       { return "mock" }
func (m *mockUser) WebAuthnDisplayName() string                { return "Mock" }
func (m *mockUser) WebAuthnCredentials() []webauthn.Credential { return nil }
func (m *mockUser) AddCredential(cred *Credential)             {}
func (m *mockUser) UpdateCredential(cred *Credential)          {}
func (m *mockUser) SetSessionData(data []byte)                 {}
func (m *mockUser) SessionData() []byte                        { return nil }
func (m *mockUser) Email() string                              { return "mock@example.com" }
func (m *mockUser) DisplayName() string                        { return "Mock" }

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

func TestMemoryCredentialStore(t *testing.T) {
	ctx := context.Background()
	store := NewMemoryCredentialStore()

	userID := []byte{1, 2, 3}
	cred := &Credential{
		ID:        []byte{4, 5, 6},
		UserID:    userID,
		PublicKey: []byte{7, 8, 9},
	}

	// Save credential
	err := store.Save(ctx, cred)
	require.NoError(t, err)
	assert.Equal(t, 1, store.Count())

	// Save duplicate
	err = store.Save(ctx, cred)
	assert.ErrorIs(t, err, ErrCredentialAlreadyExists)

	// Get by user ID
	creds, err := store.GetByUserID(ctx, userID)
	require.NoError(t, err)
	assert.Len(t, creds, 1)
	assert.Equal(t, cred.ID, creds[0].ID)

	// Get by user ID (non-existent user)
	creds, err = store.GetByUserID(ctx, []byte{99})
	require.NoError(t, err)
	assert.Empty(t, creds)

	// Get by credential ID
	retrieved, err := store.GetByCredentialID(ctx, cred.ID)
	require.NoError(t, err)
	assert.Equal(t, cred.ID, retrieved.ID)

	// Get by credential ID (non-existent)
	_, err = store.GetByCredentialID(ctx, []byte{99})
	assert.ErrorIs(t, err, ErrCredentialNotFound)

	// Update credential
	cred.Authenticator.SignCount = 10
	err = store.Update(ctx, cred)
	require.NoError(t, err)

	retrieved, err = store.GetByCredentialID(ctx, cred.ID)
	require.NoError(t, err)
	assert.Equal(t, uint32(10), retrieved.Authenticator.SignCount)

	// Update non-existent
	err = store.Update(ctx, &Credential{ID: []byte{99}})
	assert.ErrorIs(t, err, ErrCredentialNotFound)

	// Add another credential for same user
	cred2 := &Credential{
		ID:     []byte{10, 11, 12},
		UserID: userID,
	}
	err = store.Save(ctx, cred2)
	require.NoError(t, err)

	creds, err = store.GetByUserID(ctx, userID)
	require.NoError(t, err)
	assert.Len(t, creds, 2)

	// Delete credential
	err = store.Delete(ctx, cred.ID)
	require.NoError(t, err)

	creds, err = store.GetByUserID(ctx, userID)
	require.NoError(t, err)
	assert.Len(t, creds, 1)

	// Delete non-existent
	err = store.Delete(ctx, []byte{99})
	assert.ErrorIs(t, err, ErrCredentialNotFound)

	// Delete by user ID
	err = store.DeleteByUserID(ctx, userID)
	require.NoError(t, err)
	assert.Equal(t, 0, store.Count())

	// Delete by user ID (non-existent user - should not error)
	err = store.DeleteByUserID(ctx, []byte{99})
	require.NoError(t, err)

	// Clear
	_ = store.Save(ctx, &Credential{ID: []byte{1}, UserID: []byte{1}})
	_ = store.Save(ctx, &Credential{ID: []byte{2}, UserID: []byte{2}})
	assert.Equal(t, 2, store.Count())
	store.Clear()
	assert.Equal(t, 0, store.Count())
}
