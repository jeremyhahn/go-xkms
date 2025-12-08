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

package user

import (
	"context"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jeremyhahn/go-keychain/pkg/storage"
	pkgwebauthn "github.com/jeremyhahn/go-keychain/pkg/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestWebAuthnAdapters(t *testing.T) (*WebAuthnUserAdapter, *WebAuthnSessionAdapter, *WebAuthnCredentialAdapter, *FileStore, func()) {
	t.Helper()
	backend, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	store, err := NewFileStore(backend, WithCleanupInterval(100*time.Millisecond))
	require.NoError(t, err)

	userAdapter := NewWebAuthnUserAdapter(store)
	sessionAdapter := NewWebAuthnSessionAdapter(store, 5*time.Minute)
	credentialAdapter := NewWebAuthnCredentialAdapter(store)

	return userAdapter, sessionAdapter, credentialAdapter, store, func() {
		_ = store.Close()
	}
}

// WebAuthnUserAdapter tests

func TestNewWebAuthnUserAdapter(t *testing.T) {
	backend, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	store, err := NewFileStore(backend)
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	t.Run("default role is admin", func(t *testing.T) {
		adapter := NewWebAuthnUserAdapter(store)
		assert.NotNil(t, adapter)
		assert.Equal(t, RoleAdmin, adapter.defaultRole)
	})

	t.Run("with custom default role", func(t *testing.T) {
		adapter := NewWebAuthnUserAdapter(store, WithDefaultRole(RoleUser))
		assert.Equal(t, RoleUser, adapter.defaultRole)
	})
}

func TestWebAuthnUserAdapter_GetByID(t *testing.T) {
	userAdapter, _, _, store, cleanup := newTestWebAuthnAdapters(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("returns user by ID", func(t *testing.T) {
		created, err := store.Create(ctx, "getbyid@example.com", "Test User", RoleUser)
		require.NoError(t, err)

		user, err := userAdapter.GetByID(ctx, created.ID)
		require.NoError(t, err)
		assert.Equal(t, "getbyid@example.com", user.WebAuthnName())
	})

	t.Run("returns ErrUserNotFound for nonexistent", func(t *testing.T) {
		_, err := userAdapter.GetByID(ctx, []byte("nonexistent"))
		assert.ErrorIs(t, err, pkgwebauthn.ErrUserNotFound)
	})
}

func TestWebAuthnUserAdapter_GetByEmail(t *testing.T) {
	userAdapter, _, _, store, cleanup := newTestWebAuthnAdapters(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("returns user by email", func(t *testing.T) {
		_, err := store.Create(ctx, "email@example.com", "Test User", RoleUser)
		require.NoError(t, err)

		user, err := userAdapter.GetByEmail(ctx, "email@example.com")
		require.NoError(t, err)
		assert.Equal(t, "email@example.com", user.WebAuthnName())
	})

	t.Run("returns ErrUserNotFound for nonexistent", func(t *testing.T) {
		_, err := userAdapter.GetByEmail(ctx, "nonexistent@example.com")
		assert.ErrorIs(t, err, pkgwebauthn.ErrUserNotFound)
	})
}

func TestWebAuthnUserAdapter_Create(t *testing.T) {
	userAdapter, _, _, _, cleanup := newTestWebAuthnAdapters(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("creates user successfully", func(t *testing.T) {
		user, err := userAdapter.Create(ctx, "create@example.com", "Created User")
		require.NoError(t, err)
		assert.Equal(t, "create@example.com", user.WebAuthnName())
		assert.Equal(t, "Created User", user.WebAuthnDisplayName())
	})

	t.Run("returns ErrUserAlreadyExists for duplicate", func(t *testing.T) {
		_, err := userAdapter.Create(ctx, "duplicate@example.com", "First")
		require.NoError(t, err)

		_, err = userAdapter.Create(ctx, "duplicate@example.com", "Second")
		assert.ErrorIs(t, err, pkgwebauthn.ErrUserAlreadyExists)
	})
}

func TestWebAuthnUserAdapter_Save(t *testing.T) {
	userAdapter, _, _, store, cleanup := newTestWebAuthnAdapters(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("saves user successfully", func(t *testing.T) {
		created, err := store.Create(ctx, "save@example.com", "Original", RoleUser)
		require.NoError(t, err)

		// Wrap in WebAuthnUser and modify
		webAuthnUser := &WebAuthnUser{user: created}
		created.DisplayName = "Updated"

		err = userAdapter.Save(ctx, webAuthnUser)
		require.NoError(t, err)

		// Verify update
		retrieved, err := store.GetByID(ctx, created.ID)
		require.NoError(t, err)
		assert.Equal(t, "Updated", retrieved.DisplayName)
	})

	t.Run("returns error for wrong type", func(t *testing.T) {
		// Create a mock user that doesn't implement *WebAuthnUser
		mockUser := &mockPkgWebAuthnUser{}
		err := userAdapter.Save(ctx, mockUser)
		assert.ErrorIs(t, err, ErrInvalidCredential)
	})
}

func TestWebAuthnUserAdapter_Delete(t *testing.T) {
	userAdapter, _, _, store, cleanup := newTestWebAuthnAdapters(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("deletes user successfully", func(t *testing.T) {
		// Create two admins so we can delete one
		user1, err := store.Create(ctx, "delete1@example.com", "Delete1", RoleAdmin)
		require.NoError(t, err)
		_, err = store.Create(ctx, "delete2@example.com", "Delete2", RoleAdmin)
		require.NoError(t, err)

		err = userAdapter.Delete(ctx, user1.ID)
		require.NoError(t, err)

		_, err = store.GetByID(ctx, user1.ID)
		assert.ErrorIs(t, err, ErrUserNotFound)
	})

	t.Run("returns ErrUserNotFound for nonexistent", func(t *testing.T) {
		err := userAdapter.Delete(ctx, []byte("nonexistent"))
		assert.ErrorIs(t, err, pkgwebauthn.ErrUserNotFound)
	})
}

// WebAuthnUser tests

func TestWebAuthnUser_Methods(t *testing.T) {
	user := &User{
		ID:          []byte("user-id"),
		Username:    "test@example.com",
		DisplayName: "Test User",
		Credentials: []Credential{
			{
				ID:              []byte("cred-1"),
				PublicKey:       []byte("pubkey-1"),
				AttestationType: "none",
				AAGUID:          []byte("aaguid"),
				SignCount:       5,
			},
		},
	}
	webAuthnUser := &WebAuthnUser{user: user}

	t.Run("WebAuthnID", func(t *testing.T) {
		assert.Equal(t, []byte("user-id"), webAuthnUser.WebAuthnID())
	})

	t.Run("WebAuthnName", func(t *testing.T) {
		assert.Equal(t, "test@example.com", webAuthnUser.WebAuthnName())
	})

	t.Run("WebAuthnDisplayName", func(t *testing.T) {
		assert.Equal(t, "Test User", webAuthnUser.WebAuthnDisplayName())
	})

	t.Run("WebAuthnCredentials", func(t *testing.T) {
		creds := webAuthnUser.WebAuthnCredentials()
		require.Len(t, creds, 1)
		assert.Equal(t, []byte("cred-1"), creds[0].ID)
	})

	t.Run("Email", func(t *testing.T) {
		assert.Equal(t, "test@example.com", webAuthnUser.Email())
	})

	t.Run("DisplayName", func(t *testing.T) {
		assert.Equal(t, "Test User", webAuthnUser.DisplayName())
	})

	t.Run("User", func(t *testing.T) {
		assert.Equal(t, user, webAuthnUser.User())
	})
}

func TestWebAuthnUser_AddCredential(t *testing.T) {
	user := &User{Credentials: []Credential{}}
	webAuthnUser := &WebAuthnUser{user: user}

	lastUsed := time.Now().UTC()
	cred := &pkgwebauthn.Credential{
		ID:              []byte("new-cred"),
		PublicKey:       []byte("pubkey"),
		AttestationType: "direct",
		Authenticator: pkgwebauthn.AuthenticatorData{
			AAGUID:    []byte("aaguid"),
			SignCount: 10,
		},
		CreatedAt:  time.Now().UTC(),
		LastUsedAt: lastUsed,
	}

	webAuthnUser.AddCredential(cred)

	require.Len(t, user.Credentials, 1)
	assert.Equal(t, []byte("new-cred"), user.Credentials[0].ID)
	assert.Equal(t, "WebAuthn Credential", user.Credentials[0].Name)
	assert.NotNil(t, user.Credentials[0].LastUsedAt)
}

func TestWebAuthnUser_AddCredential_NoLastUsed(t *testing.T) {
	user := &User{Credentials: []Credential{}}
	webAuthnUser := &WebAuthnUser{user: user}

	cred := &pkgwebauthn.Credential{
		ID:        []byte("new-cred"),
		CreatedAt: time.Now().UTC(),
		// LastUsedAt is zero
	}

	webAuthnUser.AddCredential(cred)

	require.Len(t, user.Credentials, 1)
	assert.Nil(t, user.Credentials[0].LastUsedAt)
}

func TestWebAuthnUser_UpdateCredential(t *testing.T) {
	user := &User{
		Credentials: []Credential{
			{ID: []byte("cred-1"), SignCount: 5},
		},
	}
	webAuthnUser := &WebAuthnUser{user: user}

	cred := &pkgwebauthn.Credential{
		ID: []byte("cred-1"),
		Authenticator: pkgwebauthn.AuthenticatorData{
			SignCount: 15,
		},
	}

	webAuthnUser.UpdateCredential(cred)

	assert.Equal(t, uint32(15), user.Credentials[0].SignCount)
}

func TestWebAuthnUser_SessionData(t *testing.T) {
	user := &User{}
	webAuthnUser := &WebAuthnUser{user: user}

	assert.Nil(t, webAuthnUser.SessionData())

	testData := []byte("session-data")
	webAuthnUser.SetSessionData(testData)
	assert.Equal(t, testData, webAuthnUser.SessionData())
}

// WebAuthnSessionAdapter tests

func TestNewWebAuthnSessionAdapter(t *testing.T) {
	backend, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	store, err := NewFileStore(backend)
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	t.Run("with custom TTL", func(t *testing.T) {
		adapter := NewWebAuthnSessionAdapter(store, 10*time.Minute)
		assert.Equal(t, 10*time.Minute, adapter.ttl)
	})

	t.Run("with zero TTL uses default", func(t *testing.T) {
		adapter := NewWebAuthnSessionAdapter(store, 0)
		assert.Equal(t, 5*time.Minute, adapter.ttl)
	})
}

func TestWebAuthnSessionAdapter_SaveAndGet(t *testing.T) {
	_, sessionAdapter, _, _, cleanup := newTestWebAuthnAdapters(t)
	defer cleanup()

	ctx := context.Background()

	sessionData := &webauthn.SessionData{
		Challenge: "test-challenge",
		UserID:    []byte("user-id"),
		AllowedCredentialIDs: [][]byte{
			[]byte("cred-1"),
			[]byte("cred-2"),
		},
	}

	sessionID, err := sessionAdapter.Save(ctx, sessionData)
	require.NoError(t, err)
	assert.NotEmpty(t, sessionID)

	retrieved, err := sessionAdapter.Get(ctx, sessionID)
	require.NoError(t, err)
	assert.Equal(t, "test-challenge", retrieved.Challenge)
	assert.Equal(t, []byte("user-id"), retrieved.UserID)
}

func TestWebAuthnSessionAdapter_GetNotFound(t *testing.T) {
	_, sessionAdapter, _, _, cleanup := newTestWebAuthnAdapters(t)
	defer cleanup()

	ctx := context.Background()

	_, err := sessionAdapter.Get(ctx, "nonexistent")
	assert.ErrorIs(t, err, pkgwebauthn.ErrSessionNotFound)
}

func TestWebAuthnSessionAdapter_Delete(t *testing.T) {
	_, sessionAdapter, _, _, cleanup := newTestWebAuthnAdapters(t)
	defer cleanup()

	ctx := context.Background()

	sessionData := &webauthn.SessionData{Challenge: "test"}
	sessionID, err := sessionAdapter.Save(ctx, sessionData)
	require.NoError(t, err)

	err = sessionAdapter.Delete(ctx, sessionID)
	require.NoError(t, err)

	_, err = sessionAdapter.Get(ctx, sessionID)
	assert.ErrorIs(t, err, pkgwebauthn.ErrSessionNotFound)
}

// WebAuthnCredentialAdapter tests

func TestWebAuthnCredentialAdapter_Save(t *testing.T) {
	_, _, credAdapter, store, cleanup := newTestWebAuthnAdapters(t)
	defer cleanup()

	ctx := context.Background()

	user, err := store.Create(ctx, "credsave@example.com", "Cred Save", RoleUser)
	require.NoError(t, err)

	lastUsed := time.Now().UTC()
	cred := &pkgwebauthn.Credential{
		ID:              []byte("new-cred"),
		UserID:          user.ID,
		PublicKey:       []byte("pubkey"),
		AttestationType: "none",
		Authenticator: pkgwebauthn.AuthenticatorData{
			AAGUID:    []byte("aaguid"),
			SignCount: 1,
		},
		CreatedAt:  time.Now().UTC(),
		LastUsedAt: lastUsed,
	}

	err = credAdapter.Save(ctx, cred)
	require.NoError(t, err)

	// Verify credential was added
	retrieved, err := store.GetByID(ctx, user.ID)
	require.NoError(t, err)
	require.Len(t, retrieved.Credentials, 1)
	assert.Equal(t, []byte("new-cred"), retrieved.Credentials[0].ID)
}

func TestWebAuthnCredentialAdapter_GetByUserID(t *testing.T) {
	_, _, credAdapter, store, cleanup := newTestWebAuthnAdapters(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("returns credentials for user", func(t *testing.T) {
		user, err := store.Create(ctx, "getcreds@example.com", "Get Creds", RoleUser)
		require.NoError(t, err)

		// Add credential to user
		user.AddCredential(&Credential{
			ID:        []byte("cred-1"),
			PublicKey: []byte("pubkey"),
			CreatedAt: time.Now().UTC(),
		})
		err = store.Update(ctx, user)
		require.NoError(t, err)

		creds, err := credAdapter.GetByUserID(ctx, user.ID)
		require.NoError(t, err)
		require.Len(t, creds, 1)
		assert.Equal(t, []byte("cred-1"), creds[0].ID)
	})

	t.Run("returns empty for nonexistent user", func(t *testing.T) {
		creds, err := credAdapter.GetByUserID(ctx, []byte("nonexistent"))
		require.NoError(t, err)
		assert.Len(t, creds, 0)
	})
}

func TestWebAuthnCredentialAdapter_GetByCredentialID(t *testing.T) {
	_, _, credAdapter, store, cleanup := newTestWebAuthnAdapters(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("returns credential by ID", func(t *testing.T) {
		user, err := store.Create(ctx, "getcredid@example.com", "Get Cred ID", RoleUser)
		require.NoError(t, err)

		lastUsed := time.Now().UTC()
		user.AddCredential(&Credential{
			ID:         []byte("find-me"),
			PublicKey:  []byte("pubkey"),
			CreatedAt:  time.Now().UTC(),
			LastUsedAt: &lastUsed,
		})
		err = store.Update(ctx, user)
		require.NoError(t, err)

		cred, err := credAdapter.GetByCredentialID(ctx, []byte("find-me"))
		require.NoError(t, err)
		assert.Equal(t, []byte("find-me"), cred.ID)
		assert.Equal(t, user.ID, cred.UserID)
	})

	t.Run("returns ErrCredentialNotFound for nonexistent", func(t *testing.T) {
		_, err := credAdapter.GetByCredentialID(ctx, []byte("nonexistent"))
		assert.ErrorIs(t, err, pkgwebauthn.ErrCredentialNotFound)
	})
}

func TestWebAuthnCredentialAdapter_Update(t *testing.T) {
	_, _, credAdapter, store, cleanup := newTestWebAuthnAdapters(t)
	defer cleanup()

	ctx := context.Background()

	user, err := store.Create(ctx, "updatecred@example.com", "Update Cred", RoleUser)
	require.NoError(t, err)

	user.AddCredential(&Credential{
		ID:        []byte("update-cred"),
		SignCount: 5,
	})
	err = store.Update(ctx, user)
	require.NoError(t, err)

	cred := &pkgwebauthn.Credential{
		ID:     []byte("update-cred"),
		UserID: user.ID,
		Authenticator: pkgwebauthn.AuthenticatorData{
			SignCount: 15,
		},
	}

	err = credAdapter.Update(ctx, cred)
	require.NoError(t, err)

	// Verify update
	retrieved, err := store.GetByID(ctx, user.ID)
	require.NoError(t, err)
	assert.Equal(t, uint32(15), retrieved.Credentials[0].SignCount)
}

func TestWebAuthnCredentialAdapter_Delete(t *testing.T) {
	_, _, credAdapter, store, cleanup := newTestWebAuthnAdapters(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("deletes credential successfully", func(t *testing.T) {
		user, err := store.Create(ctx, "deletecred@example.com", "Delete Cred", RoleUser)
		require.NoError(t, err)

		user.AddCredential(&Credential{ID: []byte("delete-me")})
		err = store.Update(ctx, user)
		require.NoError(t, err)

		err = credAdapter.Delete(ctx, []byte("delete-me"))
		require.NoError(t, err)

		// Verify deletion
		retrieved, err := store.GetByID(ctx, user.ID)
		require.NoError(t, err)
		assert.Len(t, retrieved.Credentials, 0)
	})

	t.Run("returns ErrCredentialNotFound for nonexistent", func(t *testing.T) {
		err := credAdapter.Delete(ctx, []byte("nonexistent"))
		assert.ErrorIs(t, err, pkgwebauthn.ErrCredentialNotFound)
	})
}

func TestWebAuthnCredentialAdapter_DeleteByUserID(t *testing.T) {
	_, _, credAdapter, store, cleanup := newTestWebAuthnAdapters(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("deletes all credentials for user", func(t *testing.T) {
		user, err := store.Create(ctx, "deleteall@example.com", "Delete All", RoleUser)
		require.NoError(t, err)

		user.AddCredential(&Credential{ID: []byte("cred-1")})
		user.AddCredential(&Credential{ID: []byte("cred-2")})
		err = store.Update(ctx, user)
		require.NoError(t, err)

		err = credAdapter.DeleteByUserID(ctx, user.ID)
		require.NoError(t, err)

		// Verify all credentials deleted
		retrieved, err := store.GetByID(ctx, user.ID)
		require.NoError(t, err)
		assert.Len(t, retrieved.Credentials, 0)
	})

	t.Run("no error for nonexistent user", func(t *testing.T) {
		err := credAdapter.DeleteByUserID(ctx, []byte("nonexistent"))
		assert.NoError(t, err)
	})
}

// Mock types for testing

type mockPkgWebAuthnUser struct{}

func (m *mockPkgWebAuthnUser) WebAuthnID() []byte          { return nil }
func (m *mockPkgWebAuthnUser) WebAuthnName() string        { return "" }
func (m *mockPkgWebAuthnUser) WebAuthnDisplayName() string { return "" }
func (m *mockPkgWebAuthnUser) WebAuthnCredentials() []webauthn.Credential {
	return nil
}
func (m *mockPkgWebAuthnUser) AddCredential(*pkgwebauthn.Credential)    {}
func (m *mockPkgWebAuthnUser) UpdateCredential(*pkgwebauthn.Credential) {}
func (m *mockPkgWebAuthnUser) SetSessionData([]byte)                    {}
func (m *mockPkgWebAuthnUser) SessionData() []byte                      { return nil }
func (m *mockPkgWebAuthnUser) Email() string                            { return "" }
func (m *mockPkgWebAuthnUser) DisplayName() string                      { return "" }
