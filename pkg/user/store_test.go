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

package user

import (
	"context"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestStore(t *testing.T) (*FileStore, func()) {
	t.Helper()
	backend, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	store, err := NewFileStore(backend, WithCleanupInterval(100*time.Millisecond))
	require.NoError(t, err)

	return store, func() {
		_ = store.Close()
	}
}

func TestNewFileStore(t *testing.T) {
	t.Run("with nil backend", func(t *testing.T) {
		_, err := NewFileStore(nil)
		assert.Error(t, err)
		assert.Contains(t, err.Error(), "backend cannot be nil")
	})

	t.Run("with valid backend", func(t *testing.T) {
		backend, err := storage.NewMemoryBackend()
		require.NoError(t, err)

		store, err := NewFileStore(backend)
		require.NoError(t, err)
		assert.NotNil(t, store)
		defer func() { _ = store.Close() }()
	})
}

func TestFileStore_Create(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("creates user successfully", func(t *testing.T) {
		user, err := store.Create(ctx, "admin@example.com", "Admin User", RoleAdmin, "")
		require.NoError(t, err)
		require.NotNil(t, user)

		assert.NotEmpty(t, user.ID)
		assert.Equal(t, "admin@example.com", user.Username)
		assert.Equal(t, "Admin User", user.DisplayName)
		assert.Equal(t, RoleAdmin, user.Role)
		assert.True(t, user.Enabled)
		assert.False(t, user.CreatedAt.IsZero())
	})

	t.Run("normalizes username to lowercase", func(t *testing.T) {
		user, err := store.Create(ctx, "TEST@EXAMPLE.COM", "Test", RoleUser, "")
		require.NoError(t, err)
		assert.Equal(t, "test@example.com", user.Username)
	})

	t.Run("rejects empty username", func(t *testing.T) {
		_, err := store.Create(ctx, "", "Display", RoleUser, "")
		assert.ErrorIs(t, err, ErrInvalidUsername)
	})

	t.Run("rejects invalid role", func(t *testing.T) {
		_, err := store.Create(ctx, "invalid@example.com", "Display", Role("invalid"), "")
		assert.ErrorIs(t, err, ErrInvalidRole)
	})

	t.Run("rejects duplicate username", func(t *testing.T) {
		_, err := store.Create(ctx, "duplicate@example.com", "First", RoleUser, "")
		require.NoError(t, err)

		_, err = store.Create(ctx, "duplicate@example.com", "Second", RoleUser, "")
		assert.ErrorIs(t, err, ErrUserAlreadyExists)
	})
}

func TestFileStore_Create_WithTenantID(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("sets tenant ID on created user", func(t *testing.T) {
		user, err := store.Create(ctx, "tenant-user@example.com", "Tenant User", RoleUser, "tenant-abc")
		require.NoError(t, err)
		require.NotNil(t, user)

		assert.Equal(t, "tenant-abc", user.TenantID)
		assert.Equal(t, "tenant-user@example.com", user.Username)
		assert.Equal(t, RoleUser, user.Role)
	})

	t.Run("persists tenant ID through storage round-trip", func(t *testing.T) {
		user, err := store.Create(ctx, "persist-tenant@example.com", "Persist", RoleOperator, "tenant-xyz")
		require.NoError(t, err)

		retrieved, err := store.GetByID(ctx, user.ID)
		require.NoError(t, err)
		assert.Equal(t, "tenant-xyz", retrieved.TenantID)
	})

	t.Run("empty tenant ID creates system-level user", func(t *testing.T) {
		user, err := store.Create(ctx, "system-user@example.com", "System", RoleAdmin, "")
		require.NoError(t, err)
		assert.Empty(t, user.TenantID)
	})
}

func TestFileStore_GetByID(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("returns user by ID", func(t *testing.T) {
		created, err := store.Create(ctx, "getbyid@example.com", "Test", RoleUser, "")
		require.NoError(t, err)

		retrieved, err := store.GetByID(ctx, created.ID)
		require.NoError(t, err)
		assert.Equal(t, created.Username, retrieved.Username)
		assert.Equal(t, created.DisplayName, retrieved.DisplayName)
	})

	t.Run("returns error for nonexistent ID", func(t *testing.T) {
		_, err := store.GetByID(ctx, []byte("nonexistent"))
		assert.ErrorIs(t, err, ErrUserNotFound)
	})
}

func TestFileStore_GetByUsername(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("returns user by username", func(t *testing.T) {
		created, err := store.Create(ctx, "getbyname@example.com", "Test", RoleOperator, "")
		require.NoError(t, err)

		retrieved, err := store.GetByUsername(ctx, "getbyname@example.com")
		require.NoError(t, err)
		assert.Equal(t, created.ID, retrieved.ID)
		assert.Equal(t, RoleOperator, retrieved.Role)
	})

	t.Run("normalizes username lookup", func(t *testing.T) {
		_, err := store.Create(ctx, "normalized@example.com", "Test", RoleUser, "")
		require.NoError(t, err)

		retrieved, err := store.GetByUsername(ctx, "  NORMALIZED@EXAMPLE.COM  ")
		require.NoError(t, err)
		assert.Equal(t, "normalized@example.com", retrieved.Username)
	})

	t.Run("returns error for nonexistent username", func(t *testing.T) {
		_, err := store.GetByUsername(ctx, "nonexistent@example.com")
		assert.ErrorIs(t, err, ErrUserNotFound)
	})
}

func TestFileStore_Update(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("updates user successfully", func(t *testing.T) {
		user, err := store.Create(ctx, "update@example.com", "Original", RoleUser, "")
		require.NoError(t, err)

		user.DisplayName = "Updated"
		user.Role = RoleOperator
		err = store.Update(ctx, user)
		require.NoError(t, err)

		retrieved, err := store.GetByID(ctx, user.ID)
		require.NoError(t, err)
		assert.Equal(t, "Updated", retrieved.DisplayName)
		assert.Equal(t, RoleOperator, retrieved.Role)
	})

	t.Run("returns error for nonexistent user", func(t *testing.T) {
		user := &User{ID: []byte("nonexistent")}
		err := store.Update(ctx, user)
		assert.ErrorIs(t, err, ErrUserNotFound)
	})
}

func TestFileStore_Delete(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("deletes user successfully", func(t *testing.T) {
		// Create two admins so we can delete one
		user1, err := store.Create(ctx, "delete1@example.com", "Delete1", RoleAdmin, "")
		require.NoError(t, err)
		_, err = store.Create(ctx, "delete2@example.com", "Delete2", RoleAdmin, "")
		require.NoError(t, err)

		err = store.Delete(ctx, user1.ID)
		require.NoError(t, err)

		_, err = store.GetByID(ctx, user1.ID)
		assert.ErrorIs(t, err, ErrUserNotFound)
	})

	t.Run("returns error for nonexistent user", func(t *testing.T) {
		err := store.Delete(ctx, []byte("nonexistent"))
		assert.ErrorIs(t, err, ErrUserNotFound)
	})

	t.Run("prevents deleting last admin", func(t *testing.T) {
		// Create a fresh store with only one admin
		store2, cleanup2 := newTestStore(t)
		defer cleanup2()

		admin, err := store2.Create(ctx, "lastadmin@example.com", "Last Admin", RoleAdmin, "")
		require.NoError(t, err)

		err = store2.Delete(ctx, admin.ID)
		assert.ErrorIs(t, err, ErrLastAdmin)
	})
}

func TestFileStore_List(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("lists all users", func(t *testing.T) {
		_, err := store.Create(ctx, "list1@example.com", "User1", RoleAdmin, "")
		require.NoError(t, err)
		_, err = store.Create(ctx, "list2@example.com", "User2", RoleUser, "")
		require.NoError(t, err)

		users, err := store.List(ctx)
		require.NoError(t, err)
		assert.Len(t, users, 2)
	})

	t.Run("returns empty slice when no users", func(t *testing.T) {
		store2, cleanup2 := newTestStore(t)
		defer cleanup2()

		users, err := store2.List(ctx)
		require.NoError(t, err)
		assert.Len(t, users, 0)
	})
}

func TestFileStore_ListByTenant(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()

	// Create users across different tenants
	_, err := store.Create(ctx, "sys1@example.com", "System User", RoleAdmin, "")
	require.NoError(t, err)
	_, err = store.Create(ctx, "a1@example.com", "Tenant A User 1", RoleUser, "tenant-a")
	require.NoError(t, err)
	_, err = store.Create(ctx, "a2@example.com", "Tenant A User 2", RoleOperator, "tenant-a")
	require.NoError(t, err)
	_, err = store.Create(ctx, "b1@example.com", "Tenant B User", RoleUser, "tenant-b")
	require.NoError(t, err)

	t.Run("returns only tenant-a users", func(t *testing.T) {
		users, err := store.ListByTenant(ctx, "tenant-a")
		require.NoError(t, err)
		assert.Len(t, users, 2)
		for _, u := range users {
			assert.Equal(t, "tenant-a", u.TenantID)
		}
	})

	t.Run("returns only tenant-b users", func(t *testing.T) {
		users, err := store.ListByTenant(ctx, "tenant-b")
		require.NoError(t, err)
		assert.Len(t, users, 1)
		assert.Equal(t, "tenant-b", users[0].TenantID)
	})

	t.Run("empty tenantID returns system-level users", func(t *testing.T) {
		users, err := store.ListByTenant(ctx, "")
		require.NoError(t, err)
		assert.Len(t, users, 1)
		assert.Empty(t, users[0].TenantID)
		assert.Equal(t, "sys1@example.com", users[0].Username)
	})
}

func TestFileStore_ListByTenant_Empty(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()

	// Create a user in a different tenant
	_, err := store.Create(ctx, "other@example.com", "Other", RoleUser, "other-tenant")
	require.NoError(t, err)

	// Query a tenant with no users
	users, err := store.ListByTenant(ctx, "nonexistent-tenant")
	require.NoError(t, err)
	assert.Empty(t, users)
}

func TestFileStore_ListByTenant_Closed(t *testing.T) {
	store, _ := newTestStore(t)
	_ = store.Close()

	ctx := context.Background()

	_, err := store.ListByTenant(ctx, "any-tenant")
	assert.ErrorIs(t, err, ErrStorageClosed)
}

func TestFileStore_Count(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()

	count, err := store.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, count)

	_, err = store.Create(ctx, "count1@example.com", "User1", RoleUser, "")
	require.NoError(t, err)

	count, err = store.Count(ctx)
	require.NoError(t, err)
	assert.Equal(t, 1, count)
}

func TestFileStore_HasAnyUsers(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()

	hasUsers, err := store.HasAnyUsers(ctx)
	require.NoError(t, err)
	assert.False(t, hasUsers)

	_, err = store.Create(ctx, "hasany@example.com", "User", RoleUser, "")
	require.NoError(t, err)

	hasUsers, err = store.HasAnyUsers(ctx)
	require.NoError(t, err)
	assert.True(t, hasUsers)
}

func TestFileStore_CountAdmins(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()

	count, err := store.CountAdmins(ctx)
	require.NoError(t, err)
	assert.Equal(t, 0, count)

	_, err = store.Create(ctx, "admin1@example.com", "Admin1", RoleAdmin, "")
	require.NoError(t, err)
	_, err = store.Create(ctx, "user1@example.com", "User1", RoleUser, "")
	require.NoError(t, err)
	_, err = store.Create(ctx, "admin2@example.com", "Admin2", RoleAdmin, "")
	require.NoError(t, err)

	count, err = store.CountAdmins(ctx)
	require.NoError(t, err)
	assert.Equal(t, 2, count)
}

func TestFileStore_Sessions(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()

	t.Run("save and retrieve session", func(t *testing.T) {
		sessionData := []byte("test-session-data")
		err := store.SaveSession(ctx, "session-1", sessionData, time.Minute)
		require.NoError(t, err)

		retrieved, err := store.GetSession(ctx, "session-1")
		require.NoError(t, err)
		assert.Equal(t, sessionData, retrieved)
	})

	t.Run("returns error for nonexistent session", func(t *testing.T) {
		_, err := store.GetSession(ctx, "nonexistent")
		assert.ErrorIs(t, err, ErrSessionNotFound)
	})

	t.Run("delete session", func(t *testing.T) {
		err := store.SaveSession(ctx, "session-2", []byte("data"), time.Minute)
		require.NoError(t, err)

		err = store.DeleteSession(ctx, "session-2")
		require.NoError(t, err)

		_, err = store.GetSession(ctx, "session-2")
		assert.ErrorIs(t, err, ErrSessionNotFound)
	})

	t.Run("expired session returns not found", func(t *testing.T) {
		err := store.SaveSession(ctx, "session-expired", []byte("data"), 1*time.Millisecond)
		require.NoError(t, err)

		time.Sleep(10 * time.Millisecond)

		_, err = store.GetSession(ctx, "session-expired")
		assert.ErrorIs(t, err, ErrSessionNotFound)
	})

	t.Run("default TTL is used when zero", func(t *testing.T) {
		err := store.SaveSession(ctx, "session-default-ttl", []byte("data"), 0)
		require.NoError(t, err)

		// Should still be available since default TTL is 5 minutes
		retrieved, err := store.GetSession(ctx, "session-default-ttl")
		require.NoError(t, err)
		assert.Equal(t, []byte("data"), retrieved)
	})
}

func TestFileStore_Close(t *testing.T) {
	store, _ := newTestStore(t)
	ctx := context.Background()

	err := store.Close()
	require.NoError(t, err)

	// Operations should fail after close
	_, err = store.Create(ctx, "closed@example.com", "Closed", RoleUser, "")
	assert.ErrorIs(t, err, ErrStorageClosed)

	_, err = store.GetByID(ctx, []byte("id"))
	assert.ErrorIs(t, err, ErrStorageClosed)

	_, err = store.GetByUsername(ctx, "user")
	assert.ErrorIs(t, err, ErrStorageClosed)

	_, err = store.List(ctx)
	assert.ErrorIs(t, err, ErrStorageClosed)

	_, err = store.Count(ctx)
	assert.ErrorIs(t, err, ErrStorageClosed)

	_, err = store.CountAdmins(ctx)
	assert.ErrorIs(t, err, ErrStorageClosed)

	err = store.Update(ctx, &User{})
	assert.ErrorIs(t, err, ErrStorageClosed)

	err = store.Delete(ctx, []byte("id"))
	assert.ErrorIs(t, err, ErrStorageClosed)

	err = store.SaveSession(ctx, "session", []byte{}, time.Minute)
	assert.ErrorIs(t, err, ErrStorageClosed)

	_, err = store.GetSession(ctx, "session")
	assert.ErrorIs(t, err, ErrStorageClosed)

	err = store.DeleteSession(ctx, "session")
	assert.ErrorIs(t, err, ErrStorageClosed)

	// Closing again should be no-op
	err = store.Close()
	require.NoError(t, err)
}

func TestFileStore_SessionCleanup(t *testing.T) {
	backend, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	store, err := NewFileStore(backend, WithCleanupInterval(50*time.Millisecond))
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	ctx := context.Background()

	// Save a session with short TTL
	err = store.SaveSession(ctx, "cleanup-session", []byte("data"), 10*time.Millisecond)
	require.NoError(t, err)

	// Wait for cleanup to run
	time.Sleep(100 * time.Millisecond)

	// Session should be cleaned up
	_, err = store.GetSession(ctx, "cleanup-session")
	assert.ErrorIs(t, err, ErrSessionNotFound)
}

func TestGenerateSessionID(t *testing.T) {
	id1, err := GenerateSessionID()
	require.NoError(t, err)
	assert.NotEmpty(t, id1)

	id2, err := GenerateSessionID()
	require.NoError(t, err)
	assert.NotEmpty(t, id2)

	// IDs should be unique
	assert.NotEqual(t, id1, id2)
}

func TestFileStore_WithCleanupInterval(t *testing.T) {
	backend, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	store, err := NewFileStore(backend, WithCleanupInterval(30*time.Second))
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	assert.Equal(t, 30*time.Second, store.cleanupInterval)
}

func TestFileStore_HasAnyUsers_Error(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()

	// First close the store to trigger error
	_ = store.Close()

	_, err := store.HasAnyUsers(ctx)
	assert.ErrorIs(t, err, ErrStorageClosed)
}

func TestFileStore_GetByCertFingerprint(t *testing.T) {
	t.Run("finds user by cert fingerprint", func(t *testing.T) {
		backend, err := storage.NewMemoryBackend()
		require.NoError(t, err)
		store, err := NewFileStore(backend, WithCleanupInterval(100*time.Millisecond))
		require.NoError(t, err)
		defer func() { _ = store.Close() }()

		ctx := context.Background()
		u, err := store.Create(ctx, "certuser@example.com", "Cert User", RoleUser, "")
		require.NoError(t, err)

		u.CertBindings = []CertBinding{
			{Fingerprint: "sha256:abc123", Name: "PIV 9a"},
		}
		err = store.Update(ctx, u)
		require.NoError(t, err)

		found, err := store.GetByCertFingerprint(ctx, "sha256:abc123")
		require.NoError(t, err)
		assert.Equal(t, "certuser@example.com", found.Username)
	})

	t.Run("returns error for unknown fingerprint", func(t *testing.T) {
		backend, err := storage.NewMemoryBackend()
		require.NoError(t, err)
		store, err := NewFileStore(backend, WithCleanupInterval(100*time.Millisecond))
		require.NoError(t, err)
		defer func() { _ = store.Close() }()

		ctx := context.Background()
		_, err = store.GetByCertFingerprint(ctx, "unknown")
		assert.ErrorIs(t, err, ErrCertBindingNotFound)
	})

	t.Run("returns error for empty fingerprint", func(t *testing.T) {
		backend, err := storage.NewMemoryBackend()
		require.NoError(t, err)
		store, err := NewFileStore(backend, WithCleanupInterval(100*time.Millisecond))
		require.NoError(t, err)
		defer func() { _ = store.Close() }()

		ctx := context.Background()
		_, err = store.GetByCertFingerprint(ctx, "")
		assert.ErrorIs(t, err, ErrCertBindingNotFound)
	})

	t.Run("returns error when closed", func(t *testing.T) {
		backend, err := storage.NewMemoryBackend()
		require.NoError(t, err)
		store, err := NewFileStore(backend, WithCleanupInterval(100*time.Millisecond))
		require.NoError(t, err)
		_ = store.Close()

		ctx := context.Background()
		_, err = store.GetByCertFingerprint(ctx, "any")
		assert.ErrorIs(t, err, ErrStorageClosed)
	})
}
