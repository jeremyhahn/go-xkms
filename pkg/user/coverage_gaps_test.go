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
	pkgwebauthn "github.com/jeremyhahn/go-xkms/pkg/webauthn"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFileStore_Delete_OnClosedStore exercises the Delete closed-store guard.
func TestFileStore_Delete_OnClosedStore(t *testing.T) {
	store, cleanup := newTestStore(t)
	cleanup() // close it immediately

	ctx := context.Background()
	err := store.Delete(ctx, []byte("any-id"))
	assert.ErrorIs(t, err, ErrStorageClosed)
}

// TestFileStore_Delete_LastAdmin ensures the last admin cannot be deleted.
func TestFileStore_Delete_LastAdmin(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()

	admin, err := store.Create(ctx, "admin@test.com", "Admin", RoleAdmin, "")
	require.NoError(t, err)

	err = store.Delete(ctx, admin.ID)
	assert.ErrorIs(t, err, ErrLastAdmin)
}

// TestFileStore_Delete_NonExistentUser returns ErrUserNotFound.
func TestFileStore_Delete_NonExistentUser(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()
	err := store.Delete(ctx, []byte("nonexistent"))
	assert.ErrorIs(t, err, ErrUserNotFound)
}

// TestFileStore_Update_OnClosedStore exercises the Update closed-store guard.
func TestFileStore_Update_OnClosedStore(t *testing.T) {
	store, cleanup := newTestStore(t)
	cleanup()

	ctx := context.Background()
	err := store.Update(ctx, &User{ID: []byte("any"), Username: "test"})
	assert.ErrorIs(t, err, ErrStorageClosed)
}

// TestFileStore_ListByTenant_OnClosedStore exercises the ListByTenant closed-store guard.
func TestFileStore_ListByTenant_OnClosedStore(t *testing.T) {
	store, cleanup := newTestStore(t)
	cleanup()

	ctx := context.Background()
	_, err := store.ListByTenant(ctx, "tenant1")
	assert.ErrorIs(t, err, ErrStorageClosed)
}

// TestFileStore_Count_OnClosedStore exercises the Count closed-store guard.
func TestFileStore_Count_OnClosedStore(t *testing.T) {
	store, cleanup := newTestStore(t)
	cleanup()

	ctx := context.Background()
	_, err := store.Count(ctx)
	assert.ErrorIs(t, err, ErrStorageClosed)
}

// TestFileStore_ListByTenant_Filtering verifies tenant-scoped listing returns
// only users matching the given tenantID.
func TestFileStore_ListByTenant_Filtering(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()

	_, err := store.Create(ctx, "a@t1.com", "A", RoleUser, "tenant1")
	require.NoError(t, err)
	_, err = store.Create(ctx, "b@t2.com", "B", RoleUser, "tenant2")
	require.NoError(t, err)
	_, err = store.Create(ctx, "c@t1.com", "C", RoleUser, "tenant1")
	require.NoError(t, err)

	users, err := store.ListByTenant(ctx, "tenant1")
	require.NoError(t, err)
	assert.Len(t, users, 2)
}

// TestFileStore_GenerateSessionID verifies format and uniqueness.
func TestFileStore_GenerateSessionID(t *testing.T) {
	id1, err := GenerateSessionID()
	require.NoError(t, err)
	assert.NotEmpty(t, id1)

	id2, err := GenerateSessionID()
	require.NoError(t, err)
	assert.NotEqual(t, id1, id2)
}

// TestFileStore_Delete_NonAdminAllowed ensures non-admin users can be deleted.
func TestFileStore_Delete_NonAdminAllowed(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()

	_, err := store.Create(ctx, "admin@test.com", "Admin", RoleAdmin, "")
	require.NoError(t, err)

	user, err := store.Create(ctx, "user@test.com", "User", RoleUser, "")
	require.NoError(t, err)

	err = store.Delete(ctx, user.ID)
	assert.NoError(t, err)

	_, err = store.GetByID(ctx, user.ID)
	assert.ErrorIs(t, err, ErrUserNotFound)
}

// TestFileStore_Delete_AdminWhenMultiple ensures an admin can be deleted
// when there is more than one.
func TestFileStore_Delete_AdminWhenMultiple(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()

	admin1, err := store.Create(ctx, "admin1@test.com", "Admin1", RoleAdmin, "")
	require.NoError(t, err)
	_, err = store.Create(ctx, "admin2@test.com", "Admin2", RoleAdmin, "")
	require.NoError(t, err)

	err = store.Delete(ctx, admin1.ID)
	assert.NoError(t, err)
}

// TestWebAuthnSessionAdapter_Get_CorruptData exercises the unmarshal error path
// in WebAuthnSessionAdapter.Get when stored session data is invalid JSON.
func TestWebAuthnSessionAdapter_Get_CorruptData(t *testing.T) {
	backend, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	store, err := NewFileStore(backend)
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	ctx := context.Background()

	// Directly store invalid JSON as session data.
	err = store.SaveSession(ctx, "corrupt-session", []byte("{invalid-json"), 5*time.Minute)
	require.NoError(t, err)

	adapter := NewWebAuthnSessionAdapter(store, 5*time.Minute)

	_, err = adapter.Get(ctx, "corrupt-session")
	assert.Error(t, err, "should fail to unmarshal corrupt session data")
}

// TestFileStore_Update_NonExistent returns ErrUserNotFound.
func TestFileStore_Update_NonExistent(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()

	err := store.Update(ctx, &User{ID: []byte("no-such-user"), Username: "ghost"})
	assert.ErrorIs(t, err, ErrUserNotFound)
}

// TestFileStore_ListByTenant_EmptyTenantID returns system-level users.
func TestFileStore_ListByTenant_EmptyTenantID(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()

	ctx := context.Background()

	_, err := store.Create(ctx, "system@test.com", "System", RoleAdmin, "")
	require.NoError(t, err)
	_, err = store.Create(ctx, "tenant@test.com", "Tenant", RoleUser, "tenant1")
	require.NoError(t, err)

	users, err := store.ListByTenant(ctx, "")
	require.NoError(t, err)
	assert.Len(t, users, 1)
	assert.Equal(t, "system@test.com", users[0].Username)
}

// TestWebAuthnCredentialAdapter_Update_NonExistentUser returns error.
func TestWebAuthnCredentialAdapter_Update_NonExistentUser(t *testing.T) {
	backend, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	store, err := NewFileStore(backend)
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	credAdapter := NewWebAuthnCredentialAdapter(store)

	cred := &pkgwebauthn.Credential{
		ID:     []byte("cred"),
		UserID: []byte("no-user"),
	}
	err = credAdapter.Update(context.Background(), cred)
	assert.Error(t, err)
}

// TestWebAuthnCredentialAdapter_Delete_NotFoundReturnsError exercises the
// credential-not-found path in Delete.
func TestWebAuthnCredentialAdapter_Delete_NotFoundReturnsError(t *testing.T) {
	backend, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	store, err := NewFileStore(backend)
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	credAdapter := NewWebAuthnCredentialAdapter(store)

	err = credAdapter.Delete(context.Background(), []byte("nonexistent"))
	assert.ErrorIs(t, err, pkgwebauthn.ErrCredentialNotFound)
}

// TestWebAuthnCredentialAdapter_DeleteByUserID_NonExistent returns nil.
func TestWebAuthnCredentialAdapter_DeleteByUserID_NonExistent(t *testing.T) {
	backend, err := storage.NewMemoryBackend()
	require.NoError(t, err)

	store, err := NewFileStore(backend)
	require.NoError(t, err)
	defer func() { _ = store.Close() }()

	credAdapter := NewWebAuthnCredentialAdapter(store)

	// Should return nil when user doesn't exist.
	err = credAdapter.DeleteByUserID(context.Background(), []byte("nonexistent"))
	assert.NoError(t, err)
}

// TestFileStore_SaveSession_OnClosedStore exercises session closed-store guard.
func TestFileStore_SaveSession_OnClosedStore(t *testing.T) {
	store, cleanup := newTestStore(t)
	cleanup()

	err := store.SaveSession(context.Background(), "s1", []byte("data"), time.Minute)
	assert.ErrorIs(t, err, ErrStorageClosed)
}

// TestFileStore_GetSession_OnClosedStore exercises session closed-store guard.
func TestFileStore_GetSession_OnClosedStore(t *testing.T) {
	store, cleanup := newTestStore(t)
	cleanup()

	_, err := store.GetSession(context.Background(), "s1")
	assert.ErrorIs(t, err, ErrStorageClosed)
}

// TestFileStore_DeleteSession_OnClosedStore exercises session closed-store guard.
func TestFileStore_DeleteSession_OnClosedStore(t *testing.T) {
	store, cleanup := newTestStore(t)
	cleanup()

	err := store.DeleteSession(context.Background(), "s1")
	assert.ErrorIs(t, err, ErrStorageClosed)
}
