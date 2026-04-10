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

package staticpw

import (
	"testing"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestScopedStore creates a ScopedStore with fresh in-memory backends.
func newTestScopedStore(t *testing.T) *ScopedStore {
	t.Helper()
	backend := storage.New()
	shared, err := NewSharedTenantStore(backend, "acme")
	require.NoError(t, err)
	personal, err := NewPersonalTenantStore(backend, "acme", "alice")
	require.NoError(t, err)
	scoped, err := NewScopedStore(shared, personal, "alice")
	require.NoError(t, err)
	return scoped
}

func TestScopedStore_ImplementsStoreInterface(t *testing.T) {
	var _ Store = (*ScopedStore)(nil)
}

// --- NewScopedStore ---

func TestNewScopedStore_Success(t *testing.T) {
	backend := storage.New()
	shared, err := NewSharedTenantStore(backend, "acme")
	require.NoError(t, err)
	personal, err := NewPersonalTenantStore(backend, "acme", "alice")
	require.NoError(t, err)

	scoped, err := NewScopedStore(shared, personal, "alice")
	require.NoError(t, err)
	assert.NotNil(t, scoped)
}

func TestNewScopedStore_NilShared(t *testing.T) {
	backend := storage.New()
	personal, err := NewPersonalTenantStore(backend, "acme", "alice")
	require.NoError(t, err)

	_, err = NewScopedStore(nil, personal, "alice")
	assert.ErrorIs(t, err, ErrNilStore)
}

func TestNewScopedStore_NilPersonal(t *testing.T) {
	backend := storage.New()
	shared, err := NewSharedTenantStore(backend, "acme")
	require.NoError(t, err)

	_, err = NewScopedStore(shared, nil, "alice")
	assert.ErrorIs(t, err, ErrNilStore)
}

func TestNewScopedStore_InvalidOwnerID(t *testing.T) {
	backend := storage.New()
	shared, err := NewSharedTenantStore(backend, "acme")
	require.NoError(t, err)
	personal, err := NewPersonalTenantStore(backend, "acme", "alice")
	require.NoError(t, err)

	_, err = NewScopedStore(shared, personal, "")
	assert.ErrorIs(t, err, ErrInvalidUserID)
}

// --- Add routing ---

func TestScopedStore_Add_Personal(t *testing.T) {
	s := newTestScopedStore(t)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "my-secret", Password: "pass123"}
	require.NoError(t, s.Add(pw))

	assert.Equal(t, "alice", pw.OwnerID)
	assert.False(t, pw.Shared)

	// Should be in personal store, not shared.
	personalPWs, err := s.ListByScope(ScopePersonal)
	require.NoError(t, err)
	assert.Len(t, personalPWs, 1)

	sharedPWs, err := s.ListByScope(ScopeShared)
	require.NoError(t, err)
	assert.Empty(t, sharedPWs)
}

func TestScopedStore_Add_Shared(t *testing.T) {
	s := newTestScopedStore(t)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "team-key", Password: "pass123", Shared: true}
	require.NoError(t, s.Add(pw))

	assert.Equal(t, "alice", pw.OwnerID)
	assert.True(t, pw.Shared)

	// Should be in shared store, not personal.
	sharedPWs, err := s.ListByScope(ScopeShared)
	require.NoError(t, err)
	assert.Len(t, sharedPWs, 1)

	personalPWs, err := s.ListByScope(ScopePersonal)
	require.NoError(t, err)
	assert.Empty(t, personalPWs)
}

func TestScopedStore_Add_SetsOwnerID(t *testing.T) {
	s := newTestScopedStore(t)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "test", Password: "p"}
	require.NoError(t, s.Add(pw))
	assert.Equal(t, "alice", pw.OwnerID)
}

func TestScopedStore_Add_ValidationError(t *testing.T) {
	s := newTestScopedStore(t)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "", Password: "p"}
	assert.ErrorIs(t, s.Add(pw), ErrInvalidName)
}

// --- Get fallback ---

func TestScopedStore_Get_PersonalFirst(t *testing.T) {
	s := newTestScopedStore(t)
	defer func() { _ = s.Close() }()

	// Add same name to both stores.
	require.NoError(t, s.Add(&StaticPassword{Name: "gmail", Password: "personal-pw"}))
	require.NoError(t, s.Add(&StaticPassword{Name: "slack", Password: "shared-pw", Shared: true}))

	// Get personal entry by name.
	pw, err := s.Get("gmail")
	require.NoError(t, err)
	assert.Equal(t, "personal-pw", pw.Password)
}

func TestScopedStore_Get_FallbackToShared(t *testing.T) {
	s := newTestScopedStore(t)
	defer func() { _ = s.Close() }()

	require.NoError(t, s.Add(&StaticPassword{Name: "shared-only", Password: "shared-pw", Shared: true}))

	pw, err := s.Get("shared-only")
	require.NoError(t, err)
	assert.Equal(t, "shared-pw", pw.Password)
}

func TestScopedStore_Get_NotFound(t *testing.T) {
	s := newTestScopedStore(t)
	defer func() { _ = s.Close() }()

	_, err := s.Get("nonexistent")
	assert.ErrorIs(t, err, ErrPasswordNotFound)
}

// --- List / ListByScope ---

func TestScopedStore_List_MergesBothStores(t *testing.T) {
	s := newTestScopedStore(t)
	defer func() { _ = s.Close() }()

	require.NoError(t, s.Add(&StaticPassword{Name: "alpha", Password: "p"}))
	require.NoError(t, s.Add(&StaticPassword{Name: "beta", Password: "p", Shared: true}))
	require.NoError(t, s.Add(&StaticPassword{Name: "gamma", Password: "p"}))

	all, err := s.List()
	require.NoError(t, err)
	assert.Len(t, all, 3)

	// Should be sorted by name.
	assert.Equal(t, "alpha", all[0].Name)
	assert.Equal(t, "beta", all[1].Name)
	assert.Equal(t, "gamma", all[2].Name)
}

func TestScopedStore_ListByScope_PersonalOnly(t *testing.T) {
	s := newTestScopedStore(t)
	defer func() { _ = s.Close() }()

	require.NoError(t, s.Add(&StaticPassword{Name: "personal1", Password: "p"}))
	require.NoError(t, s.Add(&StaticPassword{Name: "shared1", Password: "p", Shared: true}))

	pws, err := s.ListByScope(ScopePersonal)
	require.NoError(t, err)
	assert.Len(t, pws, 1)
	assert.Equal(t, "personal1", pws[0].Name)
}

func TestScopedStore_ListByScope_SharedOnly(t *testing.T) {
	s := newTestScopedStore(t)
	defer func() { _ = s.Close() }()

	require.NoError(t, s.Add(&StaticPassword{Name: "personal1", Password: "p"}))
	require.NoError(t, s.Add(&StaticPassword{Name: "shared1", Password: "p", Shared: true}))

	pws, err := s.ListByScope(ScopeShared)
	require.NoError(t, err)
	assert.Len(t, pws, 1)
	assert.Equal(t, "shared1", pws[0].Name)
}

func TestScopedStore_ListByScope_All(t *testing.T) {
	s := newTestScopedStore(t)
	defer func() { _ = s.Close() }()

	require.NoError(t, s.Add(&StaticPassword{Name: "a", Password: "p"}))
	require.NoError(t, s.Add(&StaticPassword{Name: "b", Password: "p", Shared: true}))

	pws, err := s.ListByScope(ScopeAll)
	require.NoError(t, err)
	assert.Len(t, pws, 2)
}

func TestScopedStore_ListByScope_InvalidScope(t *testing.T) {
	s := newTestScopedStore(t)
	defer func() { _ = s.Close() }()

	_, err := s.ListByScope(PasswordScope("bogus"))
	assert.ErrorIs(t, err, ErrInvalidScope)
}

func TestScopedStore_List_Empty(t *testing.T) {
	s := newTestScopedStore(t)
	defer func() { _ = s.Close() }()

	pws, err := s.List()
	require.NoError(t, err)
	assert.Empty(t, pws)
}

// --- Delete ---

func TestScopedStore_Delete_Personal(t *testing.T) {
	s := newTestScopedStore(t)
	defer func() { _ = s.Close() }()

	require.NoError(t, s.Add(&StaticPassword{Name: "to-delete", Password: "p"}))
	require.NoError(t, s.Delete("to-delete"))

	_, err := s.Get("to-delete")
	assert.ErrorIs(t, err, ErrPasswordNotFound)
}

func TestScopedStore_Delete_SharedFallback(t *testing.T) {
	s := newTestScopedStore(t)
	defer func() { _ = s.Close() }()

	require.NoError(t, s.Add(&StaticPassword{Name: "shared-del", Password: "p", Shared: true}))
	require.NoError(t, s.Delete("shared-del"))

	_, err := s.Get("shared-del")
	assert.ErrorIs(t, err, ErrPasswordNotFound)
}

func TestScopedStore_Delete_NotFound(t *testing.T) {
	s := newTestScopedStore(t)
	defer func() { _ = s.Close() }()

	assert.ErrorIs(t, s.Delete("nonexistent"), ErrPasswordNotFound)
}

// --- ForceDelete ---

func TestScopedStore_ForceDelete_Personal(t *testing.T) {
	s := newTestScopedStore(t)
	defer func() { _ = s.Close() }()

	require.NoError(t, s.Add(&StaticPassword{Name: "ro-entry", Password: "p", ReadOnly: true}))
	require.NoError(t, s.ForceDelete("ro-entry"))

	_, err := s.Get("ro-entry")
	assert.ErrorIs(t, err, ErrPasswordNotFound)
}

func TestScopedStore_ForceDelete_SharedFallback(t *testing.T) {
	s := newTestScopedStore(t)
	defer func() { _ = s.Close() }()

	require.NoError(t, s.Add(&StaticPassword{Name: "shared-ro", Password: "p", Shared: true, ReadOnly: true}))
	require.NoError(t, s.ForceDelete("shared-ro"))

	_, err := s.Get("shared-ro")
	assert.ErrorIs(t, err, ErrPasswordNotFound)
}

// --- Update ---

func TestScopedStore_Update_Personal(t *testing.T) {
	s := newTestScopedStore(t)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "updatable", Password: "old"}
	require.NoError(t, s.Add(pw))

	pw.Password = "new"
	require.NoError(t, s.Update(pw))

	retrieved, err := s.Get("updatable")
	require.NoError(t, err)
	assert.Equal(t, "new", retrieved.Password)
}

func TestScopedStore_Update_Shared(t *testing.T) {
	s := newTestScopedStore(t)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "shared-update", Password: "old", Shared: true}
	require.NoError(t, s.Add(pw))

	pw.Password = "new"
	require.NoError(t, s.Update(pw))

	retrieved, err := s.Get("shared-update")
	require.NoError(t, err)
	assert.Equal(t, "new", retrieved.Password)
}

func TestScopedStore_Update_FallbackToShared(t *testing.T) {
	s := newTestScopedStore(t)
	defer func() { _ = s.Close() }()

	// Add as shared, then try to update without Shared flag set.
	pw := &StaticPassword{Name: "fallback-up", Password: "old", Shared: true}
	require.NoError(t, s.Add(pw))

	// Update without Shared flag — will try personal first (miss), then shared.
	updatePW := &StaticPassword{ID: pw.ID, Name: "fallback-up", Password: "new"}
	require.NoError(t, s.Update(updatePW))

	retrieved, err := s.Get("fallback-up")
	require.NoError(t, err)
	assert.Equal(t, "new", retrieved.Password)
}

// --- ListByFolder ---

func TestScopedStore_ListByFolder_MergesBothStores(t *testing.T) {
	s := newTestScopedStore(t)
	defer func() { _ = s.Close() }()

	require.NoError(t, s.Add(&StaticPassword{Name: "p-email", Password: "p", FolderPath: "email"}))
	require.NoError(t, s.Add(&StaticPassword{Name: "s-email", Password: "p", FolderPath: "email", Shared: true}))
	require.NoError(t, s.Add(&StaticPassword{Name: "p-social", Password: "p", FolderPath: "social"}))

	emailPWs, err := s.ListByFolder("email")
	require.NoError(t, err)
	assert.Len(t, emailPWs, 2)
}

func TestScopedStore_ListByFolder_Empty(t *testing.T) {
	s := newTestScopedStore(t)
	defer func() { _ = s.Close() }()

	pws, err := s.ListByFolder("nonexistent")
	require.NoError(t, err)
	assert.Empty(t, pws)
}

// --- ListFolders ---

func TestScopedStore_ListFolders_DeduplicatedUnion(t *testing.T) {
	s := newTestScopedStore(t)
	defer func() { _ = s.Close() }()

	require.NoError(t, s.Add(&StaticPassword{Name: "a", Password: "p", FolderPath: "email"}))
	require.NoError(t, s.Add(&StaticPassword{Name: "b", Password: "p", FolderPath: "email", Shared: true}))
	require.NoError(t, s.Add(&StaticPassword{Name: "c", Password: "p", FolderPath: "social"}))
	require.NoError(t, s.Add(&StaticPassword{Name: "d", Password: "p", FolderPath: "work", Shared: true}))

	folders, err := s.ListFolders()
	require.NoError(t, err)
	assert.Len(t, folders, 3)
	assert.Contains(t, folders, "email")
	assert.Contains(t, folders, "social")
	assert.Contains(t, folders, "work")
}

func TestScopedStore_ListFolders_Empty(t *testing.T) {
	s := newTestScopedStore(t)
	defer func() { _ = s.Close() }()

	folders, err := s.ListFolders()
	require.NoError(t, err)
	assert.Empty(t, folders)
}

// --- MoveToFolder ---

func TestScopedStore_MoveToFolder_Personal(t *testing.T) {
	s := newTestScopedStore(t)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "movable", Password: "p", FolderPath: "old"}
	require.NoError(t, s.Add(pw))

	require.NoError(t, s.MoveToFolder(pw.ID, "new"))

	moved, err := s.Get("movable")
	require.NoError(t, err)
	assert.Equal(t, "new", moved.FolderPath)
}

func TestScopedStore_MoveToFolder_SharedFallback(t *testing.T) {
	s := newTestScopedStore(t)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "shared-move", Password: "p", FolderPath: "old", Shared: true}
	require.NoError(t, s.Add(pw))

	require.NoError(t, s.MoveToFolder(pw.ID, "new"))

	moved, err := s.Get("shared-move")
	require.NoError(t, err)
	assert.Equal(t, "new", moved.FolderPath)
}

func TestScopedStore_MoveToFolder_NotFound(t *testing.T) {
	s := newTestScopedStore(t)
	defer func() { _ = s.Close() }()

	assert.ErrorIs(t, s.MoveToFolder("nonexistent", "folder"), ErrPasswordNotFound)
}

// --- Close ---

func TestScopedStore_Close(t *testing.T) {
	s := newTestScopedStore(t)
	require.NoError(t, s.Close())

	// After close, operations should fail on both stores.
	_, err := s.List()
	assert.ErrorIs(t, err, ErrStoreClosed)
}

// --- Cross-user isolation ---

func TestScopedStore_CrossUserIsolation(t *testing.T) {
	backend := storage.New()

	// Alice's scoped store.
	aliceShared, err := NewSharedTenantStore(backend, "acme")
	require.NoError(t, err)
	alicePersonal, err := NewPersonalTenantStore(backend, "acme", "alice")
	require.NoError(t, err)
	aliceStore, err := NewScopedStore(aliceShared, alicePersonal, "alice")
	require.NoError(t, err)

	// Bob's scoped store (same shared, different personal).
	bobShared, err := NewSharedTenantStore(backend, "acme")
	require.NoError(t, err)
	bobPersonal, err := NewPersonalTenantStore(backend, "acme", "bob")
	require.NoError(t, err)
	bobStore, err := NewScopedStore(bobShared, bobPersonal, "bob")
	require.NoError(t, err)

	// Alice adds a personal password.
	require.NoError(t, aliceStore.Add(&StaticPassword{Name: "private-key", Password: "alice-secret"}))

	// Bob adds a personal password with the same name.
	require.NoError(t, bobStore.Add(&StaticPassword{Name: "private-key", Password: "bob-secret"}))

	// Alice adds a shared password.
	require.NoError(t, aliceStore.Add(&StaticPassword{Name: "team-key", Password: "team-secret", Shared: true}))

	// Alice sees her personal + the shared entry.
	aliceAll, err := aliceStore.List()
	require.NoError(t, err)
	assert.Len(t, aliceAll, 2)

	// Bob sees his personal + the same shared entry.
	bobAll, err := bobStore.List()
	require.NoError(t, err)
	assert.Len(t, bobAll, 2)

	// Alice's personal entry is invisible to Bob's personal scope.
	alicePersonalPWs, err := aliceStore.ListByScope(ScopePersonal)
	require.NoError(t, err)
	assert.Len(t, alicePersonalPWs, 1)
	assert.Equal(t, "alice-secret", alicePersonalPWs[0].Password)

	bobPersonalPWs, err := bobStore.ListByScope(ScopePersonal)
	require.NoError(t, err)
	assert.Len(t, bobPersonalPWs, 1)
	assert.Equal(t, "bob-secret", bobPersonalPWs[0].Password)

	// Both see the same shared entry.
	aliceSharedPWs, err := aliceStore.ListByScope(ScopeShared)
	require.NoError(t, err)
	assert.Len(t, aliceSharedPWs, 1)
	assert.Equal(t, "team-secret", aliceSharedPWs[0].Password)

	bobSharedPWs, err := bobStore.ListByScope(ScopeShared)
	require.NoError(t, err)
	assert.Len(t, bobSharedPWs, 1)
	assert.Equal(t, "team-secret", bobSharedPWs[0].Password)
}
