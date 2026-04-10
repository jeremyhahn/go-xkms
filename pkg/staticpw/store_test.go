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
	"context"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestStore() *BackendStore {
	return NewStore(storage.New())
}

func TestBackendStore_Add_Success(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "gmail", Password: "secret123"}
	require.NoError(t, s.Add(pw))

	assert.NotEmpty(t, pw.ID)
	assert.False(t, pw.CreatedAt.IsZero())
	assert.False(t, pw.UpdatedAt.IsZero())
}

func TestBackendStore_Add_MissingName(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Password: "secret123"}
	assert.ErrorIs(t, s.Add(pw), ErrInvalidName)
}

func TestBackendStore_Add_MissingPassword(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "gmail"}
	assert.ErrorIs(t, s.Add(pw), ErrEmptyPassword)
}

func TestBackendStore_Add_DuplicateName(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	pw1 := &StaticPassword{Name: "gmail", Password: "secret1"}
	require.NoError(t, s.Add(pw1))

	pw2 := &StaticPassword{Name: "gmail", Password: "secret2"}
	assert.ErrorIs(t, s.Add(pw2), ErrPasswordExists)
}

func TestBackendStore_Get_ByID(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "gmail", Password: "secret123"}
	require.NoError(t, s.Add(pw))

	retrieved, err := s.Get(pw.ID)
	require.NoError(t, err)
	assert.Equal(t, pw.ID, retrieved.ID)
	assert.Equal(t, "gmail", retrieved.Name)
	assert.Equal(t, "secret123", retrieved.Password)
}

func TestBackendStore_Get_ByName(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "gmail", Password: "secret123"}
	require.NoError(t, s.Add(pw))

	retrieved, err := s.Get("gmail")
	require.NoError(t, err)
	assert.Equal(t, pw.ID, retrieved.ID)
}

func TestBackendStore_Get_CaseInsensitiveName(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "Gmail", Password: "secret123"}
	require.NoError(t, s.Add(pw))

	retrieved, err := s.Get("gmail")
	require.NoError(t, err)
	assert.Equal(t, pw.ID, retrieved.ID)
}

func TestBackendStore_Get_NotFound(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	_, err := s.Get("nonexistent")
	assert.ErrorIs(t, err, ErrPasswordNotFound)
}

func TestBackendStore_List_Empty(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	entries, err := s.List()
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestBackendStore_List_MultipleEntries(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	require.NoError(t, s.Add(&StaticPassword{Name: "a", Password: "pass1"}))
	require.NoError(t, s.Add(&StaticPassword{Name: "b", Password: "pass2"}))
	require.NoError(t, s.Add(&StaticPassword{Name: "c", Password: "pass3"}))

	entries, err := s.List()
	require.NoError(t, err)
	assert.Len(t, entries, 3)
}

func TestBackendStore_Update_Success(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "gmail", Password: "old-pass"}
	require.NoError(t, s.Add(pw))

	updated := &StaticPassword{
		ID:       pw.ID,
		Name:     "gmail",
		Password: "new-pass",
	}
	require.NoError(t, s.Update(updated))

	retrieved, err := s.Get(pw.ID)
	require.NoError(t, err)
	assert.Equal(t, "new-pass", retrieved.Password)
	assert.True(t, retrieved.UpdatedAt.After(retrieved.CreatedAt) || retrieved.UpdatedAt.Equal(retrieved.CreatedAt))
}

func TestBackendStore_Update_ByName(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "gmail", Password: "old-pass"}
	require.NoError(t, s.Add(pw))

	// Update requires the ID field to be set; use the ID assigned by Add.
	updated := &StaticPassword{
		ID:       pw.ID,
		Name:     "gmail",
		Password: "new-pass",
	}
	require.NoError(t, s.Update(updated))

	retrieved, err := s.Get(pw.ID)
	require.NoError(t, err)
	assert.Equal(t, "new-pass", retrieved.Password)
}

func TestBackendStore_Update_NotFound(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{ID: "nonexistent-id", Name: "nonexistent", Password: "pass"}
	assert.ErrorIs(t, s.Update(pw), ErrPasswordNotFound)
}

func TestBackendStore_Update_ReadOnly(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "readonly", Password: "pass", ReadOnly: true}
	require.NoError(t, s.Add(pw))

	updated := &StaticPassword{ID: pw.ID, Name: "readonly", Password: "new-pass"}
	assert.ErrorIs(t, s.Update(updated), ErrPasswordReadOnly)
}

func TestBackendStore_Delete_Success(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "gmail", Password: "pass"}
	require.NoError(t, s.Add(pw))

	require.NoError(t, s.Delete(pw.ID))

	_, err := s.Get(pw.ID)
	assert.ErrorIs(t, err, ErrPasswordNotFound)
}

func TestBackendStore_Delete_ByName(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "gmail", Password: "pass"}
	require.NoError(t, s.Add(pw))

	require.NoError(t, s.Delete("gmail"))

	_, err := s.Get("gmail")
	assert.ErrorIs(t, err, ErrPasswordNotFound)
}

func TestBackendStore_Delete_NotFound(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	assert.ErrorIs(t, s.Delete("nonexistent"), ErrPasswordNotFound)
}

func TestBackendStore_Delete_ReadOnly(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "readonly", Password: "pass", ReadOnly: true}
	require.NoError(t, s.Add(pw))

	assert.ErrorIs(t, s.Delete(pw.ID), ErrPasswordReadOnly)
}

func TestBackendStore_ForceDelete_ReadOnly(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "readonly", Password: "pass", ReadOnly: true}
	require.NoError(t, s.Add(pw))

	// ForceDelete bypasses read-only check.
	require.NoError(t, s.ForceDelete(pw.ID))

	_, err := s.Get(pw.ID)
	assert.ErrorIs(t, err, ErrPasswordNotFound)
}

func TestBackendStore_ForceDelete_ByName(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "target", Password: "pass", ReadOnly: true}
	require.NoError(t, s.Add(pw))

	require.NoError(t, s.ForceDelete("target"))

	_, err := s.Get("target")
	assert.ErrorIs(t, err, ErrPasswordNotFound)
}

func TestBackendStore_ForceDelete_NotFound(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	assert.ErrorIs(t, s.ForceDelete("nonexistent"), ErrPasswordNotFound)
}

func TestBackendStore_ForceDelete_Closed(t *testing.T) {
	s := newTestStore()
	require.NoError(t, s.Close())

	assert.ErrorIs(t, s.ForceDelete("anything"), ErrStoreClosed)
}

func TestBackendStore_ListByFolder(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	require.NoError(t, s.Add(&StaticPassword{Name: "a", Password: "p", FolderPath: "email"}))
	require.NoError(t, s.Add(&StaticPassword{Name: "b", Password: "p", FolderPath: "email"}))
	require.NoError(t, s.Add(&StaticPassword{Name: "c", Password: "p", FolderPath: "social"}))

	emailPws, err := s.ListByFolder("email")
	require.NoError(t, err)
	assert.Len(t, emailPws, 2)

	socialPws, err := s.ListByFolder("social")
	require.NoError(t, err)
	assert.Len(t, socialPws, 1)
}

func TestBackendStore_ListByFolder_Empty(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	pws, err := s.ListByFolder("nonexistent")
	require.NoError(t, err)
	assert.Empty(t, pws)
}

func TestBackendStore_ListFolders(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	require.NoError(t, s.Add(&StaticPassword{Name: "a", Password: "p", FolderPath: "email"}))
	require.NoError(t, s.Add(&StaticPassword{Name: "b", Password: "p", FolderPath: "social"}))
	require.NoError(t, s.Add(&StaticPassword{Name: "c", Password: "p"})) // no folder

	folders, err := s.ListFolders()
	require.NoError(t, err)
	assert.Len(t, folders, 2)
	assert.Contains(t, folders, "email")
	assert.Contains(t, folders, "social")
}

func TestBackendStore_ListFolders_NoFolders(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	require.NoError(t, s.Add(&StaticPassword{Name: "a", Password: "p"}))

	folders, err := s.ListFolders()
	require.NoError(t, err)
	assert.Empty(t, folders)
}

func TestBackendStore_MoveToFolder_Success(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "gmail", Password: "pass", FolderPath: "email"}
	require.NoError(t, s.Add(pw))

	require.NoError(t, s.MoveToFolder(pw.ID, "work"))

	// After moving, the ID is regenerated based on the new folder. Look up by name.
	moved, err := s.Get("gmail")
	require.NoError(t, err)
	assert.Equal(t, "work", moved.FolderPath)
	assert.Equal(t, generateID("gmail", "work"), moved.ID)
}

func TestBackendStore_MoveToFolder_SameFolder(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "gmail", Password: "pass", FolderPath: "email"}
	require.NoError(t, s.Add(pw))

	assert.ErrorIs(t, s.MoveToFolder(pw.ID, "email"), ErrMoveToSameFolder)
}

func TestBackendStore_MoveToFolder_ReadOnly(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "readonly", Password: "pass", FolderPath: "a", ReadOnly: true}
	require.NoError(t, s.Add(pw))

	assert.ErrorIs(t, s.MoveToFolder(pw.ID, "b"), ErrPasswordReadOnly)
}

func TestBackendStore_MoveToFolder_NotFound(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	assert.ErrorIs(t, s.MoveToFolder("nonexistent", "folder"), ErrPasswordNotFound)
}

func TestBackendStore_Close_PreventsFurtherOps(t *testing.T) {
	s := newTestStore()
	require.NoError(t, s.Close())

	_, err := s.Get("anything")
	assert.ErrorIs(t, err, ErrStoreClosed)

	_, err = s.List()
	assert.ErrorIs(t, err, ErrStoreClosed)

	assert.ErrorIs(t, s.Add(&StaticPassword{Name: "a", Password: "p"}), ErrStoreClosed)
	assert.ErrorIs(t, s.Update(&StaticPassword{Name: "a", Password: "p"}), ErrStoreClosed)
	assert.ErrorIs(t, s.Delete("a"), ErrStoreClosed)
	assert.ErrorIs(t, s.ForceDelete("a"), ErrStoreClosed)
	_, err = s.ListByFolder("f")
	assert.ErrorIs(t, err, ErrStoreClosed)
	_, err = s.ListFolders()
	assert.ErrorIs(t, err, ErrStoreClosed)
	assert.ErrorIs(t, s.MoveToFolder("a", "b"), ErrStoreClosed)
	assert.ErrorIs(t, s.CreateFolder("f"), ErrStoreClosed)
	assert.ErrorIs(t, s.RemoveFolder("f"), ErrStoreClosed)
}

func TestBackendStore_Add_GeneratesDeterministicID(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "Test", Password: "pass"}
	require.NoError(t, s.Add(pw))

	expectedID := generateID("Test", "")
	assert.Len(t, pw.ID, 16, "ID must be a 16-char hex hash")
	assert.Equal(t, expectedID, pw.ID, "ID must be deterministic from name")

	// Same name (case-insensitive) must produce the same hash.
	assert.Equal(t, generateID("test", ""), pw.ID,
		"case-insensitive names must produce the same ID")

	// Retrieve by name still works via the hashed-ID O(1) lookup.
	retrieved, err := s.Get("Test")
	require.NoError(t, err)
	assert.Equal(t, expectedID, retrieved.ID)
}

func TestBackendStore_Update_PreservesCreatedAt(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "test", Password: "pass"}
	require.NoError(t, s.Add(pw))

	// Strip the monotonic clock reading so the comparison survives JSON roundtrip.
	originalCreatedAt := pw.CreatedAt.Round(0)

	time.Sleep(time.Millisecond)

	// Use the ID assigned by Add for the update lookup.
	updated := &StaticPassword{ID: pw.ID, Name: "test", Password: "new-pass"}
	require.NoError(t, s.Update(updated))

	retrieved, err := s.Get(pw.ID)
	require.NoError(t, err)
	assert.True(t, originalCreatedAt.Equal(retrieved.CreatedAt),
		"CreatedAt must be preserved across updates")
}

// Tenant store tests

func TestNewTenantStore_ValidID(t *testing.T) {
	s, err := NewTenantStore(storage.New(), "tenant-123")
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "test", Password: "pass"}
	require.NoError(t, s.Add(pw))

	retrieved, err := s.Get("test")
	require.NoError(t, err)
	assert.Equal(t, "test", retrieved.Name)
}

func TestNewTenantStore_EmptyID(t *testing.T) {
	_, err := NewTenantStore(storage.New(), "")
	assert.ErrorIs(t, err, ErrInvalidTenantID)
}

func TestNewTenantStore_InvalidChars(t *testing.T) {
	_, err := NewTenantStore(storage.New(), "tenant/invalid")
	assert.ErrorIs(t, err, ErrInvalidTenantID)
}

func TestNewTenantStore_TooLong(t *testing.T) {
	longID := "a"
	for len(longID) <= 64 {
		longID += "a"
	}
	_, err := NewTenantStore(storage.New(), longID)
	assert.ErrorIs(t, err, ErrInvalidTenantID)
}

func TestNewTenantStore_HyphenAtStart(t *testing.T) {
	_, err := NewTenantStore(storage.New(), "-invalid")
	assert.ErrorIs(t, err, ErrInvalidTenantID)
}

func TestNewTenantStore_HyphenAtEnd(t *testing.T) {
	// Trailing hyphens are valid per the regex pattern.
	s, err := NewTenantStore(storage.New(), "valid-")
	assert.NoError(t, err)
	assert.NotNil(t, s)
	defer func() { _ = s.Close() }()
}

func TestNewTenantStore_SingleChar(t *testing.T) {
	s, err := NewTenantStore(storage.New(), "a")
	require.NoError(t, err)
	assert.NotNil(t, s)
	defer func() { _ = s.Close() }()
}

func TestTenantStore_Isolation(t *testing.T) {
	backend := storage.New()

	s1, err := NewTenantStore(backend, "tenant1")
	require.NoError(t, err)

	s2, err := NewTenantStore(backend, "tenant2")
	require.NoError(t, err)

	require.NoError(t, s1.Add(&StaticPassword{Name: "shared-name", Password: "pass1"}))
	require.NoError(t, s2.Add(&StaticPassword{Name: "shared-name", Password: "pass2"}))

	pw1, err := s1.Get("shared-name")
	require.NoError(t, err)
	assert.Equal(t, "pass1", pw1.Password)

	pw2, err := s2.Get("shared-name")
	require.NoError(t, err)
	assert.Equal(t, "pass2", pw2.Password)

	list1, err := s1.List()
	require.NoError(t, err)
	assert.Len(t, list1, 1)

	list2, err := s2.List()
	require.NoError(t, err)
	assert.Len(t, list2, 1)
}

func TestBackendStore_ImplementsStoreInterface(t *testing.T) {
	var _ Store = (*BackendStore)(nil)
}

// --- NewSharedTenantStore ---

func TestNewSharedTenantStore_Success(t *testing.T) {
	s, err := NewSharedTenantStore(storage.New(), "tenant-1")
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "shared-pw", Password: "pass"}
	require.NoError(t, s.Add(pw))

	retrieved, err := s.Get("shared-pw")
	require.NoError(t, err)
	assert.Equal(t, "pass", retrieved.Password)
}

func TestNewSharedTenantStore_InvalidTenantID(t *testing.T) {
	_, err := NewSharedTenantStore(storage.New(), "")
	assert.ErrorIs(t, err, ErrInvalidTenantID)

	_, err = NewSharedTenantStore(storage.New(), "bad/id")
	assert.ErrorIs(t, err, ErrInvalidTenantID)
}

func TestNewSharedTenantStore_KeyPrefix(t *testing.T) {
	backend := storage.New()
	s, err := NewSharedTenantStore(backend, "acme")
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "test", Password: "p"}
	require.NoError(t, s.Add(pw))

	// The storage key uses the hashed ID, not the raw name.
	expectedKey := "acme/staticpw/shared/" + generateID("test", "") + ".json"

	// Verify the key prefix is correct by listing from the backend directly.
	keys, err := backend.List(context.Background(), "acme/staticpw/shared/")
	require.NoError(t, err)
	assert.Len(t, keys, 1)
	assert.Equal(t, expectedKey, keys[0])
}

// --- NewPersonalTenantStore ---

func TestNewPersonalTenantStore_Success(t *testing.T) {
	s, err := NewPersonalTenantStore(storage.New(), "tenant-1", "alice")
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "my-pw", Password: "secret"}
	require.NoError(t, s.Add(pw))

	retrieved, err := s.Get("my-pw")
	require.NoError(t, err)
	assert.Equal(t, "secret", retrieved.Password)
}

func TestNewPersonalTenantStore_InvalidTenantID(t *testing.T) {
	_, err := NewPersonalTenantStore(storage.New(), "", "alice")
	assert.ErrorIs(t, err, ErrInvalidTenantID)
}

func TestNewPersonalTenantStore_InvalidUserID(t *testing.T) {
	_, err := NewPersonalTenantStore(storage.New(), "tenant-1", "")
	assert.ErrorIs(t, err, ErrInvalidUserID)

	_, err = NewPersonalTenantStore(storage.New(), "tenant-1", "bad/user")
	assert.ErrorIs(t, err, ErrInvalidUserID)
}

func TestNewPersonalTenantStore_KeyPrefix(t *testing.T) {
	backend := storage.New()
	s, err := NewPersonalTenantStore(backend, "acme", "alice@acme.com")
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "test", Password: "p"}
	require.NoError(t, s.Add(pw))

	// The storage key uses the hashed ID, not the raw name.
	expectedKey := "acme/staticpw/users/alice@acme.com/" + generateID("test", "") + ".json"

	keys, err := backend.List(context.Background(), "acme/staticpw/users/alice@acme.com/")
	require.NoError(t, err)
	assert.Len(t, keys, 1)
	assert.Equal(t, expectedKey, keys[0])
}

func TestNewPersonalTenantStore_EmailUserID(t *testing.T) {
	s, err := NewPersonalTenantStore(storage.New(), "acme", "user@example.com")
	require.NoError(t, err)
	assert.NotNil(t, s)
	defer func() { _ = s.Close() }()
}

func TestNewPersonalTenantStore_DotUserID(t *testing.T) {
	s, err := NewPersonalTenantStore(storage.New(), "acme", "first.last")
	require.NoError(t, err)
	assert.NotNil(t, s)
	defer func() { _ = s.Close() }()
}

// --- Personal vs Shared Isolation ---

func TestSharedAndPersonal_Isolation(t *testing.T) {
	backend := storage.New()

	shared, err := NewSharedTenantStore(backend, "acme")
	require.NoError(t, err)
	defer func() { _ = shared.Close() }()

	personal, err := NewPersonalTenantStore(backend, "acme", "alice")
	require.NoError(t, err)
	defer func() { _ = personal.Close() }()

	// Add same-name entry to both stores.
	require.NoError(t, shared.Add(&StaticPassword{Name: "gmail", Password: "shared-pass"}))
	require.NoError(t, personal.Add(&StaticPassword{Name: "gmail", Password: "personal-pass"}))

	// Each store sees only its own entry.
	sharedPW, err := shared.Get("gmail")
	require.NoError(t, err)
	assert.Equal(t, "shared-pass", sharedPW.Password)

	personalPW, err := personal.Get("gmail")
	require.NoError(t, err)
	assert.Equal(t, "personal-pass", personalPW.Password)

	sharedList, err := shared.List()
	require.NoError(t, err)
	assert.Len(t, sharedList, 1)

	personalList, err := personal.List()
	require.NoError(t, err)
	assert.Len(t, personalList, 1)
}

// --- isValidUserID ---

func TestIsValidUserID_ValidCases(t *testing.T) {
	validIDs := []string{
		"alice",
		"bob123",
		"user_name",
		"user-name",
		"user.name",
		"user@example.com",
		"A1",
		"a",
	}
	for _, id := range validIDs {
		assert.True(t, isValidUserID(id), "expected valid: %s", id)
	}
}

func TestIsValidUserID_InvalidCases(t *testing.T) {
	invalidIDs := []string{
		"",
		"-startswithhyphen",
		".startwithdot",
		"@startswithatsign",
		"_startswithunderscore",
		"user/slash",
		"user name",
		"user\ttab",
	}
	for _, id := range invalidIDs {
		assert.False(t, isValidUserID(id), "expected invalid: %s", id)
	}
}

func TestIsValidUserID_TooLong(t *testing.T) {
	longID := "a"
	for len(longID) <= maxUserIDLength {
		longID += "a"
	}
	assert.False(t, isValidUserID(longID))
}

func TestIsValidUserID_MaxLength(t *testing.T) {
	maxID := ""
	for len(maxID) < maxUserIDLength {
		maxID += "a"
	}
	assert.True(t, isValidUserID(maxID))
}

// --- Targeted coverage tests ---

func TestBackendStore_TenantID(t *testing.T) {
	backend := storage.New()

	// Tenant store returns its tenant ID.
	tenantStore, err := NewTenantStore(backend, "my-tenant")
	require.NoError(t, err)
	assert.Equal(t, "my-tenant", tenantStore.TenantID())
	_ = tenantStore.Close()

	// System store has empty tenant ID.
	sysStore := NewStore(backend)
	assert.Equal(t, "", sysStore.TenantID())
	_ = sysStore.Close()
}

func TestBackendStore_Get_CorruptedJSON(t *testing.T) {
	backend := storage.New()

	// Write corrupted data directly to the backend at the expected key path.
	require.NoError(t, backend.Put(context.Background(), "staticpw/bad-entry.json", []byte("not-valid-json")))

	store := NewStore(backend)
	defer func() { _ = store.Close() }()

	// Lookup by ID (exact key match) should fail with unmarshal error.
	_, err := store.Get("bad-entry")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnmarshalFailed)
}

func TestBackendStore_Delete_ReadOnlyByName(t *testing.T) {
	store := newTestStore()
	defer func() { _ = store.Close() }()

	pw := &StaticPassword{Name: "Protected", Password: "p", ReadOnly: true}
	require.NoError(t, store.Add(pw))

	// The ID is now a 16-char hex hash (generateID lowercases the name).
	expectedID := generateID("Protected", "")
	assert.Equal(t, expectedID, pw.ID)
	assert.Len(t, pw.ID, 16)

	// Use a fabricated raw hex ID that does not match the stored hash
	// to force the name-scan fallback path in getUnlocked. The exact
	// ID lookup (step 1) will miss because this key does not exist in
	// the backend, and the hashed-name lookup (step 2) will also miss
	// because generateID("does-not-exist-in-store","") produces a
	// different hash. This forces step 3 (findByName scan).
	// However, since Delete takes idOrName and getUnlocked handles name
	// lookups, we can simply pass the original name to verify the
	// read-only guard works through name-based lookup.
	err := store.Delete("Protected")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPasswordReadOnly)
}

func TestBackendStore_List_SkipsCorruptedEntries(t *testing.T) {
	backend := storage.New()
	store := NewStore(backend)

	// Add a valid entry.
	require.NoError(t, store.Add(&StaticPassword{Name: "Valid", Password: "p"}))

	// Inject a corrupted entry directly into the backend.
	require.NoError(t, backend.Put(context.Background(), "staticpw/corrupt.json", []byte("not-json")))

	// List should skip the corrupted entry and return only valid ones.
	entries, err := store.List()
	require.NoError(t, err)
	assert.Len(t, entries, 1)
	assert.Equal(t, "Valid", entries[0].Name)

	_ = store.Close()
}

func TestBackendStore_FindByName_SkipsCorruptedEntries(t *testing.T) {
	backend := storage.New()
	store := NewStore(backend)

	// Add a valid entry.
	require.NoError(t, store.Add(&StaticPassword{Name: "Target", Password: "p"}))

	// Inject a corrupted entry that precedes "Target" alphabetically.
	require.NoError(t, backend.Put(context.Background(), "staticpw/aaa-corrupt.json", []byte("{bad json}")))

	// Get by name should skip the corrupted entry and find "Target".
	pw, err := store.Get("Target")
	require.NoError(t, err)
	assert.Equal(t, "Target", pw.Name)

	_ = store.Close()
}

func TestBackendStore_CheckNameConflict_ExcludeID(t *testing.T) {
	backend := storage.New()
	store := NewStore(backend)
	defer func() { _ = store.Close() }()

	// Add two entries.
	alphaPW := &StaticPassword{Name: "Alpha", Password: "p"}
	require.NoError(t, store.Add(alphaPW))
	require.NoError(t, store.Add(&StaticPassword{Name: "Beta", Password: "p"}))

	alphaID := alphaPW.ID

	// Directly call checkNameConflict with excludeID to verify it skips the
	// excluded entry. This exercises the excludeID != "" path.
	// Checking for "Alpha" excluding its own ID should return nil (no conflict).
	store.mu.Lock()
	err := store.checkNameConflict("Alpha", "", alphaID)
	store.mu.Unlock()
	assert.NoError(t, err, "checkNameConflict should skip the excluded ID")

	// Checking for "Beta" excluding Alpha's ID should return ErrPasswordExists.
	store.mu.Lock()
	err = store.checkNameConflict("Beta", "", alphaID)
	store.mu.Unlock()
	assert.ErrorIs(t, err, ErrPasswordExists)

	// Checking for "Gamma" (no conflict) should return nil regardless of excludeID.
	store.mu.Lock()
	err = store.checkNameConflict("Gamma", "", alphaID)
	store.mu.Unlock()
	assert.NoError(t, err)
}

func TestBackendStore_CheckNameConflict_SkipsCorruptedEntries(t *testing.T) {
	backend := storage.New()
	store := NewStore(backend)
	defer func() { _ = store.Close() }()

	// Add a valid entry.
	require.NoError(t, store.Add(&StaticPassword{Name: "Valid", Password: "p"}))

	// Inject a corrupted entry.
	require.NoError(t, backend.Put(context.Background(), "staticpw/corrupt.json", []byte("not-json")))

	// checkNameConflict should skip the corrupted entry and not report a false
	// conflict for a name that doesn't match any valid entry.
	store.mu.Lock()
	err := store.checkNameConflict("NoMatch", "", "")
	store.mu.Unlock()
	assert.NoError(t, err)

	// But it should still detect conflicts against valid entries.
	store.mu.Lock()
	err = store.checkNameConflict("Valid", "", "")
	store.mu.Unlock()
	assert.ErrorIs(t, err, ErrPasswordExists)
}

func TestBackendStore_Update_CorruptedExistingEntry(t *testing.T) {
	backend := storage.New()
	store := NewStore(backend)
	defer func() { _ = store.Close() }()

	// Inject a corrupted entry directly.
	require.NoError(t, backend.Put(context.Background(), "staticpw/corrupted.json", []byte("not-json")))

	// Attempt to update the corrupted entry by its ID.
	pw := &StaticPassword{ID: "corrupted", Name: "corrupted", Password: "new-pass"}
	err := store.Update(pw)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnmarshalFailed)
}

// --- CreateFolder / RemoveFolder ---

func TestBackendStore_CreateFolder(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	require.NoError(t, s.CreateFolder("work"))
	require.NoError(t, s.CreateFolder("personal/email"))

	folders, err := s.ListFolders()
	require.NoError(t, err)
	assert.Contains(t, folders, "work")
	assert.Contains(t, folders, "personal/email")
}

func TestBackendStore_CreateFolder_Empty(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	assert.ErrorIs(t, s.CreateFolder(""), ErrFolderEmpty)
}

func TestBackendStore_CreateFolder_Closed(t *testing.T) {
	s := newTestStore()
	require.NoError(t, s.Close())

	assert.ErrorIs(t, s.CreateFolder("work"), ErrStoreClosed)
}

func TestBackendStore_RemoveFolder(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	require.NoError(t, s.CreateFolder("work"))
	folders, err := s.ListFolders()
	require.NoError(t, err)
	assert.Contains(t, folders, "work")

	require.NoError(t, s.RemoveFolder("work"))
	folders, err = s.ListFolders()
	require.NoError(t, err)
	assert.NotContains(t, folders, "work")
}

func TestBackendStore_RemoveFolder_Nonexistent(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	// Should be idempotent.
	require.NoError(t, s.RemoveFolder("nonexistent"))
}

func TestBackendStore_RemoveFolder_Empty(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	assert.ErrorIs(t, s.RemoveFolder(""), ErrFolderEmpty)
}

func TestBackendStore_RemoveFolder_Closed(t *testing.T) {
	s := newTestStore()
	require.NoError(t, s.Close())

	assert.ErrorIs(t, s.RemoveFolder("work"), ErrStoreClosed)
}

func TestBackendStore_ListFolders_MergesImplicitAndExplicit(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	// Add an entry with folder "email".
	require.NoError(t, s.Add(&StaticPassword{Name: "a", Password: "p", FolderPath: "email"}))
	// Create an empty folder "work".
	require.NoError(t, s.CreateFolder("work"))

	folders, err := s.ListFolders()
	require.NoError(t, err)
	assert.Contains(t, folders, "email")
	assert.Contains(t, folders, "work")
}

func TestBackendStore_CreateFolder_DoesNotPolluteList(t *testing.T) {
	s := newTestStore()
	defer func() { _ = s.Close() }()

	require.NoError(t, s.CreateFolder("empty-folder"))
	require.NoError(t, s.Add(&StaticPassword{Name: "real", Password: "p"}))

	// List should only return real entries, not folder markers.
	entries, err := s.List()
	require.NoError(t, err)
	assert.Len(t, entries, 1)
	assert.Equal(t, "real", entries[0].Name)
}
