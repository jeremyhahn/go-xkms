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
	"errors"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-xkms/pkg/dao"
)

// newMemoryDAOs returns a DAO factory over a fresh in-memory go-qrdb store.
func newMemoryDAOs() *qrdbsdk.DAOFactory {
	return dao.NewStoreFactory(qrdbsdk.NewMemoryKVStore())
}

// newTestStore returns the platform store over a fresh in-memory store.
func newTestStore(t testing.TB) *DAOStore {
	t.Helper()
	s, err := NewStore(newMemoryDAOs())
	require.NoError(t, err)
	return s
}

func TestDAOStore_Add_Success(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "gmail", Password: "secret123"}
	require.NoError(t, s.Add(pw))

	assert.NotEmpty(t, pw.ID)
	assert.False(t, pw.CreatedAt.IsZero())
	assert.False(t, pw.UpdatedAt.IsZero())
}

// TestDAOStore_Add_PersistsAttributes proves the generic Attributes bag
// (added for xkey/pkg/secretservice's Secret Service item model) survives a
// round trip through JSON marshal/unmarshal in Add and Get, the same as
// every other field.
func TestDAOStore_Add_PersistsAttributes(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{
		Name:       "github",
		Password:   "secret123",
		Attributes: map[string]string{"host": "github.com", "protocol": "https"},
	}
	require.NoError(t, s.Add(pw))

	got, err := s.Get(pw.ID)
	require.NoError(t, err)
	assert.Equal(t, "github.com", got.Attributes["host"])
	assert.Equal(t, "https", got.Attributes["protocol"])
}

// TestDAOStore_Add_NilAttributesRoundTrips proves an entry with no
// Attributes at all (the common case for anything not created through the
// Secret Service object model) round-trips cleanly rather than gaining an
// empty map.
func TestDAOStore_Add_NilAttributesRoundTrips(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "gmail", Password: "secret123"}
	require.NoError(t, s.Add(pw))

	got, err := s.Get(pw.ID)
	require.NoError(t, err)
	assert.Empty(t, got.Attributes)
}

func TestDAOStore_Add_MissingName(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Password: "secret123"}
	assert.ErrorIs(t, s.Add(pw), ErrInvalidName)
}

func TestDAOStore_Add_MissingPassword(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "gmail"}
	assert.ErrorIs(t, s.Add(pw), ErrEmptyPassword)
}

func TestDAOStore_Add_DuplicateName(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	pw1 := &StaticPassword{Name: "gmail", Password: "secret1"}
	require.NoError(t, s.Add(pw1))

	pw2 := &StaticPassword{Name: "gmail", Password: "secret2"}
	assert.ErrorIs(t, s.Add(pw2), ErrPasswordExists)
}

func TestDAOStore_Get_ByID(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "gmail", Password: "secret123"}
	require.NoError(t, s.Add(pw))

	retrieved, err := s.Get(pw.ID)
	require.NoError(t, err)
	assert.Equal(t, pw.ID, retrieved.ID)
	assert.Equal(t, "gmail", retrieved.Name)
	assert.Equal(t, "secret123", retrieved.Password)
}

func TestDAOStore_Get_ByName(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "gmail", Password: "secret123"}
	require.NoError(t, s.Add(pw))

	retrieved, err := s.Get("gmail")
	require.NoError(t, err)
	assert.Equal(t, pw.ID, retrieved.ID)
}

func TestDAOStore_Get_CaseInsensitiveName(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "Gmail", Password: "secret123"}
	require.NoError(t, s.Add(pw))

	retrieved, err := s.Get("gmail")
	require.NoError(t, err)
	assert.Equal(t, pw.ID, retrieved.ID)
}

func TestDAOStore_Get_NotFound(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	_, err := s.Get("nonexistent")
	assert.ErrorIs(t, err, ErrPasswordNotFound)
}

func TestDAOStore_List_Empty(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	entries, err := s.List()
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestDAOStore_List_MultipleEntries(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	require.NoError(t, s.Add(&StaticPassword{Name: "a", Password: "pass1"}))
	require.NoError(t, s.Add(&StaticPassword{Name: "b", Password: "pass2"}))
	require.NoError(t, s.Add(&StaticPassword{Name: "c", Password: "pass3"}))

	entries, err := s.List()
	require.NoError(t, err)
	assert.Len(t, entries, 3)
}

func TestDAOStore_Update_Success(t *testing.T) {
	s := newTestStore(t)
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

func TestDAOStore_Update_ByName(t *testing.T) {
	s := newTestStore(t)
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

func TestDAOStore_Update_NotFound(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{ID: "nonexistent-id", Name: "nonexistent", Password: "pass"}
	assert.ErrorIs(t, s.Update(pw), ErrPasswordNotFound)
}

func TestDAOStore_Update_ReadOnly(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "readonly", Password: "pass", ReadOnly: true}
	require.NoError(t, s.Add(pw))

	updated := &StaticPassword{ID: pw.ID, Name: "readonly", Password: "new-pass"}
	assert.ErrorIs(t, s.Update(updated), ErrPasswordReadOnly)
}

func TestDAOStore_Delete_Success(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "gmail", Password: "pass"}
	require.NoError(t, s.Add(pw))

	require.NoError(t, s.Delete(pw.ID))

	_, err := s.Get(pw.ID)
	assert.ErrorIs(t, err, ErrPasswordNotFound)
}

func TestDAOStore_Delete_ByName(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "gmail", Password: "pass"}
	require.NoError(t, s.Add(pw))

	require.NoError(t, s.Delete("gmail"))

	_, err := s.Get("gmail")
	assert.ErrorIs(t, err, ErrPasswordNotFound)
}

func TestDAOStore_Delete_NotFound(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	assert.ErrorIs(t, s.Delete("nonexistent"), ErrPasswordNotFound)
}

func TestDAOStore_Delete_ReadOnly(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "readonly", Password: "pass", ReadOnly: true}
	require.NoError(t, s.Add(pw))

	assert.ErrorIs(t, s.Delete(pw.ID), ErrPasswordReadOnly)
}

func TestDAOStore_ForceDelete_ReadOnly(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "readonly", Password: "pass", ReadOnly: true}
	require.NoError(t, s.Add(pw))

	// ForceDelete bypasses read-only check.
	require.NoError(t, s.ForceDelete(pw.ID))

	_, err := s.Get(pw.ID)
	assert.ErrorIs(t, err, ErrPasswordNotFound)
}

func TestDAOStore_ForceDelete_ByName(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "target", Password: "pass", ReadOnly: true}
	require.NoError(t, s.Add(pw))

	require.NoError(t, s.ForceDelete("target"))

	_, err := s.Get("target")
	assert.ErrorIs(t, err, ErrPasswordNotFound)
}

func TestDAOStore_ForceDelete_NotFound(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	assert.ErrorIs(t, s.ForceDelete("nonexistent"), ErrPasswordNotFound)
}

func TestDAOStore_ForceDelete_Closed(t *testing.T) {
	s := newTestStore(t)
	require.NoError(t, s.Close())

	assert.ErrorIs(t, s.ForceDelete("anything"), ErrStoreClosed)
}

func TestDAOStore_ListByFolder(t *testing.T) {
	s := newTestStore(t)
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

func TestDAOStore_ListByFolder_Empty(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	pws, err := s.ListByFolder("nonexistent")
	require.NoError(t, err)
	assert.Empty(t, pws)
}

func TestDAOStore_ListFolders(t *testing.T) {
	s := newTestStore(t)
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

func TestDAOStore_ListFolders_NoFolders(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	require.NoError(t, s.Add(&StaticPassword{Name: "a", Password: "p"}))

	folders, err := s.ListFolders()
	require.NoError(t, err)
	assert.Empty(t, folders)
}

func TestDAOStore_MoveToFolder_Success(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "gmail", Password: "pass", FolderPath: "email"}
	require.NoError(t, s.Add(pw))

	require.NoError(t, s.MoveToFolder(pw.ID, "work"))

	// After moving, the ID is regenerated based on the new folder. Look up by name.
	moved, err := s.Get("gmail")
	require.NoError(t, err)
	assert.Equal(t, "work", moved.FolderPath)
	assert.Equal(t, GenerateID("gmail", "work"), moved.ID)
}

func TestDAOStore_MoveToFolder_SameFolder(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "gmail", Password: "pass", FolderPath: "email"}
	require.NoError(t, s.Add(pw))

	assert.ErrorIs(t, s.MoveToFolder(pw.ID, "email"), ErrMoveToSameFolder)
}

func TestDAOStore_MoveToFolder_ReadOnly(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "readonly", Password: "pass", FolderPath: "a", ReadOnly: true}
	require.NoError(t, s.Add(pw))

	assert.ErrorIs(t, s.MoveToFolder(pw.ID, "b"), ErrPasswordReadOnly)
}

func TestDAOStore_MoveToFolder_NotFound(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	assert.ErrorIs(t, s.MoveToFolder("nonexistent", "folder"), ErrPasswordNotFound)
}

func TestDAOStore_Close_PreventsFurtherOps(t *testing.T) {
	s := newTestStore(t)
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

func TestDAOStore_Add_GeneratesDeterministicID(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "Test", Password: "pass"}
	require.NoError(t, s.Add(pw))

	expectedID := GenerateID("Test", "")
	assert.Len(t, pw.ID, 16, "ID must be a 16-char hex hash")
	assert.Equal(t, expectedID, pw.ID, "ID must be deterministic from name")

	// Same name (case-insensitive) must produce the same hash.
	assert.Equal(t, GenerateID("test", ""), pw.ID,
		"case-insensitive names must produce the same ID")

	// Retrieve by name still works via the hashed-ID O(1) lookup.
	retrieved, err := s.Get("Test")
	require.NoError(t, err)
	assert.Equal(t, expectedID, retrieved.ID)
}

func TestDAOStore_Update_PreservesCreatedAt(t *testing.T) {
	s := newTestStore(t)
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
	s, err := NewTenantStore(newMemoryDAOs(), "tenant-123")
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "test", Password: "pass"}
	require.NoError(t, s.Add(pw))

	retrieved, err := s.Get("test")
	require.NoError(t, err)
	assert.Equal(t, "test", retrieved.Name)
}

func TestNewTenantStore_EmptyID(t *testing.T) {
	_, err := NewTenantStore(newMemoryDAOs(), "")
	assert.ErrorIs(t, err, ErrInvalidTenantID)
}

func TestNewTenantStore_InvalidChars(t *testing.T) {
	_, err := NewTenantStore(newMemoryDAOs(), "tenant/invalid")
	assert.ErrorIs(t, err, ErrInvalidTenantID)
}

func TestNewTenantStore_TooLong(t *testing.T) {
	longID := "a"
	for len(longID) <= 64 {
		longID += "a"
	}
	_, err := NewTenantStore(newMemoryDAOs(), longID)
	assert.ErrorIs(t, err, ErrInvalidTenantID)
}

func TestNewTenantStore_HyphenAtStart(t *testing.T) {
	_, err := NewTenantStore(newMemoryDAOs(), "-invalid")
	assert.ErrorIs(t, err, ErrInvalidTenantID)
}

func TestNewTenantStore_HyphenAtEnd(t *testing.T) {
	// Trailing hyphens are valid per the regex pattern.
	s, err := NewTenantStore(newMemoryDAOs(), "valid-")
	assert.NoError(t, err)
	assert.NotNil(t, s)
	defer func() { _ = s.Close() }()
}

func TestNewTenantStore_SingleChar(t *testing.T) {
	s, err := NewTenantStore(newMemoryDAOs(), "a")
	require.NoError(t, err)
	assert.NotNil(t, s)
	defer func() { _ = s.Close() }()
}

func TestTenantStore_Isolation(t *testing.T) {
	backend := newMemoryDAOs()

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

func TestDAOStore_ImplementsStoreInterface(t *testing.T) {
	var _ Store = (*DAOStore)(nil)
}

// --- NewSharedTenantStore ---

func TestNewSharedTenantStore_Success(t *testing.T) {
	s, err := NewSharedTenantStore(newMemoryDAOs(), "tenant-1")
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "shared-pw", Password: "pass"}
	require.NoError(t, s.Add(pw))

	retrieved, err := s.Get("shared-pw")
	require.NoError(t, err)
	assert.Equal(t, "pass", retrieved.Password)
}

func TestNewSharedTenantStore_InvalidTenantID(t *testing.T) {
	_, err := NewSharedTenantStore(newMemoryDAOs(), "")
	assert.ErrorIs(t, err, ErrInvalidTenantID)

	_, err = NewSharedTenantStore(newMemoryDAOs(), "bad/id")
	assert.ErrorIs(t, err, ErrInvalidTenantID)
}

func TestNewSharedTenantStore_KeyPrefix(t *testing.T) {
	s, err := NewSharedTenantStore(newMemoryDAOs(), "acme")
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "test", Password: "p"}
	require.NoError(t, s.Add(pw))

	// The record path uses the hashed ID, not the raw name.
	assertEntryPaths(t, s, "acme/staticpw/shared/entry/"+GenerateID("test", ""))
}

// assertEntryPaths asserts the store's entry records are exactly want.
func assertEntryPaths(t *testing.T, s *DAOStore, want ...string) {
	t.Helper()
	all, err := s.records.list(context.Background(), s.dir(nameKindEntry))
	require.NoError(t, err)
	paths := make([]string, 0, len(all))
	for _, r := range all {
		paths = append(paths, r.Path)
	}
	assert.ElementsMatch(t, want, paths)
}

// putRawEntry stores body as the entry record of id, bypassing encoding.
func putRawEntry(t *testing.T, s *DAOStore, id string, body []byte) {
	t.Helper()
	r := &record{Path: s.entryPath(id), Dir: s.dir(nameKindEntry), Body: body}
	require.NoError(t, s.records.put(context.Background(), r))
}

// --- NewPersonalTenantStore ---

func TestNewPersonalTenantStore_Success(t *testing.T) {
	s, err := NewPersonalTenantStore(newMemoryDAOs(), "tenant-1", "alice")
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "my-pw", Password: "secret"}
	require.NoError(t, s.Add(pw))

	retrieved, err := s.Get("my-pw")
	require.NoError(t, err)
	assert.Equal(t, "secret", retrieved.Password)
}

func TestNewPersonalTenantStore_InvalidTenantID(t *testing.T) {
	_, err := NewPersonalTenantStore(newMemoryDAOs(), "", "alice")
	assert.ErrorIs(t, err, ErrInvalidTenantID)
}

func TestNewPersonalTenantStore_InvalidUserID(t *testing.T) {
	_, err := NewPersonalTenantStore(newMemoryDAOs(), "tenant-1", "")
	assert.ErrorIs(t, err, ErrInvalidUserID)

	_, err = NewPersonalTenantStore(newMemoryDAOs(), "tenant-1", "bad/user")
	assert.ErrorIs(t, err, ErrInvalidUserID)
}

func TestNewPersonalTenantStore_KeyPrefix(t *testing.T) {
	s, err := NewPersonalTenantStore(newMemoryDAOs(), "acme", "alice@acme.com")
	require.NoError(t, err)
	defer func() { _ = s.Close() }()

	pw := &StaticPassword{Name: "test", Password: "p"}
	require.NoError(t, s.Add(pw))

	// The record path uses the hashed ID, not the raw name.
	assertEntryPaths(t, s, "acme/staticpw/users/alice@acme.com/entry/"+GenerateID("test", ""))
}

func TestNewPersonalTenantStore_EmailUserID(t *testing.T) {
	s, err := NewPersonalTenantStore(newMemoryDAOs(), "acme", "user@example.com")
	require.NoError(t, err)
	assert.NotNil(t, s)
	defer func() { _ = s.Close() }()
}

func TestNewPersonalTenantStore_DotUserID(t *testing.T) {
	s, err := NewPersonalTenantStore(newMemoryDAOs(), "acme", "first.last")
	require.NoError(t, err)
	assert.NotNil(t, s)
	defer func() { _ = s.Close() }()
}

// --- Personal vs Shared Isolation ---

func TestSharedAndPersonal_Isolation(t *testing.T) {
	backend := newMemoryDAOs()

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

func TestDAOStore_TenantID(t *testing.T) {
	backend := newMemoryDAOs()

	// Tenant store returns its tenant ID.
	tenantStore, err := NewTenantStore(backend, "my-tenant")
	require.NoError(t, err)
	assert.Equal(t, "my-tenant", tenantStore.TenantID())
	_ = tenantStore.Close()

	// System store has empty tenant ID.
	sysStore, err := NewStore(backend)
	require.NoError(t, err)
	assert.Equal(t, "", sysStore.TenantID())
	_ = sysStore.Close()
}

func TestNewStore_NilFactory(t *testing.T) {
	_, err := NewStore(nil)
	var creation ErrDAOCreation
	require.ErrorAs(t, err, &creation)
	assert.ErrorIs(t, err, dao.ErrNilFactory)

	_, err = NewTenantStore(nil, "acme")
	assert.ErrorIs(t, err, dao.ErrNilFactory)
}

func TestDAOStore_Get_CorruptedJSON(t *testing.T) {
	store := newTestStore(t)
	defer func() { _ = store.Close() }()

	putRawEntry(t, store, "bad-entry", []byte("not-valid-json"))

	// Lookup by ID (exact key match) should fail with unmarshal error.
	_, err := store.Get("bad-entry")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnmarshalFailed)
}

func TestDAOStore_Delete_ReadOnlyByName(t *testing.T) {
	store := newTestStore(t)
	defer func() { _ = store.Close() }()

	pw := &StaticPassword{Name: "Protected", Password: "p", ReadOnly: true}
	require.NoError(t, store.Add(pw))

	// The ID is now a 16-char hex hash (generateID lowercases the name).
	expectedID := GenerateID("Protected", "")
	assert.Equal(t, expectedID, pw.ID)
	assert.Len(t, pw.ID, 16)

	// Use a fabricated raw hex ID that does not match the stored hash
	// to force the name-scan fallback path in getUnlocked. The exact
	// ID lookup (step 1) will miss because this key does not exist in
	// the backend, and the hashed-name lookup (step 2) will also miss
	// because GenerateID("does-not-exist-in-store","") produces a
	// different hash. This forces step 3 (findByName scan).
	// However, since Delete takes idOrName and getUnlocked handles name
	// lookups, we can simply pass the original name to verify the
	// read-only guard works through name-based lookup.
	err := store.Delete("Protected")
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrPasswordReadOnly)
}

// A record that does not decode fails List loudly rather than vanishing
// from it, so a damaged entry is never silently dropped.
func TestDAOStore_List_CorruptedEntryFails(t *testing.T) {
	store := newTestStore(t)
	defer func() { _ = store.Close() }()

	require.NoError(t, store.Add(&StaticPassword{Name: "Valid", Password: "p"}))
	putRawEntry(t, store, "corrupt", []byte("not-json"))

	_, err := store.List()
	assert.ErrorIs(t, err, ErrUnmarshalFailed)
}

func TestDAOStore_Get_ByIDDespiteCorruptedEntry(t *testing.T) {
	store := newTestStore(t)
	defer func() { _ = store.Close() }()

	require.NoError(t, store.Add(&StaticPassword{Name: "Target", Password: "p"}))
	putRawEntry(t, store, "aaa-corrupt", []byte("{bad json}"))

	// A root-level name resolves through its hashed ID without a scan.
	pw, err := store.Get("Target")
	require.NoError(t, err)
	assert.Equal(t, "Target", pw.Name)

	// A name scan meets the corrupted entry and reports it.
	_, err = store.Get("absent")
	assert.ErrorIs(t, err, ErrUnmarshalFailed)
}

func TestDAOStore_Update_CorruptedExistingEntry(t *testing.T) {
	store := newTestStore(t)
	defer func() { _ = store.Close() }()

	putRawEntry(t, store, "corrupted", []byte("not-json"))

	// Attempt to update the corrupted entry by its ID.
	pw := &StaticPassword{ID: "corrupted", Name: "corrupted", Password: "new-pass"}
	err := store.Update(pw)
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrUnmarshalFailed)
}

// Two stores over one table see each other's writes: the guarded writes
// keep a stale writer from overwriting or deleting a newer record.
func TestDAOStore_SharedTable_RoundTrip(t *testing.T) {
	daos := newMemoryDAOs()
	first, err := NewTenantStore(daos, "acme")
	require.NoError(t, err)
	second, err := NewTenantStore(daos, "acme")
	require.NoError(t, err)

	pw := &StaticPassword{Name: "db", Password: "one"}
	require.NoError(t, first.Add(pw))
	assert.ErrorIs(t, second.Add(&StaticPassword{Name: "DB", Password: "two"}), ErrPasswordExists)

	pw.Password = "updated"
	require.NoError(t, first.Update(pw))
	got, err := second.Get("db")
	require.NoError(t, err)
	assert.Equal(t, "updated", got.Password)

	require.NoError(t, second.Delete("db"))
	_, err = first.Get("db")
	assert.ErrorIs(t, err, ErrPasswordNotFound)
}

func TestDAOStore_Update_RenameToTakenName(t *testing.T) {
	store := newTestStore(t)
	defer func() { _ = store.Close() }()

	alpha := &StaticPassword{Name: "alpha", Password: "p"}
	require.NoError(t, store.Add(alpha))
	require.NoError(t, store.Add(&StaticPassword{Name: "beta", Password: "p"}))

	alpha.Name = "beta"
	assert.ErrorIs(t, store.Update(alpha), ErrPasswordExists)

	// The failed rename leaves both entries in place.
	entries, err := store.List()
	require.NoError(t, err)
	assert.Len(t, entries, 2)
}

func TestRecords_RenameUndoesOnConflict(t *testing.T) {
	store := newTestStore(t)
	ctx := context.Background()

	current := &record{Path: store.entryPath("a"), Dir: store.dir(nameKindEntry), Body: []byte("1")}
	stored, err := store.records.create(ctx, current)
	require.NoError(t, err)
	require.True(t, stored)

	// A stale copy of current no longer matches the stored record.
	stale := *current
	stale.Body = []byte("stale")
	next := &record{Path: store.entryPath("b"), Dir: store.dir(nameKindEntry), Body: []byte("2")}

	var conflict *ConflictError
	require.ErrorAs(t, store.records.rename(ctx, &stale, next), &conflict)
	assert.Equal(t, "rename", conflict.Op)
	assert.Contains(t, conflict.Error(), "changed concurrently")

	// The write of next was undone; current is untouched.
	assertEntryPaths(t, store, current.Path)
}

// errReadFailed is the failure failingReads reports.
var errReadFailed = errors.New("read failed")

// failingReads is an in-memory store whose reads fail.
type failingReads struct {
	*qrdbsdk.MemoryKVStore
}

func (failingReads) Get(context.Context, string) ([]byte, error)    { return nil, errReadFailed }
func (failingReads) Exists(context.Context, string) (bool, error)   { return false, errReadFailed }
func (failingReads) List(context.Context, string) ([]string, error) { return nil, errReadFailed }
func (failingReads) Scan(context.Context, string, func(string, []byte) error) error {
	return errReadFailed
}
func (failingReads) QueryIndex(context.Context, string, []byte) ([][]byte, error) {
	return nil, errReadFailed
}

func TestRecords_StoreErrorOnFailedRead(t *testing.T) {
	store, err := NewStore(dao.NewStoreFactory(failingReads{qrdbsdk.NewMemoryKVStore()}))
	require.NoError(t, err)

	var storeErr *StoreError
	_, err = store.Get("x")
	require.ErrorAs(t, err, &storeErr)
	assert.Equal(t, "get", storeErr.Op)
	assert.ErrorIs(t, err, errReadFailed)
	assert.Contains(t, storeErr.Error(), "staticpw: get")

	_, err = store.ListFolders()
	assert.ErrorIs(t, err, errReadFailed)
}

// --- CreateFolder / RemoveFolder ---

func TestDAOStore_CreateFolder(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	require.NoError(t, s.CreateFolder("work"))
	require.NoError(t, s.CreateFolder("personal/email"))

	folders, err := s.ListFolders()
	require.NoError(t, err)
	assert.Contains(t, folders, "work")
	assert.Contains(t, folders, "personal/email")
}

func TestDAOStore_CreateFolder_Empty(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	assert.ErrorIs(t, s.CreateFolder(""), ErrFolderEmpty)
}

func TestDAOStore_CreateFolder_Closed(t *testing.T) {
	s := newTestStore(t)
	require.NoError(t, s.Close())

	assert.ErrorIs(t, s.CreateFolder("work"), ErrStoreClosed)
}

func TestDAOStore_RemoveFolder(t *testing.T) {
	s := newTestStore(t)
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

func TestDAOStore_RemoveFolder_Nonexistent(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	// Should be idempotent.
	require.NoError(t, s.RemoveFolder("nonexistent"))
}

func TestDAOStore_RemoveFolder_Empty(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	assert.ErrorIs(t, s.RemoveFolder(""), ErrFolderEmpty)
}

func TestDAOStore_RemoveFolder_Closed(t *testing.T) {
	s := newTestStore(t)
	require.NoError(t, s.Close())

	assert.ErrorIs(t, s.RemoveFolder("work"), ErrStoreClosed)
}

func TestDAOStore_SetAlias(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	require.NoError(t, s.SetAlias("custom", "Work"))

	folder, found, err := s.GetAlias("custom")
	require.NoError(t, err)
	assert.True(t, found)
	assert.Equal(t, "Work", folder)
}

func TestDAOStore_SetAlias_EmptyNameRefused(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	assert.ErrorIs(t, s.SetAlias("", "Work"), ErrAliasNameEmpty)

	_, _, err := s.GetAlias("")
	assert.ErrorIs(t, err, ErrAliasNameEmpty)
}

func TestDAOStore_SetAlias_EmptyFolderRemovesAlias(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	require.NoError(t, s.SetAlias("custom", "Work"))
	require.NoError(t, s.SetAlias("custom", ""))

	_, found, err := s.GetAlias("custom")
	require.NoError(t, err)
	assert.False(t, found)
}

func TestDAOStore_GetAlias_Unset(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	folder, found, err := s.GetAlias("never-set")
	require.NoError(t, err)
	assert.False(t, found)
	assert.Empty(t, folder)
}

func TestDAOStore_SetAlias_Closed(t *testing.T) {
	s := newTestStore(t)
	require.NoError(t, s.Close())

	assert.ErrorIs(t, s.SetAlias("custom", "Work"), ErrStoreClosed)
}

func TestDAOStore_GetAlias_Closed(t *testing.T) {
	s := newTestStore(t)
	require.NoError(t, s.Close())

	_, _, err := s.GetAlias("custom")
	assert.ErrorIs(t, err, ErrStoreClosed)
}

// TestDAOStore_AliasMarkersExcludedFromList proves an alias marker
// never shows up as a password entry via List/ListByFolder*, the same
// invariant folder markers already have.
func TestDAOStore_AliasMarkersExcludedFromList(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	require.NoError(t, s.SetAlias("custom", "Work"))
	require.NoError(t, s.Add(&StaticPassword{Name: "a", Password: "p"}))

	passwords, err := s.List()
	require.NoError(t, err)
	require.Len(t, passwords, 1)
	assert.Equal(t, "a", passwords[0].Name)
}

func TestDAOStore_ListFolders_MergesImplicitAndExplicit(t *testing.T) {
	s := newTestStore(t)
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

func TestDAOStore_CreateFolder_DoesNotPolluteList(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	require.NoError(t, s.CreateFolder("empty-folder"))
	require.NoError(t, s.Add(&StaticPassword{Name: "real", Password: "p"}))

	// List should only return real entries, not folder markers.
	entries, err := s.List()
	require.NoError(t, err)
	assert.Len(t, entries, 1)
	assert.Equal(t, "real", entries[0].Name)
}
