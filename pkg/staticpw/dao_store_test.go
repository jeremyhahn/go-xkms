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
	"sync"
	"testing"
	"time"

	qrdbsdk "github.com/jeremyhahn/go-qrdb/sdk/go"
	"github.com/jeremyhahn/go-xkms/pkg/storage"
	"github.com/jeremyhahn/go-xkms/pkg/storage/kvadapter"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestDAOStore creates a DAOStore backed by in-memory storage for testing.
func newTestDAOStore(t *testing.T) *DAOStore {
	t.Helper()
	backend := storage.NewMemory()
	t.Cleanup(func() { require.NoError(t, backend.Close()) })

	kvStore, err := kvadapter.New(backend)
	require.NoError(t, err)

	store, err := NewDAOStore(kvStore)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })

	return store
}

// testPassword creates a valid static password for testing.
func testPassword(name, password string) *StaticPassword {
	return &StaticPassword{
		Name:     name,
		Password: password,
		Username: name + "@example.com",
		URL:      "https://example.com/" + name,
	}
}

// testPasswordInFolder creates a valid static password in a folder.
func testPasswordInFolder(name, password, folder string) *StaticPassword {
	pw := testPassword(name, password)
	pw.FolderPath = folder
	return pw
}

// errInjectedSaveFailure is returned by failingSaveDAO for entities matched
// by its predicate, simulating a durable-write failure (e.g. a Raft quorum
// loss or disk error) independent of any application-level conflict check.
var errInjectedSaveFailure = errors.New("staticpw: injected save failure for test")

// failingSaveDAO wraps a real GenericDAO and fails Save for entities that
// match shouldFail, while delegating every other operation unchanged. It
// lets tests exercise "the destination write fails" without needing a real
// storage backend that can be forced into a failure mode.
type failingSaveDAO struct {
	qrdbsdk.GenericDAO[*PasswordEntity]
	shouldFail func(*PasswordEntity) bool
}

func (f *failingSaveDAO) Save(ctx context.Context, entity *PasswordEntity) error {
	if f.shouldFail(entity) {
		return errInjectedSaveFailure
	}
	return f.GenericDAO.Save(ctx, entity)
}

// newFailingSaveDAOStore creates a DAOStore backed by in-memory storage
// whose Save fails for any entity matching shouldFail, leaving every other
// DAO operation (Get, Delete, paging) working against the real store.
func newFailingSaveDAOStore(t *testing.T, shouldFail func(*PasswordEntity) bool) *DAOStore {
	t.Helper()
	backend := storage.NewMemory()
	t.Cleanup(func() { require.NoError(t, backend.Close()) })

	kvStore, err := kvadapter.New(backend)
	require.NoError(t, err)

	realDAO, err := qrdbsdk.NewDAO[*PasswordEntity](
		kvStore,
		"static_passwords",
		func() *PasswordEntity { return &PasswordEntity{} },
	)
	require.NoError(t, err)

	return &DAOStore{dao: &failingSaveDAO{GenericDAO: realDAO, shouldFail: shouldFail}}
}

// --- Constructor tests ---

func TestDAOStore_NewDAOStore_NilKVStore(t *testing.T) {
	store, err := NewDAOStore(nil)
	require.Error(t, err)
	var nilErr ErrNilKVStore
	require.ErrorAs(t, err, &nilErr)
	assert.Nil(t, store)
}

func TestDAOStore_ImplementsStoreInterface(t *testing.T) {
	store := newTestDAOStore(t)
	var _ Store = store
}

// --- Add tests ---

func TestDAOStore_Add_Success(t *testing.T) {
	store := newTestDAOStore(t)
	pw := testPassword("GitHub", "secret123")

	err := store.Add(pw)
	require.NoError(t, err)

	got, err := store.Get(pw.Name)
	require.NoError(t, err)
	assert.Equal(t, pw.Name, got.Name)
	assert.Equal(t, pw.Password, got.Password)
	assert.Equal(t, pw.Username, got.Username)
	assert.Equal(t, pw.URL, got.URL)
	assert.NotZero(t, got.CreatedAt)
	assert.NotZero(t, got.UpdatedAt)
	assert.NotEmpty(t, got.ID)
}

func TestDAOStore_Add_InvalidName(t *testing.T) {
	store := newTestDAOStore(t)
	pw := &StaticPassword{Name: "", Password: "secret123"}

	err := store.Add(pw)
	require.ErrorIs(t, err, ErrInvalidName)
}

func TestDAOStore_Add_EmptyPassword(t *testing.T) {
	store := newTestDAOStore(t)
	pw := &StaticPassword{Name: "GitHub", Password: ""}

	err := store.Add(pw)
	require.ErrorIs(t, err, ErrEmptyPassword)
}

func TestDAOStore_Add_DuplicateName(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Add(testPassword("GitHub", "pass1")))

	err := store.Add(testPassword("GitHub", "pass2"))
	require.ErrorIs(t, err, ErrPasswordExists)
}

func TestDAOStore_Add_DuplicateNameCaseInsensitive(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Add(testPassword("GitHub", "pass1")))

	err := store.Add(testPassword("GITHUB", "pass2"))
	require.ErrorIs(t, err, ErrPasswordExists)
}

func TestDAOStore_Add_SameNameDifferentFolder(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Add(testPasswordInFolder("Login", "pass1", "Work")))

	// Same name in a different folder should succeed.
	err := store.Add(testPasswordInFolder("Login", "pass2", "Personal"))
	require.NoError(t, err)

	all, err := store.List()
	require.NoError(t, err)
	assert.Len(t, all, 2)
}

func TestDAOStore_Add_Closed(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Close())

	err := store.Add(testPassword("GitHub", "pass"))
	require.ErrorIs(t, err, ErrStoreClosed)
}

// --- Get tests ---

func TestDAOStore_Get_ByName(t *testing.T) {
	store := newTestDAOStore(t)
	pw := testPassword("GitHub", "secret123")
	require.NoError(t, store.Add(pw))

	got, err := store.Get("GitHub")
	require.NoError(t, err)
	assert.Equal(t, pw.Name, got.Name)
	assert.Equal(t, pw.Password, got.Password)
}

func TestDAOStore_Get_ByNameCaseInsensitive(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Add(testPassword("GitHub", "secret123")))

	got, err := store.Get("github")
	require.NoError(t, err)
	assert.Equal(t, "GitHub", got.Name)
}

func TestDAOStore_Get_ByID(t *testing.T) {
	store := newTestDAOStore(t)
	pw := testPassword("GitHub", "secret123")
	require.NoError(t, store.Add(pw))

	// Retrieve by the generated hex ID.
	got, err := store.Get(pw.ID)
	require.NoError(t, err)
	assert.Equal(t, "GitHub", got.Name)
}

func TestDAOStore_Get_NotFound(t *testing.T) {
	store := newTestDAOStore(t)

	got, err := store.Get("nonexistent")
	require.ErrorIs(t, err, ErrPasswordNotFound)
	assert.Nil(t, got)
}

func TestDAOStore_Get_Closed(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Close())

	got, err := store.Get("GitHub")
	require.ErrorIs(t, err, ErrStoreClosed)
	assert.Nil(t, got)
}

// --- List tests ---

func TestDAOStore_List_Multiple(t *testing.T) {
	store := newTestDAOStore(t)

	require.NoError(t, store.Add(testPassword("Zebra", "z1")))
	require.NoError(t, store.Add(testPassword("Alpha", "a1")))
	require.NoError(t, store.Add(testPassword("Middle", "m1")))

	passwords, err := store.List()
	require.NoError(t, err)
	require.Len(t, passwords, 3)

	assert.Equal(t, "Alpha", passwords[0].Name)
	assert.Equal(t, "Middle", passwords[1].Name)
	assert.Equal(t, "Zebra", passwords[2].Name)
}

func TestDAOStore_List_Empty(t *testing.T) {
	store := newTestDAOStore(t)

	passwords, err := store.List()
	require.NoError(t, err)
	assert.Empty(t, passwords)
}

func TestDAOStore_List_ExcludesFolderMarkers(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Add(testPassword("GitHub", "pass1")))
	require.NoError(t, store.CreateFolder("Work"))

	passwords, err := store.List()
	require.NoError(t, err)
	assert.Len(t, passwords, 1)
	assert.Equal(t, "GitHub", passwords[0].Name)
}

func TestDAOStore_List_Closed(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Close())

	passwords, err := store.List()
	require.ErrorIs(t, err, ErrStoreClosed)
	assert.Nil(t, passwords)
}

// --- Update tests ---

func TestDAOStore_Update_Success(t *testing.T) {
	store := newTestDAOStore(t)
	pw := testPassword("GitHub", "oldpass")
	require.NoError(t, store.Add(pw))

	pw.Password = "newpass"
	pw.Username = "newuser"
	err := store.Update(pw)
	require.NoError(t, err)

	got, err := store.Get("GitHub")
	require.NoError(t, err)
	assert.Equal(t, "newpass", got.Password)
	assert.Equal(t, "newuser", got.Username)
}

func TestDAOStore_Update_PreservesCreatedAt(t *testing.T) {
	store := newTestDAOStore(t)
	pw := testPassword("GitHub", "pass")
	require.NoError(t, store.Add(pw))

	original, err := store.Get("GitHub")
	require.NoError(t, err)

	time.Sleep(time.Millisecond)
	original.Password = "updated"
	require.NoError(t, store.Update(original))

	got, err := store.Get("GitHub")
	require.NoError(t, err)
	assert.Equal(t, original.CreatedAt.Unix(), got.CreatedAt.Unix())
	assert.True(t, got.UpdatedAt.After(got.CreatedAt) || got.UpdatedAt.Equal(got.CreatedAt))
}

func TestDAOStore_Update_NameChange(t *testing.T) {
	store := newTestDAOStore(t)
	pw := testPassword("GitHub", "pass")
	require.NoError(t, store.Add(pw))

	pw.Name = "GitLab"
	err := store.Update(pw)
	require.NoError(t, err)

	// Old name should not resolve.
	_, err = store.Get("GitHub")
	require.ErrorIs(t, err, ErrPasswordNotFound)

	// New name should resolve.
	got, err := store.Get("GitLab")
	require.NoError(t, err)
	assert.Equal(t, "GitLab", got.Name)
}

func TestDAOStore_Update_NotFound(t *testing.T) {
	store := newTestDAOStore(t)
	pw := testPassword("Nonexistent", "pass")
	pw.ID = GenerateID("Nonexistent", "")

	err := store.Update(pw)
	require.ErrorIs(t, err, ErrPasswordNotFound)
}

func TestDAOStore_Update_InvalidFields(t *testing.T) {
	store := newTestDAOStore(t)
	pw := &StaticPassword{Name: "", Password: "pass"}

	err := store.Update(pw)
	require.ErrorIs(t, err, ErrInvalidName)
}

func TestDAOStore_Update_Closed(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Close())

	err := store.Update(testPassword("GitHub", "pass"))
	require.ErrorIs(t, err, ErrStoreClosed)
}

// TestDAOStore_Update_RenameConflictPreservesSource guards against H15: a
// rename that collides with an existing entry at the destination must leave
// the source entry untouched rather than deleting it before the conflict is
// discovered.
func TestDAOStore_Update_RenameConflictPreservesSource(t *testing.T) {
	store := newTestDAOStore(t)
	src := testPassword("GitHub", "p1")
	require.NoError(t, store.Add(src))
	require.NoError(t, store.Add(testPassword("GitLab", "p2")))

	renamed := *src
	renamed.Name = "GitLab" // collides with the existing "GitLab" entry
	err := store.Update(&renamed)
	require.ErrorIs(t, err, ErrPasswordExists)

	// The source entry must still be intact under its original name.
	got, err := store.Get("GitHub")
	require.NoError(t, err)
	assert.Equal(t, "p1", got.Password)
}

// TestDAOStore_Update_RenameSaveFailurePreservesSource guards against H15:
// if writing the renamed entity fails, the original entity must not have
// been deleted.
func TestDAOStore_Update_RenameSaveFailurePreservesSource(t *testing.T) {
	store := newFailingSaveDAOStore(t, func(e *PasswordEntity) bool {
		return e.Name == "GitLab"
	})

	pw := testPassword("GitHub", "p1")
	require.NoError(t, store.Add(pw))

	renamed := *pw
	renamed.Name = "GitLab"
	err := store.Update(&renamed)
	require.Error(t, err)

	got, err := store.Get("GitHub")
	require.NoError(t, err)
	assert.Equal(t, "p1", got.Password)
}

// --- Delete tests ---

func TestDAOStore_Delete_ByName(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Add(testPassword("GitHub", "pass")))

	err := store.Delete("GitHub")
	require.NoError(t, err)

	_, err = store.Get("GitHub")
	require.ErrorIs(t, err, ErrPasswordNotFound)
}

func TestDAOStore_Delete_ByID(t *testing.T) {
	store := newTestDAOStore(t)
	pw := testPassword("GitHub", "pass")
	require.NoError(t, store.Add(pw))

	err := store.Delete(pw.ID)
	require.NoError(t, err)

	_, err = store.Get("GitHub")
	require.ErrorIs(t, err, ErrPasswordNotFound)
}

func TestDAOStore_Delete_NotFound(t *testing.T) {
	store := newTestDAOStore(t)

	err := store.Delete("nonexistent")
	require.ErrorIs(t, err, ErrPasswordNotFound)
}

func TestDAOStore_Delete_Closed(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Close())

	err := store.Delete("GitHub")
	require.ErrorIs(t, err, ErrStoreClosed)
}

// --- ForceDelete tests ---

func TestDAOStore_ForceDelete_NotFound(t *testing.T) {
	store := newTestDAOStore(t)

	err := store.ForceDelete("nonexistent")
	require.ErrorIs(t, err, ErrPasswordNotFound)
}

func TestDAOStore_ForceDelete_Closed(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Close())

	err := store.ForceDelete("GitHub")
	require.ErrorIs(t, err, ErrStoreClosed)
}

// --- ListByFolder tests ---

func TestDAOStore_ListByFolder_IncludesSubfolders(t *testing.T) {
	store := newTestDAOStore(t)

	require.NoError(t, store.Add(testPasswordInFolder("Email", "p1", "Work")))
	require.NoError(t, store.Add(testPasswordInFolder("Slack", "p2", "Work/Chat")))
	require.NoError(t, store.Add(testPasswordInFolder("Drive", "p3", "Work/Storage")))
	require.NoError(t, store.Add(testPasswordInFolder("Netflix", "p4", "Personal")))

	result, err := store.ListByFolder("Work")
	require.NoError(t, err)
	assert.Len(t, result, 3)
}

func TestDAOStore_ListByFolder_EmptyPathReturnsAll(t *testing.T) {
	store := newTestDAOStore(t)

	require.NoError(t, store.Add(testPasswordInFolder("Email", "p1", "Work")))
	require.NoError(t, store.Add(testPassword("Root", "p2")))

	result, err := store.ListByFolder("")
	require.NoError(t, err)
	assert.Len(t, result, 2)
}

func TestDAOStore_ListByFolder_NoMatch(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Add(testPasswordInFolder("Email", "p1", "Work")))

	result, err := store.ListByFolder("Personal")
	require.NoError(t, err)
	assert.Empty(t, result)
}

// --- ListByFolderDirect tests ---

func TestDAOStore_ListByFolderDirect_ExactMatch(t *testing.T) {
	store := newTestDAOStore(t)

	require.NoError(t, store.Add(testPasswordInFolder("Email", "p1", "Work")))
	require.NoError(t, store.Add(testPasswordInFolder("Slack", "p2", "Work/Chat")))

	result, err := store.ListByFolderDirect("Work")
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, "Email", result[0].Name)
}

func TestDAOStore_ListByFolderDirect_RootLevel(t *testing.T) {
	store := newTestDAOStore(t)

	require.NoError(t, store.Add(testPassword("Root", "p1")))
	require.NoError(t, store.Add(testPasswordInFolder("Work", "p2", "Work")))

	result, err := store.ListByFolderDirect("")
	require.NoError(t, err)
	assert.Len(t, result, 1)
	assert.Equal(t, "Root", result[0].Name)
}

// --- ListFolders tests ---

func TestDAOStore_ListFolders_DeriveParents(t *testing.T) {
	store := newTestDAOStore(t)

	require.NoError(t, store.Add(testPasswordInFolder("Slack", "p1", "Work/Chat")))

	folders, err := store.ListFolders()
	require.NoError(t, err)
	assert.Contains(t, folders, "Work")
	assert.Contains(t, folders, "Work/Chat")
}

func TestDAOStore_ListFolders_IncludesMarkers(t *testing.T) {
	store := newTestDAOStore(t)

	require.NoError(t, store.CreateFolder("EmptyFolder"))

	folders, err := store.ListFolders()
	require.NoError(t, err)
	assert.Contains(t, folders, "EmptyFolder")
}

func TestDAOStore_ListFolders_Sorted(t *testing.T) {
	store := newTestDAOStore(t)

	require.NoError(t, store.Add(testPasswordInFolder("B", "p1", "Zebra")))
	require.NoError(t, store.Add(testPasswordInFolder("A", "p2", "Alpha")))

	folders, err := store.ListFolders()
	require.NoError(t, err)
	require.Len(t, folders, 2)
	assert.Equal(t, "Alpha", folders[0])
	assert.Equal(t, "Zebra", folders[1])
}

func TestDAOStore_ListFolders_Closed(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Close())

	_, err := store.ListFolders()
	require.ErrorIs(t, err, ErrStoreClosed)
}

// --- MoveToFolder tests ---

func TestDAOStore_MoveToFolder_Success(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Add(testPasswordInFolder("Email", "p1", "Work")))

	err := store.MoveToFolder("Email", "Personal")
	require.NoError(t, err)

	got, err := store.Get("Email")
	require.NoError(t, err)
	assert.Equal(t, "Personal", got.FolderPath)
	assert.Equal(t, GenerateID("Email", "Personal"), got.ID)
}

func TestDAOStore_MoveToFolder_SameFolder(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Add(testPasswordInFolder("Email", "p1", "Work")))

	err := store.MoveToFolder("Email", "Work")
	require.ErrorIs(t, err, ErrMoveToSameFolder)
}

func TestDAOStore_MoveToFolder_NotFound(t *testing.T) {
	store := newTestDAOStore(t)

	err := store.MoveToFolder("nonexistent", "Work")
	require.ErrorIs(t, err, ErrPasswordNotFound)
}

func TestDAOStore_MoveToFolder_Closed(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Close())

	err := store.MoveToFolder("Email", "Work")
	require.ErrorIs(t, err, ErrStoreClosed)
}

// TestDAOStore_MoveToFolder_ConflictPreservesSource guards against H15: a
// move whose destination collides with an existing entry must leave the
// source entry in place instead of deleting it before the conflict check.
func TestDAOStore_MoveToFolder_ConflictPreservesSource(t *testing.T) {
	store := newTestDAOStore(t)
	src := testPasswordInFolder("Email", "p1", "Work")
	require.NoError(t, store.Add(src))
	require.NoError(t, store.Add(testPasswordInFolder("Email", "p2", "Personal")))

	err := store.MoveToFolder(src.ID, "Personal")
	require.ErrorIs(t, err, ErrPasswordExists)

	// The source entry must still be intact in its original folder.
	got, err := store.Get(src.ID)
	require.NoError(t, err)
	assert.Equal(t, "Work", got.FolderPath)
	assert.Equal(t, "p1", got.Password)
}

// TestDAOStore_MoveToFolder_SaveFailurePreservesSource guards against H15:
// if writing the moved entity fails, the source entity must not have been
// deleted.
func TestDAOStore_MoveToFolder_SaveFailurePreservesSource(t *testing.T) {
	store := newFailingSaveDAOStore(t, func(e *PasswordEntity) bool {
		return e.FolderPath == "Personal"
	})

	src := testPasswordInFolder("Email", "p1", "Work")
	require.NoError(t, store.Add(src))

	err := store.MoveToFolder(src.ID, "Personal")
	require.Error(t, err)

	got, err := store.Get(src.ID)
	require.NoError(t, err)
	assert.Equal(t, "Work", got.FolderPath)
	assert.Equal(t, "p1", got.Password)
}

// --- CreateFolder / RemoveFolder tests ---

func TestDAOStore_CreateFolder_Success(t *testing.T) {
	store := newTestDAOStore(t)

	err := store.CreateFolder("Work/Projects")
	require.NoError(t, err)

	folders, err := store.ListFolders()
	require.NoError(t, err)
	assert.Contains(t, folders, "Work/Projects")
}

func TestDAOStore_CreateFolder_Idempotent(t *testing.T) {
	store := newTestDAOStore(t)

	require.NoError(t, store.CreateFolder("Work"))
	require.NoError(t, store.CreateFolder("Work"))

	folders, err := store.ListFolders()
	require.NoError(t, err)
	assert.Contains(t, folders, "Work")
}

func TestDAOStore_CreateFolder_EmptyPath(t *testing.T) {
	store := newTestDAOStore(t)

	err := store.CreateFolder("")
	require.ErrorIs(t, err, ErrFolderEmpty)
}

func TestDAOStore_CreateFolder_Closed(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Close())

	err := store.CreateFolder("Work")
	require.ErrorIs(t, err, ErrStoreClosed)
}

// TestDAOStore_CreateFolder_MarkerLookupFailureSurfaces proves that a
// findFolderMarker failure other than ErrPasswordNotFound aborts CreateFolder
// instead of being silently treated as "no such folder" (go-xkms#1347).
// Closing the underlying storage out from under the store, without marking
// the store itself closed, forces the marker lookup to fail with a real,
// non-not-found error.
func TestDAOStore_CreateFolder_MarkerLookupFailureSurfaces(t *testing.T) {
	backend := storage.NewMemory()
	kvStore, err := kvadapter.New(backend)
	require.NoError(t, err)

	store, err := NewDAOStore(kvStore)
	require.NoError(t, err)

	require.NoError(t, backend.Close())

	err = store.CreateFolder("Work")
	require.Error(t, err)
	assert.ErrorIs(t, err, storage.ErrClosed,
		"the folder-marker lookup failure must reach the caller instead of being discarded")
}

func TestDAOStore_RemoveFolder_Success(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.CreateFolder("Work"))

	err := store.RemoveFolder("Work")
	require.NoError(t, err)

	folders, err := store.ListFolders()
	require.NoError(t, err)
	assert.NotContains(t, folders, "Work")
}

func TestDAOStore_RemoveFolder_Idempotent(t *testing.T) {
	store := newTestDAOStore(t)

	// Remove a folder that never existed.
	err := store.RemoveFolder("Nonexistent")
	require.NoError(t, err)
}

func TestDAOStore_RemoveFolder_EmptyPath(t *testing.T) {
	store := newTestDAOStore(t)

	err := store.RemoveFolder("")
	require.ErrorIs(t, err, ErrFolderEmpty)
}

func TestDAOStore_RemoveFolder_Closed(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Close())

	err := store.RemoveFolder("Work")
	require.ErrorIs(t, err, ErrStoreClosed)
}

// --- Page tests ---

func TestDAOStore_Page_Pagination(t *testing.T) {
	store := newTestDAOStore(t)
	ctx := context.Background()

	for i := 0; i < 5; i++ {
		name := string(rune('A'+i)) + "-Service"
		require.NoError(t, store.Add(testPassword(name, "pass"+name)))
	}

	result, err := store.Page(ctx, qrdbsdk.PageQuery{Page: 1, PageSize: 2})
	require.NoError(t, err)
	assert.Len(t, result.Entities, 2)
	assert.Equal(t, 5, result.Total)
	assert.True(t, result.HasMore)

	result3, err := store.Page(ctx, qrdbsdk.PageQuery{Page: 3, PageSize: 2})
	require.NoError(t, err)
	assert.Len(t, result3.Entities, 1)
	assert.False(t, result3.HasMore)
}

func TestDAOStore_Page_Closed(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Close())

	_, err := store.Page(context.Background(), qrdbsdk.PageQuery{Page: 1, PageSize: 10})
	require.ErrorIs(t, err, ErrStoreClosed)
}

// --- Close tests ---

func TestDAOStore_Close_Idempotent(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Close())
	require.NoError(t, store.Close())
	require.NoError(t, store.Close())
}

// --- Converter round-trip tests ---

func TestDAOStore_ConverterRoundTrip(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	pw := &StaticPassword{
		ID:         GenerateID("GitHub", "Work"),
		Name:       "GitHub",
		Title:      "GitHub Login",
		Username:   "user@example.com",
		Password:   "supersecret",
		URL:        "https://github.com",
		Notes:      "Personal account",
		FolderPath: "Work",
		ExpiresAt:  now.Add(24 * time.Hour),
		CreatedAt:  now,
		UpdatedAt:  now,
		OwnerID:    "user1",
		Shared:     true,
	}

	entity := passwordToEntity(pw)
	assert.Equal(t, pw.Name, entity.Name)
	assert.Equal(t, pw.Title, entity.Title)
	assert.Equal(t, pw.Username, entity.Username)
	assert.Equal(t, pw.Password, entity.Password)
	assert.Equal(t, pw.URL, entity.URL)
	assert.Equal(t, pw.Notes, entity.Notes)
	assert.Equal(t, pw.FolderPath, entity.FolderPath)
	assert.Equal(t, pw.OwnerID, entity.OwnerID)
	assert.Equal(t, pw.Shared, entity.Shared)

	restored := entityToPassword(entity)
	assert.Equal(t, pw.Name, restored.Name)
	assert.Equal(t, pw.Title, restored.Title)
	assert.Equal(t, pw.Username, restored.Username)
	assert.Equal(t, pw.Password, restored.Password)
	assert.Equal(t, pw.URL, restored.URL)
	assert.Equal(t, pw.FolderPath, restored.FolderPath)
	assert.Equal(t, pw.OwnerID, restored.OwnerID)
	assert.Equal(t, pw.Shared, restored.Shared)

	// ID is regenerated from name + folder.
	assert.Equal(t, GenerateID(pw.Name, pw.FolderPath), restored.ID)
}

// --- Concurrency tests ---

func TestDAOStore_Concurrency(t *testing.T) {
	store := newTestDAOStore(t)

	const goroutines = 30
	var wg sync.WaitGroup
	wg.Add(goroutines * 3)

	for i := 0; i < goroutines; i++ {
		go func(idx int) {
			defer wg.Done()
			name := string(rune('A'+idx%26)) + "-Svc-" + string(rune('0'+idx/26))
			_ = store.Add(testPassword(name, "pass"+name))
		}(i)
	}

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, _ = store.Get("A-Svc-0")
		}()
	}

	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			_, _ = store.List()
		}()
	}

	wg.Wait()
}

// --- Error type tests ---

func TestDAOStore_ErrDAOCreation(t *testing.T) {
	err := ErrDAOCreation{Cause: ErrStoreClosed}
	assert.Contains(t, err.Error(), "failed to create DAO")
	assert.ErrorIs(t, err.Unwrap(), ErrStoreClosed)
}

func TestDAOStore_ErrNilKVStore(t *testing.T) {
	err := ErrNilKVStore{}
	assert.Contains(t, err.Error(), "nil kvstore")
}
