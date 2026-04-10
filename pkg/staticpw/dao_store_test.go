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
	"encoding/json"
	"sync"
	"testing"
	"time"

	"github.com/jeremyhahn/go-qrdb/pkg/dao"
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

	result, err := store.Page(ctx, dao.PageQuery{Page: 1, PageSize: 2})
	require.NoError(t, err)
	assert.Len(t, result.Entities, 2)
	assert.Equal(t, 5, result.Total)
	assert.True(t, result.HasMore)

	result3, err := store.Page(ctx, dao.PageQuery{Page: 3, PageSize: 2})
	require.NoError(t, err)
	assert.Len(t, result3.Entities, 1)
	assert.False(t, result3.HasMore)
}

func TestDAOStore_Page_Closed(t *testing.T) {
	store := newTestDAOStore(t)
	require.NoError(t, store.Close())

	_, err := store.Page(context.Background(), dao.PageQuery{Page: 1, PageSize: 10})
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

// --- Migration tests ---

func TestDAOStore_MigrateFromBackend_Success(t *testing.T) {
	legacyBackend := storage.NewMemory()
	t.Cleanup(func() { require.NoError(t, legacyBackend.Close()) })

	legacyStore := NewStore(legacyBackend)

	pw1 := testPassword("GitHub", "pass1")
	pw2 := testPasswordInFolder("Email", "pass2", "Work")
	require.NoError(t, legacyStore.Add(pw1))
	require.NoError(t, legacyStore.Add(pw2))

	daoStore := newTestDAOStore(t)

	ctx := context.Background()
	err := MigrateFromBackend(ctx, legacyBackend, defaultKeyPrefix, daoStore)
	require.NoError(t, err)

	got1, err := daoStore.Get("GitHub")
	require.NoError(t, err)
	assert.Equal(t, "GitHub", got1.Name)

	got2, err := daoStore.Get("Email")
	require.NoError(t, err)
	assert.Equal(t, "Email", got2.Name)
	assert.Equal(t, "Work", got2.FolderPath)

	// Verify old keys are deleted.
	keys, err := legacyBackend.List(ctx, defaultKeyPrefix)
	require.NoError(t, err)
	assert.Empty(t, keys)
}

func TestDAOStore_MigrateFromBackend_WithFolderMarkers(t *testing.T) {
	legacyBackend := storage.NewMemory()
	t.Cleanup(func() { require.NoError(t, legacyBackend.Close()) })

	legacyStore := NewStore(legacyBackend)
	require.NoError(t, legacyStore.Add(testPassword("GitHub", "pass1")))
	require.NoError(t, legacyStore.CreateFolder("EmptyFolder"))

	daoStore := newTestDAOStore(t)

	ctx := context.Background()
	err := MigrateFromBackend(ctx, legacyBackend, defaultKeyPrefix, daoStore)
	require.NoError(t, err)

	folders, err := daoStore.ListFolders()
	require.NoError(t, err)
	assert.Contains(t, folders, "EmptyFolder")
}

func TestDAOStore_MigrateFromBackend_NilBackend(t *testing.T) {
	daoStore := newTestDAOStore(t)
	err := MigrateFromBackend(context.Background(), nil, defaultKeyPrefix, daoStore)
	var nilErr ErrNilMigrationBackend
	require.ErrorAs(t, err, &nilErr)
}

func TestDAOStore_MigrateFromBackend_NilDAOStore(t *testing.T) {
	backend := storage.NewMemory()
	t.Cleanup(func() { require.NoError(t, backend.Close()) })

	err := MigrateFromBackend(context.Background(), backend, defaultKeyPrefix, nil)
	var nilErr ErrNilMigrationDAOStore
	require.ErrorAs(t, err, &nilErr)
}

func TestDAOStore_MigrateFromBackend_Idempotent(t *testing.T) {
	legacyBackend := storage.NewMemory()
	t.Cleanup(func() { require.NoError(t, legacyBackend.Close()) })

	legacyStore := NewStore(legacyBackend)
	require.NoError(t, legacyStore.Add(testPassword("GitHub", "pass1")))

	daoStore := newTestDAOStore(t)
	ctx := context.Background()

	require.NoError(t, MigrateFromBackend(ctx, legacyBackend, defaultKeyPrefix, daoStore))

	// Re-add to legacy to simulate partial migration.
	require.NoError(t, legacyStore.Add(testPassword("GitHub", "pass1")))

	// Second migration should skip the duplicate.
	require.NoError(t, MigrateFromBackend(ctx, legacyBackend, defaultKeyPrefix, daoStore))

	passwords, err := daoStore.List()
	require.NoError(t, err)
	assert.Len(t, passwords, 1)
}

func TestDAOStore_MigrateFromBackend_CorruptData(t *testing.T) {
	backend := storage.NewMemory()
	t.Cleanup(func() { require.NoError(t, backend.Close()) })

	ctx := context.Background()
	require.NoError(t, backend.Put(ctx, defaultKeyPrefix+"corrupt.json", []byte("not json")))

	daoStore := newTestDAOStore(t)
	err := MigrateFromBackend(ctx, backend, defaultKeyPrefix, daoStore)
	require.Error(t, err)
	var migErr ErrMigrationFailed
	require.ErrorAs(t, err, &migErr)
}

// --- Error type tests ---

func TestDAOStore_ErrDAOCreation(t *testing.T) {
	err := ErrDAOCreation{Cause: ErrStoreClosed}
	assert.Contains(t, err.Error(), "failed to create DAO")
	assert.ErrorIs(t, err.Unwrap(), ErrStoreClosed)
}

func TestDAOStore_ErrMigrationFailed(t *testing.T) {
	err := ErrMigrationFailed{Key: "test-key", Cause: ErrPasswordNotFound}
	assert.Contains(t, err.Error(), "test-key")
	assert.ErrorIs(t, err.Unwrap(), ErrPasswordNotFound)
}

func TestDAOStore_ErrNilKVStore(t *testing.T) {
	err := ErrNilKVStore{}
	assert.Contains(t, err.Error(), "nil kvstore")
}

func TestDAOStore_ErrNilMigrationBackend(t *testing.T) {
	err := ErrNilMigrationBackend{}
	assert.Contains(t, err.Error(), "nil backend")
}

func TestDAOStore_ErrNilMigrationDAOStore(t *testing.T) {
	err := ErrNilMigrationDAOStore{}
	assert.Contains(t, err.Error(), "nil DAO store")
}

// --- extractFolderFromMarkerKey tests ---

func TestExtractFolderFromMarkerKey(t *testing.T) {
	tests := []struct {
		name   string
		key    string
		prefix string
		want   string
	}{
		{
			name:   "standard marker",
			key:    "staticpw/__folders__/Work",
			prefix: "staticpw/",
			want:   "Work",
		},
		{
			name:   "nested folder",
			key:    "staticpw/__folders__/Work/Email",
			prefix: "staticpw/",
			want:   "Work/Email",
		},
		{
			name:   "no match returns empty",
			key:    "staticpw/something.json",
			prefix: "staticpw/",
			want:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := extractFolderFromMarkerKey(tt.key, tt.prefix)
			assert.Equal(t, tt.want, got)
		})
	}
}

// --- MigrateFromBackend with real BackendStore data ---

func TestDAOStore_MigrateFromBackend_PreservesAllFields(t *testing.T) {
	legacyBackend := storage.NewMemory()
	t.Cleanup(func() { require.NoError(t, legacyBackend.Close()) })

	ctx := context.Background()
	now := time.Now().Truncate(time.Second)

	pw := &StaticPassword{
		ID:            GenerateID("FullEntry", "Work"),
		Name:          "FullEntry",
		Title:         "Full Entry Title",
		Username:      "admin",
		Password:      "complex!pass",
		URL:           "https://example.com",
		MatchPatterns: []string{"*.example.com"},
		Notes:         "Important note",
		FolderPath:    "Work",
		ExpiresAt:     now.Add(24 * time.Hour),
		CreatedAt:     now,
		UpdatedAt:     now,
		OwnerID:       "user1",
		Shared:        true,
	}

	data, err := json.Marshal(pw)
	require.NoError(t, err)
	require.NoError(t, legacyBackend.Put(ctx, defaultKeyPrefix+pw.ID+".json", data))

	daoStore := newTestDAOStore(t)
	require.NoError(t, MigrateFromBackend(ctx, legacyBackend, defaultKeyPrefix, daoStore))

	got, err := daoStore.Get("FullEntry")
	require.NoError(t, err)
	assert.Equal(t, pw.Name, got.Name)
	assert.Equal(t, pw.Title, got.Title)
	assert.Equal(t, pw.Username, got.Username)
	assert.Equal(t, pw.Password, got.Password)
	assert.Equal(t, pw.URL, got.URL)
	assert.Equal(t, pw.Notes, got.Notes)
	assert.Equal(t, pw.FolderPath, got.FolderPath)
	assert.Equal(t, pw.OwnerID, got.OwnerID)
	assert.Equal(t, pw.Shared, got.Shared)
	assert.Len(t, got.MatchPatterns, 1)
}
