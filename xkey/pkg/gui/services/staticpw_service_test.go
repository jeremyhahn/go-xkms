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

package services

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-xkms/pkg/storage"
	filestorage "github.com/jeremyhahn/go-xkms/pkg/storage/file"
	"github.com/jeremyhahn/go-xkms/sdk/go/transport"
	"github.com/jeremyhahn/go-xkms/xkey/pkg/staticpw"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newTestStaticPWService creates a StaticPasswordService backed by an in-memory
// storage backend for testing.
func newTestStaticPWService(t *testing.T) (*StaticPasswordService, staticpw.Store) {
	t.Helper()
	backend := storage.NewMemory()
	store := staticpw.NewStore(backend)
	svc := NewStaticPasswordService(store)
	svc.SetContext(context.Background())
	return svc, store
}

func TestNewStaticPasswordService(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	assert.NotNil(t, svc)
}

func TestStaticPasswordService_SetContext(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	svc.SetContext(context.Background())
}

// --- ListPasswords ---

func TestStaticPasswordService_ListPasswords(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	// Add two passwords.
	_, err := svc.AddPassword("BetaPass", "secret1", "first note")
	require.NoError(t, err)

	_, err = svc.AddPassword("AlphaPass", "secret2", "second note")
	require.NoError(t, err)

	entries, err := svc.ListPasswords()
	require.NoError(t, err)
	require.Len(t, entries, 2)

	// The store returns sorted by name; AlphaPass should come first.
	assert.Equal(t, "AlphaPass", entries[0].Name)
	assert.Equal(t, "BetaPass", entries[1].Name)
}

func TestStaticPasswordService_ListPasswords_Empty(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	entries, err := svc.ListPasswords()
	require.NoError(t, err)
	assert.Empty(t, entries)
}

func TestStaticPasswordService_ListPasswords_NilStore(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	_, err := svc.ListPasswords()
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrStaticPWStoreNotSet))
}

// --- AddPassword ---

func TestStaticPasswordService_AddPassword(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	entry, err := svc.AddPassword("MyPassword", "s3cret!", "test notes")
	require.NoError(t, err)
	require.NotNil(t, entry)

	assert.NotEmpty(t, entry.ID)
	assert.Equal(t, "MyPassword", entry.Name)
	assert.Equal(t, "s3cret!", entry.Password)
	assert.Equal(t, "test notes", entry.Notes)
	assert.NotEmpty(t, entry.CreatedAt)
	assert.NotEmpty(t, entry.UpdatedAt)
}

func TestStaticPasswordService_AddPassword_EmptyName(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	_, err := svc.AddPassword("", "password123", "")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrStaticPWInvalidName))
}

func TestStaticPasswordService_AddPassword_EmptyPassword(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	// The underlying store validates that password is non-empty.
	_, err := svc.AddPassword("TestEntry", "", "")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, staticpw.ErrEmptyPassword))
}

func TestStaticPasswordService_AddPassword_NilStore(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	_, err := svc.AddPassword("Test", "password", "")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrStaticPWStoreNotSet))
}

func TestStaticPasswordService_AddPassword_Duplicate(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	_, err := svc.AddPassword("UniqueEntry", "pass1", "")
	require.NoError(t, err)

	_, err = svc.AddPassword("UniqueEntry", "pass2", "")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, staticpw.ErrPasswordExists))
}

// --- GetPassword ---

func TestStaticPasswordService_GetPassword(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	added, err := svc.AddPassword("LookupTest", "pw123", "some notes")
	require.NoError(t, err)

	// Get by ID.
	entry, err := svc.GetPassword(added.ID)
	require.NoError(t, err)
	assert.Equal(t, added.ID, entry.ID)
	assert.Equal(t, "LookupTest", entry.Name)
	assert.Equal(t, "pw123", entry.Password)
	assert.Equal(t, "some notes", entry.Notes)

	// Get by name.
	entry, err = svc.GetPassword("LookupTest")
	require.NoError(t, err)
	assert.Equal(t, added.ID, entry.ID)
}

func TestStaticPasswordService_GetPassword_NotFound(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	_, err := svc.GetPassword("nonexistent")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, staticpw.ErrPasswordNotFound))
}

func TestStaticPasswordService_GetPassword_EmptyID(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	_, err := svc.GetPassword("")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrStaticPWInvalidID))
}

func TestStaticPasswordService_GetPassword_NilStore(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	_, err := svc.GetPassword("some-id")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrStaticPWStoreNotSet))
}

// --- UpdatePassword ---

func TestStaticPasswordService_UpdatePassword(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	added, err := svc.AddPassword("OriginalName", "origPW", "orig notes")
	require.NoError(t, err)

	err = svc.UpdatePassword(added.ID, "UpdatedName", "newPW", "new notes")
	require.NoError(t, err)

	// Name changed, so the store regenerated the ID. Look up by new name.
	entry, err := svc.GetPassword("UpdatedName")
	require.NoError(t, err)
	assert.Equal(t, "UpdatedName", entry.Name)
	assert.Equal(t, "newPW", entry.Password)
	assert.Equal(t, "new notes", entry.Notes)
}

func TestStaticPasswordService_UpdatePassword_NotFound(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	err := svc.UpdatePassword("nonexistent-id", "Name", "pw", "")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, staticpw.ErrPasswordNotFound))
}

func TestStaticPasswordService_UpdatePassword_EmptyID(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	err := svc.UpdatePassword("", "Name", "pw", "")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrStaticPWInvalidID))
}

func TestStaticPasswordService_UpdatePassword_NilStore(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	err := svc.UpdatePassword("id", "Name", "pw", "")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrStaticPWStoreNotSet))
}

// --- DeletePassword ---

func TestStaticPasswordService_DeletePassword(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	added, err := svc.AddPassword("ToDelete", "delPW", "")
	require.NoError(t, err)

	err = svc.DeletePassword(added.ID)
	require.NoError(t, err)

	// Verify it is gone.
	_, err = svc.GetPassword(added.ID)
	assert.Error(t, err)
	assert.True(t, errors.Is(err, staticpw.ErrPasswordNotFound))
}

func TestStaticPasswordService_DeletePassword_ByName(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	_, err := svc.AddPassword("DeleteByName", "pw", "")
	require.NoError(t, err)

	err = svc.DeletePassword("DeleteByName")
	require.NoError(t, err)

	_, err = svc.GetPassword("DeleteByName")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, staticpw.ErrPasswordNotFound))
}

func TestStaticPasswordService_DeletePassword_EmptyID(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	err := svc.DeletePassword("")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrStaticPWInvalidID))
}

func TestStaticPasswordService_DeletePassword_NotFound(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	err := svc.DeletePassword("nonexistent")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, staticpw.ErrPasswordNotFound))
}

func TestStaticPasswordService_DeletePassword_NilStore(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	err := svc.DeletePassword("some-id")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, ErrStaticPWStoreNotSet))
}

// --- GeneratePassword ---

func TestStaticPasswordService_GeneratePassword(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	pw, err := svc.GeneratePassword(16, "alphanumeric")
	require.NoError(t, err)
	assert.Len(t, pw, 16)
}

func TestStaticPasswordService_GeneratePassword_DefaultLength(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	pw, err := svc.GeneratePassword(0, "")
	require.NoError(t, err)
	assert.Len(t, pw, staticpw.DefaultLength)
}

func TestStaticPasswordService_GeneratePassword_InvalidLength(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	// Too short.
	_, err := svc.GeneratePassword(3, "")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, staticpw.ErrInvalidLength))

	// Too long.
	_, err = svc.GeneratePassword(200, "")
	assert.Error(t, err)
	assert.True(t, errors.Is(err, staticpw.ErrInvalidLength))
}

func TestStaticPasswordService_GeneratePassword_NilStore(t *testing.T) {
	// GeneratePassword is a pure crypto function that does not require a store.
	svc := NewStaticPasswordService(nil)
	pw, err := svc.GeneratePassword(16, "")
	require.NoError(t, err)
	assert.Len(t, pw, 16)
}

func TestStaticPasswordService_GeneratePassword_AllCharset(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	pw, err := svc.GeneratePassword(32, "all")
	require.NoError(t, err)
	assert.Len(t, pw, 32)
}

// --- AddPasswordV2 ---

func TestStaticPasswordService_AddPasswordV2(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	expires := time.Now().Add(30 * 24 * time.Hour).Format(time.RFC3339)
	entry, err := svc.AddPasswordV2(AddPasswordParams{
		Name:       "GitHub",
		Title:      "GitHub Enterprise",
		Username:   "user@example.com",
		Password:   "secret123",
		URL:        "https://github.com",
		Notes:      "Enterprise account",
		FolderPath: "Work",
		ExpiresAt:  expires,
	})
	require.NoError(t, err)
	require.NotNil(t, entry)

	// IDs are deterministic xxhash-based hex strings derived from name+folder.
	expectedID := staticpw.GenerateID("GitHub", "Work")
	assert.Equal(t, expectedID, entry.ID)
	assert.Equal(t, "GitHub", entry.Name)
	assert.Equal(t, "GitHub Enterprise", entry.Title)
	assert.Equal(t, "user@example.com", entry.Username)
	assert.Equal(t, "secret123", entry.Password)
	assert.Equal(t, "https://github.com", entry.URL)
	assert.Equal(t, "Enterprise account", entry.Notes)
	assert.Equal(t, "Work", entry.FolderPath)
	assert.NotEmpty(t, entry.ExpiresAt)
	assert.False(t, entry.IsExpired)
	assert.Greater(t, entry.DaysUntilExpiry, 0)
}

func TestStaticPasswordService_AddPasswordV2_NilStore(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	_, err := svc.AddPasswordV2(AddPasswordParams{
		Name:     "Test",
		Password: "pw",
	})
	assert.ErrorIs(t, err, ErrStaticPWStoreNotSet)
}

func TestStaticPasswordService_AddPasswordV2_EmptyName(t *testing.T) {
	svc, _ := newTestStaticPWService(t)
	_, err := svc.AddPasswordV2(AddPasswordParams{
		Password: "pw",
	})
	assert.ErrorIs(t, err, ErrStaticPWInvalidName)
}

func TestStaticPasswordService_AddPasswordV2_InvalidExpiresAt(t *testing.T) {
	svc, _ := newTestStaticPWService(t)
	_, err := svc.AddPasswordV2(AddPasswordParams{
		Name:      "Test",
		Password:  "pw",
		ExpiresAt: "not-a-date",
	})
	assert.ErrorIs(t, err, ErrStaticPWInvalidExpiresAt)
}

func TestStaticPasswordService_AddPasswordV2_NoExpiry(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	entry, err := svc.AddPasswordV2(AddPasswordParams{
		Name:     "NoExpiry",
		Password: "pw",
	})
	require.NoError(t, err)
	assert.Empty(t, entry.ExpiresAt)
	assert.False(t, entry.IsExpired)
	assert.Equal(t, -1, entry.DaysUntilExpiry)
}

func TestStaticPasswordService_AddPasswordV2_ExpiredEntry(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	// Set expiry in the past.
	pastExpiry := time.Now().Add(-1 * time.Hour).Format(time.RFC3339)
	entry, err := svc.AddPasswordV2(AddPasswordParams{
		Name:      "Expired",
		Password:  "pw",
		ExpiresAt: pastExpiry,
	})
	require.NoError(t, err)
	assert.True(t, entry.IsExpired)
	assert.Equal(t, 0, entry.DaysUntilExpiry)
}

// --- UpdatePasswordV2 ---

func TestStaticPasswordService_UpdatePasswordV2(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	added, err := svc.AddPasswordV2(AddPasswordParams{
		Name:     "Original",
		Password: "pw1",
	})
	require.NoError(t, err)

	expires := time.Now().Add(7 * 24 * time.Hour).Format(time.RFC3339)
	err = svc.UpdatePasswordV2(UpdatePasswordParams{
		ID:         added.ID,
		Name:       "Updated",
		Title:      "Updated Title",
		Username:   "newuser",
		Password:   "newpw",
		URL:        "https://example.com",
		Notes:      "updated notes",
		FolderPath: "",
		ExpiresAt:  expires,
	})
	require.NoError(t, err)

	// Name changed, so the store regenerated the ID. Look up by new name.
	got, err := svc.GetPassword("Updated")
	require.NoError(t, err)
	assert.Equal(t, "Updated", got.Name)
	assert.Equal(t, "Updated Title", got.Title)
	assert.Equal(t, "newuser", got.Username)
	assert.Equal(t, "newpw", got.Password)
	assert.Equal(t, "https://example.com", got.URL)
	assert.Equal(t, "updated notes", got.Notes)
	assert.NotEmpty(t, got.ExpiresAt)
}

func TestStaticPasswordService_UpdatePasswordV2_NilStore(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	err := svc.UpdatePasswordV2(UpdatePasswordParams{
		ID:       "id",
		Name:     "Test",
		Password: "pw",
	})
	assert.ErrorIs(t, err, ErrStaticPWStoreNotSet)
}

func TestStaticPasswordService_UpdatePasswordV2_EmptyID(t *testing.T) {
	svc, _ := newTestStaticPWService(t)
	err := svc.UpdatePasswordV2(UpdatePasswordParams{
		Name:     "Test",
		Password: "pw",
	})
	assert.ErrorIs(t, err, ErrStaticPWInvalidID)
}

func TestStaticPasswordService_UpdatePasswordV2_InvalidExpiresAt(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	added, err := svc.AddPasswordV2(AddPasswordParams{
		Name:     "Test",
		Password: "pw",
	})
	require.NoError(t, err)

	err = svc.UpdatePasswordV2(UpdatePasswordParams{
		ID:        added.ID,
		Name:      "Test",
		Password:  "pw",
		ExpiresAt: "bad-date",
	})
	assert.ErrorIs(t, err, ErrStaticPWInvalidExpiresAt)
}

func TestStaticPasswordService_UpdatePasswordV2_ClearsExpiry(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	expires := time.Now().Add(7 * 24 * time.Hour).Format(time.RFC3339)
	added, err := svc.AddPasswordV2(AddPasswordParams{
		Name:      "WithExpiry",
		Password:  "pw",
		ExpiresAt: expires,
	})
	require.NoError(t, err)
	assert.NotEmpty(t, added.ExpiresAt)

	// Update without expiry to clear it.
	err = svc.UpdatePasswordV2(UpdatePasswordParams{
		ID:       added.ID,
		Name:     "WithExpiry",
		Password: "pw",
	})
	require.NoError(t, err)

	got, err := svc.GetPassword(added.ID)
	require.NoError(t, err)
	assert.Empty(t, got.ExpiresAt)
	assert.Equal(t, -1, got.DaysUntilExpiry)
}

// --- ListFolders ---

func TestStaticPasswordService_ListFolders(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	_, err := svc.AddPasswordV2(AddPasswordParams{
		Name: "Entry1", Password: "pw1", FolderPath: "Work",
	})
	require.NoError(t, err)

	_, err = svc.AddPasswordV2(AddPasswordParams{
		Name: "Entry2", Password: "pw2", FolderPath: "Work/Email",
	})
	require.NoError(t, err)

	_, err = svc.AddPasswordV2(AddPasswordParams{
		Name: "Entry3", Password: "pw3", FolderPath: "Personal",
	})
	require.NoError(t, err)

	folders, err := svc.ListFolders()
	require.NoError(t, err)
	assert.Equal(t, []string{"Personal", "Work", "Work/Email"}, folders)
}

func TestStaticPasswordService_ListFolders_Empty(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	folders, err := svc.ListFolders()
	require.NoError(t, err)
	assert.Empty(t, folders)
}

func TestStaticPasswordService_ListFolders_NilStore(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	_, err := svc.ListFolders()
	assert.ErrorIs(t, err, ErrStaticPWStoreNotSet)
}

// --- ListPasswordsByFolder ---

func TestStaticPasswordService_ListPasswordsByFolder(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	_, err := svc.AddPasswordV2(AddPasswordParams{
		Name: "WorkItem", Password: "pw1", FolderPath: "Work",
	})
	require.NoError(t, err)

	_, err = svc.AddPasswordV2(AddPasswordParams{
		Name: "RootItem", Password: "pw2",
	})
	require.NoError(t, err)

	// List Work folder.
	entries, err := svc.ListPasswordsByFolder("Work")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "WorkItem", entries[0].Name)
}

func TestStaticPasswordService_ListPasswordsByFolder_Root(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	_, err := svc.AddPasswordV2(AddPasswordParams{
		Name: "RootItem", Password: "pw1",
	})
	require.NoError(t, err)

	_, err = svc.AddPasswordV2(AddPasswordParams{
		Name: "FolderItem", Password: "pw2", FolderPath: "Work",
	})
	require.NoError(t, err)

	// ListByFolder("") returns ALL entries (root includes everything).
	entries, err := svc.ListPasswordsByFolder("")
	require.NoError(t, err)
	require.Len(t, entries, 2)
}

func TestStaticPasswordService_ListPasswordsByFolder_NilStore(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	_, err := svc.ListPasswordsByFolder("Work")
	assert.ErrorIs(t, err, ErrStaticPWStoreNotSet)
}

// --- MovePassword ---

func TestStaticPasswordService_MovePassword(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	added, err := svc.AddPasswordV2(AddPasswordParams{
		Name: "GitHub", Password: "secret",
	})
	require.NoError(t, err)

	err = svc.MovePassword(added.ID, "Work")
	require.NoError(t, err)

	// Moving regenerates the ID. Look up by name to find the moved entry.
	expectedID := staticpw.GenerateID("GitHub", "Work")
	got, err := svc.GetPassword("GitHub")
	require.NoError(t, err)
	assert.Equal(t, expectedID, got.ID)
	assert.Equal(t, "Work", got.FolderPath)

	// Exact new ID lookup should also work.
	gotByID, err := svc.GetPassword(expectedID)
	require.NoError(t, err)
	assert.Equal(t, "Work", gotByID.FolderPath)
}

func TestStaticPasswordService_MovePassword_EmptyID(t *testing.T) {
	svc, _ := newTestStaticPWService(t)
	err := svc.MovePassword("", "Work")
	assert.ErrorIs(t, err, ErrStaticPWInvalidID)
}

func TestStaticPasswordService_MovePassword_NilStore(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	err := svc.MovePassword("id", "Work")
	assert.ErrorIs(t, err, ErrStaticPWStoreNotSet)
}

// --- RenameFolder ---

func TestStaticPasswordService_RenameFolder(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	_, err := svc.AddPasswordV2(AddPasswordParams{
		Name: "Entry1", Password: "pw1", FolderPath: "OldName",
	})
	require.NoError(t, err)

	_, err = svc.AddPasswordV2(AddPasswordParams{
		Name: "Entry2", Password: "pw2", FolderPath: "OldName/Sub",
	})
	require.NoError(t, err)

	_, err = svc.AddPasswordV2(AddPasswordParams{
		Name: "Unaffected", Password: "pw3", FolderPath: "Other",
	})
	require.NoError(t, err)

	err = svc.RenameFolder("OldName", "NewName")
	require.NoError(t, err)

	// ListPasswordsByFolder is recursive: "NewName" includes "NewName" and
	// "NewName/Sub", so both renamed entries appear.
	entries, err := svc.ListPasswordsByFolder("NewName")
	require.NoError(t, err)
	require.Len(t, entries, 2)

	entries, err = svc.ListPasswordsByFolder("NewName/Sub")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "Entry2", entries[0].Name)

	// Old folder should be empty.
	entries, err = svc.ListPasswordsByFolder("OldName")
	require.NoError(t, err)
	assert.Empty(t, entries)

	// Unaffected entry should remain.
	entries, err = svc.ListPasswordsByFolder("Other")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "Unaffected", entries[0].Name)
}

func TestStaticPasswordService_RenameFolder_EmptyPath(t *testing.T) {
	svc, _ := newTestStaticPWService(t)
	err := svc.RenameFolder("", "NewName")
	assert.ErrorIs(t, err, ErrStaticPWInvalidFolderPath)
}

func TestStaticPasswordService_RenameFolder_NilStore(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	err := svc.RenameFolder("Old", "New")
	assert.ErrorIs(t, err, ErrStaticPWStoreNotSet)
}

// --- DeleteFolder ---

func TestStaticPasswordService_DeleteFolder(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	_, err := svc.AddPasswordV2(AddPasswordParams{
		Name: "ToDelete1", Password: "pw1", FolderPath: "Trash",
	})
	require.NoError(t, err)

	_, err = svc.AddPasswordV2(AddPasswordParams{
		Name: "ToDelete2", Password: "pw2", FolderPath: "Trash/Sub",
	})
	require.NoError(t, err)

	_, err = svc.AddPasswordV2(AddPasswordParams{
		Name: "Keep", Password: "pw3", FolderPath: "Safe",
	})
	require.NoError(t, err)

	err = svc.DeleteFolder("Trash")
	require.NoError(t, err)

	// Trash entries should be gone.
	entries, err := svc.ListPasswordsByFolder("Trash")
	require.NoError(t, err)
	assert.Empty(t, entries)

	entries, err = svc.ListPasswordsByFolder("Trash/Sub")
	require.NoError(t, err)
	assert.Empty(t, entries)

	// Safe entry should remain.
	entries, err = svc.ListPasswordsByFolder("Safe")
	require.NoError(t, err)
	require.Len(t, entries, 1)
	assert.Equal(t, "Keep", entries[0].Name)
}

func TestStaticPasswordService_DeleteFolder_EmptyPath(t *testing.T) {
	svc, _ := newTestStaticPWService(t)
	err := svc.DeleteFolder("")
	assert.ErrorIs(t, err, ErrStaticPWInvalidFolderPath)
}

func TestStaticPasswordService_DeleteFolder_NilStore(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	err := svc.DeleteFolder("Folder")
	assert.ErrorIs(t, err, ErrStaticPWStoreNotSet)
}

func TestStaticPasswordService_DeleteFolder_NonexistentFolder(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	// Deleting a folder that doesn't exist should succeed (no entries to delete).
	err := svc.DeleteFolder("NonExistent")
	require.NoError(t, err)
}

// --- SearchPasswords ---

func TestStaticPasswordService_SearchPasswords(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	_, err := svc.AddPasswordV2(AddPasswordParams{
		Name:     "GitHub",
		Title:    "GitHub Enterprise",
		Username: "user@github.com",
		Password: "pw1",
		URL:      "https://github.com",
		Notes:    "Enterprise SSO",
	})
	require.NoError(t, err)

	_, err = svc.AddPasswordV2(AddPasswordParams{
		Name:     "AWS",
		Title:    "Amazon Web Services",
		Username: "admin@aws.com",
		Password: "pw2",
		URL:      "https://aws.amazon.com",
		Notes:    "Root account",
	})
	require.NoError(t, err)

	_, err = svc.AddPasswordV2(AddPasswordParams{
		Name:     "Netflix",
		Password: "pw3",
		Notes:    "Family plan",
	})
	require.NoError(t, err)

	// Search by title.
	results, err := svc.SearchPasswords("enterprise")
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "GitHub", results[0].Name)

	// Search by username.
	results, err = svc.SearchPasswords("admin@aws")
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "AWS", results[0].Name)

	// Search by URL.
	results, err = svc.SearchPasswords("github.com")
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "GitHub", results[0].Name)

	// Search by notes.
	results, err = svc.SearchPasswords("family plan")
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "Netflix", results[0].Name)

	// Search by name.
	results, err = svc.SearchPasswords("aws")
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "AWS", results[0].Name)

	// Search matching nothing.
	results, err = svc.SearchPasswords("nonexistent-query")
	require.NoError(t, err)
	assert.Empty(t, results)
}

func TestStaticPasswordService_SearchPasswords_CaseInsensitive(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	_, err := svc.AddPasswordV2(AddPasswordParams{
		Name:     "GitHub",
		Password: "pw1",
	})
	require.NoError(t, err)

	results, err := svc.SearchPasswords("GITHUB")
	require.NoError(t, err)
	require.Len(t, results, 1)
	assert.Equal(t, "GitHub", results[0].Name)
}

func TestStaticPasswordService_SearchPasswords_NilStore(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	_, err := svc.SearchPasswords("test")
	assert.ErrorIs(t, err, ErrStaticPWStoreNotSet)
}

func TestStaticPasswordService_SearchPasswords_EmptyQuery(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	_, err := svc.AddPasswordV2(AddPasswordParams{
		Name: "Entry", Password: "pw",
	})
	require.NoError(t, err)

	// Empty query matches everything (empty string is contained in all strings).
	results, err := svc.SearchPasswords("")
	require.NoError(t, err)
	assert.Len(t, results, 1)
}

// --- staticPWToEntry ---

func TestStaticPWToEntry_AllFields(t *testing.T) {
	expires := time.Now().Add(10 * 24 * time.Hour)
	created := time.Now().Add(-24 * time.Hour)
	updated := time.Now()

	pw := &staticpw.StaticPassword{
		ID:         "work/github",
		Name:       "GitHub",
		Title:      "GitHub Enterprise",
		Username:   "user@example.com",
		Password:   "secret",
		URL:        "https://github.com",
		Notes:      "notes here",
		FolderPath: "Work",
		ExpiresAt:  expires,
		CreatedAt:  created,
		UpdatedAt:  updated,
	}

	entry := staticPWToEntry(pw)
	assert.Equal(t, "work/github", entry.ID)
	assert.Equal(t, "GitHub", entry.Name)
	assert.Equal(t, "GitHub Enterprise", entry.Title)
	assert.Equal(t, "user@example.com", entry.Username)
	assert.Equal(t, "secret", entry.Password)
	assert.Equal(t, "https://github.com", entry.URL)
	assert.Equal(t, "notes here", entry.Notes)
	assert.Equal(t, "Work", entry.FolderPath)
	assert.NotEmpty(t, entry.ExpiresAt)
	assert.NotEmpty(t, entry.CreatedAt)
	assert.NotEmpty(t, entry.UpdatedAt)
	assert.False(t, entry.IsExpired)
	assert.Greater(t, entry.DaysUntilExpiry, 0)
}

func TestStaticPWToEntry_NoExpiry(t *testing.T) {
	pw := &staticpw.StaticPassword{
		ID:       "test",
		Name:     "Test",
		Password: "pw",
	}

	entry := staticPWToEntry(pw)
	assert.Empty(t, entry.ExpiresAt)
	assert.False(t, entry.IsExpired)
	assert.Equal(t, -1, entry.DaysUntilExpiry)
}

func TestStaticPWToEntry_Expired(t *testing.T) {
	pw := &staticpw.StaticPassword{
		ID:        "test",
		Name:      "Test",
		Password:  "pw",
		ExpiresAt: time.Now().Add(-1 * time.Hour),
	}

	entry := staticPWToEntry(pw)
	assert.True(t, entry.IsExpired)
	assert.Equal(t, 0, entry.DaysUntilExpiry)
}

func TestStaticPWToEntry_DisplayTitleFallback(t *testing.T) {
	pw := &staticpw.StaticPassword{
		ID:       "test",
		Name:     "FallbackName",
		Password: "pw",
	}

	entry := staticPWToEntry(pw)
	assert.Equal(t, "FallbackName", entry.Title)
}

// --- ReadOnly: AddPasswordV2 ---

func TestAddPasswordV2_ReadOnly(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	// Add a read-only entry and verify ReadOnly=true is returned.
	entry, err := svc.AddPasswordV2(AddPasswordParams{
		Name:     "TPM Policy Auth",
		Password: "auto-generated-pw-xyz",
		ReadOnly: true,
	})
	require.NoError(t, err)
	require.NotNil(t, entry)

	assert.True(t, entry.ReadOnly)
	assert.Equal(t, "TPM Policy Auth", entry.Name)
	assert.Equal(t, "auto-generated-pw-xyz", entry.Password)

	// Retrieve and verify the persisted value.
	got, err := svc.GetPassword(entry.ID)
	require.NoError(t, err)
	assert.True(t, got.ReadOnly)
}

func TestAddPasswordV2_ReadOnly_DefaultFalse(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	// When ReadOnly is not set, the entry should default to false.
	entry, err := svc.AddPasswordV2(AddPasswordParams{
		Name:     "Regular Entry",
		Password: "regular-pw",
	})
	require.NoError(t, err)
	require.NotNil(t, entry)

	assert.False(t, entry.ReadOnly)
}

// --- ReadOnly: UpdatePasswordV2 blocked ---

func TestUpdatePasswordV2_ReadOnlyBlocked(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	// Add a read-only entry.
	added, err := svc.AddPasswordV2(AddPasswordParams{
		Name:     "Immutable Entry",
		Password: "locked-pw",
		ReadOnly: true,
	})
	require.NoError(t, err)

	// Attempt to update the read-only entry.
	err = svc.UpdatePasswordV2(UpdatePasswordParams{
		ID:       added.ID,
		Name:     "Renamed",
		Password: "new-pw",
	})
	assert.ErrorIs(t, err, ErrStaticPWReadOnly)

	// Verify the entry was not modified.
	got, err := svc.GetPassword(added.ID)
	require.NoError(t, err)
	assert.Equal(t, "Immutable Entry", got.Name)
	assert.Equal(t, "locked-pw", got.Password)
	assert.True(t, got.ReadOnly)
}

func TestUpdatePasswordV2_NonReadOnly_Succeeds(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	// Add a mutable entry (ReadOnly=false).
	added, err := svc.AddPasswordV2(AddPasswordParams{
		Name:     "Mutable",
		Password: "old-pw",
	})
	require.NoError(t, err)

	// Update should succeed.
	err = svc.UpdatePasswordV2(UpdatePasswordParams{
		ID:       added.ID,
		Name:     "Mutable Updated",
		Password: "new-pw",
	})
	require.NoError(t, err)

	// Name changed, so the store regenerated the ID. Look up by new name.
	got, err := svc.GetPassword("Mutable Updated")
	require.NoError(t, err)
	assert.Equal(t, "Mutable Updated", got.Name)
	assert.Equal(t, "new-pw", got.Password)
}

// --- ReadOnly: UpdatePassword (v1 compat) blocked ---

func TestUpdatePassword_ReadOnlyBlocked(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	// Add a read-only entry via V2.
	added, err := svc.AddPasswordV2(AddPasswordParams{
		Name:     "V1 Compat Lock",
		Password: "locked",
		ReadOnly: true,
	})
	require.NoError(t, err)

	// The v1 UpdatePassword delegates to UpdatePasswordV2, so the guard applies.
	err = svc.UpdatePassword(added.ID, "Changed", "new", "notes")
	assert.ErrorIs(t, err, ErrStaticPWReadOnly)
}

// --- ReadOnly: DeletePassword blocked ---

func TestDeletePassword_ReadOnlyBlocked(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	// Add a read-only entry.
	added, err := svc.AddPasswordV2(AddPasswordParams{
		Name:     "Protected Entry",
		Password: "do-not-delete",
		ReadOnly: true,
	})
	require.NoError(t, err)

	// Attempt to delete the read-only entry.
	err = svc.DeletePassword(added.ID)
	assert.ErrorIs(t, err, ErrStaticPWReadOnly)

	// Verify the entry still exists.
	got, err := svc.GetPassword(added.ID)
	require.NoError(t, err)
	assert.Equal(t, "Protected Entry", got.Name)
	assert.True(t, got.ReadOnly)
}

func TestDeletePassword_ReadOnlyBlocked_ByName(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	_, err := svc.AddPasswordV2(AddPasswordParams{
		Name:     "NameProtected",
		Password: "locked-pw",
		ReadOnly: true,
	})
	require.NoError(t, err)

	// Attempt to delete by name.
	err = svc.DeletePassword("NameProtected")
	assert.ErrorIs(t, err, ErrStaticPWReadOnly)
}

func TestDeletePassword_NonReadOnly_Succeeds(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	added, err := svc.AddPasswordV2(AddPasswordParams{
		Name:     "Deletable",
		Password: "bye-pw",
	})
	require.NoError(t, err)

	err = svc.DeletePassword(added.ID)
	require.NoError(t, err)

	// Verify it is gone.
	_, err = svc.GetPassword(added.ID)
	assert.ErrorIs(t, err, staticpw.ErrPasswordNotFound)
}

// --- ReadOnly: DeletePasswordForce ---

func TestDeletePasswordForce_ReadOnly(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	// Add a read-only entry.
	added, err := svc.AddPasswordV2(AddPasswordParams{
		Name:     "Force Delete Target",
		Password: "auto-pw",
		ReadOnly: true,
	})
	require.NoError(t, err)

	// Force delete should bypass the read-only check.
	err = svc.DeletePasswordForce(added.ID)
	require.NoError(t, err)

	// Verify the entry is gone.
	_, err = svc.GetPassword(added.ID)
	assert.ErrorIs(t, err, staticpw.ErrPasswordNotFound)
}

func TestDeletePasswordForce_NonReadOnly(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	// Force delete also works on regular entries.
	added, err := svc.AddPasswordV2(AddPasswordParams{
		Name:     "Regular Force",
		Password: "pw",
	})
	require.NoError(t, err)

	err = svc.DeletePasswordForce(added.ID)
	require.NoError(t, err)

	_, err = svc.GetPassword(added.ID)
	assert.ErrorIs(t, err, staticpw.ErrPasswordNotFound)
}

func TestDeletePasswordForce_NilStore(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	err := svc.DeletePasswordForce("some-id")
	assert.ErrorIs(t, err, ErrStaticPWStoreNotSet)
}

func TestDeletePasswordForce_EmptyID(t *testing.T) {
	svc, _ := newTestStaticPWService(t)
	err := svc.DeletePasswordForce("")
	assert.ErrorIs(t, err, ErrStaticPWInvalidID)
}

func TestDeletePasswordForce_NotFound(t *testing.T) {
	svc, _ := newTestStaticPWService(t)
	err := svc.DeletePasswordForce("nonexistent")
	assert.ErrorIs(t, err, staticpw.ErrPasswordNotFound)
}

// --- ReadOnly: staticPWToEntry mapping ---

func TestStaticPWToEntry_ReadOnly(t *testing.T) {
	pw := &staticpw.StaticPassword{
		ID:       "tpm-policy",
		Name:     "TPM Policy",
		Password: "auto-generated",
		ReadOnly: true,
	}

	entry := staticPWToEntry(pw)
	assert.True(t, entry.ReadOnly)
	assert.Equal(t, "tpm-policy", entry.ID)
	assert.Equal(t, "TPM Policy", entry.Name)
}

func TestStaticPWToEntry_ReadOnly_False(t *testing.T) {
	pw := &staticpw.StaticPassword{
		ID:       "regular",
		Name:     "Regular",
		Password: "pw",
		ReadOnly: false,
	}

	entry := staticPWToEntry(pw)
	assert.False(t, entry.ReadOnly)
}

func TestStaticPasswordService_SetStore(t *testing.T) {
	// Start with nil store.
	svc := NewStaticPasswordService(nil)
	_, err := svc.ListPasswords()
	assert.ErrorIs(t, err, ErrStaticPWStoreNotSet)

	// Wire a real store.
	backend, backendErr := filestorage.New(filepath.Join(t.TempDir(), "staticpw"))
	require.NoError(t, backendErr)
	store := staticpw.NewStore(backend)
	svc.SetStore(store)

	// Now listing should work.
	passwords, err := svc.ListPasswords()
	assert.NoError(t, err)
	assert.Empty(t, passwords)
}

// ---------------------------------------------------------------------------
// Mock transport client for server-side password store operations
// ---------------------------------------------------------------------------

// mockPasswordStoreClient implements the transport.PasswordService methods
// needed for testing. It embeds a nil transport.Client to satisfy the full
// interface while only implementing the PasswordStore methods.
type mockPasswordStoreClient struct {
	transport.Client // embed to satisfy interface; unused methods will panic

	unlockErr   error
	lockErr     error
	statusResp  *transport.PasswordStoreStatusResponse
	statusErr   error
	setModeErr  error
	generatePW  string
	generateErr error

	lastUnlockPIN string
	lastMode      string
	lastGenReq    *transport.PasswordGenerateRequest
}

func newMockPasswordStoreClient() *mockPasswordStoreClient {
	return &mockPasswordStoreClient{
		statusResp: &transport.PasswordStoreStatusResponse{
			AccessMode:    "pin",
			IsLocked:      true,
			AutoUnsealed:  false,
			PasswordCount: 5,
		},
		generatePW: "G3n3r@t3d!",
	}
}

func (m *mockPasswordStoreClient) PasswordStoreUnlock(_ context.Context, req *transport.PasswordStoreUnlockRequest) error {
	m.lastUnlockPIN = req.UserPIN
	return m.unlockErr
}

func (m *mockPasswordStoreClient) PasswordStoreLock(_ context.Context) error {
	return m.lockErr
}

func (m *mockPasswordStoreClient) PasswordStoreStatus(_ context.Context) (*transport.PasswordStoreStatusResponse, error) {
	return m.statusResp, m.statusErr
}

func (m *mockPasswordStoreClient) PasswordStoreSetAccessMode(_ context.Context, req *transport.PasswordStoreSetAccessModeRequest) error {
	m.lastMode = req.Mode
	return m.setModeErr
}

func (m *mockPasswordStoreClient) PasswordGenerate(_ context.Context, req *transport.PasswordGenerateRequest) (*transport.PasswordGenerateResponse, error) {
	m.lastGenReq = req
	if m.generateErr != nil {
		return nil, m.generateErr
	}
	return &transport.PasswordGenerateResponse{Password: m.generatePW}, nil
}

// newTestStaticPWServiceWithClient creates a service with both a local store
// and a transport client mock.
func newTestStaticPWServiceWithClient(t *testing.T) (*StaticPasswordService, *mockPasswordStoreClient) {
	t.Helper()
	backend := storage.NewMemory()
	store := staticpw.NewStore(backend)
	svc := NewStaticPasswordService(store)
	svc.SetContext(context.Background())
	mock := newMockPasswordStoreClient()
	svc.SetClient(mock)
	return svc, mock
}

// ---------------------------------------------------------------------------
// SetClient / getClient / getContext
// ---------------------------------------------------------------------------

func TestStaticPasswordService_SetClient(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	mock := newMockPasswordStoreClient()
	svc.SetClient(mock)

	client, err := svc.getClient()
	require.NoError(t, err)
	assert.NotNil(t, client)
}

func TestStaticPasswordService_GetClient_Nil(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	client, err := svc.getClient()
	assert.Nil(t, client)
	assert.ErrorIs(t, err, ErrStaticPWNoClient)
}

func TestStaticPasswordService_GetContext_Fallback(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	ctx := svc.getContext()
	assert.NotNil(t, ctx)
}

func TestStaticPasswordService_GetContext_Set(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	expected := context.Background()
	svc.SetContext(expected)
	assert.Equal(t, expected, svc.getContext())
}

// ---------------------------------------------------------------------------
// Unlock
// ---------------------------------------------------------------------------

func TestStaticPasswordService_Unlock(t *testing.T) {
	svc, mock := newTestStaticPWServiceWithClient(t)

	err := svc.Unlock("1234")
	require.NoError(t, err)
	assert.Equal(t, "1234", mock.lastUnlockPIN)
}

func TestStaticPasswordService_Unlock_NoClient(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	svc.SetContext(context.Background())

	err := svc.Unlock("1234")
	assert.ErrorIs(t, err, ErrStaticPWNoClient)
}

func TestStaticPasswordService_Unlock_ClientError(t *testing.T) {
	svc, mock := newTestStaticPWServiceWithClient(t)
	mock.unlockErr = errors.New("invalid pin")

	err := svc.Unlock("wrong")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid pin")
}

// ---------------------------------------------------------------------------
// Lock
// ---------------------------------------------------------------------------

func TestStaticPasswordService_Lock(t *testing.T) {
	svc, _ := newTestStaticPWServiceWithClient(t)

	err := svc.Lock()
	require.NoError(t, err)
}

func TestStaticPasswordService_Lock_NoClient(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	svc.SetContext(context.Background())

	err := svc.Lock()
	assert.ErrorIs(t, err, ErrStaticPWNoClient)
}

func TestStaticPasswordService_Lock_ClientError(t *testing.T) {
	svc, mock := newTestStaticPWServiceWithClient(t)
	mock.lockErr = errors.New("lock failed")

	err := svc.Lock()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "lock failed")
}

// ---------------------------------------------------------------------------
// GetStoreStatus
// ---------------------------------------------------------------------------

func TestStaticPasswordService_GetStoreStatus(t *testing.T) {
	svc, _ := newTestStaticPWServiceWithClient(t)

	status, err := svc.GetStoreStatus()
	require.NoError(t, err)
	require.NotNil(t, status)

	assert.Equal(t, "pin", status.AccessMode)
	assert.True(t, status.IsLocked)
	assert.False(t, status.AutoUnsealed)
	assert.Equal(t, 5, status.PasswordCount)
}

func TestStaticPasswordService_GetStoreStatus_NoClient(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	svc.SetContext(context.Background())

	_, err := svc.GetStoreStatus()
	assert.ErrorIs(t, err, ErrStaticPWNoClient)
}

func TestStaticPasswordService_GetStoreStatus_ClientError(t *testing.T) {
	svc, mock := newTestStaticPWServiceWithClient(t)
	mock.statusErr = errors.New("status unavailable")

	_, err := svc.GetStoreStatus()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "status unavailable")
}

// ---------------------------------------------------------------------------
// SetAccessMode
// ---------------------------------------------------------------------------

func TestStaticPasswordService_SetAccessMode(t *testing.T) {
	svc, mock := newTestStaticPWServiceWithClient(t)

	err := svc.SetAccessMode("open")
	require.NoError(t, err)
	assert.Equal(t, "open", mock.lastMode)
}

func TestStaticPasswordService_SetAccessMode_EmptyMode(t *testing.T) {
	svc, _ := newTestStaticPWServiceWithClient(t)

	err := svc.SetAccessMode("")
	assert.ErrorIs(t, err, ErrStaticPWInvalidAccessMode)
}

func TestStaticPasswordService_SetAccessMode_NoClient(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	svc.SetContext(context.Background())

	err := svc.SetAccessMode("pin")
	assert.ErrorIs(t, err, ErrStaticPWNoClient)
}

func TestStaticPasswordService_SetAccessMode_ClientError(t *testing.T) {
	svc, mock := newTestStaticPWServiceWithClient(t)
	mock.setModeErr = errors.New("mode not supported")

	err := svc.SetAccessMode("invalid-mode")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "mode not supported")
}

// ---------------------------------------------------------------------------
// TryAutoUnlock
// ---------------------------------------------------------------------------

func TestStaticPasswordService_TryAutoUnlock(t *testing.T) {
	svc, mock := newTestStaticPWServiceWithClient(t)

	err := svc.TryAutoUnlock()
	require.NoError(t, err)

	// Verify empty PIN was sent.
	assert.Equal(t, "", mock.lastUnlockPIN)
}

func TestStaticPasswordService_TryAutoUnlock_NoClient(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	svc.SetContext(context.Background())

	err := svc.TryAutoUnlock()
	assert.ErrorIs(t, err, ErrStaticPWNoClient)
}

func TestStaticPasswordService_TryAutoUnlock_ClientError(t *testing.T) {
	svc, mock := newTestStaticPWServiceWithClient(t)
	mock.unlockErr = errors.New("auto-unseal not available")

	err := svc.TryAutoUnlock()
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "auto-unseal not available")
}

// ---------------------------------------------------------------------------
// Generate
// ---------------------------------------------------------------------------

func TestStaticPasswordService_Generate(t *testing.T) {
	svc, mock := newTestStaticPWServiceWithClient(t)

	pw, err := svc.Generate(24, true, true, true, false)
	require.NoError(t, err)
	assert.Equal(t, "G3n3r@t3d!", pw)

	// Verify the request parameters were forwarded correctly.
	require.NotNil(t, mock.lastGenReq)
	assert.Equal(t, 24, mock.lastGenReq.Length)
	assert.True(t, mock.lastGenReq.Upper)
	assert.True(t, mock.lastGenReq.Lower)
	assert.True(t, mock.lastGenReq.Digits)
	assert.False(t, mock.lastGenReq.Symbols)
}

func TestStaticPasswordService_Generate_ZeroLength(t *testing.T) {
	svc, _ := newTestStaticPWServiceWithClient(t)

	_, err := svc.Generate(0, true, true, true, true)
	assert.ErrorIs(t, err, ErrStaticPWInvalidGenerateLength)
}

func TestStaticPasswordService_Generate_NegativeLength(t *testing.T) {
	svc, _ := newTestStaticPWServiceWithClient(t)

	_, err := svc.Generate(-5, true, true, true, true)
	assert.ErrorIs(t, err, ErrStaticPWInvalidGenerateLength)
}

func TestStaticPasswordService_Generate_NoClient(t *testing.T) {
	svc := NewStaticPasswordService(nil)
	svc.SetContext(context.Background())

	_, err := svc.Generate(16, true, true, true, true)
	assert.ErrorIs(t, err, ErrStaticPWNoClient)
}

func TestStaticPasswordService_Generate_ClientError(t *testing.T) {
	svc, mock := newTestStaticPWServiceWithClient(t)
	mock.generateErr = errors.New("generation failed")

	_, err := svc.Generate(16, true, true, true, true)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "generation failed")
}

// ---------------------------------------------------------------------------
// GeneratePassword - additional charset coverage
// ---------------------------------------------------------------------------

func TestStaticPasswordService_GeneratePassword_DefaultCharset(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	// Empty charset should default to "all" (CharsetAll).
	pw, err := svc.GeneratePassword(16, "")
	require.NoError(t, err)
	assert.Len(t, pw, 16)

	// Every character must be within CharsetAll.
	for _, c := range pw {
		assert.True(t, strings.ContainsRune(staticpw.CharsetAll, c),
			"unexpected character outside CharsetAll: %c", c)
	}
}

// ---------------------------------------------------------------------------
// AddPasswordV2 - additional field coverage
// ---------------------------------------------------------------------------

func TestStaticPasswordService_AddPasswordV2_EmptyPassword(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	// Name is set but password is empty; the underlying store rejects it.
	_, err := svc.AddPasswordV2(AddPasswordParams{
		Name: "EmptyPWEntry",
	})
	assert.Error(t, err)
	assert.ErrorIs(t, err, staticpw.ErrEmptyPassword)
}

func TestStaticPasswordService_AddPasswordV2_WithFolder(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	entry, err := svc.AddPasswordV2(AddPasswordParams{
		Name:       "FolderItem",
		Password:   "pw123",
		FolderPath: "Work/Engineering",
	})
	require.NoError(t, err)
	require.NotNil(t, entry)

	assert.Equal(t, "Work/Engineering", entry.FolderPath)

	// The deterministic ID includes the folder path.
	expectedID := staticpw.GenerateID("FolderItem", "Work/Engineering")
	assert.Equal(t, expectedID, entry.ID)
}

func TestStaticPasswordService_AddPasswordV2_WithExpiry(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	futureExpiry := time.Now().Add(90 * 24 * time.Hour).Format(time.RFC3339)
	entry, err := svc.AddPasswordV2(AddPasswordParams{
		Name:      "ExpiringEntry",
		Password:  "pw",
		ExpiresAt: futureExpiry,
	})
	require.NoError(t, err)
	require.NotNil(t, entry)

	assert.NotEmpty(t, entry.ExpiresAt)
	assert.False(t, entry.IsExpired)
	assert.Greater(t, entry.DaysUntilExpiry, 0)
}

func TestStaticPasswordService_AddPasswordV2_WithMatchPatterns(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	patterns := []string{"*.github.com", "github.com/*"}
	entry, err := svc.AddPasswordV2(AddPasswordParams{
		Name:          "GitHub",
		Password:      "secret",
		URL:           "https://github.com",
		MatchPatterns: patterns,
	})
	require.NoError(t, err)
	require.NotNil(t, entry)

	assert.Equal(t, patterns, entry.MatchPatterns)

	// Retrieve and verify match patterns persisted through the store round-trip.
	got, err := svc.GetPassword(entry.ID)
	require.NoError(t, err)
	assert.Equal(t, patterns, got.MatchPatterns)
}

// ---------------------------------------------------------------------------
// UpdatePasswordV2 - rename changes deterministic ID
// ---------------------------------------------------------------------------

func TestStaticPasswordService_UpdatePasswordV2_RenameChangesID(t *testing.T) {
	svc, _ := newTestStaticPWService(t)

	added, err := svc.AddPasswordV2(AddPasswordParams{
		Name:     "OrigName",
		Password: "pw",
	})
	require.NoError(t, err)
	origID := added.ID

	// Rename the entry.
	err = svc.UpdatePasswordV2(UpdatePasswordParams{
		ID:       origID,
		Name:     "RenamedEntry",
		Password: "pw",
	})
	require.NoError(t, err)

	// The old ID should no longer resolve.
	_, err = svc.GetPassword(origID)
	assert.ErrorIs(t, err, staticpw.ErrPasswordNotFound)

	// The new deterministic ID should work.
	newExpectedID := staticpw.GenerateID("RenamedEntry", "")
	got, err := svc.GetPassword(newExpectedID)
	require.NoError(t, err)
	assert.Equal(t, "RenamedEntry", got.Name)
	assert.Equal(t, newExpectedID, got.ID)
}
