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

// TestBackendStore_ListByFolderDirect exercises the uncovered ListByFolderDirect method.
func TestBackendStore_ListByFolderDirect(t *testing.T) {
	s := NewStore(storage.New())
	defer func() { _ = s.Close() }()

	require.NoError(t, s.Add(&StaticPassword{Name: "root1", Password: "pw"}))
	require.NoError(t, s.Add(&StaticPassword{Name: "sub1", Password: "pw", FolderPath: "Work"}))
	require.NoError(t, s.Add(&StaticPassword{Name: "sub2", Password: "pw", FolderPath: "Work"}))
	require.NoError(t, s.Add(&StaticPassword{Name: "nested", Password: "pw", FolderPath: "Work/Email"}))

	t.Run("root level returns only entries with empty folder", func(t *testing.T) {
		result, err := s.ListByFolderDirect("")
		require.NoError(t, err)
		assert.Len(t, result, 1)
		assert.Equal(t, "root1", result[0].Name)
	})

	t.Run("Work folder returns direct children only", func(t *testing.T) {
		result, err := s.ListByFolderDirect("Work")
		require.NoError(t, err)
		assert.Len(t, result, 2)
	})

	t.Run("Work/Email returns nested entry", func(t *testing.T) {
		result, err := s.ListByFolderDirect("Work/Email")
		require.NoError(t, err)
		assert.Len(t, result, 1)
		assert.Equal(t, "nested", result[0].Name)
	})

	t.Run("nonexistent folder returns empty", func(t *testing.T) {
		result, err := s.ListByFolderDirect("NoSuchFolder")
		require.NoError(t, err)
		assert.Empty(t, result)
	})
}

// TestBackendStore_Close_AlreadyClosed exercises the double-close guard.
func TestBackendStore_Close_AlreadyClosed(t *testing.T) {
	s := NewStore(storage.New())

	require.NoError(t, s.Close())
	assert.NoError(t, s.Close())
}

// TestBackendStore_FindByName_CaseInsensitive exercises case-insensitive name lookup
// via the getUnlocked fallback scan path.
func TestBackendStore_FindByName_CaseInsensitive(t *testing.T) {
	s := NewStore(storage.New())
	defer func() { _ = s.Close() }()

	require.NoError(t, s.Add(&StaticPassword{Name: "MyGmail", Password: "pw"}))

	pw, err := s.Get("mygmail")
	require.NoError(t, err)
	assert.Equal(t, "MyGmail", pw.Name)
}

// TestBackendStore_MoveToFolder_ClosedStore exercises the closed-store guard.
func TestBackendStore_MoveToFolder_ClosedStore(t *testing.T) {
	s := NewStore(storage.New())
	require.NoError(t, s.Add(&StaticPassword{Name: "test", Password: "pw"}))
	require.NoError(t, s.Close())

	err := s.MoveToFolder("test", "NewFolder")
	assert.ErrorIs(t, err, ErrStoreClosed)
}

// TestBackendStore_MoveToFolder_DuplicateAtDestination exercises the conflict check.
func TestBackendStore_MoveToFolder_DuplicateAtDestination(t *testing.T) {
	s := NewStore(storage.New())
	defer func() { _ = s.Close() }()

	pw1 := &StaticPassword{Name: "dup", Password: "pw1", FolderPath: "A"}
	require.NoError(t, s.Add(pw1))
	pw2 := &StaticPassword{Name: "dup", Password: "pw2", FolderPath: "B"}
	require.NoError(t, s.Add(pw2))

	err := s.MoveToFolder(pw1.ID, "B")
	assert.ErrorIs(t, err, ErrPasswordExists)
}

// TestBackendStore_CheckNameConflict_AcrossFolders exercises same name in different folders.
func TestBackendStore_CheckNameConflict_AcrossFolders(t *testing.T) {
	s := NewStore(storage.New())
	defer func() { _ = s.Close() }()

	require.NoError(t, s.Add(&StaticPassword{Name: "conflict", Password: "pw", FolderPath: "Work"}))

	err := s.Add(&StaticPassword{Name: "conflict", Password: "pw2", FolderPath: "Work"})
	assert.ErrorIs(t, err, ErrPasswordExists)

	err = s.Add(&StaticPassword{Name: "conflict", Password: "pw3", FolderPath: "Personal"})
	assert.NoError(t, err)
}

// TestEncryptedStore_ListByFolderDirect exercises the delegate wrapper.
func TestEncryptedStore_ListByFolderDirect(t *testing.T) {
	inner := NewStore(storage.New())
	es, err := NewEncryptedStore(inner, &mockEncrypter{})
	require.NoError(t, err)
	defer func() { _ = es.Close() }()

	require.NoError(t, es.Add(&StaticPassword{Name: "a", Password: "pw", FolderPath: "Work"}))
	require.NoError(t, es.Add(&StaticPassword{Name: "b", Password: "pw"}))

	result, err := es.ListByFolderDirect("Work")
	require.NoError(t, err)
	assert.Len(t, result, 1)

	result, err = es.ListByFolderDirect("")
	require.NoError(t, err)
	assert.Len(t, result, 1)
}

// TestEncryptedStore_CreateFolder exercises the delegate wrapper.
func TestEncryptedStore_CreateFolder(t *testing.T) {
	inner := NewStore(storage.New())
	es, err := NewEncryptedStore(inner, &mockEncrypter{})
	require.NoError(t, err)
	defer func() { _ = es.Close() }()

	require.NoError(t, es.CreateFolder("MyFolder"))
	folders, err := es.ListFolders()
	require.NoError(t, err)
	assert.Contains(t, folders, "MyFolder")
}

// TestEncryptedStore_RemoveFolder exercises the delegate wrapper.
func TestEncryptedStore_RemoveFolder(t *testing.T) {
	inner := NewStore(storage.New())
	es, err := NewEncryptedStore(inner, &mockEncrypter{})
	require.NoError(t, err)
	defer func() { _ = es.Close() }()

	require.NoError(t, es.CreateFolder("Temp"))
	require.NoError(t, es.RemoveFolder("Temp"))

	// Removing a non-existent folder should not error.
	assert.NoError(t, es.RemoveFolder("Nonexistent"))
}

// TestPINAccessStore_ListByFolderDirect exercises the delegate wrapper.
func TestPINAccessStore_ListByFolderDirect(t *testing.T) {
	pas, _ := newTestPINAccessStore(t)
	defer func() { _ = pas.Close() }()

	require.NoError(t, pas.Add(&StaticPassword{Name: "f1", Password: "pw", FolderPath: "F"}))

	result, err := pas.ListByFolderDirect("F")
	require.NoError(t, err)
	assert.Len(t, result, 1)
}

// TestPINAccessStore_CreateFolder exercises the delegate wrapper.
func TestPINAccessStore_CreateFolder(t *testing.T) {
	pas, _ := newTestPINAccessStore(t)
	defer func() { _ = pas.Close() }()

	require.NoError(t, pas.CreateFolder("PINFolder"))
}

// TestPINAccessStore_RemoveFolder exercises the delegate wrapper.
func TestPINAccessStore_RemoveFolder(t *testing.T) {
	pas, _ := newTestPINAccessStore(t)
	defer func() { _ = pas.Close() }()

	require.NoError(t, pas.CreateFolder("PINFolder"))
	require.NoError(t, pas.RemoveFolder("PINFolder"))
}

// TestSessionStore_ListByFolderDirect exercises the delegate wrapper.
func TestSessionStore_ListByFolderDirect(t *testing.T) {
	ss, _ := newTestSessionStore(t)
	defer func() { _ = ss.Close() }()

	require.NoError(t, ss.Add(&StaticPassword{Name: "s1", Password: "pw", FolderPath: "S"}))

	result, err := ss.ListByFolderDirect("S")
	require.NoError(t, err)
	assert.Len(t, result, 1)
}

// TestSessionStore_CreateFolder exercises the delegate wrapper.
func TestSessionStore_CreateFolder(t *testing.T) {
	ss, _ := newTestSessionStore(t)
	defer func() { _ = ss.Close() }()

	require.NoError(t, ss.CreateFolder("SessionFolder"))
}

// TestSessionStore_RemoveFolder exercises the delegate wrapper.
func TestSessionStore_RemoveFolder(t *testing.T) {
	ss, _ := newTestSessionStore(t)
	defer func() { _ = ss.Close() }()

	require.NoError(t, ss.CreateFolder("SessionFolder"))
	require.NoError(t, ss.RemoveFolder("SessionFolder"))
}
