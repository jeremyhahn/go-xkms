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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestDAOStore_ListByFolderDirect exercises the uncovered ListByFolderDirect method.
func TestDAOStore_ListByFolderDirect(t *testing.T) {
	s := newTestStore(t)
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

// TestDAOStore_Close_AlreadyClosed exercises the double-close guard.
func TestDAOStore_Close_AlreadyClosed(t *testing.T) {
	s := newTestStore(t)

	require.NoError(t, s.Close())
	assert.NoError(t, s.Close())
}

// TestDAOStore_FindByName_CaseInsensitive exercises case-insensitive name lookup
// via the getUnlocked fallback scan path.
func TestDAOStore_FindByName_CaseInsensitive(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	require.NoError(t, s.Add(&StaticPassword{Name: "MyGmail", Password: "pw"}))

	pw, err := s.Get("mygmail")
	require.NoError(t, err)
	assert.Equal(t, "MyGmail", pw.Name)
}

// TestDAOStore_MoveToFolder_ClosedStore exercises the closed-store guard.
func TestDAOStore_MoveToFolder_ClosedStore(t *testing.T) {
	s := newTestStore(t)
	require.NoError(t, s.Add(&StaticPassword{Name: "test", Password: "pw"}))
	require.NoError(t, s.Close())

	err := s.MoveToFolder("test", "NewFolder")
	assert.ErrorIs(t, err, ErrStoreClosed)
}

// TestDAOStore_MoveToFolder_DuplicateAtDestination exercises the conflict check.
func TestDAOStore_MoveToFolder_DuplicateAtDestination(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	pw1 := &StaticPassword{Name: "dup", Password: "pw1", FolderPath: "A"}
	require.NoError(t, s.Add(pw1))
	pw2 := &StaticPassword{Name: "dup", Password: "pw2", FolderPath: "B"}
	require.NoError(t, s.Add(pw2))

	err := s.MoveToFolder(pw1.ID, "B")
	assert.ErrorIs(t, err, ErrPasswordExists)
}

// TestDAOStore_CheckNameConflict_AcrossFolders exercises same name in different folders.
func TestDAOStore_CheckNameConflict_AcrossFolders(t *testing.T) {
	s := newTestStore(t)
	defer func() { _ = s.Close() }()

	require.NoError(t, s.Add(&StaticPassword{Name: "conflict", Password: "pw", FolderPath: "Work"}))

	err := s.Add(&StaticPassword{Name: "conflict", Password: "pw2", FolderPath: "Work"})
	assert.ErrorIs(t, err, ErrPasswordExists)

	err = s.Add(&StaticPassword{Name: "conflict", Password: "pw3", FolderPath: "Personal"})
	assert.NoError(t, err)
}
